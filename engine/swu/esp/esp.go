package esp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/kimoju/vowifi-go/engine/swu/ikev2"
)

const (
	NextHeaderIPv4   = 4
	NextHeaderIPv6   = 41
	NextHeaderNoNext = 59
)

const (
	aesGCMSaltLength       = 4
	aesGCMExplicitIVLength = 8
	aesGCMICVLength        = 16
	aesGCMPaddingAlignment = 4
)

var (
	ErrInvalidSA     = errors.New("invalid esp sa")
	ErrInvalidPacket = errors.New("invalid esp packet")
	ErrReplay        = errors.New("esp replay detected")
)

type IntegrityAlgorithm uint16

const (
	IntegrityHMACSHA1_96      IntegrityAlgorithm = IntegrityAlgorithm(ikev2.INTEG_HMAC_SHA1_96)
	IntegrityHMACSHA2_256_128 IntegrityAlgorithm = IntegrityAlgorithm(ikev2.INTEG_HMAC_SHA2_256_128)
	IntegrityHMACSHA2_384_192 IntegrityAlgorithm = IntegrityAlgorithm(ikev2.INTEG_HMAC_SHA2_384_192)
	IntegrityHMACSHA2_512_256 IntegrityAlgorithm = IntegrityAlgorithm(ikev2.INTEG_HMAC_SHA2_512_256)
)

type EncryptionAlgorithm uint16

const (
	EncryptionAESCBC    EncryptionAlgorithm = EncryptionAlgorithm(ikev2.ENCR_AES_CBC)
	EncryptionAESGCM_16 EncryptionAlgorithm = EncryptionAlgorithm(ikev2.ENCR_AES_GCM_16)
)

type SA struct {
	SPI                 uint32
	Encryption          EncryptionAlgorithm
	EncryptionKey       []byte
	IntegrityKey        []byte
	Integrity           IntegrityAlgorithm
	ICVLength           int
	BlockSize           int
	ESN                 bool
	Sequence            uint32
	SequenceHigh        uint32
	HighestSequence     uint32
	HighestSequenceHigh uint32
	ReplayWindowSize    uint32
	ReplayBitmap        uint64
}

type SealOptions struct {
	Sequence   uint32
	Sequence64 uint64
	IV         []byte
	Random     io.Reader
}

type OpenResult struct {
	SPI        uint32
	Sequence   uint32
	Sequence64 uint64
	NextHeader uint8
	Payload    []byte
}

func NewOutboundSAFromChild(child ikev2.ChildSAResult) (*SA, error) {
	spi, err := spiFromBytes(child.RemoteSPI)
	if err != nil {
		return nil, err
	}
	return NewSA(SA{
		SPI:           spi,
		Encryption:    EncryptionAlgorithm(child.Keys.Profile.EncryptionID),
		EncryptionKey: child.Keys.Outbound.EncryptionKey,
		IntegrityKey:  child.Keys.Outbound.IntegrityKey,
		Integrity:     IntegrityAlgorithm(child.Keys.Profile.IntegrityID),
		ICVLength:     icvLengthForChildProfile(child.Keys.Profile),
		BlockSize:     blockSizeForChildProfile(child.Keys.Profile),
		ESN:           child.Keys.Profile.ESN,
	})
}

func NewInboundSAFromChild(child ikev2.ChildSAResult) (*SA, error) {
	spi, err := spiFromBytes(child.LocalSPI)
	if err != nil {
		return nil, err
	}
	return NewSA(SA{
		SPI:              spi,
		Encryption:       EncryptionAlgorithm(child.Keys.Profile.EncryptionID),
		EncryptionKey:    child.Keys.Inbound.EncryptionKey,
		IntegrityKey:     child.Keys.Inbound.IntegrityKey,
		Integrity:        IntegrityAlgorithm(child.Keys.Profile.IntegrityID),
		ICVLength:        icvLengthForChildProfile(child.Keys.Profile),
		BlockSize:        blockSizeForChildProfile(child.Keys.Profile),
		ESN:              child.Keys.Profile.ESN,
		ReplayWindowSize: 64,
	})
}

func NewSA(sa SA) (*SA, error) {
	if sa.SPI == 0 {
		return nil, fmt.Errorf("%w: spi is zero", ErrInvalidSA)
	}
	switch sa.encryptionAlgorithm() {
	case EncryptionAESCBC:
		if len(sa.EncryptionKey) != 16 && len(sa.EncryptionKey) != 24 && len(sa.EncryptionKey) != 32 {
			return nil, fmt.Errorf("%w: AES key length %d", ErrInvalidSA, len(sa.EncryptionKey))
		}
		if len(sa.IntegrityKey) == 0 {
			return nil, fmt.Errorf("%w: integrity key is empty", ErrInvalidSA)
		}
		if sa.BlockSize == 0 {
			sa.BlockSize = aes.BlockSize
		}
		if sa.BlockSize != aes.BlockSize {
			return nil, fmt.Errorf("%w: block size %d", ErrInvalidSA, sa.BlockSize)
		}
		if sa.ICVLength == 0 {
			sa.ICVLength = integrityICVLength(sa.Integrity)
		}
		if sa.ICVLength <= 0 {
			return nil, fmt.Errorf("%w: unsupported integrity %d", ErrInvalidSA, sa.Integrity)
		}
	case EncryptionAESGCM_16:
		if !validAESGCMKeyLength(len(sa.EncryptionKey)) {
			return nil, fmt.Errorf("%w: AES-GCM key length %d", ErrInvalidSA, len(sa.EncryptionKey))
		}
		if sa.BlockSize == 0 {
			sa.BlockSize = aesGCMPaddingAlignment
		}
		if sa.BlockSize != aesGCMPaddingAlignment {
			return nil, fmt.Errorf("%w: block size %d", ErrInvalidSA, sa.BlockSize)
		}
		if sa.ICVLength == 0 {
			sa.ICVLength = aesGCMICVLength
		}
		if sa.ICVLength != aesGCMICVLength {
			return nil, fmt.Errorf("%w: AES-GCM ICV length %d", ErrInvalidSA, sa.ICVLength)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported encryption %d", ErrInvalidSA, sa.Encryption)
	}
	return &sa, nil
}

func (s *SA) Seal(nextHeader uint8, payload []byte, opts SealOptions) ([]byte, error) {
	if s == nil {
		return nil, ErrInvalidSA
	}
	seq64, err := s.nextSealSequence(opts)
	if err != nil {
		return nil, err
	}
	switch s.encryptionAlgorithm() {
	case EncryptionAESCBC:
		return s.sealAESCBC(nextHeader, payload, seq64, opts)
	case EncryptionAESGCM_16:
		return s.sealAESGCM(nextHeader, payload, seq64, opts)
	default:
		return nil, fmt.Errorf("%w: unsupported encryption %d", ErrInvalidSA, s.Encryption)
	}
}

func (s *SA) nextSealSequence(opts SealOptions) (uint64, error) {
	if !s.ESN {
		seq := opts.Sequence
		if seq == 0 && opts.Sequence64 != 0 {
			if opts.Sequence64 > uint64(^uint32(0)) {
				return 0, fmt.Errorf("%w: sequence overflow", ErrInvalidSA)
			}
			seq = uint32(opts.Sequence64)
		}
		if seq == 0 {
			if s.Sequence == ^uint32(0) {
				return 0, fmt.Errorf("%w: sequence overflow", ErrInvalidSA)
			}
			s.Sequence++
			seq = s.Sequence
		} else if seq > s.Sequence {
			s.Sequence = seq
		}
		return uint64(seq), nil
	}

	cur64 := (uint64(s.SequenceHigh) << 32) | uint64(s.Sequence)
	var seq64 uint64
	switch {
	case opts.Sequence64 != 0:
		seq64 = opts.Sequence64
	case opts.Sequence != 0:
		seq64 = (uint64(s.SequenceHigh) << 32) | uint64(opts.Sequence)
	default:
		if cur64 == ^uint64(0) {
			return 0, fmt.Errorf("%w: sequence overflow", ErrInvalidSA)
		}
		seq64 = cur64 + 1
	}
	if seq64 > cur64 {
		s.Sequence = uint32(seq64)
		s.SequenceHigh = uint32(seq64 >> 32)
	}
	return seq64, nil
}

func (s *SA) sealAESCBC(nextHeader uint8, payload []byte, seq64 uint64, opts SealOptions) ([]byte, error) {
	iv := append([]byte(nil), opts.IV...)
	if len(iv) == 0 {
		random := opts.Random
		if random == nil {
			random = rand.Reader
		}
		iv = make([]byte, s.BlockSize)
		if _, err := io.ReadFull(random, iv); err != nil {
			return nil, err
		}
	}
	if len(iv) != s.BlockSize {
		return nil, fmt.Errorf("%w: iv length %d", ErrInvalidPacket, len(iv))
	}
	plain := espPlaintext(payload, nextHeader, s.BlockSize)
	ciphertext, err := aesCBCEncrypt(s.EncryptionKey, iv, plain)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 8, 8+len(iv)+len(ciphertext)+s.ICVLength)
	binary.BigEndian.PutUint32(packet[0:4], s.SPI)
	binary.BigEndian.PutUint32(packet[4:8], uint32(seq64))
	packet = append(packet, iv...)
	packet = append(packet, ciphertext...)
	icv, err := s.integrity(packet, uint32(seq64>>32))
	if err != nil {
		return nil, err
	}
	packet = append(packet, icv...)
	return packet, nil
}

func (s *SA) sealAESGCM(nextHeader uint8, payload []byte, seq64 uint64, opts SealOptions) ([]byte, error) {
	iv := append([]byte(nil), opts.IV...)
	if len(iv) == 0 {
		iv = make([]byte, aesGCMExplicitIVLength)
		binary.BigEndian.PutUint64(iv, seq64)
	}
	if len(iv) != aesGCMExplicitIVLength {
		return nil, fmt.Errorf("%w: iv length %d", ErrInvalidPacket, len(iv))
	}
	aead, salt, err := s.aesGCMAEAD()
	if err != nil {
		return nil, err
	}
	plain := espPlaintext(payload, nextHeader, s.BlockSize)
	packet := make([]byte, 8, 8+len(iv)+len(plain)+aead.Overhead())
	binary.BigEndian.PutUint32(packet[0:4], s.SPI)
	binary.BigEndian.PutUint32(packet[4:8], uint32(seq64))
	packet = append(packet, iv...)
	nonce := aesGCMNonce(salt, iv)
	aad := s.aesGCMAAD(packet[:8], seq64)
	packet = aead.Seal(packet, nonce, plain, aad)
	return packet, nil
}

func (s *SA) aesGCMAAD(header8 []byte, seq64 uint64) []byte {
	if !s.ESN {
		return header8
	}
	var aad [12]byte
	copy(aad[0:4], header8[0:4])
	binary.BigEndian.PutUint64(aad[4:12], seq64)
	return aad[:]
}

func (s *SA) Open(packet []byte) (OpenResult, error) {
	if s == nil {
		return OpenResult{}, ErrInvalidSA
	}
	switch s.encryptionAlgorithm() {
	case EncryptionAESCBC:
		return s.openAESCBC(packet)
	case EncryptionAESGCM_16:
		return s.openAESGCM(packet)
	default:
		return OpenResult{}, fmt.Errorf("%w: unsupported encryption %d", ErrInvalidSA, s.Encryption)
	}
}

func (s *SA) openAESCBC(packet []byte) (OpenResult, error) {
	if len(packet) < 8+s.BlockSize+s.ICVLength+s.BlockSize {
		return OpenResult{}, fmt.Errorf("%w: too short", ErrInvalidPacket)
	}
	spi := binary.BigEndian.Uint32(packet[0:4])
	if spi != s.SPI {
		return OpenResult{}, fmt.Errorf("%w: spi %08x != %08x", ErrInvalidPacket, spi, s.SPI)
	}
	seqLow := binary.BigEndian.Uint32(packet[4:8])
	seq64, err := s.resolveInboundSequence(seqLow)
	if err != nil {
		return OpenResult{}, err
	}
	if err := s.checkReplay64(seq64); err != nil {
		return OpenResult{}, err
	}
	bodyEnd := len(packet) - s.ICVLength
	body := packet[8:bodyEnd]
	if len(body) < s.BlockSize || (len(body)-s.BlockSize)%s.BlockSize != 0 {
		return OpenResult{}, fmt.Errorf("%w: invalid encrypted body length", ErrInvalidPacket)
	}
	gotICV := packet[bodyEnd:]
	wantICV, err := s.integrity(packet[:bodyEnd], uint32(seq64>>32))
	if err != nil {
		return OpenResult{}, err
	}
	if !hmac.Equal(gotICV, wantICV) {
		return OpenResult{}, fmt.Errorf("%w: icv mismatch", ErrInvalidPacket)
	}
	iv := body[:s.BlockSize]
	ciphertext := body[s.BlockSize:]
	plain, err := aesCBCDecrypt(s.EncryptionKey, iv, ciphertext)
	if err != nil {
		return OpenResult{}, err
	}
	payload, nextHeader, err := parseESPPlaintext(plain)
	if err != nil {
		return OpenResult{}, err
	}
	s.acceptSequence64(seq64)
	return OpenResult{SPI: spi, Sequence: seqLow, Sequence64: seq64, NextHeader: nextHeader, Payload: payload}, nil
}

func (s *SA) openAESGCM(packet []byte) (OpenResult, error) {
	if len(packet) < 8+aesGCMExplicitIVLength+s.ICVLength+2 {
		return OpenResult{}, fmt.Errorf("%w: too short", ErrInvalidPacket)
	}
	spi := binary.BigEndian.Uint32(packet[0:4])
	if spi != s.SPI {
		return OpenResult{}, fmt.Errorf("%w: spi %08x != %08x", ErrInvalidPacket, spi, s.SPI)
	}
	seqLow := binary.BigEndian.Uint32(packet[4:8])
	seq64, err := s.resolveInboundSequence(seqLow)
	if err != nil {
		return OpenResult{}, err
	}
	if err := s.checkReplay64(seq64); err != nil {
		return OpenResult{}, err
	}
	aead, salt, err := s.aesGCMAEAD()
	if err != nil {
		return OpenResult{}, err
	}
	body := packet[8:]
	iv := body[:aesGCMExplicitIVLength]
	ciphertext := body[aesGCMExplicitIVLength:]
	aad := s.aesGCMAAD(packet[:8], seq64)
	plain, err := aead.Open(nil, aesGCMNonce(salt, iv), ciphertext, aad)
	if err != nil {
		return OpenResult{}, fmt.Errorf("%w: icv mismatch", ErrInvalidPacket)
	}
	payload, nextHeader, err := parseESPPlaintext(plain)
	if err != nil {
		return OpenResult{}, err
	}
	s.acceptSequence64(seq64)
	return OpenResult{SPI: spi, Sequence: seqLow, Sequence64: seq64, NextHeader: nextHeader, Payload: payload}, nil
}

func (s *SA) integrity(data []byte, seqHigh uint32) ([]byte, error) {
	var mac hashMAC
	switch s.Integrity {
	case IntegrityHMACSHA1_96:
		mac = hmac.New(sha1.New, s.IntegrityKey)
	case IntegrityHMACSHA2_256_128:
		mac = hmac.New(sha256.New, s.IntegrityKey)
	case IntegrityHMACSHA2_384_192:
		mac = hmac.New(sha512.New384, s.IntegrityKey)
	case IntegrityHMACSHA2_512_256:
		mac = hmac.New(sha512.New, s.IntegrityKey)
	default:
		return nil, fmt.Errorf("%w: unsupported integrity %d", ErrInvalidSA, s.Integrity)
	}
	_, _ = mac.Write(data)
	if s.ESN {
		var high [4]byte
		binary.BigEndian.PutUint32(high[:], seqHigh)
		_, _ = mac.Write(high[:])
	}
	sum := mac.Sum(nil)
	if s.ICVLength > len(sum) {
		return nil, fmt.Errorf("%w: icv length %d", ErrInvalidSA, s.ICVLength)
	}
	return append([]byte(nil), sum[:s.ICVLength]...), nil
}

func (s *SA) aesGCMAEAD() (cipher.AEAD, []byte, error) {
	keyLen := len(s.EncryptionKey) - aesGCMSaltLength
	block, err := aes.NewCipher(s.EncryptionKey[:keyLen])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCMWithTagSize(block, s.ICVLength)
	if err != nil {
		return nil, nil, err
	}
	return aead, s.EncryptionKey[keyLen:], nil
}

func aesGCMNonce(salt, iv []byte) []byte {
	nonce := make([]byte, 0, len(salt)+len(iv))
	nonce = append(nonce, salt...)
	nonce = append(nonce, iv...)
	return nonce
}

type hashMAC interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func (s *SA) resolveInboundSequence(seqLow uint32) (uint64, error) {
	if !s.ESN {
		if seqLow == 0 {
			return 0, fmt.Errorf("%w: sequence zero", ErrInvalidPacket)
		}
		return uint64(seqLow), nil
	}
	highest64 := (uint64(s.HighestSequenceHigh) << 32) | uint64(s.HighestSequence)
	w := uint64(s.ReplayWindowSize)
	if w == 0 {
		w = 1
	} else if w > 64 {
		w = 64
	}
	tl := s.HighestSequence
	th := s.HighestSequenceHigh
	var bl64 uint64
	if highest64+1 >= w {
		bl64 = highest64 - w + 1
	}
	bl := uint32(bl64)
	var seqHigh uint32
	if uint64(tl) >= w-1 {
		if seqLow >= bl {
			seqHigh = th
		} else {
			seqHigh = th + 1
		}
	} else {
		if seqLow >= bl {
			if th > 0 {
				seqHigh = th - 1
			} else {
				seqHigh = 0
			}
		} else {
			seqHigh = th
		}
	}
	seq64 := (uint64(seqHigh) << 32) | uint64(seqLow)
	if seq64 == 0 {
		return 0, fmt.Errorf("%w: sequence zero", ErrInvalidPacket)
	}
	return seq64, nil
}

func (s *SA) checkReplay(seq uint32) error {
	return s.checkReplay64(uint64(seq))
}

func (s *SA) checkReplay64(seq64 uint64) error {
	if s.ReplayWindowSize == 0 {
		return nil
	}
	window := uint64(s.ReplayWindowSize)
	if window > 64 {
		window = 64
	}
	highest64 := (uint64(s.HighestSequenceHigh) << 32) | uint64(s.HighestSequence)
	if !s.ESN {
		highest64 = uint64(s.HighestSequence)
	}
	if seq64 > highest64 {
		return nil
	}
	diff := highest64 - seq64
	if diff >= window {
		return ErrReplay
	}
	if s.ReplayBitmap&(uint64(1)<<diff) != 0 {
		return ErrReplay
	}
	return nil
}

func (s *SA) acceptSequence(seq uint32) {
	s.acceptSequence64(uint64(seq))
}

func (s *SA) acceptSequence64(seq64 uint64) {
	highest64 := (uint64(s.HighestSequenceHigh) << 32) | uint64(s.HighestSequence)
	if !s.ESN {
		highest64 = uint64(s.HighestSequence)
	}
	if s.ReplayWindowSize == 0 {
		if seq64 > highest64 {
			s.HighestSequence = uint32(seq64)
			if s.ESN {
				s.HighestSequenceHigh = uint32(seq64 >> 32)
			}
		}
		return
	}
	if seq64 > highest64 {
		diff := seq64 - highest64
		if diff >= 64 {
			s.ReplayBitmap = 1
		} else {
			s.ReplayBitmap = (s.ReplayBitmap << diff) | 1
		}
		s.HighestSequence = uint32(seq64)
		if s.ESN {
			s.HighestSequenceHigh = uint32(seq64 >> 32)
		}
		return
	}
	diff := highest64 - seq64
	if diff < 64 {
		s.ReplayBitmap |= uint64(1) << diff
	}
}

func espPlaintext(payload []byte, nextHeader uint8, blockSize int) []byte {
	padLen := (blockSize - ((len(payload) + 2) % blockSize)) % blockSize
	out := make([]byte, 0, len(payload)+padLen+2)
	out = append(out, payload...)
	for i := 1; i <= padLen; i++ {
		out = append(out, byte(i))
	}
	out = append(out, byte(padLen), nextHeader)
	return out
}

func parseESPPlaintext(plain []byte) ([]byte, uint8, error) {
	if len(plain) < 2 {
		return nil, 0, fmt.Errorf("%w: plaintext too short", ErrInvalidPacket)
	}
	padLen := int(plain[len(plain)-2])
	nextHeader := plain[len(plain)-1]
	if padLen+2 > len(plain) {
		return nil, 0, fmt.Errorf("%w: pad length %d", ErrInvalidPacket, padLen)
	}
	paddingStart := len(plain) - 2 - padLen
	for i := 0; i < padLen; i++ {
		if plain[paddingStart+i] != byte(i+1) {
			return nil, 0, fmt.Errorf("%w: bad padding", ErrInvalidPacket)
		}
	}
	return append([]byte(nil), plain[:paddingStart]...), nextHeader, nil
}

func aesCBCEncrypt(key, iv, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(plain)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: invalid AES-CBC input", ErrInvalidPacket)
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out, nil
}

func aesCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: invalid AES-CBC input", ErrInvalidPacket)
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}

func (s *SA) encryptionAlgorithm() EncryptionAlgorithm {
	if s.Encryption == 0 {
		return EncryptionAESCBC
	}
	return s.Encryption
}

func validAESGCMKeyLength(n int) bool {
	switch n {
	case 16 + aesGCMSaltLength, 24 + aesGCMSaltLength, 32 + aesGCMSaltLength:
		return true
	default:
		return false
	}
}

func blockSizeForChildProfile(profile ikev2.ESPKeyProfile) int {
	if EncryptionAlgorithm(profile.EncryptionID) == EncryptionAESGCM_16 {
		return aesGCMPaddingAlignment
	}
	return aes.BlockSize
}

func icvLengthForChildProfile(profile ikev2.ESPKeyProfile) int {
	if EncryptionAlgorithm(profile.EncryptionID) == EncryptionAESGCM_16 {
		return aesGCMICVLength
	}
	return integrityICVLength(IntegrityAlgorithm(profile.IntegrityID))
}

func integrityICVLength(integ IntegrityAlgorithm) int {
	switch integ {
	case IntegrityHMACSHA1_96:
		return 12
	case IntegrityHMACSHA2_256_128:
		return 16
	case IntegrityHMACSHA2_384_192:
		return 24
	case IntegrityHMACSHA2_512_256:
		return 32
	default:
		return 0
	}
}

func spiFromBytes(spi []byte) (uint32, error) {
	if len(spi) != 4 {
		return 0, fmt.Errorf("%w: spi length %d", ErrInvalidSA, len(spi))
	}
	v := binary.BigEndian.Uint32(spi)
	if v == 0 {
		return 0, fmt.Errorf("%w: spi is zero", ErrInvalidSA)
	}
	return v, nil
}
