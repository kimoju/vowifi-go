package ikev2

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var ErrInvalidSKPayload = errors.New("invalid ikev2 sk payload")

func ProtectMessage(header Header, keys IKEKeys, fromInitiator bool, inner []Payload, iv []byte) (Message, []byte, error) {
	if len(inner) == 0 && header.ExchangeType != ExchangeINFORMATIONAL {
		return Message{}, nil, fmt.Errorf("%w: no inner payloads", ErrInvalidSKPayload)
	}
	if err := validateKeySet(keys); err != nil {
		return Message{}, nil, err
	}
	firstInner, innerBytes, err := MarshalPayloads(inner)
	if err != nil {
		return Message{}, nil, err
	}
	switch keys.Profile.EncryptionID {
	case ENCR_AES_CBC:
		return protectMessageAESCBC(header, keys, fromInitiator, firstInner, innerBytes, iv)
	case ENCR_AES_GCM_16:
		return protectMessageAESGCM(header, keys, fromInitiator, firstInner, innerBytes, iv)
	default:
		return Message{}, nil, fmt.Errorf("%w: ENCR %d", ErrUnsupportedTransform, keys.Profile.EncryptionID)
	}
}

func protectMessageAESCBC(header Header, keys IKEKeys, fromInitiator bool, firstInner uint8, innerBytes, iv []byte) (Message, []byte, error) {
	blockSize := keys.Profile.EncryptionBlockSize
	var err error
	if len(iv) == 0 {
		iv, err = randomBytes(rand.Reader, blockSize)
		if err != nil {
			return Message{}, nil, err
		}
	}
	if len(iv) != blockSize {
		return Message{}, nil, fmt.Errorf("%w: IV length %d != %d", ErrInvalidSKPayload, len(iv), blockSize)
	}
	plain := padIKEPlaintext(innerBytes, blockSize)
	encrKey, integKey := keysForDirection(keys, fromInitiator)
	ciphertext, err := encryptAESCBC(encrKey, iv, plain)
	if err != nil {
		return Message{}, nil, err
	}
	bodyNoICV := make([]byte, 0, len(iv)+len(ciphertext))
	bodyNoICV = append(bodyNoICV, iv...)
	bodyNoICV = append(bodyNoICV, ciphertext...)
	icvLen := keys.Profile.IntegrityChecksumLength
	body := append(append([]byte(nil), bodyNoICV...), make([]byte, icvLen)...)
	msg := Message{
		Header: header,
		Payloads: []Payload{{
			Type:        PayloadSK,
			NextPayload: firstInner,
			Body:        body,
		}},
	}
	rawWithZeros, err := msg.MarshalBinary()
	if err != nil {
		return Message{}, nil, err
	}
	checksum, err := IntegrityChecksum(keys.Profile, integKey, rawWithZeros[:len(rawWithZeros)-icvLen])
	if err != nil {
		return Message{}, nil, err
	}
	copy(msg.Payloads[0].Body[len(bodyNoICV):], checksum)
	raw := append([]byte(nil), rawWithZeros...)
	copy(raw[len(raw)-icvLen:], checksum)
	return msg, raw, nil
}

func protectMessageAESGCM(header Header, keys IKEKeys, fromInitiator bool, firstInner uint8, innerBytes, iv []byte) (Message, []byte, error) {
	ivLen := keys.Profile.EncryptionBlockSize
	if len(iv) == 0 {
		iv = keys.nextAESGCMExplicitIV(fromInitiator)
	}
	if len(iv) != ivLen {
		return Message{}, nil, fmt.Errorf("%w: IV length %d != %d", ErrInvalidSKPayload, len(iv), ivLen)
	}
	encrKey, _ := keysForDirection(keys, fromInitiator)
	aead, salt, err := aesGCMIKEAEAD(encrKey, keys.Profile.IntegrityChecksumLength)
	if err != nil {
		return Message{}, nil, err
	}
	plain := padIKEPlaintext(innerBytes, 1)
	body := make([]byte, 0, len(iv)+len(plain)+aead.Overhead())
	body = append(body, iv...)
	body = append(body, make([]byte, len(plain)+aead.Overhead())...)
	msg := Message{
		Header: header,
		Payloads: []Payload{{
			Type:        PayloadSK,
			NextPayload: firstInner,
			Body:        body,
		}},
	}
	rawWithZeros, err := msg.MarshalBinary()
	if err != nil {
		return Message{}, nil, err
	}
	aad, err := ikeSKAssociatedData(rawWithZeros)
	if err != nil {
		return Message{}, nil, err
	}
	sealed := aead.Seal(nil, aesGCMIKENonce(salt, iv), plain, aad)
	copy(msg.Payloads[0].Body[len(iv):], sealed)
	raw := append([]byte(nil), rawWithZeros...)
	copy(raw[HeaderLength+4:], msg.Payloads[0].Body)
	return msg, raw, nil
}

func UnprotectMessage(raw []byte, keys IKEKeys, fromInitiator bool) (Message, []Payload, error) {
	if err := validateKeySet(keys); err != nil {
		return Message{}, nil, err
	}
	msg, err := ParseMessage(raw)
	if err != nil {
		return Message{}, nil, err
	}
	if len(msg.Payloads) != 1 || msg.Payloads[0].Type != PayloadSK {
		return Message{}, nil, fmt.Errorf("%w: expected single SK payload", ErrInvalidSKPayload)
	}
	switch keys.Profile.EncryptionID {
	case ENCR_AES_CBC:
		return unprotectMessageAESCBC(raw, msg, keys, fromInitiator)
	case ENCR_AES_GCM_16:
		return unprotectMessageAESGCM(raw, msg, keys, fromInitiator)
	default:
		return Message{}, nil, fmt.Errorf("%w: ENCR %d", ErrUnsupportedTransform, keys.Profile.EncryptionID)
	}
}

func unprotectMessageAESCBC(raw []byte, msg Message, keys IKEKeys, fromInitiator bool) (Message, []Payload, error) {
	sk := msg.Payloads[0]
	blockSize := keys.Profile.EncryptionBlockSize
	icvLen := keys.Profile.IntegrityChecksumLength
	if len(sk.Body) < blockSize+icvLen || len(raw) < icvLen {
		return Message{}, nil, fmt.Errorf("%w: body too short", ErrInvalidSKPayload)
	}
	bodyNoICV := sk.Body[:len(sk.Body)-icvLen]
	gotICV := sk.Body[len(sk.Body)-icvLen:]
	encrKey, integKey := keysForDirection(keys, fromInitiator)
	expected, err := IntegrityChecksum(keys.Profile, integKey, raw[:len(raw)-icvLen])
	if err != nil {
		return Message{}, nil, err
	}
	if !hmac.Equal(gotICV, expected) {
		return Message{}, nil, fmt.Errorf("%w: integrity check failed", ErrInvalidSKPayload)
	}
	iv := bodyNoICV[:blockSize]
	ciphertext := bodyNoICV[blockSize:]
	plain, err := decryptAESCBC(encrKey, iv, ciphertext)
	if err != nil {
		return Message{}, nil, err
	}
	innerBytes, err := unpadIKEPlaintext(plain)
	if err != nil {
		return Message{}, nil, err
	}
	inner, err := ParsePayloads(sk.NextPayload, innerBytes)
	if err != nil {
		return Message{}, nil, err
	}
	return msg, inner, nil
}

func unprotectMessageAESGCM(raw []byte, msg Message, keys IKEKeys, fromInitiator bool) (Message, []Payload, error) {
	sk := msg.Payloads[0]
	ivLen := keys.Profile.EncryptionBlockSize
	tagLen := keys.Profile.IntegrityChecksumLength
	if len(sk.Body) < ivLen+tagLen+1 {
		return Message{}, nil, fmt.Errorf("%w: body too short", ErrInvalidSKPayload)
	}
	iv := sk.Body[:ivLen]
	ciphertext := sk.Body[ivLen:]
	encrKey, _ := keysForDirection(keys, fromInitiator)
	aead, salt, err := aesGCMIKEAEAD(encrKey, tagLen)
	if err != nil {
		return Message{}, nil, err
	}
	aad, err := ikeSKAssociatedData(raw)
	if err != nil {
		return Message{}, nil, err
	}
	plain, err := aead.Open(nil, aesGCMIKENonce(salt, iv), ciphertext, aad)
	if err != nil {
		return Message{}, nil, fmt.Errorf("%w: integrity check failed", ErrInvalidSKPayload)
	}
	innerBytes, err := unpadIKEPlaintext(plain)
	if err != nil {
		return Message{}, nil, err
	}
	inner, err := ParsePayloads(sk.NextPayload, innerBytes)
	if err != nil {
		return Message{}, nil, err
	}
	return msg, inner, nil
}

func IntegrityChecksum(profile KeyMaterialProfile, key, data []byte) ([]byte, error) {
	hash, err := integrityHash(profile.IntegrityID)
	if err != nil {
		return nil, err
	}
	if !hash.Available() {
		return nil, fmt.Errorf("%w: integrity hash %v", ErrUnsupportedPRF, hash)
	}
	mac := hmac.New(hash.New, key)
	_, _ = mac.Write(data)
	sum := mac.Sum(nil)
	if profile.IntegrityChecksumLength <= 0 || profile.IntegrityChecksumLength > len(sum) {
		return nil, fmt.Errorf("%w: checksum length %d", ErrInvalidSKPayload, profile.IntegrityChecksumLength)
	}
	return append([]byte(nil), sum[:profile.IntegrityChecksumLength]...), nil
}

func RandomIV(random io.Reader, profile KeyMaterialProfile) ([]byte, error) {
	if profile.EncryptionID == ENCR_AES_GCM_16 {
		return fallbackAESGCMIVGenerator().next(true), nil
	}
	if random == nil {
		random = rand.Reader
	}
	return randomBytes(random, profile.EncryptionBlockSize)
}

// ProtectFragmentedMessages splits marshaled inner payloads into plaintext
// chunks and protects each chunk as an independent RFC 7383 SKF message whose
// outer wire length does not exceed maxPacketSize.
func ProtectFragmentedMessages(header Header, keys IKEKeys, fromInitiator bool, inner []Payload, maxPacketSize int) ([]Message, [][]byte, error) {
	if len(inner) == 0 && header.ExchangeType != ExchangeINFORMATIONAL {
		return nil, nil, fmt.Errorf("%w: no inner payloads", ErrInvalidSKPayload)
	}
	if err := validateKeySet(keys); err != nil {
		return nil, nil, err
	}
	if maxPacketSize <= 0 {
		maxPacketSize = DefaultIKEFragmentMTU
	}
	firstInner, innerBytes, err := MarshalPayloads(inner)
	if err != nil {
		return nil, nil, err
	}
	maxChunk, err := maxSKFPlaintextChunk(keys.Profile, maxPacketSize)
	if err != nil {
		return nil, nil, err
	}
	var chunks [][]byte
	if len(innerBytes) == 0 {
		chunks = [][]byte{nil}
	} else {
		for rest := innerBytes; len(rest) > 0; {
			n := maxChunk
			if n > len(rest) {
				n = len(rest)
			}
			chunks = append(chunks, rest[:n])
			rest = rest[n:]
		}
	}
	if len(chunks) > MaxEncryptedFragments {
		return nil, nil, fmt.Errorf("%w: fragment count %d exceeds maximum %d", ErrInvalidEncryptedFragment, len(chunks), MaxEncryptedFragments)
	}
	total := uint16(len(chunks))
	msgs := make([]Message, 0, len(chunks))
	raws := make([][]byte, 0, len(chunks))
	for i, chunk := range chunks {
		fragNum := uint16(i + 1)
		nextPayload := PayloadNoNext
		if fragNum == 1 {
			nextPayload = firstInner
		}
		msg, raw, err := protectSingleSKFFragment(header, keys, fromInitiator, nextPayload, fragNum, total, chunk)
		if err != nil {
			return nil, nil, err
		}
		msgs = append(msgs, msg)
		raws = append(raws, raw)
	}
	return msgs, raws, nil
}

func maxSKFPlaintextChunk(profile KeyMaterialProfile, maxPacketSize int) (int, error) {
	// Outer IKE Header (28) + SKF Generic Header (4) + FragNum/Total (4) = 36 bytes.
	const fixedHeaders = HeaderLength + 4 + encryptedFragmentBodyHeaderLength
	switch profile.EncryptionID {
	case ENCR_AES_CBC:
		blockSize := profile.EncryptionBlockSize
		overhead := fixedHeaders + blockSize + profile.IntegrityChecksumLength
		availCipher := maxPacketSize - overhead
		blocks := availCipher / blockSize
		if blocks < 1 {
			return 0, fmt.Errorf("%w: max packet size %d too small for AES-CBC SKF", ErrInvalidEncryptedFragment, maxPacketSize)
		}
		return blocks*blockSize - 1, nil
	case ENCR_AES_GCM_16:
		overhead := fixedHeaders + profile.EncryptionBlockSize + 1 + profile.IntegrityChecksumLength
		maxChunk := maxPacketSize - overhead
		if maxChunk < 1 {
			return 0, fmt.Errorf("%w: max packet size %d too small for AES-GCM SKF", ErrInvalidEncryptedFragment, maxPacketSize)
		}
		return maxChunk, nil
	default:
		return 0, fmt.Errorf("%w: ENCR %d", ErrUnsupportedTransform, profile.EncryptionID)
	}
}

func protectSingleSKFFragment(header Header, keys IKEKeys, fromInitiator bool, nextPayload uint8, fragNum, totalFrags uint16, chunk []byte) (Message, []byte, error) {
	switch keys.Profile.EncryptionID {
	case ENCR_AES_CBC:
		blockSize := keys.Profile.EncryptionBlockSize
		iv, err := randomBytes(rand.Reader, blockSize)
		if err != nil {
			return Message{}, nil, err
		}
		plain := padIKEPlaintext(chunk, blockSize)
		encrKey, integKey := keysForDirection(keys, fromInitiator)
		ciphertext, err := encryptAESCBC(encrKey, iv, plain)
		if err != nil {
			return Message{}, nil, err
		}
		icvLen := keys.Profile.IntegrityChecksumLength
		encContent := make([]byte, 0, len(iv)+len(ciphertext)+icvLen)
		encContent = append(encContent, iv...)
		encContent = append(encContent, ciphertext...)
		encContent = append(encContent, make([]byte, icvLen)...)
		skfPayload, err := EncryptedFragmentPayload(nextPayload, EncryptedFragment{
			FragmentNumber: fragNum,
			TotalFragments: totalFrags,
			EncryptedData:  encContent,
		})
		if err != nil {
			return Message{}, nil, err
		}
		msg := Message{Header: header, Payloads: []Payload{skfPayload}}
		rawWithZeros, err := msg.MarshalBinary()
		if err != nil {
			return Message{}, nil, err
		}
		checksum, err := IntegrityChecksum(keys.Profile, integKey, rawWithZeros[:len(rawWithZeros)-icvLen])
		if err != nil {
			return Message{}, nil, err
		}
		copy(msg.Payloads[0].Body[len(msg.Payloads[0].Body)-icvLen:], checksum)
		raw := append([]byte(nil), rawWithZeros...)
		copy(raw[len(raw)-icvLen:], checksum)
		return msg, raw, nil
	case ENCR_AES_GCM_16:
		iv := keys.nextAESGCMExplicitIV(fromInitiator)
		encrKey, _ := keysForDirection(keys, fromInitiator)
		aead, salt, err := aesGCMIKEAEAD(encrKey, keys.Profile.IntegrityChecksumLength)
		if err != nil {
			return Message{}, nil, err
		}
		plain := padIKEPlaintext(chunk, 1)
		encContent := make([]byte, 0, len(iv)+len(plain)+aead.Overhead())
		encContent = append(encContent, iv...)
		encContent = append(encContent, make([]byte, len(plain)+aead.Overhead())...)
		skfPayload, err := EncryptedFragmentPayload(nextPayload, EncryptedFragment{
			FragmentNumber: fragNum,
			TotalFragments: totalFrags,
			EncryptedData:  encContent,
		})
		if err != nil {
			return Message{}, nil, err
		}
		msg := Message{Header: header, Payloads: []Payload{skfPayload}}
		rawWithZeros, err := msg.MarshalBinary()
		if err != nil {
			return Message{}, nil, err
		}
		aad, err := ikeSKFAssociatedData(rawWithZeros)
		if err != nil {
			return Message{}, nil, err
		}
		sealed := aead.Seal(nil, aesGCMIKENonce(salt, iv), plain, aad)
		copy(msg.Payloads[0].Body[encryptedFragmentBodyHeaderLength+len(iv):], sealed)
		raw := append([]byte(nil), rawWithZeros...)
		copy(raw[HeaderLength+4:], msg.Payloads[0].Body)
		return msg, raw, nil
	default:
		return Message{}, nil, fmt.Errorf("%w: ENCR %d", ErrUnsupportedTransform, keys.Profile.EncryptionID)
	}
}

// UnprotectFragment verifies the outer ICV / AEAD authentication tag of an
// RFC 7383 SKF message BEFORE returning any fragment metadata or plaintext
// chunk for reassembly.
func UnprotectFragment(raw []byte, keys IKEKeys, fromInitiator bool) (Message, uint8, uint16, uint16, []byte, error) {
	if err := validateKeySet(keys); err != nil {
		return Message{}, 0, 0, 0, nil, err
	}
	msg, err := ParseMessage(raw)
	if err != nil {
		return Message{}, 0, 0, 0, nil, err
	}
	if len(msg.Payloads) != 1 || msg.Payloads[0].Type != PayloadSKF {
		return Message{}, 0, 0, 0, nil, fmt.Errorf("%w: expected single SKF payload", ErrInvalidSKPayload)
	}
	skf := msg.Payloads[0]
	frag, err := ParseEncryptedFragment(skf.Body)
	if err != nil {
		return Message{}, 0, 0, 0, nil, err
	}
	if frag.FragmentNumber > 1 && skf.NextPayload != PayloadNoNext {
		return Message{}, 0, 0, 0, nil, fmt.Errorf("%w: non-first fragment must have NextPayload 0, got %d", ErrInvalidEncryptedFragment, skf.NextPayload)
	}
	switch keys.Profile.EncryptionID {
	case ENCR_AES_CBC:
		blockSize := keys.Profile.EncryptionBlockSize
		icvLen := keys.Profile.IntegrityChecksumLength
		if len(frag.EncryptedData) < blockSize+icvLen || len(raw) < icvLen {
			return Message{}, 0, 0, 0, nil, fmt.Errorf("%w: SKF body too short", ErrInvalidSKPayload)
		}
		encrKey, integKey := keysForDirection(keys, fromInitiator)
		gotICV := frag.EncryptedData[len(frag.EncryptedData)-icvLen:]
		expected, err := IntegrityChecksum(keys.Profile, integKey, raw[:len(raw)-icvLen])
		if err != nil {
			return Message{}, 0, 0, 0, nil, err
		}
		if !hmac.Equal(gotICV, expected) {
			return Message{}, 0, 0, 0, nil, fmt.Errorf("%w: SKF integrity check failed", ErrInvalidSKPayload)
		}
		iv := frag.EncryptedData[:blockSize]
		ciphertext := frag.EncryptedData[blockSize : len(frag.EncryptedData)-icvLen]
		plain, err := decryptAESCBC(encrKey, iv, ciphertext)
		if err != nil {
			return Message{}, 0, 0, 0, nil, err
		}
		chunk, err := unpadIKEPlaintext(plain)
		if err != nil {
			return Message{}, 0, 0, 0, nil, err
		}
		return msg, skf.NextPayload, frag.FragmentNumber, frag.TotalFragments, chunk, nil
	case ENCR_AES_GCM_16:
		ivLen := keys.Profile.EncryptionBlockSize
		tagLen := keys.Profile.IntegrityChecksumLength
		if len(frag.EncryptedData) < ivLen+tagLen+1 {
			return Message{}, 0, 0, 0, nil, fmt.Errorf("%w: SKF body too short", ErrInvalidSKPayload)
		}
		iv := frag.EncryptedData[:ivLen]
		ciphertext := frag.EncryptedData[ivLen:]
		encrKey, _ := keysForDirection(keys, fromInitiator)
		aead, salt, err := aesGCMIKEAEAD(encrKey, tagLen)
		if err != nil {
			return Message{}, 0, 0, 0, nil, err
		}
		aad, err := ikeSKFAssociatedData(raw)
		if err != nil {
			return Message{}, 0, 0, 0, nil, err
		}
		plain, err := aead.Open(nil, aesGCMIKENonce(salt, iv), ciphertext, aad)
		if err != nil {
			return Message{}, 0, 0, 0, nil, fmt.Errorf("%w: SKF integrity check failed", ErrInvalidSKPayload)
		}
		chunk, err := unpadIKEPlaintext(plain)
		if err != nil {
			return Message{}, 0, 0, 0, nil, err
		}
		return msg, skf.NextPayload, frag.FragmentNumber, frag.TotalFragments, chunk, nil
	default:
		return Message{}, 0, 0, 0, nil, fmt.Errorf("%w: ENCR %d", ErrUnsupportedTransform, keys.Profile.EncryptionID)
	}
}

func ikeSKFAssociatedData(raw []byte) ([]byte, error) {
	if len(raw) < HeaderLength+4+encryptedFragmentBodyHeaderLength {
		return nil, fmt.Errorf("%w: SKF associated data too short", ErrInvalidSKPayload)
	}
	return raw[:HeaderLength+4+encryptedFragmentBodyHeaderLength], nil
}

type protectedExchangeConfig struct {
	Transport              InitTransport
	Header                 Header
	Keys                   IKEKeys
	FromInitiator          bool
	Inner                  []Payload
	IV                     []byte
	FragmentationSupported bool
	MaxFragmentSize        int
}

func exchangeProtectedIKE(ctx context.Context, cfg protectedExchangeConfig) (reqBytes []byte, respBytes []byte, respMsg Message, respInner []Payload, err error) {
	_, singleRaw, err := ProtectMessage(cfg.Header, cfg.Keys, cfg.FromInitiator, cfg.Inner, cfg.IV)
	if err != nil {
		return nil, nil, Message{}, nil, err
	}
	maxSize := cfg.MaxFragmentSize
	if maxSize <= 0 {
		maxSize = DefaultIKEFragmentMTU
	}
	reqPackets := [][]byte{singleRaw}
	reqBytes = singleRaw
	if cfg.FragmentationSupported && len(singleRaw) > maxSize && len(cfg.IV) == 0 {
		_, frags, err := ProtectFragmentedMessages(cfg.Header, cfg.Keys, cfg.FromInitiator, cfg.Inner, maxSize)
		if err != nil {
			return nil, nil, Message{}, nil, err
		}
		reqPackets = frags
		reqBytes = frags[0]
	}

	expectedRespFromInitiator := !cfg.FromInitiator
	if fragTransport, ok := cfg.Transport.(FragmentInitTransport); ok {
		var assembler EncryptedFragmentAssembler
		err := fragTransport.ExchangeIKEFragments(ctx, reqPackets, func(raw []byte) (bool, error) {
			if len(raw) >= HeaderLength && raw[16] == PayloadSKF {
				msg, inner, complete, fErr := assembler.AddProtectedFragment(raw, cfg.Keys, expectedRespFromInitiator)
				if fErr != nil {
					return false, fErr
				}
				if !complete {
					return false, nil
				}
				respBytes = append([]byte(nil), raw...)
				respMsg = msg
				respInner = inner
				return true, nil
			}
			msg, inner, uErr := UnprotectMessage(raw, cfg.Keys, expectedRespFromInitiator)
			if uErr != nil {
				return true, uErr
			}
			respBytes = append([]byte(nil), raw...)
			respMsg = msg
			respInner = inner
			return true, nil
		})
		if err != nil {
			return reqBytes, nil, Message{}, nil, err
		}
		return reqBytes, respBytes, respMsg, respInner, nil
	}

	var lastResp []byte
	for i, pkt := range reqPackets {
		r, exErr := cfg.Transport.ExchangeIKE(ctx, pkt)
		if exErr != nil {
			return reqBytes, nil, Message{}, nil, exErr
		}
		if len(r) > 0 || i == len(reqPackets)-1 {
			lastResp = r
		}
	}
	if len(lastResp) >= HeaderLength && lastResp[16] == PayloadSKF {
		var assembler EncryptedFragmentAssembler
		raw := lastResp
		for step := 0; step < MaxEncryptedFragments*2; step++ {
			msg, inner, complete, fErr := assembler.AddProtectedFragment(raw, cfg.Keys, expectedRespFromInitiator)
			if fErr != nil {
				return reqBytes, nil, Message{}, nil, fErr
			}
			if complete {
				return reqBytes, append([]byte(nil), raw...), msg, inner, nil
			}
			raw, err = cfg.Transport.ExchangeIKE(ctx, nil)
			if err != nil {
				return reqBytes, nil, Message{}, nil, err
			}
		}
		return reqBytes, nil, Message{}, nil, fmt.Errorf("%w: incomplete SKF response", ErrInvalidEncryptedFragment)
	}
	msg, inner, err := UnprotectMessage(lastResp, cfg.Keys, expectedRespFromInitiator)
	if err != nil {
		return reqBytes, nil, Message{}, nil, err
	}
	return reqBytes, append([]byte(nil), lastResp...), msg, inner, nil
}

func validateKeySet(keys IKEKeys) error {
	p := keys.Profile
	switch p.EncryptionID {
	case ENCR_AES_CBC:
		if p.EncryptionBlockSize != aes.BlockSize || p.EncryptionKeyLength <= 0 || p.IntegrityKeyLength <= 0 || p.IntegrityChecksumLength <= 0 {
			return fmt.Errorf("%w: incomplete key profile", ErrInvalidSKPayload)
		}
		if len(keys.SKEi) != p.EncryptionKeyLength || len(keys.SKEr) != p.EncryptionKeyLength ||
			len(keys.SKAi) != p.IntegrityKeyLength || len(keys.SKAr) != p.IntegrityKeyLength {
			return fmt.Errorf("%w: key length mismatch", ErrInvalidSKPayload)
		}
	case ENCR_AES_GCM_16:
		if p.EncryptionBlockSize != aesGCMExplicitIVLength || !validAESGCMIKEKeyLength(p.EncryptionKeyLength) ||
			p.IntegrityID != 0 || p.IntegrityKeyLength != 0 || p.IntegrityChecksumLength != aesGCM16ChecksumLength {
			return fmt.Errorf("%w: incomplete AES-GCM key profile", ErrInvalidSKPayload)
		}
		if len(keys.SKEi) != p.EncryptionKeyLength || len(keys.SKEr) != p.EncryptionKeyLength ||
			len(keys.SKAi) != 0 || len(keys.SKAr) != 0 {
			return fmt.Errorf("%w: key length mismatch", ErrInvalidSKPayload)
		}
	default:
		return fmt.Errorf("%w: ENCR %d", ErrUnsupportedTransform, p.EncryptionID)
	}
	return nil
}

func keysForDirection(keys IKEKeys, fromInitiator bool) (encrKey, integKey []byte) {
	if fromInitiator {
		return keys.SKEi, keys.SKAi
	}
	return keys.SKEr, keys.SKAr
}

func padIKEPlaintext(data []byte, blockSize int) []byte {
	padLen := (blockSize - ((len(data) + 1) % blockSize)) % blockSize
	out := make([]byte, 0, len(data)+padLen+1)
	out = append(out, data...)
	for i := 0; i < padLen; i++ {
		out = append(out, byte(i+1))
	}
	out = append(out, byte(padLen))
	return out
}

func unpadIKEPlaintext(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty plaintext", ErrInvalidSKPayload)
	}
	padLen := int(data[len(data)-1])
	if padLen+1 > len(data) {
		return nil, fmt.Errorf("%w: padding length %d", ErrInvalidSKPayload, padLen)
	}
	return append([]byte(nil), data[:len(data)-padLen-1]...), nil
}

func encryptAESCBC(key, iv, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(plain)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: invalid CBC input", ErrInvalidSKPayload)
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out, nil
}

func decryptAESCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: invalid CBC input", ErrInvalidSKPayload)
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}

func aesGCMIKEAEAD(key []byte, tagLen int) (cipher.AEAD, []byte, error) {
	if !validAESGCMIKEKeyLength(len(key)) {
		return nil, nil, fmt.Errorf("%w: AES-GCM key length %d", ErrInvalidSKPayload, len(key))
	}
	aesKeyLen := len(key) - aesGCMSaltLength
	block, err := aes.NewCipher(key[:aesKeyLen])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCMWithTagSize(block, tagLen)
	if err != nil {
		return nil, nil, err
	}
	return aead, append([]byte(nil), key[aesKeyLen:]...), nil
}

func validAESGCMIKEKeyLength(n int) bool {
	switch n {
	case 16 + aesGCMSaltLength, 24 + aesGCMSaltLength, 32 + aesGCMSaltLength:
		return true
	default:
		return false
	}
}

func aesGCMIKENonce(salt, iv []byte) []byte {
	nonce := make([]byte, 0, len(salt)+len(iv))
	nonce = append(nonce, salt...)
	nonce = append(nonce, iv...)
	return nonce
}

func ikeSKAssociatedData(raw []byte) ([]byte, error) {
	if len(raw) < HeaderLength+4 {
		return nil, fmt.Errorf("%w: associated data too short", ErrInvalidSKPayload)
	}
	return raw[:HeaderLength+4], nil
}

func integrityHash(id uint16) (crypto.Hash, error) {
	switch id {
	case INTEG_HMAC_SHA1_96:
		return crypto.SHA1, nil
	case INTEG_HMAC_SHA2_256_128:
		return crypto.SHA256, nil
	case INTEG_HMAC_SHA2_384_192:
		return crypto.SHA384, nil
	case INTEG_HMAC_SHA2_512_256:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("%w: INTEG %d", ErrUnsupportedTransform, id)
	}
}
