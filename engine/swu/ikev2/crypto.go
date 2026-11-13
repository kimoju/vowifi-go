package ikev2

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"fmt"
)

var ErrUnsupportedPRF = errors.New("unsupported ikev2 prf")

func PRF(hash crypto.Hash, key, data []byte) ([]byte, error) {
	if hash == 0 || !hash.Available() {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedPRF, hash)
	}
	mac := hmac.New(hash.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil), nil
}

func PRFPlus(hash crypto.Hash, key, seed []byte, length int) ([]byte, error) {
	if length < 0 {
		return nil, fmt.Errorf("%w: negative length", ErrInvalidLength)
	}
	if hash == 0 || !hash.Available() {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedPRF, hash)
	}
	if length == 0 {
		return nil, nil
	}
	if length > 255*hash.Size() {
		return nil, fmt.Errorf("%w: prf+ length %d", ErrInvalidLength, length)
	}
	var out []byte
	var previous []byte
	for counter := byte(1); len(out) < length; counter++ {
		input := make([]byte, 0, len(previous)+len(seed)+1)
		input = append(input, previous...)
		input = append(input, seed...)
		input = append(input, counter)
		block, err := PRF(hash, key, input)
		if err != nil {
			return nil, err
		}
		out = append(out, block...)
		previous = block
	}
	return out[:length], nil
}

func SKEYSEED(hash crypto.Hash, nonceI, nonceR, sharedSecret []byte) ([]byte, error) {
	key := make([]byte, 0, len(nonceI)+len(nonceR))
	key = append(key, nonceI...)
	key = append(key, nonceR...)
	return PRF(hash, key, sharedSecret)
}

// RekeySKEYSEED computes SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr) per
// RFC 7296 §2.18 using the old IKE SA's PRF and SK_d.
func RekeySKEYSEED(oldPRF crypto.Hash, oldSKD, sharedSecret, nonceI, nonceR []byte) ([]byte, error) {
	data := make([]byte, 0, len(sharedSecret)+len(nonceI)+len(nonceR))
	data = append(data, sharedSecret...)
	data = append(data, nonceI...)
	data = append(data, nonceR...)
	return PRF(oldPRF, oldSKD, data)
}

func DeriveIKESAKeyMaterial(hash crypto.Hash, skeyseed, nonceI, nonceR []byte, spiI, spiR uint64, length int) ([]byte, error) {
	seed := make([]byte, 0, len(nonceI)+len(nonceR)+16)
	seed = append(seed, nonceI...)
	seed = append(seed, nonceR...)
	seed = appendUint64(seed, spiI)
	seed = appendUint64(seed, spiR)
	return PRFPlus(hash, skeyseed, seed, length)
}
