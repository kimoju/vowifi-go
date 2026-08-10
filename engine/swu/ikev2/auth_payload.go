package ikev2

import (
	"crypto/hmac"
	"errors"
	"fmt"
)

const AuthMethodSharedKeyMIC uint8 = 2

var ErrInvalidAuthenticationPayload = errors.New("invalid ikev2 authentication payload")

type Authentication struct {
	Method uint8
	Data   []byte
}

func AuthenticationPayload(method uint8, data []byte) (Payload, error) {
	if method == 0 || len(data) == 0 {
		return Payload{}, ErrInvalidAuthenticationPayload
	}
	body := make([]byte, 4, 4+len(data))
	body[0] = method
	body = append(body, data...)
	return Payload{Type: PayloadAUTH, Body: body}, nil
}

func ParseAuthentication(data []byte) (Authentication, error) {
	if len(data) < 5 || data[0] == 0 {
		return Authentication{}, ErrInvalidAuthenticationPayload
	}
	return Authentication{Method: data[0], Data: append([]byte(nil), data[4:]...)}, nil
}

func eapSharedKeyAUTH(init InitResult, keys IKEKeys, identity Identity, msk []byte, initiator bool) ([]byte, error) {
	if len(msk) == 0 {
		return nil, fmt.Errorf("%w: EAP MSK is empty", ErrInvalidAuthenticationPayload)
	}
	idBody, err := identity.MarshalBinary()
	if err != nil {
		return nil, err
	}
	prfKey := keys.SKPi
	message := init.RequestBytes
	nonce := init.NonceR
	if !initiator {
		prfKey = keys.SKPr
		message = init.ResponseBytes
		nonce = init.NonceI
	}
	macID, err := PRF(keys.Profile.PRF, prfKey, idBody)
	if err != nil {
		return nil, err
	}
	signedOctets := make([]byte, 0, len(message)+len(nonce)+len(macID))
	signedOctets = append(signedOctets, message...)
	signedOctets = append(signedOctets, nonce...)
	signedOctets = append(signedOctets, macID...)
	sharedKey, err := PRF(keys.Profile.PRF, msk, []byte("Key Pad for IKEv2"))
	if err != nil {
		return nil, err
	}
	return PRF(keys.Profile.PRF, sharedKey, signedOctets)
}

func verifyEAPSharedKeyAUTH(init InitResult, keys IKEKeys, identity Identity, msk []byte, payload Payload, initiator bool) error {
	if payload.Type != PayloadAUTH {
		return fmt.Errorf("%w: payload type %d", ErrInvalidAuthenticationPayload, payload.Type)
	}
	auth, err := ParseAuthentication(payload.Body)
	if err != nil {
		return err
	}
	if auth.Method != AuthMethodSharedKeyMIC {
		return fmt.Errorf("%w: method %d", ErrInvalidAuthenticationPayload, auth.Method)
	}
	expected, err := eapSharedKeyAUTH(init, keys, identity, msk, initiator)
	if err != nil {
		return err
	}
	if !hmac.Equal(auth.Data, expected) {
		return fmt.Errorf("%w: AUTH verification failed", ErrInvalidAuthenticationPayload)
	}
	return nil
}
