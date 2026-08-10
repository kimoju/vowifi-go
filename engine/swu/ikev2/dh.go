package ikev2

import (
	"crypto/ecdh"
	"fmt"
	"io"
	"math/big"
	"strings"
)

const modpPrivateExponentBytes = 32

// RFC 3526, section 3: 2048-bit MODP group (group 14).
const modp2048PrimeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C" +
	"9DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

type dhKeyExchange struct {
	public []byte
	shared func([]byte) ([]byte, error)
}

func newDHKeyExchange(group uint16, rawPrivate []byte, random io.Reader) (dhKeyExchange, error) {
	switch group {
	case DHGroupCurve25519:
		priv, err := x25519PrivateKey(rawPrivate, random)
		if err != nil {
			return dhKeyExchange{}, err
		}
		return dhKeyExchange{
			public: priv.PublicKey().Bytes(),
			shared: func(peer []byte) ([]byte, error) {
				pub, err := ecdh.X25519().NewPublicKey(peer)
				if err != nil {
					return nil, fmt.Errorf("%w: responder KE: %w", ErrInvalidInitResponse, err)
				}
				secret, err := priv.ECDH(pub)
				if err != nil {
					return nil, fmt.Errorf("%w: ECDH: %w", ErrInvalidInitResponse, err)
				}
				return secret, nil
			},
		}, nil
	case DHGroup2048BitMODP:
		return newMODPKeyExchange(group, rawPrivate, random)
	default:
		return dhKeyExchange{}, fmt.Errorf("%w: unsupported DH group %d", ErrInvalidInitConfig, group)
	}
}

func newMODPKeyExchange(group uint16, rawPrivate []byte, random io.Reader) (dhKeyExchange, error) {
	prime, size, err := modpGroup(group)
	if err != nil {
		return dhKeyExchange{}, err
	}
	privateBytes := append([]byte(nil), rawPrivate...)
	if len(privateBytes) == 0 {
		privateBytes, err = randomBytes(random, modpPrivateExponentBytes)
		if err != nil {
			return dhKeyExchange{}, err
		}
	}

	// Map the random exponent into [2, p-2]. A 256-bit exponent provides
	// 128-bit security for the 2048-bit MODP group while keeping computation bounded.
	private := new(big.Int).SetBytes(privateBytes)
	upper := new(big.Int).Sub(prime, big.NewInt(3))
	private.Mod(private, upper)
	private.Add(private, big.NewInt(2))
	public := new(big.Int).Exp(big.NewInt(2), private, prime)
	publicBytes := leftPadBigInt(public, size)

	return dhKeyExchange{
		public: publicBytes,
		shared: func(peer []byte) ([]byte, error) {
			if len(peer) == 0 || len(peer) > size {
				return nil, fmt.Errorf("%w: invalid MODP peer key length %d", ErrInvalidInitResponse, len(peer))
			}
			peerPublic := new(big.Int).SetBytes(peer)
			maxPeer := new(big.Int).Sub(prime, big.NewInt(2))
			if peerPublic.Cmp(big.NewInt(2)) < 0 || peerPublic.Cmp(maxPeer) > 0 {
				return nil, fmt.Errorf("%w: MODP peer key outside valid range", ErrInvalidInitResponse)
			}
			secret := new(big.Int).Exp(peerPublic, private, prime)
			return leftPadBigInt(secret, size), nil
		},
	}, nil
}

func modpGroup(group uint16) (*big.Int, int, error) {
	if group != DHGroup2048BitMODP {
		return nil, 0, fmt.Errorf("%w: unsupported MODP group %d", ErrInvalidInitConfig, group)
	}
	prime, ok := new(big.Int).SetString(strings.ReplaceAll(modp2048PrimeHex, " ", ""), 16)
	if !ok {
		return nil, 0, fmt.Errorf("%w: invalid MODP prime", ErrInvalidInitConfig)
	}
	return prime, (prime.BitLen() + 7) / 8, nil
}

func leftPadBigInt(value *big.Int, size int) []byte {
	out := make([]byte, size)
	value.FillBytes(out)
	return out
}

func dhGroupFromSA(sa SecurityAssociation) (uint16, error) {
	for _, proposal := range sa.Proposals {
		for _, transform := range proposal.Transforms {
			if transform.Type == TransformDHRGroup {
				return transform.ID, nil
			}
		}
	}
	return 0, fmt.Errorf("%w: IKE proposal missing DH group", ErrInvalidInitConfig)
}
