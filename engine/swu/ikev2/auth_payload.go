package ikev2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
)

const (
	AuthMethodRSADigitalSignature uint8 = 1
	AuthMethodSharedKeyMIC        uint8 = 2
	AuthMethodECDSASHA256P256     uint8 = 9
	AuthMethodECDSASHA384P384     uint8 = 10
	AuthMethodECDSASHA512P521     uint8 = 11
	AuthMethodDigitalSignature    uint8 = 14
)

const (
	CertEncodingX509Sig uint8 = 4
)

var (
	ErrInvalidAuthenticationPayload = errors.New("invalid ikev2 authentication payload")
	ErrInvalidCertificatePayload    = errors.New("invalid ikev2 certificate payload")
)

var (
	oidSHA1WithRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidRSASSAPSS               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSHA256WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512         = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519                 = asn1.ObjectIdentifier{1, 3, 101, 112}

	oidHashSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidHashSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidHashSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidHashSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

type Authentication struct {
	Method uint8
	Data   []byte
}

type Certificate struct {
	Encoding uint8
	Data     []byte
}

type rsaPSSParamsASN1 struct {
	Hash         pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MaskGen      pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SaltLength   int                      `asn1:"optional,explicit,tag:2,default:20"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
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

func CertificatePayload(encoding uint8, certDER []byte) (Payload, error) {
	if encoding == 0 || len(certDER) == 0 {
		return Payload{}, ErrInvalidCertificatePayload
	}
	body := make([]byte, 1+len(certDER))
	body[0] = encoding
	copy(body[1:], certDER)
	return Payload{Type: PayloadCERT, Body: body}, nil
}

func ParseCertificate(data []byte) (Certificate, error) {
	if len(data) < 2 || data[0] == 0 {
		return Certificate{}, ErrInvalidCertificatePayload
	}
	return Certificate{Encoding: data[0], Data: append([]byte(nil), data[1:]...)}, nil
}

func CertReqPayload(encoding uint8, authorityData []byte) (Payload, error) {
	if encoding == 0 {
		return Payload{}, ErrInvalidCertificatePayload
	}
	if len(authorityData)%sha1.Size != 0 {
		return Payload{}, fmt.Errorf("%w: CERTREQ authority data length %d is not a multiple of %d", ErrInvalidCertificatePayload, len(authorityData), sha1.Size)
	}
	body := make([]byte, 1+len(authorityData))
	body[0] = encoding
	copy(body[1:], authorityData)
	return Payload{Type: PayloadCERTREQ, Body: body}, nil
}

func CertReqForCAs(caCerts []*x509.Certificate) (Payload, error) {
	auth := make([]byte, 0, len(caCerts)*sha1.Size)
	for _, cert := range caCerts {
		if cert == nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
			continue
		}
		sum := sha1.Sum(cert.RawSubjectPublicKeyInfo)
		auth = append(auth, sum[:]...)
	}
	return CertReqPayload(CertEncodingX509Sig, auth)
}

func ikeSignedOctets(init InitResult, keys IKEKeys, identity Identity, initiator bool) ([]byte, error) {
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
	return signedOctets, nil
}

func eapSharedKeyAUTH(init InitResult, keys IKEKeys, identity Identity, msk []byte, initiator bool) ([]byte, error) {
	if len(msk) == 0 {
		return nil, fmt.Errorf("%w: EAP MSK is empty", ErrInvalidAuthenticationPayload)
	}
	signedOctets, err := ikeSignedOctets(init, keys, identity, initiator)
	if err != nil {
		return nil, err
	}
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

func parseAuthCertificates(payloads []Payload) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, p := range payloads {
		if p.Type != PayloadCERT {
			continue
		}
		certPayload, err := ParseCertificate(p.Body)
		if err != nil {
			return nil, err
		}
		if certPayload.Encoding != CertEncodingX509Sig {
			continue
		}
		parsed, err := x509.ParseCertificate(certPayload.Data)
		if err != nil {
			return nil, fmt.Errorf("%w: parse x509 certificate: %w", ErrInvalidCertificatePayload, err)
		}
		certs = append(certs, parsed)
	}
	return certs, nil
}

func identitiesEqual(a, b Identity) bool {
	if a.Type != b.Type {
		return false
	}
	switch a.Type {
	case IDFQDN, IDRFC822Addr:
		left := strings.TrimSuffix(strings.TrimSpace(string(a.Data)), ".")
		right := strings.TrimSuffix(strings.TrimSpace(string(b.Data)), ".")
		return strings.EqualFold(left, right)
	case IDIPv4Addr:
		ipA, ipB := net.IP(a.Data).To4(), net.IP(b.Data).To4()
		if ipA != nil && ipB != nil {
			return ipA.Equal(ipB)
		}
		return bytes.Equal(a.Data, b.Data)
	case IDIPv6Addr:
		ipA, ipB := net.IP(a.Data).To16(), net.IP(b.Data).To16()
		if ipA != nil && ipB != nil && net.IP(a.Data).To4() == nil && net.IP(b.Data).To4() == nil {
			return ipA.Equal(ipB)
		}
		return bytes.Equal(a.Data, b.Data)
	default:
		return bytes.Equal(a.Data, b.Data)
	}
}

func verifyCertificateMatchesIdentity(cert *x509.Certificate, id Identity) error {
	if cert == nil {
		return fmt.Errorf("%w: certificate is nil", ErrInvalidCertificatePayload)
	}
	switch id.Type {
	case IDFQDN:
		fqdn := strings.TrimSuffix(strings.TrimSpace(string(id.Data)), ".")
		if fqdn == "" {
			return fmt.Errorf("%w: empty FQDN responder identity", ErrInvalidIdentity)
		}
		if err := cert.VerifyHostname(fqdn); err == nil {
			return nil
		}
		cn := strings.TrimSuffix(strings.TrimSpace(cert.Subject.CommonName), ".")
		if len(cert.DNSNames) == 0 && cn != "" && strings.EqualFold(cn, fqdn) {
			return nil
		}
		return fmt.Errorf("%w: certificate does not match FQDN %q", ErrInvalidCertificatePayload, fqdn)
	case IDIPv4Addr, IDIPv6Addr:
		ip := net.IP(id.Data)
		if id.Type == IDIPv4Addr {
			ip = ip.To4()
		} else if ip.To4() != nil {
			ip = nil
		} else {
			ip = ip.To16()
		}
		if ip == nil {
			return fmt.Errorf("%w: invalid IP responder identity", ErrInvalidIdentity)
		}
		for _, candidate := range cert.IPAddresses {
			if candidate.Equal(ip) {
				return nil
			}
		}
		if err := cert.VerifyHostname(ip.String()); err == nil {
			return nil
		}
		return fmt.Errorf("%w: certificate does not match IP %s", ErrInvalidCertificatePayload, ip)
	case IDRFC822Addr:
		email := strings.TrimSpace(string(id.Data))
		if email == "" {
			return fmt.Errorf("%w: empty RFC822 responder identity", ErrInvalidIdentity)
		}
		for _, candidate := range cert.EmailAddresses {
			if strings.EqualFold(strings.TrimSpace(candidate), email) {
				return nil
			}
		}
		if len(cert.EmailAddresses) == 0 && strings.EqualFold(strings.TrimSpace(cert.Subject.CommonName), email) {
			return nil
		}
		return fmt.Errorf("%w: certificate does not match RFC822 identity %q", ErrInvalidCertificatePayload, email)
	case IDDERASN1DN:
		if bytes.Equal(cert.RawSubject, id.Data) {
			return nil
		}
		var wantRDN, gotRDN pkix.RDNSequence
		if _, err1 := asn1.Unmarshal(id.Data, &wantRDN); err1 == nil {
			if _, err2 := asn1.Unmarshal(cert.RawSubject, &gotRDN); err2 == nil && wantRDN.String() == gotRDN.String() {
				return nil
			}
		}
		return fmt.Errorf("%w: certificate subject DN does not match IDr", ErrInvalidCertificatePayload)
	default:
		return fmt.Errorf("%w: unsupported responder identity type %d for certificate validation", ErrInvalidCertificatePayload, id.Type)
	}
}

func verifyResponderPublicKeyAUTH(init InitResult, keys IKEKeys, responderID Identity, authPayload Payload, certs []*x509.Certificate, rootCAs *x509.CertPool) error {
	if authPayload.Type != PayloadAUTH {
		return fmt.Errorf("%w: payload type %d", ErrInvalidAuthenticationPayload, authPayload.Type)
	}
	if len(certs) == 0 {
		return fmt.Errorf("%w: missing responder certificate", ErrInvalidCertificatePayload)
	}
	leaf := certs[0]
	if rootCAs != nil {
		intermediates := x509.NewCertPool()
		for _, ic := range certs[1:] {
			intermediates.AddCert(ic)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         rootCAs,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return fmt.Errorf("%w: certificate chain verification failed: %w", ErrInvalidCertificatePayload, err)
		}
	}
	if err := verifyCertificateMatchesIdentity(leaf, responderID); err != nil {
		return err
	}
	auth, err := ParseAuthentication(authPayload.Body)
	if err != nil {
		return err
	}
	if auth.Method == AuthMethodSharedKeyMIC {
		return fmt.Errorf("%w: unexpected shared-key AUTH method for certificate authentication", ErrInvalidAuthenticationPayload)
	}
	signedOctets, err := ikeSignedOctets(init, keys, responderID, false)
	if err != nil {
		return err
	}
	return verifyPublicKeySignature(leaf.PublicKey, auth, signedOctets)
}

func verifyPublicKeySignature(pub crypto.PublicKey, auth Authentication, signedOctets []byte) error {
	switch auth.Method {
	case AuthMethodRSADigitalSignature:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: expected RSA public key for AUTH method 1", ErrInvalidAuthenticationPayload)
		}
		digest := sha1.Sum(signedOctets)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA1, digest[:], auth.Data); err != nil {
			return fmt.Errorf("%w: RSA AUTH verification failed: %w", ErrInvalidAuthenticationPayload, err)
		}
		return nil
	case AuthMethodECDSASHA256P256:
		return verifyRawECDSAAUTH(pub, elliptic.P256(), crypto.SHA256, 32, signedOctets, auth.Data)
	case AuthMethodECDSASHA384P384:
		return verifyRawECDSAAUTH(pub, elliptic.P384(), crypto.SHA384, 48, signedOctets, auth.Data)
	case AuthMethodECDSASHA512P521:
		return verifyRawECDSAAUTH(pub, elliptic.P521(), crypto.SHA512, 66, signedOctets, auth.Data)
	case AuthMethodDigitalSignature:
		return verifyRFC7427DigitalSignature(pub, signedOctets, auth.Data)
	default:
		return fmt.Errorf("%w: unsupported public-key AUTH method %d", ErrInvalidAuthenticationPayload, auth.Method)
	}
}

func verifyRawECDSAAUTH(pub crypto.PublicKey, wantCurve elliptic.Curve, hash crypto.Hash, coordLen int, signedOctets, sig []byte) error {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || ecPub.Curve != wantCurve {
		return fmt.Errorf("%w: ECDSA curve mismatch", ErrInvalidAuthenticationPayload)
	}
	if len(sig) != coordLen*2 {
		return fmt.Errorf("%w: ECDSA raw signature length %d != %d", ErrInvalidAuthenticationPayload, len(sig), coordLen*2)
	}
	h := hash.New()
	_, _ = h.Write(signedOctets)
	digest := h.Sum(nil)
	r := new(big.Int).SetBytes(sig[:coordLen])
	s := new(big.Int).SetBytes(sig[coordLen:])
	if !ecdsa.Verify(ecPub, digest, r, s) {
		return fmt.Errorf("%w: ECDSA AUTH verification failed", ErrInvalidAuthenticationPayload)
	}
	return nil
}

func verifyRFC7427DigitalSignature(pub crypto.PublicKey, signedOctets, data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("%w: RFC 7427 AUTH data too short", ErrInvalidAuthenticationPayload)
	}
	algLen := int(data[0])
	if algLen == 0 || len(data) <= 1+algLen {
		return fmt.Errorf("%w: invalid RFC 7427 AlgorithmIdentifier length %d", ErrInvalidAuthenticationPayload, algLen)
	}
	algDER := data[1 : 1+algLen]
	sig := data[1+algLen:]
	var algID pkix.AlgorithmIdentifier
	rest, err := asn1.Unmarshal(algDER, &algID)
	if err != nil || len(rest) != 0 {
		return fmt.Errorf("%w: parse RFC 7427 AlgorithmIdentifier: %v", ErrInvalidAuthenticationPayload, err)
	}

	switch {
	case algID.Algorithm.Equal(oidSHA1WithRSAEncryption):
		return verifyRSAPKCS1v15Hash(pub, crypto.SHA1, signedOctets, sig)
	case algID.Algorithm.Equal(oidSHA256WithRSAEncryption):
		return verifyRSAPKCS1v15Hash(pub, crypto.SHA256, signedOctets, sig)
	case algID.Algorithm.Equal(oidSHA384WithRSAEncryption):
		return verifyRSAPKCS1v15Hash(pub, crypto.SHA384, signedOctets, sig)
	case algID.Algorithm.Equal(oidSHA512WithRSAEncryption):
		return verifyRSAPKCS1v15Hash(pub, crypto.SHA512, signedOctets, sig)
	case algID.Algorithm.Equal(oidRSASSAPSS):
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: expected RSA public key for RSASSA-PSS", ErrInvalidAuthenticationPayload)
		}
		hashAlg, saltLen, err := parseRSAPSSParams(algID.Parameters)
		if err != nil {
			return err
		}
		h := hashAlg.New()
		_, _ = h.Write(signedOctets)
		if err := rsa.VerifyPSS(rsaPub, hashAlg, h.Sum(nil), sig, &rsa.PSSOptions{SaltLength: saltLen, Hash: hashAlg}); err != nil {
			return fmt.Errorf("%w: RSASSA-PSS AUTH verification failed: %w", ErrInvalidAuthenticationPayload, err)
		}
		return nil
	case algID.Algorithm.Equal(oidECDSAWithSHA256):
		return verifyECDSAASN1Hash(pub, crypto.SHA256, signedOctets, sig)
	case algID.Algorithm.Equal(oidECDSAWithSHA384):
		return verifyECDSAASN1Hash(pub, crypto.SHA384, signedOctets, sig)
	case algID.Algorithm.Equal(oidECDSAWithSHA512):
		return verifyECDSAASN1Hash(pub, crypto.SHA512, signedOctets, sig)
	case algID.Algorithm.Equal(oidEd25519):
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: expected Ed25519 public key", ErrInvalidAuthenticationPayload)
		}
		if !ed25519.Verify(edPub, signedOctets, sig) {
			return fmt.Errorf("%w: Ed25519 AUTH verification failed", ErrInvalidAuthenticationPayload)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported RFC 7427 signature OID %s", ErrInvalidAuthenticationPayload, algID.Algorithm)
	}
}

func verifyRSAPKCS1v15Hash(pub crypto.PublicKey, hash crypto.Hash, signedOctets, sig []byte) error {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: expected RSA public key", ErrInvalidAuthenticationPayload)
	}
	h := hash.New()
	_, _ = h.Write(signedOctets)
	if err := rsa.VerifyPKCS1v15(rsaPub, hash, h.Sum(nil), sig); err != nil {
		return fmt.Errorf("%w: RSA PKCS#1v1.5 AUTH verification failed: %w", ErrInvalidAuthenticationPayload, err)
	}
	return nil
}

func verifyECDSAASN1Hash(pub crypto.PublicKey, hash crypto.Hash, signedOctets, sig []byte) error {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: expected ECDSA public key", ErrInvalidAuthenticationPayload)
	}
	h := hash.New()
	_, _ = h.Write(signedOctets)
	if !ecdsa.VerifyASN1(ecPub, h.Sum(nil), sig) {
		return fmt.Errorf("%w: ECDSA ASN.1 AUTH verification failed", ErrInvalidAuthenticationPayload)
	}
	return nil
}

func parseRSAPSSParams(raw asn1.RawValue) (crypto.Hash, int, error) {
	if len(raw.FullBytes) == 0 {
		return crypto.SHA1, 20, nil
	}
	var params rsaPSSParamsASN1
	if _, err := asn1.Unmarshal(raw.FullBytes, &params); err != nil {
		return 0, 0, fmt.Errorf("%w: invalid RSASSA-PSS parameters: %w", ErrInvalidAuthenticationPayload, err)
	}
	hashAlg := crypto.SHA1
	if len(params.Hash.Algorithm) > 0 {
		switch {
		case params.Hash.Algorithm.Equal(oidHashSHA1):
			hashAlg = crypto.SHA1
		case params.Hash.Algorithm.Equal(oidHashSHA256):
			hashAlg = crypto.SHA256
		case params.Hash.Algorithm.Equal(oidHashSHA384):
			hashAlg = crypto.SHA384
		case params.Hash.Algorithm.Equal(oidHashSHA512):
			hashAlg = crypto.SHA512
		default:
			return 0, 0, fmt.Errorf("%w: unsupported RSASSA-PSS hash OID %s", ErrInvalidAuthenticationPayload, params.Hash.Algorithm)
		}
	}
	saltLen := params.SaltLength
	if saltLen <= 0 {
		saltLen = hashAlg.Size()
	}
	return hashAlg, saltLen, nil
}

// BuildPublicKeyAUTH constructs a public-key AUTH payload (RFC 7296 methods 1,
// 9, 10, 11 or RFC 7427 method 14) over the initiator or responder signed octets.
func BuildPublicKeyAUTH(init InitResult, keys IKEKeys, identity Identity, signer crypto.Signer, method uint8, hash crypto.Hash, initiator bool, random io.Reader) (Payload, error) {
	if signer == nil {
		return Payload{}, fmt.Errorf("%w: signer is nil", ErrInvalidAuthenticationPayload)
	}
	if random == nil {
		random = rand.Reader
	}
	signedOctets, err := ikeSignedOctets(init, keys, identity, initiator)
	if err != nil {
		return Payload{}, err
	}
	switch method {
	case AuthMethodRSADigitalSignature:
		digest := sha1.Sum(signedOctets)
		sig, err := signer.Sign(random, digest[:], crypto.SHA1)
		if err != nil {
			return Payload{}, err
		}
		return AuthenticationPayload(method, sig)
	case AuthMethodECDSASHA256P256:
		return buildRawECDSAAUTH(signer, crypto.SHA256, 32, method, signedOctets, random)
	case AuthMethodECDSASHA384P384:
		return buildRawECDSAAUTH(signer, crypto.SHA384, 48, method, signedOctets, random)
	case AuthMethodECDSASHA512P521:
		return buildRawECDSAAUTH(signer, crypto.SHA512, 66, method, signedOctets, random)
	case AuthMethodDigitalSignature:
		return buildRFC7427DigitalSignatureAUTH(signer, hash, signedOctets, random)
	default:
		return Payload{}, fmt.Errorf("%w: unsupported public-key AUTH method %d", ErrInvalidAuthenticationPayload, method)
	}
}

func buildRawECDSAAUTH(signer crypto.Signer, hash crypto.Hash, coordLen int, method uint8, signedOctets []byte, random io.Reader) (Payload, error) {
	h := hash.New()
	_, _ = h.Write(signedOctets)
	derSig, err := signer.Sign(random, h.Sum(nil), hash)
	if err != nil {
		return Payload{}, err
	}
	var rs struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(derSig, &rs); err != nil || rs.R == nil || rs.S == nil {
		return Payload{}, fmt.Errorf("%w: invalid ECDSA signature ASN.1", ErrInvalidAuthenticationPayload)
	}
	raw := make([]byte, coordLen*2)
	rs.R.FillBytes(raw[:coordLen])
	rs.S.FillBytes(raw[coordLen:])
	return AuthenticationPayload(method, raw)
}

func buildRFC7427DigitalSignatureAUTH(signer crypto.Signer, hash crypto.Hash, signedOctets []byte, random io.Reader) (Payload, error) {
	if hash == 0 {
		hash = crypto.SHA256
	}
	var algID pkix.AlgorithmIdentifier
	var sig []byte
	switch pub := signer.Public().(type) {
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			algID = pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSAEncryption, Parameters: asn1.NullRawValue}
		case crypto.SHA384:
			algID = pkix.AlgorithmIdentifier{Algorithm: oidSHA384WithRSAEncryption, Parameters: asn1.NullRawValue}
		case crypto.SHA512:
			algID = pkix.AlgorithmIdentifier{Algorithm: oidSHA512WithRSAEncryption, Parameters: asn1.NullRawValue}
		default:
			return Payload{}, fmt.Errorf("%w: unsupported RSA RFC 7427 hash %v", ErrInvalidAuthenticationPayload, hash)
		}
		h := hash.New()
		_, _ = h.Write(signedOctets)
		var err error
		sig, err = signer.Sign(random, h.Sum(nil), hash)
		if err != nil {
			return Payload{}, err
		}
		_ = pub
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			algID = pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}
		case crypto.SHA384:
			algID = pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA384}
		case crypto.SHA512:
			algID = pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA512}
		default:
			return Payload{}, fmt.Errorf("%w: unsupported ECDSA RFC 7427 hash %v", ErrInvalidAuthenticationPayload, hash)
		}
		h := hash.New()
		_, _ = h.Write(signedOctets)
		var err error
		sig, err = signer.Sign(random, h.Sum(nil), hash)
		if err != nil {
			return Payload{}, err
		}
	case ed25519.PublicKey:
		algID = pkix.AlgorithmIdentifier{Algorithm: oidEd25519}
		var err error
		sig, err = signer.Sign(random, signedOctets, crypto.Hash(0))
		if err != nil {
			return Payload{}, err
		}
	default:
		return Payload{}, fmt.Errorf("%w: unsupported signer type %T", ErrInvalidAuthenticationPayload, pub)
	}
	algDER, err := asn1.Marshal(algID)
	if err != nil {
		return Payload{}, err
	}
	if len(algDER) > 255 {
		return Payload{}, fmt.Errorf("%w: RFC 7427 AlgorithmIdentifier too long (%d)", ErrInvalidAuthenticationPayload, len(algDER))
	}
	data := make([]byte, 0, 1+len(algDER)+len(sig))
	data = append(data, byte(len(algDER)))
	data = append(data, algDER...)
	data = append(data, sig...)
	return AuthenticationPayload(AuthMethodDigitalSignature, data)
}
