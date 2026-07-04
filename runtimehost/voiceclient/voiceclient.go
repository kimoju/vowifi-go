package voiceclient

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/iniwex5/vowifi-go/engine/sim"
)

var ErrInvalidChallenge = errors.New("invalid SIP digest challenge")
var ErrRegistrationRejected = errors.New("IMS registration rejected")

type IMSProfile struct {
	IMPI      string
	IMPU      string
	Domain    string
	LocalIP   string
	UserAgent string
}

type DigestChallenge struct {
	Scheme    string
	Realm     string
	Nonce     string
	Algorithm string
	QOP       string
	Opaque    string
	Stale     bool
}

type DigestAuthInput struct {
	Method   string
	URI      string
	Username string
	Password string
	CNonce   string
	NC       int
}

type RegisterMessage struct {
	URI     string
	Headers map[string]string
	Body    []byte
}

type RegisterResponse struct {
	StatusCode int
	Reason     string
	Headers    map[string][]string
	Body       []byte
}

type SIPRegisterTransport interface {
	RoundTripRegister(context.Context, RegisterMessage) (RegisterResponse, error)
}

type RegisterSession struct {
	Transport    SIPRegisterTransport
	AKAProvider  sim.AKAProvider
	Profile      IMSProfile
	RegistrarURI string
	ContactURI   string
	CallID       string
	CNonce       string
	Expires      int
}

type RegisterResult struct {
	Registered bool
	StatusCode int
	Reason     string
	Attempts   int
	Challenge  DigestChallenge
}

func ParseWWWAuthenticate(header string) (DigestChallenge, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return DigestChallenge{}, ErrInvalidChallenge
	}
	scheme, rest, ok := strings.Cut(header, " ")
	if !ok {
		return DigestChallenge{}, ErrInvalidChallenge
	}
	ch := DigestChallenge{Scheme: strings.TrimSpace(scheme)}
	if !strings.EqualFold(ch.Scheme, "Digest") {
		return DigestChallenge{}, ErrInvalidChallenge
	}
	for _, part := range splitAuthParams(rest) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = unquote(strings.TrimSpace(value))
		switch key {
		case "realm":
			ch.Realm = value
		case "nonce":
			ch.Nonce = value
		case "algorithm":
			ch.Algorithm = value
		case "qop":
			ch.QOP = firstQOP(value)
		case "opaque":
			ch.Opaque = value
		case "stale":
			ch.Stale = strings.EqualFold(value, "true")
		}
	}
	if ch.Realm == "" || ch.Nonce == "" {
		return DigestChallenge{}, ErrInvalidChallenge
	}
	if ch.Algorithm == "" {
		ch.Algorithm = "MD5"
	}
	return ch, nil
}

func ExtractAKAChallengeNonce(nonce string) (rand16, autn16 []byte, ok bool) {
	raw, ok := decodeNonceBytes(nonce)
	if !ok || len(raw) < 32 {
		return nil, nil, false
	}
	return append([]byte(nil), raw[:16]...), append([]byte(nil), raw[16:32]...), true
}

func BuildDigestAuthorization(ch DigestChallenge, in DigestAuthInput) (string, error) {
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	uri := strings.TrimSpace(in.URI)
	username := strings.TrimSpace(in.Username)
	if method == "" || uri == "" || username == "" || ch.Realm == "" || ch.Nonce == "" {
		return "", ErrInvalidChallenge
	}
	algorithm := strings.TrimSpace(ch.Algorithm)
	if algorithm == "" {
		algorithm = "MD5"
	}
	if !strings.EqualFold(algorithm, "MD5") && !strings.EqualFold(algorithm, "AKAv1-MD5") {
		return "", fmt.Errorf("unsupported digest algorithm %q", algorithm)
	}

	ha1 := md5Hex(username + ":" + ch.Realm + ":" + in.Password)
	ha2 := md5Hex(method + ":" + uri)
	response := ""
	qop := firstQOP(ch.QOP)
	nc := in.NC
	if nc <= 0 {
		nc = 1
	}
	ncText := fmt.Sprintf("%08x", nc)
	cnonce := strings.TrimSpace(in.CNonce)
	if qop != "" {
		if cnonce == "" {
			return "", errors.New("cnonce required when qop is present")
		}
		response = md5Hex(ha1 + ":" + ch.Nonce + ":" + ncText + ":" + cnonce + ":" + qop + ":" + ha2)
	} else {
		response = md5Hex(ha1 + ":" + ch.Nonce + ":" + ha2)
	}

	parts := []string{
		`Digest username="` + quote(username) + `"`,
		`realm="` + quote(ch.Realm) + `"`,
		`nonce="` + quote(ch.Nonce) + `"`,
		`uri="` + quote(uri) + `"`,
		`response="` + response + `"`,
		`algorithm=` + algorithm,
	}
	if ch.Opaque != "" {
		parts = append(parts, `opaque="`+quote(ch.Opaque)+`"`)
	}
	if qop != "" {
		parts = append(parts, `qop=`+qop, `nc=`+ncText, `cnonce="`+quote(cnonce)+`"`)
	}
	return strings.Join(parts, ", "), nil
}

func BuildRegisterHeaders(profile IMSProfile, contactURI, callID, cseq string) map[string]string {
	domain := strings.TrimSpace(profile.Domain)
	impu := strings.TrimSpace(profile.IMPU)
	if impu == "" && domain != "" {
		impu = "sip:" + strings.TrimSpace(profile.IMPI) + "@" + domain
	}
	headers := map[string]string{
		"To":              "<" + impu + ">",
		"From":            "<" + impu + ">;tag=vowifi-go",
		"Contact":         "<" + strings.TrimSpace(contactURI) + ">;+sip.instance=\"<urn:uuid:vowifi-go>\"",
		"Call-ID":         strings.TrimSpace(callID),
		"CSeq":            strings.TrimSpace(cseq) + " REGISTER",
		"Max-Forwards":    "70",
		"User-Agent":      firstNonEmpty(profile.UserAgent, "vowifi-go"),
		"Allow":           "INVITE, ACK, CANCEL, BYE, PRACK, UPDATE, MESSAGE, OPTIONS",
		"Supported":       "path, gruu, outbound, sec-agree",
		"Security-Client": `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=0;spi-s=0;port-c=0;port-s=0`,
	}
	return headers
}

func (s RegisterSession) Register(ctx context.Context) (RegisterResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Transport == nil {
		return RegisterResult{}, errors.New("nil SIP register transport")
	}
	registrarURI := strings.TrimSpace(s.RegistrarURI)
	contactURI := strings.TrimSpace(s.ContactURI)
	if registrarURI == "" || contactURI == "" {
		return RegisterResult{}, errors.New("registrar URI and contact URI are required")
	}
	callID := firstNonEmpty(s.CallID, "vowifi-go-register")
	expires := s.Expires
	if expires <= 0 {
		expires = 3600
	}

	msg := RegisterMessage{
		URI:     registrarURI,
		Headers: BuildRegisterHeaders(s.Profile, contactURI, callID, "1"),
	}
	msg.Headers["Expires"] = strconv.Itoa(expires)
	resp, err := s.Transport.RoundTripRegister(ctx, cloneRegisterMessage(msg))
	if err != nil {
		return RegisterResult{}, err
	}
	if isSIPSuccess(resp.StatusCode) {
		return RegisterResult{Registered: true, StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: 1}, nil
	}
	if resp.StatusCode != 401 && resp.StatusCode != 407 {
		return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: 1}, fmt.Errorf("%w: %d %s", ErrRegistrationRejected, resp.StatusCode, resp.Reason)
	}

	headerName := "WWW-Authenticate"
	authHeader := firstHeader(resp.Headers, headerName)
	authzHeader := "Authorization"
	if authHeader == "" {
		headerName = "Proxy-Authenticate"
		authHeader = firstHeader(resp.Headers, headerName)
		authzHeader = "Proxy-Authorization"
	}
	ch, err := ParseWWWAuthenticate(authHeader)
	if err != nil {
		return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: 1}, err
	}

	password := ""
	if strings.EqualFold(ch.Algorithm, "AKAv1-MD5") {
		rand16, autn16, ok := ExtractAKAChallengeNonce(ch.Nonce)
		if !ok {
			return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: 1, Challenge: ch}, ErrInvalidChallenge
		}
		if s.AKAProvider == nil {
			return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: 1, Challenge: ch}, errors.New("AKA provider required for AKAv1-MD5")
		}
		aka, err := s.AKAProvider.CalculateAKA(rand16, autn16)
		if err != nil {
			return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: 1, Challenge: ch}, err
		}
		password = strings.ToUpper(hex.EncodeToString(aka.RES))
	}

	authz, err := BuildDigestAuthorization(ch, DigestAuthInput{
		Method:   "REGISTER",
		URI:      registrarURI,
		Username: firstNonEmpty(s.Profile.IMPI, s.Profile.IMPU),
		Password: password,
		CNonce:   firstNonEmpty(s.CNonce, "vowifi-go"),
		NC:       1,
	})
	if err != nil {
		return RegisterResult{StatusCode: resp.StatusCode, Reason: resp.Reason, Attempts: 1, Challenge: ch}, err
	}

	msg.Headers = BuildRegisterHeaders(s.Profile, contactURI, callID, "2")
	msg.Headers["Expires"] = strconv.Itoa(expires)
	msg.Headers[authzHeader] = authz
	resp2, err := s.Transport.RoundTripRegister(ctx, cloneRegisterMessage(msg))
	if err != nil {
		return RegisterResult{Attempts: 2, Challenge: ch}, err
	}
	result := RegisterResult{
		Registered: isSIPSuccess(resp2.StatusCode),
		StatusCode: resp2.StatusCode,
		Reason:     resp2.Reason,
		Attempts:   2,
		Challenge:  ch,
	}
	if !result.Registered {
		return result, fmt.Errorf("%w: %d %s", ErrRegistrationRejected, resp2.StatusCode, resp2.Reason)
	}
	return result, nil
}

func splitAuthParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			cur.WriteRune(r)
			escaped = true
		case r == '"':
			cur.WriteRune(r)
			inQuote = !inQuote
		case r == ',' && !inQuote:
			if part := strings.TrimSpace(cur.String()); part != "" {
				out = append(out, part)
			}
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if part := strings.TrimSpace(cur.String()); part != "" {
		out = append(out, part)
	}
	return out
}

func firstQOP(qop string) string {
	for _, part := range strings.Split(qop, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p == "auth" {
			return p
		}
	}
	return strings.ToLower(strings.TrimSpace(qop))
}

func firstHeader(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	}
	return ""
}

func isSIPSuccess(code int) bool {
	return code >= 200 && code < 300
}

func cloneRegisterMessage(msg RegisterMessage) RegisterMessage {
	out := RegisterMessage{
		URI:     msg.URI,
		Headers: make(map[string]string, len(msg.Headers)),
		Body:    append([]byte(nil), msg.Body...),
	}
	for k, v := range msg.Headers {
		out.Headers[k] = v
	}
	return out
}

func decodeNonceBytes(nonce string) ([]byte, bool) {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return nil, false
	}
	clean := strings.NewReplacer(":", "", "-", "", " ", "").Replace(nonce)
	if raw, err := hex.DecodeString(clean); err == nil {
		return raw, true
	}
	if raw, err := base64.StdEncoding.DecodeString(nonce); err == nil {
		return raw, true
	}
	if raw, err := base64.RawStdEncoding.DecodeString(nonce); err == nil {
		return raw, true
	}
	return nil, false
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if out, err := strconv.Unquote(s); err == nil {
			return out
		}
		return s[1 : len(s)-1]
	}
	return s
}

func quote(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

func firstNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}
