package voiceclient

import (
	"context"
	"errors"
	"strings"
	"sync"
)

var ErrSIPTransportUnavailable = errors.New("sip transport unavailable")

// DigestAuthSession keeps SIP Digest state shared across IMS dialog requests.
type DigestAuthSession struct {
	mu         sync.Mutex
	headerName string
	header     string
	state      DigestAuthState
}

func NewDigestAuthSession(headerName, header string, state DigestAuthState) *DigestAuthSession {
	headerName = firstNonEmpty(headerName, state.headerName, "Authorization")
	return &DigestAuthSession{
		headerName: headerName,
		header:     firstNonEmpty(header),
		state:      state.clone(),
	}
}

func (s *DigestAuthSession) Usable() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Usable() || firstNonEmpty(s.header) != ""
}

func (s *DigestAuthSession) Snapshot() (headerName, header string, state DigestAuthState) {
	if s == nil {
		return "", "", DigestAuthState{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headerName, s.header, s.state.clone()
}

func (s *DigestAuthSession) Next(method, uri string) (headerName, header string, err error) {
	return s.NextWithBody(method, uri, nil)
}

func (s *DigestAuthSession) NextWithBody(method, uri string, body []byte) (headerName, header string, err error) {
	if s == nil {
		return "", "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, authz, next, err := nextDigestAuthorizationWithBody(s.state, method, uri, body, s.headerName, s.header)
	if err != nil {
		return name, "", err
	}
	s.headerName = firstNonEmpty(name, s.headerName, "Authorization")
	if firstNonEmpty(authz) != "" {
		s.header = authz
	}
	s.state = next
	return s.headerName, authz, nil
}

func (s *DigestAuthSession) UpdateFromResponse(resp SIPResponse) error {
	if s == nil || !isSIPSuccess(resp.StatusCode) {
		return nil
	}
	return s.UpdateFromAuthenticationInfo(resp.Headers, resp.Body)
}

func (s *DigestAuthSession) UpdateFromAuthenticationInfo(headers map[string][]string, body []byte) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := updateDigestAuthStateFromInfo(s.state, headers, s.headerName, body)
	if err != nil {
		return err
	}
	s.state = next
	return nil
}

func (s *DigestAuthSession) AuthorizeChallenge(resp SIPResponse, method, uri string, body []byte) (headerName, header string, ok bool, err error) {
	if s == nil || !isSIPDigestChallengeStatus(resp.StatusCode) {
		return "", "", false, nil
	}
	challengeHeader, authHeaderName := digestChallengeHeaders(resp.StatusCode)
	ch, err := SelectDigestChallenge(resp.Headers, challengeHeader)
	if err != nil {
		return authHeaderName, "", false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Usable() {
		return authHeaderName, "", false, ErrInvalidChallenge
	}
	next := s.state.clone()
	next.challenge = ch
	next.headerName = authHeaderName
	next.input.NC = 1
	next.nextNC = 1
	next.lastHeader = ""
	authz, next, err := next.BuildWithBody(method, uri, body)
	if err != nil {
		return authHeaderName, "", false, err
	}
	s.headerName = authHeaderName
	s.header = authz
	s.state = next
	return authHeaderName, authz, true, nil
}

func ApplyDigestAuthenticationInfo(msg SIPRequestMessage, resp SIPResponse) error {
	if msg.AuthSession == nil {
		return nil
	}
	return msg.AuthSession.UpdateFromResponse(resp)
}

func DigestChallengeRetryRequest(msg SIPRequestMessage, resp SIPResponse) (SIPRequestMessage, bool, error) {
	if msg.AuthSession == nil || !isSIPDigestChallengeStatus(resp.StatusCode) || !methodAllowsDigestChallengeRetry(msg.Method) {
		return SIPRequestMessage{}, false, nil
	}
	headerName, header, ok, err := msg.AuthSession.AuthorizeChallenge(resp, msg.Method, msg.URI, msg.Body)
	if err != nil || !ok {
		return SIPRequestMessage{}, false, err
	}
	retry := cloneSIPRequestMessage(msg)
	if retry.Headers == nil {
		retry.Headers = make(map[string]string)
	}
	delete(retry.Headers, "Authorization")
	delete(retry.Headers, "Proxy-Authorization")
	retry.Headers[headerName] = header
	return retry, true, nil
}

func RoundTripRequestWithDigestAuth(ctx context.Context, transport SIPRequestTransport, msg SIPRequestMessage) (SIPResponse, error) {
	if transport == nil {
		return SIPResponse{}, ErrSIPTransportUnavailable
	}
	resp, err := transport.RoundTripRequest(ctx, msg)
	if err != nil {
		return resp, err
	}
	if retry, ok, err := DigestChallengeRetryRequest(msg, resp); err != nil {
		return resp, err
	} else if ok {
		resp, err = transport.RoundTripRequest(ctx, retry)
		if err != nil {
			return resp, err
		}
		return resp, ApplyDigestAuthenticationInfo(retry, resp)
	}
	return resp, ApplyDigestAuthenticationInfo(msg, resp)
}

func isSIPDigestChallengeStatus(code int) bool {
	return code == 401 || code == 407
}

func digestChallengeHeaders(statusCode int) (challengeHeader, authHeader string) {
	if statusCode == 407 {
		return "Proxy-Authenticate", "Proxy-Authorization"
	}
	return "WWW-Authenticate", "Authorization"
}

func methodAllowsDigestChallengeRetry(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "", "INVITE", "ACK", "CANCEL":
		return false
	default:
		return true
	}
}

func bindDigestAuth(binding RegistrationBinding, headerName, header string, state DigestAuthState) RegistrationBinding {
	binding.AuthHeaderName = firstNonEmpty(headerName, state.headerName, binding.AuthHeaderName)
	binding.AuthHeader = firstNonEmpty(header, binding.AuthHeader)
	if state.Usable() || binding.AuthHeader != "" {
		binding.AuthSession = NewDigestAuthSession(binding.AuthHeaderName, binding.AuthHeader, state)
	}
	return binding
}
