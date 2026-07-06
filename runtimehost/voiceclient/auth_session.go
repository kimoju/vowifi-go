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
	mu             sync.Mutex
	headerName     string
	header         string
	state          DigestAuthState
	challengeInput DigestChallengeInputFunc
}

type DigestChallengeInputFunc func(DigestChallenge, string) (DigestAuthInput, error)

type DigestChallengeAuthorization struct {
	HeaderName  string
	Header      string
	SyncFailure bool
}

type DigestChallengeRetryResult struct {
	Authorization DigestChallengeAuthorization
}

func NewDigestAuthSession(headerName, header string, state DigestAuthState) *DigestAuthSession {
	return NewDigestAuthSessionWithChallengeInput(headerName, header, state, nil)
}

func NewDigestAuthSessionWithChallengeInput(headerName, header string, state DigestAuthState, input DigestChallengeInputFunc) *DigestAuthSession {
	headerName = firstNonEmpty(headerName, state.headerName, "Authorization")
	return &DigestAuthSession{
		headerName:     headerName,
		header:         firstNonEmpty(header),
		state:          state.clone(),
		challengeInput: input,
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
	authz, ok, err := s.AuthorizeChallengeWithResult(resp, method, uri, body)
	if err != nil || !ok {
		return authz.HeaderName, "", ok, err
	}
	return authz.HeaderName, authz.Header, true, nil
}

func (s *DigestAuthSession) AuthorizeChallengeWithResult(resp SIPResponse, method, uri string, body []byte) (DigestChallengeAuthorization, bool, error) {
	if s == nil || !isSIPDigestChallengeStatus(resp.StatusCode) {
		return DigestChallengeAuthorization{}, false, nil
	}
	challengeHeader, authHeaderName := digestChallengeHeaders(resp.StatusCode)
	ch, err := SelectDigestChallenge(resp.Headers, challengeHeader)
	if err != nil {
		return DigestChallengeAuthorization{HeaderName: authHeaderName}, false, err
	}
	if s.challengeInput != nil {
		return s.authorizeChallengeWithInput(ch, authHeaderName, method, uri, body)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.Usable() {
		return DigestChallengeAuthorization{HeaderName: authHeaderName}, false, ErrInvalidChallenge
	}
	next := s.state.clone()
	next.challenge = ch
	next.headerName = authHeaderName
	next.input.NC = 1
	next.nextNC = 1
	next.lastHeader = ""
	authz, next, err := next.BuildWithBody(method, uri, body)
	if err != nil {
		return DigestChallengeAuthorization{HeaderName: authHeaderName}, false, err
	}
	s.headerName = authHeaderName
	s.header = authz
	s.state = next
	return DigestChallengeAuthorization{HeaderName: authHeaderName, Header: authz}, true, nil
}

func (s *DigestAuthSession) authorizeChallengeWithInput(ch DigestChallenge, authHeaderName, method, uri string, body []byte) (DigestChallengeAuthorization, bool, error) {
	input, err := s.challengeInput(ch, uri)
	if err != nil {
		return DigestChallengeAuthorization{HeaderName: authHeaderName}, false, err
	}
	input.Method = strings.ToUpper(strings.TrimSpace(method))
	input.URI = strings.TrimSpace(uri)
	input.NC = 1
	input.Body = append([]byte(nil), body...)
	authz, err := BuildDigestAuthorization(ch, input)
	if err != nil {
		return DigestChallengeAuthorization{HeaderName: authHeaderName}, false, err
	}
	result := DigestChallengeAuthorization{
		HeaderName:  authHeaderName,
		Header:      authz,
		SyncFailure: len(input.AUTS) > 0,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.headerName = authHeaderName
	s.header = authz
	if len(input.AUTS) == 0 {
		s.state = newDigestAuthState(authHeaderName, ch, input, authz)
	}
	return result, true, nil
}

func ApplyDigestAuthenticationInfo(msg SIPRequestMessage, resp SIPResponse) error {
	if msg.AuthSession == nil {
		return nil
	}
	return msg.AuthSession.UpdateFromResponse(resp)
}

func DigestChallengeRetryRequest(msg SIPRequestMessage, resp SIPResponse) (SIPRequestMessage, bool, error) {
	retry, _, ok, err := DigestChallengeRetryRequestWithResult(msg, resp)
	return retry, ok, err
}

func DigestChallengeRetryRequestWithResult(msg SIPRequestMessage, resp SIPResponse) (SIPRequestMessage, DigestChallengeRetryResult, bool, error) {
	if msg.AuthSession == nil || !isSIPDigestChallengeStatus(resp.StatusCode) || !methodAllowsDigestChallengeRetry(msg.Method) {
		return SIPRequestMessage{}, DigestChallengeRetryResult{}, false, nil
	}
	authz, ok, err := msg.AuthSession.AuthorizeChallengeWithResult(resp, msg.Method, msg.URI, msg.Body)
	if err != nil || !ok {
		return SIPRequestMessage{}, DigestChallengeRetryResult{Authorization: authz}, false, err
	}
	retry := cloneSIPRequestMessage(msg)
	if retry.Headers == nil {
		retry.Headers = make(map[string]string)
	}
	delete(retry.Headers, "Authorization")
	delete(retry.Headers, "Proxy-Authorization")
	retry.Headers[authz.HeaderName] = authz.Header
	return retry, DigestChallengeRetryResult{Authorization: authz}, true, nil
}

func RoundTripRequestWithDigestAuth(ctx context.Context, transport SIPRequestTransport, msg SIPRequestMessage) (SIPResponse, error) {
	if transport == nil {
		return SIPResponse{}, ErrSIPTransportUnavailable
	}
	resp, err := transport.RoundTripRequest(ctx, msg)
	if err != nil {
		return resp, err
	}
	current := msg
	allowChallengeRetry := true
	for retries := 0; retries < 2 && allowChallengeRetry; retries++ {
		retry, result, ok, err := DigestChallengeRetryRequestWithResult(current, resp)
		if err != nil {
			return resp, err
		}
		if !ok {
			break
		}
		current = retry
		resp, err = transport.RoundTripRequest(ctx, current)
		if err != nil {
			return resp, err
		}
		allowChallengeRetry = result.Authorization.SyncFailure
	}
	return resp, ApplyDigestAuthenticationInfo(current, resp)
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
	return bindDigestAuthWithChallengeInput(binding, headerName, header, state, nil)
}

func bindDigestAuthWithChallengeInput(binding RegistrationBinding, headerName, header string, state DigestAuthState, input DigestChallengeInputFunc) RegistrationBinding {
	binding.AuthHeaderName = firstNonEmpty(headerName, state.headerName, binding.AuthHeaderName)
	binding.AuthHeader = firstNonEmpty(header, binding.AuthHeader)
	if state.Usable() || binding.AuthHeader != "" {
		binding.AuthSession = NewDigestAuthSessionWithChallengeInput(binding.AuthHeaderName, binding.AuthHeader, state, input)
	}
	return binding
}
