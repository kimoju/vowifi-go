package voiceclient

import "sync"

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

func ApplyDigestAuthenticationInfo(msg SIPRequestMessage, resp SIPResponse) error {
	if msg.AuthSession == nil {
		return nil
	}
	return msg.AuthSession.UpdateFromResponse(resp)
}

func bindDigestAuth(binding RegistrationBinding, headerName, header string, state DigestAuthState) RegistrationBinding {
	binding.AuthHeaderName = firstNonEmpty(headerName, state.headerName, binding.AuthHeaderName)
	binding.AuthHeader = firstNonEmpty(header, binding.AuthHeader)
	if state.Usable() || binding.AuthHeader != "" {
		binding.AuthSession = NewDigestAuthSession(binding.AuthHeaderName, binding.AuthHeader, state)
	}
	return binding
}
