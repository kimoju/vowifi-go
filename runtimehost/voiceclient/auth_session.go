package voiceclient

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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

func (s *DigestAuthSession) SetChallengeInput(input DigestChallengeInputFunc) {
	if s == nil || input == nil {
		return
	}
	s.mu.Lock()
	s.challengeInput = input
	s.mu.Unlock()
}

func (s *DigestAuthSession) ReplaceState(headerName, header string, state DigestAuthState) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if name := firstNonEmpty(headerName, state.headerName); name != "" {
		s.headerName = name
	}
	if h := strings.TrimSpace(header); h != "" {
		s.header = h
	}
	if state.Usable() {
		next := state.clone()
		if s.state.Usable() &&
			s.state.challenge.Nonce == next.challenge.Nonce &&
			s.state.input.CNonce == next.input.CNonce &&
			s.state.nextNC > next.nextNC {
			next.nextNC = s.state.nextNC
			if strings.TrimSpace(s.header) != "" {
				next.lastHeader = s.header
			}
		}
		s.state = next
	}
}

func (s *DigestAuthSession) ReplaceFrom(other *DigestAuthSession) {
	if s == nil || other == nil || s == other {
		return
	}
	other.mu.Lock()
	headerName := other.headerName
	header := other.header
	state := other.state.clone()
	input := other.challengeInput
	other.mu.Unlock()

	s.ReplaceState(headerName, header, state)
	if input != nil {
		s.SetChallengeInput(input)
	}
}

func (s *DigestAuthSession) forceReplaceState(headerName, header string, state DigestAuthState) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if name := firstNonEmpty(headerName, state.headerName); name != "" {
		s.headerName = name
	}
	if h := strings.TrimSpace(header); h != "" {
		s.header = h
	}
	s.state = state.clone()
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
	if !digestRetryRequestHasRequiredCSeq(msg) {
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
	deleteSIPHeader(retry.Headers, "Authorization")
	deleteSIPHeader(retry.Headers, "Proxy-Authorization")
	retry.Headers[authz.HeaderName] = authz.Header
	incrementDigestRetryCSeq(retry.Headers, msg.Method)
	if via := firstHeaderValue(retry.Headers, "Via"); via != "" {
		setSIPHeader(retry.Headers, "Via", replaceSIPViaBranchValue(via, newBranch()))
	}
	return retry, DigestChallengeRetryResult{Authorization: authz}, true, nil
}

func RoundTripRequestWithDigestAuth(ctx context.Context, transport SIPRequestTransport, msg SIPRequestMessage) (SIPResponse, error) {
	resp, _, err := RoundTripRequestWithDigestAuthResult(ctx, transport, msg)
	return resp, err
}

func RoundTripRequestWithDigestAuthResult(ctx context.Context, transport SIPRequestTransport, msg SIPRequestMessage) (SIPResponse, SIPRequestMessage, error) {
	if transport == nil {
		return SIPResponse{}, cloneSIPRequestMessage(msg), ErrSIPTransportUnavailable
	}
	current := cloneSIPRequestMessage(msg)
	resp, err := transport.RoundTripRequest(ctx, current)
	if err != nil {
		return resp, current, err
	}
	syncRequestViaFromResponse(&current, resp)
	allowNonStaleChallengeRetry := true
	for retries := 0; retries < 2; retries++ {
		if !allowNonStaleChallengeRetry && !sipDigestChallengeIsStale(resp) {
			break
		}
		retry, result, ok, err := DigestChallengeRetryRequestWithResult(current, resp)
		if err != nil {
			return resp, current, err
		}
		if !ok {
			break
		}
		if err := ackInviteDigestChallenge(ctx, transport, current, resp); err != nil {
			return resp, current, err
		}
		current = retry
		resp, err = transport.RoundTripRequest(ctx, current)
		if err != nil {
			return resp, current, err
		}
		syncRequestViaFromResponse(&current, resp)
		allowNonStaleChallengeRetry = result.Authorization.SyncFailure
	}
	return resp, current, ApplyDigestAuthenticationInfo(current, resp)
}

func syncRequestViaFromResponse(msg *SIPRequestMessage, resp SIPResponse) {
	if msg == nil || firstHeaderValue(msg.Headers, "Via") != "" {
		return
	}
	topVia := firstTopViaHeader(resp.Headers)
	if topVia == "" {
		return
	}
	if msg.Headers == nil {
		msg.Headers = make(map[string]string)
	}
	msg.Headers["Via"] = sanitizeEchoedClientVia(topVia)
}

func firstTopViaHeader(headers map[string][]string) string {
	for _, v := range headerListValues(headers, "Via") {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func sanitizeEchoedClientVia(via string) string {
	parts := splitSIPHeaderParams(via)
	if len(parts) == 0 {
		return strings.TrimSpace(via)
	}
	out := []string{parts[0]}
	for _, p := range parts[1:] {
		k, _, ok := strings.Cut(strings.TrimSpace(p), "=")
		kl := strings.ToLower(strings.TrimSpace(k))
		if ok && kl == "received" {
			continue
		}
		if ok && kl == "rport" {
			out = append(out, "rport")
			continue
		}
		out = append(out, strings.TrimSpace(p))
	}
	return strings.Join(out, ";")
}

func sipDigestChallengeIsStale(resp SIPResponse) bool {
	if !isSIPDigestChallengeStatus(resp.StatusCode) {
		return false
	}
	challengeHeader, _ := digestChallengeHeaders(resp.StatusCode)
	ch, err := SelectDigestChallenge(resp.Headers, challengeHeader)
	return err == nil && ch.Stale
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
	case "", "ACK", "CANCEL":
		return false
	default:
		return true
	}
}

func digestRetryRequestHasRequiredCSeq(msg SIPRequestMessage) bool {
	if !strings.EqualFold(strings.TrimSpace(msg.Method), "INVITE") {
		return true
	}
	_, method, ok := sipCSeqParts(firstHeaderValue(msg.Headers, "CSeq"))
	return ok && strings.EqualFold(method, "INVITE")
}

func incrementDigestRetryCSeq(headers map[string]string, method string) {
	if headers == nil {
		return
	}
	seq, cseqMethod, ok := sipCSeqParts(firstHeaderValue(headers, "CSeq"))
	if !ok || !strings.EqualFold(cseqMethod, strings.TrimSpace(method)) {
		return
	}
	setSIPHeader(headers, "CSeq", strconv.Itoa(seq+1)+" "+strings.ToUpper(strings.TrimSpace(cseqMethod)))
}

// BuildNon2xxInviteAck constructs a hop-by-hop non-2xx INVITE ACK per RFC 3261
// §17.1.1.3, preserving the INVITE Request-URI, initial Route header, CSeq
// number, and top Via branch while copying any To-tag from resp.
func BuildNon2xxInviteAck(invite SIPRequestMessage, resp SIPResponse) (SIPRequestMessage, error) {
	ack, ok := inviteDigestChallengeAck(invite, resp)
	if !ok {
		return SIPRequestMessage{}, errors.New("cannot build non-2xx INVITE ACK: missing dialog headers")
	}
	return ack, nil
}

// ParseSIPCSeqNumber extracts the sequence number from a SIP CSeq header value.
func ParseSIPCSeqNumber(value string) int {
	seq, _, ok := sipCSeqParts(value)
	if !ok {
		return 0
	}
	return seq
}

// EnsureDialogRequestVia populates a Via header with a fresh RFC 3261 z9hG4bK
// branch on msg if one is not already present, deriving sent-by from cfg.
func EnsureDialogRequestVia(msg *SIPRequestMessage, cfg DialogRequestConfig) string {
	if msg == nil {
		return ""
	}
	if msg.Headers == nil {
		msg.Headers = make(map[string]string)
	}
	if existing := firstHeaderValue(msg.Headers, "Via"); existing != "" {
		if branch := sipViaBranch(existing); branch != "" {
			return branch
		}
		branch := newBranch()
		setSIPHeader(msg.Headers, "Via", replaceSIPViaBranchValue(existing, branch))
		return branch
	}
	proto := "UDP"
	if tp := dialogURITransport(firstNonEmpty(msg.URI, cfg.RemoteTargetURI, cfg.ContactURI)); tp != "" {
		proto = strings.ToUpper(tp)
	}
	sentBy := dialogSentByHostPort(cfg)
	branch := newBranch()
	msg.Headers["Via"] = fmt.Sprintf("SIP/2.0/%s %s;rport;branch=%s", proto, sentBy, branch)
	return branch
}

func dialogURITransport(raw string) string {
	raw = strings.Trim(strings.TrimSpace(raw), "<>")
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "sips:") {
		return "tls"
	}
	if q := strings.IndexByte(raw, '?'); q >= 0 {
		raw = raw[:q]
	}
	if at := strings.LastIndexByte(raw, '@'); at >= 0 {
		raw = raw[at+1:]
	}
	semi := indexOutsideBrackets(raw, ';')
	if semi < 0 {
		return ""
	}
	for _, part := range strings.Split(raw[semi+1:], ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "transport") {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "udp", "tcp", "tls":
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	return ""
}

func dialogSentByHostPort(cfg DialogRequestConfig) string {
	for _, candidate := range []string{cfg.ContactURI, cfg.Registration.ContactURI} {
		raw := strings.Trim(strings.TrimSpace(candidate), "<>")
		if raw == "" {
			continue
		}
		if idx := strings.IndexByte(raw, ':'); idx >= 0 {
			scheme := strings.ToLower(strings.TrimSpace(raw[:idx]))
			if scheme == "sip" || scheme == "sips" {
				rest := raw[idx+1:]
				if q := strings.IndexByte(rest, '?'); q >= 0 {
					rest = rest[:q]
				}
				if at := strings.LastIndexByte(rest, '@'); at >= 0 {
					rest = rest[at+1:]
				}
				if semi := indexOutsideBrackets(rest, ';'); semi >= 0 {
					rest = rest[:semi]
				}
				rest = strings.TrimSpace(rest)
				if rest != "" {
					return rest
				}
			}
		}
	}
	ip := strings.Trim(strings.TrimSpace(cfg.Profile.LocalIP), "[]")
	if ip == "" {
		return "0.0.0.0"
	}
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}

func ackInviteDigestChallenge(ctx context.Context, transport SIPRequestTransport, msg SIPRequestMessage, resp SIPResponse) error {
	if !strings.EqualFold(strings.TrimSpace(msg.Method), "INVITE") || !isSIPDigestChallengeStatus(resp.StatusCode) {
		return nil
	}
	ack, ok := inviteDigestChallengeAck(msg, resp)
	if !ok {
		return nil
	}
	return transport.WriteRequest(ctx, ack)
}

func inviteDigestChallengeAck(msg SIPRequestMessage, resp SIPResponse) (SIPRequestMessage, bool) {
	seq, method, ok := sipCSeqParts(firstHeaderValue(msg.Headers, "CSeq"))
	if !ok || !strings.EqualFold(method, "INVITE") {
		return SIPRequestMessage{}, false
	}
	headers := make(map[string]string)
	copySIPHeader(headers, msg.Headers, "Via")
	if firstHeaderValue(headers, "Via") == "" {
		if topVia := firstTopViaHeader(resp.Headers); topVia != "" {
			headers["Via"] = sanitizeEchoedClientVia(topVia)
		}
	}
	copySIPHeader(headers, msg.Headers, "Route")
	copySIPHeader(headers, msg.Headers, "Max-Forwards")
	copySIPHeader(headers, msg.Headers, "From")
	copySIPHeader(headers, msg.Headers, "Call-ID")
	copySIPHeader(headers, msg.Headers, "User-Agent")
	copySIPHeader(headers, msg.Headers, "Supported")
	copySIPHeader(headers, msg.Headers, "Contact")
	if to := firstHeader(resp.Headers, "To"); strings.TrimSpace(to) != "" {
		headers["To"] = strings.TrimSpace(to)
	} else {
		copySIPHeader(headers, msg.Headers, "To")
	}
	headers["CSeq"] = strconv.Itoa(seq) + " ACK"
	return SIPRequestMessage{
		Method:  "ACK",
		URI:     msg.URI,
		Headers: headers,
	}, true
}

func copySIPHeader(dst map[string]string, src map[string]string, name string) {
	if dst == nil || src == nil {
		return
	}
	want := canonicalHeaderName(name)
	for key, value := range src {
		if (strings.EqualFold(key, name) || strings.EqualFold(canonicalHeaderName(key), want)) && strings.TrimSpace(value) != "" {
			dst[want] = strings.TrimSpace(value)
			return
		}
	}
}

func deleteSIPHeader(headers map[string]string, name string) {
	want := canonicalHeaderName(name)
	for key := range headers {
		if strings.EqualFold(key, name) || strings.EqualFold(canonicalHeaderName(key), want) {
			delete(headers, key)
		}
	}
}

func setSIPHeader(headers map[string]string, name, value string) {
	if headers == nil {
		return
	}
	want := canonicalHeaderName(name)
	for key := range headers {
		if strings.EqualFold(key, name) || strings.EqualFold(canonicalHeaderName(key), want) {
			if key != want {
				delete(headers, key)
			}
			headers[want] = value
			return
		}
	}
	headers[want] = value
}

func bindDigestAuth(binding RegistrationBinding, headerName, header string, state DigestAuthState) RegistrationBinding {
	return bindDigestAuthWithChallengeInput(binding, headerName, header, state, nil)
}

func bindDigestAuthWithChallengeInput(binding RegistrationBinding, headerName, header string, state DigestAuthState, input DigestChallengeInputFunc) RegistrationBinding {
	binding.AuthHeaderName = firstNonEmpty(headerName, state.headerName, binding.AuthHeaderName)
	binding.AuthHeader = firstNonEmpty(header, binding.AuthHeader)
	if binding.AuthSession != nil {
		binding.AuthSession.SetChallengeInput(input)
		binding.AuthSession.ReplaceState(binding.AuthHeaderName, binding.AuthHeader, state)
		return binding
	}
	if state.Usable() || binding.AuthHeader != "" {
		binding.AuthSession = NewDigestAuthSessionWithChallengeInput(binding.AuthHeaderName, binding.AuthHeader, state, input)
	}
	return binding
}
