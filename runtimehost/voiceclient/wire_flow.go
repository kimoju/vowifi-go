package voiceclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrSIPFlowClosed = errors.New("SIP flow is closed")
var ErrSIPFinalResponseTimeout = errors.New("SIP final response timeout")

type sipFinalResponseTimeoutError struct {
	Method string
	Err    error
}

func (e sipFinalResponseTimeoutError) Error() string {
	method := strings.ToUpper(strings.TrimSpace(e.Method))
	if method == "" {
		method = "SIP"
	}
	if e.Err == nil {
		return method + " final response timeout"
	}
	return method + " final response timeout: " + e.Err.Error()
}

func (e sipFinalResponseTimeoutError) Unwrap() []error {
	if e.Err == nil {
		return []error{ErrSIPFinalResponseTimeout}
	}
	return []error{ErrSIPFinalResponseTimeout, e.Err}
}

type WireSIPFlow struct {
	Network               string
	ServerAddr            string
	LocalAddr             string
	Resolver              SIPServerResolver
	Timeout               time.Duration
	RetransmitInterval    time.Duration
	MaxRetransmitInterval time.Duration
	MaxRetransmits        int
	FinalResponseDrain    time.Duration
	TLSConfig             *tls.Config

	mu                   sync.Mutex
	conn                 net.Conn
	securityResponseConn net.PacketConn
	reader               *bufio.Reader
	network              string
	target               string
	targets              []string
	targetIndex          int
	closed               bool

	responseMu       sync.RWMutex
	responseExternal bool
	responsePacketCh chan []byte
}

var _ SIPRegisterTransport = (*WireSIPFlow)(nil)
var _ SIPRequestTransport = (*WireSIPFlow)(nil)
var _ SIPInviteTransport = (*WireSIPFlow)(nil)
var _ SecurityAssociationTransport = (*WireSIPFlow)(nil)
var _ SecurityAssociationEndpointProvider = (*WireSIPFlow)(nil)

func (f *WireSIPFlow) SecurityAssociationAddresses() (string, string) {
	if f == nil {
		return "", ""
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		return sipEndpointHost(f.conn.LocalAddr().String()), sipEndpointHost(f.conn.RemoteAddr().String())
	}
	return sipEndpointHost(f.LocalAddr), sipEndpointHost(firstNonEmpty(f.target, f.ServerAddr))
}

func sipEndpointHost(value string) string {
	host, _, ok := splitIMSSecurityEndpointAddr(value)
	if ok {
		return strings.TrimSpace(host)
	}
	return strings.Trim(strings.TrimSpace(value), "[]")
}

func (f *WireSIPFlow) RoundTripRegister(ctx context.Context, msg RegisterMessage) (RegisterResponse, error) {
	return f.roundTrip(ctx, SIPRequestMessage{
		Method:  "REGISTER",
		URI:     msg.URI,
		Headers: cloneStringMap(msg.Headers),
		Body:    append([]byte(nil), msg.Body...),
	}, nil, sipRegisterTargetFailoverStatus)
}

func (f *WireSIPFlow) RoundTripRequest(ctx context.Context, msg SIPRequestMessage) (SIPResponse, error) {
	return f.roundTrip(ctx, msg, nil, sipDialogTargetFailoverStatus)
}

func (f *WireSIPFlow) RoundTripInvite(ctx context.Context, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler) (SIPResponse, error) {
	return f.roundTrip(ctx, msg, onProvisional, sipDialogTargetFailoverStatus)
}

func (f *WireSIPFlow) WriteRequest(ctx context.Context, msg SIPRequestMessage) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if f == nil {
		return errors.New("nil SIP flow")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	attempts := 0
	shouldRetry := func(err error) bool {
		if ctx.Err() != nil || errors.Is(err, ErrSIPFinalResponseTimeout) || !isSIPRetryableTransportError(err) {
			return false
		}
		attempts++
		if attempts >= f.targetCountLocked() {
			return false
		}
		return f.advanceTargetLocked()
	}
	for {
		conn, network, timeout, err := f.ensureConnLocked(ctx, msg)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !shouldRetry(err) {
				return err
			}
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			f.closeConnLocked()
			if !shouldRetry(err) {
				return err
			}
			continue
		}
		attempt := cloneSIPRequestMessage(msg)
		ensureSIPRequestVia(&attempt, transportName(network), conn.LocalAddr())
		wire, err := buildSIPRequestWire(attempt, transportName(network), conn.LocalAddr())
		if err != nil {
			return err
		}
		if _, err := conn.Write(wire); err != nil {
			f.closeConnLocked()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !shouldRetry(err) {
				return err
			}
			continue
		}
		return nil
	}
}

func (f *WireSIPFlow) SendCRLFKeepalive(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if f == nil {
		return errors.New("nil SIP flow")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrSIPFlowClosed
	}
	conn := f.conn
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if conn == nil {
		target := strings.TrimSpace(f.ServerAddr)
		if target == "" && len(f.targets) > 0 && f.targetIndex >= 0 && f.targetIndex < len(f.targets) {
			target = f.targets[f.targetIndex]
		}
		if target == "" {
			return errors.New("SIP flow has no connected remote for keepalive")
		}
		var err error
		conn, _, timeout, err = f.ensureConnLocked(ctx, SIPRequestMessage{URI: "sip:" + target})
		if err != nil {
			return err
		}
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		f.closeConnLocked()
		return err
	}
	if _, err := conn.Write([]byte("\r\n\r\n")); err != nil {
		f.closeConnLocked()
		return err
	}
	return nil
}

func (f *WireSIPFlow) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	err := f.closeConnLocked()
	if f.securityResponseConn != nil {
		err = errors.Join(err, f.securityResponseConn.Close())
		f.securityResponseConn = nil
	}
	return err
}

func (f *WireSIPFlow) Reset() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrSIPFlowClosed
	}
	err := f.closeConnLocked()
	f.targets = nil
	f.targetIndex = 0
	return err
}

func (f *WireSIPFlow) ResetToNextTarget() (bool, error) {
	if f == nil {
		return false, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false, ErrSIPFlowClosed
	}
	err := f.closeConnLocked()
	if strings.TrimSpace(f.ServerAddr) != "" {
		return false, err
	}
	if len(f.targets) <= 1 {
		f.targets = nil
		f.targetIndex = 0
		return false, err
	}
	old := f.targetIndex
	switched := f.advanceTargetLocked() && f.targetIndex != old
	return switched, err
}

func (f *WireSIPFlow) UseSecurityAssociation(ctx context.Context, req IMSSecurityAssociationInstallRequest) error {
	if f == nil {
		return errors.New("nil SIP flow")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrSIPFlowClosed
	}
	localAddr, err := sipSecurityAssociationAddr(f.LocalAddr, req.LocalEndpoint, true)
	if err != nil {
		return err
	}
	currentTarget := firstNonEmpty(f.target, f.ServerAddr)
	remoteEndpoint := req.RemoteEndpoint
	if host, _, ok := splitIMSSecurityEndpointAddr(currentTarget); ok && strings.TrimSpace(host) != "" {
		remoteEndpoint.Address = host
	}
	remoteAddr, err := sipSecurityAssociationAddr(currentTarget, remoteEndpoint, false)
	if err != nil {
		return err
	}
	if localAddr != "" {
		f.LocalAddr = localAddr
	}
	if remoteAddr != "" {
		f.ServerAddr = remoteAddr
		f.targets = []string{remoteAddr}
		f.targetIndex = 0
	}
	if err := f.closeConnLocked(); err != nil {
		return err
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.Network)), "tcp") &&
		!strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.Network)), "tls") {
		responsePort := req.ClientAgreement.PortServer
		if responsePort > 0 {
			responseAddr := net.JoinHostPort(strings.TrimSpace(req.LocalEndpoint.Address), strconv.Itoa(responsePort))
			packet, listenErr := net.ListenPacket(sipPacketNetwork(responseAddr), responseAddr)
			if listenErr != nil {
				return listenErr
			}
			if f.securityResponseConn != nil {
				_ = f.securityResponseConn.Close()
			}
			f.securityResponseConn = packet
		}
	}
	return nil
}

func sipPacketNetwork(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil && strings.Contains(host, ":") {
		return "udp6"
	}
	return "udp4"
}

// TakeSecurityResponsePacketConn transfers the protected IMS server port to
// the inbound SIP server after REGISTER completes.
func (f *WireSIPFlow) TakeSecurityResponsePacketConn() net.PacketConn {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	packet := f.securityResponseConn
	f.securityResponseConn = nil
	if packet != nil {
		f.responseMu.Lock()
		if f.responsePacketCh == nil {
			f.responsePacketCh = make(chan []byte, 32)
		}
		f.responseExternal = true
		f.responseMu.Unlock()
	}
	return packet
}

// HandleSIPResponsePacket forwards a SIP response read by the shared protected
// inbound socket to the currently serialized client transaction. After IMS
// registration, that socket is owned by IMSInboundWireServer, while REGISTER
// refresh responses still arrive on it.
func (f *WireSIPFlow) HandleSIPResponsePacket(raw []byte) bool {
	if f == nil || !isSIPResponseWire(raw) {
		return false
	}
	f.responseMu.RLock()
	external := f.responseExternal
	ch := f.responsePacketCh
	f.responseMu.RUnlock()
	if !external || ch == nil {
		return false
	}
	packet := append([]byte(nil), raw...)
	select {
	case ch <- packet:
	default:
		// The flow serializes client transactions, so a full queue consists of
		// stale retransmissions. Drop the oldest packet before accepting new data.
		select {
		case <-ch:
		default:
		}
		select {
		case ch <- packet:
		default:
		}
	}
	return true
}

func (f *WireSIPFlow) externalResponsePackets() <-chan []byte {
	if f == nil {
		return nil
	}
	f.responseMu.RLock()
	defer f.responseMu.RUnlock()
	if !f.responseExternal {
		return nil
	}
	return f.responsePacketCh
}

func sipSecurityAssociationAddr(current string, endpoint IMSSecurityAssociationEndpoint, allowWildcardHost bool) (string, error) {
	host := strings.TrimSpace(endpoint.Address)
	port := endpoint.Port
	if strings.TrimSpace(current) != "" {
		currentHost, currentPort, ok := splitIMSSecurityEndpointAddr(current)
		if ok {
			if host == "" {
				host = strings.TrimSpace(currentHost)
			}
			if port <= 0 {
				port = parseSecurityPort(currentPort)
			}
		}
	}
	if port <= 0 {
		return "", nil
	}
	if port > 65535 {
		return "", errors.New("security association endpoint port out of range")
	}
	if host == "" && !allowWildcardHost {
		return "", nil
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func (f *WireSIPFlow) roundTrip(ctx context.Context, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler, retryStatus func(int) bool) (SIPResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if f == nil {
		return SIPResponse{}, errors.New("nil SIP flow")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	attempts := 0
	redirects := 0
	shouldRetry := func(err error) bool {
		if ctx.Err() != nil || errors.Is(err, ErrSIPFinalResponseTimeout) || !isSIPRetryableTransportError(err) {
			return false
		}
		attempts++
		if attempts >= f.targetCountLocked() {
			return false
		}
		return f.advanceTargetLocked()
	}
	shouldRetryResponse := func(resp SIPResponse) bool {
		if ctx.Err() != nil || retryStatus == nil || !retryStatus(resp.StatusCode) {
			return false
		}
		attempts++
		if attempts >= f.targetCountLocked() {
			return false
		}
		f.closeConnLocked()
		return f.advanceTargetLocked()
	}
	shouldRedirectResponse := func(resp SIPResponse) bool {
		if ctx.Err() != nil || redirects >= maxSIPRedirectTargets || !sipRedirectStatus(resp.StatusCode) ||
			strings.EqualFold(strings.TrimSpace(msg.Method), "INVITE") {
			return false
		}
		if !f.redirectToResponseTargetsLocked(resp) {
			return false
		}
		redirects++
		f.closeConnLocked()
		return true
	}
	for {
		conn, network, timeout, err := f.ensureConnLocked(ctx, msg)
		if err != nil {
			if ctx.Err() != nil {
				return SIPResponse{}, ctx.Err()
			}
			if !shouldRetry(err) {
				return SIPResponse{}, err
			}
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			f.closeConnLocked()
			if !shouldRetry(err) {
				return SIPResponse{}, err
			}
			continue
		}
		attempt := cloneSIPRequestMessage(msg)
		ensureSIPRequestVia(&attempt, transportName(network), conn.LocalAddr())
		wire, err := buildSIPRequestWire(attempt, transportName(network), conn.LocalAddr())
		if err != nil {
			return SIPResponse{}, err
		}
		if _, err := conn.Write(wire); err != nil {
			f.closeConnLocked()
			if ctx.Err() != nil {
				return SIPResponse{}, ctx.Err()
			}
			if !shouldRetry(err) {
				return SIPResponse{}, err
			}
			continue
		}
		if isSIPStreamNetwork(network) {
			resp, err := readFinalSIPFlowResponse(ctx, f.reader, attempt, onProvisional)
			if err != nil {
				f.closeConnLocked()
				if ctx.Err() != nil {
					return SIPResponse{}, ctx.Err()
				}
				if !shouldRetry(err) {
					return SIPResponse{}, err
				}
				continue
			}
			if shouldRedirectResponse(resp) {
				continue
			}
			if shouldRetryResponse(resp) {
				continue
			}
			return resp, nil
		}
		readConn := net.Conn(conn)
		if f.securityResponseConn != nil {
			if protected, ok := f.securityResponseConn.(net.Conn); ok {
				readConn = protected
			}
		}
		resp, err := f.readUDPResponseLocked(ctx, readConn, f.externalResponsePackets(), conn, timeout, wire, attempt, onProvisional)
		if err != nil {
			f.closeConnLocked()
			if ctx.Err() != nil {
				return SIPResponse{}, ctx.Err()
			}
			if !shouldRetry(err) {
				return SIPResponse{}, err
			}
			continue
		}
		if shouldRedirectResponse(resp) {
			continue
		}
		if shouldRetryResponse(resp) {
			continue
		}
		return resp, nil
	}
}

func (f *WireSIPFlow) readUDPResponseLocked(ctx context.Context, readConn net.Conn, responsePackets <-chan []byte, writeConn net.Conn, timeout time.Duration, wire []byte, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler) (SIPResponse, error) {
	buf := make([]byte, 65535)
	timerConfig := sipFlowTransactionTimerConfig(msg.Method, timeout, f.RetransmitInterval, f.MaxRetransmitInterval)
	interval := timerConfig.T1
	deadline := time.Now().Add(timeout)
	retransmits := 0
	state := InitialSIPClientTransactionState(msg.Method)
	retransmitExhausted := false
	for {
		readInterval := interval
		if retransmitExhausted || !sipClientTransactionRetransmitTimerActive(msg.Method, state) {
			readInterval = time.Until(deadline)
		}
		readDeadline := nextSIPReadDeadline(deadline, readInterval)
		n, err := readSIPFlowUDPDatagram(ctx, readConn, responsePackets, readDeadline, buf)
		if err != nil {
			if ctx.Err() != nil {
				return SIPResponse{}, ctx.Err()
			}
			if !isSIPTimeout(err) || !time.Now().Before(deadline) {
				if state == SIPClientTransactionStateProceeding && isSIPTimeout(err) {
					return SIPResponse{}, sipFinalResponseTimeoutError{Method: msg.Method, Err: err}
				}
				return SIPResponse{}, err
			}
			step := AdvanceSIPClientTransaction(SIPClientTransactionInput{
				Method:                   msg.Method,
				State:                    state,
				Event:                    SIPClientTransactionEventRetransmitTimer,
				LastRetransmitInterval:   interval,
				TimerConfig:              timerConfig,
				MaxRetransmits:           f.MaxRetransmits,
				CompletedRetransmissions: retransmits,
			})
			state = step.NextState
			if !retransmitExhausted && step.RetransmitRequest {
				if _, writeErr := writeConn.Write(wire); writeErr != nil {
					return SIPResponse{}, writeErr
				}
				retransmits++
				interval = step.NextRetransmitInterval
				continue
			}
			if !sipClientTransactionRetransmitTimerActive(msg.Method, state) || !shouldSIPRetransmit(retransmits, f.MaxRetransmits) {
				retransmitExhausted = true
				continue
			}
			return SIPResponse{}, err
		}
		if !isSIPResponseWire(buf[:n]) {
			continue
		}
		resp, err := ParseSIPResponse(buf[:n])
		if err != nil {
			return SIPResponse{}, err
		}
		if !sipResponseMatchesRequest(resp, msg) {
			continue
		}
		step := AdvanceSIPClientTransaction(SIPClientTransactionInput{
			Method:      msg.Method,
			State:       state,
			Event:       SIPClientTransactionEventResponse,
			Response:    resp,
			TimerConfig: timerConfig,
		})
		state = step.NextState
		if step.Final && step.DeliverResponse {
			if responsePackets != nil {
				drainSIPFlowExternalFinalResponses(ctx, responsePackets, msg, sipFinalResponseDrainDuration(msg.Method, f.FinalResponseDrain))
			} else {
				drainSIPUDPFinalResponses(ctx, readConn, msg, sipFinalResponseDrainDuration(msg.Method, f.FinalResponseDrain))
			}
			return resp, nil
		}
		if step.Provisional && step.DeliverResponse && onProvisional != nil && shouldReportSIPProvisionalResponse(msg.Method) {
			if err := onProvisional(ctx, msg, resp); err != nil {
				return SIPResponse{}, err
			}
		}
	}
}

type sipFlowPacketTimeoutError struct{}

func (sipFlowPacketTimeoutError) Error() string   { return "SIP packet read timeout" }
func (sipFlowPacketTimeoutError) Timeout() bool   { return true }
func (sipFlowPacketTimeoutError) Temporary() bool { return true }

func readSIPFlowUDPDatagram(ctx context.Context, readConn net.Conn, responsePackets <-chan []byte, deadline time.Time, buf []byte) (int, error) {
	if responsePackets == nil {
		if err := readConn.SetReadDeadline(deadline); err != nil {
			return 0, err
		}
		return readConn.Read(buf)
	}
	wait := time.Until(deadline)
	if wait <= 0 {
		return 0, sipFlowPacketTimeoutError{}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-timer.C:
		return 0, sipFlowPacketTimeoutError{}
	case raw := <-responsePackets:
		return copy(buf, raw), nil
	}
}

func drainSIPFlowExternalFinalResponses(ctx context.Context, responsePackets <-chan []byte, msg SIPRequestMessage, duration time.Duration) {
	if duration <= 0 || responsePackets == nil {
		return
	}
	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case raw := <-responsePackets:
			resp, err := ParseSIPResponse(raw)
			if err != nil || !sipResponseMatchesRequest(resp, msg) || isSIPProvisionalResponse(resp.StatusCode) {
				continue
			}
		}
	}
}

func readFinalSIPFlowResponse(ctx context.Context, reader *bufio.Reader, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler) (SIPResponse, error) {
	gotResponse := false
	for {
		raw, err := readSIPStreamMessage(reader)
		if err != nil {
			if gotResponse && isSIPTimeout(err) {
				return SIPResponse{}, sipFinalResponseTimeoutError{Method: msg.Method, Err: err}
			}
			return SIPResponse{}, err
		}
		resp, err := ParseSIPResponse(raw)
		if err != nil {
			return SIPResponse{}, err
		}
		if !sipResponseMatchesRequest(resp, msg) {
			continue
		}
		if !isSIPProvisionalResponse(resp.StatusCode) {
			return resp, nil
		}
		if onProvisional != nil && shouldReportSIPProvisionalResponse(msg.Method) {
			if err := onProvisional(ctx, msg, resp); err != nil {
				return SIPResponse{}, err
			}
		}
		gotResponse = true
	}
}

func sipFlowTransactionTimerConfig(method string, timeout, retransmitInterval, maxRetransmitInterval time.Duration) SIPTransactionTimerConfig {
	return SIPTransactionTimerConfig{
		T1: sipRetransmitInterval(method, timeout, retransmitInterval),
		T2: sipMaxRetransmitInterval(method, timeout, maxRetransmitInterval),
	}
}

func (f *WireSIPFlow) ensureConnLocked(ctx context.Context, msg SIPRequestMessage) (net.Conn, string, time.Duration, error) {
	if f.closed {
		return nil, "", 0, ErrSIPFlowClosed
	}
	network := sipNetworkForRequest(f.Network, msg.URI)
	if strings.TrimSpace(f.Network) == "" && f.conn != nil && strings.TrimSpace(f.network) != "" {
		network = f.network
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if f.conn != nil && f.network == network && (strings.TrimSpace(f.ServerAddr) == "" || f.target == strings.TrimSpace(f.ServerAddr)) {
		return f.conn, network, timeout, nil
	}
	targets, err := f.ensureTargetsLocked(ctx, network, msg.URI)
	if err != nil {
		return nil, "", 0, err
	}
	if len(targets) == 0 {
		return nil, "", 0, errSIPDNSResolverEmpty()
	}
	target := targets[f.targetIndex]
	if f.conn != nil && f.network == network && f.target == target {
		return f.conn, network, timeout, nil
	}
	_ = f.closeConnLocked()
	conn, err := dialSIPConn(ctx, network, target, f.LocalAddr, timeout, f.TLSConfig, sipTLSServerNameForURI(msg.URI))
	if err != nil {
		return nil, "", 0, err
	}
	f.conn = conn
	f.network = network
	f.target = target
	if isSIPStreamNetwork(network) {
		f.reader = bufio.NewReader(conn)
	} else {
		f.reader = nil
	}
	return conn, network, timeout, nil
}

func (f *WireSIPFlow) ensureTargetsLocked(ctx context.Context, network, uri string) ([]string, error) {
	if target := strings.TrimSpace(f.ServerAddr); target != "" {
		if len(f.targets) == 0 || f.targets[0] != target {
			f.targets = []string{target}
			f.targetIndex = 0
		}
		if f.targetIndex < 0 || f.targetIndex >= len(f.targets) {
			f.targetIndex = 0
		}
		return f.targets, nil
	}
	if len(f.targets) == 0 {
		targets, err := resolveSIPServerAddrs(ctx, f.Resolver, network, uri)
		if err != nil {
			return nil, err
		}
		f.targets = appendSIPTargets(nil, targets...)
		f.targetIndex = 0
	}
	if f.targetIndex < 0 || f.targetIndex >= len(f.targets) {
		f.targetIndex = 0
	}
	return f.targets, nil
}

func (f *WireSIPFlow) redirectToResponseTargetsLocked(resp SIPResponse) bool {
	targets, nextIndex, ok := sipTargetsWithRedirects(f.targets, f.targetIndex, sipRedirectTargets(resp))
	if !ok {
		return false
	}
	f.targets = targets
	f.targetIndex = nextIndex
	return true
}

func (f *WireSIPFlow) advanceTargetLocked() bool {
	if len(f.targets) <= 1 {
		return false
	}
	f.targetIndex = (f.targetIndex + 1) % len(f.targets)
	return true
}

func (f *WireSIPFlow) targetCountLocked() int {
	if len(f.targets) == 0 {
		return 1
	}
	return len(f.targets)
}

func (f *WireSIPFlow) closeConnLocked() error {
	if f.conn == nil {
		f.reader = nil
		f.network = ""
		f.target = ""
		return nil
	}
	err := f.conn.Close()
	f.conn = nil
	f.reader = nil
	f.network = ""
	f.target = ""
	return err
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneSIPRequestMessage(msg SIPRequestMessage) SIPRequestMessage {
	msg.Headers = cloneStringMap(msg.Headers)
	msg.Body = append([]byte(nil), msg.Body...)
	return msg
}
