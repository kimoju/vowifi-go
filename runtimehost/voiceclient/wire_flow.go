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

const sipInboundInviteHandlerTimeout = 2 * time.Minute

type sipFinalResponseTimeoutError struct {
	Method string
	Err    error
}

// SIPIncomingRequestHandler turns an unsolicited SIP request into one or more
// complete SIP response datagrams. The flow owns the socket and writes the
// returned datagrams from the same protected endpoint that received the
// request.
type SIPIncomingRequestHandler func(context.Context, SIPIncomingRequest) ([][]byte, error)

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

	mu                  sync.Mutex
	conn                net.Conn
	securityReceiveConn net.Conn
	incomingHandler     SIPIncomingRequestHandler
	reader              *bufio.Reader
	network             string
	target              string
	targets             []string
	targetIndex         int
	closed              bool
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
	if f.conn == nil {
		return endpointHost(f.LocalAddr), endpointHost(firstNonEmpty(f.target, f.ServerAddr))
	}
	return endpointHost(f.conn.LocalAddr().String()), endpointHost(f.conn.RemoteAddr().String())
}

func endpointHost(value string) string {
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

// SetIncomingRequestHandler installs the handler used for unsolicited SIP
// requests received on this flow, including requests that arrive while a
// client transaction is waiting for its response.
func (f *WireSIPFlow) SetIncomingRequestHandler(handler SIPIncomingRequestHandler) error {
	if f == nil {
		return errors.New("nil SIP flow")
	}
	if handler == nil {
		return errors.New("nil SIP incoming request handler")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrSIPFlowClosed
	}
	f.incomingHandler = handler
	return nil
}

// ServeIncomingRequests continuously drains unsolicited UDP SIP requests.
// Round trips and this loop share the flow lock so only one reader can consume
// a protected socket datagram at a time.
func (f *WireSIPFlow) ServeIncomingRequests(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if f == nil {
		return errors.New("nil SIP flow")
	}
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil {
			return nil
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return nil
		}
		handler := f.incomingHandler
		conn := f.securityReceiveConn
		if conn == nil {
			conn = f.conn
		}
		if handler == nil || conn == nil || isSIPStreamNetwork(f.network) {
			f.mu.Unlock()
			if !waitSIPIncomingPoll(ctx, 50*time.Millisecond) {
				return nil
			}
			continue
		}
		if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			f.mu.Unlock()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		n, err := conn.Read(buf)
		if err == nil && n > 0 && !isSIPResponseWire(buf[:n]) {
			err = f.handleIncomingRequestLocked(ctx, conn, buf[:n])
		}
		f.mu.Unlock()
		if err == nil || isSIPTimeout(err) {
			continue
		}
		if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func waitSIPIncomingPoll(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func sipOperationDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if ctx != nil {
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			return ctxDeadline
		}
	}
	return deadline
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
		if err := conn.SetDeadline(sipOperationDeadline(ctx, timeout)); err != nil {
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
	if err := conn.SetDeadline(sipOperationDeadline(ctx, timeout)); err != nil {
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
	return f.closeConnLocked()
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
	receiveLocalEndpoint := req.LocalEndpoint
	receiveLocalEndpoint.Port = req.ClientAgreement.PortServer
	receiveLocalAddr, err := sipSecurityAssociationAddr(f.LocalAddr, receiveLocalEndpoint, true)
	if err != nil {
		return err
	}
	receiveRemoteEndpoint := remoteEndpoint
	receiveRemoteEndpoint.Port = req.Agreement.PortClient
	receiveRemoteAddr, err := sipSecurityAssociationAddr(currentTarget, receiveRemoteEndpoint, false)
	if err != nil {
		return err
	}
	if err := f.closeConnLocked(); err != nil {
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
	if receiveLocalAddr == "" || receiveRemoteAddr == "" || req.ClientAgreement.PortServer <= 0 || req.Agreement.PortClient <= 0 {
		return nil
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	receiveConn, err := dialSIPConn(ctx, "udp", receiveRemoteAddr, receiveLocalAddr, timeout, nil, "")
	if err != nil {
		return err
	}
	f.securityReceiveConn = receiveConn
	return nil
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
		if err := conn.SetDeadline(sipOperationDeadline(ctx, timeout)); err != nil {
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
		resp, err := f.readUDPResponseLocked(ctx, conn, timeout, wire, attempt, onProvisional)
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

func (f *WireSIPFlow) readUDPResponseLocked(ctx context.Context, conn net.Conn, timeout time.Duration, wire []byte, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler) (SIPResponse, error) {
	buf := make([]byte, 65535)
	timerConfig := sipFlowTransactionTimerConfig(msg.Method, timeout, f.RetransmitInterval, f.MaxRetransmitInterval)
	interval := timerConfig.T1
	deadline := sipOperationDeadline(ctx, timeout)
	retransmits := 0
	state := InitialSIPClientTransactionState(msg.Method)
	retransmitExhausted := false
	for {
		readInterval := interval
		if retransmitExhausted || !sipClientTransactionRetransmitTimerActive(msg.Method, state) {
			readInterval = time.Until(deadline)
		}
		if err := conn.SetReadDeadline(nextSIPReadDeadline(deadline, readInterval)); err != nil {
			return SIPResponse{}, err
		}
		n, source, err := f.readUDPDatagramLocked(conn, buf, nextSIPReadDeadline(deadline, readInterval))
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
				if _, writeErr := conn.Write(wire); writeErr != nil {
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
			if err := f.handleIncomingRequestLocked(ctx, source, buf[:n]); err != nil {
				return SIPResponse{}, err
			}
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
			drainSIPUDPFinalResponses(ctx, conn, msg, sipFinalResponseDrainDuration(msg.Method, f.FinalResponseDrain))
			return resp, nil
		}
		if step.Provisional && step.DeliverResponse && onProvisional != nil && shouldReportSIPProvisionalResponse(msg.Method) {
			if err := onProvisional(ctx, msg, resp); err != nil {
				return SIPResponse{}, err
			}
		}
	}
}

type sipUDPReadResult struct {
	n    int
	err  error
	buf  []byte
	conn net.Conn
}

func (f *WireSIPFlow) readUDPDatagramLocked(primary net.Conn, buf []byte, deadline time.Time) (int, net.Conn, error) {
	secondary := f.securityReceiveConn
	if secondary == nil || secondary == primary {
		if err := primary.SetReadDeadline(deadline); err != nil {
			return 0, nil, err
		}
		n, err := primary.Read(buf)
		return n, primary, err
	}
	primaryBuf := make([]byte, len(buf))
	secondaryBuf := make([]byte, len(buf))
	results := make(chan sipUDPReadResult, 2)
	read := func(conn net.Conn, target []byte) {
		if err := conn.SetReadDeadline(deadline); err != nil {
			results <- sipUDPReadResult{err: err, buf: target, conn: conn}
			return
		}
		n, err := conn.Read(target)
		results <- sipUDPReadResult{n: n, err: err, buf: target, conn: conn}
	}
	go read(primary, primaryBuf)
	go read(secondary, secondaryBuf)
	first := <-results
	if first.err == nil {
		_ = primary.SetReadDeadline(time.Now())
		_ = secondary.SetReadDeadline(time.Now())
		<-results
		copy(buf, first.buf[:first.n])
		return first.n, first.conn, nil
	}
	second := <-results
	if second.err == nil {
		copy(buf, second.buf[:second.n])
		return second.n, second.conn, nil
	}
	return 0, nil, first.err
}

func (f *WireSIPFlow) handleIncomingRequestLocked(ctx context.Context, conn net.Conn, raw []byte) error {
	if f == nil || f.incomingHandler == nil || conn == nil {
		return nil
	}
	req, err := ParseSIPRequest(raw)
	if err != nil {
		return nil
	}
	handler := f.incomingHandler
	if strings.EqualFold(req.Method, "INVITE") {
		// An inbound INVITE remains open while the browser is ringing. Running
		// it on the socket reader would prevent the same IMS flow from reading
		// the matching CANCEL, leaving a canceled call stuck in the UI. Send the
		// mandatory transaction progress response before detaching: a SIP UAC
		// cannot send CANCEL until it has received a provisional response.
		trying, buildErr := BuildSIPResponseWire(req, 100, "Trying", nil, nil)
		if buildErr != nil {
			return buildErr
		}
		if _, writeErr := conn.Write(trying); writeErr != nil {
			return writeErr
		}
		handlerBase := context.Background()
		if ctx != nil {
			handlerBase = context.WithoutCancel(ctx)
		}
		handlerCtx, cancel := context.WithTimeout(handlerBase, sipInboundInviteHandlerTimeout)
		go func() {
			defer cancel()
			_ = writeSIPIncomingHandlerResponses(handlerCtx, conn, handler, req)
		}()
		return nil
	}
	handlerCtx := ctx
	if handlerCtx == nil || handlerCtx.Err() != nil {
		handlerCtx = context.Background()
	}
	return writeSIPIncomingHandlerResponses(handlerCtx, conn, handler, req)
}

func writeSIPIncomingHandlerResponses(ctx context.Context, conn net.Conn, handler SIPIncomingRequestHandler, req SIPIncomingRequest) error {
	wires, _ := handler(ctx, req)
	for _, wire := range wires {
		if len(wire) == 0 {
			continue
		}
		if _, err := conn.Write(wire); err != nil {
			return err
		}
	}
	return nil
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
	_ = f.closePrimaryConnLocked()
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
	err := f.closePrimaryConnLocked()
	if f.securityReceiveConn != nil {
		err = errors.Join(err, f.securityReceiveConn.Close())
		f.securityReceiveConn = nil
	}
	return err
}

func (f *WireSIPFlow) closePrimaryConnLocked() error {
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
