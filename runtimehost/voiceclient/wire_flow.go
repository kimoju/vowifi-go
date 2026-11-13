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
	"syscall"
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
	Targets               []string
	LocalAddr             string
	LocalIPv4             string
	LocalIPv6             string
	Resolver              SIPServerResolver
	Timeout               time.Duration
	RetransmitInterval    time.Duration
	MaxRetransmitInterval time.Duration
	MaxRetransmits        int
	FinalResponseDrain    time.Duration
	TLSConfig             *tls.Config

	mu                        sync.Mutex
	conn                      net.Conn
	tcpConn                   net.Conn
	tcpReader                 *bufio.Reader
	tcpNetwork                string
	tcpTarget                 string
	targetTransports          map[string]string
	securityResponseConn      net.PacketConn
	securityResponseAddr      string
	securityAssociationActive bool
	reservedPortC             int
	reservedPortS             int
	releaseReservedPorts      func()
	unprotectedLocalAddr      string
	unprotectedLocalSaved     bool
	unprotectedTargets        []string
	pendingDatagrams          [][]byte
	reader                    *bufio.Reader
	network                   string
	target                    string
	targets                   []string
	targetIndex               int
	closed                    bool

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
		reqMsg := cloneSIPRequestMessage(msg)
		if attempts > 0 && !strings.EqualFold(strings.TrimSpace(reqMsg.Method), "CANCEL") && !strings.EqualFold(strings.TrimSpace(reqMsg.Method), "ACK") {
			refreshHeaderViaBranch(reqMsg.Headers)
		}
		conn, network, explicitURI, timeout, err := f.ensureConnWithTransportLocked(ctx, reqMsg)
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
		attempt := cloneSIPRequestMessage(reqMsg)
		ensureSIPRequestVia(&attempt, transportName(network), conn.LocalAddr())
		wire, err := buildSIPRequestWire(attempt, transportName(network), conn.LocalAddr())
		if err != nil {
			return err
		}
		if isSIPUDPNetwork(network) && !explicitURI && len(wire) > sipUDPMaxPayloadSize &&
			!strings.EqualFold(strings.TrimSpace(attempt.Method), "CANCEL") {
			if tcpErr := f.writeStreamFallbackLocked(ctx, sipTCPFallbackNetwork(network), f.target, timeout, reqMsg); tcpErr == nil {
				return nil
			} else if !errors.Is(tcpErr, syscall.ECONNREFUSED) {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if !shouldRetry(tcpErr) {
					return tcpErr
				}
				continue
			}
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
	f.pendingDatagrams = nil
	if f.releaseReservedPorts != nil {
		f.releaseReservedPorts()
		f.releaseReservedPorts = nil
		f.reservedPortC = 0
		f.reservedPortS = 0
	}
	err := f.closeConnLocked()
	if f.securityResponseConn != nil {
		err = errors.Join(err, f.securityResponseConn.Close())
		f.securityResponseConn = nil
	}
	return err
}

// EnsureSecurityClientPorts reserves and returns a conflict-free (port-c, port-s)
// pair for this flow, reusing any pair already owned by this flow across
// re-registration and recovery.
func (f *WireSIPFlow) EnsureSecurityClientPorts(localHost string) (int, int) {
	if f == nil {
		portC, portS, release := AllocateSecurityClientPorts(localHost, 0, 0)
		if release != nil {
			release()
		}
		return portC, portS
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reservedPortC > 0 && f.reservedPortS > 0 {
		return f.reservedPortC, f.reservedPortS
	}
	ownedPortS := f.ownedPortSLocked()
	host := strings.TrimSpace(localHost)
	if host == "" {
		host = sipEndpointHost(f.LocalAddr)
	}
	portC, portS, release := AllocateSecurityClientPorts(host, 0, ownedPortS)
	f.reservedPortC = portC
	f.reservedPortS = portS
	f.releaseReservedPorts = release
	return portC, portS
}

// ReleaseUnusedSecurityClientPorts frees pre-reserved security ports if no
// security association was established on this flow.
func (f *WireSIPFlow) ReleaseUnusedSecurityClientPorts() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.securityAssociationActive {
		return
	}
	if f.releaseReservedPorts != nil {
		f.releaseReservedPorts()
		f.releaseReservedPorts = nil
		f.reservedPortC = 0
		f.reservedPortS = 0
	}
}

func (f *WireSIPFlow) ownedPortSLocked() int {
	if f.securityResponseConn != nil && f.securityResponseConn.LocalAddr() != nil {
		if p := udpAddrPort(f.securityResponseConn.LocalAddr()); p > 0 {
			return p
		}
	}
	if f.securityResponseAddr != "" {
		if _, portStr, err := net.SplitHostPort(f.securityResponseAddr); err == nil {
			if p, pErr := strconv.Atoi(portStr); pErr == nil && p > 0 {
				return p
			}
		}
	}
	return 0
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
	f.pendingDatagrams = nil
	if f.unprotectedLocalSaved {
		f.LocalAddr = f.unprotectedLocalAddr
	}
	if len(f.Targets) > 0 {
		f.targets = appendSIPTargets(nil, f.Targets...)
		f.unprotectedTargets = append([]string(nil), f.targets...)
	} else {
		f.targets = nil
		f.unprotectedTargets = nil
	}
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
	f.pendingDatagrams = nil
	if f.unprotectedLocalSaved {
		f.LocalAddr = f.unprotectedLocalAddr
	}
	if strings.TrimSpace(f.ServerAddr) != "" {
		return false, err
	}
	if len(f.targets) == 0 && len(f.Targets) > 0 {
		f.targets = appendSIPTargets(nil, f.Targets...)
		f.unprotectedTargets = append([]string(nil), f.targets...)
	}
	if len(f.targets) <= 1 {
		f.targets = nil
		f.unprotectedTargets = nil
		f.targetIndex = 0
		return false, err
	}
	if f.targetIndex >= 0 && f.targetIndex < len(f.unprotectedTargets) && f.unprotectedTargets[f.targetIndex] != "" {
		f.targets[f.targetIndex] = f.unprotectedTargets[f.targetIndex]
	}
	old := f.targetIndex
	switched := f.advanceTargetLocked() && f.targetIndex != old
	return switched, err
}

func (f *WireSIPFlow) UseSecurityAssociation(ctx context.Context, req IMSSecurityAssociationInstallRequest) error {
	_ = ctx
	if f == nil {
		return errors.New("nil SIP flow")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrSIPFlowClosed
	}
	if !f.unprotectedLocalSaved {
		f.unprotectedLocalAddr = f.LocalAddr
		f.unprotectedLocalSaved = true
	}
	localAddr, err := sipSecurityAssociationAddr(f.LocalAddr, req.LocalEndpoint, true)
	if err != nil {
		return err
	}
	currentTarget := firstNonEmpty(f.target, f.ServerAddr)
	if currentTarget == "" && len(f.targets) > 0 && f.targetIndex >= 0 && f.targetIndex < len(f.targets) {
		currentTarget = f.targets[f.targetIndex]
	}
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
		if strings.TrimSpace(f.ServerAddr) != "" {
			f.ServerAddr = remoteAddr
			f.targets = []string{remoteAddr}
			f.targetIndex = 0
		} else {
			if len(f.targets) == 0 && len(f.Targets) > 0 {
				f.targets = appendSIPTargets(nil, f.Targets...)
				f.unprotectedTargets = append([]string(nil), f.targets...)
			}
			if len(f.targets) == 0 {
				f.targets = []string{remoteAddr}
				f.unprotectedTargets = []string{remoteAddr}
				f.targetIndex = 0
			} else {
				if f.targetIndex < 0 || f.targetIndex >= len(f.targets) {
					f.targetIndex = 0
				}
				if len(f.unprotectedTargets) != len(f.targets) {
					f.unprotectedTargets = append([]string(nil), f.targets...)
				}
				f.targets[f.targetIndex] = remoteAddr
			}
		}
	}
	f.pendingDatagrams = nil
	if err := f.closeConnLocked(); err != nil {
		return err
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.Network)), "tcp") &&
		!strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.Network)), "tls") {
		responsePort := req.ClientAgreement.PortServer
		if responsePort > 0 {
			responseAddr := net.JoinHostPort(strings.TrimSpace(req.LocalEndpoint.Address), strconv.Itoa(responsePort))
			if f.isExternalResponseAddrLocked(responseAddr) {
				f.drainExternalResponseChannel()
			} else if f.securityResponseConn != nil && sameUDPListenAddr(f.securityResponseConn.LocalAddr().String(), responseAddr) {
				// Already listening on the requested port-s socket; keep it open.
			} else {
				packet, listenErr := net.ListenPacket(sipPacketNetwork(responseAddr), responseAddr)
				if listenErr != nil {
					return listenErr
				}
				if f.securityResponseConn != nil {
					_ = f.securityResponseConn.Close()
				}
				f.securityResponseConn = packet
				if packet.LocalAddr() != nil {
					f.securityResponseAddr = packet.LocalAddr().String()
				} else {
					f.securityResponseAddr = responseAddr
				}
				f.responseMu.Lock()
				f.responseExternal = false
				f.responseMu.Unlock()
			}
		}
	}
	f.securityAssociationActive = true
	return nil
}

func (f *WireSIPFlow) isExternalResponseAddrLocked(responseAddr string) bool {
	f.responseMu.RLock()
	external := f.responseExternal
	f.responseMu.RUnlock()
	if !external {
		return false
	}
	return sameUDPListenAddr(f.securityResponseAddr, responseAddr)
}

func (f *WireSIPFlow) drainExternalResponseChannel() {
	f.responseMu.RLock()
	ch := f.responsePacketCh
	f.responseMu.RUnlock()
	if ch == nil {
		return
	}
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func sameUDPListenAddr(a, b string) bool {
	hostA, portA, errA := net.SplitHostPort(strings.TrimSpace(a))
	hostB, portB, errB := net.SplitHostPort(strings.TrimSpace(b))
	if errA != nil || errB != nil || portA != portB || portA == "" || portA == "0" {
		return false
	}
	ipA := net.ParseIP(strings.Trim(hostA, "[]"))
	ipB := net.ParseIP(strings.Trim(hostB, "[]"))
	if ipA != nil && ipB != nil {
		if ipA.IsUnspecified() || ipB.IsUnspecified() {
			return (ipA.To4() == nil) == (ipB.To4() == nil)
		}
		return ipA.Equal(ipB)
	}
	if hostA == "" || hostB == "" {
		return true
	}
	return strings.EqualFold(strings.Trim(hostA, "[]"), strings.Trim(hostB, "[]"))
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
		if packet.LocalAddr() != nil {
			f.securityResponseAddr = packet.LocalAddr().String()
		}
		f.responseMu.Lock()
		if f.responsePacketCh == nil {
			f.responsePacketCh = make(chan []byte, 32)
		}
		f.responseExternal = true
		f.responseMu.Unlock()
	}
	return packet
}

// BindExternalResponseAddr registers an externally owned inbound UDP listener
// address so SIP responses forwarded via HandleSIPResponsePacket are accepted
// and UseSecurityAssociation reuses the shared port-s socket without EADDRINUSE.
func (f *WireSIPFlow) BindExternalResponseAddr(addr string) {
	if f == nil {
		return
	}
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return
	}
	f.mu.Lock()
	f.securityResponseAddr = addr
	f.mu.Unlock()
	f.responseMu.Lock()
	if f.responsePacketCh == nil {
		f.responsePacketCh = make(chan []byte, 32)
	}
	f.responseExternal = true
	f.responseMu.Unlock()
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
		reqMsg := cloneSIPRequestMessage(msg)
		if attempts > 0 || redirects > 0 {
			refreshHeaderViaBranch(reqMsg.Headers)
		}
		conn, network, explicitURI, timeout, err := f.ensureConnWithTransportLocked(ctx, reqMsg)
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
		attempt := cloneSIPRequestMessage(reqMsg)
		ensureSIPRequestVia(&attempt, transportName(network), conn.LocalAddr())
		wire, err := buildSIPRequestWire(attempt, transportName(network), conn.LocalAddr())
		if err != nil {
			return SIPResponse{}, err
		}
		if isSIPUDPNetwork(network) && !explicitURI && len(wire) > sipUDPMaxPayloadSize &&
			!strings.EqualFold(strings.TrimSpace(attempt.Method), "CANCEL") {
			resp, tcpVia, tcpErr := f.roundTripStreamFallbackLocked(ctx, sipTCPFallbackNetwork(network), f.target, timeout, reqMsg, false, onProvisional)
			if tcpErr == nil {
				if shouldRedirectResponse(resp) {
					continue
				}
				if shouldRetryResponse(resp) {
					continue
				}
				writeBackGeneratedSIPVia(msg.Headers, tcpVia)
				return resp, nil
			}
			if !errors.Is(tcpErr, syscall.ECONNREFUSED) {
				if ctx.Err() != nil {
					return SIPResponse{}, ctx.Err()
				}
				if !shouldRetry(tcpErr) {
					return SIPResponse{}, tcpErr
				}
				continue
			}
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
			reader := f.reader
			if conn == f.tcpConn && f.tcpReader != nil {
				reader = f.tcpReader
			}
			resp, err := readFinalSIPFlowResponse(ctx, reader, attempt, onProvisional)
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
			writeBackGeneratedSIPVia(msg.Headers, firstHeaderValue(attempt.Headers, "Via"))
			return resp, nil
		}
		f.pendingDatagrams = nil
		resp, err := f.readUDPResponseLocked(ctx, conn, f.securityResponseConn, f.externalResponsePackets(), timeout, wire, attempt, onProvisional)
		if err != nil {
			if ctx.Err() != nil {
				return SIPResponse{}, ctx.Err()
			}
			f.closeConnLocked()
			if !shouldRetry(err) {
				return SIPResponse{}, err
			}
			continue
		}
		sentVia := firstHeaderValue(attempt.Headers, "Via")
		if resp.StatusCode == 513 && !explicitURI {
			tcpResp, tcpVia, tcpErr := f.roundTripStreamFallbackLocked(ctx, sipTCPFallbackNetwork(network), f.target, timeout, reqMsg, true, onProvisional)
			if tcpErr != nil {
				return SIPResponse{}, tcpErr
			}
			resp = tcpResp
			sentVia = tcpVia
		}
		if shouldRedirectResponse(resp) {
			continue
		}
		if shouldRetryResponse(resp) {
			continue
		}
		writeBackGeneratedSIPVia(msg.Headers, sentVia)
		return resp, nil
	}
}

func (f *WireSIPFlow) readUDPResponseLocked(ctx context.Context, writeConn net.Conn, protectedConn net.PacketConn, responsePackets <-chan []byte, timeout time.Duration, wire []byte, msg SIPRequestMessage, onProvisional ProvisionalResponseHandler) (SIPResponse, error) {
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
		n, err := f.readNextUDPDatagramLocked(ctx, writeConn, protectedConn, responsePackets, readDeadline, buf)
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
			f.drainUDPFinalResponsesLocked(ctx, writeConn, protectedConn, responsePackets, msg, sipFinalResponseDrainDuration(msg.Method, f.FinalResponseDrain))
			f.pendingDatagrams = nil
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

type sipUDPReadResult struct {
	data []byte
	err  error
}

func (f *WireSIPFlow) readNextUDPDatagramLocked(ctx context.Context, conn net.Conn, protectedConn net.PacketConn, responsePackets <-chan []byte, deadline time.Time, buf []byte) (int, error) {
	if len(f.pendingDatagrams) > 0 {
		pkt := f.pendingDatagrams[0]
		f.pendingDatagrams = f.pendingDatagrams[1:]
		return copy(buf, pkt), nil
	}
	if protectedConn == nil && responsePackets == nil {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return 0, err
		}
		if ctx != nil && ctx.Done() != nil {
			stop := context.AfterFunc(ctx, func() {
				_ = conn.SetReadDeadline(time.Unix(1, 0))
			})
			defer func() {
				stop()
				_ = conn.SetReadDeadline(time.Time{})
			}()
		}
		n, err := conn.Read(buf)
		if ctx != nil && ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return n, err
	}

	if responsePackets != nil {
		select {
		case raw := <-responsePackets:
			return copy(buf, raw), nil
		default:
		}
	}

	wait := time.Until(deadline)
	if wait <= 0 {
		return 0, sipFlowPacketTimeoutError{}
	}

	results := make(chan sipUDPReadResult, 2)
	var wg sync.WaitGroup
	activeReaders := 0

	if conn != nil {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return 0, err
		}
		activeReaders++
		wg.Add(1)
		go func() {
			defer wg.Done()
			tmp := make([]byte, 65535)
			n, rErr := conn.Read(tmp)
			if rErr != nil {
				results <- sipUDPReadResult{err: rErr}
				return
			}
			results <- sipUDPReadResult{data: append([]byte(nil), tmp[:n]...)}
		}()
	}

	if protectedConn != nil && !samePacketAndConn(protectedConn, conn) {
		if err := protectedConn.SetReadDeadline(deadline); err != nil {
			if conn != nil {
				_ = conn.SetReadDeadline(time.Unix(1, 0))
			}
			wg.Wait()
			return 0, err
		}
		activeReaders++
		wg.Add(1)
		go func() {
			defer wg.Done()
			tmp := make([]byte, 65535)
			n, _, rErr := protectedConn.ReadFrom(tmp)
			if rErr != nil {
				results <- sipUDPReadResult{err: rErr}
				return
			}
			results <- sipUDPReadResult{data: append([]byte(nil), tmp[:n]...)}
		}()
	}

	finishReaders := func() {
		if conn != nil {
			_ = conn.SetReadDeadline(time.Unix(1, 0))
		}
		if protectedConn != nil {
			_ = protectedConn.SetReadDeadline(time.Unix(1, 0))
		}
		wg.Wait()
		if conn != nil {
			_ = conn.SetReadDeadline(time.Time{})
		}
		if protectedConn != nil {
			_ = protectedConn.SetReadDeadline(time.Time{})
		}
		for {
			select {
			case extra := <-results:
				if extra.err == nil && len(extra.data) > 0 {
					f.pendingDatagrams = append(f.pendingDatagrams, extra.data)
				}
			default:
				return
			}
		}
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	var firstErr error
	for {
		select {
		case <-ctx.Done():
			finishReaders()
			return 0, ctx.Err()
		case <-timer.C:
			finishReaders()
			return 0, sipFlowPacketTimeoutError{}
		case raw := <-responsePackets:
			finishReaders()
			return copy(buf, raw), nil
		case res := <-results:
			activeReaders--
			if res.err == nil {
				finishReaders()
				return copy(buf, res.data), nil
			}
			if firstErr == nil {
				firstErr = res.err
			}
			if activeReaders == 0 && responsePackets == nil {
				finishReaders()
				if ctx.Err() != nil {
					return 0, ctx.Err()
				}
				return 0, firstErr
			}
		}
	}
}

func samePacketAndConn(pc net.PacketConn, c net.Conn) bool {
	if pc == nil || c == nil {
		return false
	}
	pa := pc.LocalAddr()
	ca := c.LocalAddr()
	if pa == nil || ca == nil {
		return false
	}
	return pa.Network() == ca.Network() && pa.String() == ca.String()
}

func (f *WireSIPFlow) drainUDPFinalResponsesLocked(ctx context.Context, conn net.Conn, protectedConn net.PacketConn, responsePackets <-chan []byte, msg SIPRequestMessage, duration time.Duration) {
	if duration <= 0 {
		return
	}
	if protectedConn == nil && responsePackets == nil {
		drainSIPUDPFinalResponses(ctx, conn, msg, duration)
		return
	}
	end := time.Now().Add(duration)
	buf := make([]byte, 65535)
	for {
		if !time.Now().Before(end) {
			return
		}
		n, err := f.readNextUDPDatagramLocked(ctx, conn, protectedConn, responsePackets, end, buf)
		if err != nil {
			return
		}
		resp, parseErr := ParseSIPResponse(buf[:n])
		if parseErr != nil || !sipResponseMatchesRequest(resp, msg) || isSIPProvisionalResponse(resp.StatusCode) {
			continue
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
	conn, network, _, timeout, err := f.ensureConnWithTransportLocked(ctx, msg)
	return conn, network, timeout, err
}

func (f *WireSIPFlow) ensureConnWithTransportLocked(ctx context.Context, msg SIPRequestMessage) (net.Conn, string, bool, time.Duration, error) {
	if f.closed {
		return nil, "", false, 0, ErrSIPFlowClosed
	}
	network, explicitURI := sipNetworkForMethodWithHeaders(msg.Method, f.Network, msg.URI, msg.Headers)
	if !explicitURI && strings.TrimSpace(f.Network) == "" && f.conn != nil && strings.TrimSpace(f.network) != "" {
		network = f.network
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	targets, err := f.ensureTargetsLocked(ctx, network, msg.URI)
	if err != nil {
		return nil, "", false, 0, err
	}
	if len(targets) == 0 {
		return nil, "", false, 0, errSIPDNSResolverEmpty()
	}
	target := targets[f.targetIndex]
	if f.targetTransports != nil {
		if override := f.targetTransports[target]; override != "" {
			network = applyNetworkFamilySuffix(override, network)
			explicitURI = true
		}
	}
	// When an individual request requires TCP/TLS while the base flow is UDP,
	// maintain a dedicated stream connection so UDP flow state stays intact.
	if isSIPStreamNetwork(network) && f.conn != nil && isSIPUDPNetwork(f.network) {
		streamConn, err := f.ensureStreamConnLocked(ctx, network, target, timeout, msg.URI)
		if err != nil {
			return nil, "", false, 0, err
		}
		return streamConn, network, explicitURI, timeout, nil
	}
	if f.conn != nil && f.network == network && f.target == target {
		return f.conn, network, explicitURI, timeout, nil
	}
	_ = f.closeConnLocked()
	localAddr := f.localAddrForTargetLocked(target)
	conn, err := dialSIPConn(ctx, network, target, localAddr, timeout, f.TLSConfig, sipTLSServerNameForURI(msg.URI))
	if err != nil {
		return nil, "", false, 0, err
	}
	f.conn = conn
	f.network = network
	f.target = target
	if isSIPStreamNetwork(network) {
		f.reader = bufio.NewReader(conn)
	} else {
		f.reader = nil
	}
	return conn, network, explicitURI, timeout, nil
}

func (f *WireSIPFlow) ensureStreamConnLocked(ctx context.Context, network, target string, timeout time.Duration, uri string) (net.Conn, error) {
	if f.tcpConn != nil && f.tcpNetwork == network && f.tcpTarget == target {
		return f.tcpConn, nil
	}
	_ = f.closeStreamConnLocked()
	localAddr := f.localAddrForTargetLocked(target)
	conn, err := dialSIPConn(ctx, network, target, localAddr, timeout, f.TLSConfig, sipTLSServerNameForURI(uri))
	if err != nil {
		return nil, err
	}
	f.tcpConn = conn
	f.tcpNetwork = network
	f.tcpTarget = target
	f.tcpReader = bufio.NewReader(conn)
	return conn, nil
}

func (f *WireSIPFlow) closeStreamConnLocked() error {
	if f.tcpConn == nil {
		f.tcpReader = nil
		f.tcpNetwork = ""
		f.tcpTarget = ""
		return nil
	}
	err := f.tcpConn.Close()
	f.tcpConn = nil
	f.tcpReader = nil
	f.tcpNetwork = ""
	f.tcpTarget = ""
	return err
}

func (f *WireSIPFlow) roundTripStreamFallbackLocked(ctx context.Context, network, target string, timeout time.Duration, msg SIPRequestMessage, freshBranch bool, onProvisional ProvisionalResponseHandler) (SIPResponse, string, error) {
	conn, err := f.ensureStreamConnLocked(ctx, network, target, timeout, msg.URI)
	if err != nil {
		return SIPResponse{}, "", err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = f.closeStreamConnLocked()
		return SIPResponse{}, "", err
	}
	attempt := cloneSIPRequestMessage(msg)
	if freshBranch {
		refreshHeaderViaBranch(attempt.Headers)
	}
	ensureSIPRequestVia(&attempt, transportName(network), conn.LocalAddr())
	sentVia := firstHeaderValue(attempt.Headers, "Via")
	wire, err := buildSIPRequestWire(attempt, transportName(network), conn.LocalAddr())
	if err != nil {
		return SIPResponse{}, "", err
	}
	if _, err := conn.Write(wire); err != nil {
		_ = f.closeStreamConnLocked()
		return SIPResponse{}, "", err
	}
	resp, err := readFinalSIPFlowResponse(ctx, f.tcpReader, attempt, onProvisional)
	if err != nil {
		_ = f.closeStreamConnLocked()
		return SIPResponse{}, "", err
	}
	return resp, sentVia, nil
}

func writeBackGeneratedSIPVia(headers map[string]string, sentVia string) {
	if headers == nil || strings.TrimSpace(sentVia) == "" {
		return
	}
	if firstHeaderValue(headers, "Via") != "" {
		return
	}
	setSIPHeader(headers, "Via", sentVia)
}

func (f *WireSIPFlow) writeStreamFallbackLocked(ctx context.Context, network, target string, timeout time.Duration, msg SIPRequestMessage) error {
	conn, err := f.ensureStreamConnLocked(ctx, network, target, timeout, msg.URI)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = f.closeStreamConnLocked()
		return err
	}
	attempt := cloneSIPRequestMessage(msg)
	ensureSIPRequestVia(&attempt, transportName(network), conn.LocalAddr())
	wire, err := buildSIPRequestWire(attempt, transportName(network), conn.LocalAddr())
	if err != nil {
		return err
	}
	if _, err := conn.Write(wire); err != nil {
		_ = f.closeStreamConnLocked()
		return err
	}
	return nil
}

func (f *WireSIPFlow) localAddrForTargetLocked(target string) string {
	localAddr := strings.TrimSpace(f.LocalAddr)
	targetHost, _, ok := splitIMSSecurityEndpointAddr(target)
	if !ok {
		return localAddr
	}
	targetIP := net.ParseIP(strings.Trim(strings.TrimSpace(targetHost), "[]"))
	if targetIP == nil {
		return localAddr
	}
	targetIsV6 := targetIP.To4() == nil
	localHost, localPort, localOK := splitIMSSecurityEndpointAddr(localAddr)
	if localOK && strings.TrimSpace(localHost) != "" {
		if localIP := net.ParseIP(strings.Trim(strings.TrimSpace(localHost), "[]")); localIP != nil {
			if (localIP.To4() == nil) == targetIsV6 {
				return localAddr
			}
		}
	}
	altHost := strings.Trim(strings.TrimSpace(f.LocalIPv4), "[]")
	if targetIsV6 {
		altHost = strings.Trim(strings.TrimSpace(f.LocalIPv6), "[]")
	}
	if altHost == "" || !isLocallyBindableSecurityHost(altHost) {
		if localOK && strings.TrimSpace(localHost) != "" {
			if localIP := net.ParseIP(strings.Trim(strings.TrimSpace(localHost), "[]")); localIP != nil && (localIP.To4() == nil) != targetIsV6 {
				return ""
			}
		}
		return localAddr
	}
	if localPort == "" {
		localPort = "0"
	}
	return net.JoinHostPort(altHost, localPort)
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
		if len(f.Targets) > 0 {
			f.targets = appendSIPTargets(nil, f.Targets...)
		} else {
			targets, err := resolveSIPServerAddrs(ctx, f.Resolver, network, uri)
			if err != nil {
				return nil, err
			}
			f.targets = appendSIPTargets(nil, targets...)
		}
		f.unprotectedTargets = append([]string(nil), f.targets...)
		f.targetIndex = 0
	}
	if f.targetIndex < 0 || f.targetIndex >= len(f.targets) {
		f.targetIndex = 0
	}
	return f.targets, nil
}

func (f *WireSIPFlow) redirectToResponseTargetsLocked(resp SIPResponse) bool {
	redirectTargets, redirectTransports := sipRedirectTargetsWithTransports(resp)
	targets, nextIndex, ok := sipTargetsWithRedirects(f.targets, f.targetIndex, redirectTargets)
	if !ok {
		return false
	}
	if len(redirectTransports) > 0 {
		if f.targetTransports == nil {
			f.targetTransports = make(map[string]string, len(redirectTransports))
		}
		for k, v := range redirectTransports {
			f.targetTransports[k] = v
		}
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
	streamErr := f.closeStreamConnLocked()
	if f.conn == nil {
		f.reader = nil
		f.network = ""
		f.target = ""
		return streamErr
	}
	err := f.conn.Close()
	f.conn = nil
	f.reader = nil
	f.network = ""
	f.target = ""
	return errors.Join(err, streamErr)
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
