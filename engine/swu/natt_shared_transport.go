package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kimoju/vowifi-go/engine/swu/ikev2"
)

// sharedNATTUDPConn demultiplexes IKE (four-byte non-ESP marker) and ESP on
// one connected UDP socket. NAT-T requires both protocols to retain the same
// outer five-tuple; separate ephemeral sockets are rejected by strict ePDGs.
type sharedNATTUDPConn struct {
	remoteAddr string
	localAddr  string
	timeout    time.Duration
	proxy      *ProxyConfig

	mu        sync.Mutex
	conn      net.Conn
	closed    bool
	closedCh  chan struct{}
	closeOnce sync.Once
	failedCh  chan struct{}
	failOnce  sync.Once
	readErr   error
	ikeRespCh chan []byte
	ikeReqCh  chan []byte
	espCh     chan []byte
	ikeMu     sync.Mutex
	writeMu   sync.Mutex
}

type sharedNATTIKETransport struct{ core *sharedNATTUDPConn }
type sharedNATTESPTransport struct{ core *sharedNATTUDPConn }

type sharedNATTESPProvider interface {
	sharedESPTransport() ESPPacketTransport
}

type ikeRequestReceiver interface {
	ReadIKERequest(context.Context) ([]byte, error)
}

type ikeMessageSender interface {
	SendIKEMessage(context.Context, []byte) error
}

func newSharedNATTTransport(remoteAddr, localAddr string, timeout time.Duration) *sharedNATTIKETransport {
	return newSharedNATTTransportWithProxy(remoteAddr, localAddr, timeout, nil)
}

func newSharedNATTTransportWithProxy(remoteAddr, localAddr string, timeout time.Duration, proxy *ProxyConfig) *sharedNATTIKETransport {
	core := &sharedNATTUDPConn{
		remoteAddr: strings.TrimSpace(remoteAddr),
		localAddr:  strings.TrimSpace(localAddr),
		timeout:    timeout,
		proxy:      cloneProxyConfig(proxy),
		closedCh:   make(chan struct{}),
		failedCh:   make(chan struct{}),
		ikeRespCh:  make(chan []byte, 32),
		ikeReqCh:   make(chan []byte, 32),
		espCh:      make(chan []byte, 512),
	}
	return &sharedNATTIKETransport{core: core}
}

func (t *sharedNATTIKETransport) sharedESPTransport() ESPPacketTransport {
	if t == nil {
		return nil
	}
	return &sharedNATTESPTransport{core: t.core}
}

func (t *sharedNATTIKETransport) ExchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	if t == nil || t.core == nil {
		return nil, ErrInvalidPacketTunnel
	}
	return t.core.exchangeIKE(ctx, request)
}

func (t *sharedNATTIKETransport) SendIKEMessage(ctx context.Context, payload []byte) error {
	if t == nil || t.core == nil {
		return ErrInvalidPacketTunnel
	}
	wire := append([]byte{0, 0, 0, 0}, payload...)
	return t.core.write(ctx, wire)
}

func (t *sharedNATTIKETransport) ReadIKERequest(ctx context.Context) ([]byte, error) {
	if t == nil || t.core == nil {
		return nil, ErrInvalidPacketTunnel
	}
	return t.core.readIKERequest(ctx)
}

func (t *sharedNATTIKETransport) proxyRouteIPs() []net.IP {
	if t == nil || t.core == nil {
		return nil
	}
	return t.core.proxyRouteIPs()
}

func (t *sharedNATTIKETransport) prepareNetworkEndpoints(ctx context.Context) (net.Addr, net.Addr, error) {
	if t == nil || t.core == nil {
		return nil, nil, ErrInvalidPacketTunnel
	}
	conn, err := t.core.ensureConn(ctx)
	if err != nil {
		return nil, nil, err
	}
	return conn.LocalAddr(), conn.RemoteAddr(), nil
}

func (t *sharedNATTIKETransport) Close() error {
	if t == nil || t.core == nil {
		return nil
	}
	return t.core.close()
}

func (t *sharedNATTESPTransport) SendESPPacket(ctx context.Context, packet []byte) error {
	if t == nil || t.core == nil || len(packet) < 8 || isNonESPMarker(packet) {
		return ErrInvalidPacketTunnel
	}
	return t.core.write(ctx, packet)
}

func (t *sharedNATTESPTransport) SendNATTKeepalive(ctx context.Context) error {
	if t == nil || t.core == nil {
		return ErrInvalidPacketTunnel
	}
	return t.core.write(ctx, []byte{0xff})
}

func (t *sharedNATTESPTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	if t == nil || t.core == nil {
		return nil, ErrInvalidPacketTunnel
	}
	return t.core.readESP(ctx)
}

func (t *sharedNATTESPTransport) SendIKEMessage(ctx context.Context, payload []byte) error {
	if t == nil || t.core == nil {
		return ErrInvalidPacketTunnel
	}
	wire := append([]byte{0, 0, 0, 0}, payload...)
	return t.core.write(ctx, wire)
}

func (t *sharedNATTESPTransport) ReadIKERequest(ctx context.Context) ([]byte, error) {
	if t == nil || t.core == nil {
		return nil, ErrInvalidPacketTunnel
	}
	return t.core.readIKERequest(ctx)
}

func (t *sharedNATTESPTransport) Close(context.Context) error {
	if t == nil || t.core == nil {
		return nil
	}
	return t.core.close()
}

func (t *sharedNATTESPTransport) LocalNetworkAddr() net.Addr {
	if t == nil || t.core == nil {
		return nil
	}
	return t.core.localNetworkAddr()
}

func (t *sharedNATTESPTransport) proxyRouteIPs() []net.IP {
	if t == nil || t.core == nil {
		return nil
	}
	return t.core.proxyRouteIPs()
}

func (c *sharedNATTUDPConn) ensureConn(ctx context.Context) (net.Conn, error) {
	if c == nil {
		return nil, ErrInvalidPacketTunnel
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrPacketTunnelClosed
	}
	if c.conn != nil {
		return c.conn, nil
	}
	if c.proxy.IsActive() {
		conn, err := dialSOCKS5UDPConn(ctx, c.proxy, c.remoteAddr, c.localAddr, c.timeout)
		if err != nil {
			return nil, err
		}
		c.conn = conn
		go c.readLoop(conn)
		return conn, nil
	}
	remote, err := udpAddrWithDefaultPort(c.remoteAddr, DefaultNATTUDPPort)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{}
	if c.localAddr != "" {
		local, err := udpAddrWithDefaultPort(c.localAddr, "0")
		if err != nil {
			return nil, err
		}
		addr, err := net.ResolveUDPAddr("udp", local)
		if err != nil {
			return nil, err
		}
		dialer.LocalAddr = addr
	}
	conn, err := dialer.DialContext(ctx, "udp", remote)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	go c.readLoop(conn)
	return conn, nil
}

func (c *sharedNATTUDPConn) exchangeIKE(ctx context.Context, request []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.ikeMu.Lock()
	defer c.ikeMu.Unlock()
	reqMsgID, hasReqHeader := parseWireIKEMessageID(request)
	wire := append([]byte{0, 0, 0, 0}, request...)
	if err := c.write(ctx, wire); err != nil {
		return nil, err
	}
	timer, timerCh := c.responseTimer()
	if timer != nil {
		defer timer.Stop()
	}
	for {
		select {
		case packet := <-c.ikeRespCh:
			if hasReqHeader {
				if respMsgID, ok := parseWireIKEMessageID(packet); ok && respMsgID != reqMsgID {
					continue
				}
			}
			return packet, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timerCh:
			return nil, &sharedNATTTimeoutError{op: "read"}
		case <-c.failedCh:
			return nil, c.failure()
		case <-c.closedCh:
			return nil, ErrPacketTunnelClosed
		}
	}
}

func (c *sharedNATTUDPConn) readIKERequest(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := c.ensureConn(ctx); err != nil {
		return nil, err
	}
	select {
	case packet := <-c.ikeReqCh:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.failedCh:
		return nil, c.failure()
	case <-c.closedCh:
		return nil, ErrPacketTunnelClosed
	}
}

func (c *sharedNATTUDPConn) write(ctx context.Context, packet []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	conn, err := c.ensureConn(ctx)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := conn.SetWriteDeadline(c.deadline(ctx)); err != nil {
		return err
	}
	_, err = conn.Write(packet)
	return transportNetError(ctx, err)
}

func (c *sharedNATTUDPConn) readESP(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := c.ensureConn(ctx); err != nil {
		return nil, err
	}
	select {
	case packet := <-c.espCh:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.failedCh:
		return nil, c.failure()
	case <-c.closedCh:
		return nil, ErrPacketTunnelClosed
	}
}

func (c *sharedNATTUDPConn) readLoop(conn net.Conn) {
	buf := make([]byte, 64*1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-c.closedCh:
				return
			default:
			}
			if isTransientUDPReadError(err) {
				continue
			}
			c.fail(err)
			return
		}
		packet := append([]byte(nil), buf[:n]...)
		switch {
		case isNATTKeepalive(packet):
			continue
		case isNonESPMarker(packet):
			packet = packet[4:]
			if isInboundIKERequestPacket(packet) {
				enqueueNonBlockingPacket(c.ikeReqCh, packet, c.closedCh)
			} else {
				enqueueNonBlockingPacket(c.ikeRespCh, packet, c.closedCh)
			}
		case len(packet) >= 8:
			enqueueNonBlockingPacket(c.espCh, packet, c.closedCh)
		}
	}
}

func enqueueNonBlockingPacket(ch chan []byte, packet []byte, closedCh <-chan struct{}) {
	for {
		select {
		case <-closedCh:
			return
		case ch <- packet:
			return
		default:
			select {
			case <-ch:
			default:
			}
		}
	}
}

func isInboundIKERequestPacket(packet []byte) bool {
	if len(packet) < ikev2.HeaderLength {
		return false
	}
	if packet[17] != 0x20 {
		return false
	}
	msgLen := int(binary.BigEndian.Uint32(packet[24:28]))
	if msgLen < ikev2.HeaderLength || msgLen != len(packet) {
		return false
	}
	return packet[19]&ikev2.FlagResponse == 0
}

func parseWireIKEMessageID(packet []byte) (uint32, bool) {
	if len(packet) < ikev2.HeaderLength || packet[17] != 0x20 {
		return 0, false
	}
	msgLen := int(binary.BigEndian.Uint32(packet[24:28]))
	if msgLen < ikev2.HeaderLength || msgLen != len(packet) {
		return 0, false
	}
	return binary.BigEndian.Uint32(packet[20:24]), true
}

func isTransientUDPReadError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EMSGSIZE) ||
		errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.ENOBUFS)
}

func (c *sharedNATTUDPConn) proxyRouteIPs() []net.IP {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if provider, ok := conn.(proxyRouteIPProvider); ok {
		return provider.proxyRouteIPs()
	}
	return nil
}

func (c *sharedNATTUDPConn) close() error {
	if c == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		conn := c.conn
		c.conn = nil
		c.mu.Unlock()
		close(c.closedCh)
		if conn != nil {
			err = conn.Close()
		}
	})
	return err
}

func (c *sharedNATTUDPConn) fail(err error) {
	c.failOnce.Do(func() {
		c.mu.Lock()
		c.readErr = err
		c.mu.Unlock()
		close(c.failedCh)
	})
}

func (c *sharedNATTUDPConn) failure() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr == nil {
		return ErrPacketTunnelClosed
	}
	return c.readErr
}

func (c *sharedNATTUDPConn) localNetworkAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	return c.conn.LocalAddr()
}

func (c *sharedNATTUDPConn) deadline(ctx context.Context) time.Time {
	var deadline time.Time
	if ctx != nil {
		deadline, _ = ctx.Deadline()
	}
	if c.timeout > 0 {
		candidate := time.Now().Add(c.timeout)
		if deadline.IsZero() || candidate.Before(deadline) {
			deadline = candidate
		}
	}
	return deadline
}

func (c *sharedNATTUDPConn) responseTimer() (*time.Timer, <-chan time.Time) {
	if c.timeout <= 0 {
		return nil, nil
	}
	timer := time.NewTimer(c.timeout)
	return timer, timer.C
}

type sharedNATTTimeoutError struct{ op string }

func (e *sharedNATTTimeoutError) Error() string   { return fmt.Sprintf("%s udp: i/o timeout", e.op) }
func (e *sharedNATTTimeoutError) Timeout() bool   { return true }
func (e *sharedNATTTimeoutError) Temporary() bool { return true }

var _ net.Error = (*sharedNATTTimeoutError)(nil)
var _ ESPPacketReadWriteTransport = (*sharedNATTESPTransport)(nil)
var _ ESPPacketTransportCloser = (*sharedNATTESPTransport)(nil)
