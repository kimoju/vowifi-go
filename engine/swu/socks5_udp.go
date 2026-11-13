package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kimoju/vowifi-go/engine/swu/ikev2"
)

const (
	socks5Version            = 0x05
	socks5AuthNone           = 0x00
	socks5AuthUsernamePass   = 0x02
	socks5AuthNoAcceptable   = 0xff
	socks5UserPassVersion    = 0x01
	socks5CmdUDPAssociate    = 0x03
	socks5ATYPIPv4           = 0x01
	socks5ATYPDomain         = 0x03
	socks5ATYPIPv6           = 0x04
	defaultSOCKS5Port        = "1080"
	defaultSOCKS5HandTimeout = 10 * time.Second
)

var ErrSOCKS5Proxy = errors.New("swu socks5 proxy error")

// IsActive reports whether p is configured for proxy dialing.
func (p *ProxyConfig) IsActive() bool {
	if p == nil {
		return false
	}
	return p.Enabled ||
		strings.TrimSpace(p.URL) != "" ||
		strings.TrimSpace(p.Address) != "" ||
		strings.TrimSpace(p.Addr) != ""
}

func cloneProxyConfig(p *ProxyConfig) *ProxyConfig {
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}

type parsedSOCKS5Proxy struct {
	HostPort string
	Host     string
	Port     string
	Username string
	Password string
}

func parseSOCKS5ProxyConfig(p *ProxyConfig) (parsedSOCKS5Proxy, error) {
	if !p.IsActive() {
		return parsedSOCKS5Proxy{}, fmt.Errorf("%w: proxy config is inactive", ErrSOCKS5Proxy)
	}
	username := p.Username
	password := p.Password
	raw := strings.TrimSpace(p.URL)
	if raw == "" {
		raw = firstPacketNonEmpty(p.Address, p.Addr)
	}
	if raw == "" {
		return parsedSOCKS5Proxy{}, fmt.Errorf("%w: proxy address is empty", ErrInvalidTunnelConfig)
	}
	var hostPort string
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return parsedSOCKS5Proxy{}, fmt.Errorf("%w: invalid proxy url %q: %v", ErrInvalidTunnelConfig, raw, err)
		}
		scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
		switch scheme {
		case "socks5", "socks5h", "socks":
		default:
			return parsedSOCKS5Proxy{}, fmt.Errorf("%w: unsupported proxy scheme %q", ErrInvalidTunnelConfig, u.Scheme)
		}
		if u.User != nil {
			if username == "" {
				username = u.User.Username()
			}
			if password == "" {
				if pass, ok := u.User.Password(); ok {
					password = pass
				}
			}
		}
		hostPort = strings.TrimSpace(u.Host)
	} else {
		hostPort = raw
	}
	host, port, err := splitProxyHostPort(hostPort, defaultSOCKS5Port)
	if err != nil {
		return parsedSOCKS5Proxy{}, fmt.Errorf("%w: %v", ErrInvalidTunnelConfig, err)
	}
	if len(username) > 255 || len(password) > 255 {
		return parsedSOCKS5Proxy{}, fmt.Errorf("%w: socks5 credentials exceed 255 bytes", ErrInvalidTunnelConfig)
	}
	return parsedSOCKS5Proxy{
		HostPort: net.JoinHostPort(host, port),
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
	}, nil
}

func splitProxyHostPort(raw, defaultPort string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("proxy host is empty")
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		host = strings.Trim(strings.TrimSpace(host), "[]")
		port = strings.TrimSpace(port)
		if host == "" {
			return "", "", errors.New("proxy host is empty")
		}
		if port == "" {
			port = defaultPort
		}
		if n, parseErr := strconv.Atoi(port); parseErr != nil || n <= 0 || n > 65535 {
			return "", "", fmt.Errorf("invalid proxy port %q", port)
		}
		return host, port, nil
	}
	host := strings.Trim(raw, "[]")
	if host == "" {
		return "", "", errors.New("proxy host is empty")
	}
	return host, defaultPort, nil
}

type socks5TargetSpec struct {
	rawAddr string
	host    string
	ip      net.IP
	port    uint16
	header  []byte
}

func parseSOCKS5Target(remoteAddr, defaultPort string) (socks5TargetSpec, error) {
	withPort, err := udpAddrWithDefaultPort(remoteAddr, defaultPort)
	if err != nil {
		return socks5TargetSpec{}, err
	}
	host, portStr, err := net.SplitHostPort(withPort)
	if err != nil {
		return socks5TargetSpec{}, fmt.Errorf("%w: invalid target address %q: %v", ErrSOCKS5Proxy, remoteAddr, err)
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return socks5TargetSpec{}, fmt.Errorf("%w: target host is empty", ErrSOCKS5Proxy)
	}
	portNum, err := strconv.ParseUint(strings.TrimSpace(portStr), 10, 16)
	if err != nil || portNum == 0 {
		return socks5TargetSpec{}, fmt.Errorf("%w: invalid target port %q", ErrSOCKS5Proxy, portStr)
	}
	header, parsedIP, err := buildSOCKS5UDPHeader(host, uint16(portNum))
	if err != nil {
		return socks5TargetSpec{}, err
	}
	return socks5TargetSpec{
		rawAddr: net.JoinHostPort(host, strconv.Itoa(int(portNum))),
		host:    host,
		ip:      parsedIP,
		port:    uint16(portNum),
		header:  header,
	}, nil
}

func buildSOCKS5UDPHeader(host string, port uint16) ([]byte, net.IP, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			hdr := make([]byte, 10)
			hdr[3] = socks5ATYPIPv4
			copy(hdr[4:8], ip4)
			binary.BigEndian.PutUint16(hdr[8:10], port)
			return hdr, append(net.IP(nil), ip4...), nil
		}
		ip16 := ip.To16()
		hdr := make([]byte, 22)
		hdr[3] = socks5ATYPIPv6
		copy(hdr[4:20], ip16)
		binary.BigEndian.PutUint16(hdr[20:22], port)
		return hdr, append(net.IP(nil), ip16...), nil
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, nil, fmt.Errorf("%w: domain length %d invalid for socks5", ErrSOCKS5Proxy, len(host))
	}
	hdr := make([]byte, 4+1+len(host)+2)
	hdr[3] = socks5ATYPDomain
	hdr[4] = byte(len(host))
	copy(hdr[5:5+len(host)], host)
	binary.BigEndian.PutUint16(hdr[5+len(host):], port)
	return hdr, nil, nil
}

func decapsulateSOCKS5UDPDatagram(datagram []byte) (payload []byte, ok bool) {
	_, _, _, payload, ok = decapsulateSOCKS5UDPDatagramFrom(datagram)
	return payload, ok
}

func decapsulateSOCKS5UDPDatagramFrom(datagram []byte) (srcHost string, srcIP net.IP, srcPort uint16, payload []byte, ok bool) {
	if len(datagram) < 4 {
		return "", nil, 0, nil, false
	}
	// RSV must be 0x0000; FRAG != 0 must be silently discarded per RFC 1928 §7.
	if datagram[0] != 0x00 || datagram[1] != 0x00 || datagram[2] != 0x00 {
		return "", nil, 0, nil, false
	}
	var hdrLen int
	switch datagram[3] {
	case socks5ATYPIPv4:
		hdrLen = 4 + net.IPv4len + 2
		if len(datagram) < hdrLen {
			return "", nil, 0, nil, false
		}
		srcIP = net.IPv4(datagram[4], datagram[5], datagram[6], datagram[7])
		srcPort = binary.BigEndian.Uint16(datagram[8:10])
	case socks5ATYPIPv6:
		hdrLen = 4 + net.IPv6len + 2
		if len(datagram) < hdrLen {
			return "", nil, 0, nil, false
		}
		srcIP = append(net.IP(nil), datagram[4:20]...)
		srcPort = binary.BigEndian.Uint16(datagram[20:22])
	case socks5ATYPDomain:
		if len(datagram) < 5 {
			return "", nil, 0, nil, false
		}
		dlen := int(datagram[4])
		hdrLen = 4 + 1 + dlen + 2
		if dlen == 0 || len(datagram) < hdrLen {
			return "", nil, 0, nil, false
		}
		srcHost = strings.Trim(strings.TrimSpace(string(datagram[5:5+dlen])), "[]")
		srcPort = binary.BigEndian.Uint16(datagram[5+dlen : 7+dlen])
	default:
		return "", nil, 0, nil, false
	}
	return srcHost, srcIP, srcPort, datagram[hdrLen:], true
}

type socks5UDPConn struct {
	tcpConn   net.Conn
	udpConn   *net.UDPConn
	relayAddr *net.UDPAddr
	proxyIP   net.IP
	target    socks5TargetSpec

	closeOnce      sync.Once
	closedCh       chan struct{}
	mu             sync.Mutex
	ctrlErr        error
	pinnedRemoteIP net.IP
}

var _ net.Conn = (*socks5UDPConn)(nil)

type proxyRouteIPProvider interface {
	proxyRouteIPs() []net.IP
}

func dialSOCKS5UDPConn(ctx context.Context, proxy *ProxyConfig, remoteAddr, localAddr string, timeout time.Duration) (*socks5UDPConn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	parsedProxy, err := parseSOCKS5ProxyConfig(proxy)
	if err != nil {
		return nil, err
	}
	target, err := parseSOCKS5Target(remoteAddr, DefaultNATTUDPPort)
	if err != nil {
		return nil, err
	}

	handTimeout := timeout
	if handTimeout <= 0 {
		handTimeout = defaultSOCKS5HandTimeout
	}
	handCtx, cancel := context.WithTimeout(ctx, handTimeout)
	defer cancel()

	var dialer net.Dialer
	var localBindIP net.IP
	if strings.TrimSpace(localAddr) != "" {
		if host := tunnelAddressHost(localAddr); host != "" {
			if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
				localBindIP = ip
				// Only bind local TCP IP if proxy host is not loopback or localBindIP is also loopback.
				proxyLiteralIP := net.ParseIP(parsedProxy.Host)
				if proxyLiteralIP == nil || proxyLiteralIP.IsLoopback() == ip.IsLoopback() {
					if (proxyLiteralIP == nil) || ((proxyLiteralIP.To4() != nil) == (ip.To4() != nil)) {
						dialer.LocalAddr = &net.TCPAddr{IP: ip, Port: 0}
					}
				}
			}
		}
	}

	tcpConn, err := dialer.DialContext(handCtx, "tcp", parsedProxy.HostPort)
	if err != nil {
		return nil, fmt.Errorf("%w: dial tcp %s: %v", ErrSOCKS5Proxy, parsedProxy.HostPort, err)
	}
	if deadline, ok := handCtx.Deadline(); ok {
		_ = tcpConn.SetDeadline(deadline)
	}

	relayAddr, proxyServerIP, err := negotiateSOCKS5UDPAssociate(handCtx, tcpConn, parsedProxy)
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	// Clear handshake deadline and enable TCP keepalives so dead SOCKS5 proxies
	// or silent NAT drops are detected promptly.
	_ = tcpConn.SetDeadline(time.Time{})
	if kaConn, ok := tcpConn.(*net.TCPConn); ok {
		_ = kaConn.SetKeepAlive(true)
		_ = kaConn.SetKeepAlivePeriod(30 * time.Second)
	}

	udpConn, err := openSOCKS5LocalUDPSocket(tcpConn, relayAddr, localBindIP)
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}

	c := &socks5UDPConn{
		tcpConn:   tcpConn,
		udpConn:   udpConn,
		relayAddr: relayAddr,
		proxyIP:   proxyServerIP,
		target:    target,
		closedCh:  make(chan struct{}),
	}
	go c.monitorControl()
	return c, nil
}

func openSOCKS5LocalUDPSocket(tcpConn net.Conn, relayAddr *net.UDPAddr, localBindIP net.IP) (*net.UDPConn, error) {
	network := "udp4"
	var bindIP net.IP
	if relayAddr != nil && relayAddr.IP != nil && relayAddr.IP.To4() == nil {
		network = "udp6"
	}
	if tcpLocal, ok := tcpConn.LocalAddr().(*net.TCPAddr); ok && tcpLocal.IP != nil && !tcpLocal.IP.IsUnspecified() {
		if (network == "udp4") == (tcpLocal.IP.To4() != nil) {
			bindIP = tcpLocal.IP
		}
	}
	if bindIP == nil && localBindIP != nil && !localBindIP.IsUnspecified() {
		if (network == "udp4") == (localBindIP.To4() != nil) {
			if relayAddr == nil || relayAddr.IP == nil || relayAddr.IP.IsLoopback() == localBindIP.IsLoopback() {
				bindIP = localBindIP
			}
		}
	}
	laddr := &net.UDPAddr{IP: bindIP, Port: 0}
	udpConn, err := net.ListenUDP(network, laddr)
	if err != nil && bindIP != nil {
		udpConn, err = net.ListenUDP(network, &net.UDPAddr{Port: 0})
	}
	if err != nil {
		return nil, fmt.Errorf("%w: listen %s: %v", ErrSOCKS5Proxy, network, err)
	}
	return udpConn, nil
}

func negotiateSOCKS5UDPAssociate(ctx context.Context, tcpConn net.Conn, proxy parsedSOCKS5Proxy) (*net.UDPAddr, net.IP, error) {
	hasAuth := proxy.Username != "" || proxy.Password != ""
	var greeting []byte
	if hasAuth {
		greeting = []byte{socks5Version, 0x02, socks5AuthNone, socks5AuthUsernamePass}
	} else {
		greeting = []byte{socks5Version, 0x01, socks5AuthNone}
	}
	if _, err := tcpConn.Write(greeting); err != nil {
		return nil, nil, fmt.Errorf("%w: write greeting: %v", ErrSOCKS5Proxy, err)
	}
	var methodResp [2]byte
	if _, err := io.ReadFull(tcpConn, methodResp[:]); err != nil {
		return nil, nil, fmt.Errorf("%w: read auth selection: %v", ErrSOCKS5Proxy, err)
	}
	if methodResp[0] != socks5Version {
		return nil, nil, fmt.Errorf("%w: unexpected socks version %d", ErrSOCKS5Proxy, methodResp[0])
	}
	switch methodResp[1] {
	case socks5AuthNone:
	case socks5AuthUsernamePass:
		if !hasAuth {
			return nil, nil, fmt.Errorf("%w: proxy requires username/password authentication", ErrSOCKS5Proxy)
		}
		authReq := make([]byte, 0, 3+len(proxy.Username)+len(proxy.Password))
		authReq = append(authReq, socks5UserPassVersion, byte(len(proxy.Username)))
		authReq = append(authReq, proxy.Username...)
		authReq = append(authReq, byte(len(proxy.Password)))
		authReq = append(authReq, proxy.Password...)
		if _, err := tcpConn.Write(authReq); err != nil {
			return nil, nil, fmt.Errorf("%w: write RFC1929 auth: %v", ErrSOCKS5Proxy, err)
		}
		var authResp [2]byte
		if _, err := io.ReadFull(tcpConn, authResp[:]); err != nil {
			return nil, nil, fmt.Errorf("%w: read RFC1929 auth reply: %v", ErrSOCKS5Proxy, err)
		}
		if authResp[0] != socks5UserPassVersion || authResp[1] != 0x00 {
			return nil, nil, fmt.Errorf("%w: RFC1929 authentication failed (status=%d)", ErrSOCKS5Proxy, authResp[1])
		}
	case socks5AuthNoAcceptable:
		return nil, nil, fmt.Errorf("%w: no acceptable socks5 authentication method", ErrSOCKS5Proxy)
	default:
		return nil, nil, fmt.Errorf("%w: unsupported socks5 authentication method %d", ErrSOCKS5Proxy, methodResp[1])
	}

	var proxyServerIP net.IP
	if tcpRemote, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok && tcpRemote.IP != nil {
		proxyServerIP = normalizedMOBIKEIP(tcpRemote.IP)
	}

	var assocReq []byte
	if proxyServerIP != nil && proxyServerIP.To4() == nil {
		assocReq = make([]byte, 22)
		assocReq[0] = socks5Version
		assocReq[1] = socks5CmdUDPAssociate
		assocReq[2] = 0x00
		assocReq[3] = socks5ATYPIPv6
	} else {
		assocReq = []byte{
			socks5Version, socks5CmdUDPAssociate, 0x00, socks5ATYPIPv4,
			0, 0, 0, 0,
			0, 0,
		}
	}
	if _, err := tcpConn.Write(assocReq); err != nil {
		return nil, nil, fmt.Errorf("%w: write UDP ASSOCIATE: %v", ErrSOCKS5Proxy, err)
	}

	var replyHdr [4]byte
	if _, err := io.ReadFull(tcpConn, replyHdr[:]); err != nil {
		return nil, nil, fmt.Errorf("%w: read UDP ASSOCIATE header: %v", ErrSOCKS5Proxy, err)
	}
	if replyHdr[0] != socks5Version {
		return nil, nil, fmt.Errorf("%w: unexpected reply version %d", ErrSOCKS5Proxy, replyHdr[0])
	}
	if replyHdr[1] != 0x00 {
		return nil, nil, fmt.Errorf("%w: UDP ASSOCIATE rejected with reply code 0x%02x", ErrSOCKS5Proxy, replyHdr[1])
	}

	var bndIP net.IP
	switch replyHdr[3] {
	case socks5ATYPIPv4:
		var rawIP [4]byte
		if _, err := io.ReadFull(tcpConn, rawIP[:]); err != nil {
			return nil, nil, fmt.Errorf("%w: read BND.ADDR IPv4: %v", ErrSOCKS5Proxy, err)
		}
		bndIP = net.IPv4(rawIP[0], rawIP[1], rawIP[2], rawIP[3])
	case socks5ATYPIPv6:
		var rawIP [16]byte
		if _, err := io.ReadFull(tcpConn, rawIP[:]); err != nil {
			return nil, nil, fmt.Errorf("%w: read BND.ADDR IPv6: %v", ErrSOCKS5Proxy, err)
		}
		bndIP = append(net.IP(nil), rawIP[:]...)
	case socks5ATYPDomain:
		var dlen [1]byte
		if _, err := io.ReadFull(tcpConn, dlen[:]); err != nil {
			return nil, nil, fmt.Errorf("%w: read BND.ADDR domain length: %v", ErrSOCKS5Proxy, err)
		}
		if dlen[0] == 0 {
			return nil, nil, fmt.Errorf("%w: empty BND.ADDR domain", ErrSOCKS5Proxy)
		}
		domainBuf := make([]byte, int(dlen[0]))
		if _, err := io.ReadFull(tcpConn, domainBuf); err != nil {
			return nil, nil, fmt.Errorf("%w: read BND.ADDR domain: %v", ErrSOCKS5Proxy, err)
		}
		domain := strings.Trim(strings.TrimSpace(string(domainBuf)), "[]")
		if parsed := net.ParseIP(domain); parsed != nil {
			bndIP = parsed
		} else {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
			if err != nil || len(addrs) == 0 {
				return nil, nil, fmt.Errorf("%w: resolve BND.ADDR domain %q: %v", ErrSOCKS5Proxy, domain, err)
			}
			bndIP = addrs[0].IP
		}
	default:
		return nil, nil, fmt.Errorf("%w: unsupported BND.ADDR ATYP 0x%02x", ErrSOCKS5Proxy, replyHdr[3])
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(tcpConn, portBuf[:]); err != nil {
		return nil, nil, fmt.Errorf("%w: read BND.PORT: %v", ErrSOCKS5Proxy, err)
	}
	bndPort := int(binary.BigEndian.Uint16(portBuf[:]))
	if bndPort <= 0 || bndPort > 65535 {
		return nil, nil, fmt.Errorf("%w: invalid BND.PORT %d", ErrSOCKS5Proxy, bndPort)
	}
	if bndIP == nil || bndIP.IsUnspecified() {
		if proxyServerIP == nil {
			return nil, nil, fmt.Errorf("%w: BND.ADDR is unspecified and proxy TCP peer IP is unknown", ErrSOCKS5Proxy)
		}
		bndIP = append(net.IP(nil), proxyServerIP...)
	} else {
		bndIP = normalizedMOBIKEIP(bndIP)
	}
	return &net.UDPAddr{IP: bndIP, Port: bndPort}, proxyServerIP, nil
}

func (c *socks5UDPConn) monitorControl() {
	var buf [1]byte
	for {
		_, err := c.tcpConn.Read(buf[:])
		if err != nil {
			c.mu.Lock()
			if c.ctrlErr == nil {
				c.ctrlErr = fmt.Errorf("%w: socks5 tcp control closed: %v", net.ErrClosed, err)
			}
			c.mu.Unlock()
			_ = c.Close()
			return
		}
	}
}

func (c *socks5UDPConn) closedError() error {
	c.mu.Lock()
	err := c.ctrlErr
	c.mu.Unlock()
	if err != nil {
		return err
	}
	return net.ErrClosed
}

func (c *socks5UDPConn) matchesInnerSource(srcHost string, srcIP net.IP, srcPort uint16) bool {
	if c.target.port != 0 && srcPort != c.target.port {
		return false
	}
	if c.target.ip != nil {
		if srcIP != nil {
			return srcIP.Equal(c.target.ip)
		}
		if parsed := net.ParseIP(srcHost); parsed != nil {
			return parsed.Equal(c.target.ip)
		}
		return strings.EqualFold(strings.TrimSuffix(srcHost, "."), strings.TrimSuffix(c.target.host, "."))
	}
	if srcHost != "" {
		if parsed := net.ParseIP(srcHost); parsed != nil {
			srcIP = parsed
		} else {
			return strings.EqualFold(strings.TrimSuffix(srcHost, "."), strings.TrimSuffix(c.target.host, "."))
		}
	}
	if srcIP != nil {
		if srcIP.IsUnspecified() {
			return false
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.pinnedRemoteIP == nil {
			c.pinnedRemoteIP = normalizedMOBIKEIP(srcIP)
			return true
		}
		return srcIP.Equal(c.pinnedRemoteIP)
	}
	return false
}

func (c *socks5UDPConn) Write(p []byte) (int, error) {
	select {
	case <-c.closedCh:
		return 0, c.closedError()
	default:
	}
	frame := make([]byte, len(c.target.header)+len(p))
	copy(frame, c.target.header)
	copy(frame[len(c.target.header):], p)
	if _, err := c.udpConn.WriteToUDP(frame, c.relayAddr); err != nil {
		select {
		case <-c.closedCh:
			return 0, c.closedError()
		default:
		}
		return 0, err
	}
	return len(p), nil
}

func (c *socks5UDPConn) Read(p []byte) (int, error) {
	buf := make([]byte, 64*1024)
	for {
		n, srcAddr, err := c.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.closedCh:
				return 0, c.closedError()
			default:
			}
			return 0, err
		}
		if c.relayAddr != nil && srcAddr != nil {
			if c.relayAddr.Port != 0 && srcAddr.Port != c.relayAddr.Port {
				continue
			}
			if len(c.relayAddr.IP) > 0 && !c.relayAddr.IP.IsUnspecified() && !srcAddr.IP.Equal(c.relayAddr.IP) {
				continue
			}
		}
		srcHost, srcIP, srcPort, payload, ok := decapsulateSOCKS5UDPDatagramFrom(buf[:n])
		if !ok {
			continue
		}
		if !c.matchesInnerSource(srcHost, srcIP, srcPort) {
			continue
		}
		if len(payload) > len(p) {
			return 0, syscall.EMSGSIZE
		}
		copied := copy(p, payload)
		return copied, nil
	}
}

func (c *socks5UDPConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		close(c.closedCh)
		if c.udpConn != nil {
			closeErr = errors.Join(closeErr, c.udpConn.Close())
		}
		if c.tcpConn != nil {
			closeErr = errors.Join(closeErr, c.tcpConn.Close())
		}
	})
	return closeErr
}

func (c *socks5UDPConn) LocalAddr() net.Addr {
	if c == nil || c.udpConn == nil {
		return nil
	}
	return c.udpConn.LocalAddr()
}

func (c *socks5UDPConn) RemoteAddr() net.Addr {
	if c == nil {
		return nil
	}
	if c.target.ip != nil {
		return &net.UDPAddr{IP: append(net.IP(nil), c.target.ip...), Port: int(c.target.port)}
	}
	// When the target is a domain name forwarded via ATYP=0x03 without local DNS
	// resolution, synthesize a family-matched unspecified UDPAddr so IKE_SA_INIT
	// still emits NAT_DETECTION_* notifications while guaranteeing NAT detection.
	placeholder := net.IPv4zero
	if localUDP, ok := c.LocalAddr().(*net.UDPAddr); ok && localUDP.IP != nil && localUDP.IP.To4() == nil {
		placeholder = net.IPv6zero
	}
	return &net.UDPAddr{IP: placeholder, Port: int(c.target.port)}
}

func (c *socks5UDPConn) SetDeadline(t time.Time) error {
	if c == nil || c.udpConn == nil {
		return net.ErrClosed
	}
	return c.udpConn.SetDeadline(t)
}

func (c *socks5UDPConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.udpConn == nil {
		return net.ErrClosed
	}
	return c.udpConn.SetReadDeadline(t)
}

func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.udpConn == nil {
		return net.ErrClosed
	}
	return c.udpConn.SetWriteDeadline(t)
}

func (c *socks5UDPConn) proxyRouteIPs() []net.IP {
	if c == nil {
		return nil
	}
	var out []net.IP
	if ip := normalizedMOBIKEIP(c.proxyIP); ip != nil && !ip.IsUnspecified() {
		out = append(out, ip)
	}
	if c.relayAddr != nil {
		if relayIP := normalizedMOBIKEIP(c.relayAddr.IP); relayIP != nil && !relayIP.IsUnspecified() {
			if len(out) == 0 || !out[0].Equal(relayIP) {
				out = append(out, relayIP)
			}
		}
	}
	return out
}

// IKEUDPTransportWithProxy returns cfg wired to dial via SOCKS5 UDP ASSOCIATE when proxy is active.
func IKEUDPTransportWithProxy(cfg ikev2.UDPTransport, proxy *ProxyConfig) ikev2.UDPTransport {
	if !proxy.IsActive() {
		return cfg
	}
	cloned := cloneProxyConfig(proxy)
	localAddr := cfg.LocalAddr
	timeout := cfg.Timeout
	cfg.DialFunc = func(ctx context.Context, _ string, remote string) (net.Conn, error) {
		return dialSOCKS5UDPConn(ctx, cloned, remote, localAddr, timeout)
	}
	return cfg
}
