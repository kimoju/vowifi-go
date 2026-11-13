package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

type localSOCKS5UDPTestServer struct {
	t            *testing.T
	tcpLn        net.Listener
	udpRelay     *net.UDPConn
	username     string
	password     string
	bindAtyp     byte
	bindOverride string

	mu           sync.Mutex
	targetAddrs  []string
	controlConns []net.Conn
	closed       bool
}

func startLocalSOCKS5UDPTestServer(t *testing.T, network string, username, password string, bindAtyp byte, bindOverride string) *localSOCKS5UDPTestServer {
	t.Helper()
	listenHost := "127.0.0.1:0"
	if network == "tcp6" {
		listenHost = "[::1]:0"
	}
	tcpLn, err := net.Listen(network, listenHost)
	if err != nil {
		if network == "tcp6" {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		t.Fatalf("Listen(%s) error = %v", network, err)
	}
	udpNet := "udp4"
	udpBind := "127.0.0.1:0"
	if network == "tcp6" {
		udpNet = "udp6"
		udpBind = "[::1]:0"
	}
	udpAddr, err := net.ResolveUDPAddr(udpNet, udpBind)
	if err != nil {
		_ = tcpLn.Close()
		t.Fatalf("ResolveUDPAddr error = %v", err)
	}
	udpRelay, err := net.ListenUDP(udpNet, udpAddr)
	if err != nil {
		_ = tcpLn.Close()
		t.Fatalf("ListenUDP error = %v", err)
	}
	srv := &localSOCKS5UDPTestServer{
		t:            t,
		tcpLn:        tcpLn,
		udpRelay:     udpRelay,
		username:     username,
		password:     password,
		bindAtyp:     bindAtyp,
		bindOverride: bindOverride,
	}
	go srv.acceptLoop()
	t.Cleanup(srv.Close)
	return srv
}

func (s *localSOCKS5UDPTestServer) Addr() string {
	return s.tcpLn.Addr().String()
}

func (s *localSOCKS5UDPTestServer) CloseControlConns() {
	s.mu.Lock()
	conns := append([]net.Conn(nil), s.controlConns...)
	s.controlConns = nil
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (s *localSOCKS5UDPTestServer) RecordedTargets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.targetAddrs...)
}

func (s *localSOCKS5UDPTestServer) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conns := append([]net.Conn(nil), s.controlConns...)
	s.mu.Unlock()
	_ = s.tcpLn.Close()
	_ = s.udpRelay.Close()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (s *localSOCKS5UDPTestServer) acceptLoop() {
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.controlConns = append(s.controlConns, conn)
		s.mu.Unlock()
		go s.handleTCP(conn)
	}
}

func (s *localSOCKS5UDPTestServer) handleTCP(conn net.Conn) {
	var greet [2]byte
	if _, err := io.ReadFull(conn, greet[:]); err != nil {
		_ = conn.Close()
		return
	}
	methods := make([]byte, int(greet[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		_ = conn.Close()
		return
	}
	if s.username != "" {
		_, _ = conn.Write([]byte{socks5Version, socks5AuthUsernamePass})
		var authHdr [2]byte
		if _, err := io.ReadFull(conn, authHdr[:]); err != nil {
			_ = conn.Close()
			return
		}
		u := make([]byte, int(authHdr[1]))
		if _, err := io.ReadFull(conn, u); err != nil {
			_ = conn.Close()
			return
		}
		var plen [1]byte
		if _, err := io.ReadFull(conn, plen[:]); err != nil {
			_ = conn.Close()
			return
		}
		p := make([]byte, int(plen[0]))
		if _, err := io.ReadFull(conn, p); err != nil {
			_ = conn.Close()
			return
		}
		if string(u) != s.username || string(p) != s.password {
			_, _ = conn.Write([]byte{socks5UserPassVersion, 0x01})
			_ = conn.Close()
			return
		}
		_, _ = conn.Write([]byte{socks5UserPassVersion, 0x00})
	} else {
		_, _ = conn.Write([]byte{socks5Version, socks5AuthNone})
	}

	var reqHdr [4]byte
	if _, err := io.ReadFull(conn, reqHdr[:]); err != nil {
		_ = conn.Close()
		return
	}
	switch reqHdr[3] {
	case socks5ATYPIPv4:
		_, _ = io.CopyN(io.Discard, conn, 6)
	case socks5ATYPIPv6:
		_, _ = io.CopyN(io.Discard, conn, 18)
	case socks5ATYPDomain:
		var l [1]byte
		_, _ = io.ReadFull(conn, l[:])
		_, _ = io.CopyN(io.Discard, conn, int64(l[0])+2)
	}

	relayUDP := s.udpRelay.LocalAddr().(*net.UDPAddr)
	reply := []byte{socks5Version, 0x00, 0x00, s.bindAtyp}
	host := s.bindOverride
	if host == "" {
		host = relayUDP.IP.String()
	}
	switch s.bindAtyp {
	case socks5ATYPIPv4:
		reply = append(reply, net.ParseIP(host).To4()...)
	case socks5ATYPIPv6:
		reply = append(reply, net.ParseIP(host).To16()...)
	case socks5ATYPDomain:
		reply = append(reply, byte(len(host)))
		reply = append(reply, host...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(relayUDP.Port))
	reply = append(reply, portBuf[:]...)
	_, _ = conn.Write(reply)
}

func (s *localSOCKS5UDPTestServer) runEchoOnce(echoTarget *net.UDPConn) {
	buf := make([]byte, 4096)
	n, clientAddr, err := s.udpRelay.ReadFromUDP(buf)
	if err != nil {
		return
	}
	payload, targetHostPort, err := parseSOCKS5UDPTestFrame(buf[:n])
	if err != nil {
		return
	}
	s.mu.Lock()
	s.targetAddrs = append(s.targetAddrs, targetHostPort)
	s.mu.Unlock()

	if echoTarget != nil {
		_, _ = echoTarget.WriteToUDP(payload, echoTarget.LocalAddr().(*net.UDPAddr))
		respBuf := make([]byte, 4096)
		rn, _, err := echoTarget.ReadFromUDP(respBuf)
		if err == nil {
			payload = respBuf[:rn]
		}
	}
	spec, err := parseSOCKS5Target(targetHostPort, DefaultNATTUDPPort)
	if err != nil {
		return
	}
	respFrame := append(append([]byte(nil), spec.header...), payload...)
	_, _ = s.udpRelay.WriteToUDP(respFrame, clientAddr)
}

func parseSOCKS5UDPTestFrame(frame []byte) ([]byte, string, error) {
	if len(frame) < 4 || frame[2] != 0 {
		return nil, "", ErrSOCKS5Proxy
	}
	offset := 4
	var host string
	switch frame[3] {
	case socks5ATYPIPv4:
		host = net.IP(frame[offset : offset+4]).String()
		offset += 4
	case socks5ATYPIPv6:
		host = net.IP(frame[offset : offset+16]).String()
		offset += 16
	case socks5ATYPDomain:
		dlen := int(frame[offset])
		offset++
		host = string(frame[offset : offset+dlen])
		offset += dlen
	default:
		return nil, "", ErrSOCKS5Proxy
	}
	port := binary.BigEndian.Uint16(frame[offset : offset+2])
	offset += 2
	return append([]byte(nil), frame[offset:]...), net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func TestSOCKS5UDPAssociateAuthWildcardBindDomainTargetAndEOFMonitor(t *testing.T) {
	for _, tc := range []struct {
		name         string
		network      string
		user         string
		pass         string
		bindAtyp     byte
		bindOverride string
		target       string
	}{
		{
			name:         "no-auth wildcard IPv4 bind and FQDN target without host DNS",
			network:      "tcp4",
			bindAtyp:     socks5ATYPIPv4,
			bindOverride: "0.0.0.0",
			target:       "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org:4500",
		},
		{
			name:         "rfc1929 auth domain bind",
			network:      "tcp4",
			user:         "modem1",
			pass:         "secret1",
			bindAtyp:     socks5ATYPDomain,
			bindOverride: "localhost",
			target:       "198.51.100.20:4500",
		},
		{
			name:         "rfc1929 auth wildcard IPv6 bind",
			network:      "tcp6",
			user:         "modem6",
			pass:         "secret6",
			bindAtyp:     socks5ATYPIPv6,
			bindOverride: "::",
			target:       "[2001:db8::9]:4500",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startLocalSOCKS5UDPTestServer(t, tc.network, tc.user, tc.pass, tc.bindAtyp, tc.bindOverride)
			go srv.runEchoOnce(nil)

			conn, err := dialSOCKS5UDPConn(context.Background(), &ProxyConfig{
				Enabled:  true,
				Address:  srv.Addr(),
				Username: tc.user,
				Password: tc.pass,
			}, tc.target, "", 2*time.Second)
			if err != nil {
				t.Fatalf("dialSOCKS5UDPConn() error = %v", err)
			}
			defer conn.Close()

			want := []byte{0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef}
			if _, err := conn.Write(want); err != nil {
				t.Fatalf("conn.Write error = %v", err)
			}
			buf := make([]byte, 128)
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("conn.Read error = %v", err)
			}
			if !bytes.Equal(buf[:n], want) {
				t.Fatalf("echo = %x, want %x", buf[:n], want)
			}
			targets := srv.RecordedTargets()
			if len(targets) != 1 || targets[0] != tc.target {
				t.Fatalf("recorded SOCKS5 target = %v, want [%s]", targets, tc.target)
			}

			readErrCh := make(chan error, 1)
			go func() {
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, rerr := conn.Read(make([]byte, 64))
				readErrCh <- rerr
			}()
			time.Sleep(25 * time.Millisecond)
			srv.CloseControlConns()
			select {
			case rerr := <-readErrCh:
				if rerr == nil {
					t.Fatal("expected Read error after SOCKS5 TCP control EOF")
				}
			case <-time.After(time.Second):
				t.Fatal("UDP relay Read did not wake up after SOCKS5 TCP control EOF")
			}
		})
	}
}

func TestTUNTunnelManagerProxyExcludesProxyIPAndFallsBackFromKernelMode(t *testing.T) {
	var resolvedHosts []string
	baseSession := newTUNManagerPacketSession(TunnelResult{
		Ready:            true,
		Mode:             DataplaneModeUserspace,
		EPDGAddress:      "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org",
		LocalInnerIP:     "10.88.0.2",
		LocalInnerIPv4:   "10.88.0.2",
		IKEEstablished:   true,
		IPsecEstablished: true,
	})
	base := &tunManagerBase{session: baseSession}
	routing := &tunManagerRouting{}
	manager := NewTUNTunnelManager(TUNTunnelManagerConfig{
		Base:               base,
		RoutingManager:     routing,
		IsolateHostRouting: true,
		ProtectEPDGRoutes:  true,
		DisableMaintenance: true,
		EPDGRouteResolver: func(ctx context.Context, host string) ([]net.IP, error) {
			resolvedHosts = append(resolvedHosts, host)
			if host == "proxy.local" {
				return []net.IP{net.ParseIP("192.0.2.55")}, nil
			}
			return nil, errors.New("unexpected host DNS lookup for ePDG FQDN")
		},
		DeviceFactory: func(context.Context, TunnelConfig, TunnelResult) (InnerPacketDevice, string, error) {
			return newTUNManagerDevice("tun3"), "tun3", nil
		},
	})

	session, err := manager.EstablishTunnel(context.Background(), TunnelConfig{
		DeviceID:       "dev-proxy",
		Mode:           DataplaneModeKernel,
		EPDGAddress:    "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org",
		LocalInterface: "eth0",
		OuterLocalIP:   "192.0.2.10",
		IMSI:           "310260000000001",
		Proxy: &ProxyConfig{
			Enabled: true,
			Address: "socks5://proxy.local:1080",
		},
	})
	if err != nil {
		t.Fatalf("EstablishTunnel() error = %v", err)
	}
	defer session.Close(context.Background())

	if base.config.Mode != DataplaneModeUserspace {
		t.Fatalf("base saw mode = %q, want %q", base.config.Mode, DataplaneModeUserspace)
	}
	if len(resolvedHosts) != 1 || resolvedHosts[0] != "proxy.local" {
		t.Fatalf("resolved hosts = %v, want [proxy.local]", resolvedHosts)
	}
	applied := routing.applies[0]
	if len(applied.EPDGRouteExclusions) != 1 || applied.EPDGRouteExclusions[0].Address != "192.0.2.55" {
		t.Fatalf("exclusions = %+v, want proxy IP 192.0.2.55", applied.EPDGRouteExclusions)
	}
	if got := applied.EPDGRouteExclusions[0].Tables; len(got) != 1 || got[0] != "20003" {
		t.Fatalf("exclusion tables = %v, want [20003]", got)
	}
}
