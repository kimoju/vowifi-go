package swu

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kimoju/vowifi-go/engine/swu/esp"
	"github.com/kimoju/vowifi-go/engine/swu/ikev2"
)

func TestAuditRound2_CRIT02_CRIT04_IKETunnelManagerSecurityWiring(t *testing.T) {
	pool := x509.NewCertPool()
	var gotAuth ikev2.FullAuthConfig

	manager := NewIKEPacketTunnelManager(IKEPacketTunnelManagerConfig{
		SIM:      ikeTunnelAKAProvider{},
		Random:   rand.Reader,
		RemoteIP: net.IPv4(198, 51, 100, 7),
		IKETransportFactory: func(TunnelConfig, IKETransportConfig) (ikev2.InitTransport, error) {
			return ikeTunnelNoopTransport{}, nil
		},
		ESPTransportFactory: func(TunnelConfig, ESPTransportConfig) (ESPPacketTransport, error) {
			return &captureESPPacketTransport{}, nil
		},
		InitRunner: func(context.Context, ikev2.InitConfig) (ikev2.InitResult, error) {
			return ikev2.InitResult{MOBIKESupported: true, NATDetected: true}, nil
		},
		AuthRunner: func(_ context.Context, cfg ikev2.FullAuthConfig) (ikev2.FullAuthResult, error) {
			gotAuth = cfg
			child := packetChildSA(true)
			child.LocalSPI = append([]byte(nil), cfg.ChildSPI...)
			return ikev2.FullAuthResult{ChildSA: &child, NextMessageID: 3}, nil
		},
	})

	session, err := manager.EstablishTunnel(context.Background(), TunnelConfig{
		DeviceID:              "dev-sec",
		Mode:                  DataplaneModeUserspace,
		EPDGAddress:           "epdg.epc.mnc280.mcc310.pub.3gppnetwork.org",
		OuterLocalIP:          "192.0.2.10",
		IMSI:                  "310280233641503",
		MCC:                   "310",
		MNC:                   "280",
		ExpectedResponderID:   "epdg.epc.mnc280.mcc310.pub.3gppnetwork.org",
		RootCAs:               pool,
		EAPOnlyAuthentication: true,
		RequireResponderCert:  true,
		SendCertReq:           true,
		ExpectedNetworkName:   "WLAN",
	})
	if err != nil {
		t.Fatalf("EstablishTunnel() error = %v", err)
	}
	defer session.Close(context.Background())

	if gotAuth.ExpectedResponderID == nil ||
		gotAuth.ExpectedResponderID.Type != ikev2.IDFQDN ||
		string(gotAuth.ExpectedResponderID.Data) != "epdg.epc.mnc280.mcc310.pub.3gppnetwork.org" {
		t.Fatalf("ExpectedResponderID = %+v", gotAuth.ExpectedResponderID)
	}
	if gotAuth.RootCAs != pool {
		t.Fatal("RootCAs not wired into FullAuthConfig")
	}
	if !gotAuth.EAPOnlyAuthentication || !gotAuth.RequireResponderCert || !gotAuth.SendCertReq {
		t.Fatalf("auth flags not wired: EAPOnly=%v RequireCert=%v SendCertReq=%v",
			gotAuth.EAPOnlyAuthentication, gotAuth.RequireResponderCert, gotAuth.SendCertReq)
	}
	if gotAuth.ExpectedNetworkName != "WLAN" {
		t.Fatalf("ExpectedNetworkName = %q, want WLAN", gotAuth.ExpectedNetworkName)
	}
	if gotAuth.EAPIdentity != "6310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org" {
		t.Fatalf("EAPIdentity = %q, want '6'-prefixed EAP-AKA' NAI", gotAuth.EAPIdentity)
	}
}

func TestAuditRound2_CRIT03_MED02_MED07_XFRMAndRouting(t *testing.T) {
	// 1. replay-window 64 + flag esn + SHA-384/SHA-512 support in LinuxXFRMManager.
	for _, tc := range []struct {
		name     string
		integID  uint16
		keyBytes int
		wantAlgo string
		wantBits string
	}{
		{
			name:     "SHA384_192_ESN",
			integID:  ikev2.INTEG_HMAC_SHA2_384_192,
			keyBytes: 48,
			wantAlgo: "hmac(sha384)",
			wantBits: "192",
		},
		{
			name:     "SHA512_256_ESN",
			integID:  ikev2.INTEG_HMAC_SHA2_512_256,
			keyBytes: 64,
			wantAlgo: "hmac(sha512)",
			wantBits: "256",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeIPRunner{}
			mgr := LinuxXFRMManager{Runner: runner}
			child := ikev2.ChildSAResult{
				LocalSPI:  []byte{0xaa, 0xbb, 0xcc, 0x01},
				RemoteSPI: []byte{0xaa, 0xbb, 0xcc, 0x02},
				Keys: ikev2.ChildSAKeys{
					Profile: ikev2.ESPKeyProfile{
						EncryptionID:        ikev2.ENCR_AES_CBC,
						IntegrityID:         tc.integID,
						ESN:                 true,
						EncryptionKeyLength: 16,
						IntegrityKeyLength:  tc.keyBytes,
					},
					Outbound: ikev2.ESPKeys{
						EncryptionKey: bytes.Repeat([]byte{0x11}, 16),
						IntegrityKey:  bytes.Repeat([]byte{0x22}, tc.keyBytes),
					},
					Inbound: ikev2.ESPKeys{
						EncryptionKey: bytes.Repeat([]byte{0x33}, 16),
						IntegrityKey:  bytes.Repeat([]byte{0x44}, tc.keyBytes),
					},
				},
			}
			state, err := mgr.Apply(context.Background(), KernelXFRMConfig{
				OuterLocalIP:      "192.0.2.10",
				OuterRemoteIP:     "198.51.100.7",
				InnerLocalPrefix:  "10.0.0.2/32",
				InnerRemotePrefix: "0.0.0.0/0",
				ChildSA:           child,
			})
			if err != nil {
				t.Fatalf("Apply() error = %v", err)
			}
			stateUpdates := 0
			for _, args := range runner.commands {
				cmd := "ip " + strings.Join(args, " ")
				if strings.HasPrefix(cmd, "ip xfrm state update ") {
					stateUpdates++
					if !strings.Contains(cmd, "replay-window 64") {
						t.Fatalf("missing replay-window 64 in command: %s", cmd)
					}
					if !strings.Contains(cmd, "flag esn") {
						t.Fatalf("missing flag esn in command: %s", cmd)
					}
					if !strings.Contains(cmd, "auth-trunc "+tc.wantAlgo+" ") || !strings.Contains(cmd, " "+tc.wantBits+" ") {
						t.Fatalf("unexpected auth-trunc in command: %s", cmd)
					}
				}
			}
			if stateUpdates != 2 {
				t.Fatalf("stateUpdates = %d, want 2; cmds=%v", stateUpdates, runner.commands)
			}
			if err := mgr.Cleanup(context.Background(), state); err != nil {
				t.Fatalf("Cleanup() error = %v", err)
			}
		})
	}

	// 2. Unique ReqID/IfID allocation + Dual-Stack IPv4/IPv6 PolicyPairs + non-CIDR range decomposition.
	dualChild := xfrmChildSA(ikev2.INTEG_HMAC_SHA2_256_128)
	dualChild.TSi = ikev2.TrafficSelectors{Selectors: []ikev2.TrafficSelector{
		{
			Type:      ikev2.TSIPv4AddressRange,
			StartAddr: net.IPv4(10, 0, 0, 2).To4(),
			EndAddr:   net.IPv4(10, 0, 0, 5).To4(), // non-CIDR 4-IP range -> 10.0.0.2/31 + 10.0.0.4/31
		},
		{
			Type:      ikev2.TSIPv6AddressRange,
			StartAddr: net.ParseIP("2001:db8:44::").To16(),
			EndAddr:   net.ParseIP("2001:db8:44::ffff:ffff:ffff:ffff").To16(),
		},
	}}
	dualChild.TSr = ikev2.SWuAnyTrafficSelectors()

	cfg1, err := KernelXFRMConfigFromIKE(KernelXFRMConfigFromIKEConfig{
		Tunnel:        TunnelConfig{OuterLocalIP: "192.0.2.10"},
		Transport:     IKETransportConfig{LocalIP: net.IPv4(192, 0, 2, 10), RemoteIP: net.IPv4(198, 51, 100, 7), LocalPort: 4500, RemotePort: 4500},
		Init:          ikev2.InitResult{NATDetected: true},
		ChildSA:       dualChild,
		XFRMInterface: XFRMInterfaceConfig{Name: "xfrmi1", OuterDev: "wlan0"},
	})
	if err != nil {
		t.Fatalf("KernelXFRMConfigFromIKE(cfg1) error = %v", err)
	}
	cfg2, err := KernelXFRMConfigFromIKE(KernelXFRMConfigFromIKEConfig{
		Tunnel:        TunnelConfig{OuterLocalIP: "192.0.2.11"},
		Transport:     IKETransportConfig{LocalIP: net.IPv4(192, 0, 2, 11), RemoteIP: net.IPv4(198, 51, 100, 7), LocalPort: 4500, RemotePort: 4500},
		Init:          ikev2.InitResult{NATDetected: true},
		ChildSA:       dualChild,
		XFRMInterface: XFRMInterfaceConfig{Name: "xfrmi2", OuterDev: "wlan0"},
	})
	if err != nil {
		t.Fatalf("KernelXFRMConfigFromIKE(cfg2) error = %v", err)
	}

	if cfg1.ReqID == 0 || cfg2.ReqID == 0 || cfg1.ReqID == cfg2.ReqID {
		t.Fatalf("expected unique non-zero ReqIDs, got %d and %d", cfg1.ReqID, cfg2.ReqID)
	}
	if cfg1.XFRMInterface.IfID == 0 || cfg2.XFRMInterface.IfID == 0 || cfg1.XFRMInterface.IfID == cfg2.XFRMInterface.IfID {
		t.Fatalf("expected unique non-zero IfIDs, got %d and %d", cfg1.XFRMInterface.IfID, cfg2.XFRMInterface.IfID)
	}

	// Verify policy pairs without xfrmi decompose non-CIDR IPv4 range AND include IPv6 policy!
	cfgNoXFRMI, err := KernelXFRMConfigFromIKE(KernelXFRMConfigFromIKEConfig{
		Tunnel:    TunnelConfig{OuterLocalIP: "192.0.2.10"},
		Transport: IKETransportConfig{LocalIP: net.IPv4(192, 0, 2, 10), RemoteIP: net.IPv4(198, 51, 100, 7)},
		ChildSA:   dualChild,
	})
	if err != nil {
		t.Fatalf("KernelXFRMConfigFromIKE(cfgNoXFRMI) error = %v", err)
	}
	var hasV4First, hasV4Second, hasV6 bool
	for _, p := range cfgNoXFRMI.PolicyPairs {
		if p.LocalPrefix == "10.0.0.2/31" && p.RemotePrefix == "0.0.0.0/0" {
			hasV4First = true
		}
		if p.LocalPrefix == "10.0.0.4/31" && p.RemotePrefix == "0.0.0.0/0" {
			hasV4Second = true
		}
		if p.LocalPrefix == "2001:db8:44::/64" && p.RemotePrefix == "::/0" {
			hasV6 = true
		}
	}
	if !hasV4First || !hasV4Second || !hasV6 {
		t.Fatalf("PolicyPairs missing decomposed CIDR or IPv6 selector: %+v", cfgNoXFRMI.PolicyPairs)
	}

	// 3. normalizeInterfaceAddress preserves /64 on IPv6.
	gotV6Prefix, err := normalizeInterfaceAddress("2001:db8:44::2/64", "address")
	if err != nil || gotV6Prefix != "2001:db8:44::2/64" {
		t.Fatalf("normalizeInterfaceAddress(2001:db8:44::2/64) = %q, %v", gotV6Prefix, err)
	}
}

func TestAuditRound2_HIGH01_SharedNATTIKEFragmentsEndToEnd(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer serverConn.Close()

	keys := testAuditIKEKeysGCM(t)
	initSPI := uint64(0x1122334455667788)
	respSPI := uint64(0x8877665544332211)

	largeCertLikeData := bytes.Repeat([]byte{0xab}, 2600)
	reqHdr := ikev2.Header{
		InitiatorSPI: initSPI,
		ResponderSPI: respSPI,
		ExchangeType: ikev2.ExchangeIKE_AUTH,
		Flags:        ikev2.FlagInitiator,
		MessageID:    1,
	}
	reqPayloads := []ikev2.Payload{
		{Type: ikev2.PayloadIDi, Body: append([]byte{ikev2.IDRFC822Addr, 0, 0, 0}, []byte("6310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org")...)},
		{Type: ikev2.PayloadCERT, Body: largeCertLikeData},
	}
	_, reqFrags, err := ikev2.ProtectFragmentedMessages(reqHdr, keys, true, reqPayloads, 700)
	if err != nil {
		t.Fatalf("ProtectFragmentedMessages(req) error = %v", err)
	}
	if len(reqFrags) < 4 {
		t.Fatalf("expected >= 4 outbound SKF fragments, got %d", len(reqFrags))
	}

	respCertChain := bytes.Repeat([]byte{0xcd}, 2900)
	serverErrCh := make(chan error, 1)
	go func() {
		var asm ikev2.EncryptedFragmentAssembler
		buf := make([]byte, 4096)
		for {
			n, clientAddr, rerr := serverConn.ReadFromUDP(buf)
			if rerr != nil {
				serverErrCh <- rerr
				return
			}
			if n <= 4 || !bytes.Equal(buf[:4], []byte{0, 0, 0, 0}) {
				serverErrCh <- errors.New("missing non-ESP marker on SKF datagram")
				return
			}
			msg, inner, complete, uerr := asm.AddProtectedFragment(buf[4:n], keys, true)
			if uerr != nil {
				serverErrCh <- uerr
				return
			}
			if !complete {
				continue
			}
			if len(inner) != 2 || !bytes.Equal(inner[1].Body, largeCertLikeData) {
				serverErrCh <- errors.New("reassembled request inner payload mismatch")
				return
			}
			respHdr := ikev2.Header{
				InitiatorSPI: msg.Header.InitiatorSPI,
				ResponderSPI: msg.Header.ResponderSPI,
				ExchangeType: ikev2.ExchangeIKE_AUTH,
				Flags:        ikev2.FlagResponse,
				MessageID:    msg.Header.MessageID,
			}
			respInner := []ikev2.Payload{
				{Type: ikev2.PayloadCERT, Body: respCertChain},
			}
			_, respFrags, perr := ikev2.ProtectFragmentedMessages(respHdr, keys, false, respInner, 700)
			if perr != nil {
				serverErrCh <- perr
				return
			}
			for _, f := range respFrags {
				wire := append([]byte{0, 0, 0, 0}, f...)
				if _, werr := serverConn.WriteToUDP(wire, clientAddr); werr != nil {
					serverErrCh <- werr
					return
				}
			}
			serverErrCh <- nil
			return
		}
	}()

	transport := newSharedNATTTransport(serverConn.LocalAddr().String(), "127.0.0.1:0", 3*time.Second)
	defer transport.Close()

	var respAsm ikev2.EncryptedFragmentAssembler
	var gotRespInner []ikev2.Payload
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = transport.ExchangeIKEFragments(ctx, reqFrags, func(raw []byte) (bool, error) {
		_, inner, complete, ferr := respAsm.AddProtectedFragment(raw, keys, false)
		if ferr != nil {
			return false, ferr
		}
		if complete {
			gotRespInner = inner
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("ExchangeIKEFragments() error = %v", err)
	}
	if serr := <-serverErrCh; serr != nil {
		t.Fatalf("server SKF error = %v", serr)
	}
	if len(gotRespInner) != 1 || gotRespInner[0].Type != ikev2.PayloadCERT || !bytes.Equal(gotRespInner[0].Body, respCertChain) {
		t.Fatalf("reassembled response mismatch: count=%d", len(gotRespInner))
	}
}

func TestAuditRound2_HIGH02_HIGH03_CPAttributesIPv6PrefixAndNAI(t *testing.T) {
	ipv6Addr17 := append(net.ParseIP("2001:db8:44::2").To16(), 64)
	child := packetChildSA(true)
	child.Configuration = &ikev2.Configuration{
		Type: ikev2.CFGReply,
		Attributes: []ikev2.ConfigurationAttribute{
			{Type: ikev2.ConfigInternalIPv4Address, Value: []byte{10, 88, 0, 2}},
			{Type: ikev2.ConfigInternalIPv4Address, Value: []byte{10, 88, 0, 3, 99}}, // malformed 5B -> ignored
			{Type: ikev2.ConfigInternalIPv6Address, Value: ipv6Addr17},               // RFC 7296 17B (16B IP + 1B prefix)
			{Type: ikev2.ConfigInternalIPv6Address, Value: make([]byte, 18)},         // malformed 18B -> ignored
			{Type: ikev2.Config3GPPPCSCFIPv4Address, Value: []byte{172, 16, 10, 9}},
			{Type: ikev2.Config3GPPPCSCFIPv6Address, Value: net.ParseIP("2001:db8:44::5060").To16()},
		},
	}

	res := tunnelResultFromIKE(TunnelConfig{}, "epdg.example", ikev2.InitResult{MOBIKESupported: true}, child, DataplaneModeUserspace)
	if res.LocalInnerIPv4 != "10.88.0.2" ||
		res.LocalInnerIPv6 != "2001:db8:44::2" ||
		res.LocalInnerIPv6PrefixLen != 64 ||
		res.LocalInnerIPv6Prefix != "2001:db8:44::2/64" {
		t.Fatalf("unexpected TunnelResult IPv4/IPv6 fields: %+v", res)
	}
	if len(res.LocalInnerIPs) != 2 || res.LocalInnerIPs[0] != "10.88.0.2" || res.LocalInnerIPs[1] != "2001:db8:44::2" {
		t.Fatalf("unexpected LocalInnerIPs: %v", res.LocalInnerIPs)
	}
	if len(res.PCSCFServers) != 2 || res.PCSCFServers[0] != "172.16.10.9" || res.PCSCFServers[1] != "2001:db8:44::5060" {
		t.Fatalf("3GPP private P-CSCF attributes not parsed: %v", res.PCSCFServers)
	}

	tunAddrs := innerAddressesForTUN(res)
	if len(tunAddrs) != 2 || tunAddrs[0] != "10.88.0.2" || tunAddrs[1] != "2001:db8:44::2/64" {
		t.Fatalf("innerAddressesForTUN() = %v, want [10.88.0.2 2001:db8:44::2/64]", tunAddrs)
	}

	// HIGH-03: default '6' EAP-AKA' NAI vs LegacyEAPAKAIdentity '0'.
	naiPrime, err := eapIdentityForTunnel(TunnelConfig{IMSI: "310280233641503", MCC: "310", MNC: "280"}, "")
	if err != nil || naiPrime != "6310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org" {
		t.Fatalf("naiPrime = %q, err = %v", naiPrime, err)
	}
	naiLegacy, err := eapIdentityForTunnel(TunnelConfig{IMSI: "310280233641503", MCC: "310", MNC: "280", LegacyEAPAKAIdentity: true}, "")
	if err != nil || naiLegacy != "0310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org" {
		t.Fatalf("naiLegacy = %q, err = %v", naiLegacy, err)
	}
}

func TestAuditRound2_HIGH05_SOCKS5ControlDropWakesSharedNATTAndFiltersSource(t *testing.T) {
	targetUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(target) error = %v", err)
	}
	defer targetUDP.Close()

	srv := startLocalSOCKS5UDPTestServer(t, "tcp4", "", "", socks5ATYPIPv4, "")

	// 1. Source filtering & EMSGSIZE on socks5UDPConn directly.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sConn, err := dialSOCKS5UDPConn(ctx, &ProxyConfig{Enabled: true, Address: srv.Addr()}, targetUDP.LocalAddr().String(), "", 2*time.Second)
	if err != nil {
		t.Fatalf("dialSOCKS5UDPConn() error = %v", err)
	}
	defer sConn.Close()

	// Send one datagram so relay learns client UDP addr.
	clientUDPAddrCh := make(chan *net.UDPAddr, 1)
	go func() {
		buf := make([]byte, 2048)
		_, addr, rerr := srv.udpRelay.ReadFromUDP(buf)
		if rerr == nil {
			clientUDPAddrCh <- addr
		}
	}()
	if _, err := sConn.Write([]byte("hello")); err != nil {
		t.Fatalf("sConn.Write() error = %v", err)
	}
	clientUDPAddr := <-clientUDPAddrCh

	// Inject forged source IP (127.0.0.2 instead of 127.0.0.1) followed by valid target source IP!
	forgedSpec, _ := parseSOCKS5Target("127.0.0.2:4500", DefaultNATTUDPPort)
	validSpec, _ := parseSOCKS5Target(targetUDP.LocalAddr().String(), DefaultNATTUDPPort)
	_, _ = srv.udpRelay.WriteToUDP(append(append([]byte(nil), forgedSpec.header...), []byte("forged")...), clientUDPAddr)
	_, _ = srv.udpRelay.WriteToUDP(append(append([]byte(nil), validSpec.header...), []byte("authentic")...), clientUDPAddr)

	_ = sConn.SetReadDeadline(time.Now().Add(time.Second))
	readBuf := make([]byte, 64)
	n, err := sConn.Read(readBuf)
	if err != nil || string(readBuf[:n]) != "authentic" {
		t.Fatalf("Read() = %q, %v (forged packet was not filtered!)", string(readBuf[:n]), err)
	}

	// Oversized payload > caller buffer must return EMSGSIZE instead of truncating.
	_, _ = srv.udpRelay.WriteToUDP(append(append([]byte(nil), validSpec.header...), bytes.Repeat([]byte("X"), 32)...), clientUDPAddr)
	smallBuf := make([]byte, 8)
	if _, err := sConn.Read(smallBuf); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("expected EMSGSIZE on short read buffer, got %v", err)
	}

	// 2. Shared NATT transport wakes blocked ReadESPPacket & ReadIKERequest immediately when SOCKS5 TCP control drops!
	sharedIKE := newSharedNATTTransportWithProxy(
		targetUDP.LocalAddr().String(),
		"",
		2*time.Second,
		&ProxyConfig{Enabled: true, Address: srv.Addr()},
	)
	defer sharedIKE.Close()
	if _, _, err := sharedIKE.prepareNetworkEndpoints(ctx); err != nil {
		t.Fatalf("prepareNetworkEndpoints() error = %v", err)
	}
	sharedESP := sharedIKE.sharedESPTransport()

	espErrCh := make(chan error, 1)
	ikeErrCh := make(chan error, 1)
	readCtx, cancelReads := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelReads()
	go func() {
		_, rerr := sharedESP.(ESPPacketReceiver).ReadESPPacket(readCtx)
		espErrCh <- rerr
	}()
	go func() {
		_, rerr := sharedIKE.ReadIKERequest(readCtx)
		ikeErrCh <- rerr
	}()

	time.Sleep(40 * time.Millisecond)
	srv.CloseControlConns()

	select {
	case rerr := <-espErrCh:
		if rerr == nil || errors.Is(rerr, context.DeadlineExceeded) {
			t.Fatalf("ReadESPPacket did not wake with control error: %v", rerr)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("DEADLOCK: ReadESPPacket hung after SOCKS5 TCP control channel dropped!")
	}
	select {
	case rerr := <-ikeErrCh:
		if rerr == nil || errors.Is(rerr, context.DeadlineExceeded) {
			t.Fatalf("ReadIKERequest did not wake with control error: %v", rerr)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("DEADLOCK: ReadIKERequest hung after SOCKS5 TCP control channel dropped!")
	}
}

func TestAuditRound2_HIGH06_MTUCalculationTCPMSSClampingAndICMPPTB(t *testing.T) {
	// 1. effectiveSessionMTU calculation & route advmss.
	if got := effectiveSessionMTU(0, TunnelConfig{OuterLocalIP: "192.0.2.10"}, TunnelResult{LocalInnerIPv4: "10.0.0.2"}); got != 1360 {
		t.Fatalf("default IPv4 MTU = %d, want 1360", got)
	}
	if got := effectiveSessionMTU(0, TunnelConfig{
		OuterLocalIP: "192.0.2.10",
		Proxy:        &ProxyConfig{Enabled: true, Address: "127.0.0.1:1080"},
	}, TunnelResult{LocalInnerIPv6: "2001:db8::2"}); got != 1280 {
		t.Fatalf("SOCKS5 IPv6 MTU = %d, want 1280", got)
	}
	if got := effectiveSessionMTU(1200, TunnelConfig{}, TunnelResult{LocalInnerIPv6: "2001:db8::2"}); got != 1280 {
		t.Fatalf("IPv6 minimum MTU clamp = %d, want 1280", got)
	}
	tunMgr := &TUNTunnelManager{Config: TUNTunnelManagerConfig{IsolateHostRouting: true}}
	rcfg, err := tunMgr.routingConfig(context.Background(), TunnelConfig{OuterLocalIP: "192.0.2.10"}, TunnelResult{
		LocalInnerIPv4:       "10.0.0.2",
		LocalInnerIPv6:       "2001:db8::2",
		LocalInnerIPv6Prefix: "2001:db8::2/64",
	}, "tun7")
	if err != nil {
		t.Fatalf("routingConfig() error = %v", err)
	}
	if rcfg.MTU != 1360 || len(rcfg.Routes) != 2 || rcfg.Routes[0].AdvMSS != 1320 || rcfg.Routes[1].AdvMSS != 1300 {
		t.Fatalf("unexpected routingConfig MTU/AdvMSS: %+v", rcfg)
	}

	// 2. TCP SYN MSS clamping (both even and odd option offsets, IPv4 & IPv6) with valid TCP checksum.
	wire := &blockingQueueESPTransport{ch: make(chan []byte, 8)}
	sender, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(true),
		Transport: wire,
		MTU:       1360,
	})
	if err != nil {
		t.Fatalf("NewPacketSession(sender) error = %v", err)
	}
	receiver, err := NewPacketSession(PacketSessionConfig{
		ChildSA:   packetChildSA(false),
		Transport: wire,
		MTU:       1360,
	})
	if err != nil {
		t.Fatalf("NewPacketSession(receiver) error = %v", err)
	}

	// Odd-offset IPv4 TCP SYN: [NOP(1), MSS(4)=1460, NOP(1), NOP(1), NOP(1)] -> MSS value at TCP[23:25]!
	oddOpts := []byte{1, 2, 4, 0x05, 0xb4, 1, 1, 1}
	v4Syn := buildTestIPv4TCPSYN(net.IPv4(10, 0, 0, 2), net.IPv4(172, 16, 0, 10), 50620, 5060, true, oddOpts)
	if err := sender.SendInnerPacket(context.Background(), v4Syn); err != nil {
		t.Fatalf("SendInnerPacket(v4Syn) error = %v", err)
	}
	espPkt := <-wire.ch
	gotV4SynPkt, err := receiver.ReceiveESPPacket(context.Background(), espPkt)
	if err != nil {
		t.Fatalf("ReceiveESPPacket(v4Syn) error = %v", err)
	}
	gotV4Syn := gotV4SynPkt.Payload
	if mss := binary.BigEndian.Uint16(gotV4Syn[20+23 : 20+25]); mss != 1320 {
		t.Fatalf("clamped IPv4 odd-offset MSS = %d, want 1320", mss)
	}
	if !verifyIPv4TCPChecksum(gotV4Syn) {
		t.Fatal("IPv4 TCP checksum invalid after odd-offset MSS clamp!")
	}

	// Even-offset IPv6 TCP SYN+ACK: [MSS(4)=1440] -> MSS value at TCP[22:24]!
	evenOpts := []byte{2, 4, 0x05, 0xa0}
	v6Syn := buildTestIPv6TCPSYN(net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::5060"), 5060, 50620, evenOpts)
	if err := sender.SendInnerPacket(context.Background(), v6Syn); err != nil {
		t.Fatalf("SendInnerPacket(v6Syn) error = %v", err)
	}
	espPkt6 := <-wire.ch
	gotV6SynPkt, err := receiver.ReceiveESPPacket(context.Background(), espPkt6)
	if err != nil {
		t.Fatalf("ReceiveESPPacket(v6Syn) error = %v", err)
	}
	gotV6Syn := gotV6SynPkt.Payload
	if mss := binary.BigEndian.Uint16(gotV6Syn[40+22 : 40+24]); mss != 1300 {
		t.Fatalf("clamped IPv6 MSS = %d, want 1300", mss)
	}
	if !verifyIPv6TCPChecksum(gotV6Syn) {
		t.Fatal("IPv6 TCP checksum invalid after MSS clamp!")
	}

	// 3. Oversized DF=1 IPv4 and oversized IPv6 packets immediately wake ReadInnerPacket with ICMP PTB!
	ptbCh := make(chan []byte, 2)
	readCtx, cancelRead := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelRead()
	go func() {
		pkt, rerr := sender.ReadInnerPacket(readCtx)
		if rerr == nil {
			ptbCh <- pkt.Payload
		}
	}()
	time.Sleep(25 * time.Millisecond)

	bigV4 := buildTestIPv4TCPSYN(net.IPv4(10, 0, 0, 2), net.IPv4(172, 16, 0, 10), 40000, 5060, true, nil)
	bigV4 = append(bigV4, bytes.Repeat([]byte("S"), 1400)...)
	binary.BigEndian.PutUint16(bigV4[2:4], uint16(len(bigV4)))
	binary.BigEndian.PutUint16(bigV4[10:12], 0)
	binary.BigEndian.PutUint16(bigV4[10:12], computeOnesComplementChecksum(bigV4[:20]))

	if err := sender.SendInnerPacket(context.Background(), bigV4); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("SendInnerPacket(bigV4) error = %v, want EMSGSIZE", err)
	}
	select {
	case icmp4 := <-ptbCh:
		if len(icmp4) < 28 || icmp4[9] != 1 || icmp4[20] != 3 || icmp4[21] != 4 {
			t.Fatalf("unexpected ICMPv4 PTB header: %x", icmp4[:min(len(icmp4), 28)])
		}
		if mtu := binary.BigEndian.Uint16(icmp4[26:28]); mtu != 1360 {
			t.Fatalf("ICMPv4 Next-Hop MTU = %d, want 1360", mtu)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadInnerPacket was not immediately woken with ICMPv4 Fragmentation Needed!")
	}

	bigV6 := testValidIPv6Packet(net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::5060"), bytes.Repeat([]byte("V"), 1400))
	if err := sender.SendInnerPacket(context.Background(), bigV6); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("SendInnerPacket(bigV6) error = %v, want EMSGSIZE", err)
	}
	icmp6Pkt, err := sender.ReadInnerPacket(readCtx)
	if err != nil {
		t.Fatalf("ReadInnerPacket(icmp6) error = %v", err)
	}
	icmp6 := icmp6Pkt.Payload
	if len(icmp6) < 48 || icmp6[6] != 58 || icmp6[40] != 2 || icmp6[41] != 0 {
		t.Fatalf("unexpected ICMPv6 PTB packet: %x", icmp6[:min(len(icmp6), 48)])
	}
	if mtu := binary.BigEndian.Uint32(icmp6[44:48]); mtu != 1360 {
		t.Fatalf("ICMPv6 PTB MTU = %d, want 1360", mtu)
	}
}

func TestAuditRound2_HIGH07_PeerCreateChildSARekeyIKESAAndKernelSessionMaintenance(t *testing.T) {
	keys := testAuditIKEKeysGCM(t)
	profile := testAuditIKEProfileGCM(t)
	initRes := ikev2.InitResult{
		InitiatorSPI:    0x1111222233334444,
		ResponderSPI:    0x5555666677778888,
		Keys:            keys,
		PRF:             profile.PRF,
		SelectedSA:      testAuditSelectedIKESA(),
		MOBIKESupported: true,
		NATDetected:     true,
	}
	oldChild := packetChildSA(true)
	oldChild.Keys.Profile.EncryptionID = ikev2.ENCR_AES_CBC
	oldChild.Keys.Profile.EncryptionKeyLength = 16
	oldChild.Keys.Profile.IntegrityKeyLength = 32
	oldChild.SelectedSA = ikev2.SecurityAssociation{
		Proposals: []ikev2.Proposal{
			{
				Number:     1,
				ProtocolID: ikev2.ProtocolESP,
				SPI:        append([]byte(nil), oldChild.RemoteSPI...),
				Transforms: []ikev2.Transform{
					{Type: ikev2.TransformENCR, ID: ikev2.ENCR_AES_CBC, Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(128)}},
					{Type: ikev2.TransformINTEG, ID: ikev2.INTEG_HMAC_SHA2_256_128},
					{Type: ikev2.TransformESN, ID: ikev2.ESNNo},
				},
			},
		},
	}
	oldChild.TSi = ikev2.SWuAnyTrafficSelectors()
	oldChild.TSr = ikev2.SWuAnyTrafficSelectors()

	// 1. Simultaneous collision (rekeyInFlight = true) returns TEMPORARY_FAILURE (43).
	peerChildReq := buildPeerChildRekeyRequest(t, initRes, keys, oldChild, 7)
	collisionOut, err := processPeerIKERequest(peerChildReq, initRes, keys, nil, ikev2.IKEKeys{}, oldChild, true, rand.Reader)
	if err != nil {
		t.Fatalf("processPeerIKERequest(collision) error = %v", err)
	}
	_, collisionInner, err := ikev2.UnprotectMessage(collisionOut.Response, keys, true)
	if err != nil {
		t.Fatalf("UnprotectMessage(collision) error = %v", err)
	}
	if len(collisionInner) != 1 || collisionInner[0].Type != ikev2.PayloadNotify {
		t.Fatalf("expected 1 Notify payload on collision, got %+v", collisionInner)
	}
	ntf, err := ikev2.ParseNotify(collisionInner[0].Body)
	if err != nil || ntf.NotifyType != ikev2.NotifyTemporaryFailure {
		t.Fatalf("expected TEMPORARY_FAILURE notify on collision, got %+v (err=%v)", ntf, err)
	}

	// 2. Peer-initiated ESP Child SA rekey succeeds.
	rekeyOut, err := processPeerIKERequest(peerChildReq, initRes, keys, nil, ikev2.IKEKeys{}, oldChild, false, rand.Reader)
	if err != nil || rekeyOut.NewChildSA == nil {
		t.Fatalf("processPeerIKERequest(child rekey) out=%+v err=%v", rekeyOut, err)
	}
	if len(rekeyOut.NewChildSA.LocalSPI) != 4 || bytes.Equal(rekeyOut.NewChildSA.LocalSPI, oldChild.LocalSPI) {
		t.Fatalf("NewChildSA.LocalSPI = %x", rekeyOut.NewChildSA.LocalSPI)
	}

	// 3. Peer-initiated IKE SA rekey + subsequent old-IKE-SA DELETE does NOT tear down tunnel!
	peerIKEReq := buildPeerIKERekeyRequest(t, initRes, keys, 8)
	ikeRekeyOut, err := processPeerIKERequest(peerIKEReq, initRes, keys, nil, ikev2.IKEKeys{}, *rekeyOut.NewChildSA, false, rand.Reader)
	if err != nil || ikeRekeyOut.NewIKEInit == nil {
		t.Fatalf("processPeerIKERequest(IKE rekey) out=%+v err=%v", ikeRekeyOut, err)
	}
	oldSADeleteReq := buildPeerIKEDeleteRequest(t, initRes, keys, 9)
	delOut, err := processPeerIKERequest(oldSADeleteReq, *ikeRekeyOut.NewIKEInit, ikeRekeyOut.NewIKEInit.Keys, &initRes, keys, *rekeyOut.NewChildSA, false, rand.Reader)
	if err != nil {
		t.Fatalf("processPeerIKERequest(old IKE SA delete) error = %v", err)
	}
	if delOut.CloseReason != "" {
		t.Fatalf("old IKE SA delete must NOT close active rekeyed tunnel! CloseReason=%q", delOut.CloseReason)
	}
	if len(delOut.Response) == 0 {
		t.Fatal("expected authenticated INFORMATIONAL ACK for old IKE SA delete")
	}

	// 4. kernelTunnelSession: NAT-T keepalives, inbound peer DPD, RekeyChildSA, RekeyIKESA, and MOBIKE XFRM update!
	mockXFRM := &recordingXFRMManager{}
	mockPeerPipe := &mockKernelIKETransport{
		inboundReqs: make(chan []byte, 4),
		sentMsgs:    make(chan []byte, 4),
	}
	start := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	liveness, err := NewIKELivenessState(IKELivenessConfig{
		KeepaliveInterval: 10 * time.Second,
		DPDInterval:       30 * time.Second,
		DPDTimeout:        10 * time.Second,
	}, start)
	if err != nil {
		t.Fatalf("NewIKELivenessState() error = %v", err)
	}

	initialXFRMCfg, err := KernelXFRMConfigFromIKE(KernelXFRMConfigFromIKEConfig{
		Tunnel:        TunnelConfig{OuterLocalIP: "192.0.2.10"},
		Transport:     IKETransportConfig{LocalIP: net.IPv4(192, 0, 2, 10), RemoteIP: net.IPv4(198, 51, 100, 7), LocalPort: 4500, RemotePort: 4500},
		Init:          initRes,
		ChildSA:       oldChild,
		XFRMInterface: XFRMInterfaceConfig{Name: "xfrmi9", OuterDev: "wlan0"},
	})
	if err != nil {
		t.Fatalf("KernelXFRMConfigFromIKE(initial) error = %v", err)
	}
	initState, _ := mockXFRM.Apply(context.Background(), initialXFRMCfg)

	ks, err := newKernelTunnelSessionWithControl(kernelTunnelSessionConfig{
		Result: TunnelResult{
			Ready:            true,
			Mode:             DataplaneModeKernel,
			LocalInnerIP:     "10.0.0.2",
			IKEEstablished:   true,
			IPsecEstablished: true,
			MOBIKESupported:  true,
			EstablishedAt:    start,
		},
		Transport:   mockPeerPipe,
		Init:        initRes,
		ChildSA:     oldChild,
		XFRMConfig:  initialXFRMCfg,
		XFRMManager: mockXFRM,
		XFRMState:   initState,
		Liveness:    liveness,
		MOBIKEHandler: func(_ context.Context, req MOBIKERequest) (MOBIKEResult, error) {
			return MOBIKEResult{OuterLocalIP: req.NewIP, Reason: "mobike updated"}, nil
		},
		RekeyHandler: func(context.Context) (ikev2.ChildSAResult, error) {
			next := packetRekeyChildSA(true)
			next.Keys.Profile.EncryptionID = ikev2.ENCR_AES_CBC
			next.Keys.Profile.EncryptionKeyLength = 16
			next.Keys.Profile.IntegrityKeyLength = 32
			return next, nil
		},
		IKERekeyHandler: func(context.Context) (ikev2.InitResult, error) {
			next := initRes
			next.InitiatorSPI = 0x9999000011112222
			next.Rekeyed = true
			return next, nil
		},
		PeerIKERequestHandler: func(_ context.Context, raw []byte) (PeerIKERequestOutcome, error) {
			return processPeerIKERequest(raw, initRes, keys, nil, ikev2.IKEKeys{}, oldChild, false, rand.Reader)
		},
	})
	if err != nil {
		t.Fatalf("newKernelTunnelSessionWithControl() error = %v", err)
	}
	defer ks.Close(context.Background())

	// NAT-T keepalive on kernel session.
	dec, err := ks.AdvanceIKELiveness(context.Background(), start.Add(10*time.Second))
	if err != nil || dec.Action != IKELivenessSendKeepalive || mockPeerPipe.keepalivesCount() != 1 {
		t.Fatalf("kernel keepalive dec=%+v err=%v count=%d", dec, err, mockPeerPipe.keepalivesCount())
	}

	// Inbound peer DPD probe answered automatically on kernel session!
	_, dpdProbe, err := ikev2.ProtectMessage(ikev2.Header{
		InitiatorSPI: initRes.InitiatorSPI,
		ResponderSPI: initRes.ResponderSPI,
		ExchangeType: ikev2.ExchangeINFORMATIONAL,
		Flags:        0, // responder-initiated request
		MessageID:    3,
	}, keys, false, nil, nil)
	if err != nil {
		t.Fatalf("ProtectMessage(dpdProbe) error = %v", err)
	}
	mockPeerPipe.inboundReqs <- dpdProbe
	select {
	case respBytes := <-mockPeerPipe.sentMsgs:
		respHdr, inner, uerr := ikev2.UnprotectMessage(respBytes, keys, true)
		if uerr != nil || respHdr.Header.MessageID != 3 || len(inner) != 0 {
			t.Fatalf("unexpected DPD ACK: hdr=%+v inner=%v err=%v", respHdr.Header, inner, uerr)
		}
	case <-time.After(time.Second):
		t.Fatal("kernelTunnelSession did not reply to inbound peer DPD probe!")
	}

	// Initiator RekeyChildSA updates XFRM in-place (SkipCreateLink = true).
	if _, err := ks.RekeyChildSA(context.Background()); err != nil {
		t.Fatalf("ks.RekeyChildSA() error = %v", err)
	}
	lastCfg := mockXFRM.lastApplied()
	if !lastCfg.XFRMInterface.SkipCreateLink || !bytes.Equal(lastCfg.ChildSA.LocalSPI, []byte{0x33, 0x33, 0x33, 0x33}) {
		t.Fatalf("kernel RekeyChildSA XFRM cfg = %+v", lastCfg)
	}

	// Initiator RekeyIKESA updates kernel session IKE state.
	rekeyedRes, err := ks.RekeyIKESA(context.Background())
	if err != nil || !rekeyedRes.IsReady() || ks.init.InitiatorSPI != 0x9999000011112222 {
		t.Fatalf("ks.RekeyIKESA() = %+v, err=%v, spi=%x", rekeyedRes, err, ks.init.InitiatorSPI)
	}

	// MOBIKE updates XFRM OuterLocalIP in-place.
	if _, err := ks.MOBIKE(context.Background(), MOBIKERequest{OldIP: "192.0.2.10", NewIP: "192.0.2.99"}); err != nil {
		t.Fatalf("ks.MOBIKE() error = %v", err)
	}
	if gotOuter := mockXFRM.lastApplied().OuterLocalIP; gotOuter != "192.0.2.99" {
		t.Fatalf("kernel MOBIKE XFRM OuterLocalIP = %q, want 192.0.2.99", gotOuter)
	}
}

func TestAuditRound2_HIGH09_InnerPacketValidationPadStripAndTrafficSelectors(t *testing.T) {
	wire := &captureESPPacketTransport{}
	childA := packetChildSA(true)
	childA.TSi = ikev2.TrafficSelectors{Selectors: []ikev2.TrafficSelector{
		{
			Type:       ikev2.TSIPv4AddressRange,
			IPProtocol: 17, // UDP only
			StartPort:  5060,
			EndPort:    5061,
			StartAddr:  net.IPv4(10, 0, 0, 2).To4(),
			EndAddr:    net.IPv4(10, 0, 0, 2).To4(),
		},
		{
			Type:      ikev2.TSIPv6AddressRange,
			StartAddr: net.ParseIP("2001:db8::2").To16(),
			EndAddr:   net.ParseIP("2001:db8::2").To16(),
		},
	}}
	childA.TSr = ikev2.TrafficSelectors{Selectors: []ikev2.TrafficSelector{
		{
			Type:       ikev2.TSIPv4AddressRange,
			IPProtocol: 17,
			StartPort:  5060,
			EndPort:    5061,
			StartAddr:  net.IPv4(172, 16, 0, 10).To4(),
			EndAddr:    net.IPv4(172, 16, 0, 10).To4(),
		},
		{
			Type:      ikev2.TSIPv6AddressRange,
			StartAddr: net.ParseIP("2001:db8::10").To16(),
			EndAddr:   net.ParseIP("2001:db8::10").To16(),
		},
	}}
	childB := packetChildSA(false)
	childB.TSi = childA.TSr
	childB.TSr = childA.TSi

	sender, err := NewPacketSession(PacketSessionConfig{ChildSA: childA, Transport: wire})
	if err != nil {
		t.Fatalf("NewPacketSession(sender) error = %v", err)
	}
	receiver, err := NewPacketSession(PacketSessionConfig{ChildSA: childB, Transport: wire})
	if err != nil {
		t.Fatalf("NewPacketSession(receiver) error = %v", err)
	}

	// 1. Malformed packets rejected with ErrUnsupportedInnerPacket.
	badChecksumV4 := testValidIPv4Packet(net.IPv4(10, 0, 0, 2), net.IPv4(172, 16, 0, 10), []byte("ok"))
	badChecksumV4[10] ^= 0xff
	badIHLV4 := testValidIPv4Packet(net.IPv4(10, 0, 0, 2), net.IPv4(172, 16, 0, 10), []byte("ok"))
	badIHLV4[0] = 0x44 // IHL=4 (<5)
	badLenV6 := testValidIPv6Packet(net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::10"), []byte("abcd"))
	binary.BigEndian.PutUint16(badLenV6[4:6], 50) // claims 50B payload, actual 4B

	for name, pkt := range map[string][]byte{
		"1byte_v4":     {0x45},
		"1byte_v6":     {0x60},
		"bad_checksum": badChecksumV4,
		"bad_ihl":      badIHLV4,
		"bad_v6_len":   badLenV6,
	} {
		if err := sender.SendInnerPacket(context.Background(), pkt); !errors.Is(err, ErrUnsupportedInnerPacket) {
			t.Fatalf("%s: SendInnerPacket err = %v, want ErrUnsupportedInnerPacket", name, err)
		}
	}

	// 2. Traffic selector violations (wrong source IP, wrong protocol, wrong port) rejected!
	spoofedSrc := buildTestIPv4UDPPacket(net.IPv4(10, 0, 0, 99), net.IPv4(172, 16, 0, 10), 5060, 5060, []byte("sip"))
	if err := sender.SendInnerPacket(context.Background(), spoofedSrc); !errors.Is(err, ErrUnsupportedInnerPacket) || !strings.Contains(err.Error(), "outside traffic selectors") {
		t.Fatalf("spoofedSrc err = %v, want traffic selector rejection", err)
	}
	wrongPort := buildTestIPv4UDPPacket(net.IPv4(10, 0, 0, 2), net.IPv4(172, 16, 0, 10), 9999, 5060, []byte("sip"))
	if err := sender.SendInnerPacket(context.Background(), wrongPort); !errors.Is(err, ErrUnsupportedInnerPacket) || !strings.Contains(err.Error(), "outside traffic selectors") {
		t.Fatalf("wrongPort err = %v, want traffic selector rejection", err)
	}

	// Valid UDP 5060 packet with trailing RFC 4301 padding bytes: trailing bytes stripped on ReceiveESPPacket!
	validUDP := buildTestIPv4UDPPacket(net.IPv4(10, 0, 0, 2), net.IPv4(172, 16, 0, 10), 5060, 5060, []byte("REGISTER sip:ims"))
	paddedWireInner := append(append([]byte(nil), validUDP...), 0xde, 0xad, 0xbe, 0xef)
	peerRawSA, err := esp.NewOutboundSAFromChild(childA)
	if err != nil {
		t.Fatalf("NewOutboundSAFromChild() error = %v", err)
	}
	rawESP, err := peerRawSA.Seal(esp.NextHeaderIPv4, paddedWireInner, esp.SealOptions{})
	if err != nil {
		t.Fatalf("peerRawSA.Seal() error = %v", err)
	}
	opened, err := receiver.ReceiveESPPacket(context.Background(), rawESP)
	if err != nil {
		t.Fatalf("ReceiveESPPacket() error = %v", err)
	}
	if !bytes.Equal(opened.Payload, validUDP) {
		t.Fatalf("trailing pad not stripped: got len=%d want len=%d", len(opened.Payload), len(validUDP))
	}

	// Inbound TS violation: packet encrypted with valid SA keys by peer, but inner src IP is 127.0.0.1!
	spoofedLoopback := buildTestIPv4UDPPacket(net.IPv4(127, 0, 0, 1), net.IPv4(172, 16, 0, 10), 5060, 5060, []byte("inject"))
	spoofedESP, err := peerRawSA.Seal(esp.NextHeaderIPv4, spoofedLoopback, esp.SealOptions{})
	if err != nil {
		t.Fatalf("peerRawSA.Seal(spoofed) error = %v", err)
	}
	if _, err := receiver.ReceiveESPPacket(context.Background(), spoofedESP); !errors.Is(err, ErrUnsupportedInnerPacket) || !strings.Contains(err.Error(), "outside traffic selectors") {
		t.Fatalf("inbound spoofed loopback ESP err = %v, want traffic selector rejection", err)
	}
}

func TestAuditRound2_MED06_MOBIKEConcurrencyAndLocalSocketRebind(t *testing.T) {
	// 1. Real localhost UDP socket rebind before UPDATE_SA_ADDRESSES!
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer serverConn.Close()

	keys := testAuditIKEKeysGCM(t)
	profile := testAuditIKEProfileGCM(t)
	initRes := ikev2.InitResult{
		InitiatorSPI:    0xaaaa1111bbbb2222,
		ResponderSPI:    0xcccc3333dddd4444,
		Keys:            keys,
		PRF:             profile.PRF,
		SelectedSA:      testAuditSelectedIKESA(),
		MOBIKESupported: true,
		NATDetected:     true,
	}

	shared := newSharedNATTTransport(serverConn.LocalAddr().String(), "127.0.0.1:0", 2*time.Second)
	defer shared.Close()
	firstLocal, _, err := shared.prepareNetworkEndpoints(context.Background())
	if err != nil {
		t.Fatalf("prepareNetworkEndpoints() error = %v", err)
	}
	firstPort := firstLocal.(*net.UDPAddr).Port

	observedPorts := make(chan int, 16)
	stopServer := make(chan struct{})
	defer close(stopServer)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, clientAddr, rerr := serverConn.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			select {
			case <-stopServer:
				return
			default:
			}
			if n <= 4 {
				continue
			}
			observedPorts <- clientAddr.Port
			reqHdr, inner, uerr := ikev2.UnprotectMessage(buf[4:n], keys, true)
			if uerr != nil {
				continue
			}
			var respPayloads []ikev2.Payload
			if reqHdr.Header.ExchangeType == ikev2.ExchangeCREATE_CHILD_SA {
				respPayloads = buildResponderChildRekeyPayloads(t, inner)
			} else {
				for _, p := range inner {
					if p.Type != ikev2.PayloadNotify {
						continue
					}
					ntf, nerr := ikev2.ParseNotify(p.Body)
					if nerr == nil && ntf.NotifyType == ikev2.NotifyCookie2 {
						np, _ := ikev2.NotifyPayload(ntf)
						respPayloads = append(respPayloads, np)
					}
				}
			}
			_, respRaw, perr := ikev2.ProtectMessage(ikev2.Header{
				InitiatorSPI: reqHdr.Header.InitiatorSPI,
				ResponderSPI: reqHdr.Header.ResponderSPI,
				ExchangeType: reqHdr.Header.ExchangeType,
				Flags:        ikev2.FlagResponse,
				MessageID:    reqHdr.Header.MessageID,
			}, keys, false, respPayloads, nil)
			if perr == nil {
				_, _ = serverConn.WriteToUDP(append([]byte{0, 0, 0, 0}, respRaw...), clientAddr)
			}
		}
	}()

	child := packetChildSA(true)
	_, mobikeFn, rekeyFn, _, deleteFn, dpdFn, _ := controlHandlersFromWithIKERekey(
		IKEPacketTunnelManagerConfig{Random: rand.Reader},
		shared,
		initRes,
		ikev2.FullAuthResult{ChildSA: &child, NextMessageID: 2},
		child,
		TunnelResult{Ready: true, IKEEstablished: true, IPsecEstablished: true, MOBIKESupported: true},
		IKETransportConfig{
			LocalIP:    net.IPv4(127, 0, 0, 1),
			RemoteIP:   net.IPv4(127, 0, 0, 1),
			LocalPort:  uint16(firstPort),
			RemotePort: uint16(serverConn.LocalAddr().(*net.UDPAddr).Port),
		},
	)

	// Run concurrent MOBIKE + RekeyChildSA + DPD + DeleteChildSA under -race!
	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	wg.Add(4)
	go func() {
		defer wg.Done()
		_, merr := mobikeFn(context.Background(), MOBIKERequest{OldIP: "127.0.0.1", NewIP: "127.0.0.1"})
		errCh <- merr
	}()
	go func() {
		defer wg.Done()
		_, rerr := rekeyFn(context.Background())
		errCh <- rerr
	}()
	go func() {
		defer wg.Done()
		errCh <- dpdFn(context.Background())
	}()
	go func() {
		defer wg.Done()
		errCh <- deleteFn(context.Background(), []byte{0xde, 0xad, 0x00, 0x01})
	}()
	wg.Wait()
	close(errCh)
	for cerr := range errCh {
		if cerr != nil {
			t.Fatalf("concurrent control operation error = %v", cerr)
		}
	}

	// Confirm the UDP socket was actually rebound (new local ephemeral port != firstPort).
	reboundAddr := shared.underlyingUDPConn().LocalAddr().(*net.UDPAddr)
	if reboundAddr.Port == firstPort {
		t.Fatalf("expected MOBIKE RebindLocalIP to bind a fresh socket; port remained %d", firstPort)
	}
}

// --- Test Helpers ---

func testAuditIKEProfileGCM(t *testing.T) ikev2.KeyMaterialProfile {
	t.Helper()
	p, err := ikev2.KeyMaterialProfileFromSA(testAuditSelectedIKESA())
	if err != nil {
		t.Fatalf("KeyMaterialProfileFromSA() error = %v", err)
	}
	return p
}

func testAuditIKEKeysGCM(t *testing.T) ikev2.IKEKeys {
	t.Helper()
	p := testAuditIKEProfileGCM(t)
	mat := bytes.Repeat([]byte{0x42}, p.RequiredLength())
	k, err := ikev2.SplitIKEKeys(p, mat)
	if err != nil {
		t.Fatalf("SplitIKEKeys() error = %v", err)
	}
	return k
}

func testAuditSelectedIKESA() ikev2.SecurityAssociation {
	return ikev2.SecurityAssociation{
		Proposals: []ikev2.Proposal{
			{
				Number:     1,
				ProtocolID: ikev2.ProtocolIKE,
				Transforms: []ikev2.Transform{
					{Type: ikev2.TransformENCR, ID: ikev2.ENCR_AES_GCM_16, Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(128)}},
					{Type: ikev2.TransformPRF, ID: ikev2.PRF_HMAC_SHA2_256},
					{Type: ikev2.TransformDHRGroup, ID: ikev2.DHGroupCurve25519},
				},
			},
		},
	}
}

type blockingQueueESPTransport struct {
	ch chan []byte
}

func (b *blockingQueueESPTransport) SendESPPacket(_ context.Context, pkt []byte) error {
	b.ch <- append([]byte(nil), pkt...)
	return nil
}

func (b *blockingQueueESPTransport) ReadESPPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case pkt := <-b.ch:
		return pkt, nil
	}
}

func (b *blockingQueueESPTransport) SendNATTKeepalive(context.Context) error { return nil }
func (b *blockingQueueESPTransport) Close(context.Context) error             { return nil }

func buildTestIPv4TCPSYN(src, dst net.IP, srcPort, dstPort uint16, df bool, opts []byte) []byte {
	for len(opts)%4 != 0 {
		opts = append(opts, 0)
	}
	tcpLen := 20 + len(opts)
	totalLen := 20 + tcpLen
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	if df {
		binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	}
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[10:12], computeOnesComplementChecksum(pkt[:20]))

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = uint8((tcpLen / 4) << 4)
	tcp[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], opts)
	binary.BigEndian.PutUint16(tcp[16:18], ipv4TCPChecksum(src.To4(), dst.To4(), tcp))
	return pkt
}

func buildTestIPv6TCPSYN(src, dst net.IP, srcPort, dstPort uint16, opts []byte) []byte {
	for len(opts)%4 != 0 {
		opts = append(opts, 0)
	}
	tcpLen := 20 + len(opts)
	pkt := make([]byte, 40+tcpLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(tcpLen))
	pkt[6] = 6 // TCP
	pkt[7] = 64
	copy(pkt[8:24], src.To16())
	copy(pkt[24:40], dst.To16())

	tcp := pkt[40:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = uint8((tcpLen / 4) << 4)
	tcp[13] = 0x12 // SYN+ACK
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], opts)
	binary.BigEndian.PutUint16(tcp[16:18], ipv6TCPChecksum(src.To16(), dst.To16(), tcp))
	return pkt
}

func buildTestIPv4UDPPacket(src, dst net.IP, srcPort, dstPort uint16, body []byte) []byte {
	udpLen := 8 + len(body)
	totalLen := 20 + udpLen
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[10:12], computeOnesComplementChecksum(pkt[:20]))
	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], body)
	return pkt
}

func ipv4TCPChecksum(src4, dst4, tcp []byte) uint16 {
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], src4)
	copy(pseudo[4:8], dst4)
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	return computeOnesComplementChecksum(pseudo)
}

func ipv6TCPChecksum(src16, dst16, tcp []byte) uint16 {
	pseudo := make([]byte, 40+len(tcp))
	copy(pseudo[0:16], src16)
	copy(pseudo[16:32], dst16)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(tcp)))
	pseudo[39] = 6
	copy(pseudo[40:], tcp)
	return computeOnesComplementChecksum(pseudo)
}

func verifyIPv4TCPChecksum(pkt []byte) bool {
	return ipv4TCPChecksum(pkt[12:16], pkt[16:20], pkt[20:]) == 0
}

func verifyIPv6TCPChecksum(pkt []byte) bool {
	return ipv6TCPChecksum(pkt[8:24], pkt[24:40], pkt[40:]) == 0
}

func buildPeerChildRekeyRequest(t *testing.T, init ikev2.InitResult, keys ikev2.IKEKeys, oldChild ikev2.ChildSAResult, msgID uint32) []byte {
	t.Helper()
	rekeyNotify, err := ikev2.NotifyPayload(ikev2.Notify{
		ProtocolID: ikev2.ProtocolESP,
		SPI:        append([]byte(nil), oldChild.LocalSPI...),
		NotifyType: ikev2.NotifyRekeySA,
	})
	if err != nil {
		t.Fatalf("NotifyPayload(REKEY_SA) error = %v", err)
	}
	saPayload, err := ikev2.SecurityAssociationPayload(ikev2.DefaultESPProposal([]byte{0x77, 0x88, 0x99, 0xaa}))
	if err != nil {
		t.Fatalf("SecurityAssociationPayload() error = %v", err)
	}
	tsi, err := ikev2.TrafficSelectorsPayload(ikev2.PayloadTSi, ikev2.SWuAnyTrafficSelectors())
	if err != nil {
		t.Fatalf("TrafficSelectorsPayload(TSi) error = %v", err)
	}
	tsr, err := ikev2.TrafficSelectorsPayload(ikev2.PayloadTSr, ikev2.SWuAnyTrafficSelectors())
	if err != nil {
		t.Fatalf("TrafficSelectorsPayload(TSr) error = %v", err)
	}
	_, raw, err := ikev2.ProtectMessage(ikev2.Header{
		InitiatorSPI: init.InitiatorSPI,
		ResponderSPI: init.ResponderSPI,
		ExchangeType: ikev2.ExchangeCREATE_CHILD_SA,
		Flags:        0, // peer responder initiates
		MessageID:    msgID,
	}, keys, false, []ikev2.Payload{
		rekeyNotify,
		saPayload,
		ikev2.NoncePayload(bytes.Repeat([]byte{0x5a}, 32)),
		tsi,
		tsr,
	}, nil)
	if err != nil {
		t.Fatalf("ProtectMessage(peerChildRekey) error = %v", err)
	}
	return raw
}

func buildPeerIKERekeyRequest(t *testing.T, init ikev2.InitResult, keys ikev2.IKEKeys, msgID uint32) []byte {
	t.Helper()
	dhPeer, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("X25519.GenerateKey() error = %v", err)
	}
	kePayload := ikev2.KeyExchangePayload(ikev2.DHGroupCurve25519, dhPeer.PublicKey().Bytes())
	sa := ikev2.SecurityAssociation{
		Proposals: []ikev2.Proposal{
			{
				Number:     1,
				ProtocolID: ikev2.ProtocolIKE,
				SPI:        []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04},
				Transforms: []ikev2.Transform{
					{Type: ikev2.TransformENCR, ID: ikev2.ENCR_AES_GCM_16, Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(128)}},
					{Type: ikev2.TransformPRF, ID: ikev2.PRF_HMAC_SHA2_256},
					{Type: ikev2.TransformDHRGroup, ID: ikev2.DHGroupCurve25519},
				},
			},
		},
	}
	saPayload, err := ikev2.SecurityAssociationPayload(sa)
	if err != nil {
		t.Fatalf("SecurityAssociationPayload() error = %v", err)
	}
	_, raw, err := ikev2.ProtectMessage(ikev2.Header{
		InitiatorSPI: init.InitiatorSPI,
		ResponderSPI: init.ResponderSPI,
		ExchangeType: ikev2.ExchangeCREATE_CHILD_SA,
		Flags:        0,
		MessageID:    msgID,
	}, keys, false, []ikev2.Payload{
		saPayload,
		ikev2.NoncePayload(bytes.Repeat([]byte{0x6b}, 32)),
		kePayload,
	}, nil)
	if err != nil {
		t.Fatalf("ProtectMessage(peerIKERekey) error = %v", err)
	}
	return raw
}

func buildPeerIKEDeleteRequest(t *testing.T, init ikev2.InitResult, keys ikev2.IKEKeys, msgID uint32) []byte {
	t.Helper()
	_, raw, err := ikev2.ProtectMessage(ikev2.Header{
		InitiatorSPI: init.InitiatorSPI,
		ResponderSPI: init.ResponderSPI,
		ExchangeType: ikev2.ExchangeINFORMATIONAL,
		Flags:        0,
		MessageID:    msgID,
	}, keys, false, []ikev2.Payload{ikev2.IKEDeletePayload()}, nil)
	if err != nil {
		t.Fatalf("ProtectMessage(peerIKEDelete) error = %v", err)
	}
	return raw
}

func buildResponderChildRekeyPayloads(t *testing.T, _ []ikev2.Payload) []ikev2.Payload {
	t.Helper()
	selected := ikev2.SecurityAssociation{
		Proposals: []ikev2.Proposal{
			{
				Number:     1,
				ProtocolID: ikev2.ProtocolESP,
				SPI:        []byte{0x99, 0x88, 0x77, 0x66},
				Transforms: []ikev2.Transform{
					{Type: ikev2.TransformENCR, ID: ikev2.ENCR_AES_CBC, Attributes: []ikev2.TransformAttribute{ikev2.KeyLengthAttribute(128)}},
					{Type: ikev2.TransformINTEG, ID: ikev2.INTEG_HMAC_SHA2_256_128},
					{Type: ikev2.TransformESN, ID: ikev2.ESNNo},
				},
			},
		},
	}
	saPayload, err := ikev2.SecurityAssociationPayload(selected)
	if err != nil {
		t.Fatalf("SecurityAssociationPayload() error = %v", err)
	}
	tsi, _ := ikev2.TrafficSelectorsPayload(ikev2.PayloadTSi, ikev2.SWuAnyTrafficSelectors())
	tsr, _ := ikev2.TrafficSelectorsPayload(ikev2.PayloadTSr, ikev2.SWuAnyTrafficSelectors())
	return []ikev2.Payload{
		saPayload,
		ikev2.NoncePayload(bytes.Repeat([]byte{0x7c}, 32)),
		tsi,
		tsr,
	}
}

type recordingXFRMManager struct {
	mu      sync.Mutex
	applied []KernelXFRMConfig
	cleans  int
}

func (m *recordingXFRMManager) Apply(_ context.Context, cfg KernelXFRMConfig) (KernelXFRMState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applied = append(m.applied, cfg)
	return KernelXFRMState{
		undo: []ipCommand{
			{args: []string{"xfrm", "state", "delete", "src", cfg.OuterLocalIP, "dst", cfg.OuterRemoteIP, "proto", "esp", "spi", "0x1"}},
			{args: []string{"link", "del", "dev", "xfrmi9"}},
		},
	}, nil
}

func (m *recordingXFRMManager) Cleanup(context.Context, KernelXFRMState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleans++
	return nil
}

func (m *recordingXFRMManager) lastApplied() KernelXFRMConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applied[len(m.applied)-1]
}

type mockKernelIKETransport struct {
	mu          sync.Mutex
	keepalives  int
	inboundReqs chan []byte
	sentMsgs    chan []byte
}

func (m *mockKernelIKETransport) ExchangeIKE(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("unused in test")
}

func (m *mockKernelIKETransport) SendNATTKeepalive(context.Context) error {
	m.mu.Lock()
	m.keepalives++
	m.mu.Unlock()
	return nil
}

func (m *mockKernelIKETransport) keepalivesCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keepalives
}

func (m *mockKernelIKETransport) ReadIKERequest(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case pkt := <-m.inboundReqs:
		return pkt, nil
	}
}

func (m *mockKernelIKETransport) SendIKEMessage(_ context.Context, raw []byte) error {
	m.sentMsgs <- append([]byte(nil), raw...)
	return nil
}
