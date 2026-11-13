package voiceclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRegisterSessionRewritesContactPortToNegotiatedPortS(t *testing.T) {
	nonce := base64.StdEncoding.EncodeToString(make([]byte, 32))
	transport := &fakeRegisterTransport{
		responses: []RegisterResponse{
			{
				StatusCode: 401,
				Reason:     "Unauthorized",
				Headers: map[string][]string{
					"WWW-Authenticate": {`Digest realm="ims.example", nonce="` + nonce + `", algorithm=AKAv1-MD5, qop="auth"`},
					"Security-Server":  {`ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=401;spi-s=402;port-c=6100;port-s=6101;q=0.9`},
				},
			},
			{
				StatusCode: 200,
				Reason:     "OK",
				Headers: map[string][]string{
					"Contact":          {`<sip:user@192.0.2.10:5060>;expires=1800`},
					"P-Associated-URI": {`<sip:user@ims.example>`},
				},
			},
		},
	}
	res, err := RegisterSession{
		Transport:    transport,
		AKAProvider:  &registerAKAProvider{},
		Profile:      IMSProfile{IMPI: "impi@ims.example", IMPU: "sip:user@ims.example", Domain: "ims.example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@192.0.2.10:5060",
		CallID:       "sec-contact-port-s",
		CNonce:       "cnonce",
		SecurityClient: SecurityAgreement{
			Protocol:            DefaultSecurityProtocol,
			Algorithm:           DefaultSecurityAlgorithm,
			EncryptionAlgorithm: DefaultSecurityEAlg,
			PortClient:          5162,
			PortServer:          5163,
		},
	}.Register(context.Background())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if len(transport.requests) != 2 {
		t.Fatalf("requests=%d, want 2", len(transport.requests))
	}
	if !strings.Contains(transport.requests[0].Headers["Contact"], "<sip:user@192.0.2.10:5060>") {
		t.Fatalf("initial Contact=%q, want port 5060", transport.requests[0].Headers["Contact"])
	}
	if !strings.Contains(transport.requests[1].Headers["Contact"], "<sip:user@192.0.2.10:5163>") {
		t.Fatalf("authenticated Contact=%q, want protected port-s 5163", transport.requests[1].Headers["Contact"])
	}
	if res.Binding.ContactURI != "sip:user@192.0.2.10:5163" {
		t.Fatalf("Binding.ContactURI=%q, want sip:user@192.0.2.10:5163", res.Binding.ContactURI)
	}
	if res.Binding.Expires != 1800 {
		t.Fatalf("Binding.Expires=%d, want 1800", res.Binding.Expires)
	}
}

func TestWireSIPFlowReceivesRportResponsesOnPortCAndReusesExternalPortS(t *testing.T) {
	pcscfUnprotected, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(unprotected) error = %v", err)
	}
	defer pcscfUnprotected.Close()

	pcscfProtected, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(protected) error = %v", err)
	}
	defer pcscfProtected.Close()
	pcscfProtectedPort := udpAddrPort(pcscfProtected.LocalAddr())

	portC, portS, release := AllocateSecurityClientPorts("127.0.0.1", 0, 0)
	release()

	nonce1 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	nonce2 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, 32))
	go func() {
		buf := make([]byte, 65535)
		for {
			_ = pcscfUnprotected.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, rErr := pcscfUnprotected.ReadFrom(buf)
			if rErr != nil {
				return
			}
			req, pErr := ParseSIPRequest(buf[:n])
			if pErr != nil {
				return
			}
			headers := map[string]string{
				"WWW-Authenticate": `Digest realm="ims.example", nonce="` + nonce1 + `", algorithm=AKAv1-MD5, qop="auth"`,
				"Security-Server":  `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=701;spi-s=702;port-c=` + strconv.Itoa(pcscfProtectedPort) + `;port-s=` + strconv.Itoa(pcscfProtectedPort) + `;q=0.9`,
			}
			resp, bErr := BuildSIPResponseWire(req, 401, "Unauthorized", headers, nil)
			if bErr == nil {
				_, _ = pcscfUnprotected.WriteTo(resp, addr)
			}
		}
	}()

	// P-CSCF sends replies back to source port (:port-c, RFC 3581 rport behavior)
	// on first authenticated REGISTER, then sends 401 + 200 on refresh!
	protectedStep := 0
	go func() {
		buf := make([]byte, 65535)
		for {
			_ = pcscfProtected.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, rErr := pcscfProtected.ReadFrom(buf)
			if rErr != nil {
				return
			}
			req, pErr := ParseSIPRequest(buf[:n])
			if pErr != nil {
				return
			}
			protectedStep++
			switch protectedStep {
			case 1:
				// Reply directly to addr (:port-c) to verify rport reception!
				okWire, _ := BuildSIPResponseWire(req, 200, "OK", nil, nil)
				_, _ = pcscfProtected.WriteTo(okWire, addr)
			case 2:
				// Challenge Refresh with 401 so UseSecurityAssociation runs AGAIN while port-s is externally owned!
				headers := map[string]string{
					"WWW-Authenticate": `Digest realm="ims.example", nonce="` + nonce2 + `", algorithm=AKAv1-MD5, qop="auth"`,
					"Security-Server":  `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c=801;spi-s=802;port-c=` + strconv.Itoa(pcscfProtectedPort) + `;port-s=` + strconv.Itoa(pcscfProtectedPort) + `;q=0.9`,
				}
				chalWire, _ := BuildSIPResponseWire(req, 401, "Unauthorized", headers, nil)
				_, _ = pcscfProtected.WriteTo(chalWire, addr)
			case 3:
				// Reply to port-s (handed over to external inbound listener) on re-auth!
				okWire, _ := BuildSIPResponseWire(req, 200, "OK", nil, nil)
				uAddr := addr.(*net.UDPAddr)
				_, _ = pcscfProtected.WriteTo(okWire, &net.UDPAddr{IP: uAddr.IP, Port: portS})
			}
		}
	}()

	flow := &WireSIPFlow{
		Network: "udp4",
		Targets: []string{pcscfUnprotected.LocalAddr().String()},
		Timeout: time.Second,
	}
	defer flow.Close()

	session := RegisterSession{
		Transport:    flow,
		AKAProvider:  &registerAKAProvider{},
		Profile:      IMSProfile{IMPI: "impi@ims.example", IMPU: "sip:user@ims.example", Domain: "ims.example"},
		RegistrarURI: "sip:ims.example",
		ContactURI:   "sip:user@127.0.0.1:5060",
		CallID:       "rport-and-handover",
		CNonce:       "cnonce",
		SecurityClient: SecurityAgreement{
			Protocol:            DefaultSecurityProtocol,
			Algorithm:           DefaultSecurityAlgorithm,
			EncryptionAlgorithm: DefaultSecurityEAlg,
			PortClient:          portC,
			PortServer:          portS,
		},
		SecurityPlanInstaller: &fakeSecurityPlanInstaller{},
		SecurityLocalAddr:     "127.0.0.1",
	}

	regRes, err := session.Register(context.Background())
	if err != nil || !regRes.Registered {
		t.Fatalf("Register() res=%+v err=%v", regRes, err)
	}

	// Simulate IMSInboundWireServer taking ownership of port-s and forwarding SIP responses.
	inboundPC := flow.TakeSecurityResponsePacketConn()
	if inboundPC == nil {
		t.Fatal("expected TakeSecurityResponsePacketConn() to return bound port-s socket")
	}
	defer inboundPC.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, rErr := inboundPC.ReadFrom(buf)
			if rErr != nil {
				return
			}
			flow.HandleSIPResponsePacket(buf[:n])
		}
	}()

	// Refresh receives 401 -> calls UseSecurityAssociation again while inboundPC holds port-s!
	refRes, err := session.Refresh(context.Background(), RefreshRequest{
		Binding:        regRes.Binding,
		CSeq:           regRes.NextCSeq,
		AuthHeader:     regRes.AuthHeader,
		AuthHeaderName: regRes.AuthHeaderName,
		AuthState:      regRes.AuthState,
	})
	if err != nil || !refRes.Refreshed {
		t.Fatalf("Refresh() after port-s handover failed (EADDRINUSE regression?): res=%+v err=%v", refRes, err)
	}
}

func TestWireSIPFlowPreservesTargetsFailoverAcrossUseSecurityAssociation(t *testing.T) {
	flow := &WireSIPFlow{
		Network: "udp4",
		Resolver: SIPServerCandidateResolverFunc(func(ctx context.Context, network, uri string) ([]string, error) {
			return []string{"127.0.0.1:15060", "127.0.0.1:15061"}, nil
		}),
		Timeout: 200 * time.Millisecond,
	}
	defer flow.Close()

	flow.mu.Lock()
	_, err := flow.ensureTargetsLocked(context.Background(), "udp4", "sip:ims.example")
	flow.mu.Unlock()
	if err != nil {
		t.Fatalf("ensureTargetsLocked() error = %v", err)
	}

	portC, portS, release := AllocateSecurityClientPorts("127.0.0.1", 0, 0)
	defer release()

	err = flow.UseSecurityAssociation(context.Background(), IMSSecurityAssociationInstallRequest{
		ClientAgreement: SecurityAgreement{PortClient: portC, PortServer: portS},
		LocalEndpoint:   IMSSecurityAssociationEndpoint{Address: "127.0.0.1", Port: portC},
		RemoteEndpoint:  IMSSecurityAssociationEndpoint{Address: "127.0.0.1", Port: 16060},
	})
	if err != nil {
		t.Fatalf("UseSecurityAssociation() error = %v", err)
	}

	switched, err := flow.ResetToNextTarget()
	if err != nil {
		t.Fatalf("ResetToNextTarget() error = %v", err)
	}
	if !switched {
		t.Fatal("expected ResetToNextTarget() to advance to target 1 instead of locking onto target 0")
	}
	_, remote := flow.SecurityAssociationAddresses()
	_ = remote
	flow.mu.Lock()
	idx := flow.targetIndex
	gotTargets := append([]string(nil), flow.targets...)
	flow.mu.Unlock()
	if idx != 1 || len(gotTargets) != 2 || gotTargets[1] != "127.0.0.1:15061" {
		t.Fatalf("targetIndex=%d targets=%v, want index 1 -> 127.0.0.1:15061", idx, gotTargets)
	}
}

func TestUniqueSecuritySPIsAndDynamicPortsWhenDefaultsBusy(t *testing.T) {
	seen := make(map[uint32]struct{}, 64)
	for i := 0; i < 32; i++ {
		ag := DefaultSecurityClientAgreement(nil)
		if ag.SPIClient < 256 || ag.SPIServer < 256 || ag.SPIClient == ag.SPIServer {
			t.Fatalf("invalid SPIs in %+v", ag)
		}
		if _, dup := seen[ag.SPIClient]; dup {
			t.Fatalf("duplicate SPIClient %d", ag.SPIClient)
		}
		if _, dup := seen[ag.SPIServer]; dup {
			t.Fatalf("duplicate SPIServer %d", ag.SPIServer)
		}
		seen[ag.SPIClient] = struct{}{}
		seen[ag.SPIServer] = struct{}{}
	}

	flow1 := &WireSIPFlow{Network: "udp4", LocalAddr: "127.0.0.1:0"}
	defer flow1.Close()
	flow2 := &WireSIPFlow{Network: "udp4", LocalAddr: "127.0.0.1:0"}
	defer flow2.Close()

	c1, s1 := flow1.EnsureSecurityClientPorts("127.0.0.1")
	c2, s2 := flow2.EnsureSecurityClientPorts("127.0.0.1")
	if c1 <= 0 || s1 <= 0 || c2 <= 0 || s2 <= 0 {
		t.Fatalf("invalid allocated ports: (%d,%d) and (%d,%d)", c1, s1, c2, s2)
	}
	if c1 == c2 || c1 == s2 || s1 == c2 || s1 == s2 {
		t.Fatalf("concurrent flows received colliding security ports: (%d,%d) vs (%d,%d)", c1, s1, c2, s2)
	}
}

type ctxCheckXFRMRunner struct {
	failAt     int
	calls      int
	ctxErrSeen []error
}

func (r *ctxCheckXFRMRunner) RunIP(ctx context.Context, _ ...string) error {
	idx := r.calls
	r.calls++
	r.ctxErrSeen = append(r.ctxErrSeen, ctx.Err())
	if r.failAt >= 0 && idx == r.failAt {
		return errors.New("simulated ip xfrm error")
	}
	return nil
}

func TestLinuxIMSSecurityXFRMInstallerUsesIndependentCleanupContext(t *testing.T) {
	req := validSecurityXFRMInstallRequest()
	runner := &ctxCheckXFRMRunner{failAt: -1}
	installer := &LinuxIMSSecurityXFRMInstaller{Runner: runner}
	if _, err := installer.Apply(context.Background(), req); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	runner.ctxErrSeen = nil
	if err := installer.Cleanup(cancelledCtx); err != nil {
		t.Fatalf("Cleanup(cancelledCtx) error = %v", err)
	}
	if len(runner.ctxErrSeen) == 0 {
		t.Fatal("expected Cleanup to execute undo commands")
	}
	for i, seenErr := range runner.ctxErrSeen {
		if seenErr != nil {
			t.Fatalf("undo command %d received cancelled context: %v", i, seenErr)
		}
	}
}

func TestReadSIPStreamMessageBoundsHeaderAndContentLength(t *testing.T) {
	oversizedLine := bytes.Repeat([]byte("A"), maxSIPStreamHeaderBytes+1024)
	_, err := readSIPStreamMessage(bufio.NewReader(bytes.NewReader(oversizedLine)))
	if !errors.Is(err, ErrInvalidSIPMessage) {
		t.Fatalf("oversized header line err=%v, want ErrInvalidSIPMessage", err)
	}

	hugeBodyMsg := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1\r\n" +
		"From: <sip:a@ims.example>;tag=1\r\n" +
		"To: <sip:b@ims.example>;tag=2\r\n" +
		"Call-ID: huge-body\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Content-Length: " + strconv.Itoa(maxSIPStreamBodyBytes+1) + "\r\n\r\n"
	_, err = readSIPStreamMessage(bufio.NewReader(strings.NewReader(hugeBodyMsg)))
	if !errors.Is(err, ErrInvalidSIPMessage) {
		t.Fatalf("oversized Content-Length err=%v, want ErrInvalidSIPMessage", err)
	}
}
