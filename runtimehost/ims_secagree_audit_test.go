package runtimehost

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kimoju/vowifi-go/engine/swu"
	"github.com/kimoju/vowifi-go/runtimehost/identity"
	"github.com/kimoju/vowifi-go/runtimehost/messaging"
	"github.com/kimoju/vowifi-go/runtimehost/simauth"
	"github.com/kimoju/vowifi-go/runtimehost/simtransport"
	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
)

func TestStartRuntimeIMSInboundServesBothUDPAndTCPOnPortS(t *testing.T) {
	inst := &Instance{state: State{DeviceID: "dev-inbound-dual"}}
	inbound, err := startRuntimeIMSInbound(IMSInboundConfig{
		Network:    "udp4",
		LocalAddr:  "127.0.0.1:0",
		ContactURI: "sip:ue@127.0.0.1:5063",
		UserAgent:  "vowifi-go-test",
	}, inst)
	if err != nil {
		t.Fatalf("startRuntimeIMSInbound() error = %v", err)
	}
	defer func() { _ = inbound.close(context.Background()) }()

	if inbound.packet == nil || inbound.listener == nil {
		t.Fatalf("expected both UDP PacketConn and TCP Listener to be bound: packet=%v listener=%v", inbound.packet, inbound.listener)
	}
	if inbound.packet.LocalAddr().String() != inbound.listener.Addr().String() {
		t.Fatalf("UDP addr %s != TCP addr %s", inbound.packet.LocalAddr(), inbound.listener.Addr())
	}

	// Send an MTU-exceeding SIP OPTIONS over TCP to port-s and verify 200 OK.
	tcpConn, err := net.DialTimeout("tcp4", inbound.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("DialTimeout(tcp) error = %v", err)
	}
	defer tcpConn.Close()
	_ = tcpConn.SetDeadline(time.Now().Add(2 * time.Second))

	padding := strings.Repeat("X", 2048)
	req := "OPTIONS sip:ue@" + inbound.listener.Addr().String() + " SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 127.0.0.1:40000;branch=z9hG4bK-tcp-mtu\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:pcscf@ims.example>;tag=p1\r\n" +
		"To: <sip:ue@ims.example>\r\n" +
		"Call-ID: tcp-mtu-options\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"X-MTU-Pad: " + padding + "\r\n" +
		"Content-Length: 0\r\n\r\n"
	if _, err := tcpConn.Write([]byte(req)); err != nil {
		t.Fatalf("tcp Write() error = %v", err)
	}
	reader := bufio.NewReader(tcpConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("tcp ReadString() error = %v", err)
	}
	if !strings.HasPrefix(statusLine, "SIP/2.0 200") {
		t.Fatalf("TCP response status line=%q, want 200 OK", statusLine)
	}
	_ = bytes.NewReader(nil)
}

func TestWireIMSRegistrarDualStackSelectsMatchingInnerIPFamily(t *testing.T) {
	tunnel := swu.TunnelResult{
		LocalInnerIP:   "10.20.0.2",
		LocalInnerIPv4: "10.20.0.2",
		LocalInnerIPv6: "2001:db8::2",
		LocalInnerIPs:  []string{"10.20.0.2", "2001:db8::2"},
	}

	v6Transport := &wireIMSRegistrarTransport{responses: []voiceclient.RegisterResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"P-Associated-URI": {"<sip:user@ims.mnc260.mcc310.3gppnetwork.org>"},
			},
		},
	}}
	v6Res, err := WireIMSRegistrar{
		Transport:      v6Transport,
		ContactPort:    5060,
		DisableRefresh: true,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-v6",
		Profile:  identity.Profile{IMSI: "310260123456789"},
		Tunnel: swu.TunnelResult{
			LocalInnerIP:   tunnel.LocalInnerIP,
			LocalInnerIPv4: tunnel.LocalInnerIPv4,
			LocalInnerIPv6: tunnel.LocalInnerIPv6,
			LocalInnerIPs:  tunnel.LocalInnerIPs,
			PCSCFServers:   []string{"2001:db8::10"},
		},
	})
	if err != nil {
		t.Fatalf("RegisterIMS(IPv6 P-CSCF) error = %v", err)
	}
	if v6Res.Profile.LocalIP != "2001:db8::2" {
		t.Fatalf("IPv6 P-CSCF Profile.LocalIP=%q, want 2001:db8::2", v6Res.Profile.LocalIP)
	}
	if !strings.Contains(v6Transport.requests[0].Headers["Contact"], "<sip:310260123456789@[2001:db8::2]:5060>") {
		t.Fatalf("IPv6 Contact=%q", v6Transport.requests[0].Headers["Contact"])
	}
	if v6Res.Inbound == nil || v6Res.Inbound.LocalAddr != "[2001:db8::2]:5060" {
		t.Fatalf("IPv6 Inbound=%+v, want [2001:db8::2]:5060", v6Res.Inbound)
	}

	v4Transport := &wireIMSRegistrarTransport{responses: []voiceclient.RegisterResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"P-Associated-URI": {"<sip:user@ims.mnc00.mcc460.3gppnetwork.org>"},
			},
		},
	}}
	v4Res, err := WireIMSRegistrar{
		Transport:      v4Transport,
		ContactPort:    5060,
		DisableRefresh: true,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-v4",
		Profile:  identity.Profile{IMSI: "460001357924680"},
		Tunnel: swu.TunnelResult{
			LocalInnerIP:   "2001:db8::2",
			LocalInnerIPv4: "10.20.0.2",
			LocalInnerIPv6: "2001:db8::2",
			LocalInnerIPs:  []string{"2001:db8::2", "10.20.0.2"},
			PCSCFServers:   []string{"192.0.2.10"},
		},
	})
	if err != nil {
		t.Fatalf("RegisterIMS(IPv4 P-CSCF) error = %v", err)
	}
	if v4Res.Profile.LocalIP != "10.20.0.2" {
		t.Fatalf("IPv4 P-CSCF Profile.LocalIP=%q, want 10.20.0.2", v4Res.Profile.LocalIP)
	}
	if v4Res.Profile.Domain != "ims.mnc000.mcc460.3gppnetwork.org" {
		t.Fatalf("2-digit MNC Profile.Domain=%q, want ims.mnc000.mcc460.3gppnetwork.org", v4Res.Profile.Domain)
	}
	if v4Res.Inbound == nil || v4Res.Inbound.LocalAddr != "10.20.0.2:5060" {
		t.Fatalf("IPv4 Inbound=%+v, want 10.20.0.2:5060", v4Res.Inbound)
	}
}

type querySMSCTestModem struct {
	testModem
	smsc string
}

func (m querySMSCTestModem) QuerySMSC() (string, error) {
	return m.smsc, nil
}

func TestRuntimeSMSCWiringFromUSIMEFSMSPAndModem(t *testing.T) {
	// 1. Verify USIM EF_SMSP (0x6F42, 3GPP TS 31.102 §4.2.25) with 4-byte Alpha-ID prefix.
	record := make([]byte, 32)
	for i := range record {
		record[i] = 0xFF
	}
	copy(record[:4], []byte("SMSC"))
	params := record[4:]
	params[0] = 0xFD // bit 1 (0x02) == 0 -> TS-Service Centre Address present
	// +8613800250500 -> 13 digits -> 7 BCD bytes + 1 TOA byte = 8 octets:
	// 68 31 08 20 05 05 F0
	copy(params[13:22], []byte{0x08, 0x91, 0x68, 0x31, 0x08, 0x20, 0x05, 0x05, 0xF0})
	decodedSMSC, err := simauth.DecodeUSIMSMSP(record)
	if err != nil || decodedSMSC != "+8613800250500" {
		t.Fatalf("DecodeUSIMSMSP() = %q, err=%v, want +8613800250500", decodedSMSC, err)
	}

	// 2. Verify AT+CSCA? extraction (international TOA 145 and UCS2 hex).
	if got, ok := simtransport.ExtractSMSC("\r\n+CSCA: \"8613800250500\",145\r\nOK\r\n"); !ok || got != "+8613800250500" {
		t.Fatalf("ExtractSMSC(145) = %q, %v", got, ok)
	}
	if got, ok := simtransport.ExtractSMSC("\r\n+CSCA: \"002B00310033003100320033003100340039003800310030\",145\r\nOK\r\n"); !ok || got != "+13123149810" {
		t.Fatalf("ExtractSMSC(UCS2) = %q, %v", got, ok)
	}

	// 3. Verify Modem.QuerySMSC -> PrepareStart -> WireIMSRegistrar -> IMSSMSTransport.SMSC.
	access := NewModemAccessAdapter(querySMSCTestModem{smsc: "+8613800250500"})
	prepared, err := identity.PrepareStart(identity.PrepareStartInput{
		DeviceID: "dev-smsc",
		Profile:  identity.Profile{IMSI: "460001357924680"},
		Access:   access,
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if prepared.Profile.SMSC != "+8613800250500" {
		t.Fatalf("prepared.Profile.SMSC = %q, want +8613800250500", prepared.Profile.SMSC)
	}

	sipTransport := &wireIMSRegistrarTransport{responses: []voiceclient.RegisterResponse{{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string][]string{
			"Contact": {"<sip:460001357924680@10.20.0.2:5060>;expires=600"},
		},
	}}}
	regRes, err := WireIMSRegistrar{
		Transport:      sipTransport,
		VoiceTransport: voiceclient.WireSIPTransport{},
		ContactPort:    5060,
		DisableRefresh: true,
	}.RegisterIMS(context.Background(), IMSRegistrationConfig{
		DeviceID: "dev-smsc",
		Profile:  identity.Profile{IMSI: "460001357924680"},
		Prepared: &prepared,
		Access:   access,
		Tunnel: swu.TunnelResult{
			LocalInnerIP: "10.20.0.2",
			PCSCFServers: []string{"192.0.2.10"},
		},
	})
	if err != nil {
		t.Fatalf("RegisterIMS() error = %v", err)
	}
	smsTransport, ok := regRes.SMSTransport.(messaging.IMSSMSTransport)
	if !ok || smsTransport.SMSC != "+8613800250500" {
		t.Fatalf("SMSTransport = %#v, want IMSSMSTransport with SMSC=+8613800250500", regRes.SMSTransport)
	}
}
