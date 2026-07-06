package voicehost

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/runtimehost/voiceclient"
)

func TestIMSInboundWireServerServesUDPInviteAckAndBye(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	transport := newWireInboundTransport([]voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=client-tag"},
				"Contact": {"<sip:client@127.0.0.1:5070>"},
			},
			Body: []byte(sampleSDP("127.0.0.1", 4002)),
		},
		{StatusCode: 200, Reason: "OK"},
	})
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		LocalTag:    "ue-tag",
		ContactURI:  "sip:vowifi@127.0.0.1:5060",
		ReadTimeout: 50 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServePacket(ctx, pc)
	}()

	invite := wireIMSInvite("wire-call-1", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170)))
	if _, err := client.Write(invite); err != nil {
		t.Fatalf("client INVITE Write() error = %v", err)
	}
	trying := readUDPWireResponse(t, client)
	ok := readUDPWireResponse(t, client)
	if trying.StatusCode != 100 || ok.StatusCode != 200 || !strings.Contains(string(ok.Body), "m=audio 4002 RTP/AVP") {
		t.Fatalf("trying=%+v ok=%+v body=%q", trying, ok, ok.Body)
	}
	if to := firstVoiceHeader(ok.Headers, "To"); !strings.Contains(to, "ue-tag") {
		t.Fatalf("200 OK To=%q", to)
	}
	inviteReq := transport.readRequest(t)
	if inviteReq.Method != "INVITE" || inviteReq.URI != "sip:client@127.0.0.1:5070" {
		t.Fatalf("client INVITE=%+v", inviteReq)
	}

	if _, err := client.Write(wireIMSInvite("wire-call-1", "ACK", 1, nil)); err != nil {
		t.Fatalf("client ACK Write() error = %v", err)
	}
	ack := transport.readWrite(t)
	if ack.Method != "ACK" || ack.URI != "sip:client@127.0.0.1:5070" {
		t.Fatalf("client ACK=%+v", ack)
	}

	if _, err := client.Write(wireIMSInvite("wire-call-1", "BYE", 2, nil)); err != nil {
		t.Fatalf("client BYE Write() error = %v", err)
	}
	byeOK := readUDPWireResponse(t, client)
	if byeOK.StatusCode != 200 {
		t.Fatalf("BYE response=%+v", byeOK)
	}
	bye := transport.readRequest(t)
	if bye.Method != "BYE" || bye.Headers["CSeq"] != "2 BYE" {
		t.Fatalf("client BYE=%+v", bye)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServePacket() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("ServePacket() did not stop")
	}
}

func TestIMSInboundWireServerSendsTryingBeforeClientFinal(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	transport := newBlockingWireInboundTransport()
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		LocalTag:       "ue-tag",
		ContactURI:     "sip:vowifi@127.0.0.1:5060",
		ReadTimeout:    50 * time.Millisecond,
		TransactionTTL: time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServePacket(ctx, pc)
	}()

	invite := wireIMSInvite("wire-call-early-trying", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170)))
	if _, err := client.Write(invite); err != nil {
		t.Fatalf("client INVITE Write() error = %v", err)
	}
	trying := readUDPWireResponse(t, client)
	if trying.StatusCode != 100 {
		t.Fatalf("first response=%+v, want immediate 100", trying)
	}
	req := transport.readRequest(t)
	if req.Method != "INVITE" {
		t.Fatalf("client request=%+v", req)
	}

	if _, err := client.Write(invite); err != nil {
		t.Fatalf("retransmitted INVITE Write() error = %v", err)
	}
	replayed := readUDPWireResponse(t, client)
	if replayed.StatusCode != 100 {
		t.Fatalf("replayed response=%+v, want cached 100 while final pending", replayed)
	}
	select {
	case msg := <-transport.requests:
		t.Fatalf("unexpected duplicate client INVITE while pending=%+v", msg)
	case <-time.After(100 * time.Millisecond):
	}

	transport.respond(voiceclient.SIPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string][]string{
			"To":      {"<sip:user@ims.example>;tag=client-tag"},
			"Contact": {"<sip:client@127.0.0.1:5070>"},
		},
		Body: []byte(sampleSDP("127.0.0.1", 4002)),
	})
	ok := readUDPWireResponse(t, client)
	if ok.StatusCode != 200 || !strings.Contains(string(ok.Body), "m=audio 4002 RTP/AVP") {
		t.Fatalf("final response=%+v body=%q", ok, ok.Body)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServePacket() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("ServePacket() did not stop")
	}
}

func TestIMSInboundWireServerSendsProvisionalBeforeClientFinal(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	transport := newProvisionalBlockingInboundTransport([]voiceclient.SIPResponse{
		{
			StatusCode: 183,
			Reason:     "Session Progress",
			Headers: map[string][]string{
				"Require": {"100rel"},
				"RSeq":    {"91"},
			},
			Body: []byte(sampleSDP("127.0.0.1", 4002)),
		},
	})
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		LocalTag:       "ue-tag",
		ContactURI:     "sip:vowifi@127.0.0.1:5060",
		ReadTimeout:    50 * time.Millisecond,
		TransactionTTL: time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServePacket(ctx, pc)
	}()

	invite := wireIMSInvite("wire-call-early-provisional", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170)))
	if _, err := client.Write(invite); err != nil {
		t.Fatalf("client INVITE Write() error = %v", err)
	}
	trying := readUDPWireResponse(t, client)
	if trying.StatusCode != 100 {
		t.Fatalf("first response=%+v, want 100", trying)
	}
	if req := transport.readRequest(t); req.Method != "INVITE" {
		t.Fatalf("client request=%+v", req)
	}
	provisional := readUDPWireResponse(t, client)
	if provisional.StatusCode != 183 ||
		firstVoiceHeader(provisional.Headers, "Require") != "100rel" ||
		firstVoiceHeader(provisional.Headers, "RSeq") != "91" ||
		firstVoiceHeader(provisional.Headers, "Contact") != "<sip:vowifi@127.0.0.1:5060>" ||
		!strings.Contains(string(provisional.Body), "m=audio 4002 RTP/AVP") {
		t.Fatalf("provisional=%+v body=%q", provisional, provisional.Body)
	}

	transport.respond(voiceclient.SIPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tag"}},
		Body:       []byte(sampleSDP("127.0.0.1", 4004)),
	})
	ok := readUDPWireResponse(t, client)
	if ok.StatusCode != 200 || !strings.Contains(string(ok.Body), "m=audio 4004 RTP/AVP") {
		t.Fatalf("final response=%+v body=%q", ok, ok.Body)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServePacket() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("ServePacket() did not stop")
	}
}

func TestIMSInboundWireServerRoutesPrackAfterReliableProvisional(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	transport := newReliableProvisionalInboundTransport([]voiceclient.SIPResponse{
		{
			StatusCode: 183,
			Reason:     "Session Progress",
			Headers: map[string][]string{
				"To":           {"<sip:user@ims.example>;tag=early-tag"},
				"Contact":      {"<sip:client@192.0.2.70:5060>"},
				"Record-Route": {"<sip:client-proxy1.example;lr>, <sip:client-proxy2.example;lr>"},
				"Require":      {"100rel"},
				"RSeq":         {"42"},
			},
			Body: []byte(sampleSDP("127.0.0.1", 4002)),
		},
	})
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		LocalTag:       "ue-tag",
		ContactURI:     "sip:vowifi@127.0.0.1:5060",
		ReadTimeout:    50 * time.Millisecond,
		TransactionTTL: time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServePacket(ctx, pc)
	}()

	if _, err := client.Write(wireIMSInvite("wire-call-prack-route", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170)))); err != nil {
		t.Fatalf("client INVITE Write() error = %v", err)
	}
	if trying := readUDPWireResponse(t, client); trying.StatusCode != 100 {
		t.Fatalf("trying=%+v", trying)
	}
	if req := transport.readInvite(t); req.Method != "INVITE" {
		t.Fatalf("client INVITE=%+v", req)
	}
	provisional := readUDPWireResponse(t, client)
	if provisional.StatusCode != 183 || firstVoiceHeader(provisional.Headers, "RSeq") != "42" {
		t.Fatalf("provisional=%+v", provisional)
	}

	prackRaw := wireIMSRequest("wire-call-prack-route", "PRACK", 2, nil, "RAck: 42 1 INVITE\r\n")
	if _, err := client.Write(prackRaw); err != nil {
		t.Fatalf("client PRACK Write() error = %v", err)
	}
	prack := transport.readRequest(t)
	if prack.Method != "PRACK" || prack.URI != "sip:client@192.0.2.70:5060" ||
		prack.Headers["RAck"] != "42 1 INVITE" ||
		!strings.Contains(prack.Headers["To"], "early-tag") {
		t.Fatalf("client PRACK=%+v", prack)
	}
	if prack.Headers["Route"] != "<sip:client-proxy2.example;lr>, <sip:client-proxy1.example;lr>" {
		t.Fatalf("client PRACK Route=%q", prack.Headers["Route"])
	}
	transport.respondRequest(voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"})
	prackOK := readUDPWireResponse(t, client)
	if prackOK.StatusCode != 200 || firstVoiceHeader(prackOK.Headers, "CSeq") != "2 PRACK" {
		t.Fatalf("PRACK response=%+v", prackOK)
	}

	transport.respondInvite(voiceclient.SIPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=final-tag"}},
		Body:       []byte(sampleSDP("127.0.0.1", 4004)),
	})
	final := readUDPWireResponse(t, client)
	if final.StatusCode != 200 || firstVoiceHeader(final.Headers, "CSeq") != "1 INVITE" {
		t.Fatalf("final=%+v", final)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServePacket() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("ServePacket() did not stop")
	}
}

func TestIMSInboundWireServerRetransmitsReliableProvisionalUntilPrack(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	transport := newReliableProvisionalInboundTransport([]voiceclient.SIPResponse{
		{
			StatusCode: 183,
			Reason:     "Session Progress",
			Headers: map[string][]string{
				"To":      {"<sip:user@ims.example>;tag=early-tag"},
				"Contact": {"<sip:client@192.0.2.70:5060>"},
				"Require": {"100rel"},
				"RSeq":    {"77"},
			},
			Body: []byte(sampleSDP("127.0.0.1", 4002)),
		},
	})
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		LocalTag:       "ue-tag",
		ContactURI:     "sip:vowifi@127.0.0.1:5060",
		ReadTimeout:    50 * time.Millisecond,
		TransactionTTL: 2 * time.Second,
		Reliable1xxT1:  50 * time.Millisecond,
		Reliable1xxT2:  200 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServePacket(ctx, pc)
	}()

	invite := wireIMSInvite("wire-call-provisional-retransmit", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170)))
	if _, err := client.Write(invite); err != nil {
		t.Fatalf("client INVITE Write() error = %v", err)
	}
	if trying := readUDPWireResponse(t, client); trying.StatusCode != 100 {
		t.Fatalf("trying=%+v", trying)
	}
	if req := transport.readInvite(t); req.Method != "INVITE" {
		t.Fatalf("client INVITE=%+v", req)
	}
	provisional := readUDPWireResponse(t, client)
	if provisional.StatusCode != 183 ||
		firstVoiceHeader(provisional.Headers, "RSeq") != "77" ||
		firstVoiceHeader(provisional.Headers, "Require") != "100rel" {
		t.Fatalf("provisional=%+v", provisional)
	}
	retransmitted := readUDPWireResponse(t, client)
	if retransmitted.StatusCode != 183 ||
		firstVoiceHeader(retransmitted.Headers, "RSeq") != "77" ||
		string(retransmitted.Body) != string(provisional.Body) {
		t.Fatalf("retransmitted provisional=%+v body=%q first=%+v", retransmitted, retransmitted.Body, provisional)
	}

	if _, err := client.Write(wireIMSRequest("wire-call-provisional-retransmit", "PRACK", 2, nil, "RAck: 77 1 INVITE\r\n")); err != nil {
		t.Fatalf("client PRACK Write() error = %v", err)
	}
	prack := transport.readRequest(t)
	if prack.Method != "PRACK" || prack.Headers["RAck"] != "77 1 INVITE" {
		t.Fatalf("client PRACK=%+v", prack)
	}
	transport.respondRequest(voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"})
	prackOK := readUDPWireResponse(t, client)
	if prackOK.StatusCode != 200 || firstVoiceHeader(prackOK.Headers, "CSeq") != "2 PRACK" {
		t.Fatalf("PRACK response=%+v", prackOK)
	}
	assertNoUDPWireResponse(t, client, 140*time.Millisecond)

	if _, err := client.Write(invite); err != nil {
		t.Fatalf("retransmitted INVITE after PRACK Write() error = %v", err)
	}
	replayedTrying := readUDPWireResponse(t, client)
	replayedProvisional := readUDPWireResponse(t, client)
	if replayedTrying.StatusCode != 100 ||
		replayedProvisional.StatusCode != 183 ||
		firstVoiceHeader(replayedProvisional.Headers, "RSeq") != "77" {
		t.Fatalf("cached replay after PRACK=%+v/%+v", replayedTrying, replayedProvisional)
	}
	assertNoUDPWireResponse(t, client, 140*time.Millisecond)

	transport.respondInvite(voiceclient.SIPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=final-tag"}},
		Body:       []byte(sampleSDP("127.0.0.1", 4004)),
	})
	final := readUDPWireResponse(t, client)
	if final.StatusCode != 200 || firstVoiceHeader(final.Headers, "CSeq") != "1 INVITE" {
		t.Fatalf("final=%+v", final)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServePacket() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("ServePacket() did not stop")
	}
}

func TestIMSInboundWireServerRejectsMalformedPrackRAck(t *testing.T) {
	transport := newWireInboundTransport(nil)
	agent := &IMSInboundAgent{ClientTransport: transport}
	agent.storeInboundDialog("wire-call-bad-prack-1", imsInboundDialogState{
		clientCfg: voiceclient.DialogRequestConfig{
			RemoteTargetURI: "sip:client@127.0.0.1:5070",
			CallID:          "wire-call-bad-prack-1",
			CSeq:            1,
		},
	})
	agent.storeInboundDialog("wire-call-bad-prack-2", imsInboundDialogState{
		clientCfg: voiceclient.DialogRequestConfig{
			RemoteTargetURI: "sip:client@127.0.0.1:5070",
			CallID:          "wire-call-bad-prack-2",
			CSeq:            1,
		},
	})
	server := &IMSInboundWireServer{Agent: agent}
	tests := []struct {
		name string
		req  voiceclient.SIPIncomingRequest
	}{
		{
			name: "missing",
			req:  parseWireIncoming(t, wireIMSRequest("wire-call-bad-prack-1", "PRACK", 2, nil)),
		},
		{
			name: "bad_numbers",
			req:  parseWireIncoming(t, wireIMSRequest("wire-call-bad-prack-2", "PRACK", 2, nil, "RAck: seven 1 INVITE\r\n")),
		},
	}
	for _, tc := range tests {
		responses, err := server.HandleRequest(context.Background(), tc.req)
		if err != nil {
			t.Fatalf("%s HandleRequest(PRACK) error = %v", tc.name, err)
		}
		if len(responses) != 1 || responses[0].StatusCode != 400 {
			t.Fatalf("%s responses=%+v, want 400", tc.name, responses)
		}
	}
	select {
	case req := <-transport.requests:
		t.Fatalf("unexpected client PRACK request=%+v", req)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestIMSInboundWireServerRejectsMalformedCSeq(t *testing.T) {
	transport := newWireInboundTransport(nil)
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{ClientTransport: transport},
	}
	tests := []struct {
		name string
		req  voiceclient.SIPIncomingRequest
	}{
		{
			name: "missing",
			req: voiceclient.SIPIncomingRequest{
				Method: "MESSAGE",
				URI:    "sip:user@ims.example",
				Headers: map[string][]string{
					"Call-ID": {"bad-cseq-missing"},
				},
			},
		},
		{
			name: "bad_number",
			req: voiceclient.SIPIncomingRequest{
				Method: "INVITE",
				URI:    "sip:user@ims.example",
				Headers: map[string][]string{
					"Call-ID": {"bad-cseq-number"},
					"CSeq":    {"zero INVITE"},
				},
			},
		},
		{
			name: "method_mismatch",
			req: voiceclient.SIPIncomingRequest{
				Method: "UPDATE",
				URI:    "sip:user@ims.example",
				Headers: map[string][]string{
					"Call-ID": {"bad-cseq-method"},
					"CSeq":    {"3 INVITE"},
				},
			},
		},
	}
	for _, tc := range tests {
		responses, err := server.HandleRequest(context.Background(), tc.req)
		if err != nil {
			t.Fatalf("%s HandleRequest() error = %v", tc.name, err)
		}
		if len(responses) != 1 || responses[0].StatusCode != 400 {
			t.Fatalf("%s responses=%+v, want 400", tc.name, responses)
		}
	}
	select {
	case req := <-transport.requests:
		t.Fatalf("unexpected client request for bad CSeq=%+v", req)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestIMSInboundWireServerRejectsBadMaxForwards(t *testing.T) {
	handled := false
	server := &IMSInboundWireServer{
		MessageHandler: IMSMessageHandlerFunc(func(ctx context.Context, req IMSMessageRequest) (IMSMessageResult, error) {
			handled = true
			return IMSMessageResult{StatusCode: 200, Reason: "OK"}, nil
		}),
	}
	tests := []struct {
		name       string
		value      string
		statusCode int
		reason     string
	}{
		{name: "zero", value: "0", statusCode: 483, reason: "Too Many Hops"},
		{name: "blank", value: "", statusCode: 400, reason: "Bad Max-Forwards"},
		{name: "nondigit", value: "ten", statusCode: 400, reason: "Bad Max-Forwards"},
		{name: "negative", value: "-1", statusCode: 400, reason: "Bad Max-Forwards"},
		{name: "overflow", value: strings.Repeat("9", 64), statusCode: 400, reason: "Bad Max-Forwards"},
	}
	for _, tc := range tests {
		handled = false
		responses, err := server.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
			Method: "MESSAGE",
			URI:    "sip:user@ims.example",
			Headers: map[string][]string{
				"Call-ID":      {"bad-max-forwards-" + tc.name},
				"CSeq":         {"1 MESSAGE"},
				"Max-Forwards": {tc.value},
			},
		})
		if err != nil {
			t.Fatalf("%s HandleRequest() error = %v", tc.name, err)
		}
		if len(responses) != 1 || responses[0].StatusCode != tc.statusCode || responses[0].Reason != tc.reason {
			t.Fatalf("%s responses=%+v, want %d %s", tc.name, responses, tc.statusCode, tc.reason)
		}
		if handled {
			t.Fatalf("%s bad Max-Forwards reached message handler", tc.name)
		}
	}
}

func TestIMSInboundWireServerCancelsPendingInvite(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	transport := newCancelAwareInboundTransport()
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		LocalTag:       "ue-tag",
		ContactURI:     "sip:vowifi@127.0.0.1:5060",
		ReadTimeout:    50 * time.Millisecond,
		TransactionTTL: time.Second,
	}
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServePacket(ctx, pc)
	}()

	invite := wireIMSInvite("wire-call-cancel", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170)))
	if _, err := client.Write(invite); err != nil {
		t.Fatalf("client INVITE Write() error = %v", err)
	}
	trying := readUDPWireResponse(t, client)
	if trying.StatusCode != 100 || firstVoiceHeader(trying.Headers, "CSeq") != "1 INVITE" {
		t.Fatalf("trying=%+v", trying)
	}
	clientInvite := transport.readInvite(t)
	if clientInvite.Method != "INVITE" {
		t.Fatalf("client INVITE=%+v", clientInvite)
	}

	if _, err := client.Write(wireIMSInvite("wire-call-cancel", "CANCEL", 1, nil)); err != nil {
		t.Fatalf("client CANCEL Write() error = %v", err)
	}
	clientCancel := transport.readCancel(t)
	if clientCancel.Method != "CANCEL" || clientCancel.Headers["Via"] != clientInvite.Headers["Via"] {
		t.Fatalf("client CANCEL=%+v INVITE Via=%q", clientCancel, clientInvite.Headers["Via"])
	}
	transport.respondCancel(voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"})
	cancelOK := readUDPWireResponse(t, client)
	if cancelOK.StatusCode != 200 || firstVoiceHeader(cancelOK.Headers, "CSeq") != "1 CANCEL" {
		t.Fatalf("CANCEL response=%+v", cancelOK)
	}

	transport.respondInvite(voiceclient.SIPResponse{
		StatusCode: 487,
		Reason:     "Request Terminated",
		Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=canceled"}},
	})
	terminated := readUDPWireResponse(t, client)
	if terminated.StatusCode != 487 || firstVoiceHeader(terminated.Headers, "CSeq") != "1 INVITE" {
		t.Fatalf("INVITE final=%+v", terminated)
	}
	clientACK := transport.readWrite(t)
	if clientACK.Method != "ACK" || clientACK.Headers["Via"] != clientInvite.Headers["Via"] {
		t.Fatalf("client ACK=%+v INVITE Via=%q", clientACK, clientInvite.Headers["Via"])
	}

	cancelCtx()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServePacket() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("ServePacket() did not stop")
	}
}

func TestIMSInboundWireServerRejectsCancelWithoutPendingInvite(t *testing.T) {
	transport := newWireInboundTransport(nil)
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport: transport,
		},
	}
	cancel := parseWireIncoming(t, wireIMSInvite("wire-call-stray-cancel", "CANCEL", 1, nil))
	responses, err := server.HandleRequest(context.Background(), cancel)
	if err != nil {
		t.Fatalf("HandleRequest(CANCEL) error = %v", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 481 {
		t.Fatalf("CANCEL responses=%+v, want 481", responses)
	}
	select {
	case req := <-transport.requests:
		t.Fatalf("unexpected client request for stray CANCEL=%+v", req)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestIMSInboundWireServerForwardsProvisionalInviteResponses(t *testing.T) {
	transport := &fakeIMSVoiceTransport{
		provisionals: []voiceclient.SIPResponse{
			{
				StatusCode: 183,
				Reason:     "Session Progress",
				Headers: map[string][]string{
					"Require": {"100rel"},
					"RSeq":    {"77"},
					"Contact": {"<sip:client@127.0.0.1:5070>"},
				},
				Body: []byte(sampleSDP("127.0.0.1", 4002)),
			},
		},
		responses: []voiceclient.SIPResponse{
			{
				StatusCode: 200,
				Reason:     "OK",
				Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tag"}},
				Body:       []byte(sampleSDP("127.0.0.1", 4004)),
			},
		},
	}
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		ContactURI: "sip:vowifi@127.0.0.1:5060",
	}
	invite := parseWireIncoming(t, wireIMSInvite("wire-call-provisional", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170))))
	responses, err := server.HandleRequest(context.Background(), invite)
	if err != nil {
		t.Fatalf("HandleRequest(INVITE) error = %v", err)
	}
	if len(responses) != 3 || responses[0].StatusCode != 100 || responses[1].StatusCode != 183 || responses[2].StatusCode != 200 {
		t.Fatalf("responses=%+v", responses)
	}
	if responses[1].Reason != "Session Progress" ||
		responses[1].Headers["Require"] != "100rel" ||
		responses[1].Headers["RSeq"] != "77" ||
		responses[1].Headers["Contact"] != "<sip:vowifi@127.0.0.1:5060>" ||
		responses[1].Headers["Content-Type"] != "application/sdp" ||
		!strings.Contains(string(responses[1].Body), "m=audio 4002 RTP/AVP") {
		t.Fatalf("provisional response=%+v body=%q", responses[1], responses[1].Body)
	}
	if responses[2].Headers["Contact"] != "<sip:vowifi@127.0.0.1:5060>" ||
		!strings.Contains(string(responses[2].Body), "m=audio 4004 RTP/AVP") {
		t.Fatalf("final response=%+v body=%q", responses[2], responses[2].Body)
	}
}

func TestIMSInboundWireServerKeepsReliableProvisionalSDPOffFinal(t *testing.T) {
	transport := &fakeIMSVoiceTransport{
		provisionals: []voiceclient.SIPResponse{
			{
				StatusCode: 183,
				Reason:     "Session Progress",
				Headers: map[string][]string{
					"To":      {"<sip:user@ims.example>;tag=early-tag"},
					"Require": {"100rel"},
					"RSeq":    {"9"},
				},
				Body: []byte(sampleSDP("127.0.0.1", 4090)),
			},
		},
		responses: []voiceclient.SIPResponse{
			{
				StatusCode: 200,
				Reason:     "OK",
				Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tag"}},
			},
		},
	}
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		ContactURI: "sip:vowifi@127.0.0.1:5060",
	}
	invite := parseWireIncoming(t, wireIMSInvite("wire-call-provisional-answer", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170))))
	responses, err := server.HandleRequest(context.Background(), invite)
	if err != nil {
		t.Fatalf("HandleRequest(INVITE) error = %v", err)
	}
	if len(responses) != 3 || responses[0].StatusCode != 100 || responses[1].StatusCode != 183 || responses[2].StatusCode != 200 {
		t.Fatalf("responses=%+v", responses)
	}
	if !strings.Contains(string(responses[1].Body), "m=audio 4090 RTP/AVP") || responses[1].Headers["Content-Type"] != "application/sdp" {
		t.Fatalf("provisional response=%+v body=%q", responses[1], responses[1].Body)
	}
	if len(responses[2].Body) != 0 || responses[2].Headers["Content-Type"] != "" {
		t.Fatalf("final response should not repeat SDP: %+v body=%q", responses[2], responses[2].Body)
	}
}

func TestIMSInboundWireServerServesTCPInvite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()
	transport := newWireInboundTransport([]voiceclient.SIPResponse{{
		StatusCode: 200,
		Reason:     "OK",
		Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tag"}},
		Body:       []byte(sampleSDP("127.0.0.1", 4002)),
	}})
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		ReadTimeout: 50 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServeListener(ctx, ln)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(wireIMSInvite("wire-call-tcp", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170)))); err != nil {
		t.Fatalf("TCP INVITE Write() error = %v", err)
	}
	reader := bufio.NewReader(conn)
	tryingRaw, err := voiceclient.ReadSIPStreamMessage(reader)
	if err != nil {
		t.Fatalf("read TCP 100 error = %v", err)
	}
	okRaw, err := voiceclient.ReadSIPStreamMessage(reader)
	if err != nil {
		t.Fatalf("read TCP 200 error = %v", err)
	}
	trying, err := voiceclient.ParseSIPResponse(tryingRaw)
	if err != nil {
		t.Fatalf("ParseSIPResponse(trying) error = %v", err)
	}
	ok, err := voiceclient.ParseSIPResponse(okRaw)
	if err != nil {
		t.Fatalf("ParseSIPResponse(ok) error = %v", err)
	}
	if trying.StatusCode != 100 || ok.StatusCode != 200 {
		t.Fatalf("trying=%+v ok=%+v", trying, ok)
	}
	if req := transport.readRequest(t); req.Method != "INVITE" {
		t.Fatalf("client request=%+v", req)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServeListener() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("ServeListener() did not stop")
	}
}

func TestIMSInboundWireServerReplaysCachedInviteTransaction(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	transport := newWireInboundTransport([]voiceclient.SIPResponse{{
		StatusCode: 200,
		Reason:     "OK",
		Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tag"}},
		Body:       []byte(sampleSDP("127.0.0.1", 4002)),
	}})
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		ReadTimeout:    50 * time.Millisecond,
		TransactionTTL: time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServePacket(ctx, pc)
	}()

	invite := wireIMSInvite("wire-call-cache", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170)))
	if _, err := client.Write(invite); err != nil {
		t.Fatalf("first INVITE Write() error = %v", err)
	}
	firstTrying := readUDPWireResponse(t, client)
	firstOK := readUDPWireResponse(t, client)
	if firstTrying.StatusCode != 100 || firstOK.StatusCode != 200 {
		t.Fatalf("first responses=%+v/%+v", firstTrying, firstOK)
	}
	_ = transport.readRequest(t)

	if _, err := client.Write(invite); err != nil {
		t.Fatalf("retransmitted INVITE Write() error = %v", err)
	}
	secondTrying := readUDPWireResponse(t, client)
	secondOK := readUDPWireResponse(t, client)
	if secondTrying.StatusCode != 100 || secondOK.StatusCode != 200 || string(secondOK.Body) != string(firstOK.Body) {
		t.Fatalf("cached responses=%+v/%+v first=%+v", secondTrying, secondOK, firstOK)
	}
	select {
	case msg := <-transport.requests:
		t.Fatalf("unexpected second client INVITE=%+v", msg)
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServePacket() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("ServePacket() did not stop")
	}
}

func TestIMSInboundWireServerRetransmitsInviteFinalUntilAck(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	transport := newWireInboundTransport([]voiceclient.SIPResponse{{
		StatusCode: 200,
		Reason:     "OK",
		Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tag"}},
		Body:       []byte(sampleSDP("127.0.0.1", 4002)),
	}})
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		LocalTag:       "ue-tag",
		ContactURI:     "sip:vowifi@127.0.0.1:5060",
		ReadTimeout:    50 * time.Millisecond,
		TransactionTTL: 400 * time.Millisecond,
		InviteFinalT1:  20 * time.Millisecond,
		InviteFinalT2:  80 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServePacket(ctx, pc)
	}()

	invite := wireIMSInvite("wire-call-final-retransmit", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170)))
	if _, err := client.Write(invite); err != nil {
		t.Fatalf("client INVITE Write() error = %v", err)
	}
	trying := readUDPWireResponse(t, client)
	ok := readUDPWireResponse(t, client)
	if trying.StatusCode != 100 || ok.StatusCode != 200 {
		t.Fatalf("first responses=%+v/%+v", trying, ok)
	}
	_ = transport.readRequest(t)

	retransmitted := readUDPWireResponse(t, client)
	if retransmitted.StatusCode != 200 ||
		firstVoiceHeader(retransmitted.Headers, "CSeq") != "1 INVITE" ||
		string(retransmitted.Body) != string(ok.Body) {
		t.Fatalf("retransmitted final=%+v body=%q first=%+v", retransmitted, retransmitted.Body, ok)
	}

	if _, err := client.Write(wireIMSInvite("wire-call-final-retransmit", "ACK", 1, nil)); err != nil {
		t.Fatalf("client ACK Write() error = %v", err)
	}
	clientACK := transport.readWrite(t)
	if clientACK.Method != "ACK" || clientACK.Headers["CSeq"] != "1 ACK" {
		t.Fatalf("client ACK=%+v", clientACK)
	}
	assertNoUDPWireResponse(t, client, 120*time.Millisecond)

	if _, err := client.Write(invite); err != nil {
		t.Fatalf("retransmitted INVITE after ACK Write() error = %v", err)
	}
	replayedTrying := readUDPWireResponse(t, client)
	replayedOK := readUDPWireResponse(t, client)
	if replayedTrying.StatusCode != 100 || replayedOK.StatusCode != 200 {
		t.Fatalf("cached replay after ACK=%+v/%+v", replayedTrying, replayedOK)
	}
	assertNoUDPWireResponse(t, client, 120*time.Millisecond)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServePacket() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("ServePacket() did not stop")
	}
}

func TestIMSInboundWireServerDispatchesPrackUpdateAndOptions(t *testing.T) {
	transport := newWireInboundTransport([]voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tag"}},
			Body:       []byte(sampleSDP("127.0.0.1", 4002)),
		},
		{StatusCode: 200, Reason: "OK"},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"Contact": {"<sip:client@127.0.0.1:5070>"}},
			Body:       []byte(sampleSDP("127.0.0.1", 4004)),
		},
	})
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		ContactURI: "sip:vowifi@127.0.0.1:5060",
	}
	invite := parseWireIncoming(t, wireIMSInvite("wire-call-dialog", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170))))
	responses, err := server.HandleRequest(context.Background(), invite)
	if err != nil {
		t.Fatalf("HandleRequest(INVITE) error = %v", err)
	}
	if len(responses) != 2 || responses[1].StatusCode != 200 {
		t.Fatalf("INVITE responses=%+v", responses)
	}
	_ = transport.readRequest(t)

	prack := parseWireIncoming(t, wireIMSRequest("wire-call-dialog", "PRACK", 2, nil, "RAck: 1 1 INVITE\r\n"))
	responses, err = server.HandleRequest(context.Background(), prack)
	if err != nil {
		t.Fatalf("HandleRequest(PRACK) error = %v", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 200 {
		t.Fatalf("PRACK responses=%+v", responses)
	}
	prackReq := transport.readRequest(t)
	if prackReq.Method != "PRACK" || prackReq.Headers["RAck"] != "1 1 INVITE" {
		t.Fatalf("client PRACK=%+v", prackReq)
	}

	update := parseWireIncoming(t, wireIMSRequest("wire-call-dialog", "UPDATE", 3, []byte(sampleSDP("203.0.113.20", 49172))))
	responses, err = server.HandleRequest(context.Background(), update)
	if err != nil {
		t.Fatalf("HandleRequest(UPDATE) error = %v", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 200 || !strings.Contains(string(responses[0].Body), "m=audio 4004 RTP/AVP") {
		t.Fatalf("UPDATE responses=%+v body=%q", responses, responses[0].Body)
	}
	updateReq := transport.readRequest(t)
	if updateReq.Method != "UPDATE" || !strings.Contains(string(updateReq.Body), "m=audio 49172 RTP/AVP") {
		t.Fatalf("client UPDATE=%+v", updateReq)
	}

	options := parseWireIncoming(t, wireIMSRequest("wire-options", "OPTIONS", 1, nil))
	responses, err = server.HandleRequest(context.Background(), options)
	if err != nil {
		t.Fatalf("HandleRequest(OPTIONS) error = %v", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 200 || !strings.Contains(responses[0].Headers["Allow"], "UPDATE") || responses[0].Headers["Contact"] == "" {
		t.Fatalf("OPTIONS responses=%+v", responses)
	}
}

func TestIMSInboundWireServerPropagatesSessionTimerHeaders(t *testing.T) {
	transport := newWireInboundTransport([]voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"To":              {"<sip:user@ims.example>;tag=client-tag"},
				"Contact":         {"<sip:client@127.0.0.1:5070>"},
				"Session-Expires": {"1200;refresher=uac"},
				"Min-SE":          {"90"},
			},
			Body: []byte(sampleSDP("127.0.0.1", 4002)),
		},
		{
			StatusCode: 422,
			Reason:     "Session Interval Too Small",
			Headers: map[string][]string{
				"Min-SE": {"900"},
			},
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers: map[string][]string{
				"Session-Expires": {"900;refresher=uas"},
				"Min-SE":          {"900"},
			},
		},
	})
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		ContactURI: "sip:vowifi@127.0.0.1:5060",
	}
	invite := parseWireIncoming(t, wireIMSRequest("wire-call-session-timer", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170)),
		"Session-Expires: 1800;refresher=uas\r\n",
		"Min-SE: 90\r\n"))
	responses, err := server.HandleRequest(context.Background(), invite)
	if err != nil {
		t.Fatalf("HandleRequest(INVITE) error = %v", err)
	}
	if len(responses) != 2 || responses[1].StatusCode != 200 ||
		responses[1].Headers["Session-Expires"] != "1200;refresher=uac" ||
		responses[1].Headers["Min-SE"] != "90" {
		t.Fatalf("INVITE responses=%+v", responses)
	}
	clientInvite := transport.readRequest(t)
	if clientInvite.Headers["Session-Expires"] != "1800;refresher=uas" || clientInvite.Headers["Min-SE"] != "90" {
		t.Fatalf("client INVITE=%+v", clientInvite)
	}

	update := parseWireIncoming(t, wireIMSRequest("wire-call-session-timer", "UPDATE", 3, nil,
		"Session-Expires: 300;refresher=uac\r\n",
		"Min-SE: 900\r\n"))
	responses, err = server.HandleRequest(context.Background(), update)
	if err != nil {
		t.Fatalf("HandleRequest(UPDATE) error = %v", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 200 ||
		responses[0].Headers["Session-Expires"] != "900;refresher=uas" ||
		responses[0].Headers["Min-SE"] != "900" {
		t.Fatalf("UPDATE responses=%+v", responses)
	}
	clientUpdate := transport.readRequest(t)
	if clientUpdate.Headers["Session-Expires"] != "300;refresher=uac" || clientUpdate.Headers["Min-SE"] != "900" {
		t.Fatalf("client UPDATE=%+v", clientUpdate)
	}
	retryUpdate := transport.readRequest(t)
	if retryUpdate.Headers["CSeq"] != "4 UPDATE" ||
		retryUpdate.Headers["Session-Expires"] != "900;refresher=uac" ||
		retryUpdate.Headers["Min-SE"] != "900" {
		t.Fatalf("client retry UPDATE=%+v", retryUpdate)
	}
}

func TestIMSInboundWireServerDispatchesReinviteAndAck(t *testing.T) {
	transport := newWireInboundTransport([]voiceclient.SIPResponse{
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tag"}},
			Body:       []byte(sampleSDP("127.0.0.1", 4002)),
		},
		{
			StatusCode: 200,
			Reason:     "OK",
			Headers:    map[string][]string{"Contact": {"<sip:client@127.0.0.1:5070>"}},
			Body:       []byte(sampleSDP("127.0.0.1", 4006)),
		},
	})
	server := &IMSInboundWireServer{
		Agent: &IMSInboundAgent{
			ClientTransport:  transport,
			ClientContactURI: "sip:client@127.0.0.1:5070",
			LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		},
		ContactURI: "sip:vowifi@127.0.0.1:5060",
	}
	initial := parseWireIncoming(t, wireIMSInvite("wire-call-reinvite", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170))))
	responses, err := server.HandleRequest(context.Background(), initial)
	if err != nil {
		t.Fatalf("HandleRequest(initial INVITE) error = %v", err)
	}
	if len(responses) != 2 || responses[1].StatusCode != 200 {
		t.Fatalf("initial responses=%+v", responses)
	}
	_ = transport.readRequest(t)

	reinvite := parseWireIncoming(t, wireIMSRequest("wire-call-reinvite", "INVITE", 4, []byte(sampleSDP("203.0.113.20", 49172))))
	responses, err = server.HandleRequest(context.Background(), reinvite)
	if err != nil {
		t.Fatalf("HandleRequest(re-INVITE) error = %v", err)
	}
	if len(responses) != 2 || responses[1].StatusCode != 200 || !strings.Contains(string(responses[1].Body), "m=audio 4006 RTP/AVP") {
		t.Fatalf("re-INVITE responses=%+v body=%q", responses, responses[1].Body)
	}
	clientReinvite := transport.readRequest(t)
	if clientReinvite.Method != "INVITE" || clientReinvite.Headers["CSeq"] != "4 INVITE" || !strings.Contains(string(clientReinvite.Body), "m=audio 49172 RTP/AVP") {
		t.Fatalf("client re-INVITE=%+v", clientReinvite)
	}
	ack := parseWireIncoming(t, wireIMSRequest("wire-call-reinvite", "ACK", 4, nil))
	responses, err = server.HandleRequest(context.Background(), ack)
	if err != nil {
		t.Fatalf("HandleRequest(ACK) error = %v", err)
	}
	if len(responses) != 0 {
		t.Fatalf("ACK responses=%+v", responses)
	}
	clientACK := transport.readWrite(t)
	if clientACK.Method != "ACK" || clientACK.Headers["CSeq"] != "4 ACK" {
		t.Fatalf("client ACK=%+v", clientACK)
	}
}

func TestIMSInboundWireServerRejectsUnsupportedMethod(t *testing.T) {
	server := &IMSInboundWireServer{}
	responses, err := server.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method: "SUBSCRIBE",
		URI:    "sip:user@ims.example",
		Headers: map[string][]string{
			"Call-ID": {"call-options"},
			"CSeq":    {"1 SUBSCRIBE"},
		},
	})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 405 || !strings.Contains(responses[0].Headers["Allow"], "UPDATE") {
		t.Fatalf("responses=%+v", responses)
	}
}

func TestIMSInboundWireServerDispatchesMessage(t *testing.T) {
	var handled IMSMessageRequest
	server := &IMSInboundWireServer{
		MessageHandler: IMSMessageHandlerFunc(func(ctx context.Context, req IMSMessageRequest) (IMSMessageResult, error) {
			handled = req
			return IMSMessageResult{
				StatusCode:  200,
				Reason:      "OK",
				ContentType: "application/vnd.3gpp.sms",
				Body:        []byte{0x02, 0x33},
			}, nil
		}),
	}
	req := voiceclient.SIPIncomingRequest{
		Method: "MESSAGE",
		URI:    "sip:user@ims.example",
		Headers: map[string][]string{
			"Call-ID":      {"sms-call-1"},
			"CSeq":         {"3 MESSAGE"},
			"From":         {"<sip:smsc@ims.example>;tag=net"},
			"To":           {"<sip:user@ims.example>"},
			"Content-Type": {"application/vnd.3gpp.sms"},
		},
		Body: []byte{0x01, 0x33, 0x00, 0x00, 0x00},
	}
	responses, err := server.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest(MESSAGE) error = %v", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 200 || responses[0].Headers["Content-Type"] != "application/vnd.3gpp.sms" || string(responses[0].Body) != string([]byte{0x02, 0x33}) {
		t.Fatalf("responses=%+v", responses)
	}
	if handled.CallID != "sms-call-1" || handled.CSeq != 3 || handled.FromURI != "sip:smsc@ims.example" || handled.ContentType != "application/vnd.3gpp.sms" {
		t.Fatalf("handled=%+v", handled)
	}
	options, err := server.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method: "OPTIONS",
		URI:    "sip:user@ims.example",
		Headers: map[string][]string{
			"Call-ID": {"options-call"},
			"CSeq":    {"1 OPTIONS"},
		},
	})
	if err != nil {
		t.Fatalf("HandleRequest(OPTIONS) error = %v", err)
	}
	if len(options) != 1 || !strings.Contains(options[0].Headers["Allow"], "MESSAGE") || !strings.Contains(options[0].Headers["Accept"], "application/vnd.3gpp.sms") {
		t.Fatalf("options=%+v", options)
	}
}

func TestIMSInboundWireServerDispatchesInfoAndUSSDBye(t *testing.T) {
	var handledInfo IMSInfoRequest
	var handledBye IMSByeRequest
	server := &IMSInboundWireServer{
		InfoHandler: IMSInfoHandlerFunc(func(ctx context.Context, req IMSInfoRequest) (IMSInfoResult, error) {
			handledInfo = req
			return IMSInfoResult{Handled: true, StatusCode: 200, Reason: "OK"}, nil
		}),
		ByeHandler: IMSByeHandlerFunc(func(ctx context.Context, req IMSByeRequest) (IMSByeResult, error) {
			handledBye = req
			return IMSByeResult{Handled: true, StatusCode: 200, Reason: "OK"}, nil
		}),
	}
	info := voiceclient.SIPIncomingRequest{
		Method: "INFO",
		URI:    "sip:user@ims.example",
		Headers: map[string][]string{
			"Call-ID":      {"ussd-call-1"},
			"CSeq":         {"2 INFO"},
			"From":         {"<sip:ussd-as@ims.example>;tag=as"},
			"To":           {"<sip:user@ims.example>;tag=ue"},
			"Content-Type": {"application/vnd.3gpp.ussd+xml"},
			"Info-Package": {"g.3gpp.ussd"},
		},
		Body: []byte(`<ussd-data><ussd-string>menu</ussd-string><UnstructuredSS-Request/></ussd-data>`),
	}
	responses, err := server.HandleRequest(context.Background(), info)
	if err != nil {
		t.Fatalf("HandleRequest(INFO) error = %v", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 200 {
		t.Fatalf("INFO responses=%+v", responses)
	}
	if handledInfo.CallID != "ussd-call-1" || handledInfo.CSeq != 2 || handledInfo.InfoPackage != "g.3gpp.ussd" || handledInfo.ContentType != "application/vnd.3gpp.ussd+xml" {
		t.Fatalf("handledInfo=%+v", handledInfo)
	}
	bye := voiceclient.SIPIncomingRequest{
		Method: "BYE",
		URI:    "sip:user@ims.example",
		Headers: map[string][]string{
			"Call-ID":      {"ussd-call-1"},
			"CSeq":         {"3 BYE"},
			"From":         {"<sip:ussd-as@ims.example>;tag=as"},
			"To":           {"<sip:user@ims.example>;tag=ue"},
			"Content-Type": {"application/vnd.3gpp.ussd+xml"},
		},
		Body: []byte(`<ussd-data><ussd-string>bye</ussd-string><UnstructuredSS-Notify/></ussd-data>`),
	}
	responses, err = server.HandleRequest(context.Background(), bye)
	if err != nil {
		t.Fatalf("HandleRequest(BYE) error = %v", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 200 {
		t.Fatalf("BYE responses=%+v", responses)
	}
	if handledBye.CallID != "ussd-call-1" || handledBye.CSeq != 3 || handledBye.ContentType != "application/vnd.3gpp.ussd+xml" {
		t.Fatalf("handledBye=%+v", handledBye)
	}
	options, err := server.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method: "OPTIONS",
		URI:    "sip:user@ims.example",
		Headers: map[string][]string{
			"Call-ID": {"options-info"},
			"CSeq":    {"1 OPTIONS"},
		},
	})
	if err != nil {
		t.Fatalf("HandleRequest(OPTIONS) error = %v", err)
	}
	if len(options) != 1 || !strings.Contains(options[0].Headers["Allow"], "INFO") || !strings.Contains(options[0].Headers["Accept"], "application/vnd.3gpp.ussd+xml") {
		t.Fatalf("options=%+v", options)
	}
}

func TestIMSInboundWireServerReturnsAgentByeCancelErrors(t *testing.T) {
	transport := newWireInboundTransport([]voiceclient.SIPResponse{
		{StatusCode: 503, Reason: "client bye failed"},
		{StatusCode: 503, Reason: "client cancel failed"},
	})
	agent := &IMSInboundAgent{ClientTransport: transport}
	agent.storeInboundDialog("wire-error-call", imsInboundDialogState{
		clientCfg: voiceclient.DialogRequestConfig{
			Profile:         voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
			LocalURI:        "sip:user@ims.example",
			ContactURI:      "sip:user@127.0.0.1:5060",
			RemoteURI:       "sip:+18005551212@ims.example",
			RemoteTargetURI: "sip:client@127.0.0.1:5070",
			CallID:          "wire-error-call",
			LocalTag:        "wire-local",
			RemoteTag:       "client-remote",
			CSeq:            1,
		},
		early: true,
	})
	server := &IMSInboundWireServer{Agent: agent}

	responses, err := server.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method: "BYE",
		URI:    "sip:user@ims.example",
		Headers: map[string][]string{
			"Call-ID": {"wire-error-call"},
			"CSeq":    {"2 BYE"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "client BYE rejected") {
		t.Fatalf("HandleRequest(BYE) err=%v, want client BYE rejection", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 500 || !strings.Contains(responses[0].Reason, "client BYE rejected") {
		t.Fatalf("BYE responses=%+v", responses)
	}
	if req := transport.readRequest(t); req.Method != "BYE" {
		t.Fatalf("client BYE request=%+v", req)
	}

	pendingInvite := parseWireIncoming(t, wireIMSInvite("wire-error-call", "INVITE", 1, nil))
	server.storeTransaction(wireTransactionKey(pendingInvite), []IMSInboundWireResponse{wireResponse(100, "Trying")})
	responses, err = server.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method: "CANCEL",
		URI:    "sip:user@ims.example",
		Headers: map[string][]string{
			"Call-ID": {"wire-error-call"},
			"CSeq":    {"1 CANCEL"},
			"Via":     {"SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-INVITE"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "client CANCEL rejected") {
		t.Fatalf("HandleRequest(CANCEL) err=%v, want client CANCEL rejection", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 500 || !strings.Contains(responses[0].Reason, "client CANCEL rejected") {
		t.Fatalf("CANCEL responses=%+v", responses)
	}
	if req := transport.readRequest(t); req.Method != "CANCEL" {
		t.Fatalf("client CANCEL request=%+v", req)
	}
}

func TestIMSInboundWireServerFallsBackToAgentForUnhandledNonUSSDInfo(t *testing.T) {
	transport := &fakeIMSVoiceTransport{responses: []voiceclient.SIPResponse{{
		StatusCode: 200,
		Reason:     "OK",
		Headers:    map[string][]string{"X-Client": {"dtmf-ok"}},
	}}}
	agent := &IMSInboundAgent{
		ClientTransport: transport,
	}
	agent.storeInboundDialog("dtmf-call", imsInboundDialogState{
		clientCfg: voiceclient.DialogRequestConfig{
			Profile:         voiceclient.IMSProfile{IMPU: "sip:user@ims.example", Domain: "ims.example"},
			LocalURI:        "sip:+18005551212@ims.example",
			ContactURI:      "sip:vowifi@127.0.0.1:5060",
			RemoteURI:       "sip:user@ims.example",
			RemoteTargetURI: "sip:client@127.0.0.1:5070",
			CallID:          "dtmf-call",
			LocalTag:        "ims-tag",
			RemoteTag:       "client-tag",
			CSeq:            2,
		},
	})
	server := &IMSInboundWireServer{
		Agent: agent,
		InfoHandler: IMSInfoHandlerFunc(func(ctx context.Context, req IMSInfoRequest) (IMSInfoResult, error) {
			return IMSInfoResult{Handled: false}, nil
		}),
	}
	responses, err := server.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method: "INFO",
		URI:    "sip:user@ims.example",
		Headers: map[string][]string{
			"Call-ID":      {"dtmf-call"},
			"CSeq":         {"9 INFO"},
			"From":         {"<sip:+18005551212@ims.example>;tag=ims-tag"},
			"To":           {"<sip:user@ims.example>;tag=ue"},
			"Content-Type": {"application/dtmf-relay"},
		},
		Body: []byte("Signal=7\r\nDuration=90\r\n"),
	})
	if err != nil {
		t.Fatalf("HandleRequest(INFO) error = %v", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 200 || responses[0].Headers["X-Client"] != "dtmf-ok" {
		t.Fatalf("responses=%+v", responses)
	}
	if len(transport.requests) != 1 || transport.requests[0].Method != "INFO" {
		t.Fatalf("requests=%+v", transport.requests)
	}
	info := transport.requests[0]
	if info.URI != "sip:client@127.0.0.1:5070" || info.Headers["CSeq"] != "9 INFO" ||
		info.Headers["Content-Type"] != "application/dtmf-relay" || !strings.Contains(string(info.Body), "Signal=7") {
		t.Fatalf("forwarded INFO=%+v body=%q", info, info.Body)
	}
}

func TestIMSInboundWireServerRejectsMessageWithoutHandler(t *testing.T) {
	server := &IMSInboundWireServer{}
	responses, err := server.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method: "MESSAGE",
		URI:    "sip:user@ims.example",
		Headers: map[string][]string{
			"Call-ID": {"sms-call-2"},
			"CSeq":    {"1 MESSAGE"},
		},
	})
	if err != nil {
		t.Fatalf("HandleRequest(MESSAGE) error = %v", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 405 || strings.Contains(responses[0].Headers["Allow"], "MESSAGE") {
		t.Fatalf("responses=%+v", responses)
	}
}

type wireInboundTransport struct {
	mu        sync.Mutex
	responses []voiceclient.SIPResponse
	requests  chan voiceclient.SIPRequestMessage
	writes    chan voiceclient.SIPRequestMessage
}

func newWireInboundTransport(responses []voiceclient.SIPResponse) *wireInboundTransport {
	return &wireInboundTransport{
		responses: append([]voiceclient.SIPResponse(nil), responses...),
		requests:  make(chan voiceclient.SIPRequestMessage, 8),
		writes:    make(chan voiceclient.SIPRequestMessage, 8),
	}
}

func (t *wireInboundTransport) RoundTripRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	t.requests <- msg
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.responses) == 0 {
		return voiceclient.SIPResponse{StatusCode: 500, Reason: "empty"}, nil
	}
	resp := t.responses[0]
	t.responses = t.responses[1:]
	return resp, nil
}

func (t *wireInboundTransport) WriteRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) error {
	t.writes <- msg
	return nil
}

func (t *wireInboundTransport) readRequest(tb testing.TB) voiceclient.SIPRequestMessage {
	tb.Helper()
	select {
	case msg := <-t.requests:
		return msg
	case <-time.After(time.Second):
		tb.Fatalf("timed out waiting for client request")
		return voiceclient.SIPRequestMessage{}
	}
}

func (t *wireInboundTransport) readWrite(tb testing.TB) voiceclient.SIPRequestMessage {
	tb.Helper()
	select {
	case msg := <-t.writes:
		return msg
	case <-time.After(time.Second):
		tb.Fatalf("timed out waiting for client write")
		return voiceclient.SIPRequestMessage{}
	}
}

type blockingWireInboundTransport struct {
	requests  chan voiceclient.SIPRequestMessage
	writes    chan voiceclient.SIPRequestMessage
	responses chan voiceclient.SIPResponse
}

func newBlockingWireInboundTransport() *blockingWireInboundTransport {
	return &blockingWireInboundTransport{
		requests:  make(chan voiceclient.SIPRequestMessage, 8),
		writes:    make(chan voiceclient.SIPRequestMessage, 8),
		responses: make(chan voiceclient.SIPResponse, 8),
	}
}

func (t *blockingWireInboundTransport) RoundTripRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	t.requests <- msg
	select {
	case resp := <-t.responses:
		return resp, nil
	case <-ctx.Done():
		return voiceclient.SIPResponse{}, ctx.Err()
	}
}

func (t *blockingWireInboundTransport) WriteRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) error {
	t.writes <- msg
	return nil
}

func (t *blockingWireInboundTransport) readRequest(tb testing.TB) voiceclient.SIPRequestMessage {
	tb.Helper()
	select {
	case msg := <-t.requests:
		return msg
	case <-time.After(time.Second):
		tb.Fatalf("timed out waiting for client request")
		return voiceclient.SIPRequestMessage{}
	}
}

func (t *blockingWireInboundTransport) respond(resp voiceclient.SIPResponse) {
	t.responses <- resp
}

type provisionalBlockingInboundTransport struct {
	requests     chan voiceclient.SIPRequestMessage
	writes       chan voiceclient.SIPRequestMessage
	responses    chan voiceclient.SIPResponse
	provisionals []voiceclient.SIPResponse
}

func newProvisionalBlockingInboundTransport(provisionals []voiceclient.SIPResponse) *provisionalBlockingInboundTransport {
	return &provisionalBlockingInboundTransport{
		requests:     make(chan voiceclient.SIPRequestMessage, 8),
		writes:       make(chan voiceclient.SIPRequestMessage, 8),
		responses:    make(chan voiceclient.SIPResponse, 8),
		provisionals: append([]voiceclient.SIPResponse(nil), provisionals...),
	}
}

func (t *provisionalBlockingInboundTransport) RoundTripInvite(ctx context.Context, msg voiceclient.SIPRequestMessage, onProvisional voiceclient.ProvisionalResponseHandler) (voiceclient.SIPResponse, error) {
	t.requests <- msg
	for _, resp := range t.provisionals {
		if onProvisional != nil {
			if err := onProvisional(ctx, msg, resp); err != nil {
				return voiceclient.SIPResponse{}, err
			}
		}
	}
	select {
	case resp := <-t.responses:
		return resp, nil
	case <-ctx.Done():
		return voiceclient.SIPResponse{}, ctx.Err()
	}
}

func (t *provisionalBlockingInboundTransport) RoundTripRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	t.requests <- msg
	select {
	case resp := <-t.responses:
		return resp, nil
	case <-ctx.Done():
		return voiceclient.SIPResponse{}, ctx.Err()
	}
}

func (t *provisionalBlockingInboundTransport) WriteRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) error {
	t.writes <- msg
	return nil
}

func (t *provisionalBlockingInboundTransport) readRequest(tb testing.TB) voiceclient.SIPRequestMessage {
	tb.Helper()
	select {
	case msg := <-t.requests:
		return msg
	case <-time.After(time.Second):
		tb.Fatalf("timed out waiting for client request")
		return voiceclient.SIPRequestMessage{}
	}
}

func (t *provisionalBlockingInboundTransport) respond(resp voiceclient.SIPResponse) {
	t.responses <- resp
}

func wireIMSInvite(callID, method string, cseq int, body []byte) []byte {
	return wireIMSRequest(callID, method, cseq, body)
}

func wireIMSRequest(callID, method string, cseq int, body []byte, extraHeaders ...string) []byte {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "INVITE"
	}
	branchMethod := method
	if method == "CANCEL" {
		branchMethod = "INVITE"
	}
	var b strings.Builder
	b.WriteString(method + " sip:user@ims.example SIP/2.0\r\n")
	b.WriteString("Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-" + branchMethod + "\r\n")
	b.WriteString("From: <sip:+18005551212@ims.example>;tag=ims-tag\r\n")
	b.WriteString("To: <sip:user@ims.example>\r\n")
	b.WriteString("Call-ID: " + callID + "\r\n")
	b.WriteString("CSeq: " + strconv.Itoa(cseq) + " " + method + "\r\n")
	b.WriteString("Contact: <sip:ims@203.0.113.10:5060>\r\n")
	for _, header := range extraHeaders {
		b.WriteString(header)
	}
	if len(body) > 0 {
		b.WriteString("Content-Type: application/sdp\r\n")
	}
	b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n")
	b.Write(body)
	return []byte(b.String())
}

func parseWireIncoming(t *testing.T, raw []byte) voiceclient.SIPIncomingRequest {
	t.Helper()
	req, err := voiceclient.ParseSIPRequest(raw)
	if err != nil {
		t.Fatalf("ParseSIPRequest() error = %v", err)
	}
	return req
}

func readUDPWireResponse(t *testing.T, conn net.Conn) voiceclient.SIPResponse {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("UDP Read() error = %v", err)
	}
	resp, err := voiceclient.ParseSIPResponse(buf[:n])
	if err != nil {
		t.Fatalf("ParseSIPResponse() error = %v", err)
	}
	return resp
}

func assertNoUDPWireResponse(t *testing.T, conn net.Conn, wait time.Duration) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err == nil {
		resp, parseErr := voiceclient.ParseSIPResponse(buf[:n])
		if parseErr != nil {
			t.Fatalf("unexpected UDP response raw=%q", buf[:n])
		}
		t.Fatalf("unexpected UDP response=%+v", resp)
	}
	if !isTimeout(err) {
		t.Fatalf("UDP Read() error = %v", err)
	}
}
