package voicehost

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
)

type round2StatefulTransport struct {
	mu      sync.Mutex
	handler func(ctx context.Context, msg voiceclient.SIPRequestMessage, onProvisional voiceclient.ProvisionalResponseHandler) (voiceclient.SIPResponse, error)
	sent    []voiceclient.SIPRequestMessage
	written []voiceclient.SIPRequestMessage
}

func (t *round2StatefulTransport) RoundTripInvite(ctx context.Context, msg voiceclient.SIPRequestMessage, onProvisional voiceclient.ProvisionalResponseHandler) (voiceclient.SIPResponse, error) {
	c := cloneSIPRequestMessage(msg)
	t.mu.Lock()
	t.sent = append(t.sent, c)
	fn := t.handler
	t.mu.Unlock()
	if fn != nil {
		return fn(ctx, c, onProvisional)
	}
	return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
}

func (t *round2StatefulTransport) RoundTripRequest(ctx context.Context, msg voiceclient.SIPRequestMessage) (voiceclient.SIPResponse, error) {
	return t.RoundTripInvite(ctx, msg, nil)
}

func (t *round2StatefulTransport) WriteRequest(_ context.Context, msg voiceclient.SIPRequestMessage) error {
	c := cloneSIPRequestMessage(msg)
	t.mu.Lock()
	t.written = append(t.written, c)
	t.mu.Unlock()
	return nil
}

func (t *round2StatefulTransport) snapshot() ([]voiceclient.SIPRequestMessage, []voiceclient.SIPRequestMessage) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := make([]voiceclient.SIPRequestMessage, len(t.sent))
	for i := range t.sent {
		s[i] = cloneSIPRequestMessage(t.sent[i])
	}
	w := make([]voiceclient.SIPRequestMessage, len(t.written))
	for i := range t.written {
		w[i] = cloneSIPRequestMessage(t.written[i])
	}
	return s, w
}

// VH-01 & VH-02: Inbound call client->IMS UAC leg (hold/resume/DTMF INFO/BYE),
// Gateway agentForCall inbound routing, unreversed UAS Record-Route RouteSet,
// and Record-Route preservation on 18x/200 OK.
func TestRound2VH01AndVH02InboundClientToIMSUACLegAndRecordRoute(t *testing.T) {
	clientTransport := &round2StatefulTransport{
		handler: func(ctx context.Context, msg voiceclient.SIPRequestMessage, onProv voiceclient.ProvisionalResponseHandler) (voiceclient.SIPResponse, error) {
			if msg.Method == "INVITE" {
				if onProv != nil {
					_ = onProv(ctx, msg, voiceclient.SIPResponse{
						StatusCode: 180,
						Reason:     "Ringing",
						Headers:    map[string][]string{"To": {"<sip:alice@ims.example>;tag=client-tag-1"}},
					})
				}
				return voiceclient.SIPResponse{
					StatusCode: 200,
					Reason:     "OK",
					Headers: map[string][]string{
						"To":      {"<sip:alice@ims.example>;tag=client-tag-1"},
						"Contact": {"<sip:alice@127.0.0.1:5070>"},
					},
					Body: []byte(sampleSDP("127.0.0.1", 4010)),
				}, nil
			}
			return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
		},
	}
	imsTransport := &round2StatefulTransport{
		handler: func(_ context.Context, msg voiceclient.SIPRequestMessage, _ voiceclient.ProvisionalResponseHandler) (voiceclient.SIPResponse, error) {
			switch msg.Method {
			case "INVITE", "UPDATE":
				return voiceclient.SIPResponse{
					StatusCode: 200,
					Reason:     "OK",
					Headers:    map[string][]string{"Contact": {"<sip:caller@203.0.113.10:5060>"}},
					Body:       []byte(sampleSDP("203.0.113.10", 49170)),
				}, nil
			default:
				return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
			}
		},
	}

	inboundAgent := &IMSInboundAgent{
		DeviceID:         "dev-1",
		ClientTransport:  clientTransport,
		IMSTransport:     imsTransport,
		ClientContactURI: "sip:alice@127.0.0.1:5070",
		LocalContactURI:  "sip:alice@192.0.2.55:5060",
		Profile:          voiceclient.IMSProfile{IMPU: "sip:alice@ims.example", Domain: "ims.example"},
	}
	outboundAgent := &IMSOutboundAgent{Transport: imsTransport}
	gw := NewGateway()
	gw.RegisterAgent("dev-1", outboundAgent)
	gw.RegisterInboundAgent("dev-1", inboundAgent)

	server := &IMSInboundWireServer{
		Agent:      inboundAgent,
		ContactURI: "sip:alice@192.0.2.55:5060",
	}

	rawInvite := wireIMSRequest("vh01-call", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170)),
		"Record-Route: <sip:pcscf.ims.example;lr>\r\n",
		"Record-Route: <sip:scscf.ims.example;lr>\r\n",
	)
	inviteReq := parseWireIncoming(t, rawInvite)
	resps, err := server.HandleRequest(context.Background(), inviteReq)
	if err != nil {
		t.Fatalf("HandleRequest(INVITE) error = %v", err)
	}
	if len(resps) != 3 || resps[0].StatusCode != 100 || resps[1].StatusCode != 180 || resps[2].StatusCode != 200 {
		t.Fatalf("INVITE responses = %+v", resps)
	}
	wantRR := "<sip:pcscf.ims.example;lr>, <sip:scscf.ims.example;lr>"
	if resps[1].Headers["Record-Route"] != wantRR {
		t.Fatalf("180 Record-Route = %q, want %q", resps[1].Headers["Record-Route"], wantRR)
	}
	if resps[2].Headers["Record-Route"] != wantRR {
		t.Fatalf("200 Record-Route = %q, want %q", resps[2].Headers["Record-Route"], wantRR)
	}

	// Gateway must resolve the active inbound dialog to inboundAgent (NOT outboundAgent!).
	resolved := gw.agentForCall("dev-1", "vh01-call")
	if resolved != inboundAgent {
		t.Fatalf("Gateway.agentForCall resolved %T, want *IMSInboundAgent", resolved)
	}

	holdCtrl, ok := resolved.(DialogHoldController)
	if !ok {
		t.Fatalf("IMSInboundAgent does not implement DialogHoldController")
	}
	if res, err := holdCtrl.SendDialogHold(context.Background(), DialogHoldRequest{
		DeviceID: "dev-1",
		CallID:   "vh01-call",
	}); err != nil || !res.Accepted {
		t.Fatalf("SendDialogHold on inbound call res=%+v err=%v", res, err)
	}
	if res, err := holdCtrl.SendDialogResume(context.Background(), DialogResumeRequest{
		DeviceID: "dev-1",
		CallID:   "vh01-call",
	}); err != nil || !res.Accepted {
		t.Fatalf("SendDialogResume on inbound call res=%+v err=%v", res, err)
	}
	dtmfRes, err := inboundAgent.SendDialogDTMF(context.Background(), DialogDTMFRequest{
		DeviceID:   "dev-1",
		CallID:     "vh01-call",
		Signal:     "5",
		DurationMS: 160,
	})
	if err != nil || !dtmfRes.Accepted {
		t.Fatalf("SendDialogDTMF on inbound call res=%+v err=%v", dtmfRes, err)
	}
	byeRes, err := inboundAgent.EndVoiceCallWithResult(context.Background(), DialogInfo{
		DeviceID: "dev-1",
		CallID:   "vh01-call",
	})
	if err != nil || !byeRes.Accepted || byeRes.StatusCode != 200 {
		t.Fatalf("EndVoiceCallWithResult on inbound call res=%+v err=%v", byeRes, err)
	}

	imsSent, _ := imsTransport.snapshot()
	if len(imsSent) < 4 {
		t.Fatalf("expected >=4 IMS UAC requests (hold, resume, INFO, BYE), got %d: %+v", len(imsSent), imsSent)
	}
	for i, req := range imsSent {
		if req.Headers["Route"] != wantRR {
			t.Fatalf("IMS UAC req[%d] (%s) Route = %q, want unreversed %q", i, req.Method, req.Headers["Route"], wantRR)
		}
	}
	if imsSent[len(imsSent)-1].Method != "BYE" {
		t.Fatalf("last IMS UAC method = %q, want BYE", imsSent[len(imsSent)-1].Method)
	}
}

// VH-03: Persistent TCP ringing > ReadTimeout, async RP-ACK over same TCP stream, and Timer H on TCP 2xx.
func TestRound2VH03TCPStreamRingingDeliveryReportAndTimerH(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(tcp) error = %v", err)
	}
	defer ln.Close()

	clientTransport := &round2StatefulTransport{
		handler: func(ctx context.Context, msg voiceclient.SIPRequestMessage, onProv voiceclient.ProvisionalResponseHandler) (voiceclient.SIPResponse, error) {
			if msg.Method == "INVITE" {
				if onProv != nil {
					_ = onProv(ctx, msg, voiceclient.SIPResponse{
						StatusCode: 180,
						Reason:     "Ringing",
						Headers:    map[string][]string{"To": {"<sip:user@ims.example>;tag=client-tcp"}},
					})
				}
				time.Sleep(120 * time.Millisecond)
				return voiceclient.SIPResponse{
					StatusCode: 200,
					Reason:     "OK",
					Headers: map[string][]string{
						"To":      {"<sip:user@ims.example>;tag=client-tcp"},
						"Contact": {"<sip:client@127.0.0.1:5070>"},
					},
					Body: []byte(sampleSDP("127.0.0.1", 4020)),
				}, nil
			}
			return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
		},
	}

	var serverConnMu sync.Mutex
	var peerConn net.Conn
	rpAckRespCh := make(chan voiceclient.SIPResponse, 1)
	terminatedCh := make(chan int, 2)

	inboundAgent := &IMSInboundAgent{
		ClientTransport:  clientTransport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
		OnDialogEvent: func(_ context.Context, info DialogInfo, _, _ string, statusCode int, _ string) {
			if info.State == DialogStateTerminated && statusCode == 408 {
				select {
				case terminatedCh <- statusCode:
				default:
				}
			}
		},
	}

	server := &IMSInboundWireServer{
		Agent:          inboundAgent,
		ContactURI:     "sip:vowifi@127.0.0.1:5060",
		ReadTimeout:    30 * time.Millisecond,
		TransactionTTL: 140 * time.Millisecond,
		ResponsePacketHandler: &funcResponsePacketHandler{fn: func(raw []byte) bool {
			if !strings.HasPrefix(string(raw), "SIP/2.0 ") {
				return false
			}
			if resp, parseErr := voiceclient.ParseSIPResponse(raw); parseErr == nil {
				select {
				case rpAckRespCh <- resp:
				default:
				}
			}
			return true
		}},
		MessageHandler: IMSMessageHandlerFunc(func(_ context.Context, _ IMSMessageRequest) (IMSMessageResult, error) {
			return IMSMessageResult{
				StatusCode: 200,
				Reason:     "OK",
				DeliveryReport: &IMSMessageDeliveryReport{
					RemoteURI:   "sip:ipsmgw@ims.example",
					ContentType: "application/vnd.3gpp.sms",
					Body:        []byte{0x02, 0x09},
				},
			}, nil
		}),
		MessageDeliveryReportSender: &funcDeliveryReportSender{fn: func(_ context.Context, report IMSMessageDeliveryReport) error {
			serverConnMu.Lock()
			c := peerConn
			serverConnMu.Unlock()
			if c != nil {
				_, _ = c.Write([]byte("SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-rpack\r\nFrom: <sip:user@ims.example>;tag=1\r\nTo: <sip:ipsmgw@ims.example>;tag=2\r\nCall-ID: rpack-1\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n"))
			}
			_ = report
			return nil
		}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- server.ServeListener(ctx, ln)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial(tcp) error = %v", err)
	}
	defer conn.Close()
	serverConnMu.Lock()
	peerConn = conn
	serverConnMu.Unlock()

	if _, err := conn.Write([]byte("\r\n\r\n")); err != nil {
		t.Fatalf("write CRLF keepalive error = %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	msgWire := wireIMSRequest("tcp-sms-1", "MESSAGE", 1, nil, "Content-Type: application/vnd.3gpp.sms\r\n")
	if _, err := conn.Write(msgWire); err != nil {
		t.Fatalf("write TCP MESSAGE error = %v", err)
	}
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgOKRaw, err := voiceclient.ReadSIPStreamMessage(reader)
	if err != nil {
		t.Fatalf("read TCP MESSAGE 200 OK error = %v", err)
	}
	msgOK, err := voiceclient.ParseSIPResponse(msgOKRaw)
	if err != nil || msgOK.StatusCode != 200 {
		t.Fatalf("TCP MESSAGE response = %+v err=%v", msgOK, err)
	}
	select {
	case rpResp := <-rpAckRespCh:
		if rpResp.StatusCode != 200 {
			t.Fatalf("demuxed RP-ACK response status = %d, want 200", rpResp.StatusCode)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for demultiplexed SIP 200 OK on persistent TCP stream")
	}

	invWire := wireIMSInvite("tcp-ring-no-ack", "INVITE", 1, []byte(sampleSDP("203.0.113.10", 49170)))
	if _, err := conn.Write(invWire); err != nil {
		t.Fatalf("write TCP INVITE error = %v", err)
	}
	var gotCodes []int
	for len(gotCodes) < 3 {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		raw, rErr := voiceclient.ReadSIPStreamMessage(reader)
		if rErr != nil {
			t.Fatalf("read TCP INVITE response %d error = %v", len(gotCodes), rErr)
		}
		resp, pErr := voiceclient.ParseSIPResponse(raw)
		if pErr != nil {
			t.Fatalf("parse TCP INVITE response error = %v", pErr)
		}
		if resp.StatusCode == 100 && sipHeaderTag(firstVoiceHeader(resp.Headers, "To")) != "" {
			t.Fatalf("100 Trying unexpectedly included To tag: %q", firstVoiceHeader(resp.Headers, "To"))
		}
		gotCodes = append(gotCodes, resp.StatusCode)
	}
	if gotCodes[0] != 100 || gotCodes[1] != 180 || gotCodes[2] != 200 {
		t.Fatalf("TCP INVITE status sequence = %v, want [100 180 200]", gotCodes)
	}

	select {
	case code := <-terminatedCh:
		if code != 408 {
			t.Fatalf("Timer H termination code = %d, want 408", code)
		}
	case <-time.After(time.Second):
		t.Fatal("Timer H did not expire un-ACKed TCP INVITE dialog")
	}
	if inboundAgent.HasInboundDialog("tcp-ring-no-ack") {
		t.Fatal("inbound dialog still active after TCP Timer H ACK timeout")
	}

	cancel()
	<-done
}

type funcResponsePacketHandler struct {
	fn func([]byte) bool
}

func (h *funcResponsePacketHandler) HandleSIPResponsePacket(raw []byte) bool {
	return h.fn(raw)
}

type funcDeliveryReportSender struct {
	fn func(context.Context, IMSMessageDeliveryReport) error
}

func (s *funcDeliveryReportSender) SendIMSMessageDeliveryReport(ctx context.Context, r IMSMessageDeliveryReport) error {
	return s.fn(ctx, r)
}

// VH-04 & VH-07: Concurrent Headers safety, exact INVITE Via branch on non-2xx ACK & CANCEL,
// pre-1xx CANCEL deferral, and CANCEL vs 200 OK glare (ACK + immediate BYE).
func TestRound2VH04AndVH07CancelDeferralViaBranchAnd200OKGlare(t *testing.T) {
	inviteEntered := make(chan voiceclient.SIPRequestMessage, 1)
	release100 := make(chan struct{})
	releaseFinal := make(chan voiceclient.SIPResponse, 1)
	cancelSeen := make(chan voiceclient.SIPRequestMessage, 1)
	byeSeen := make(chan voiceclient.SIPRequestMessage, 1)

	transport := &round2StatefulTransport{
		handler: func(ctx context.Context, msg voiceclient.SIPRequestMessage, onProv voiceclient.ProvisionalResponseHandler) (voiceclient.SIPResponse, error) {
			switch msg.Method {
			case "INVITE":
				inviteEntered <- msg
				<-release100
				if onProv != nil {
					_ = onProv(ctx, msg, voiceclient.SIPResponse{StatusCode: 100, Reason: "Trying"})
				}
				resp := <-releaseFinal
				return resp, nil
			case "CANCEL":
				cancelSeen <- msg
				return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
			case "BYE":
				byeSeen <- msg
				return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
			default:
				return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
			}
		},
	}

	agent := &IMSOutboundAgent{
		Transport: transport,
		Profile:   voiceclient.IMSProfile{IMPU: "sip:alice@ims.example", Domain: "ims.example", LocalIP: "192.0.2.10"},
		Registration: voiceclient.RegistrationBinding{
			PublicIdentity: "sip:alice@ims.example",
			ContactURI:     "sip:alice@192.0.2.10:5060",
		},
	}

	callerHeaders := map[string]string{"X-Custom": "vh04"}
	stopReaders := make(chan struct{})
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for {
			select {
			case <-stopReaders:
				return
			default:
				for k, v := range callerHeaders {
					_ = k
					_ = v
				}
			}
		}
	}()

	type callOutcome struct {
		res OutboundCallResult
		err error
	}
	callOutCh := make(chan callOutcome, 1)
	go func() {
		res, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
			CallID:  "vh07-glare-call",
			Callee:  "+18005550199",
			RawSDP:  []byte(sampleSDP("192.0.2.10", 4000)),
			Headers: callerHeaders,
		})
		callOutCh <- callOutcome{res: res, err: err}
	}()

	inv := <-inviteEntered
	close(stopReaders)
	readerWG.Wait()

	invBranch := wireViaBranch(inv.Headers["Via"])
	if !strings.HasPrefix(invBranch, "z9hG4bK") {
		t.Fatalf("INVITE Via branch = %q, want z9hG4bK*", invBranch)
	}

	if err := agent.CancelVoiceCall(context.Background(), DialogInfo{CallID: "vh07-glare-call"}); err != nil {
		t.Fatalf("CancelVoiceCall(pre-1xx) error = %v", err)
	}
	select {
	case premature := <-cancelSeen:
		t.Fatalf("CANCEL transmitted before 1xx provisional: %+v", premature)
	case <-time.After(40 * time.Millisecond):
	}

	close(release100)
	var cancelReq voiceclient.SIPRequestMessage
	select {
	case cancelReq = <-cancelSeen:
	case <-time.After(time.Second):
		t.Fatal("deferred CANCEL was not sent upon 100 Trying")
	}
	if wireViaBranch(cancelReq.Headers["Via"]) != invBranch {
		t.Fatalf("CANCEL Via branch = %q, want exact INVITE branch %q", wireViaBranch(cancelReq.Headers["Via"]), invBranch)
	}

	releaseFinal <- voiceclient.SIPResponse{
		StatusCode: 200,
		Reason:     "OK",
		Headers: map[string][]string{
			"To":      {"<sip:+18005550199@ims.example>;tag=uas-glare"},
			"Contact": {"<sip:callee@203.0.113.88:5060>"},
		},
		Body: []byte(sampleSDP("203.0.113.88", 49170)),
	}

	outcome := <-callOutCh
	if outcome.res.Accepted || outcome.res.StatusCode != 487 {
		t.Fatalf("StartOutboundCall glare outcome = %+v err=%v, want Accepted=false StatusCode=487", outcome.res, outcome.err)
	}
	select {
	case byeReq := <-byeSeen:
		if byeReq.URI != "sip:callee@203.0.113.88:5060" {
			t.Fatalf("glare BYE URI = %q, want callee Contact", byeReq.URI)
		}
	case <-time.After(time.Second):
		t.Fatal("expected immediate BYE after ACK on CANCEL/200 OK glare")
	}
	_, written := transport.snapshot()
	if len(written) == 0 || written[0].Method != "ACK" {
		t.Fatalf("expected ACK before BYE on glare, written=%+v", written)
	}
}

// VH-05: 3GPP precondition negotiation (183 Session Progress -> PRACK -> UPDATE QoS confirmation).
func TestRound2VH05PreconditionsOutboundAndInboundAnswer(t *testing.T) {
	imsOffer := strings.Join([]string{
		"v=0",
		"o=- 10 10 IN IP4 203.0.113.10",
		"s=-",
		"c=IN IP4 203.0.113.10",
		"t=0 0",
		"m=audio 49170 RTP/AVP 0",
		"a=rtpmap:0 PCMU/8000",
		"a=curr:qos local none",
		"a=curr:qos remote none",
		"a=des:qos mandatory local sendrecv",
		"a=des:qos mandatory remote sendrecv",
		"a=conf:qos remote sendrecv",
		"",
	}, "\r\n")
	plainClientAnswer := sampleSDP("192.0.2.10", 4002)
	rewritten := string(RewriteSDPPreconditionsForAnswer([]byte(imsOffer), []byte(plainClientAnswer)))
	if !strings.Contains(rewritten, "a=curr:qos local sendrecv\r\n") ||
		!strings.Contains(rewritten, "a=des:qos mandatory local sendrecv\r\n") ||
		!strings.Contains(rewritten, "a=des:qos mandatory remote sendrecv\r\n") {
		t.Fatalf("RewriteSDPPreconditionsForAnswer missing QoS lines:\n%s", rewritten)
	}

	cls := ClassifyIMSInboundRequireOptions(map[string][]string{"Require": {"100rel, precondition"}})
	if len(cls.Unsupported) != 0 {
		t.Fatalf("precondition must be supported on IMSInboundWireServer, got unsupported=%v", cls.Unsupported)
	}

	transport := &round2StatefulTransport{}
	transport.handler = func(ctx context.Context, msg voiceclient.SIPRequestMessage, onProv voiceclient.ProvisionalResponseHandler) (voiceclient.SIPResponse, error) {
		switch msg.Method {
		case "INVITE":
			if onProv != nil {
				sdp183 := strings.Join([]string{
					"v=0",
					"o=- 20 20 IN IP4 203.0.113.20",
					"s=-",
					"c=IN IP4 203.0.113.20",
					"t=0 0",
					"m=audio 49200 RTP/AVP 0",
					"a=rtpmap:0 PCMU/8000",
					"a=curr:qos local none",
					"a=curr:qos remote none",
					"a=des:qos mandatory local sendrecv",
					"a=des:qos mandatory remote sendrecv",
					"a=conf:qos remote sendrecv",
					"",
				}, "\r\n")
				if err := onProv(ctx, msg, voiceclient.SIPResponse{
					StatusCode: 183,
					Reason:     "Session Progress",
					Headers: map[string][]string{
						"To":      {"<sip:+18005551212@ims.example>;tag=early-tag"},
						"Contact": {"<sip:ims@203.0.113.20:5060>"},
						"Require": {"100rel, precondition"},
						"RSeq":    {"7"},
					},
					Body: []byte(sdp183),
				}); err != nil {
					return voiceclient.SIPResponse{}, err
				}
			}
			return voiceclient.SIPResponse{
				StatusCode: 200,
				Reason:     "OK",
				Headers: map[string][]string{
					"To":      {"<sip:+18005551212@ims.example>;tag=early-tag"},
					"Contact": {"<sip:ims@203.0.113.20:5060>"},
				},
				Body: []byte(sampleSDP("203.0.113.20", 49200)),
			}, nil
		case "PRACK":
			return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
		case "UPDATE":
			return voiceclient.SIPResponse{
				StatusCode: 200,
				Reason:     "OK",
				Body:       []byte(sampleSDP("203.0.113.20", 49200)),
			}, nil
		default:
			return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
		}
	}

	agent := &IMSOutboundAgent{
		Transport: transport,
		Profile:   voiceclient.IMSProfile{IMPU: "sip:alice@ims.example", Domain: "ims.example", LocalIP: "192.0.2.10"},
		Registration: voiceclient.RegistrationBinding{
			PublicIdentity: "sip:alice@ims.example",
			ContactURI:     "sip:alice@192.0.2.10:5060",
		},
	}
	res, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
		CallID: "vh05-precond-out",
		Callee: "+18005551212",
		RawSDP: []byte(sampleSDP("192.0.2.10", 4000)),
	})
	if err != nil || !res.Accepted {
		t.Fatalf("StartOutboundCall(precondition) res=%+v err=%v", res, err)
	}
	sent, _ := transport.snapshot()
	if len(sent) < 3 || sent[1].Method != "PRACK" || sent[2].Method != "UPDATE" {
		t.Fatalf("expected [INVITE, PRACK, UPDATE], got %+v", sent)
	}
	if !strings.Contains(sent[1].Headers["To"], "tag=early-tag") || !strings.Contains(sent[2].Headers["To"], "tag=early-tag") {
		t.Fatalf("PRACK/UPDATE missing early-dialog To tag: prack=%q update=%q", sent[1].Headers["To"], sent[2].Headers["To"])
	}
	if !strings.Contains(string(sent[2].Body), "a=curr:qos local sendrecv") {
		t.Fatalf("precondition UPDATE SDP missing local QoS confirmation:\n%s", sent[2].Body)
	}
}

// VH-06: SRTP SDES RTP/AVP <-> RTP/SAVP bridging, matching offered crypto tag, MKI stripping, and mid-dialog rekey.
func TestRound2VH06SRTPSDESRelayTagMatchingMKIAndMidDialogRekey(t *testing.T) {
	key1 := "inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj"
	key2 := "inline:NzB4d1BINUAvLEw6UzF3WSJ+PSdFcGdUJShpX1Zj"
	imsOffer := strings.Join([]string{
		"v=0",
		"o=- 1 1 IN IP4 127.0.0.1",
		"s=-",
		"c=IN IP4 127.0.0.1",
		"t=0 0",
		"m=audio 49170 RTP/SAVP 0",
		"a=rtpmap:0 PCMU/8000",
		"a=crypto:1 F8_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj",
		"a=crypto:2 AES_CM_128_HMAC_SHA1_80 " + key1 + "|2^20|1:4 UNENCRYPTED_SRTCP",
		"",
	}, "\r\n")

	_, secInfo, err := ParseSDPWithSecurity([]byte(imsOffer))
	if err != nil {
		t.Fatalf("ParseSDPWithSecurity(MKI + session param) error = %v", err)
	}
	if len(secInfo.Crypto) != 1 || secInfo.Crypto[0].Tag != "2" {
		t.Fatalf("parsed crypto attrs = %+v", secInfo.Crypto)
	}

	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP: "127.0.0.1",
		IMSListenIP:    "127.0.0.1",
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 4090})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()

	neg, err := newInboundSDESRelayNegotiation([]byte(imsOffer), RTPRelaySRTPConfig{ClientPlaintext: true})
	if err != nil || neg == nil {
		t.Fatalf("newInboundSDESRelayNegotiation() neg=%v err=%v", neg, err)
	}
	clientOffer := neg.RewriteClientOffer(RewriteSDPMediaEndpoint([]byte(imsOffer), relay.ClientEndpoint()))
	if !strings.Contains(string(clientOffer), "RTP/AVP") || strings.Contains(string(clientOffer), "a=crypto:") {
		t.Fatalf("RewriteClientOffer(ClientPlaintext) failed:\n%s", clientOffer)
	}

	plainClientAns := sampleSDP("127.0.0.1", 4090)
	clientSDP, _ := ParseSDP([]byte(plainClientAns))
	imsAns, _, err := neg.RewriteIMSAnswer(relay, []byte(plainClientAns), clientSDP)
	if err != nil {
		t.Fatalf("RewriteIMSAnswer() error = %v", err)
	}
	if !strings.Contains(string(imsAns), "RTP/SAVP") || !strings.Contains(string(imsAns), "a=crypto:2 AES_CM_128_HMAC_SHA1_80 ") {
		t.Fatalf("IMS SRTP answer did not match offered tag 2:\n%s", imsAns)
	}

	rekeyOffer := strings.Join([]string{
		"v=0",
		"o=- 1 2 IN IP4 127.0.0.1",
		"s=-",
		"c=IN IP4 127.0.0.1",
		"t=0 0",
		"m=audio 49170 RTP/SAVP 0",
		"a=rtpmap:0 PCMU/8000",
		"a=crypto:3 AES_CM_128_HMAC_SHA1_80 " + key2,
		"",
	}, "\r\n")
	midNeg, err := neg.PrepareIMSMidDialogOffer([]byte(rekeyOffer))
	if err != nil || midNeg == nil {
		t.Fatalf("PrepareIMSMidDialogOffer() neg=%v err=%v", midNeg, err)
	}
	rekeyAns, _, err := midNeg.RewriteIMSAnswer(relay, []byte(plainClientAns), clientSDP)
	if err != nil {
		t.Fatalf("mid-dialog RewriteIMSAnswer() error = %v", err)
	}
	if !strings.Contains(string(rekeyAns), "a=crypto:3 AES_CM_128_HMAC_SHA1_80 ") {
		t.Fatalf("mid-dialog SRTP answer did not use rotated tag 3:\n%s", rekeyAns)
	}
}

// VH-08, VH-14 & VH-15: Periodic compound RTCP (SR/RR + SDES CNAME), continuous DTMF SSRC/Seq/0dBm0,
// and per-interval delta FractionLost in RTPStreamStats.
func TestRound2VH08VH14VH15CompoundRTCPDTMFAndDeltaFractionLost(t *testing.T) {
	imsRTP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(imsRTP) error = %v", err)
	}
	defer imsRTP.Close()
	imsRTCP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(imsRTCP) error = %v", err)
	}
	defer imsRTCP.Close()

	imsRTPPort := imsRTP.LocalAddr().(*net.UDPAddr).Port
	imsRTCPPort := imsRTCP.LocalAddr().(*net.UDPAddr).Port

	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP: "127.0.0.1",
		IMSListenIP:    "127.0.0.1",
		RTCPReportSchedule: RTPRelayRTCPReportScheduleConfig{
			Enabled:          true,
			Interval:         25 * time.Millisecond,
			ClientToIMS:      true,
			ClientToIMSCNAME: "ue@ims.example",
			RunImmediately:   true,
		},
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 4092})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()

	if err := relay.SetIMSRemote(SDPInfo{
		ConnectionIP:           "127.0.0.1",
		MediaPort:              imsRTPPort,
		RTCPPort:               imsRTCPPort,
		Payloads:               []int{0, 101},
		TelephoneEventPayloads: map[uint8]int{101: 8000},
		Codecs: []SDPCodec{
			{Payload: 0, EncodingName: "PCMU", ClockRate: 8000},
			{Payload: 101, EncodingName: "telephone-event", ClockRate: 8000},
		},
		Direction: "sendrecv",
	}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}

	_ = imsRTCP.SetReadDeadline(time.Now().Add(time.Second))
	rtcpBuf := make([]byte, 1500)
	n, _, err := imsRTCP.ReadFrom(rtcpBuf)
	if err != nil {
		t.Fatalf("expected periodic compound RTCP packet, ReadFrom error = %v", err)
	}
	if n < 16 || (rtcpBuf[1] != 200 && rtcpBuf[1] != 201) {
		t.Fatalf("first RTCP packet PT=%d len=%d, want SR(200) or RR(201)", rtcpBuf[1], n)
	}
	firstLenBytes := (int(binary.BigEndian.Uint16(rtcpBuf[2:4])) + 1) * 4
	if n <= firstLenBytes || rtcpBuf[firstLenBytes+1] != 202 {
		t.Fatalf("compound RTCP missing mandatory SDES (PT=202): len=%d firstLen=%d raw=%x", n, firstLenBytes, rtcpBuf[:n])
	}

	// VH-14: Send two consecutive DTMF digits via relay with Volume=0, HasVolume=true (0 dBm0 -> wire 0)
	// and verify continuous SSRC, monotonically increasing sequence numbers, and advancing RTP timestamps!
	r1, err := relay.SendRTPDTMF(context.Background(), RTPRelayDTMFRequest{
		Direction:      RTPDTMFClientToIMS,
		Signal:         "1",
		DurationMS:     40,
		StepMS:         20,
		EndPacketCount: 1,
		Volume:         0,
		HasVolume:      true,
	})
	if err != nil {
		t.Fatalf("SendRTPDTMF('1') error = %v", err)
	}
	r2, err := relay.SendRTPDTMF(context.Background(), RTPRelayDTMFRequest{
		Direction:      RTPDTMFClientToIMS,
		Signal:         "2",
		DurationMS:     40,
		StepMS:         20,
		EndPacketCount: 1,
		Volume:         0,
		HasVolume:      true,
	})
	if err != nil {
		t.Fatalf("SendRTPDTMF('2') error = %v", err)
	}
	if r1.SSRC == 0 || r2.SSRC != r1.SSRC {
		t.Fatalf("DTMF SSRC not continuous across digits: r1=%#x r2=%#x", r1.SSRC, r2.SSRC)
	}
	if r2.Timestamp <= r1.Timestamp {
		t.Fatalf("second DTMF timestamp %d did not advance past %d", r2.Timestamp, r1.Timestamp)
	}
	_ = imsRTP.SetReadDeadline(time.Now().Add(time.Second))
	rtpBuf := make([]byte, 256)
	rn, _, err := imsRTP.ReadFrom(rtpBuf)
	if err != nil || rn < 16 {
		t.Fatalf("read DTMF RTP packet rn=%d err=%v", rn, err)
	}
	if gotVol := rtpBuf[13] & 0x3f; gotVol != 0 {
		t.Fatalf("0 dBm0 telephone-event wire volume = %d, want 0", gotVol)
	}

	// VH-15: Per-interval delta FractionLost in RTPStreamStatsTracker!
	var tracker RTPStreamStatsTracker
	base := time.Now()
	makeRTP := func(seq uint16, ts uint32) []byte {
		b := make([]byte, 16)
		b[0] = 0x80
		b[1] = 0
		binary.BigEndian.PutUint16(b[2:4], seq)
		binary.BigEndian.PutUint32(b[4:8], ts)
		binary.BigEndian.PutUint32(b[8:12], 0x11223344)
		return b
	}
	_, _ = tracker.ObserveRTPPacket(makeRTP(1, 160), base, 8000)
	_, _ = tracker.ObserveRTPPacket(makeRTP(2, 320), base.Add(20*time.Millisecond), 8000)
	_, _ = tracker.ObserveRTPPacket(makeRTP(4, 640), base.Add(60*time.Millisecond), 8000)
	rep1 := tracker.TakeRTCPReportStatsAt(base.Add(80 * time.Millisecond))
	if len(rep1) != 1 || rep1[0].FractionLost != 64 {
		t.Fatalf("interval 1 report = %+v, want FractionLost=64 (25%%)", rep1)
	}
	for i := uint16(5); i <= 8; i++ {
		_, _ = tracker.ObserveRTPPacket(makeRTP(i, uint32(i)*160), base.Add(time.Duration(i)*20*time.Millisecond), 8000)
	}
	rep2 := tracker.TakeRTCPReportStatsAt(base.Add(200 * time.Millisecond))
	if len(rep2) != 1 || rep2[0].FractionLost != 0 {
		t.Fatalf("interval 2 delta report = %+v, want FractionLost=0 (LostPackets=%d)", rep2, rep2[0].LostPackets)
	}
}

// VH-09, VH-10, VH-11, VH-16: Session Timer UAS expiry watchdog, Digest-challenged re-INVITE ACK CSeq/Via,
// late-offer SDP-less re-INVITE + ACK SDP answer, and IPv6 SDP rewrite with dynamic PTs & o= version bump.
func TestRound2VH09VH10VH11VH16SessionTimerDigestReinviteLateOfferAndIPv6SDP(t *testing.T) {
	ipv6Offer := strings.Join([]string{
		"v=0",
		"o=ims 100 5 IN IP4 203.0.113.1",
		"s=-",
		"c=IN IP4 203.0.113.1",
		"t=0 0",
		"m=audio 49170 RTP/AVP 96 101",
		"a=rtcp:49171 IN IP4 203.0.113.1",
		"a=rtpmap:96 AMR-WB/16000/1",
		"a=fmtp:96 mode-set=0,1,2",
		"a=rtpmap:101 telephone-event/16000",
		"",
	}, "\r\n")
	rewrittenIPv6 := string(RewriteSDPMediaEndpoint([]byte(ipv6Offer), SDPInfo{
		ConnectionIP: "2001:db8::42",
		MediaPort:    50000,
		RTCPPort:     50001,
	}))
	if !strings.Contains(rewrittenIPv6, "o=ims 100 6 IN IP6 2001:db8::42\r\n") ||
		!strings.Contains(rewrittenIPv6, "c=IN IP6 2001:db8::42\r\n") ||
		!strings.Contains(rewrittenIPv6, "a=rtcp:50001 IN IP6 2001:db8::42\r\n") ||
		!strings.Contains(rewrittenIPv6, "a=rtpmap:96 AMR-WB/16000/1\r\n") {
		t.Fatalf("IPv6 SDP rewrite failed:\n%s", rewrittenIPv6)
	}

	binding := testVoiceDigestBinding(t, "nonce-initial")
	authSession := binding.AuthSession
	reinviteStep := 0
	transport := &round2StatefulTransport{
		handler: func(_ context.Context, msg voiceclient.SIPRequestMessage, _ voiceclient.ProvisionalResponseHandler) (voiceclient.SIPResponse, error) {
			if msg.Method == "INVITE" {
				reinviteStep++
				switch reinviteStep {
				case 1:
					return voiceclient.SIPResponse{
						StatusCode: 200,
						Reason:     "OK",
						Headers: map[string][]string{
							"To":      {"<sip:bob@ims.example>;tag=bob-tag"},
							"Contact": {"<sip:bob@203.0.113.50:5060>"},
						},
						Body: []byte(sampleSDP("203.0.113.50", 49170)),
					}, nil
				case 2:
					return voiceclient.SIPResponse{
						StatusCode: 401,
						Reason:     "Unauthorized",
						Headers: map[string][]string{
							"To":               {"<sip:bob@ims.example>;tag=bob-tag"},
							"WWW-Authenticate": {`Digest realm="ims.example", nonce="bm9uY2UxMjM0NTY=", algorithm=MD5, qop="auth"`},
						},
					}, nil
				case 3:
					return voiceclient.SIPResponse{
						StatusCode: 200,
						Reason:     "OK",
						Headers: map[string][]string{
							"To":      {"<sip:bob@ims.example>;tag=bob-tag"},
							"Contact": {"<sip:bob@203.0.113.50:5060>"},
						},
						Body: []byte(sampleSDP("203.0.113.50", 49172)),
					}, nil
				}
			}
			return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
		},
	}

	terminatedReason := make(chan string, 1)
	agent := &IMSOutboundAgent{
		Transport: transport,
		Profile:   voiceclient.IMSProfile{IMPU: "sip:alice@ims.example", Domain: "ims.example", LocalIP: "192.0.2.10"},
		Registration: voiceclient.RegistrationBinding{
			PublicIdentity: "sip:alice@ims.example",
			ContactURI:     "sip:alice@192.0.2.10:5060",
			AuthSession:    authSession,
		},
		OnDialogTerminated: func(_ context.Context, _ string, reason string) {
			select {
			case terminatedReason <- reason:
			default:
			}
		},
	}

	if _, err := agent.StartOutboundCall(context.Background(), OutboundCallRequest{
		CallID:     "vh10-11-call",
		Callee:     "bob",
		RequestURI: "sip:bob@ims.example",
		RawSDP:     []byte(sampleSDP("192.0.2.10", 4000)),
	}); err != nil {
		t.Fatalf("StartOutboundCall() error = %v", err)
	}

	reRes, err := agent.SendDialogReinvite(context.Background(), DialogReinviteRequest{
		CallID:   "vh10-11-call",
		DeferAck: true,
	})
	if err != nil || !reRes.Accepted || len(reRes.Body) == 0 {
		t.Fatalf("SendDialogReinvite(SDP-less + 401) res=%+v err=%v", reRes, err)
	}
	if err := agent.AckDialog(context.Background(), DialogAckRequest{
		CallID:      "vh10-11-call",
		ContentType: "application/sdp",
		Body:        []byte(sampleSDP("192.0.2.10", 4004)),
	}); err != nil {
		t.Fatalf("AckDialog(late answer) error = %v", err)
	}

	sent, written := transport.snapshot()
	if len(sent) != 3 {
		t.Fatalf("expected 3 INVITE transmissions, got %d", len(sent))
	}
	if wireViaBranch(sent[1].Headers["Via"]) == wireViaBranch(sent[2].Headers["Via"]) {
		t.Fatalf("401 retry re-INVITE reused Via branch %q", sent[2].Headers["Via"])
	}
	if len(written) != 3 {
		t.Fatalf("expected 3 ACKs (initial, 401, post-auth 200), got %d: %+v", len(written), written)
	}
	if written[1].Headers["CSeq"] != "2 ACK" || wireViaBranch(written[1].Headers["Via"]) != wireViaBranch(sent[1].Headers["Via"]) {
		t.Fatalf("401 non-2xx ACK = %+v, want CSeq '2 ACK' & Via branch matching sent[1]", written[1])
	}
	if written[2].Headers["CSeq"] != "3 ACK" || !strings.Contains(string(written[2].Body), "m=audio 4004 RTP/AVP") {
		t.Fatalf("post-auth 200 ACK = %+v body=%q, want CSeq '3 ACK' & SDP answer", written[2], written[2].Body)
	}

	agent.storeDialog("vh09-uas-expire", imsDialogState{
		cfg: voiceclient.DialogRequestConfig{
			Profile:          agent.Profile,
			LocalURI:         "sip:alice@ims.example",
			ContactURI:       "sip:alice@192.0.2.10:5060",
			RemoteURI:        "sip:bob@ims.example",
			RemoteTargetURI:  "sip:bob@203.0.113.50:5060",
			CallID:           "vh09-uas-expire",
			LocalTag:         "tag-a",
			RemoteTag:        "tag-b",
			CSeq:             2,
			SessionExpires:   1,
			SessionRefresher: "uas",
		},
	})
	agent.scheduleDialogSessionRefresh("vh09-uas-expire")
	select {
	case reason := <-terminatedReason:
		if !strings.Contains(reason, "expired") {
			t.Fatalf("unexpected termination reason %q", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UAS session expiration watchdog did not terminate unrefreshed session")
	}
}

// VH-12 & VH-13: Independent CSeq spaces, monotonic remote CSeq enforcement (500),
// unique non-"vowifi-go" dialog LocalTags, Contact on 200 OK, and 481 on mid-dialog tag mismatch.
func TestRound2VH12AndVH13CSeqIsolationUniqueTagsAndTagValidation(t *testing.T) {
	clientTransport := &round2StatefulTransport{
		handler: func(_ context.Context, msg voiceclient.SIPRequestMessage, _ voiceclient.ProvisionalResponseHandler) (voiceclient.SIPResponse, error) {
			if msg.Method == "INVITE" {
				return voiceclient.SIPResponse{
					StatusCode: 200,
					Reason:     "OK",
					Headers: map[string][]string{
						"To":      {"<sip:user@ims.example>;tag=client-rx"},
						"Contact": {"<sip:client@127.0.0.1:5070>"},
					},
					Body: []byte(sampleSDP("127.0.0.1", 4030)),
				}, nil
			}
			return voiceclient.SIPResponse{StatusCode: 200, Reason: "OK"}, nil
		},
	}

	inboundAgent := &IMSInboundAgent{
		ClientTransport:  clientTransport,
		ClientContactURI: "sip:client@127.0.0.1:5070",
		LocalContactURI:  "sip:vowifi@127.0.0.1:5060",
	}
	server := &IMSInboundWireServer{
		Agent:      inboundAgent,
		ContactURI: "sip:vowifi@127.0.0.1:5060",
	}

	inv1 := parseWireIncoming(t, wireIMSInvite("vh13-call-1", "INVITE", 10, []byte(sampleSDP("203.0.113.10", 49170))))
	r1, err := server.HandleRequest(context.Background(), inv1)
	if err != nil || len(r1) != 2 || r1[1].StatusCode != 200 {
		t.Fatalf("call 1 INVITE r1=%+v err=%v", r1, err)
	}
	inv2 := parseWireIncoming(t, wireIMSInvite("vh13-call-2", "INVITE", 1, []byte(sampleSDP("203.0.113.11", 49172))))
	r2, err := server.HandleRequest(context.Background(), inv2)
	if err != nil || len(r2) != 2 || r2[1].StatusCode != 200 {
		t.Fatalf("call 2 INVITE r2=%+v err=%v", r2, err)
	}

	tag1 := inboundAgent.InboundDialogLocalTag("vh13-call-1")
	tag2 := inboundAgent.InboundDialogLocalTag("vh13-call-2")
	if tag1 == "" || tag2 == "" || tag1 == tag2 || tag1 == "vowifi-go" || tag2 == "vowifi-go" {
		t.Fatalf("expected unique cryptographic dialog tags, got tag1=%q tag2=%q", tag1, tag2)
	}
	if r1[1].Headers["Contact"] != "<sip:vowifi@127.0.0.1:5060>" {
		t.Fatalf("200 OK missing Contact header: %+v", r1[1].Headers)
	}

	wrongTagInfo := voiceclient.SIPIncomingRequest{
		Method: "INFO",
		URI:    "sip:vowifi@127.0.0.1:5060",
		Headers: map[string][]string{
			"Via":          {"SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-wrongtag"},
			"From":         {"<sip:+18005551212@ims.example>;tag=ims-tag"},
			"To":           {"<sip:user@ims.example>;tag=spoofed-tag"},
			"Call-ID":      {"vh13-call-1"},
			"CSeq":         {"11 INFO"},
			"Content-Type": {"application/dtmf-relay"},
		},
		Body: []byte("Signal=1\r\nDuration=100\r\n"),
	}
	resWrongTag, _ := server.HandleRequest(context.Background(), wrongTagInfo)
	if len(resWrongTag) != 1 || resWrongTag[0].StatusCode != 481 {
		t.Fatalf("wrong To tag INFO responses = %+v, want 481", resWrongTag)
	}

	validInfo := wrongTagInfo
	validInfo.Headers = cloneSIPHeaders(wrongTagInfo.Headers)
	validInfo.Headers["Via"] = []string{"SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-valid11"}
	validInfo.Headers["To"] = []string{"<sip:user@ims.example>;tag=" + tag1}
	resValid, err := server.HandleRequest(context.Background(), validInfo)
	if err != nil || len(resValid) != 1 || resValid[0].StatusCode != 200 {
		t.Fatalf("valid INFO responses=%+v err=%v", resValid, err)
	}

	staleInfo := validInfo
	staleInfo.Headers = cloneSIPHeaders(validInfo.Headers)
	staleInfo.Headers["Via"] = []string{"SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-stale9"}
	staleInfo.Headers["CSeq"] = []string{"9 INFO"}
	resStale, _ := server.HandleRequest(context.Background(), staleInfo)
	if len(resStale) != 1 || resStale[0].StatusCode != 500 {
		t.Fatalf("stale CSeq INFO responses = %+v, want 500", resStale)
	}
}
