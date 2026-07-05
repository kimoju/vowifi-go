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

func TestIMSInboundWireServerRejectsUnsupportedMethod(t *testing.T) {
	server := &IMSInboundWireServer{}
	responses, err := server.HandleRequest(context.Background(), voiceclient.SIPIncomingRequest{
		Method: "OPTIONS",
		URI:    "sip:user@ims.example",
		Headers: map[string][]string{
			"Call-ID": {"call-options"},
			"CSeq":    {"1 OPTIONS"},
		},
	})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if len(responses) != 1 || responses[0].StatusCode != 405 || !strings.Contains(responses[0].Headers["Allow"], "INVITE") {
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

func wireIMSInvite(callID, method string, cseq int, body []byte) []byte {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "INVITE"
	}
	var b strings.Builder
	b.WriteString(method + " sip:user@ims.example SIP/2.0\r\n")
	b.WriteString("Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-" + method + "\r\n")
	b.WriteString("From: <sip:+18005551212@ims.example>;tag=ims-tag\r\n")
	b.WriteString("To: <sip:user@ims.example>\r\n")
	b.WriteString("Call-ID: " + callID + "\r\n")
	b.WriteString("CSeq: " + strconv.Itoa(cseq) + " " + method + "\r\n")
	b.WriteString("Contact: <sip:ims@203.0.113.10:5060>\r\n")
	if len(body) > 0 {
		b.WriteString("Content-Type: application/sdp\r\n")
	}
	b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n")
	b.Write(body)
	return []byte(b.String())
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
