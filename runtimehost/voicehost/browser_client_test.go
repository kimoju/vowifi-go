package voicehost

import (
	"context"
	"testing"
	"time"

	"github.com/kimoju/vowifi-go/runtimehost/voiceclient"
)

func TestGatewayBrowserClientPublishesAndAnswersInboundCall(t *testing.T) {
	gateway := NewGateway()
	gateway.SetInboundEnabled(true)
	transport := gateway.ClientTransport("dev-1").(voiceclient.SIPInviteTransport)
	responseCh := make(chan voiceclient.SIPResponse, 1)
	go func() {
		response, _ := transport.RoundTripInvite(context.Background(), voiceclient.SIPRequestMessage{
			Method:  "INVITE",
			Headers: map[string]string{"Call-ID": "incoming-1", "From": "<sip:+15551234567@ims.example>", "To": "<sip:user@ims.example>"},
			Body:    []byte("v=0\r\nm=audio 4000 RTP/AVP 0\r\n"),
		}, nil)
		responseCh <- response
	}()

	deadline := time.Now().Add(time.Second)
	for len(gateway.InboundCalls("dev-1")) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	calls := gateway.InboundCalls("dev-1")
	if len(calls) != 1 || calls[0].Caller != "sip:+15551234567@ims.example" || calls[0].State != "ringing" {
		t.Fatalf("InboundCalls() = %+v", calls)
	}
	answer := []byte("v=0\r\nm=audio 5000 RTP/AVP 0\r\n")
	if err := gateway.AnswerInboundCall("incoming-1", answer); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-responseCh:
		if response.StatusCode != 200 || string(response.Body) != string(answer) {
			t.Fatalf("response = %+v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("inbound answer timed out")
	}
}

func TestGatewayBrowserClientRejectsInboundCall(t *testing.T) {
	gateway := NewGateway()
	gateway.SetInboundEnabled(true)
	transport := gateway.ClientTransport("dev-1")
	responseCh := make(chan voiceclient.SIPResponse, 1)
	go func() {
		response, _ := transport.RoundTripRequest(context.Background(), voiceclient.SIPRequestMessage{Method: "INVITE", Headers: map[string]string{"Call-ID": "incoming-2"}})
		responseCh <- response
	}()
	deadline := time.Now().Add(time.Second)
	for len(gateway.InboundCalls("")) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := gateway.RejectInboundCall("incoming-2"); err != nil {
		t.Fatal(err)
	}
	if response := <-responseCh; response.StatusCode != 486 {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if calls := gateway.InboundCalls(""); len(calls) != 0 {
		t.Fatalf("calls after reject = %+v", calls)
	}
}

func TestGatewayBrowserClientRejectsInboundCallWhileDisabled(t *testing.T) {
	gateway := NewGateway()
	transport := gateway.ClientTransport("dev-1")
	response, err := transport.RoundTripRequest(context.Background(), voiceclient.SIPRequestMessage{
		Method:  "INVITE",
		Headers: map[string]string{"Call-ID": "incoming-disabled"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 480 || len(gateway.InboundCalls("")) != 0 {
		t.Fatalf("response=%+v calls=%+v", response, gateway.InboundCalls(""))
	}
}
