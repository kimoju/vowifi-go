package runtimehost

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/runtimehost/eventhost"
	"github.com/boa-z/vowifi-go/runtimehost/messaging"
)

type inboundRuntimeDispatcher struct {
	events chan eventhost.Event
}

func (d *inboundRuntimeDispatcher) Dispatch(_ context.Context, event eventhost.Event) {
	select {
	case d.events <- event:
	default:
	}
}

func TestRuntimeIMSInboundReceivesSIPMessageAndDispatchesSMS(t *testing.T) {
	dispatch := &inboundRuntimeDispatcher{events: make(chan eventhost.Event, 4)}
	inst := &Instance{
		state:   State{DeviceID: "reader-1", Phase: PhaseReady, IMSReady: true},
		service: messaging.NewService("reader-1", "310260123456789", nil, dispatch),
	}
	inbound, err := startRuntimeIMSInbound(IMSInboundConfig{
		Network:    "udp4",
		LocalAddr:  "127.0.0.1:0",
		ContactURI: "sip:reader@127.0.0.1:5060",
		UserAgent:  "vohive-test",
	}, inst)
	if err != nil {
		t.Fatalf("startRuntimeIMSInbound() error = %v", err)
	}
	defer inbound.close(context.Background())

	serverAddr := inbound.packet.LocalAddr().String()
	conn, err := net.Dial("udp4", serverAddr)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	body := "hello from IMS"
	request := strings.Join([]string{
		"MESSAGE sip:reader@127.0.0.1:5060 SIP/2.0",
		"Via: SIP/2.0/UDP 127.0.0.1:5090;branch=z9hG4bK-inbound-test",
		"Max-Forwards: 70",
		"From: <sip:+18005550199@ims.example>;tag=sender",
		"To: <sip:reader@ims.example>",
		"Call-ID: inbound-sms-test",
		"CSeq: 1 MESSAGE",
		"Content-Type: text/plain",
		fmt.Sprintf("Content-Length: %d", len(body)),
		"",
		body,
	}, "\r\n")
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if !strings.Contains(string(response[:n]), "SIP/2.0 200 OK") {
		t.Fatalf("response=%q, want 200 OK", response[:n])
	}

	select {
	case event := <-dispatch.events:
		sms, ok := event.(eventhost.SMSReceived)
		if !ok {
			t.Fatalf("event type = %T, want SMSReceived", event)
		}
		if sms.DevID != "reader-1" || sms.Content != body || !strings.Contains(sms.Sender, "+18005550199") {
			t.Fatalf("SMSReceived=%+v", sms)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for inbound SMS dispatch")
	}
}
