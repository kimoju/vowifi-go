package voicehost

import (
	"errors"
	"strings"
	"testing"
)

func TestBuildAndParseDTMFRelayBody(t *testing.T) {
	body, err := BuildDTMFRelayBody("a", 120)
	if err != nil {
		t.Fatalf("BuildDTMFRelayBody() error = %v", err)
	}
	if string(body) != "Signal=A\r\nDuration=120\r\n" {
		t.Fatalf("body=%q", body)
	}
	signal, duration, err := ParseDTMFRelayBody(body)
	if err != nil {
		t.Fatalf("ParseDTMFRelayBody() error = %v", err)
	}
	if signal != "A" || duration != 120 {
		t.Fatalf("signal=%q duration=%d", signal, duration)
	}
}

func TestBuildDTMFRelayBodyDefaultsDuration(t *testing.T) {
	body, err := BuildDTMFRelayBody("#", 0)
	if err != nil {
		t.Fatalf("BuildDTMFRelayBody(default) error = %v", err)
	}
	if !strings.Contains(string(body), "Signal=#\r\n") || !strings.Contains(string(body), "Duration=160\r\n") {
		t.Fatalf("body=%q", body)
	}
}

func TestParseDTMFRelayBodyAcceptsLFAndWhitespace(t *testing.T) {
	signal, duration, err := ParseDTMFRelayBody([]byte(" Signal = * \n Duration = 90 \n"))
	if err != nil {
		t.Fatalf("ParseDTMFRelayBody() error = %v", err)
	}
	if signal != "*" || duration != 90 {
		t.Fatalf("signal=%q duration=%d", signal, duration)
	}
}

func TestDTMFRelayRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "missing signal", body: []byte("Duration=90\r\n")},
		{name: "multi signal", body: []byte("Signal=12\r\nDuration=90\r\n")},
		{name: "unsupported signal", body: []byte("Signal=X\r\nDuration=90\r\n")},
		{name: "missing duration", body: []byte("Signal=1\r\n")},
		{name: "bad duration", body: []byte("Signal=1\r\nDuration=bad\r\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := ParseDTMFRelayBody(tt.body); !errors.Is(err, ErrInvalidDTMF) {
				t.Fatalf("ParseDTMFRelayBody() err=%v, want ErrInvalidDTMF", err)
			}
		})
	}
	if _, err := BuildDTMFRelayBody("1", MaxDTMFDurationMS+1); !errors.Is(err, ErrInvalidDTMF) {
		t.Fatalf("BuildDTMFRelayBody(max) err=%v, want ErrInvalidDTMF", err)
	}
}

func TestBuildDialogDTMFInfoRequest(t *testing.T) {
	req, err := BuildDialogDTMFInfoRequest(DialogDTMFRequest{
		DeviceID:   " dev-1 ",
		CallID:     " call-1 ",
		Signal:     "5",
		DurationMS: 100,
		Headers:    map[string]string{"X-Test": "dtmf"},
	})
	if err != nil {
		t.Fatalf("BuildDialogDTMFInfoRequest() error = %v", err)
	}
	if req.DeviceID != "dev-1" || req.CallID != "call-1" || req.ContentType != DTMFRelayContentType || req.InfoPackage != DTMFInfoPackage {
		t.Fatalf("request=%+v", req)
	}
	if req.Headers["X-Test"] != "dtmf" || string(req.Body) != "Signal=5\r\nDuration=100\r\n" {
		t.Fatalf("headers/body=%+v/%q", req.Headers, req.Body)
	}
	req.Headers["X-Test"] = "changed"
	if req2, err := BuildDialogDTMFInfoRequest(DialogDTMFRequest{CallID: "call-1", Signal: "5", Headers: map[string]string{"X-Test": "dtmf"}}); err != nil || req2.Headers["X-Test"] != "dtmf" {
		t.Fatalf("headers were not cloned req=%+v err=%v", req2, err)
	}
}

func TestBuildAndParseRTPDTMFPacket(t *testing.T) {
	packet, err := BuildRTPDTMFPacket(RTPDTMFPacket{
		PayloadType:     110,
		Marker:          true,
		SequenceNumber:  77,
		Timestamp:       0x01020304,
		SSRC:            0x11223344,
		Signal:          "#",
		End:             true,
		Volume:          6,
		DurationSamples: 800,
		ClockRate:       16000,
	})
	if err != nil {
		t.Fatalf("BuildRTPDTMFPacket() error = %v", err)
	}
	event, ok, err := ParseRTPDTMFEvent(RTPDTMFClientToIMS, packet, map[uint8]int{110: 16000})
	if err != nil {
		t.Fatalf("ParseRTPDTMFEvent() error = %v", err)
	}
	if !ok {
		t.Fatalf("ParseRTPDTMFEvent() ok=false")
	}
	if event.Direction != RTPDTMFClientToIMS || event.PayloadType != 110 || event.EventCode != 11 || event.Signal != "#" || !event.End || !event.Marker {
		t.Fatalf("event=%+v", event)
	}
	if event.Volume != 6 || event.DurationSamples != 800 || event.DurationMS != 50 || event.SequenceNumber != 77 || event.Timestamp != 0x01020304 || event.SSRC != 0x11223344 {
		t.Fatalf("event timing/header=%+v", event)
	}
	if _, ok, err := ParseRTPDTMFEvent(RTPDTMFClientToIMS, packet, map[uint8]int{101: 8000}); err != nil || ok {
		t.Fatalf("ParseRTPDTMFEvent(non dtmf) ok=%v err=%v", ok, err)
	}
}

func TestRTPDTMFRejectsInvalidValues(t *testing.T) {
	if _, err := BuildRTPDTMFPacket(RTPDTMFPacket{PayloadType: 128, Signal: "1"}); !errors.Is(err, ErrInvalidDTMF) {
		t.Fatalf("BuildRTPDTMFPacket(payload) err=%v, want ErrInvalidDTMF", err)
	}
	if _, err := BuildRTPDTMFPacket(RTPDTMFPacket{Signal: "X"}); !errors.Is(err, ErrInvalidDTMF) {
		t.Fatalf("BuildRTPDTMFPacket(signal) err=%v, want ErrInvalidDTMF", err)
	}
	packet, err := BuildRTPDTMFPacket(RTPDTMFPacket{Signal: "1"})
	if err != nil {
		t.Fatalf("BuildRTPDTMFPacket() error = %v", err)
	}
	if _, _, err := ParseRTPDTMFEvent(RTPDTMFClientToIMS, packet[:15], map[uint8]int{DefaultRTPDTMFPayloadType: DefaultRTPDTMFClockRate}); !errors.Is(err, ErrInvalidDTMF) {
		t.Fatalf("ParseRTPDTMFEvent(short) err=%v, want ErrInvalidDTMF", err)
	}
	packet[12] = 99
	if _, _, err := ParseRTPDTMFEvent(RTPDTMFClientToIMS, packet, map[uint8]int{DefaultRTPDTMFPayloadType: DefaultRTPDTMFClockRate}); !errors.Is(err, ErrInvalidDTMF) {
		t.Fatalf("ParseRTPDTMFEvent(code) err=%v, want ErrInvalidDTMF", err)
	}
}
