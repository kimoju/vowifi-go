package voicehost

import (
	"testing"

	"github.com/pion/rtcp"
)

func TestInspectRTCPFeedbackReportsReceptionBlocks(t *testing.T) {
	raw, err := rtcp.Marshal([]rtcp.Packet{
		&rtcp.ReceiverReport{
			SSRC: 0x11111111,
			Reports: []rtcp.ReceptionReport{{
				SSRC:               0x22222222,
				FractionLost:       32,
				TotalLost:          7,
				LastSequenceNumber: 0x00010010,
				Jitter:             41,
				LastSenderReport:   0x12345678,
				Delay:              0x00001000,
			}},
		},
		&rtcp.SenderReport{
			SSRC: 0x33333333,
			Reports: []rtcp.ReceptionReport{{
				SSRC:               0x44444444,
				FractionLost:       8,
				TotalLost:          2,
				LastSequenceNumber: 0x00020020,
				Jitter:             11,
			}},
		},
	})
	if err != nil {
		t.Fatalf("rtcp.Marshal() error = %v", err)
	}

	var events []RTCPFeedbackEvent
	summary, err := InspectRTCPFeedback(RTCPFeedbackIMSToClient, raw, func(event RTCPFeedbackEvent) {
		events = append(events, event)
	})
	if err != nil {
		t.Fatalf("InspectRTCPFeedback() error = %v", err)
	}
	if summary.Packets != 2 || summary.ReceiverReports != 1 || summary.SenderReports != 1 {
		t.Fatalf("summary=%+v", summary)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d, want 2", len(events))
	}

	rr := events[0]
	if rr.Direction != RTCPFeedbackIMSToClient || rr.Kind != RTCPFeedbackReceiverReport || rr.SSRC != 0x11111111 || rr.ReportCount != 1 {
		t.Fatalf("receiver report event=%+v", rr)
	}
	if len(rr.Reports) != 1 {
		t.Fatalf("receiver report blocks=%+v", rr.Reports)
	}
	if got := rr.Reports[0]; got.SSRC != 0x22222222 || got.FractionLost != 32 || got.TotalLost != 7 ||
		got.LastSequenceNumber != 0x00010010 || got.Jitter != 41 || got.LastSenderReport != 0x12345678 || got.Delay != 0x00001000 {
		t.Fatalf("receiver report block=%+v", got)
	}

	sr := events[1]
	if sr.Kind != RTCPFeedbackSenderReport || sr.SSRC != 0x33333333 || sr.ReportCount != 1 {
		t.Fatalf("sender report event=%+v", sr)
	}
	if len(sr.Reports) != 1 {
		t.Fatalf("sender report blocks=%+v", sr.Reports)
	}
	if got := sr.Reports[0]; got.SSRC != 0x44444444 || got.FractionLost != 8 || got.TotalLost != 2 ||
		got.LastSequenceNumber != 0x00020020 || got.Jitter != 11 {
		t.Fatalf("sender report block=%+v", got)
	}
}
