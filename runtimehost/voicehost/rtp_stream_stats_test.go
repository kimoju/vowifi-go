package voicehost

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/pion/rtcp"
)

func TestRTPStreamStatsSequentialPackets(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	ssrc := uint32(0x11223344)
	for i := 0; i < 3; i++ {
		packet := buildRTPStatsPacket(ssrc, uint16(10+i), uint32(1000+i*160))
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(time.Duration(i)*20*time.Millisecond), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", i, err)
		}
	}

	stats, ok := tracker.StatsForSSRC(ssrc)
	if !ok {
		t.Fatalf("StatsForSSRC() ok=false")
	}
	if stats.Packets != 3 || stats.ExpectedPackets != 3 || stats.LostPackets != 0 || stats.FractionLost != 0 {
		t.Fatalf("stats packet/loss=%+v", stats)
	}
	if stats.LastSequenceNumber != 12 || stats.Jitter != 0 {
		t.Fatalf("stats sequence/jitter=%+v", stats)
	}
}

func TestRTPStreamStatsEstimatesLoss(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	ssrc := uint32(0x22334455)
	inputs := []struct {
		sequence  uint16
		timestamp uint32
		arrival   time.Duration
	}{
		{sequence: 10, timestamp: 1000},
		{sequence: 12, timestamp: 1320, arrival: 40 * time.Millisecond},
	}
	for _, input := range inputs {
		packet := buildRTPStatsPacket(ssrc, input.sequence, input.timestamp)
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(input.arrival), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", input.sequence, err)
		}
	}

	stats, ok := tracker.StatsForSSRC(ssrc)
	if !ok {
		t.Fatalf("StatsForSSRC() ok=false")
	}
	if stats.Packets != 2 || stats.ExpectedPackets != 3 || stats.LostPackets != 1 || stats.FractionLost != 85 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestRTPStreamStatsOutOfOrderAndDuplicate(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	ssrc := uint32(0x33445566)
	packets := []struct {
		sequence  uint16
		timestamp uint32
		arrival   time.Duration
	}{
		{sequence: 10, timestamp: 1000},
		{sequence: 12, timestamp: 1320, arrival: 40 * time.Millisecond},
		{sequence: 12, timestamp: 1320, arrival: 45 * time.Millisecond},
		{sequence: 11, timestamp: 1160, arrival: 50 * time.Millisecond},
	}
	for _, packet := range packets {
		raw := buildRTPStatsPacket(ssrc, packet.sequence, packet.timestamp)
		if _, err := tracker.ObserveRTPPacket(raw, base.Add(packet.arrival), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", packet.sequence, err)
		}
	}

	stats, ok := tracker.StatsForSSRC(ssrc)
	if !ok {
		t.Fatalf("StatsForSSRC() ok=false")
	}
	if stats.Packets != 3 || stats.ExpectedPackets != 3 || stats.LostPackets != 0 || stats.LastSequenceNumber != 12 {
		t.Fatalf("stats=%+v", stats)
	}
	if stats.DuplicatePackets != 1 || stats.OutOfOrderPackets != 1 {
		t.Fatalf("duplicate/out-of-order stats=%+v", stats)
	}
}

func TestRTPStreamStatsTracksMultipleSSRCs(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	firstSSRC := uint32(0x33445566)
	secondSSRC := uint32(0x33445567)
	inputs := []struct {
		ssrc      uint32
		sequence  uint16
		timestamp uint32
	}{
		{ssrc: secondSSRC, sequence: 44, timestamp: 2000},
		{ssrc: firstSSRC, sequence: 7, timestamp: 1000},
		{ssrc: secondSSRC, sequence: 45, timestamp: 2160},
	}
	for i, input := range inputs {
		packet := buildRTPStatsPacket(input.ssrc, input.sequence, input.timestamp)
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(time.Duration(i)*20*time.Millisecond), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", i, err)
		}
	}

	stats := tracker.Stats()
	if len(stats) != 2 {
		t.Fatalf("stats=%+v", stats)
	}
	if stats[0].SSRC != firstSSRC || stats[0].Packets != 1 || stats[0].LastSequenceNumber != 7 {
		t.Fatalf("first stats=%+v", stats[0])
	}
	if stats[1].SSRC != secondSSRC || stats[1].Packets != 2 || stats[1].LastSequenceNumber != 45 {
		t.Fatalf("second stats=%+v", stats[1])
	}
}

func TestRTPStreamStatsSequenceRollover(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	ssrc := uint32(0x44556677)
	sequences := []uint16{0xfffe, 0xffff, 0x0000, 0x0001}
	for i, sequence := range sequences {
		packet := buildRTPStatsPacket(ssrc, sequence, uint32(1000+i*160))
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(time.Duration(i)*20*time.Millisecond), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", sequence, err)
		}
	}

	stats, ok := tracker.StatsForSSRC(ssrc)
	if !ok {
		t.Fatalf("StatsForSSRC() ok=false")
	}
	if stats.Packets != 4 || stats.ExpectedPackets != 4 || stats.LostPackets != 0 {
		t.Fatalf("stats=%+v", stats)
	}
	if stats.LastSequenceNumber != 0x00010001 {
		t.Fatalf("LastSequenceNumber=%d, want %d", stats.LastSequenceNumber, uint32(0x00010001))
	}
}

func TestBuildReceiverReport(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	mediaSSRC := uint32(0x55667788)
	inputs := []struct {
		sequence  uint16
		timestamp uint32
		arrival   time.Duration
	}{
		{sequence: 10, timestamp: 1000},
		{sequence: 12, timestamp: 1320, arrival: 45 * time.Millisecond},
	}
	for _, input := range inputs {
		packet := buildRTPStatsPacket(mediaSSRC, input.sequence, input.timestamp)
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(input.arrival), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", input.sequence, err)
		}
	}

	report := BuildReceiverReport(0x01020304, tracker.Stats())
	if report.SSRC != 0x01020304 || len(report.Reports) != 1 {
		t.Fatalf("report=%+v", report)
	}
	block := report.Reports[0]
	if block.SSRC != mediaSSRC || block.TotalLost != 1 || block.FractionLost != 85 || block.LastSequenceNumber != 12 {
		t.Fatalf("report block=%+v", block)
	}
	if block.Jitter != 2 {
		t.Fatalf("Jitter=%d, want 2", block.Jitter)
	}
	raw, err := report.Marshal()
	if err != nil {
		t.Fatalf("ReceiverReport.Marshal() error = %v", err)
	}
	packets, err := rtcp.Unmarshal(raw)
	if err != nil {
		t.Fatalf("rtcp.Unmarshal() error = %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("packets=%d, want 1", len(packets))
	}
}

func TestBuildSenderReportAndSourceDescription(t *testing.T) {
	var tracker RTPStreamStatsTracker
	base := time.Unix(0, 0)
	mediaSSRC := uint32(0x66778899)
	for _, input := range []struct {
		sequence  uint16
		timestamp uint32
		arrival   time.Duration
	}{
		{sequence: 20, timestamp: 2000},
		{sequence: 22, timestamp: 2320, arrival: 45 * time.Millisecond},
	} {
		packet := buildRTPStatsPacket(mediaSSRC, input.sequence, input.timestamp)
		if _, err := tracker.ObserveRTPPacket(packet, base.Add(input.arrival), 8000); err != nil {
			t.Fatalf("ObserveRTPPacket(%d) error = %v", input.sequence, err)
		}
	}

	wallClock := time.Unix(1, int64(250*time.Millisecond))
	report := BuildSenderReport(RTCPSenderReportConfig{
		SSRC:           0x01020304,
		WallClock:      wallClock,
		RTPTime:        0x10203040,
		PacketCount:    17,
		OctetCount:     3200,
		ReceptionStats: tracker.Stats(),
	})
	wantNTP := uint64(ntpEpochOffsetSeconds+1)<<32 | uint64(1<<30)
	if report.SSRC != 0x01020304 || report.NTPTime != wantNTP || report.RTPTime != 0x10203040 ||
		report.PacketCount != 17 || report.OctetCount != 3200 || len(report.Reports) != 1 {
		t.Fatalf("sender report=%+v", report)
	}
	if block := report.Reports[0]; block.SSRC != mediaSSRC || block.TotalLost != 1 || block.FractionLost != 85 || block.LastSequenceNumber != 22 {
		t.Fatalf("sender report block=%+v", block)
	}

	sdes := BuildSourceDescription(RTCPSourceDescriptionConfig{
		SSRC:  0x01020304,
		CNAME: "session-01020304",
		Name:  "ims-audio",
		Tool:  "vowifi-go",
	})
	raw, err := rtcp.Marshal([]rtcp.Packet{report, sdes})
	if err != nil {
		t.Fatalf("rtcp.Marshal() error = %v", err)
	}
	packets, err := rtcp.Unmarshal(raw)
	if err != nil {
		t.Fatalf("rtcp.Unmarshal() error = %v", err)
	}
	if len(packets) != 2 {
		t.Fatalf("packets=%d, want 2", len(packets))
	}
	gotSR, ok := packets[0].(*rtcp.SenderReport)
	if !ok || gotSR.SSRC != 0x01020304 || len(gotSR.Reports) != 1 {
		t.Fatalf("sender report packet=%+v ok=%v", packets[0], ok)
	}
	gotSDES, ok := packets[1].(*rtcp.SourceDescription)
	if !ok || len(gotSDES.Chunks) != 1 || gotSDES.Chunks[0].Source != 0x01020304 || len(gotSDES.Chunks[0].Items) != 3 {
		t.Fatalf("source description packet=%+v ok=%v", packets[1], ok)
	}
	if gotSDES.Chunks[0].Items[0].Type != rtcp.SDESCNAME || gotSDES.Chunks[0].Items[0].Text != "session-01020304" {
		t.Fatalf("source description CNAME=%+v", gotSDES.Chunks[0].Items[0])
	}
}

func buildRTPStatsPacket(ssrc uint32, sequence uint16, timestamp uint32) []byte {
	packet := make([]byte, 13)
	packet[0] = 0x80
	packet[1] = 0x00
	binary.BigEndian.PutUint16(packet[2:4], sequence)
	binary.BigEndian.PutUint32(packet[4:8], timestamp)
	binary.BigEndian.PutUint32(packet[8:12], ssrc)
	packet[12] = 0xff
	return packet
}
