package voicehost

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

var ErrRTPStreamStats = errors.New("invalid rtp stream stats")

// RTPStreamStats is a reception snapshot for one RTP SSRC.
type RTPStreamStats struct {
	SSRC               uint32
	Packets            uint64
	DuplicatePackets   uint64
	OutOfOrderPackets  uint64
	ExpectedPackets    uint64
	LostPackets        uint64
	FractionLost       uint8
	LastSequenceNumber uint32
	Jitter             uint32
	LastSenderReport   uint32
	Delay              uint32
}

// RTPStreamStatsTracker keeps RTP reception statistics split by SSRC.
type RTPStreamStatsTracker struct {
	streams       map[uint32]*rtpStreamStatsState
	senderReports map[uint32]rtpStreamSenderReportState
}

// NewRTPStreamStatsTracker returns an empty tracker. The zero value is also usable.
func NewRTPStreamStatsTracker() *RTPStreamStatsTracker {
	return &RTPStreamStatsTracker{}
}

// ObserveRTPPacket parses one RTP packet and updates the matching SSRC stream.
func (t *RTPStreamStatsTracker) ObserveRTPPacket(packet []byte, arrival time.Time, clockRate int) (RTPStreamStats, error) {
	if clockRate <= 0 {
		return RTPStreamStats{}, fmt.Errorf("%w: clock rate must be positive", ErrRTPStreamStats)
	}
	header, _, err := parseRTPPacket(packet)
	if err != nil {
		return RTPStreamStats{}, err
	}
	if t.streams == nil {
		t.streams = make(map[uint32]*rtpStreamStatsState)
	}
	state := t.streams[header.SSRC]
	if state == nil {
		state = newRTPStreamStatsState(header, arrival)
		if senderReport, ok := t.senderReports[header.SSRC]; ok {
			state.senderReport = senderReport
		}
		t.streams[header.SSRC] = state
		return state.snapshotAt(arrival), nil
	}
	state.observe(header, arrival, clockRate)
	return state.snapshotAt(arrival), nil
}

// ObserveRTCPSenderReport records the newest SR timing for an RTP source so
// future RTCP reception reports can include LSR/DLSR timing fields.
func (t *RTPStreamStatsTracker) ObserveRTCPSenderReport(ssrc uint32, ntpTime uint64, arrival time.Time) (RTPStreamStats, bool) {
	if ntpTime == 0 {
		return RTPStreamStats{}, false
	}
	if arrival.IsZero() {
		arrival = time.Now()
	}
	report := rtpStreamSenderReportState{
		lastSenderReport: rtcpLastSenderReport(ntpTime),
		arrival:          arrival,
	}
	if t.senderReports == nil {
		t.senderReports = make(map[uint32]rtpStreamSenderReportState)
	}
	t.senderReports[ssrc] = report
	state := t.streams[ssrc]
	if state == nil {
		return RTPStreamStats{}, false
	}
	state.senderReport = report
	return state.snapshotAt(arrival), true
}

// Stats returns deterministic snapshots ordered by SSRC.
func (t *RTPStreamStatsTracker) Stats() []RTPStreamStats {
	return t.StatsAt(time.Now())
}

// StatsAt returns deterministic snapshots ordered by SSRC with DLSR measured
// against now for streams that have observed an RTCP sender report.
func (t *RTPStreamStatsTracker) StatsAt(now time.Time) []RTPStreamStats {
	if t == nil || len(t.streams) == 0 {
		return nil
	}
	out := make([]RTPStreamStats, 0, len(t.streams))
	for _, state := range t.streams {
		out = append(out, state.snapshotAt(now))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SSRC < out[j].SSRC
	})
	return out
}

// StatsForSSRC returns a snapshot for one SSRC when the tracker has observed it.
func (t *RTPStreamStatsTracker) StatsForSSRC(ssrc uint32) (RTPStreamStats, bool) {
	return t.StatsForSSRCAt(ssrc, time.Now())
}

// StatsForSSRCAt returns a snapshot for one SSRC with DLSR measured against now.
func (t *RTPStreamStatsTracker) StatsForSSRCAt(ssrc uint32, now time.Time) (RTPStreamStats, bool) {
	if t == nil {
		return RTPStreamStats{}, false
	}
	state := t.streams[ssrc]
	if state == nil {
		return RTPStreamStats{}, false
	}
	return state.snapshotAt(now), true
}

type rtpStreamStatsState struct {
	stats         RTPStreamStats
	baseSeq       uint32
	maxSeq        uint32
	seenSequences map[uint32]struct{}
	baseArrival   time.Time
	baseTimestamp uint32
	lastTransit   int64
	jitter        float64
	senderReport  rtpStreamSenderReportState
}

type rtpStreamSenderReportState struct {
	lastSenderReport uint32
	arrival          time.Time
}

func newRTPStreamStatsState(header rtpPacketHeader, arrival time.Time) *rtpStreamStatsState {
	seq := uint32(header.SequenceNumber)
	state := &rtpStreamStatsState{
		stats: RTPStreamStats{
			SSRC:               header.SSRC,
			Packets:            1,
			ExpectedPackets:    1,
			LastSequenceNumber: seq,
		},
		baseSeq:       seq,
		maxSeq:        seq,
		seenSequences: map[uint32]struct{}{seq: {}},
		baseArrival:   arrival,
		baseTimestamp: header.Timestamp,
	}
	return state
}

func (s *rtpStreamStatsState) observe(header rtpPacketHeader, arrival time.Time, clockRate int) {
	seq := extendRTPSequence(s.maxSeq, header.SequenceNumber)
	if _, ok := s.seenSequences[seq]; ok {
		s.stats.DuplicatePackets++
		return
	}
	s.seenSequences[seq] = struct{}{}
	s.stats.Packets++

	if seq > s.maxSeq {
		s.maxSeq = seq
		s.updateJitter(header, arrival, clockRate)
	} else {
		s.stats.OutOfOrderPackets++
	}
	s.recalculateLoss()
}

func (s *rtpStreamStatsState) updateJitter(header rtpPacketHeader, arrival time.Time, clockRate int) {
	arrivalOffset := rtpDurationUnits(arrival.Sub(s.baseArrival), clockRate)
	timestampOffset := int64(int32(header.Timestamp - s.baseTimestamp))
	transit := arrivalOffset - timestampOffset
	delta := transit - s.lastTransit
	if delta < 0 {
		delta = -delta
	}
	// RFC3550 estimates interarrival jitter as J = J + (|D| - J) / 16.
	s.jitter += (float64(delta) - s.jitter) / 16
	s.lastTransit = transit
	s.stats.Jitter = uint32(s.jitter)
}

func (s *rtpStreamStatsState) recalculateLoss() {
	expected := uint64(s.maxSeq-s.baseSeq) + 1
	s.stats.ExpectedPackets = expected
	if expected > s.stats.Packets {
		s.stats.LostPackets = expected - s.stats.Packets
	} else {
		s.stats.LostPackets = 0
	}
	if expected == 0 || s.stats.LostPackets == 0 {
		s.stats.FractionLost = 0
		return
	}
	fraction := s.stats.LostPackets * 256 / expected
	if fraction > 255 {
		fraction = 255
	}
	s.stats.FractionLost = uint8(fraction)
}

func (s *rtpStreamStatsState) snapshotAt(now time.Time) RTPStreamStats {
	stats := s.stats
	stats.LastSequenceNumber = s.maxSeq
	stats.LastSenderReport = s.senderReport.lastSenderReport
	if !now.IsZero() && !s.senderReport.arrival.IsZero() {
		stats.Delay = rtcpCompactDelay(now.Sub(s.senderReport.arrival))
	} else {
		stats.Delay = 0
	}
	return stats
}

func extendRTPSequence(maxSeq uint32, seq uint16) uint32 {
	cycles := maxSeq & 0xffff0000
	maxLow := uint16(maxSeq)
	switch {
	case seq < maxLow && maxLow-seq > 0x8000:
		cycles += 1 << 16
	case seq > maxLow && seq-maxLow > 0x8000 && cycles >= 1<<16:
		cycles -= 1 << 16
	}
	return cycles | uint32(seq)
}

func rtpDurationUnits(d time.Duration, clockRate int) int64 {
	sign := int64(1)
	if d < 0 {
		sign = -1
		d = -d
	}
	seconds := d / time.Second
	remainder := d % time.Second
	units := int64(seconds)*int64(clockRate) + int64(remainder)*int64(clockRate)/int64(time.Second)
	return sign * units
}
