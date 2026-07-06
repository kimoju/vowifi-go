package voicehost

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	DefaultRTPDTMFPayloadType = 101
	DefaultRTPDTMFClockRate   = 8000
	DefaultRTPDTMFVolume      = 10
)

type RTPDTMFDirection string

const (
	RTPDTMFClientToIMS RTPDTMFDirection = "client_to_ims"
	RTPDTMFIMSToClient RTPDTMFDirection = "ims_to_client"
)

type RTPDTMFHandler func(RTPDTMFEvent)

type RTPDTMFPacket struct {
	PayloadType     uint8
	Marker          bool
	SequenceNumber  uint16
	Timestamp       uint32
	SSRC            uint32
	Signal          string
	End             bool
	Volume          uint8
	DurationSamples uint16
	ClockRate       int
}

type RTPDTMFEvent struct {
	Direction       RTPDTMFDirection
	PayloadType     uint8
	EventCode       uint8
	Signal          string
	End             bool
	Volume          uint8
	DurationSamples uint16
	DurationMS      int
	SequenceNumber  uint16
	Timestamp       uint32
	SSRC            uint32
	Marker          bool
	ClockRate       int
	Packet          []byte
}

type RTPDTMFSummary struct {
	Events    uint64
	EndEvents uint64
}

func BuildRTPDTMFPacket(in RTPDTMFPacket) ([]byte, error) {
	signal, err := NormalizeRTPDTMFSignal(in.Signal)
	if err != nil {
		return nil, err
	}
	eventCode, err := RTPDTMFEventCode(signal)
	if err != nil {
		return nil, err
	}
	payloadType := in.PayloadType
	if payloadType == 0 {
		payloadType = DefaultRTPDTMFPayloadType
	}
	if payloadType > 127 {
		return nil, fmt.Errorf("%w: RTP payload type %d exceeds 127", ErrInvalidDTMF, payloadType)
	}
	clockRate := in.ClockRate
	if clockRate <= 0 {
		clockRate = DefaultRTPDTMFClockRate
	}
	volume := in.Volume
	if volume == 0 {
		volume = DefaultRTPDTMFVolume
	}
	if volume > 63 {
		return nil, fmt.Errorf("%w: RTP DTMF volume %d exceeds 63", ErrInvalidDTMF, volume)
	}
	durationSamples := in.DurationSamples
	if durationSamples == 0 {
		durationSamples = uint16((DefaultDTMFDurationMS * clockRate) / 1000)
	}
	packet := make([]byte, 16)
	packet[0] = 0x80
	packet[1] = payloadType & 0x7f
	if in.Marker {
		packet[1] |= 0x80
	}
	binary.BigEndian.PutUint16(packet[2:4], in.SequenceNumber)
	binary.BigEndian.PutUint32(packet[4:8], in.Timestamp)
	binary.BigEndian.PutUint32(packet[8:12], in.SSRC)
	packet[12] = eventCode
	packet[13] = volume & 0x3f
	if in.End {
		packet[13] |= 0x80
	}
	binary.BigEndian.PutUint16(packet[14:16], durationSamples)
	return packet, nil
}

func InspectRTPDTMF(direction RTPDTMFDirection, packet []byte, payloadTypes map[uint8]int, handler RTPDTMFHandler) (RTPDTMFSummary, error) {
	var summary RTPDTMFSummary
	if len(payloadTypes) == 0 {
		return summary, nil
	}
	event, ok, err := ParseRTPDTMFEvent(direction, packet, payloadTypes)
	if err != nil || !ok {
		return summary, err
	}
	summary.Events = 1
	if event.End {
		summary.EndEvents = 1
	}
	emitRTPDTMF(handler, event)
	return summary, nil
}

func ParseRTPDTMFEvent(direction RTPDTMFDirection, packet []byte, payloadTypes map[uint8]int) (RTPDTMFEvent, bool, error) {
	header, payload, err := parseRTPPacket(packet)
	if err != nil {
		return RTPDTMFEvent{}, false, err
	}
	clockRate, ok := payloadTypes[header.PayloadType]
	if !ok {
		return RTPDTMFEvent{}, false, nil
	}
	if clockRate <= 0 {
		clockRate = DefaultRTPDTMFClockRate
	}
	if len(payload) < 4 {
		return RTPDTMFEvent{}, false, fmt.Errorf("%w: RTP DTMF payload too short", ErrInvalidDTMF)
	}
	signal := RTPDTMFSignalFromEventCode(payload[0])
	if signal == "" {
		return RTPDTMFEvent{}, false, fmt.Errorf("%w: unsupported RTP DTMF event %d", ErrInvalidDTMF, payload[0])
	}
	durationSamples := binary.BigEndian.Uint16(payload[2:4])
	durationMS := 0
	if clockRate > 0 {
		durationMS = int((uint32(durationSamples)*1000 + uint32(clockRate/2)) / uint32(clockRate))
	}
	return RTPDTMFEvent{
		Direction:       direction,
		PayloadType:     header.PayloadType,
		EventCode:       payload[0],
		Signal:          signal,
		End:             payload[1]&0x80 != 0,
		Volume:          payload[1] & 0x3f,
		DurationSamples: durationSamples,
		DurationMS:      durationMS,
		SequenceNumber:  header.SequenceNumber,
		Timestamp:       header.Timestamp,
		SSRC:            header.SSRC,
		Marker:          header.Marker,
		ClockRate:       clockRate,
		Packet:          append([]byte(nil), packet...),
	}, true, nil
}

func NormalizeRTPDTMFSignal(signal string) (string, error) {
	signal = strings.ToUpper(strings.TrimSpace(signal))
	if signal == "FLASH" {
		return signal, nil
	}
	return NormalizeDTMFSignal(signal)
}

func RTPDTMFEventCode(signal string) (uint8, error) {
	signal, err := NormalizeRTPDTMFSignal(signal)
	if err != nil {
		return 0, err
	}
	switch signal {
	case "*":
		return 10, nil
	case "#":
		return 11, nil
	case "A":
		return 12, nil
	case "B":
		return 13, nil
	case "C":
		return 14, nil
	case "D":
		return 15, nil
	case "FLASH":
		return 16, nil
	default:
		if len(signal) == 1 && signal[0] >= '0' && signal[0] <= '9' {
			return signal[0] - '0', nil
		}
	}
	return 0, fmt.Errorf("%w: unsupported RTP DTMF signal %q", ErrInvalidDTMF, signal)
}

func RTPDTMFSignalFromEventCode(code uint8) string {
	switch {
	case code <= 9:
		return string(rune('0' + code))
	case code == 10:
		return "*"
	case code == 11:
		return "#"
	case code == 12:
		return "A"
	case code == 13:
		return "B"
	case code == 14:
		return "C"
	case code == 15:
		return "D"
	case code == 16:
		return "FLASH"
	default:
		return ""
	}
}

type rtpPacketHeader struct {
	PayloadType    uint8
	Marker         bool
	SequenceNumber uint16
	Timestamp      uint32
	SSRC           uint32
}

func parseRTPPacket(packet []byte) (rtpPacketHeader, []byte, error) {
	if len(packet) < 12 {
		return rtpPacketHeader{}, nil, fmt.Errorf("%w: RTP packet too short", ErrInvalidDTMF)
	}
	if packet[0]>>6 != 2 {
		return rtpPacketHeader{}, nil, fmt.Errorf("%w: unsupported RTP version", ErrInvalidDTMF)
	}
	csrcCount := int(packet[0] & 0x0f)
	headerLen := 12 + csrcCount*4
	if len(packet) < headerLen {
		return rtpPacketHeader{}, nil, fmt.Errorf("%w: RTP CSRC list truncated", ErrInvalidDTMF)
	}
	if packet[0]&0x10 != 0 {
		if len(packet) < headerLen+4 {
			return rtpPacketHeader{}, nil, fmt.Errorf("%w: RTP extension header truncated", ErrInvalidDTMF)
		}
		extWords := int(binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4]))
		headerLen += 4 + extWords*4
		if len(packet) < headerLen {
			return rtpPacketHeader{}, nil, fmt.Errorf("%w: RTP extension payload truncated", ErrInvalidDTMF)
		}
	}
	end := len(packet)
	if packet[0]&0x20 != 0 {
		pad := int(packet[len(packet)-1])
		if pad == 0 || pad > end-headerLen {
			return rtpPacketHeader{}, nil, fmt.Errorf("%w: invalid RTP padding", ErrInvalidDTMF)
		}
		end -= pad
	}
	return rtpPacketHeader{
		PayloadType:    packet[1] & 0x7f,
		Marker:         packet[1]&0x80 != 0,
		SequenceNumber: binary.BigEndian.Uint16(packet[2:4]),
		Timestamp:      binary.BigEndian.Uint32(packet[4:8]),
		SSRC:           binary.BigEndian.Uint32(packet[8:12]),
	}, packet[headerLen:end], nil
}

func emitRTPDTMF(handler RTPDTMFHandler, event RTPDTMFEvent) {
	if handler == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	handler(event)
}

func rtpDTMFPayloadTypesFromSDP(info SDPInfo) map[uint8]int {
	out := cloneRTPDTMFPayloadTypes(info.TelephoneEventPayloads)
	if len(out) == 0 && sdpPayloadsContain(info.Payloads, DefaultRTPDTMFPayloadType) {
		out = map[uint8]int{DefaultRTPDTMFPayloadType: DefaultRTPDTMFClockRate}
	}
	for payload, clockRate := range out {
		if clockRate <= 0 {
			out[payload] = DefaultRTPDTMFClockRate
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneRTPDTMFPayloadTypes(in map[uint8]int) map[uint8]int {
	if len(in) == 0 {
		return nil
	}
	out := make(map[uint8]int, len(in))
	for payload, clockRate := range in {
		out[payload] = clockRate
	}
	return out
}
