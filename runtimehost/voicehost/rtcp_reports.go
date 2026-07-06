package voicehost

import "github.com/pion/rtcp"

const maxRTCPReceiverReportBlocks = 31
const maxRTCPPositiveLostPackets = 0x7fffff

// BuildReceiverReport converts RTP reception snapshots into an RTCP RR packet.
// A ReceiverReport can carry at most 31 report blocks, so extra streams are ignored.
func BuildReceiverReport(senderSSRC uint32, stats []RTPStreamStats) *rtcp.ReceiverReport {
	reports := make([]rtcp.ReceptionReport, 0, min(len(stats), maxRTCPReceiverReportBlocks))
	for _, stream := range stats {
		if len(reports) == maxRTCPReceiverReportBlocks {
			break
		}
		reports = append(reports, rtcp.ReceptionReport{
			SSRC:               stream.SSRC,
			FractionLost:       stream.FractionLost,
			TotalLost:          rtcpReportLostPackets(stream.LostPackets),
			LastSequenceNumber: stream.LastSequenceNumber,
			Jitter:             stream.Jitter,
		})
	}
	return &rtcp.ReceiverReport{
		SSRC:    senderSSRC,
		Reports: reports,
	}
}

func rtcpReportLostPackets(lost uint64) uint32 {
	if lost > maxRTCPPositiveLostPackets {
		return maxRTCPPositiveLostPackets
	}
	return uint32(lost)
}
