package voicehost

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/pion/rtcp"
)

func TestRTPRelaySessionForwardsBidirectionalPackets(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientRTCPPeer := listenTestUDP(t)
	defer clientRTCPPeer.Close()
	imsPeer := listenTestUDP(t)
	defer imsPeer.Close()
	imsRTCPPeer := listenTestUDP(t)
	defer imsRTCPPeer.Close()

	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	clientRTCPAddr := clientRTCPPeer.LocalAddr().(*net.UDPAddr)
	imsAddr := imsPeer.LocalAddr().(*net.UDPAddr)
	imsRTCPAddr := imsRTCPPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "127.0.0.1",
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, RTCPPort: clientRTCPAddr.Port})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: imsAddr.Port, RTCPPort: imsRTCPAddr.Port}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}

	clientEndpoint := udpAddrFromSDP(t, relay.ClientEndpoint())
	clientRTCPEndpoint := udpRTCPAddrFromSDP(t, relay.ClientEndpoint())
	imsEndpoint := udpAddrFromSDP(t, relay.IMSEndpoint())
	imsRTCPEndpoint := udpRTCPAddrFromSDP(t, relay.IMSEndpoint())

	if _, err := clientPeer.WriteToUDP([]byte{0x11, 0x22, 0x33}, clientEndpoint); err != nil {
		t.Fatalf("client WriteToUDP() error = %v", err)
	}
	got, from := readTestUDP(t, imsPeer)
	if string(got) != string([]byte{0x11, 0x22, 0x33}) {
		t.Fatalf("IMS got=%x", got)
	}
	if from.Port != imsEndpoint.Port {
		t.Fatalf("IMS packet source port=%d, want relay IMS port %d", from.Port, imsEndpoint.Port)
	}

	if _, err := imsPeer.WriteToUDP([]byte{0x44, 0x55}, imsEndpoint); err != nil {
		t.Fatalf("ims WriteToUDP() error = %v", err)
	}
	got, from = readTestUDP(t, clientPeer)
	if string(got) != string([]byte{0x44, 0x55}) {
		t.Fatalf("client got=%x", got)
	}
	if from.Port != clientEndpoint.Port {
		t.Fatalf("client packet source port=%d, want relay client port %d", from.Port, clientEndpoint.Port)
	}

	if _, err := clientRTCPPeer.WriteToUDP([]byte{0x81, 0xc9}, clientRTCPEndpoint); err != nil {
		t.Fatalf("client RTCP WriteToUDP() error = %v", err)
	}
	got, from = readTestUDP(t, imsRTCPPeer)
	if string(got) != string([]byte{0x81, 0xc9}) {
		t.Fatalf("IMS RTCP got=%x", got)
	}
	if from.Port != imsRTCPEndpoint.Port {
		t.Fatalf("IMS RTCP packet source port=%d, want relay IMS RTCP port %d", from.Port, imsRTCPEndpoint.Port)
	}

	if _, err := imsRTCPPeer.WriteToUDP([]byte{0x82, 0xca, 0x00}, imsRTCPEndpoint); err != nil {
		t.Fatalf("IMS RTCP WriteToUDP() error = %v", err)
	}
	got, from = readTestUDP(t, clientRTCPPeer)
	if string(got) != string([]byte{0x82, 0xca, 0x00}) {
		t.Fatalf("client RTCP got=%x", got)
	}
	if from.Port != clientRTCPEndpoint.Port {
		t.Fatalf("client RTCP packet source port=%d, want relay client RTCP port %d", from.Port, clientRTCPEndpoint.Port)
	}

	stats := relay.Stats()
	if stats.ClientToIMSRTPPackets != 1 || stats.IMSToClientRTPPackets != 1 || stats.ClientToIMSRTCPPackets != 1 || stats.IMSToClientRTCPPackets != 1 {
		t.Fatalf("stats packets=%+v", stats)
	}
	if stats.ClientToIMSRTPBytes != 3 || stats.IMSToClientRTPBytes != 2 || stats.ClientToIMSRTCPBytes != 2 || stats.IMSToClientRTCPBytes != 3 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestRTPRelaySessionAppliesSDPMediaDirection(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientRTCPPeer := listenTestUDP(t)
	defer clientRTCPPeer.Close()
	imsPeer := listenTestUDP(t)
	defer imsPeer.Close()
	imsRTCPPeer := listenTestUDP(t)
	defer imsRTCPPeer.Close()

	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	clientRTCPAddr := clientRTCPPeer.LocalAddr().(*net.UDPAddr)
	imsAddr := imsPeer.LocalAddr().(*net.UDPAddr)
	imsRTCPAddr := imsRTCPPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "127.0.0.1",
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, RTCPPort: clientRTCPAddr.Port, Direction: "sendrecv"})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: imsAddr.Port, RTCPPort: imsRTCPAddr.Port, Direction: "sendrecv"}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}
	clientEndpoint := udpAddrFromSDP(t, relay.ClientEndpoint())
	imsEndpoint := udpAddrFromSDP(t, relay.IMSEndpoint())

	if _, err := clientPeer.WriteToUDP([]byte{0x10}, clientEndpoint); err != nil {
		t.Fatalf("client initial WriteToUDP() error = %v", err)
	}
	if got, _ := readTestUDP(t, imsPeer); !bytes.Equal(got, []byte{0x10}) {
		t.Fatalf("IMS initial got=%x", got)
	}

	if err := relay.SetClientRemote(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, RTCPPort: clientRTCPAddr.Port, Direction: "recvonly"}); err != nil {
		t.Fatalf("SetClientRemote(recvonly) error = %v", err)
	}
	if _, err := clientPeer.WriteToUDP([]byte{0x11}, clientEndpoint); err != nil {
		t.Fatalf("client recvonly WriteToUDP() error = %v", err)
	}
	expectNoTestUDP(t, imsPeer)

	if _, err := imsPeer.WriteToUDP([]byte{0x22}, imsEndpoint); err != nil {
		t.Fatalf("ims WriteToUDP() error = %v", err)
	}
	if got, _ := readTestUDP(t, clientPeer); !bytes.Equal(got, []byte{0x22}) {
		t.Fatalf("client recvonly got=%x", got)
	}

	if err := relay.SetIMSRemote(SDPInfo{ConnectionIP: "0.0.0.0", MediaPort: imsAddr.Port}); err != nil {
		t.Fatalf("SetIMSRemote(0.0.0.0) error = %v", err)
	}
	if _, err := clientPeer.WriteToUDP([]byte{0x12}, clientEndpoint); err != nil {
		t.Fatalf("client zero-target WriteToUDP() error = %v", err)
	}
	expectNoTestUDP(t, imsPeer)
	if err := relay.SetIMSRemote(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: 0, Direction: "inactive"}); err != nil {
		t.Fatalf("SetIMSRemote(port 0) error = %v", err)
	}
	if _, err := clientPeer.WriteToUDP([]byte{0x13}, clientEndpoint); err != nil {
		t.Fatalf("client disabled-port WriteToUDP() error = %v", err)
	}
	expectNoTestUDP(t, imsPeer)

	stats := waitRelayStats(t, relay, func(stats RTPRelayStats) bool {
		return stats.ClientToIMSRTPPackets == 1 && stats.ClientToIMSRTPDrops >= 1 && stats.IMSToClientRTPPackets == 1
	})
	if stats.ClientToIMSRTPPackets != 1 || stats.ClientToIMSRTPDrops < 1 || stats.IMSToClientRTPPackets != 1 {
		t.Fatalf("direction stats=%+v", stats)
	}
}

func TestRTPRelaySessionRewritesSDP(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "198.51.100.10",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "203.0.113.10",
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, RTCPPort: clientAddr.Port + 1, Payloads: []int{0, 101}, Direction: "sendrecv"})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()

	offer, err := ParseSDP(relay.IMSOfferSDP(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, Payloads: []int{0, 101}}))
	if err != nil {
		t.Fatalf("ParseSDP(offer) error = %v", err)
	}
	if offer.ConnectionIP != "203.0.113.10" || offer.MediaPort != relay.IMSEndpoint().MediaPort || offer.RTCPPort != relay.IMSEndpoint().RTCPPort {
		t.Fatalf("offer=%+v relayIMS=%+v", offer, relay.IMSEndpoint())
	}
	answer, err := ParseSDP(relay.ClientAnswerSDP(SDPInfo{ConnectionIP: "192.0.2.20", MediaPort: 49170, RTCPPort: 49171, Payloads: []int{0}}))
	if err != nil {
		t.Fatalf("ParseSDP(answer) error = %v", err)
	}
	if answer.ConnectionIP != "198.51.100.10" || answer.MediaPort != relay.ClientEndpoint().MediaPort || answer.RTCPPort != relay.ClientEndpoint().RTCPPort {
		t.Fatalf("answer=%+v relayClient=%+v", answer, relay.ClientEndpoint())
	}
}

func TestRTPRelaySessionAppliesSRTPTransforms(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientRTCPPeer := listenTestUDP(t)
	defer clientRTCPPeer.Close()
	imsPeer := listenTestUDP(t)
	defer imsPeer.Close()
	imsRTCPPeer := listenTestUDP(t)
	defer imsRTCPPeer.Close()
	media, err := NewSRTPMediaSession(testSRTPMediaConfig())
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	clientRTCPAddr := clientRTCPPeer.LocalAddr().(*net.UDPAddr)
	imsAddr := imsPeer.LocalAddr().(*net.UDPAddr)
	imsRTCPAddr := imsRTCPPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "127.0.0.1",
		Transforms:        media.RelayTransforms(),
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, RTCPPort: clientRTCPAddr.Port})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: imsAddr.Port, RTCPPort: imsRTCPAddr.Port}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}
	clientEndpoint := udpAddrFromSDP(t, relay.ClientEndpoint())
	imsEndpoint := udpAddrFromSDP(t, relay.IMSEndpoint())

	clientPlain := testRTPPacket(31, 0x11111111, []byte{0x01, 0x02, 0x03})
	clientProtected, err := media.ProtectClientRTP(clientPlain)
	if err != nil {
		t.Fatalf("ProtectClientRTP() error = %v", err)
	}
	if _, err := clientPeer.WriteToUDP(clientProtected, clientEndpoint); err != nil {
		t.Fatalf("client WriteToUDP() error = %v", err)
	}
	got, _ := readTestUDP(t, imsPeer)
	if bytes.Equal(got, clientPlain) || bytes.Equal(got, clientProtected) {
		t.Fatalf("IMS got untransformed packet=%x", got)
	}
	gotPlain, err := media.UnprotectIMSRTP(got)
	if err != nil {
		t.Fatalf("UnprotectIMSRTP() error = %v", err)
	}
	if !bytes.Equal(gotPlain, clientPlain) {
		t.Fatalf("IMS plain=%x, want %x", gotPlain, clientPlain)
	}

	imsPlain := testRTPPacket(32, 0x22222222, []byte{0x04, 0x05})
	imsProtected, err := media.ProtectIMSRTP(imsPlain)
	if err != nil {
		t.Fatalf("ProtectIMSRTP() error = %v", err)
	}
	if _, err := imsPeer.WriteToUDP(imsProtected, imsEndpoint); err != nil {
		t.Fatalf("ims WriteToUDP() error = %v", err)
	}
	got, _ = readTestUDP(t, clientPeer)
	if bytes.Equal(got, imsPlain) || bytes.Equal(got, imsProtected) {
		t.Fatalf("client got untransformed packet=%x", got)
	}
	gotPlain, err = media.UnprotectClientRTP(got)
	if err != nil {
		t.Fatalf("UnprotectClientRTP() error = %v", err)
	}
	if !bytes.Equal(gotPlain, imsPlain) {
		t.Fatalf("client plain=%x, want %x", gotPlain, imsPlain)
	}
	stats := waitRelayStats(t, relay, func(stats RTPRelayStats) bool {
		return stats.ClientToIMSRTPPackets == 1 && stats.IMSToClientRTPPackets == 1
	})
	if stats.ClientToIMSRTPDrops != 0 || stats.IMSToClientRTPDrops != 0 || stats.ClientToIMSRTPPackets != 1 || stats.IMSToClientRTPPackets != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestRTPRelaySessionTracksSRTPPlaintextStreams(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientRTCPPeer := listenTestUDP(t)
	defer clientRTCPPeer.Close()
	imsPeer := listenTestUDP(t)
	defer imsPeer.Close()
	imsRTCPPeer := listenTestUDP(t)
	defer imsRTCPPeer.Close()
	media, err := NewSRTPMediaSession(testSRTPMediaConfig())
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	clientRTCPAddr := clientRTCPPeer.LocalAddr().(*net.UDPAddr)
	imsAddr := imsPeer.LocalAddr().(*net.UDPAddr)
	imsRTCPAddr := imsRTCPPeer.LocalAddr().(*net.UDPAddr)
	var relay *RTPRelaySession
	transforms := media.RelayTransformsWithMediaObservers(nil, nil, func(event RTPPlaintextEvent) {
		if relay != nil {
			relay.ObserveRTPPlaintext(event)
		}
	}, nil, nil)
	relay, err = NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:     "127.0.0.1",
		ClientAdvertiseIP:  "127.0.0.1",
		IMSListenIP:        "127.0.0.1",
		IMSAdvertiseIP:     "127.0.0.1",
		ClientRTPClockRate: 16000,
		IMSRTPClockRate:    8000,
		Transforms:         transforms,
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, RTCPPort: clientRTCPAddr.Port})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: imsAddr.Port, RTCPPort: imsRTCPAddr.Port}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}
	clientEndpoint := udpAddrFromSDP(t, relay.ClientEndpoint())
	imsEndpoint := udpAddrFromSDP(t, relay.IMSEndpoint())

	for _, seq := range []uint16{100, 102} {
		packet := testRTPPacket(seq, 0x11111111, []byte{byte(seq)})
		protected, err := media.ProtectClientRTP(packet)
		if err != nil {
			t.Fatalf("ProtectClientRTP(%d) error = %v", seq, err)
		}
		if _, err := clientPeer.WriteToUDP(protected, clientEndpoint); err != nil {
			t.Fatalf("client WriteToUDP(%d) error = %v", seq, err)
		}
		got, _ := readTestUDP(t, imsPeer)
		plain, err := media.UnprotectIMSRTP(got)
		if err != nil {
			t.Fatalf("UnprotectIMSRTP(%d) error = %v", seq, err)
		}
		if !bytes.Equal(plain, packet) {
			t.Fatalf("IMS plain seq=%d got=%x want=%x", seq, plain, packet)
		}
	}
	for _, seq := range []uint16{200, 202} {
		packet := testRTPPacket(seq, 0x22222222, []byte{byte(seq)})
		protected, err := media.ProtectIMSRTP(packet)
		if err != nil {
			t.Fatalf("ProtectIMSRTP(%d) error = %v", seq, err)
		}
		if _, err := imsPeer.WriteToUDP(protected, imsEndpoint); err != nil {
			t.Fatalf("ims WriteToUDP(%d) error = %v", seq, err)
		}
		got, _ := readTestUDP(t, clientPeer)
		plain, err := media.UnprotectClientRTP(got)
		if err != nil {
			t.Fatalf("UnprotectClientRTP(%d) error = %v", seq, err)
		}
		if !bytes.Equal(plain, packet) {
			t.Fatalf("client plain seq=%d got=%x want=%x", seq, plain, packet)
		}
	}

	stats := waitRelayStats(t, relay, func(stats RTPRelayStats) bool {
		return len(stats.ClientToIMSRTPStreams) == 1 && len(stats.IMSToClientRTPStreams) == 1 &&
			stats.ClientToIMSRTPStreams[0].LostPackets == 1 && stats.IMSToClientRTPStreams[0].LostPackets == 1
	})
	if len(stats.ClientToIMSRTPStreams) != 1 || len(stats.IMSToClientRTPStreams) != 1 {
		t.Fatalf("stream stats=%+v", stats)
	}
	if stream := stats.ClientToIMSRTPStreams[0]; stream.SSRC != 0x11111111 || stream.Packets != 2 || stream.ExpectedPackets != 3 || stream.LostPackets != 1 {
		t.Fatalf("client-to-IMS stream=%+v", stream)
	}
	if stream := stats.IMSToClientRTPStreams[0]; stream.SSRC != 0x22222222 || stream.Packets != 2 || stream.ExpectedPackets != 3 || stream.LostPackets != 1 {
		t.Fatalf("IMS-to-client stream=%+v", stream)
	}
}

func TestRTPRelaySessionReportsRTCPFeedback(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientRTCPPeer := listenTestUDP(t)
	defer clientRTCPPeer.Close()
	imsPeer := listenTestUDP(t)
	defer imsPeer.Close()
	imsRTCPPeer := listenTestUDP(t)
	defer imsRTCPPeer.Close()

	events := make(chan RTCPFeedbackEvent, 4)
	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	clientRTCPAddr := clientRTCPPeer.LocalAddr().(*net.UDPAddr)
	imsAddr := imsPeer.LocalAddr().(*net.UDPAddr)
	imsRTCPAddr := imsRTCPPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "127.0.0.1",
		RTCPFeedbackHandler: func(event RTCPFeedbackEvent) {
			events <- event
		},
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, RTCPPort: clientRTCPAddr.Port})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: imsAddr.Port, RTCPPort: imsRTCPAddr.Port}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}

	packet, err := rtcp.Marshal([]rtcp.Packet{
		&rtcp.PictureLossIndication{SenderSSRC: 0x11111111, MediaSSRC: 0x22222222},
		&rtcp.TransportLayerNack{
			SenderSSRC: 0x11111111,
			MediaSSRC:  0x22222222,
			Nacks:      rtcp.NackPairsFromSequenceNumbers([]uint16{7, 8, 12}),
		},
	})
	if err != nil {
		t.Fatalf("rtcp.Marshal() error = %v", err)
	}
	clientRTCPEndpoint := udpRTCPAddrFromSDP(t, relay.ClientEndpoint())
	if _, err := clientRTCPPeer.WriteToUDP(packet, clientRTCPEndpoint); err != nil {
		t.Fatalf("client RTCP WriteToUDP() error = %v", err)
	}
	got, _ := readTestUDP(t, imsRTCPPeer)
	if !bytes.Equal(got, packet) {
		t.Fatalf("IMS RTCP got=%x, want %x", got, packet)
	}

	first := readRTCPFeedbackEvent(t, events)
	second := readRTCPFeedbackEvent(t, events)
	seen := map[RTCPFeedbackKind]RTCPFeedbackEvent{
		first.Kind:  first,
		second.Kind: second,
	}
	if event, ok := seen[RTCPFeedbackPictureLossIndication]; !ok || event.Direction != RTCPFeedbackClientToIMS || event.MediaSSRC != 0x22222222 {
		t.Fatalf("PLI event=%+v seen=%v", event, ok)
	}
	if event, ok := seen[RTCPFeedbackTransportLayerNack]; !ok || event.NACKCount != 3 {
		t.Fatalf("NACK event=%+v seen=%v", event, ok)
	}
	stats := waitRelayStats(t, relay, func(stats RTPRelayStats) bool {
		return stats.RTCPFeedbackPackets == 2
	})
	if stats.RTCPPictureLossIndications != 1 || stats.RTCPTransportLayerNacks != 1 || stats.RTCPFeedbackParseErrors != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestRTPRelaySessionSendsGeneratedRTCPToIMS(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientRTCPPeer := listenTestUDP(t)
	defer clientRTCPPeer.Close()
	imsPeer := listenTestUDP(t)
	defer imsPeer.Close()
	imsRTCPPeer := listenTestUDP(t)
	defer imsRTCPPeer.Close()

	events := make(chan RTCPFeedbackEvent, 4)
	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	clientRTCPAddr := clientRTCPPeer.LocalAddr().(*net.UDPAddr)
	imsAddr := imsPeer.LocalAddr().(*net.UDPAddr)
	imsRTCPAddr := imsRTCPPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "127.0.0.1",
		RTCPFeedbackHandler: func(event RTCPFeedbackEvent) {
			events <- event
		},
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, RTCPPort: clientRTCPAddr.Port})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: imsAddr.Port, RTCPPort: imsRTCPAddr.Port}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}

	result, err := relay.SendRTCPToIMS(context.Background(),
		&rtcp.ReceiverReport{
			SSRC: 0x11111111,
			Reports: []rtcp.ReceptionReport{{
				SSRC:               0x22222222,
				LastSequenceNumber: 77,
				Jitter:             9,
			}},
		},
		&rtcp.PictureLossIndication{SenderSSRC: 0x11111111, MediaSSRC: 0x22222222},
	)
	if err != nil {
		t.Fatalf("SendRTCPToIMS() error = %v", err)
	}
	if result.Datagrams != 1 || result.Feedback.Packets != 2 || result.Feedback.ReceiverReports != 1 || result.Feedback.PictureLossIndications != 1 {
		t.Fatalf("result=%+v", result)
	}
	got, from := readTestUDP(t, imsRTCPPeer)
	if from.Port != relay.IMSEndpoint().RTCPPort {
		t.Fatalf("IMS RTCP packet source port=%d, want relay IMS RTCP port %d", from.Port, relay.IMSEndpoint().RTCPPort)
	}
	packets, err := rtcp.Unmarshal(got)
	if err != nil {
		t.Fatalf("rtcp.Unmarshal() error = %v", err)
	}
	if len(packets) != 2 {
		t.Fatalf("packets=%d, want 2", len(packets))
	}
	first := readRTCPFeedbackEvent(t, events)
	second := readRTCPFeedbackEvent(t, events)
	seen := map[RTCPFeedbackKind]bool{first.Kind: true, second.Kind: true}
	if !seen[RTCPFeedbackReceiverReport] || !seen[RTCPFeedbackPictureLossIndication] {
		t.Fatalf("events=%+v %+v", first, second)
	}
	stats := relay.Stats()
	if stats.ClientToIMSRTCPPackets != 1 || stats.RTCPFeedbackPackets != 2 || stats.RTCPReceiverReports != 1 || stats.RTCPPictureLossIndications != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestRTPRelaySessionTracksRTPStreamsAndSendsReceiverReport(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientRTCPPeer := listenTestUDP(t)
	defer clientRTCPPeer.Close()
	imsPeer := listenTestUDP(t)
	defer imsPeer.Close()
	imsRTCPPeer := listenTestUDP(t)
	defer imsRTCPPeer.Close()

	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	clientRTCPAddr := clientRTCPPeer.LocalAddr().(*net.UDPAddr)
	imsAddr := imsPeer.LocalAddr().(*net.UDPAddr)
	imsRTCPAddr := imsRTCPPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "127.0.0.1",
		IMSRTPClockRate:   8000,
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, RTCPPort: clientRTCPAddr.Port})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: imsAddr.Port, RTCPPort: imsRTCPAddr.Port}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}

	imsEndpoint := udpAddrFromSDP(t, relay.IMSEndpoint())
	for _, seq := range []uint16{10, 12} {
		packet := testRTPPacket(seq, 0x22222222, []byte{byte(seq)})
		if _, err := imsPeer.WriteToUDP(packet, imsEndpoint); err != nil {
			t.Fatalf("ims WriteToUDP(%d) error = %v", seq, err)
		}
		if got, _ := readTestUDP(t, clientPeer); !bytes.Equal(got, packet) {
			t.Fatalf("client got seq=%d packet=%x, want %x", seq, got, packet)
		}
	}

	stats := waitRelayStats(t, relay, func(stats RTPRelayStats) bool {
		return len(stats.IMSToClientRTPStreams) == 1 && stats.IMSToClientRTPStreams[0].LostPackets == 1
	})
	if len(stats.IMSToClientRTPStreams) != 1 {
		t.Fatalf("stream stats=%+v", stats)
	}
	stream := stats.IMSToClientRTPStreams[0]
	if stream.SSRC != 0x22222222 || stream.Packets != 2 || stream.ExpectedPackets != 3 || stream.LostPackets != 1 || stream.LastSequenceNumber != 12 {
		t.Fatalf("stream=%+v", stream)
	}

	result, err := relay.SendReceiverReportToIMS(context.Background(), 0x33333333)
	if err != nil {
		t.Fatalf("SendReceiverReportToIMS() error = %v", err)
	}
	if result.Feedback.ReceiverReports != 1 || result.Datagrams != 1 {
		t.Fatalf("result=%+v", result)
	}
	got, from := readTestUDP(t, imsRTCPPeer)
	if from.Port != relay.IMSEndpoint().RTCPPort {
		t.Fatalf("IMS RTCP source port=%d, want relay IMS RTCP port %d", from.Port, relay.IMSEndpoint().RTCPPort)
	}
	packets, err := rtcp.Unmarshal(got)
	if err != nil {
		t.Fatalf("rtcp.Unmarshal() error = %v packet=%x", err, got)
	}
	if len(packets) != 1 {
		t.Fatalf("packets=%d, want 1", len(packets))
	}
	rr, ok := packets[0].(*rtcp.ReceiverReport)
	if !ok {
		t.Fatalf("packet type=%T, want ReceiverReport", packets[0])
	}
	if rr.SSRC != 0x33333333 || len(rr.Reports) != 1 {
		t.Fatalf("receiver report=%+v", rr)
	}
	report := rr.Reports[0]
	if report.SSRC != 0x22222222 || report.TotalLost != 1 || report.LastSequenceNumber != 12 {
		t.Fatalf("reception report=%+v", report)
	}
}

func TestRTPRelaySessionSendsSenderReportWithSourceDescription(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientRTCPPeer := listenTestUDP(t)
	defer clientRTCPPeer.Close()
	imsPeer := listenTestUDP(t)
	defer imsPeer.Close()
	imsRTCPPeer := listenTestUDP(t)
	defer imsRTCPPeer.Close()

	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	clientRTCPAddr := clientRTCPPeer.LocalAddr().(*net.UDPAddr)
	imsAddr := imsPeer.LocalAddr().(*net.UDPAddr)
	imsRTCPAddr := imsRTCPPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "127.0.0.1",
		IMSRTPClockRate:   8000,
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, RTCPPort: clientRTCPAddr.Port})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: imsAddr.Port, RTCPPort: imsRTCPAddr.Port}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}

	imsEndpoint := udpAddrFromSDP(t, relay.IMSEndpoint())
	for _, seq := range []uint16{30, 32} {
		packet := testRTPPacket(seq, 0x51525354, []byte{byte(seq)})
		if _, err := imsPeer.WriteToUDP(packet, imsEndpoint); err != nil {
			t.Fatalf("ims WriteToUDP(%d) error = %v", seq, err)
		}
		if got, _ := readTestUDP(t, clientPeer); !bytes.Equal(got, packet) {
			t.Fatalf("client got seq=%d packet=%x, want %x", seq, got, packet)
		}
	}
	_ = waitRelayStats(t, relay, func(stats RTPRelayStats) bool {
		return len(stats.IMSToClientRTPStreams) == 1 && stats.IMSToClientRTPStreams[0].LostPackets == 1
	})

	result, err := relay.SendSenderReportToIMS(context.Background(), RTPRelaySenderReportRequest{
		SSRC:        0x61626364,
		CNAME:       "session-61626364",
		WallClock:   time.Unix(10, 0),
		RTPTime:     0x10203040,
		PacketCount: 4,
		OctetCount:  640,
	})
	if err != nil {
		t.Fatalf("SendSenderReportToIMS() error = %v", err)
	}
	if result.Datagrams != 1 || result.Feedback.SenderReports != 1 || result.Feedback.SourceDescriptions != 1 {
		t.Fatalf("result=%+v", result)
	}
	got, from := readTestUDP(t, imsRTCPPeer)
	if from.Port != relay.IMSEndpoint().RTCPPort {
		t.Fatalf("IMS RTCP source port=%d, want relay IMS RTCP port %d", from.Port, relay.IMSEndpoint().RTCPPort)
	}
	packets, err := rtcp.Unmarshal(got)
	if err != nil {
		t.Fatalf("rtcp.Unmarshal() error = %v packet=%x", err, got)
	}
	if len(packets) != 2 {
		t.Fatalf("packets=%d, want 2", len(packets))
	}
	sr, ok := packets[0].(*rtcp.SenderReport)
	if !ok || sr.SSRC != 0x61626364 || sr.RTPTime != 0x10203040 || sr.PacketCount != 4 || sr.OctetCount != 640 || len(sr.Reports) != 1 {
		t.Fatalf("sender report=%+v ok=%v", packets[0], ok)
	}
	if report := sr.Reports[0]; report.SSRC != 0x51525354 || report.TotalLost != 1 || report.LastSequenceNumber != 32 {
		t.Fatalf("sender report reception block=%+v", report)
	}
	sdes, ok := packets[1].(*rtcp.SourceDescription)
	if !ok || len(sdes.Chunks) != 1 || sdes.Chunks[0].Source != 0x61626364 ||
		len(sdes.Chunks[0].Items) != 1 || sdes.Chunks[0].Items[0].Type != rtcp.SDESCNAME ||
		sdes.Chunks[0].Items[0].Text != "session-61626364" {
		t.Fatalf("source description=%+v ok=%v", packets[1], ok)
	}
	stats := relay.Stats()
	if stats.ClientToIMSRTCPPackets != 1 || stats.RTCPSenderReports != 1 || stats.RTCPSourceDescriptions != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestRTPRelaySessionReportsRTPDTMFEvents(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientRTCPPeer := listenTestUDP(t)
	defer clientRTCPPeer.Close()
	imsPeer := listenTestUDP(t)
	defer imsPeer.Close()
	imsRTCPPeer := listenTestUDP(t)
	defer imsRTCPPeer.Close()

	events := make(chan RTPDTMFEvent, 4)
	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	clientRTCPAddr := clientRTCPPeer.LocalAddr().(*net.UDPAddr)
	imsAddr := imsPeer.LocalAddr().(*net.UDPAddr)
	imsRTCPAddr := imsRTCPPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "127.0.0.1",
		RTPDTMFHandler: func(event RTPDTMFEvent) {
			events <- event
		},
	}, SDPInfo{
		ConnectionIP:           "127.0.0.1",
		MediaPort:              clientAddr.Port,
		RTCPPort:               clientRTCPAddr.Port,
		Payloads:               []int{0, 110},
		TelephoneEventPayloads: map[uint8]int{110: 16000},
	})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{
		ConnectionIP:           "127.0.0.1",
		MediaPort:              imsAddr.Port,
		RTCPPort:               imsRTCPAddr.Port,
		Payloads:               []int{0, 101},
		TelephoneEventPayloads: map[uint8]int{101: 8000},
	}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}

	clientEndpoint := udpAddrFromSDP(t, relay.ClientEndpoint())
	imsEndpoint := udpAddrFromSDP(t, relay.IMSEndpoint())
	clientPacket, err := BuildRTPDTMFPacket(RTPDTMFPacket{PayloadType: 110, Marker: true, SequenceNumber: 10, Timestamp: 160, SSRC: 0x11111111, Signal: "5", DurationSamples: 1600, ClockRate: 16000})
	if err != nil {
		t.Fatalf("BuildRTPDTMFPacket(client) error = %v", err)
	}
	if _, err := clientPeer.WriteToUDP(clientPacket, clientEndpoint); err != nil {
		t.Fatalf("client WriteToUDP() error = %v", err)
	}
	wantClientToIMS, remapped, err := RewriteRTPDTMFPayloadType(clientPacket, map[uint8]int{110: 16000}, map[uint8]int{101: 8000})
	if err != nil || !remapped {
		t.Fatalf("RewriteRTPDTMFPayloadType(client) remapped=%v err=%v", remapped, err)
	}
	if got, _ := readTestUDP(t, imsPeer); !bytes.Equal(got, wantClientToIMS) {
		t.Fatalf("IMS got=%x, want %x", got, wantClientToIMS)
	}
	clientEvent := readRTPDTMFEvent(t, events)
	if clientEvent.Direction != RTPDTMFClientToIMS || clientEvent.PayloadType != 110 || clientEvent.Signal != "5" || clientEvent.DurationMS != 100 {
		t.Fatalf("client event=%+v", clientEvent)
	}

	imsPacket, err := BuildRTPDTMFPacket(RTPDTMFPacket{PayloadType: 101, SequenceNumber: 11, Timestamp: 320, SSRC: 0x22222222, Signal: "#", End: true, DurationSamples: 800, ClockRate: 8000})
	if err != nil {
		t.Fatalf("BuildRTPDTMFPacket(ims) error = %v", err)
	}
	if _, err := imsPeer.WriteToUDP(imsPacket, imsEndpoint); err != nil {
		t.Fatalf("ims WriteToUDP() error = %v", err)
	}
	wantIMSToClient, remapped, err := RewriteRTPDTMFPayloadType(imsPacket, map[uint8]int{101: 8000}, map[uint8]int{110: 16000})
	if err != nil || !remapped {
		t.Fatalf("RewriteRTPDTMFPayloadType(ims) remapped=%v err=%v", remapped, err)
	}
	if got, _ := readTestUDP(t, clientPeer); !bytes.Equal(got, wantIMSToClient) {
		t.Fatalf("client got=%x, want %x", got, wantIMSToClient)
	}
	imsEvent := readRTPDTMFEvent(t, events)
	if imsEvent.Direction != RTPDTMFIMSToClient || imsEvent.PayloadType != 101 || imsEvent.Signal != "#" || !imsEvent.End || imsEvent.DurationMS != 100 {
		t.Fatalf("IMS event=%+v", imsEvent)
	}

	stats := waitRelayStats(t, relay, func(stats RTPRelayStats) bool {
		return stats.RTPDTMFEvents == 2
	})
	if stats.RTPDTMFEvents != 2 || stats.RTPDTMFEndEvents != 1 || stats.RTPDTMFClientToIMSEvents != 1 || stats.RTPDTMFIMSToClientEvents != 1 ||
		stats.RTPDTMFRemappedEvents != 2 || stats.RTPDTMFClientToIMSRemappedEvents != 1 || stats.RTPDTMFIMSToClientRemappedEvents != 1 || stats.RTPDTMFParseErrors != 0 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestRTPRelaySessionSendsGeneratedRTPDTMFToIMS(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientRTCPPeer := listenTestUDP(t)
	defer clientRTCPPeer.Close()
	imsPeer := listenTestUDP(t)
	defer imsPeer.Close()
	imsRTCPPeer := listenTestUDP(t)
	defer imsRTCPPeer.Close()

	events := make(chan RTPDTMFEvent, 8)
	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	clientRTCPAddr := clientRTCPPeer.LocalAddr().(*net.UDPAddr)
	imsAddr := imsPeer.LocalAddr().(*net.UDPAddr)
	imsRTCPAddr := imsRTCPPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "127.0.0.1",
		RTPDTMFHandler: func(event RTPDTMFEvent) {
			events <- event
		},
	}, SDPInfo{
		ConnectionIP:           "127.0.0.1",
		MediaPort:              clientAddr.Port,
		RTCPPort:               clientRTCPAddr.Port,
		TelephoneEventPayloads: map[uint8]int{101: 8000},
	})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{
		ConnectionIP:           "127.0.0.1",
		MediaPort:              imsAddr.Port,
		RTCPPort:               imsRTCPAddr.Port,
		TelephoneEventPayloads: map[uint8]int{110: 16000},
	}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}

	result, err := relay.SendRTPDTMFToIMS(context.Background(), RTPRelayDTMFRequest{
		Signal:         "6",
		DurationMS:     20,
		StepMS:         5,
		EndPacketCount: 2,
		Volume:         8,
		SequenceNumber: 700,
		Timestamp:      0x01020304,
		SSRC:           0x11223344,
	})
	if err != nil {
		t.Fatalf("SendRTPDTMFToIMS() error = %v", err)
	}
	if result.PayloadType != 110 || result.ClockRate != 16000 || result.Packets != 5 || result.Signal != "6" {
		t.Fatalf("result=%+v", result)
	}
	for i := 0; i < result.Packets; i++ {
		got, from := readTestUDP(t, imsPeer)
		if from.Port != relay.IMSEndpoint().MediaPort {
			t.Fatalf("IMS packet source port=%d, want relay IMS port %d", from.Port, relay.IMSEndpoint().MediaPort)
		}
		event, ok, err := ParseRTPDTMFEvent(RTPDTMFClientToIMS, got, map[uint8]int{110: 16000})
		if err != nil || !ok {
			t.Fatalf("ParseRTPDTMFEvent(%d) ok=%v err=%v packet=%x", i, ok, err, got)
		}
		if event.Signal != "6" || event.PayloadType != 110 || event.Volume != 8 || event.SequenceNumber != uint16(700+i) || event.Timestamp != 0x01020304 || event.SSRC != 0x11223344 {
			t.Fatalf("event[%d]=%+v", i, event)
		}
		if event.End != (i >= result.Packets-2) {
			t.Fatalf("event[%d] end=%v", i, event.End)
		}
	}
	for i := 0; i < result.Packets; i++ {
		event := readRTPDTMFEvent(t, events)
		if event.Direction != RTPDTMFClientToIMS || event.PayloadType != 110 || event.Signal != "6" {
			t.Fatalf("callback[%d]=%+v", i, event)
		}
	}
	stats := relay.Stats()
	if stats.ClientToIMSRTPPackets != uint64(result.Packets) || stats.RTPDTMFEvents != uint64(result.Packets) || stats.RTPDTMFEndEvents != 2 {
		t.Fatalf("stats=%+v result=%+v", stats, result)
	}
}

func TestRTPRelaySessionSendsGeneratedRTPDTMFThroughSRTPTransform(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientRTCPPeer := listenTestUDP(t)
	defer clientRTCPPeer.Close()
	imsPeer := listenTestUDP(t)
	defer imsPeer.Close()
	imsRTCPPeer := listenTestUDP(t)
	defer imsRTCPPeer.Close()

	media, err := NewSRTPMediaSession(testSRTPMediaConfig())
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	clientRTCPAddr := clientRTCPPeer.LocalAddr().(*net.UDPAddr)
	imsAddr := imsPeer.LocalAddr().(*net.UDPAddr)
	imsRTCPAddr := imsRTCPPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "127.0.0.1",
		Transforms:        media.RelayTransforms(),
	}, SDPInfo{
		ConnectionIP:           "127.0.0.1",
		MediaPort:              clientAddr.Port,
		RTCPPort:               clientRTCPAddr.Port,
		TelephoneEventPayloads: map[uint8]int{101: 8000},
	})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{
		ConnectionIP:           "127.0.0.1",
		MediaPort:              imsAddr.Port,
		RTCPPort:               imsRTCPAddr.Port,
		TelephoneEventPayloads: map[uint8]int{101: 8000},
	}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}
	result, err := relay.SendRTPDTMFToIMS(context.Background(), RTPRelayDTMFRequest{
		Signal:         "#",
		DurationMS:     10,
		StepMS:         5,
		EndPacketCount: 1,
		SequenceNumber: 9,
		Timestamp:      0x10,
		SSRC:           0x22334455,
	})
	if err != nil {
		t.Fatalf("SendRTPDTMFToIMS() error = %v", err)
	}
	if result.Packets != 2 {
		t.Fatalf("result=%+v", result)
	}
	for i := 0; i < result.Packets; i++ {
		got, _ := readTestUDP(t, imsPeer)
		if len(got) <= 16 {
			t.Fatalf("IMS got unprotected RTP packet=%x", got)
		}
		plain, err := media.UnprotectIMSRTP(got)
		if err != nil {
			t.Fatalf("UnprotectIMSRTP(%d) error = %v", i, err)
		}
		event, ok, err := ParseRTPDTMFEvent(RTPDTMFClientToIMS, plain, map[uint8]int{101: 8000})
		if err != nil || !ok {
			t.Fatalf("ParseRTPDTMFEvent(%d) ok=%v err=%v plain=%x", i, ok, err, plain)
		}
		if event.Signal != "#" || event.SequenceNumber != uint16(9+i) || event.End != (i == result.Packets-1) {
			t.Fatalf("event[%d]=%+v", i, event)
		}
	}
}

func TestRTPRelaySessionSendsGeneratedRTCPThroughSRTPTransform(t *testing.T) {
	clientPeer := listenTestUDP(t)
	defer clientPeer.Close()
	clientRTCPPeer := listenTestUDP(t)
	defer clientRTCPPeer.Close()
	imsPeer := listenTestUDP(t)
	defer imsPeer.Close()
	imsRTCPPeer := listenTestUDP(t)
	defer imsRTCPPeer.Close()

	media, err := NewSRTPMediaSession(testSRTPMediaConfig())
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	clientAddr := clientPeer.LocalAddr().(*net.UDPAddr)
	clientRTCPAddr := clientRTCPPeer.LocalAddr().(*net.UDPAddr)
	imsAddr := imsPeer.LocalAddr().(*net.UDPAddr)
	imsRTCPAddr := imsRTCPPeer.LocalAddr().(*net.UDPAddr)
	relay, err := NewRTPRelaySession(context.Background(), RTPRelayConfig{
		ClientListenIP:    "127.0.0.1",
		ClientAdvertiseIP: "127.0.0.1",
		IMSListenIP:       "127.0.0.1",
		IMSAdvertiseIP:    "127.0.0.1",
		Transforms:        media.RelayTransforms(),
	}, SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: clientAddr.Port, RTCPPort: clientRTCPAddr.Port})
	if err != nil {
		t.Fatalf("NewRTPRelaySession() error = %v", err)
	}
	defer relay.Close()
	if err := relay.SetIMSRemote(SDPInfo{ConnectionIP: "127.0.0.1", MediaPort: imsAddr.Port, RTCPPort: imsRTCPAddr.Port}); err != nil {
		t.Fatalf("SetIMSRemote() error = %v", err)
	}
	result, err := relay.SendRTCPToClient(context.Background(), &rtcp.ReceiverReport{
		SSRC: 0x33333333,
		Reports: []rtcp.ReceptionReport{{
			SSRC:               0x44444444,
			LastSequenceNumber: 91,
			Jitter:             12,
		}},
	})
	if err != nil {
		t.Fatalf("SendRTCPToClient() error = %v", err)
	}
	if result.Datagrams != 1 || result.Feedback.ReceiverReports != 1 {
		t.Fatalf("result=%+v", result)
	}
	got, _ := readTestUDP(t, clientRTCPPeer)
	plain, err := media.UnprotectClientRTCP(got)
	if err != nil {
		t.Fatalf("UnprotectClientRTCP() error = %v", err)
	}
	if bytes.Equal(got, plain) || len(got) <= len(plain) {
		t.Fatalf("client got unprotected RTCP packet=%x plain=%x", got, plain)
	}
	packets, err := rtcp.Unmarshal(plain)
	if err != nil {
		t.Fatalf("rtcp.Unmarshal() error = %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("packets=%d, want 1", len(packets))
	}
	if rr, ok := packets[0].(*rtcp.ReceiverReport); !ok || rr.SSRC != 0x33333333 || len(rr.Reports) != 1 || rr.Reports[0].SSRC != 0x44444444 {
		t.Fatalf("receiver report=%+v ok=%v", packets[0], ok)
	}
}

func listenTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	return conn
}

func readTestUDP(t *testing.T, conn *net.UDPConn) ([]byte, *net.UDPAddr) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 128)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP() error = %v", err)
	}
	return append([]byte(nil), buf[:n]...), addr
}

func expectNoTestUDP(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 128)
	n, addr, err := conn.ReadFromUDP(buf)
	if err == nil {
		t.Fatalf("unexpected UDP packet from %v: %x", addr, buf[:n])
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("ReadFromUDP() error = %v, want timeout", err)
	}
}

func readRTCPFeedbackEvent(t *testing.T, events <-chan RTCPFeedbackEvent) RTCPFeedbackEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for RTCP feedback event")
		return RTCPFeedbackEvent{}
	}
}

func readRTPDTMFEvent(t *testing.T, events <-chan RTPDTMFEvent) RTPDTMFEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for RTP DTMF event")
		return RTPDTMFEvent{}
	}
}

func waitRelayStats(t *testing.T, relay *RTPRelaySession, pred func(RTPRelayStats) bool) RTPRelayStats {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		stats := relay.Stats()
		if pred(stats) {
			return stats
		}
		if time.Now().After(deadline) {
			return stats
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func udpAddrFromSDP(t *testing.T, info SDPInfo) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(info.ConnectionIP, strconv.Itoa(info.MediaPort)))
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%+v) error = %v", info, err)
	}
	return addr
}

func udpRTCPAddrFromSDP(t *testing.T, info SDPInfo) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(info.ConnectionIP, strconv.Itoa(info.RTCPPort)))
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%+v RTCP) error = %v", info, err)
	}
	return addr
}
