package voicehost

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var ErrRTPRelayConfig = errors.New("invalid rtp relay config")

type RTPRelayConfig struct {
	ClientListenIP      string
	ClientAdvertiseIP   string
	ClientPort          int
	ClientRTCPPort      int
	IMSListenIP         string
	IMSAdvertiseIP      string
	IMSPort             int
	IMSRTCPPort         int
	BufferSize          int
	Transforms          RTPRelayTransforms
	RTCPFeedbackHandler RTCPFeedbackHandler
	RTPDTMFHandler      RTPDTMFHandler
}

type RTPRelayTransform func([]byte) ([]byte, error)

type RTPRelayTransforms struct {
	ClientToIMSRTP       RTPRelayTransform
	IMSToClientRTP       RTPRelayTransform
	ClientToIMSRTCP      RTPRelayTransform
	IMSToClientRTCP      RTPRelayTransform
	GeneratedToIMSRTP    RTPRelayTransform
	GeneratedToClientRTP RTPRelayTransform
}

type RTPRelayDTMFRequest struct {
	Direction      RTPDTMFDirection
	Signal         string
	DurationMS     int
	StepMS         int
	EndPacketCount int
	Volume         uint8
	SequenceNumber uint16
	Timestamp      uint32
	SSRC           uint32
	PayloadType    uint8
	ClockRate      int
}

type RTPRelayDTMFResult struct {
	Packets        int
	Bytes          int
	PayloadType    uint8
	ClockRate      int
	SequenceNumber uint16
	Timestamp      uint32
	SSRC           uint32
	Signal         string
	DurationMS     int
}

type RTPRelayStats struct {
	ClientToIMSPackets                   uint64
	IMSToClientPackets                   uint64
	ClientToIMSBytes                     uint64
	IMSToClientBytes                     uint64
	ClientToIMSRTPPackets                uint64
	IMSToClientRTPPackets                uint64
	ClientToIMSRTCPPackets               uint64
	IMSToClientRTCPPackets               uint64
	ClientToIMSRTPBytes                  uint64
	IMSToClientRTPBytes                  uint64
	ClientToIMSRTCPBytes                 uint64
	IMSToClientRTCPBytes                 uint64
	ClientToIMSRTPDrops                  uint64
	IMSToClientRTPDrops                  uint64
	ClientToIMSRTCPDrops                 uint64
	IMSToClientRTCPDrops                 uint64
	RTCPFeedbackPackets                  uint64
	RTCPFeedbackParseErrors              uint64
	RTCPSenderReports                    uint64
	RTCPReceiverReports                  uint64
	RTCPPictureLossIndications           uint64
	RTCPFullIntraRequests                uint64
	RTCPRapidResynchronizationRequests   uint64
	RTCPTransportLayerNacks              uint64
	RTCPReceiverEstimatedMaximumBitrates uint64
	RTCPTransportLayerCongestionControls uint64
	RTCPSliceLossIndications             uint64
	RTCPExtendedReports                  uint64
	RTCPSourceDescriptions               uint64
	RTCPGoodbyes                         uint64
	RTCPApplicationDefined               uint64
	RTCPUnknownPackets                   uint64
	RTPDTMFEvents                        uint64
	RTPDTMFEndEvents                     uint64
	RTPDTMFClientToIMSEvents             uint64
	RTPDTMFIMSToClientEvents             uint64
	RTPDTMFRemappedEvents                uint64
	RTPDTMFClientToIMSRemappedEvents     uint64
	RTPDTMFIMSToClientRemappedEvents     uint64
	RTPDTMFParseErrors                   uint64
}

type RTPRelaySession struct {
	clientConn     *net.UDPConn
	imsConn        *net.UDPConn
	clientRTCPConn *net.UDPConn
	imsRTCPConn    *net.UDPConn

	clientTarget     *net.UDPAddr
	clientRTCPTarget *net.UDPAddr

	mu            sync.RWMutex
	imsTarget     *net.UDPAddr
	imsRTCPTarget *net.UDPAddr
	imsDirection  string
	closed        bool

	clientDirection       string
	clientRTPDTMFPayloads map[uint8]int
	imsRTPDTMFPayloads    map[uint8]int

	clientAdvertiseIP string
	imsAdvertiseIP    string
	bufferSize        int

	cancel context.CancelFunc
	wg     sync.WaitGroup

	dtmfMu               sync.Mutex
	dtmfClientToIMSState rtpDTMFSequenceState
	dtmfIMSToClientState rtpDTMFSequenceState

	clientToIMSRTPPackets                atomic.Uint64
	imsToClientRTPPackets                atomic.Uint64
	clientToIMSRTCPPackets               atomic.Uint64
	imsToClientRTCPPackets               atomic.Uint64
	clientToIMSRTPBytes                  atomic.Uint64
	imsToClientRTPBytes                  atomic.Uint64
	clientToIMSRTCPBytes                 atomic.Uint64
	imsToClientRTCPBytes                 atomic.Uint64
	clientToIMSRTPDrops                  atomic.Uint64
	imsToClientRTPDrops                  atomic.Uint64
	clientToIMSRTCPDrops                 atomic.Uint64
	imsToClientRTCPDrops                 atomic.Uint64
	transforms                           RTPRelayTransforms
	rtcpFeedbackHandler                  RTCPFeedbackHandler
	rtpDTMFHandler                       RTPDTMFHandler
	rtcpFeedbackPackets                  atomic.Uint64
	rtcpFeedbackParseErrors              atomic.Uint64
	rtcpSenderReports                    atomic.Uint64
	rtcpReceiverReports                  atomic.Uint64
	rtcpPictureLossIndications           atomic.Uint64
	rtcpFullIntraRequests                atomic.Uint64
	rtcpRapidResynchronizationRequests   atomic.Uint64
	rtcpTransportLayerNacks              atomic.Uint64
	rtcpReceiverEstimatedMaximumBitrates atomic.Uint64
	rtcpTransportLayerCongestionControls atomic.Uint64
	rtcpSliceLossIndications             atomic.Uint64
	rtcpExtendedReports                  atomic.Uint64
	rtcpSourceDescriptions               atomic.Uint64
	rtcpGoodbyes                         atomic.Uint64
	rtcpApplicationDefined               atomic.Uint64
	rtcpUnknownPackets                   atomic.Uint64
	rtpDTMFEvents                        atomic.Uint64
	rtpDTMFEndEvents                     atomic.Uint64
	rtpDTMFClientToIMSEvents             atomic.Uint64
	rtpDTMFIMSToClientEvents             atomic.Uint64
	rtpDTMFRemappedEvents                atomic.Uint64
	rtpDTMFClientToIMSRemappedEvents     atomic.Uint64
	rtpDTMFIMSToClientRemappedEvents     atomic.Uint64
	rtpDTMFParseErrors                   atomic.Uint64
}

type rtpDTMFSequenceState struct {
	nextSeq       uint16
	nextTimestamp uint32
	ssrc          uint32
}

func NewRTPRelaySession(ctx context.Context, cfg RTPRelayConfig, clientTarget SDPInfo) (*RTPRelaySession, error) {
	s, err := newRTPRelaySession(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := s.SetClientRemote(clientTarget); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func NewRTPRelaySessionForIMSRemote(ctx context.Context, cfg RTPRelayConfig, imsTarget SDPInfo) (*RTPRelaySession, error) {
	s, err := newRTPRelaySession(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := s.SetIMSRemote(imsTarget); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func newRTPRelaySession(ctx context.Context, cfg RTPRelayConfig) (*RTPRelaySession, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	clientListenIP := firstVoiceNonEmpty(cfg.ClientListenIP, "0.0.0.0")
	imsListenIP := firstVoiceNonEmpty(cfg.IMSListenIP, clientListenIP)
	clientConn, err := listenUDP(clientListenIP, cfg.ClientPort)
	if err != nil {
		return nil, err
	}
	imsConn, err := listenUDP(imsListenIP, cfg.IMSPort)
	if err != nil {
		_ = clientConn.Close()
		return nil, err
	}
	clientRTCPConn, err := listenUDP(clientListenIP, cfg.ClientRTCPPort)
	if err != nil {
		_ = clientConn.Close()
		_ = imsConn.Close()
		return nil, err
	}
	imsRTCPConn, err := listenUDP(imsListenIP, cfg.IMSRTCPPort)
	if err != nil {
		_ = clientConn.Close()
		_ = imsConn.Close()
		_ = clientRTCPConn.Close()
		return nil, err
	}
	childCtx, cancel := context.WithCancel(ctx)
	s := &RTPRelaySession{
		clientConn:           clientConn,
		imsConn:              imsConn,
		clientRTCPConn:       clientRTCPConn,
		imsRTCPConn:          imsRTCPConn,
		clientAdvertiseIP:    advertiseIP(cfg.ClientAdvertiseIP, clientListenIP),
		imsAdvertiseIP:       advertiseIP(cfg.IMSAdvertiseIP, imsListenIP),
		bufferSize:           cfg.BufferSize,
		cancel:               cancel,
		transforms:           cfg.Transforms,
		rtcpFeedbackHandler:  cfg.RTCPFeedbackHandler,
		rtpDTMFHandler:       cfg.RTPDTMFHandler,
		dtmfClientToIMSState: newRTPDTMFSequenceState(),
		dtmfIMSToClientState: newRTPDTMFSequenceState(),
	}
	if s.bufferSize <= 0 {
		s.bufferSize = 2048
	}
	s.wg.Add(4)
	go s.forwardLoop(childCtx, s.clientConn, s.imsConn, s.currentIMSTarget, s.allowClientToIMSRTP, &s.clientToIMSRTPPackets, &s.clientToIMSRTPBytes, &s.clientToIMSRTPDrops, s.transforms.ClientToIMSRTP, "", RTPDTMFClientToIMS, s.currentClientRTPDTMFPayloads, s.currentIMSRTPDTMFPayloads)
	go s.forwardLoop(childCtx, s.imsConn, s.clientConn, s.currentClientTarget, s.allowIMSToClientRTP, &s.imsToClientRTPPackets, &s.imsToClientRTPBytes, &s.imsToClientRTPDrops, s.transforms.IMSToClientRTP, "", RTPDTMFIMSToClient, s.currentIMSRTPDTMFPayloads, s.currentClientRTPDTMFPayloads)
	go s.forwardLoop(childCtx, s.clientRTCPConn, s.imsRTCPConn, s.currentIMSRTCPTarget, nil, &s.clientToIMSRTCPPackets, &s.clientToIMSRTCPBytes, &s.clientToIMSRTCPDrops, s.transforms.ClientToIMSRTCP, RTCPFeedbackClientToIMS, "", nil, nil)
	go s.forwardLoop(childCtx, s.imsRTCPConn, s.clientRTCPConn, s.currentClientRTCPTarget, nil, &s.imsToClientRTCPPackets, &s.imsToClientRTCPBytes, &s.imsToClientRTCPDrops, s.transforms.IMSToClientRTCP, RTCPFeedbackIMSToClient, "", nil, nil)
	return s, nil
}

func (s *RTPRelaySession) IMSOfferSDP(clientOffer SDPInfo) []byte {
	info := clientOffer
	info.ConnectionIP = s.imsAdvertiseIP
	info.MediaPort = s.imsPort()
	info.RTCPPort = s.imsRTCPPort()
	return BuildSDPAnswer(info)
}

func (s *RTPRelaySession) ClientAnswerSDP(imsAnswer SDPInfo) []byte {
	info := imsAnswer
	info.ConnectionIP = s.clientAdvertiseIP
	info.MediaPort = s.clientPort()
	info.RTCPPort = s.clientRTCPPort()
	return BuildSDPAnswer(info)
}

func (s *RTPRelaySession) SetIMSRemote(info SDPInfo) error {
	if s == nil {
		return nil
	}
	addr, rtcpAddr, err := resolveSDPEndpoint(info, "IMS")
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.imsTarget = addr
	s.imsRTCPTarget = rtcpAddr
	s.imsDirection = normalizeSDPDirection(info.Direction)
	s.imsRTPDTMFPayloads = rtpDTMFPayloadTypesFromSDP(info)
	s.mu.Unlock()
	return nil
}

func (s *RTPRelaySession) SetClientRemote(info SDPInfo) error {
	if s == nil {
		return nil
	}
	addr, rtcpAddr, err := resolveSDPEndpoint(info, "client")
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.clientTarget = addr
	s.clientRTCPTarget = rtcpAddr
	s.clientDirection = normalizeSDPDirection(info.Direction)
	s.clientRTPDTMFPayloads = rtpDTMFPayloadTypesFromSDP(info)
	s.mu.Unlock()
	return nil
}

func (s *RTPRelaySession) ClientEndpoint() SDPInfo {
	if s == nil {
		return SDPInfo{}
	}
	return SDPInfo{ConnectionIP: s.clientAdvertiseIP, MediaPort: s.clientPort(), RTCPIP: s.clientAdvertiseIP, RTCPPort: s.clientRTCPPort()}
}

func (s *RTPRelaySession) IMSEndpoint() SDPInfo {
	if s == nil {
		return SDPInfo{}
	}
	return SDPInfo{ConnectionIP: s.imsAdvertiseIP, MediaPort: s.imsPort(), RTCPIP: s.imsAdvertiseIP, RTCPPort: s.imsRTCPPort()}
}

func (s *RTPRelaySession) Stats() RTPRelayStats {
	if s == nil {
		return RTPRelayStats{}
	}
	rtpOutPackets := s.clientToIMSRTPPackets.Load()
	rtpInPackets := s.imsToClientRTPPackets.Load()
	rtpOutBytes := s.clientToIMSRTPBytes.Load()
	rtpInBytes := s.imsToClientRTPBytes.Load()
	return RTPRelayStats{
		ClientToIMSPackets:                   rtpOutPackets,
		IMSToClientPackets:                   rtpInPackets,
		ClientToIMSBytes:                     rtpOutBytes,
		IMSToClientBytes:                     rtpInBytes,
		ClientToIMSRTPPackets:                rtpOutPackets,
		IMSToClientRTPPackets:                rtpInPackets,
		ClientToIMSRTCPPackets:               s.clientToIMSRTCPPackets.Load(),
		IMSToClientRTCPPackets:               s.imsToClientRTCPPackets.Load(),
		ClientToIMSRTPBytes:                  rtpOutBytes,
		IMSToClientRTPBytes:                  rtpInBytes,
		ClientToIMSRTCPBytes:                 s.clientToIMSRTCPBytes.Load(),
		IMSToClientRTCPBytes:                 s.imsToClientRTCPBytes.Load(),
		ClientToIMSRTPDrops:                  s.clientToIMSRTPDrops.Load(),
		IMSToClientRTPDrops:                  s.imsToClientRTPDrops.Load(),
		ClientToIMSRTCPDrops:                 s.clientToIMSRTCPDrops.Load(),
		IMSToClientRTCPDrops:                 s.imsToClientRTCPDrops.Load(),
		RTCPFeedbackPackets:                  s.rtcpFeedbackPackets.Load(),
		RTCPFeedbackParseErrors:              s.rtcpFeedbackParseErrors.Load(),
		RTCPSenderReports:                    s.rtcpSenderReports.Load(),
		RTCPReceiverReports:                  s.rtcpReceiverReports.Load(),
		RTCPPictureLossIndications:           s.rtcpPictureLossIndications.Load(),
		RTCPFullIntraRequests:                s.rtcpFullIntraRequests.Load(),
		RTCPRapidResynchronizationRequests:   s.rtcpRapidResynchronizationRequests.Load(),
		RTCPTransportLayerNacks:              s.rtcpTransportLayerNacks.Load(),
		RTCPReceiverEstimatedMaximumBitrates: s.rtcpReceiverEstimatedMaximumBitrates.Load(),
		RTCPTransportLayerCongestionControls: s.rtcpTransportLayerCongestionControls.Load(),
		RTCPSliceLossIndications:             s.rtcpSliceLossIndications.Load(),
		RTCPExtendedReports:                  s.rtcpExtendedReports.Load(),
		RTCPSourceDescriptions:               s.rtcpSourceDescriptions.Load(),
		RTCPGoodbyes:                         s.rtcpGoodbyes.Load(),
		RTCPApplicationDefined:               s.rtcpApplicationDefined.Load(),
		RTCPUnknownPackets:                   s.rtcpUnknownPackets.Load(),
		RTPDTMFEvents:                        s.rtpDTMFEvents.Load(),
		RTPDTMFEndEvents:                     s.rtpDTMFEndEvents.Load(),
		RTPDTMFClientToIMSEvents:             s.rtpDTMFClientToIMSEvents.Load(),
		RTPDTMFIMSToClientEvents:             s.rtpDTMFIMSToClientEvents.Load(),
		RTPDTMFRemappedEvents:                s.rtpDTMFRemappedEvents.Load(),
		RTPDTMFClientToIMSRemappedEvents:     s.rtpDTMFClientToIMSRemappedEvents.Load(),
		RTPDTMFIMSToClientRemappedEvents:     s.rtpDTMFIMSToClientRemappedEvents.Load(),
		RTPDTMFParseErrors:                   s.rtpDTMFParseErrors.Load(),
	}
}

func (s *RTPRelaySession) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	var err error
	if s.clientConn != nil {
		err = errors.Join(err, s.clientConn.Close())
	}
	if s.imsConn != nil {
		err = errors.Join(err, s.imsConn.Close())
	}
	if s.clientRTCPConn != nil {
		err = errors.Join(err, s.clientRTCPConn.Close())
	}
	if s.imsRTCPConn != nil {
		err = errors.Join(err, s.imsRTCPConn.Close())
	}
	s.wg.Wait()
	return err
}

func (s *RTPRelaySession) SendRTPDTMFToIMS(ctx context.Context, req RTPRelayDTMFRequest) (RTPRelayDTMFResult, error) {
	req.Direction = RTPDTMFClientToIMS
	return s.SendRTPDTMF(ctx, req)
}

func (s *RTPRelaySession) SendRTPDTMFToClient(ctx context.Context, req RTPRelayDTMFRequest) (RTPRelayDTMFResult, error) {
	req.Direction = RTPDTMFIMSToClient
	return s.SendRTPDTMF(ctx, req)
}

func (s *RTPRelaySession) SendRTPDTMF(ctx context.Context, req RTPRelayDTMFRequest) (RTPRelayDTMFResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil {
		return RTPRelayDTMFResult{}, ErrRTPRelayConfig
	}
	direction, err := normalizeRTPDTMFDirection(req.Direction)
	if err != nil {
		return RTPRelayDTMFResult{DurationMS: rtpDTMFDurationMS(req.DurationMS)}, err
	}
	signal, err := NormalizeRTPDTMFSignal(req.Signal)
	if err != nil {
		return RTPRelayDTMFResult{DurationMS: rtpDTMFDurationMS(req.DurationMS)}, err
	}
	route, err := s.rtpDTMFSendRoute(direction)
	if err != nil {
		return RTPRelayDTMFResult{Signal: signal, DurationMS: rtpDTMFDurationMS(req.DurationMS)}, err
	}
	if route.target == nil {
		return RTPRelayDTMFResult{Signal: signal, DurationMS: rtpDTMFDurationMS(req.DurationMS)}, fmt.Errorf("%w: %s RTP target unavailable", ErrRTPRelayConfig, route.label)
	}
	if route.conn == nil {
		return RTPRelayDTMFResult{Signal: signal, DurationMS: rtpDTMFDurationMS(req.DurationMS)}, fmt.Errorf("%w: %s RTP socket unavailable", ErrRTPRelayConfig, route.label)
	}
	if route.allow != nil && !route.allow() {
		route.drops.Add(1)
		return RTPRelayDTMFResult{Signal: signal, DurationMS: rtpDTMFDurationMS(req.DurationMS)}, fmt.Errorf("%w: %s RTP direction is not sendable", ErrRTPRelayConfig, route.label)
	}
	if len(route.payloads) == 0 && req.PayloadType == 0 {
		route.drops.Add(1)
		return RTPRelayDTMFResult{Signal: signal, DurationMS: rtpDTMFDurationMS(req.DurationMS)}, fmt.Errorf("%w: %s RTP telephone-event payload unavailable", ErrRTPRelayConfig, route.label)
	}
	payloadType, clockRate := rtpDTMFGenerationPayload(req, route.payloads)
	req.Signal = signal
	packets, cfg, err := s.buildGeneratedRTPDTMFSequence(direction, req, payloadType, clockRate)
	result := RTPRelayDTMFResult{
		PayloadType:    cfg.PayloadType,
		ClockRate:      cfg.ClockRate,
		SequenceNumber: cfg.SequenceNumber,
		Timestamp:      cfg.Timestamp,
		SSRC:           cfg.SSRC,
		Signal:         signal,
		DurationMS:     rtpDTMFDurationMS(req.DurationMS),
	}
	if err != nil {
		return result, err
	}
	interval := time.Duration(rtpDTMFStepMS(req.StepMS, result.DurationMS)) * time.Millisecond
	payloads := map[uint8]int{cfg.PayloadType: cfg.ClockRate}
	for i, packet := range packets {
		if i > 0 {
			if err := waitRTPDTMFInterval(ctx, interval); err != nil {
				return result, err
			}
		} else {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}
		}
		summary, err := InspectRTPDTMF(direction, packet, payloads, s.rtpDTMFHandler)
		if err != nil {
			route.drops.Add(1)
			s.rtpDTMFParseErrors.Add(1)
			return result, err
		}
		s.recordRTPDTMFSummary(direction, summary)
		out := packet
		if route.transform != nil {
			transformed, err := route.transform(packet)
			if err != nil {
				route.drops.Add(1)
				return result, err
			}
			out = transformed
		}
		if _, err := route.conn.WriteToUDP(out, route.target); err != nil {
			route.drops.Add(1)
			return result, err
		}
		route.packets.Add(1)
		route.bytes.Add(uint64(len(out)))
		result.Packets++
		result.Bytes += len(out)
	}
	return result, nil
}

func (s *RTPRelaySession) forwardLoop(ctx context.Context, src, out *net.UDPConn, target func() *net.UDPAddr, allow func() bool, packets, bytes, drops *atomic.Uint64, transform RTPRelayTransform, rtcpDirection RTCPFeedbackDirection, dtmfDirection RTPDTMFDirection, dtmfPayloads, dtmfTargetPayloads func() map[uint8]int) {
	defer s.wg.Done()
	buf := make([]byte, s.bufferSize)
	for {
		n, _, err := src.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				return
			}
		}
		dst := target()
		if dst == nil {
			continue
		}
		if allow != nil && !allow() {
			drops.Add(1)
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		if transform != nil {
			transformed, err := transform(packet)
			if err != nil {
				drops.Add(1)
				continue
			}
			packet = transformed
		}
		if rtcpDirection != "" && transform == nil {
			s.inspectRTCPFeedback(rtcpDirection, packet)
		}
		if dtmfDirection != "" && transform == nil && dtmfPayloads != nil {
			var targetPayloads map[uint8]int
			if dtmfTargetPayloads != nil {
				targetPayloads = dtmfTargetPayloads()
			}
			packet = s.processRTPDTMF(dtmfDirection, packet, dtmfPayloads(), targetPayloads)
		}
		if _, err := out.WriteToUDP(packet, dst); err != nil {
			drops.Add(1)
			continue
		}
		packets.Add(1)
		bytes.Add(uint64(len(packet)))
	}
}

func (s *RTPRelaySession) processRTPDTMF(direction RTPDTMFDirection, packet []byte, sourcePayloads, targetPayloads map[uint8]int) []byte {
	if s == nil || len(sourcePayloads) == 0 {
		return packet
	}
	summary, err := InspectRTPDTMF(direction, packet, sourcePayloads, s.rtpDTMFHandler)
	if err != nil {
		s.rtpDTMFParseErrors.Add(1)
		return packet
	}
	if summary.Events == 0 {
		return packet
	}
	s.recordRTPDTMFSummary(direction, summary)
	rewritten, remapped, err := RewriteRTPDTMFPayloadType(packet, sourcePayloads, targetPayloads)
	if err != nil {
		s.rtpDTMFParseErrors.Add(1)
		return packet
	}
	if remapped {
		s.recordRTPDTMFRemap(direction)
		return rewritten
	}
	return packet
}

func (s *RTPRelaySession) inspectRTPDTMF(direction RTPDTMFDirection, packet []byte, payloads map[uint8]int) {
	if s == nil || len(payloads) == 0 {
		return
	}
	summary, err := InspectRTPDTMF(direction, packet, payloads, s.rtpDTMFHandler)
	if err != nil {
		s.rtpDTMFParseErrors.Add(1)
		return
	}
	if summary.Events == 0 {
		return
	}
	s.recordRTPDTMFSummary(direction, summary)
}

func (s *RTPRelaySession) recordRTPDTMFSummary(direction RTPDTMFDirection, summary RTPDTMFSummary) {
	if s == nil {
		return
	}
	s.rtpDTMFEvents.Add(summary.Events)
	s.rtpDTMFEndEvents.Add(summary.EndEvents)
	switch direction {
	case RTPDTMFClientToIMS:
		s.rtpDTMFClientToIMSEvents.Add(summary.Events)
	case RTPDTMFIMSToClient:
		s.rtpDTMFIMSToClientEvents.Add(summary.Events)
	}
}

func (s *RTPRelaySession) recordRTPDTMFRemap(direction RTPDTMFDirection) {
	if s == nil {
		return
	}
	s.rtpDTMFRemappedEvents.Add(1)
	switch direction {
	case RTPDTMFClientToIMS:
		s.rtpDTMFClientToIMSRemappedEvents.Add(1)
	case RTPDTMFIMSToClient:
		s.rtpDTMFIMSToClientRemappedEvents.Add(1)
	}
}

type rtpDTMFSendRoute struct {
	label     string
	conn      *net.UDPConn
	target    *net.UDPAddr
	allow     func() bool
	payloads  map[uint8]int
	transform RTPRelayTransform
	packets   *atomic.Uint64
	bytes     *atomic.Uint64
	drops     *atomic.Uint64
}

func (s *RTPRelaySession) rtpDTMFSendRoute(direction RTPDTMFDirection) (rtpDTMFSendRoute, error) {
	if s == nil {
		return rtpDTMFSendRoute{}, ErrRTPRelayConfig
	}
	switch direction {
	case RTPDTMFClientToIMS:
		return rtpDTMFSendRoute{
			label:     "IMS",
			conn:      s.imsConn,
			target:    s.currentIMSTarget(),
			allow:     s.allowClientToIMSRTP,
			payloads:  s.currentIMSRTPDTMFPayloads(),
			transform: s.transforms.GeneratedToIMSRTP,
			packets:   &s.clientToIMSRTPPackets,
			bytes:     &s.clientToIMSRTPBytes,
			drops:     &s.clientToIMSRTPDrops,
		}, nil
	case RTPDTMFIMSToClient:
		return rtpDTMFSendRoute{
			label:     "client",
			conn:      s.clientConn,
			target:    s.currentClientTarget(),
			allow:     s.allowIMSToClientRTP,
			payloads:  s.currentClientRTPDTMFPayloads(),
			transform: s.transforms.GeneratedToClientRTP,
			packets:   &s.imsToClientRTPPackets,
			bytes:     &s.imsToClientRTPBytes,
			drops:     &s.imsToClientRTPDrops,
		}, nil
	default:
		return rtpDTMFSendRoute{}, fmt.Errorf("%w: unsupported RTP DTMF direction %q", ErrInvalidDTMF, direction)
	}
}

func (s *RTPRelaySession) buildGeneratedRTPDTMFSequence(direction RTPDTMFDirection, req RTPRelayDTMFRequest, payloadType uint8, clockRate int) ([][]byte, RTPDTMFSequenceConfig, error) {
	if s == nil {
		return nil, RTPDTMFSequenceConfig{}, ErrRTPRelayConfig
	}
	if clockRate <= 0 {
		clockRate = DefaultRTPDTMFClockRate
	}
	cfg := RTPDTMFSequenceConfig{
		PayloadType:    payloadType,
		Signal:         req.Signal,
		DurationMS:     rtpDTMFDurationMS(req.DurationMS),
		StepMS:         req.StepMS,
		EndPacketCount: req.EndPacketCount,
		Volume:         req.Volume,
		SequenceNumber: req.SequenceNumber,
		Timestamp:      req.Timestamp,
		SSRC:           req.SSRC,
		ClockRate:      clockRate,
	}
	s.dtmfMu.Lock()
	defer s.dtmfMu.Unlock()
	state := &s.dtmfClientToIMSState
	if direction == RTPDTMFIMSToClient {
		state = &s.dtmfIMSToClientState
	}
	if state.ssrc == 0 {
		*state = newRTPDTMFSequenceState()
	}
	if cfg.SequenceNumber == 0 {
		cfg.SequenceNumber = state.nextSeq
	}
	if cfg.Timestamp == 0 {
		cfg.Timestamp = state.nextTimestamp
	}
	if cfg.SSRC == 0 {
		cfg.SSRC = state.ssrc
	}
	packets, err := BuildRTPDTMFSequence(cfg)
	if err != nil {
		return nil, cfg, err
	}
	durationSamples, err := rtpDTMFSamplesForDuration(cfg.DurationMS, cfg.ClockRate)
	if err != nil {
		return nil, cfg, err
	}
	state.nextSeq = cfg.SequenceNumber + uint16(len(packets))
	state.nextTimestamp = cfg.Timestamp + uint32(durationSamples)
	state.ssrc = cfg.SSRC
	return packets, cfg, nil
}

func normalizeRTPDTMFDirection(direction RTPDTMFDirection) (RTPDTMFDirection, error) {
	switch direction {
	case "", RTPDTMFClientToIMS:
		return RTPDTMFClientToIMS, nil
	case RTPDTMFIMSToClient:
		return RTPDTMFIMSToClient, nil
	default:
		return "", fmt.Errorf("%w: unsupported RTP DTMF direction %q", ErrInvalidDTMF, direction)
	}
}

func rtpDTMFGenerationPayload(req RTPRelayDTMFRequest, payloads map[uint8]int) (uint8, int) {
	if req.PayloadType != 0 {
		clockRate := req.ClockRate
		if clockRate <= 0 {
			clockRate = payloads[req.PayloadType]
		}
		if clockRate <= 0 {
			clockRate = DefaultRTPDTMFClockRate
		}
		return req.PayloadType, clockRate
	}
	preferredClock := req.ClockRate
	if payload, clockRate, ok := preferredRTPDTMFPayload(payloads, preferredClock); ok {
		return payload, clockRate
	}
	clockRate := preferredClock
	if clockRate <= 0 {
		clockRate = DefaultRTPDTMFClockRate
	}
	return DefaultRTPDTMFPayloadType, clockRate
}

func preferredRTPDTMFPayload(payloads map[uint8]int, preferredClock int) (uint8, int, bool) {
	if len(payloads) == 0 {
		return 0, 0, false
	}
	if clockRate, ok := payloads[DefaultRTPDTMFPayloadType]; ok && (preferredClock <= 0 || clockRate == preferredClock) {
		if clockRate <= 0 {
			clockRate = DefaultRTPDTMFClockRate
		}
		return DefaultRTPDTMFPayloadType, clockRate, true
	}
	var bestPayload uint8
	var bestClock int
	found := false
	for payload, clockRate := range payloads {
		if clockRate <= 0 {
			clockRate = DefaultRTPDTMFClockRate
		}
		if preferredClock > 0 && clockRate != preferredClock {
			continue
		}
		if !found || payload < bestPayload {
			bestPayload = payload
			bestClock = clockRate
			found = true
		}
	}
	if found {
		return bestPayload, bestClock, true
	}
	for payload, clockRate := range payloads {
		if clockRate <= 0 {
			clockRate = DefaultRTPDTMFClockRate
		}
		if !found || payload < bestPayload {
			bestPayload = payload
			bestClock = clockRate
			found = true
		}
	}
	return bestPayload, bestClock, found
}

func rtpDTMFDurationMS(durationMS int) int {
	if durationMS <= 0 {
		return DefaultDTMFDurationMS
	}
	return durationMS
}

func rtpDTMFStepMS(stepMS, durationMS int) int {
	if durationMS <= 0 {
		durationMS = DefaultDTMFDurationMS
	}
	if stepMS <= 0 {
		stepMS = DefaultRTPDTMFStepMS
	}
	if stepMS > durationMS {
		return durationMS
	}
	return stepMS
}

func waitRTPDTMFInterval(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func newRTPDTMFSequenceState() rtpDTMFSequenceState {
	return rtpDTMFSequenceState{
		nextSeq:       uint16(randomRTPDTMFUint32()),
		nextTimestamp: randomRTPDTMFUint32(),
		ssrc:          randomRTPDTMFNonZeroUint32(),
	}
}

func randomRTPDTMFNonZeroUint32() uint32 {
	v := randomRTPDTMFUint32()
	if v != 0 {
		return v
	}
	return uint32(time.Now().UnixNano()) | 1
}

func randomRTPDTMFUint32() uint32 {
	var b [4]byte
	if _, err := crand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint32(b[:])
	}
	return uint32(time.Now().UnixNano())
}

func (s *RTPRelaySession) allowClientToIMSRTP() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	clientDirection := s.clientDirection
	imsDirection := s.imsDirection
	s.mu.RUnlock()
	return sdpDirectionAllowsSend(clientDirection) && sdpDirectionAllowsReceive(imsDirection)
}

func (s *RTPRelaySession) allowIMSToClientRTP() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	clientDirection := s.clientDirection
	imsDirection := s.imsDirection
	s.mu.RUnlock()
	return sdpDirectionAllowsSend(imsDirection) && sdpDirectionAllowsReceive(clientDirection)
}

func normalizeSDPDirection(direction string) string {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "sendonly", "recvonly", "inactive":
		return strings.ToLower(strings.TrimSpace(direction))
	default:
		return "sendrecv"
	}
}

func sdpDirectionAllowsSend(direction string) bool {
	switch normalizeSDPDirection(direction) {
	case "sendrecv", "sendonly":
		return true
	default:
		return false
	}
}

func sdpDirectionAllowsReceive(direction string) bool {
	switch normalizeSDPDirection(direction) {
	case "sendrecv", "recvonly":
		return true
	default:
		return false
	}
}

func (s *RTPRelaySession) inspectRTCPFeedback(direction RTCPFeedbackDirection, packet []byte) {
	if s == nil {
		return
	}
	summary, err := InspectRTCPFeedback(direction, packet, s.rtcpFeedbackHandler)
	if err != nil {
		s.rtcpFeedbackParseErrors.Add(1)
		return
	}
	s.recordRTCPFeedbackSummary(summary)
}

func (s *RTPRelaySession) recordRTCPFeedbackSummary(summary RTCPFeedbackSummary) {
	if s == nil {
		return
	}
	s.rtcpFeedbackPackets.Add(summary.Packets)
	s.rtcpSenderReports.Add(summary.SenderReports)
	s.rtcpReceiverReports.Add(summary.ReceiverReports)
	s.rtcpPictureLossIndications.Add(summary.PictureLossIndications)
	s.rtcpFullIntraRequests.Add(summary.FullIntraRequests)
	s.rtcpRapidResynchronizationRequests.Add(summary.RapidResynchronizationRequests)
	s.rtcpTransportLayerNacks.Add(summary.TransportLayerNacks)
	s.rtcpReceiverEstimatedMaximumBitrates.Add(summary.ReceiverEstimatedMaximumBitrates)
	s.rtcpTransportLayerCongestionControls.Add(summary.TransportLayerCongestionControls)
	s.rtcpSliceLossIndications.Add(summary.SliceLossIndications)
	s.rtcpExtendedReports.Add(summary.ExtendedReports)
	s.rtcpSourceDescriptions.Add(summary.SourceDescriptions)
	s.rtcpGoodbyes.Add(summary.Goodbyes)
	s.rtcpApplicationDefined.Add(summary.ApplicationDefined)
	s.rtcpUnknownPackets.Add(summary.UnknownPackets)
}

func (s *RTPRelaySession) currentIMSTarget() *net.UDPAddr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.imsTarget == nil {
		return nil
	}
	cp := *s.imsTarget
	return &cp
}

func (s *RTPRelaySession) currentIMSRTCPTarget() *net.UDPAddr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.imsRTCPTarget == nil {
		return nil
	}
	cp := *s.imsRTCPTarget
	return &cp
}

func (s *RTPRelaySession) currentClientTarget() *net.UDPAddr {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.clientTarget == nil {
		return nil
	}
	cp := *s.clientTarget
	return &cp
}

func (s *RTPRelaySession) currentClientRTCPTarget() *net.UDPAddr {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.clientRTCPTarget == nil {
		return nil
	}
	cp := *s.clientRTCPTarget
	return &cp
}

func (s *RTPRelaySession) currentClientRTPDTMFPayloads() map[uint8]int {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRTPDTMFPayloadTypes(s.clientRTPDTMFPayloads)
}

func (s *RTPRelaySession) currentIMSRTPDTMFPayloads() map[uint8]int {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRTPDTMFPayloadTypes(s.imsRTPDTMFPayloads)
}

func (s *RTPRelaySession) clientPort() int {
	if s == nil || s.clientConn == nil {
		return 0
	}
	return udpLocalPort(s.clientConn)
}

func (s *RTPRelaySession) clientRTCPPort() int {
	if s == nil || s.clientRTCPConn == nil {
		return 0
	}
	return udpLocalPort(s.clientRTCPConn)
}

func (s *RTPRelaySession) imsPort() int {
	if s == nil || s.imsConn == nil {
		return 0
	}
	return udpLocalPort(s.imsConn)
}

func (s *RTPRelaySession) imsRTCPPort() int {
	if s == nil || s.imsRTCPConn == nil {
		return 0
	}
	return udpLocalPort(s.imsRTCPConn)
}

func listenUDP(host string, port int) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", addr)
}

func udpLocalPort(conn *net.UDPConn) int {
	if conn == nil {
		return 0
	}
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.Port
	}
	return 0
}

func resolveSDPEndpoint(info SDPInfo, label string) (*net.UDPAddr, *net.UDPAddr, error) {
	if info.MediaPort == 0 {
		return nil, nil, nil
	}
	if strings.TrimSpace(info.ConnectionIP) == "" || info.MediaPort < 0 {
		return nil, nil, fmt.Errorf("%w: %s media target is incomplete", ErrRTPRelayConfig, label)
	}
	if ip := net.ParseIP(strings.TrimSpace(info.ConnectionIP)); ip != nil && ip.IsUnspecified() {
		return nil, nil, nil
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(strings.TrimSpace(info.ConnectionIP), strconv.Itoa(info.MediaPort)))
	if err != nil {
		return nil, nil, err
	}
	rtcpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(defaultRTCPIP(info), strconv.Itoa(defaultRTCPPort(info))))
	if err != nil {
		return nil, nil, err
	}
	return addr, rtcpAddr, nil
}

func defaultRTCPPort(info SDPInfo) int {
	if info.RTCPPort > 0 {
		return info.RTCPPort
	}
	if info.MediaPort > 0 {
		return info.MediaPort + 1
	}
	return 0
}

func defaultRTCPIP(info SDPInfo) string {
	if strings.TrimSpace(info.RTCPIP) != "" {
		return strings.TrimSpace(info.RTCPIP)
	}
	return strings.TrimSpace(info.ConnectionIP)
}

func advertiseIP(explicit, listenIP string) string {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit)
	}
	ip := strings.TrimSpace(listenIP)
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		return "127.0.0.1"
	}
	return ip
}
