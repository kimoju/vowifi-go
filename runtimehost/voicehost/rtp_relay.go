package voicehost

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/rtcp"
)

var ErrRTPRelayConfig = errors.New("invalid rtp relay config")

type RTPRelayConfig struct {
	ClientListenIP      string
	ClientAdvertiseIP   string
	ClientPort          int
	ClientRTCPPort      int
	ClientRTPClockRate  int
	IMSListenIP         string
	IMSAdvertiseIP      string
	IMSPort             int
	IMSRTCPPort         int
	IMSRTPClockRate     int
	BufferSize          int
	Transforms          RTPRelayTransforms
	SRTP                *RTPRelaySRTPConfig
	RTCPFeedbackHandler RTCPFeedbackHandler
	RTPDTMFHandler      RTPDTMFHandler
	RTPQualityHandler   RTPRelayQualityHandler
	RTPQualityConfig    RTPRelayQualityConfig
	RTCPReportSchedule  RTPRelayRTCPReportScheduleConfig
	implicitIMSListenIP bool
}

type RTPRelayTransform func([]byte) ([]byte, error)

type RTPRelayTransforms struct {
	ClientToIMSRTP        RTPRelayTransform
	IMSToClientRTP        RTPRelayTransform
	ClientToIMSRTCP       RTPRelayTransform
	IMSToClientRTCP       RTPRelayTransform
	GeneratedToIMSRTP     RTPRelayTransform
	GeneratedToClientRTP  RTPRelayTransform
	GeneratedToIMSRTCP    RTPRelayTransform
	GeneratedToClientRTCP RTPRelayTransform
}

type rtpRelayTransformSelector func(RTPRelayTransforms) RTPRelayTransform

type RTPRelayDTMFRequest struct {
	Direction      RTPDTMFDirection
	Signal         string
	DurationMS     int
	StepMS         int
	EndPacketCount int
	Volume         uint8
	HasVolume      bool
	SequenceNumber uint16
	Timestamp      uint32
	SSRC           uint32
	PayloadType    uint8
	HasPayloadType bool
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

type RTPRelayRTCPRequest struct {
	Direction RTCPFeedbackDirection
	Packets   []rtcp.Packet
}

type RTPRelayRTCPResult struct {
	Datagrams int
	Bytes     int
	Feedback  RTCPFeedbackSummary
}

type RTPRelayReceiverReportRequest struct {
	Direction  RTCPFeedbackDirection
	SenderSSRC uint32
	CNAME      string
}

type RTPRelaySenderReportRequest struct {
	Direction   RTCPFeedbackDirection
	SSRC        uint32
	CNAME       string
	NTPTime     uint64
	WallClock   time.Time
	RTPTime     uint32
	PacketCount uint32
	OctetCount  uint32
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
	ClientToIMSRTPStreams                []RTPStreamStats
	IMSToClientRTPStreams                []RTPStreamStats
}

type RTPRelayQualityStats struct {
	ClientToIMS             RTPRelayDirectionQuality
	IMSToClient             RTPRelayDirectionQuality
	RTCPFeedback            RTCPFeedbackSummary
	RTCPFeedbackParseErrors uint64
}

type RTPRelayQualityHandler func(RTPRelayQualityEvent)

type RTPRelayQualityConfig struct {
	ClientToIMS RTPStreamDiagnosisConfig
	IMSToClient RTPStreamDiagnosisConfig
	EmitInitial bool
}

type RTPRelayQualityEvent struct {
	Direction      RTCPFeedbackDirection
	Status         RTPStreamDiagnosisStatus
	PreviousStatus RTPStreamDiagnosisStatus
	Reasons        []RTPStreamDiagnosisReason
	Quality        RTPRelayDirectionQuality
	Diagnoses      []RTPStreamDiagnosis
	ObservedAt     time.Time
}

type RTPRelayDirectionQuality struct {
	Direction             RTCPFeedbackDirection
	RTPPackets            uint64
	RTPBytes              uint64
	RTPDrops              uint64
	RTCPPackets           uint64
	RTCPBytes             uint64
	RTCPDrops             uint64
	RTPReceivedPackets    uint64
	RTPExpectedPackets    uint64
	RTPLostPackets        uint64
	RTPDuplicatePackets   uint64
	RTPOutOfOrderPackets  uint64
	RTPSequenceRollovers  uint64
	RTPTimestampRollovers uint64
	RTPFractionLost       uint8
	RTPMaxJitter          uint32
	RTPStreams            []RTPStreamStats
	RTCPReports           []RTPRelayRTCPReportQuality
	RTCPMaxRoundTripTime  time.Duration
}

type RTPRelayRTCPReportQuality struct {
	Direction          RTCPFeedbackDirection
	ReporterSSRC       uint32
	MediaSSRC          uint32
	FractionLost       uint8
	TotalLost          uint32
	LastSequenceNumber uint32
	Jitter             uint32
	LastSenderReport   uint32
	Delay              uint32
	RoundTripTime      time.Duration
}

// RTPRelayQualityAction is a recovery hint for media quality degradation.
type RTPRelayQualityAction string

const (
	RTPRelayQualityActionNone                 RTPRelayQualityAction = "none"
	RTPRelayQualityActionMonitor              RTPRelayQualityAction = "monitor"
	RTPRelayQualityActionIncreaseJitterBuffer RTPRelayQualityAction = "increase_jitter_buffer"
	RTPRelayQualityActionReduceBitrate        RTPRelayQualityAction = "reduce_bitrate"
	RTPRelayQualityActionRecoverMediaPath     RTPRelayQualityAction = "recover_media_path"
)

// RTPRelayRTCPReportDiagnosis classifies one remote RTCP reception report.
type RTPRelayRTCPReportDiagnosis struct {
	Direction     RTCPFeedbackDirection
	ReporterSSRC  uint32
	MediaSSRC     uint32
	Status        RTPStreamDiagnosisStatus
	Reasons       []RTPStreamDiagnosisReason
	Action        RTPRelayQualityAction
	Loss          RTPRelayRTCPReportLossDiagnosis
	Jitter        RTPRelayRTCPReportJitterDiagnosis
	RoundTripTime RTPRelayRTCPReportRoundTripTimeDiagnosis
}

// RTPRelayRTCPReportLossDiagnosis classifies the report-block loss fields.
type RTPRelayRTCPReportLossDiagnosis struct {
	Status       RTPStreamDiagnosisStatus
	FractionLost uint8
	TotalLost    uint32
}

// RTPRelayRTCPReportJitterDiagnosis classifies report-block jitter using the configured clock rate.
type RTPRelayRTCPReportJitterDiagnosis struct {
	Status   RTPStreamDiagnosisStatus
	Jitter   uint32
	Duration time.Duration
}

// RTPRelayRTCPReportRoundTripTimeDiagnosis classifies RTT computed from LSR/DLSR timing.
type RTPRelayRTCPReportRoundTripTimeDiagnosis struct {
	Status        RTPStreamDiagnosisStatus
	RoundTripTime time.Duration
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
	clientCodecs          []SDPCodec
	imsCodecs             []SDPCodec

	clientAdvertiseIP  string
	imsAdvertiseIP     string
	bufferSize         int
	clientRTPClockRate int
	imsRTPClockRate    int

	cancel context.CancelFunc
	wg     sync.WaitGroup

	rtcpReportScheduleMu sync.Mutex
	rtcpReportSchedule   *rtpRelayRTCPReportScheduler

	dtmfMu                 sync.Mutex
	dtmfClientToIMSState   rtpDTMFSequenceState
	dtmfIMSToClientState   rtpDTMFSequenceState
	rtpStatsMu             sync.Mutex
	clientToIMSRTPStats    RTPStreamStatsTracker
	imsToClientRTPStats    RTPStreamStatsTracker
	rtcpQualityMu          sync.Mutex
	clientToIMSRTCPReports map[rtpRelayRTCPReportKey]RTPRelayRTCPReportQuality
	imsToClientRTCPReports map[rtpRelayRTCPReportKey]RTPRelayRTCPReportQuality
	rtcpSenderReportTiming map[rtpRelayRTCPSenderReportKey]rtpRelayRTCPSenderReportTiming
	qualityEventMu         sync.Mutex
	qualityEventState      map[RTCPFeedbackDirection]rtpRelayQualitySignature

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
	rtpQualityHandler                    RTPRelayQualityHandler
	rtpQualityConfig                     RTPRelayQualityConfig
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
	nextSeq            uint16
	nextTimestamp      uint32
	ssrc               uint32
	hasAudio           bool
	hasSentDTMF        bool
	audioSSRC          uint32
	lastAudioOrigSeq   uint16
	lastAudioTimestamp uint32
	lastAudioArrival   time.Time
	audioClockRate     int
	seqOffset          uint16
	lastScheduledSent  uint64
}

type rtpRelayRTCPReportKey struct {
	reporterSSRC uint32
	mediaSSRC    uint32
}

type rtpRelayRTCPSenderReportKey struct {
	direction RTCPFeedbackDirection
	ssrc      uint32
}

type rtpRelayRTCPSenderReportTiming struct {
	lastSenderReport uint32
	observedAt       time.Time
}

type rtpRelayQualitySignature struct {
	status  RTPStreamDiagnosisStatus
	reasons string
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clientListenIP := firstVoiceNonEmpty(cfg.ClientListenIP, "0.0.0.0")
	imsListenIP := firstVoiceNonEmpty(cfg.IMSListenIP, clientListenIP)
	clientConn, err := listenUDP(clientListenIP, cfg.ClientPort)
	if err != nil {
		return nil, err
	}
	imsConn, imsListenIP, err := listenIMSUDP(imsListenIP, cfg.IMSPort, cfg.implicitIMSListenIP)
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
	imsRTCPConn, _, err := listenIMSUDP(imsListenIP, cfg.IMSRTCPPort, cfg.implicitIMSListenIP)
	if err != nil {
		_ = clientConn.Close()
		_ = imsConn.Close()
		_ = clientRTCPConn.Close()
		return nil, err
	}
	childCtx, cancel := context.WithCancel(context.Background())
	s := &RTPRelaySession{
		clientConn:           clientConn,
		imsConn:              imsConn,
		clientRTCPConn:       clientRTCPConn,
		imsRTCPConn:          imsRTCPConn,
		clientAdvertiseIP:    advertiseIP(cfg.ClientAdvertiseIP, clientListenIP),
		imsAdvertiseIP:       advertiseIP(cfg.IMSAdvertiseIP, imsListenIP),
		bufferSize:           cfg.BufferSize,
		clientRTPClockRate:   relayRTPClockRate(cfg.ClientRTPClockRate),
		imsRTPClockRate:      relayRTPClockRate(cfg.IMSRTPClockRate),
		cancel:               cancel,
		transforms:           cfg.Transforms,
		rtcpFeedbackHandler:  cfg.RTCPFeedbackHandler,
		rtpDTMFHandler:       cfg.RTPDTMFHandler,
		rtpQualityHandler:    cfg.RTPQualityHandler,
		rtpQualityConfig:     cfg.RTPQualityConfig,
		dtmfClientToIMSState: newRTPDTMFSequenceState(),
		dtmfIMSToClientState: newRTPDTMFSequenceState(),
	}
	if s.bufferSize <= 0 {
		s.bufferSize = 2048
	}
	s.wg.Add(4)
	go s.forwardLoop(childCtx, s.clientConn, s.imsConn, s.currentIMSTarget, s.allowClientToIMSRTP, &s.clientToIMSRTPPackets, &s.clientToIMSRTPBytes, &s.clientToIMSRTPDrops, selectClientToIMSRTPTransform, "", RTPDTMFClientToIMS, s.currentClientRTPDTMFPayloads, s.currentIMSRTPDTMFPayloads, RTPDTMFClientToIMS, s.clientRTPClockRate)
	go s.forwardLoop(childCtx, s.imsConn, s.clientConn, s.currentClientTarget, s.allowIMSToClientRTP, &s.imsToClientRTPPackets, &s.imsToClientRTPBytes, &s.imsToClientRTPDrops, selectIMSToClientRTPTransform, "", RTPDTMFIMSToClient, s.currentIMSRTPDTMFPayloads, s.currentClientRTPDTMFPayloads, RTPDTMFIMSToClient, s.imsRTPClockRate)
	go s.forwardLoop(childCtx, s.clientRTCPConn, s.imsRTCPConn, s.currentIMSRTCPTarget, nil, &s.clientToIMSRTCPPackets, &s.clientToIMSRTCPBytes, &s.clientToIMSRTCPDrops, selectClientToIMSRTCPTransform, RTCPFeedbackClientToIMS, "", nil, nil, "", 0)
	go s.forwardLoop(childCtx, s.imsRTCPConn, s.clientRTCPConn, s.currentClientRTCPTarget, nil, &s.imsToClientRTCPPackets, &s.imsToClientRTCPBytes, &s.imsToClientRTCPDrops, selectIMSToClientRTCPTransform, RTCPFeedbackIMSToClient, "", nil, nil, "", 0)
	if err := s.StartRTCPReportSchedule(childCtx, cfg.RTCPReportSchedule); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *RTPRelaySession) SetTransforms(transforms RTPRelayTransforms) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("%w: relay is closed", ErrRTPRelayConfig)
	}
	s.transforms = transforms
	return nil
}

func (s *RTPRelaySession) Transforms() RTPRelayTransforms {
	if s == nil {
		return RTPRelayTransforms{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.transforms
}

func (s *RTPRelaySession) IMSOfferSDP(clientOffer SDPInfo) []byte {
	return BuildSDPAnswer(relayAdvertisedSDP(clientOffer, s.imsAdvertiseIP, s.imsPort(), s.imsRTCPPort()))
}

func (s *RTPRelaySession) ClientAnswerSDP(imsAnswer SDPInfo) []byte {
	return BuildSDPAnswer(relayAdvertisedSDP(imsAnswer, s.clientAdvertiseIP, s.clientPort(), s.clientRTCPPort()))
}

func relayAdvertisedSDP(info SDPInfo, advertiseIP string, mediaPort, rtcpPort int) SDPInfo {
	out := info
	if out.MediaPort <= 0 {
		out.MediaPort = 0
		out.RTCPIP = ""
		out.RTCPPort = 0
		out.Direction = "inactive"
		return out
	}
	if sdpConnectionIsUnspecified(out.ConnectionIP) {
		out.Direction = "inactive"
		return out
	}
	if normalizeSDPDirection(out.Direction) == "inactive" {
		out.Direction = "inactive"
		return out
	}
	out.ConnectionIP = advertiseIP
	out.MediaPort = mediaPort
	out.RTCPIP = advertiseIP
	out.RTCPPort = rtcpPort
	return out
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
	if len(info.Codecs) > 0 {
		s.imsCodecs = cloneSDPCodecs(info.Codecs)
	}
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
	if len(info.Codecs) > 0 {
		s.clientCodecs = cloneSDPCodecs(info.Codecs)
	}
	s.mu.Unlock()
	return nil
}

func (s *RTPRelaySession) SetClientCodecs(codecs []SDPCodec) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.clientCodecs = cloneSDPCodecs(codecs)
	s.mu.Unlock()
}

func (s *RTPRelaySession) SetIMSCodecs(codecs []SDPCodec) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.imsCodecs = cloneSDPCodecs(codecs)
	s.mu.Unlock()
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
	clientToIMSStreams := s.ClientToIMSRTPStreamStats()
	imsToClientStreams := s.IMSToClientRTPStreamStats()
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
		ClientToIMSRTPStreams:                clientToIMSStreams,
		IMSToClientRTPStreams:                imsToClientStreams,
	}
}

func (s *RTPRelaySession) Quality() RTPRelayQualityStats {
	if s == nil {
		return RTPRelayQualityStats{}
	}
	stats := s.Stats()
	return RTPRelayQualityStats{
		ClientToIMS: newRTPRelayDirectionQuality(
			RTCPFeedbackClientToIMS,
			stats.ClientToIMSRTPPackets,
			stats.ClientToIMSRTPBytes,
			stats.ClientToIMSRTPDrops,
			stats.ClientToIMSRTCPPackets,
			stats.ClientToIMSRTCPBytes,
			stats.ClientToIMSRTCPDrops,
			stats.ClientToIMSRTPStreams,
			s.rtcpReportQuality(RTCPFeedbackClientToIMS),
		),
		IMSToClient: newRTPRelayDirectionQuality(
			RTCPFeedbackIMSToClient,
			stats.IMSToClientRTPPackets,
			stats.IMSToClientRTPBytes,
			stats.IMSToClientRTPDrops,
			stats.IMSToClientRTCPPackets,
			stats.IMSToClientRTCPBytes,
			stats.IMSToClientRTCPDrops,
			stats.IMSToClientRTPStreams,
			s.rtcpReportQuality(RTCPFeedbackIMSToClient),
		),
		RTCPFeedback: RTCPFeedbackSummary{
			Packets:                          stats.RTCPFeedbackPackets,
			SenderReports:                    stats.RTCPSenderReports,
			ReceiverReports:                  stats.RTCPReceiverReports,
			PictureLossIndications:           stats.RTCPPictureLossIndications,
			FullIntraRequests:                stats.RTCPFullIntraRequests,
			RapidResynchronizationRequests:   stats.RTCPRapidResynchronizationRequests,
			TransportLayerNacks:              stats.RTCPTransportLayerNacks,
			ReceiverEstimatedMaximumBitrates: stats.RTCPReceiverEstimatedMaximumBitrates,
			TransportLayerCongestionControls: stats.RTCPTransportLayerCongestionControls,
			SliceLossIndications:             stats.RTCPSliceLossIndications,
			ExtendedReports:                  stats.RTCPExtendedReports,
			SourceDescriptions:               stats.RTCPSourceDescriptions,
			Goodbyes:                         stats.RTCPGoodbyes,
			ApplicationDefined:               stats.RTCPApplicationDefined,
			UnknownPackets:                   stats.RTCPUnknownPackets,
		},
		RTCPFeedbackParseErrors: stats.RTCPFeedbackParseErrors,
	}
}

func (s *RTPRelaySession) ClientToIMSRTPStreamStats() []RTPStreamStats {
	if s == nil {
		return nil
	}
	s.rtpStatsMu.Lock()
	defer s.rtpStatsMu.Unlock()
	return s.clientToIMSRTPStats.Stats()
}

func (s *RTPRelaySession) IMSToClientRTPStreamStats() []RTPStreamStats {
	if s == nil {
		return nil
	}
	s.rtpStatsMu.Lock()
	defer s.rtpStatsMu.Unlock()
	return s.imsToClientRTPStats.Stats()
}

func (s *RTPRelaySession) takeClientToIMSRTPStreamStats() []RTPStreamStats {
	if s == nil {
		return nil
	}
	s.rtpStatsMu.Lock()
	defer s.rtpStatsMu.Unlock()
	return s.clientToIMSRTPStats.TakeRTCPReportStats()
}

func (s *RTPRelaySession) takeIMSToClientRTPStreamStats() []RTPStreamStats {
	if s == nil {
		return nil
	}
	s.rtpStatsMu.Lock()
	defer s.rtpStatsMu.Unlock()
	return s.imsToClientRTPStats.TakeRTCPReportStats()
}

func newRTPRelayDirectionQuality(direction RTCPFeedbackDirection, rtpPackets, rtpBytes, rtpDrops, rtcpPackets, rtcpBytes, rtcpDrops uint64, streams []RTPStreamStats, reports []RTPRelayRTCPReportQuality) RTPRelayDirectionQuality {
	quality := RTPRelayDirectionQuality{
		Direction:   direction,
		RTPPackets:  rtpPackets,
		RTPBytes:    rtpBytes,
		RTPDrops:    rtpDrops,
		RTCPPackets: rtcpPackets,
		RTCPBytes:   rtcpBytes,
		RTCPDrops:   rtcpDrops,
		RTPStreams:  append([]RTPStreamStats(nil), streams...),
		RTCPReports: append([]RTPRelayRTCPReportQuality(nil), reports...),
	}
	for _, stream := range streams {
		quality.RTPReceivedPackets += stream.Packets
		quality.RTPExpectedPackets += stream.ExpectedPackets
		quality.RTPLostPackets += stream.LostPackets
		quality.RTPDuplicatePackets += stream.DuplicatePackets
		quality.RTPOutOfOrderPackets += stream.OutOfOrderPackets
		quality.RTPSequenceRollovers += uint64(stream.SequenceRollovers)
		quality.RTPTimestampRollovers += uint64(stream.TimestampRollovers)
		if stream.Jitter > quality.RTPMaxJitter {
			quality.RTPMaxJitter = stream.Jitter
		}
	}
	for _, report := range reports {
		if report.RoundTripTime > quality.RTCPMaxRoundTripTime {
			quality.RTCPMaxRoundTripTime = report.RoundTripTime
		}
	}
	quality.RTPFractionLost = rtpRelayFractionLost(quality.RTPLostPackets, quality.RTPExpectedPackets)
	return quality
}

func rtpRelayFractionLost(lost, expected uint64) uint8 {
	if lost == 0 || expected == 0 {
		return 0
	}
	fraction := lost * 256 / expected
	if fraction > 255 {
		return 255
	}
	return uint8(fraction)
}

// DiagnoseRTPRelayRTCPReports classifies remote RTCP reception reports and
// preserves the input order.
func DiagnoseRTPRelayRTCPReports(reports []RTPRelayRTCPReportQuality, cfg RTPStreamDiagnosisConfig) []RTPRelayRTCPReportDiagnosis {
	if len(reports) == 0 {
		return nil
	}
	out := make([]RTPRelayRTCPReportDiagnosis, 0, len(reports))
	for _, report := range reports {
		out = append(out, report.Diagnose(cfg))
	}
	return out
}

// DiagnoseRTCPReports classifies the RTCP reports already present in a quality snapshot.
func (q RTPRelayDirectionQuality) DiagnoseRTCPReports(cfg RTPStreamDiagnosisConfig) []RTPRelayRTCPReportDiagnosis {
	return DiagnoseRTPRelayRTCPReports(q.RTCPReports, cfg)
}

// Diagnose classifies loss, jitter, and RTT for one remote RTCP reception report.
func (r RTPRelayRTCPReportQuality) Diagnose(cfg RTPStreamDiagnosisConfig) RTPRelayRTCPReportDiagnosis {
	cfg = normalizeRTPStreamDiagnosisConfig(cfg)
	diagnosis := RTPRelayRTCPReportDiagnosis{
		Direction:     r.Direction,
		ReporterSSRC:  r.ReporterSSRC,
		MediaSSRC:     r.MediaSSRC,
		Status:        RTPStreamDiagnosisStatusUnknown,
		Loss:          diagnoseRTPRelayRTCPReportLoss(r, cfg),
		Jitter:        diagnoseRTPRelayRTCPReportJitter(r, cfg),
		RoundTripTime: diagnoseRTPRelayRTCPReportRoundTripTime(r, cfg),
	}
	diagnosis.addMetric(diagnosis.Loss.Status, RTPStreamDiagnosisReasonPacketLoss)
	diagnosis.addMetric(diagnosis.Jitter.Status, RTPStreamDiagnosisReasonJitter)
	diagnosis.addMetric(diagnosis.RoundTripTime.Status, RTPStreamDiagnosisReasonRoundTripTime)
	diagnosis.Action = rtpRelayRTCPReportAction(diagnosis)
	return diagnosis
}

func (s *RTPRelaySession) emitRTPQualityEventIfChanged(direction RTCPFeedbackDirection, observedAt time.Time) {
	if s == nil || s.rtpQualityHandler == nil {
		return
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	quality := s.rtpRelayDirectionQuality(direction)
	diagnosisConfig := s.rtpQualityDiagnosisConfig(direction)
	diagnoses := DiagnoseRTPStreamStats(quality.RTPStreams, diagnosisConfig)
	status, reasons := summarizeRTPRelayQualityDiagnoses(diagnoses)
	status, reasons = summarizeRTPRelayRTCPReportQuality(quality.RTCPReports, diagnosisConfig, status, reasons)
	if status == RTPStreamDiagnosisStatusUnknown {
		return
	}
	signature := newRTPRelayQualitySignature(status, reasons)
	previousStatus := RTPStreamDiagnosisStatusUnknown
	emit := false

	s.qualityEventMu.Lock()
	if s.qualityEventState == nil {
		s.qualityEventState = make(map[RTCPFeedbackDirection]rtpRelayQualitySignature)
	}
	previous, ok := s.qualityEventState[direction]
	if ok {
		previousStatus = previous.status
	}
	switch {
	case !ok:
		s.qualityEventState[direction] = signature
		emit = s.rtpQualityConfig.EmitInitial || rtpStreamDiagnosisStatusRank(status) >= rtpStreamDiagnosisStatusRank(RTPStreamDiagnosisStatusWarning)
	case previous != signature:
		s.qualityEventState[direction] = signature
		emit = true
	}
	s.qualityEventMu.Unlock()

	if !emit {
		return
	}
	emitRTPRelayQuality(s.rtpQualityHandler, RTPRelayQualityEvent{
		Direction:      direction,
		Status:         status,
		PreviousStatus: previousStatus,
		Reasons:        append([]RTPStreamDiagnosisReason(nil), reasons...),
		Quality:        quality,
		Diagnoses:      cloneRTPStreamDiagnoses(diagnoses),
		ObservedAt:     observedAt,
	})
}

func (s *RTPRelaySession) rtpRelayDirectionQuality(direction RTCPFeedbackDirection) RTPRelayDirectionQuality {
	stats := s.Stats()
	switch direction {
	case RTCPFeedbackIMSToClient:
		return newRTPRelayDirectionQuality(
			RTCPFeedbackIMSToClient,
			stats.IMSToClientRTPPackets,
			stats.IMSToClientRTPBytes,
			stats.IMSToClientRTPDrops,
			stats.IMSToClientRTCPPackets,
			stats.IMSToClientRTCPBytes,
			stats.IMSToClientRTCPDrops,
			stats.IMSToClientRTPStreams,
			s.rtcpReportQuality(RTCPFeedbackIMSToClient),
		)
	default:
		return newRTPRelayDirectionQuality(
			RTCPFeedbackClientToIMS,
			stats.ClientToIMSRTPPackets,
			stats.ClientToIMSRTPBytes,
			stats.ClientToIMSRTPDrops,
			stats.ClientToIMSRTCPPackets,
			stats.ClientToIMSRTCPBytes,
			stats.ClientToIMSRTCPDrops,
			stats.ClientToIMSRTPStreams,
			s.rtcpReportQuality(RTCPFeedbackClientToIMS),
		)
	}
}

func (s *RTPRelaySession) rtpQualityDiagnosisConfig(direction RTCPFeedbackDirection) RTPStreamDiagnosisConfig {
	if s == nil {
		return RTPStreamDiagnosisConfig{}
	}
	cfg := s.rtpQualityConfig.ClientToIMS
	clockRate := s.clientRTPClockRate
	if direction == RTCPFeedbackIMSToClient {
		cfg = s.rtpQualityConfig.IMSToClient
		clockRate = s.imsRTPClockRate
	}
	if cfg.ClockRate <= 0 {
		cfg.ClockRate = relayRTPClockRate(clockRate)
	}
	return cfg
}

func summarizeRTPRelayQualityDiagnoses(diagnoses []RTPStreamDiagnosis) (RTPStreamDiagnosisStatus, []RTPStreamDiagnosisReason) {
	status := RTPStreamDiagnosisStatusUnknown
	if len(diagnoses) == 0 {
		return status, nil
	}
	var reasons []RTPStreamDiagnosisReason
	seenReasons := make(map[RTPStreamDiagnosisReason]struct{})
	for _, diagnosis := range diagnoses {
		if rtpStreamDiagnosisStatusRank(diagnosis.Status) > rtpStreamDiagnosisStatusRank(status) {
			status = diagnosis.Status
		}
		for _, reason := range diagnosis.Reasons {
			if _, ok := seenReasons[reason]; ok {
				continue
			}
			seenReasons[reason] = struct{}{}
			reasons = append(reasons, reason)
		}
	}
	return status, reasons
}

func summarizeRTPRelayRTCPReportQuality(reports []RTPRelayRTCPReportQuality, cfg RTPStreamDiagnosisConfig, status RTPStreamDiagnosisStatus, reasons []RTPStreamDiagnosisReason) (RTPStreamDiagnosisStatus, []RTPStreamDiagnosisReason) {
	diagnoses := DiagnoseRTPRelayRTCPReports(reports, cfg)
	if len(diagnoses) == 0 {
		return status, reasons
	}
	seenReasons := make(map[RTPStreamDiagnosisReason]struct{}, len(reasons))
	for _, reason := range reasons {
		seenReasons[reason] = struct{}{}
	}
	add := func(metric RTPStreamDiagnosisStatus, reason RTPStreamDiagnosisReason) {
		if rtpStreamDiagnosisStatusRank(metric) > rtpStreamDiagnosisStatusRank(status) {
			status = metric
		}
		if rtpStreamDiagnosisStatusRank(metric) < rtpStreamDiagnosisStatusRank(RTPStreamDiagnosisStatusWarning) {
			return
		}
		if _, ok := seenReasons[reason]; ok {
			return
		}
		seenReasons[reason] = struct{}{}
		reasons = append(reasons, reason)
	}
	for _, diagnosis := range diagnoses {
		add(diagnosis.Loss.Status, RTPStreamDiagnosisReasonPacketLoss)
		add(diagnosis.Jitter.Status, RTPStreamDiagnosisReasonJitter)
		add(diagnosis.RoundTripTime.Status, RTPStreamDiagnosisReasonRoundTripTime)
	}
	return status, reasons
}

func diagnoseRTPRelayRTCPReportLoss(report RTPRelayRTCPReportQuality, cfg RTPStreamDiagnosisConfig) RTPRelayRTCPReportLossDiagnosis {
	return RTPRelayRTCPReportLossDiagnosis{
		Status:       rtpRelayRTCPReportLossStatus(report, cfg),
		FractionLost: report.FractionLost,
		TotalLost:    report.TotalLost,
	}
}

func diagnoseRTPRelayRTCPReportJitter(report RTPRelayRTCPReportQuality, cfg RTPStreamDiagnosisConfig) RTPRelayRTCPReportJitterDiagnosis {
	diagnosis := RTPRelayRTCPReportJitterDiagnosis{
		Status: RTPStreamDiagnosisStatusUnknown,
		Jitter: report.Jitter,
	}
	if cfg.ClockRate <= 0 {
		return diagnosis
	}
	diagnosis.Duration = rtpTimestampUnitsDuration(report.Jitter, cfg.ClockRate)
	diagnosis.Status = rtpRelayRTCPReportJitterStatus(report, cfg)
	return diagnosis
}

func diagnoseRTPRelayRTCPReportRoundTripTime(report RTPRelayRTCPReportQuality, cfg RTPStreamDiagnosisConfig) RTPRelayRTCPReportRoundTripTimeDiagnosis {
	diagnosis := RTPRelayRTCPReportRoundTripTimeDiagnosis{
		Status:        RTPStreamDiagnosisStatusUnknown,
		RoundTripTime: report.RoundTripTime,
	}
	if report.RoundTripTime <= 0 {
		return diagnosis
	}
	switch {
	case report.RoundTripTime >= cfg.RoundTripCritical:
		diagnosis.Status = RTPStreamDiagnosisStatusCritical
	case report.RoundTripTime >= cfg.RoundTripWarning:
		diagnosis.Status = RTPStreamDiagnosisStatusWarning
	default:
		diagnosis.Status = RTPStreamDiagnosisStatusOK
	}
	return diagnosis
}

func rtpRelayRTCPReportLossStatus(report RTPRelayRTCPReportQuality, cfg RTPStreamDiagnosisConfig) RTPStreamDiagnosisStatus {
	switch {
	case report.FractionLost >= cfg.LossCriticalFraction:
		return RTPStreamDiagnosisStatusCritical
	case report.FractionLost >= cfg.LossWarningFraction:
		return RTPStreamDiagnosisStatusWarning
	default:
		return RTPStreamDiagnosisStatusOK
	}
}

func rtpRelayRTCPReportJitterStatus(report RTPRelayRTCPReportQuality, cfg RTPStreamDiagnosisConfig) RTPStreamDiagnosisStatus {
	if cfg.ClockRate <= 0 {
		return RTPStreamDiagnosisStatusUnknown
	}
	jitter := rtpTimestampUnitsDuration(report.Jitter, cfg.ClockRate)
	switch {
	case jitter >= cfg.JitterCritical:
		return RTPStreamDiagnosisStatusCritical
	case jitter >= cfg.JitterWarning:
		return RTPStreamDiagnosisStatusWarning
	default:
		return RTPStreamDiagnosisStatusOK
	}
}

func (d *RTPRelayRTCPReportDiagnosis) addMetric(status RTPStreamDiagnosisStatus, reason RTPStreamDiagnosisReason) {
	if rtpStreamDiagnosisStatusRank(status) > rtpStreamDiagnosisStatusRank(d.Status) {
		d.Status = status
	}
	if rtpStreamDiagnosisStatusRank(status) >= rtpStreamDiagnosisStatusRank(RTPStreamDiagnosisStatusWarning) {
		d.Reasons = append(d.Reasons, reason)
	}
}

func rtpRelayRTCPReportAction(diagnosis RTPRelayRTCPReportDiagnosis) RTPRelayQualityAction {
	if rtpStreamDiagnosisStatusRank(diagnosis.Status) < rtpStreamDiagnosisStatusRank(RTPStreamDiagnosisStatusWarning) {
		return RTPRelayQualityActionNone
	}
	if diagnosis.Loss.Status == RTPStreamDiagnosisStatusCritical ||
		diagnosis.RoundTripTime.Status == RTPStreamDiagnosisStatusCritical {
		return RTPRelayQualityActionRecoverMediaPath
	}
	if diagnosis.Jitter.Status == RTPStreamDiagnosisStatusCritical {
		return RTPRelayQualityActionIncreaseJitterBuffer
	}
	if diagnosis.Loss.Status == RTPStreamDiagnosisStatusWarning {
		return RTPRelayQualityActionReduceBitrate
	}
	if diagnosis.Jitter.Status == RTPStreamDiagnosisStatusWarning {
		return RTPRelayQualityActionIncreaseJitterBuffer
	}
	if diagnosis.RoundTripTime.Status == RTPStreamDiagnosisStatusWarning {
		return RTPRelayQualityActionMonitor
	}
	return RTPRelayQualityActionMonitor
}

func newRTPRelayQualitySignature(status RTPStreamDiagnosisStatus, reasons []RTPStreamDiagnosisReason) rtpRelayQualitySignature {
	parts := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		parts = append(parts, string(reason))
	}
	return rtpRelayQualitySignature{status: status, reasons: strings.Join(parts, "\x00")}
}

func cloneRTPStreamDiagnoses(in []RTPStreamDiagnosis) []RTPStreamDiagnosis {
	out := append([]RTPStreamDiagnosis(nil), in...)
	for i := range out {
		out[i].Reasons = append([]RTPStreamDiagnosisReason(nil), out[i].Reasons...)
	}
	return out
}

func emitRTPRelayQuality(handler RTPRelayQualityHandler, event RTPRelayQualityEvent) {
	if handler != nil {
		handler(event)
	}
}

func (s *RTPRelaySession) RTCPFeedbackHandler() RTCPFeedbackHandler {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rtcpFeedbackHandler
}

func (s *RTPRelaySession) RTPDTMFHandler() RTPDTMFHandler {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rtpDTMFHandler
}

func (s *RTPRelaySession) RTPPlaintextHandler() RTPPlaintextHandler {
	if s == nil {
		return nil
	}
	return s.ObserveRTPPlaintext
}

func (s *RTPRelaySession) RTPPlaintextRewriter() RTPPlaintextRewriter {
	if s == nil {
		return nil
	}
	return s.rewriteSRTPPlaintextRTP
}

func (s *RTPRelaySession) ObserveRTPPlaintext(event RTPPlaintextEvent) {
	if s == nil {
		return
	}
	clockRate := s.clientRTPClockRate
	if event.Direction == RTPDTMFIMSToClient {
		clockRate = s.imsRTPClockRate
	}
	s.observeRTPStream(event.Direction, event.Packet, time.Now(), clockRate)
}

func (s *RTPRelaySession) rewriteSRTPPlaintextRTP(direction RTPDTMFDirection, packet []byte) []byte {
	if s == nil {
		return packet
	}
	clockRate := s.clientRTPClockRate
	if direction == RTPDTMFIMSToClient {
		clockRate = s.imsRTPClockRate
	}
	return s.rewritePlaintextRTP(direction, packet, clockRate)
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
	s.StopRTCPReportSchedule()
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
	if len(route.payloads) == 0 && req.PayloadType == 0 && !req.HasPayloadType {
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
		summary, err := InspectRTPDTMF(direction, packet, payloads, s.RTPDTMFHandler())
		if err != nil {
			route.drops.Add(1)
			s.rtpDTMFParseErrors.Add(1)
			return result, err
		}
		s.recordRTPDTMFSummary(direction, summary)
		out := packet
		if transform := route.transform(); transform != nil {
			transformed, err := transform(packet)
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

func (s *RTPRelaySession) SendRTCPToIMS(ctx context.Context, packets ...rtcp.Packet) (RTPRelayRTCPResult, error) {
	return s.SendRTCP(ctx, RTPRelayRTCPRequest{Direction: RTCPFeedbackClientToIMS, Packets: packets})
}

func (s *RTPRelaySession) SendRTCPToClient(ctx context.Context, packets ...rtcp.Packet) (RTPRelayRTCPResult, error) {
	return s.SendRTCP(ctx, RTPRelayRTCPRequest{Direction: RTCPFeedbackIMSToClient, Packets: packets})
}

func (s *RTPRelaySession) SendRTCP(ctx context.Context, req RTPRelayRTCPRequest) (RTPRelayRTCPResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil {
		return RTPRelayRTCPResult{}, ErrRTPRelayConfig
	}
	direction, err := normalizeRTCPFeedbackDirection(req.Direction)
	if err != nil {
		return RTPRelayRTCPResult{}, err
	}
	if len(req.Packets) == 0 {
		return RTPRelayRTCPResult{}, fmt.Errorf("%w: RTCP packet list is empty", ErrRTPRelayConfig)
	}
	route, err := s.rtcpSendRoute(direction)
	if err != nil {
		return RTPRelayRTCPResult{}, err
	}
	if route.target == nil {
		return RTPRelayRTCPResult{}, fmt.Errorf("%w: %s RTCP target unavailable", ErrRTPRelayConfig, route.label)
	}
	if route.conn == nil {
		return RTPRelayRTCPResult{}, fmt.Errorf("%w: %s RTCP socket unavailable", ErrRTPRelayConfig, route.label)
	}
	select {
	case <-ctx.Done():
		return RTPRelayRTCPResult{}, ctx.Err()
	default:
	}
	packet, err := rtcp.Marshal(req.Packets)
	if err != nil {
		route.drops.Add(1)
		return RTPRelayRTCPResult{}, err
	}
	summary, err := s.inspectRTCPFeedbackPacket(direction, packet)
	if err != nil {
		route.drops.Add(1)
		s.rtcpFeedbackParseErrors.Add(1)
		return RTPRelayRTCPResult{}, err
	}
	s.recordRTCPFeedbackSummary(summary)
	out := packet
	if transform := route.transform(); transform != nil {
		transformed, err := transform(packet)
		if err != nil {
			route.drops.Add(1)
			return RTPRelayRTCPResult{Feedback: summary}, err
		}
		out = transformed
	}
	if _, err := route.conn.WriteToUDP(out, route.target); err != nil {
		route.drops.Add(1)
		return RTPRelayRTCPResult{Feedback: summary}, err
	}
	route.packets.Add(1)
	route.bytes.Add(uint64(len(out)))
	return RTPRelayRTCPResult{Datagrams: 1, Bytes: len(out), Feedback: summary}, nil
}

func (s *RTPRelaySession) SendReceiverReportToIMS(ctx context.Context, senderSSRC uint32) (RTPRelayRTCPResult, error) {
	return s.SendReceiverReport(ctx, RTPRelayReceiverReportRequest{Direction: RTCPFeedbackClientToIMS, SenderSSRC: senderSSRC})
}

func (s *RTPRelaySession) SendReceiverReportToClient(ctx context.Context, senderSSRC uint32) (RTPRelayRTCPResult, error) {
	return s.SendReceiverReport(ctx, RTPRelayReceiverReportRequest{Direction: RTCPFeedbackIMSToClient, SenderSSRC: senderSSRC})
}

func (s *RTPRelaySession) SendReceiverReport(ctx context.Context, req RTPRelayReceiverReportRequest) (RTPRelayRTCPResult, error) {
	if s == nil {
		return RTPRelayRTCPResult{}, ErrRTPRelayConfig
	}
	direction, err := normalizeRTCPFeedbackDirection(req.Direction)
	if err != nil {
		return RTPRelayRTCPResult{}, err
	}
	stats := s.takeIMSToClientRTPStreamStats()
	if direction == RTCPFeedbackIMSToClient {
		stats = s.takeClientToIMSRTPStreamStats()
	}
	senderSSRC := req.SenderSSRC
	if senderSSRC == 0 {
		senderSSRC = s.defaultReportSSRC(direction)
	}
	cname := strings.TrimSpace(req.CNAME)
	if cname == "" {
		cname = s.defaultReportCNAME(direction)
	}
	return s.SendRTCP(ctx, RTPRelayRTCPRequest{
		Direction: direction,
		Packets: []rtcp.Packet{
			BuildReceiverReport(senderSSRC, stats),
			BuildSourceDescription(RTCPSourceDescriptionConfig{SSRC: senderSSRC, CNAME: cname}),
		},
	})
}

func (s *RTPRelaySession) SendSenderReportToIMS(ctx context.Context, req RTPRelaySenderReportRequest) (RTPRelayRTCPResult, error) {
	req.Direction = RTCPFeedbackClientToIMS
	return s.SendSenderReport(ctx, req)
}

func (s *RTPRelaySession) SendSenderReportToClient(ctx context.Context, req RTPRelaySenderReportRequest) (RTPRelayRTCPResult, error) {
	req.Direction = RTCPFeedbackIMSToClient
	return s.SendSenderReport(ctx, req)
}

func (s *RTPRelaySession) SendSenderReport(ctx context.Context, req RTPRelaySenderReportRequest) (RTPRelayRTCPResult, error) {
	if s == nil {
		return RTPRelayRTCPResult{}, ErrRTPRelayConfig
	}
	direction, err := normalizeRTCPFeedbackDirection(req.Direction)
	if err != nil {
		return RTPRelayRTCPResult{}, err
	}
	stats := s.takeIMSToClientRTPStreamStats()
	if direction == RTCPFeedbackIMSToClient {
		stats = s.takeClientToIMSRTPStreamStats()
	}
	ssrc := req.SSRC
	if ssrc == 0 {
		ssrc = s.defaultReportSSRC(direction)
	}
	rtpTime := req.RTPTime
	if rtpTime == 0 {
		wall := req.WallClock
		if wall.IsZero() {
			wall = time.Now()
		}
		rtpTime = s.extrapolatedSenderRTPTime(direction, wall)
	}
	cname := strings.TrimSpace(req.CNAME)
	if cname == "" {
		cname = s.defaultReportCNAME(direction)
	}
	packets := []rtcp.Packet{
		BuildSenderReport(RTCPSenderReportConfig{
			SSRC:           ssrc,
			NTPTime:        req.NTPTime,
			WallClock:      req.WallClock,
			RTPTime:        rtpTime,
			PacketCount:    req.PacketCount,
			OctetCount:     req.OctetCount,
			ReceptionStats: stats,
		}),
		BuildSourceDescription(RTCPSourceDescriptionConfig{SSRC: ssrc, CNAME: cname}),
	}
	return s.SendRTCP(ctx, RTPRelayRTCPRequest{
		Direction: direction,
		Packets:   packets,
	})
}

func (s *RTPRelaySession) isClosed() bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	return closed
}

func (s *RTPRelaySession) forwardLoop(ctx context.Context, src, out *net.UDPConn, target func() *net.UDPAddr, allow func() bool, packets, bytes, drops *atomic.Uint64, transformSelector rtpRelayTransformSelector, rtcpDirection RTCPFeedbackDirection, dtmfDirection RTPDTMFDirection, dtmfPayloads, dtmfTargetPayloads func() map[uint8]int, rtpStatsDirection RTPDTMFDirection, rtpClockRate int) {
	defer s.wg.Done()
	buf := make([]byte, s.bufferSize)
	for {
		n, _, err := src.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || s.isClosed() {
				return
			}
			if isTransientRelayUDPError(err) {
				continue
			}
			return
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
		transform := s.currentTransform(transformSelector)
		if transform == nil && rtpStatsDirection != "" {
			s.observeRTPStream(rtpStatsDirection, packet, time.Now(), rtpClockRate)
		}
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
		if transform == nil && rtpStatsDirection != "" {
			packet = s.rewritePlaintextRTP(rtpStatsDirection, packet, rtpClockRate)
		}
		pktLen := uint64(len(packet))
		packets.Add(1)
		bytes.Add(pktLen)
		if _, err := out.WriteToUDP(packet, dst); err != nil {
			packets.Add(^uint64(0))
			if pktLen > 0 {
				bytes.Add(^uint64(pktLen - 1))
			}
			drops.Add(1)
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || s.isClosed() {
				return
			}
			continue
		}
	}
}

func (s *RTPRelaySession) observeRTPStream(direction RTPDTMFDirection, packet []byte, arrival time.Time, clockRate int) {
	if s == nil || len(packet) == 0 || clockRate <= 0 {
		return
	}
	observed := false
	s.rtpStatsMu.Lock()
	switch direction {
	case RTPDTMFClientToIMS:
		_, err := s.clientToIMSRTPStats.ObserveRTPPacket(packet, arrival, clockRate)
		observed = err == nil
	case RTPDTMFIMSToClient:
		_, err := s.imsToClientRTPStats.ObserveRTPPacket(packet, arrival, clockRate)
		observed = err == nil
	}
	s.rtpStatsMu.Unlock()
	if !observed {
		return
	}
	if qualityDirection, ok := rtcpFeedbackDirectionFromRTPDirection(direction); ok {
		s.emitRTPQualityEventIfChanged(qualityDirection, arrival)
	}
}

func (s *RTPRelaySession) processRTPDTMF(direction RTPDTMFDirection, packet []byte, sourcePayloads, targetPayloads map[uint8]int) []byte {
	if s == nil || len(sourcePayloads) == 0 {
		return packet
	}
	summary, err := InspectRTPDTMF(direction, packet, sourcePayloads, s.RTPDTMFHandler())
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
	summary, err := InspectRTPDTMF(direction, packet, payloads, s.RTPDTMFHandler())
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
	transform func() RTPRelayTransform
	packets   *atomic.Uint64
	bytes     *atomic.Uint64
	drops     *atomic.Uint64
}

type rtcpSendRoute struct {
	label     string
	conn      *net.UDPConn
	target    *net.UDPAddr
	transform func() RTPRelayTransform
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
			transform: func() RTPRelayTransform { return s.currentTransform(selectGeneratedToIMSRTPTransform) },
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
			transform: func() RTPRelayTransform { return s.currentTransform(selectGeneratedToClientRTPTransform) },
			packets:   &s.imsToClientRTPPackets,
			bytes:     &s.imsToClientRTPBytes,
			drops:     &s.imsToClientRTPDrops,
		}, nil
	default:
		return rtpDTMFSendRoute{}, fmt.Errorf("%w: unsupported RTP DTMF direction %q", ErrInvalidDTMF, direction)
	}
}

func (s *RTPRelaySession) rtcpSendRoute(direction RTCPFeedbackDirection) (rtcpSendRoute, error) {
	if s == nil {
		return rtcpSendRoute{}, ErrRTPRelayConfig
	}
	switch direction {
	case RTCPFeedbackClientToIMS:
		return rtcpSendRoute{
			label:     "IMS",
			conn:      s.imsRTCPConn,
			target:    s.currentIMSRTCPTarget(),
			transform: func() RTPRelayTransform { return s.currentTransform(selectGeneratedToIMSRTCPTransform) },
			packets:   &s.clientToIMSRTCPPackets,
			bytes:     &s.clientToIMSRTCPBytes,
			drops:     &s.clientToIMSRTCPDrops,
		}, nil
	case RTCPFeedbackIMSToClient:
		return rtcpSendRoute{
			label:     "client",
			conn:      s.clientRTCPConn,
			target:    s.currentClientRTCPTarget(),
			transform: func() RTPRelayTransform { return s.currentTransform(selectGeneratedToClientRTCPTransform) },
			packets:   &s.imsToClientRTCPPackets,
			bytes:     &s.imsToClientRTCPBytes,
			drops:     &s.imsToClientRTCPDrops,
		}, nil
	default:
		return rtcpSendRoute{}, fmt.Errorf("%w: unsupported RTCP feedback direction %q", ErrRTPRelayConfig, direction)
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
		HasPayloadType: req.HasPayloadType || payloadType != 0,
		Signal:         req.Signal,
		DurationMS:     rtpDTMFDurationMS(req.DurationMS),
		StepMS:         req.StepMS,
		EndPacketCount: req.EndPacketCount,
		Volume:         req.Volume,
		HasVolume:      req.HasVolume,
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
	if state.hasAudio {
		if cfg.SSRC == 0 {
			cfg.SSRC = state.audioSSRC
		}
		if cfg.SequenceNumber == 0 {
			cfg.SequenceNumber = state.lastAudioOrigSeq + state.seqOffset + 1
		}
		if cfg.Timestamp == 0 {
			elapsed := time.Since(state.lastAudioArrival)
			if elapsed < 0 {
				elapsed = 0
			}
			extrapolated := state.lastAudioTimestamp + uint32(elapsed.Seconds()*float64(cfg.ClockRate))
			if extrapolated == state.lastAudioTimestamp {
				step := uint32(cfg.ClockRate / 50)
				if step == 0 {
					step = 160
				}
				extrapolated += step
			}
			if state.hasSentDTMF && int32(state.nextTimestamp-extrapolated) > 0 {
				cfg.Timestamp = state.nextTimestamp
			} else {
				cfg.Timestamp = extrapolated
			}
		}
	} else {
		if cfg.SequenceNumber == 0 {
			cfg.SequenceNumber = state.nextSeq
		}
		if cfg.Timestamp == 0 {
			cfg.Timestamp = state.nextTimestamp
		}
		if cfg.SSRC == 0 {
			cfg.SSRC = state.ssrc
		}
	}
	packets, err := BuildRTPDTMFSequence(cfg)
	if err != nil {
		return nil, cfg, err
	}
	durationSamples, err := rtpDTMFSamplesForDuration(cfg.DurationMS, cfg.ClockRate)
	if err != nil {
		return nil, cfg, err
	}
	if state.hasAudio && req.SequenceNumber == 0 {
		state.seqOffset += uint16(len(packets))
	}
	state.hasSentDTMF = true
	state.nextSeq = cfg.SequenceNumber + uint16(len(packets))
	state.nextTimestamp = cfg.Timestamp + uint32(durationSamples)
	state.ssrc = cfg.SSRC
	return packets, cfg, nil
}

func (s *RTPRelaySession) currentTransform(selector rtpRelayTransformSelector) RTPRelayTransform {
	if s == nil || selector == nil {
		return nil
	}
	s.mu.RLock()
	transforms := s.transforms
	s.mu.RUnlock()
	return selector(transforms)
}

func selectClientToIMSRTPTransform(transforms RTPRelayTransforms) RTPRelayTransform {
	return transforms.ClientToIMSRTP
}

func selectIMSToClientRTPTransform(transforms RTPRelayTransforms) RTPRelayTransform {
	return transforms.IMSToClientRTP
}

func selectClientToIMSRTCPTransform(transforms RTPRelayTransforms) RTPRelayTransform {
	return transforms.ClientToIMSRTCP
}

func selectIMSToClientRTCPTransform(transforms RTPRelayTransforms) RTPRelayTransform {
	return transforms.IMSToClientRTCP
}

func selectGeneratedToIMSRTPTransform(transforms RTPRelayTransforms) RTPRelayTransform {
	return transforms.GeneratedToIMSRTP
}

func selectGeneratedToClientRTPTransform(transforms RTPRelayTransforms) RTPRelayTransform {
	return transforms.GeneratedToClientRTP
}

func selectGeneratedToIMSRTCPTransform(transforms RTPRelayTransforms) RTPRelayTransform {
	return transforms.GeneratedToIMSRTCP
}

func selectGeneratedToClientRTCPTransform(transforms RTPRelayTransforms) RTPRelayTransform {
	return transforms.GeneratedToClientRTCP
}

func normalizeRTCPFeedbackDirection(direction RTCPFeedbackDirection) (RTCPFeedbackDirection, error) {
	switch direction {
	case "", RTCPFeedbackClientToIMS:
		return RTCPFeedbackClientToIMS, nil
	case RTCPFeedbackIMSToClient:
		return RTCPFeedbackIMSToClient, nil
	default:
		return "", fmt.Errorf("%w: unsupported RTCP feedback direction %q", ErrRTPRelayConfig, direction)
	}
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

func rtcpFeedbackDirectionFromRTPDirection(direction RTPDTMFDirection) (RTCPFeedbackDirection, bool) {
	switch direction {
	case RTPDTMFClientToIMS:
		return RTCPFeedbackClientToIMS, true
	case RTPDTMFIMSToClient:
		return RTCPFeedbackIMSToClient, true
	default:
		return "", false
	}
}

func rtpDTMFGenerationPayload(req RTPRelayDTMFRequest, payloads map[uint8]int) (uint8, int) {
	if req.PayloadType != 0 || req.HasPayloadType {
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

func relayRTPClockRate(clockRate int) int {
	if clockRate > 0 {
		return clockRate
	}
	return 8000
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

func sdpConnectionIsUnspecified(connectionIP string) bool {
	ip := net.ParseIP(strings.TrimSpace(connectionIP))
	return ip != nil && ip.IsUnspecified()
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
	summary, err := s.inspectRTCPFeedbackPacket(direction, packet)
	if err != nil {
		s.rtcpFeedbackParseErrors.Add(1)
		return
	}
	s.recordRTCPFeedbackSummary(summary)
}

func (s *RTPRelaySession) inspectRTCPFeedbackPacket(direction RTCPFeedbackDirection, packet []byte) (RTCPFeedbackSummary, error) {
	observedAt := time.Now()
	handler := s.RTCPFeedbackHandler()
	return InspectRTCPFeedback(direction, packet, func(event RTCPFeedbackEvent) {
		s.recordRTCPSenderReport(event, observedAt)
		s.recordRTCPReportQuality(event, observedAt)
		emitRTCPFeedback(handler, event)
	})
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

func (s *RTPRelaySession) recordRTCPSenderReport(event RTCPFeedbackEvent, observedAt time.Time) {
	if s == nil || observedAt.IsZero() {
		return
	}
	if event.Kind != RTCPFeedbackSenderReport || event.NTPTime == 0 {
		return
	}
	direction, err := normalizeRTCPFeedbackDirection(event.Direction)
	if err != nil {
		return
	}
	timing := rtpRelayRTCPSenderReportTiming{
		lastSenderReport: rtcpLastSenderReport(event.NTPTime),
		observedAt:       observedAt,
	}
	s.rtcpQualityMu.Lock()
	if s.rtcpSenderReportTiming == nil {
		s.rtcpSenderReportTiming = make(map[rtpRelayRTCPSenderReportKey]rtpRelayRTCPSenderReportTiming)
	}
	s.rtcpSenderReportTiming[rtpRelayRTCPSenderReportKey{direction: direction, ssrc: event.SSRC}] = timing
	s.rtcpQualityMu.Unlock()

	updated := false
	s.rtpStatsMu.Lock()
	switch direction {
	case RTCPFeedbackClientToIMS:
		_, updated = s.clientToIMSRTPStats.ObserveRTCPSenderReport(event.SSRC, event.NTPTime, observedAt)
	case RTCPFeedbackIMSToClient:
		_, updated = s.imsToClientRTPStats.ObserveRTCPSenderReport(event.SSRC, event.NTPTime, observedAt)
	}
	s.rtpStatsMu.Unlock()
	if updated {
		s.emitRTPQualityEventIfChanged(direction, observedAt)
	}
}

func (s *RTPRelaySession) recordRTCPReportQuality(event RTCPFeedbackEvent, observedAt time.Time) {
	if s == nil || len(event.Reports) == 0 {
		return
	}
	direction, err := normalizeRTCPFeedbackDirection(event.Direction)
	if err != nil {
		return
	}
	s.rtcpQualityMu.Lock()
	reports := s.clientToIMSRTCPReports
	if direction == RTCPFeedbackIMSToClient {
		reports = s.imsToClientRTCPReports
	}
	if reports == nil {
		reports = make(map[rtpRelayRTCPReportKey]RTPRelayRTCPReportQuality)
		if direction == RTCPFeedbackIMSToClient {
			s.imsToClientRTCPReports = reports
		} else {
			s.clientToIMSRTCPReports = reports
		}
	}
	for _, report := range event.Reports {
		key := rtpRelayRTCPReportKey{reporterSSRC: event.SSRC, mediaSSRC: report.SSRC}
		roundTripTime := s.rtcpReportRoundTripTimeLocked(direction, report, observedAt)
		reports[key] = RTPRelayRTCPReportQuality{
			Direction:          direction,
			ReporterSSRC:       event.SSRC,
			MediaSSRC:          report.SSRC,
			FractionLost:       report.FractionLost,
			TotalLost:          report.TotalLost,
			LastSequenceNumber: report.LastSequenceNumber,
			Jitter:             report.Jitter,
			LastSenderReport:   report.LastSenderReport,
			Delay:              report.Delay,
			RoundTripTime:      roundTripTime,
		}
	}
	s.rtcpQualityMu.Unlock()
	s.emitRTPQualityEventIfChanged(direction, observedAt)
}

func (s *RTPRelaySession) rtcpReportRoundTripTimeLocked(direction RTCPFeedbackDirection, report RTCPReceptionReport, observedAt time.Time) time.Duration {
	if report.LastSenderReport == 0 || observedAt.IsZero() {
		return 0
	}
	timing := s.rtcpSenderReportTiming[rtpRelayRTCPSenderReportKey{direction: oppositeRTCPFeedbackDirection(direction), ssrc: report.SSRC}]
	if timing.lastSenderReport != report.LastSenderReport || timing.observedAt.IsZero() {
		return 0
	}
	elapsed := observedAt.Sub(timing.observedAt)
	delay := rtcpCompactDelayDuration(report.Delay)
	if elapsed <= delay {
		return 0
	}
	return elapsed - delay
}

func oppositeRTCPFeedbackDirection(direction RTCPFeedbackDirection) RTCPFeedbackDirection {
	switch direction {
	case RTCPFeedbackClientToIMS:
		return RTCPFeedbackIMSToClient
	case RTCPFeedbackIMSToClient:
		return RTCPFeedbackClientToIMS
	default:
		return ""
	}
}

func (s *RTPRelaySession) rtcpReportQuality(direction RTCPFeedbackDirection) []RTPRelayRTCPReportQuality {
	if s == nil {
		return nil
	}
	s.rtcpQualityMu.Lock()
	defer s.rtcpQualityMu.Unlock()
	reports := s.clientToIMSRTCPReports
	if direction == RTCPFeedbackIMSToClient {
		reports = s.imsToClientRTCPReports
	}
	if len(reports) == 0 {
		return nil
	}
	out := make([]RTPRelayRTCPReportQuality, 0, len(reports))
	for _, report := range reports {
		out = append(out, report)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ReporterSSRC != out[j].ReporterSSRC {
			return out[i].ReporterSSRC < out[j].ReporterSSRC
		}
		return out[i].MediaSSRC < out[j].MediaSSRC
	})
	return out
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
	trimmed := strings.TrimSpace(host)
	network := "udp"
	if ip := net.ParseIP(trimmed); ip != nil {
		if ip.To4() != nil {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}
	addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(trimmed, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	return net.ListenUDP(network, addr)
}

func listenIMSUDP(host string, port int, allowImplicitFallback bool) (*net.UDPConn, string, error) {
	conn, err := listenUDP(host, port)
	if err == nil {
		return conn, host, nil
	}
	if !allowImplicitFallback || !strings.Contains(strings.ToLower(err.Error()), "cannot assign requested address") {
		return nil, host, err
	}
	fallbackHost := "0.0.0.0"
	if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil && ip.To4() == nil {
		fallbackHost = "::"
	}
	conn, fallbackErr := listenUDP(fallbackHost, port)
	if fallbackErr != nil {
		return nil, host, err
	}
	return conn, fallbackHost, nil
}

func isTransientRelayUDPError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "host unreachable") ||
		strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "network is down") ||
		strings.Contains(msg, "host is down") ||
		strings.Contains(msg, "message too long") ||
		strings.Contains(msg, "no buffer space available") ||
		strings.Contains(msg, "resource temporarily unavailable") ||
		strings.Contains(msg, "interrupted system call")
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

func (s *RTPRelaySession) defaultReportSSRC(direction RTCPFeedbackDirection) uint32 {
	if s == nil {
		return randomRTPDTMFNonZeroUint32()
	}
	s.dtmfMu.Lock()
	defer s.dtmfMu.Unlock()
	state := &s.dtmfClientToIMSState
	if direction == RTCPFeedbackIMSToClient {
		state = &s.dtmfIMSToClientState
	}
	if state.ssrc == 0 {
		*state = newRTPDTMFSequenceState()
	}
	if state.hasAudio && state.audioSSRC != 0 {
		return state.audioSSRC
	}
	return state.ssrc
}

func (s *RTPRelaySession) defaultReportCNAME(direction RTCPFeedbackDirection) string {
	if s == nil {
		return "vowifi-go@127.0.0.1"
	}
	host := s.imsAdvertiseIP
	if direction == RTCPFeedbackIMSToClient {
		host = s.clientAdvertiseIP
	}
	host = strings.TrimSpace(host)
	if host == "" {
		host = "127.0.0.1"
	}
	return "vowifi-go@" + host
}

func (s *RTPRelaySession) takeScheduledSenderIntervalActive(direction RTCPFeedbackDirection) bool {
	if s == nil {
		return false
	}
	current := s.clientToIMSRTPPackets.Load()
	if direction == RTCPFeedbackIMSToClient {
		current = s.imsToClientRTPPackets.Load()
	}
	s.dtmfMu.Lock()
	defer s.dtmfMu.Unlock()
	state := &s.dtmfClientToIMSState
	if direction == RTCPFeedbackIMSToClient {
		state = &s.dtmfIMSToClientState
	}
	active := current > state.lastScheduledSent
	state.lastScheduledSent = current
	return active
}

func (s *RTPRelaySession) extrapolatedSenderRTPTime(direction RTCPFeedbackDirection, now time.Time) uint32 {
	if s == nil {
		return randomRTPDTMFUint32()
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.dtmfMu.Lock()
	defer s.dtmfMu.Unlock()
	state := &s.dtmfClientToIMSState
	if direction == RTCPFeedbackIMSToClient {
		state = &s.dtmfIMSToClientState
	}
	if state.ssrc == 0 {
		*state = newRTPDTMFSequenceState()
	}
	if state.hasAudio {
		clock := state.audioClockRate
		if clock <= 0 {
			clock = DefaultRTPDTMFClockRate
		}
		elapsed := now.Sub(state.lastAudioArrival)
		if elapsed < 0 {
			elapsed = 0
		}
		return state.lastAudioTimestamp + uint32(elapsed.Seconds()*float64(clock))
	}
	return state.nextTimestamp
}

func (s *RTPRelaySession) rewritePlaintextRTP(direction RTPDTMFDirection, packet []byte, clockRate int) []byte {
	if s == nil || len(packet) < 12 || (packet[0]>>6) != 2 {
		return packet
	}
	headerLen, ok := rtpHeaderByteLen(packet)
	if !ok {
		return packet
	}
	pt := packet[1] & 0x7F
	if pt >= 72 && pt <= 76 {
		return packet
	}
	origSeq := binary.BigEndian.Uint16(packet[2:4])
	ts := binary.BigEndian.Uint32(packet[4:8])
	ssrc := binary.BigEndian.Uint32(packet[8:12])

	s.mu.RLock()
	var srcCodecs, dstCodecs []SDPCodec
	var srcDTMF, dstDTMF map[uint8]int
	if direction == RTPDTMFIMSToClient {
		srcCodecs = s.imsCodecs
		dstCodecs = s.clientCodecs
		srcDTMF = s.imsRTPDTMFPayloads
		dstDTMF = s.clientRTPDTMFPayloads
	} else {
		srcCodecs = s.clientCodecs
		dstCodecs = s.imsCodecs
		srcDTMF = s.clientRTPDTMFPayloads
		dstDTMF = s.imsRTPDTMFPayloads
	}
	s.mu.RUnlock()

	_, isSrcDTMF := srcDTMF[pt]
	_, isDstDTMF := dstDTMF[pt]
	isDTMF := isSrcDTMF || isDstDTMF

	s.dtmfMu.Lock()
	state := &s.dtmfClientToIMSState
	if direction == RTPDTMFIMSToClient {
		state = &s.dtmfIMSToClientState
	}
	if state.ssrc == 0 {
		*state = newRTPDTMFSequenceState()
	}
	if !isDTMF || (state.hasAudio && state.audioSSRC == ssrc) {
		state.hasAudio = true
		state.audioSSRC = ssrc
		state.lastAudioOrigSeq = origSeq
		state.lastAudioTimestamp = ts
		state.lastAudioArrival = time.Now()
		if clockRate > 0 {
			state.audioClockRate = clockRate
		}
	}
	seqOffset := state.seqOffset
	s.dtmfMu.Unlock()

	out := packet
	copied := false
	ensureCopy := func() {
		if !copied {
			out = append([]byte(nil), packet...)
			copied = true
		}
	}
	if seqOffset != 0 {
		ensureCopy()
		binary.BigEndian.PutUint16(out[2:4], origSeq+seqOffset)
	}
	if isDTMF || len(srcCodecs) == 0 || len(dstCodecs) == 0 {
		return out
	}
	srcCodec, foundSrc := findSDPCodecByPT(srcCodecs, int(pt))
	if !foundSrc || strings.TrimSpace(srcCodec.EncodingName) == "" {
		return out
	}
	dstCodec, foundDst := findMatchingTargetSDPCodec(srcCodec, dstCodecs)
	if !foundDst {
		return out
	}
	if dstCodec.Payload != int(pt) && dstCodec.Payload >= 0 && dstCodec.Payload <= 127 {
		ensureCopy()
		out[1] = (out[1] & 0x80) | uint8(dstCodec.Payload)
	}
	if strings.EqualFold(srcCodec.EncodingName, "AMR") || strings.EqualFold(srcCodec.EncodingName, "AMR-WB") {
		srcOctet := amrCodecOctetAligned(srcCodec.FMTP)
		dstOctet := amrCodecOctetAligned(dstCodec.FMTP)
		if srcOctet != dstOctet {
			payloadEnd := len(out)
			if out[0]&0x20 != 0 {
				pad := int(out[len(out)-1])
				if pad <= 0 || headerLen+pad > len(out) {
					return out
				}
				payloadEnd -= pad
			}
			repacked, repackedOK := repackAMRPayload(strings.EqualFold(srcCodec.EncodingName, "AMR-WB"), srcOctet, dstOctet, out[headerLen:payloadEnd])
			if repackedOK {
				rebuilt := make([]byte, headerLen+len(repacked))
				copy(rebuilt, out[:headerLen])
				rebuilt[0] &^= 0x20 // clear padding bit on repacked payload
				copy(rebuilt[headerLen:], repacked)
				out = rebuilt
			}
		}
	}
	return out
}

func rtpHeaderByteLen(packet []byte) (int, bool) {
	if len(packet) < 12 || (packet[0]>>6) != 2 {
		return 0, false
	}
	cc := int(packet[0] & 0x0F)
	offset := 12 + cc*4
	if len(packet) < offset {
		return 0, false
	}
	if packet[0]&0x10 != 0 {
		if len(packet) < offset+4 {
			return 0, false
		}
		extWords := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		offset += 4 + extWords*4
		if len(packet) < offset {
			return 0, false
		}
	}
	return offset, true
}

func findSDPCodecByPT(codecs []SDPCodec, pt int) (SDPCodec, bool) {
	for _, c := range codecs {
		if c.Payload == pt {
			return c, true
		}
	}
	return SDPCodec{}, false
}

func findMatchingTargetSDPCodec(src SDPCodec, dstCodecs []SDPCodec) (SDPCodec, bool) {
	// Prefer exact same PT if target already defines the same codec there.
	for _, c := range dstCodecs {
		if c.Payload == src.Payload && sdpCodecSameEncoding(src, c) {
			return c, true
		}
	}
	for _, c := range dstCodecs {
		if sdpCodecSameEncoding(src, c) {
			return c, true
		}
	}
	return SDPCodec{}, false
}

func sdpCodecSameEncoding(a, b SDPCodec) bool {
	if !strings.EqualFold(strings.TrimSpace(a.EncodingName), strings.TrimSpace(b.EncodingName)) {
		return false
	}
	ca := a.ClockRate
	if ca <= 0 {
		ca = 8000
	}
	cb := b.ClockRate
	if cb <= 0 {
		cb = 8000
	}
	return ca == cb
}

func amrCodecOctetAligned(fmtp string) bool {
	for _, part := range strings.Split(fmtp, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "octet-align") {
			return strings.TrimSpace(v) == "1"
		}
	}
	return false
}

var (
	amrSpeechFrameBits   = [9]int{95, 103, 118, 134, 148, 159, 204, 244, 39}
	amrWBSpeechFrameBits = [10]int{132, 177, 253, 285, 317, 365, 397, 461, 477, 40}
)

func amrFrameSpeechBits(wideband bool, ft uint8) (int, bool) {
	if ft == 15 || (wideband && ft == 14) {
		return 0, true
	}
	if wideband {
		if int(ft) < len(amrWBSpeechFrameBits) {
			return amrWBSpeechFrameBits[ft], true
		}
		return 0, false
	}
	if int(ft) < len(amrSpeechFrameBits) {
		return amrSpeechFrameBits[ft], true
	}
	return 0, false
}

func repackAMRPayload(wideband, srcOctetAligned, dstOctetAligned bool, payload []byte) ([]byte, bool) {
	if srcOctetAligned == dstOctetAligned {
		return payload, false
	}
	if srcOctetAligned && !dstOctetAligned {
		// Octet-aligned (RFC 4867 §4.4) -> Bandwidth-efficient (RFC 4867 §4.3), single frame (F=0).
		if len(payload) < 2 {
			return nil, false
		}
		cmr := (payload[0] >> 4) & 0x0F
		f := (payload[1] >> 7) & 0x01
		if f != 0 {
			return nil, false
		}
		ft := (payload[1] >> 3) & 0x0F
		q := (payload[1] >> 2) & 0x01
		speechBits, ok := amrFrameSpeechBits(wideband, ft)
		if !ok {
			return nil, false
		}
		needBytes := (speechBits + 7) / 8
		if len(payload) < 2+needBytes {
			return nil, false
		}
		totalBits := 10 + speechBits
		out := make([]byte, (totalBits+7)/8)
		writeBit(out, 0, (cmr>>3)&1)
		writeBit(out, 1, (cmr>>2)&1)
		writeBit(out, 2, (cmr>>1)&1)
		writeBit(out, 3, cmr&1)
		writeBit(out, 4, 0)
		writeBit(out, 5, (ft>>3)&1)
		writeBit(out, 6, (ft>>2)&1)
		writeBit(out, 7, (ft>>1)&1)
		writeBit(out, 8, ft&1)
		writeBit(out, 9, q&1)
		speech := payload[2:]
		for i := 0; i < speechBits; i++ {
			writeBit(out, 10+i, readBit(speech, i))
		}
		return out, true
	}
	// Bandwidth-efficient (RFC 4867 §4.3) -> Octet-aligned (RFC 4867 §4.4), single frame (F=0).
	if len(payload) < 2 {
		return nil, false
	}
	cmr := (readBit(payload, 0) << 3) | (readBit(payload, 1) << 2) | (readBit(payload, 2) << 1) | readBit(payload, 3)
	f := readBit(payload, 4)
	if f != 0 {
		return nil, false
	}
	ft := (readBit(payload, 5) << 3) | (readBit(payload, 6) << 2) | (readBit(payload, 7) << 1) | readBit(payload, 8)
	q := readBit(payload, 9)
	speechBits, ok := amrFrameSpeechBits(wideband, ft)
	if !ok || len(payload)*8 < 10+speechBits {
		return nil, false
	}
	out := make([]byte, 2+(speechBits+7)/8)
	out[0] = cmr << 4
	out[1] = (ft << 3) | (q << 2)
	speech := out[2:]
	for i := 0; i < speechBits; i++ {
		writeBit(speech, i, readBit(payload, 10+i))
	}
	return out, true
}

func readBit(buf []byte, bitIdx int) uint8 {
	return (buf[bitIdx/8] >> (7 - uint(bitIdx%8))) & 1
}

func writeBit(buf []byte, bitIdx int, val uint8) {
	if val != 0 {
		buf[bitIdx/8] |= 1 << (7 - uint(bitIdx%8))
	}
}
