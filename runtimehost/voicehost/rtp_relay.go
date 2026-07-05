package voicehost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

var ErrRTPRelayConfig = errors.New("invalid rtp relay config")

type RTPRelayConfig struct {
	ClientListenIP    string
	ClientAdvertiseIP string
	ClientPort        int
	ClientRTCPPort    int
	IMSListenIP       string
	IMSAdvertiseIP    string
	IMSPort           int
	IMSRTCPPort       int
	BufferSize        int
	Transforms        RTPRelayTransforms
}

type RTPRelayTransform func([]byte) ([]byte, error)

type RTPRelayTransforms struct {
	ClientToIMSRTP  RTPRelayTransform
	IMSToClientRTP  RTPRelayTransform
	ClientToIMSRTCP RTPRelayTransform
	IMSToClientRTCP RTPRelayTransform
}

type RTPRelayStats struct {
	ClientToIMSPackets     uint64
	IMSToClientPackets     uint64
	ClientToIMSBytes       uint64
	IMSToClientBytes       uint64
	ClientToIMSRTPPackets  uint64
	IMSToClientRTPPackets  uint64
	ClientToIMSRTCPPackets uint64
	IMSToClientRTCPPackets uint64
	ClientToIMSRTPBytes    uint64
	IMSToClientRTPBytes    uint64
	ClientToIMSRTCPBytes   uint64
	IMSToClientRTCPBytes   uint64
	ClientToIMSRTPDrops    uint64
	IMSToClientRTPDrops    uint64
	ClientToIMSRTCPDrops   uint64
	IMSToClientRTCPDrops   uint64
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
	closed        bool

	clientAdvertiseIP string
	imsAdvertiseIP    string
	bufferSize        int

	cancel context.CancelFunc
	wg     sync.WaitGroup

	clientToIMSRTPPackets  atomic.Uint64
	imsToClientRTPPackets  atomic.Uint64
	clientToIMSRTCPPackets atomic.Uint64
	imsToClientRTCPPackets atomic.Uint64
	clientToIMSRTPBytes    atomic.Uint64
	imsToClientRTPBytes    atomic.Uint64
	clientToIMSRTCPBytes   atomic.Uint64
	imsToClientRTCPBytes   atomic.Uint64
	clientToIMSRTPDrops    atomic.Uint64
	imsToClientRTPDrops    atomic.Uint64
	clientToIMSRTCPDrops   atomic.Uint64
	imsToClientRTCPDrops   atomic.Uint64
	transforms             RTPRelayTransforms
}

func NewRTPRelaySession(ctx context.Context, cfg RTPRelayConfig, clientTarget SDPInfo) (*RTPRelaySession, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(clientTarget.ConnectionIP) == "" || clientTarget.MediaPort <= 0 {
		return nil, fmt.Errorf("%w: client media target is incomplete", ErrRTPRelayConfig)
	}
	clientAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(clientTarget.ConnectionIP, strconv.Itoa(clientTarget.MediaPort)))
	if err != nil {
		return nil, err
	}
	clientRTCPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(defaultRTCPIP(clientTarget), strconv.Itoa(defaultRTCPPort(clientTarget))))
	if err != nil {
		return nil, err
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
		clientConn:        clientConn,
		imsConn:           imsConn,
		clientRTCPConn:    clientRTCPConn,
		imsRTCPConn:       imsRTCPConn,
		clientTarget:      clientAddr,
		clientRTCPTarget:  clientRTCPAddr,
		clientAdvertiseIP: advertiseIP(cfg.ClientAdvertiseIP, clientListenIP),
		imsAdvertiseIP:    advertiseIP(cfg.IMSAdvertiseIP, imsListenIP),
		bufferSize:        cfg.BufferSize,
		cancel:            cancel,
		transforms:        cfg.Transforms,
	}
	if s.bufferSize <= 0 {
		s.bufferSize = 2048
	}
	s.wg.Add(4)
	go s.forwardLoop(childCtx, s.clientConn, s.imsConn, s.currentIMSTarget, &s.clientToIMSRTPPackets, &s.clientToIMSRTPBytes, &s.clientToIMSRTPDrops, s.transforms.ClientToIMSRTP)
	go s.forwardLoop(childCtx, s.imsConn, s.clientConn, s.currentClientTarget, &s.imsToClientRTPPackets, &s.imsToClientRTPBytes, &s.imsToClientRTPDrops, s.transforms.IMSToClientRTP)
	go s.forwardLoop(childCtx, s.clientRTCPConn, s.imsRTCPConn, s.currentIMSRTCPTarget, &s.clientToIMSRTCPPackets, &s.clientToIMSRTCPBytes, &s.clientToIMSRTCPDrops, s.transforms.ClientToIMSRTCP)
	go s.forwardLoop(childCtx, s.imsRTCPConn, s.clientRTCPConn, s.currentClientRTCPTarget, &s.imsToClientRTCPPackets, &s.imsToClientRTCPBytes, &s.imsToClientRTCPDrops, s.transforms.IMSToClientRTCP)
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
	if strings.TrimSpace(info.ConnectionIP) == "" || info.MediaPort <= 0 {
		return fmt.Errorf("%w: IMS media target is incomplete", ErrRTPRelayConfig)
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(info.ConnectionIP, strconv.Itoa(info.MediaPort)))
	if err != nil {
		return err
	}
	rtcpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(defaultRTCPIP(info), strconv.Itoa(defaultRTCPPort(info))))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.imsTarget = addr
	s.imsRTCPTarget = rtcpAddr
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
		ClientToIMSPackets:     rtpOutPackets,
		IMSToClientPackets:     rtpInPackets,
		ClientToIMSBytes:       rtpOutBytes,
		IMSToClientBytes:       rtpInBytes,
		ClientToIMSRTPPackets:  rtpOutPackets,
		IMSToClientRTPPackets:  rtpInPackets,
		ClientToIMSRTCPPackets: s.clientToIMSRTCPPackets.Load(),
		IMSToClientRTCPPackets: s.imsToClientRTCPPackets.Load(),
		ClientToIMSRTPBytes:    rtpOutBytes,
		IMSToClientRTPBytes:    rtpInBytes,
		ClientToIMSRTCPBytes:   s.clientToIMSRTCPBytes.Load(),
		IMSToClientRTCPBytes:   s.imsToClientRTCPBytes.Load(),
		ClientToIMSRTPDrops:    s.clientToIMSRTPDrops.Load(),
		IMSToClientRTPDrops:    s.imsToClientRTPDrops.Load(),
		ClientToIMSRTCPDrops:   s.clientToIMSRTCPDrops.Load(),
		IMSToClientRTCPDrops:   s.imsToClientRTCPDrops.Load(),
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

func (s *RTPRelaySession) forwardLoop(ctx context.Context, src, out *net.UDPConn, target func() *net.UDPAddr, packets, bytes, drops *atomic.Uint64, transform RTPRelayTransform) {
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
		packet := append([]byte(nil), buf[:n]...)
		if transform != nil {
			transformed, err := transform(packet)
			if err != nil {
				drops.Add(1)
				continue
			}
			packet = transformed
		}
		if _, err := out.WriteToUDP(packet, dst); err != nil {
			drops.Add(1)
			continue
		}
		packets.Add(1)
		bytes.Add(uint64(len(packet)))
	}
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
	if s == nil || s.clientTarget == nil {
		return nil
	}
	cp := *s.clientTarget
	return &cp
}

func (s *RTPRelaySession) currentClientRTCPTarget() *net.UDPAddr {
	if s == nil || s.clientRTCPTarget == nil {
		return nil
	}
	cp := *s.clientRTCPTarget
	return &cp
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
