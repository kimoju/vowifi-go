package swu

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kimoju/vowifi-go/engine/sim"
	"github.com/kimoju/vowifi-go/engine/swu/ikev2"
)

var ErrInvalidIKETunnelManager = errors.New("invalid swu ike tunnel manager")

type IKEInitRunner func(context.Context, ikev2.InitConfig) (ikev2.InitResult, error)

type IKEAuthRunner func(context.Context, ikev2.FullAuthConfig) (ikev2.FullAuthResult, error)

type IKEPacketSessionFactory func(PacketSessionConfig) (TunnelSession, error)

type IKETransportFactory func(TunnelConfig, IKETransportConfig) (ikev2.InitTransport, error)

type IKEESPTransportFactory func(TunnelConfig, ESPTransportConfig) (ESPPacketTransport, error)

type IKETransportConfig struct {
	EPDGAddress     string
	RemoteAddr      string
	LocalAddr       string
	LocalIP         net.IP
	RemoteIP        net.IP
	LocalPort       uint16
	RemotePort      uint16
	Timeout         time.Duration
	UseNonESPMarker bool
}

type ESPTransportConfig struct {
	EPDGAddress string
	RemoteAddr  string
	LocalAddr   string
	Timeout     time.Duration
}

type IKEPacketTunnelManagerConfig struct {
	Transport                ikev2.InitTransport
	ESPTransport             ESPPacketTransport
	SIM                      sim.AKAProvider
	Random                   io.Reader
	Timeout                  time.Duration
	LocalIP                  net.IP
	RemoteIP                 net.IP
	LocalPort                uint16
	RemotePort               uint16
	UseNonESPMarker          bool
	EAPIdentity              string
	Reauthentication         EAPReauthenticationState
	OnReauthenticationState  func(EAPReauthenticationState)
	ReauthenticationLifetime time.Duration
	InitiatorID              ikev2.Identity
	IKETransportFactory      IKETransportFactory
	ESPTransportFactory      IKEESPTransportFactory
	InitRunner               IKEInitRunner
	AuthRunner               IKEAuthRunner
	PacketSessionFactory     IKEPacketSessionFactory
	KernelXFRMManager        KernelXFRMManager
	KernelXFRMConfig         KernelXFRMConfig
	SA                       ikev2.SecurityAssociation
	ChildSA                  ikev2.SecurityAssociation
	ChildSPI                 []byte
	TSi                      ikev2.TrafficSelectors
	TSr                      ikev2.TrafficSelectors
	Configuration            ikev2.Configuration
	AdditionalAddresses      []net.IP
	NoAdditionalAddresses    bool
	Liveness                 IKELivenessConfig
	ChildSARekey             ChildSARekeyPolicy
	DisableControlPlaneHooks bool
}

type IKEPacketTunnelManager struct {
	reauthMu sync.Mutex
	Config   IKEPacketTunnelManagerConfig
}

type IKETunnelManagerConfig = IKEPacketTunnelManagerConfig

type IKETunnelManager = IKEPacketTunnelManager

var _ TunnelManager = (*IKEPacketTunnelManager)(nil)

func NewIKEPacketTunnelManager(cfg IKEPacketTunnelManagerConfig) *IKEPacketTunnelManager {
	return &IKEPacketTunnelManager{Config: cfg}
}

func NewIKETunnelManager(cfg IKETunnelManagerConfig) *IKETunnelManager {
	return NewIKEPacketTunnelManager(cfg)
}

func (m *IKEPacketTunnelManager) snapshotConfig() IKEPacketTunnelManagerConfig {
	m.reauthMu.Lock()
	defer m.reauthMu.Unlock()
	cfg := m.Config
	cfg.Reauthentication = m.Config.Reauthentication.clone()
	cfg.AdditionalAddresses = cloneIPs(m.Config.AdditionalAddresses)
	cfg.ChildSPI = append([]byte(nil), m.Config.ChildSPI...)
	return cfg
}

func (m *IKEPacketTunnelManager) EstablishTunnel(ctx context.Context, cfg TunnelConfig) (TunnelSession, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: manager is nil", ErrInvalidIKETunnelManager)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	mgrCfg := m.snapshotConfig()
	mode := cfg.NormalizedMode()
	if mode == DataplaneModeDisabled {
		return nil, fmt.Errorf("%w: dataplane mode is disabled", ErrInvalidTunnelConfig)
	}
	if mode != DataplaneModeUserspace && mode != DataplaneModeKernel {
		return nil, fmt.Errorf("%w: unsupported dataplane mode %q", ErrInvalidTunnelConfig, mode)
	}
	if mode == DataplaneModeKernel && cfg.Proxy.IsActive() && mgrCfg.KernelXFRMManager == nil {
		mode = DataplaneModeUserspace
	}
	provider := mgrCfg.SIM
	if provider == nil {
		return nil, fmt.Errorf("%w: SIM AKA provider is nil", ErrInvalidIKETunnelManager)
	}
	epdg := epdgAddressForTunnel(cfg)
	if epdg == "" {
		return nil, fmt.Errorf("%w: ePDG address is empty", ErrInvalidTunnelConfig)
	}
	identity, err := eapIdentityForTunnel(cfg, mgrCfg.EAPIdentity)
	if err != nil {
		return nil, err
	}
	operatorRealm := eapOperatorRealm(identity)
	initiatorID := mgrCfg.InitiatorID
	if initiatorID.Type == 0 {
		initiatorID = ikev2.Identity{Type: ikev2.IDRFC822Addr, Data: []byte(identity)}
	}
	random := mgrCfg.Random
	if random == nil {
		random = rand.Reader
	}
	transportCfg, espCfg := transportConfigsFrom(mgrCfg, cfg, epdg)
	transport, err := ikeTransportFrom(mgrCfg, cfg, transportCfg)
	if err != nil {
		return nil, err
	}
	if preparer, ok := transport.(interface {
		prepareNetworkEndpoints(context.Context) (net.Addr, net.Addr, error)
	}); ok {
		localEndpoint, remoteEndpoint, prepareErr := preparer.prepareNetworkEndpoints(ctx)
		if prepareErr != nil {
			_ = closeIKETransport(transport)
			return nil, prepareErr
		}
		if udpEndpoint, ok := localEndpoint.(*net.UDPAddr); ok && udpEndpoint.Port > 0 && udpEndpoint.Port <= 65535 {
			transportCfg.LocalIP = append(net.IP(nil), udpEndpoint.IP...)
			transportCfg.LocalPort = uint16(udpEndpoint.Port)
		}
		if udpEndpoint, ok := remoteEndpoint.(*net.UDPAddr); ok && udpEndpoint.Port > 0 && udpEndpoint.Port <= 65535 {
			transportCfg.RemoteIP = append(net.IP(nil), udpEndpoint.IP...)
			transportCfg.RemotePort = uint16(udpEndpoint.Port)
		}
	}
	transportHandedOff := false
	defer func() {
		if !transportHandedOff {
			_ = closeIKETransport(transport)
		}
	}()
	childSPI, err := childSPIFrom(mgrCfg, random)
	if err != nil {
		return nil, err
	}
	initRunner := mgrCfg.InitRunner
	if initRunner == nil {
		initRunner = ikev2.RunIKE_SA_INIT
	}
	init, err := initRunner(ctx, ikev2.InitConfig{
		Transport:  transport,
		Random:     random,
		SA:         mgrCfg.SA,
		LocalIP:    transportCfg.LocalIP,
		LocalPort:  transportCfg.LocalPort,
		RemoteIP:   transportCfg.RemoteIP,
		RemotePort: transportCfg.RemotePort,
	})
	if err != nil {
		return nil, err
	}
	authRunner := mgrCfg.AuthRunner
	if authRunner == nil {
		authRunner = ikev2.RunIKE_AUTH_Full
	}
	reauth := mgrCfg.Reauthentication.authStateAt(reauthenticationNow(cfg.StartedAt), operatorRealm)
	auth, err := authRunner(ctx, ikev2.FullAuthConfig{
		Transport:          transport,
		Init:               init,
		Keys:               init.Keys,
		SIM:                provider,
		EAPKeys:            reauth.Keys,
		InitiatorID:        initiatorID,
		EAPIdentity:        identity,
		EAPPseudonym:       reauth.NextPseudonym,
		EAPReauthIdentity:  reauth.Identity,
		EAPReauthCounter:   reauth.Counter,
		EAPReauthCounterOK: reauth.CounterOK,
		ChildSA:            mgrCfg.ChildSA,
		ChildSPI:           childSPI,
		TSi:                mgrCfg.TSi,
		TSr:                mgrCfg.TSr,
		Configuration:      mgrCfg.Configuration,
		Random:             random,
	})
	if err != nil {
		return nil, err
	}
	if auth.ChildSA == nil {
		return nil, fmt.Errorf("%w: IKE_AUTH completed without CHILD_SA", ErrTunnelNotReady)
	}
	child := *auth.ChildSA
	m.updateReauthenticationState(mgrCfg, auth, operatorRealm)
	result := tunnelResultFromIKE(cfg, epdg, init, child, mode)
	closeHandler, mobikeHandler, rekeyHandler, deleteChildHandler, dpdHandler, peerIKEHandler := controlHandlersFrom(mgrCfg, transport, init, auth, child, result, transportCfg)
	if mode == DataplaneModeKernel {
		session, err := establishKernelSessionFrom(ctx, mgrCfg, cfg, transportCfg, init, child, result, closeHandler)
		if err != nil {
			return nil, err
		}
		transportHandedOff = true
		return session, nil
	}
	var espTransport ESPPacketTransport
	if provider, ok := transport.(sharedNATTESPProvider); ok && mgrCfg.ESPTransport == nil && mgrCfg.ESPTransportFactory == nil {
		espTransport = provider.sharedESPTransport()
	} else {
		espTransport, err = espTransportFrom(mgrCfg, cfg, espCfg)
		if err != nil {
			return nil, err
		}
	}
	livenessCfg := mgrCfg.Liveness
	if dpdHandler == nil {
		livenessCfg.DisableDPD = true
	}
	liveness, err := NewIKELivenessState(livenessCfg, result.EstablishedAt)
	if err != nil {
		if closer, ok := espTransport.(ESPPacketTransportCloser); ok {
			cleanupCtx, cancel := independentCleanupContext(ctx)
			_ = closer.Close(cleanupCtx)
			cancel()
		}
		return nil, err
	}
	sessionFactory := mgrCfg.PacketSessionFactory
	if sessionFactory == nil {
		sessionFactory = func(pc PacketSessionConfig) (TunnelSession, error) {
			return NewPacketSession(pc)
		}
	}
	session, err := sessionFactory(PacketSessionConfig{
		Result:                result,
		ChildSA:               child,
		Transport:             espTransport,
		Random:                random,
		MOBIKEHandler:         mobikeHandler,
		RekeyHandler:          rekeyHandler,
		ChildSADeleteHandler:  deleteChildHandler,
		PeerIKERequestHandler: peerIKEHandler,
		IKEInit:               init,
		IKEKeys:               init.Keys,
		RekeyPolicy:           mgrCfg.ChildSARekey,
		MOBIKENAT: NewMOBIKENATState(MOBIKENATStateConfig{
			MOBIKESupported: result.MOBIKESupported,
			LocalIP:         transportCfg.LocalIP,
			RemoteIP:        transportCfg.RemoteIP,
			LocalPort:       transportCfg.LocalPort,
			RemotePort:      transportCfg.RemotePort,
			NATDetected:     init.NATDetected,
			UpdatedAt:       result.EstablishedAt,
		}),
		Liveness:              liveness,
		DPDHandler:            dpdHandler,
		CloseHandler:          closeHandler,
		BackgroundMaintenance: !mgrCfg.DisableControlPlaneHooks,
	})
	if err != nil {
		if closer, ok := espTransport.(ESPPacketTransportCloser); ok {
			cleanupCtx, cancel := independentCleanupContext(ctx)
			_ = closer.Close(cleanupCtx)
			cancel()
		}
		return nil, err
	}
	if session == nil {
		if closer, ok := espTransport.(ESPPacketTransportCloser); ok {
			cleanupCtx, cancel := independentCleanupContext(ctx)
			_ = closer.Close(cleanupCtx)
			cancel()
		}
		return nil, fmt.Errorf("%w: packet session factory returned nil", ErrInvalidIKETunnelManager)
	}
	transportHandedOff = true
	return session, nil
}

func establishKernelSessionFrom(ctx context.Context, mgrCfg IKEPacketTunnelManagerConfig, cfg TunnelConfig, transportCfg IKETransportConfig, init ikev2.InitResult, child ikev2.ChildSAResult, result TunnelResult, closeHandler func(context.Context) error) (TunnelSession, error) {
	xfrmTemplate := mgrCfg.KernelXFRMConfig
	xfrmCfg, err := KernelXFRMConfigFromIKE(KernelXFRMConfigFromIKEConfig{
		Tunnel:               cfg,
		Transport:            transportCfg,
		Init:                 init,
		ChildSA:              child,
		InnerLocalPrefix:     xfrmTemplate.InnerLocalPrefix,
		InnerRemotePrefix:    xfrmTemplate.InnerRemotePrefix,
		ReqID:                xfrmTemplate.ReqID,
		Mark:                 xfrmTemplate.Mark,
		InterfaceID:          xfrmTemplate.InterfaceID,
		IncludeForwardPolicy: xfrmTemplate.IncludeForwardPolicy,
		XFRMInterface:        xfrmTemplate.XFRMInterface,
		NATTraversal:         xfrmTemplate.NATTraversal,
	})
	if err != nil {
		cleanupCtx, cancel := independentCleanupContext(ctx)
		defer cancel()
		return nil, errors.Join(err, closeIKEBestEffort(cleanupCtx, closeHandler))
	}
	xfrmManager := mgrCfg.KernelXFRMManager
	if xfrmManager == nil {
		xfrmManager = LinuxXFRMManager{}
	}
	xfrmState, err := xfrmManager.Apply(ctx, xfrmCfg)
	if err != nil {
		cleanupCtx, cancel := independentCleanupContext(ctx)
		defer cancel()
		return nil, errors.Join(err, closeIKEBestEffort(cleanupCtx, closeHandler))
	}
	session, err := newKernelTunnelSession(result, xfrmManager, xfrmState, closeHandler)
	if err != nil {
		cleanupCtx, cancel := independentCleanupContext(ctx)
		defer cancel()
		return nil, errors.Join(err, xfrmManager.Cleanup(cleanupCtx, xfrmState), closeIKEBestEffort(cleanupCtx, closeHandler))
	}
	return session, nil
}

func closeIKEBestEffort(ctx context.Context, closeHandler func(context.Context) error) error {
	if closeHandler == nil {
		return nil
	}
	return closeHandler(ctx)
}

func (m *IKEPacketTunnelManager) updateReauthenticationState(mgrCfg IKEPacketTunnelManagerConfig, auth ikev2.FullAuthResult, operatorRealm string) {
	if m == nil || len(auth.EAPKeys.KAut) == 0 || len(auth.EAPKeys.KEncr) == 0 {
		return
	}
	var expiresAt time.Time
	if mgrCfg.ReauthenticationLifetime > 0 {
		expiresAt = time.Now().Add(mgrCfg.ReauthenticationLifetime)
	}
	m.reauthMu.Lock()
	next, ok := m.Config.Reauthentication.ApplyUpdate(EAPReauthenticationUpdate{
		NextReauthID:    auth.EAPNextReauthID,
		NextPseudonym:   auth.EAPNextPseudonym,
		Keys:            auth.EAPKeys,
		Reauthenticated: auth.EAPReauthenticated,
		CounterTooSmall: auth.EAPReauthCounterTooSmall,
		Counter:         auth.EAPReauthCounter,
		ExpiresAt:       expiresAt,
		OperatorRealm:   operatorRealm,
	})
	if !ok {
		m.reauthMu.Unlock()
		return
	}
	m.Config.Reauthentication = next
	cb := mgrCfg.OnReauthenticationState
	cloned := next.clone()
	m.reauthMu.Unlock()
	if cb != nil {
		cb(cloned)
	}
}

func transportConfigsFrom(mgrCfg IKEPacketTunnelManagerConfig, cfg TunnelConfig, epdg string) (IKETransportConfig, ESPTransportConfig) {
	remotePort := mgrCfg.RemotePort
	if remotePort == 0 {
		remotePort = 4500
	}
	localPort := mgrCfg.LocalPort
	localIP := normalizedMOBIKEIP(mgrCfg.LocalIP, cfg.OuterLocalIP)
	remoteIP := normalizedMOBIKEIP(mgrCfg.RemoteIP, tunnelAddressHost(epdg))
	remoteAddr := tunnelUDPAddr(epdg, remotePort)
	localAddr := ""
	if local := firstPacketNonEmpty(cfg.OuterLocalIP); local != "" {
		localAddr = tunnelUDPAddr(local, localPort)
	}
	timeout := mgrCfg.Timeout
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	useMarker := mgrCfg.UseNonESPMarker
	if !useMarker {
		useMarker = remotePort == 4500
	}
	ikeCfg := IKETransportConfig{
		EPDGAddress:     epdg,
		RemoteAddr:      remoteAddr,
		LocalAddr:       localAddr,
		LocalIP:         localIP,
		RemoteIP:        remoteIP,
		LocalPort:       localPort,
		RemotePort:      remotePort,
		Timeout:         timeout,
		UseNonESPMarker: useMarker,
	}
	espCfg := ESPTransportConfig{
		EPDGAddress: epdg,
		RemoteAddr:  remoteAddr,
		LocalAddr:   localAddr,
		Timeout:     timeout,
	}
	return ikeCfg, espCfg
}

func ikeTransportFrom(mgrCfg IKEPacketTunnelManagerConfig, cfg TunnelConfig, transportCfg IKETransportConfig) (ikev2.InitTransport, error) {
	if mgrCfg.Transport != nil {
		return mgrCfg.Transport, nil
	}
	if mgrCfg.IKETransportFactory != nil {
		return mgrCfg.IKETransportFactory(cfg, transportCfg)
	}
	return newSharedNATTTransportWithProxy(transportCfg.RemoteAddr, transportCfg.LocalAddr, transportCfg.Timeout, cfg.Proxy), nil
}

func espTransportFrom(mgrCfg IKEPacketTunnelManagerConfig, cfg TunnelConfig, transportCfg ESPTransportConfig) (ESPPacketTransport, error) {
	if mgrCfg.ESPTransport != nil {
		return mgrCfg.ESPTransport, nil
	}
	if mgrCfg.ESPTransportFactory != nil {
		return mgrCfg.ESPTransportFactory(cfg, transportCfg)
	}
	return &UDPESPPacketTransport{
		RemoteAddr: transportCfg.RemoteAddr,
		LocalAddr:  transportCfg.LocalAddr,
		Timeout:    transportCfg.Timeout,
		Proxy:      cloneProxyConfig(cfg.Proxy),
	}, nil
}

func childSPIFrom(mgrCfg IKEPacketTunnelManagerConfig, random io.Reader) ([]byte, error) {
	if len(mgrCfg.ChildSPI) > 0 {
		if len(mgrCfg.ChildSPI) != 4 {
			return nil, fmt.Errorf("%w: child SPI length %d", ErrInvalidIKETunnelManager, len(mgrCfg.ChildSPI))
		}
		return append([]byte(nil), mgrCfg.ChildSPI...), nil
	}
	spi := make([]byte, 4)
	if _, err := io.ReadFull(random, spi); err != nil {
		return nil, err
	}
	if spi[0] == 0 && spi[1] == 0 && spi[2] == 0 && spi[3] == 0 {
		spi[3] = 1
	}
	return spi, nil
}

func controlHandlersFrom(mgrCfg IKEPacketTunnelManagerConfig, transport ikev2.InitTransport, init ikev2.InitResult, auth ikev2.FullAuthResult, child ikev2.ChildSAResult, result TunnelResult, transportCfg IKETransportConfig) (func(context.Context) error, func(context.Context, MOBIKERequest) (MOBIKEResult, error), ChildSARekeyHandler, func(context.Context, []byte) error, func(context.Context) error, PeerIKERequestHandler) {
	if mgrCfg.DisableControlPlaneHooks || auth.NextMessageID == 0 || !ikeKeysUsable(init.Keys) {
		return func(context.Context) error { return closeIKETransport(transport) }, nil, nil, nil, nil, nil
	}
	control := &ikePacketTunnelControl{
		transport:             transport,
		init:                  init,
		keys:                  init.Keys,
		child:                 child,
		nextMessageID:         auth.NextMessageID,
		result:                result,
		localIP:               transportCfg.LocalIP,
		remoteIP:              transportCfg.RemoteIP,
		localPort:             transportCfg.LocalPort,
		remotePort:            transportCfg.RemotePort,
		additionalAddresses:   cloneIPs(mgrCfg.AdditionalAddresses),
		noAdditionalAddresses: mgrCfg.NoAdditionalAddresses,
		random:                mgrCfg.Random,
	}
	closeHandler := control.close
	var mobikeHandler func(context.Context, MOBIKERequest) (MOBIKEResult, error)
	if init.MOBIKESupported {
		mobikeHandler = control.mobike
	}
	return closeHandler, mobikeHandler, control.rekeyChildSA, control.deleteChildSA, control.dpd, control.handlePeerIKERequest
}

type ikePacketTunnelControl struct {
	mu                    sync.Mutex
	transport             ikev2.InitTransport
	init                  ikev2.InitResult
	keys                  ikev2.IKEKeys
	child                 ikev2.ChildSAResult
	nextMessageID         uint32
	result                TunnelResult
	localIP               net.IP
	remoteIP              net.IP
	localPort             uint16
	remotePort            uint16
	additionalAddresses   []net.IP
	noAdditionalAddresses bool
	random                io.Reader
}

func (c *ikePacketTunnelControl) close(ctx context.Context) (err error) {
	if c == nil {
		return nil
	}
	cleanupCtx, cancel := independentCleanupContext(ctx)
	defer cancel()
	defer func() {
		err = errors.Join(err, closeIKETransport(c.transport))
	}()
	c.mu.Lock()
	messageID := c.nextMessageID
	c.nextMessageID++
	child := c.child
	c.mu.Unlock()
	payloads, err := ikev2.TeardownDeletePayloads(child, true)
	if err != nil {
		return err
	}
	_, err = ikev2.RunInformationalExchange(cleanupCtx, ikev2.InformationalConfig{
		Transport: newRetransmittingIKETransport(c.transport, defaultIKEControlMaxRetransmits),
		Init:      c.init,
		Keys:      c.keys,
		MessageID: messageID,
		Payloads:  payloads,
		Random:    randomWithCryptoFallback(c.random),
	})
	return err
}

func closeIKETransport(transport ikev2.InitTransport) error {
	closer, ok := transport.(interface{ Close() error })
	if !ok || closer == nil {
		return nil
	}
	return closer.Close()
}

func (c *ikePacketTunnelControl) rekeyChildSA(ctx context.Context) (ikev2.ChildSAResult, error) {
	if c == nil {
		return ikev2.ChildSAResult{}, ErrInvalidIKEControl
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nextMessageID == 0 {
		return ikev2.ChildSAResult{}, fmt.Errorf("%w: next message_id is zero", ErrInvalidIKEControl)
	}
	messageID := c.nextMessageID
	c.nextMessageID++
	res, err := ikev2.RunCREATE_CHILD_SARekey(ctx, ikev2.ChildSARekeyConfig{
		Transport:  newRetransmittingIKETransport(c.transport, defaultIKEControlMaxRetransmits),
		Init:       c.init,
		Keys:       c.keys,
		MessageID:  messageID,
		OldChildSA: c.child,
		Random:     c.random,
	})
	if err != nil {
		return ikev2.ChildSAResult{}, err
	}
	if res.NextMessageID != 0 {
		c.nextMessageID = res.NextMessageID
	}
	c.child = res.ChildSA
	c.result.ChildSAIdentifier = childSAIdentifier(res.ChildSA)
	c.result.IKEEstablished = true
	c.result.IPsecEstablished = true
	c.result.Ready = true
	c.result.Reason = "child sa rekeyed"
	return res.ChildSA, nil
}

func (c *ikePacketTunnelControl) deleteChildSA(ctx context.Context, oldLocalSPI []byte) error {
	if c == nil || len(oldLocalSPI) != 4 {
		return nil
	}
	payload, err := ikev2.ESPDeletePayload(oldLocalSPI)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.nextMessageID == 0 {
		c.mu.Unlock()
		return fmt.Errorf("%w: next message_id is zero", ErrInvalidIKEControl)
	}
	messageID := c.nextMessageID
	c.nextMessageID++
	c.mu.Unlock()
	_, err = ikev2.RunInformationalExchange(ctx, ikev2.InformationalConfig{
		Transport: newRetransmittingIKETransport(c.transport, defaultIKEControlMaxRetransmits),
		Init:      c.init,
		Keys:      c.keys,
		MessageID: messageID,
		Payloads:  []ikev2.Payload{payload},
		Random:    randomWithCryptoFallback(c.random),
	})
	return err
}

func (c *ikePacketTunnelControl) handlePeerIKERequest(_ context.Context, raw []byte) (PeerIKERequestOutcome, error) {
	if c == nil {
		return PeerIKERequestOutcome{}, ErrInvalidIKEControl
	}
	c.mu.Lock()
	init := c.init
	keys := c.keys
	child := c.child
	random := c.random
	c.mu.Unlock()
	return processPeerInformationalRequest(raw, init, keys, child, random)
}

func (c *ikePacketTunnelControl) dpd(ctx context.Context) error {
	if c == nil {
		return ErrInvalidIKEControl
	}
	c.mu.Lock()
	messageID := c.nextMessageID
	c.nextMessageID++
	c.mu.Unlock()
	_, err := ikev2.RunLivenessCheck(ctx, ikev2.InformationalConfig{
		Transport: newRetransmittingIKETransport(c.transport, defaultIKEControlMaxRetransmits),
		Init:      c.init,
		Keys:      c.keys,
		MessageID: messageID,
		Random:    randomWithCryptoFallback(c.random),
	})
	return err
}

func (c *ikePacketTunnelControl) mobike(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
	if c == nil {
		return MOBIKEResult{}, ErrInvalidIKEControl
	}
	c.mu.Lock()
	messageID := c.nextMessageID
	c.nextMessageID++
	c.mu.Unlock()
	payloads, err := mobikeUpdatePayloads(IKEMOBIKEConfig{
		Init:                  c.init,
		Result:                c.result,
		LocalIP:               c.localIP,
		RemoteIP:              c.remoteIP,
		LocalPort:             c.localPort,
		RemotePort:            c.remotePort,
		AdditionalAddresses:   c.additionalAddresses,
		NoAdditionalAddresses: c.noAdditionalAddresses,
	}, c.additionalAddresses, req)
	if err != nil {
		return MOBIKEResult{}, err
	}
	res, err := ikev2.RunInformationalExchange(ctx, ikev2.InformationalConfig{
		Transport: newRetransmittingIKETransport(c.transport, defaultIKEControlMaxRetransmits),
		Init:      c.init,
		Keys:      c.keys,
		MessageID: messageID,
		Payloads:  payloads,
		Random:    c.random,
	})
	if err != nil {
		return MOBIKEResult{}, err
	}
	if err := rejectMOBIKEResponse(res.ResponseInner); err != nil {
		return MOBIKEResult{}, err
	}
	return MOBIKEResult{
		Rekeyed:          false,
		OuterLocalIP:     firstPacketNonEmpty(req.NewIP, req.OldIP, c.result.EPDGAddress),
		LocalInnerIP:     c.result.LocalInnerIP,
		RemoteInnerIP:    c.result.RemoteInnerIP,
		IKEEstablished:   true,
		IPsecEstablished: true,
		Reason:           "mobike update sa addresses sent",
		UpdatedAt:        time.Now(),
	}, nil
}

func tunnelResultFromIKE(cfg TunnelConfig, epdg string, init ikev2.InitResult, child ikev2.ChildSAResult, mode string) TunnelResult {
	mode = firstPacketNonEmpty(mode, DataplaneModeUserspace)
	v4Addrs := childConfigurationIPStrings(child, ikev2.ConfigInternalIPv4Address)
	v6Addrs := childConfigurationIPStrings(child, ikev2.ConfigInternalIPv6Address)
	localV4 := childConfigurationAddress(child, ikev2.ConfigInternalIPv4Address)
	localV6 := childConfigurationAddress(child, ikev2.ConfigInternalIPv6Address)
	if cfgInner := strings.TrimSpace(cfg.InnerLocalIP); cfgInner != "" {
		if parsed, ok := parseInnerIPFamily(cfgInner); ok {
			if parsed.Is4() && localV4 == "" {
				localV4 = cfgInner
			} else if parsed.Is6() && localV6 == "" {
				localV6 = cfgInner
			}
		}
	}
	innerIPs := mergeInnerIPStrings(localV4, localV6, v4Addrs, v6Addrs)
	if cfgInner := strings.TrimSpace(cfg.InnerLocalIP); cfgInner != "" {
		innerIPs = mergeInnerIPStrings(cfgInner, "", innerIPs, nil)
	}
	return TunnelResult{
		Ready:              true,
		Mode:               mode,
		EPDGAddress:        epdg,
		LocalInnerIP:       firstPacketNonEmpty(cfg.InnerLocalIP, localV4, localV6),
		LocalInnerIPv4:     localV4,
		LocalInnerIPv6:     localV6,
		LocalInnerIPs:      innerIPs,
		RemoteInnerIP:      strings.TrimSpace(cfg.RemoteInnerIP),
		DNSServers:         childConfigurationDNS(child),
		PCSCFServers:       childConfigurationPCSCF(child),
		ESPEncryptionID:    child.Keys.Profile.EncryptionID,
		ESPIntegrityID:     child.Keys.Profile.IntegrityID,
		InitiatorSelectors: childTrafficSelectorStrings(child.TSi),
		ResponderSelectors: childTrafficSelectorStrings(child.TSr),
		IKEEstablished:     true,
		IPsecEstablished:   true,
		MOBIKESupported:    init.MOBIKESupported,
		ChildSAIdentifier:  childSAIdentifier(child),
		Reason:             "ike ipsec tunnel ready",
		EstablishedAt:      time.Now(),
	}
}

func parseInnerIPFamily(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr().Unmap(), true
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap(), true
	}
	return netip.Addr{}, false
}

func mergeInnerIPStrings(primaryA, primaryB string, listA, listB []string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	add(primaryA)
	for _, item := range listA {
		add(item)
	}
	add(primaryB)
	for _, item := range listB {
		add(item)
	}
	return out
}

func childTrafficSelectorStrings(selectors ikev2.TrafficSelectors) []string {
	out := make([]string, 0, len(selectors.Selectors))
	for _, selector := range selectors.Selectors {
		out = append(out, fmt.Sprintf("type=%d proto=%d ports=%d-%d addr=%s-%s",
			selector.Type, selector.IPProtocol, selector.StartPort, selector.EndPort,
			selector.StartAddr.String(), selector.EndAddr.String()))
	}
	return out
}

func childConfigurationAddress(child ikev2.ChildSAResult, attrType uint16) string {
	values := childConfigurationIPStrings(child, attrType)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func childConfigurationDNS(child ikev2.ChildSAResult) []string {
	return append(childConfigurationIPStrings(child, ikev2.ConfigInternalIPv4DNS), childConfigurationIPStrings(child, ikev2.ConfigInternalIPv6DNS)...)
}

func childConfigurationPCSCF(child ikev2.ChildSAResult) []string {
	return append(childConfigurationIPStrings(child, ikev2.ConfigPCSCFIPv4Address), childConfigurationIPStrings(child, ikev2.ConfigPCSCFIPv6Address)...)
}

func childConfigurationIPStrings(child ikev2.ChildSAResult, attrType uint16) []string {
	if child.Configuration == nil {
		return nil
	}
	width := 0
	switch attrType {
	case ikev2.ConfigInternalIPv4Address, ikev2.ConfigInternalIPv4DNS, ikev2.ConfigPCSCFIPv4Address:
		width = net.IPv4len
	case ikev2.ConfigInternalIPv6Address, ikev2.ConfigInternalIPv6DNS, ikev2.ConfigPCSCFIPv6Address:
		width = net.IPv6len
	default:
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, attr := range child.Configuration.Attributes {
		if attr.Type != attrType {
			continue
		}
		for value := attr.Value; len(value) >= width; value = value[width:] {
			ip := net.IP(value[:width]).String()
			if ip != "" && !seen[ip] {
				out = append(out, ip)
				seen[ip] = true
			}
		}
	}
	return out
}

func childSAIdentifier(child ikev2.ChildSAResult) string {
	local := hex.EncodeToString(child.LocalSPI)
	remote := hex.EncodeToString(child.RemoteSPI)
	switch {
	case local != "" && remote != "":
		return local + "/" + remote
	case local != "":
		return local
	default:
		return remote
	}
}

func epdgAddressForTunnel(cfg TunnelConfig) string {
	if epdg := strings.TrimSpace(cfg.EPDGAddress); epdg != "" {
		return epdg
	}
	mcc, mnc := tunnelMCCMNC(cfg)
	if mcc == "" || mnc == "" {
		return ""
	}
	return fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", leftPadTunnel(mnc, 3), mcc)
}

func eapIdentityForTunnel(cfg TunnelConfig, override string) (string, error) {
	raw := firstPacketNonEmpty(override, cfg.Identity.IMPI, cfg.IMSI, cfg.Identity.IMPU)
	if raw == "" {
		return "", fmt.Errorf("%w: EAP identity is empty", ErrInvalidTunnelConfig)
	}
	raw = normalizeTunnelIdentity(raw)
	if strings.Contains(raw, "@") {
		return raw, nil
	}
	mcc, mnc := tunnelMCCMNC(cfg)
	if mcc == "" || mnc == "" {
		return "", fmt.Errorf("%w: MCC/MNC is required for IMSI-derived EAP identity", ErrInvalidTunnelConfig)
	}
	prefix := ""
	if isDecimalString(raw) {
		prefix = "0"
	}
	return fmt.Sprintf("%s%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org", prefix, raw, leftPadTunnel(mnc, 3), mcc), nil
}

func eapOperatorRealm(identity string) string {
	identity = normalizeTunnelIdentity(identity)
	at := strings.LastIndexByte(identity, '@')
	if at < 0 || at == len(identity)-1 {
		return ""
	}
	return normalizeEAPOperatorRealm(identity[at+1:])
}

func reauthenticationNow(startedAt time.Time) time.Time {
	if !startedAt.IsZero() {
		return startedAt
	}
	return time.Now()
}

func normalizeTunnelIdentity(identity string) string {
	identity = strings.TrimSpace(identity)
	identity = strings.Trim(identity, "<>")
	if strings.HasPrefix(strings.ToLower(identity), "sip:") {
		identity = identity[4:]
	}
	if semi := strings.IndexByte(identity, ';'); semi >= 0 {
		identity = identity[:semi]
	}
	return strings.TrimSpace(identity)
}

func tunnelMCCMNC(cfg TunnelConfig) (string, string) {
	mcc := strings.TrimSpace(cfg.MCC)
	mnc := strings.TrimSpace(cfg.MNC)
	imsi := strings.TrimSpace(cfg.IMSI)
	if mcc == "" && len(imsi) >= 3 && isDecimalString(imsi) {
		mcc = imsi[:3]
	}
	if mnc == "" && len(imsi) >= 5 && isDecimalString(imsi) {
		mncLen := 2
		if isThreeDigitTunnelMCC(mcc) && len(imsi) >= 6 {
			mncLen = 3
		}
		mnc = imsi[3 : 3+mncLen]
	}
	return mcc, mnc
}

func isThreeDigitTunnelMCC(mcc string) bool {
	switch mcc {
	case "001",
		"302", "308",
		"310", "311", "312", "313", "314", "315", "316", "318", "319", "332",
		"334",
		"338", "342", "344", "346", "348", "350", "352", "354", "356", "358", "360", "362",
		"364", "365", "366", "368", "370", "372", "374", "376",
		"405", "406",
		"722", "732":
		return true
	default:
		return false
	}
}

func tunnelUDPAddr(addr string, port uint16) string {
	addr = strings.TrimSpace(addr)
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), strconv.Itoa(int(port)))
}

func tunnelAddressHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(addr, "[]")
}

func leftPadTunnel(value string, width int) string {
	value = strings.TrimSpace(value)
	for len(value) < width {
		value = "0" + value
	}
	return value
}

func isDecimalString(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func ikeKeysUsable(keys ikev2.IKEKeys) bool {
	p := keys.Profile
	return p.RequiredLength() > 0 &&
		len(keys.SKD) >= p.PRFKeyLength &&
		len(keys.SKAi) >= p.IntegrityKeyLength &&
		len(keys.SKAr) >= p.IntegrityKeyLength &&
		len(keys.SKEi) >= p.EncryptionKeyLength &&
		len(keys.SKEr) >= p.EncryptionKeyLength &&
		len(keys.SKPi) >= p.PRFKeyLength &&
		len(keys.SKPr) >= p.PRFKeyLength
}
