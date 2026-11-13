package swu

import (
	"context"
	"crypto/rand"
	"crypto/x509"
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
	LegacyEAPAKAIdentity     bool
	Reauthentication         EAPReauthenticationState
	OnReauthenticationState  func(EAPReauthenticationState)
	ReauthenticationLifetime time.Duration
	InitiatorID              ikev2.Identity
	ExpectedResponderID      *ikev2.Identity
	RootCAs                  *x509.CertPool
	EAPOnlyAuthentication    bool
	RequireResponderCert     bool
	SendCertReq              bool
	CertReqCAs               []*x509.Certificate
	ExpectedNetworkName      string
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
	IKESARekey               ChildSARekeyPolicy
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
	if m.Config.ExpectedResponderID != nil {
		idCopy := *m.Config.ExpectedResponderID
		idCopy.Data = append([]byte(nil), m.Config.ExpectedResponderID.Data...)
		cfg.ExpectedResponderID = &idCopy
	}
	if len(m.Config.CertReqCAs) > 0 {
		cfg.CertReqCAs = append([]*x509.Certificate(nil), m.Config.CertReqCAs...)
	}
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
	identityCfg := cfg
	if mgrCfg.LegacyEAPAKAIdentity {
		identityCfg.LegacyEAPAKAIdentity = true
	}
	identity, err := eapIdentityForTunnel(identityCfg, mgrCfg.EAPIdentity)
	if err != nil {
		return nil, err
	}
	operatorRealm := eapOperatorRealm(identity)
	initiatorID := mgrCfg.InitiatorID
	if initiatorID.Type == 0 {
		initiatorID = ikev2.Identity{Type: ikev2.IDRFC822Addr, Data: []byte(identity)}
	}
	expectedResponderID := expectedResponderIdentityFrom(mgrCfg, cfg)
	rootCAs := mgrCfg.RootCAs
	if rootCAs == nil {
		rootCAs = cfg.RootCAs
	}
	expectedNetworkName := firstPacketNonEmpty(cfg.ExpectedNetworkName, mgrCfg.ExpectedNetworkName)
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
		Transport:             transport,
		Init:                  init,
		Keys:                  init.Keys,
		SIM:                   provider,
		EAPKeys:               reauth.Keys,
		InitiatorID:           initiatorID,
		ExpectedResponderID:   expectedResponderID,
		RootCAs:               rootCAs,
		EAPOnlyAuthentication: mgrCfg.EAPOnlyAuthentication || cfg.EAPOnlyAuthentication,
		RequireResponderCert:  mgrCfg.RequireResponderCert || cfg.RequireResponderCert,
		SendCertReq:           mgrCfg.SendCertReq || cfg.SendCertReq,
		CertReqCAs:            mgrCfg.CertReqCAs,
		ExpectedNetworkName:   expectedNetworkName,
		EAPIdentity:           identity,
		EAPPseudonym:          reauth.NextPseudonym,
		EAPReauthIdentity:     reauth.Identity,
		EAPReauthCounter:      reauth.Counter,
		EAPReauthCounterOK:    reauth.CounterOK,
		ChildSA:               mgrCfg.ChildSA,
		ChildSPI:              childSPI,
		TSi:                   mgrCfg.TSi,
		TSr:                   mgrCfg.TSr,
		Configuration:         mgrCfg.Configuration,
		Random:                random,
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
	closeHandler, mobikeHandler, rekeyHandler, ikeRekeyHandler, deleteChildHandler, dpdHandler, peerIKEHandler := controlHandlersFromWithIKERekey(mgrCfg, transport, init, auth, child, result, transportCfg)
	if mode == DataplaneModeKernel {
		session, err := establishKernelSessionFrom(ctx, mgrCfg, cfg, transportCfg, transport, init, child, result, closeHandler, mobikeHandler, rekeyHandler, ikeRekeyHandler, deleteChildHandler, dpdHandler, peerIKEHandler)
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
		MTU:                   effectiveSessionMTU(0, cfg, result),
		Random:                random,
		MOBIKEHandler:         mobikeHandler,
		RekeyHandler:          rekeyHandler,
		IKERekeyHandler:       ikeRekeyHandler,
		ChildSADeleteHandler:  deleteChildHandler,
		PeerIKERequestHandler: peerIKEHandler,
		IKEInit:               init,
		IKEKeys:               init.Keys,
		RekeyPolicy:           mgrCfg.ChildSARekey,
		IKERekeyPolicy:        mgrCfg.IKESARekey,
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

func establishKernelSessionFrom(
	ctx context.Context,
	mgrCfg IKEPacketTunnelManagerConfig,
	cfg TunnelConfig,
	transportCfg IKETransportConfig,
	transport ikev2.InitTransport,
	init ikev2.InitResult,
	child ikev2.ChildSAResult,
	result TunnelResult,
	closeHandler func(context.Context) error,
	mobikeHandler func(context.Context, MOBIKERequest) (MOBIKEResult, error),
	rekeyHandler ChildSARekeyHandler,
	ikeRekeyHandler IKESARekeyHandler,
	deleteChildHandler func(context.Context, []byte) error,
	dpdHandler func(context.Context) error,
	peerIKEHandler PeerIKERequestHandler,
) (TunnelSession, error) {
	if init.NATDetected || transportCfg.UseNonESPMarker {
		_ = enableTransportKernelESPEncap(transport)
	}
	xfrmTemplate := mgrCfg.KernelXFRMConfig
	xfrmCfg, err := KernelXFRMConfigFromIKE(KernelXFRMConfigFromIKEConfig{
		Tunnel:               cfg,
		Transport:            transportCfg,
		Init:                 init,
		ChildSA:              child,
		InnerLocalPrefix:     xfrmTemplate.InnerLocalPrefix,
		InnerRemotePrefix:    xfrmTemplate.InnerRemotePrefix,
		InnerLocalPrefixes:   xfrmTemplate.InnerLocalPrefixes,
		InnerRemotePrefixes:  xfrmTemplate.InnerRemotePrefixes,
		ReplayWindow:         xfrmTemplate.ReplayWindow,
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
	livenessCfg := mgrCfg.Liveness
	if dpdHandler == nil {
		livenessCfg.DisableDPD = true
	}
	liveness, err := NewIKELivenessState(livenessCfg, result.EstablishedAt)
	if err != nil {
		cleanupCtx, cancel := independentCleanupContext(ctx)
		defer cancel()
		return nil, errors.Join(err, xfrmManager.Cleanup(cleanupCtx, xfrmState), closeIKEBestEffort(cleanupCtx, closeHandler))
	}
	session, err := newKernelTunnelSessionWithControl(kernelTunnelSessionConfig{
		Result:                result,
		Tunnel:                cfg,
		TransportCfg:          transportCfg,
		Transport:             transport,
		Init:                  init,
		ChildSA:               child,
		XFRMConfig:            xfrmCfg,
		XFRMManager:           xfrmManager,
		XFRMState:             xfrmState,
		Liveness:              liveness,
		RekeyPolicy:           mgrCfg.ChildSARekey,
		IKERekeyPolicy:        mgrCfg.IKESARekey,
		MOBIKEHandler:         mobikeHandler,
		RekeyHandler:          rekeyHandler,
		IKERekeyHandler:       ikeRekeyHandler,
		ChildSADeleteHandler:  deleteChildHandler,
		DPDHandler:            dpdHandler,
		PeerIKERequestHandler: peerIKEHandler,
		CloseHandler:          closeHandler,
		BackgroundMaintenance: !mgrCfg.DisableControlPlaneHooks,
	})
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
	closeH, mobikeH, rekeyH, _, delH, dpdH, peerH := controlHandlersFromWithIKERekey(mgrCfg, transport, init, auth, child, result, transportCfg)
	return closeH, mobikeH, rekeyH, delH, dpdH, peerH
}

func controlHandlersFromWithIKERekey(mgrCfg IKEPacketTunnelManagerConfig, transport ikev2.InitTransport, init ikev2.InitResult, auth ikev2.FullAuthResult, child ikev2.ChildSAResult, result TunnelResult, transportCfg IKETransportConfig) (func(context.Context) error, func(context.Context, MOBIKERequest) (MOBIKEResult, error), ChildSARekeyHandler, IKESARekeyHandler, func(context.Context, []byte) error, func(context.Context) error, PeerIKERequestHandler) {
	if mgrCfg.DisableControlPlaneHooks || auth.NextMessageID == 0 || !ikeKeysUsable(init.Keys) {
		return func(context.Context) error { return closeIKETransport(transport) }, nil, nil, nil, nil, nil, nil
	}
	control := &ikePacketTunnelControl{
		transport:             transport,
		init:                  init,
		keys:                  init.Keys,
		child:                 child,
		nextMessageID:         auth.NextMessageID,
		result:                cloneTunnelResult(result),
		localIP:               normalizedMOBIKEIP(transportCfg.LocalIP),
		remoteIP:              normalizedMOBIKEIP(transportCfg.RemoteIP),
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
	return closeHandler, mobikeHandler, control.rekeyChildSA, control.rekeyIKESA, control.deleteChildSA, control.dpd, control.handlePeerIKERequest
}

type ikePacketTunnelControl struct {
	opMu                  sync.Mutex
	mu                    sync.Mutex
	transport             ikev2.InitTransport
	init                  ikev2.InitResult
	keys                  ikev2.IKEKeys
	prevInit              *ikev2.InitResult
	prevKeys              ikev2.IKEKeys
	child                 ikev2.ChildSAResult
	nextMessageID         uint32
	rekeyInFlight         int
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
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.mu.Lock()
	transport := c.transport
	messageID := c.nextMessageID
	c.nextMessageID++
	init := c.init
	keys := c.keys
	child := c.child
	random := c.random
	c.mu.Unlock()
	defer func() {
		err = errors.Join(err, closeIKETransport(transport))
	}()
	payloads, err := ikev2.TeardownDeletePayloads(child, true)
	if err != nil {
		return err
	}
	_, err = ikev2.RunInformationalExchange(cleanupCtx, ikev2.InformationalConfig{
		Transport: newRetransmittingIKETransport(transport, defaultIKEControlMaxRetransmits),
		Init:      init,
		Keys:      keys,
		MessageID: messageID,
		Payloads:  payloads,
		Random:    randomWithCryptoFallback(random),
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
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.mu.Lock()
	if c.nextMessageID == 0 && !c.init.Rekeyed {
		c.mu.Unlock()
		return ikev2.ChildSAResult{}, fmt.Errorf("%w: next message_id is zero", ErrInvalidIKEControl)
	}
	messageID := c.nextMessageID
	c.nextMessageID++
	transport := c.transport
	init := c.init
	keys := c.keys
	oldChild := c.child
	random := c.random
	c.rekeyInFlight++
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.rekeyInFlight--
		c.mu.Unlock()
	}()
	res, err := ikev2.RunCREATE_CHILD_SARekey(ctx, ikev2.ChildSARekeyConfig{
		Transport:  newRetransmittingIKETransport(transport, defaultIKEControlMaxRetransmits),
		Init:       init,
		Keys:       keys,
		MessageID:  messageID,
		OldChildSA: oldChild,
		Random:     random,
	})
	if err != nil {
		return ikev2.ChildSAResult{}, err
	}
	c.mu.Lock()
	if res.NextMessageID > c.nextMessageID {
		c.nextMessageID = res.NextMessageID
	}
	c.child = res.ChildSA
	c.result.ChildSAIdentifier = childSAIdentifier(res.ChildSA)
	c.result.IKEEstablished = true
	c.result.IPsecEstablished = true
	c.result.Ready = true
	c.result.Reason = "child sa rekeyed"
	c.mu.Unlock()
	return res.ChildSA, nil
}

func (c *ikePacketTunnelControl) rekeyIKESA(ctx context.Context) (ikev2.InitResult, error) {
	if c == nil {
		return ikev2.InitResult{}, ErrInvalidIKEControl
	}
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.mu.Lock()
	if c.nextMessageID == 0 && !c.init.Rekeyed {
		c.mu.Unlock()
		return ikev2.InitResult{}, fmt.Errorf("%w: next message_id is zero", ErrInvalidIKEControl)
	}
	messageID := c.nextMessageID
	c.nextMessageID++
	deleteOldMsgID := c.nextMessageID
	c.nextMessageID++
	transport := c.transport
	oldInit := c.init
	oldKeys := c.keys
	random := c.random
	c.rekeyInFlight++
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.rekeyInFlight--
		c.mu.Unlock()
	}()
	res, err := ikev2.RunRekeyIKESA(ctx, ikev2.IKESARekeyConfig{
		Transport: newRetransmittingIKETransport(transport, defaultIKEControlMaxRetransmits),
		Init:      oldInit,
		Keys:      oldKeys,
		MessageID: messageID,
		Random:    random,
	})
	if err != nil {
		return ikev2.InitResult{}, err
	}
	c.mu.Lock()
	prevCopy := oldInit
	c.prevInit = &prevCopy
	c.prevKeys = oldKeys
	c.init = res.NewInit
	c.keys = res.NewInit.Keys
	c.nextMessageID = res.NextMessageID
	c.result.IKEEstablished = true
	c.result.Ready = c.result.IPsecEstablished
	c.result.Reason = "ike sa rekeyed"
	c.mu.Unlock()

	delPayload := ikev2.IKEDeletePayload()
	delCtx, cancel := independentCleanupContext(ctx)
	_, _ = ikev2.RunInformationalExchange(delCtx, ikev2.InformationalConfig{
		Transport: newRetransmittingIKETransport(transport, defaultIKEControlMaxRetransmits),
		Init:      oldInit,
		Keys:      oldKeys,
		MessageID: deleteOldMsgID,
		Payloads:  []ikev2.Payload{delPayload},
		Random:    randomWithCryptoFallback(random),
	})
	cancel()
	return res.NewInit, nil
}

func (c *ikePacketTunnelControl) deleteChildSA(ctx context.Context, oldLocalSPI []byte) error {
	if c == nil || len(oldLocalSPI) != 4 {
		return nil
	}
	payload, err := ikev2.ESPDeletePayload(oldLocalSPI)
	if err != nil {
		return err
	}
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.mu.Lock()
	if c.nextMessageID == 0 && !c.init.Rekeyed {
		c.mu.Unlock()
		return fmt.Errorf("%w: next message_id is zero", ErrInvalidIKEControl)
	}
	messageID := c.nextMessageID
	c.nextMessageID++
	transport := c.transport
	init := c.init
	keys := c.keys
	random := c.random
	c.mu.Unlock()
	_, err = ikev2.RunInformationalExchange(ctx, ikev2.InformationalConfig{
		Transport: newRetransmittingIKETransport(transport, defaultIKEControlMaxRetransmits),
		Init:      init,
		Keys:      keys,
		MessageID: messageID,
		Payloads:  []ikev2.Payload{payload},
		Random:    randomWithCryptoFallback(random),
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
	var prevInit *ikev2.InitResult
	if c.prevInit != nil {
		cp := *c.prevInit
		prevInit = &cp
	}
	prevKeys := c.prevKeys
	child := c.child
	random := c.random
	rekeyInFlight := c.rekeyInFlight > 0
	c.mu.Unlock()

	outcome, err := processPeerIKERequest(raw, init, keys, prevInit, prevKeys, child, rekeyInFlight, random)
	if err != nil {
		return PeerIKERequestOutcome{}, err
	}
	if outcome.NewChildSA != nil || outcome.NewIKEInit != nil {
		c.mu.Lock()
		if outcome.NewChildSA != nil {
			c.child = *outcome.NewChildSA
			c.result.ChildSAIdentifier = childSAIdentifier(*outcome.NewChildSA)
			c.result.IKEEstablished = true
			c.result.IPsecEstablished = true
			c.result.Ready = true
			c.result.Reason = "peer child sa rekeyed"
		}
		if outcome.NewIKEInit != nil {
			prevCopy := c.init
			c.prevInit = &prevCopy
			c.prevKeys = c.keys
			c.init = *outcome.NewIKEInit
			c.keys = outcome.NewIKEInit.Keys
			c.nextMessageID = 0
			c.result.IKEEstablished = true
			c.result.Reason = "peer ike sa rekeyed"
		}
		c.mu.Unlock()
	}
	return outcome, nil
}

func (c *ikePacketTunnelControl) dpd(ctx context.Context) error {
	if c == nil {
		return ErrInvalidIKEControl
	}
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.mu.Lock()
	messageID := c.nextMessageID
	c.nextMessageID++
	transport := c.transport
	init := c.init
	keys := c.keys
	random := c.random
	c.mu.Unlock()
	_, err := ikev2.RunLivenessCheck(ctx, ikev2.InformationalConfig{
		Transport: newRetransmittingIKETransport(transport, defaultIKEControlMaxRetransmits),
		Init:      init,
		Keys:      keys,
		MessageID: messageID,
		Random:    randomWithCryptoFallback(random),
	})
	return err
}

func (c *ikePacketTunnelControl) mobike(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
	if c == nil {
		return MOBIKEResult{}, ErrInvalidIKEControl
	}
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.mu.Lock()
	messageID := c.nextMessageID
	c.nextMessageID++
	transport := c.transport
	init := c.init
	keys := c.keys
	result := cloneTunnelResult(c.result)
	localIP := normalizedMOBIKEIP(c.localIP)
	remoteIP := normalizedMOBIKEIP(c.remoteIP)
	localPort := c.localPort
	remotePort := c.remotePort
	additional := cloneIPs(c.additionalAddresses)
	noAdditional := c.noAdditionalAddresses
	random := c.random
	c.mu.Unlock()

	if newIP := normalizedMOBIKEIP(nil, req.NewIP); newIP != nil {
		if rebinder, ok := transport.(localIPRebinder); ok {
			reboundAddr, err := rebinder.RebindLocalIP(ctx, newIP)
			if err != nil {
				return MOBIKEResult{}, err
			}
			localIP = newIP
			if udpAddr, ok := reboundAddr.(*net.UDPAddr); ok && udpAddr.Port > 0 && udpAddr.Port <= 65535 {
				localPort = uint16(udpAddr.Port)
			}
		} else {
			localIP = newIP
		}
	}

	payloads, err := mobikeUpdatePayloads(IKEMOBIKEConfig{
		Init:                  init,
		Result:                result,
		LocalIP:               localIP,
		RemoteIP:              remoteIP,
		LocalPort:             localPort,
		RemotePort:            remotePort,
		AdditionalAddresses:   additional,
		NoAdditionalAddresses: noAdditional,
	}, additional, req)
	if err != nil {
		return MOBIKEResult{}, err
	}
	res, err := ikev2.RunInformationalExchange(ctx, ikev2.InformationalConfig{
		Transport: newRetransmittingIKETransport(transport, defaultIKEControlMaxRetransmits),
		Init:      init,
		Keys:      keys,
		MessageID: messageID,
		Payloads:  payloads,
		Random:    randomWithCryptoFallback(random),
	})
	if err != nil {
		return MOBIKEResult{}, err
	}
	if err := rejectMOBIKEResponse(res.ResponseInner); err != nil {
		return MOBIKEResult{}, err
	}
	outerLocal := firstPacketNonEmpty(req.NewIP, req.OldIP, result.EPDGAddress)
	if localIP != nil {
		outerLocal = localIP.String()
	}
	c.mu.Lock()
	if localIP != nil {
		c.localIP = append(net.IP(nil), localIP...)
	}
	if localPort != 0 {
		c.localPort = localPort
	}
	c.result.IKEEstablished = true
	c.result.IPsecEstablished = true
	c.result.Ready = true
	c.result.Reason = "mobike update sa addresses sent"
	localInner := c.result.LocalInnerIP
	remoteInner := c.result.RemoteInnerIP
	c.mu.Unlock()
	return MOBIKEResult{
		Rekeyed:          false,
		OuterLocalIP:     outerLocal,
		LocalInnerIP:     localInner,
		RemoteInnerIP:    remoteInner,
		IKEEstablished:   true,
		IPsecEstablished: true,
		Reason:           "mobike update sa addresses sent",
		UpdatedAt:        time.Now(),
	}, nil
}

func expectedResponderIdentityFrom(mgrCfg IKEPacketTunnelManagerConfig, cfg TunnelConfig) *ikev2.Identity {
	if mgrCfg.ExpectedResponderID != nil {
		cp := *mgrCfg.ExpectedResponderID
		cp.Data = append([]byte(nil), mgrCfg.ExpectedResponderID.Data...)
		return &cp
	}
	raw := strings.TrimSpace(cfg.ExpectedResponderID)
	if raw == "" {
		return nil
	}
	if ip := net.ParseIP(strings.Trim(raw, "[]")); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return &ikev2.Identity{Type: ikev2.IDIPv4Addr, Data: append([]byte(nil), ip4...)}
		}
		return &ikev2.Identity{Type: ikev2.IDIPv6Addr, Data: append([]byte(nil), ip.To16()...)}
	}
	if strings.Contains(raw, "@") {
		return &ikev2.Identity{Type: ikev2.IDRFC822Addr, Data: []byte(raw)}
	}
	return &ikev2.Identity{Type: ikev2.IDFQDN, Data: []byte(raw)}
}

func tunnelResultFromIKE(cfg TunnelConfig, epdg string, init ikev2.InitResult, child ikev2.ChildSAResult, mode string) TunnelResult {
	mode = firstPacketNonEmpty(mode, DataplaneModeUserspace)
	v4Addrs := childConfigurationIPStrings(child, ikev2.ConfigInternalIPv4Address)
	v6Addrs := childConfigurationIPStrings(child, ikev2.ConfigInternalIPv6Address)
	localV4 := childConfigurationAddress(child, ikev2.ConfigInternalIPv4Address)
	localV6 := childConfigurationAddress(child, ikev2.ConfigInternalIPv6Address)
	localV6Prefix, localV6PrefixLen, _ := firstChildConfigurationIPv6Prefix(child)
	if cfgInner := strings.TrimSpace(cfg.InnerLocalIP); cfgInner != "" {
		if parsed, ok := parseInnerIPFamily(cfgInner); ok {
			if parsed.Is4() && localV4 == "" {
				localV4 = parsed.String()
			} else if parsed.Is6() && localV6 == "" {
				localV6 = parsed.String()
				if pfx, err := netip.ParsePrefix(cfgInner); err == nil {
					localV6PrefixLen = uint8(pfx.Bits())
					localV6Prefix = fmt.Sprintf("%s/%d", parsed.String(), pfx.Bits())
				}
			}
		}
	}
	innerIPs := mergeInnerIPStrings(localV4, localV6, v4Addrs, v6Addrs)
	if cfgInner := strings.TrimSpace(cfg.InnerLocalIP); cfgInner != "" {
		innerIPs = mergeInnerIPStrings(cfgInner, "", innerIPs, nil)
	}
	return TunnelResult{
		Ready:                   true,
		Mode:                    mode,
		EPDGAddress:             epdg,
		LocalInnerIP:            firstPacketNonEmpty(cfg.InnerLocalIP, localV4, localV6),
		LocalInnerIPv4:          localV4,
		LocalInnerIPv6:          localV6,
		LocalInnerIPv6PrefixLen: localV6PrefixLen,
		LocalInnerIPv6Prefix:    localV6Prefix,
		LocalInnerIPs:           innerIPs,
		RemoteInnerIP:           strings.TrimSpace(cfg.RemoteInnerIP),
		DNSServers:              childConfigurationDNS(child),
		PCSCFServers:            childConfigurationPCSCF(child),
		ESPEncryptionID:         child.Keys.Profile.EncryptionID,
		ESPIntegrityID:          child.Keys.Profile.IntegrityID,
		InitiatorSelectors:      childTrafficSelectorStrings(child.TSi),
		ResponderSelectors:      childTrafficSelectorStrings(child.TSr),
		IKEEstablished:          true,
		IPsecEstablished:        true,
		MOBIKESupported:         init.MOBIKESupported,
		ChildSAIdentifier:       childSAIdentifier(child),
		Reason:                  "ike ipsec tunnel ready",
		EstablishedAt:           time.Now(),
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
	var all []string
	all = append(all, childConfigurationIPStrings(child, ikev2.ConfigPCSCFIPv4Address)...)
	all = append(all, childConfigurationIPStrings(child, ikev2.Config3GPPPCSCFIPv4Address)...)
	all = append(all, childConfigurationIPStrings(child, ikev2.ConfigPCSCFIPv6Address)...)
	all = append(all, childConfigurationIPStrings(child, ikev2.Config3GPPPCSCFIPv6Address)...)
	seen := make(map[string]bool, len(all))
	var out []string
	for _, item := range all {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

func childConfigurationIPStrings(child ikev2.ChildSAResult, attrType uint16) []string {
	if child.Configuration == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, attr := range child.Configuration.Attributes {
		if (attr.Type & 0x7FFF) != attrType {
			continue
		}
		var ip string
		switch attrType {
		case ikev2.ConfigInternalIPv4Address, ikev2.ConfigInternalIPv4DNS, ikev2.ConfigPCSCFIPv4Address, ikev2.Config3GPPPCSCFIPv4Address:
			if len(attr.Value) != net.IPv4len {
				continue
			}
			ip = net.IP(attr.Value).To4().String()
		case ikev2.ConfigInternalIPv6Address:
			switch len(attr.Value) {
			case 17:
				if attr.Value[16] > 128 {
					continue
				}
				ip = net.IP(attr.Value[:16]).String()
			case net.IPv6len:
				ip = net.IP(attr.Value).String()
			default:
				continue
			}
		case ikev2.ConfigInternalIPv6DNS, ikev2.ConfigPCSCFIPv6Address, ikev2.Config3GPPPCSCFIPv6Address:
			if len(attr.Value) != net.IPv6len {
				continue
			}
			ip = net.IP(attr.Value).String()
		default:
			continue
		}
		if ip != "" && !seen[ip] {
			out = append(out, ip)
			seen[ip] = true
		}
	}
	return out
}

func firstChildConfigurationIPv6Prefix(child ikev2.ChildSAResult) (string, uint8, bool) {
	if child.Configuration == nil {
		return "", 0, false
	}
	for _, attr := range child.Configuration.Attributes {
		if (attr.Type & 0x7FFF) != ikev2.ConfigInternalIPv6Address {
			continue
		}
		switch len(attr.Value) {
		case 17:
			if attr.Value[16] > 128 {
				continue
			}
			ip := net.IP(attr.Value[:16]).String()
			if ip == "" {
				continue
			}
			return fmt.Sprintf("%s/%d", ip, attr.Value[16]), attr.Value[16], true
		case net.IPv6len:
			ip := net.IP(attr.Value).String()
			if ip == "" {
				continue
			}
			return "", 128, false
		}
	}
	return "", 0, false
}

func childConfigurationIPv6Prefixes(child ikev2.ChildSAResult) []string {
	if child.Configuration == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, attr := range child.Configuration.Attributes {
		if (attr.Type & 0x7FFF) != ikev2.ConfigInternalIPv6Address {
			continue
		}
		var pfx string
		switch len(attr.Value) {
		case 17:
			if attr.Value[16] > 128 {
				continue
			}
			ip := net.IP(attr.Value[:16]).String()
			if ip != "" {
				pfx = fmt.Sprintf("%s/%d", ip, attr.Value[16])
			}
		case net.IPv6len:
			ip := net.IP(attr.Value).String()
			if ip != "" {
				pfx = ip + "/128"
			}
		}
		if pfx != "" && !seen[pfx] {
			seen[pfx] = true
			out = append(out, pfx)
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
		if cfg.LegacyEAPAKAIdentity {
			prefix = "0"
		} else {
			prefix = "6"
		}
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
