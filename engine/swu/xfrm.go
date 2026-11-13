package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/kimoju/vowifi-go/engine/swu/ikev2"
)

var ErrInvalidXFRMConfig = errors.New("invalid swu xfrm config")

const (
	xfrmAeadAESGCMRFC4106   = "rfc4106(gcm(aes))"
	xfrmAESGCMSaltLength    = 4
	xfrmAESGCMICVBits       = 128
	DefaultXFRMReplayWindow = 64
)

var (
	nextKernelXFRMReqID atomic.Uint32
	nextKernelXFRMIfID  atomic.Uint32
)

type XFRMPolicyPair struct {
	LocalPrefix  string
	RemotePrefix string
}

type XFRMInterfaceConfig struct {
	Name           string
	OuterDev       string
	IfID           uint32
	MTU            int
	SkipCreateLink bool
}

type XFRMNATTraversalConfig struct {
	Enabled         bool
	LocalPort       uint16
	RemotePort      uint16
	OriginalAddress string
}

type KernelXFRMConfig struct {
	ChildSA              ikev2.ChildSAResult
	OuterLocalIP         string
	OuterRemoteIP        string
	InnerLocalPrefix     string
	InnerRemotePrefix    string
	InnerLocalPrefixes   []string
	InnerRemotePrefixes  []string
	PolicyPairs          []XFRMPolicyPair
	ReplayWindow         int
	ReqID                int
	Mark                 string
	InterfaceID          uint32
	IncludeForwardPolicy bool
	XFRMInterface        XFRMInterfaceConfig
	NATTraversal         XFRMNATTraversalConfig
}

// KernelXFRMConfigFromIKEConfig carries the negotiated IKE state needed to build a kernel XFRM config.
type KernelXFRMConfigFromIKEConfig struct {
	Tunnel               TunnelConfig
	Transport            IKETransportConfig
	Init                 ikev2.InitResult
	ChildSA              ikev2.ChildSAResult
	InnerLocalPrefix     string
	InnerRemotePrefix    string
	InnerLocalPrefixes   []string
	InnerRemotePrefixes  []string
	ReplayWindow         int
	ReqID                int
	Mark                 string
	InterfaceID          uint32
	IncludeForwardPolicy bool
	XFRMInterface        XFRMInterfaceConfig
	NATTraversal         XFRMNATTraversalConfig
}

type KernelXFRMState struct {
	undo []ipCommand
}

type KernelXFRMManager interface {
	Apply(context.Context, KernelXFRMConfig) (KernelXFRMState, error)
	Cleanup(context.Context, KernelXFRMState) error
}

type LinuxXFRMManager struct {
	Runner IPCommandRunner
}

func (m LinuxXFRMManager) Apply(ctx context.Context, cfg KernelXFRMConfig) (KernelXFRMState, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	runner := m.Runner
	if runner == nil {
		runner = ExecIPCommandRunner{}
	}
	commands, err := buildKernelXFRMCommands(cfg)
	if err != nil {
		return KernelXFRMState{}, err
	}
	var state KernelXFRMState
	for _, command := range commands {
		if err := runIPApplyCommand(ctx, runner, command); err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), defaultSWUCleanupTimeout)
			rollbackErr := runIPUndo(cleanupCtx, runner, state.undo)
			cancel()
			if rollbackErr != nil {
				return state, errors.Join(err, rollbackErr)
			}
			return state, err
		}
		if len(command.undo) > 0 {
			state.undo = append(state.undo, ipCommand{args: append([]string(nil), command.undo...)})
		}
	}
	return state, nil
}

func (m LinuxXFRMManager) Cleanup(ctx context.Context, state KernelXFRMState) error {
	cleanupCtx, cancel := independentCleanupContext(ctx)
	defer cancel()
	runner := m.Runner
	if runner == nil {
		runner = ExecIPCommandRunner{}
	}
	return runIPUndo(cleanupCtx, runner, state.undo)
}

// KernelXFRMConfigFromIKE builds a validated XFRM config without applying kernel state.
func KernelXFRMConfigFromIKE(cfg KernelXFRMConfigFromIKEConfig) (KernelXFRMConfig, error) {
	outerLocal := xfrmIPString(cfg.Transport.LocalIP, tunnelAddressHost(cfg.Transport.LocalAddr), tunnelAddressHost(cfg.Tunnel.OuterLocalIP))
	if outerLocal == "" {
		return KernelXFRMConfig{}, fmt.Errorf("%w: outer local ip is empty", ErrInvalidXFRMConfig)
	}
	epdg := firstPacketNonEmpty(cfg.Transport.EPDGAddress, cfg.Tunnel.EPDGAddress, epdgAddressForTunnel(cfg.Tunnel))
	outerRemote := xfrmIPString(cfg.Transport.RemoteIP, tunnelAddressHost(cfg.Transport.RemoteAddr), tunnelAddressHost(epdg))
	if outerRemote == "" {
		return KernelXFRMConfig{}, fmt.Errorf("%w: outer remote ip is empty", ErrInvalidXFRMConfig)
	}

	localPrefixes, remotePrefixes, pairs, err := deriveXFRMSelectorPairsFromIKE(cfg)
	if err != nil {
		return KernelXFRMConfig{}, err
	}
	if len(pairs) == 0 {
		if len(localPrefixes) == 0 {
			return KernelXFRMConfig{}, fmt.Errorf("%w: inner local prefix is empty", ErrInvalidXFRMConfig)
		}
		return KernelXFRMConfig{}, fmt.Errorf("%w: inner remote prefix is empty", ErrInvalidXFRMConfig)
	}

	reqID := cfg.ReqID
	if reqID == 0 {
		reqID = int(nextKernelXFRMReqID.Add(1))
	}
	xfrmi := cfg.XFRMInterface
	ifID := cfg.InterfaceID
	if strings.TrimSpace(xfrmi.Name) != "" {
		if xfrmi.IfID == 0 && ifID == 0 {
			allocated := nextKernelXFRMIfID.Add(1)
			xfrmi.IfID = allocated
			ifID = allocated
		}
		if xfrmi.MTU == 0 {
			if addr, parseErr := netip.ParseAddr(outerRemote); parseErr == nil && addr.Is6() {
				xfrmi.MTU = MinIPv6TunnelInnerMTU
			} else {
				xfrmi.MTU = DefaultTunnelInnerMTU
			}
		}
	}

	natt := cfg.NATTraversal
	if natt.Enabled || cfg.Init.NATDetected {
		natt.Enabled = true
		if natt.LocalPort == 0 {
			natt.LocalPort = xfrmTransportPort(cfg.Transport.LocalPort, cfg.Transport.LocalAddr)
		}
		if natt.RemotePort == 0 {
			natt.RemotePort = xfrmTransportPort(cfg.Transport.RemotePort, cfg.Transport.RemoteAddr)
		}
	}
	out := KernelXFRMConfig{
		ChildSA:              cfg.ChildSA,
		OuterLocalIP:         outerLocal,
		OuterRemoteIP:        outerRemote,
		InnerLocalPrefix:     pairs[0].LocalPrefix,
		InnerRemotePrefix:    pairs[0].RemotePrefix,
		InnerLocalPrefixes:   localPrefixes,
		InnerRemotePrefixes:  remotePrefixes,
		PolicyPairs:          pairs,
		ReplayWindow:         cfg.ReplayWindow,
		ReqID:                reqID,
		Mark:                 cfg.Mark,
		InterfaceID:          ifID,
		IncludeForwardPolicy: cfg.IncludeForwardPolicy,
		XFRMInterface:        xfrmi,
		NATTraversal:         natt,
	}
	params, err := normalizeKernelXFRMConfig(out)
	if err != nil {
		return KernelXFRMConfig{}, err
	}
	out.OuterLocalIP = params.outerLocal
	out.OuterRemoteIP = params.outerRemote
	out.InnerLocalPrefix = params.innerLocal
	out.InnerRemotePrefix = params.innerRemote
	out.PolicyPairs = append([]XFRMPolicyPair(nil), params.policyPairs...)
	if params.natt.enabled {
		out.NATTraversal.Enabled = true
		out.NATTraversal.LocalPort = xfrmPortUint16(params.natt.localPort)
		out.NATTraversal.RemotePort = xfrmPortUint16(params.natt.remotePort)
		out.NATTraversal.OriginalAddress = params.natt.originalAddress
	}
	return out, nil
}

func deriveXFRMSelectorPairsFromIKE(cfg KernelXFRMConfigFromIKEConfig) ([]string, []string, []XFRMPolicyPair, error) {
	var localCandidates []string
	if strings.TrimSpace(cfg.InnerLocalPrefix) != "" {
		localCandidates = append(localCandidates, cfg.InnerLocalPrefix)
	}
	localCandidates = append(localCandidates, cfg.InnerLocalPrefixes...)
	if len(localCandidates) == 0 {
		if strings.TrimSpace(cfg.Tunnel.InnerLocalIP) != "" {
			localCandidates = append(localCandidates, cfg.Tunnel.InnerLocalIP)
		}
		localCandidates = append(localCandidates, childConfigurationIPStrings(cfg.ChildSA, ikev2.ConfigInternalIPv4Address)...)
		localCandidates = append(localCandidates, childConfigurationIPv6Prefixes(cfg.ChildSA)...)
		if len(localCandidates) == 0 {
			localCandidates = append(localCandidates, xfrmTrafficSelectorPrefixes(cfg.ChildSA.TSi)...)
		} else {
			// Also include any negotiated address family from TSi not yet covered by CFG_REPLY.
			hasV4, hasV6 := addressFamiliesForTUN(localCandidates)
			for _, p := range xfrmTrafficSelectorPrefixes(cfg.ChildSA.TSi) {
				if is4, err := xfrmPrefixIs4(p); err == nil {
					if (is4 && !hasV4) || (!is4 && !hasV6) {
						localCandidates = append(localCandidates, p)
					}
				}
			}
		}
	}

	var remoteCandidates []string
	if strings.TrimSpace(cfg.InnerRemotePrefix) != "" {
		remoteCandidates = append(remoteCandidates, cfg.InnerRemotePrefix)
	}
	remoteCandidates = append(remoteCandidates, cfg.InnerRemotePrefixes...)
	if len(remoteCandidates) == 0 {
		if strings.TrimSpace(cfg.Tunnel.RemoteInnerIP) != "" {
			remoteCandidates = append(remoteCandidates, cfg.Tunnel.RemoteInnerIP)
		}
		if len(remoteCandidates) == 0 {
			remoteCandidates = append(remoteCandidates, xfrmTrafficSelectorPrefixes(cfg.ChildSA.TSr)...)
		} else {
			hasV4, hasV6 := addressFamiliesForTUN(remoteCandidates)
			for _, p := range xfrmTrafficSelectorPrefixes(cfg.ChildSA.TSr) {
				if is4, err := xfrmPrefixIs4(p); err == nil {
					if (is4 && !hasV4) || (!is4 && !hasV6) {
						remoteCandidates = append(remoteCandidates, p)
					}
				}
			}
		}
	}

	normLocals, err := normalizeUniqueXFRMPrefixes(localCandidates, "inner local prefix")
	if err != nil {
		return nil, nil, nil, err
	}
	normRemotes, err := normalizeUniqueXFRMPrefixes(remoteCandidates, "inner remote prefix")
	if err != nil {
		return nil, nil, nil, err
	}
	pairs, err := pairXFRMPrefixesByFamily(normLocals, normRemotes)
	if err != nil {
		return nil, nil, nil, err
	}
	return normLocals, normRemotes, pairs, nil
}

func normalizeUniqueXFRMPrefixes(values []string, field string) ([]string, error) {
	seen := make(map[string]bool, len(values))
	var out []string
	for _, raw := range values {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		norm, err := normalizeIPPrefix(raw, field)
		if err != nil {
			return nil, wrapXFRMError(err)
		}
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	return out, nil
}

func pairXFRMPrefixesByFamily(locals, remotes []string) ([]XFRMPolicyPair, error) {
	var local4, local6, remote4, remote6 []string
	for _, l := range locals {
		is4, err := xfrmPrefixIs4(l)
		if err != nil {
			return nil, err
		}
		if is4 {
			local4 = append(local4, l)
		} else {
			local6 = append(local6, l)
		}
	}
	for _, r := range remotes {
		is4, err := xfrmPrefixIs4(r)
		if err != nil {
			return nil, err
		}
		if is4 {
			remote4 = append(remote4, r)
		} else {
			remote6 = append(remote6, r)
		}
	}
	var pairs []XFRMPolicyPair
	for _, l := range local4 {
		for _, r := range remote4 {
			pairs = append(pairs, XFRMPolicyPair{LocalPrefix: l, RemotePrefix: r})
		}
	}
	for _, l := range local6 {
		for _, r := range remote6 {
			pairs = append(pairs, XFRMPolicyPair{LocalPrefix: l, RemotePrefix: r})
		}
	}
	if len(pairs) == 0 && len(locals) > 0 && len(remotes) > 0 {
		return nil, fmt.Errorf("%w: inner local and remote prefix families differ", ErrInvalidXFRMConfig)
	}
	return pairs, nil
}

func buildKernelXFRMCommands(cfg KernelXFRMConfig) ([]ipCommand, error) {
	params, err := normalizeKernelXFRMConfig(cfg)
	if err != nil {
		return nil, err
	}
	var commands []ipCommand
	if params.xfrmiName != "" {
		if !cfg.XFRMInterface.SkipCreateLink {
			args := []string{"link", "add", params.xfrmiName, "type", "xfrm", "dev", params.xfrmiOuterDev, "if_id", params.ifID}
			delArgs := []string{"link", "del", params.xfrmiName}
			commands = append(commands, ipCommand{
				args:     args,
				undo:     delArgs,
				preClean: append([]string(nil), delArgs...),
			})
		}
		if params.xfrmiMTU > 0 {
			commands = append(commands, ipCommand{args: []string{"link", "set", "dev", params.xfrmiName, "mtu", strconv.Itoa(params.xfrmiMTU)}})
		}
		commands = append(commands, ipCommand{args: []string{"link", "set", "dev", params.xfrmiName, "up"}})
	}
	commands = append(commands,
		ipCommand{args: xfrmStateAddArgs(params, true), undo: xfrmStateDelArgs(params, true)},
		ipCommand{args: xfrmStateAddArgs(params, false), undo: xfrmStateDelArgs(params, false)},
	)
	for _, pair := range params.policyPairs {
		commands = append(commands,
			ipCommand{args: xfrmPolicyAddArgsForPair(params, pair, "out"), undo: xfrmPolicyDelArgsForPair(params, pair, "out")},
			ipCommand{args: xfrmPolicyAddArgsForPair(params, pair, "in"), undo: xfrmPolicyDelArgsForPair(params, pair, "in")},
		)
		if params.includeForward {
			commands = append(commands, ipCommand{args: xfrmPolicyAddArgsForPair(params, pair, "fwd"), undo: xfrmPolicyDelArgsForPair(params, pair, "fwd")})
		}
	}
	return commands, nil
}

type kernelXFRMParams struct {
	child          ikev2.ChildSAResult
	outerLocal     string
	outerRemote    string
	innerLocal     string
	innerRemote    string
	policyPairs    []XFRMPolicyPair
	replayWindow   int
	reqID          string
	mark           string
	ifID           string
	includeForward bool
	xfrmiName      string
	xfrmiOuterDev  string
	xfrmiMTU       int
	natt           kernelXFRMNATTraversal
}

type kernelXFRMNATTraversal struct {
	enabled         bool
	localPort       string
	remotePort      string
	originalAddress string
}

func normalizeKernelXFRMConfig(cfg KernelXFRMConfig) (kernelXFRMParams, error) {
	outerLocal, err := normalizeIPAddress(cfg.OuterLocalIP, "outer local ip")
	if err != nil {
		return kernelXFRMParams{}, wrapXFRMError(err)
	}
	outerRemote, err := normalizeIPAddress(cfg.OuterRemoteIP, "outer remote ip")
	if err != nil {
		return kernelXFRMParams{}, wrapXFRMError(err)
	}
	outerLocalIs4, err := xfrmAddressIs4(outerLocal)
	if err != nil {
		return kernelXFRMParams{}, wrapXFRMError(err)
	}
	outerRemoteIs4, err := xfrmAddressIs4(outerRemote)
	if err != nil {
		return kernelXFRMParams{}, wrapXFRMError(err)
	}
	if outerLocalIs4 != outerRemoteIs4 {
		return kernelXFRMParams{}, fmt.Errorf("%w: outer local and remote address families differ", ErrInvalidXFRMConfig)
	}

	var policyPairs []XFRMPolicyPair
	if len(cfg.PolicyPairs) > 0 {
		seen := make(map[XFRMPolicyPair]bool, len(cfg.PolicyPairs))
		for _, pair := range cfg.PolicyPairs {
			localNorm, lErr := normalizeIPPrefix(pair.LocalPrefix, "inner local prefix")
			if lErr != nil {
				return kernelXFRMParams{}, wrapXFRMError(lErr)
			}
			remoteNorm, rErr := normalizeIPPrefix(pair.RemotePrefix, "inner remote prefix")
			if rErr != nil {
				return kernelXFRMParams{}, wrapXFRMError(rErr)
			}
			if fErr := validateKernelXFRMInnerPair(localNorm, remoteNorm); fErr != nil {
				return kernelXFRMParams{}, fErr
			}
			normPair := XFRMPolicyPair{LocalPrefix: localNorm, RemotePrefix: remoteNorm}
			if !seen[normPair] {
				seen[normPair] = true
				policyPairs = append(policyPairs, normPair)
			}
		}
	} else if len(cfg.InnerLocalPrefixes) > 0 || len(cfg.InnerRemotePrefixes) > 0 {
		localIn := cfg.InnerLocalPrefixes
		if len(localIn) == 0 && strings.TrimSpace(cfg.InnerLocalPrefix) != "" {
			localIn = []string{cfg.InnerLocalPrefix}
		}
		remoteIn := cfg.InnerRemotePrefixes
		if len(remoteIn) == 0 && strings.TrimSpace(cfg.InnerRemotePrefix) != "" {
			remoteIn = []string{cfg.InnerRemotePrefix}
		}
		normLocals, lErr := normalizeUniqueXFRMPrefixes(localIn, "inner local prefix")
		if lErr != nil {
			return kernelXFRMParams{}, lErr
		}
		normRemotes, rErr := normalizeUniqueXFRMPrefixes(remoteIn, "inner remote prefix")
		if rErr != nil {
			return kernelXFRMParams{}, rErr
		}
		if len(normLocals) == 0 {
			return kernelXFRMParams{}, fmt.Errorf("%w: inner local prefix is empty", ErrInvalidXFRMConfig)
		}
		if len(normRemotes) == 0 {
			return kernelXFRMParams{}, fmt.Errorf("%w: inner remote prefix is empty", ErrInvalidXFRMConfig)
		}
		policyPairs, err = pairXFRMPrefixesByFamily(normLocals, normRemotes)
		if err != nil {
			return kernelXFRMParams{}, err
		}
	} else {
		innerLocal, lErr := normalizeIPPrefix(cfg.InnerLocalPrefix, "inner local prefix")
		if lErr != nil {
			return kernelXFRMParams{}, wrapXFRMError(lErr)
		}
		innerRemote, rErr := normalizeIPPrefix(cfg.InnerRemotePrefix, "inner remote prefix")
		if rErr != nil {
			return kernelXFRMParams{}, wrapXFRMError(rErr)
		}
		if fErr := validateKernelXFRMInnerPair(innerLocal, innerRemote); fErr != nil {
			return kernelXFRMParams{}, fErr
		}
		policyPairs = []XFRMPolicyPair{{LocalPrefix: innerLocal, RemotePrefix: innerRemote}}
	}
	if len(policyPairs) == 0 {
		return kernelXFRMParams{}, fmt.Errorf("%w: inner policy pairs are empty", ErrInvalidXFRMConfig)
	}

	if err := validateChildSAForXFRM(cfg.ChildSA); err != nil {
		return kernelXFRMParams{}, err
	}
	replayWindow := cfg.ReplayWindow
	if replayWindow < 0 {
		return kernelXFRMParams{}, fmt.Errorf("%w: replay window must be non-negative", ErrInvalidXFRMConfig)
	}
	if replayWindow == 0 {
		replayWindow = DefaultXFRMReplayWindow
	}
	reqID := cfg.ReqID
	if reqID < 0 {
		return kernelXFRMParams{}, fmt.Errorf("%w: reqid must be positive", ErrInvalidXFRMConfig)
	}
	if reqID == 0 {
		reqID = 1
	}
	mark := ""
	if strings.TrimSpace(cfg.Mark) != "" {
		mark, err = normalizeRoutingToken(cfg.Mark, "xfrm mark")
		if err != nil {
			return kernelXFRMParams{}, wrapXFRMError(err)
		}
	}
	ifID := cfg.InterfaceID
	xfrmiName := strings.TrimSpace(cfg.XFRMInterface.Name)
	xfrmiOuterDev := strings.TrimSpace(cfg.XFRMInterface.OuterDev)
	if cfg.XFRMInterface.IfID != 0 {
		ifID = cfg.XFRMInterface.IfID
	}
	if xfrmiName != "" {
		if err := validateRoutingInterfaceName(xfrmiName); err != nil {
			return kernelXFRMParams{}, fmt.Errorf("%w: xfrm interface name: %v", ErrInvalidXFRMConfig, err)
		}
		if xfrmiOuterDev == "" {
			return kernelXFRMParams{}, fmt.Errorf("%w: xfrm interface outer dev is empty", ErrInvalidXFRMConfig)
		}
		if err := validateRoutingInterfaceName(xfrmiOuterDev); err != nil {
			return kernelXFRMParams{}, fmt.Errorf("%w: xfrm interface outer dev: %v", ErrInvalidXFRMConfig, err)
		}
		if ifID == 0 {
			return kernelXFRMParams{}, fmt.Errorf("%w: xfrm interface if_id is zero", ErrInvalidXFRMConfig)
		}
		if cfg.XFRMInterface.MTU < 0 {
			return kernelXFRMParams{}, fmt.Errorf("%w: xfrm interface mtu must be positive", ErrInvalidXFRMConfig)
		}
	}
	natt, err := normalizeXFRMNATTraversal(cfg.NATTraversal)
	if err != nil {
		return kernelXFRMParams{}, err
	}
	return kernelXFRMParams{
		child:          cfg.ChildSA,
		outerLocal:     outerLocal,
		outerRemote:    outerRemote,
		innerLocal:     policyPairs[0].LocalPrefix,
		innerRemote:    policyPairs[0].RemotePrefix,
		policyPairs:    policyPairs,
		replayWindow:   replayWindow,
		reqID:          strconv.Itoa(reqID),
		mark:           mark,
		ifID:           xfrmID(ifID),
		includeForward: cfg.IncludeForwardPolicy,
		xfrmiName:      xfrmiName,
		xfrmiOuterDev:  xfrmiOuterDev,
		xfrmiMTU:       cfg.XFRMInterface.MTU,
		natt:           natt,
	}, nil
}

func normalizeXFRMNATTraversal(cfg XFRMNATTraversalConfig) (kernelXFRMNATTraversal, error) {
	if !cfg.Enabled {
		if cfg.LocalPort != 0 || cfg.RemotePort != 0 || strings.TrimSpace(cfg.OriginalAddress) != "" {
			return kernelXFRMNATTraversal{}, fmt.Errorf("%w: nat traversal parameters require nat traversal enabled", ErrInvalidXFRMConfig)
		}
		return kernelXFRMNATTraversal{}, nil
	}
	localPort := cfg.LocalPort
	if localPort == 0 {
		localPort = 4500
	}
	remotePort := cfg.RemotePort
	if remotePort == 0 {
		remotePort = 4500
	}
	originalAddress := "0.0.0.0"
	if strings.TrimSpace(cfg.OriginalAddress) != "" {
		addr, err := normalizeIPAddress(cfg.OriginalAddress, "xfrm nat original address")
		if err != nil {
			return kernelXFRMNATTraversal{}, wrapXFRMError(err)
		}
		originalAddress = addr
	}
	return kernelXFRMNATTraversal{
		enabled:         true,
		localPort:       strconv.Itoa(int(localPort)),
		remotePort:      strconv.Itoa(int(remotePort)),
		originalAddress: originalAddress,
	}, nil
}

func validateChildSAForXFRM(child ikev2.ChildSAResult) error {
	if _, err := xfrmSPI(child.RemoteSPI); err != nil {
		return fmt.Errorf("%w: remote spi: %v", ErrInvalidXFRMConfig, err)
	}
	if _, err := xfrmSPI(child.LocalSPI); err != nil {
		return fmt.Errorf("%w: local spi: %v", ErrInvalidXFRMConfig, err)
	}
	switch child.Keys.Profile.EncryptionID {
	case ikev2.ENCR_AES_CBC:
		if _, _, err := xfrmAuthAlgorithm(child.Keys.Profile.IntegrityID); err != nil {
			return err
		}
		if err := validateXFRMCBCKeys(child.Keys.Profile, child.Keys.Outbound, "outbound"); err != nil {
			return err
		}
		if err := validateXFRMCBCKeys(child.Keys.Profile, child.Keys.Inbound, "inbound"); err != nil {
			return err
		}
	case ikev2.ENCR_AES_GCM_16:
		if child.Keys.Profile.IntegrityID != 0 || child.Keys.Profile.IntegrityKeyLength != 0 {
			return fmt.Errorf("%w: AES-GCM ESP must not include integrity transform", ErrInvalidXFRMConfig)
		}
		if err := validateXFRMAEADKeys(child.Keys.Profile, child.Keys.Outbound, "outbound"); err != nil {
			return err
		}
		if err := validateXFRMAEADKeys(child.Keys.Profile, child.Keys.Inbound, "inbound"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unsupported ESP encryption %d", ErrInvalidXFRMConfig, child.Keys.Profile.EncryptionID)
	}
	return nil
}

func validateKernelXFRMInnerPair(innerLocal, innerRemote string) error {
	innerLocalIs4, err := xfrmPrefixIs4(innerLocal)
	if err != nil {
		return wrapXFRMError(err)
	}
	innerRemoteIs4, err := xfrmPrefixIs4(innerRemote)
	if err != nil {
		return wrapXFRMError(err)
	}
	if innerLocalIs4 != innerRemoteIs4 {
		return fmt.Errorf("%w: inner local and remote prefix families differ", ErrInvalidXFRMConfig)
	}
	return nil
}

func validateKernelXFRMFamilies(outerLocal, outerRemote, innerLocal, innerRemote string) error {
	outerLocalIs4, err := xfrmAddressIs4(outerLocal)
	if err != nil {
		return wrapXFRMError(err)
	}
	outerRemoteIs4, err := xfrmAddressIs4(outerRemote)
	if err != nil {
		return wrapXFRMError(err)
	}
	if outerLocalIs4 != outerRemoteIs4 {
		return fmt.Errorf("%w: outer local and remote address families differ", ErrInvalidXFRMConfig)
	}
	return validateKernelXFRMInnerPair(innerLocal, innerRemote)
}

func xfrmAddressIs4(value string) (bool, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return false, fmt.Errorf("%w: invalid xfrm address %q", ErrInvalidXFRMConfig, value)
	}
	return addr.Is4(), nil
}

func xfrmPrefixIs4(value string) (bool, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return false, fmt.Errorf("%w: invalid xfrm prefix %q", ErrInvalidXFRMConfig, value)
	}
	return prefix.Addr().Is4(), nil
}

func validateXFRMCBCKeys(profile ikev2.ESPKeyProfile, keys ikev2.ESPKeys, direction string) error {
	if len(keys.EncryptionKey) != 16 && len(keys.EncryptionKey) != 24 && len(keys.EncryptionKey) != 32 {
		return fmt.Errorf("%w: %s AES key length %d", ErrInvalidXFRMConfig, direction, len(keys.EncryptionKey))
	}
	if profile.EncryptionKeyLength > 0 && len(keys.EncryptionKey) != profile.EncryptionKeyLength {
		return fmt.Errorf("%w: %s encryption key length %d != %d", ErrInvalidXFRMConfig, direction, len(keys.EncryptionKey), profile.EncryptionKeyLength)
	}
	if len(keys.IntegrityKey) == 0 {
		return fmt.Errorf("%w: %s integrity key is empty", ErrInvalidXFRMConfig, direction)
	}
	if profile.IntegrityKeyLength > 0 && len(keys.IntegrityKey) != profile.IntegrityKeyLength {
		return fmt.Errorf("%w: %s integrity key length %d != %d", ErrInvalidXFRMConfig, direction, len(keys.IntegrityKey), profile.IntegrityKeyLength)
	}
	return nil
}

func validateXFRMAEADKeys(profile ikev2.ESPKeyProfile, keys ikev2.ESPKeys, direction string) error {
	if !validXFRMAESGCMKeyLength(len(keys.EncryptionKey)) {
		return fmt.Errorf("%w: %s AES-GCM key length %d", ErrInvalidXFRMConfig, direction, len(keys.EncryptionKey))
	}
	if profile.EncryptionKeyLength > 0 && len(keys.EncryptionKey) != profile.EncryptionKeyLength {
		return fmt.Errorf("%w: %s encryption key length %d != %d", ErrInvalidXFRMConfig, direction, len(keys.EncryptionKey), profile.EncryptionKeyLength)
	}
	if len(keys.IntegrityKey) != 0 {
		return fmt.Errorf("%w: %s AES-GCM integrity key must be empty", ErrInvalidXFRMConfig, direction)
	}
	return nil
}

func xfrmStateAddArgs(params kernelXFRMParams, outbound bool) []string {
	src, dst, spi, keys := xfrmDirection(params, outbound)
	args := []string{
		"xfrm", "state", "update",
		"src", src,
		"dst", dst,
		"proto", "esp",
		"spi", spi,
		"reqid", params.reqID,
		"mode", "tunnel",
	}
	args = append(args, xfrmStateCryptoArgs(params.child.Keys.Profile, keys)...)
	args = append(args, "replay-window", strconv.Itoa(params.replayWindow))
	if params.child.Keys.Profile.ESN {
		args = append(args, "flag", "esn")
	}
	args = appendXFRMCommonSelectors(args, params)
	args = appendXFRMNATTraversal(args, params, outbound)
	return args
}

func xfrmStateCryptoArgs(profile ikev2.ESPKeyProfile, keys ikev2.ESPKeys) []string {
	switch profile.EncryptionID {
	case ikev2.ENCR_AES_GCM_16:
		return []string{"aead", xfrmAeadAESGCMRFC4106, xfrmHexKey(keys.EncryptionKey), strconv.Itoa(xfrmAESGCMICVBits)}
	default:
		authAlg, truncBits, _ := xfrmAuthAlgorithm(profile.IntegrityID)
		return []string{
			"auth-trunc", authAlg, xfrmHexKey(keys.IntegrityKey), strconv.Itoa(truncBits),
			"enc", "cbc(aes)", xfrmHexKey(keys.EncryptionKey),
		}
	}
}

func xfrmStateDelArgs(params kernelXFRMParams, outbound bool) []string {
	src, dst, spi, _ := xfrmDirection(params, outbound)
	args := []string{"xfrm", "state", "delete", "src", src, "dst", dst, "proto", "esp", "spi", spi}
	args = appendXFRMCommonSelectors(args, params)
	return args
}

func xfrmPolicyAddArgs(params kernelXFRMParams, dir string) []string {
	return xfrmPolicyAddArgsForPair(params, XFRMPolicyPair{LocalPrefix: params.innerLocal, RemotePrefix: params.innerRemote}, dir)
}

func xfrmPolicyAddArgsForPair(params kernelXFRMParams, pair XFRMPolicyPair, dir string) []string {
	src, dst, tmplSrc, tmplDst := xfrmPolicyDirectionForPair(params, pair, dir)
	args := []string{
		"xfrm", "policy", "update",
		"src", src,
		"dst", dst,
		"dir", dir,
	}
	args = appendXFRMCommonSelectors(args, params)
	args = append(args,
		"tmpl",
		"src", tmplSrc,
		"dst", tmplDst,
		"proto", "esp",
		"reqid", params.reqID,
		"mode", "tunnel",
	)
	return args
}

func xfrmPolicyDelArgs(params kernelXFRMParams, dir string) []string {
	return xfrmPolicyDelArgsForPair(params, XFRMPolicyPair{LocalPrefix: params.innerLocal, RemotePrefix: params.innerRemote}, dir)
}

func xfrmPolicyDelArgsForPair(params kernelXFRMParams, pair XFRMPolicyPair, dir string) []string {
	src, dst, _, _ := xfrmPolicyDirectionForPair(params, pair, dir)
	args := []string{
		"xfrm", "policy", "delete",
		"src", src,
		"dst", dst,
		"dir", dir,
	}
	args = appendXFRMCommonSelectors(args, params)
	return args
}

func xfrmDirection(params kernelXFRMParams, outbound bool) (src, dst, spi string, keys ikev2.ESPKeys) {
	if outbound {
		spi, _ = xfrmSPI(params.child.RemoteSPI)
		return params.outerLocal, params.outerRemote, spi, params.child.Keys.Outbound
	}
	spi, _ = xfrmSPI(params.child.LocalSPI)
	return params.outerRemote, params.outerLocal, spi, params.child.Keys.Inbound
}

func xfrmPolicyDirection(params kernelXFRMParams, dir string) (src, dst, tmplSrc, tmplDst string) {
	return xfrmPolicyDirectionForPair(params, XFRMPolicyPair{LocalPrefix: params.innerLocal, RemotePrefix: params.innerRemote}, dir)
}

func xfrmPolicyDirectionForPair(params kernelXFRMParams, pair XFRMPolicyPair, dir string) (src, dst, tmplSrc, tmplDst string) {
	if dir == "out" {
		return pair.LocalPrefix, pair.RemotePrefix, params.outerLocal, params.outerRemote
	}
	return pair.RemotePrefix, pair.LocalPrefix, params.outerRemote, params.outerLocal
}

func appendXFRMCommonSelectors(args []string, params kernelXFRMParams) []string {
	if params.mark != "" {
		args = append(args, "mark", params.mark)
	}
	if params.ifID != "" {
		args = append(args, "if_id", params.ifID)
	}
	return args
}

func appendXFRMNATTraversal(args []string, params kernelXFRMParams, outbound bool) []string {
	if !params.natt.enabled {
		return args
	}
	sourcePort, destPort := params.natt.localPort, params.natt.remotePort
	if !outbound {
		sourcePort, destPort = destPort, sourcePort
	}
	return append(args, "encap", "espinudp", sourcePort, destPort, params.natt.originalAddress)
}

func xfrmSPI(spi []byte) (string, error) {
	if len(spi) != 4 {
		return "", fmt.Errorf("spi length %d", len(spi))
	}
	v := binary.BigEndian.Uint32(spi)
	if v == 0 {
		return "", errors.New("spi is zero")
	}
	return fmt.Sprintf("0x%08x", v), nil
}

func xfrmHexKey(key []byte) string {
	return "0x" + hex.EncodeToString(key)
}

func xfrmAuthAlgorithm(integrity uint16) (name string, truncBits int, err error) {
	switch integrity {
	case ikev2.INTEG_HMAC_SHA1_96:
		return "hmac(sha1)", 96, nil
	case ikev2.INTEG_HMAC_SHA2_256_128:
		return "hmac(sha256)", 128, nil
	case ikev2.INTEG_HMAC_SHA2_384_192:
		return "hmac(sha384)", 192, nil
	case ikev2.INTEG_HMAC_SHA2_512_256:
		return "hmac(sha512)", 256, nil
	default:
		return "", 0, fmt.Errorf("%w: unsupported ESP integrity %d", ErrInvalidXFRMConfig, integrity)
	}
}

func validXFRMAESGCMKeyLength(n int) bool {
	switch n {
	case 16 + xfrmAESGCMSaltLength, 24 + xfrmAESGCMSaltLength, 32 + xfrmAESGCMSaltLength:
		return true
	default:
		return false
	}
}

func xfrmIPString(primary net.IP, fallbacks ...string) string {
	if ip := normalizedMOBIKEIP(primary, fallbacks...); ip != nil {
		return ip.String()
	}
	return ""
}

func firstXFRMTrafficSelectorPrefix(ts ikev2.TrafficSelectors) string {
	prefixes := xfrmTrafficSelectorPrefixes(ts)
	if len(prefixes) == 0 {
		return ""
	}
	return prefixes[0]
}

func xfrmTrafficSelectorPrefixes(ts ikev2.TrafficSelectors) []string {
	var out []string
	seen := make(map[string]bool)
	for _, selector := range ts.Selectors {
		for _, prefix := range xfrmTrafficSelectorRangePrefixes(selector) {
			if !seen[prefix] {
				seen[prefix] = true
				out = append(out, prefix)
			}
		}
	}
	return out
}

func xfrmTrafficSelectorPrefix(selector ikev2.TrafficSelector) (string, bool) {
	prefixes := xfrmTrafficSelectorRangePrefixes(selector)
	if len(prefixes) != 1 {
		return "", false
	}
	return prefixes[0], true
}

func xfrmTrafficSelectorRangePrefixes(selector ikev2.TrafficSelector) []string {
	switch selector.Type {
	case ikev2.TSIPv4AddressRange:
		start, end := selector.StartAddr.To4(), selector.EndAddr.To4()
		if start == nil || end == nil {
			return nil
		}
		return xfrmIPv4RangeToCIDRs(start, end)
	case ikev2.TSIPv6AddressRange:
		if selector.StartAddr.To4() != nil || selector.EndAddr.To4() != nil {
			return nil
		}
		start, end := selector.StartAddr.To16(), selector.EndAddr.To16()
		if start == nil || end == nil {
			return nil
		}
		return xfrmIPv6RangeToCIDRs(start, end)
	default:
		return nil
	}
}

func xfrmIPv4RangeToCIDRs(startBytes, endBytes []byte) []string {
	if len(startBytes) != 4 || len(endBytes) != 4 {
		return nil
	}
	cur := binary.BigEndian.Uint32(startBytes)
	end := binary.BigEndian.Uint32(endBytes)
	if cur > end {
		return nil
	}
	var out []string
	for {
		tz := bits.TrailingZeros32(cur)
		if cur == 0 {
			tz = 32
		}
		rem := uint64(end) - uint64(cur) + 1
		maxLog2 := 63 - bits.LeadingZeros64(rem)
		stepBits := tz
		if maxLog2 < stepBits {
			stepBits = maxLog2
		}
		prefixLen := 32 - stepBits
		var ipBuf [4]byte
		binary.BigEndian.PutUint32(ipBuf[:], cur)
		out = append(out, fmt.Sprintf("%s/%d", netip.AddrFrom4(ipBuf).String(), prefixLen))
		if stepBits == 32 {
			break
		}
		blockLast := cur + (uint32(1)<<uint(stepBits) - 1)
		if blockLast >= end {
			break
		}
		cur = blockLast + 1
	}
	return out
}

type xfrmUint128 struct {
	hi uint64
	lo uint64
}

func xfrmIPv6RangeToCIDRs(startBytes, endBytes []byte) []string {
	if len(startBytes) != 16 || len(endBytes) != 16 {
		return nil
	}
	cur := xfrmUint128{
		hi: binary.BigEndian.Uint64(startBytes[:8]),
		lo: binary.BigEndian.Uint64(startBytes[8:16]),
	}
	end := xfrmUint128{
		hi: binary.BigEndian.Uint64(endBytes[:8]),
		lo: binary.BigEndian.Uint64(endBytes[8:16]),
	}
	if cur.hi > end.hi || (cur.hi == end.hi && cur.lo > end.lo) {
		return nil
	}
	var out []string
	for {
		tz := cur.trailingZeros()
		stepBits := tz
		maxLog2 := xfrmUint128SpanLog2(cur, end)
		if maxLog2 < stepBits {
			stepBits = maxLog2
		}
		prefixLen := 128 - stepBits
		var ipBuf [16]byte
		binary.BigEndian.PutUint64(ipBuf[:8], cur.hi)
		binary.BigEndian.PutUint64(ipBuf[8:16], cur.lo)
		out = append(out, fmt.Sprintf("%s/%d", netip.AddrFrom16(ipBuf).String(), prefixLen))
		if stepBits == 128 {
			break
		}
		blockLast := cur.blockLast(stepBits)
		if blockLast.hi > end.hi || (blockLast.hi == end.hi && blockLast.lo >= end.lo) {
			break
		}
		cur = blockLast.inc()
	}
	return out
}

func (u xfrmUint128) trailingZeros() int {
	if u.lo != 0 {
		return bits.TrailingZeros64(u.lo)
	}
	if u.hi != 0 {
		return 64 + bits.TrailingZeros64(u.hi)
	}
	return 128
}

func (u xfrmUint128) blockLast(stepBits int) xfrmUint128 {
	if stepBits <= 0 {
		return u
	}
	if stepBits >= 128 {
		return xfrmUint128{hi: ^uint64(0), lo: ^uint64(0)}
	}
	if stepBits < 64 {
		mask := (uint64(1) << uint(stepBits)) - 1
		return xfrmUint128{hi: u.hi, lo: u.lo | mask}
	}
	if stepBits == 64 {
		return xfrmUint128{hi: u.hi, lo: ^uint64(0)}
	}
	hiMask := (uint64(1) << uint(stepBits-64)) - 1
	return xfrmUint128{hi: u.hi | hiMask, lo: ^uint64(0)}
}

func (u xfrmUint128) inc() xfrmUint128 {
	lo, carry := bits.Add64(u.lo, 1, 0)
	hi, _ := bits.Add64(u.hi, 0, carry)
	return xfrmUint128{hi: hi, lo: lo}
}

func xfrmUint128SpanLog2(cur, end xfrmUint128) int {
	diffLo, borrow := bits.Sub64(end.lo, cur.lo, 0)
	diffHi, _ := bits.Sub64(end.hi, cur.hi, borrow)
	if diffHi == ^uint64(0) && diffLo == ^uint64(0) {
		return 128
	}
	remLo, carry := bits.Add64(diffLo, 1, 0)
	remHi, _ := bits.Add64(diffHi, 0, carry)
	if remHi != 0 {
		return 64 + (63 - bits.LeadingZeros64(remHi))
	}
	return 63 - bits.LeadingZeros64(remLo)
}

func xfrmSinglePrefixRange(start, end []byte) (int, bool) {
	if len(start) == 0 || len(start) != len(end) || bytes.Compare(start, end) > 0 {
		return 0, false
	}
	prefixLen := len(start) * 8
	for i := range start {
		diff := start[i] ^ end[i]
		if diff == 0 {
			continue
		}
		prefixLen = i*8 + bits.LeadingZeros8(diff)
		break
	}
	for bit := prefixLen; bit < len(start)*8; bit++ {
		if xfrmIPBit(start, bit) != 0 || xfrmIPBit(end, bit) != 1 {
			return 0, false
		}
	}
	return prefixLen, true
}

func xfrmIPBit(ip []byte, bit int) byte {
	return (ip[bit/8] >> (7 - uint(bit%8))) & 1
}

func xfrmPortUint16(value string) uint16 {
	port, _ := strconv.ParseUint(value, 10, 16)
	return uint16(port)
}

func xfrmTransportPort(port uint16, addr string) uint16 {
	if port != 0 {
		return port
	}
	_, rawPort, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return 0
	}
	parsed, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(parsed)
}

func xfrmID(id uint32) string {
	if id == 0 {
		return ""
	}
	return fmt.Sprintf("0x%x", id)
}

func wrapXFRMError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrInvalidXFRMConfig) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrInvalidXFRMConfig, err)
}
