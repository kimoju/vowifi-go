package swu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrInvalidTUNTunnelManager = errors.New("invalid swu tun tunnel manager")

type TUNDeviceFactory func(context.Context, TunnelConfig, TunnelResult) (InnerPacketDevice, string, error)

type TUNRoutingConfigFactory func(TunnelConfig, TunnelResult, string) (TUNRoutingConfig, error)

type TUNRoutingManager interface {
	Apply(context.Context, TUNRoutingConfig) (TUNRoutingState, error)
	Cleanup(context.Context, TUNRoutingState) error
}

type EPDGRouteResolver func(context.Context, string) ([]net.IP, error)

type EPDGOuterRoute struct {
	InterfaceName string
	Via           string
	Source        string
}

type EPDGOuterRouteResolver func(context.Context, net.IP) (EPDGOuterRoute, error)

type TUNTunnelManagerConfig struct {
	Base                   TunnelManager
	TUN                    TUNDeviceConfig
	DeviceFactory          TUNDeviceFactory
	RoutingManager         TUNRoutingManager
	RoutingConfigFactory   TUNRoutingConfigFactory
	DisableRouting         bool
	DefaultRoutes          bool
	IsolateHostRouting     bool
	ProtectEPDGRoutes      bool
	EPDGRouteResolver      EPDGRouteResolver
	EPDGOuterRouteResolver EPDGOuterRouteResolver
	MTU                    int
	Addresses              []string
	EPDGRouteExclusions    []EPDGRouteExclusion
	Routes                 []TUNRoute
	Rules                  []TUNRule
	OnPumpError            func(PacketPumpDirection, error)
	MaintenanceInterval    time.Duration
	DisableMaintenance     bool
}

type TUNTunnelManager struct {
	Config TUNTunnelManagerConfig
}

type TUNPacketTunnelSession struct {
	mu             sync.Mutex
	base           PacketTunnelReadSession
	pump           *PacketPump
	routing        TUNRoutingManager
	routingState   TUNRoutingState
	routingApplied bool
	result         TunnelResult
	maintCancel    context.CancelFunc
	maintDone      chan struct{}
	closed         bool
}

var _ TunnelManager = (*TUNTunnelManager)(nil)
var _ TunnelSession = (*TUNPacketTunnelSession)(nil)
var _ ChildSARekeyScheduler = (*TUNPacketTunnelSession)(nil)
var _ IKELivenessController = (*TUNPacketTunnelSession)(nil)
var _ MOBIKENATObserver = (*TUNPacketTunnelSession)(nil)

func NewTUNTunnelManager(cfg TUNTunnelManagerConfig) *TUNTunnelManager {
	return &TUNTunnelManager{Config: cfg}
}

func NewTUNIKETunnelManager(ikeCfg IKEPacketTunnelManagerConfig, tunCfg TUNTunnelManagerConfig) *TUNTunnelManager {
	tunCfg.Base = NewIKEPacketTunnelManager(ikeCfg)
	return NewTUNTunnelManager(tunCfg)
}

func (m *TUNTunnelManager) EstablishTunnel(ctx context.Context, cfg TunnelConfig) (TunnelSession, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: manager is nil", ErrInvalidTUNTunnelManager)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	base := m.Config.Base
	if base == nil {
		return nil, fmt.Errorf("%w: base manager is nil", ErrInvalidTUNTunnelManager)
	}
	baseCfg := cfg
	if baseCfg.NormalizedMode() == DataplaneModeKernel && baseCfg.Proxy.IsActive() {
		baseCfg.Mode = DataplaneModeUserspace
	}
	baseSession, err := base.EstablishTunnel(ctx, baseCfg)
	if err != nil {
		return nil, err
	}
	packetSession, ok := baseSession.(PacketTunnelReadSession)
	if !ok {
		cleanupCtx, cancel := independentCleanupContext(ctx)
		_ = baseSession.Close(cleanupCtx)
		cancel()
		return nil, fmt.Errorf("%w: base session cannot read packet tunnel traffic", ErrInvalidTUNTunnelManager)
	}
	result := completeTUNResult(packetSession.Result())
	device, iface, err := m.openDevice(ctx, baseCfg, result)
	if err != nil {
		cleanupCtx, cancel := independentCleanupContext(ctx)
		_ = packetSession.Close(cleanupCtx)
		cancel()
		return nil, err
	}
	routing := m.Config.RoutingManager
	if routing == nil {
		routing = LinuxTUNRoutingManager{}
	}
	var extraProxyIPs []net.IP
	if provider, ok := packetSession.(proxyRouteIPProvider); ok {
		extraProxyIPs = provider.proxyRouteIPs()
	}
	var routingState TUNRoutingState
	routingApplied := false
	if !m.Config.DisableRouting {
		routingCfg, err := m.routingConfigWithSessionIPs(ctx, baseCfg, result, iface, extraProxyIPs)
		if err != nil {
			cleanupCtx, cancel := independentCleanupContext(ctx)
			_ = closeInnerPacketDevice(cleanupCtx, device)
			_ = packetSession.Close(cleanupCtx)
			cancel()
			return nil, err
		}
		routingState, err = routing.Apply(ctx, routingCfg)
		if err != nil {
			cleanupCtx, cancel := independentCleanupContext(ctx)
			_ = closeInnerPacketDevice(cleanupCtx, device)
			_ = packetSession.Close(cleanupCtx)
			cancel()
			return nil, err
		}
		routingApplied = true
	}
	pump, err := NewPacketPump(PacketPumpConfig{
		Session: packetSession,
		Device:  device,
		OnError: m.Config.OnPumpError,
	})
	if err != nil {
		cleanupCtx, cancel := independentCleanupContext(ctx)
		if routingApplied {
			_ = routing.Cleanup(cleanupCtx, routingState)
		}
		_ = closeInnerPacketDevice(cleanupCtx, device)
		_ = packetSession.Close(cleanupCtx)
		cancel()
		return nil, err
	}
	if err := pump.Start(context.Background()); err != nil {
		cleanupCtx, cancel := independentCleanupContext(ctx)
		if routingApplied {
			_ = routing.Cleanup(cleanupCtx, routingState)
		}
		_ = pump.Close(cleanupCtx)
		cancel()
		return nil, err
	}
	tunSession := &TUNPacketTunnelSession{
		base:           packetSession,
		pump:           pump,
		routing:        routing,
		routingState:   routingState,
		routingApplied: routingApplied,
		result:         result,
	}
	if !m.Config.DisableMaintenance && !baseHasBackgroundMaintenance(packetSession) {
		interval := m.Config.MaintenanceInterval
		if interval <= 0 {
			interval = defaultPacketMaintInterval
		}
		maintCtx, cancel := context.WithCancel(context.Background())
		tunSession.maintCancel = cancel
		tunSession.maintDone = make(chan struct{})
		go tunSession.maintenanceLoop(maintCtx, interval)
	}
	return tunSession, nil
}

func baseHasBackgroundMaintenance(base PacketTunnelReadSession) bool {
	if checker, ok := base.(interface{ hasBackgroundMaintenance() bool }); ok {
		return checker.hasBackgroundMaintenance()
	}
	return false
}

func (s *TUNPacketTunnelSession) maintenanceLoop(ctx context.Context, interval time.Duration) {
	defer close(s.maintDone)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			_, _ = s.AdvanceIKELiveness(ctx, now)
			_, _ = s.RunChildSARekeyDue(ctx, now)
		}
	}
}

func (m *TUNTunnelManager) openDevice(ctx context.Context, cfg TunnelConfig, result TunnelResult) (InnerPacketDevice, string, error) {
	if m.Config.DeviceFactory != nil {
		device, name, err := m.Config.DeviceFactory(ctx, cfg, result)
		if err != nil {
			return nil, "", err
		}
		if device == nil {
			return nil, "", fmt.Errorf("%w: device factory returned nil", ErrInvalidTUNTunnelManager)
		}
		name = firstPacketNonEmpty(name, innerPacketDeviceName(device), m.Config.TUN.Name)
		if strings.TrimSpace(name) == "" && !m.Config.DisableRouting {
			return nil, "", fmt.Errorf("%w: tun interface name is empty", ErrInvalidTUNTunnelManager)
		}
		return device, name, nil
	}
	device, err := OpenTUNDevice(m.Config.TUN)
	if err != nil {
		return nil, "", err
	}
	name := firstPacketNonEmpty(device.Name(), m.Config.TUN.Name)
	if strings.TrimSpace(name) == "" {
		_ = device.Close(ctx)
		return nil, "", fmt.Errorf("%w: tun interface name is empty", ErrInvalidTUNTunnelManager)
	}
	return device, name, nil
}

func (m *TUNTunnelManager) routingConfig(ctx context.Context, cfg TunnelConfig, result TunnelResult, iface string) (TUNRoutingConfig, error) {
	return m.routingConfigWithSessionIPs(ctx, cfg, result, iface, nil)
}

func (m *TUNTunnelManager) routingConfigWithSessionIPs(ctx context.Context, cfg TunnelConfig, result TunnelResult, iface string, extraProxyIPs []net.IP) (TUNRoutingConfig, error) {
	if m.Config.RoutingConfigFactory != nil {
		return m.Config.RoutingConfigFactory(cfg, result, iface)
	}
	addresses := append([]string(nil), m.Config.Addresses...)
	if len(addresses) == 0 {
		addresses = innerAddressesForTUN(result)
	}
	routes := cloneTUNRoutes(m.Config.Routes)
	rules := cloneTUNRules(m.Config.Rules)
	if m.Config.IsolateHostRouting && len(routes) == 0 && len(rules) == 0 {
		candidates := innerAddressesForTUN(result)
		if len(candidates) == 0 {
			candidates = []string{strings.TrimSpace(result.LocalInnerIP)}
		}
		table, priority := isolatedTUNRoutingIdentity(iface)
		seenDest := make(map[string]bool)
		for _, candidate := range candidates {
			source, err := isolatedTUNSourcePrefix(candidate)
			if err != nil {
				return TUNRoutingConfig{}, err
			}
			destination := "default"
			if prefix, parseErr := netip.ParsePrefix(source); parseErr == nil && prefix.Addr().Is6() {
				destination = "::/0"
			}
			if !seenDest[destination] {
				seenDest[destination] = true
				routes = append(routes, TUNRoute{Destination: destination, Table: table})
			}
			rules = append(rules, TUNRule{Priority: priority, From: source, Table: table})
		}
	} else if m.Config.DefaultRoutes && len(routes) == 0 {
		hasV4, hasV6 := addressFamiliesForTUN(addresses)
		if hasV4 || !hasV6 {
			routes = append(routes, TUNRoute{Destination: "default"})
		}
		if hasV6 {
			routes = append(routes, TUNRoute{Destination: "::/0"})
		}
	}
	exclusions := cloneEPDGRouteExclusions(m.Config.EPDGRouteExclusions)
	if m.Config.ProtectEPDGRoutes {
		defaultExclusions, err := m.defaultEPDGRouteExclusionsWithExtra(ctx, cfg, result, routes, extraProxyIPs)
		if err != nil {
			return TUNRoutingConfig{}, err
		}
		exclusions = append(exclusions, defaultExclusions...)
	}
	return TUNRoutingConfig{
		InterfaceName:       iface,
		MTU:                 m.Config.MTU,
		Addresses:           addresses,
		EPDGRouteExclusions: exclusions,
		Routes:              routes,
		Rules:               rules,
	}, nil
}

func innerAddressesForTUN(result TunnelResult) []string {
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
	for _, addr := range result.LocalInnerIPs {
		add(addr)
	}
	add(result.LocalInnerIPv4)
	add(result.LocalInnerIPv6)
	add(result.LocalInnerIP)
	return out
}

func addressFamiliesForTUN(addresses []string) (hasV4 bool, hasV6 bool) {
	for _, item := range addresses {
		if addr, ok := parseInnerIPFamily(item); ok {
			if addr.Is4() {
				hasV4 = true
			} else if addr.Is6() {
				hasV6 = true
			}
		}
	}
	return hasV4, hasV6
}

func isolatedTUNSourcePrefix(value string) (string, error) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("%w: isolated TUN source address %q is invalid", ErrInvalidTUNTunnelManager, value)
	}
	return netip.PrefixFrom(addr, addr.BitLen()).String(), nil
}

// Each auto-created TUN (tun0, tun1, ...) gets its own routing table. Only
// packets sourced from that tunnel's inner address select the table, so neither
// a modem nor a reader can replace the host's main/default route.
func isolatedTUNRoutingIdentity(iface string) (table string, priority int) {
	trimmed := strings.TrimSpace(iface)
	start := len(trimmed)
	for start > 0 && trimmed[start-1] >= '0' && trimmed[start-1] <= '9' {
		start--
	}
	if start < len(trimmed) {
		if index, err := strconv.Atoi(trimmed[start:]); err == nil && index >= 0 && index < 1000000 {
			return strconv.Itoa(20000 + index), 20000 + index%10000
		}
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(trimmed))
	index := int(h.Sum32() % 10000)
	return strconv.Itoa(120000 + index), 20000 + index
}

func (m *TUNTunnelManager) defaultEPDGRouteExclusions(ctx context.Context, cfg TunnelConfig, result TunnelResult, routes []TUNRoute) ([]EPDGRouteExclusion, error) {
	return m.defaultEPDGRouteExclusionsWithExtra(ctx, cfg, result, routes, nil)
}

func (m *TUNTunnelManager) defaultEPDGRouteExclusionsWithExtra(ctx context.Context, cfg TunnelConfig, result TunnelResult, routes []TUNRoute, extraIPs []net.IP) ([]EPDGRouteExclusion, error) {
	if len(routes) == 0 {
		return nil, nil
	}
	var ips []net.IP
	if cfg.Proxy.IsActive() {
		parsedProxy, err := parseSOCKS5ProxyConfig(cfg.Proxy)
		if err != nil {
			return nil, err
		}
		resolvedProxyIPs, err := m.resolveEPDGRouteIPs(ctx, parsedProxy.Host)
		if err != nil {
			return nil, err
		}
		ips = append(ips, resolvedProxyIPs...)
		ips = append(ips, extraIPs...)
	} else {
		host := tunnelAddressHost(firstPacketNonEmpty(result.EPDGAddress, cfg.EPDGAddress))
		if host == "" {
			return nil, nil
		}
		resolvedIPs, err := m.resolveEPDGRouteIPs(ctx, host)
		if err != nil {
			return nil, err
		}
		ips = append(ips, resolvedIPs...)
	}
	if len(ips) == 0 {
		return nil, nil
	}
	tables := routingTablesForRoutes(routes)
	out := make([]EPDGRouteExclusion, 0, len(ips))
	seen := make(map[string]bool, len(ips))
	for _, ip := range ips {
		normalized := normalizedMOBIKEIP(ip)
		if normalized == nil {
			continue
		}
		key := normalized.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		outerSource := strings.TrimSpace(cfg.OuterLocalIP)
		if outerSource != "" {
			if srcIP := normalizedMOBIKEIP(net.ParseIP(outerSource)); srcIP != nil && (srcIP.To4() != nil) != (normalized.To4() != nil) {
				outerSource = ""
			}
		}
		outer := EPDGOuterRoute{
			InterfaceName: strings.TrimSpace(cfg.LocalInterface),
			Source:        outerSource,
		}
		if outer.InterfaceName == "" {
			resolver := m.Config.EPDGOuterRouteResolver
			if resolver == nil {
				resolver = resolveSystemEPDGOuterRoute
			}
			var err error
			outer, err = resolver(ctx, normalized)
			if err != nil {
				return nil, err
			}
		}
		if strings.TrimSpace(outer.InterfaceName) == "" {
			return nil, fmt.Errorf("%w: ePDG route protection could not resolve outer interface", ErrInvalidTUNTunnelManager)
		}
		out = append(out, EPDGRouteExclusion{
			Address:       key,
			InterfaceName: strings.TrimSpace(outer.InterfaceName),
			Via:           strings.TrimSpace(outer.Via),
			Source:        strings.TrimSpace(outer.Source),
			Tables:        tables,
		})
	}
	return out, nil
}

func resolveSystemEPDGOuterRoute(ctx context.Context, ip net.IP) (EPDGOuterRoute, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized := normalizedMOBIKEIP(ip)
	if normalized == nil {
		return EPDGOuterRoute{}, fmt.Errorf("%w: invalid ePDG route address", ErrInvalidTUNTunnelManager)
	}
	args := []string{"-j", "route", "get", normalized.String()}
	if normalized.To4() == nil {
		args = []string{"-6", "-j", "route", "get", normalized.String()}
	}
	output, err := exec.CommandContext(ctx, "ip", args...).Output()
	if err != nil {
		return EPDGOuterRoute{}, fmt.Errorf("%w: resolve ePDG outer route: %v", ErrInvalidTUNTunnelManager, err)
	}
	var rows []struct {
		Dev     string `json:"dev"`
		Gateway string `json:"gateway"`
		PrefSrc string `json:"prefsrc"`
		Source  string `json:"src"`
	}
	if err := json.Unmarshal(output, &rows); err != nil || len(rows) == 0 {
		return EPDGOuterRoute{}, fmt.Errorf("%w: parse ePDG outer route: %v", ErrInvalidTUNTunnelManager, err)
	}
	source := strings.TrimSpace(rows[0].PrefSrc)
	if source == "" {
		source = strings.TrimSpace(rows[0].Source)
	}
	return EPDGOuterRoute{
		InterfaceName: strings.TrimSpace(rows[0].Dev),
		Via:           strings.TrimSpace(rows[0].Gateway),
		Source:        source,
	}, nil
}

func (m *TUNTunnelManager) resolveEPDGRouteIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return []net.IP{append(net.IP(nil), ip...)}, nil
	}
	resolver := m.Config.EPDGRouteResolver
	if resolver != nil {
		return resolver(ctx, host)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve ePDG route host %q: %v", ErrInvalidTUNTunnelManager, host, err)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, append(net.IP(nil), addr.IP...))
	}
	return ips, nil
}

func isDefaultRouteDestination(destination string) bool {
	switch normalizeRouteDestinationForRoutingTables(destination) {
	case "default", "0.0.0.0/0", "::/0":
		return true
	default:
		return false
	}
}

func routingTablesForRoutes(routes []TUNRoute) []string {
	if len(routes) == 0 {
		return nil
	}
	hasDefault := false
	for _, route := range routes {
		if isDefaultRouteDestination(route.Destination) {
			hasDefault = true
			break
		}
	}
	seen := map[string]bool{}
	var nonMain []string
	targetsMain := false
	for _, route := range routes {
		if hasDefault && !isDefaultRouteDestination(route.Destination) {
			continue
		}
		table := strings.TrimSpace(route.Table)
		if table == "" || strings.EqualFold(table, "main") {
			targetsMain = true
			continue
		}
		if !seen[table] {
			seen[table] = true
			nonMain = append(nonMain, table)
		}
	}
	if len(nonMain) == 0 {
		return nil
	}
	if targetsMain {
		return append([]string{"main"}, nonMain...)
	}
	return nonMain
}

func normalizeRouteDestinationForRoutingTables(destination string) string {
	return strings.ToLower(strings.TrimSpace(destination))
}

func (s *TUNPacketTunnelSession) Result() TunnelResult {
	if s == nil {
		return TunnelResult{}
	}
	if s.base != nil {
		if result := s.base.Result(); !isZeroTunnelResult(result) {
			return s.setResult(result)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneTunnelResult(s.result)
}

func (s *TUNPacketTunnelSession) RekeyChildSA(ctx context.Context) (TunnelResult, error) {
	if s == nil || s.base == nil {
		return TunnelResult{}, ErrInvalidTUNTunnelManager
	}
	controller, ok := s.base.(ChildSARekeyController)
	if !ok {
		return TunnelResult{}, fmt.Errorf("%w: base session cannot rekey child sa", ErrInvalidTUNTunnelManager)
	}
	result, err := controller.RekeyChildSA(ctx)
	if err != nil {
		return TunnelResult{}, err
	}
	return s.setResult(result), nil
}

func (s *TUNPacketTunnelSession) NextChildSARekeyDue() (time.Time, bool) {
	if s == nil || s.base == nil {
		return time.Time{}, false
	}
	scheduler, ok := s.base.(ChildSARekeyScheduler)
	if !ok {
		return time.Time{}, false
	}
	return scheduler.NextChildSARekeyDue()
}

func (s *TUNPacketTunnelSession) RunChildSARekeyDue(ctx context.Context, now time.Time) (ChildSARekeyDecision, error) {
	if s == nil || s.base == nil {
		return ChildSARekeyDecision{}, ErrInvalidTUNTunnelManager
	}
	scheduler, ok := s.base.(ChildSARekeyScheduler)
	if !ok {
		return ChildSARekeyDecision{Action: ChildSARekeyNoAction, Reason: "rekey disabled"}, nil
	}
	decision, err := scheduler.RunChildSARekeyDue(ctx, now)
	if err != nil {
		return decision, err
	}
	if decision.Action == ChildSARekeyDue {
		s.refreshResultFromBase()
	}
	return decision, nil
}

func (s *TUNPacketTunnelSession) ChildSARekeySnapshot() ChildSARekeySnapshot {
	if s == nil || s.base == nil {
		return ChildSARekeySnapshot{}
	}
	scheduler, ok := s.base.(ChildSARekeyScheduler)
	if !ok {
		return ChildSARekeySnapshot{}
	}
	return scheduler.ChildSARekeySnapshot()
}

func (s *TUNPacketTunnelSession) MOBIKE(ctx context.Context, req MOBIKERequest) (MOBIKEResult, error) {
	if s == nil || s.base == nil {
		return MOBIKEResult{}, ErrInvalidTUNTunnelManager
	}
	res, err := s.base.MOBIKE(ctx, req)
	if err != nil {
		return MOBIKEResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if res.LocalInnerIP != "" {
		s.result.LocalInnerIP = res.LocalInnerIP
	}
	if res.RemoteInnerIP != "" {
		s.result.RemoteInnerIP = res.RemoteInnerIP
	}
	if len(res.DNSServers) > 0 {
		s.result.DNSServers = append([]string(nil), res.DNSServers...)
	}
	if res.IKEEstablished || res.IPsecEstablished {
		s.result.IKEEstablished = res.IKEEstablished
		s.result.IPsecEstablished = res.IPsecEstablished
		s.result.Ready = res.IKEEstablished && res.IPsecEstablished
	}
	if res.Reason != "" {
		s.result.Reason = res.Reason
	}
	return res, nil
}

func (s *TUNPacketTunnelSession) refreshResultFromBase() TunnelResult {
	if s == nil || s.base == nil {
		return TunnelResult{}
	}
	result := s.base.Result()
	if isZeroTunnelResult(result) {
		s.mu.Lock()
		defer s.mu.Unlock()
		return cloneTunnelResult(s.result)
	}
	return s.setResult(result)
}

func (s *TUNPacketTunnelSession) setResult(result TunnelResult) TunnelResult {
	result = completeTUNResult(result)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result = result
	return cloneTunnelResult(s.result)
}

func (s *TUNPacketTunnelSession) ObserveMOBIKENAT(ctx context.Context, obs MOBIKENATObservation) (MOBIKENATChange, MOBIKEResult, error) {
	if s == nil || s.base == nil {
		return MOBIKENATChange{}, MOBIKEResult{}, ErrInvalidTUNTunnelManager
	}
	observer, ok := s.base.(MOBIKENATObserver)
	if !ok {
		return MOBIKENATChange{}, MOBIKEResult{}, fmt.Errorf("%w: base session cannot observe mobike nat", ErrInvalidTUNTunnelManager)
	}
	change, res, err := observer.ObserveMOBIKENAT(ctx, obs)
	if err != nil {
		return change, res, err
	}
	if change.RequiresMOBIKEUpdate {
		s.refreshResultFromBase()
	}
	return change, res, nil
}

func (s *TUNPacketTunnelSession) MOBIKENATSnapshot() (MOBIKENATEndpoint, time.Time) {
	if s == nil || s.base == nil {
		return MOBIKENATEndpoint{}, time.Time{}
	}
	observer, ok := s.base.(MOBIKENATObserver)
	if !ok {
		return MOBIKENATEndpoint{}, time.Time{}
	}
	return observer.MOBIKENATSnapshot()
}

func (s *TUNPacketTunnelSession) AdvanceIKELiveness(ctx context.Context, now time.Time) (IKELivenessDecision, error) {
	if s == nil || s.base == nil {
		return IKELivenessDecision{}, ErrInvalidTUNTunnelManager
	}
	controller, ok := s.base.(IKELivenessController)
	if !ok {
		return IKELivenessDecision{Action: IKELivenessNoAction, Reason: "liveness disabled"}, nil
	}
	decision, err := controller.AdvanceIKELiveness(ctx, now)
	if decision.Dead || decision.Action == IKELivenessDeclareDead {
		s.refreshResultFromBase()
	}
	return decision, err
}

func (s *TUNPacketTunnelSession) RecordIKELivenessInbound(at time.Time) {
	if s == nil || s.base == nil {
		return
	}
	if controller, ok := s.base.(IKELivenessController); ok {
		controller.RecordIKELivenessInbound(at)
	}
}

func (s *TUNPacketTunnelSession) RecordIKELivenessOutbound(at time.Time) {
	if s == nil || s.base == nil {
		return
	}
	if controller, ok := s.base.(IKELivenessController); ok {
		controller.RecordIKELivenessOutbound(at)
	}
}

func (s *TUNPacketTunnelSession) RecordIKELivenessResult(at time.Time, okResult bool) {
	if s == nil || s.base == nil {
		return
	}
	if controller, ok := s.base.(IKELivenessController); ok {
		controller.RecordIKELivenessResult(at, okResult)
	}
}

func (s *TUNPacketTunnelSession) IKELivenessSnapshot() IKELivenessSnapshot {
	if s == nil || s.base == nil {
		return IKELivenessSnapshot{}
	}
	controller, ok := s.base.(IKELivenessController)
	if !ok {
		return IKELivenessSnapshot{}
	}
	return controller.IKELivenessSnapshot()
}

func (s *TUNPacketTunnelSession) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	maintCancel := s.maintCancel
	maintDone := s.maintDone
	pump := s.pump
	routing := s.routing
	routingState := s.routingState
	routingApplied := s.routingApplied
	s.mu.Unlock()

	if maintCancel != nil {
		maintCancel()
	}
	if maintDone != nil {
		<-maintDone
	}

	var err error
	if routingApplied && routing != nil {
		// Runtime shutdown commonly arrives with an already-cancelled request
		// context. Route/rule cleanup must still run so a stopped device cannot
		// leave host networking artifacts behind.
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Second)
		err = routing.Cleanup(cleanupCtx, routingState)
		cancelCleanup()
	}
	if pump != nil {
		cleanupCtx, cancelPump := independentCleanupContext(ctx)
		err = errors.Join(err, pump.Close(cleanupCtx))
		cancelPump()
	}
	return err
}

func completeTUNResult(result TunnelResult) TunnelResult {
	if result.Mode == "" {
		result.Mode = DataplaneModeUserspace
	}
	if result.Reason == "" {
		result.Reason = "tun packet pump ready"
	}
	return result
}

func innerPacketDeviceName(device InnerPacketDevice) string {
	named, ok := device.(interface{ Name() string })
	if !ok || named == nil {
		return ""
	}
	return strings.TrimSpace(named.Name())
}

func closeInnerPacketDevice(ctx context.Context, device InnerPacketDevice) error {
	if closer, ok := device.(InnerPacketDeviceCloser); ok {
		return closer.Close(ctx)
	}
	return nil
}

func cloneEPDGRouteExclusions(in []EPDGRouteExclusion) []EPDGRouteExclusion {
	out := make([]EPDGRouteExclusion, len(in))
	for i, item := range in {
		out[i] = item
		out[i].Tables = append([]string(nil), item.Tables...)
	}
	return out
}

func cloneTUNRoutes(in []TUNRoute) []TUNRoute {
	out := make([]TUNRoute, len(in))
	copy(out, in)
	return out
}

func cloneTUNRules(in []TUNRule) []TUNRule {
	out := make([]TUNRule, len(in))
	copy(out, in)
	return out
}
