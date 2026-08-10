package swu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var ErrInvalidTUNTunnelManager = errors.New("invalid swu tun tunnel manager")

const (
	DefaultTUNPolicyRoutingTable    = "51820"
	DefaultTUNPolicyRoutingPriority = 12000
)

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
	SourcePolicyRouting    bool
	PolicyRoutingTable     string
	PolicyRoutingPriority  int
	ProtectEPDGRoutes      bool
	EPDGRouteResolver      EPDGRouteResolver
	EPDGOuterRouteResolver EPDGOuterRouteResolver
	MTU                    int
	Addresses              []string
	EPDGRouteExclusions    []EPDGRouteExclusion
	Routes                 []TUNRoute
	Rules                  []TUNRule
	OnPumpError            func(PacketPumpDirection, error)
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
	closed         bool
}

var _ TunnelManager = (*TUNTunnelManager)(nil)
var _ TunnelSession = (*TUNPacketTunnelSession)(nil)
var _ ChildSARekeyScheduler = (*TUNPacketTunnelSession)(nil)

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
	baseSession, err := base.EstablishTunnel(ctx, cfg)
	if err != nil {
		return nil, err
	}
	packetSession, ok := baseSession.(PacketTunnelReadSession)
	if !ok {
		_ = baseSession.Close(ctx)
		return nil, fmt.Errorf("%w: base session cannot read packet tunnel traffic", ErrInvalidTUNTunnelManager)
	}
	result := completeTUNResult(packetSession.Result())
	device, iface, err := m.openDevice(ctx, cfg, result)
	if err != nil {
		_ = packetSession.Close(ctx)
		return nil, err
	}
	routing := m.Config.RoutingManager
	if routing == nil {
		routing = LinuxTUNRoutingManager{}
	}
	var routingState TUNRoutingState
	routingApplied := false
	if !m.Config.DisableRouting {
		routingCfg, err := m.routingConfig(ctx, cfg, result, iface)
		if err != nil {
			_ = closeInnerPacketDevice(ctx, device)
			_ = packetSession.Close(ctx)
			return nil, err
		}
		routingState, err = routing.Apply(ctx, routingCfg)
		if err != nil {
			_ = closeInnerPacketDevice(ctx, device)
			_ = packetSession.Close(ctx)
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
		if routingApplied {
			_ = routing.Cleanup(ctx, routingState)
		}
		_ = closeInnerPacketDevice(ctx, device)
		_ = packetSession.Close(ctx)
		return nil, err
	}
	if err := pump.Start(context.Background()); err != nil {
		if routingApplied {
			_ = routing.Cleanup(ctx, routingState)
		}
		_ = pump.Close(ctx)
		return nil, err
	}
	return &TUNPacketTunnelSession{
		base:           packetSession,
		pump:           pump,
		routing:        routing,
		routingState:   routingState,
		routingApplied: routingApplied,
		result:         result,
	}, nil
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
	if m.Config.RoutingConfigFactory != nil {
		return m.Config.RoutingConfigFactory(cfg, result, iface)
	}
	addresses := append([]string(nil), m.Config.Addresses...)
	if len(addresses) == 0 && strings.TrimSpace(result.LocalInnerIP) != "" {
		addresses = append(addresses, strings.TrimSpace(result.LocalInnerIP))
	}
	routes := cloneTUNRoutes(m.Config.Routes)
	if m.Config.DefaultRoutes && len(routes) == 0 {
		routes = append(routes, TUNRoute{Destination: "default"})
	}
	rules := cloneTUNRules(m.Config.Rules)
	if m.Config.SourcePolicyRouting && len(routes) == 0 {
		policyRoutes, policyRules, err := sourcePolicyRouting(addresses, m.Config.PolicyRoutingTable, m.Config.PolicyRoutingPriority)
		if err != nil {
			return TUNRoutingConfig{}, err
		}
		routes = append(routes, policyRoutes...)
		rules = append(rules, policyRules...)
	}
	exclusions := cloneEPDGRouteExclusions(m.Config.EPDGRouteExclusions)
	if m.Config.ProtectEPDGRoutes {
		defaultExclusions, err := m.defaultEPDGRouteExclusions(ctx, cfg, result, routes)
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

func sourcePolicyRouting(addresses []string, table string, priority int) ([]TUNRoute, []TUNRule, error) {
	table = strings.TrimSpace(table)
	if table == "" {
		table = DefaultTUNPolicyRoutingTable
	}
	if priority == 0 {
		priority = DefaultTUNPolicyRoutingPriority
	}
	if priority < 0 {
		return nil, nil, fmt.Errorf("%w: policy routing priority must be positive", ErrInvalidTUNTunnelManager)
	}
	routeFamilies := map[bool]bool{}
	seenSources := map[string]bool{}
	var routes []TUNRoute
	var rules []TUNRule
	for _, address := range addresses {
		source, err := normalizeIPPrefix(address, "policy routing source")
		if err != nil {
			return nil, nil, err
		}
		prefix, err := netip.ParsePrefix(source)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: policy routing source %q: %v", ErrInvalidTUNTunnelManager, source, err)
		}
		isIPv6 := prefix.Addr().Is6()
		if !routeFamilies[isIPv6] {
			destination := "0.0.0.0/0"
			if isIPv6 {
				destination = "::/0"
			}
			routes = append(routes, TUNRoute{Destination: destination, Table: table})
			routeFamilies[isIPv6] = true
		}
		if !seenSources[source] {
			rules = append(rules, TUNRule{Priority: priority, From: source, Table: table})
			seenSources[source] = true
		}
	}
	if len(routes) == 0 {
		return nil, nil, fmt.Errorf("%w: source policy routing requires an inner address", ErrInvalidTUNTunnelManager)
	}
	return routes, rules, nil
}

func (m *TUNTunnelManager) defaultEPDGRouteExclusions(ctx context.Context, cfg TunnelConfig, result TunnelResult, routes []TUNRoute) ([]EPDGRouteExclusion, error) {
	host := tunnelAddressHost(firstPacketNonEmpty(result.EPDGAddress, cfg.EPDGAddress))
	if host == "" {
		return nil, nil
	}
	ips, err := m.resolveEPDGRouteIPs(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, nil
	}
	tables := routingTablesForRoutes(routes)
	out := make([]EPDGRouteExclusion, 0, len(ips))
	for _, ip := range ips {
		normalized := normalizedMOBIKEIP(ip)
		if normalized == nil {
			continue
		}
		outer := EPDGOuterRoute{
			InterfaceName: strings.TrimSpace(cfg.LocalInterface),
			Source:        strings.TrimSpace(cfg.OuterLocalIP),
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
			Address:       normalized.String(),
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
	output, err := exec.CommandContext(ctx, "ip", "-j", "route", "get", normalized.String()).Output()
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

func routingTablesForRoutes(routes []TUNRoute) []string {
	seen := map[string]bool{}
	var out []string
	for _, route := range routes {
		if !isDefaultRouteDestination(route.Destination) {
			continue
		}
		table := strings.TrimSpace(route.Table)
		if table == "" || seen[table] {
			continue
		}
		seen[table] = true
		out = append(out, table)
	}
	return out
}

func isDefaultRouteDestination(destination string) bool {
	normalized := strings.ToLower(strings.TrimSpace(destination))
	if normalized == "default" {
		return true
	}
	prefix, err := netip.ParsePrefix(normalized)
	return err == nil && prefix.Bits() == 0
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
	pump := s.pump
	routing := s.routing
	routingState := s.routingState
	routingApplied := s.routingApplied
	s.mu.Unlock()

	var err error
	if pump != nil {
		err = pump.Close(ctx)
	}
	if routingApplied && routing != nil {
		err = errors.Join(err, routing.Cleanup(ctx, routingState))
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
