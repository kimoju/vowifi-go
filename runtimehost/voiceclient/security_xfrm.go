package voiceclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var nextIMSSecurityXFRMReqID atomic.Uint32

func allocateIMSSecurityXFRMReqIDPair() (int, int) {
	for {
		cur := nextIMSSecurityXFRMReqID.Load()
		base := cur
		if base < 1000 || base > 0x7ffffff0 {
			base = 1000
		}
		next := base + 2
		if nextIMSSecurityXFRMReqID.CompareAndSwap(cur, next) {
			return int(base), int(base + 1)
		}
	}
}

// ErrInvalidIMSSecurityXFRMPlan marks an install request that cannot be mapped to Linux XFRM.
var ErrInvalidIMSSecurityXFRMPlan = errors.New("invalid IMS security XFRM plan")

// IMSSecurityAssociationXFRMInstallPlan is a pure-data model of the ip xfrm work
// needed for an IMS Security-Agree association. Building it does not touch the OS.
type IMSSecurityAssociationXFRMInstallPlan struct {
	ReqID         int
	Mode          string
	LocalAddress  string
	RemoteAddress string
	Commands      []IMSSecurityAssociationXFRMCommand
}

// IMSSecurityAssociationXFRMCommand contains ip(8) arguments and the matching
// reverse operation arguments for a future installer.
type IMSSecurityAssociationXFRMCommand struct {
	Args     []string
	UndoArgs []string
}

type IMSSecurityAssociationXFRMState struct {
	Plan IMSSecurityAssociationXFRMInstallPlan
	undo []IMSSecurityAssociationXFRMCommand
}

type IMSSecurityXFRMCommandRunner interface {
	RunIP(context.Context, ...string) error
}

type IMSSecurityXFRMCommandRunnerFunc func(context.Context, ...string) error

func (f IMSSecurityXFRMCommandRunnerFunc) RunIP(ctx context.Context, args ...string) error {
	return f(ctx, args...)
}

type ExecIMSSecurityXFRMCommandRunner struct {
	Path string
}

func (r ExecIMSSecurityXFRMCommandRunner) RunIP(ctx context.Context, args ...string) error {
	path := strings.TrimSpace(r.Path)
	if path == "" {
		path = "ip"
	}
	cmd := exec.CommandContext(ctx, path, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

type LinuxIMSSecurityXFRMInstaller struct {
	Runner IMSSecurityXFRMCommandRunner

	mu     sync.Mutex
	states []IMSSecurityAssociationXFRMState
}

var (
	_ SecurityPlanInstaller        = (*LinuxIMSSecurityXFRMInstaller)(nil)
	_ SecurityPlanRequestInstaller = (*LinuxIMSSecurityXFRMInstaller)(nil)
)

type imsSecurityXFRMParams struct {
	clientReqIDNum    int
	clientReqID       string
	serverReqID       string
	mode              string
	localAddress      string
	remoteAddress     string
	localPort         string
	remotePort        string
	spiClient         string
	spiServer         string
	inboundLocalPort  string
	inboundRemotePort string
	inboundSPI        string
	serverLocalPort   string
	serverRemotePort  string
	serverInboundSPI  string
	serverOutboundSPI string
	hasServerFlow     bool
	authAlgorithm     string
	authKey           string
	authTruncBits     string
	encAlgorithm      string
	encKey            string
}

// BuildIMSSecurityAssociationXFRMInstallPlan converts an IMS Security-Agree
// install request into Linux XFRM state and policy command arguments.
func BuildIMSSecurityAssociationXFRMInstallPlan(req IMSSecurityAssociationInstallRequest) (IMSSecurityAssociationXFRMInstallPlan, error) {
	params, err := normalizeIMSSecurityAssociationXFRMRequest(req)
	if err != nil {
		return IMSSecurityAssociationXFRMInstallPlan{}, err
	}
	commands := []IMSSecurityAssociationXFRMCommand{
		imssSecurityXFRMStateCommand(params, true),
		imssSecurityXFRMStateCommand(params, false),
	}
	if params.hasServerFlow {
		commands = append(commands,
			imssSecurityXFRMServerStateCommand(params, true),
			imssSecurityXFRMServerStateCommand(params, false),
		)
	}
	commands = append(commands,
		imssSecurityXFRMPolicyCommand(params, "udp", "out"),
		imssSecurityXFRMPolicyCommand(params, "udp", "in"),
		imssSecurityXFRMPolicyCommand(params, "tcp", "out"),
		imssSecurityXFRMPolicyCommand(params, "tcp", "in"),
	)
	if params.hasServerFlow {
		commands = append(commands,
			imssSecurityXFRMServerPolicyCommand(params, "udp", "out"),
			imssSecurityXFRMServerPolicyCommand(params, "udp", "in"),
			imssSecurityXFRMServerPolicyCommand(params, "tcp", "out"),
			imssSecurityXFRMServerPolicyCommand(params, "tcp", "in"),
		)
	}
	return IMSSecurityAssociationXFRMInstallPlan{
		ReqID:         params.clientReqIDNum,
		Mode:          params.mode,
		LocalAddress:  params.localAddress,
		RemoteAddress: params.remoteAddress,
		Commands:      commands,
	}, nil
}

// InstallSecurityPlan implements the compatibility interface. Linux needs the
// AKA keys and concrete endpoints carried by the richer request, which
// RegisterSession selects whenever this installer is used.
func (i *LinuxIMSSecurityXFRMInstaller) InstallSecurityPlan(context.Context, IMSSecurityAssociationPlan) error {
	return fmt.Errorf("%w: Linux XFRM requires a full IMS security install request", ErrInvalidIMSSecurityXFRMPlan)
}

func (i *LinuxIMSSecurityXFRMInstaller) InstallSecurityPlanRequest(ctx context.Context, req IMSSecurityAssociationInstallRequest) error {
	_, err := i.Apply(ctx, req)
	return err
}

func (i *LinuxIMSSecurityXFRMInstaller) Apply(ctx context.Context, req IMSSecurityAssociationInstallRequest) (IMSSecurityAssociationXFRMState, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	plan, err := BuildIMSSecurityAssociationXFRMInstallPlan(req)
	if err != nil {
		return IMSSecurityAssociationXFRMState{}, err
	}
	runner := imssSecurityXFRMRunner(i.Runner)
	state, err := applyIMSSecurityXFRMPlan(ctx, runner, plan)
	if err != nil {
		return state, err
	}

	i.mu.Lock()
	prior := append([]IMSSecurityAssociationXFRMState(nil), i.states...)
	i.states = []IMSSecurityAssociationXFRMState{state}
	i.mu.Unlock()

	if superseded := supersededIMSSecurityXFRMUndo(prior, state); len(superseded) > 0 {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		remaining, _ := runIMSSecurityXFRMUndoIdempotent(cleanupCtx, runner, superseded)
		cancel()
		if len(remaining) > 0 {
			i.mu.Lock()
			i.states = append([]IMSSecurityAssociationXFRMState{{undo: remaining}}, i.states...)
			i.mu.Unlock()
		}
	}
	return state, nil
}

func (i *LinuxIMSSecurityXFRMInstaller) Cleanup(ctx context.Context) error {
	_ = ctx
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	i.mu.Lock()
	states := append([]IMSSecurityAssociationXFRMState(nil), i.states...)
	i.states = nil
	i.mu.Unlock()

	var allUndo []IMSSecurityAssociationXFRMCommand
	for _, st := range states {
		allUndo = append(allUndo, st.undo...)
	}
	runner := imssSecurityXFRMRunner(i.Runner)
	remaining, err := runIMSSecurityXFRMUndoIdempotent(cleanupCtx, runner, allUndo)
	if len(remaining) > 0 {
		i.mu.Lock()
		i.states = append([]IMSSecurityAssociationXFRMState{{undo: remaining}}, i.states...)
		i.mu.Unlock()
	}
	return err
}

func (i *LinuxIMSSecurityXFRMInstaller) StateCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.states)
}

func applyIMSSecurityXFRMPlan(ctx context.Context, runner IMSSecurityXFRMCommandRunner, plan IMSSecurityAssociationXFRMInstallPlan) (IMSSecurityAssociationXFRMState, error) {
	state := IMSSecurityAssociationXFRMState{Plan: plan}
	for _, command := range plan.Commands {
		if err := runner.RunIP(ctx, command.Args...); err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, rollbackErr := runIMSSecurityXFRMUndoIdempotent(cleanupCtx, runner, state.undo)
			cancel()
			if rollbackErr != nil {
				return state, errors.Join(err, rollbackErr)
			}
			return state, err
		}
		if len(command.UndoArgs) > 0 {
			state.undo = append(state.undo, cloneIMSSecurityXFRMCommand(command, true))
		}
	}
	return state, nil
}

func cleanupIMSSecurityXFRMState(ctx context.Context, runner IMSSecurityXFRMCommandRunner, state IMSSecurityAssociationXFRMState) error {
	_, err := runIMSSecurityXFRMUndoIdempotent(ctx, runner, state.undo)
	return err
}

func runIMSSecurityXFRMUndo(ctx context.Context, runner IMSSecurityXFRMCommandRunner, undo []IMSSecurityAssociationXFRMCommand) error {
	_, err := runIMSSecurityXFRMUndoIdempotent(ctx, runner, undo)
	return err
}

func runIMSSecurityXFRMUndoIdempotent(ctx context.Context, runner IMSSecurityXFRMCommandRunner, undo []IMSSecurityAssociationXFRMCommand) ([]IMSSecurityAssociationXFRMCommand, error) {
	var err error
	var failed []IMSSecurityAssociationXFRMCommand
	seen := make(map[string]bool, len(undo))
	for idx := len(undo) - 1; idx >= 0; idx-- {
		args := undo[idx].UndoArgs
		if len(args) == 0 {
			continue
		}
		key := xfrmArgsKey(args)
		if seen[key] {
			continue
		}
		seen[key] = true
		if runErr := runner.RunIP(ctx, args...); runErr != nil && !isBenignIMSSecurityXFRMDeleteError(runErr) {
			err = errors.Join(err, runErr)
			failed = append([]IMSSecurityAssociationXFRMCommand{cloneIMSSecurityXFRMCommand(undo[idx], true)}, failed...)
		}
	}
	return failed, err
}

func supersededIMSSecurityXFRMUndo(prior []IMSSecurityAssociationXFRMState, current IMSSecurityAssociationXFRMState) []IMSSecurityAssociationXFRMCommand {
	if len(prior) == 0 {
		return nil
	}
	active := make(map[string]bool, len(current.undo))
	for _, cmd := range current.undo {
		if len(cmd.UndoArgs) > 0 {
			active[xfrmArgsKey(cmd.UndoArgs)] = true
		}
	}
	var out []IMSSecurityAssociationXFRMCommand
	for _, st := range prior {
		for _, cmd := range st.undo {
			if len(cmd.UndoArgs) == 0 {
				continue
			}
			if active[xfrmArgsKey(cmd.UndoArgs)] {
				continue
			}
			out = append(out, cloneIMSSecurityXFRMCommand(cmd, true))
		}
	}
	return out
}

func xfrmArgsKey(args []string) string {
	return strings.Join(args, "\x00")
}

func isBenignIMSSecurityXFRMDeleteError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "no such process") ||
		strings.Contains(msg, "does not exist")
}

func imssSecurityXFRMRunner(runner IMSSecurityXFRMCommandRunner) IMSSecurityXFRMCommandRunner {
	if runner != nil {
		return runner
	}
	return ExecIMSSecurityXFRMCommandRunner{}
}

func cloneIMSSecurityXFRMCommand(command IMSSecurityAssociationXFRMCommand, undoOnly bool) IMSSecurityAssociationXFRMCommand {
	out := IMSSecurityAssociationXFRMCommand{
		UndoArgs: append([]string(nil), command.UndoArgs...),
	}
	if !undoOnly {
		out.Args = append([]string(nil), command.Args...)
	}
	return out
}

func normalizeIMSSecurityAssociationXFRMRequest(req IMSSecurityAssociationInstallRequest) (imsSecurityXFRMParams, error) {
	plan := req.Plan
	if isZeroIMSSecurityAssociationPlan(plan) {
		var ok bool
		plan, ok = BuildIMSSecurityAssociationPlan(req.Agreement)
		if !ok && len(req.SelectedParameters) == 0 {
			return imsSecurityXFRMParams{}, fmt.Errorf("%w: missing Security-Agree plan", ErrInvalidIMSSecurityXFRMPlan)
		}
	}
	protocol := strings.ToLower(strings.TrimSpace(firstNonEmpty(plan.Protocol, req.Agreement.Protocol, DefaultSecurityProtocol)))
	if protocol != DefaultSecurityProtocol {
		return imsSecurityXFRMParams{}, fmt.Errorf("%w: unsupported protocol %q", ErrInvalidIMSSecurityXFRMPlan, protocol)
	}
	if err := imssSecurityXFRMProtocol(firstNonEmpty(req.Agreement.Parameters["prot"], req.SelectedParameters["prot"], defaultSecurityIPSecProtocol)); err != nil {
		return imsSecurityXFRMParams{}, err
	}
	mode, err := imssSecurityXFRMMode(firstNonEmpty(plan.Mode, req.Agreement.Parameters["mode"], req.Agreement.Parameters["mod"], req.SelectedParameters["mode"], req.SelectedParameters["mod"], defaultSecurityMode))
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	authAlgorithm, authTruncBits, err := imssSecurityXFRMAuthAlgorithm(firstNonEmpty(plan.Algorithm, req.Agreement.Algorithm, req.SelectedParameters["alg"], DefaultSecurityAlgorithm))
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	if len(req.AKA.IK) != 16 {
		return imsSecurityXFRMParams{}, fmt.Errorf("%w: IK length %d", ErrInvalidIMSSecurityXFRMPlan, len(req.AKA.IK))
	}
	encAlgorithm, encKey, err := imssSecurityXFRMEncryption(firstNonEmpty(plan.EncryptionAlgorithm, req.Agreement.EncryptionAlgorithm, req.SelectedParameters["ealg"], DefaultSecurityEAlg), req.AKA.CK)
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	localAddress, err := imssSecurityXFRMAddress(req.LocalEndpoint, "local")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	remoteAddress, err := imssSecurityXFRMAddress(req.RemoteEndpoint, "remote")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	client := req.ClientAgreement
	localPort, err := imssSecurityXFRMPort(firstIMSSecurityPositiveInt(client.PortClient, req.LocalEndpoint.Port, plan.Outbound.LocalPort, plan.PortClient, req.Agreement.PortClient, parseSecurityPort(req.SelectedParameters["port-c"])), "local")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	remotePort, err := imssSecurityXFRMPort(firstIMSSecurityPositiveInt(plan.PortServer, plan.Outbound.RemotePort, plan.Inbound.RemotePort, req.Agreement.PortServer, parseSecurityPort(req.SelectedParameters["port-s"]), req.RemoteEndpoint.Port), "remote")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	spiClient, err := imssSecurityXFRMSPI(firstIMSSecurityNonZeroUint32(plan.SPIClient, plan.Inbound.SPI, req.Agreement.SPIClient, parseSecurityUint32(req.SelectedParameters["spi-c"])), "client")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	spiServer, err := imssSecurityXFRMSPI(firstIMSSecurityNonZeroUint32(plan.SPIServer, plan.Outbound.SPI, req.Agreement.SPIServer, parseSecurityUint32(req.SelectedParameters["spi-s"])), "server")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	inboundLocalPort, err := imssSecurityXFRMPort(firstIMSSecurityPositiveInt(client.PortClient, req.LocalEndpoint.Port, plan.Inbound.LocalPort, plan.PortClient, req.Agreement.PortClient, parseSecurityPort(req.SelectedParameters["port-c"])), "inbound local")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	inboundRemotePort, err := imssSecurityXFRMPort(firstIMSSecurityPositiveInt(req.Agreement.PortServer, plan.Inbound.RemotePort, req.RemoteEndpoint.Port, parseSecurityPort(req.SelectedParameters["port-s"])), "inbound remote")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	// The two protected flows are crossed: traffic from the P-CSCF server
	// port reaches the UE client port with spi-c, while replies from the
	// P-CSCF client port reach the UE server port with spi-s.
	inboundSPIRaw := firstIMSSecurityNonZeroUint32(plan.Inbound.SPI, req.Agreement.SPIClient, parseSecurityUint32(req.SelectedParameters["spi-c"]))
	if !isZeroSecurityAgreement(client) {
		inboundSPIRaw = client.SPIClient
	}
	inboundSPI, err := imssSecurityXFRMSPI(inboundSPIRaw, "inbound client")
	if err != nil {
		return imsSecurityXFRMParams{}, err
	}
	hasServerFlow := !isZeroSecurityAgreement(client)
	serverLocalPort, serverRemotePort, serverInboundSPI, serverOutboundSPI := "", "", "", ""
	if hasServerFlow {
		serverLocalPort, err = imssSecurityXFRMPort(client.PortServer, "server local")
		if err != nil {
			return imsSecurityXFRMParams{}, err
		}
		serverRemotePort, err = imssSecurityXFRMPort(req.Agreement.PortClient, "server remote")
		if err != nil {
			return imsSecurityXFRMParams{}, err
		}
		serverInboundSPI, err = imssSecurityXFRMSPI(client.SPIServer, "server inbound")
		if err != nil {
			return imsSecurityXFRMParams{}, err
		}
		serverOutboundSPI, err = imssSecurityXFRMSPI(req.Agreement.SPIClient, "server outbound")
		if err != nil {
			return imsSecurityXFRMParams{}, err
		}
	}
	clientReqIDNum, serverReqIDNum := allocateIMSSecurityXFRMReqIDPair()
	return imsSecurityXFRMParams{
		clientReqIDNum:    clientReqIDNum,
		clientReqID:       strconv.Itoa(clientReqIDNum),
		serverReqID:       strconv.Itoa(serverReqIDNum),
		mode:              mode,
		localAddress:      localAddress,
		remoteAddress:     remoteAddress,
		localPort:         localPort,
		remotePort:        remotePort,
		spiClient:         spiClient,
		spiServer:         spiServer,
		inboundLocalPort:  inboundLocalPort,
		inboundRemotePort: inboundRemotePort,
		inboundSPI:        inboundSPI,
		serverLocalPort:   serverLocalPort,
		serverRemotePort:  serverRemotePort,
		serverInboundSPI:  serverInboundSPI,
		serverOutboundSPI: serverOutboundSPI,
		hasServerFlow:     hasServerFlow,
		authAlgorithm:     authAlgorithm,
		authKey:           imssSecurityXFRMHexKey(req.AKA.IK),
		authTruncBits:     authTruncBits,
		encAlgorithm:      encAlgorithm,
		encKey:            encKey,
	}, nil
}

func imssSecurityXFRMServerStateCommand(params imsSecurityXFRMParams, outbound bool) IMSSecurityAssociationXFRMCommand {
	src, dst, spi := params.localAddress, params.remoteAddress, params.serverOutboundSPI
	if !outbound {
		src, dst, spi = params.remoteAddress, params.localAddress, params.serverInboundSPI
	}
	args := []string{
		"xfrm", "state", "update", "src", src, "dst", dst, "proto", "esp", "spi", spi,
		"reqid", params.serverReqID, "mode", params.mode,
		"auth-trunc", params.authAlgorithm, params.authKey, params.authTruncBits,
		"enc", params.encAlgorithm, params.encKey,
	}
	undo := []string{"xfrm", "state", "delete", "src", src, "dst", dst, "proto", "esp", "spi", spi}
	return IMSSecurityAssociationXFRMCommand{Args: args, UndoArgs: undo}
}

func imssSecurityXFRMStateCommand(params imsSecurityXFRMParams, outbound bool) IMSSecurityAssociationXFRMCommand {
	src, dst, spi := params.localAddress, params.remoteAddress, params.spiServer
	if !outbound {
		src, dst, spi = params.remoteAddress, params.localAddress, params.inboundSPI
	}
	args := []string{
		"xfrm", "state", "update",
		"src", src,
		"dst", dst,
		"proto", "esp",
		"spi", spi,
		"reqid", params.clientReqID,
		"mode", params.mode,
		"auth-trunc", params.authAlgorithm, params.authKey, params.authTruncBits,
		"enc", params.encAlgorithm, params.encKey,
	}
	undo := []string{"xfrm", "state", "delete", "src", src, "dst", dst, "proto", "esp", "spi", spi}
	return IMSSecurityAssociationXFRMCommand{Args: args, UndoArgs: undo}
}

func imssSecurityXFRMPolicyCommand(params imsSecurityXFRMParams, proto, dir string) IMSSecurityAssociationXFRMCommand {
	src, dst, sport, dport := params.localAddress, params.remoteAddress, params.localPort, params.remotePort
	if dir == "in" {
		src, dst, sport, dport = params.remoteAddress, params.localAddress, params.inboundRemotePort, params.inboundLocalPort
	}
	args := []string{
		"xfrm", "policy", "update",
		"src", src,
		"dst", dst,
		"proto", proto,
		"sport", sport,
		"dport", dport,
		"dir", dir,
	}
	args = append(args, imssSecurityXFRMPolicyTemplate(src, dst, params.clientReqID, params.mode, dir)...)
	undo := []string{
		"xfrm", "policy", "delete",
		"src", src,
		"dst", dst,
		"proto", proto,
		"sport", sport,
		"dport", dport,
		"dir", dir,
	}
	return IMSSecurityAssociationXFRMCommand{Args: args, UndoArgs: undo}
}

func imssSecurityXFRMServerPolicyCommand(params imsSecurityXFRMParams, proto, dir string) IMSSecurityAssociationXFRMCommand {
	src, dst, sport, dport := params.localAddress, params.remoteAddress, params.serverLocalPort, params.serverRemotePort
	if dir == "in" {
		src, dst, sport, dport = params.remoteAddress, params.localAddress, params.serverRemotePort, params.serverLocalPort
	}
	selector := []string{"src", src, "dst", dst, "proto", proto, "sport", sport, "dport", dport}
	args := append([]string{"xfrm", "policy", "update"}, selector...)
	args = append(args, "dir", dir)
	args = append(args, imssSecurityXFRMPolicyTemplate(src, dst, params.serverReqID, params.mode, dir)...)
	undo := append([]string{"xfrm", "policy", "delete"}, selector...)
	undo = append(undo, "dir", dir)
	return IMSSecurityAssociationXFRMCommand{Args: args, UndoArgs: undo}
}

func imssSecurityXFRMPolicyTemplate(src, dst, reqID, mode, dir string) []string {
	_ = dir
	return []string{
		"tmpl", "src", src, "dst", dst, "proto", "esp",
		"reqid", reqID, "mode", mode,
	}
}

func imssSecurityXFRMProtocol(protocol string) error {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", defaultSecurityIPSecProtocol:
		return nil
	default:
		return fmt.Errorf("%w: unsupported ipsec protocol %q", ErrInvalidIMSSecurityXFRMPlan, protocol)
	}
}

func imssSecurityXFRMMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "trans", "transport":
		return "transport", nil
	default:
		return "", fmt.Errorf("%w: unsupported mode %q", ErrInvalidIMSSecurityXFRMPlan, mode)
	}
}

func imssSecurityXFRMAuthAlgorithm(algorithm string) (name, truncBits string, err error) {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case DefaultSecurityAlgorithm:
		return "hmac(sha1)", "96", nil
	case SecurityAlgorithmHMACMD596:
		return "hmac(md5)", "96", nil
	default:
		return "", "", fmt.Errorf("%w: unsupported auth algorithm %q", ErrInvalidIMSSecurityXFRMPlan, algorithm)
	}
}

func imssSecurityXFRMEncryption(algorithm string, ck []byte) (name, key string, err error) {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case DefaultSecurityEAlg:
		// iproute2 passes the zero-length key as an empty argument. "0x" is
		// parsed as malformed key material and the kernel rejects the state.
		return "ecb(cipher_null)", "", nil
	case SecurityEncryptionAlgorithmAES:
		if len(ck) != 16 {
			return "", "", fmt.Errorf("%w: CK length %d for %s", ErrInvalidIMSSecurityXFRMPlan, len(ck), SecurityEncryptionAlgorithmAES)
		}
		return "cbc(aes)", imssSecurityXFRMHexKey(ck), nil
	default:
		return "", "", fmt.Errorf("%w: unsupported encryption algorithm %q", ErrInvalidIMSSecurityXFRMPlan, algorithm)
	}
}

func imssSecurityXFRMAddress(endpoint IMSSecurityAssociationEndpoint, label string) (string, error) {
	raw := strings.Trim(strings.TrimSpace(endpoint.Address), "[]")
	if raw == "" {
		return "", fmt.Errorf("%w: %s address is empty", ErrInvalidIMSSecurityXFRMPlan, label)
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %s address %q: %v", ErrInvalidIMSSecurityXFRMPlan, label, endpoint.Address, err)
	}
	return addr.Unmap().String(), nil
}

func imssSecurityXFRMPort(port int, label string) (string, error) {
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("%w: %s port %d", ErrInvalidIMSSecurityXFRMPlan, label, port)
	}
	return strconv.Itoa(port), nil
}

func imssSecurityXFRMSPI(spi uint32, label string) (string, error) {
	if spi == 0 {
		return "", fmt.Errorf("%w: %s spi is zero", ErrInvalidIMSSecurityXFRMPlan, label)
	}
	return fmt.Sprintf("0x%08x", spi), nil
}

func imssSecurityXFRMHexKey(key []byte) string {
	return "0x" + hex.EncodeToString(key)
}

func firstIMSSecurityPositiveInt(items ...int) int {
	for _, item := range items {
		if item > 0 {
			return item
		}
	}
	return 0
}

func firstIMSSecurityNonZeroUint32(items ...uint32) uint32 {
	for _, item := range items {
		if item != 0 {
			return item
		}
	}
	return 0
}
