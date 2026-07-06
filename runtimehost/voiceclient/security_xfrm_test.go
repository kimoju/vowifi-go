package voiceclient

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

func TestBuildIMSSecurityAssociationXFRMInstallPlanBuildsTransportCommands(t *testing.T) {
	req := validSecurityXFRMInstallRequest()
	installPlan, err := BuildIMSSecurityAssociationXFRMInstallPlan(req)
	if err != nil {
		t.Fatalf("BuildIMSSecurityAssociationXFRMInstallPlan() error = %v", err)
	}
	if installPlan.ReqID != 1 || installPlan.Mode != "transport" ||
		installPlan.LocalAddress != "192.0.2.20" || installPlan.RemoteAddress != "198.51.100.10" {
		t.Fatalf("install plan metadata=%+v", installPlan)
	}
	ik := securityXFRMHexKey(req.AKA.IK)
	want := []IMSSecurityAssociationXFRMCommand{
		{
			Args: []string{
				"xfrm", "state", "add",
				"src", "192.0.2.20",
				"dst", "198.51.100.10",
				"proto", "esp",
				"spi", "0x0a0b0c0d",
				"reqid", "1",
				"mode", "transport",
				"auth-trunc", "hmac(sha1)", ik, "96",
				"enc", "ecb(cipher_null)", "0x",
				"sel",
				"src", "192.0.2.20",
				"dst", "198.51.100.10",
				"proto", "udp",
				"sport", "5062",
				"dport", "5063",
			},
			UndoArgs: []string{"xfrm", "state", "delete", "src", "192.0.2.20", "dst", "198.51.100.10", "proto", "esp", "spi", "0x0a0b0c0d"},
		},
		{
			Args: []string{
				"xfrm", "state", "add",
				"src", "198.51.100.10",
				"dst", "192.0.2.20",
				"proto", "esp",
				"spi", "0x01020304",
				"reqid", "1",
				"mode", "transport",
				"auth-trunc", "hmac(sha1)", ik, "96",
				"enc", "ecb(cipher_null)", "0x",
				"sel",
				"src", "198.51.100.10",
				"dst", "192.0.2.20",
				"proto", "udp",
				"sport", "5063",
				"dport", "5062",
			},
			UndoArgs: []string{"xfrm", "state", "delete", "src", "198.51.100.10", "dst", "192.0.2.20", "proto", "esp", "spi", "0x01020304"},
		},
		{
			Args: []string{
				"xfrm", "policy", "add",
				"src", "192.0.2.20",
				"dst", "198.51.100.10",
				"proto", "udp",
				"sport", "5062",
				"dport", "5063",
				"dir", "out",
				"tmpl",
				"src", "192.0.2.20",
				"dst", "198.51.100.10",
				"proto", "esp",
				"reqid", "1",
				"mode", "transport",
			},
			UndoArgs: []string{"xfrm", "policy", "delete", "src", "192.0.2.20", "dst", "198.51.100.10", "proto", "udp", "sport", "5062", "dport", "5063", "dir", "out"},
		},
		{
			Args: []string{
				"xfrm", "policy", "add",
				"src", "198.51.100.10",
				"dst", "192.0.2.20",
				"proto", "udp",
				"sport", "5063",
				"dport", "5062",
				"dir", "in",
				"tmpl",
				"src", "198.51.100.10",
				"dst", "192.0.2.20",
				"proto", "esp",
				"reqid", "1",
				"mode", "transport",
			},
			UndoArgs: []string{"xfrm", "policy", "delete", "src", "198.51.100.10", "dst", "192.0.2.20", "proto", "udp", "sport", "5063", "dport", "5062", "dir", "in"},
		},
	}
	if !reflect.DeepEqual(installPlan.Commands, want) {
		t.Fatalf("commands=\n%v\nwant\n%v", installPlan.Commands, want)
	}
}

func TestBuildIMSSecurityAssociationXFRMInstallPlanDerivesPlanFromAgreement(t *testing.T) {
	req := validSecurityXFRMInstallRequest()
	req.Plan = IMSSecurityAssociationPlan{}
	req.Agreement = SecurityAgreement{
		Protocol:            DefaultSecurityProtocol,
		Algorithm:           DefaultSecurityAlgorithm,
		EncryptionAlgorithm: DefaultSecurityEAlg,
		SPIClient:           0x01020304,
		SPIServer:           0x0a0b0c0d,
		PortClient:          5062,
		PortServer:          5063,
		Parameters:          map[string]string{"mode": "trans"},
	}
	installPlan, err := BuildIMSSecurityAssociationXFRMInstallPlan(req)
	if err != nil {
		t.Fatalf("BuildIMSSecurityAssociationXFRMInstallPlan() error = %v", err)
	}
	if len(installPlan.Commands) != 4 || installPlan.Commands[0].Args[10] != "0x0a0b0c0d" ||
		installPlan.Commands[1].Args[10] != "0x01020304" {
		t.Fatalf("install plan commands=%+v", installPlan.Commands)
	}
}

func TestBuildIMSSecurityAssociationXFRMInstallPlanRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		edit func(*IMSSecurityAssociationInstallRequest)
	}{
		{name: "missing IK", edit: func(req *IMSSecurityAssociationInstallRequest) {
			req.AKA.IK = nil
		}},
		{name: "bad local address", edit: func(req *IMSSecurityAssociationInstallRequest) {
			req.LocalEndpoint.Address = "not an ip"
		}},
		{name: "missing remote port", edit: func(req *IMSSecurityAssociationInstallRequest) {
			req.Plan.PortServer = 0
			req.Plan.Outbound.RemotePort = 0
			req.Plan.Inbound.RemotePort = 0
			req.RemoteEndpoint.Port = 0
		}},
		{name: "missing client spi", edit: func(req *IMSSecurityAssociationInstallRequest) {
			req.Plan.SPIClient = 0
			req.Plan.Inbound.SPI = 0
			req.Agreement.SPIClient = 0
		}},
		{name: "unsupported auth", edit: func(req *IMSSecurityAssociationInstallRequest) {
			req.Plan.Algorithm = "hmac-md5-96"
		}},
		{name: "unsupported encryption", edit: func(req *IMSSecurityAssociationInstallRequest) {
			req.Plan.EncryptionAlgorithm = "aes-cbc"
		}},
		{name: "unsupported mode", edit: func(req *IMSSecurityAssociationInstallRequest) {
			req.Plan.Mode = "tunnel"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validSecurityXFRMInstallRequest()
			tc.edit(&req)
			_, err := BuildIMSSecurityAssociationXFRMInstallPlan(req)
			if !errors.Is(err, ErrInvalidIMSSecurityXFRMPlan) {
				t.Fatalf("BuildIMSSecurityAssociationXFRMInstallPlan() err=%v, want ErrInvalidIMSSecurityXFRMPlan", err)
			}
		})
	}
}

func TestLinuxIMSSecurityXFRMInstallerApplyInstallAndCleanup(t *testing.T) {
	req := validSecurityXFRMInstallRequest()
	plan, err := BuildIMSSecurityAssociationXFRMInstallPlan(req)
	if err != nil {
		t.Fatalf("BuildIMSSecurityAssociationXFRMInstallPlan() error = %v", err)
	}
	runner := &fakeIMSSecurityXFRMRunner{}
	installer := &LinuxIMSSecurityXFRMInstaller{Runner: runner}
	state, err := installer.Apply(context.Background(), req)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if installer.StateCount() != 1 || state.Plan.LocalAddress != "192.0.2.20" || len(state.undo) != len(plan.Commands) {
		t.Fatalf("state=%+v count=%d", state, installer.StateCount())
	}
	if !reflect.DeepEqual(runner.commands, imsSecurityXFRMCommandArgs(plan.Commands, false)) {
		t.Fatalf("apply commands=\n%v\nwant\n%v", runner.commands, imsSecurityXFRMCommandArgs(plan.Commands, false))
	}

	if err := installer.InstallSecurityPlanRequest(context.Background(), req); err != nil {
		t.Fatalf("InstallSecurityPlanRequest() error = %v", err)
	}
	if installer.StateCount() != 2 {
		t.Fatalf("StateCount()=%d, want 2", installer.StateCount())
	}

	want := append([][]string{}, imsSecurityXFRMCommandArgs(plan.Commands, false)...)
	want = append(want, imsSecurityXFRMCommandArgs(plan.Commands, false)...)
	want = append(want, imsSecurityXFRMCommandArgs(plan.Commands, true)...)
	want = append(want, imsSecurityXFRMCommandArgs(plan.Commands, true)...)
	if err := installer.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if installer.StateCount() != 0 {
		t.Fatalf("StateCount(after cleanup)=%d, want 0", installer.StateCount())
	}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("all commands=\n%v\nwant\n%v", runner.commands, want)
	}
}

func TestLinuxIMSSecurityXFRMInstallerRollsBackOnFailure(t *testing.T) {
	wantErr := errors.New("policy install failed")
	req := validSecurityXFRMInstallRequest()
	plan, err := BuildIMSSecurityAssociationXFRMInstallPlan(req)
	if err != nil {
		t.Fatalf("BuildIMSSecurityAssociationXFRMInstallPlan() error = %v", err)
	}
	runner := &fakeIMSSecurityXFRMRunner{failAt: 2, err: wantErr}
	installer := &LinuxIMSSecurityXFRMInstaller{Runner: runner}
	_, err = installer.Apply(context.Background(), req)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Apply() err=%v, want policy failure", err)
	}
	if installer.StateCount() != 0 {
		t.Fatalf("StateCount()=%d, want 0 after rollback", installer.StateCount())
	}
	want := [][]string{
		plan.Commands[0].Args,
		plan.Commands[1].Args,
		plan.Commands[2].Args,
		plan.Commands[1].UndoArgs,
		plan.Commands[0].UndoArgs,
	}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("commands=\n%v\nwant\n%v", runner.commands, want)
	}
}

func TestLinuxIMSSecurityXFRMInstallerKeepsStateWhenCleanupFails(t *testing.T) {
	req := validSecurityXFRMInstallRequest()
	runner := &fakeIMSSecurityXFRMRunner{}
	installer := &LinuxIMSSecurityXFRMInstaller{Runner: runner}
	if _, err := installer.Apply(context.Background(), req); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	wantErr := errors.New("cleanup failed")
	runner.failAt = len(runner.commands)
	runner.err = wantErr
	if err := installer.Cleanup(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("Cleanup() err=%v, want cleanup failure", err)
	}
	if installer.StateCount() != 1 {
		t.Fatalf("StateCount()=%d, want state kept for retry", installer.StateCount())
	}
	runner.err = nil
	if err := installer.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup(retry) error = %v", err)
	}
	if installer.StateCount() != 0 {
		t.Fatalf("StateCount(after retry)=%d, want 0", installer.StateCount())
	}
}

func validSecurityXFRMInstallRequest() IMSSecurityAssociationInstallRequest {
	return IMSSecurityAssociationInstallRequest{
		Plan: IMSSecurityAssociationPlan{
			Protocol:            DefaultSecurityProtocol,
			Mode:                "trans",
			Algorithm:           DefaultSecurityAlgorithm,
			EncryptionAlgorithm: DefaultSecurityEAlg,
			SPIClient:           0x01020304,
			SPIServer:           0x0a0b0c0d,
			PortClient:          5062,
			PortServer:          5063,
			Inbound: IMSSecurityAssociationDirection{
				Direction:  "inbound",
				LocalPort:  5062,
				RemotePort: 5063,
				SPI:        0x01020304,
			},
			Outbound: IMSSecurityAssociationDirection{
				Direction:  "outbound",
				LocalPort:  5062,
				RemotePort: 5063,
				SPI:        0x0a0b0c0d,
			},
		},
		Agreement: SecurityAgreement{
			Protocol:            DefaultSecurityProtocol,
			Algorithm:           DefaultSecurityAlgorithm,
			EncryptionAlgorithm: DefaultSecurityEAlg,
			SPIClient:           0x01020304,
			SPIServer:           0x0a0b0c0d,
			PortClient:          5062,
			PortServer:          5063,
		},
		AKA: IMSSecurityAKAKeys{
			CK: securityXFRMBytes(0xa0, 16),
			IK: securityXFRMBytes(0xb0, 16),
		},
		LocalEndpoint:  IMSSecurityAssociationEndpoint{Address: "192.0.2.20", Port: 5062},
		RemoteEndpoint: IMSSecurityAssociationEndpoint{Address: "198.51.100.10", Port: 5063},
	}
}

func securityXFRMBytes(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func securityXFRMHexKey(key []byte) string {
	return "0x" + hex.EncodeToString(key)
}

type fakeIMSSecurityXFRMRunner struct {
	commands [][]string
	failAt   int
	err      error
}

func (r *fakeIMSSecurityXFRMRunner) RunIP(ctx context.Context, args ...string) error {
	copied := append([]string(nil), args...)
	r.commands = append(r.commands, copied)
	if r.err != nil && len(r.commands)-1 == r.failAt {
		return r.err
	}
	return nil
}

func imsSecurityXFRMCommandArgs(commands []IMSSecurityAssociationXFRMCommand, undo bool) [][]string {
	out := make([][]string, 0, len(commands))
	if !undo {
		for _, command := range commands {
			out = append(out, command.Args)
		}
		return out
	}
	for idx := len(commands) - 1; idx >= 0; idx-- {
		out = append(out, commands[idx].UndoArgs)
	}
	return out
}
