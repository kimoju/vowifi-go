package runtimehost

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/boa-z/vowifi-go/runtimehost/eventhost"
)

func TestSafeDiagnosticStateRedactsSensitiveRuntimeText(t *testing.T) {
	next := time.Now().Add(time.Minute)
	unixPath := "/" + "home" + "/" + "boa" + "/vohive/config/config.yaml"
	macPath := "/" + "Users" + "/" + "boa" + "/trace.txt"
	state := State{
		DeviceID:                 "wwan0-imei-490154203237518",
		Phase:                    PhaseReady,
		DataplaneMode:            "tun",
		SIMReady:                 true,
		AccessReady:              true,
		TunnelReady:              true,
		IMSReady:                 true,
		SMSReady:                 true,
		RegStatus:                1,
		RegStatusText:            "registered IMSI 310280233641503 from 192.168.31.34",
		NetworkMode:              "LTE ue-ip=192.168.31.34",
		LastErrorClass:           "ims",
		LastError:                `Authorization: Digest nonce="nonce-secret", response="0123456789abcdef0123456789abcdef"; ck=0123456789abcdef0123456789abcdef; path=` + unixPath,
		LastReason:               "mobike 192.168.31.34 -> 87.194.9.8 for sip:310280233641503@ims.example using " + unixPath,
		IMSRecoveryPending:       true,
		IMSRecoveryRetryAfter:    3 * time.Second,
		IMSRecoveryNextAttemptAt: next,
		IMSRecoveryReason:        "retry trace " + macPath + "; Proxy-Authenticate: Digest nonce=\"recover-secret\"",
		UpdatedAt:                next.Add(-time.Second),
	}

	got := SafeDiagnosticState(state)
	if !got.Redacted || got.Phase != PhaseReady || !got.SIMReady || !got.TunnelReady ||
		got.IMSRecoveryRetryAfter != 3*time.Second || !got.IMSRecoveryNextAttemptAt.Equal(next) {
		t.Fatalf("diagnostic state lost operational fields: %+v", got)
	}
	assertNoRuntimeDiagnosticLeak(t, fmt.Sprintf("%+v", got), unixPath, macPath)
	for _, want := range []string{"<redacted", ".invalid", "<redacted-local-path>"} {
		if !strings.Contains(fmt.Sprintf("%+v", got), want) {
			t.Fatalf("diagnostic state does not contain redaction marker %q: %+v", want, got)
		}
	}
	if state.LastError == got.LastError || state.LastReason == got.LastReason || state.DeviceID == got.DeviceID {
		t.Fatalf("sensitive fields were not redacted: state=%+v diagnostic=%+v", state, got)
	}
}

func TestRuntimeSnapshotAndObsUseDiagnosticState(t *testing.T) {
	dispatch := &runtimeDispatcher{}
	inst := &Instance{
		state: State{
			DeviceID:          "dev-imsi-310280233641503",
			Phase:             PhaseReady,
			IMSReady:          true,
			SMSReady:          true,
			LastReason:        "registration from 192.168.31.34",
			IMSRecoveryReason: `WWW-Authenticate: Digest nonce="recover-secret"`,
			UpdatedAt:         time.Now(),
		},
		dispatch: dispatch,
	}

	diag := inst.DiagnosticState()
	assertNoRuntimeDiagnosticLeak(t, fmt.Sprintf("%+v", diag))

	obs := inst.Obs()
	if obs["redacted"] != true {
		t.Fatalf("Obs redacted flag=%v, want true", obs["redacted"])
	}
	assertNoRuntimeDiagnosticLeak(t, fmt.Sprintf("%+v", obs))

	inst.dispatchRuntimeState(context.Background())
	if len(dispatch.events) != 1 {
		t.Fatalf("events=%d, want one runtime snapshot", len(dispatch.events))
	}
	snapshot, ok := dispatch.events[0].(eventhost.RuntimeStateSnapshot)
	if !ok {
		t.Fatalf("event type=%T, want RuntimeStateSnapshot", dispatch.events[0])
	}
	assertNoRuntimeDiagnosticLeak(t, fmt.Sprintf("%+v", snapshot))
	if snapshot.Phase != eventhost.RuntimePhaseReady || !snapshot.IMSReady || !snapshot.SMSReady {
		t.Fatalf("snapshot lost operational fields: %+v", snapshot)
	}
}

func TestSafeDiagnosticIMSRegisterResponseDecisionRedactsReason(t *testing.T) {
	reason := `403 Forbidden for sip:310280233641503@ims.example from 192.168.31.34; WWW-Authenticate: Digest nonce="recover-secret"; path=/` + "home" + `/boa/vohive/ims.log`
	decision := ClassifyIMSRegisterResponse(503, 7*time.Second)

	got := SafeDiagnosticIMSRegisterResponseDecision(decision, reason)
	if !got.Redacted || got.StatusCode != 503 || got.Action != IMSRegisterResponseActionBackoffRetry ||
		!got.Recoverable || !got.Retry || !got.Backoff || got.RetryAfter != 7*time.Second {
		t.Fatalf("diagnostic decision lost recovery fields: %+v", got)
	}
	assertNoRuntimeDiagnosticLeak(t, fmt.Sprintf("%+v", got), "/"+filepathJoinForDiagnosticTest("home", "boa", "vohive", "ims.log"))
	for _, want := range []string{"<redacted", ".invalid", "<redacted-local-path>"} {
		if !strings.Contains(fmt.Sprintf("%+v", got), want) {
			t.Fatalf("diagnostic decision does not contain redaction marker %q: %+v", want, got)
		}
	}
}

func assertNoRuntimeDiagnosticLeak(t *testing.T, value string, extraLeaks ...string) {
	t.Helper()
	leaks := []string{
		"490154203237518",
		"310280233641503",
		"192.168.31.34",
		"87.194.9.8",
		"nonce-secret",
		"recover-secret",
		"0123456789abcdef0123456789abcdef",
	}
	leaks = append(leaks, extraLeaks...)
	for _, leak := range leaks {
		if strings.Contains(value, leak) {
			t.Fatalf("diagnostic output leaked %q in %q", leak, value)
		}
	}
}

func filepathJoinForDiagnosticTest(parts ...string) string {
	return strings.Join(parts, "/")
}
