package eventhost

import (
	"context"
	"fmt"
	"testing"

	"github.com/kimoju/vowifi-go/runtimehost/simtransport"
)

func TestRound2Audit8B17CanceledControlPortHangNotPromotedAndHintCloned(t *testing.T) {
	canceledErr := fmt.Errorf("service stopping: %w", context.Canceled)
	ev := NewControlPortHangRecovery("dev-1", "identity", "AT", "read_imsi", canceledErr)
	if ev.Class != simtransport.RecoveryClassNone || ev.Recoverable {
		t.Fatalf("NewControlPortHangRecovery(context.Canceled) = %+v, want RecoveryClassNone Recoverable=false", ev)
	}
	if ev.Hint == nil || ev.Hint.SuggestedAction != "" {
		t.Fatalf("NewControlPortHangRecovery(context.Canceled) hint = %+v, want empty SuggestedAction", ev.Hint)
	}

	// Verify DispatchRecovery deep-copies *ControlPortHint so caller/consumer mutations cannot race.
	mutatingHint := &ControlPortHint{
		PortType:        ControlPortAT,
		Operation:       "read_imsi",
		SuggestedAction: RecoveryActionRestartControlPort,
	}
	in := RuntimeRecovery{
		DevID:       "dev-1",
		Component:   "identity",
		Class:       simtransport.RecoveryClassControlPortHung,
		Recoverable: true,
		Hint:        mutatingHint,
	}
	dispatcher := &captureDispatcher{}
	if !DispatchRecovery(context.Background(), dispatcher, in) {
		t.Fatal("DispatchRecovery() = false, want true")
	}
	mutatingHint.Operation = "mutated-by-caller"
	mutatingHint.SuggestedAction = RecoveryActionRetryLater

	got, ok := dispatcher.events[0].(RuntimeRecovery)
	if !ok {
		t.Fatalf("dispatched event = %T, want RuntimeRecovery", dispatcher.events[0])
	}
	if got.Hint == nil || got.Hint == mutatingHint {
		t.Fatal("dispatched RuntimeRecovery.Hint aliases caller pointer")
	}
	if got.Hint.Operation != "read_imsi" || got.Hint.SuggestedAction != RecoveryActionRestartControlPort {
		t.Fatalf("dispatched Hint = %+v, want original unmutated fields", got.Hint)
	}
}
