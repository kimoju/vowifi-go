package tracefixture

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestTranscriptJSONSchemaIsValid(t *testing.T) {
	if !json.Valid([]byte(TranscriptJSONSchema)) {
		t.Fatal("transcript JSON schema is not valid JSON")
	}
	var schema map[string]any
	if err := json.Unmarshal([]byte(TranscriptJSONSchema), &schema); err != nil {
		t.Fatalf("unmarshal transcript JSON schema: %v", err)
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema properties missing: %#v", schema["properties"])
	}
	schemaProp, ok := props["schema"].(map[string]any)
	if !ok || schemaProp["const"] != TranscriptSchemaVersion {
		t.Fatalf("schema const mismatch: %#v", props["schema"])
	}
}

func TestParseTranscriptJSONAcceptsRedactedTranscript(t *testing.T) {
	raw := marshalTranscript(t, Transcript{
		Schema: TranscriptSchemaVersion,
		Name:   "register-401-redacted",
		Events: []TranscriptEvent{
			{
				Label:     "initial-register",
				Direction: "outbound",
				Transport: "udp",
				Wire: strings.Join([]string{
					"REGISTER sip:ims.example.invalid SIP/2.0",
					"Via: SIP/2.0/UDP redacted.invalid:5060;branch=z9hG4bKfixture",
					"From: <sip:redacted.invalid>;tag=fixture",
					"To: <sip:redacted.invalid>",
					"Call-ID: fixture-call",
					"CSeq: 1 REGISTER",
					"Authorization: <redacted>",
					"Content-Length: 0",
					"",
					"",
				}, "\r\n"),
			},
		},
	})

	transcript, err := ParseTranscriptJSON(raw)
	if err != nil {
		t.Fatalf("ParseTranscriptJSON returned error: %v", err)
	}
	if transcript.Name != "register-401-redacted" || len(transcript.Events) != 1 {
		t.Fatalf("unexpected transcript: %#v", transcript)
	}
}

func TestParseTranscriptJSONRejectsSensitiveFixture(t *testing.T) {
	tests := []struct {
		name     string
		wire     string
		secret   string
		wantKind string
	}{
		{
			name:     "imsi",
			wire:     "X-IMSI: 001010000000000",
			secret:   "001010000000000",
			wantKind: "subscriber",
		},
		{
			name:     "imei",
			wire:     "X-IMEI: 004999010640000",
			secret:   "004999010640000",
			wantKind: "subscriber",
		},
		{
			name:     "msisdn",
			wire:     "To: <tel:+15550101234>",
			secret:   "+15550101234",
			wantKind: "msisdn",
		},
		{
			name:     "auth",
			wire:     `Authorization: Digest username="<redacted-sip-user-1>", nonce="auth-secret", response="auth-response"`,
			secret:   "auth-secret",
			wantKind: "auth",
		},
		{
			name:     "aka",
			wire:     "X-AKA: rand=00112233445566778899AABBCCDDEEFF",
			secret:   "00112233445566778899AABBCCDDEEFF",
			wantKind: "aka",
		},
		{
			name:     "ip",
			wire:     "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKfixture",
			secret:   "192.0.2.10",
			wantKind: "ip",
		},
		{
			name:     "ipv6",
			wire:     "Via: SIP/2.0/TCP [2001:db8::10]:5060;branch=z9hG4bKfixture",
			secret:   "2001:db8::10",
			wantKind: "ip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := marshalTranscript(t, Transcript{
				Schema: TranscriptSchemaVersion,
				Name:   "sensitive-" + tt.name,
				Events: []TranscriptEvent{
					{
						Direction: "inbound",
						Transport: "udp",
						Wire:      tt.wire,
					},
				},
			})

			_, err := ParseTranscriptJSON(raw)
			if !errors.Is(err, ErrSensitiveFixture) {
				t.Fatalf("ParseTranscriptJSON error = %v, want ErrSensitiveFixture", err)
			}
			if strings.Contains(err.Error(), tt.secret) {
				t.Fatalf("redaction error leaked sensitive value %q: %v", tt.secret, err)
			}
			var redactionErr *RedactionError
			if !errors.As(err, &redactionErr) {
				t.Fatalf("error does not expose RedactionError: %T", err)
			}
			if len(redactionErr.Violations) == 0 {
				t.Fatal("redaction error had no violations")
			}
			if !strings.Contains(redactionErr.Violations[0].Kind, tt.wantKind) {
				t.Fatalf("violation kind = %q, want substring %q", redactionErr.Violations[0].Kind, tt.wantKind)
			}
		})
	}
}

func TestParseTranscriptJSONRejectsInvalidShape(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "unknown top-level field",
			raw:  `{"schema":"vowifi-go.tracefixture.transcript.v1","name":"x","events":[{"direction":"inbound","transport":"udp","wire":"SIP/2.0 200 OK\r\n\r\n"}],"extra":true}`,
		},
		{
			name: "wrong schema",
			raw:  `{"schema":"vowifi-go.tracefixture.transcript.v0","name":"x","events":[{"direction":"inbound","transport":"udp","wire":"SIP/2.0 200 OK\r\n\r\n"}]}`,
		},
		{
			name: "empty events",
			raw:  `{"schema":"vowifi-go.tracefixture.transcript.v1","name":"x","events":[]}`,
		},
		{
			name: "trailing json",
			raw:  `{"schema":"vowifi-go.tracefixture.transcript.v1","name":"x","events":[{"direction":"inbound","transport":"udp","wire":"SIP/2.0 200 OK\r\n\r\n"}]} {}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTranscriptJSON([]byte(tt.raw))
			if !errors.Is(err, ErrInvalidTranscript) {
				t.Fatalf("ParseTranscriptJSON error = %v, want ErrInvalidTranscript", err)
			}
		})
	}
}

func marshalTranscript(t *testing.T, transcript Transcript) []byte {
	t.Helper()
	raw, err := json.Marshal(transcript)
	if err != nil {
		t.Fatalf("marshal transcript: %v", err)
	}
	return raw
}
