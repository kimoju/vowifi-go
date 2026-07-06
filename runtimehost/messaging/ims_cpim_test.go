package messaging

import (
	"bytes"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
)

func TestIMSCPIMMessageHeaderRoundTrip(t *testing.T) {
	body := []byte(`<imdn><message-id>msg-123</message-id></imdn>`)
	messageHeaders := map[string][]string{
		"From":            {"<sip:alice@example.com>;tag=from-tag"},
		"To":              {"<sip:bob@example.com>"},
		"DateTime":        {"2026-07-07T02:03:04Z"},
		"NS":              {"imdn <urn:ietf:params:imdn>"},
		"Require":         {"imdn.Delivery-Notification"},
		"imdn.Message-ID": {"msg-123"},
	}
	contentHeaders := map[string][]string{
		"Content-Type":        {`message/imdn+xml; charset=UTF-8`},
		"Content-Disposition": {"notification"},
		"Content-Length":      {"999"},
	}

	encoded, err := BuildIMSCPIMMessageWithHeaders(messageHeaders, contentHeaders, body)
	if err != nil {
		t.Fatalf("BuildIMSCPIMMessageWithHeaders() error = %v", err)
	}
	if bytes.Contains(encoded, []byte("Content-Length: 999")) {
		t.Fatalf("encoded CPIM kept stale Content-Length:\n%s", encoded)
	}
	parsed, err := ParseIMSCPIMMessage(encoded)
	if err != nil {
		t.Fatalf("ParseIMSCPIMMessage() error = %v body=%s", err, encoded)
	}

	headers := textproto.MIMEHeader(parsed.Headers)
	if got := headers.Get("From"); got != "<sip:alice@example.com>;tag=from-tag" {
		t.Fatalf("From=%q", got)
	}
	if got := headers.Get("To"); got != "<sip:bob@example.com>" {
		t.Fatalf("To=%q", got)
	}
	if got := headers.Get("DateTime"); got != "2026-07-07T02:03:04Z" {
		t.Fatalf("DateTime=%q", got)
	}
	if got := headers.Get("NS"); got != "imdn <urn:ietf:params:imdn>" {
		t.Fatalf("NS=%q", got)
	}
	if got := headers.Get("Require"); got != "imdn.Delivery-Notification" {
		t.Fatalf("Require=%q", got)
	}
	if got := imsHeaderValue(parsed.Headers, "imdn.Message-ID"); got != "msg-123" {
		t.Fatalf("imdn.Message-ID=%q", got)
	}

	content := textproto.MIMEHeader(parsed.ContentHeaders)
	if parsed.ContentType != "message/imdn+xml" {
		t.Fatalf("ContentType=%q", parsed.ContentType)
	}
	if got := content.Get("Content-Type"); got != `message/imdn+xml; charset=UTF-8` {
		t.Fatalf("Content-Type=%q", got)
	}
	if got := content.Get("Content-Disposition"); got != "notification" {
		t.Fatalf("Content-Disposition=%q", got)
	}
	if got := content.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length=%q want %d", got, len(body))
	}
	if string(parsed.Body) != string(body) {
		t.Fatalf("Body=%q want %q", parsed.Body, body)
	}

	if got := contentHeaders["Content-Length"][0]; got != "999" {
		t.Fatalf("caller content headers mutated: Content-Length=%q", got)
	}
}

func TestBuildIMSCPIMMessageWithHeadersDeduplicatesContentLength(t *testing.T) {
	body := []byte("hello")
	encoded, err := BuildIMSCPIMMessageWithHeaders(map[string][]string{
		"From": {"<sip:alice@example.com>"},
	}, map[string][]string{
		"Content-Type":   {"text/plain"},
		"Content-Length": {"999"},
		"content-length": {"888"},
	}, body)
	if err != nil {
		t.Fatalf("BuildIMSCPIMMessageWithHeaders() error = %v", err)
	}
	if count := bytes.Count(encoded, []byte("Content-Length:")); count != 1 {
		t.Fatalf("Content-Length count=%d body=\n%s", count, encoded)
	}
	if strings.Contains(string(encoded), "999") || strings.Contains(string(encoded), "888") {
		t.Fatalf("encoded CPIM kept stale duplicate length:\n%s", encoded)
	}
	parsed, err := ParseIMSCPIMMessage(encoded)
	if err != nil {
		t.Fatalf("ParseIMSCPIMMessage() error = %v body=%s", err, encoded)
	}
	content := textproto.MIMEHeader(parsed.ContentHeaders)
	if got := content.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length=%q want %d", got, len(body))
	}
}

func TestParseIMSCPIMMessageNormalizesIMDNNamespaceAlias(t *testing.T) {
	payload := "<imdn><message-id>msg-aliased</message-id></imdn>"
	body := []byte(strings.Join([]string{
		"From: <sip:alice@example.com>",
		"NS: MsgState <URN:IETF:PARAMS:IMDN>",
		"MsgState.Message-Id: msg-aliased",
		"MsgState.Disposition-Notification: positive-delivery, display",
		"",
		"Content-Type: message/imdn+xml",
		"Content-Length: " + strconv.Itoa(len(payload)),
		"",
		payload,
	}, "\r\n"))

	parsed, err := ParseIMSCPIMMessage(body)
	if err != nil {
		t.Fatalf("ParseIMSCPIMMessage() error = %v", err)
	}

	if got := imsHeaderValue(parsed.Headers, "imdn.Message-ID"); got != "msg-aliased" {
		t.Fatalf("imdn.Message-ID=%q", got)
	}
	if got := imsHeaderValue(parsed.Headers, "imdn.Disposition-Notification"); got != "positive-delivery, display" {
		t.Fatalf("imdn.Disposition-Notification=%q", got)
	}
	if got := imsHeaderValue(parsed.Headers, "MsgState.Message-ID"); got != "" {
		t.Fatalf("aliased MsgState.Message-ID still present as %q", got)
	}
	if values := parsed.Headers["imdn.Message-ID"]; len(values) != 1 || values[0] != "msg-aliased" {
		t.Fatalf("normalized Message-ID header=%+v", parsed.Headers)
	}
}

func TestParseIMSCPIMMessageMergesCanonicalAndAliasedIMDNHeaders(t *testing.T) {
	payload := "<imdn/>"
	body := []byte(strings.Join([]string{
		"From: <sip:alice@example.com>",
		"NS: x <urn:ietf:params:imdn>",
		"imdn.Message-ID: canonical",
		"x.Message-ID: aliased",
		"",
		"Content-Type: message/imdn+xml",
		"Content-Length: " + strconv.Itoa(len(payload)),
		"",
		payload,
	}, "\r\n"))

	parsed, err := ParseIMSCPIMMessage(body)
	if err != nil {
		t.Fatalf("ParseIMSCPIMMessage() error = %v", err)
	}
	values := parsed.Headers["imdn.Message-ID"]
	if len(values) != 2 || !cpimTestHasValue(values, "canonical") || !cpimTestHasValue(values, "aliased") {
		t.Fatalf("merged imdn.Message-ID values=%+v headers=%+v", values, parsed.Headers)
	}
	if got := parsed.Headers["x.Message-ID"]; len(got) != 0 {
		t.Fatalf("alias key still present: %+v", got)
	}
}

func cpimTestHasValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestBuildIMSCPIMMessageWithHeadersRejectsInvalidHeaders(t *testing.T) {
	_, err := BuildIMSCPIMMessageWithHeaders(nil, map[string][]string{"Content-Type": {"text/plain"}}, []byte("hello"))
	if err != nil {
		t.Fatalf("BuildIMSCPIMMessageWithHeaders(valid) error = %v", err)
	}

	tests := []struct {
		name           string
		messageHeaders map[string][]string
		contentHeaders map[string][]string
		want           string
	}{
		{
			name:           "missing content type",
			contentHeaders: map[string][]string{},
			want:           "content type is empty",
		},
		{
			name:           "bad message header name",
			messageHeaders: map[string][]string{"Bad: Name": {"value"}},
			contentHeaders: map[string][]string{"Content-Type": {"text/plain"}},
			want:           "invalid CPIM header name",
		},
		{
			name:           "bad content header value",
			messageHeaders: map[string][]string{"From": {"<sip:alice@example.com>"}},
			contentHeaders: map[string][]string{"Content-Type": {"text/plain\r\nInjected: yes"}},
			want:           "line break",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildIMSCPIMMessageWithHeaders(tt.messageHeaders, tt.contentHeaders, []byte("hello"))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("BuildIMSCPIMMessageWithHeaders() err=%v, want %q", err, tt.want)
			}
		})
	}
}
