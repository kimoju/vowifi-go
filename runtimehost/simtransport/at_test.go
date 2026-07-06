package simtransport

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeAT struct {
	calls     []string
	timeouts  []time.Duration
	responses []string
	err       error
}

func (f *fakeAT) ExecuteATSilent(cmd string, timeout time.Duration) (string, error) {
	f.calls = append(f.calls, cmd)
	f.timeouts = append(f.timeouts, timeout)
	if f.err != nil {
		return "", f.err
	}
	if len(f.responses) == 0 {
		return "OK", nil
	}
	out := f.responses[0]
	f.responses = f.responses[1:]
	return out, nil
}

func TestAdapterCCHOCGLACCHC(t *testing.T) {
	at := &fakeAT{responses: []string{
		"AT+CCHO=\"A0000000871004\"\r\n\r\n+CCHO: 2\r\n\r\nOK\r\n",
		"\r\n+CGLA: 8,\"DEAD9000\"\r\n\r\nOK\r\n",
		"\r\nOK\r\n",
	}}
	adapter := NewAdapter(at)

	channel, err := adapter.OpenLogicalChannel("a0000000871004")
	if err != nil {
		t.Fatalf("OpenLogicalChannel() error = %v", err)
	}
	if channel != 2 {
		t.Fatalf("channel = %d, want 2", channel)
	}
	resp, err := adapter.TransmitAPDU(channel, "00a4040002")
	if err != nil {
		t.Fatalf("TransmitAPDU() error = %v", err)
	}
	if resp != "DEAD9000" {
		t.Fatalf("response = %s, want DEAD9000", resp)
	}
	if err := adapter.CloseLogicalChannel(channel); err != nil {
		t.Fatalf("CloseLogicalChannel() error = %v", err)
	}

	want := []string{
		`AT+CCHO="A0000000871004"`,
		`AT+CGLA=2,10,"00A4040002"`,
		`AT+CCHC=2`,
	}
	if !reflect.DeepEqual(at.calls, want) {
		t.Fatalf("calls = %#v, want %#v", at.calls, want)
	}
	for _, timeout := range at.timeouts {
		if timeout != defaultTimeout {
			t.Fatalf("timeout = %v, want %v", timeout, defaultTimeout)
		}
	}
}

func TestAdapterExecuteATSilentDelegates(t *testing.T) {
	at := &fakeAT{responses: []string{"OK"}}
	adapter := NewAdapter(at)

	out, err := adapter.ExecuteATSilent("AT", 3*time.Second)
	if err != nil {
		t.Fatalf("ExecuteATSilent() error = %v", err)
	}
	if out != "OK" {
		t.Fatalf("out = %q, want OK", out)
	}
	if len(at.calls) != 1 || at.calls[0] != "AT" || at.timeouts[0] != 3*time.Second {
		t.Fatalf("delegated calls=%+v timeouts=%+v", at.calls, at.timeouts)
	}
}

func TestAdapterCSIMOnBasicChannel(t *testing.T) {
	at := &fakeAT{responses: []string{`+CSIM: 4,"9000"`}}
	adapter := &Adapter{Control: at, Timeout: 2 * time.Second}

	resp, err := adapter.TransmitAPDU(0, "00")
	if err != nil {
		t.Fatalf("TransmitAPDU() error = %v", err)
	}
	if resp != "9000" {
		t.Fatalf("response = %s, want 9000", resp)
	}
	want := []string{`AT+CSIM=2,"00"`}
	if !reflect.DeepEqual(at.calls, want) {
		t.Fatalf("calls = %#v, want %#v", at.calls, want)
	}
	if at.timeouts[0] != 2*time.Second {
		t.Fatalf("timeout = %v, want 2s", at.timeouts[0])
	}
}

func TestParseAPDUResultVariants(t *testing.T) {
	tests := []struct {
		name string
		in   string
		body string
		sw   string
	}{
		{name: "cgla quoted", in: "\r\n+CGLA: 12,\"01029000\"\r\nOK\r\n", body: "0102", sw: "9000"},
		{name: "csim quoted", in: "+CSIM: 4,\"6A82\"", body: "", sw: "6A82"},
		{name: "plain hex", in: "DEADBEEF9000", body: "DEADBEEF", sw: "9000"},
		{name: "lowercase quoted", in: "\"beef6283\"", body: "BEEF", sw: "6283"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAPDUResult(tt.in)
			if err != nil {
				t.Fatalf("ParseAPDUResult() error = %v", err)
			}
			if got.Body != tt.body || got.StatusString() != tt.sw {
				t.Fatalf("result = body %s sw %s, want body %s sw %s", got.Body, got.StatusString(), tt.body, tt.sw)
			}
		})
	}
}

func TestParseATErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "error", in: "\r\nERROR\r\n", want: "AT ERROR"},
		{name: "cme", in: "\r\n+CME ERROR: SIM busy\r\n", want: "AT CME ERROR: SIM busy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAPDUResult(tt.in)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidationAndCommandErrors(t *testing.T) {
	if _, err := NewAdapter(&fakeAT{}).TransmitAPDU(1, "ABC"); err == nil {
		t.Fatal("TransmitAPDU(odd hex) err=nil, want error")
	}
	if _, err := NewAdapter(&fakeAT{}).OpenLogicalChannel("not-hex"); err == nil {
		t.Fatal("OpenLogicalChannel(non-hex) err=nil, want error")
	}

	sentinel := errors.New("boom")
	_, err := NewAdapter(&fakeAT{err: sentinel}).TransmitAPDU(1, "00")
	if !errors.Is(err, sentinel) {
		t.Fatalf("TransmitAPDU() err = %v, want sentinel", err)
	}

	_, err = NewAdapter(&fakeAT{responses: []string{"OK"}}).OpenLogicalChannel("A000")
	if err == nil || !strings.Contains(err.Error(), "parse CCHO channel") {
		t.Fatalf("OpenLogicalChannel(no channel) err = %v, want parse error", err)
	}
}
