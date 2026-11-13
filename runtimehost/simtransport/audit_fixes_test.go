package simtransport

import (
	"sync"
	"testing"
	"time"
)

func TestOpenLogicalChannelParsesCCHOTrailingFieldsAndRejectsZeroOrEcho(t *testing.T) {
	// Modem returning +CCHO: <sessionid>,<sw1>,<sw2> after echoed AT+CCHO="<aid>".
	at := &fakeAT{responses: []string{
		"AT+CCHO=\"A0000000871004\"\r\n+CCHO: 3,144,0\r\nOK\r\n",
	}}
	ch, err := NewAdapter(at).OpenLogicalChannel("A0000000871004")
	if err != nil {
		t.Fatalf("OpenLogicalChannel(trailing status) error = %v", err)
	}
	if ch != 3 {
		t.Fatalf("channel = %d, want 3", ch)
	}

	// Echoed AT+CCHO line without a +CCHO response must NOT parse digits from the AID!
	echoOnly := &fakeAT{responses: []string{
		"AT+CCHO=\"A0000000871004\"\r\nOK\r\n",
	}}
	if got, err := NewAdapter(echoOnly).OpenLogicalChannel("A0000000871004"); err == nil {
		t.Fatalf("OpenLogicalChannel(echo only) = %d, nil; want error", got)
	}

	// Channel <= 0 must be rejected.
	zeroCh := &fakeAT{responses: []string{"+CCHO: 0\r\nOK\r\n"}}
	if got, err := NewAdapter(zeroCh).OpenLogicalChannel("A0000000871004"); err == nil {
		t.Fatalf("OpenLogicalChannel(0) = %d, nil; want error", got)
	}
	if err := NewAdapter(&fakeAT{}).CloseLogicalChannel(0); err == nil {
		t.Fatal("CloseLogicalChannel(0) = nil, want error")
	}
}

type concurrentATMock struct {
	mu     sync.Mutex
	active int
	maxSim int
}

func (m *concurrentATMock) ExecuteATSilent(cmd string, _ time.Duration) (string, error) {
	m.mu.Lock()
	m.active++
	if m.active > m.maxSim {
		m.maxSim = m.active
	}
	m.mu.Unlock()
	time.Sleep(2 * time.Millisecond)
	m.mu.Lock()
	m.active--
	m.mu.Unlock()
	return "+CCHO: 1\r\nOK\r\n", nil
}

func TestAdapterSerializesConcurrentATAndLogicalChannelSessions(t *testing.T) {
	mock := &concurrentATMock{}
	adapter := NewAdapter(mock)

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := adapter.LockLogicalChannelSession()
			defer unlock()
			ch, err := adapter.OpenLogicalChannel("A0000000871004")
			if err != nil {
				t.Errorf("OpenLogicalChannel error = %v", err)
				return
			}
			_ = adapter.CloseLogicalChannel(ch)
		}()
	}
	wg.Wait()
	if mock.maxSim != 1 {
		t.Fatalf("max concurrent AT commands = %d, want 1", mock.maxSim)
	}
}
