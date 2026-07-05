package messaging

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestBuildSMSSubmitTPDUGSM7(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("+18005551212", SMSPart{PartNo: 2, TotalParts: 2, Text: "hello", Encoding: "gsm7"}, 2)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	got := strings.ToUpper(hex.EncodeToString(tpdu))
	want := "01020B918100551512F2000005E8329BFD06"
	if got != want {
		t.Fatalf("TPDU=%s want %s", got, want)
	}
}

func TestBuildSMSSubmitTPDUUCS2(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("10086", SMSPart{Text: "你", Encoding: "ucs2"}, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	got := strings.ToUpper(hex.EncodeToString(tpdu))
	want := "010105810180F60008024F60"
	if got != want {
		t.Fatalf("TPDU=%s want %s", got, want)
	}
}

func TestBuildAndParseSMSRPData(t *testing.T) {
	tpdu, err := BuildSMSSubmitTPDU("+18005551212", SMSPart{Text: "hello", Encoding: "gsm7"}, 7)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	rpData, err := BuildSMSRPData(7, "", tpdu)
	if err != nil {
		t.Fatalf("BuildSMSRPData() error = %v", err)
	}
	got := strings.ToUpper(hex.EncodeToString(rpData))
	want := "000700001201070B918100551512F2000005E8329BFD06"
	if got != want {
		t.Fatalf("RP-DATA=%s want %s", got, want)
	}
	rpMR, parsedTPDU, err := ParseSMSRPData(rpData)
	if err != nil {
		t.Fatalf("ParseSMSRPData() error = %v", err)
	}
	if rpMR != 7 || string(parsedTPDU) != string(tpdu) {
		t.Fatalf("rpMR=%d tpdu=%x want %d/%x", rpMR, parsedTPDU, 7, tpdu)
	}
}

func TestBuildSMSSubmitTPDUGSM7WithUDH(t *testing.T) {
	part := SMSPart{PartNo: 1, TotalParts: 2, Text: strings.Repeat("a", 153), Encoding: "gsm7", UDH: concatUDH(2, 1)}
	tpdu, err := BuildSMSSubmitTPDU("+18005551212", part, 1)
	if err != nil {
		t.Fatalf("BuildSMSSubmitTPDU() error = %v", err)
	}
	if tpdu[0] != 0x41 {
		t.Fatalf("first octet=0x%02x want UDHI set", tpdu[0])
	}
	if tpdu[12] != 160 {
		t.Fatalf("UDL=%d want 160 septets", tpdu[12])
	}
	if len(tpdu) != 13+140 {
		t.Fatalf("TPDU length=%d want %d", len(tpdu), 153)
	}
}
