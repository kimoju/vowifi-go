package identity

import (
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/boa-z/vowifi-go/runtimehost/simtransport"
)

type isimTransportFake struct {
	aid       string
	closed    []int
	calls     []string
	responses []string
}

func (f *isimTransportFake) ResolveLogicalChannelAID(app string, fallbackAID string) (string, string, error) {
	return "A0000000871004FFFFFFFF8903020000", "test_card_status", nil
}

func (f *isimTransportFake) OpenLogicalChannel(aid string) (int, error) {
	f.aid = aid
	return 7, nil
}

func (f *isimTransportFake) CloseLogicalChannel(channel int) error {
	f.closed = append(f.closed, channel)
	return nil
}

func (f *isimTransportFake) TransmitAPDU(channel int, hexAPDU string) (string, error) {
	f.calls = append(f.calls, hexAPDU)
	if len(f.responses) == 0 {
		return "6A82", nil
	}
	resp := f.responses[0]
	f.responses = f.responses[1:]
	return resp, nil
}

func TestReadISIMIdentityReadsIMPIIMPUAndDomain(t *testing.T) {
	ft := &isimTransportFake{responses: []string{
		"9000",
		hexResponse(isimTLVString("310280233621715@private.att.net")),
		"9000",
		hexResponse(isimLengthString("one.att.net")),
		"6207820521000028029000",
		hexResponse(padRecord(isimTLVString("sip:310280233621715@one.att.net"), 40)),
		hexResponse(padRecord(isimLengthString("tel:+13105551212"), 40)),
	}}

	id, err := ReadISIMIdentity(ft)
	if err != nil {
		t.Fatalf("ReadISIMIdentity() error = %v", err)
	}
	if ft.aid != "A0000000871004FFFFFFFF8903020000" {
		t.Fatalf("opened AID = %q", ft.aid)
	}
	if !reflect.DeepEqual(ft.closed, []int{7}) {
		t.Fatalf("closed = %#v, want channel 7", ft.closed)
	}
	if id.IMPI != "310280233621715@private.att.net" || id.Domain != "one.att.net" {
		t.Fatalf("identity = %+v", id)
	}
	wantIMPU := []string{"sip:310280233621715@one.att.net", "tel:+13105551212"}
	if !reflect.DeepEqual(id.IMPU, wantIMPU) {
		t.Fatalf("IMPU = %#v, want %#v", id.IMPU, wantIMPU)
	}
	wantCalls := []string{
		"00A40004026F02", "00B0000000",
		"00A40004026F03", "00B0000000",
		"00A40004026F04", "00B2010428", "00B2020428",
	}
	if !reflect.DeepEqual(ft.calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", ft.calls, wantCalls)
	}
}

func TestReadISIMIdentityReturnsPartialIdentityForStrictPrepare(t *testing.T) {
	ft := &isimTransportFake{responses: []string{
		"9000",
		hexResponse(isimTLVString("310280233621715@private.att.net")),
		"6A82",
		"6A82",
	}}
	id, err := ReadISIMIdentity(ft)
	if err != nil {
		t.Fatalf("ReadISIMIdentity() error = %v", err)
	}
	if id.IMPI == "" || id.Domain != "" || len(id.IMPU) != 0 {
		t.Fatalf("identity = %+v, want partial IMPI only", id)
	}

	_, err = PrepareStart(PrepareStartInput{
		Profile: Profile{IMSI: "310280233621715"},
		Access:  partialAccess{id: id},
	})
	if err == nil || !strings.Contains(err.Error(), "ISIM 身份不完整") {
		t.Fatalf("PrepareStart() err = %v, want incomplete ISIM error", err)
	}
}

func TestPrepareStartPrefersSIPIMPUOverTEL(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		Profile: Profile{IMSI: "001010123456789"},
		Access: partialAccess{id: Identity{
			IMPI:   "001010123456789@private.example.test",
			IMPU:   []string{"tel:+15550101000", "sip:001010123456789@ims.example.test"},
			Domain: "ims.example.test",
		}},
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if got := prepared.IMSIdentity.IMPU; got != "sip:001010123456789@ims.example.test" {
		t.Fatalf("IMPU = %q, want SIP identity", got)
	}
}

func TestPrepareStartPrefersDomainMatchedSIPIMPU(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		Profile: Profile{IMSI: "001010123456789"},
		Access: partialAccess{id: Identity{
			IMPI: "001010123456789@private.example.test",
			IMPU: []string{
				"sip:001010123456789@visited.example.test",
				"sip:001010123456789@ims.example.test;user=phone",
			},
			Domain: "ims.example.test",
		}},
	})
	if err != nil {
		t.Fatalf("PrepareStart() error = %v", err)
	}
	if got := prepared.IMSIdentity.IMPU; got != "sip:001010123456789@ims.example.test;user=phone" {
		t.Fatalf("IMPU = %q, want domain-matched SIP identity", got)
	}
}

type partialAccess struct {
	id Identity
}

func (a partialAccess) GetISIMIdentity() (Identity, error) { return a.id, nil }

type crsmIdentityFake struct {
	binaryCalls []string
	recordCalls []string
	binary      []simtransport.CRSMResult
	records     []simtransport.CRSMResult
}

func (f *crsmIdentityFake) ReadCRSMBinary(fileID uint16, offset, length int, pathID string) (simtransport.CRSMResult, error) {
	f.binaryCalls = append(f.binaryCalls, crsmCall(fileID, offset, length, pathID))
	if len(f.binary) == 0 {
		return simtransport.CRSMResult{SW1: 0x6A, SW2: 0x82}, nil
	}
	resp := f.binary[0]
	f.binary = f.binary[1:]
	return resp, nil
}

func (f *crsmIdentityFake) ReadCRSMRecord(fileID uint16, record, length int, pathID string) (simtransport.CRSMResult, error) {
	f.recordCalls = append(f.recordCalls, crsmCall(fileID, record, length, pathID))
	if len(f.records) == 0 {
		return simtransport.CRSMResult{SW1: 0x6A, SW2: 0x82}, nil
	}
	resp := f.records[0]
	f.records = f.records[1:]
	return resp, nil
}

func TestReadISIMIdentityCRSMReadsIMPIIMPUAndDomain(t *testing.T) {
	ft := &crsmIdentityFake{
		binary: []simtransport.CRSMResult{
			crsmOK(isimTLVString("001010123456789@private.example.test")),
			crsmOK(isimLengthString("ims.example.test")),
		},
		records: []simtransport.CRSMResult{
			crsmOK(padRecord(isimTLVString("sip:001010123456789@ims.example.test"), 48)),
			crsmOK(padRecord(isimLengthString("tel:+15550101000"), 48)),
			{SW1: 0x6A, SW2: 0x83},
		},
	}

	id, err := ReadISIMIdentityCRSM(ft, "7fff")
	if err != nil {
		t.Fatalf("ReadISIMIdentityCRSM() error = %v", err)
	}
	if id.IMPI != "001010123456789@private.example.test" || id.Domain != "ims.example.test" {
		t.Fatalf("identity = %+v", id)
	}
	wantIMPU := []string{"sip:001010123456789@ims.example.test", "tel:+15550101000"}
	if !reflect.DeepEqual(id.IMPU, wantIMPU) {
		t.Fatalf("IMPU = %#v, want %#v", id.IMPU, wantIMPU)
	}
	if want := []string{"6F02/0/256/7fff", "6F03/0/256/7fff"}; !reflect.DeepEqual(ft.binaryCalls, want) {
		t.Fatalf("binary calls = %#v, want %#v", ft.binaryCalls, want)
	}
	if want := []string{"6F04/1/256/7fff", "6F04/2/256/7fff", "6F04/3/256/7fff"}; !reflect.DeepEqual(ft.recordCalls, want) {
		t.Fatalf("record calls = %#v, want %#v", ft.recordCalls, want)
	}
}

func TestReadISIMIdentityCRSMReturnsPartialIdentity(t *testing.T) {
	ft := &crsmIdentityFake{
		binary: []simtransport.CRSMResult{
			crsmOK(isimTLVString("001010123456789@private.example.test")),
			{SW1: 0x6A, SW2: 0x82},
		},
		records: []simtransport.CRSMResult{{SW1: 0x6A, SW2: 0x82}},
	}
	id, err := ReadISIMIdentityCRSM(ft, "")
	if err != nil {
		t.Fatalf("ReadISIMIdentityCRSM() error = %v", err)
	}
	if id.IMPI == "" || id.Domain != "" || len(id.IMPU) != 0 {
		t.Fatalf("identity = %+v, want partial IMPI only", id)
	}
}

func TestReadISIMIdentityCRSMReturnsErrorWhenNoEFCanBeRead(t *testing.T) {
	ft := &crsmIdentityFake{}
	_, err := ReadISIMIdentityCRSM(ft, "")
	if err == nil {
		t.Fatal("ReadISIMIdentityCRSM() err=nil, want joined read error")
	}
	if !strings.Contains(err.Error(), "CRSM read EF_IMPI") {
		t.Fatalf("err = %v, want CRSM EF read context", err)
	}
}

func TestReadISIMIdentityReturnsErrorWhenEFDataIsEmpty(t *testing.T) {
	ft := &isimTransportFake{responses: []string{"9000", "9000", "9000", "9000", "9000", "9000"}}
	_, err := ReadISIMIdentity(ft)
	if err == nil || !strings.Contains(err.Error(), "ISIM identity data empty") {
		t.Fatalf("ReadISIMIdentity(empty) err=%v, want empty identity error", err)
	}
	var readErr *ISIMIdentityReadError
	if !errors.As(err, &readErr) || readErr.Class != simtransport.RecoveryClassEmptyEF || !errors.Is(err, ErrISIMIdentityDataEmpty) {
		t.Fatalf("ReadISIMIdentity(empty) readErr=%+v err=%v, want empty EF class", readErr, err)
	}

	crsm := &crsmIdentityFake{
		binary:  []simtransport.CRSMResult{{SW1: 0x90, SW2: 0x00}, {SW1: 0x90, SW2: 0x00}},
		records: []simtransport.CRSMResult{{SW1: 0x90, SW2: 0x00}},
	}
	_, err = ReadISIMIdentityCRSM(crsm, "")
	if err == nil || !strings.Contains(err.Error(), "ISIM identity data empty") {
		t.Fatalf("ReadISIMIdentityCRSM(empty) err=%v, want empty identity error", err)
	}
	readErr = nil
	if !errors.As(err, &readErr) || readErr.Class != simtransport.RecoveryClassEmptyEF || !IsISIMIdentityDataEmpty(err) {
		t.Fatalf("ReadISIMIdentityCRSM(empty) readErr=%+v err=%v, want empty EF class", readErr, err)
	}
}

func TestReadISIMIdentityReturnsErrorWhenNoEFCanBeRead(t *testing.T) {
	ft := &isimTransportFake{responses: []string{"6A82", "6A82", "6A82"}}
	_, err := ReadISIMIdentity(ft)
	if err == nil {
		t.Fatal("ReadISIMIdentity() err=nil, want joined read error")
	}
	if !strings.Contains(err.Error(), "read EF_IMPI") {
		t.Fatalf("err = %v, want EF read context", err)
	}
}

func isimTLVString(s string) []byte {
	return append([]byte{0x80, byte(len(s))}, []byte(s)...)
}

func isimLengthString(s string) []byte {
	return append([]byte{byte(len(s))}, []byte(s)...)
}

func hexResponse(body []byte) string {
	out := append(append([]byte(nil), body...), 0x90, 0x00)
	return strings.ToUpper(hex.EncodeToString(out))
}

func crsmOK(body []byte) simtransport.CRSMResult {
	return simtransport.CRSMResult{Data: strings.ToUpper(hex.EncodeToString(body)), SW1: 0x90, SW2: 0x00}
}

func crsmCall(fileID uint16, p1, length int, pathID string) string {
	return strings.ToUpper(hex.EncodeToString([]byte{byte(fileID >> 8), byte(fileID)})) + "/" +
		strings.Join([]string{
			strconv.Itoa(p1),
			strconv.Itoa(length),
			pathID,
		}, "/")
}

func padRecord(body []byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = 0xFF
	}
	copy(out, body)
	return out
}
