package e911

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/engine/swu/eapaka"
	"github.com/iniwex5/vowifi-go/runtimehost/carrier"
)

type fakeHTTPClient struct {
	responses []*HTTPResponse
	requests  []*HTTPRequest
}

func (f *fakeHTTPClient) Do(req *HTTPRequest) (*HTTPResponse, error) {
	f.requests = append(f.requests, req)
	if len(f.responses) == 0 {
		return &HTTPResponse{StatusCode: 500, Body: []byte(`{}`)}, nil
	}
	resp := f.responses[0]
	f.responses = f.responses[1:]
	return resp, nil
}

type fakeAKAProvider struct {
	rand []byte
	autn []byte
}

func (f *fakeAKAProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	f.rand = append([]byte(nil), rand16...)
	f.autn = append([]byte(nil), autn16...)
	return e911AKAResult(), nil
}

func TestStartEmergencyAddressUpdateReturnsWebsheetFromEntitlementToken(t *testing.T) {
	client := &fakeHTTPClient{responses: []*HTTPResponse{{
		StatusCode: 200,
		Body:       []byte(`[{"status":1000,"token":"abc123","title":"E911"}]`),
	}}}
	ws, err := StartEmergencyAddressUpdate(context.Background(), Request{
		Carrier: carrier.EffectiveCarrierConfig{
			E911: carrier.E911Config{
				Provider:            "att-ts43",
				Websheet:            "https://example.test/websheet",
				EntitlementEndpoint: "https://example.test/entitlement",
			},
		},
		Identity: Identity{IMSI: "310280233641503", IMEI: "356306952701762", MCC: "310", MNC: "280"},
		Client:   client,
	})
	if err != nil {
		t.Fatalf("StartEmergencyAddressUpdate() error = %v", err)
	}
	if ws.UserData != "abc123" || !strings.Contains(ws.URL, "token=abc123") || ws.Title != "E911" {
		t.Fatalf("websheet=%+v", ws)
	}
	if len(client.requests) != 1 || string(client.requests[0].Body) == "" {
		t.Fatalf("requests=%d body=%q", len(client.requests), client.requests[0].Body)
	}
}

func TestStartEmergencyAddressUpdateHandlesAKAChallenge(t *testing.T) {
	randHex := strings.ToUpper(hex.EncodeToString(bytesFrom(0x10, 16)))
	autnHex := strings.ToUpper(hex.EncodeToString(bytesFrom(0x40, 16)))
	client := &fakeHTTPClient{responses: []*HTTPResponse{
		{StatusCode: 200, Body: []byte(`{"status":6004,"response-id":7,"rand":"` + randHex + `","autn":"` + autnHex + `"}`)},
		{StatusCode: 200, Body: []byte(`{"status":1000,"websheet-url":"https://example.test/address?ok=1"}`)},
	}}
	aka := &fakeAKAProvider{}

	ws, err := StartEmergencyAddressUpdate(context.Background(), Request{
		Carrier: carrier.EffectiveCarrierConfig{
			E911: carrier.E911Config{
				Provider:            "att-ts43",
				Websheet:            "https://example.test/websheet",
				EntitlementEndpoint: "https://example.test/entitlement",
			},
		},
		Identity:    Identity{IMSI: "310280233641503", IMEI: "356306952701762", MCC: "310", MNC: "280"},
		AKAProvider: aka,
		Client:      client,
	})
	if err != nil {
		t.Fatalf("StartEmergencyAddressUpdate() error = %v", err)
	}
	if ws.URL != "https://example.test/address?ok=1" {
		t.Fatalf("URL=%q", ws.URL)
	}
	if len(client.requests) != 2 {
		t.Fatalf("requests=%d, want challenge response", len(client.requests))
	}
	if got := strings.ToUpper(hex.EncodeToString(aka.rand)); got != randHex {
		t.Fatalf("AKA RAND=%s, want %s", got, randHex)
	}
	if got := string(client.requests[1].Body); !strings.Contains(got, "11223344") || !strings.Contains(got, "response-id") {
		t.Fatalf("AKA answer body=%s", got)
	}
}

func TestStartEmergencyAddressUpdateHandlesEAPRelayChallenge(t *testing.T) {
	identity := "310280233641503@private.att.net"
	relayPacket := signedEAPRelayChallenge(t, identity, e911AKAResult())
	client := &fakeHTTPClient{responses: []*HTTPResponse{
		{StatusCode: 200, Body: []byte(`{"status":6004,"response-id":9,"eap-relay-packet":"` + relayPacket + `"}`)},
		{StatusCode: 200, Body: []byte(`{"status":1000,"websheet-url":"https://example.test/address?ok=1"}`)},
	}}
	aka := &fakeAKAProvider{}

	_, err := StartEmergencyAddressUpdate(context.Background(), Request{
		Carrier: carrier.EffectiveCarrierConfig{
			E911: carrier.E911Config{
				Provider:            "att-ts43",
				Websheet:            "https://example.test/websheet",
				EntitlementEndpoint: "https://example.test/entitlement",
			},
		},
		Identity:    Identity{IMSI: "310280233641503", IMEI: "356306952701762", MCC: "310", MNC: "280", SIPUsername: identity},
		AKAProvider: aka,
		Client:      client,
	})
	if err != nil {
		t.Fatalf("StartEmergencyAddressUpdate() error = %v", err)
	}
	if len(client.requests) != 2 {
		t.Fatalf("requests=%d, want relay challenge response", len(client.requests))
	}
	var payload []map[string]any
	if err := json.Unmarshal(client.requests[1].Body, &payload); err != nil {
		t.Fatalf("answer JSON error = %v body=%s", err, client.requests[1].Body)
	}
	relay, _ := payload[0]["eap-relay-packet"].(string)
	raw, err := base64.StdEncoding.DecodeString(relay)
	if err != nil {
		t.Fatalf("relay response base64 error = %v", err)
	}
	packet, err := eapaka.ParsePacket(raw)
	if err != nil {
		t.Fatalf("relay response parse error = %v", err)
	}
	resAttr, ok := eapaka.FindAttribute(packet.Attributes, eapaka.AttributeRES)
	if !ok || packet.Code != eapaka.CodeResponse || packet.Subtype != eapaka.SubtypeChallenge {
		t.Fatalf("relay response packet=%+v", packet)
	}
	res, bits, err := resAttr.RESValue()
	if err != nil {
		t.Fatalf("RESValue() error = %v", err)
	}
	if bits != 32 || strings.ToUpper(hex.EncodeToString(res)) != "11223344" {
		t.Fatalf("RES bits=%d value=%s", bits, strings.ToUpper(hex.EncodeToString(res)))
	}
}

func TestStartEmergencyAddressUpdateReportsIncompleteChallenge(t *testing.T) {
	client := &fakeHTTPClient{responses: []*HTTPResponse{{
		StatusCode: 200,
		Body:       []byte(`[{"status":6004,"response-id":3}]`),
	}}}
	_, err := StartEmergencyAddressUpdate(context.Background(), Request{
		Carrier: carrier.EffectiveCarrierConfig{
			E911: carrier.E911Config{
				Provider:            "att-ts43",
				Websheet:            "https://example.test/websheet",
				EntitlementEndpoint: "https://example.test/entitlement",
			},
		},
		Client: client,
	})
	if !errors.Is(err, ErrChallengeNotImplemented) {
		t.Fatalf("err=%v, want ErrChallengeNotImplemented", err)
	}
}

func TestStartEmergencyAddressUpdateFallsBackToConfiguredWebsheet(t *testing.T) {
	ws, err := StartEmergencyAddressUpdate(context.Background(), Request{
		Carrier: carrier.EffectiveCarrierConfig{
			E911: carrier.E911Config{Provider: "att-ts43", Websheet: "https://example.test/static"},
		},
	})
	if err != nil {
		t.Fatalf("StartEmergencyAddressUpdate() error = %v", err)
	}
	if ws.URL != "https://example.test/static" {
		t.Fatalf("URL=%q", ws.URL)
	}
}

func bytesFrom(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func e911AKAResult() sim.AKAResult {
	return sim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44},
		CK:  bytesFrom(0xA0, 16),
		IK:  bytesFrom(0xB0, 16),
	}
}

func signedEAPRelayChallenge(t *testing.T, identity string, aka sim.AKAResult) string {
	t.Helper()
	keys, err := eapaka.DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	packet := eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 7,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			eapaka.RANDAttribute(bytesFrom(0x10, 16)),
			eapaka.AUTNAttribute(bytesFrom(0x40, 16)),
			eapaka.MACAttribute(nil),
		},
	}
	raw, err := packet.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	mac, err := eapaka.CalculateMAC(keys.KAut, raw, nil)
	if err != nil {
		t.Fatalf("CalculateMAC() error = %v", err)
	}
	packet.Attributes[len(packet.Attributes)-1] = eapaka.MACAttribute(mac)
	raw, err = packet.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
