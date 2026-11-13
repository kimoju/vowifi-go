package ikev2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kimoju/vowifi-go/engine/sim"
	"github.com/kimoju/vowifi-go/engine/swu/eapaka"
)

func TestAuditCRIT01_RejectsPrematureChildSAAtAllAuthStages(t *testing.T) {
	init := fakeInitResult(t)
	identity := "0310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := simAKAResult()
	eapKeys, err := eapaka.DeriveKeys(identity, aka)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	prematurePayloads, err := authSuccessChildPayloads(t, 9, []byte{0xde, 0xad, 0xbe, 0xef})
	if err != nil {
		t.Fatalf("authSuccessChildPayloads() error = %v", err)
	}

	t.Run("stage1_initial_response", func(t *testing.T) {
		tr := InitTransportFunc(func(ctx context.Context, req []byte) ([]byte, error) {
			msg, _, uErr := UnprotectMessage(req, init.Keys, true)
			if uErr != nil {
				return nil, uErr
			}
			_, raw, pErr := ProtectMessage(authHeader(init, msg.Header.MessageID, false), init.Keys, false, prematurePayloads[1:], nil)
			return raw, pErr
		})
		_, err := RunIKE_AUTH_Full(context.Background(), FullAuthConfig{
			Transport:   tr,
			Init:        init,
			SIM:         akaProviderStub{result: aka},
			InitiatorID: Identity{Type: IDRFC822Addr, Data: []byte(identity)},
			EAPIdentity: identity,
		})
		if !errors.Is(err, ErrInvalidAuthResponse) {
			t.Fatalf("stage1 err=%v, want ErrInvalidAuthResponse", err)
		}
	})

	t.Run("stage2_eap_success_bundled_child_sa", func(t *testing.T) {
		step := 0
		tr := InitTransportFunc(func(ctx context.Context, req []byte) ([]byte, error) {
			msg, _, uErr := UnprotectMessage(req, init.Keys, true)
			if uErr != nil {
				return nil, uErr
			}
			step++
			switch step {
			case 1:
				ch := signedAKAChallenge(t, identity, aka)
				rawCh, _ := ch.MarshalBinary()
				_, raw, pErr := ProtectMessage(authHeader(init, msg.Header.MessageID, false), init.Keys, false, []Payload{EAPPayload(rawCh)}, nil)
				return raw, pErr
			case 2:
				_, raw, pErr := ProtectMessage(authHeader(init, msg.Header.MessageID, false), init.Keys, false, prematurePayloads, nil)
				return raw, pErr
			default:
				return nil, errors.New("unexpected exchange")
			}
		})
		_, err := RunIKE_AUTH_Full(context.Background(), FullAuthConfig{
			Transport:   tr,
			Init:        init,
			SIM:         akaProviderStub{result: aka},
			InitiatorID: Identity{Type: IDRFC822Addr, Data: []byte(identity)},
			EAPIdentity: identity,
		})
		if !errors.Is(err, ErrInvalidAuthResponse) {
			t.Fatalf("stage2 err=%v, want ErrInvalidAuthResponse", err)
		}
	})

	t.Run("stage3_immediate_eap_success_with_cached_keys", func(t *testing.T) {
		tr := InitTransportFunc(func(ctx context.Context, req []byte) ([]byte, error) {
			msg, _, uErr := UnprotectMessage(req, init.Keys, true)
			if uErr != nil {
				return nil, uErr
			}
			success, _ := (eapaka.Packet{Code: eapaka.CodeSuccess, Identifier: 1}).MarshalBinary()
			_, raw, pErr := ProtectMessage(authHeader(init, msg.Header.MessageID, false), init.Keys, false, []Payload{EAPPayload(success)}, nil)
			return raw, pErr
		})
		_, err := RunIKE_AUTH_Full(context.Background(), FullAuthConfig{
			Transport:   tr,
			Init:        init,
			EAPKeys:     eapKeys,
			InitiatorID: Identity{Type: IDRFC822Addr, Data: []byte(identity)},
			EAPIdentity: identity,
		})
		if !errors.Is(err, ErrInvalidAuthResponse) {
			t.Fatalf("stage3 err=%v, want ErrInvalidAuthResponse", err)
		}
	})
}

func TestAuditCRIT02_ResponderCertAuthEAPOnlyAndIDrValidation(t *testing.T) {
	init := fakeInitResult(t)
	init.RequestBytes = []byte("fake-ike-sa-init-req")
	init.ResponseBytes = []byte("fake-ike-sa-init-resp")

	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(CA) error = %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "3GPP Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("CreateCertificate(CA) error = %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate(CA) error = %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	epdgFQDN := "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org"
	responderID := Identity{Type: IDFQDN, Data: []byte(epdgFQDN)}

	t.Run("ecdsa_p256_and_rfc7427_rsa_ed25519_verification", func(t *testing.T) {
		ecLeafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ecLeafDER := issueTestLeafCert(t, caCert, caPriv, &ecLeafPriv.PublicKey, epdgFQDN)
		ecLeafCert, _ := x509.ParseCertificate(ecLeafDER)

		auth9, err := BuildPublicKeyAUTH(init, init.Keys, responderID, ecLeafPriv, AuthMethodECDSASHA256P256, crypto.SHA256, false, rand.Reader)
		if err != nil {
			t.Fatalf("BuildPublicKeyAUTH(ECDSA-9) error = %v", err)
		}
		if err := verifyResponderPublicKeyAUTH(init, init.Keys, responderID, auth9, []*x509.Certificate{ecLeafCert}, roots); err != nil {
			t.Fatalf("verifyResponderPublicKeyAUTH(ECDSA-9) error = %v", err)
		}

		rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
		rsaLeafDER := issueTestLeafCert(t, caCert, caPriv, &rsaPriv.PublicKey, epdgFQDN)
		rsaLeafCert, _ := x509.ParseCertificate(rsaLeafDER)
		auth14RSA, err := BuildPublicKeyAUTH(init, init.Keys, responderID, rsaPriv, AuthMethodDigitalSignature, crypto.SHA256, false, rand.Reader)
		if err != nil {
			t.Fatalf("BuildPublicKeyAUTH(RFC7427-RSA) error = %v", err)
		}
		if err := verifyResponderPublicKeyAUTH(init, init.Keys, responderID, auth14RSA, []*x509.Certificate{rsaLeafCert}, roots); err != nil {
			t.Fatalf("verifyResponderPublicKeyAUTH(RFC7427-RSA) error = %v", err)
		}

		edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
		edLeafDER := issueTestLeafCert(t, caCert, caPriv, edPub, epdgFQDN)
		edLeafCert, _ := x509.ParseCertificate(edLeafDER)
		auth14Ed, err := BuildPublicKeyAUTH(init, init.Keys, responderID, edPriv, AuthMethodDigitalSignature, 0, false, rand.Reader)
		if err != nil {
			t.Fatalf("BuildPublicKeyAUTH(RFC7427-Ed25519) error = %v", err)
		}
		if err := verifyResponderPublicKeyAUTH(init, init.Keys, responderID, auth14Ed, []*x509.Certificate{edLeafCert}, roots); err != nil {
			t.Fatalf("verifyResponderPublicKeyAUTH(RFC7427-Ed25519) error = %v", err)
		}

		// Tamper signature byte -> must fail.
		tampered := auth14RSA
		tampered.Body = append([]byte(nil), auth14RSA.Body...)
		tampered.Body[len(tampered.Body)-1] ^= 0xff
		if err := verifyResponderPublicKeyAUTH(init, init.Keys, responderID, tampered, []*x509.Certificate{rsaLeafCert}, roots); err == nil {
			t.Fatal("expected tampered responder AUTH signature to fail")
		}
	})

	t.Run("eap_only_forbids_legacy_aka_and_emits_notify", func(t *testing.T) {
		payloads, err := BuildIKEAuthInitialPayloads(AuthConfig{
			InitiatorID:           Identity{Type: IDRFC822Addr, Data: []byte("6310260123456789@nai.epc.mnc260.mcc310.3gppnetwork.org")},
			EAPOnlyAuthentication: true,
			SendCertReq:           true,
		})
		if err != nil {
			t.Fatalf("BuildIKEAuthInitialPayloads() error = %v", err)
		}
		var sawCertReq, sawEAPOnly bool
		for _, p := range payloads {
			if p.Type == PayloadCERTREQ {
				sawCertReq = true
			}
			if p.Type == PayloadNotify {
				n, nErr := ParseNotify(p.Body)
				if nErr == nil && n.NotifyType == NotifyEAPOnlyAuthentication {
					sawEAPOnly = true
				}
			}
		}
		if !sawCertReq || !sawEAPOnly {
			t.Fatalf("expected CERTREQ (%t) and EAP_ONLY_AUTHENTICATION (%t)", sawCertReq, sawEAPOnly)
		}

		tr := InitTransportFunc(func(ctx context.Context, req []byte) ([]byte, error) {
			msg, _, uErr := UnprotectMessage(req, init.Keys, true)
			if uErr != nil {
				return nil, uErr
			}
			akaReq, _ := (eapaka.Packet{
				Code:       eapaka.CodeRequest,
				Identifier: 1,
				Type:       eapaka.TypeAKA,
				Subtype:    eapaka.SubtypeIdentity,
			}).MarshalBinary()
			_, raw, pErr := ProtectMessage(authHeader(init, msg.Header.MessageID, false), init.Keys, false, []Payload{EAPPayload(akaReq)}, nil)
			return raw, pErr
		})
		_, err = RunIKE_AUTH_EAPIdentity(context.Background(), AuthConfig{
			Transport:             tr,
			Init:                  init,
			InitiatorID:           Identity{Type: IDRFC822Addr, Data: []byte("6310260123456789@nai.epc.mnc260.mcc310.3gppnetwork.org")},
			EAPOnlyAuthentication: true,
		})
		if !errors.Is(err, ErrInvalidAuthResponse) {
			t.Fatalf("RunIKE_AUTH_EAPIdentity(EAPOnly + TypeAKA) err=%v, want ErrInvalidAuthResponse", err)
		}
	})

	t.Run("rejects_idr_mismatch_and_idr_mid_exchange_change", func(t *testing.T) {
		identity := "0310260123456789@nai.epc.mnc260.mcc310.3gppnetwork.org"
		aka := simAKAResult()
		eapKeys, _ := eapaka.DeriveKeys(identity, aka)
		step := 0
		tr := InitTransportFunc(func(ctx context.Context, req []byte) ([]byte, error) {
			msg, _, uErr := UnprotectMessage(req, init.Keys, true)
			if uErr != nil {
				return nil, uErr
			}
			step++
			switch step {
			case 1:
				idr1, _ := IdentityPayload(PayloadIDr, responderID)
				ch := signedAKAChallenge(t, identity, aka)
				rawCh, _ := ch.MarshalBinary()
				_, raw, pErr := ProtectMessage(authHeader(init, msg.Header.MessageID, false), init.Keys, false, []Payload{idr1, EAPPayload(rawCh)}, nil)
				return raw, pErr
			case 2:
				success, _ := (eapaka.Packet{Code: eapaka.CodeSuccess, Identifier: 10}).MarshalBinary()
				_, raw, pErr := ProtectMessage(authHeader(init, msg.Header.MessageID, false), init.Keys, false, []Payload{EAPPayload(success)}, nil)
				return raw, pErr
			case 3:
				wrongIDr := Identity{Type: IDFQDN, Data: []byte("attacker.example.org")}
				idr2, _ := IdentityPayload(PayloadIDr, wrongIDr)
				authBytes, _ := eapSharedKeyAUTH(init, init.Keys, responderID, eapKeys.MSK, false)
				authP, _ := AuthenticationPayload(AuthMethodSharedKeyMIC, authBytes)
				childPayloads, _ := authSuccessChildPayloads(t, 10, []byte{1, 2, 3, 4})
				payloads := append([]Payload{idr2, authP}, childPayloads[1:]...)
				_, raw, pErr := ProtectMessage(authHeader(init, msg.Header.MessageID, false), init.Keys, false, payloads, nil)
				return raw, pErr
			default:
				return nil, errors.New("unexpected exchange")
			}
		})
		_, err := RunIKE_AUTH_Full(context.Background(), FullAuthConfig{
			Transport:           tr,
			Init:                init,
			SIM:                 akaProviderStub{result: aka},
			InitiatorID:         Identity{Type: IDRFC822Addr, Data: []byte(identity)},
			ExpectedResponderID: &responderID,
			EAPIdentity:         identity,
		})
		if !errors.Is(err, ErrInvalidAuthResponse) {
			t.Fatalf("changed IDr err=%v, want ErrInvalidAuthResponse", err)
		}
	})
}

type countingSIMProvider struct {
	calls  atomic.Int32
	result sim.AKAResult
}

func (p *countingSIMProvider) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	p.calls.Add(1)
	return p.result, nil
}

func TestAuditCRIT04_HIGH04_IKEAuthRejectsWrongNetworkNameAndBadMACBeforeUSIM(t *testing.T) {
	init := fakeInitResult(t)
	identity := "6310280233641503@nai.epc.mnc280.mcc310.3gppnetwork.org"
	aka := simAKAResult()
	simProv := &countingSIMProvider{result: aka}

	evilChallenge := signedAKAPrimeChallenge(t, identity, "ETHERNET", aka)
	tr := InitTransportFunc(func(ctx context.Context, req []byte) ([]byte, error) {
		msg, inner, err := UnprotectMessage(req, init.Keys, true)
		if err != nil {
			return nil, err
		}
		pkt := parseTestEAP(t, inner[0].Body)
		if pkt.Code != eapaka.CodeResponse || pkt.Subtype != eapaka.SubtypeAuthenticationReject {
			t.Fatalf("expected AKA-Authentication-Reject on network name mismatch per RFC 5448 §3.1, got %+v", pkt)
		}
		fail, _ := (eapaka.Packet{Code: eapaka.CodeFailure, Identifier: pkt.Identifier}).MarshalBinary()
		_, raw, err := ProtectMessage(authHeader(init, msg.Header.MessageID, false), init.Keys, false, []Payload{EAPPayload(fail)}, nil)
		return raw, err
	})

	res, err := RunIKE_AUTH_AKAChallenge(context.Background(), AKAChallengeConfig{
		Transport:           tr,
		Init:                init,
		SIM:                 simProv,
		Identity:            identity,
		ExpectedNetworkName: "WLAN",
		Request:             evilChallenge,
		MessageID:           3,
	})
	if err != nil {
		t.Fatalf("RunIKE_AUTH_AKAChallenge() error = %v", err)
	}
	if !res.AuthFailure {
		t.Fatalf("expected AuthFailure=true, got %+v", res)
	}
	if got := simProv.calls.Load(); got != 0 {
		t.Fatalf("SIM CalculateAKA called %d times on wrong network name, want 0", got)
	}

	// Missing AT_MAC must emit AKA-Client-Error without touching USIM.
	noMACChallenge := eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 12,
		Type:       eapaka.TypeAKAPrime,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			eapaka.RANDAttribute(bytes.Repeat([]byte{0xa1}, 16)),
			eapaka.AUTNAttribute(bytes.Repeat([]byte{0xb2}, 16)),
			eapaka.KDFInputAttribute("WLAN"),
			eapaka.KDFAttribute(eapaka.AKAPrimeKDFDefault),
		},
	}
	trNoMAC := InitTransportFunc(func(ctx context.Context, req []byte) ([]byte, error) {
		msg, inner, err := UnprotectMessage(req, init.Keys, true)
		if err != nil {
			return nil, err
		}
		pkt := parseTestEAP(t, inner[0].Body)
		if pkt.Code != eapaka.CodeResponse || pkt.Subtype != eapaka.SubtypeClientError {
			t.Fatalf("expected AKA-Client-Error on missing AT_MAC, got %+v", pkt)
		}
		fail, _ := (eapaka.Packet{Code: eapaka.CodeFailure, Identifier: pkt.Identifier}).MarshalBinary()
		_, raw, err := ProtectMessage(authHeader(init, msg.Header.MessageID, false), init.Keys, false, []Payload{EAPPayload(fail)}, nil)
		return raw, err
	})
	resNoMAC, err := RunIKE_AUTH_AKAChallenge(context.Background(), AKAChallengeConfig{
		Transport:           trNoMAC,
		Init:                init,
		SIM:                 simProv,
		Identity:            identity,
		ExpectedNetworkName: "WLAN",
		Request:             noMACChallenge,
		MessageID:           4,
	})
	if err != nil || !resNoMAC.EAPClientError || simProv.calls.Load() != 0 {
		t.Fatalf("no-MAC challenge err=%v res=%+v simCalls=%d", err, resNoMAC, simProv.calls.Load())
	}
}

func TestAuditHIGH01_RFC7383SKFFragmentationAndPreAuthMACCheck(t *testing.T) {
	init := fakeInitResult(t)
	init.FragmentationSupported = true
	largeCert := bytes.Repeat([]byte{0x5a}, 2400)
	certPayload, err := CertificatePayload(CertEncodingX509Sig, largeCert)
	if err != nil {
		t.Fatalf("CertificatePayload() error = %v", err)
	}
	notifyPayload := FragmentationSupportedNotify()
	inner := []Payload{certPayload, notifyPayload}

	hdr := authHeader(init, 1, true)
	msgs, raws, err := ProtectFragmentedMessages(hdr, init.Keys, true, inner, 576)
	if err != nil {
		t.Fatalf("ProtectFragmentedMessages() error = %v", err)
	}
	if len(raws) < 5 {
		t.Fatalf("expected >= 5 fragments, got %d", len(raws))
	}
	for i, raw := range raws {
		if len(raw) > 576 {
			t.Fatalf("fragment %d size %d exceeds maxPacketSize 576", i, len(raw))
		}
		if msgs[i].Payloads[0].Type != PayloadSKF {
			t.Fatalf("fragment %d outer payload=%d, want SKF", i, msgs[i].Payloads[0].Type)
		}
	}

	var assembler EncryptedFragmentAssembler
	// Inject a forged unauthenticated SKF claiming TotalFragments=60 BEFORE legitimate fragments.
	forged := append([]byte(nil), raws[0]...)
	binary.BigEndian.PutUint16(forged[HeaderLength+6:HeaderLength+8], 60)
	if _, _, _, err := assembler.AddProtectedFragment(forged, init.Keys, true); err == nil {
		t.Fatal("expected forged SKF fragment with invalid MAC to be rejected")
	}
	if assembler.total != 0 || len(assembler.parts) != 0 {
		t.Fatalf("forged SKF mutated reassembly state: total=%d parts=%d", assembler.total, len(assembler.parts))
	}

	var reassembled []Payload
	for i, raw := range raws {
		_, gotInner, complete, err := assembler.AddProtectedFragment(raw, init.Keys, true)
		if err != nil {
			t.Fatalf("AddProtectedFragment(%d) error = %v", i, err)
		}
		if i < len(raws)-1 && complete {
			t.Fatalf("premature completion at fragment %d", i)
		}
		if i == len(raws)-1 {
			if !complete {
				t.Fatal("expected completion on final fragment")
			}
			reassembled = gotInner
		}
	}
	if len(reassembled) != 2 || reassembled[0].Type != PayloadCERT || !bytes.Equal(reassembled[0].Body[1:], largeCert) {
		t.Fatalf("reassembled payloads mismatch: count=%d", len(reassembled))
	}
}

func TestAuditHIGH02_ConfigurationRBitMaskAnd3GPPPCSCF(t *testing.T) {
	// Attribute type 8 with reserved R-bit (0x8008) and 17-byte IPv6 prefix value.
	raw := []byte{
		CFGReply, 0, 0, 0,
		0x80, 0x08, 0x00, 17,
	}
	raw = append(raw, net.ParseIP("2001:db8::1").To16()...)
	raw = append(raw, 64)
	cfg, err := ParseConfiguration(raw)
	if err != nil {
		t.Fatalf("ParseConfiguration(R-bit) error = %v", err)
	}
	if len(cfg.Attributes) != 1 || cfg.Attributes[0].Type != ConfigInternalIPv6Address || len(cfg.Attributes[0].Value) != 17 {
		t.Fatalf("parsed=%+v", cfg)
	}
	if _, err := (Configuration{Type: CFGRequest, Attributes: []ConfigurationAttribute{{Type: 0x8001}}}).MarshalBinary(); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("MarshalBinary(0x8001) err=%v, want ErrInvalidConfiguration", err)
	}
}

func TestAuditHIGH03_PermanentNAIPrefixAdaptedForEAPType(t *testing.T) {
	if got := adaptPermanentNAIForEAPType("0310260123456789@nai.epc.mnc260.mcc310.3gppnetwork.org", eapaka.TypeAKAPrime); got != "6310260123456789@nai.epc.mnc260.mcc310.3gppnetwork.org" {
		t.Fatalf("TypeAKAPrime NAI=%q", got)
	}
	if got := adaptPermanentNAIForEAPType("6310260123456789@nai.epc.mnc260.mcc310.3gppnetwork.org", eapaka.TypeAKA); got != "0310260123456789@nai.epc.mnc260.mcc310.3gppnetwork.org" {
		t.Fatalf("TypeAKA NAI=%q", got)
	}
	// Unprefixed 15-digit MCC=001 test IMSI must not be altered.
	if got := adaptPermanentNAIForEAPType("001010123456789@wlan.mnc010.mcc001.3gppnetwork.org", eapaka.TypeAKAPrime); got != "001010123456789@wlan.mnc010.mcc001.3gppnetwork.org" {
		t.Fatalf("MCC=001 unprefixed NAI altered to %q", got)
	}
}

func TestAuditHIGH07_ResponderCreateChildSAAndIKERekeyAndCollision(t *testing.T) {
	init := fakeInitResult(t)
	oldChild := ChildSAResult{
		SelectedSA: DefaultESPProposal([]byte{0xde, 0xad, 0xbe, 0xef}),
		LocalSPI:   []byte{0x11, 0x22, 0x33, 0x44},
		RemoteSPI:  []byte{0xde, 0xad, 0xbe, 0xef},
		TSi:        SWuAnyTrafficSelectors(),
		TSr:        SWuAnyTrafficSelectors(),
	}

	t.Run("peer_initiated_child_sa_rekey_key_direction", func(t *testing.T) {
		peerNewSPI := []byte{0xaa, 0xbb, 0xcc, 0xdd}
		peerNonce := bytes.Repeat([]byte{0x21}, 32)
		rekeyNotify, _ := NotifyPayload(Notify{
			ProtocolID: ProtocolESP,
			NotifyType: NotifyRekeySA,
			SPI:        oldChild.RemoteSPI,
		})
		saP, _ := SecurityAssociationPayload(DefaultESPProposal(peerNewSPI))
		tsiP, _ := TrafficSelectorsPayload(PayloadTSi, SWuAnyTrafficSelectors())
		tsrP, _ := TrafficSelectorsPayload(PayloadTSr, SWuAnyTrafficSelectors())
		peerReqHdr := Header{
			InitiatorSPI: init.InitiatorSPI,
			ResponderSPI: init.ResponderSPI,
			ExchangeType: ExchangeCREATE_CHILD_SA,
			Flags:        0,
			MessageID:    0,
		}
		_, rawReq, err := ProtectMessage(peerReqHdr, init.Keys, false, []Payload{rekeyNotify, saP, NoncePayload(peerNonce), tsiP, tsrP}, nil)
		if err != nil {
			t.Fatalf("ProtectMessage(peer req) error = %v", err)
		}

		// RekeyInFlight -> TEMPORARY_FAILURE
		busyRes, err := HandleResponderCreateChildSA(ResponderCreateChildConfig{
			RawRequest:     rawReq,
			Init:           init,
			ActiveChildren: []ChildSAResult{oldChild},
			RekeyInFlight:  true,
		})
		if err != nil {
			t.Fatalf("HandleResponderCreateChildSA(busy) error = %v", err)
		}
		if busyRes.RejectedNotify == nil || busyRes.RejectedNotify.NotifyType != NotifyTemporaryFailure {
			t.Fatalf("expected TEMPORARY_FAILURE, got %+v", busyRes.RejectedNotify)
		}

		// Normal peer-initiated rekey
		ourNewSPI := []byte{0x55, 0x66, 0x77, 0x88}
		ourNonce := bytes.Repeat([]byte{0x34}, 32)
		res, err := HandleResponderCreateChildSA(ResponderCreateChildConfig{
			RawRequest:     rawReq,
			Init:           init,
			ActiveChildren: []ChildSAResult{oldChild},
			LocalChildSPI:  ourNewSPI,
			ResponseNonce:  ourNonce,
		})
		if err != nil {
			t.Fatalf("HandleResponderCreateChildSA() error = %v", err)
		}
		if !res.IsChildRekey || res.ChildSA == nil || res.RejectedNotify != nil {
			t.Fatalf("unexpected responder result: %+v", res)
		}
		// Peer (exchange initiator)Outbound == Our Inbound!
		peerDerived, err := DeriveChildSAKeysForRole(init.Keys.Profile.PRF, init.Keys.SKD, nil, peerNonce, ourNonce, res.ChildSA.SelectedSA, true)
		if err != nil {
			t.Fatalf("DeriveChildSAKeysForRole() error = %v", err)
		}
		if !bytes.Equal(res.ChildSA.Keys.Inbound.EncryptionKey, peerDerived.Outbound.EncryptionKey) ||
			!bytes.Equal(res.ChildSA.Keys.Outbound.EncryptionKey, peerDerived.Inbound.EncryptionKey) {
			t.Fatalf("responder key direction mismatch: ours=%+v peer=%+v", res.ChildSA.Keys, peerDerived)
		}
	})

	t.Run("initiator_and_responder_ike_sa_rekey", func(t *testing.T) {
		peerSideInit := init
		peerSideInit.LocalIsResponder = true
		var serverNewInit *InitResult
		tr := InitTransportFunc(func(ctx context.Context, req []byte) ([]byte, error) {
			resp, err := HandleResponderCreateChildSA(ResponderCreateChildConfig{
				RawRequest:  req,
				Init:        peerSideInit,
				LocalIKESPI: 0xfeedfacecafebeef,
			})
			if err != nil {
				return nil, err
			}
			if resp.RejectedNotify != nil || !resp.IsIKERekey || resp.NewInit == nil {
				t.Fatalf("responder IKE rekey failed: %+v", resp)
			}
			serverNewInit = resp.NewInit
			return resp.ResponseBytes, nil
		})
		rekeyRes, err := RunRekeyIKESA(context.Background(), IKESARekeyConfig{
			Transport:    tr,
			Init:         init,
			MessageID:    4,
			InitiatorSPI: 0x0a0b0c0d0e0f1011,
		})
		if err != nil {
			t.Fatalf("RunRekeyIKESA() error = %v", err)
		}
		if serverNewInit == nil {
			t.Fatal("serverNewInit is nil")
		}
		if !bytes.Equal(rekeyRes.NewInit.Keys.SKD, serverNewInit.Keys.SKD) ||
			!bytes.Equal(rekeyRes.NewInit.Keys.SKEi, serverNewInit.Keys.SKEi) ||
			!bytes.Equal(rekeyRes.NewInit.Keys.SKEr, serverNewInit.Keys.SKEr) {
			t.Fatal("initiator and responder IKE rekey derived different keys")
		}
	})

	t.Run("collision_nonce_comparison", func(t *testing.T) {
		if CompareRekeyCollisionNonces([]byte{0x50}, []byte{0x60}, []byte{0x10}, []byte{0x90}) <= 0 {
			t.Fatal("expected min(0x50,0x60)=0x50 > min(0x10,0x90)=0x10 so local wins")
		}
		if CompareRekeyCollisionNonces([]byte{0x05}, []byte{0x80}, []byte{0x20}, []byte{0x30}) >= 0 {
			t.Fatal("expected min(0x05,0x80)=0x05 < min(0x20,0x30)=0x20 so peer wins")
		}
	})
}

func TestAuditHIGH08_AESGCMMonotonicCounterIV(t *testing.T) {
	sa := SecurityAssociation{Proposals: []Proposal{{
		Number:     1,
		ProtocolID: ProtocolIKE,
		Transforms: []Transform{
			{Type: TransformENCR, ID: ENCR_AES_GCM_16, Attributes: []TransformAttribute{KeyLengthAttribute(128)}},
			{Type: TransformPRF, ID: PRF_HMAC_SHA2_256},
			{Type: TransformDHRGroup, ID: DHGroupCurve25519},
		},
	}}}
	profile, err := KeyMaterialProfileFromSA(sa)
	if err != nil {
		t.Fatalf("KeyMaterialProfileFromSA() error = %v", err)
	}
	keys, err := SplitIKEKeys(profile, incrementalBytes(profile.RequiredLength()))
	if err != nil {
		t.Fatalf("SplitIKEKeys() error = %v", err)
	}
	hdr := Header{InitiatorSPI: 1, ResponderSPI: 2, ExchangeType: ExchangeINFORMATIONAL, Flags: FlagInitiator}
	msg1, _, err := ProtectMessage(hdr, keys, true, nil, nil)
	if err != nil {
		t.Fatalf("ProtectMessage(1) error = %v", err)
	}
	msg2, _, err := ProtectMessage(hdr, keys, true, nil, nil)
	if err != nil {
		t.Fatalf("ProtectMessage(2) error = %v", err)
	}
	iv1 := binary.BigEndian.Uint64(msg1.Payloads[0].Body[:8])
	iv2 := binary.BigEndian.Uint64(msg2.Payloads[0].Body[:8])
	if iv1 == iv2 || (iv1^iv2) != (uint64(1)^uint64(2)) {
		t.Fatalf("expected deterministic counter-XOR-salt progression, got iv1=%#x iv2=%#x", iv1, iv2)
	}
}

func TestAuditMED01_MED03_MED04(t *testing.T) {
	if _, err := PRF(0, []byte("k"), []byte("d")); !errors.Is(err, ErrUnsupportedPRF) {
		t.Fatalf("PRF(0) err=%v, want ErrUnsupportedPRF", err)
	}
	if _, err := PRFPlus(0, []byte("k"), []byte("s"), 32); !errors.Is(err, ErrUnsupportedPRF) {
		t.Fatalf("PRFPlus(0) err=%v, want ErrUnsupportedPRF", err)
	}

	// MED-01: AES-256-CBC + SHA-512 requires 328 bytes (> DefaultIKEKeyMaterialLength 192).
	highSA := SecurityAssociation{Proposals: []Proposal{{
		Number:     1,
		ProtocolID: ProtocolIKE,
		Transforms: []Transform{
			{Type: TransformENCR, ID: ENCR_AES_CBC, Attributes: []TransformAttribute{KeyLengthAttribute(256)}},
			{Type: TransformPRF, ID: PRF_HMAC_SHA2_512},
			{Type: TransformINTEG, ID: INTEG_HMAC_SHA2_512_256},
			{Type: TransformDHRGroup, ID: DHGroupCurve25519},
		},
	}}}
	tr := InitTransportFunc(func(ctx context.Context, reqRaw []byte) ([]byte, error) {
		req, err := ParseMessage(reqRaw)
		if err != nil {
			return nil, err
		}
		dhR, err := newDHKeyExchange(DHGroupCurve25519, nil, rand.Reader)
		if err != nil {
			return nil, err
		}
		saP, _ := SecurityAssociationPayload(highSA)
		resp := Message{
			Header: Header{
				InitiatorSPI: req.Header.InitiatorSPI,
				ResponderSPI: 0x1122334455667788,
				ExchangeType: ExchangeIKE_SA_INIT,
				Flags:        FlagResponse,
			},
			Payloads: []Payload{saP, KeyExchangePayload(DHGroupCurve25519, dhR.public), NoncePayload(bytes.Repeat([]byte{0x42}, 32))},
		}
		return resp.MarshalBinary()
	})
	initRes, err := RunIKE_SA_INIT(context.Background(), InitConfig{Transport: tr, SA: highSA})
	if err != nil {
		t.Fatalf("RunIKE_SA_INIT(AES-256+SHA-512) error = %v", err)
	}
	if len(initRes.Keys.SKEi) != 32 || len(initRes.Keys.SKAi) != 64 || len(initRes.Keys.SKD) != 64 {
		t.Fatalf("unexpected derived key lengths: %+v", initRes.Keys)
	}

	// MED-03: BACKOFF_TIMER (41041), TEMPORARY_FAILURE (43), CHILD_SA_NOT_FOUND (44), COOKIE ResponderSPI != 0.
	// GPRS Timer 3: unit 101 (1 minute, 0xa0), value 5 -> 5 minutes; prefixed with length=1 per TS 24.302.
	backoffNotify := Notify{NotifyType: Notify3GPPBackoffTimer, NotificationData: []byte{0x01, 0xa5}}
	action := ClassifyNotifyAction(backoffNotify)
	if action.Kind != NotifyActionWaitAndRetry || action.BackoffDuration != 5*time.Minute {
		t.Fatalf("BACKOFF_TIMER action=%+v", action)
	}
	if ClassifyNotifyAction(Notify{NotifyType: NotifyTemporaryFailure}).Kind != NotifyActionWaitAndRetry {
		t.Fatal("expected NotifyTemporaryFailure -> NotifyActionWaitAndRetry")
	}
	if ClassifyNotifyAction(Notify{NotifyType: NotifyChildSANotFound, ProtocolID: ProtocolESP, SPI: []byte{1, 2, 3, 4}}).Kind != NotifyActionRecreateChildSA {
		t.Fatal("expected NotifyChildSANotFound -> NotifyActionRecreateChildSA")
	}
	cookieP, _ := CookieNotify([]byte("cookie"))
	if _, ok, err := initResponseCookie(Message{
		Header:   Header{InitiatorSPI: 1, ResponderSPI: 99, ExchangeType: ExchangeIKE_SA_INIT, Flags: FlagResponse},
		Payloads: []Payload{cookieP},
	}, 1); err != nil || ok {
		t.Fatalf("expected non-zero ResponderSPI COOKIE to be ignored, ok=%t err=%v", ok, err)
	}

	// MED-04: Duplicate TransformENCR, missing AttributeKeyLength, and dual-stack CREATE_CHILD_SA default TS.
	offered := DefaultESPProposal([]byte{1, 2, 3, 4})
	dup := DefaultESPProposal([]byte{5, 6, 7, 8})
	dup.Proposals[0].Transforms = append(dup.Proposals[0].Transforms, Transform{
		Type:       TransformENCR,
		ID:         ENCR_AES_CBC,
		Attributes: []TransformAttribute{KeyLengthAttribute(128)},
	})
	if err := ValidateSelectedSA(offered, dup); err == nil {
		t.Fatal("expected duplicate TransformENCR to be rejected")
	}
	noKeyLen := SecurityAssociation{Proposals: []Proposal{{
		Number:     1,
		ProtocolID: ProtocolIKE,
		Transforms: []Transform{
			{Type: TransformENCR, ID: ENCR_AES_CBC},
			{Type: TransformPRF, ID: PRF_HMAC_SHA2_256},
			{Type: TransformINTEG, ID: INTEG_HMAC_SHA2_256_128},
			{Type: TransformDHRGroup, ID: DHGroupCurve25519},
		},
	}}}
	if _, err := KeyMaterialProfileFromSA(noKeyLen); err == nil {
		t.Fatal("expected AES-CBC without explicit KEY_LENGTH to be rejected")
	}
	ccPayloads, _, _, err := BuildCreateChildSAPayloads(CreateChildSAConfig{
		Init:     initRes,
		ChildSPI: []byte{1, 2, 3, 4},
		Nonce:    bytes.Repeat([]byte{0x11}, 32),
	})
	if err != nil {
		t.Fatalf("BuildCreateChildSAPayloads() error = %v", err)
	}
	for _, p := range ccPayloads {
		if p.Type == PayloadTSi || p.Type == PayloadTSr {
			ts, err := ParseTrafficSelectors(p.Body)
			if err != nil || len(ts.Selectors) != 2 {
				t.Fatalf("expected dual-stack IPv4+IPv6 default selectors, got %+v err=%v", ts, err)
			}
		}
	}
}

func issueTestLeafCert(t *testing.T, caCert *x509.Certificate, caSigner crypto.Signer, pub crypto.PublicKey, dnsName string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caSigner)
	if err != nil {
		t.Fatalf("CreateCertificate(leaf) error = %v", err)
	}
	return der
}
