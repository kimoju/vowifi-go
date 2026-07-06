package voicehost

import (
	"strings"
	"testing"
)

func TestSDPSecurityPlaintextDefaultBehavior(t *testing.T) {
	plain := []byte("v=0\r\n" +
		"o=user 0 0 IN IP4 203.0.113.8\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.8\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0 8 101\r\n" +
		"a=sendrecv\r\n")
	info, security, err := ParseSDPWithSecurity(plain)
	if err != nil {
		t.Fatalf("ParseSDPWithSecurity() error = %v", err)
	}
	if security.RTPProfile != "RTP/AVP" || security.HasSecurityAttributes() {
		t.Fatalf("security=%+v", security)
	}
	if got, want := string(BuildSDPAnswerWithSecurity(info, SDPSecurityInfo{})), string(BuildSDPAnswer(info)); got != want {
		t.Fatalf("BuildSDPAnswerWithSecurity(zero) changed plaintext SDP:\ngot:\n%s\nwant:\n%s", got, want)
	}

	secure := []byte("v=0\r\n" +
		"c=IN IP4 203.0.113.8\r\n" +
		"m=audio 49170 RTP/SAVP 96 110\r\n" +
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:MTIzNDU2Nzg5MDEyMzQ1Ng==\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n")
	secureInfo, err := ParseSDP(secure)
	if err != nil {
		t.Fatalf("ParseSDP(secure) error = %v", err)
	}
	answer := string(BuildSDPAnswer(secureInfo))
	if !strings.Contains(answer, "m=audio 49170 RTP/AVP 96 110\r\n") {
		t.Fatalf("default BuildSDPAnswer did not keep plaintext profile:\n%s", answer)
	}
	for _, unexpected := range []string{"RTP/SAVP", "a=crypto:", "a=fingerprint:", "a=setup:"} {
		if strings.Contains(answer, unexpected) {
			t.Fatalf("default BuildSDPAnswer leaked %q:\n%s", unexpected, answer)
		}
	}
}

func TestParseSDPSecuritySAVPCrypto(t *testing.T) {
	raw := []byte("v=0\r\n" +
		"o=user 0 0 IN IP4 203.0.113.8\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.8\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/SAVP 96 110\r\n" +
		"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:MTIzNDU2Nzg5MDEyMzQ1Ng==|2^20|1:32 UNENCRYPTED_SRTCP\r\n" +
		"a=rtpmap:96 AMR/8000\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n" +
		"a=sendrecv\r\n")
	info, security, err := ParseSDPWithSecurity(raw)
	if err != nil {
		t.Fatalf("ParseSDPWithSecurity() error = %v", err)
	}
	if info.ConnectionIP != "203.0.113.8" || info.MediaPort != 49170 || len(info.Payloads) != 2 || info.Payloads[0] != 96 || info.Payloads[1] != 110 {
		t.Fatalf("info=%+v", info)
	}
	if security.RTPProfile != "RTP/SAVP" || len(security.Crypto) != 1 {
		t.Fatalf("security=%+v", security)
	}
	crypto := security.Crypto[0]
	if crypto.Tag != "1" ||
		crypto.Suite != "AES_CM_128_HMAC_SHA1_80" ||
		crypto.KeyParams != "inline:MTIzNDU2Nzg5MDEyMzQ1Ng==|2^20|1:32" ||
		crypto.SessionParams != "UNENCRYPTED_SRTCP" {
		t.Fatalf("crypto=%+v", crypto)
	}
}

func TestParseAndBuildSDPSecurityFingerprintSetup(t *testing.T) {
	raw := []byte("v=0\r\n" +
		"o=user 0 0 IN IP4 203.0.113.8\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.8\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/SAVPF 111 101\r\n" +
		"a=fingerprint:SHA-256 AA:BB:CC:DD:EE:FF\r\n" +
		"a=setup:actpass\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=sendrecv\r\n")
	info, security, err := ParseSDPWithSecurity(raw)
	if err != nil {
		t.Fatalf("ParseSDPWithSecurity() error = %v", err)
	}
	if security.RTPProfile != "RTP/SAVPF" || security.Setup != "actpass" || len(security.Fingerprints) != 1 {
		t.Fatalf("security=%+v", security)
	}
	fingerprint := security.Fingerprints[0]
	if fingerprint.HashFunc != "SHA-256" || fingerprint.Fingerprint != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("fingerprint=%+v", fingerprint)
	}

	answer := string(BuildSDPAnswerWithSecurity(info, security))
	for _, want := range []string{
		"m=audio 49170 RTP/SAVPF 111 101\r\n",
		"a=fingerprint:SHA-256 AA:BB:CC:DD:EE:FF\r\n",
		"a=setup:actpass\r\n",
		"a=rtpmap:101 telephone-event/8000\r\n",
	} {
		if !strings.Contains(answer, want) {
			t.Fatalf("answer missing %q:\n%s", want, answer)
		}
	}
	_, reparsed, err := ParseSDPWithSecurity([]byte(answer))
	if err != nil {
		t.Fatalf("ParseSDPWithSecurity(answer) error = %v", err)
	}
	if reparsed.RTPProfile != "RTP/SAVPF" || reparsed.Setup != "actpass" || len(reparsed.Fingerprints) != 1 {
		t.Fatalf("reparsed security=%+v", reparsed)
	}
}

func TestBuildSDPAnswerWithSecurityConstructsCrypto(t *testing.T) {
	security := SDPSecurityInfo{
		RTPProfile: "RTP/SAVP",
		Crypto: []SDPCryptoAttribute{{
			Tag:       "2",
			Suite:     "AES_CM_128_HMAC_SHA1_32",
			KeyParams: "inline:YWJjZGVmZ2hpamtsbW5vcA==",
		}},
	}
	answer := string(BuildSDPAnswerWithSecurity(SDPInfo{
		ConnectionIP: "192.0.2.2",
		MediaPort:    6000,
		Payloads:     []int{0, 101},
		Direction:    "sendrecv",
	}, security))
	for _, want := range []string{
		"m=audio 6000 RTP/SAVP 0 101\r\n",
		"a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:YWJjZGVmZ2hpamtsbW5vcA==\r\n",
		"a=sendrecv\r\n",
	} {
		if !strings.Contains(answer, want) {
			t.Fatalf("answer missing %q:\n%s", want, answer)
		}
	}
	_, parsed, err := ParseSDPWithSecurity([]byte(answer))
	if err != nil {
		t.Fatalf("ParseSDPWithSecurity(answer) error = %v", err)
	}
	if parsed.RTPProfile != "RTP/SAVP" || len(parsed.Crypto) != 1 || parsed.Crypto[0].Suite != "AES_CM_128_HMAC_SHA1_32" {
		t.Fatalf("parsed security=%+v", parsed)
	}
}
