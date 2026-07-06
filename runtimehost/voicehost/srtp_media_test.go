package voicehost

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/pion/rtcp"
)

func TestSRTPMediaSessionProtectsRTPAndRTCP(t *testing.T) {
	session, err := NewSRTPMediaSession(testSRTPMediaConfig())
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	clientRTP := testRTPPacket(1, 0x11111111, []byte{0xaa, 0xbb, 0xcc})
	clientProtected, err := session.ProtectClientRTP(clientRTP)
	if err != nil {
		t.Fatalf("ProtectClientRTP() error = %v", err)
	}
	if bytes.Equal(clientProtected, clientRTP) || len(clientProtected) <= len(clientRTP) {
		t.Fatalf("client SRTP did not protect packet: %x", clientProtected)
	}
	gotClientRTP, err := session.UnprotectClientRTP(clientProtected)
	if err != nil {
		t.Fatalf("UnprotectClientRTP() error = %v", err)
	}
	if !bytes.Equal(gotClientRTP, clientRTP) {
		t.Fatalf("client RTP=%x, want %x", gotClientRTP, clientRTP)
	}

	imsRTP := testRTPPacket(2, 0x22222222, []byte{0x44, 0x55})
	imsProtected, err := session.ProtectIMSRTP(imsRTP)
	if err != nil {
		t.Fatalf("ProtectIMSRTP() error = %v", err)
	}
	gotIMSRTP, err := session.UnprotectIMSRTP(imsProtected)
	if err != nil {
		t.Fatalf("UnprotectIMSRTP() error = %v", err)
	}
	if !bytes.Equal(gotIMSRTP, imsRTP) {
		t.Fatalf("IMS RTP=%x, want %x", gotIMSRTP, imsRTP)
	}

	clientRTCP := testRTCPPacket(0x11111111)
	clientRTCPProtected, err := session.ProtectClientRTCP(clientRTCP)
	if err != nil {
		t.Fatalf("ProtectClientRTCP() error = %v", err)
	}
	if bytes.Equal(clientRTCPProtected, clientRTCP) || len(clientRTCPProtected) <= len(clientRTCP) {
		t.Fatalf("client SRTCP did not protect packet: %x", clientRTCPProtected)
	}
	gotClientRTCP, err := session.UnprotectClientRTCP(clientRTCPProtected)
	if err != nil {
		t.Fatalf("UnprotectClientRTCP() error = %v", err)
	}
	if !bytes.Equal(gotClientRTCP, clientRTCP) {
		t.Fatalf("client RTCP=%x, want %x", gotClientRTCP, clientRTCP)
	}

	imsRTCP := testRTCPPacket(0x22222222)
	imsRTCPProtected, err := session.ProtectIMSRTCP(imsRTCP)
	if err != nil {
		t.Fatalf("ProtectIMSRTCP() error = %v", err)
	}
	gotIMSRTCP, err := session.UnprotectIMSRTCP(imsRTCPProtected)
	if err != nil {
		t.Fatalf("UnprotectIMSRTCP() error = %v", err)
	}
	if !bytes.Equal(gotIMSRTCP, imsRTCP) {
		t.Fatalf("IMS RTCP=%x, want %x", gotIMSRTCP, imsRTCP)
	}
}

func TestSRTPMediaSessionRejectsReplay(t *testing.T) {
	session, err := NewSRTPMediaSession(testSRTPMediaConfig())
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	protected, err := session.ProtectClientRTP(testRTPPacket(10, 0x11111111, []byte{0xaa}))
	if err != nil {
		t.Fatalf("ProtectClientRTP() error = %v", err)
	}
	if _, err := session.UnprotectClientRTP(protected); err != nil {
		t.Fatalf("first UnprotectClientRTP() error = %v", err)
	}
	if _, err := session.UnprotectClientRTP(protected); err == nil {
		t.Fatalf("second UnprotectClientRTP() error = nil, want replay rejection")
	}
}

func TestSRTPMediaSessionRejectsWrongKey(t *testing.T) {
	good, err := NewSRTPMediaSession(testSRTPMediaConfig())
	if err != nil {
		t.Fatalf("NewSRTPMediaSession(good) error = %v", err)
	}
	badCfg := testSRTPMediaConfig()
	badCfg.ClientKeys.MasterKey[0] ^= 0xff
	bad, err := NewSRTPMediaSession(badCfg)
	if err != nil {
		t.Fatalf("NewSRTPMediaSession(bad) error = %v", err)
	}
	protected, err := good.ProtectClientRTP(testRTPPacket(11, 0x11111111, []byte{0xaa}))
	if err != nil {
		t.Fatalf("ProtectClientRTP() error = %v", err)
	}
	if _, err := bad.UnprotectClientRTP(protected); err == nil {
		t.Fatalf("UnprotectClientRTP(wrong key) error = nil")
	}
}

func TestSRTPMediaSessionRejectsInvalidConfig(t *testing.T) {
	cfg := testSRTPMediaConfig()
	cfg.ClientKeys.MasterKey = cfg.ClientKeys.MasterKey[:15]
	if _, err := NewSRTPMediaSession(cfg); !errors.Is(err, ErrSRTPMediaConfig) {
		t.Fatalf("NewSRTPMediaSession(short key) err=%v, want ErrSRTPMediaConfig", err)
	}
	cfg = testSRTPMediaConfig()
	cfg.IMSKeys.MasterSalt = cfg.IMSKeys.MasterSalt[:13]
	if _, err := NewSRTPMediaSession(cfg); !errors.Is(err, ErrSRTPMediaConfig) {
		t.Fatalf("NewSRTPMediaSession(short salt) err=%v, want ErrSRTPMediaConfig", err)
	}
	cfg = testSRTPMediaConfig()
	cfg.Profile = "bogus"
	if _, err := NewSRTPMediaSession(cfg); !errors.Is(err, ErrSRTPMediaConfig) {
		t.Fatalf("NewSRTPMediaSession(profile) err=%v, want ErrSRTPMediaConfig", err)
	}
}

func TestSRTPProtectionProfileFromSDPCryptoSuite(t *testing.T) {
	profile, err := SRTPProtectionProfileFromSDPCryptoSuite("aes_cm_128_hmac_sha1_80")
	if err != nil {
		t.Fatalf("SRTPProtectionProfileFromSDPCryptoSuite() error = %v", err)
	}
	if profile != SRTPProfileAes128CmHmacSha1_80 || profile.SDPCryptoSuite() != "AES_CM_128_HMAC_SHA1_80" {
		t.Fatalf("profile=%q suite=%q", profile, profile.SDPCryptoSuite())
	}
	if _, err := SRTPProtectionProfileFromSDPCryptoSuite("bogus"); !errors.Is(err, ErrSRTPMediaConfig) {
		t.Fatalf("SRTPProtectionProfileFromSDPCryptoSuite(bogus) err=%v, want ErrSRTPMediaConfig", err)
	}
}

func TestSDPCryptoInlineKeyParamsRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x10}, 16)
	salt := bytes.Repeat([]byte{0x20}, 14)
	raw := append(append([]byte(nil), key...), salt...)
	params, err := ParseSDPCryptoInlineKeyParams(SRTPProfileAes128CmHmacSha1_80, "inline:"+base64.StdEncoding.EncodeToString(raw)+"|2^20|1:32")
	if err != nil {
		t.Fatalf("ParseSDPCryptoInlineKeyParams() error = %v", err)
	}
	if !bytes.Equal(params.MasterKey, key) || !bytes.Equal(params.MasterSalt, salt) || params.Lifetime != "2^20" || params.MKIValue != "1" || params.MKILength != 32 {
		t.Fatalf("params=%+v", params)
	}
	built, err := BuildSDPCryptoInlineKeyParams(SRTPProfileAes128CmHmacSha1_80, params)
	if err != nil {
		t.Fatalf("BuildSDPCryptoInlineKeyParams() error = %v", err)
	}
	reparsed, err := ParseSDPCryptoInlineKeyParams(SRTPProfileAes128CmHmacSha1_80, built)
	if err != nil {
		t.Fatalf("ParseSDPCryptoInlineKeyParams(built) error = %v", err)
	}
	if !bytes.Equal(reparsed.MasterKey, key) || !bytes.Equal(reparsed.MasterSalt, salt) || reparsed.Lifetime != "2^20" || reparsed.MKILength != 32 {
		t.Fatalf("reparsed=%+v built=%q", reparsed, built)
	}
}

func TestSRTPMediaSessionSupportsGCMProfile(t *testing.T) {
	cfg := testSRTPMediaConfig()
	cfg.Profile = SRTPProfileAeadAes128Gcm
	cfg.ClientKeys.MasterSalt = bytes.Repeat([]byte{0x20}, 12)
	cfg.IMSKeys.MasterSalt = bytes.Repeat([]byte{0x40}, 12)
	session, err := NewSRTPMediaSession(cfg)
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	protected, err := session.ProtectClientRTP(testRTPPacket(12, 0x11111111, []byte{0xaa, 0xbb}))
	if err != nil {
		t.Fatalf("ProtectClientRTP() error = %v", err)
	}
	got, err := session.UnprotectClientRTP(protected)
	if err != nil {
		t.Fatalf("UnprotectClientRTP() error = %v", err)
	}
	if want := testRTPPacket(12, 0x11111111, []byte{0xaa, 0xbb}); !bytes.Equal(got, want) {
		t.Fatalf("RTP=%x, want %x", got, want)
	}
}

func TestSRTPMediaSessionReportsRTCPFeedbackInRelayTransform(t *testing.T) {
	events := make(chan RTCPFeedbackEvent, 1)
	cfg := testSRTPMediaConfig()
	cfg.RTCPFeedbackHandler = func(event RTCPFeedbackEvent) {
		events <- event
	}
	session, err := NewSRTPMediaSession(cfg)
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	packet, err := (&rtcp.PictureLossIndication{SenderSSRC: 0x11111111, MediaSSRC: 0x22222222}).Marshal()
	if err != nil {
		t.Fatalf("PLI Marshal() error = %v", err)
	}
	protected, err := session.ProtectClientRTCP(packet)
	if err != nil {
		t.Fatalf("ProtectClientRTCP() error = %v", err)
	}
	transformed, err := session.RelayTransforms().ClientToIMSRTCP(protected)
	if err != nil {
		t.Fatalf("ClientToIMSRTCP() error = %v", err)
	}
	plain, err := session.UnprotectIMSRTCP(transformed)
	if err != nil {
		t.Fatalf("UnprotectIMSRTCP() error = %v", err)
	}
	if !bytes.Equal(plain, packet) {
		t.Fatalf("RTCP plain=%x, want %x", plain, packet)
	}
	event := readRTCPFeedbackEvent(t, events)
	if event.Direction != RTCPFeedbackClientToIMS || event.Kind != RTCPFeedbackPictureLossIndication || event.MediaSSRC != 0x22222222 {
		t.Fatalf("event=%+v", event)
	}
}

func TestSRTPMediaSessionReportsRTPDTMFInRelayTransform(t *testing.T) {
	events := make(chan RTPDTMFEvent, 1)
	cfg := testSRTPMediaConfig()
	cfg.ClientRTPDTMFPayloads = map[uint8]int{110: 16000}
	cfg.IMSRTPDTMFPayloads = map[uint8]int{101: 8000}
	cfg.RTPDTMFHandler = func(event RTPDTMFEvent) {
		events <- event
	}
	session, err := NewSRTPMediaSession(cfg)
	if err != nil {
		t.Fatalf("NewSRTPMediaSession() error = %v", err)
	}
	packet, err := BuildRTPDTMFPacket(RTPDTMFPacket{PayloadType: 110, Marker: true, SequenceNumber: 44, Timestamp: 3200, SSRC: 0x11111111, Signal: "A", DurationSamples: 1600, ClockRate: 16000})
	if err != nil {
		t.Fatalf("BuildRTPDTMFPacket() error = %v", err)
	}
	protected, err := session.ProtectClientRTP(packet)
	if err != nil {
		t.Fatalf("ProtectClientRTP() error = %v", err)
	}
	transformed, err := session.RelayTransforms().ClientToIMSRTP(protected)
	if err != nil {
		t.Fatalf("ClientToIMSRTP() error = %v", err)
	}
	plain, err := session.UnprotectIMSRTP(transformed)
	if err != nil {
		t.Fatalf("UnprotectIMSRTP() error = %v", err)
	}
	wantPlain, remapped, err := RewriteRTPDTMFPayloadType(packet, cfg.ClientRTPDTMFPayloads, cfg.IMSRTPDTMFPayloads)
	if err != nil || !remapped {
		t.Fatalf("RewriteRTPDTMFPayloadType() remapped=%v err=%v", remapped, err)
	}
	if !bytes.Equal(plain, wantPlain) {
		t.Fatalf("RTP plain=%x, want %x", plain, wantPlain)
	}
	event := readRTPDTMFEvent(t, events)
	if event.Direction != RTPDTMFClientToIMS || event.PayloadType != 110 || event.Signal != "A" || event.DurationMS != 100 || !event.Marker {
		t.Fatalf("event=%+v", event)
	}
}

func testSRTPMediaConfig() SRTPMediaConfig {
	return SRTPMediaConfig{
		Profile: SRTPProfileAes128CmHmacSha1_80,
		ClientKeys: SRTPKeys{
			MasterKey:  bytes.Repeat([]byte{0x10}, 16),
			MasterSalt: bytes.Repeat([]byte{0x20}, 14),
		},
		IMSKeys: SRTPKeys{
			MasterKey:  bytes.Repeat([]byte{0x30}, 16),
			MasterSalt: bytes.Repeat([]byte{0x40}, 14),
		},
	}
}

func testRTPPacket(sequence uint16, ssrc uint32, payload []byte) []byte {
	packet := []byte{
		0x80, 0x00,
		byte(sequence >> 8), byte(sequence),
		0x00, 0x00, 0x00, 0x01,
		byte(ssrc >> 24), byte(ssrc >> 16), byte(ssrc >> 8), byte(ssrc),
	}
	return append(packet, payload...)
}

func testRTCPPacket(ssrc uint32) []byte {
	return []byte{
		0x80, 0xc9, 0x00, 0x01,
		byte(ssrc >> 24), byte(ssrc >> 16), byte(ssrc >> 8), byte(ssrc),
	}
}
