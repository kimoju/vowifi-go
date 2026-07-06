package voicehost

import (
	"errors"
	"strings"
	"testing"
)

func TestRewriteSDPMediaEndpointPreservesCodecAttributes(t *testing.T) {
	raw := []byte("v=0\r\n" +
		"o=user 0 0 IN IP4 192.0.2.10\r\n" +
		"s=-\r\n" +
		"c=IN IP4 192.0.2.10\r\n" +
		"t=0 0\r\n" +
		"m=audio 4002 RTP/AVP 96 101\r\n" +
		"a=rtcp:4003 IN IP4 192.0.2.10\r\n" +
		"a=rtpmap:96 AMR/8000\r\n" +
		"a=fmtp:96 octet-align=1\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n")
	got := string(RewriteSDPMediaEndpoint(raw, SDPInfo{ConnectionIP: "198.51.100.20", MediaPort: 49170, RTCPPort: 49171}))
	if !strings.Contains(got, "c=IN IP4 198.51.100.20\r\n") || !strings.Contains(got, "m=audio 49170 RTP/AVP 96 101\r\n") {
		t.Fatalf("rewritten SDP endpoint wrong:\n%s", got)
	}
	for _, want := range []string{"a=rtcp:49171 IN IP4 198.51.100.20", "a=rtpmap:96 AMR/8000", "a=fmtp:96 octet-align=1", "a=rtpmap:101 telephone-event/8000"} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten SDP missing %q:\n%s", want, got)
		}
	}
}

func TestRewriteSDPMediaEndpointUsesIPv6ConnectionLine(t *testing.T) {
	raw := []byte("v=0\r\nm=audio 4002 RTP/AVP 0\r\n")
	got := string(RewriteSDPMediaEndpoint(raw, SDPInfo{ConnectionIP: "2001:db8::1", MediaPort: 5004, RTCPIP: "2001:db8::2", RTCPPort: 5005}))
	if !strings.Contains(got, "c=IN IP6 2001:db8::1\r\n") || !strings.Contains(got, "m=audio 5004 RTP/AVP 0\r\n") || !strings.Contains(got, "a=rtcp:5005 IN IP6 2001:db8::2\r\n") {
		t.Fatalf("rewritten IPv6 SDP:\n%s", got)
	}
}

func TestRewriteSDPMediaEndpointWithRTCPMux(t *testing.T) {
	raw := []byte("v=0\r\n" +
		"c=IN IP4 192.0.2.10\r\n" +
		"m=audio 4002 RTP/SAVPF 111 110\r\n" +
		"a=rtcp:4003 IN IP4 192.0.2.10\r\n" +
		"a=rtpmap:111 opus/48000/2\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n")
	got := string(RewriteSDPMediaEndpointWithOptions(raw, SDPInfo{ConnectionIP: "198.51.100.20", MediaPort: 49170, RTCPPort: 49171}, SDPMediaRewriteOptions{RTCPMux: true}))
	if !strings.Contains(got, "c=IN IP4 198.51.100.20\r\n") ||
		!strings.Contains(got, "m=audio 49170 RTP/SAVPF 111 110\r\na=rtcp-mux\r\n") ||
		!strings.Contains(got, "a=rtpmap:111 opus/48000/2\r\n") {
		t.Fatalf("rewritten SDP:\n%s", got)
	}
	if strings.Contains(got, "a=rtcp:") || strings.Contains(got, "49171") {
		t.Fatalf("RTCP mux rewrite kept separate RTCP endpoint:\n%s", got)
	}
}

func TestRewriteSDPMediaEndpointPreservesDisabledAudioPort(t *testing.T) {
	raw := []byte("v=0\r\n" +
		"o=user 0 0 IN IP4 192.0.2.10\r\n" +
		"s=-\r\n" +
		"c=IN IP4 0.0.0.0\r\n" +
		"t=0 0\r\n" +
		"m=audio 0 RTP/AVP 0\r\n" +
		"a=inactive\r\n")
	got := string(RewriteSDPMediaEndpoint(raw, SDPInfo{ConnectionIP: "198.51.100.20", MediaPort: 49170, RTCPPort: 49171}))
	for _, want := range []string{"c=IN IP4 0.0.0.0", "m=audio 0 RTP/AVP 0", "a=inactive"} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten disabled SDP missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "49170") || strings.Contains(got, "49171") || strings.Contains(got, "198.51.100.20") {
		t.Fatalf("rewritten disabled SDP leaked relay endpoint:\n%s", got)
	}
}

func TestParseSDPMediaDescriptionCapturesRTCPMuxAndCodecs(t *testing.T) {
	raw := []byte("v=0\r\n" +
		"o=user 0 0 IN IP4 203.0.113.8\r\n" +
		"s=-\r\n" +
		"c=IN IP4 203.0.113.8\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/SAVPF 111 110 0\r\n" +
		"a=rtcp:5300 IN IP4 198.51.100.9\r\n" +
		"a=rtcp-mux\r\n" +
		"a=rtpmap:111 opus/48000/2\r\n" +
		"a=fmtp:111 useinbandfec=1\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n")
	got, err := ParseSDPMediaDescription(raw)
	if err != nil {
		t.Fatalf("ParseSDPMediaDescription() error = %v", err)
	}
	if got.RTPProfile != "RTP/SAVPF" || !got.RTCPMux || !got.ExplicitRTCP {
		t.Fatalf("media=%+v", got)
	}
	if got.Info.RTCPPort != 49170 || got.Info.RTCPIP != "203.0.113.8" {
		t.Fatalf("effective RTCP endpoint info=%+v", got.Info)
	}
	if len(got.Codecs) != 3 ||
		got.Codecs[0].Payload != 111 || got.Codecs[0].EncodingName != "opus" || got.Codecs[0].ClockRate != 48000 || got.Codecs[0].Channels != 2 || got.Codecs[0].FMTP != "useinbandfec=1" ||
		got.Codecs[1].Payload != 110 || got.Codecs[1].EncodingName != "telephone-event" || got.Codecs[1].ClockRate != 16000 ||
		got.Codecs[2].Payload != 0 || got.Codecs[2].EncodingName != "PCMU" {
		t.Fatalf("codecs=%+v", got.Codecs)
	}
}

func TestSelectSDPAnswerCodecsAndBuildMuxedAnswer(t *testing.T) {
	offer, err := ParseSDPMediaDescription([]byte("v=0\r\n" +
		"c=IN IP4 203.0.113.8\r\n" +
		"m=audio 49170 RTP/SAVPF 111 96 110\r\n" +
		"a=rtcp-mux\r\n" +
		"a=rtpmap:111 opus/48000/2\r\n" +
		"a=rtpmap:96 AMR/8000\r\n" +
		"a=fmtp:96 octet-align=0\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n"))
	if err != nil {
		t.Fatalf("ParseSDPMediaDescription() error = %v", err)
	}
	codecs := SelectSDPAnswerCodecs(offer.Codecs, []SDPCodec{
		{EncodingName: "AMR", ClockRate: 8000, FMTP: "octet-align=1"},
		{EncodingName: "telephone-event", ClockRate: 16000},
	})
	if len(codecs) != 2 || codecs[0].Payload != 96 || codecs[1].Payload != 110 {
		t.Fatalf("selected codecs=%+v", codecs)
	}
	answer := string(BuildSDPAnswerWithOptions(SDPInfo{
		ConnectionIP: "192.0.2.2",
		MediaPort:    6000,
		RTCPPort:     6001,
		Direction:    "sendrecv",
	}, SDPAnswerOptions{
		RTPProfile: offer.RTPProfile,
		RTCPMux:    offer.RTCPMux,
		Codecs:     codecs,
	}))
	for _, want := range []string{
		"m=audio 6000 RTP/SAVPF 96 110\r\n",
		"a=rtcp-mux\r\n",
		"a=rtpmap:96 AMR/8000\r\n",
		"a=fmtp:96 octet-align=1\r\n",
		"a=rtpmap:110 telephone-event/16000\r\n",
	} {
		if !strings.Contains(answer, want) {
			t.Fatalf("answer missing %q:\n%s", want, answer)
		}
	}
	if strings.Contains(answer, "a=rtcp:") || strings.Contains(answer, "opus") || strings.Contains(answer, "111") {
		t.Fatalf("answer kept unselected media:\n%s", answer)
	}
}

func TestBuildSDPAnswerWithOptionsZeroMatchesDefault(t *testing.T) {
	info := SDPInfo{ConnectionIP: "192.0.2.2", MediaPort: 6000, RTCPPort: 6001, Payloads: []int{0, 101}, Direction: "sendrecv"}
	if got, want := string(BuildSDPAnswerWithOptions(info, SDPAnswerOptions{})), string(BuildSDPAnswer(info)); got != want {
		t.Fatalf("BuildSDPAnswerWithOptions(zero) changed default:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestParseSDPKeepsSeparateRTCPAddress(t *testing.T) {
	info, err := ParseSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nm=audio 4002 RTP/AVP 0\r\na=rtcp:5005 IN IP4 198.51.100.20\r\n"))
	if err != nil {
		t.Fatalf("ParseSDP() error = %v", err)
	}
	if info.ConnectionIP != "192.0.2.10" || info.RTCPIP != "198.51.100.20" || info.RTCPPort != 5005 {
		t.Fatalf("info=%+v", info)
	}
}

func TestRewriteSDPMediaDirectionReplacesDirection(t *testing.T) {
	raw := []byte("v=0\r\n" +
		"c=IN IP4 192.0.2.10\r\n" +
		"m=audio 4002 RTP/AVP 0 101\r\n" +
		"a=rtcp:4003 IN IP4 192.0.2.10\r\n" +
		"a=sendrecv\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n")
	got, err := RewriteSDPMediaDirection(raw, "sendonly")
	if err != nil {
		t.Fatalf("RewriteSDPMediaDirection() error = %v", err)
	}
	text := string(got)
	if !strings.Contains(text, "m=audio 4002 RTP/AVP 0 101\r\n") ||
		!strings.Contains(text, "a=sendonly\r\n") ||
		!strings.Contains(text, "a=rtpmap:101 telephone-event/8000\r\n") ||
		strings.Contains(text, "a=sendrecv") {
		t.Fatalf("rewritten SDP:\n%s", text)
	}
}

func TestRewriteSDPMediaDirectionInsertsMissingDirection(t *testing.T) {
	raw := []byte("v=0\r\nc=IN IP4 192.0.2.10\r\nm=audio 4002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
	got, err := RewriteSDPMediaDirection(raw, "inactive")
	if err != nil {
		t.Fatalf("RewriteSDPMediaDirection() error = %v", err)
	}
	text := string(got)
	if !strings.Contains(text, "m=audio 4002 RTP/AVP 0\r\na=inactive\r\na=rtpmap:0 PCMU/8000\r\n") {
		t.Fatalf("rewritten SDP:\n%s", text)
	}
}

func TestRewriteSDPMediaDirectionRejectsInvalidDirection(t *testing.T) {
	_, err := RewriteSDPMediaDirection([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nm=audio 4002 RTP/AVP 0\r\n"), "hold")
	if !errors.Is(err, ErrInvalidSDPDirection) {
		t.Fatalf("RewriteSDPMediaDirection() err=%v, want ErrInvalidSDPDirection", err)
	}
}
