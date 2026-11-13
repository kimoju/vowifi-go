package e911

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/kimoju/vowifi-go/runtimehost/carrier"
)

func TestDefaultHTTPClientContextCancellationBodyCapAndSOCKS5Proxy(t *testing.T) {
	// 1. Context cancellation wakes Do immediately.
	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer slowSrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	client := NewDefaultHTTPClient()
	if _, err := client.Do(&HTTPRequest{Context: ctx, Method: "GET", URL: slowSrv.URL}); err == nil {
		t.Fatal("expected context timeout error from defaultHTTPClient.Do")
	}

	// 2. Oversized response body is capped at 2 MiB.
	hugeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("A"), (2<<20)+4096))
	}))
	defer hugeSrv.Close()

	resp, err := client.Do(&HTTPRequest{Method: "GET", URL: hugeSrv.URL})
	if err != nil {
		t.Fatalf("Do(hugeSrv) error = %v", err)
	}
	if len(resp.Body) != 2<<20 {
		t.Fatalf("capped body len = %d, want %d", len(resp.Body), 2<<20)
	}

	// 3. SOCKS5 TCP CONNECT proxy with RFC 1929 auth forwards HTTP entitlement request.
	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":1000,"websheet-url":"https://example.test/ws-proxied"}`))
	}))
	defer originSrv.Close()

	proxyAddr, sawProxyTarget := startLocalE911SOCKS5ConnectProxy(t, "e911user", "e911pass")
	ws, err := StartEmergencyAddressUpdate(context.Background(), Request{
		Carrier: carrier.EffectiveCarrierConfig{
			E911: carrier.E911Config{
				Provider:            "att-ts43",
				Websheet:            "https://example.test/fallback",
				EntitlementEndpoint: originSrv.URL + "/entitlement",
			},
		},
		Identity: Identity{IMSI: "310280233641503", IMEI: "356306952701762", MCC: "310", MNC: "280"},
		Proxy: &ProxyConfig{
			Enabled:  true,
			Address:  "socks5://" + proxyAddr,
			Username: "e911user",
			Password: "e911pass",
		},
	})
	if err != nil {
		t.Fatalf("StartEmergencyAddressUpdate(proxy) error = %v", err)
	}
	if ws.URL != "https://example.test/ws-proxied" {
		t.Fatalf("ws.URL = %q, want proxied URL", ws.URL)
	}
	select {
	case target := <-sawProxyTarget:
		if target == "" {
			t.Fatal("proxy saw empty target")
		}
	case <-time.After(time.Second):
		t.Fatal("request did not traverse SOCKS5 proxy")
	}
}

func startLocalE911SOCKS5ConnectProxy(t *testing.T, wantUser, wantPass string) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	targets := make(chan string, 4)
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var greet [2]byte
				if _, rerr := io.ReadFull(c, greet[:]); rerr != nil {
					return
				}
				methods := make([]byte, int(greet[1]))
				if _, rerr := io.ReadFull(c, methods); rerr != nil {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x02})
				var ah [2]byte
				if _, rerr := io.ReadFull(c, ah[:]); rerr != nil {
					return
				}
				u := make([]byte, int(ah[1]))
				_, _ = io.ReadFull(c, u)
				var pl [1]byte
				_, _ = io.ReadFull(c, pl[:])
				p := make([]byte, int(pl[0]))
				_, _ = io.ReadFull(c, p)
				if string(u) != wantUser || string(p) != wantPass {
					_, _ = c.Write([]byte{0x01, 0x01})
					return
				}
				_, _ = c.Write([]byte{0x01, 0x00})

				var rh [4]byte
				if _, rerr := io.ReadFull(c, rh[:]); rerr != nil || rh[1] != 0x01 {
					return
				}
				var host string
				switch rh[3] {
				case 0x01:
					var ipb [4]byte
					_, _ = io.ReadFull(c, ipb[:])
					host = net.IP(ipb[:]).String()
				case 0x03:
					var dl [1]byte
					_, _ = io.ReadFull(c, dl[:])
					db := make([]byte, int(dl[0]))
					_, _ = io.ReadFull(c, db)
					host = string(db)
				case 0x04:
					var ipb [16]byte
					_, _ = io.ReadFull(c, ipb[:])
					host = net.IP(ipb[:]).String()
				}
				var pb [2]byte
				_, _ = io.ReadFull(c, pb[:])
				port := binary.BigEndian.Uint16(pb[:])
				target := net.JoinHostPort(host, strconv.Itoa(int(port)))
				targets <- target

				upstream, derr := net.Dial("tcp", target)
				if derr != nil {
					_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer upstream.Close()
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
				go func() { _, _ = io.Copy(upstream, c) }()
				_, _ = io.Copy(c, upstream)
			}(conn)
		}
	}()
	return ln.Addr().String(), targets
}

func TestHTTPDigestStaleRetryAnd407To401MultiStepChallenge(t *testing.T) {
	proxyNonce := append(bytesFrom(0x11, 16), bytesFrom(0x21, 16)...)
	originNonce1 := append(bytesFrom(0x12, 16), bytesFrom(0x22, 16)...)
	originNonce2 := append(bytesFrom(0x13, 16), bytesFrom(0x23, 16)...)

	proxyChallenge := `Digest realm="proxy.example", nonce="` + base64.StdEncoding.EncodeToString(proxyNonce) + `", algorithm=AKAv1-MD5, qop="auth"`
	originChallenge1 := `Digest realm="origin.example", nonce="` + base64.StdEncoding.EncodeToString(originNonce1) + `", algorithm=AKAv1-MD5, qop="auth"`
	originChallengeStale := `Digest realm="origin.example", nonce="` + base64.StdEncoding.EncodeToString(originNonce2) + `", algorithm=AKAv1-MD5, qop="auth", stale=true`

	client := &fakeHTTPClient{responses: []*HTTPResponse{
		{StatusCode: 407, Headers: []HeaderPair{{Key: "Proxy-Authenticate", Value: proxyChallenge}}},
		{StatusCode: 401, Headers: []HeaderPair{{Key: "WWW-Authenticate", Value: originChallenge1}}},
		{StatusCode: 401, Headers: []HeaderPair{{Key: "WWW-Authenticate", Value: originChallengeStale}}},
		{StatusCode: 200, Body: []byte(`{"status":1000,"websheet-url":"https://example.test/multi-ok"}`)},
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
		Identity:    Identity{IMSI: "310280233641503", IMEI: "356306952701762", MCC: "310", MNC: "280", SIPUsername: "sip:user@example"},
		AKAProvider: aka,
		Client:      client,
		Random:      bytes.NewReader(bytes.Repeat([]byte{0x33}, 64)),
	})
	if err != nil {
		t.Fatalf("StartEmergencyAddressUpdate(407->401->stale) error = %v", err)
	}
	if ws.URL != "https://example.test/multi-ok" {
		t.Fatalf("ws.URL = %q", ws.URL)
	}
	if len(client.requests) != 4 {
		t.Fatalf("requests = %d, want 4", len(client.requests))
	}
	if headerValue(client.requests[3].Headers, "Proxy-Authorization") == "" ||
		headerValue(client.requests[3].Headers, "Authorization") == "" {
		t.Fatalf("final request missing both auth headers: %+v", client.requests[3].Headers)
	}
}
