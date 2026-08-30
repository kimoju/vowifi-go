package swu

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestSharedNATTTransportKeepsIKEAndESPOnOneUDPEndpoint(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer server.Close()

	type observed struct {
		ikeAddr string
		espAddr string
		err     error
	}
	seen := make(chan observed, 1)
	go func() {
		buf := make([]byte, 2048)
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, ikeAddr, readErr := server.ReadFrom(buf)
		if readErr != nil {
			seen <- observed{err: readErr}
			return
		}
		if n < 4 || !bytes.Equal(buf[:4], []byte{0, 0, 0, 0}) {
			seen <- observed{err: ErrInvalidPacketTunnel}
			return
		}
		_, _ = server.WriteTo(append([]byte{0, 0, 0, 0}, []byte("ike-response")...), ikeAddr)

		n, espAddr, readErr := server.ReadFrom(buf)
		if readErr != nil {
			seen <- observed{err: readErr}
			return
		}
		if n < 8 || isNonESPMarker(buf[:n]) {
			seen <- observed{err: ErrInvalidPacketTunnel}
			return
		}
		_, _ = server.WriteTo([]byte{1, 2, 3, 4, 0, 0, 0, 1}, espAddr)
		seen <- observed{ikeAddr: ikeAddr.String(), espAddr: espAddr.String()}
	}()

	ike := newSharedNATTTransport(server.LocalAddr().String(), "127.0.0.1:0", time.Second)
	defer ike.Close()
	localEndpoint, remoteEndpoint, err := ike.prepareNetworkEndpoints(context.Background())
	if err != nil {
		t.Fatalf("prepareNetworkEndpoints() error = %v", err)
	}
	localUDP, ok := localEndpoint.(*net.UDPAddr)
	if !ok || localUDP.Port == 0 {
		t.Fatalf("local endpoint=%v, want UDP port", localEndpoint)
	}
	remoteUDP, ok := remoteEndpoint.(*net.UDPAddr)
	if !ok || remoteUDP.Port != server.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("remote endpoint=%v, want %v", remoteEndpoint, server.LocalAddr())
	}
	response, err := ike.ExchangeIKE(context.Background(), []byte("ike-request"))
	if err != nil || string(response) != "ike-response" {
		t.Fatalf("ExchangeIKE() response=%q err=%v", response, err)
	}
	esp := ike.sharedESPTransport().(*sharedNATTESPTransport)
	if err := esp.SendESPPacket(context.Background(), []byte{9, 8, 7, 6, 0, 0, 0, 1}); err != nil {
		t.Fatalf("SendESPPacket() error = %v", err)
	}
	packet, err := esp.ReadESPPacket(context.Background())
	if err != nil || !bytes.Equal(packet, []byte{1, 2, 3, 4, 0, 0, 0, 1}) {
		t.Fatalf("ReadESPPacket() packet=%x err=%v", packet, err)
	}
	got := <-seen
	if got.err != nil {
		t.Fatalf("server error = %v", got.err)
	}
	if got.ikeAddr == "" || got.ikeAddr != got.espAddr {
		t.Fatalf("outer endpoints differ: IKE=%q ESP=%q", got.ikeAddr, got.espAddr)
	}
}
