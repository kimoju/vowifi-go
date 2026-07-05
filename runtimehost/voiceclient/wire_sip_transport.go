package voiceclient

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type SIPResponse = RegisterResponse

type SIPRequestTransport interface {
	RoundTripRequest(context.Context, SIPRequestMessage) (SIPResponse, error)
	WriteRequest(context.Context, SIPRequestMessage) error
}

type WireSIPTransport struct {
	Network    string
	ServerAddr string
	LocalAddr  string
	Timeout    time.Duration
}

func (t WireSIPTransport) RoundTripRequest(ctx context.Context, msg SIPRequestMessage) (SIPResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	conn, network, timeout, err := t.dial(ctx, msg)
	if err != nil {
		return SIPResponse{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return SIPResponse{}, err
	}
	wire, err := buildSIPRequestWire(msg, transportName(network), conn.LocalAddr())
	if err != nil {
		return SIPResponse{}, err
	}
	if _, err := conn.Write(wire); err != nil {
		return SIPResponse{}, err
	}
	if strings.HasPrefix(network, "tcp") {
		reader := bufio.NewReader(conn)
		return readFinalSIPResponse(reader, msg.Method)
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return SIPResponse{}, err
		}
		resp, err := ParseSIPResponse(buf[:n])
		if err != nil {
			return SIPResponse{}, err
		}
		if !isProvisionalResponse(resp.StatusCode, msg.Method) {
			return resp, nil
		}
	}
}

func (t WireSIPTransport) WriteRequest(ctx context.Context, msg SIPRequestMessage) error {
	if ctx == nil {
		ctx = context.Background()
	}
	conn, network, timeout, err := t.dial(ctx, msg)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	wire, err := buildSIPRequestWire(msg, transportName(network), conn.LocalAddr())
	if err != nil {
		return err
	}
	_, err = conn.Write(wire)
	return err
}

func (t WireSIPTransport) dial(ctx context.Context, msg SIPRequestMessage) (net.Conn, string, time.Duration, error) {
	network := strings.ToLower(strings.TrimSpace(t.Network))
	if network == "" {
		network = "udp"
	}
	target := strings.TrimSpace(t.ServerAddr)
	if target == "" {
		addr, err := sipURIAddr(msg.URI)
		if err != nil {
			return nil, "", 0, err
		}
		target = addr
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	switch network {
	case "udp", "udp4", "udp6":
		if strings.TrimSpace(t.LocalAddr) != "" {
			addr, err := net.ResolveUDPAddr(network, t.LocalAddr)
			if err != nil {
				return nil, "", 0, err
			}
			dialer.LocalAddr = addr
		}
	case "tcp", "tcp4", "tcp6":
		if strings.TrimSpace(t.LocalAddr) != "" {
			addr, err := net.ResolveTCPAddr(network, t.LocalAddr)
			if err != nil {
				return nil, "", 0, err
			}
			dialer.LocalAddr = addr
		}
	default:
		return nil, "", 0, fmt.Errorf("unsupported SIP network %q", network)
	}
	conn, err := dialer.DialContext(ctx, network, target)
	if err != nil {
		return nil, "", 0, err
	}
	return conn, network, timeout, nil
}

func readFinalSIPResponse(reader *bufio.Reader, method string) (SIPResponse, error) {
	for {
		raw, err := readSIPStreamMessage(reader)
		if err != nil {
			return SIPResponse{}, err
		}
		resp, err := ParseSIPResponse(raw)
		if err != nil {
			return SIPResponse{}, err
		}
		if !isProvisionalResponse(resp.StatusCode, method) {
			return resp, nil
		}
	}
}

func isProvisionalResponse(code int, method string) bool {
	return strings.EqualFold(strings.TrimSpace(method), "INVITE") && code >= 100 && code < 200
}

func transportName(network string) string {
	if strings.HasPrefix(strings.ToLower(network), "tcp") {
		return "TCP"
	}
	return "UDP"
}
