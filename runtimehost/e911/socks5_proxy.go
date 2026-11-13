package e911

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kimoju/vowifi-go/engine/swu"
)

const (
	defaultE911HTTPTimeout       = 15 * time.Second
	maxE911ResponseBodyBytes     = 2 << 20
	e911SOCKS5Version            = 0x05
	e911SOCKS5AuthNone           = 0x00
	e911SOCKS5AuthUsernamePass   = 0x02
	e911SOCKS5UserPassVersion    = 0x01
	e911SOCKS5CmdConnect         = 0x01
	e911SOCKS5ATYPIPv4           = 0x01
	e911SOCKS5ATYPDomain         = 0x03
	e911SOCKS5ATYPIPv6           = 0x04
	defaultE911SOCKS5HandshakeTO = 10 * time.Second
)

type ProxyConfig = swu.ProxyConfig

func NewHTTPClientWithProxy(proxy *ProxyConfig) HTTPClient {
	return defaultHTTPClient{
		client: newStandardHTTPClient(proxy, defaultE911HTTPTimeout),
		proxy:  cloneE911ProxyConfig(proxy),
	}
}

func cloneE911ProxyConfig(p *ProxyConfig) *ProxyConfig {
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}

func newStandardHTTPClient(proxy *ProxyConfig, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = defaultE911HTTPTimeout
	}
	if !proxy.IsActive() {
		return &http.Client{Timeout: timeout}
	}
	scheme, proxyURL, socksTarget, err := parseE911Proxy(proxy)
	if err != nil {
		return &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					return nil, err
				},
			},
		}
	}
	if scheme == "http" || scheme == "https" {
		return &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialSOCKS5TCPConnect(ctx, socksTarget, addr)
			},
		},
	}
}

type parsedE911SOCKS5 struct {
	HostPort string
	Username string
	Password string
}

func parseE911Proxy(p *ProxyConfig) (string, *url.URL, parsedE911SOCKS5, error) {
	username := p.Username
	password := p.Password
	raw := strings.TrimSpace(p.URL)
	if raw == "" {
		raw = firstNonEmpty(strings.TrimSpace(p.Address), strings.TrimSpace(p.Addr))
	}
	if raw == "" {
		return "", nil, parsedE911SOCKS5{}, errors.New("e911 proxy address is empty")
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", nil, parsedE911SOCKS5{}, fmt.Errorf("invalid e911 proxy URL: %w", err)
		}
		scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
		switch scheme {
		case "http", "https":
			if u.User == nil && username != "" {
				u.User = url.UserPassword(username, password)
			}
			return scheme, u, parsedE911SOCKS5{}, nil
		case "socks5", "socks5h":
			if u.User != nil {
				if uName := u.User.Username(); uName != "" && username == "" {
					username = uName
					if pw, ok := u.User.Password(); ok && password == "" {
						password = pw
					}
				}
			}
			host := strings.Trim(u.Hostname(), "[]")
			port := u.Port()
			if port == "" {
				port = "1080"
			}
			if host == "" {
				return "", nil, parsedE911SOCKS5{}, errors.New("e911 socks5 proxy host is empty")
			}
			return "socks5", nil, parsedE911SOCKS5{
				HostPort: net.JoinHostPort(host, port),
				Username: username,
				Password: password,
			}, nil
		default:
			return "", nil, parsedE911SOCKS5{}, fmt.Errorf("unsupported e911 proxy scheme %q", scheme)
		}
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		host = strings.Trim(raw, "[]")
		port = "1080"
	} else {
		host = strings.Trim(host, "[]")
	}
	if host == "" {
		return "", nil, parsedE911SOCKS5{}, errors.New("e911 socks5 proxy host is empty")
	}
	return "socks5", nil, parsedE911SOCKS5{
		HostPort: net.JoinHostPort(host, port),
		Username: username,
		Password: password,
	}, nil
}

func dialSOCKS5TCPConnect(ctx context.Context, proxy parsedE911SOCKS5, targetAddr string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("e911 socks5 invalid target %q: %w", targetAddr, err)
	}
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || portNum == 0 {
		return nil, fmt.Errorf("e911 socks5 invalid target port %q", portStr)
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return nil, errors.New("e911 socks5 empty target host")
	}

	var dialer net.Dialer
	handCtx, cancel := context.WithTimeout(ctx, defaultE911SOCKS5HandshakeTO)
	defer cancel()
	conn, err := dialer.DialContext(handCtx, "tcp", proxy.HostPort)
	if err != nil {
		return nil, err
	}
	if deadline, ok := handCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	var greeting []byte
	if proxy.Username != "" || proxy.Password != "" {
		greeting = []byte{e911SOCKS5Version, 2, e911SOCKS5AuthNone, e911SOCKS5AuthUsernamePass}
	} else {
		greeting = []byte{e911SOCKS5Version, 1, e911SOCKS5AuthNone}
	}
	if _, err := conn.Write(greeting); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var methodReply [2]byte
	if _, err := io.ReadFull(conn, methodReply[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if methodReply[0] != e911SOCKS5Version {
		_ = conn.Close()
		return nil, fmt.Errorf("e911 socks5 invalid version %d", methodReply[0])
	}
	switch methodReply[1] {
	case e911SOCKS5AuthNone:
	case e911SOCKS5AuthUsernamePass:
		if len(proxy.Username) > 255 || len(proxy.Password) > 255 {
			_ = conn.Close()
			return nil, errors.New("e911 socks5 credentials exceed 255 bytes")
		}
		authReq := make([]byte, 0, 3+len(proxy.Username)+len(proxy.Password))
		authReq = append(authReq, e911SOCKS5UserPassVersion, byte(len(proxy.Username)))
		authReq = append(authReq, proxy.Username...)
		authReq = append(authReq, byte(len(proxy.Password)))
		authReq = append(authReq, proxy.Password...)
		if _, err := conn.Write(authReq); err != nil {
			_ = conn.Close()
			return nil, err
		}
		var authResp [2]byte
		if _, err := io.ReadFull(conn, authResp[:]); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if authResp[1] != 0x00 {
			_ = conn.Close()
			return nil, fmt.Errorf("e911 socks5 authentication failed (%d)", authResp[1])
		}
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("e911 socks5 unsupported auth method %d", methodReply[1])
	}

	req := []byte{e911SOCKS5Version, e911SOCKS5CmdConnect, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, e911SOCKS5ATYPIPv4)
			req = append(req, v4...)
		} else {
			req = append(req, e911SOCKS5ATYPIPv6)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			_ = conn.Close()
			return nil, errors.New("e911 socks5 domain exceeds 255 bytes")
		}
		req = append(req, e911SOCKS5ATYPDomain, byte(len(host)))
		req = append(req, host...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(portNum))
	req = append(req, portBytes[:]...)
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, err
	}

	var respHdr [4]byte
	if _, err := io.ReadFull(conn, respHdr[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if respHdr[0] != e911SOCKS5Version || respHdr[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("e911 socks5 connect failed (reply=%d)", respHdr[1])
	}
	switch respHdr[3] {
	case e911SOCKS5ATYPIPv4:
		if _, err := io.CopyN(io.Discard, conn, 6); err != nil {
			_ = conn.Close()
			return nil, err
		}
	case e911SOCKS5ATYPIPv6:
		if _, err := io.CopyN(io.Discard, conn, 18); err != nil {
			_ = conn.Close()
			return nil, err
		}
	case e911SOCKS5ATYPDomain:
		var dlen [1]byte
		if _, err := io.ReadFull(conn, dlen[:]); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if _, err := io.CopyN(io.Discard, conn, int64(dlen[0])+2); err != nil {
			_ = conn.Close()
			return nil, err
		}
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("e911 socks5 unsupported bind atyp %d", respHdr[3])
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
