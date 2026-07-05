package voiceclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

var ErrInvalidSIPMessage = errors.New("invalid SIP message")

type WireRegisterTransport struct {
	Network    string
	ServerAddr string
	LocalAddr  string
	Timeout    time.Duration
}

func (t WireRegisterTransport) RoundTripRegister(ctx context.Context, msg RegisterMessage) (RegisterResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	network := strings.ToLower(strings.TrimSpace(t.Network))
	if network == "" {
		network = "udp"
	}
	target := strings.TrimSpace(t.ServerAddr)
	if target == "" {
		addr, err := sipURIAddr(msg.URI)
		if err != nil {
			return RegisterResponse{}, err
		}
		target = addr
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	switch network {
	case "udp", "udp4", "udp6":
		return t.roundTripUDP(ctx, network, target, timeout, msg)
	case "tcp", "tcp4", "tcp6":
		return t.roundTripTCP(ctx, network, target, timeout, msg)
	default:
		return RegisterResponse{}, fmt.Errorf("unsupported SIP register network %q", network)
	}
}

func (t WireRegisterTransport) roundTripUDP(ctx context.Context, network, target string, timeout time.Duration, msg RegisterMessage) (RegisterResponse, error) {
	dialer := net.Dialer{Timeout: timeout}
	if strings.TrimSpace(t.LocalAddr) != "" {
		addr, err := net.ResolveUDPAddr(network, t.LocalAddr)
		if err != nil {
			return RegisterResponse{}, err
		}
		dialer.LocalAddr = addr
	}
	conn, err := dialer.DialContext(ctx, network, target)
	if err != nil {
		return RegisterResponse{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return RegisterResponse{}, err
	}
	wire, err := buildRegisterWire(msg, "UDP", conn.LocalAddr())
	if err != nil {
		return RegisterResponse{}, err
	}
	if _, err := conn.Write(wire); err != nil {
		return RegisterResponse{}, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return RegisterResponse{}, err
	}
	return ParseSIPResponse(buf[:n])
}

func (t WireRegisterTransport) roundTripTCP(ctx context.Context, network, target string, timeout time.Duration, msg RegisterMessage) (RegisterResponse, error) {
	dialer := net.Dialer{Timeout: timeout}
	if strings.TrimSpace(t.LocalAddr) != "" {
		addr, err := net.ResolveTCPAddr(network, t.LocalAddr)
		if err != nil {
			return RegisterResponse{}, err
		}
		dialer.LocalAddr = addr
	}
	conn, err := dialer.DialContext(ctx, network, target)
	if err != nil {
		return RegisterResponse{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return RegisterResponse{}, err
	}
	wire, err := buildRegisterWire(msg, "TCP", conn.LocalAddr())
	if err != nil {
		return RegisterResponse{}, err
	}
	if _, err := conn.Write(wire); err != nil {
		return RegisterResponse{}, err
	}
	raw, err := readSIPStreamMessage(bufio.NewReader(conn))
	if err != nil {
		return RegisterResponse{}, err
	}
	return ParseSIPResponse(raw)
}

func buildRegisterWire(msg RegisterMessage, transport string, localAddr net.Addr) ([]byte, error) {
	return buildSIPRequestWire(SIPRequestMessage{
		Method:  "REGISTER",
		URI:     msg.URI,
		Headers: msg.Headers,
		Body:    msg.Body,
	}, transport, localAddr)
}

func buildSIPRequestWire(msg SIPRequestMessage, transport string, localAddr net.Addr) ([]byte, error) {
	method := strings.ToUpper(strings.TrimSpace(msg.Method))
	if method == "" {
		return nil, errors.New("SIP method is empty")
	}
	uri := strings.TrimSpace(msg.URI)
	if uri == "" {
		return nil, errors.New("SIP request URI is empty")
	}
	headers := make(map[string]string, len(msg.Headers)+4)
	for k, v := range msg.Headers {
		if strings.TrimSpace(k) != "" {
			headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if firstHeaderValue(headers, "Via") == "" {
		headers["Via"] = buildViaHeader(transport, localAddr)
	}
	if firstHeaderValue(headers, "Content-Length") == "" {
		headers["Content-Length"] = strconv.Itoa(len(msg.Body))
	}
	var out bytes.Buffer
	out.WriteString(method)
	out.WriteString(" ")
	out.WriteString(uri)
	out.WriteString(" SIP/2.0\r\n")
	writeOrderedHeaders(&out, headers)
	out.WriteString("\r\n")
	out.Write(msg.Body)
	return out.Bytes(), nil
}

func writeOrderedHeaders(out *bytes.Buffer, headers map[string]string) {
	order := []string{
		"Via", "Route", "Max-Forwards", "To", "From", "Call-ID", "CSeq", "Contact",
		"Expires", "P-Preferred-Identity", "User-Agent", "Allow", "Supported", "Require",
		"P-Access-Network-Info", "Security-Client", "Security-Verify", "Authorization",
		"Proxy-Authorization", "Session-Expires", "Content-Type", "Accept",
	}
	written := make(map[string]bool, len(order))
	contentLength := ""
	for _, name := range order {
		for key, value := range headers {
			if strings.EqualFold(key, name) && strings.TrimSpace(value) != "" {
				out.WriteString(name)
				out.WriteString(": ")
				out.WriteString(value)
				out.WriteString("\r\n")
				written[strings.ToLower(key)] = true
			}
		}
	}
	for key, value := range headers {
		if strings.EqualFold(key, "Content-Length") {
			contentLength = strings.TrimSpace(value)
			written[strings.ToLower(key)] = true
			continue
		}
		if written[strings.ToLower(key)] || strings.TrimSpace(value) == "" {
			continue
		}
		out.WriteString(key)
		out.WriteString(": ")
		out.WriteString(value)
		out.WriteString("\r\n")
	}
	if contentLength != "" {
		out.WriteString("Content-Length: ")
		out.WriteString(contentLength)
		out.WriteString("\r\n")
	}
}

func buildViaHeader(transport string, addr net.Addr) string {
	host, port := localHostPort(addr)
	if host == "" {
		host = "0.0.0.0"
	}
	if port == 0 {
		port = 5060
	}
	return "SIP/2.0/" + strings.ToUpper(strings.TrimSpace(transport)) + " " + host + ":" + strconv.Itoa(port) + ";branch=" + newBranch() + ";rport"
}

func localHostPort(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0
	}
	port, _ := strconv.Atoi(portText)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host, port
}

func newBranch() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "z9hG4bKvowifigo"
	}
	return "z9hG4bK" + hex.EncodeToString(b[:])
}

func ParseSIPResponse(raw []byte) (RegisterResponse, error) {
	head, body, err := splitSIPMessage(raw)
	if err != nil {
		return RegisterResponse{}, err
	}
	lines := splitHeaderLines(head)
	if len(lines) == 0 {
		return RegisterResponse{}, ErrInvalidSIPMessage
	}
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 || !strings.EqualFold(parts[0], "SIP/2.0") {
		return RegisterResponse{}, fmt.Errorf("%w: invalid status line", ErrInvalidSIPMessage)
	}
	code, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("%w: invalid status code", ErrInvalidSIPMessage)
	}
	reason := ""
	if len(parts) == 3 {
		reason = strings.TrimSpace(parts[2])
	}
	headers, err := parseSIPHeaders(lines[1:])
	if err != nil {
		return RegisterResponse{}, err
	}
	if n, ok := contentLength(headers); ok && n <= len(body) {
		body = body[:n]
	}
	return RegisterResponse{
		StatusCode: code,
		Reason:     reason,
		Headers:    headers,
		Body:       append([]byte(nil), body...),
	}, nil
}

func splitSIPMessage(raw []byte) (string, []byte, error) {
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return string(raw[:idx]), raw[idx+4:], nil
	}
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return string(raw[:idx]), raw[idx+2:], nil
	}
	return "", nil, fmt.Errorf("%w: missing header terminator", ErrInvalidSIPMessage)
}

func splitHeaderLines(head string) []string {
	raw := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		if line == "" {
			continue
		}
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && len(out) > 0 {
			out[len(out)-1] += " " + strings.TrimSpace(line)
			continue
		}
		out = append(out, strings.TrimSpace(line))
	}
	return out
}

func parseSIPHeaders(lines []string) (map[string][]string, error) {
	headers := make(map[string][]string)
	for _, line := range lines {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("%w: malformed header %q", ErrInvalidSIPMessage, line)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" {
			return nil, fmt.Errorf("%w: empty header name", ErrInvalidSIPMessage)
		}
		canonical := canonicalHeaderName(name)
		headers[canonical] = append(headers[canonical], value)
	}
	return headers, nil
}

func readSIPStreamMessage(r *bufio.Reader) ([]byte, error) {
	var raw []byte
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		raw = append(raw, line...)
		if bytes.HasSuffix(raw, []byte("\r\n\r\n")) || bytes.HasSuffix(raw, []byte("\n\n")) {
			break
		}
	}
	headers, _, err := splitSIPMessage(raw)
	if err != nil {
		return nil, err
	}
	parsed, err := parseSIPHeaders(splitHeaderLines(headers)[1:])
	if err != nil {
		return nil, err
	}
	n, _ := contentLength(parsed)
	if n > 0 {
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		raw = append(raw, body...)
	}
	return raw, nil
}

func contentLength(headers map[string][]string) (int, bool) {
	for key, values := range headers {
		if !strings.EqualFold(key, "Content-Length") && !strings.EqualFold(key, "l") {
			continue
		}
		for _, value := range values {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err == nil && n >= 0 {
				return n, true
			}
		}
	}
	return 0, false
}

func sipURIAddr(uri string) (string, error) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return "", errors.New("SIP URI is empty")
	}
	lower := strings.ToLower(uri)
	if strings.HasPrefix(lower, "sip:") {
		uri = uri[4:]
	} else if strings.HasPrefix(lower, "sips:") {
		uri = uri[5:]
	} else {
		return "", fmt.Errorf("unsupported SIP URI %q", uri)
	}
	if user, host, ok := strings.Cut(uri, "@"); ok {
		_ = user
		uri = host
	}
	if semi := strings.IndexByte(uri, ';'); semi >= 0 {
		uri = uri[:semi]
	}
	if q := strings.IndexByte(uri, '?'); q >= 0 {
		uri = uri[:q]
	}
	host := strings.Trim(uri, "[] ")
	port := "5060"
	if strings.HasPrefix(strings.TrimSpace(uri), "[") {
		end := strings.IndexByte(uri, ']')
		if end < 0 {
			return "", fmt.Errorf("invalid SIP URI host %q", uri)
		}
		host = strings.Trim(uri[1:end], " ")
		if rest := strings.TrimSpace(uri[end+1:]); strings.HasPrefix(rest, ":") {
			port = strings.TrimSpace(rest[1:])
		}
	} else if h, p, err := net.SplitHostPort(uri); err == nil {
		host = strings.Trim(h, "[]")
		port = p
	} else if idx := strings.LastIndex(uri, ":"); idx > 0 && !strings.Contains(uri[idx+1:], ":") {
		host = strings.Trim(uri[:idx], "[] ")
		port = strings.TrimSpace(uri[idx+1:])
	}
	if host == "" {
		return "", fmt.Errorf("SIP URI host is empty: %q", uri)
	}
	return net.JoinHostPort(host, port), nil
}

func canonicalHeaderName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "i":
		return "Call-ID"
	case "call-id":
		return "Call-ID"
	case "m":
		return "Contact"
	case "l":
		return "Content-Length"
	case "content-length":
		return "Content-Length"
	case "c":
		return "Content-Type"
	case "content-type":
		return "Content-Type"
	case "f":
		return "From"
	case "t":
		return "To"
	case "v":
		return "Via"
	case "www-authenticate":
		return "WWW-Authenticate"
	case "proxy-authenticate":
		return "Proxy-Authenticate"
	case "p-associated-uri":
		return "P-Associated-URI"
	case "p-preferred-identity":
		return "P-Preferred-Identity"
	case "p-access-network-info":
		return "P-Access-Network-Info"
	case "service-route":
		return "Service-Route"
	case "security-server":
		return "Security-Server"
	case "security-client":
		return "Security-Client"
	case "security-verify":
		return "Security-Verify"
	default:
		parts := strings.Split(name, "-")
		for i, part := range parts {
			if part == "" {
				continue
			}
			parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
		}
		return strings.Join(parts, "-")
	}
}

func firstHeaderValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
