package messaging

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"mime"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
)

const IMSCPIMContentType = "message/cpim"

const imsCPIMIMDNNamespace = "urn:ietf:params:imdn"

type IMSCPIMMessage struct {
	Headers        map[string][]string
	ContentHeaders map[string][]string
	ContentType    string
	Body           []byte
}

func ParseIMSCPIMMessage(body []byte) (IMSCPIMMessage, error) {
	messageHeaderBlock, rest, ok := splitCPIMHeaderBlock(body)
	if !ok {
		return IMSCPIMMessage{}, errors.New("CPIM message headers missing terminator")
	}
	messageHeaders, err := parseCPIMHeaders(messageHeaderBlock)
	if err != nil {
		return IMSCPIMMessage{}, fmt.Errorf("CPIM message headers: %w", err)
	}
	contentHeaderBlock, content, ok := splitCPIMHeaderBlock(rest)
	if !ok {
		return IMSCPIMMessage{}, errors.New("CPIM content headers missing terminator")
	}
	contentHeaders, err := parseCPIMHeaders(contentHeaderBlock)
	if err != nil {
		return IMSCPIMMessage{}, fmt.Errorf("CPIM content headers: %w", err)
	}
	contentType := normalizedIMSMessageContentType(textproto.MIMEHeader(contentHeaders).Get("Content-Type"))
	if contentType == "" {
		return IMSCPIMMessage{}, errors.New("CPIM content type is empty")
	}
	if contentLength := strings.TrimSpace(textproto.MIMEHeader(contentHeaders).Get("Content-Length")); contentLength != "" {
		n, err := strconv.Atoi(contentLength)
		if err != nil || n < 0 {
			return IMSCPIMMessage{}, fmt.Errorf("invalid CPIM content length: %q", contentLength)
		}
		if n > len(content) {
			return IMSCPIMMessage{}, errors.New("CPIM content truncated")
		}
		content = content[:n]
	}
	return IMSCPIMMessage{
		Headers:        messageHeaders,
		ContentHeaders: contentHeaders,
		ContentType:    contentType,
		Body:           append([]byte(nil), content...),
	}, nil
}

func BuildIMSCPIMMessage(from, to, contentType string, body []byte) ([]byte, error) {
	messageHeaders := make(map[string][]string, 2)
	if strings.TrimSpace(from) != "" {
		messageHeaders["From"] = []string{strings.TrimSpace(from)}
	}
	if strings.TrimSpace(to) != "" {
		messageHeaders["To"] = []string{strings.TrimSpace(to)}
	}
	return BuildIMSCPIMMessageWithHeaders(messageHeaders, map[string][]string{"Content-Type": {contentType}}, body)
}

func BuildIMSCPIMMessageWithHeaders(messageHeaders, contentHeaders map[string][]string, body []byte) ([]byte, error) {
	contentType := firstCPIMHeaderValue(contentHeaders, "Content-Type")
	if strings.TrimSpace(contentType) == "" {
		return nil, errors.New("CPIM content type is empty")
	}
	contentHeaders = cloneCPIMHeaders(contentHeaders)
	setCPIMHeader(contentHeaders, "Content-Length", strconv.Itoa(len(body)))
	var out bytes.Buffer
	if err := writeCPIMHeaders(&out, messageHeaders); err != nil {
		return nil, err
	}
	out.WriteString("\r\n")
	if err := writeCPIMHeaders(&out, contentHeaders); err != nil {
		return nil, err
	}
	out.WriteString("\r\n")
	out.Write(body)
	return out.Bytes(), nil
}

func splitCPIMHeaderBlock(data []byte) (block []byte, rest []byte, ok bool) {
	crlf := bytes.Index(data, []byte("\r\n\r\n"))
	lf := bytes.Index(data, []byte("\n\n"))
	switch {
	case crlf >= 0 && (lf < 0 || crlf <= lf):
		return data[:crlf], data[crlf+4:], true
	case lf >= 0:
		return data[:lf], data[lf+2:], true
	default:
		return nil, nil, false
	}
}

func parseCPIMHeaders(block []byte) (map[string][]string, error) {
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(append([]byte(nil), block...), []byte("\r\n\r\n")...))))
	header, err := reader.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(header))
	for key, values := range header {
		out[key] = append([]string(nil), values...)
	}
	normalizeCPIMIMDNHeaders(out)
	return out, nil
}

func normalizedIMSMessageContentType(contentType string) string {
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err == nil {
		return strings.ToLower(strings.TrimSpace(mediaType))
	}
	if semi := strings.IndexByte(contentType, ';'); semi >= 0 {
		contentType = contentType[:semi]
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

func cloneCPIMHeaders(headers map[string][]string) map[string][]string {
	out := make(map[string][]string, len(headers))
	for key, values := range headers {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func firstCPIMHeaderValue(headers map[string][]string, key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	for candidate, values := range headers {
		if strings.ToLower(strings.TrimSpace(candidate)) == key {
			for _, value := range values {
				if strings.TrimSpace(value) != "" {
					return value
				}
			}
		}
	}
	return ""
}

func setCPIMHeader(headers map[string][]string, key, value string) {
	for candidate := range headers {
		if strings.EqualFold(strings.TrimSpace(candidate), key) {
			delete(headers, candidate)
		}
	}
	headers[key] = []string{value}
}

func normalizeCPIMIMDNHeaders(headers map[string][]string) {
	prefixes := cpimNamespacePrefixes(headers, imsCPIMIMDNNamespace)
	if len(prefixes) == 0 {
		return
	}
	normalized := make(map[string][]string, len(headers))
	changed := false
	for key, values := range headers {
		target := key
		if normalizedKey, ok := normalizeCPIMIMDNHeaderName(key, prefixes); ok {
			target = normalizedKey
			if key != normalizedKey {
				changed = true
			}
		}
		appendCPIMHeaderValues(normalized, target, values)
	}
	if !changed {
		return
	}
	for key := range headers {
		delete(headers, key)
	}
	for key, values := range normalized {
		headers[key] = values
	}
}

func cpimNamespacePrefixes(headers map[string][]string, namespaceURI string) map[string]bool {
	prefixes := map[string]bool{}
	for _, value := range cpimHeaderValues(headers, "NS") {
		prefix, uri, ok := parseCPIMNamespaceHeader(value)
		if !ok || !strings.EqualFold(uri, namespaceURI) {
			continue
		}
		prefixes[strings.ToLower(prefix)] = true
	}
	return prefixes
}

func cpimHeaderValues(headers map[string][]string, key string) []string {
	var out []string
	for candidate, values := range headers {
		if strings.EqualFold(strings.TrimSpace(candidate), key) {
			out = append(out, values...)
		}
	}
	return out
}

func parseCPIMNamespaceHeader(value string) (prefix, uri string, ok bool) {
	value = strings.TrimSpace(value)
	start := strings.IndexByte(value, '<')
	end := strings.LastIndexByte(value, '>')
	if start <= 0 || end <= start {
		return "", "", false
	}
	prefix = strings.TrimSpace(value[:start])
	uri = strings.TrimSpace(value[start+1 : end])
	if !validCPIMHeaderName(prefix) || uri == "" {
		return "", "", false
	}
	return prefix, uri, true
}

func normalizeCPIMIMDNHeaderName(name string, prefixes map[string]bool) (string, bool) {
	name = strings.TrimSpace(name)
	prefix, suffix, ok := strings.Cut(name, ".")
	if !ok || strings.TrimSpace(suffix) == "" {
		return "", false
	}
	lowerPrefix := strings.ToLower(prefix)
	if lowerPrefix != "imdn" && !prefixes[lowerPrefix] {
		return "", false
	}
	return "imdn." + canonicalCPIMIMDNHeaderSuffix(suffix), true
}

func canonicalCPIMIMDNHeaderSuffix(suffix string) string {
	switch strings.ToLower(strings.TrimSpace(suffix)) {
	case "message-id":
		return "Message-ID"
	case "disposition-notification":
		return "Disposition-Notification"
	case "original-to":
		return "Original-To"
	case "datetime":
		return "DateTime"
	default:
		return strings.TrimSpace(suffix)
	}
}

func appendCPIMHeaderValues(headers map[string][]string, key string, values []string) {
	for candidate, existing := range headers {
		if !strings.EqualFold(strings.TrimSpace(candidate), key) {
			continue
		}
		if candidate != key {
			delete(headers, candidate)
		}
		headers[key] = append(append([]string(nil), existing...), values...)
		return
	}
	headers[key] = append([]string(nil), values...)
}

func writeCPIMHeaders(out *bytes.Buffer, headers map[string][]string) error {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return strings.ToLower(strings.TrimSpace(keys[i])) < strings.ToLower(strings.TrimSpace(keys[j]))
	})
	for _, key := range keys {
		name := strings.TrimSpace(key)
		if !validCPIMHeaderName(name) {
			return fmt.Errorf("invalid CPIM header name: %q", key)
		}
		for _, value := range headers[key] {
			if strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("invalid CPIM header %s value contains line break", name)
			}
			if strings.TrimSpace(value) == "" {
				continue
			}
			fmt.Fprintf(out, "%s: %s\r\n", name, strings.TrimSpace(value))
		}
	}
	return nil
}

func validCPIMHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			continue
		case r == '!', r == '#', r == '$', r == '%', r == '&', r == '\'', r == '*', r == '+',
			r == '-', r == '.', r == '^', r == '_', r == '`', r == '|', r == '~':
			continue
		default:
			return false
		}
	}
	return true
}
