package messaging

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"mime"
	"net/textproto"
	"strconv"
	"strings"
)

const IMSCPIMContentType = "message/cpim"

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
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		return nil, errors.New("CPIM content type is empty")
	}
	var out bytes.Buffer
	if strings.TrimSpace(from) != "" {
		fmt.Fprintf(&out, "From: %s\r\n", strings.TrimSpace(from))
	}
	if strings.TrimSpace(to) != "" {
		fmt.Fprintf(&out, "To: %s\r\n", strings.TrimSpace(to))
	}
	out.WriteString("\r\n")
	fmt.Fprintf(&out, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(&out, "Content-Length: %d\r\n", len(body))
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
