package voicehost

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

var ErrInvalidSDPDirection = errors.New("invalid SDP media direction")

func RewriteSDPMediaEndpoint(body []byte, endpoint SDPInfo) []byte {
	if len(body) == 0 || strings.TrimSpace(endpoint.ConnectionIP) == "" || endpoint.MediaPort <= 0 {
		return BuildSDPAnswer(endpoint)
	}
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	audioDisabled := sdpAudioPortDisabled(lines)
	ipVersion := "IP4"
	if ip := net.ParseIP(endpoint.ConnectionIP); ip != nil && ip.To4() == nil {
		ipVersion = "IP6"
	}
	rtcpIP := strings.TrimSpace(endpoint.RTCPIP)
	if rtcpIP == "" {
		rtcpIP = endpoint.ConnectionIP
	}
	rtcpIPVersion := "IP4"
	if ip := net.ParseIP(rtcpIP); ip != nil && ip.To4() == nil {
		rtcpIPVersion = "IP6"
	}
	rewroteConnection := false
	rewroteAudio := false
	rewroteRTCP := false
	out := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "c=IN IP"):
			if audioDisabled {
				out = append(out, line)
			} else {
				out = append(out, "c=IN "+ipVersion+" "+endpoint.ConnectionIP)
			}
			rewroteConnection = true
		case strings.HasPrefix(line, "m=audio "):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if fields[1] != "0" {
					fields[1] = strconv.Itoa(endpoint.MediaPort)
				}
				line = strings.Join(fields, " ")
				rewroteAudio = true
			}
			out = append(out, line)
		case strings.HasPrefix(line, "a=rtcp:") && endpoint.RTCPPort > 0:
			if audioDisabled {
				out = append(out, line)
			} else {
				out = append(out, "a=rtcp:"+strconv.Itoa(endpoint.RTCPPort)+" IN "+rtcpIPVersion+" "+rtcpIP)
			}
			rewroteRTCP = true
		default:
			out = append(out, line)
		}
	}
	if !rewroteAudio {
		return BuildSDPAnswer(endpoint)
	}
	if !rewroteConnection && !audioDisabled {
		insertAt := len(out)
		for i, line := range out {
			if strings.HasPrefix(line, "m=audio ") {
				insertAt = i
				break
			}
		}
		out = append(out, "")
		copy(out[insertAt+1:], out[insertAt:])
		out[insertAt] = "c=IN " + ipVersion + " " + endpoint.ConnectionIP
	}
	if endpoint.RTCPPort > 0 && !rewroteRTCP && !audioDisabled {
		insertAt := len(out)
		for i, line := range out {
			if strings.HasPrefix(line, "m=audio ") {
				insertAt = i + 1
				break
			}
		}
		out = append(out, "")
		copy(out[insertAt+1:], out[insertAt:])
		out[insertAt] = "a=rtcp:" + strconv.Itoa(endpoint.RTCPPort) + " IN " + rtcpIPVersion + " " + rtcpIP
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n")
}

func RewriteSDPMediaDirection(body []byte, direction string) ([]byte, error) {
	direction, err := normalizeExplicitSDPDirection(direction)
	if err != nil {
		return nil, err
	}
	if _, err := ParseSDP(body); err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines)+1)
	replaced := false
	inserted := false
	for _, line := range lines {
		if line == "" {
			continue
		}
		if isSDPDirectionLine(line) {
			if !replaced {
				out = append(out, "a="+direction)
				replaced = true
			}
			continue
		}
		out = append(out, line)
		if !replaced && !inserted && strings.HasPrefix(line, "m=audio ") {
			out = append(out, "a="+direction)
			inserted = true
		}
	}
	if !replaced && !inserted {
		out = append(out, "a="+direction)
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n"), nil
}

func normalizeExplicitSDPDirection(direction string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "sendrecv", "sendonly", "recvonly", "inactive":
		return strings.ToLower(strings.TrimSpace(direction)), nil
	default:
		return "", ErrInvalidSDPDirection
	}
}

func isSDPDirectionLine(line string) bool {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "a=sendrecv", "a=sendonly", "a=recvonly", "a=inactive":
		return true
	default:
		return false
	}
}

func sdpAudioPortDisabled(lines []string) bool {
	for _, line := range lines {
		if !strings.HasPrefix(line, "m=audio ") {
			continue
		}
		fields := strings.Fields(line)
		return len(fields) >= 2 && strings.TrimSpace(fields[1]) == "0"
	}
	return false
}
