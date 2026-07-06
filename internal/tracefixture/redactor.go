package tracefixture

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
)

var (
	sensitiveHeaderLineRE = regexp.MustCompile(`(?im)^((?:Proxy-)?Authorization|(?:WWW-|Proxy-)?Authenticate|Security-Client|Security-Server|Security-Verify)\s*:\s*.*$`)
	authParamRE           = regexp.MustCompile(`(?i)\b(nonce|cnonce|response|auts|res|rand|autn|ck|ik)="[^"]*"`)
	sipURIRE              = regexp.MustCompile(`(?i)\bsips?:([^@\s;>,"]+)@([A-Za-z0-9._:-]+)`)
	telURIRE              = regexp.MustCompile(`(?i)\btel:\+?[0-9][0-9(). -]{5,}[0-9]`)
	e164RE                = regexp.MustCompile(`\+[1-9][0-9]{7,14}`)
	longDigitRE           = regexp.MustCompile(`\b[0-9]{14,16}\b`)
	longHexRE             = regexp.MustCompile(`(?i)\b[0-9a-f]{32,}\b`)
	ipv4RE                = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
)

type Redactor struct {
	mu       sync.Mutex
	counters map[string]int
	values   map[string]string
}

func NewRedactor() *Redactor {
	return &Redactor{
		counters: make(map[string]int),
		values:   make(map[string]string),
	}
}

func RedactString(s string) string {
	return NewRedactor().RedactString(s)
}

func RedactBytes(b []byte) []byte {
	return []byte(RedactString(string(b)))
}

func (r *Redactor) RedactBytes(b []byte) []byte {
	if r == nil {
		return RedactBytes(b)
	}
	return []byte(r.RedactString(string(b)))
}

func (r *Redactor) RedactString(s string) string {
	if r == nil {
		r = NewRedactor()
	}
	out := sensitiveHeaderLineRE.ReplaceAllStringFunc(s, func(line string) string {
		if name, _, ok := strings.Cut(line, ":"); ok {
			return strings.TrimSpace(name) + ": <redacted>"
		}
		return "<redacted>"
	})
	out = authParamRE.ReplaceAllString(out, `$1="<redacted>"`)
	out = sipURIRE.ReplaceAllStringFunc(out, func(uri string) string {
		match := sipURIRE.FindStringSubmatch(uri)
		if len(match) != 3 {
			return uri
		}
		prefix := strings.SplitN(uri, ":", 2)[0]
		user := r.placeholder("sip-user", match[1])
		domain := r.redactDomain(match[2])
		return prefix + ":" + user + "@" + domain
	})
	out = telURIRE.ReplaceAllStringFunc(out, func(v string) string {
		prefix := v[:strings.Index(v, ":")+1]
		return prefix + r.placeholder("msisdn", v[len(prefix):])
	})
	out = e164RE.ReplaceAllStringFunc(out, func(v string) string {
		return "+" + r.placeholder("msisdn", v)
	})
	out = ipv4RE.ReplaceAllStringFunc(out, func(v string) string {
		ip := net.ParseIP(v)
		if ip == nil || ip.To4() == nil {
			return v
		}
		return r.placeholder("ipv4", v)
	})
	out = longDigitRE.ReplaceAllStringFunc(out, func(v string) string {
		return r.placeholder("id", v)
	})
	out = longHexRE.ReplaceAllStringFunc(out, func(v string) string {
		return r.placeholder("hex", strings.ToLower(v))
	})
	return out
}

func (r *Redactor) redactDomain(domain string) string {
	host := domain
	suffix := ""
	if h, rest, ok := strings.Cut(domain, ":"); ok {
		host = h
		suffix = ":" + rest
	}
	if host == "" {
		return "redacted.invalid" + suffix
	}
	if ip := net.ParseIP(host); ip != nil {
		return r.placeholder("ip", host) + suffix
	}
	return r.placeholder("domain", strings.ToLower(host)) + ".invalid" + suffix
}

func (r *Redactor) placeholder(kind, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "<redacted-" + kind + ">"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := kind + "\x00" + value
	if out, ok := r.values[key]; ok {
		return out
	}
	r.counters[kind]++
	out := fmt.Sprintf("<redacted-%s-%d>", kind, r.counters[kind])
	r.values[key] = out
	return out
}

func RedactLines(lines [][]byte) [][]byte {
	r := NewRedactor()
	out := make([][]byte, len(lines))
	for i, line := range lines {
		out[i] = r.RedactBytes(bytes.Clone(line))
	}
	return out
}
