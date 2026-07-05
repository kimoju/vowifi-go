package voiceclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type SIPServerResolver interface {
	ResolveSIPServer(context.Context, string, string) (string, error)
}

type SIPServerResolverFunc func(context.Context, string, string) (string, error)

func (f SIPServerResolverFunc) ResolveSIPServer(ctx context.Context, network, uri string) (string, error) {
	return f(ctx, network, uri)
}

type NetSIPResolver struct {
	Resolver *net.Resolver
}

func (r NetSIPResolver) ResolveSIPServer(ctx context.Context, network, uri string) (string, error) {
	endpoint, err := parseSIPURIEndpoint(uri)
	if err != nil {
		return "", err
	}
	if endpoint.ExplicitPort || net.ParseIP(strings.Trim(endpoint.Host, "[]")) != nil {
		return endpoint.addr(), nil
	}
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	service := "sip"
	if endpoint.Secure {
		service = "sips"
	}
	_, records, err := resolver.LookupSRV(ctx, service, sipResolverProto(network, endpoint.Secure), endpoint.Host)
	if err == nil && len(records) > 0 {
		target := strings.TrimSuffix(strings.TrimSpace(records[0].Target), ".")
		if target != "" {
			return net.JoinHostPort(target, strconv.Itoa(int(records[0].Port))), nil
		}
	}
	return endpoint.addr(), nil
}

func ResolveSIPServer(ctx context.Context, network, uri string) (string, error) {
	return NetSIPResolver{}.ResolveSIPServer(ctx, network, uri)
}

func resolveSIPServerAddr(ctx context.Context, resolver SIPServerResolver, network, uri string) (string, error) {
	if resolver == nil {
		resolver = NetSIPResolver{}
	}
	return resolver.ResolveSIPServer(ctx, network, uri)
}

type sipURIEndpoint struct {
	Host         string
	Port         string
	Secure       bool
	ExplicitPort bool
}

func (e sipURIEndpoint) addr() string {
	return net.JoinHostPort(strings.Trim(e.Host, "[]"), e.Port)
}

func parseSIPURIEndpoint(uri string) (sipURIEndpoint, error) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return sipURIEndpoint{}, errSIPURIEmpty()
	}
	lower := strings.ToLower(uri)
	secure := false
	if strings.HasPrefix(lower, "sip:") {
		uri = uri[4:]
	} else if strings.HasPrefix(lower, "sips:") {
		uri = uri[5:]
		secure = true
	} else {
		return sipURIEndpoint{}, errUnsupportedSIPURI(uri)
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
	rawHostPort := strings.TrimSpace(uri)
	defaultPort := "5060"
	if secure {
		defaultPort = "5061"
	}
	host := strings.Trim(rawHostPort, "[] ")
	port := defaultPort
	explicitPort := false
	if strings.HasPrefix(rawHostPort, "[") {
		end := strings.IndexByte(rawHostPort, ']')
		if end < 0 {
			return sipURIEndpoint{}, errInvalidSIPURIHost(rawHostPort)
		}
		host = strings.TrimSpace(rawHostPort[1:end])
		if rest := strings.TrimSpace(rawHostPort[end+1:]); strings.HasPrefix(rest, ":") {
			port = strings.TrimSpace(rest[1:])
			explicitPort = true
		}
	} else if h, p, err := net.SplitHostPort(rawHostPort); err == nil {
		host = strings.Trim(h, "[]")
		port = p
		explicitPort = true
	} else if idx := strings.LastIndex(rawHostPort, ":"); idx > 0 && !strings.Contains(rawHostPort[idx+1:], ":") {
		host = strings.Trim(rawHostPort[:idx], "[] ")
		port = strings.TrimSpace(rawHostPort[idx+1:])
		explicitPort = true
	}
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		return sipURIEndpoint{}, errSIPURIHostEmpty(rawHostPort)
	}
	if port == "" {
		port = defaultPort
	}
	return sipURIEndpoint{Host: host, Port: port, Secure: secure, ExplicitPort: explicitPort}, nil
}

func sipResolverProto(network string, secure bool) string {
	if secure {
		return "tcp"
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(network)), "tcp") {
		return "tcp"
	}
	return "udp"
}

func errSIPURIEmpty() error {
	return errors.New("SIP URI is empty")
}

func errUnsupportedSIPURI(uri string) error {
	return fmt.Errorf("unsupported SIP URI %q", uri)
}

func errInvalidSIPURIHost(uri string) error {
	return fmt.Errorf("invalid SIP URI host %q", uri)
}

func errSIPURIHostEmpty(uri string) error {
	return fmt.Errorf("SIP URI host is empty: %q", uri)
}
