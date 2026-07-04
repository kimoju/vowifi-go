package e911

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/runtimehost/carrier"
)

var (
	ErrUnsupportedProvider     = errors.New("unsupported e911 provider")
	ErrChallengeNotImplemented = errors.New("e911 challenge not implemented")
	ErrWebsheetUnavailable     = errors.New("e911 websheet unavailable")
)

type HeaderPair struct {
	Key   string
	Value string
}

type HTTPRequest struct {
	Method  string
	URL     string
	Headers []HeaderPair
	Body    []byte
}

type HTTPResponse struct {
	StatusCode int
	Body       []byte
}

type HTTPClient interface {
	Do(req *HTTPRequest) (*HTTPResponse, error)
}

type defaultHTTPClient struct {
	client *http.Client
}

func NewDefaultHTTPClient() HTTPClient {
	return defaultHTTPClient{client: http.DefaultClient}
}

func (c defaultHTTPClient) Do(req *HTTPRequest) (*HTTPResponse, error) {
	if req == nil {
		return nil, errors.New("nil request")
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	hreq, err := http.NewRequest(method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, err
	}
	for _, h := range req.Headers {
		hreq.Header.Add(h.Key, h.Value)
	}
	client := c.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return &HTTPResponse{StatusCode: resp.StatusCode, Body: body}, nil
}

type Identity struct {
	IMSI        string
	IMEI        string
	MCC         string
	MNC         string
	SIPUsername string
	DisplayName string
	CachedToken string
}

type TraceSink interface {
	Request(*HTTPRequest)
	Response(*HTTPRequest, *HTTPResponse)
	Error(*HTTPRequest, error)
}

type Request struct {
	Carrier     carrier.EffectiveCarrierConfig
	Identity    Identity
	AKAProvider sim.AKAProvider
	Client      HTTPClient
	Trace       TraceSink
}

type WebsheetRequest struct {
	URL         string
	UserData    string
	ContentType string
	Title       string
}

func StartEmergencyAddressUpdate(ctx context.Context, req Request) (WebsheetRequest, error) {
	if req.Carrier.E911.Provider == "" {
		return WebsheetRequest{}, ErrUnsupportedProvider
	}
	if req.Carrier.E911.Websheet == "" {
		return WebsheetRequest{}, ErrWebsheetUnavailable
	}
	return WebsheetRequest{
		URL:         req.Carrier.E911.Websheet,
		ContentType: "text/html",
		Title:       "Emergency address",
	}, nil
}
