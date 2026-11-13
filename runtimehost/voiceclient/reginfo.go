package voiceclient

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const RegInfoXMLNamespace = "urn:ietf:params:xml:ns:reginfo"

var ErrInvalidRegInfoXML = errors.New("invalid RFC 3680 reginfo XML")

// RegInfoDocument models an RFC 3680 application/reginfo+xml document.
type RegInfoDocument struct {
	XMLName       xml.Name              `xml:"reginfo"`
	Version       int                   `xml:"version,attr"`
	HasVersion    bool                  `xml:"-"`
	State         string                `xml:"state,attr"`
	Registrations []RegInfoRegistration `xml:"registration"`
}

type RegInfoRegistration struct {
	AOR      string           `xml:"aor,attr"`
	ID       string           `xml:"id,attr"`
	State    string           `xml:"state,attr"`
	Contacts []RegInfoContact `xml:"contact"`
}

type RegInfoContact struct {
	ID                 string         `xml:"id,attr"`
	State              string         `xml:"state,attr"`
	Event              string         `xml:"event,attr"`
	Expires            *int           `xml:"expires,attr"`
	RetryAfter         *int           `xml:"retry-after,attr"`
	DurationRegistered *int           `xml:"duration-registered,attr"`
	Q                  string         `xml:"q,attr"`
	CallID             string         `xml:"callid,attr"`
	CSeq               *int           `xml:"cseq,attr"`
	URI                string         `xml:"uri"`
	DisplayName        string         `xml:"display-name"`
	UnknownParams      []RegInfoParam `xml:"unknown-param"`
}

type RegInfoParam struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// SubscriptionStateInfo models a parsed RFC 6665 Subscription-State header.
type SubscriptionStateInfo struct {
	State      string
	Reason     string
	Expires    int
	HasExpires bool
	RetryAfter time.Duration
	HasRetry   bool
}

type RegEventAction string

const (
	RegEventActionNone        RegEventAction = "none"
	RegEventActionReRegister  RegEventAction = "re_register"
	RegEventActionResubscribe RegEventAction = "resubscribe"
	RegEventActionHalt        RegEventAction = "halt"
)

// RegEventEvaluation summarizes how IMS registration maintenance should react
// to an inbound Event: reg NOTIFY request.
type RegEventEvaluation struct {
	Action           RegEventAction
	Reason           string
	RetryAfter       time.Duration
	ShortenedExpires int
	Version          int
	HasVersion       bool
}

// ParseRegInfoXML parses an RFC 3680 application/reginfo+xml body.
func ParseRegInfoXML(raw []byte) (RegInfoDocument, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return RegInfoDocument{}, fmt.Errorf("%w: empty body", ErrInvalidRegInfoXML)
	}
	dec := xml.NewDecoder(bytes.NewReader(trimmed))
	dec.Strict = false
	var start xml.StartElement
	found := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return RegInfoDocument{}, fmt.Errorf("%w: %v", ErrInvalidRegInfoXML, err)
		}
		if se, ok := tok.(xml.StartElement); ok {
			start = se
			found = true
			break
		}
	}
	if !found || !strings.EqualFold(start.Name.Local, "reginfo") {
		return RegInfoDocument{}, fmt.Errorf("%w: root element is not <reginfo>", ErrInvalidRegInfoXML)
	}
	if start.Name.Space != "" && !strings.EqualFold(start.Name.Space, RegInfoXMLNamespace) {
		return RegInfoDocument{}, fmt.Errorf("%w: unexpected namespace %q", ErrInvalidRegInfoXML, start.Name.Space)
	}
	var doc RegInfoDocument
	if err := dec.DecodeElement(&doc, &start); err != nil {
		return RegInfoDocument{}, fmt.Errorf("%w: %v", ErrInvalidRegInfoXML, err)
	}
	for _, attr := range start.Attr {
		if strings.EqualFold(attr.Name.Local, "version") {
			v, err := strconv.Atoi(strings.TrimSpace(attr.Value))
			if err != nil || v < 0 {
				return RegInfoDocument{}, fmt.Errorf("%w: invalid reginfo version %q", ErrInvalidRegInfoXML, attr.Value)
			}
			doc.Version = v
			doc.HasVersion = true
		}
	}
	doc.State = strings.ToLower(strings.TrimSpace(doc.State))
	if doc.State != "" && doc.State != "full" && doc.State != "partial" {
		return RegInfoDocument{}, fmt.Errorf("%w: invalid reginfo state %q", ErrInvalidRegInfoXML, doc.State)
	}
	for i := range doc.Registrations {
		doc.Registrations[i].AOR = strings.TrimSpace(doc.Registrations[i].AOR)
		doc.Registrations[i].State = strings.ToLower(strings.TrimSpace(doc.Registrations[i].State))
		for j := range doc.Registrations[i].Contacts {
			c := &doc.Registrations[i].Contacts[j]
			c.State = strings.ToLower(strings.TrimSpace(c.State))
			c.Event = strings.ToLower(strings.TrimSpace(c.Event))
			c.URI = strings.TrimSpace(c.URI)
			c.DisplayName = strings.TrimSpace(c.DisplayName)
		}
	}
	return doc, nil
}

// ParseSubscriptionStateHeader parses an RFC 6665 Subscription-State header value.
func ParseSubscriptionStateHeader(value string) (SubscriptionStateInfo, error) {
	parts := splitSIPHeaderParams(strings.TrimSpace(value))
	if len(parts) == 0 {
		return SubscriptionStateInfo{}, fmt.Errorf("%w: empty Subscription-State", ErrInvalidSIPMessage)
	}
	state := strings.ToLower(strings.TrimSpace(parts[0]))
	if state == "" {
		return SubscriptionStateInfo{}, fmt.Errorf("%w: empty Subscription-State", ErrInvalidSIPMessage)
	}
	info := SubscriptionStateInfo{State: state}
	for _, param := range parts[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(param), "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(unquote(strings.TrimSpace(v)))
		switch k {
		case "reason":
			info.Reason = strings.ToLower(v)
		case "expires":
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				info.Expires = n
				info.HasExpires = true
			}
		case "retry-after":
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				info.RetryAfter = time.Duration(n) * time.Second
				info.HasRetry = true
			}
		}
	}
	return info, nil
}

// EvaluateRegEventNotify evaluates an RFC 3680 / 3GPP TS 24.229 §5.1.1.3 reg
// event notification against the local UE Contact URI.
func EvaluateRegEventNotify(subState SubscriptionStateInfo, doc *RegInfoDocument, localContactURI string) RegEventEvaluation {
	out := RegEventEvaluation{Action: RegEventActionNone}
	if doc != nil {
		out.Version = doc.Version
		out.HasVersion = doc.HasVersion

		targetContact := normalizeSIPURIForContactMatch(localContactURI)
		targetUserHost := normalizeSIPURIUserHostForContactMatch(localContactURI)

		for _, reg := range doc.Registrations {
			matchedAny := false
			for _, contact := range reg.Contacts {
				if !regInfoContactMatches(contact.URI, targetContact, targetUserHost) {
					continue
				}
				matchedAny = true
				if eval, terminal := evaluateRegInfoContact(contact); terminal {
					eval.Version = out.Version
					eval.HasVersion = out.HasVersion
					return eval
				} else if eval.ShortenedExpires > 0 && (out.ShortenedExpires == 0 || eval.ShortenedExpires < out.ShortenedExpires) {
					out.ShortenedExpires = eval.ShortenedExpires
					out.Reason = eval.Reason
				}
			}
			// If the entire registration AOR is terminated and either no contacts
			// were listed or our contact was not kept active, evaluate termination.
			if reg.State == "terminated" {
				if !matchedAny && len(reg.Contacts) > 0 {
					// Check if any contact carries an explicit terminal event.
					for _, contact := range reg.Contacts {
						if eval, terminal := evaluateRegInfoContact(contact); terminal {
							eval.Version = out.Version
							eval.HasVersion = out.HasVersion
							return eval
						}
					}
				}
				return RegEventEvaluation{
					Action:     RegEventActionReRegister,
					Reason:     "reg-event registration state=terminated",
					Version:    out.Version,
					HasVersion: out.HasVersion,
				}
			}
		}
	}

	if subState.State == "terminated" {
		switch subState.Reason {
		case "rejected", "noresource":
			return RegEventEvaluation{
				Action:     RegEventActionHalt,
				Reason:     "reg-event subscription terminated: " + subState.Reason,
				Version:    out.Version,
				HasVersion: out.HasVersion,
			}
		case "deactivated":
			return RegEventEvaluation{
				Action:     RegEventActionReRegister,
				Reason:     "reg-event subscription deactivated",
				Version:    out.Version,
				HasVersion: out.HasVersion,
			}
		case "probation", "giveup":
			return RegEventEvaluation{
				Action:     RegEventActionReRegister,
				Reason:     "reg-event subscription " + subState.Reason,
				RetryAfter: subState.RetryAfter,
				Version:    out.Version,
				HasVersion: out.HasVersion,
			}
		case "timeout":
			return RegEventEvaluation{
				Action:     RegEventActionResubscribe,
				Reason:     "reg-event subscription timeout",
				Version:    out.Version,
				HasVersion: out.HasVersion,
			}
		default:
			return RegEventEvaluation{
				Action:     RegEventActionReRegister,
				Reason:     firstNonEmpty("reg-event subscription terminated: "+subState.Reason, "reg-event subscription terminated"),
				RetryAfter: subState.RetryAfter,
				Version:    out.Version,
				HasVersion: out.HasVersion,
			}
		}
	}
	return out
}

func regInfoContactMatches(contactURI, targetContact, targetUserHost string) bool {
	contactURI = strings.TrimSpace(contactURI)
	if contactURI == "" {
		return true
	}
	if targetContact == "" {
		return true
	}
	if normalizeSIPURIForContactMatch(contactURI) == targetContact {
		return true
	}
	if targetUserHost != "" && normalizeSIPURIUserHostForContactMatch(contactURI) == targetUserHost {
		return true
	}
	return false
}

func evaluateRegInfoContact(c RegInfoContact) (RegEventEvaluation, bool) {
	var retryAfter time.Duration
	if c.RetryAfter != nil && *c.RetryAfter > 0 {
		retryAfter = time.Duration(*c.RetryAfter) * time.Second
	}
	if c.State == "terminated" {
		switch c.Event {
		case "rejected", "unregistered":
			return RegEventEvaluation{
				Action: RegEventActionHalt,
				Reason: "reg-event contact " + c.Event,
			}, true
		case "probation":
			return RegEventEvaluation{
				Action:     RegEventActionReRegister,
				Reason:     "reg-event contact probation",
				RetryAfter: retryAfter,
			}, true
		case "deactivated", "expired", "":
			ev := c.Event
			if ev == "" {
				ev = "terminated"
			}
			return RegEventEvaluation{
				Action:     RegEventActionReRegister,
				Reason:     "reg-event contact " + ev,
				RetryAfter: retryAfter,
			}, true
		default:
			return RegEventEvaluation{
				Action:     RegEventActionReRegister,
				Reason:     "reg-event contact " + c.Event,
				RetryAfter: retryAfter,
			}, true
		}
	}
	if c.State == "active" && c.Expires != nil && *c.Expires > 0 {
		return RegEventEvaluation{
			Action:           RegEventActionNone,
			Reason:           firstNonEmpty(c.Event, "active"),
			ShortenedExpires: *c.Expires,
		}, false
	}
	return RegEventEvaluation{Action: RegEventActionNone}, false
}
