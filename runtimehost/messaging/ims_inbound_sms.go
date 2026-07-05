package messaging

import (
	"context"
	"errors"
	"strings"
	"time"
)

type IMSMessageRequest struct {
	FromURI     string
	ToURI       string
	CallID      string
	CSeq        int
	ContentType string
	Body        []byte
	Headers     map[string][]string
}

type IMSMessageResult struct {
	StatusCode         int
	Reason             string
	RPDU               SMSRPDU
	Incoming           *IncomingSMS
	DeliveryReport     *SMSDeliveryReport
	ReplyContentType   string
	ReplyBody          []byte
	UnsupportedContent bool
}

func (s *Service) HandleIMSMessage(ctx context.Context, msg IMSMessageRequest) (IMSMessageResult, error) {
	contentType := strings.ToLower(strings.TrimSpace(msg.ContentType))
	if semi := strings.IndexByte(contentType, ';'); semi >= 0 {
		contentType = strings.TrimSpace(contentType[:semi])
	}
	switch contentType {
	case "", "text/plain":
		incoming := IncomingSMS{
			Sender:    firstNonEmpty(msg.FromURI, "unknown"),
			Recipient: msg.ToURI,
			Content:   strings.ToValidUTF8(string(msg.Body), ""),
		}
		if err := s.HandleIncomingSMS(ctx, incoming); err != nil {
			return IMSMessageResult{StatusCode: 400, Reason: err.Error(), Incoming: &incoming}, err
		}
		return IMSMessageResult{StatusCode: 200, Reason: "OK", Incoming: &incoming}, nil
	case IMS3GPPSMSContentType:
		return s.handleIMS3GPPSMS(ctx, msg)
	default:
		err := errors.New("unsupported IMS MESSAGE content type")
		return IMSMessageResult{StatusCode: 415, Reason: err.Error(), UnsupportedContent: true}, err
	}
}

func (s *Service) handleIMS3GPPSMS(ctx context.Context, msg IMSMessageRequest) (IMSMessageResult, error) {
	rpdu, err := ParseSMSRPDU(msg.Body)
	if err != nil {
		return IMSMessageResult{StatusCode: 400, Reason: err.Error()}, err
	}
	out := IMSMessageResult{StatusCode: 200, Reason: "OK", RPDU: rpdu}
	switch rpdu.Kind {
	case SMSRPDUKindData:
		return s.handleIMSRPData(ctx, msg, rpdu, out)
	case SMSRPDUKindAck:
		report := SMSDeliveryReport{
			CallID:   msg.CallID,
			RPMR:     int(rpdu.MR),
			State:    "delivered",
			SIPCode:  200,
			ReportAt: time.Time{},
		}
		_, err := s.HandleSMSDeliveryReport(ctx, report)
		out.DeliveryReport = &report
		if err != nil && !errors.Is(err, ErrDeliveryNotFound) {
			out.StatusCode = 500
			out.Reason = err.Error()
			return out, err
		}
		return out, nil
	case SMSRPDUKindError:
		report := SMSDeliveryReport{
			CallID:    msg.CallID,
			RPMR:      int(rpdu.MR),
			State:     "failed",
			SIPCode:   200,
			RPCause:   rpdu.Cause,
			ErrorText: RPCauseText(rpdu.Cause),
			ReportAt:  time.Time{},
		}
		_, err := s.HandleSMSDeliveryReport(ctx, report)
		out.DeliveryReport = &report
		if err != nil && !errors.Is(err, ErrDeliveryNotFound) {
			out.StatusCode = 500
			out.Reason = err.Error()
			return out, err
		}
		return out, nil
	default:
		err := errors.New("unsupported IMS SMS RPDU kind")
		out.StatusCode = 400
		out.Reason = err.Error()
		return out, err
	}
}

func (s *Service) handleIMSRPData(ctx context.Context, msg IMSMessageRequest, rpdu SMSRPDU, out IMSMessageResult) (IMSMessageResult, error) {
	if len(rpdu.TPDU) == 0 {
		err := errors.New("IMS SMS RP-DATA has no TPDU")
		out.StatusCode = 400
		out.Reason = err.Error()
		out.ReplyContentType = IMS3GPPSMSContentType
		out.ReplyBody = BuildSMSRPError(rpdu.MR, SMSRPCauseTemporaryFailure)
		return out, err
	}
	switch rpdu.TPDU[0] & 0x03 {
	case 0x00:
		deliver, err := ParseSMSDeliverTPDU(rpdu.TPDU)
		if err != nil {
			out.StatusCode = 400
			out.Reason = err.Error()
			out.ReplyContentType = IMS3GPPSMSContentType
			out.ReplyBody = BuildSMSRPError(rpdu.MR, SMSRPCauseTemporaryFailure)
			return out, err
		}
		incoming := IncomingSMS{
			Sender:    firstNonEmpty(deliver.Sender, rpdu.Originator, msg.FromURI),
			Recipient: firstNonEmpty(deliver.Recipient, rpdu.Destination, msg.ToURI),
			Content:   deliver.Text,
			Timestamp: deliver.Timestamp,
		}
		if err := s.HandleIncomingSMS(ctx, incoming); err != nil {
			out.StatusCode = 400
			out.Reason = err.Error()
			out.Incoming = &incoming
			out.ReplyContentType = IMS3GPPSMSContentType
			out.ReplyBody = BuildSMSRPError(rpdu.MR, SMSRPCauseTemporaryFailure)
			return out, err
		}
		out.Incoming = &incoming
		out.ReplyContentType = IMS3GPPSMSContentType
		out.ReplyBody = BuildSMSRPAck(rpdu.MR)
		return out, nil
	case 0x02:
		reportTPDU, err := ParseSMSStatusReportTPDU(rpdu.TPDU)
		if err != nil {
			out.StatusCode = 400
			out.Reason = err.Error()
			out.ReplyContentType = IMS3GPPSMSContentType
			out.ReplyBody = BuildSMSRPError(rpdu.MR, SMSRPCauseTemporaryFailure)
			return out, err
		}
		report := SMSDeliveryReport{
			CallID:    msg.CallID,
			RPMR:      int(reportTPDU.Reference),
			State:     reportTPDU.State,
			SIPCode:   200,
			RPCause:   int(reportTPDU.Status),
			ReportAt:  reportTPDU.DoneAt,
			ErrorText: smsStatusReportError(reportTPDU),
		}
		_, err = s.HandleSMSDeliveryReport(ctx, report)
		out.DeliveryReport = &report
		out.ReplyContentType = IMS3GPPSMSContentType
		out.ReplyBody = BuildSMSRPAck(rpdu.MR)
		if err != nil && !errors.Is(err, ErrDeliveryNotFound) {
			out.StatusCode = 500
			out.Reason = err.Error()
			return out, err
		}
		return out, nil
	default:
		err := errors.New("unsupported IMS SMS TPDU type")
		out.StatusCode = 400
		out.Reason = err.Error()
		out.ReplyContentType = IMS3GPPSMSContentType
		out.ReplyBody = BuildSMSRPError(rpdu.MR, SMSRPCauseTemporaryFailure)
		return out, err
	}
}

func smsStatusReportError(report SMSStatusReport) string {
	if report.State != "failed" {
		return ""
	}
	return "SMS status report 0x" + strings.ToUpper(hexByte(report.Status))
}

func hexByte(v byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[v>>4], digits[v&0x0f]})
}
