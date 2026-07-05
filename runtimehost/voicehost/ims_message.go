package voicehost

import "context"

type IMSMessageRequest struct {
	URI         string
	FromURI     string
	ToURI       string
	CallID      string
	CSeq        int
	ContentType string
	Body        []byte
	Headers     map[string][]string
}

type IMSMessageResult struct {
	StatusCode  int
	Reason      string
	ContentType string
	Body        []byte
	Headers     map[string]string
}

type IMSMessageHandler interface {
	HandleIMSMessage(context.Context, IMSMessageRequest) (IMSMessageResult, error)
}

type IMSMessageHandlerFunc func(context.Context, IMSMessageRequest) (IMSMessageResult, error)

func (f IMSMessageHandlerFunc) HandleIMSMessage(ctx context.Context, req IMSMessageRequest) (IMSMessageResult, error) {
	return f(ctx, req)
}
