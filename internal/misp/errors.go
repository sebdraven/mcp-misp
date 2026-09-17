package misp

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Kind separates the diagnoses an operator actually has to act on. "The
// instance said no" and "the instance said nothing in time" call for different
// work, and collapsing them into one error string costs an hour every time.
type Kind string

const (
	KindUnknown     Kind = "unknown"
	KindRefused     Kind = "refused_by_instance"
	KindNotFound    Kind = "not_found"
	KindRateLimited Kind = "rate_limited"
	KindInstanceErr Kind = "instance_error"
	KindTimeout     Kind = "instance_timeout"
	KindUnreachable Kind = "instance_unreachable"
	KindTLS         Kind = "tls_error"
	KindCanceled    Kind = "canceled"
	KindTooLarge    Kind = "response_too_large"
	KindMalformed   Kind = "malformed_response"
)

type kinder interface{ ErrorKind() Kind }

// APIError is a non-2xx answer: the instance was reached and refused.
type APIError struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration

	kind Kind
}

func (e *APIError) ErrorKind() Kind { return e.kind }

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "misp: %s (http %d", e.kind, e.Status)
	if e.Code != "" {
		fmt.Fprintf(&b, " %s", e.Code)
	}
	b.WriteString(")")
	if e.Message != "" {
		fmt.Fprintf(&b, ": %s", e.Message)
	}
	return b.String()
}

// TransportError is a request that never produced an answer.
//
// It deliberately has no Unwrap: the original error carries the request URL and
// whatever the TLS stack put in its message, and the only copy this type keeps
// has already been through Redact. Nothing downstream can reach around it.
type TransportError struct {
	Op      string
	Message string

	kind Kind
}

func (e *TransportError) ErrorKind() Kind { return e.kind }

func (e *TransportError) Error() string {
	return fmt.Sprintf("misp: %s during %s: %s", e.kind, e.Op, e.Message)
}

// ErrorKind classifies err, returning KindUnknown for anything not produced by
// this package.
func ErrorKind(err error) Kind {
	var k kinder
	if errors.As(err, &k) {
		return k.ErrorKind()
	}
	if err == nil {
		return ""
	}
	return KindUnknown
}

func NotFound(err error) bool { return ErrorKind(err) == KindNotFound }

// Refused reports whether the instance answered and declined.
func Refused(err error) bool {
	switch ErrorKind(err) {
	case KindRefused, KindRateLimited, KindNotFound, KindInstanceErr:
		return true
	}
	return false
}

// Unreachable reports whether the instance failed to answer at all.
func Unreachable(err error) bool {
	switch ErrorKind(err) {
	case KindTimeout, KindUnreachable, KindTLS:
		return true
	}
	return false
}

// Redact removes secrets from a string before it reaches a log, an error or a
// tool result.
func Redact(s string, secrets ...string) string {
	for _, sec := range secrets {
		if sec == "" {
			continue
		}
		s = strings.ReplaceAll(s, sec, "[redacted]")
	}
	return s
}

func kindForStatus(status int) Kind {
	switch {
	case status == 404:
		return KindNotFound
	case status == 429:
		return KindRateLimited
	case status >= 500:
		return KindInstanceErr
	case status >= 400:
		return KindRefused
	}
	return KindUnknown
}

// retryable covers the failures where the same request later has a real chance
// of succeeding.
//
// Timeouts are excluded on purpose: replaying a slow query against a loaded
// instance multiplies the wait without changing the outcome. So is a bare 500,
// which MISP also returns for a query it cannot make sense of — only the
// gateway statuses, which say "not now" rather than "not this".
func retryable(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case 429, 502, 503, 504:
			return true
		}
		return false
	}
	return ErrorKind(err) == KindUnreachable
}
