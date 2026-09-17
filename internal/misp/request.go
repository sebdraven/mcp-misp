package misp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type reqOpts struct {
	query url.Values
	body  any
	// idempotent gates retries. Writes never set it, so a create that timed out
	// halfway is never replayed into a duplicate.
	idempotent bool
}

func (c *Client) get(ctx context.Context, path string, query url.Values) (json.RawMessage, error) {
	return c.do(ctx, http.MethodGet, path, reqOpts{query: query, idempotent: true})
}

func (c *Client) post(ctx context.Context, path string, body any, idempotent bool) (json.RawMessage, error) {
	return c.do(ctx, http.MethodPost, path, reqOpts{body: body, idempotent: idempotent})
}

func (c *Client) do(ctx context.Context, method, path string, o reqOpts) (json.RawMessage, error) {
	var payload []byte
	if o.body != nil {
		var err error
		if payload, err = json.Marshal(o.body); err != nil {
			return nil, fmt.Errorf("misp: encoding request body: %w", err)
		}
	}

	attempts := 1
	if o.idempotent {
		attempts += c.retries
	}

	var lastErr error
	for attempt := range attempts {
		raw, err := c.attempt(ctx, method, path, o.query, payload)
		if err == nil {
			return raw, nil
		}
		lastErr = err
		if attempt == attempts-1 || !retryable(err) {
			return nil, err
		}
		if err := sleepCtx(ctx, c.backoffFor(err, attempt)); err != nil {
			return nil, c.transportErr(method+" "+path, err)
		}
	}
	return nil, lastErr
}

func (c *Client) attempt(ctx context.Context, method, path string, query url.Values, payload []byte) (json.RawMessage, error) {
	op := method + " " + path

	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, c.transportErr(op, ctx.Err())
	}
	defer func() { <-c.sem }()

	endpoint := c.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, c.transportErr(op, err)
	}
	req.Header.Set("Authorization", c.key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, c.transportErr(op, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return nil, c.transportErr(op, err)
	}
	if int64(len(raw)) > c.maxBody {
		return nil, &APIError{
			Status:  resp.StatusCode,
			kind:    KindTooLarge,
			Message: fmt.Sprintf("the instance returned more than %d bytes for %s; narrow the query or lower the limit", c.maxBody, op),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, c.apiErr(resp, raw)
	}
	return json.RawMessage(raw), nil
}

func (c *Client) apiErr(resp *http.Response, raw []byte) error {
	e := &APIError{
		Status:     resp.StatusCode,
		kind:       kindForStatus(resp.StatusCode),
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
	}
	e.Code, e.Message = c.parseErrorBody(raw)
	if e.Message == "" {
		e.Message = c.scrub(strings.TrimSpace(firstLine(string(raw), 200)))
	}
	return e
}

// parseErrorBody reads MISP's error envelope, which comes in several shapes
// depending on the endpoint and the version.
func (c *Client) parseErrorBody(raw []byte) (code, message string) {
	var env struct {
		Name    string          `json:"name"`
		Message string          `json:"message"`
		URL     string          `json:"url"`
		Errors  json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return "", ""
	}
	code = env.Message
	message = env.Name
	if len(env.Errors) > 0 {
		var s string
		if json.Unmarshal(env.Errors, &s) == nil && s != "" {
			message = joinNonEmpty(message, s)
		} else {
			message = joinNonEmpty(message, firstLine(string(env.Errors), 300))
		}
	}
	return c.scrub(code), c.scrub(message)
}

func (c *Client) transportErr(op string, err error) error {
	e := &TransportError{Op: op, Message: c.scrub(err.Error())}
	switch {
	case errors.Is(err, context.Canceled):
		e.kind = KindCanceled
	case errors.Is(err, context.DeadlineExceeded):
		e.kind = KindTimeout
	default:
		var ce *tls.CertificateVerificationError
		var ne net.Error
		switch {
		case errors.As(err, &ce):
			e.kind = KindTLS
			e.Message += " (set MISP_VERIFY_SSL=false only if this instance uses a certificate you trust out of band)"
		case errors.As(err, &ne) && ne.Timeout():
			e.kind = KindTimeout
		default:
			e.kind = KindUnreachable
		}
	}
	return e
}

// backoffFor honours Retry-After when the instance sends one, and otherwise
// backs off exponentially with jitter so parallel callers do not resynchronise
// onto the same retry instant.
func (c *Client) backoffFor(err error, attempt int) time.Duration {
	var ae *APIError
	if errors.As(err, &ae) && ae.RetryAfter > 0 {
		return min(ae.RetryAfter, 60*time.Second)
	}
	d := c.backoffBase << attempt
	d += rand.N(d/2 + 1)
	return min(d, 30*time.Second)
}

func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func firstLine(s string, limit int) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > limit {
		s = s[:limit] + "..."
	}
	return s
}

func joinNonEmpty(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ": ")
}
