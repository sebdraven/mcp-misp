// Package misp is a hand-written client for the MISP REST API.
//
// It covers the endpoints this server needs and nothing else. The existing Go
// MISP libraries were not reused: they stop at search, and the parts that
// matter here — warninglist evaluation, paginated restSearch, sighting-bearing
// attribute lookups — are exactly the parts they do not implement.
package misp

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	defaultTimeout     = 60 * time.Second
	defaultRetries     = 3
	defaultConcurrency = 4
	defaultBackoff     = 500 * time.Millisecond
	userAgent          = "mcp-misp"

	// maxBody caps what a single response may pull into memory. A MISP event
	// with a five-figure attribute count is a real thing, and the point of the
	// cap is to fail with a message that says "lower the limit" rather than to
	// take the process down.
	maxBody = 64 << 20
)

type Client struct {
	baseURL string
	key     string

	http        *http.Client
	sem         chan struct{}
	retries     int
	backoffBase time.Duration

	timeout     time.Duration
	insecure    bool
	concurrency int
	maxBody     int64
}

type Option func(*Client)

// WithTimeout bounds a single attempt, not the whole retried sequence.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithInsecureSkipVerify disables certificate verification. Reachable only
// through MISP_VERIFY_SSL=false, which warns at startup.
func WithInsecureSkipVerify(v bool) Option {
	return func(c *Client) { c.insecure = v }
}

func WithMaxConcurrency(n int) Option {
	return func(c *Client) {
		if n > 0 {
			c.concurrency = n
		}
	}
}

func WithRetries(n int) Option {
	return func(c *Client) {
		if n >= 0 {
			c.retries = n
		}
	}
}

// WithHTTPClient replaces the whole transport; WithTimeout and
// WithInsecureSkipVerify no longer apply.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.http = h
		}
	}
}

func withBackoffBase(d time.Duration) Option {
	return func(c *Client) { c.backoffBase = d }
}

func withMaxBody(n int64) Option {
	return func(c *Client) {
		if n > 0 {
			c.maxBody = n
		}
	}
}

func New(baseURL, key string, opts ...Option) *Client {
	c := &Client{
		baseURL:     strings.TrimRight(baseURL, "/"),
		key:         key,
		timeout:     defaultTimeout,
		retries:     defaultRetries,
		concurrency: defaultConcurrency,
		backoffBase: defaultBackoff,
		maxBody:     maxBody,
	}
	for _, o := range opts {
		o(c)
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: c.timeout, Transport: newTransport(c.insecure)}
	}
	c.sem = make(chan struct{}, max(1, c.concurrency))
	return c
}

// BaseURL is the normalised instance root, safe to log.
func (c *Client) BaseURL() string { return c.baseURL }

func (c *Client) scrub(s string) string { return Redact(s, c.key) }

func newTransport(insecure bool) http.RoundTripper {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return http.DefaultTransport
	}
	t = t.Clone()
	t.MaxIdleConnsPerHost = 8
	t.ForceAttemptHTTP2 = true
	if insecure {
		if t.TLSClientConfig == nil {
			t.TLSClientConfig = &tls.Config{}
		}
		t.TLSClientConfig.InsecureSkipVerify = true
	}
	t.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	return t
}
