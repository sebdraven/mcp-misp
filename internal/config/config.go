// Package config assembles the whole server configuration from the environment.
//
// Every ambiguous value is a startup failure rather than a default: this server
// runs against other people's MISP instances, and silently falling back to
// read-write or to a public listener is not a recoverable mistake.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultTransport = "stdio"
	DefaultHTTPAddr  = "127.0.0.1:8080"
	DefaultTimeout   = 60 * time.Second
)

// Caps are the hard ceilings the tools enforce. MISP_MAX_RESULTS can only lower
// them.
type Caps struct {
	SearchDefault  int
	SearchMax      int
	AttrDefault    int
	AttrMax        int
	ContextDefault int
	ContextMax     int
	CheckValues    int
	ResponseBytes  int

	// Write-path ceilings. MISP_MAX_RESULTS does not touch these: it bounds how
	// much comes back, which is a different question from how much one call may
	// push into somebody's instance.
	ObjectsPerBatch    int
	ValuesPerObject    int
	ReferencesPerBatch int
}

func defaultCaps() Caps {
	return Caps{
		SearchDefault:  50,
		SearchMax:      500,
		AttrDefault:    100,
		AttrMax:        1000,
		ContextDefault: 20,
		ContextMax:     200,
		CheckValues:    1000,
		ResponseBytes:  256 << 10,

		ObjectsPerBatch:    50,
		ValuesPerObject:    128,
		ReferencesPerBatch: 256,
	}
}

// Warninglists configures the local fallback engine only. The nominal path
// delegates matching to the instance and needs none of this.
type Warninglists struct {
	MaxEntries    int
	TTL           time.Duration
	LocalFallback bool
}

type Config struct {
	URL       string
	VerifySSL bool
	Timeout   time.Duration
	ReadOnly  bool

	OutRoot string

	MaxConcurrency int
	MaxRetries     int

	Transport       string
	HTTPAddr        string
	AllowPublicBind bool

	Caps         Caps
	Warninglists Warninglists

	// Warnings are conditions that are legal but worth saying out loud once,
	// at startup, on stderr.
	Warnings []string

	key string
}

// Key returns the API key. It is unexported on the struct so that no accidental
// marshalling of a Config can carry it out of the process.
func (c *Config) Key() string { return c.key }

func (c *Config) String() string {
	return fmt.Sprintf("misp=%s readonly=%t verify_ssl=%t timeout=%s transport=%s addr=%s key=[redacted]",
		c.URL, c.ReadOnly, c.VerifySSL, c.Timeout, c.Transport, c.HTTPAddr)
}

func Load() (*Config, error) {
	c := &Config{
		VerifySSL:      true,
		ReadOnly:       true,
		Timeout:        DefaultTimeout,
		MaxConcurrency: 4,
		MaxRetries:     3,
		Transport:      DefaultTransport,
		HTTPAddr:       DefaultHTTPAddr,
		Caps:           defaultCaps(),
		Warninglists: Warninglists{
			MaxEntries:    200_000,
			TTL:           6 * time.Hour,
			LocalFallback: true,
		},
	}

	raw := strings.TrimSpace(os.Getenv("MISP_URL"))
	if raw == "" {
		return nil, errors.New("MISP_URL is required")
	}
	base, insecureScheme, err := normaliseURL(raw)
	if err != nil {
		return nil, err
	}
	c.URL = base

	c.key = strings.TrimSpace(os.Getenv("MISP_KEY"))
	if c.key == "" {
		return nil, errors.New("MISP_KEY is required")
	}

	if c.VerifySSL, err = envBool("MISP_VERIFY_SSL", c.VerifySSL); err != nil {
		return nil, err
	}
	if c.ReadOnly, err = envBool("MISP_READONLY", c.ReadOnly); err != nil {
		return nil, err
	}
	if c.Timeout, err = envDuration("MISP_TIMEOUT", c.Timeout); err != nil {
		return nil, err
	}
	if c.Timeout <= 0 {
		return nil, fmt.Errorf("MISP_TIMEOUT must be positive, got %s", c.Timeout)
	}
	if c.MaxConcurrency, err = envInt("MISP_MAX_CONCURRENCY", c.MaxConcurrency, 1, 64); err != nil {
		return nil, err
	}
	if c.MaxRetries, err = envInt("MISP_MAX_RETRIES", c.MaxRetries, 0, 10); err != nil {
		return nil, err
	}
	if c.AllowPublicBind, err = envBool("MISP_ALLOW_PUBLIC_BIND", false); err != nil {
		return nil, err
	}
	if c.Warninglists.MaxEntries, err = envInt("MISP_WARNINGLIST_MAX_ENTRIES", c.Warninglists.MaxEntries, 0, 20_000_000); err != nil {
		return nil, err
	}
	if c.Warninglists.TTL, err = envDuration("MISP_WARNINGLIST_TTL", c.Warninglists.TTL); err != nil {
		return nil, err
	}
	if c.Warninglists.LocalFallback, err = envBool("MISP_WARNINGLIST_LOCAL_FALLBACK", true); err != nil {
		return nil, err
	}

	if c.OutRoot, err = outRoot(); err != nil {
		return nil, err
	}

	if v := strings.TrimSpace(os.Getenv("MCP_TRANSPORT")); v != "" {
		c.Transport = strings.ToLower(v)
	}
	switch c.Transport {
	case "stdio", "http":
	default:
		return nil, fmt.Errorf("MCP_TRANSPORT %q: want stdio or http", c.Transport)
	}
	if v := strings.TrimSpace(os.Getenv("MCP_HTTP_ADDR")); v != "" {
		c.HTTPAddr = v
	}

	if max, ok, err := envIntOpt("MISP_MAX_RESULTS", 1, 100_000); err != nil {
		return nil, err
	} else if ok {
		c.Caps.lower(max)
	}

	if c.Transport == "http" {
		if err := checkBind(c.HTTPAddr, c.AllowPublicBind); err != nil {
			return nil, err
		}
		if c.AllowPublicBind && !isLoopbackHost(hostOf(c.HTTPAddr)) {
			c.Warnings = append(c.Warnings,
				"MISP_ALLOW_PUBLIC_BIND=true: the listener is reachable beyond loopback and this server has no authentication of its own")
		}
	}
	if !c.VerifySSL {
		c.Warnings = append(c.Warnings,
			"MISP_VERIFY_SSL=false: the instance certificate is not verified, so the API key is exposed to anyone able to intercept the connection")
	}
	if insecureScheme {
		c.Warnings = append(c.Warnings,
			"MISP_URL uses plain HTTP to a non-loopback host: the API key travels unencrypted")
	}
	if !c.ReadOnly {
		c.Warnings = append(c.Warnings,
			"MISP_READONLY=false: the write tools are registered (attribute creation, tagging)")
	}

	return c, nil
}

// lower applies MISP_MAX_RESULTS. It never raises a ceiling: an operator can
// make this server less greedy than it ships, not more.
func (c *Caps) lower(max int) {
	c.SearchMax = min(c.SearchMax, max)
	c.AttrMax = min(c.AttrMax, max)
	c.ContextMax = min(c.ContextMax, max)
	c.SearchDefault = min(c.SearchDefault, c.SearchMax)
	c.AttrDefault = min(c.AttrDefault, c.AttrMax)
	c.ContextDefault = min(c.ContextDefault, c.ContextMax)
}

// normaliseURL reports, alongside the cleaned root, whether the scheme leaves
// the key in clear on the wire to somewhere other than this machine.
func normaliseURL(raw string) (string, bool, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false, fmt.Errorf("MISP_URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return "", false, fmt.Errorf("MISP_URL %q: want an http or https URL", raw)
	}
	if u.Host == "" {
		return "", false, fmt.Errorf("MISP_URL %q: no host", raw)
	}
	if u.User != nil {
		return "", false, errors.New("MISP_URL must not carry credentials; use MISP_KEY")
	}
	u.RawQuery, u.Fragment = "", ""
	u.Path = strings.TrimRight(u.Path, "/")
	insecure := u.Scheme == "http" && !isLoopbackHost(u.Hostname())
	return u.String(), insecure, nil
}

func outRoot() (string, error) {
	v := strings.TrimSpace(os.Getenv("MISP_OUT_ROOT"))
	if v == "" {
		v = filepath.Join(os.TempDir(), "mcp-misp")
	}
	abs, err := filepath.Abs(v)
	if err != nil {
		return "", fmt.Errorf("MISP_OUT_ROOT %q: %w", v, err)
	}
	return filepath.Clean(abs), nil
}

func checkBind(addr string, allow bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("MCP_HTTP_ADDR %q: want host:port, e.g. 127.0.0.1:8080", addr)
	}
	if port == "" {
		return fmt.Errorf("MCP_HTTP_ADDR %q: no port", addr)
	}
	if allow || isLoopbackHost(host) {
		return nil
	}
	return fmt.Errorf("MCP_HTTP_ADDR %q binds beyond loopback. This server has no authentication of its own "+
		"and holds a MISP API key that may be allowed to write, so anything able to reach the port holds that key. "+
		"Keep the listener on 127.0.0.1 and publish it with a reverse proxy or `tailscale serve`, "+
		"or set MISP_ALLOW_PUBLIC_BIND=true to accept the risk", addr)
}

func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// isLoopbackHost treats an empty host as non-loopback: ":8080" listens on every
// interface, which is precisely the accident this guard exists for.
func isLoopbackHost(h string) bool {
	switch h {
	case "":
		return false
	case "localhost":
		return true
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func envBool(key string, def bool) (bool, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	switch strings.ToLower(v) {
	case "1", "t", "true", "y", "yes", "on":
		return true, nil
	case "0", "f", "false", "n", "no", "off":
		return false, nil
	}
	return def, fmt.Errorf("%s=%q is not a boolean", key, v)
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d, nil
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return def, fmt.Errorf("%s=%q is not a duration (want 60s, 2m, or a number of seconds)", key, v)
}

func envInt(key string, def, lo, hi int) (int, error) {
	n, ok, err := envIntOpt(key, lo, hi)
	if err != nil || !ok {
		return def, err
	}
	return n, nil
}

func envIntOpt(key string, lo, hi int) (int, bool, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0, false, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false, fmt.Errorf("%s=%q is not a number", key, v)
	}
	if n < lo || n > hi {
		return 0, false, fmt.Errorf("%s=%d is out of range [%d, %d]", key, n, lo, hi)
	}
	return n, true, nil
}
