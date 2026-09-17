package config

import (
	"strings"
	"testing"
	"time"
)

func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	base := map[string]string{
		"MISP_URL": "https://misp.example.org",
		"MISP_KEY": "0123456789abcdef0123456789abcdef01234567",
	}
	for k, v := range kv {
		base[k] = v
	}
	for _, k := range []string{
		"MISP_VERIFY_SSL", "MISP_TIMEOUT", "MISP_READONLY", "MISP_OUT_ROOT",
		"MISP_MAX_CONCURRENCY", "MISP_MAX_RETRIES", "MISP_MAX_RESULTS",
		"MISP_ALLOW_PUBLIC_BIND", "MISP_WARNINGLIST_MAX_ENTRIES",
		"MISP_WARNINGLIST_TTL", "MISP_WARNINGLIST_LOCAL_FALLBACK",
		"MCP_TRANSPORT", "MCP_HTTP_ADDR",
	} {
		if _, ok := base[k]; !ok {
			t.Setenv(k, "")
		}
	}
	for k, v := range base {
		t.Setenv(k, v)
	}
}

func TestDefaultsAreSafe(t *testing.T) {
	withEnv(t, nil)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.ReadOnly {
		t.Error("MISP_READONLY must default to true")
	}
	if !c.VerifySSL {
		t.Error("MISP_VERIFY_SSL must default to true")
	}
	if c.HTTPAddr != DefaultHTTPAddr {
		t.Errorf("HTTPAddr = %q, want %q", c.HTTPAddr, DefaultHTTPAddr)
	}
	if c.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %s, want %s", c.Timeout, DefaultTimeout)
	}
}

func TestKeyNeverAppearsInString(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef01234567"
	withEnv(t, map[string]string{"MISP_KEY": key})
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if strings.Contains(c.String(), key) {
		t.Fatalf("Config.String leaked the key: %s", c.String())
	}
	if c.Key() != key {
		t.Error("Key() should return the configured key")
	}
}

func TestUnparseableBoolIsFatal(t *testing.T) {
	withEnv(t, map[string]string{"MISP_READONLY": "maybe"})
	if _, err := Load(); err == nil {
		t.Fatal("a non-boolean MISP_READONLY must fail startup, not fall back")
	}
}

func TestBoolSpellings(t *testing.T) {
	for _, v := range []string{"0", "false", "FALSE", "no", "off", "n"} {
		withEnv(t, map[string]string{"MISP_READONLY": v})
		c, err := Load()
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if c.ReadOnly {
			t.Errorf("%q should disable read-only", v)
		}
	}
}

func TestNonLoopbackBindIsRefused(t *testing.T) {
	for _, addr := range []string{":8080", "0.0.0.0:8080", "192.0.2.10:8080", "[::]:8080"} {
		withEnv(t, map[string]string{"MCP_TRANSPORT": "http", "MCP_HTTP_ADDR": addr})
		_, err := Load()
		if err == nil {
			t.Errorf("%s should be refused without MISP_ALLOW_PUBLIC_BIND", addr)
			continue
		}
		if !strings.Contains(err.Error(), "MISP_ALLOW_PUBLIC_BIND") {
			t.Errorf("%s: error should name the escape hatch, got %v", addr, err)
		}
	}
}

func TestLoopbackBindIsAccepted(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		withEnv(t, map[string]string{"MCP_TRANSPORT": "http", "MCP_HTTP_ADDR": addr})
		if _, err := Load(); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestPublicBindNeedsOptInAndWarns(t *testing.T) {
	withEnv(t, map[string]string{
		"MCP_TRANSPORT":          "http",
		"MCP_HTTP_ADDR":          "0.0.0.0:8080",
		"MISP_ALLOW_PUBLIC_BIND": "true",
	})
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !hasWarning(c, "MISP_ALLOW_PUBLIC_BIND") {
		t.Error("an opted-in public bind should still warn")
	}
}

// A stdio server never listens, so the bind guard must not block it.
func TestBindGuardIgnoredOnStdio(t *testing.T) {
	withEnv(t, map[string]string{"MCP_HTTP_ADDR": "0.0.0.0:8080"})
	if _, err := Load(); err != nil {
		t.Fatalf("stdio transport should not be gated on the listen address: %v", err)
	}
}

func TestMaxResultsOnlyLowers(t *testing.T) {
	withEnv(t, map[string]string{"MISP_MAX_RESULTS": "10"})
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Caps.SearchMax != 10 || c.Caps.AttrMax != 10 || c.Caps.ContextMax != 10 {
		t.Errorf("ceilings not lowered: %+v", c.Caps)
	}
	if c.Caps.SearchDefault > 10 || c.Caps.AttrDefault > 10 {
		t.Errorf("defaults must follow the ceiling down: %+v", c.Caps)
	}

	withEnv(t, map[string]string{"MISP_MAX_RESULTS": "100000"})
	c, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Caps.SearchMax != DefaultCaps().SearchMax {
		t.Errorf("MISP_MAX_RESULTS must not raise a ceiling, got %d", c.Caps.SearchMax)
	}
}

func TestTimeoutAcceptsBareSeconds(t *testing.T) {
	withEnv(t, map[string]string{"MISP_TIMEOUT": "90"})
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Timeout != 90*time.Second {
		t.Errorf("Timeout = %s, want 90s", c.Timeout)
	}
}

func TestURLValidation(t *testing.T) {
	cases := map[string]bool{
		"https://misp.example.org":         true,
		"https://misp.example.org/":        true,
		"https://misp.example.org/misp/":   true,
		"http://127.0.0.1:8080":            true,
		"ftp://misp.example.org":           false,
		"misp.example.org":                 false,
		"https://user:pw@misp.example.org": false,
	}
	for raw, ok := range cases {
		withEnv(t, map[string]string{"MISP_URL": raw})
		_, err := Load()
		if ok && err != nil {
			t.Errorf("%s should be accepted: %v", raw, err)
		}
		if !ok && err == nil {
			t.Errorf("%s should be rejected", raw)
		}
	}
}

func TestTrailingSlashStripped(t *testing.T) {
	withEnv(t, map[string]string{"MISP_URL": "https://misp.example.org/misp///"})
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.URL != "https://misp.example.org/misp" {
		t.Errorf("URL = %q", c.URL)
	}
}

func TestPlainHTTPWarnsOffLoopback(t *testing.T) {
	withEnv(t, map[string]string{"MISP_URL": "http://misp.example.org"})
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !hasWarning(c, "unencrypted") {
		t.Error("plain HTTP to a remote host should warn")
	}

	withEnv(t, map[string]string{"MISP_URL": "http://127.0.0.1:8080"})
	c, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if hasWarning(c, "unencrypted") {
		t.Error("plain HTTP to loopback should not warn")
	}
}

func TestMissingRequired(t *testing.T) {
	withEnv(t, map[string]string{"MISP_URL": ""})
	if _, err := Load(); err == nil {
		t.Error("MISP_URL is required")
	}
	withEnv(t, map[string]string{"MISP_KEY": "  "})
	if _, err := Load(); err == nil {
		t.Error("MISP_KEY is required")
	}
}

func hasWarning(c *Config, substr string) bool {
	for _, w := range c.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}
