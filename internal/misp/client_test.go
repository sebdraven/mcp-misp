package misp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "0123456789abcdef0123456789abcdef01234567"

func newTestClient(t *testing.T, h http.HandlerFunc, opts ...Option) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	base := []Option{withBackoffBase(time.Millisecond)}
	return New(srv.URL, testKey, append(base, opts...)...)
}

func TestRequestHeaders(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	var body []byte
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		body, _ = readAll(r)
		mu.Unlock()
		w.Write([]byte(`{"response":{"Attribute":[]}}`))
	})

	if _, err := c.SearchAttributes(context.Background(), SearchParams{Value: "1.2.3.4"}); err != nil {
		t.Fatalf("SearchAttributes: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got.Get("Authorization") != testKey {
		t.Errorf("Authorization = %q", got.Get("Authorization"))
	}
	if got.Get("Accept") != "application/json" {
		t.Errorf("Accept = %q", got.Get("Accept"))
	}
	if got.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", got.Get("Content-Type"))
	}
	if got.Get("User-Agent") != userAgent {
		t.Errorf("User-Agent = %q", got.Get("User-Agent"))
	}
	if !strings.Contains(string(body), `"value":"1.2.3.4"`) {
		t.Errorf("body = %s", body)
	}
}

// Unset filters must not reach the instance at all: MISP treats an explicit
// null on some keys as a filter rather than as an absence.
func TestSearchPayloadOnlyCarriesSetFields(t *testing.T) {
	toIDs := false
	var mu sync.Mutex
	var payload map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := readAll(r)
		mu.Lock()
		_ = json.Unmarshal(b, &payload)
		mu.Unlock()
		w.Write([]byte(`{"response":{"Attribute":[]}}`))
	})

	_, err := c.SearchAttributes(context.Background(), SearchParams{
		Value:            "evil.example",
		ToIDs:            &toIDs,
		IncludeEventTags: true,
		Limit:            10,
	})
	if err != nil {
		t.Fatalf("SearchAttributes: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if payload["returnFormat"] != "json" {
		t.Errorf("returnFormat = %v", payload["returnFormat"])
	}
	if payload["to_ids"] != float64(0) {
		t.Errorf("to_ids = %v, want 0 (MISP wants 0/1, not false)", payload["to_ids"])
	}
	if payload["includeEventTags"] != float64(1) {
		t.Errorf("includeEventTags = %v", payload["includeEventTags"])
	}
	for _, absent := range []string{"published", "metadata", "enforceWarninglist", "org", "page", "includeSightings"} {
		if _, ok := payload[absent]; ok {
			t.Errorf("%s should be absent when unset, got %v", absent, payload[absent])
		}
	}
}

func TestStatusClassification(t *testing.T) {
	cases := []struct {
		status int
		kind   Kind
	}{
		{404, KindNotFound},
		{403, KindRefused},
		{401, KindRefused},
		{429, KindRateLimited},
		{500, KindInstanceErr},
		{503, KindInstanceErr},
	}
	for _, tc := range cases {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			w.Write([]byte(`{"name":"nope","message":"Not authorised"}`))
		}, WithRetries(0))

		_, err := c.Tags(context.Background())
		if got := ErrorKind(err); got != tc.kind {
			t.Errorf("status %d: kind = %q, want %q", tc.status, got, tc.kind)
		}
		if !Refused(err) {
			t.Errorf("status %d: an answered request should count as refused", tc.status)
		}
		if Unreachable(err) {
			t.Errorf("status %d: an answered request is not unreachable", tc.status)
		}
	}
}

func TestNotFoundHelper(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}, WithRetries(0))
	_, err := c.Warninglist(context.Background(), "9999")
	if !NotFound(err) {
		t.Fatalf("want NotFound, got %v", err)
	}
}

func TestRateLimitIsRetriedAndHonoursRetryAfter(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			return
		}
		w.Write([]byte(`{"Tag":[{"id":"1","name":"tlp:clear"}]}`))
	}, WithRetries(3))

	tags, err := c.Tags(context.Background())
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", calls.Load())
	}
	if len(tags) != 1 || tags[0].Name != "tlp:clear" {
		t.Errorf("tags = %+v", tags)
	}
}

func TestGatewayErrorsRetriedButPlainFiveHundredIsNot(t *testing.T) {
	for status, want := range map[int]int32{503: 4, 502: 4, 504: 4, 500: 1} {
		var calls atomic.Int32
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(status)
		}, WithRetries(3))

		if _, err := c.Tags(context.Background()); err == nil {
			t.Fatalf("status %d: expected an error", status)
		}
		if calls.Load() != want {
			t.Errorf("status %d: calls = %d, want %d", status, calls.Load(), want)
		}
	}
}

// A create that timed out mid-flight may well have landed on the instance.
// Replaying it would duplicate the attribute, so writes are never retried.
func TestWritesAreNeverRetried(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(503)
	}, WithRetries(3))

	if _, err := c.AddAttribute(context.Background(), "42", AttributeInput{Type: "ip-dst", Value: "1.2.3.4"}); err == nil {
		t.Fatal("expected an error")
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1", calls.Load())
	}

	calls.Store(0)
	if err := c.AttachTag(context.Background(), "uuid", "tlp:clear"); err == nil {
		t.Fatal("expected an error")
	}
	if calls.Load() != 1 {
		t.Errorf("AttachTag calls = %d, want 1", calls.Load())
	}
}

func TestTimeoutIsNotRetriedAndIsClassified(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	var calls atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}, WithRetries(3), WithTimeout(50*time.Millisecond))

	_, err := c.Tags(context.Background())
	if got := ErrorKind(err); got != KindTimeout {
		t.Fatalf("kind = %q, want %q (err: %v)", got, KindTimeout, err)
	}
	if !Unreachable(err) {
		t.Error("a timeout means the instance did not answer")
	}
	if Refused(err) {
		t.Error("a timeout is not a refusal")
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1: replaying a slow query multiplies the wait", calls.Load())
	}
}

func TestOversizedResponseIsRejectedWithGuidance(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", 4096)))
	}, withMaxBody(1024), WithRetries(0))

	_, err := c.Tags(context.Background())
	if got := ErrorKind(err); got != KindTooLarge {
		t.Fatalf("kind = %q, want %q", got, KindTooLarge)
	}
	if !strings.Contains(err.Error(), "lower the limit") {
		t.Errorf("the error should tell the operator what to do: %v", err)
	}
}

// The key is the one thing that must never surface. An instance that echoes it
// back in an error body is exactly the case a header-only discipline misses.
func TestKeyNeverReachesAnErrorMessage(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"name":"Authentication failed","message":"bad key ` + testKey + `","url":"/tags/index?key=` + testKey + `"}`))
	}, WithRetries(0))

	_, err := c.Tags(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatalf("the API key leaked into an error: %v", err)
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Errorf("the redaction should be visible: %v", err)
	}
}

func TestTransportErrorHasNoUnwrap(t *testing.T) {
	// Nothing downstream may reach the original error: it carries the request
	// URL and whatever the transport put in its message, unredacted.
	var e error = &TransportError{Op: "GET /x", Message: "boom", kind: KindUnreachable}
	if u, ok := e.(interface{ Unwrap() error }); ok {
		t.Fatalf("TransportError must not expose Unwrap, got %v", u)
	}
}

func TestConcurrencyIsCapped(t *testing.T) {
	const limit = 3
	var inFlight, peak atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		inFlight.Add(-1)
		w.Write([]byte(`{"Tag":[]}`))
	}, WithMaxConcurrency(limit))

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Tags(context.Background()); err != nil {
				t.Errorf("Tags: %v", err)
			}
		}()
	}
	wg.Wait()

	if peak.Load() > limit {
		t.Errorf("peak concurrency = %d, want <= %d", peak.Load(), limit)
	}
}

func TestCancelledContextDoesNotCallOut(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"Tag":[]}`))
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Tags(ctx)
	if got := ErrorKind(err); got != KindCanceled {
		t.Errorf("kind = %q, want %q", got, KindCanceled)
	}
	if calls.Load() != 0 {
		t.Errorf("calls = %d, want 0", calls.Load())
	}
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 512)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}

// withMaxBody exists for the oversized-response test. This guards the default
// it must not have changed.
func TestDefaultBodyCapIsProduction(t *testing.T) {
	c := New("http://x", testKey)
	if c.maxBody != maxBody {
		t.Fatalf("default maxBody = %d, want %d", c.maxBody, maxBody)
	}
	if maxBody != 64<<20 {
		t.Fatalf("production body cap = %d, want 64 MiB", maxBody)
	}
}
