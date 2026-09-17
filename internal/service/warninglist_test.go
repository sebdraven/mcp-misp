package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sebdraven/mcp-misp/internal/config"
	"github.com/sebdraven/mcp-misp/internal/misp"
)

type stubList struct {
	ID              string
	Name            string
	Type            string
	Category        string
	ValidAttributes string
	Enabled         bool
	Entries         []string
	// Count overrides the advertised entry count, to exercise budget decisions
	// taken before anything is downloaded.
	Count      int
	ViewStatus int
}

type stubInstance struct {
	lists []stubList
	// checkStatus non-zero makes /warninglists/checkValue answer with it.
	checkStatus int
	checkBody   string

	mu    sync.Mutex
	calls map[string]int
}

func (s *stubInstance) record(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[key]++
}

func (s *stubInstance) count(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[key]
}

func (s *stubInstance) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case path == "/warninglists/checkValue":
			s.record("checkValue")
			if s.checkStatus != 0 {
				w.WriteHeader(s.checkStatus)
				w.Write([]byte(`{"name":"nope"}`))
				return
			}
			w.Write([]byte(s.checkBody))

		case path == "/warninglists/index":
			s.record("index")
			var out struct {
				Warninglists []map[string]any `json:"Warninglists"`
			}
			for _, l := range s.lists {
				count := l.Count
				if count == 0 {
					count = len(l.Entries)
				}
				out.Warninglists = append(out.Warninglists, map[string]any{
					"Warninglist": map[string]any{
						"id": l.ID, "name": l.Name, "type": l.Type,
						"category": l.Category, "enabled": l.Enabled,
						"warninglist_entry_count": fmt.Sprint(count),
						"valid_attributes":        l.ValidAttributes,
					},
				})
			}
			json.NewEncoder(w).Encode(out)

		case strings.HasPrefix(path, "/warninglists/view/"):
			id := strings.TrimPrefix(path, "/warninglists/view/")
			s.record("view:" + id)
			for _, l := range s.lists {
				if l.ID != id {
					continue
				}
				if l.ViewStatus != 0 {
					w.WriteHeader(l.ViewStatus)
					return
				}
				entries := make([]map[string]string, 0, len(l.Entries))
				for _, e := range l.Entries {
					entries = append(entries, map[string]string{"value": e})
				}
				json.NewEncoder(w).Encode(map[string]any{
					"Warninglist": map[string]any{
						"id": l.ID, "name": l.Name, "type": l.Type,
						"category": l.Category, "enabled": l.Enabled,
						"valid_attributes": l.ValidAttributes,
						"WarninglistEntry": entries,
					},
				})
				return
			}
			w.WriteHeader(404)

		default:
			t.Errorf("unexpected request to %s", path)
			w.WriteHeader(500)
		}
	}
}

func newChecker(t *testing.T, s *stubInstance, cfg config.Warninglists) *Checker {
	t.Helper()
	srv := httptest.NewServer(s.handler(t))
	t.Cleanup(srv.Close)
	client := misp.New(srv.URL, "0123456789abcdef0123456789abcdef01234567", misp.WithRetries(0))
	return NewChecker(client, cfg)
}

func localOnly(lists ...stubList) *stubInstance {
	// A 404 on checkValue is what an instance too old to expose it looks like.
	return &stubInstance{lists: lists, checkStatus: 404}
}

func defaultCfg() config.Warninglists {
	return config.Warninglists{MaxEntries: 200_000, TTL: time.Hour, LocalFallback: true}
}

// ---- delegation --------------------------------------------------------------

func TestInstanceEngineIsPreferred(t *testing.T) {
	s := &stubInstance{
		checkBody: `{"1.1.1.1":[{"id":"7","name":"Public DNS resolvers","type":"cidr"}]}`,
	}
	k := newChecker(t, s, defaultCfg())

	got, rep := k.Check(context.Background(), []Subject{{Value: "1.1.1.1", Type: "ip-dst"}, {Value: "9.9.9.9"}})

	if rep.Engine != EngineInstance {
		t.Errorf("engine = %q, want %q", rep.Engine, EngineInstance)
	}
	if rep.Coverage != CoverageComplete {
		t.Errorf("coverage = %q", rep.Coverage)
	}
	if !got["1.1.1.1"].Hit || got["9.9.9.9"].Hit {
		t.Errorf("hits = %+v", got)
	}
	if rep.Checked != 2 || rep.Hits != 1 {
		t.Errorf("report = %+v", rep)
	}
	if rep.ByList["Public DNS resolvers"] != 1 {
		t.Errorf("by_list = %+v", rep.ByList)
	}
	if s.count("index") != 0 {
		t.Error("the local index must not be built when the instance answers")
	}
}

func TestValuesAreDedupedBeforeTheCall(t *testing.T) {
	s := &stubInstance{checkBody: `{}`}
	k := newChecker(t, s, defaultCfg())
	_, rep := k.Check(context.Background(), []Subject{{Value: "a"}, {Value: "a"}, {Value: "b"}})
	if rep.Checked != 2 {
		t.Errorf("checked = %d, want 2", rep.Checked)
	}
}

func TestFallsBackToLocalWhenEndpointIsAbsent(t *testing.T) {
	s := localOnly(stubList{
		ID: "1", Name: "Public DNS resolvers", Type: "cidr", Enabled: true,
		Entries: []string{"1.1.1.0/24"},
	})
	k := newChecker(t, s, defaultCfg())

	got, rep := k.Check(context.Background(), []Subject{{Value: "1.1.1.1", Type: "ip-dst"}})
	if rep.Engine != EngineLocal {
		t.Fatalf("engine = %q, want %q (note: %s)", rep.Engine, EngineLocal, rep.Note)
	}
	if rep.Coverage != CoverageComplete {
		t.Errorf("coverage = %q, note = %s", rep.Coverage, rep.Note)
	}
	if !got["1.1.1.1"].Hit {
		t.Error("1.1.1.1 is inside 1.1.1.0/24")
	}
}

// An instance that does not expose the endpoint will not start exposing it
// between two searches, so it is asked once and then left alone.
func TestAbsentEndpointIsRemembered(t *testing.T) {
	s := localOnly(stubList{ID: "1", Name: "l", Type: "string", Enabled: true, Entries: []string{"x"}})
	k := newChecker(t, s, defaultCfg())

	k.Check(context.Background(), []Subject{{Value: "x"}})
	k.Check(context.Background(), []Subject{{Value: "y"}})

	if s.count("checkValue") != 1 {
		t.Errorf("checkValue called %d times, want 1", s.count("checkValue"))
	}
}

// A timeout says nothing about whether the endpoint exists, so it must not
// disable the instance path.
func TestTransientFailureIsNotRemembered(t *testing.T) {
	s := &stubInstance{checkStatus: 503}
	k := newChecker(t, s, config.Warninglists{MaxEntries: 1000, TTL: time.Hour, LocalFallback: false})

	k.Check(context.Background(), []Subject{{Value: "x"}})
	k.Check(context.Background(), []Subject{{Value: "y"}})

	if s.count("checkValue") != 2 {
		t.Errorf("checkValue called %d times, want 2", s.count("checkValue"))
	}
}

func TestUnavailableIsNeverReportedAsClean(t *testing.T) {
	s := &stubInstance{checkStatus: 403}
	k := newChecker(t, s, config.Warninglists{MaxEntries: 1000, TTL: time.Hour, LocalFallback: false})

	got, rep := k.Check(context.Background(), []Subject{{Value: "1.1.1.1"}})
	if rep.Coverage != CoverageUnavailable {
		t.Fatalf("coverage = %q, want %q", rep.Coverage, CoverageUnavailable)
	}
	if len(got) != 0 {
		t.Errorf("no value may be reported as checked-and-clean: %+v", got)
	}
	if !strings.Contains(rep.Note, "MISP_WARNINGLIST_LOCAL_FALLBACK") {
		t.Errorf("the note should name the disabled fallback: %s", rep.Note)
	}
}

func TestErrorNoteCarriesNoKey(t *testing.T) {
	s := &stubInstance{checkStatus: 403}
	k := newChecker(t, s, config.Warninglists{MaxEntries: 1000, TTL: time.Hour, LocalFallback: false})
	_, rep := k.Check(context.Background(), []Subject{{Value: "x"}})
	if strings.Contains(rep.Note, "0123456789abcdef") {
		t.Fatalf("the key leaked into the report note: %s", rep.Note)
	}
}

// ---- matching types ----------------------------------------------------------

func checkOne(t *testing.T, list stubList, s Subject) (Check, Report) {
	t.Helper()
	k := newChecker(t, localOnly(list), defaultCfg())
	got, rep := k.Check(context.Background(), []Subject{s})
	return got[s.Value], rep
}

func TestMatchString(t *testing.T) {
	l := stubList{ID: "1", Name: "exact", Type: "string", Enabled: true,
		Entries: []string{"Example.COM", "10.0.0.1"}}

	for _, v := range []string{"example.com", "EXAMPLE.com", "10.0.0.1"} {
		if c, _ := checkOne(t, l, Subject{Value: v}); !c.Hit {
			t.Errorf("%q should match exactly (case-insensitively)", v)
		}
	}
	for _, v := range []string{"sub.example.com", "example.co", "xexample.com"} {
		if c, _ := checkOne(t, l, Subject{Value: v}); c.Hit {
			t.Errorf("%q must not match an exact-string list", v)
		}
	}
}

func TestMatchSubstring(t *testing.T) {
	l := stubList{ID: "1", Name: "sub", Type: "substring", Enabled: true,
		Entries: []string{"cdn-provider"}}

	if c, _ := checkOne(t, l, Subject{Value: "assets.cdn-provider.net/x"}); !c.Hit {
		t.Error("the entry is contained in the value")
	}
	if c, _ := checkOne(t, l, Subject{Value: "cdn.provider.net"}); c.Hit {
		t.Error("substring is a containment test, not a fuzzy one")
	}
}

// One entry for a domain has to cover every host under it; that is the whole
// point of the hostname type.
func TestMatchHostnameWalksParents(t *testing.T) {
	l := stubList{ID: "1", Name: "host", Type: "hostname", Enabled: true,
		Entries: []string{"example.com", "cdn.akamai.net."}}

	for _, v := range []string{
		"example.com", "www.example.com", "mail.corp.example.com",
		"https://www.example.com/path?a=b", "www.example.com:8443",
		"EXAMPLE.COM", "example.com.", "edge.cdn.akamai.net",
	} {
		if c, _ := checkOne(t, l, Subject{Value: v}); !c.Hit {
			t.Errorf("%q should match", v)
		}
	}
	for _, v := range []string{"notexample.com", "example.com.evil.net", "example.org"} {
		if c, _ := checkOne(t, l, Subject{Value: v}); c.Hit {
			t.Errorf("%q must not match: parent walking goes up, never down", v)
		}
	}
}

func TestMatchCIDR(t *testing.T) {
	l := stubList{ID: "1", Name: "cidr", Type: "cidr", Enabled: true,
		Entries: []string{"10.0.0.0/8", "192.0.2.42", "2001:db8::/32"}}

	for _, v := range []string{"10.1.2.3", "10.0.0.0", "192.0.2.42", "2001:db8::1"} {
		if c, _ := checkOne(t, l, Subject{Value: v}); !c.Hit {
			t.Errorf("%q should be inside the list", v)
		}
	}
	for _, v := range []string{"11.1.2.3", "192.0.2.43", "2001:db9::1", "not-an-ip"} {
		if c, _ := checkOne(t, l, Subject{Value: v}); c.Hit {
			t.Errorf("%q must not match", v)
		}
	}
}

// An IPv4 address must not fall inside an IPv6 prefix through a mapped form.
func TestMatchCIDRDoesNotCrossFamilies(t *testing.T) {
	l := stubList{ID: "1", Name: "v6", Type: "cidr", Enabled: true, Entries: []string{"::/0"}}
	if c, _ := checkOne(t, l, Subject{Value: "10.0.0.1"}); c.Hit {
		t.Error("an IPv4 address must not match an IPv6 prefix")
	}
}

func TestMatchRegex(t *testing.T) {
	l := stubList{ID: "1", Name: "re", Type: "regex", Enabled: true,
		Entries: []string{`^https?://localhost(:\d+)?/`}}

	if c, _ := checkOne(t, l, Subject{Value: "http://localhost:8080/x"}); !c.Hit {
		t.Error("the pattern should match")
	}
	if c, _ := checkOne(t, l, Subject{Value: "http://example.com/"}); c.Hit {
		t.Error("the pattern should not match")
	}
}

// MISP evaluates PCRE and Go evaluates RE2: an entry using a construct RE2
// lacks is dropped, and dropping it silently would turn a real hit into a clean
// answer. The list is therefore reported as not fully applied.
func TestUncompilableRegexMarksTheListUncovered(t *testing.T) {
	l := stubList{ID: "1", Name: "pcre-only", Type: "regex", Enabled: true,
		Entries: []string{`(?<=evil)\.com`, `^good\.net$`}}

	c, rep := checkOne(t, l, Subject{Value: "good.net"})
	if !c.Hit {
		t.Error("the compilable entry should still work")
	}
	if rep.Coverage != CoveragePartial {
		t.Errorf("coverage = %q, want %q", rep.Coverage, CoveragePartial)
	}
	if !slices.Contains(rep.UncoveredLists, "pcre-only") {
		t.Errorf("uncovered_lists = %v", rep.UncoveredLists)
	}
}

func TestUnknownMatchingTypeIsNotGuessed(t *testing.T) {
	l := stubList{ID: "1", Name: "weird", Type: "bloomfilter", Enabled: true,
		Entries: []string{"example.com"}}

	c, rep := checkOne(t, l, Subject{Value: "example.com"})
	if c.Hit {
		t.Error("an unknown matching type must not be silently treated as a string list")
	}
	if !slices.Contains(rep.UncoveredLists, "weird") {
		t.Errorf("uncovered_lists = %v", rep.UncoveredLists)
	}
	if rep.Coverage != CoveragePartial {
		t.Errorf("coverage = %q", rep.Coverage)
	}
}

func TestValidAttributesRestrictsTheList(t *testing.T) {
	l := stubList{ID: "1", Name: "hosts", Type: "hostname", Enabled: true,
		ValidAttributes: "domain,hostname", Entries: []string{"example.com"}}

	if c, _ := checkOne(t, l, Subject{Value: "example.com", Type: "domain"}); !c.Hit {
		t.Error("domain is in valid_attributes")
	}
	if c, _ := checkOne(t, l, Subject{Value: "example.com", Type: "ip-dst"}); c.Hit {
		t.Error("ip-dst is not in valid_attributes")
	}
	// With no type to go on, the list has to apply: skipping would be a silent
	// false negative.
	if c, _ := checkOne(t, l, Subject{Value: "example.com"}); !c.Hit {
		t.Error("an untyped value must still be checked")
	}
}

func TestDisabledListsAreIgnored(t *testing.T) {
	l := stubList{ID: "1", Name: "off", Type: "string", Enabled: false, Entries: []string{"x"}}
	c, rep := checkOne(t, l, Subject{Value: "x"})
	if c.Hit {
		t.Error("a disabled warninglist must not produce hits")
	}
	if rep.Coverage != CoverageComplete {
		t.Errorf("a disabled list is not missing coverage: %q", rep.Coverage)
	}
}

// ---- budget ------------------------------------------------------------------

func TestEntryBudgetLoadsSmallestFirstAndReportsTheRest(t *testing.T) {
	s := localOnly(
		stubList{ID: "1", Name: "huge", Type: "string", Enabled: true, Count: 500_000, Entries: []string{"huge-value"}},
		stubList{ID: "2", Name: "small", Type: "string", Enabled: true, Entries: []string{"small-value"}},
	)
	k := newChecker(t, s, config.Warninglists{MaxEntries: 10, TTL: time.Hour, LocalFallback: true})

	got, rep := k.Check(context.Background(), []Subject{{Value: "small-value"}, {Value: "huge-value"}})

	if !got["small-value"].Hit {
		t.Error("the small list should fit in the budget")
	}
	if got["huge-value"].Hit {
		t.Error("the oversized list should not have been loaded")
	}
	if rep.Coverage != CoveragePartial {
		t.Errorf("coverage = %q, want %q", rep.Coverage, CoveragePartial)
	}
	if !slices.Contains(rep.UncoveredLists, "huge") {
		t.Errorf("uncovered_lists = %v", rep.UncoveredLists)
	}
	if s.count("view:1") != 0 {
		t.Error("an oversized list must be skipped before it is downloaded")
	}
	if !strings.Contains(rep.Note, "entry budget") {
		t.Errorf("the note should explain the gap: %s", rep.Note)
	}
}

func TestListThatFailsToLoadIsReportedNotDropped(t *testing.T) {
	s := localOnly(
		stubList{ID: "1", Name: "broken", Type: "string", Enabled: true, Entries: []string{"x"}, ViewStatus: 500},
		stubList{ID: "2", Name: "fine", Type: "string", Enabled: true, Entries: []string{"y"}},
	)
	k := newChecker(t, s, defaultCfg())

	got, rep := k.Check(context.Background(), []Subject{{Value: "y"}})
	if !got["y"].Hit {
		t.Error("the healthy list should still work")
	}
	if !slices.Contains(rep.UncoveredLists, "broken") {
		t.Errorf("uncovered_lists = %v", rep.UncoveredLists)
	}
}

func TestIndexIsCachedForItsTTL(t *testing.T) {
	s := localOnly(stubList{ID: "1", Name: "l", Type: "string", Enabled: true, Entries: []string{"x"}})
	k := newChecker(t, s, defaultCfg())

	for range 3 {
		k.Check(context.Background(), []Subject{{Value: "x"}})
	}
	if s.count("index") != 1 {
		t.Errorf("index built %d times, want 1", s.count("index"))
	}
}

func TestEmptyInputIsCompleteNotUnavailable(t *testing.T) {
	k := newChecker(t, &stubInstance{checkBody: `{}`}, defaultCfg())
	got, rep := k.Check(context.Background(), nil)
	if len(got) != 0 {
		t.Errorf("got = %+v", got)
	}
	if rep.Coverage != CoverageComplete {
		t.Errorf("checking nothing succeeds completely: %q", rep.Coverage)
	}
}

func TestCancelledContextStopsWithoutClaimingCoverage(t *testing.T) {
	k := newChecker(t, &stubInstance{checkBody: `{}`}, defaultCfg())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, rep := k.Check(ctx, []Subject{{Value: "x"}})
	if rep.Coverage != CoverageUnavailable {
		t.Errorf("coverage = %q", rep.Coverage)
	}
	if len(got) != 0 {
		t.Errorf("got = %+v", got)
	}
}
