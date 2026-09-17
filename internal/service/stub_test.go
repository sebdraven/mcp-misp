package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sebdraven/mcp-misp/internal/config"
	"github.com/sebdraven/mcp-misp/internal/misp"
)

// stubMISP is a minimal instance: enough surface for the service layer, with
// real pagination so the limit+1 probing is exercised rather than assumed.
type stubMISP struct {
	mu    sync.Mutex
	calls map[string]int

	lastAttrQuery  map[string]any
	lastEventQuery map[string]any

	attributes []map[string]any
	events     []map[string]any
	orgs       []map[string]any
	tags       []map[string]any
	taxonomies []map[string]any
	entries    []map[string]any
	attrByID   map[string]map[string]any

	checkValue       map[string]any
	checkValueStatus int
	warninglists     []map[string]any

	added       map[string]any
	addedStatus int
	attached    []string
	attachFail  map[string]bool
}

func (s *stubMISP) record(k string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[k]++
}

func (s *stubMISP) count(k string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[k]
}

func (s *stubMISP) attrQuery() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAttrQuery
}

func (s *stubMISP) eventQuery() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastEventQuery
}

func (s *stubMISP) attachedTags() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.attached...)
}

func decodeBody(r *http.Request) map[string]any {
	var m map[string]any
	json.NewDecoder(r.Body).Decode(&m)
	return m
}

func window(items []map[string]any, q map[string]any) []map[string]any {
	limit, page := 0, 1
	if v, ok := q["limit"].(float64); ok {
		limit = int(v)
	}
	if v, ok := q["page"].(float64); ok && v > 0 {
		page = int(v)
	}
	if limit <= 0 {
		return items
	}
	start := (page - 1) * limit
	if start >= len(items) {
		return nil
	}
	end := min(start+limit, len(items))
	return items[start:end]
}

func (s *stubMISP) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case path == "/attributes/restSearch":
			s.record("attributes/restSearch")
			q := decodeBody(r)
			s.mu.Lock()
			s.lastAttrQuery = q
			s.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{
				"response": map[string]any{"Attribute": window(s.attributes, q)},
			})

		case path == "/events/restSearch":
			s.record("events/restSearch")
			q := decodeBody(r)
			s.mu.Lock()
			s.lastEventQuery = q
			s.mu.Unlock()
			matched := s.events
			if id, ok := q["eventid"].(string); ok {
				matched = filterEvents(s.events, "id", id)
			}
			if u, ok := q["uuid"].(string); ok {
				matched = filterEvents(s.events, "uuid", u)
			}
			out := make([]map[string]any, 0, len(matched))
			for _, e := range window(matched, q) {
				out = append(out, map[string]any{"Event": e})
			}
			json.NewEncoder(w).Encode(map[string]any{"response": out})

		case path == "/organisations/index/scope:all":
			s.record("organisations")
			out := make([]map[string]any, 0, len(s.orgs))
			for _, o := range s.orgs {
				out = append(out, map[string]any{"Organisation": o})
			}
			json.NewEncoder(w).Encode(out)

		case path == "/warninglists/checkValue":
			s.record("checkValue")
			if s.checkValueStatus != 0 {
				w.WriteHeader(s.checkValueStatus)
				w.Write([]byte(`{"name":"nope"}`))
				return
			}
			if s.checkValue == nil {
				w.Write([]byte(`{}`))
				return
			}
			json.NewEncoder(w).Encode(s.checkValue)

		case path == "/warninglists/index":
			s.record("warninglists/index")
			out := make([]map[string]any, 0, len(s.warninglists))
			for _, l := range s.warninglists {
				out = append(out, map[string]any{"Warninglist": l})
			}
			json.NewEncoder(w).Encode(map[string]any{"Warninglists": out})

		case path == "/tags/index":
			s.record("tags/index")
			json.NewEncoder(w).Encode(map[string]any{"Tag": s.tags})

		case path == "/taxonomies/index":
			s.record("taxonomies/index")
			out := make([]map[string]any, 0, len(s.taxonomies))
			for _, tx := range s.taxonomies {
				out = append(out, map[string]any{"Taxonomy": tx})
			}
			json.NewEncoder(w).Encode(out)

		case strings.HasPrefix(path, "/taxonomies/view/"):
			s.record("taxonomies/view")
			json.NewEncoder(w).Encode(map[string]any{
				"Taxonomy": map[string]any{"id": "1", "namespace": "tlp"},
				"entries":  s.entries,
			})

		case strings.HasPrefix(path, "/attributes/add/"):
			s.record("attributes/add")
			if s.addedStatus != 0 {
				w.WriteHeader(s.addedStatus)
				w.Write([]byte(`{"name":"refused"}`))
				return
			}
			body := decodeBody(r)
			out := map[string]any{"id": "900", "uuid": "new-attr-uuid", "event_id": "7"}
			for k, v := range body {
				out[k] = v
			}
			s.mu.Lock()
			s.added = out
			s.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"Attribute": out})

		case path == "/tags/attachTagToObject":
			s.record("attachTag")
			body := decodeBody(r)
			tag, _ := body["tag"].(string)
			if s.attachFail[tag] {
				json.NewEncoder(w).Encode(map[string]any{"errors": "tag not allowed"})
				return
			}
			s.mu.Lock()
			s.attached = append(s.attached, tag)
			s.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"saved": true})

		case strings.HasPrefix(path, "/attributes/view/"):
			s.record("attributes/view")
			id := strings.TrimPrefix(path, "/attributes/view/")
			if a, ok := s.attrByID[id]; ok {
				json.NewEncoder(w).Encode(map[string]any{"Attribute": a})
				return
			}
			w.WriteHeader(404)

		case path == "/servers/getVersion":
			s.record("version")
			json.NewEncoder(w).Encode(map[string]any{"version": "2.4.999"})

		case path == "/attributes/describeTypes.json":
			s.record("describeTypes")
			json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{
				"types":                  []string{"ip-dst", "domain", "sha256"},
				"categories":             []string{"Network activity", "Payload delivery"},
				"category_type_mappings": map[string][]string{"Network activity": {"ip-dst", "domain"}},
			}})

		default:
			t.Errorf("unexpected request to %s", path)
			w.WriteHeader(500)
		}
	}
}

func filterEvents(events []map[string]any, key, want string) []map[string]any {
	var out []map[string]any
	for _, e := range events {
		if v, _ := e[key].(string); v == want {
			out = append(out, e)
		}
	}
	return out
}

func newService(t *testing.T, s *stubMISP, tweak ...func(*config.Config)) *Service {
	t.Helper()
	srv := httptest.NewServer(s.handler(t))
	t.Cleanup(srv.Close)

	cfg := &config.Config{
		URL:       srv.URL,
		VerifySSL: true,
		ReadOnly:  true,
		OutRoot:   t.TempDir(),
		Caps: config.Caps{
			SearchDefault: 50, SearchMax: 500,
			AttrDefault: 100, AttrMax: 1000,
			ContextDefault: 20, ContextMax: 200,
			CheckValues: 1000, ResponseBytes: 256 << 10,
		},
		Warninglists: config.Warninglists{MaxEntries: 1000, TTL: time.Hour, LocalFallback: false},
	}
	for _, f := range tweak {
		f(cfg)
	}
	client := misp.New(srv.URL, "0123456789abcdef0123456789abcdef01234567", misp.WithRetries(0))
	return New(client, cfg)
}

func attr(id, value, typ, eventID string, toIDs bool, extra map[string]any) map[string]any {
	a := map[string]any{
		"id": id, "uuid": "attr-" + id, "event_id": eventID,
		"type": typ, "category": "Network activity", "value": value,
		"to_ids": toIDs, "timestamp": "1700000000",
		"Event": map[string]any{
			"id": eventID, "uuid": "event-" + eventID, "info": "campaign " + eventID,
			"org_id": "1", "orgc_id": "2", "date": "2026-01-15", "published": true,
		},
	}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

func defaultOrgs() []map[string]any {
	return []map[string]any{
		{"id": "1", "name": "CERT-HOST", "uuid": "org-1", "local": true},
		{"id": "2", "name": "CERT-PRODUCER", "uuid": "org-2", "local": false},
	}
}
