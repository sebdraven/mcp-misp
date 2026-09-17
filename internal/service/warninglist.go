// Package service holds the layer between the MISP client and the MCP tools:
// projection, hard ceilings, warninglist annotation and on-disk spill.
package service

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sebdraven/mcp-misp/internal/config"
	"github.com/sebdraven/mcp-misp/internal/misp"
)

// Coverage says how much of the instance's warninglist set actually took part
// in an answer. A clean result under anything but Complete is "we did not see a
// hit", never "there is no hit".
type Coverage string

const (
	CoverageComplete    Coverage = "complete"
	CoveragePartial     Coverage = "partial"
	CoverageUnavailable Coverage = "unavailable"
)

// Engine records who did the matching.
type Engine string

const (
	EngineInstance Engine = "instance"
	EngineLocal    Engine = "local"
	EngineNone     Engine = "none"
)

// Subject is a value to check. Type is the MISP attribute type when known; the
// local engine uses it to honour a list's valid_attributes, and the instance
// engine ignores it.
type Subject struct {
	Value string
	Type  string
}

// Check is the per-value annotation attached to every value this server hands
// back.
type Check struct {
	Hit   bool                  `json:"hit"`
	Lists []misp.WarninglistHit `json:"lists,omitempty"`
}

// Report describes the check itself rather than its results. It travels with
// every tool output that carries warninglist information.
type Report struct {
	Engine   Engine         `json:"engine"`
	Coverage Coverage       `json:"coverage"`
	Checked  int            `json:"checked"`
	Hits     int            `json:"hits"`
	ByList   map[string]int `json:"by_list,omitempty"`
	// UncoveredLists names enabled warninglists that did not take part, or took
	// part only in part.
	UncoveredLists []string `json:"uncovered_lists,omitempty"`
	// LoadedEntries and LoadedBytes describe the local index when it answered.
	// The budget is counted in entries, but a CIDR and a long substring do not
	// cost the same, so the measured size is what an operator needs to set it.
	LoadedEntries int    `json:"loaded_entries,omitempty"`
	LoadedBytes   int    `json:"loaded_bytes,omitempty"`
	Note          string `json:"note,omitempty"`
}

// instanceCooldown is how long the instance path stays disabled after the
// endpoint proved absent or forbidden. Short enough that an operator granting
// the permission does not have to restart the server.
const instanceCooldown = 10 * time.Minute

type Checker struct {
	client *misp.Client
	cfg    config.Warninglists

	mu           sync.Mutex
	index        *localIndex
	instanceDown time.Time
}

func NewChecker(c *misp.Client, cfg config.Warninglists) *Checker {
	return &Checker{client: c, cfg: cfg}
}

// Check annotates values, preferring the instance's own matching engine.
//
// It does not return an error for a failed check: a search whose warninglist
// annotation could not be produced is still a useful search, as long as the
// report says so. Only a cancelled context stops the work.
func (k *Checker) Check(ctx context.Context, subjects []Subject) (map[string]Check, Report) {
	values := dedupeValues(subjects)
	report := Report{Engine: EngineNone, Coverage: CoverageUnavailable, Checked: len(values)}
	if len(values) == 0 {
		report.Coverage = CoverageComplete
		return map[string]Check{}, report
	}

	if k.instanceUsable() {
		hits, err := k.client.CheckValues(ctx, values)
		switch {
		case err == nil:
			report.Engine = EngineInstance
			report.Coverage = CoverageComplete
			return finish(values, hits, &report)
		case misp.ErrorKind(err) == misp.KindCanceled:
			report.Note = "cancelled before the warninglist check ran"
			return map[string]Check{}, report
		default:
			if endpointAbsent(err) {
				k.markInstanceDown()
			}
			report.Note = "instance warninglist check failed: " + err.Error()
		}
	} else {
		report.Note = "instance warninglist check unavailable on this instance"
	}

	if !k.cfg.LocalFallback {
		report.Note = joinNote(report.Note, "local fallback disabled (MISP_WARNINGLIST_LOCAL_FALLBACK=false)")
		return map[string]Check{}, report
	}

	idx, err := k.localIndex(ctx)
	if err != nil {
		report.Note = joinNote(report.Note, "local warninglist index unavailable: "+err.Error())
		return map[string]Check{}, report
	}

	report.Engine = EngineLocal
	report.Coverage = CoverageComplete
	if !idx.complete {
		report.Coverage = CoveragePartial
	}
	report.UncoveredLists = idx.uncovered
	report.LoadedEntries = idx.entries
	report.LoadedBytes = idx.bytes
	report.Note = joinNote(report.Note, idx.note)

	hits := make(map[string][]misp.WarninglistHit, len(values))
	for _, s := range subjects {
		if _, done := hits[s.Value]; done {
			continue
		}
		if h := idx.match(s); len(h) > 0 {
			hits[s.Value] = h
		}
	}
	return finish(values, hits, &report)
}

func finish(values []string, hits map[string][]misp.WarninglistHit, report *Report) (map[string]Check, Report) {
	out := make(map[string]Check, len(values))
	for _, v := range values {
		h := hits[v]
		c := Check{Hit: len(h) > 0, Lists: h}
		out[v] = c
		if c.Hit {
			report.Hits++
			if report.ByList == nil {
				report.ByList = map[string]int{}
			}
			for _, l := range h {
				report.ByList[l.Name]++
			}
		}
	}
	return out, *report
}

func (k *Checker) instanceUsable() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.instanceDown.IsZero() || time.Since(k.instanceDown) > instanceCooldown
}

func (k *Checker) markInstanceDown() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.instanceDown = time.Now()
}

// endpointAbsent separates "this instance will never answer that call" from
// "it did not answer this time". Only the former is worth remembering.
func endpointAbsent(err error) bool {
	switch misp.ErrorKind(err) {
	case misp.KindNotFound, misp.KindRefused, misp.KindMalformed:
		return true
	}
	return false
}

func dedupeValues(subjects []Subject) []string {
	seen := make(map[string]struct{}, len(subjects))
	out := make([]string, 0, len(subjects))
	for _, s := range subjects {
		if s.Value == "" {
			continue
		}
		if _, ok := seen[s.Value]; ok {
			continue
		}
		seen[s.Value] = struct{}{}
		out = append(out, s.Value)
	}
	return out
}

func joinNote(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "; ")
}

// ---- local fallback engine --------------------------------------------------

// The local engine exists only for instances where /warninglists/checkValue is
// absent or forbidden. It reimplements MISP's five matching types, and the one
// place it knowingly diverges is regex: MISP evaluates PCRE, Go evaluates RE2,
// so an entry using a construct RE2 lacks is reported uncovered rather than
// silently skipped.

type localIndex struct {
	loadedAt  time.Time
	lists     []*localList
	uncovered []string
	entries   int
	bytes     int
	complete  bool
	note      string
}

type localList struct {
	id       string
	name     string
	typ      string
	category string
	types    []string
	m        matcher
}

type matcher interface{ match(value string) bool }

func (i *localIndex) match(s Subject) []misp.WarninglistHit {
	var out []misp.WarninglistHit
	for _, l := range i.lists {
		if !l.applies(s.Type) {
			continue
		}
		if l.m.match(s.Value) {
			out = append(out, misp.WarninglistHit{ID: l.id, Name: l.name, Type: l.typ, Category: l.category})
		}
	}
	return out
}

// applies honours valid_attributes. The instance endpoint does not do this,
// so the local engine can be stricter than the instance would be — which is the
// safe direction, and is documented.
func (l *localList) applies(attrType string) bool {
	if len(l.types) == 0 || attrType == "" {
		return true
	}
	for _, t := range l.types {
		if t == attrType {
			return true
		}
	}
	return false
}

func (k *Checker) localIndex(ctx context.Context) (*localIndex, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.index != nil && time.Since(k.index.loadedAt) < k.cfg.TTL {
		return k.index, nil
	}
	idx, err := k.buildIndex(ctx)
	if err != nil {
		return nil, err
	}
	k.index = idx
	return idx, nil
}

// buildIndex loads enabled warninglists smallest-first under a global entry
// budget. Smallest-first is what makes a tight budget useful: a single
// half-million-entry list would otherwise consume it and leave every small,
// high-signal list unloaded.
func (k *Checker) buildIndex(ctx context.Context) (*localIndex, error) {
	metas, err := k.client.Warninglists(ctx)
	if err != nil {
		return nil, err
	}

	enabled := make([]misp.Warninglist, 0, len(metas))
	for _, m := range metas {
		if m.Enabled.Bool() {
			enabled = append(enabled, m)
		}
	}
	sort.SliceStable(enabled, func(a, b int) bool {
		return enabled[a].EntryCount() < enabled[b].EntryCount()
	})

	idx := &localIndex{loadedAt: time.Now()}
	budget := k.cfg.MaxEntries
	used := 0

	for _, meta := range enabled {
		if n := meta.EntryCount(); n > 0 && used+n > budget {
			idx.uncovered = append(idx.uncovered, meta.Name)
			continue
		}
		full, err := k.client.Warninglist(ctx, meta.ID.String())
		if err != nil {
			if misp.ErrorKind(err) == misp.KindCanceled {
				return nil, err
			}
			idx.uncovered = append(idx.uncovered, meta.Name)
			continue
		}
		entries := make([]string, 0, len(full.WarninglistEntry))
		bytes := 0
		for _, e := range full.WarninglistEntry {
			if e.Value != "" {
				entries = append(entries, e.Value)
				bytes += len(e.Value)
			}
		}
		if used+len(entries) > budget {
			idx.uncovered = append(idx.uncovered, meta.Name)
			continue
		}

		m, partial, err := newMatcher(full.Type, entries)
		if err != nil {
			idx.uncovered = append(idx.uncovered, meta.Name)
			continue
		}
		if partial {
			idx.uncovered = append(idx.uncovered, meta.Name)
		}
		used += len(entries)
		idx.bytes += bytes
		idx.lists = append(idx.lists, &localList{
			id:       meta.ID.String(),
			name:     meta.Name,
			typ:      full.Type,
			category: meta.Category,
			types:    full.MatchingAttributes(),
			m:        m,
		})
	}

	idx.entries = used
	idx.complete = len(idx.uncovered) == 0
	if !idx.complete {
		idx.note = fmt.Sprintf("%d of %d enabled warninglists were not fully applied (entry budget %d, used %d entries / %d bytes)",
			len(idx.uncovered), len(enabled), budget, used, idx.bytes)
	}
	return idx, nil
}

// newMatcher reports partial when the list was built but some entries could not
// be honoured.
func newMatcher(typ string, entries []string) (m matcher, partial bool, err error) {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "string", "":
		return newExactMatcher(entries), false, nil
	case "substring":
		return newSubstringMatcher(entries), false, nil
	case "hostname":
		return newHostnameMatcher(entries), false, nil
	case "cidr":
		return newCIDRMatcher(entries)
	case "regex":
		return newRegexMatcher(entries)
	}
	return nil, false, fmt.Errorf("unknown warninglist matching type %q", typ)
}

type exactMatcher map[string]struct{}

func newExactMatcher(entries []string) exactMatcher {
	m := make(exactMatcher, len(entries))
	for _, e := range entries {
		m[strings.ToLower(strings.TrimSpace(e))] = struct{}{}
	}
	return m
}

func (m exactMatcher) match(v string) bool {
	_, ok := m[strings.ToLower(strings.TrimSpace(v))]
	return ok
}

type substringMatcher []string

func newSubstringMatcher(entries []string) substringMatcher {
	m := make(substringMatcher, 0, len(entries))
	for _, e := range entries {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			m = append(m, e)
		}
	}
	return m
}

func (m substringMatcher) match(v string) bool {
	v = strings.ToLower(v)
	for _, e := range m {
		if strings.Contains(v, e) {
			return true
		}
	}
	return false
}

// hostnameMatcher matches a host and every parent domain of it, which is what
// makes one entry for example.com cover mail.corp.example.com.
type hostnameMatcher map[string]struct{}

func newHostnameMatcher(entries []string) hostnameMatcher {
	m := make(hostnameMatcher, len(entries))
	for _, e := range entries {
		if h := hostOfValue(e); h != "" {
			m[h] = struct{}{}
		}
	}
	return m
}

func (m hostnameMatcher) match(v string) bool {
	host := hostOfValue(v)
	if host == "" {
		return false
	}
	if _, ok := m[host]; ok {
		return true
	}
	for i := 0; i < len(host); i++ {
		if host[i] != '.' {
			continue
		}
		if _, ok := m[host[i+1:]]; ok {
			return true
		}
	}
	return false
}

// hostOfValue reduces a URL, a host:port or a bare hostname to its host.
func hostOfValue(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	if i := strings.LastIndex(v, "@"); i >= 0 {
		v = v[i+1:]
	}
	if strings.HasPrefix(v, "[") {
		if j := strings.Index(v, "]"); j >= 0 {
			v = v[1:j]
		}
	} else if strings.Count(v, ":") == 1 {
		v = v[:strings.LastIndex(v, ":")]
	}
	return strings.TrimSuffix(v, ".")
}

type cidrMatcher []netip.Prefix

func newCIDRMatcher(entries []string) (matcher, bool, error) {
	m := make(cidrMatcher, 0, len(entries))
	partial := false
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if p, err := netip.ParsePrefix(e); err == nil {
			m = append(m, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			m = append(m, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		partial = true
	}
	return m, partial, nil
}

func (m cidrMatcher) match(v string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil {
		p, perr := netip.ParsePrefix(strings.TrimSpace(v))
		if perr != nil {
			return false
		}
		a = p.Addr()
	}
	a = a.Unmap()
	for _, p := range m {
		if p.Addr().Is4() == a.Is4() && p.Contains(a) {
			return true
		}
	}
	return false
}

type regexMatcher []*regexp.Regexp

// newRegexMatcher reports partial for any entry RE2 cannot compile. MISP
// evaluates these with PCRE, so a lookaround or a backreference is valid there
// and not here; dropping it silently would turn a real hit into a clean answer.
func newRegexMatcher(entries []string) (matcher, bool, error) {
	m := make(regexMatcher, 0, len(entries))
	partial := false
	for _, e := range entries {
		re, err := regexp.Compile(e)
		if err != nil {
			partial = true
			continue
		}
		m = append(m, re)
	}
	return m, partial, nil
}

func (m regexMatcher) match(v string) bool {
	for _, re := range m {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}
