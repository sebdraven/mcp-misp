package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sebdraven/mcp-misp/internal/config"
	"github.com/sebdraven/mcp-misp/internal/misp"
)

// metadataTTL applies to the instance descriptions that barely move:
// organisations, attribute types, server version.
const metadataTTL = time.Hour

type Service struct {
	client *misp.Client
	cfg    *config.Config
	wl     *Checker

	mu         sync.Mutex
	orgs       map[string]string
	orgsAt     time.Time
	describe   *misp.DescribeTypes
	describeAt time.Time
	version    *misp.ServerVersion
	versionAt  time.Time
}

func New(client *misp.Client, cfg *config.Config) *Service {
	return &Service{
		client: client,
		cfg:    cfg,
		wl:     NewChecker(client, cfg.Warninglists),
	}
}

func (s *Service) ReadOnly() bool { return s.cfg.ReadOnly }

// orgIndex maps organisation ids to names.
//
// /attributes/restSearch nests an event stub carrying org_id and orgc_id but no
// names, and a CTI answer that says "org 4" instead of naming the producer is
// not usable. One cached index covers every attribute of every page; callers
// index it directly, and a nil index from a failed lookup yields empty names
// rather than an error that would sink the whole tool.
func (s *Service) orgIndex(ctx context.Context) (map[string]string, error) {
	s.mu.Lock()
	if s.orgs != nil && time.Since(s.orgsAt) < metadataTTL {
		defer s.mu.Unlock()
		return s.orgs, nil
	}
	s.mu.Unlock()

	orgs, err := s.client.Organisations(ctx)
	if err != nil {
		return nil, err
	}
	idx := make(map[string]string, len(orgs))
	for _, o := range orgs {
		idx[o.ID.String()] = o.Name
	}

	s.mu.Lock()
	s.orgs, s.orgsAt = idx, time.Now()
	s.mu.Unlock()
	return idx, nil
}

func (s *Service) describeTypes(ctx context.Context) (*misp.DescribeTypes, error) {
	s.mu.Lock()
	if s.describe != nil && time.Since(s.describeAt) < metadataTTL {
		defer s.mu.Unlock()
		return s.describe, nil
	}
	s.mu.Unlock()

	d, err := s.client.DescribeTypes(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.describe, s.describeAt = d, time.Now()
	s.mu.Unlock()
	return d, nil
}

func (s *Service) serverVersion(ctx context.Context) (*misp.ServerVersion, error) {
	s.mu.Lock()
	if s.version != nil && time.Since(s.versionAt) < metadataTTL {
		defer s.mu.Unlock()
		return s.version, nil
	}
	s.mu.Unlock()

	v, err := s.client.Version(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.version, s.versionAt = v, time.Now()
	s.mu.Unlock()
	return v, nil
}

// resolveEvent accepts a numeric id or a UUID and returns the event metadata,
// without its attributes.
func (s *Service) resolveEvent(ctx context.Context, ref string) (*misp.Event, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("no event given")
	}
	p := misp.SearchParams{Metadata: true, Limit: 1}
	if looksNumeric(ref) {
		p.EventID = ref
	} else {
		p.UUID = ref
	}
	events, err := s.client.SearchEvents(ctx, p)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("event %q not found, or not visible to this API key", ref)
	}
	return &events[0], nil
}

func looksNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// MISP core enums. These are protocol, not local convention, so decoding them
// is safe on an instance this server has never seen.
var (
	threatLevels  = map[string]string{"1": "high", "2": "medium", "3": "low", "4": "undefined"}
	analysisState = map[string]string{"0": "initial", "1": "ongoing", "2": "completed"}
	distributions = map[string]string{
		"0": "your organisation only",
		"1": "this community only",
		"2": "connected communities",
		"3": "all communities",
		"4": "sharing group",
		"5": "inherit event",
	}
)

func label(table map[string]string, id misp.Str) string {
	if id == "" {
		return ""
	}
	if v, ok := table[id.String()]; ok {
		return v
	}
	return id.String()
}

// splitTags separates attribute-level tags from those MISP copied down from the
// parent event.
//
// The split rests on the "inherited" marker, which older instances do not send.
// When nothing is marked, everything is reported as attribute-level and the
// caller is told the instance did not say — guessing would misattribute an
// event's TLP tag to a single attribute.
func splitTags(tags []misp.Tag) (own, inherited []string, marked bool) {
	for _, t := range tags {
		if t.Name == "" {
			continue
		}
		if t.Inherited.Bool() {
			marked = true
			inherited = append(inherited, t.Name)
			continue
		}
		own = append(own, t.Name)
	}
	return own, inherited, marked
}

func tagNames(tags []misp.Tag) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if t.Name != "" {
			out = append(out, t.Name)
		}
	}
	return out
}

// galaxyReservation is emitted rather than guessed.
//
// Events are read with metadata=1, which MISP documents as returning the event,
// its tags and its relations while omitting attributes. Whether the galaxy
// expansion survives that has not been verified against a live instance, so an
// empty galaxy list says which of the two it is instead of implying the event
// has none.
const galaxyReservation = "galaxies were requested and none came back; events are read with metadata=1 and whether that carries the galaxy expansion depends on the MISP version, so this may mean the event has no galaxy cluster or that this instance does not expand them here. Galaxy tags, if any, are still listed under tags."

func boolPtr(b bool) *bool { return &b }

func clamp(v, def, maxv int) int {
	if v <= 0 {
		v = def
	}
	if v > maxv {
		v = maxv
	}
	if v < 1 {
		v = 1
	}
	return v
}
