package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sebdraven/mcp-misp/internal/misp"
)

type SearchInput struct {
	Value     string
	Type      []string
	Category  []string
	Tags      []string
	EventTags []string
	Org       string
	From      string
	To        string
	ToIDs     *bool
	Published *bool

	Returns              string
	ExcludeWarninglisted bool
	Fields               []string

	Limit  int
	Cursor string
	OutDir string
}

type SearchResult struct {
	Returns     string          `json:"returns"`
	Page        int             `json:"page"`
	Returned    int             `json:"returned"`
	NextCursor  string          `json:"next_cursor,omitempty"`
	Truncated   bool            `json:"truncated"`
	Attributes  []AttributeView `json:"attributes,omitempty"`
	Events      []EventView     `json:"events,omitempty"`
	Warninglist Report          `json:"warninglist"`
	Flags       []string        `json:"flags,omitempty"`
	Spill       *Spill          `json:"spill,omitempty"`
	Notes       []string        `json:"notes,omitempty"`
}

func (s *Service) Search(ctx context.Context, in SearchInput) (*SearchResult, error) {
	returns := strings.ToLower(strings.TrimSpace(in.Returns))
	if returns == "" {
		returns = "attributes"
	}
	if returns != "attributes" && returns != "events" {
		return nil, fmt.Errorf("returns %q: want attributes or events", in.Returns)
	}

	from, err := normaliseDate(in.From, time.Now())
	if err != nil {
		return nil, err
	}
	to, err := normaliseDate(in.To, time.Now())
	if err != nil {
		return nil, err
	}

	sig := fingerprint(returns, in.Value, in.Type, in.Category, in.Tags, in.EventTags,
		in.Org, from, to, in.ToIDs, in.Published, in.ExcludeWarninglisted)
	page, _, err := decodeCursor(in.Cursor, sig)
	if err != nil {
		return nil, err
	}
	limit := clamp(in.Limit, s.cfg.Caps.SearchDefault, s.cfg.Caps.SearchMax)

	p := misp.SearchParams{
		Value:              in.Value,
		Type:               in.Type,
		Category:           in.Category,
		Tags:               in.Tags,
		EventTags:          in.EventTags,
		Org:                in.Org,
		From:               from,
		To:                 to,
		ToIDs:              in.ToIDs,
		Published:          in.Published,
		Limit:              limit,
		Page:               page,
		EnforceWarninglist: in.ExcludeWarninglisted,
		IncludeEventUUID:   true,
		IncludeEventTags:   true,
	}

	out := &SearchResult{Returns: returns, Page: page}
	if in.ExcludeWarninglisted {
		out.Notes = append(out.Notes, "exclude_warninglisted is on: the instance removed warninglisted attributes before this server saw them, so they are absent rather than flagged")
	}

	if returns == "events" {
		p.Metadata = true
		return s.searchEvents(ctx, p, in, out, limit, sig)
	}
	return s.searchAttributes(ctx, p, in, out, limit, sig)
}

func (s *Service) searchAttributes(ctx context.Context, p misp.SearchParams, in SearchInput, out *SearchResult, limit int, sig string) (*SearchResult, error) {
	allow, err := resolveFields(in.Fields, attributeFields, defaultAttributeFields)
	if err != nil {
		return nil, err
	}

	attrs, err := s.client.SearchAttributes(ctx, p)
	if err != nil {
		return nil, err
	}
	// A full page means there may be another. Asking for limit+1 to find out
	// is not an option: MISP paginates by page x limit with no offset, so the
	// next page would start one record past where this one ended.
	hasMore := len(attrs) == limit

	orgs, _ := s.orgIndex(ctx)
	views := make([]AttributeView, 0, len(attrs))
	subjects := make([]Subject, 0, len(attrs))
	for _, a := range attrs {
		views = append(views, s.attributeView(a, orgs))
		subjects = append(subjects, Subject{Value: a.Value, Type: a.Type})
	}

	checks, report := s.wl.Check(ctx, subjects)
	out.Warninglist = report
	for i := range views {
		c := checks[attrs[i].Value]
		views[i].Warninglist = &c
		projectAttribute(&views[i], allow)
	}

	if in.OutDir != "" {
		return s.spillSearch(in, out, views, hasMore, limit, sig)
	}

	views, truncated := fitBudget(views, s.cfg.Caps.ResponseBytes)
	out.Attributes = views
	out.Returned = len(views)
	out.Truncated = truncated
	out.Flags = append(out.Flags, coverageFlags(report)...)
	if truncated {
		out.Flags = append(out.Flags, FlagResultsTruncated)
		out.Notes = append(out.Notes, "the response byte ceiling trimmed this page; pass out_dir to get the whole set on disk")
	}
	if hasMore && !truncated {
		out.NextCursor = encodeCursor(out.Page+1, limit, sig)
	}
	return out, nil
}

func (s *Service) searchEvents(ctx context.Context, p misp.SearchParams, in SearchInput, out *SearchResult, limit int, sig string) (*SearchResult, error) {
	allow, err := resolveFields(in.Fields, eventFields, defaultEventFields)
	if err != nil {
		return nil, err
	}

	events, err := s.client.SearchEvents(ctx, p)
	if err != nil {
		return nil, err
	}
	hasMore := len(events) == limit

	orgs, _ := s.orgIndex(ctx)
	views := make([]EventView, 0, len(events))
	galaxies := 0
	for _, e := range events {
		v := s.eventView(e, orgs)
		projectEvent(&v, allow)
		galaxies += len(v.Galaxies)
		views = append(views, v)
	}
	if allow["galaxies"] && galaxies == 0 && len(views) > 0 {
		out.Notes = append(out.Notes, galaxyReservation)
	}

	// Event mode returns no attribute values, so there is nothing to annotate.
	// Saying so beats reporting a clean check that never ran.
	out.Warninglist = Report{
		Engine:   EngineNone,
		Coverage: CoverageComplete,
		Note:     "event mode returns event metadata and no attribute values; use returns=attributes for warninglist annotation",
	}

	if in.OutDir != "" {
		return s.spillSearchEvents(in, out, views, hasMore, limit, sig)
	}

	views, truncated := fitBudget(views, s.cfg.Caps.ResponseBytes)
	out.Events = views
	out.Returned = len(views)
	out.Truncated = truncated
	if truncated {
		out.Flags = append(out.Flags, FlagResultsTruncated)
	}
	if hasMore && !truncated {
		out.NextCursor = encodeCursor(out.Page+1, limit, sig)
	}
	return out, nil
}

type searchManifest struct {
	Tool        string   `json:"tool"`
	Instance    string   `json:"instance"`
	Returns     string   `json:"returns"`
	Page        int      `json:"page"`
	Limit       int      `json:"limit"`
	Records     int      `json:"records"`
	Query       any      `json:"query"`
	Warninglist Report   `json:"warninglist"`
	Files       []string `json:"files"`
}

func (s *Service) spillSearch(in SearchInput, out *SearchResult, views []AttributeView, hasMore bool, limit int, sig string) (*SearchResult, error) {
	dir, err := resolveOutDir(s.cfg.OutRoot, in.OutDir)
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf("misp-search-%s-p%d", sig, out.Page)
	path, err := spillJSONL(dir, name, views)
	if err != nil {
		return nil, err
	}
	manifest := searchManifest{
		Tool: "misp_search", Instance: s.client.BaseURL(), Returns: out.Returns,
		Page: out.Page, Limit: limit, Records: len(views),
		Query: in, Warninglist: out.Warninglist, Files: []string{path},
	}
	mpath, err := writeManifest(dir, name, manifest)
	if err != nil {
		return nil, err
	}
	out.Spill = &Spill{Dir: dir, Files: []string{path, mpath}, Records: len(views)}
	out.Returned = len(views)
	out.Flags = append(out.Flags, coverageFlags(out.Warninglist)...)
	if hasMore {
		out.NextCursor = encodeCursor(out.Page+1, limit, sig)
	}
	return out, nil
}

func (s *Service) spillSearchEvents(in SearchInput, out *SearchResult, views []EventView, hasMore bool, limit int, sig string) (*SearchResult, error) {
	dir, err := resolveOutDir(s.cfg.OutRoot, in.OutDir)
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf("misp-search-%s-p%d", sig, out.Page)
	path, err := spillJSONL(dir, name, views)
	if err != nil {
		return nil, err
	}
	manifest := searchManifest{
		Tool: "misp_search", Instance: s.client.BaseURL(), Returns: out.Returns,
		Page: out.Page, Limit: limit, Records: len(views),
		Query: in, Warninglist: out.Warninglist, Files: []string{path},
	}
	mpath, err := writeManifest(dir, name, manifest)
	if err != nil {
		return nil, err
	}
	out.Spill = &Spill{Dir: dir, Files: []string{path, mpath}, Records: len(views)}
	out.Returned = len(views)
	if hasMore {
		out.NextCursor = encodeCursor(out.Page+1, limit, sig)
	}
	return out, nil
}
