package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/sebdraven/mcp-misp/internal/misp"
)

type TaxonomyInput struct {
	Namespace         string
	TagSearch         string
	IncludePredicates bool
	Limit             int
	Cursor            string
	OutDir            string
}

type TaxonomyView struct {
	Namespace   string   `json:"namespace"`
	Description string   `json:"description,omitempty"`
	Version     string   `json:"version,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
	Exclusive   *bool    `json:"exclusive,omitempty"`
	Required    *bool    `json:"required,omitempty"`
	Predicates  []string `json:"predicates,omitempty"`
}

type TagView struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	Colour    string `json:"colour,omitempty"`
	Taxonomy  string `json:"taxonomy,omitempty"`
	Count     int    `json:"count,omitempty"`
	LocalOnly *bool  `json:"local_only,omitempty"`
}

type TaxonomyResult struct {
	Taxonomies   []TaxonomyView `json:"taxonomies,omitempty"`
	Tags         []TagView      `json:"tags,omitempty"`
	TagsTotal    int            `json:"tags_total"`
	TagsReturned int            `json:"tags_returned"`
	Page         int            `json:"page"`
	NextCursor   string         `json:"next_cursor,omitempty"`
	Truncated    bool           `json:"truncated"`
	Flags        []string       `json:"flags,omitempty"`
	Spill        *Spill         `json:"spill,omitempty"`
	Notes        []string       `json:"notes,omitempty"`
}

// Taxonomies reports what vocabulary this instance actually carries.
//
// Nothing about tagging is assumed anywhere else in this server; this is where
// a caller finds out what exists here before filtering on it.
func (s *Service) Taxonomies(ctx context.Context, in TaxonomyInput) (*TaxonomyResult, error) {
	taxonomies, err := s.client.Taxonomies(ctx)
	if err != nil {
		return nil, err
	}
	tags, err := s.client.Tags(ctx)
	if err != nil {
		return nil, err
	}

	ns := strings.ToLower(strings.TrimSpace(in.Namespace))
	out := &TaxonomyResult{}

	views := make([]TaxonomyView, 0, len(taxonomies))
	for _, t := range taxonomies {
		if ns != "" && !strings.EqualFold(t.Namespace, ns) {
			continue
		}
		views = append(views, TaxonomyView{
			Namespace:   t.Namespace,
			Description: t.Description,
			Version:     t.Version.String(),
			Enabled:     boolPtr(t.Enabled.Bool()),
			Exclusive:   boolPtr(t.Exclusive.Bool()),
			Required:    boolPtr(t.Required.Bool()),
		})
	}
	if ns != "" && len(views) == 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("no taxonomy with namespace %q on this instance", in.Namespace))
	}

	// Predicates are only expanded for a single named taxonomy. Expanding the
	// whole set means one call per taxonomy and tens of thousands of entries,
	// which is the volume problem this server is built to avoid.
	if in.IncludePredicates {
		switch {
		case ns == "":
			out.Notes = append(out.Notes, "include_predicates needs a namespace: expanding every taxonomy would be one call per taxonomy and tens of thousands of entries")
		case len(views) == 1:
			if preds, err := s.predicates(ctx, taxonomies, ns); err != nil {
				out.Notes = append(out.Notes, "predicates unavailable: "+err.Error())
			} else {
				views[0].Predicates = preds
			}
		}
	}
	out.Taxonomies = views

	search := strings.ToLower(strings.TrimSpace(in.TagSearch))
	matched := make([]TagView, 0, len(tags))
	for _, t := range tags {
		if t.Name == "" {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(t.Name), search) {
			continue
		}
		taxonomy := ""
		if i := strings.Index(t.Name, ":"); i > 0 {
			taxonomy = t.Name[:i]
		}
		if ns != "" && !strings.EqualFold(taxonomy, ns) {
			continue
		}
		matched = append(matched, TagView{
			ID: t.ID.String(), Name: t.Name, Colour: t.Colour,
			Taxonomy: taxonomy, Count: t.Count.Int(),
			LocalOnly: boolPtr(t.LocalOnly.Bool()),
		})
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Name < matched[j].Name })
	out.TagsTotal = len(matched)

	sig := fingerprint("taxonomies", ns, search)
	page, _, err := decodeCursor(in.Cursor, sig)
	if err != nil {
		return nil, err
	}
	limit := clamp(in.Limit, s.cfg.Caps.SearchDefault, s.cfg.Caps.SearchMax)

	// tags/index is not paginated by MISP, so the window is applied here.
	start := (page - 1) * limit
	if start > len(matched) {
		start = len(matched)
	}
	end := min(start+limit, len(matched))
	pageTags := matched[start:end]
	hasMore := end < len(matched)

	if in.OutDir != "" {
		dir, err := resolveOutDir(s.cfg.OutRoot, in.OutDir)
		if err != nil {
			return nil, err
		}
		name := fmt.Sprintf("misp-taxonomies-%s", sig)
		path, err := spillJSONL(dir, name, matched)
		if err != nil {
			return nil, err
		}
		mpath, err := writeManifest(dir, name, map[string]any{
			"tool": "misp_taxonomies", "instance": s.client.BaseURL(),
			"namespace": in.Namespace, "tag_search": in.TagSearch,
			"taxonomies": views, "records": len(matched), "files": []string{path},
		})
		if err != nil {
			return nil, err
		}
		out.Spill = &Spill{Dir: dir, Files: []string{path, mpath}, Records: len(matched)}
		out.Page = page
		out.TagsReturned = len(matched)
		return out, nil
	}

	pageTags, truncated := fitBudget(pageTags, s.cfg.Caps.ResponseBytes)
	out.Tags = pageTags
	out.TagsReturned = len(pageTags)
	out.Page = page
	out.Truncated = truncated
	if truncated {
		out.Flags = append(out.Flags, FlagResultsTruncated)
	}
	if hasMore && !truncated {
		out.NextCursor = encodeCursor(page+1, limit, sig)
	}
	return out, nil
}

func (s *Service) predicates(ctx context.Context, taxonomies []misp.Taxonomy, ns string) ([]string, error) {
	for _, t := range taxonomies {
		if !strings.EqualFold(t.Namespace, ns) {
			continue
		}
		_, entries, err := s.client.Taxonomy(ctx, t.ID.String())
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.Tag != "" {
				out = append(out, e.Tag)
			}
		}
		sort.Strings(out)
		return out, nil
	}
	return nil, fmt.Errorf("taxonomy %q not found", ns)
}
