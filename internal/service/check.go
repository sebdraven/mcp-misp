package service

import (
	"context"
	"fmt"

	"github.com/sebdraven/mcp-misp/internal/misp"
)

type CheckInput struct {
	Values []string
	Type   string
}

type CheckEntry struct {
	Value string                `json:"value"`
	Hit   bool                  `json:"hit"`
	Lists []misp.WarninglistHit `json:"lists,omitempty"`
}

type WarninglistView struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Type        string   `json:"type,omitempty"`
	Category    string   `json:"category,omitempty"`
	Description string   `json:"description,omitempty"`
	Entries     int      `json:"entries,omitempty"`
	AppliesTo   []string `json:"applies_to,omitempty"`
}

type CheckResult struct {
	Results      []CheckEntry      `json:"results,omitempty"`
	Report       Report            `json:"report"`
	Warninglists []WarninglistView `json:"warninglists,omitempty"`
	Flags        []string          `json:"flags,omitempty"`
	Notes        []string          `json:"notes,omitempty"`
}

// CheckWarninglists answers the question directly, for values that did not come
// out of a search. With no values it inventories the enabled lists instead,
// which is what a caller needs before reading any hit this instance reports.
func (s *Service) CheckWarninglists(ctx context.Context, in CheckInput) (*CheckResult, error) {
	if len(in.Values) == 0 {
		return s.listWarninglists(ctx)
	}
	if len(in.Values) > s.cfg.Caps.CheckValues {
		return nil, fmt.Errorf("too many values: %d, ceiling is %d per call", len(in.Values), s.cfg.Caps.CheckValues)
	}

	subjects := make([]Subject, 0, len(in.Values))
	for _, v := range in.Values {
		subjects = append(subjects, Subject{Value: v, Type: in.Type})
	}
	checks, report := s.wl.Check(ctx, subjects)

	out := &CheckResult{Report: report}
	seen := map[string]bool{}
	for _, v := range in.Values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		c := checks[v]
		out.Results = append(out.Results, CheckEntry{Value: v, Hit: c.Hit, Lists: c.Lists})
	}
	out.Flags = append(out.Flags, coverageFlags(report)...)
	if report.Hits > 0 {
		out.Flags = append(out.Flags, FlagWarninglisted)
	}
	if report.Coverage != CoverageComplete {
		out.Notes = append(out.Notes, "coverage is not complete: a value reported without a hit was not necessarily checked against every enabled list")
	}
	return out, nil
}

func (s *Service) listWarninglists(ctx context.Context) (*CheckResult, error) {
	lists, err := s.client.Warninglists(ctx)
	if err != nil {
		return nil, err
	}
	out := &CheckResult{Report: Report{Engine: EngineNone, Coverage: CoverageComplete}}
	for _, l := range lists {
		if !l.Enabled.Bool() {
			continue
		}
		out.Warninglists = append(out.Warninglists, WarninglistView{
			ID: l.ID.String(), Name: l.Name, Type: l.Type, Category: l.Category,
			Description: l.Description, Entries: l.EntryCount(),
			AppliesTo: l.MatchingAttributes(),
		})
	}
	out.Notes = append(out.Notes, fmt.Sprintf("%d of %d warninglists are enabled on this instance; only enabled lists ever produce a hit", len(out.Warninglists), len(lists)))
	return out, nil
}
