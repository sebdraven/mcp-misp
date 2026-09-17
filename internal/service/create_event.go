package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/sebdraven/mcp-misp/internal/misp"
)

// Distribution is named rather than numeric on the write path.
//
// MISP encodes it 0-4. A caller passing 3 in the belief that it restricts
// sharing publishes to every connected community, and nothing in the number
// says otherwise. Spelling the level out makes that mistake impossible to make
// by accident.
var distributionByName = map[string]int{
	"your_organisation_only": 0,
	"this_community":         1,
	"connected_communities":  2,
	"all_communities":        3,
	"sharing_group":          4,
}

var threatLevelByName = map[string]int{"high": 1, "medium": 2, "low": 3, "undefined": 4}

var analysisByName = map[string]int{"initial": 0, "ongoing": 1, "completed": 2}

type CreateEventInput struct {
	Info           string
	Distribution   string
	SharingGroupID *int
	Date           string
	ThreatLevel    string
	Analysis       string
	Tags           []string
}

type CreateEventResult struct {
	ID           string   `json:"id"`
	UUID         string   `json:"uuid"`
	Info         string   `json:"info"`
	Date         string   `json:"date,omitempty"`
	Distribution string   `json:"distribution"`
	Published    *bool    `json:"published"`
	Org          string   `json:"org,omitempty"`
	Orgc         string   `json:"orgc,omitempty"`
	TagsApplied  []string `json:"tags_applied,omitempty"`
	TagFailures  []string `json:"tag_failures,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

func (s *Service) CreateEvent(ctx context.Context, in CreateEventInput) (*CreateEventResult, error) {
	if s.cfg.ReadOnly {
		return nil, fmt.Errorf("this server is read-only (MISP_READONLY is not false)")
	}
	if strings.TrimSpace(in.Info) == "" {
		return nil, fmt.Errorf("info is required")
	}

	dist, err := namedLevel("distribution", in.Distribution, distributionByName)
	if err != nil {
		return nil, err
	}
	if in.Distribution == "sharing_group" && in.SharingGroupID == nil {
		return nil, fmt.Errorf("distribution=sharing_group requires sharing_group_id")
	}
	if in.Distribution != "sharing_group" && in.SharingGroupID != nil {
		return nil, fmt.Errorf("sharing_group_id only applies to distribution=sharing_group")
	}

	payload := misp.EventPayload{Info: in.Info, Date: in.Date, Distribution: dist}
	if in.SharingGroupID != nil {
		payload.SharingGroupID = in.SharingGroupID
	}
	if in.ThreatLevel != "" {
		v, err := namedLevel("threat_level", in.ThreatLevel, threatLevelByName)
		if err != nil {
			return nil, err
		}
		payload.ThreatLevelID = &v
	}
	if in.Analysis != "" {
		v, err := namedLevel("analysis", in.Analysis, analysisByName)
		if err != nil {
			return nil, err
		}
		payload.Analysis = &v
	}

	event, err := s.client.AddEvent(ctx, payload)
	if err != nil {
		return nil, err
	}

	orgs, _ := s.orgIndex(ctx)
	out := &CreateEventResult{
		ID: event.ID.String(), UUID: event.UUID, Info: event.Info,
		Date: event.Date, Distribution: in.Distribution,
		Published: boolPtr(event.Published.Bool()),
	}
	if event.Org != nil {
		out.Org = event.Org.Name
	} else {
		out.Org = orgs[event.OrgID.String()]
	}
	if event.Orgc != nil {
		out.Orgc = event.Orgc.Name
	} else {
		out.Orgc = orgs[event.OrgcID.String()]
	}

	for _, tag := range in.Tags {
		if tag = strings.TrimSpace(tag); tag == "" {
			continue
		}
		if err := s.client.AttachTag(ctx, event.UUID, tag); err != nil {
			out.TagFailures = append(out.TagFailures, fmt.Sprintf("%s: %v", tag, err))
			continue
		}
		out.TagsApplied = append(out.TagsApplied, tag)
	}
	if len(out.TagFailures) > 0 {
		out.Notes = append(out.Notes, "the event was created; the tags under tag_failures were not applied")
	}
	out.Notes = append(out.Notes,
		"the event is a draft: published is not settable through this server, and publishing stays a human decision in the MISP interface")
	return out, nil
}

func namedLevel(field, value string, table map[string]int) (int, error) {
	v, ok := table[strings.ToLower(strings.TrimSpace(value))]
	if ok {
		return v, nil
	}
	names := make([]string, 0, len(table))
	for n := range table {
		names = append(names, n)
	}
	sort.Strings(names)
	if strings.TrimSpace(value) == "" {
		return 0, fmt.Errorf("%s is required and must be one of: %s", field, strings.Join(names, ", "))
	}
	return 0, fmt.Errorf("%s %q is not one of: %s", field, value, strings.Join(names, ", "))
}
