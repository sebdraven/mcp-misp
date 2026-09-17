package service

import (
	"context"
	"fmt"
	"sort"

	"github.com/sebdraven/mcp-misp/internal/misp"
)

type ContextInput struct {
	Value            string
	Type             []string
	MaxEvents        int
	IncludeSightings *bool
	OutDir           string
}

type ContextAttribute struct {
	UUID      string           `json:"uuid,omitempty"`
	Type      string           `json:"type,omitempty"`
	Category  string           `json:"category,omitempty"`
	ToIDs     *bool            `json:"to_ids,omitempty"`
	Comment   string           `json:"comment,omitempty"`
	Timestamp string           `json:"timestamp,omitempty"`
	Tags      []string         `json:"tags,omitempty"`
	Sightings *SightingSummary `json:"sightings,omitempty"`
}

type ContextEvent struct {
	EventID    string             `json:"event_id,omitempty"`
	EventUUID  string             `json:"event_uuid,omitempty"`
	EventInfo  string             `json:"event_info,omitempty"`
	EventDate  string             `json:"event_date,omitempty"`
	Published  *bool              `json:"published,omitempty"`
	Org        string             `json:"org,omitempty"`
	Orgc       string             `json:"orgc,omitempty"`
	EventTags  []string           `json:"event_tags,omitempty"`
	Attributes []ContextAttribute `json:"attributes,omitempty"`
}

type TagCount struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
}

type ContextAggregate struct {
	EventCount     int        `json:"event_count"`
	AttributeCount int        `json:"attribute_count"`
	Orgs           []string   `json:"orgs,omitempty"`
	ToIDsTrue      int        `json:"to_ids_true"`
	ToIDsFalse     int        `json:"to_ids_false"`
	FirstSeen      string     `json:"first_seen,omitempty"`
	LastSeen       string     `json:"last_seen,omitempty"`
	Types          []string   `json:"types,omitempty"`
	Tags           []TagCount `json:"tags,omitempty"`
}

type ContextResult struct {
	Value             string           `json:"value"`
	Warninglist       Check            `json:"warninglist"`
	WarninglistReport Report           `json:"warninglist_report"`
	Aggregate         ContextAggregate `json:"aggregate"`
	Sightings         SightingSummary  `json:"sightings"`
	Events            []ContextEvent   `json:"events,omitempty"`
	Truncated         bool             `json:"truncated"`
	Flags             []string         `json:"flags,omitempty"`
	Spill             *Spill           `json:"spill,omitempty"`
	Notes             []string         `json:"notes,omitempty"`
}

// IOCContext answers "what does this instance know about this value" in two
// calls: one attribute search carrying sightings and event tags, one warninglist
// check.
//
// The warninglist verdict is returned whether or not the value appears in any
// event, because "not in this MISP, and on an exclusion list" and "not in this
// MISP" are different answers.
func (s *Service) IOCContext(ctx context.Context, in ContextInput) (*ContextResult, error) {
	if in.Value == "" {
		return nil, fmt.Errorf("value is required")
	}
	maxEvents := clamp(in.MaxEvents, s.cfg.Caps.ContextDefault, s.cfg.Caps.ContextMax)
	withSightings := in.IncludeSightings == nil || *in.IncludeSightings

	// An IOC may carry several attributes in one event, so the attribute
	// ceiling has to be looser than the event ceiling it feeds.
	attrLimit := clamp(maxEvents*4, s.cfg.Caps.AttrDefault, s.cfg.Caps.AttrMax)

	attrs, err := s.client.SearchAttributes(ctx, misp.SearchParams{
		Value:            in.Value,
		Type:             in.Type,
		Limit:            attrLimit,
		Page:             1,
		IncludeEventUUID: true,
		IncludeEventTags: true,
		IncludeSightings: withSightings,
	})
	if err != nil {
		return nil, err
	}
	moreAttrs := len(attrs) == attrLimit

	subjects := []Subject{{Value: in.Value}}
	for _, a := range attrs {
		subjects = append(subjects, Subject{Value: a.Value, Type: a.Type})
	}
	checks, report := s.wl.Check(ctx, subjects)

	out := &ContextResult{
		Value:             in.Value,
		Warninglist:       checks[in.Value],
		WarninglistReport: report,
	}

	orgs, _ := s.orgIndex(ctx)
	byEvent := map[string]*ContextEvent{}
	var order []string
	agg := ContextAggregate{}
	orgSeen := map[string]bool{}
	typeSeen := map[string]bool{}
	tagCount := map[string]int{}

	for _, a := range attrs {
		key := a.EventID.String()
		if a.Event != nil {
			key = a.Event.UUID
		}
		ce, ok := byEvent[key]
		if !ok {
			ce = &ContextEvent{EventID: a.EventID.String()}
			if a.Event != nil {
				ce.EventID = a.Event.ID.String()
				ce.EventUUID = a.Event.UUID
				ce.EventInfo = a.Event.Info
				ce.EventDate = a.Event.Date
				ce.Published = boolPtr(a.Event.Published.Bool())
				ce.Org = orgs[a.Event.OrgID.String()]
				ce.Orgc = orgs[a.Event.OrgcID.String()]
			}
			byEvent[key] = ce
			order = append(order, key)
		}

		own, inherited, _ := splitTags(a.Tag)
		if ce.EventTags == nil && len(inherited) > 0 {
			ce.EventTags = inherited
		}
		ca := ContextAttribute{
			UUID: a.UUID, Type: a.Type, Category: a.Category,
			ToIDs: boolPtr(a.ToIDs.Bool()), Comment: a.Comment,
			Timestamp: a.Timestamp.String(), Tags: own,
		}
		if withSightings && len(a.Sighting) > 0 {
			ca.Sightings = summariseSightings(a.Sighting)
			out.Sightings.Count += ca.Sightings.Count
			out.Sightings.FalsePositive += ca.Sightings.FalsePositive
			out.Sightings.Expiration += ca.Sightings.Expiration
			if out.Sightings.First == "" || (ca.Sightings.First != "" && ca.Sightings.First < out.Sightings.First) {
				out.Sightings.First = ca.Sightings.First
			}
			if ca.Sightings.Last > out.Sightings.Last {
				out.Sightings.Last = ca.Sightings.Last
			}
		}
		ce.Attributes = append(ce.Attributes, ca)

		agg.AttributeCount++
		if a.ToIDs.Bool() {
			agg.ToIDsTrue++
		} else {
			agg.ToIDsFalse++
		}
		if ts := a.Timestamp.String(); ts != "" {
			if agg.FirstSeen == "" || ts < agg.FirstSeen {
				agg.FirstSeen = ts
			}
			if ts > agg.LastSeen {
				agg.LastSeen = ts
			}
		}
		if a.Type != "" && !typeSeen[a.Type] {
			typeSeen[a.Type] = true
			agg.Types = append(agg.Types, a.Type)
		}
		for _, o := range []string{ce.Org, ce.Orgc} {
			if o != "" && !orgSeen[o] {
				orgSeen[o] = true
				agg.Orgs = append(agg.Orgs, o)
			}
		}
		for _, t := range append(own, inherited...) {
			tagCount[t]++
		}
	}

	agg.EventCount = len(order)
	for t, n := range tagCount {
		agg.Tags = append(agg.Tags, TagCount{Tag: t, Count: n})
	}
	sort.Slice(agg.Tags, func(i, j int) bool {
		if agg.Tags[i].Count != agg.Tags[j].Count {
			return agg.Tags[i].Count > agg.Tags[j].Count
		}
		return agg.Tags[i].Tag < agg.Tags[j].Tag
	})
	out.Aggregate = agg

	events := make([]ContextEvent, 0, len(order))
	for _, k := range order {
		events = append(events, *byEvent[k])
	}
	eventsTruncated := false
	if len(events) > maxEvents {
		events = events[:maxEvents]
		eventsTruncated = true
	}

	out.Flags = append(out.Flags, coverageFlags(report)...)
	if out.Warninglist.Hit {
		out.Flags = append(out.Flags, FlagWarninglisted)
		if agg.ToIDsTrue > 0 {
			out.Flags = append(out.Flags, FlagWarninglistedAndToIDs)
		}
	}
	if moreAttrs {
		out.Notes = append(out.Notes, fmt.Sprintf("more than %d attributes carry this value; the aggregate covers the first %d only", attrLimit, attrLimit))
	}

	if in.OutDir != "" {
		dir, err := resolveOutDir(s.cfg.OutRoot, in.OutDir)
		if err != nil {
			return nil, err
		}
		name := fmt.Sprintf("misp-ioc-%s", fingerprint("ioc", in.Value, in.Type))
		path, err := spillJSONL(dir, name, events)
		if err != nil {
			return nil, err
		}
		mpath, err := writeManifest(dir, name, map[string]any{
			"tool": "misp_ioc_context", "instance": s.client.BaseURL(),
			"value": in.Value, "aggregate": agg, "sightings": out.Sightings,
			"warninglist": out.Warninglist, "warninglist_report": report,
			"records": len(events), "files": []string{path},
		})
		if err != nil {
			return nil, err
		}
		out.Spill = &Spill{Dir: dir, Files: []string{path, mpath}, Records: len(events)}
		out.Truncated = eventsTruncated
		if eventsTruncated {
			out.Flags = append(out.Flags, FlagResultsTruncated)
		}
		return out, nil
	}

	events, budgetTruncated := fitBudget(events, s.cfg.Caps.ResponseBytes)
	out.Events = events
	out.Truncated = eventsTruncated || budgetTruncated
	if out.Truncated {
		out.Flags = append(out.Flags, FlagResultsTruncated)
		out.Notes = append(out.Notes, "the event list was trimmed; the aggregate above still covers every attribute that was read")
	}
	return out, nil
}
