package service

import (
	"context"
	"fmt"

	"github.com/sebdraven/mcp-misp/internal/misp"
)

type EventInput struct {
	Event             string
	Fields            []string
	AttributeFields   []string
	AttributeType     []string
	AttributeCategory []string
	ToIDsOnly         bool
	AttributeLimit    int
	AttributeCursor   string
	OutDir            string
}

type EventResult struct {
	Event               EventView       `json:"event"`
	Attributes          []AttributeView `json:"attributes,omitempty"`
	AttributesReturned  int             `json:"attributes_returned"`
	AttributePage       int             `json:"attribute_page"`
	NextAttributeCursor string          `json:"next_attribute_cursor,omitempty"`
	Truncated           bool            `json:"truncated"`
	Warninglist         Report          `json:"warninglist"`
	Flags               []string        `json:"flags,omitempty"`
	Spill               *Spill          `json:"spill,omitempty"`
	Notes               []string        `json:"notes,omitempty"`
}

// Event reads one event in two bounded calls: metadata first, then a page of
// attributes.
//
// It never asks for the event object itself. /events/view on an event with tens
// of thousands of attributes serialises all of them, which is precisely the
// failure this server exists to avoid; metadata=1 plus a paginated attribute
// search has a ceiling by construction.
func (s *Service) Event(ctx context.Context, in EventInput) (*EventResult, error) {
	eventAllow, err := resolveFields(in.Fields, eventFields, defaultEventFields)
	if err != nil {
		return nil, err
	}
	attrAllow, err := resolveFields(in.AttributeFields, attributeFields, defaultAttributeFields)
	if err != nil {
		return nil, err
	}

	event, err := s.resolveEvent(ctx, in.Event)
	if err != nil {
		return nil, err
	}

	orgs, _ := s.orgIndex(ctx)
	view := s.eventView(*event, orgs)
	total := view.AttributeCount
	projectEvent(&view, eventAllow)

	sig := fingerprint("event", event.UUID, in.AttributeType, in.AttributeCategory, in.ToIDsOnly)
	page, _, err := decodeCursor(in.AttributeCursor, sig)
	if err != nil {
		return nil, err
	}
	limit := clamp(in.AttributeLimit, s.cfg.Caps.AttrDefault, s.cfg.Caps.AttrMax)

	p := misp.SearchParams{
		EventID:          event.ID.String(),
		Type:             in.AttributeType,
		Category:         in.AttributeCategory,
		Limit:            limit,
		Page:             page,
		IncludeEventUUID: true,
	}
	if in.ToIDsOnly {
		p.ToIDs = boolPtr(true)
	}

	attrs, err := s.client.SearchAttributes(ctx, p)
	if err != nil {
		return nil, err
	}
	hasMore := len(attrs) == limit

	views := make([]AttributeView, 0, len(attrs))
	subjects := make([]Subject, 0, len(attrs))
	for _, a := range attrs {
		v := s.attributeView(a, orgs)
		// The header already carries the event; repeating it on every row of a
		// thousand-attribute page is pure volume.
		v.EventInfo, v.EventDate, v.EventPublished = "", "", nil
		v.Org, v.Orgc, v.EventTags = "", "", nil
		views = append(views, v)
		subjects = append(subjects, Subject{Value: a.Value, Type: a.Type})
	}

	checks, report := s.wl.Check(ctx, subjects)
	for i := range views {
		c := checks[attrs[i].Value]
		views[i].Warninglist = &c
		projectAttribute(&views[i], attrAllow)
	}

	out := &EventResult{Event: view, AttributePage: page, Warninglist: report}
	out.Flags = append(out.Flags, coverageFlags(report)...)
	if eventAllow["galaxies"] && len(view.Galaxies) == 0 {
		out.Notes = append(out.Notes, galaxyReservation)
	}
	if total > limit {
		out.Notes = append(out.Notes, fmt.Sprintf("the event carries %d attributes; this is one page of %d", total, limit))
	}

	if in.OutDir != "" {
		dir, err := resolveOutDir(s.cfg.OutRoot, in.OutDir)
		if err != nil {
			return nil, err
		}
		name := fmt.Sprintf("misp-event-%s-p%d", event.UUID, page)
		path, err := spillJSONL(dir, name, views)
		if err != nil {
			return nil, err
		}
		mpath, err := writeManifest(dir, name, map[string]any{
			"tool": "misp_event", "instance": s.client.BaseURL(),
			"event": view, "page": page, "limit": limit,
			"records": len(views), "attribute_count": total,
			"warninglist": report, "files": []string{path},
		})
		if err != nil {
			return nil, err
		}
		out.Spill = &Spill{Dir: dir, Files: []string{path, mpath}, Records: len(views)}
		out.AttributesReturned = len(views)
		if hasMore {
			out.NextAttributeCursor = encodeCursor(page+1, limit, sig)
		}
		return out, nil
	}

	views, truncated := fitBudget(views, s.cfg.Caps.ResponseBytes)
	out.Attributes = views
	out.AttributesReturned = len(views)
	out.Truncated = truncated
	if truncated {
		out.Flags = append(out.Flags, FlagResultsTruncated)
		out.Notes = append(out.Notes, "the response byte ceiling trimmed this page; pass out_dir to get the whole set on disk")
	}
	if hasMore && !truncated {
		out.NextAttributeCursor = encodeCursor(page+1, limit, sig)
	}
	return out, nil
}
