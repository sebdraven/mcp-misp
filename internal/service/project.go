package service

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/sebdraven/mcp-misp/internal/misp"
)

// AttributeView is the projected shape of a MISP attribute.
//
// Every field is omitempty and the default set is narrow: a MISP event can
// carry thousands of attributes, and the raw object is never what a caller
// needs. The event context travels with each attribute on purpose — an
// attribute on its own says nothing in CTI, and making the caller fetch the
// event per result would put the volume straight back.
type AttributeView struct {
	EventID        string   `json:"event_id,omitempty"`
	EventUUID      string   `json:"event_uuid,omitempty"`
	EventInfo      string   `json:"event_info,omitempty"`
	EventDate      string   `json:"event_date,omitempty"`
	EventPublished *bool    `json:"event_published,omitempty"`
	Org            string   `json:"org,omitempty"`
	Orgc           string   `json:"orgc,omitempty"`
	EventTags      []string `json:"event_tags,omitempty"`

	UUID           string   `json:"uuid,omitempty"`
	Type           string   `json:"type,omitempty"`
	Category       string   `json:"category,omitempty"`
	Value          string   `json:"value,omitempty"`
	ToIDs          *bool    `json:"to_ids,omitempty"`
	Comment        string   `json:"comment,omitempty"`
	Timestamp      string   `json:"timestamp,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	ObjectID       string   `json:"object_id,omitempty"`
	ObjectRelation string   `json:"object_relation,omitempty"`
	FirstSeen      string   `json:"first_seen,omitempty"`
	LastSeen       string   `json:"last_seen,omitempty"`

	Sightings   *SightingSummary `json:"sightings,omitempty"`
	Warninglist *Check           `json:"warninglist,omitempty"`
}

type SightingSummary struct {
	Count         int    `json:"count"`
	FalsePositive int    `json:"false_positive,omitempty"`
	Expiration    int    `json:"expiration,omitempty"`
	First         string `json:"first,omitempty"`
	Last          string `json:"last,omitempty"`
}

type GalaxyView struct {
	Namespace string   `json:"namespace,omitempty"`
	Type      string   `json:"type,omitempty"`
	Clusters  []string `json:"clusters,omitempty"`
}

type EventView struct {
	ID             string       `json:"id,omitempty"`
	UUID           string       `json:"uuid,omitempty"`
	Info           string       `json:"info,omitempty"`
	Date           string       `json:"date,omitempty"`
	Published      *bool        `json:"published,omitempty"`
	ThreatLevel    string       `json:"threat_level,omitempty"`
	Analysis       string       `json:"analysis,omitempty"`
	Distribution   string       `json:"distribution,omitempty"`
	Org            string       `json:"org,omitempty"`
	Orgc           string       `json:"orgc,omitempty"`
	Timestamp      string       `json:"timestamp,omitempty"`
	Tags           []string     `json:"tags,omitempty"`
	Galaxies       []GalaxyView `json:"galaxies,omitempty"`
	AttributeCount int          `json:"attribute_count,omitempty"`
}

// attributeFields is the vocabulary of the fields parameter. warninglist is
// absent on purpose: it is always returned and cannot be projected away.
var attributeFields = []string{
	"event_id", "event_uuid", "event_info", "event_date", "event_published",
	"org", "orgc", "event_tags",
	"uuid", "type", "category", "value", "to_ids", "comment", "timestamp", "tags",
	"object_id", "object_relation", "first_seen", "last_seen", "sightings",
}

var defaultAttributeFields = []string{
	"event_id", "event_uuid", "event_info", "event_date", "event_published",
	"org", "orgc", "event_tags",
	"uuid", "type", "category", "value", "to_ids", "comment", "timestamp", "tags",
}

var eventFields = []string{
	"id", "uuid", "info", "date", "published", "threat_level", "analysis",
	"distribution", "org", "orgc", "timestamp", "tags", "galaxies",
	"attribute_count",
}

var defaultEventFields = []string{
	"id", "uuid", "info", "date", "published", "threat_level", "analysis",
	"org", "orgc", "tags", "attribute_count",
}

// resolveFields validates a requested projection against a vocabulary. An
// unknown name is an error naming the valid ones rather than a silent no-op,
// because a silently ignored field looks exactly like an empty result.
func resolveFields(requested, known, def []string) (map[string]bool, error) {
	if len(requested) == 0 {
		return setOf(def), nil
	}
	out := make(map[string]bool, len(requested))
	var unknown []string
	for _, f := range requested {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		if !slices.Contains(known, f) {
			unknown = append(unknown, f)
			continue
		}
		out[f] = true
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown field(s) %s; valid fields are: %s",
			strings.Join(unknown, ", "), strings.Join(known, ", "))
	}
	if len(out) == 0 {
		return setOf(def), nil
	}
	return out, nil
}

func setOf(v []string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}

func (s *Service) attributeView(a misp.Attribute, orgs map[string]string) AttributeView {
	own, inherited, _ := splitTags(a.Tag)
	v := AttributeView{
		UUID:           a.UUID,
		Type:           a.Type,
		Category:       a.Category,
		Value:          a.Value,
		ToIDs:          boolPtr(a.ToIDs.Bool()),
		Comment:        a.Comment,
		Timestamp:      a.Timestamp.String(),
		Tags:           own,
		EventTags:      inherited,
		ObjectID:       a.ObjectID.String(),
		ObjectRelation: a.ObjectRelation,
		FirstSeen:      a.FirstSeen.String(),
		LastSeen:       a.LastSeen.String(),
		EventID:        a.EventID.String(),
	}
	if a.Event != nil {
		v.EventID = a.Event.ID.String()
		v.EventUUID = a.Event.UUID
		v.EventInfo = a.Event.Info
		v.EventDate = a.Event.Date
		v.EventPublished = boolPtr(a.Event.Published.Bool())
		v.Org = orgs[a.Event.OrgID.String()]
		v.Orgc = orgs[a.Event.OrgcID.String()]
	}
	if len(a.Sighting) > 0 {
		v.Sightings = summariseSightings(a.Sighting)
	}
	return v
}

func summariseSightings(ss []misp.Sighting) *SightingSummary {
	out := &SightingSummary{}
	for _, s := range ss {
		switch s.Type.String() {
		case misp.SightingFalsePositive:
			out.FalsePositive++
		case misp.SightingExpiration:
			out.Expiration++
		default:
			out.Count++
		}
		d := s.DateSighting.String()
		if d == "" {
			continue
		}
		if out.First == "" || d < out.First {
			out.First = d
		}
		if d > out.Last {
			out.Last = d
		}
	}
	return out
}

func projectAttribute(v *AttributeView, allow map[string]bool) {
	if !allow["event_id"] {
		v.EventID = ""
	}
	if !allow["event_uuid"] {
		v.EventUUID = ""
	}
	if !allow["event_info"] {
		v.EventInfo = ""
	}
	if !allow["event_date"] {
		v.EventDate = ""
	}
	if !allow["event_published"] {
		v.EventPublished = nil
	}
	if !allow["org"] {
		v.Org = ""
	}
	if !allow["orgc"] {
		v.Orgc = ""
	}
	if !allow["event_tags"] {
		v.EventTags = nil
	}
	if !allow["uuid"] {
		v.UUID = ""
	}
	if !allow["type"] {
		v.Type = ""
	}
	if !allow["category"] {
		v.Category = ""
	}
	if !allow["value"] {
		v.Value = ""
	}
	if !allow["to_ids"] {
		v.ToIDs = nil
	}
	if !allow["comment"] {
		v.Comment = ""
	}
	if !allow["timestamp"] {
		v.Timestamp = ""
	}
	if !allow["tags"] {
		v.Tags = nil
	}
	if !allow["object_id"] {
		v.ObjectID = ""
	}
	if !allow["object_relation"] {
		v.ObjectRelation = ""
	}
	if !allow["first_seen"] {
		v.FirstSeen = ""
	}
	if !allow["last_seen"] {
		v.LastSeen = ""
	}
	if !allow["sightings"] {
		v.Sightings = nil
	}
}

func (s *Service) eventView(e misp.Event, orgs map[string]string) EventView {
	v := EventView{
		ID:             e.ID.String(),
		UUID:           e.UUID,
		Info:           e.Info,
		Date:           e.Date,
		Published:      boolPtr(e.Published.Bool()),
		ThreatLevel:    label(threatLevels, e.ThreatLevelID),
		Analysis:       label(analysisState, e.Analysis),
		Distribution:   label(distributions, e.Distribution),
		Timestamp:      e.Timestamp.String(),
		Tags:           tagNames(e.Tag),
		AttributeCount: e.AttributeCount.Int(),
	}
	if e.Org != nil {
		v.Org = e.Org.Name
	} else {
		v.Org = orgs[e.OrgID.String()]
	}
	if e.Orgc != nil {
		v.Orgc = e.Orgc.Name
	} else {
		v.Orgc = orgs[e.OrgcID.String()]
	}
	for _, g := range e.Galaxy {
		gv := GalaxyView{Namespace: g.Namespace, Type: g.Type}
		for _, c := range g.Clusters {
			if c.TagName != "" {
				gv.Clusters = append(gv.Clusters, c.TagName)
			} else if c.Value != "" {
				gv.Clusters = append(gv.Clusters, c.Value)
			}
		}
		v.Galaxies = append(v.Galaxies, gv)
	}
	return v
}

func projectEvent(v *EventView, allow map[string]bool) {
	if !allow["id"] {
		v.ID = ""
	}
	if !allow["uuid"] {
		v.UUID = ""
	}
	if !allow["info"] {
		v.Info = ""
	}
	if !allow["date"] {
		v.Date = ""
	}
	if !allow["published"] {
		v.Published = nil
	}
	if !allow["threat_level"] {
		v.ThreatLevel = ""
	}
	if !allow["analysis"] {
		v.Analysis = ""
	}
	if !allow["distribution"] {
		v.Distribution = ""
	}
	if !allow["org"] {
		v.Org = ""
	}
	if !allow["orgc"] {
		v.Orgc = ""
	}
	if !allow["timestamp"] {
		v.Timestamp = ""
	}
	if !allow["tags"] {
		v.Tags = nil
	}
	if !allow["galaxies"] {
		v.Galaxies = nil
	}
	if !allow["attribute_count"] {
		v.AttributeCount = 0
	}
}

// fitBudget trims a result set to a byte ceiling, reporting whether it had to.
// The ceiling is the last line of defence: the per-tool limits already bound
// the count, but an attribute's comment field has no bound of its own.
func fitBudget[T any](items []T, budget int) ([]T, bool) {
	if budget <= 0 || len(items) == 0 {
		return items, false
	}
	total := 2
	for i, it := range items {
		b, err := json.Marshal(it)
		if err != nil {
			continue
		}
		total += len(b) + 1
		if total > budget {
			return items[:i], true
		}
	}
	return items, false
}
