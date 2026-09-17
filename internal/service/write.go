package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/sebdraven/mcp-misp/internal/misp"
)

type AddAttributeInput struct {
	Event              string
	Type               string
	Value              string
	Category           string
	Comment            string
	ToIDs              *bool
	Distribution       *int
	Tags               []string
	AllowWarninglisted bool
}

type AddAttributeResult struct {
	Created     bool           `json:"created"`
	Refused     string         `json:"refused,omitempty"`
	Attribute   *AttributeView `json:"attribute,omitempty"`
	Warninglist Check          `json:"warninglist"`
	Report      Report         `json:"warninglist_report"`
	TagsApplied []string       `json:"tags_applied,omitempty"`
	TagFailures []string       `json:"tag_failures,omitempty"`
	Flags       []string       `json:"flags,omitempty"`
	Notes       []string       `json:"notes,omitempty"`
}

func (s *Service) AddAttribute(ctx context.Context, in AddAttributeInput) (*AddAttributeResult, error) {
	if s.cfg.ReadOnly {
		return nil, fmt.Errorf("this server is read-only (MISP_READONLY is not false)")
	}
	if in.Event == "" || in.Type == "" || in.Value == "" {
		return nil, fmt.Errorf("event, type and value are required")
	}

	event, err := s.resolveEvent(ctx, in.Event)
	if err != nil {
		return nil, err
	}

	checks, report := s.wl.Check(ctx, []Subject{{Value: in.Value, Type: in.Type}})
	check := checks[in.Value]

	out := &AddAttributeResult{Warninglist: check, Report: report}
	out.Flags = append(out.Flags, coverageFlags(report)...)
	if check.Hit {
		out.Flags = append(out.Flags, FlagWarninglisted)
	}
	if report.Coverage != CoverageComplete {
		out.Notes = append(out.Notes, "the warninglist check did not cover every enabled list, so a clean verdict here is weaker than usual")
	}

	if check.Hit && !in.AllowWarninglisted {
		out.Refused = refusalMessage(in.Value, check, report)
		return out, nil
	}

	created, err := s.client.AddAttribute(ctx, event.ID.String(), misp.AttributeInput{
		Type:         in.Type,
		Value:        in.Value,
		Category:     in.Category,
		ToIDs:        in.ToIDs,
		Comment:      in.Comment,
		Distribution: in.Distribution,
	})
	if err != nil {
		return nil, err
	}
	out.Created = true

	orgs, _ := s.orgIndex(ctx)
	view := s.attributeView(*created, orgs)
	view.Warninglist = &check
	out.Attribute = &view

	for _, tag := range in.Tags {
		if tag = strings.TrimSpace(tag); tag == "" {
			continue
		}
		if err := s.client.AttachTag(ctx, created.UUID, tag); err != nil {
			out.TagFailures = append(out.TagFailures, fmt.Sprintf("%s: %v", tag, err))
			continue
		}
		out.TagsApplied = append(out.TagsApplied, tag)
	}
	if len(out.TagFailures) > 0 {
		out.Notes = append(out.Notes, "the attribute was created; the tags listed under tag_failures were not applied")
	}
	return out, nil
}

// refusalMessage names the engine that decided and the lists it matched.
//
// The local fallback also honours each list's valid_attributes, which the
// instance's own checkValue does not, so it can refuse a value the MISP web UI
// would accept. A refusal that does not say which engine ruled, and on which
// list, leaves the user with a value that works in one place and not the other
// and no way to tell why.
func refusalMessage(value string, check Check, report Report) string {
	names := make([]string, 0, len(check.Lists))
	for _, l := range check.Lists {
		names = append(names, fmt.Sprintf("%q", l.Name))
	}
	lists := strings.Join(names, ", ")

	switch report.Engine {
	case EngineLocal:
		return fmt.Sprintf(
			"not created: %q matches warninglist(s) %s. Decided by this server's local fallback engine, "+
				"because the instance does not expose POST /warninglists/checkValue. The fallback also applies each list's "+
				"valid_attributes, which the instance's own check does not, so this value may be accepted through the MISP web UI. "+
				"Pass allow_warninglisted=true to create it anyway.",
			value, lists)
	default:
		return fmt.Sprintf(
			"not created: %q matches warninglist(s) %s. Decided by the instance's own matching engine "+
				"(POST /warninglists/checkValue). Pass allow_warninglisted=true to create it anyway.",
			value, lists)
	}
}

type TagInput struct {
	Target string
	ID     string
	Tags   []string
}

type TagResult struct {
	Target   string   `json:"target"`
	UUID     string   `json:"uuid"`
	Applied  []string `json:"applied,omitempty"`
	Failures []string `json:"failures,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

// Tag attaches tags to an event or an attribute.
//
// Adding only. Removal is deliberately absent: tlp: and PAP: tags drive
// distribution, so a removal tool is a distribution change wearing the clothes
// of an annotation. Were one ever added, it would have to refuse those two
// namespaces outright.
func (s *Service) Tag(ctx context.Context, in TagInput) (*TagResult, error) {
	if s.cfg.ReadOnly {
		return nil, fmt.Errorf("this server is read-only (MISP_READONLY is not false)")
	}
	target := strings.ToLower(strings.TrimSpace(in.Target))
	if target != "event" && target != "attribute" {
		return nil, fmt.Errorf("target %q: want event or attribute", in.Target)
	}
	if len(in.Tags) == 0 {
		return nil, fmt.Errorf("at least one tag is required")
	}

	uuid, err := s.targetUUID(ctx, target, in.ID)
	if err != nil {
		return nil, err
	}

	out := &TagResult{Target: target, UUID: uuid}
	for _, tag := range in.Tags {
		if tag = strings.TrimSpace(tag); tag == "" {
			continue
		}
		if err := s.client.AttachTag(ctx, uuid, tag); err != nil {
			out.Failures = append(out.Failures, fmt.Sprintf("%s: %v", tag, err))
			continue
		}
		out.Applied = append(out.Applied, tag)
	}
	return out, nil
}

// targetUUID turns a numeric id into the UUID the tagging endpoint needs.
func (s *Service) targetUUID(ctx context.Context, target, id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("id is required")
	}
	if !looksNumeric(id) {
		return id, nil
	}
	if target == "event" {
		event, err := s.resolveEvent(ctx, id)
		if err != nil {
			return "", err
		}
		return event.UUID, nil
	}
	attr, err := s.client.Attribute(ctx, id)
	if err != nil {
		return "", err
	}
	if attr.UUID == "" {
		return "", fmt.Errorf("attribute %s has no uuid", id)
	}
	return attr.UUID, nil
}
