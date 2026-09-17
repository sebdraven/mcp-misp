package misp

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
)

// ObjectTemplate is one row of /objectTemplates/index: metadata only, no
// relations.
type ObjectTemplate struct {
	ID           Str    `json:"id"`
	UUID         string `json:"uuid"`
	Name         string `json:"name"`
	Version      Str    `json:"version"`
	MetaCategory string `json:"meta-category"`
	Description  string `json:"description"`
	Active       Bool   `json:"active"`
	Fixed        Bool   `json:"fixed"`
	Requirements struct {
		Required      []string `json:"required"`
		RequiredOneOf []string `json:"requiredOneOf"`
	} `json:"requirements"`
}

// ObjectTemplateAttribute is one relation of a template definition.
type ObjectTemplateAttribute struct {
	MISPAttribute      string   `json:"misp-attribute"`
	Description        string   `json:"description"`
	Multiple           Bool     `json:"multiple"`
	Categories         []string `json:"categories"`
	DisableCorrelation Bool     `json:"disable_correlation"`
	SaneDefault        []string `json:"sane_default"`
	ValuesList         []string `json:"values_list"`
	UIPriority         Str      `json:"ui-priority"`
}

// ObjectTemplateDefinition is the raw template as misp-objects defines it.
//
// Required and RequiredOneOf are the only constraints the format carries. There
// is no deduplication key: that question is settled at write time by
// breakOnDuplicate, not by the template.
type ObjectTemplateDefinition struct {
	Name          string                             `json:"name"`
	UUID          string                             `json:"uuid"`
	Version       Str                                `json:"version"`
	MetaCategory  string                             `json:"meta-category"`
	Description   string                             `json:"description"`
	Required      []string                           `json:"required"`
	RequiredOneOf []string                           `json:"requiredOneOf"`
	Attributes    map[string]ObjectTemplateAttribute `json:"attributes"`
}

type ObjectRelationship struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Opposite    string `json:"opposite"`
}

// ObjectTemplates returns GET /objectTemplates/index.
func (c *Client) ObjectTemplates(ctx context.Context) ([]ObjectTemplate, error) {
	raw, err := c.get(ctx, "/objectTemplates/index", nil)
	if err != nil {
		return nil, err
	}
	var listed []struct {
		ObjectTemplate ObjectTemplate `json:"ObjectTemplate"`
	}
	if err := json.Unmarshal(raw, &listed); err != nil {
		return nil, c.malformed("/objectTemplates/index", err)
	}
	out := make([]ObjectTemplate, 0, len(listed))
	for _, t := range listed {
		out = append(out, t.ObjectTemplate)
	}
	return out, nil
}

// ObjectTemplateRaw returns the template definition. The endpoint accepts a
// name as well as a uuid, which is what lets a caller name "file" rather than
// carry a uuid around.
func (c *Client) ObjectTemplateRaw(ctx context.Context, nameOrUUID string) (*ObjectTemplateDefinition, error) {
	raw, err := c.get(ctx, "/objectTemplates/getRaw/"+url.PathEscape(nameOrUUID), nil)
	if err != nil {
		return nil, err
	}
	var def ObjectTemplateDefinition
	if err := json.Unmarshal(raw, &def); err != nil {
		return nil, c.malformed("/objectTemplates/getRaw", err)
	}
	if def.Name == "" || def.Attributes == nil {
		return nil, &APIError{kind: KindNotFound, Message: "object template " + nameOrUUID + " not found on this instance"}
	}
	return &def, nil
}

// ObjectRelationships probes the instance for its object-relationship
// vocabulary.
//
// MISP seeds these from misp-objects into a table, but exposes no documented
// REST index for them and stores relationship_type as free text. The probe
// exists so an instance that does expose them gets validation for free; when it
// does not, the caller degrades and says so rather than validating against a
// table baked in here.
func (c *Client) ObjectRelationships(ctx context.Context) ([]ObjectRelationship, error) {
	raw, err := c.get(ctx, "/object_relationships/index", nil)
	if err != nil {
		return nil, err
	}
	var listed []struct {
		ObjectRelationship ObjectRelationship `json:"ObjectRelationship"`
	}
	if err := json.Unmarshal(raw, &listed); err == nil && len(listed) > 0 {
		out := make([]ObjectRelationship, 0, len(listed))
		for _, r := range listed {
			out = append(out, r.ObjectRelationship)
		}
		return out, nil
	}
	var grouped struct {
		ObjectRelationship []ObjectRelationship `json:"ObjectRelationship"`
	}
	if err := json.Unmarshal(raw, &grouped); err == nil && len(grouped.ObjectRelationship) > 0 {
		return grouped.ObjectRelationship, nil
	}
	var flat []ObjectRelationship
	if err := json.Unmarshal(raw, &flat); err == nil && len(flat) > 0 {
		return flat, nil
	}
	return nil, &APIError{kind: KindMalformed, Message: "object relationship vocabulary not exposed by this instance"}
}

// EventPayload is the body of POST /events/add.
//
// It has no published field, deliberately: an event created here is a draft,
// and publishing stays a human gesture in the MISP interface.
type EventPayload struct {
	Info           string `json:"info"`
	Date           string `json:"date,omitempty"`
	ThreatLevelID  *int   `json:"threat_level_id,omitempty"`
	Analysis       *int   `json:"analysis,omitempty"`
	Distribution   int    `json:"distribution"`
	SharingGroupID *int   `json:"sharing_group_id,omitempty"`
}

func (c *Client) AddEvent(ctx context.Context, p EventPayload) (*Event, error) {
	raw, err := c.post(ctx, "/events/add", p, false)
	if err != nil {
		return nil, err
	}
	var env struct {
		Event *Event `json:"Event"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, c.malformed("/events/add", err)
	}
	if env.Event == nil {
		return nil, &APIError{kind: KindMalformed, Message: "events/add returned no event"}
	}
	return env.Event, nil
}

type ObjectAttributePayload struct {
	Type           string `json:"type"`
	ObjectRelation string `json:"object_relation"`
	Value          string `json:"value"`
	Category       string `json:"category,omitempty"`
	Comment        string `json:"comment,omitempty"`
	ToIDs          *bool  `json:"to_ids,omitempty"`
}

type ObjectPayload struct {
	Name            string                   `json:"name"`
	MetaCategory    string                   `json:"meta-category,omitempty"`
	Description     string                   `json:"description,omitempty"`
	TemplateUUID    string                   `json:"template_uuid,omitempty"`
	TemplateVersion string                   `json:"template_version,omitempty"`
	Comment         string                   `json:"comment,omitempty"`
	Distribution    *int                     `json:"distribution,omitempty"`
	Attribute       []ObjectAttributePayload `json:"Attribute"`
}

type ObjectResult struct {
	ID        Str         `json:"id"`
	UUID      string      `json:"uuid"`
	Name      string      `json:"name"`
	Attribute []Attribute `json:"Attribute"`
}

// AddObject creates an object on an event.
//
// breakOnDuplicate is always sent explicitly rather than left to the instance
// default, and it travels as a CakePHP named path parameter, not a query
// string. Never retried: a create that timed out mid-flight may have landed.
func (c *Client) AddObject(ctx context.Context, eventID string, p ObjectPayload, breakOnDuplicate bool) (*ObjectResult, error) {
	path := "/objects/add/" + url.PathEscape(eventID)
	if breakOnDuplicate {
		path += "/breakOnDuplicate:1"
	} else {
		path += "/breakOnDuplicate:0"
	}
	raw, err := c.post(ctx, path, p, false)
	if err != nil {
		return nil, err
	}
	var env struct {
		Object *ObjectResult   `json:"Object"`
		Errors json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, c.malformed("/objects/add", err)
	}
	if len(env.Errors) > 0 && string(env.Errors) != "null" {
		return nil, &APIError{Status: 200, kind: KindRefused, Message: c.scrub(firstLine(string(env.Errors), 300))}
	}
	if env.Object == nil {
		return nil, &APIError{kind: KindMalformed, Message: "objects/add returned no object"}
	}
	return env.Object, nil
}

type ObjectReferencePayload struct {
	ObjectUUID       string `json:"object_uuid"`
	ReferencedUUID   string `json:"referenced_uuid"`
	RelationshipType string `json:"relationship_type"`
	Comment          string `json:"comment,omitempty"`
}

func (c *Client) AddObjectReference(ctx context.Context, p ObjectReferencePayload) error {
	raw, err := c.post(ctx, "/objectReferences/add", p, false)
	if err != nil {
		return err
	}
	var env struct {
		Errors json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return c.malformed("/objectReferences/add", err)
	}
	if len(env.Errors) > 0 && string(env.Errors) != "null" {
		return &APIError{Status: 200, kind: KindRefused, Message: c.scrub(firstLine(string(env.Errors), 300))}
	}
	return nil
}

// IsDuplicate reports whether err is MISP refusing a write because an identical
// object already exists. The signal is the message text, which is why the raw
// message is always carried through to the caller as well.
func IsDuplicate(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "duplicate") ||
		strings.Contains(strings.ToLower(err.Error()), "similar object")
}
