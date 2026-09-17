package misp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// SearchParams is the shared shape of /events/restSearch and
// /attributes/restSearch. Only the fields a caller sets reach the instance.
type SearchParams struct {
	Value     string
	Type      []string
	Category  []string
	Tags      []string
	EventTags []string
	Org       string
	From      string
	To        string
	EventID   string
	UUID      string
	ToIDs     *bool
	Published *bool

	Limit int
	Page  int

	Metadata           bool
	EnforceWarninglist bool
	IncludeEventUUID   bool
	IncludeEventTags   bool
	IncludeSightings   bool
	IncludeContext     bool
	ExcludeDecayed     bool
}

func (p SearchParams) payload() map[string]any {
	q := map[string]any{"returnFormat": "json"}
	setStr(q, "value", p.Value)
	setList(q, "type", p.Type)
	setList(q, "category", p.Category)
	setList(q, "tags", p.Tags)
	setList(q, "event_tags", p.EventTags)
	setStr(q, "org", p.Org)
	setStr(q, "from", p.From)
	setStr(q, "to", p.To)
	setStr(q, "eventid", p.EventID)
	setStr(q, "uuid", p.UUID)
	if p.ToIDs != nil {
		q["to_ids"] = boolToInt(*p.ToIDs)
	}
	if p.Published != nil {
		q["published"] = *p.Published
	}
	if p.Limit > 0 {
		q["limit"] = p.Limit
	}
	if p.Page > 0 {
		q["page"] = p.Page
	}
	setFlag(q, "metadata", p.Metadata)
	setFlag(q, "enforceWarninglist", p.EnforceWarninglist)
	setFlag(q, "includeEventUuid", p.IncludeEventUUID)
	setFlag(q, "includeEventTags", p.IncludeEventTags)
	setFlag(q, "includeSightings", p.IncludeSightings)
	setFlag(q, "includeContext", p.IncludeContext)
	setFlag(q, "excludeDecayed", p.ExcludeDecayed)
	return q
}

// SearchAttributes runs /attributes/restSearch.
func (c *Client) SearchAttributes(ctx context.Context, p SearchParams) ([]Attribute, error) {
	raw, err := c.post(ctx, "/attributes/restSearch", p.payload(), true)
	if err != nil {
		return nil, err
	}
	var env struct {
		Response struct {
			Attribute []Attribute `json:"Attribute"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, c.malformed("/attributes/restSearch", err)
	}
	return env.Response.Attribute, nil
}

// SearchEvents runs /events/restSearch. Callers that only need event metadata
// must set Metadata, or the instance serialises every attribute of every match.
func (c *Client) SearchEvents(ctx context.Context, p SearchParams) ([]Event, error) {
	raw, err := c.post(ctx, "/events/restSearch", p.payload(), true)
	if err != nil {
		return nil, err
	}
	return c.decodeEvents(raw)
}

// decodeEvents absorbs the two envelopes seen in the wild: a list of {"Event":…}
// wrappers, and a single {"Event":[…]} object.
func (c *Client) decodeEvents(raw json.RawMessage) ([]Event, error) {
	var listed struct {
		Response []struct {
			Event *Event `json:"Event"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &listed); err == nil && listed.Response != nil {
		out := make([]Event, 0, len(listed.Response))
		for _, e := range listed.Response {
			if e.Event != nil {
				out = append(out, *e.Event)
			}
		}
		return out, nil
	}

	var grouped struct {
		Response struct {
			Event []Event `json:"Event"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &grouped); err != nil {
		return nil, c.malformed("/events/restSearch", err)
	}
	return grouped.Response.Event, nil
}

// WarninglistHit is one warninglist a value matched.
type WarninglistHit struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`
	Category string `json:"category,omitempty"`
}

// CheckValues asks the instance itself which warninglists each value hits.
//
// This is the whole reason there is no matching engine on the nominal path:
// cidr, hostname, substring, string and regex semantics stay MISP's, so the
// answer cannot drift from what the instance would enforce.
func (c *Client) CheckValues(ctx context.Context, values []string) (map[string][]WarninglistHit, error) {
	if len(values) == 0 {
		return map[string][]WarninglistHit{}, nil
	}
	raw, err := c.post(ctx, "/warninglists/checkValue", values, true)
	if err != nil {
		return nil, err
	}
	return decodeCheckValue(raw)
}

// decodeCheckValue tolerates the shapes this endpoint has returned over the
// years: objects per hit, bare names, or a name-keyed map.
func decodeCheckValue(raw json.RawMessage) (map[string][]WarninglistHit, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, &APIError{kind: KindMalformed, Message: "warninglists/checkValue: " + err.Error()}
	}
	out := make(map[string][]WarninglistHit, len(envelope))
	for value, entry := range envelope {
		hits, ok := decodeHits(entry)
		if !ok {
			continue
		}
		if len(hits) > 0 {
			out[value] = hits
		}
	}
	return out, nil
}

func decodeHits(entry json.RawMessage) ([]WarninglistHit, bool) {
	var objs []struct {
		ID       Str    `json:"id"`
		Name     string `json:"name"`
		Type     string `json:"type"`
		Category string `json:"category"`
	}
	if json.Unmarshal(entry, &objs) == nil {
		hits := make([]WarninglistHit, 0, len(objs))
		for _, o := range objs {
			hits = append(hits, WarninglistHit{ID: o.ID.String(), Name: o.Name, Type: o.Type, Category: o.Category})
		}
		return hits, true
	}

	var names []string
	if json.Unmarshal(entry, &names) == nil {
		hits := make([]WarninglistHit, 0, len(names))
		for _, n := range names {
			hits = append(hits, WarninglistHit{Name: n})
		}
		return hits, true
	}

	var keyed map[string]json.RawMessage
	if json.Unmarshal(entry, &keyed) == nil {
		hits := make([]WarninglistHit, 0, len(keyed))
		for n := range keyed {
			hits = append(hits, WarninglistHit{Name: n})
		}
		return hits, true
	}
	return nil, false
}

// Warninglists returns /warninglists/index, without entries.
func (c *Client) Warninglists(ctx context.Context) ([]Warninglist, error) {
	raw, err := c.get(ctx, "/warninglists/index", nil)
	if err != nil {
		return nil, err
	}
	var env struct {
		Warninglists []struct {
			Warninglist Warninglist `json:"Warninglist"`
		} `json:"Warninglists"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, c.malformed("/warninglists/index", err)
	}
	out := make([]Warninglist, 0, len(env.Warninglists))
	for _, w := range env.Warninglists {
		out = append(out, w.Warninglist)
	}
	return out, nil
}

// Warninglist returns one list with its entries. Only the local fallback engine
// needs this; it is the expensive call in the package.
func (c *Client) Warninglist(ctx context.Context, id string) (*Warninglist, error) {
	raw, err := c.get(ctx, "/warninglists/view/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	var env struct {
		Warninglist Warninglist `json:"Warninglist"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, c.malformed("/warninglists/view", err)
	}
	return &env.Warninglist, nil
}

func (c *Client) Taxonomies(ctx context.Context) ([]Taxonomy, error) {
	raw, err := c.get(ctx, "/taxonomies/index", nil)
	if err != nil {
		return nil, err
	}
	var listed []struct {
		Taxonomy Taxonomy `json:"Taxonomy"`
	}
	if err := json.Unmarshal(raw, &listed); err != nil {
		return nil, c.malformed("/taxonomies/index", err)
	}
	out := make([]Taxonomy, 0, len(listed))
	for _, t := range listed {
		out = append(out, t.Taxonomy)
	}
	return out, nil
}

// TaxonomyEntry is one predicate/value pair of a taxonomy, with the tag it
// produces.
type TaxonomyEntry struct {
	Tag         string `json:"tag"`
	Expanded    string `json:"expanded"`
	Description string `json:"description"`
}

func (c *Client) Taxonomy(ctx context.Context, id string) (*Taxonomy, []TaxonomyEntry, error) {
	raw, err := c.get(ctx, "/taxonomies/view/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, nil, err
	}
	var env struct {
		Taxonomy Taxonomy        `json:"Taxonomy"`
		Entries  []TaxonomyEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, c.malformed("/taxonomies/view", err)
	}
	return &env.Taxonomy, env.Entries, nil
}

func (c *Client) Tags(ctx context.Context) ([]Tag, error) {
	raw, err := c.get(ctx, "/tags/index", nil)
	if err != nil {
		return nil, err
	}
	var env struct {
		Tag []Tag `json:"Tag"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, c.malformed("/tags/index", err)
	}
	return env.Tag, nil
}

func (c *Client) Organisations(ctx context.Context) ([]Organisation, error) {
	raw, err := c.get(ctx, "/organisations/index/scope:all", nil)
	if err != nil {
		return nil, err
	}
	var listed []struct {
		Organisation Organisation `json:"Organisation"`
	}
	if err := json.Unmarshal(raw, &listed); err != nil {
		return nil, c.malformed("/organisations/index", err)
	}
	out := make([]Organisation, 0, len(listed))
	for _, o := range listed {
		out = append(out, o.Organisation)
	}
	return out, nil
}

func (c *Client) DescribeTypes(ctx context.Context) (*DescribeTypes, error) {
	raw, err := c.get(ctx, "/attributes/describeTypes.json", nil)
	if err != nil {
		return nil, err
	}
	var env struct {
		Result DescribeTypes `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, c.malformed("/attributes/describeTypes.json", err)
	}
	return &env.Result, nil
}

func (c *Client) Version(ctx context.Context) (*ServerVersion, error) {
	raw, err := c.get(ctx, "/servers/getVersion", nil)
	if err != nil {
		return nil, err
	}
	var v ServerVersion
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, c.malformed("/servers/getVersion", err)
	}
	return &v, nil
}

// AddAttribute creates an attribute on an event. Never retried: a create that
// timed out mid-flight may well have landed.
func (c *Client) AddAttribute(ctx context.Context, event string, in AttributeInput) (*Attribute, error) {
	raw, err := c.post(ctx, "/attributes/add/"+url.PathEscape(event), in, false)
	if err != nil {
		return nil, err
	}
	var env struct {
		Attribute *Attribute `json:"Attribute"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, c.malformed("/attributes/add", err)
	}
	if env.Attribute == nil {
		return nil, &APIError{kind: KindMalformed, Message: "attributes/add returned no attribute"}
	}
	return env.Attribute, nil
}

// AttachTag tags an event or an attribute by UUID. MISP resolves which of the
// two the UUID designates.
func (c *Client) AttachTag(ctx context.Context, targetUUID, tag string) error {
	body := map[string]any{"uuid": targetUUID, "tag": tag}
	raw, err := c.post(ctx, "/tags/attachTagToObject", body, false)
	if err != nil {
		return err
	}
	var env struct {
		Saved   Bool   `json:"saved"`
		Success string `json:"success"`
		Errors  string `json:"errors"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return c.malformed("/tags/attachTagToObject", err)
	}
	if env.Errors != "" {
		return &APIError{Status: 200, kind: KindRefused, Message: c.scrub(env.Errors)}
	}
	return nil
}

func (c *Client) malformed(endpoint string, err error) error {
	return &APIError{
		kind:    KindMalformed,
		Message: fmt.Sprintf("%s: %s", endpoint, c.scrub(err.Error())),
	}
}

func setStr(q map[string]any, key, v string) {
	if v = strings.TrimSpace(v); v != "" {
		q[key] = v
	}
}

func setList(q map[string]any, key string, v []string) {
	if len(v) > 0 {
		q[key] = v
	}
}

func setFlag(q map[string]any, key string, v bool) {
	if v {
		q[key] = 1
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
