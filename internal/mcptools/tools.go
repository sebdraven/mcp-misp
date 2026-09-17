// Package mcptools registers the MCP tools on a server.
//
// Tool descriptions carry more weight here than parameter documentation does in
// a REST API: they are the only thing a model reads before choosing. Three
// things are therefore stated outright, because getting them wrong produces
// confident nonsense — that a warninglist hit is not an opinion but this
// instance saying the value is a known false positive, that a page is a page
// and attribute_count says how much was not read, and that nothing about the
// local tagging vocabulary can be assumed before misp_taxonomies has been
// called.
package mcptools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sebdraven/mcp-misp/internal/service"
)

type registry struct {
	svc *service.Service
}

// RegisterAll wires the tool set this server should expose.
//
// The read-only gate lives here rather than in main so that it is covered by a
// test: on a default deployment the write tools are not merely refused, they
// are absent from the tool list, and a client cannot offer what it never saw.
func RegisterAll(s *mcp.Server, svc *service.Service) []*mcp.Tool {
	tools := Register(s, svc)
	if !svc.ReadOnly() {
		tools = append(tools, RegisterWrite(s, svc)...)
	}
	return tools
}

// add records each tool as it is registered, so the set can be asserted on
// without standing up a session.
func add[In, Out any](s *mcp.Server, tools *[]*mcp.Tool, t *mcp.Tool,
	h func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, Out, error),
) {
	*tools = append(*tools, t)
	mcp.AddTool(s, t, h)
}

// Register wires the read-only tools.
func Register(s *mcp.Server, svc *service.Service) []*mcp.Tool {
	r := &registry{svc: svc}
	var tools []*mcp.Tool

	add(s, &tools, &mcp.Tool{
		Name: "misp_search",
		Description: "Search this MISP instance for attributes (default) or events, filtering on value, attribute type, category, tags, date range, to_ids, published state or producing organisation. " +
			"Each returned attribute carries its parent event — id, uuid, info, date, producing organisation, event tags — so a row is readable on its own; do NOT follow up with misp_event per result, that is the volume problem this tool exists to avoid. " +
			"Every returned value carries a warninglist verdict. Treat a hit as this instance stating the value is a known false positive, not as a hint: a hit on an attribute that is also to_ids=true is a contradiction inside the data, not a finding. " +
			"Read the 'warninglist' report before drawing anything from an ABSENCE of hits — only coverage=complete means every enabled list took part. " +
			"Paginate with next_cursor. The cursor is bound to the query that issued it and is refused against different filters. A full page always yields a cursor, so the last page can come back empty; that is the end of the set, not an error. " +
			"exclude_warninglisted asks the instance to drop warninglisted attributes before sending them: the count that comes back is then NOT a measure of how often the value appears here, because MISP does not report how many rows it removed. " +
			"For a large set pass out_dir: rows are written as JSONL on disk and only paths, counts and the summary come back.",
	}, r.search)

	add(s, &tools, &mcp.Tool{
		Name: "misp_event",
		Description: "Read one event by numeric id or UUID, as a header plus ONE PAGE of its attributes. " +
			"It never returns the whole event: a MISP event can carry tens of thousands of attributes and dumping one fills the context with no room left to reason. " +
			"attribute_count on the header is the real size — compare it with attributes_returned to know how much you did not see, and walk the rest with next_attribute_cursor rather than concluding from the first page. " +
			"Projection is separate for the header (fields) and for the attributes (attribute_fields); an unknown field name is an error listing the valid ones. " +
			"The event context lives on the header and is deliberately not repeated on every attribute row. Attributes carry their own warninglist verdict. " +
			"Objects are not returned as such: group attributes with the object_id and object_relation attribute fields.",
	}, r.event)

	add(s, &tools, &mcp.Tool{
		Name: "misp_ioc_context",
		Description: "Answer 'what does this instance know about this value' for one IOC: which events carry it, with what to_ids setting, which tags, which producing organisations, how many sightings, and its warninglist verdict. " +
			"This is the tool for deciding whether to act on an indicator, where misp_search is the tool for finding candidates. " +
			"The warninglist verdict is returned even when the value appears in no event at all, because 'unknown here AND on an exclusion list' is a different answer from 'unknown here'. " +
			"Read the flags before the events: warninglisted_and_to_ids means this instance simultaneously marks the value actionable and carries it on an exclusion list — resolve that before acting on it. " +
			"The aggregate (event_count, to_ids_true/false, first_seen, last_seen, tag counts) covers every attribute that was read, even when the event list itself was trimmed, so use the aggregate for counting and the event list for reading.",
	}, r.iocContext)

	add(s, &tools, &mcp.Tool{
		Name: "misp_warninglist_check",
		Description: "Check values against this instance's enabled warninglists — for values that did NOT come out of a search, such as a list lifted from a report before deciding what is worth looking up. " +
			"Call it with no values to inventory the enabled lists instead, with each one's matching type (cidr, hostname, substring, string, regex) and the attribute types it applies to. " +
			"Matching is done by the instance itself wherever it exposes the endpoint, so the verdict is the one the instance would enforce. Where it does not, a local engine takes over and the report says engine=local. " +
			"The report is the part to read: an absence of hits means something only under coverage=complete. Under partial or unavailable coverage a clean value was simply not checked against everything, and uncovered_lists names what was missed.",
	}, r.check)

	add(s, &tools, &mcp.Tool{
		Name: "misp_taxonomies",
		Description: "List the taxonomies and tags this instance actually carries. " +
			"Call it before filtering on any tag: this server assumes no taxonomy and no tagging convention, and a tag that exists on one MISP does not exist on the next — a filter on a tag this instance has never heard of returns nothing and looks exactly like a real absence of results. " +
			"Disabled taxonomies are listed and marked rather than hidden, because their tags may still be attached to older events. Tags outside any taxonomy are listed too: those are local conventions, and they are often where an organisation puts what matters to it. " +
			"include_predicates expands one named taxonomy into its full tag list and requires a namespace; expanding all of them is tens of thousands of entries.",
	}, r.taxonomies)

	add(s, &tools, &mcp.Tool{
		Name: "misp_describe_instance",
		Description: "Report what this particular instance offers: MISP version, the attribute types and categories it accepts, its organisations, how many warninglists are enabled, whether this server is read-only, and the ceilings it enforces. " +
			"Call it first against an unfamiliar instance. The attribute type names and organisation names valid here are the ones misp_search expects, and guessing them is how one deployment's conventions end up hard-coded into every query. " +
			"The limits it reports are what to plan pagination around. category_type_mapping is a large matrix and is omitted unless include_type_mapping is set. " +
			"Each lookup degrades on its own: an API key lacking one permission still gets the rest, and what failed is named in notes.",
	}, r.describe)

	return tools
}

// ---- inputs -----------------------------------------------------------------

type searchInput struct {
	Value                string   `json:"value,omitempty" jsonschema:"the attribute value to look for; % is a wildcard, so 8.8.8.% matches a range"`
	Type                 []string `json:"type,omitempty" jsonschema:"MISP attribute types to keep, e.g. ip-dst, domain, sha256; misp_describe_instance lists what this instance accepts"`
	Category             []string `json:"category,omitempty" jsonschema:"MISP attribute categories to keep, e.g. Network activity"`
	Tags                 []string `json:"tags,omitempty" jsonschema:"attribute-level tags; prefix with ! to exclude, use % for a prefix match. Call misp_taxonomies first: this instance may not carry the tag you have in mind"`
	EventTags            []string `json:"event_tags,omitempty" jsonschema:"tags matched at event level rather than attribute level"`
	Org                  string   `json:"org,omitempty" jsonschema:"producing organisation; misp_describe_instance lists the names valid here"`
	From                 string   `json:"from,omitempty" jsonschema:"earliest event date, YYYY-MM-DD or a relative window such as 30d, 12h, 4w, 6m"`
	To                   string   `json:"to,omitempty" jsonschema:"latest event date, same formats as from"`
	ToIDs                *bool    `json:"to_ids,omitempty" jsonschema:"restrict to attributes marked actionable (true) or not (false); omit for both"`
	Published            *bool    `json:"published,omitempty" jsonschema:"restrict to published events (true) or unpublished ones (false); omit for both"`
	Returns              string   `json:"returns,omitempty" jsonschema:"attributes (default, finer grained and cheaper) or events (metadata only, no attribute values and so no warninglist annotation)"`
	ExcludeWarninglisted bool     `json:"exclude_warninglisted,omitempty" jsonschema:"ask the instance to drop warninglisted attributes before sending them; the returned count is then not a prevalence, since MISP does not say how many it removed"`
	Fields               []string `json:"fields,omitempty" jsonschema:"replaces the default projection; an unknown name is an error listing the valid ones. The warninglist verdict is always returned and cannot be projected away"`
	Limit                int      `json:"limit,omitempty" jsonschema:"rows per page; capped by the server and reported by misp_describe_instance"`
	Cursor               string   `json:"cursor,omitempty" jsonschema:"next_cursor from the previous call; bound to that call's filters and refused if they changed"`
	OutDir               string   `json:"out_dir,omitempty" jsonschema:"write results to JSONL in this directory and return only paths and a summary; must sit under the server's permitted root"`
}

type eventInput struct {
	Event             string   `json:"event" jsonschema:"numeric event id or event UUID"`
	Fields            []string `json:"fields,omitempty" jsonschema:"projection for the event header; an unknown name is an error listing the valid ones"`
	AttributeFields   []string `json:"attribute_fields,omitempty" jsonschema:"projection for the attribute rows; a separate vocabulary from fields"`
	AttributeType     []string `json:"attribute_type,omitempty" jsonschema:"keep only these attribute types"`
	AttributeCategory []string `json:"attribute_category,omitempty" jsonschema:"keep only these attribute categories"`
	ToIDsOnly         bool     `json:"to_ids_only,omitempty" jsonschema:"keep only attributes marked actionable"`
	AttributeLimit    int      `json:"attribute_limit,omitempty" jsonschema:"attributes per page; capped by the server"`
	AttributeCursor   string   `json:"attribute_cursor,omitempty" jsonschema:"next_attribute_cursor from the previous call"`
	OutDir            string   `json:"out_dir,omitempty" jsonschema:"write the attribute page to JSONL in this directory and return only paths and a summary"`
}

type contextInput struct {
	Value            string   `json:"value" jsonschema:"the IOC to look up, exactly as it appears"`
	Type             []string `json:"type,omitempty" jsonschema:"narrow to these attribute types when the same string is valid as several"`
	MaxEvents        int      `json:"max_events,omitempty" jsonschema:"how many events to detail; the aggregate still covers every attribute read"`
	IncludeSightings *bool    `json:"include_sightings,omitempty" jsonschema:"include sighting counts and window; defaults to true"`
	OutDir           string   `json:"out_dir,omitempty" jsonschema:"write the event list to JSONL in this directory and return only paths and a summary"`
}

type checkInput struct {
	Values []string `json:"values,omitempty" jsonschema:"values to check; leave empty to inventory the instance's enabled warninglists instead"`
	Type   string   `json:"type,omitempty" jsonschema:"MISP attribute type of these values, when known; the local fallback engine uses it to honour each list's valid_attributes"`
}

type taxonomyInput struct {
	Namespace         string `json:"namespace,omitempty" jsonschema:"restrict to one taxonomy namespace, e.g. tlp"`
	TagSearch         string `json:"tag_search,omitempty" jsonschema:"substring match over tag names actually present on this instance"`
	IncludePredicates bool   `json:"include_predicates,omitempty" jsonschema:"expand the named taxonomy into its full tag list; requires namespace"`
	Limit             int    `json:"limit,omitempty" jsonschema:"tags per page"`
	Cursor            string `json:"cursor,omitempty" jsonschema:"next_cursor from the previous call"`
	OutDir            string `json:"out_dir,omitempty" jsonschema:"write the whole matching tag set to JSONL in this directory"`
}

type describeInput struct {
	IncludeTypeMapping bool `json:"include_type_mapping,omitempty" jsonschema:"include the category-to-type matrix; large, and rarely needed"`
}

// ---- handlers ---------------------------------------------------------------

func (r *registry) search(ctx context.Context, _ *mcp.CallToolRequest, in searchInput) (*mcp.CallToolResult, service.SearchResult, error) {
	res, err := r.svc.Search(ctx, service.SearchInput{
		Value: in.Value, Type: in.Type, Category: in.Category,
		Tags: in.Tags, EventTags: in.EventTags, Org: in.Org,
		From: in.From, To: in.To, ToIDs: in.ToIDs, Published: in.Published,
		Returns: in.Returns, ExcludeWarninglisted: in.ExcludeWarninglisted,
		Fields: in.Fields, Limit: in.Limit, Cursor: in.Cursor, OutDir: in.OutDir,
	})
	if err != nil {
		return nil, service.SearchResult{}, err
	}
	return nil, *res, nil
}

func (r *registry) event(ctx context.Context, _ *mcp.CallToolRequest, in eventInput) (*mcp.CallToolResult, service.EventResult, error) {
	res, err := r.svc.Event(ctx, service.EventInput{
		Event: in.Event, Fields: in.Fields, AttributeFields: in.AttributeFields,
		AttributeType: in.AttributeType, AttributeCategory: in.AttributeCategory,
		ToIDsOnly: in.ToIDsOnly, AttributeLimit: in.AttributeLimit,
		AttributeCursor: in.AttributeCursor, OutDir: in.OutDir,
	})
	if err != nil {
		return nil, service.EventResult{}, err
	}
	return nil, *res, nil
}

func (r *registry) iocContext(ctx context.Context, _ *mcp.CallToolRequest, in contextInput) (*mcp.CallToolResult, service.ContextResult, error) {
	res, err := r.svc.IOCContext(ctx, service.ContextInput{
		Value: in.Value, Type: in.Type, MaxEvents: in.MaxEvents,
		IncludeSightings: in.IncludeSightings, OutDir: in.OutDir,
	})
	if err != nil {
		return nil, service.ContextResult{}, err
	}
	return nil, *res, nil
}

func (r *registry) check(ctx context.Context, _ *mcp.CallToolRequest, in checkInput) (*mcp.CallToolResult, service.CheckResult, error) {
	res, err := r.svc.CheckWarninglists(ctx, service.CheckInput{Values: in.Values, Type: in.Type})
	if err != nil {
		return nil, service.CheckResult{}, err
	}
	return nil, *res, nil
}

func (r *registry) taxonomies(ctx context.Context, _ *mcp.CallToolRequest, in taxonomyInput) (*mcp.CallToolResult, service.TaxonomyResult, error) {
	res, err := r.svc.Taxonomies(ctx, service.TaxonomyInput{
		Namespace: in.Namespace, TagSearch: in.TagSearch,
		IncludePredicates: in.IncludePredicates,
		Limit:             in.Limit, Cursor: in.Cursor, OutDir: in.OutDir,
	})
	if err != nil {
		return nil, service.TaxonomyResult{}, err
	}
	return nil, *res, nil
}

func (r *registry) describe(ctx context.Context, _ *mcp.CallToolRequest, in describeInput) (*mcp.CallToolResult, service.DescribeResult, error) {
	res, err := r.svc.Describe(ctx, service.DescribeInput{IncludeTypeMapping: in.IncludeTypeMapping})
	if err != nil {
		return nil, service.DescribeResult{}, err
	}
	return nil, *res, nil
}
