package mcptools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sebdraven/mcp-misp/internal/service"
)

// RegisterWrite wires the two write tools. RegisterAll calls it only when the
// server is not read-only.
func RegisterWrite(s *mcp.Server, svc *service.Service) []*mcp.Tool {
	r := &registry{svc: svc}
	var tools []*mcp.Tool

	add(s, &tools, &mcp.Tool{
		Name: "misp_add_attribute",
		Description: "Create one attribute on an existing event. This writes to a shared instance other teams consume, so it is present only because this server was started with MISP_READONLY=false. " +
			"The value is checked against the warninglists BEFORE anything is written, and a hit refuses the creation. The refusal names the list and the engine that decided, because the two engines do not agree in one respect: " +
			"the local fallback also applies each list's valid_attributes, which the instance's own check does not, so it can refuse a value the MISP web UI would accept. " +
			"allow_warninglisted=true overrides the refusal — the right call for an indicator that is genuinely malicious despite sitting inside a broad exclusion range, and the wrong one for silencing a check you did not read. " +
			"Use misp_describe_instance for the valid type and category names and misp_taxonomies for the tags that exist here; both are instance-specific. " +
			"Tags are applied after the attribute exists: a tag failure is reported and does not undo the creation. There is no publish tool, so the event stays where its owner left it.",
	}, r.addAttribute)

	add(s, &tools, &mcp.Tool{
		Name: "misp_create_event",
		Description: "Create a new MISP event. Present only because this server was started with MISP_READONLY=false. " +
			"distribution is REQUIRED and is given by name, never as a number: MISP encodes these 0-4, and a caller passing 3 in the belief that it restricts sharing publishes to every connected community. " +
			"Accepted values are your_organisation_only, this_community, connected_communities, all_communities and sharing_group; the last one also needs sharing_group_id. " +
			"There is no default: on a CSIRT instance the instance-wide default can be all_communities, and a badly distributed event is a sharing incident, not a typo. " +
			"The event is created UNPUBLISHED and there is no way to publish it from here — publishing stays a human decision in the MISP interface, same reason there has never been a publish tool. " +
			"Returns the id and uuid, which is what misp_add_objects takes next.",
	}, r.createEvent)

	add(s, &tools, &mcp.Tool{
		Name: "misp_add_objects",
		Description: "Add several MISP objects to an event IN ONE CALL, with the references that link them. " +
			"This is the tool for landing a whole analysis — a file, its certificate, its C2 domains, its permissions — as one linked graph rather than as ten calls with a uuid carried between them. " +
			"Each object may declare a local 'ref'; references[] joins those refs, so objects created in the same call can be linked without knowing their uuid in advance. A reference endpoint may also be the uuid of an object already in the event. " +
			"Call misp_object_templates FIRST: relation names come from the template, and a relation the template does not declare is refused. " +
			"VALIDATION IS WHOLE-BATCH AND HAPPENS BEFORE ANY WRITE. An unknown relation, a wrong attribute type, a missing required relation, a violated multiplicity, an unresolvable reference or a warninglist hit refuses the ENTIRE batch with per-object, per-relation detail, and nothing is created. " +
			"allow_unknown_relations loosens only the unknown-relation case, and it still refuses to coerce a value that looks like a hash, IP, domain, URL or email into free text — MISP never correlates on text, so that would be intel written and lost. " +
			"on_duplicate decides what MISP does when an identical object already exists: reject (default) or create. It is always sent explicitly, never left to the instance's setting. " +
			"There is NO ROLLBACK — this server has no delete. If a write fails after validation, read failed_at and not_attempted: they name exactly what exists and exactly what does not.",
	}, r.addObjects)

	add(s, &tools, &mcp.Tool{
		Name: "misp_tag",
		Description: "Attach tags to an existing event or attribute. Present only because this server was started with MISP_READONLY=false. " +
			"Adding only: there is no removal tool, and that is deliberate. tlp: and PAP: tags drive how MISP distributes data, so removing one is a sharing decision dressed as an annotation. " +
			"Call misp_taxonomies first — a tag this instance does not carry is refused by MISP, and inventing a namespace pollutes a shared vocabulary that other teams depend on. " +
			"Accepts a numeric id or a UUID; a numeric id costs one extra lookup to resolve. Each tag is applied independently, so a partial result is normal and is reported as applied plus failures.",
	}, r.tag)

	return tools
}

type addAttributeInput struct {
	Event              string   `json:"event" jsonschema:"numeric id or UUID of the event to add to"`
	Type               string   `json:"type" jsonschema:"MISP attribute type, e.g. ip-dst; misp_describe_instance lists what this instance accepts"`
	Value              string   `json:"value" jsonschema:"the attribute value"`
	Category           string   `json:"category,omitempty" jsonschema:"MISP attribute category; the instance picks its default for the type when omitted"`
	Comment            string   `json:"comment,omitempty" jsonschema:"free-text comment; this is where the provenance of the indicator belongs"`
	ToIDs              *bool    `json:"to_ids,omitempty" jsonschema:"mark the attribute actionable for detection; the instance's default for the type applies when omitted"`
	Distribution       *int     `json:"distribution,omitempty" jsonschema:"MISP distribution level 0-5; omit to inherit the event's"`
	Tags               []string `json:"tags,omitempty" jsonschema:"tags to attach once the attribute exists; they must already exist on this instance"`
	AllowWarninglisted bool     `json:"allow_warninglisted,omitempty" jsonschema:"create the attribute even though its value matches a warninglist; read the refusal first, it names the list"`
}

type createEventInput struct {
	Info           string   `json:"info" jsonschema:"the event title; this is what an analyst reads first in a list of events"`
	Distribution   string   `json:"distribution" jsonschema:"REQUIRED, by name: your_organisation_only, this_community, connected_communities, all_communities or sharing_group"`
	SharingGroupID *int     `json:"sharing_group_id,omitempty" jsonschema:"required when distribution is sharing_group, rejected otherwise"`
	Date           string   `json:"date,omitempty" jsonschema:"event date, YYYY-MM-DD; the instance uses today when omitted"`
	ThreatLevel    string   `json:"threat_level,omitempty" jsonschema:"high, medium, low or undefined"`
	Analysis       string   `json:"analysis,omitempty" jsonschema:"initial, ongoing or completed"`
	Tags           []string `json:"tags,omitempty" jsonschema:"tags to attach; they must already exist on this instance, see misp_taxonomies"`
}

type objectSpecInput struct {
	Ref          string         `json:"ref,omitempty" jsonschema:"a local name for this object, used by references[] within this call; never sent to MISP"`
	Template     string         `json:"template" jsonschema:"object template name, e.g. file or x509; see misp_object_templates"`
	Values       map[string]any `json:"values" jsonschema:"relation name to value, or to a list of values when the template marks the relation multiple"`
	Comment      string         `json:"comment,omitempty" jsonschema:"comment carried on the object"`
	Distribution string         `json:"distribution,omitempty" jsonschema:"by name, as in misp_create_event; omit to inherit the event's"`
}

type referenceSpecInput struct {
	From             string `json:"from" jsonschema:"a ref declared in this call, or the uuid of an object already in the event"`
	To               string `json:"to" jsonschema:"a ref declared in this call, or the uuid of an object already in the event"`
	RelationshipType string `json:"relationship_type" jsonschema:"e.g. derived-from, contains, executes; validated only when the instance exposes its vocabulary, and the value actually written is echoed back either way"`
	Comment          string `json:"comment,omitempty"`
}

type addObjectsInput struct {
	Event                 string               `json:"event" jsonschema:"numeric id or uuid of the event to add to"`
	Objects               []objectSpecInput    `json:"objects" jsonschema:"the objects to create, validated as a whole before any of them is written"`
	References            []referenceSpecInput `json:"references,omitempty" jsonschema:"links between the objects of this call, or to objects already in the event"`
	OnDuplicate           string               `json:"on_duplicate,omitempty" jsonschema:"reject (default) refuses an object whose attributes match one already in the event; create writes it anyway"`
	AllowUnknownRelations bool                 `json:"allow_unknown_relations,omitempty" jsonschema:"accept relations the template does not declare, writing them as text; still refused for values that look like an IOC"`
	AllowWarninglisted    bool                 `json:"allow_warninglisted,omitempty" jsonschema:"write values that match a warninglist; read the refusal first, it names the list and the engine"`
}

type tagInput struct {
	Target string   `json:"target" jsonschema:"event or attribute"`
	ID     string   `json:"id" jsonschema:"numeric id or UUID of the target"`
	Tags   []string `json:"tags" jsonschema:"tags to attach; misp_taxonomies lists the ones this instance carries"`
}

func (r *registry) addAttribute(ctx context.Context, _ *mcp.CallToolRequest, in addAttributeInput) (*mcp.CallToolResult, service.AddAttributeResult, error) {
	res, err := r.svc.AddAttribute(ctx, service.AddAttributeInput{
		Event: in.Event, Type: in.Type, Value: in.Value, Category: in.Category,
		Comment: in.Comment, ToIDs: in.ToIDs, Distribution: in.Distribution,
		Tags: in.Tags, AllowWarninglisted: in.AllowWarninglisted,
	})
	if err != nil {
		return nil, service.AddAttributeResult{}, err
	}
	return nil, *res, nil
}

func (r *registry) createEvent(ctx context.Context, _ *mcp.CallToolRequest, in createEventInput) (*mcp.CallToolResult, service.CreateEventResult, error) {
	res, err := r.svc.CreateEvent(ctx, service.CreateEventInput{
		Info: in.Info, Distribution: in.Distribution, SharingGroupID: in.SharingGroupID,
		Date: in.Date, ThreatLevel: in.ThreatLevel, Analysis: in.Analysis, Tags: in.Tags,
	})
	if err != nil {
		return nil, service.CreateEventResult{}, err
	}
	return nil, *res, nil
}

func (r *registry) addObjects(ctx context.Context, _ *mcp.CallToolRequest, in addObjectsInput) (*mcp.CallToolResult, service.AddObjectsResult, error) {
	objects := make([]service.ObjectSpec, 0, len(in.Objects))
	for _, o := range in.Objects {
		objects = append(objects, service.ObjectSpec{
			Ref: o.Ref, Template: o.Template, Values: o.Values,
			Comment: o.Comment, Distribution: o.Distribution,
		})
	}
	references := make([]service.ReferenceSpec, 0, len(in.References))
	for _, r := range in.References {
		references = append(references, service.ReferenceSpec{
			From: r.From, To: r.To, RelationshipType: r.RelationshipType, Comment: r.Comment,
		})
	}

	res, err := r.svc.AddObjects(ctx, service.AddObjectsInput{
		Event: in.Event, Objects: objects, References: references,
		OnDuplicate: in.OnDuplicate, AllowUnknownRelations: in.AllowUnknownRelations,
		AllowWarninglisted: in.AllowWarninglisted,
	})
	if err != nil {
		return nil, service.AddObjectsResult{}, err
	}
	return nil, *res, nil
}

func (r *registry) tag(ctx context.Context, _ *mcp.CallToolRequest, in tagInput) (*mcp.CallToolResult, service.TagResult, error) {
	res, err := r.svc.Tag(ctx, service.TagInput{Target: in.Target, ID: in.ID, Tags: in.Tags})
	if err != nil {
		return nil, service.TagResult{}, err
	}
	return nil, *res, nil
}
