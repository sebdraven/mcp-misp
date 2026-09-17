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

func (r *registry) tag(ctx context.Context, _ *mcp.CallToolRequest, in tagInput) (*mcp.CallToolResult, service.TagResult, error) {
	res, err := r.svc.Tag(ctx, service.TagInput{Target: in.Target, ID: in.ID, Tags: in.Tags})
	if err != nil {
		return nil, service.TagResult{}, err
	}
	return nil, *res, nil
}
