package service

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sebdraven/mcp-misp/internal/misp"
)

type ObjectSpec struct {
	Ref          string
	Template     string
	Values       map[string]any
	Comment      string
	Distribution string
}

type ReferenceSpec struct {
	From             string
	To               string
	RelationshipType string
	Comment          string
}

type AddObjectsInput struct {
	Event                 string
	Objects               []ObjectSpec
	References            []ReferenceSpec
	OnDuplicate           string
	AllowUnknownRelations bool
	AllowWarninglisted    bool
}

type ValidationIssue struct {
	ObjectIndex    int    `json:"object_index,omitempty"`
	ReferenceIndex int    `json:"reference_index,omitempty"`
	Ref            string `json:"ref,omitempty"`
	Template       string `json:"template,omitempty"`
	Relation       string `json:"relation,omitempty"`
	Problem        string `json:"problem"`
	Expected       string `json:"expected,omitempty"`
	Got            string `json:"got,omitempty"`
}

type CoercedRelation struct {
	ObjectIndex int    `json:"object_index"`
	Ref         string `json:"ref,omitempty"`
	Relation    string `json:"relation"`
	WrittenAs   string `json:"written_as"`
}

type CreatedObject struct {
	Ref        string `json:"ref,omitempty"`
	Template   string `json:"template"`
	UUID       string `json:"uuid"`
	ID         string `json:"id,omitempty"`
	Attributes int    `json:"attributes"`
}

type CreatedReference struct {
	From             string `json:"from"`
	To               string `json:"to"`
	FromUUID         string `json:"from_uuid"`
	ToUUID           string `json:"to_uuid"`
	RelationshipType string `json:"relationship_type"`
	TypeValidated    bool   `json:"relationship_type_validated"`
}

type DuplicateOutcome struct {
	ObjectIndex int    `json:"object_index"`
	Ref         string `json:"ref,omitempty"`
	Template    string `json:"template"`
	Message     string `json:"instance_message,omitempty"`
}

type WriteFailure struct {
	Stage string `json:"stage"`
	Index int    `json:"index"`
	Ref   string `json:"ref,omitempty"`
	Error string `json:"error"`
}

type AddObjectsResult struct {
	EventID   string `json:"event_id"`
	EventUUID string `json:"event_uuid"`

	Validated        bool              `json:"validated"`
	ValidationErrors []ValidationIssue `json:"validation_errors,omitempty"`

	CreatedObjects    []CreatedObject    `json:"created_objects,omitempty"`
	CreatedReferences []CreatedReference `json:"created_references,omitempty"`
	Duplicates        []DuplicateOutcome `json:"duplicates,omitempty"`
	CoercedRelations  []CoercedRelation  `json:"coerced_relations,omitempty"`

	RelationshipTypesValidated   bool     `json:"relationship_types_validated"`
	UnvalidatedRelationshipTypes []string `json:"unvalidated_relationship_types,omitempty"`

	FailedAt     *WriteFailure `json:"failed_at,omitempty"`
	NotAttempted []string      `json:"not_attempted,omitempty"`

	Warninglist Report   `json:"warninglist_report"`
	Flags       []string `json:"flags,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

// AddObjects validates a whole batch before writing any of it, then writes.
//
// The order is what makes the tool usable: an APK, its certificate, its C2
// domains and its permissions go in one call, linked, without the caller
// holding a uuid between steps. The cost is that a failure mid-write cannot be
// rolled back — this server has no delete — so the answer names exactly what
// was created and exactly what was not.
func (s *Service) AddObjects(ctx context.Context, in AddObjectsInput) (*AddObjectsResult, error) {
	if s.cfg.ReadOnly {
		return nil, fmt.Errorf("this server is read-only (MISP_READONLY is not false)")
	}
	breakOnDuplicate, err := duplicatePolicy(in.OnDuplicate)
	if err != nil {
		return nil, err
	}
	if len(in.Objects) == 0 {
		return nil, fmt.Errorf("at least one object is required")
	}
	caps := s.cfg.Caps
	if len(in.Objects) > caps.ObjectsPerBatch {
		return nil, fmt.Errorf("batch carries %d objects, ceiling is %d", len(in.Objects), caps.ObjectsPerBatch)
	}
	if len(in.References) > caps.ReferencesPerBatch {
		return nil, fmt.Errorf("batch carries %d references, ceiling is %d", len(in.References), caps.ReferencesPerBatch)
	}

	event, err := s.resolveEvent(ctx, in.Event)
	if err != nil {
		return nil, err
	}
	out := &AddObjectsResult{EventID: event.ID.String(), EventUUID: event.UUID}

	plan, issues := s.validateBatch(ctx, in, out)
	if len(issues) > 0 {
		out.Validated = false
		out.ValidationErrors = issues
		out.Notes = append(out.Notes, fmt.Sprintf("nothing was written: %d problem(s) found, and the batch is refused whole so a partial event is never created", len(issues)))
		return out, nil
	}
	out.Validated = true

	s.writeBatch(ctx, in, plan, breakOnDuplicate, out)
	return out, nil
}

// plannedObject is a validated object, ready to write.
type plannedObject struct {
	index    int
	ref      string
	template string
	payload  misp.ObjectPayload
}

type plannedReference struct {
	index int
	spec  ReferenceSpec
}

type batchPlan struct {
	objects    []plannedObject
	references []plannedReference
}

func (s *Service) validateBatch(ctx context.Context, in AddObjectsInput, out *AddObjectsResult) (batchPlan, []ValidationIssue) {
	var issues []ValidationIssue
	var plan batchPlan

	defs := map[string]*misp.ObjectTemplateDefinition{}
	for _, o := range in.Objects {
		name := strings.TrimSpace(o.Template)
		if name == "" || defs[name] != nil {
			continue
		}
		def, err := s.templateDef(ctx, name)
		if err != nil {
			issues = append(issues, ValidationIssue{Template: name, Problem: err.Error()})
			continue
		}
		defs[name] = def
	}

	refSeen := map[string]int{}
	var subjects []Subject
	type valueSite struct {
		index    int
		ref      string
		relation string
	}
	sites := map[string][]valueSite{}

	for i, o := range in.Objects {
		name := strings.TrimSpace(o.Template)
		if name == "" {
			issues = append(issues, ValidationIssue{ObjectIndex: i, Ref: o.Ref, Problem: "template is required"})
			continue
		}
		if o.Ref != "" {
			if prev, dup := refSeen[o.Ref]; dup {
				issues = append(issues, ValidationIssue{
					ObjectIndex: i, Ref: o.Ref,
					Problem: fmt.Sprintf("ref %q is already used by object %d; refs must be unique within a batch", o.Ref, prev),
				})
				continue
			}
			refSeen[o.Ref] = i
		}
		def := defs[name]
		if def == nil {
			continue
		}
		if len(o.Values) == 0 {
			issues = append(issues, ValidationIssue{ObjectIndex: i, Ref: o.Ref, Template: name, Problem: "values is empty"})
			continue
		}

		relationTypes := make(map[string]string, len(def.Attributes))
		for r, a := range def.Attributes {
			relationTypes[r] = a.MISPAttribute
		}

		payload := misp.ObjectPayload{
			Name: def.Name, MetaCategory: def.MetaCategory, Description: def.Description,
			TemplateUUID: def.UUID, TemplateVersion: def.Version.String(), Comment: o.Comment,
		}
		if o.Distribution != "" {
			d, err := namedLevel("distribution", o.Distribution, distributionByName)
			if err != nil {
				issues = append(issues, ValidationIssue{ObjectIndex: i, Ref: o.Ref, Template: name, Problem: err.Error()})
			} else {
				payload.Distribution = &d
			}
		}

		present := map[string]bool{}
		total := 0
		for _, relation := range sortedKeys(o.Values) {
			values, ok := normaliseValues(o.Values[relation])
			if !ok {
				issues = append(issues, ValidationIssue{
					ObjectIndex: i, Ref: o.Ref, Template: name, Relation: relation,
					Problem: "value must be a string, a number, or a list of them",
				})
				continue
			}
			if len(values) == 0 {
				issues = append(issues, ValidationIssue{
					ObjectIndex: i, Ref: o.Ref, Template: name, Relation: relation,
					Problem: "no usable value",
				})
				continue
			}
			total += len(values)
			if total > s.cfg.Caps.ValuesPerObject {
				issues = append(issues, ValidationIssue{
					ObjectIndex: i, Ref: o.Ref, Template: name,
					Problem: fmt.Sprintf("object carries more than %d values", s.cfg.Caps.ValuesPerObject),
				})
				break
			}

			attr, known := def.Attributes[relation]
			attrType := attr.MISPAttribute

			if !known {
				if !in.AllowUnknownRelations {
					issue := ValidationIssue{
						ObjectIndex: i, Ref: o.Ref, Template: name, Relation: relation,
						Problem: fmt.Sprintf("relation is not declared by template %q", def.Name),
					}
					if kind, structured := detectStructured(values[0]); structured {
						if s := suggestRelation(relationTypes, kind); s != "" {
							issue.Expected = fmt.Sprintf("relation %q carries %s values on this template", s, kind.Name)
						}
					}
					issues = append(issues, issue)
					continue
				}
				// Coercion to text is refused for anything MISP correlates on:
				// such a value would sit in the database invisible to every
				// pivot, which is worse than not writing it.
				refused := false
				for _, v := range values {
					kind, structured := detectStructured(v)
					if !structured {
						continue
					}
					issue := ValidationIssue{
						ObjectIndex: i, Ref: o.Ref, Template: name, Relation: relation,
						Problem: fmt.Sprintf("value looks like %s and would be written as free text, which MISP never correlates on; allow_unknown_relations does not cover this", kind.Name),
						Got:     v,
					}
					if s := suggestRelation(relationTypes, kind); s != "" {
						issue.Expected = fmt.Sprintf("use relation %q, which template %q declares as %s", s, def.Name, relationTypes[s])
					} else {
						issue.Expected = fmt.Sprintf("a relation of template %q declaring one of: %s", def.Name, strings.Join(kind.Types, ", "))
					}
					issues = append(issues, issue)
					refused = true
				}
				if refused {
					continue
				}
				attrType = "text"
				out.CoercedRelations = append(out.CoercedRelations, CoercedRelation{
					ObjectIndex: i, Ref: o.Ref, Relation: relation, WrittenAs: "text",
				})
			} else if !attr.Multiple.Bool() && len(values) > 1 {
				issues = append(issues, ValidationIssue{
					ObjectIndex: i, Ref: o.Ref, Template: name, Relation: relation,
					Problem:  "relation is not multiple on this template",
					Expected: "one value",
					Got:      fmt.Sprintf("%d values", len(values)),
				})
				continue
			}

			present[relation] = true
			for _, v := range values {
				payload.Attribute = append(payload.Attribute, misp.ObjectAttributePayload{
					Type: attrType, ObjectRelation: relation, Value: v,
				})
				subjects = append(subjects, Subject{Value: v, Type: attrType})
				sites[v] = append(sites[v], valueSite{index: i, ref: o.Ref, relation: relation})
			}
		}

		for _, r := range def.Required {
			if !present[r] {
				issues = append(issues, ValidationIssue{
					ObjectIndex: i, Ref: o.Ref, Template: name, Relation: r,
					Problem: "template requires this relation",
				})
			}
		}
		if len(def.RequiredOneOf) > 0 {
			any := false
			for _, r := range def.RequiredOneOf {
				if present[r] {
					any = true
					break
				}
			}
			if !any {
				issues = append(issues, ValidationIssue{
					ObjectIndex: i, Ref: o.Ref, Template: name,
					Problem:  "template requires at least one of these relations",
					Expected: strings.Join(def.RequiredOneOf, ", "),
				})
			}
		}

		plan.objects = append(plan.objects, plannedObject{index: i, ref: o.Ref, template: def.Name, payload: payload})
	}

	vocab := s.relationshipVocabulary(ctx)
	out.RelationshipTypesValidated = len(vocab) > 0

	for j, r := range in.References {
		if strings.TrimSpace(r.RelationshipType) == "" {
			issues = append(issues, ValidationIssue{ReferenceIndex: j, Problem: "relationship_type is required"})
		} else if out.RelationshipTypesValidated && !vocab[r.RelationshipType] {
			issues = append(issues, ValidationIssue{
				ReferenceIndex: j, Problem: "relationship_type is not in this instance's vocabulary",
				Got: r.RelationshipType,
			})
		}
		for label, side := range map[string]string{"from": r.From, "to": r.To} {
			if strings.TrimSpace(side) == "" {
				issues = append(issues, ValidationIssue{ReferenceIndex: j, Problem: label + " is required"})
				continue
			}
			if _, isLocal := refSeen[side]; isLocal {
				continue
			}
			if looksLikeUUID(side) {
				continue
			}
			issues = append(issues, ValidationIssue{
				ReferenceIndex: j,
				Problem:        fmt.Sprintf("%s %q is neither a ref declared in this batch nor a uuid", label, side),
			})
		}
		plan.references = append(plan.references, plannedReference{index: j, spec: r})
	}

	checks, report := s.wl.Check(ctx, subjects)
	out.Warninglist = report
	out.Flags = append(out.Flags, coverageFlags(report)...)
	if report.Hits > 0 {
		out.Flags = append(out.Flags, FlagWarninglisted)
	}
	if !in.AllowWarninglisted {
		for _, value := range sortedKeys(checks) {
			c := checks[value]
			if !c.Hit {
				continue
			}
			for _, site := range sites[value] {
				issues = append(issues, ValidationIssue{
					ObjectIndex: site.index, Ref: site.ref, Relation: site.relation,
					Problem: refusalMessage(value, c, report), Got: value,
				})
			}
		}
	}
	if report.Coverage != CoverageComplete {
		out.Notes = append(out.Notes, "the warninglist check did not cover every enabled list, so a clean verdict on these values is weaker than usual")
	}

	sort.SliceStable(issues, func(a, b int) bool { return issues[a].ObjectIndex < issues[b].ObjectIndex })
	return plan, issues
}

func (s *Service) writeBatch(ctx context.Context, in AddObjectsInput, plan batchPlan, breakOnDuplicate bool, out *AddObjectsResult) {
	uuidByRef := map[string]string{}
	skipped := map[string]string{}

	for n, po := range plan.objects {
		res, err := s.client.AddObject(ctx, out.EventID, po.payload, breakOnDuplicate)
		if err != nil {
			// A duplicate rejection is an expected outcome of on_duplicate=reject,
			// not a failure: it is recorded and the batch carries on, so a
			// re-run after a partial write creates what is still missing.
			if breakOnDuplicate && misp.IsDuplicate(err) {
				out.Duplicates = append(out.Duplicates, DuplicateOutcome{
					ObjectIndex: po.index, Ref: po.ref, Template: po.template, Message: err.Error(),
				})
				if po.ref != "" {
					skipped[po.ref] = "identical object already present in the event; not created"
				}
				continue
			}
			out.FailedAt = &WriteFailure{Stage: "objects", Index: po.index, Ref: po.ref, Error: err.Error()}
			for _, rest := range plan.objects[n+1:] {
				out.NotAttempted = append(out.NotAttempted, describeObject(rest))
			}
			for _, r := range plan.references {
				out.NotAttempted = append(out.NotAttempted, describeReference(r))
			}
			out.Notes = append(out.Notes, "writing stopped at the first failure and nothing is rolled back; not_attempted lists what was left untouched")
			return
		}
		out.CreatedObjects = append(out.CreatedObjects, CreatedObject{
			Ref: po.ref, Template: po.template, UUID: res.UUID,
			ID: res.ID.String(), Attributes: len(res.Attribute),
		})
		if po.ref != "" {
			uuidByRef[po.ref] = res.UUID
		}
	}

	var unvalidated []string
	for n, pr := range plan.references {
		from, okFrom := resolveSide(pr.spec.From, uuidByRef)
		to, okTo := resolveSide(pr.spec.To, uuidByRef)
		if !okFrom || !okTo {
			reason := skipped[pr.spec.From]
			if !okTo {
				reason = skipped[pr.spec.To]
			}
			if reason == "" {
				reason = "endpoint object was not created"
			}
			out.NotAttempted = append(out.NotAttempted, describeReference(pr)+" ("+reason+")")
			continue
		}

		err := s.client.AddObjectReference(ctx, misp.ObjectReferencePayload{
			ObjectUUID: from, ReferencedUUID: to,
			RelationshipType: pr.spec.RelationshipType, Comment: pr.spec.Comment,
		})
		if err != nil {
			out.FailedAt = &WriteFailure{Stage: "references", Index: pr.index, Error: err.Error()}
			for _, rest := range plan.references[n+1:] {
				out.NotAttempted = append(out.NotAttempted, describeReference(rest))
			}
			out.Notes = append(out.Notes, "the objects above exist; writing stopped in the reference stage and nothing is rolled back")
			return
		}
		out.CreatedReferences = append(out.CreatedReferences, CreatedReference{
			From: pr.spec.From, To: pr.spec.To, FromUUID: from, ToUUID: to,
			RelationshipType: pr.spec.RelationshipType,
			TypeValidated:    out.RelationshipTypesValidated,
		})
		if !out.RelationshipTypesValidated {
			unvalidated = append(unvalidated, pr.spec.RelationshipType)
		}
	}

	if !out.RelationshipTypesValidated && len(out.CreatedReferences) > 0 {
		out.UnvalidatedRelationshipTypes = distinct(unvalidated)
		out.Notes = append(out.Notes,
			"this instance exposes no object-relationship vocabulary, so relationship_type was written unchecked. "+
				"MISP stores it as free text: a typo is accepted silently and produces two relations that look alike and do not match. "+
				"The exact string written for each reference is in created_references, and the distinct values are listed in unvalidated_relationship_types — check them.")
	}
	if len(out.Duplicates) > 0 {
		out.Notes = append(out.Notes,
			"on_duplicate=reject: the objects under duplicates already existed with identical attributes and were not created; references touching them are listed in not_attempted")
	}
}

func duplicatePolicy(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "reject":
		return true, nil
	case "create":
		return false, nil
	}
	return false, fmt.Errorf("on_duplicate %q: want reject or create", v)
}

func resolveSide(side string, uuidByRef map[string]string) (string, bool) {
	if u, ok := uuidByRef[side]; ok {
		return u, true
	}
	if looksLikeUUID(side) {
		return side, true
	}
	return "", false
}

func looksLikeUUID(v string) bool {
	if len(v) != 36 {
		return false
	}
	for i, c := range v {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
	}
	return true
}

func describeObject(o plannedObject) string {
	if o.ref != "" {
		return fmt.Sprintf("object[%d] %s (ref %s)", o.index, o.template, o.ref)
	}
	return fmt.Sprintf("object[%d] %s", o.index, o.template)
}

func describeReference(r plannedReference) string {
	return fmt.Sprintf("reference[%d] %s -%s-> %s", r.index, r.spec.From, r.spec.RelationshipType, r.spec.To)
}

// normaliseValues accepts a scalar or a list of scalars, which is the shape a
// caller naturally writes.
func normaliseValues(raw any) ([]string, bool) {
	switch v := raw.(type) {
	case nil:
		return nil, true
	case string:
		if strings.TrimSpace(v) == "" {
			return nil, true
		}
		return []string{v}, true
	case bool:
		return []string{strconv.FormatBool(v)}, true
	case float64:
		return []string{strconv.FormatFloat(v, 'f', -1, 64)}, true
	case int:
		return []string{strconv.Itoa(v)}, true
	case []string:
		return trimAll(v), true
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			got, ok := normaliseValues(item)
			if !ok {
				return nil, false
			}
			out = append(out, got...)
		}
		return out, true
	}
	return nil, false
}

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func distinct(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
