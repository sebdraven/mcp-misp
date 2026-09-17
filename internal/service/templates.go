package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sebdraven/mcp-misp/internal/misp"
)

type TemplateInput struct {
	Template string
	Search   string
	Limit    int
	Cursor   string
}

type TemplateSummary struct {
	Name          string `json:"name"`
	UUID          string `json:"uuid,omitempty"`
	Version       string `json:"version,omitempty"`
	MetaCategory  string `json:"meta_category,omitempty"`
	Description   string `json:"description,omitempty"`
	RelationCount int    `json:"relation_count,omitempty"`
	Active        *bool  `json:"active,omitempty"`
}

type TemplateRelation struct {
	Relation    string   `json:"relation"`
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Multiple    *bool    `json:"multiple,omitempty"`
	Categories  []string `json:"categories,omitempty"`
	ValuesList  []string `json:"values_list,omitempty"`
}

type TemplateDetail struct {
	Name          string             `json:"name"`
	UUID          string             `json:"uuid,omitempty"`
	Version       string             `json:"version,omitempty"`
	MetaCategory  string             `json:"meta_category,omitempty"`
	Description   string             `json:"description,omitempty"`
	Required      []string           `json:"required,omitempty"`
	RequiredOneOf []string           `json:"required_one_of,omitempty"`
	Relations     []TemplateRelation `json:"relations,omitempty"`
}

type TemplateResult struct {
	Template   *TemplateDetail   `json:"template,omitempty"`
	Templates  []TemplateSummary `json:"templates,omitempty"`
	Total      int               `json:"total,omitempty"`
	Returned   int               `json:"returned,omitempty"`
	Page       int               `json:"page,omitempty"`
	NextCursor string            `json:"next_cursor,omitempty"`
	Truncated  bool              `json:"truncated,omitempty"`
	Notes      []string          `json:"notes,omitempty"`
}

// noDedupKeyNote is stated on every template detail because it is the question
// callers arrive with, and the honest answer is that the format has no room for
// it.
const noDedupKeyNote = "MISP object templates declare no deduplication key: the only constraints in the format are required and required_one_of. Duplicate handling is decided at write time by the on_duplicate parameter of misp_add_objects."

// ObjectTemplates inventories the instance's templates, or details one.
func (s *Service) ObjectTemplates(ctx context.Context, in TemplateInput) (*TemplateResult, error) {
	if name := strings.TrimSpace(in.Template); name != "" {
		def, err := s.templateDef(ctx, name)
		if err != nil {
			return nil, err
		}
		return &TemplateResult{Template: templateDetail(def), Notes: []string{noDedupKeyNote}}, nil
	}

	templates, err := s.templateIndex(ctx)
	if err != nil {
		return nil, err
	}

	search := strings.ToLower(strings.TrimSpace(in.Search))
	matched := make([]TemplateSummary, 0, len(templates))
	for _, t := range templates {
		if search != "" &&
			!strings.Contains(strings.ToLower(t.Name), search) &&
			!strings.Contains(strings.ToLower(t.Description), search) {
			continue
		}
		matched = append(matched, TemplateSummary{
			Name: t.Name, UUID: t.UUID, Version: t.Version.String(),
			MetaCategory: t.MetaCategory, Description: t.Description,
			RelationCount: len(t.Requirements.Required) + len(t.Requirements.RequiredOneOf),
			Active:        boolPtr(t.Active.Bool()),
		})
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Name < matched[j].Name })

	sig := fingerprint("object_templates", search)
	page, _, err := decodeCursor(in.Cursor, sig)
	if err != nil {
		return nil, err
	}
	limit := clamp(in.Limit, s.cfg.Caps.SearchDefault, s.cfg.Caps.SearchMax)

	start := min((page-1)*limit, len(matched))
	end := min(start+limit, len(matched))
	pageItems := matched[start:end]
	hasMore := end < len(matched)

	pageItems, truncated := fitBudget(pageItems, s.cfg.Caps.ResponseBytes)
	out := &TemplateResult{
		Templates: pageItems, Total: len(matched), Returned: len(pageItems),
		Page: page, Truncated: truncated,
	}
	if truncated {
		out.Notes = append(out.Notes, "the response byte ceiling trimmed this page")
	}
	if hasMore && !truncated {
		out.NextCursor = encodeCursor(page+1, limit, sig)
	}
	out.Notes = append(out.Notes, "relation_count here counts declared constraints only; pass template to get the full relation list")
	return out, nil
}

func templateDetail(def *misp.ObjectTemplateDefinition) *TemplateDetail {
	d := &TemplateDetail{
		Name: def.Name, UUID: def.UUID, Version: def.Version.String(),
		MetaCategory: def.MetaCategory, Description: def.Description,
		Required: def.Required, RequiredOneOf: def.RequiredOneOf,
	}
	for relation, a := range def.Attributes {
		d.Relations = append(d.Relations, TemplateRelation{
			Relation: relation, Type: a.MISPAttribute, Description: a.Description,
			Multiple: boolPtr(a.Multiple.Bool()), Categories: a.Categories,
			ValuesList: a.ValuesList,
		})
	}
	sort.Slice(d.Relations, func(i, j int) bool { return d.Relations[i].Relation < d.Relations[j].Relation })
	return d
}

func (s *Service) templateIndex(ctx context.Context) ([]misp.ObjectTemplate, error) {
	s.mu.Lock()
	if s.templates != nil && time.Since(s.templatesAt) < metadataTTL {
		defer s.mu.Unlock()
		return s.templates, nil
	}
	s.mu.Unlock()

	t, err := s.client.ObjectTemplates(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.templates, s.templatesAt = t, time.Now()
	s.mu.Unlock()
	return t, nil
}

// templateDef fetches one template definition, cached by the name it was asked
// for. A batch touching six objects of the same template costs one call.
func (s *Service) templateDef(ctx context.Context, name string) (*misp.ObjectTemplateDefinition, error) {
	key := strings.ToLower(name)

	s.mu.Lock()
	if e, ok := s.templateDefs[key]; ok && time.Since(e.at) < metadataTTL {
		defer s.mu.Unlock()
		return e.def, nil
	}
	s.mu.Unlock()

	def, err := s.client.ObjectTemplateRaw(ctx, name)
	if err != nil {
		if misp.NotFound(err) {
			return nil, fmt.Errorf("object template %q is not on this instance; call misp_object_templates with no argument to see what is", name)
		}
		return nil, err
	}

	s.mu.Lock()
	if s.templateDefs == nil {
		s.templateDefs = map[string]templateCacheEntry{}
	}
	s.templateDefs[key] = templateCacheEntry{def: def, at: time.Now()}
	s.mu.Unlock()
	return def, nil
}

// relationshipVocabulary probes the instance once per TTL.
//
// MISP stores relationship_type as free text and exposes no documented index
// for the vocabulary, so this is expected to come back empty on most instances.
// When it does, references are written unvalidated and every answer says so.
func (s *Service) relationshipVocabulary(ctx context.Context) map[string]bool {
	s.mu.Lock()
	if s.relationships != nil && time.Since(s.relationshipsAt) < metadataTTL {
		defer s.mu.Unlock()
		return s.relationships
	}
	s.mu.Unlock()

	var vocab map[string]bool
	if rels, err := s.client.ObjectRelationships(ctx); err == nil && len(rels) > 0 {
		vocab = make(map[string]bool, len(rels))
		for _, r := range rels {
			if r.Name != "" {
				vocab[r.Name] = true
			}
		}
	} else {
		// An empty non-nil map records "probed, not available", so the probe is
		// not repeated on every call within the TTL.
		vocab = map[string]bool{}
	}

	s.mu.Lock()
	s.relationships, s.relationshipsAt = vocab, time.Now()
	s.mu.Unlock()
	return vocab
}
