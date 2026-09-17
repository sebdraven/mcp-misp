package service

import (
	"context"
	"testing"
)

func taxonomyStub() *stubMISP {
	return &stubMISP{
		taxonomies: []map[string]any{
			{"id": "1", "namespace": "tlp", "description": "Traffic Light Protocol", "version": "9", "enabled": true, "required": true},
			{"id": "2", "namespace": "admiralty-scale", "description": "Admiralty Scale", "version": "3", "enabled": false},
		},
		tags: []map[string]any{
			{"id": "1", "name": "tlp:amber", "colour": "#FFC000", "count": 12},
			{"id": "2", "name": "tlp:clear", "colour": "#FFFFFF", "count": 3},
			{"id": "3", "name": "misp-galaxy:threat-actor=\"APT28\"", "colour": "#0088cc"},
			{"id": "4", "name": "some-local-convention", "colour": "#000000"},
		},
		entries: []map[string]any{
			{"tag": "tlp:amber", "expanded": "Amber"},
			{"tag": "tlp:clear", "expanded": "Clear"},
		},
	}
}

// Nothing about tagging is assumed anywhere else; this is where a caller finds
// out what exists on this instance, local conventions included.
func TestTaxonomiesListsWhatTheInstanceCarries(t *testing.T) {
	svc := newService(t, taxonomyStub())

	res, err := svc.Taxonomies(context.Background(), TaxonomyInput{})
	if err != nil {
		t.Fatalf("Taxonomies: %v", err)
	}
	if len(res.Taxonomies) != 2 {
		t.Errorf("taxonomies = %+v", res.Taxonomies)
	}
	if res.TagsTotal != 4 {
		t.Errorf("tags_total = %d", res.TagsTotal)
	}

	var local *TagView
	for i := range res.Tags {
		if res.Tags[i].Name == "some-local-convention" {
			local = &res.Tags[i]
		}
	}
	if local == nil {
		t.Fatal("a tag outside any taxonomy must still be listed")
	}
	if local.Taxonomy != "" {
		t.Errorf("a tag with no namespace has no taxonomy: %+v", local)
	}
}

func TestTaxonomiesDisabledOnesAreListedNotHidden(t *testing.T) {
	svc := newService(t, taxonomyStub())
	res, err := svc.Taxonomies(context.Background(), TaxonomyInput{})
	if err != nil {
		t.Fatalf("Taxonomies: %v", err)
	}
	for _, tx := range res.Taxonomies {
		if tx.Namespace == "admiralty-scale" {
			if tx.Enabled == nil || *tx.Enabled {
				t.Error("a disabled taxonomy should be reported as disabled, not omitted")
			}
			return
		}
	}
	t.Error("the disabled taxonomy is missing")
}

func TestTaxonomiesNamespaceFilter(t *testing.T) {
	svc := newService(t, taxonomyStub())
	res, err := svc.Taxonomies(context.Background(), TaxonomyInput{Namespace: "tlp"})
	if err != nil {
		t.Fatalf("Taxonomies: %v", err)
	}
	if len(res.Taxonomies) != 1 || res.Taxonomies[0].Namespace != "tlp" {
		t.Errorf("taxonomies = %+v", res.Taxonomies)
	}
	if res.TagsTotal != 2 {
		t.Errorf("only tlp: tags should remain, got %d", res.TagsTotal)
	}
}

func TestTaxonomiesUnknownNamespaceSaysSo(t *testing.T) {
	svc := newService(t, taxonomyStub())
	res, err := svc.Taxonomies(context.Background(), TaxonomyInput{Namespace: "does-not-exist"})
	if err != nil {
		t.Fatalf("Taxonomies: %v", err)
	}
	if !hasNote(res.Notes, "no taxonomy with namespace") {
		t.Errorf("an empty result should say why: %v", res.Notes)
	}
}

func TestTaxonomiesTagSearch(t *testing.T) {
	svc := newService(t, taxonomyStub())
	res, err := svc.Taxonomies(context.Background(), TaxonomyInput{TagSearch: "APT28"})
	if err != nil {
		t.Fatalf("Taxonomies: %v", err)
	}
	if res.TagsTotal != 1 {
		t.Errorf("tags = %+v", res.Tags)
	}
}

// Expanding every taxonomy is one call per taxonomy and tens of thousands of
// entries, which is the volume problem this server exists to avoid.
func TestPredicatesNeedANamespace(t *testing.T) {
	s := taxonomyStub()
	svc := newService(t, s)

	res, err := svc.Taxonomies(context.Background(), TaxonomyInput{IncludePredicates: true})
	if err != nil {
		t.Fatalf("Taxonomies: %v", err)
	}
	if s.count("taxonomies/view") != 0 {
		t.Error("no taxonomy should be expanded without a namespace")
	}
	if !hasNote(res.Notes, "include_predicates needs a namespace") {
		t.Errorf("notes = %v", res.Notes)
	}

	res, err = svc.Taxonomies(context.Background(), TaxonomyInput{Namespace: "tlp", IncludePredicates: true})
	if err != nil {
		t.Fatalf("Taxonomies: %v", err)
	}
	if len(res.Taxonomies) != 1 || len(res.Taxonomies[0].Predicates) != 2 {
		t.Errorf("predicates = %+v", res.Taxonomies)
	}
}

func TestTaxonomiesPaginateTags(t *testing.T) {
	svc := newService(t, taxonomyStub())

	first, err := svc.Taxonomies(context.Background(), TaxonomyInput{Limit: 2})
	if err != nil {
		t.Fatalf("Taxonomies: %v", err)
	}
	if first.TagsReturned != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %+v", first)
	}

	second, err := svc.Taxonomies(context.Background(), TaxonomyInput{Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if second.TagsReturned != 2 || second.NextCursor != "" {
		t.Errorf("second page = %+v", second)
	}
	if second.Tags[0].Name == first.Tags[0].Name {
		t.Error("page 2 should not repeat page 1")
	}
}
