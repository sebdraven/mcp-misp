package service

import (
	"context"
	"strings"
	"testing"
)

func TestObjectTemplatesInventory(t *testing.T) {
	s := objectsStub()
	svc := newService(t, s)

	res, err := svc.ObjectTemplates(context.Background(), TemplateInput{})
	if err != nil {
		t.Fatalf("ObjectTemplates: %v", err)
	}
	if len(res.Templates) != 2 {
		t.Fatalf("templates = %+v", res.Templates)
	}
	if res.Templates[0].Name != "file" {
		t.Errorf("templates should be sorted by name: %+v", res.Templates)
	}
	if s.count("getRaw:file") != 0 {
		t.Error("an inventory must not expand every template")
	}
}

func TestObjectTemplateDetail(t *testing.T) {
	s := objectsStub()
	svc := newService(t, s)

	res, err := svc.ObjectTemplates(context.Background(), TemplateInput{Template: "x509"})
	if err != nil {
		t.Fatalf("ObjectTemplates: %v", err)
	}
	d := res.Template
	if d == nil || d.Name != "x509" {
		t.Fatalf("template = %+v", d)
	}
	if len(d.Required) != 1 || d.Required[0] != "x509-fingerprint-sha1" {
		t.Errorf("required = %v", d.Required)
	}
	if len(d.RequiredOneOf) != 2 {
		t.Errorf("required_one_of = %v", d.RequiredOneOf)
	}

	byName := map[string]TemplateRelation{}
	for _, r := range d.Relations {
		byName[r.Relation] = r
	}
	if byName["dns_names"].Type != "hostname" || byName["dns_names"].Multiple == nil || !*byName["dns_names"].Multiple {
		t.Errorf("dns_names = %+v", byName["dns_names"])
	}
	if byName["issuer"].Multiple == nil || *byName["issuer"].Multiple {
		t.Errorf("issuer should not be multiple: %+v", byName["issuer"])
	}
}

// The question callers arrive with, answered every time.
func TestTemplateDetailStatesThereIsNoDedupKey(t *testing.T) {
	svc := newService(t, objectsStub())
	res, err := svc.ObjectTemplates(context.Background(), TemplateInput{Template: "file"})
	if err != nil {
		t.Fatalf("ObjectTemplates: %v", err)
	}
	if !hasNote(res.Notes, "no deduplication key") {
		t.Errorf("notes = %v", res.Notes)
	}
	if !hasNote(res.Notes, "on_duplicate") {
		t.Errorf("the note should point at where duplicates are actually decided: %v", res.Notes)
	}
}

func TestUnknownTemplateNamesTheDiscoveryTool(t *testing.T) {
	svc := newService(t, objectsStub())
	_, err := svc.ObjectTemplates(context.Background(), TemplateInput{Template: "nope"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "misp_object_templates") {
		t.Errorf("the error should say how to find the valid names: %v", err)
	}
}

func TestTemplateSearchAndCaching(t *testing.T) {
	s := objectsStub()
	svc := newService(t, s)

	res, err := svc.ObjectTemplates(context.Background(), TemplateInput{Search: "certificate"})
	if err != nil {
		t.Fatalf("ObjectTemplates: %v", err)
	}
	if len(res.Templates) != 1 || res.Templates[0].Name != "x509" {
		t.Errorf("search matched %+v", res.Templates)
	}

	for range 3 {
		svc.ObjectTemplates(context.Background(), TemplateInput{Template: "file"})
	}
	if s.count("getRaw:file") != 1 {
		t.Errorf("the definition should be cached, fetched %d times", s.count("getRaw:file"))
	}
}
