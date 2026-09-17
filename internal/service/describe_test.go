package service

import (
	"context"
	"testing"

	"github.com/sebdraven/mcp-misp/internal/config"
)

func describeStub() *stubMISP {
	return &stubMISP{
		orgs: defaultOrgs(),
		warninglists: []map[string]any{
			{"id": "1", "name": "a", "enabled": true},
			{"id": "2", "name": "b", "enabled": false},
		},
	}
}

func TestDescribeReportsTheInstance(t *testing.T) {
	svc := newService(t, describeStub())

	res, err := svc.Describe(context.Background(), DescribeInput{})
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if res.MISPVersion != "2.4.999" {
		t.Errorf("version = %q", res.MISPVersion)
	}
	if len(res.AttributeTypes) != 3 || len(res.AttributeCategories) != 2 {
		t.Errorf("types/categories = %v / %v", res.AttributeTypes, res.AttributeCategories)
	}
	if len(res.Organisations) != 2 {
		t.Errorf("organisations = %+v", res.Organisations)
	}
	if res.Warninglists.Total != 2 || res.Warninglists.Enabled != 1 {
		t.Errorf("warninglists = %+v", res.Warninglists)
	}
	if !res.ReadOnly || res.WriteTools {
		t.Errorf("a read-only server must say so: %+v", res)
	}
	if res.Caps.SearchMax == 0 || res.Caps.ResponseBytes == 0 {
		t.Errorf("the ceilings are part of what a caller has to plan around: %+v", res.Caps)
	}
	if res.Host == "" {
		t.Error("host should be reported")
	}
}

// The mapping is a large matrix and most callers never need it.
func TestDescribeOmitsTypeMappingByDefault(t *testing.T) {
	svc := newService(t, describeStub())

	res, err := svc.Describe(context.Background(), DescribeInput{})
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if res.CategoryTypeMapping != nil {
		t.Error("the mapping should be omitted unless asked for")
	}
	if !hasNote(res.Notes, "include_type_mapping") {
		t.Errorf("the caller should be told how to get it: %v", res.Notes)
	}

	res, err = svc.Describe(context.Background(), DescribeInput{IncludeTypeMapping: true})
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if len(res.CategoryTypeMapping) == 0 {
		t.Error("include_type_mapping should return it")
	}
}

// A key without one permission should still get the rest.
func TestDescribeDegradesPerLookup(t *testing.T) {
	s := describeStub()
	s.warninglists = nil
	svc := newService(t, s, func(c *config.Config) { c.ReadOnly = false })

	res, err := svc.Describe(context.Background(), DescribeInput{})
	if err != nil {
		t.Fatalf("a partial instance must not fail the whole tool: %v", err)
	}
	if res.MISPVersion == "" {
		t.Error("the lookups that worked should still be reported")
	}
	if !res.WriteTools {
		t.Error("a writable server should report its write tools as registered")
	}
}
