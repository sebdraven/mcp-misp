package service

import (
	"context"
	"strings"
	"testing"
)

func TestCheckWarninglistValues(t *testing.T) {
	s := &stubMISP{checkValue: map[string]any{
		"1.1.1.1": []map[string]any{{"id": "7", "name": "Public DNS resolvers", "type": "cidr"}},
	}}
	svc := newService(t, s)

	res, err := svc.CheckWarninglists(context.Background(), CheckInput{
		Values: []string{"1.1.1.1", "203.0.113.5"},
	})
	if err != nil {
		t.Fatalf("CheckWarninglists: %v", err)
	}
	if len(res.Results) != 2 {
		t.Fatalf("results = %+v", res.Results)
	}
	if !res.Results[0].Hit || res.Results[1].Hit {
		t.Errorf("results = %+v", res.Results)
	}
	if res.Report.Coverage != CoverageComplete {
		t.Errorf("report = %+v", res.Report)
	}
}

func TestCheckRespectsTheValueCeiling(t *testing.T) {
	svc := newService(t, &stubMISP{})
	values := make([]string, 1001)
	for i := range values {
		values[i] = "v"
	}
	_, err := svc.CheckWarninglists(context.Background(), CheckInput{Values: values})
	if err == nil {
		t.Fatal("the per-call ceiling must be enforced")
	}
	if !strings.Contains(err.Error(), "ceiling is 1000") {
		t.Errorf("the error should state the ceiling: %v", err)
	}
}

// With no values the tool inventories the lists instead: a caller needs to know
// what can produce a hit before reading one.
func TestCheckWithNoValuesInventoriesTheLists(t *testing.T) {
	s := &stubMISP{warninglists: []map[string]any{
		{"id": "1", "name": "Public DNS resolvers", "type": "cidr", "enabled": true,
			"warninglist_entry_count": "42", "valid_attributes": "ip-src,ip-dst"},
		{"id": "2", "name": "Disabled list", "type": "string", "enabled": false},
	}}
	svc := newService(t, s)

	res, err := svc.CheckWarninglists(context.Background(), CheckInput{})
	if err != nil {
		t.Fatalf("CheckWarninglists: %v", err)
	}
	if len(res.Warninglists) != 1 {
		t.Fatalf("only enabled lists can produce a hit: %+v", res.Warninglists)
	}
	w := res.Warninglists[0]
	if w.Entries != 42 || len(w.AppliesTo) != 2 {
		t.Errorf("warninglist = %+v", w)
	}
	if !hasNote(res.Notes, "1 of 2 warninglists are enabled") {
		t.Errorf("notes = %v", res.Notes)
	}
}

func TestCheckWarnsWhenCoverageIsIncomplete(t *testing.T) {
	s := &stubMISP{checkValueStatus: 403}
	svc := newService(t, s)

	res, err := svc.CheckWarninglists(context.Background(), CheckInput{Values: []string{"1.1.1.1"}})
	if err != nil {
		t.Fatalf("CheckWarninglists: %v", err)
	}
	if res.Report.Coverage != CoverageUnavailable {
		t.Errorf("coverage = %q", res.Report.Coverage)
	}
	if !contains(res.Flags, FlagCheckUnavailable) {
		t.Errorf("flags = %v", res.Flags)
	}
	if !hasNote(res.Notes, "not necessarily checked") {
		t.Errorf("a clean line under partial coverage must be qualified: %v", res.Notes)
	}
}
