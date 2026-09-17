package service

import (
	"context"
	"testing"
)

func contextStub(attrs ...map[string]any) *stubMISP {
	return &stubMISP{attributes: attrs, orgs: defaultOrgs()}
}

func TestIOCContextAggregates(t *testing.T) {
	s := contextStub(
		attr("1", "1.1.1.1", "ip-dst", "7", true, map[string]any{
			"Tag": []map[string]any{
				{"id": "1", "name": "tlp:amber", "inherited": 1},
				{"id": "2", "name": "type:OSINT"},
			},
		}),
		attr("2", "1.1.1.1", "ip-src", "8", false, map[string]any{
			"Tag": []map[string]any{{"id": "1", "name": "tlp:amber", "inherited": 1}},
		}),
	)
	svc := newService(t, s)

	res, err := svc.IOCContext(context.Background(), ContextInput{Value: "1.1.1.1"})
	if err != nil {
		t.Fatalf("IOCContext: %v", err)
	}
	a := res.Aggregate
	if a.EventCount != 2 || a.AttributeCount != 2 {
		t.Errorf("aggregate = %+v", a)
	}
	if a.ToIDsTrue != 1 || a.ToIDsFalse != 1 {
		t.Errorf("to_ids split = %d/%d", a.ToIDsTrue, a.ToIDsFalse)
	}
	if len(a.Types) != 2 {
		t.Errorf("types = %v", a.Types)
	}
	if len(a.Orgs) != 2 {
		t.Errorf("orgs = %v", a.Orgs)
	}
	if len(a.Tags) == 0 || a.Tags[0].Tag != "tlp:amber" || a.Tags[0].Count != 2 {
		t.Errorf("tags should be counted and ranked: %+v", a.Tags)
	}
	if len(res.Events) != 2 {
		t.Errorf("events = %+v", res.Events)
	}
}

// The event-level TLP tag belongs to the event, not to the attribute it was
// copied onto.
func TestIOCContextSeparatesInheritedTags(t *testing.T) {
	s := contextStub(attr("1", "1.1.1.1", "ip-dst", "7", true, map[string]any{
		"Tag": []map[string]any{
			{"id": "1", "name": "tlp:amber", "inherited": 1},
			{"id": "2", "name": "type:OSINT"},
		},
	}))
	svc := newService(t, s)

	res, err := svc.IOCContext(context.Background(), ContextInput{Value: "1.1.1.1"})
	if err != nil {
		t.Fatalf("IOCContext: %v", err)
	}
	e := res.Events[0]
	if len(e.EventTags) != 1 || e.EventTags[0] != "tlp:amber" {
		t.Errorf("event tags = %v", e.EventTags)
	}
	if len(e.Attributes[0].Tags) != 1 || e.Attributes[0].Tags[0] != "type:OSINT" {
		t.Errorf("attribute tags = %v", e.Attributes[0].Tags)
	}
}

// "Not in this MISP, and on an exclusion list" is a different answer from "not
// in this MISP", so the verdict is returned either way.
func TestIOCContextReportsWarninglistWithNoEvents(t *testing.T) {
	s := contextStub()
	s.checkValue = map[string]any{
		"8.8.8.8": []map[string]any{{"id": "7", "name": "Public DNS resolvers"}},
	}
	svc := newService(t, s)

	res, err := svc.IOCContext(context.Background(), ContextInput{Value: "8.8.8.8"})
	if err != nil {
		t.Fatalf("IOCContext: %v", err)
	}
	if !res.Warninglist.Hit {
		t.Fatal("the warninglist verdict must not depend on the value being known here")
	}
	if res.Aggregate.EventCount != 0 {
		t.Errorf("event_count = %d", res.Aggregate.EventCount)
	}
	if !contains(res.Flags, FlagWarninglisted) {
		t.Errorf("flags = %v", res.Flags)
	}
	if contains(res.Flags, FlagWarninglistedAndToIDs) {
		t.Error("no attribute marks it to_ids, so the combined flag must not fire")
	}
}

func TestIOCContextFlagsWarninglistedAndToIDs(t *testing.T) {
	s := contextStub(attr("1", "1.1.1.1", "ip-dst", "7", true, nil))
	s.checkValue = map[string]any{
		"1.1.1.1": []map[string]any{{"id": "7", "name": "Public DNS resolvers"}},
	}
	svc := newService(t, s)

	res, err := svc.IOCContext(context.Background(), ContextInput{Value: "1.1.1.1"})
	if err != nil {
		t.Fatalf("IOCContext: %v", err)
	}
	if !contains(res.Flags, FlagWarninglistedAndToIDs) {
		t.Errorf("flags = %v", res.Flags)
	}
}

// The server states facts; it does not write the conclusion.
func TestIOCContextCarriesNoProse(t *testing.T) {
	s := contextStub(attr("1", "1.1.1.1", "ip-dst", "7", true, nil))
	s.checkValue = map[string]any{"1.1.1.1": []map[string]any{{"name": "Public DNS resolvers"}}}
	svc := newService(t, s)

	res, err := svc.IOCContext(context.Background(), ContextInput{Value: "1.1.1.1"})
	if err != nil {
		t.Fatalf("IOCContext: %v", err)
	}
	for _, f := range res.Flags {
		switch f {
		case FlagWarninglisted, FlagWarninglistedAndToIDs, FlagCoveragePartial,
			FlagCheckUnavailable, FlagResultsTruncated:
		default:
			t.Errorf("flags must come from the documented vocabulary, got %q", f)
		}
	}
}

func TestIOCContextSightings(t *testing.T) {
	s := contextStub(attr("1", "1.1.1.1", "ip-dst", "7", true, map[string]any{
		"Sighting": []map[string]any{
			{"id": "1", "type": "0", "date_sighting": "1700000100"},
			{"id": "2", "type": "1", "date_sighting": "1700000200"},
			{"id": "3", "type": "0", "date_sighting": "1700000050"},
		},
	}))
	svc := newService(t, s)

	res, err := svc.IOCContext(context.Background(), ContextInput{Value: "1.1.1.1"})
	if err != nil {
		t.Fatalf("IOCContext: %v", err)
	}
	if res.Sightings.Count != 2 || res.Sightings.FalsePositive != 1 {
		t.Errorf("sightings = %+v", res.Sightings)
	}
	if res.Sightings.First != "1700000050" || res.Sightings.Last != "1700000200" {
		t.Errorf("sighting window = %+v", res.Sightings)
	}
	if s.attrQuery()["includeSightings"] != float64(1) {
		t.Error("sightings must be asked for in the same call, not fetched per attribute")
	}
}

func TestIOCContextCanSkipSightings(t *testing.T) {
	s := contextStub(attr("1", "1.1.1.1", "ip-dst", "7", true, nil))
	svc := newService(t, s)
	off := false

	if _, err := svc.IOCContext(context.Background(), ContextInput{Value: "1.1.1.1", IncludeSightings: &off}); err != nil {
		t.Fatalf("IOCContext: %v", err)
	}
	if _, ok := s.attrQuery()["includeSightings"]; ok {
		t.Error("includeSightings should be absent when switched off")
	}
}

func TestIOCContextRequiresAValue(t *testing.T) {
	svc := newService(t, contextStub())
	if _, err := svc.IOCContext(context.Background(), ContextInput{}); err == nil {
		t.Fatal("value is required")
	}
}

func TestIOCContextTrimsEventsButKeepsTheAggregate(t *testing.T) {
	var attrs []map[string]any
	for i := range 5 {
		attrs = append(attrs, attr(string(rune('1'+i)), "1.1.1.1", "ip-dst", string(rune('1'+i)), true, nil))
	}
	s := contextStub(attrs...)
	svc := newService(t, s)

	res, err := svc.IOCContext(context.Background(), ContextInput{Value: "1.1.1.1", MaxEvents: 2})
	if err != nil {
		t.Fatalf("IOCContext: %v", err)
	}
	if len(res.Events) != 2 {
		t.Errorf("events = %d, want 2", len(res.Events))
	}
	if res.Aggregate.EventCount != 5 || res.Aggregate.AttributeCount != 5 {
		t.Errorf("the aggregate must cover everything read, not just what is shown: %+v", res.Aggregate)
	}
	if !contains(res.Flags, FlagResultsTruncated) {
		t.Errorf("flags = %v", res.Flags)
	}
}
