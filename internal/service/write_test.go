package service

import (
	"context"
	"strings"
	"testing"

	"github.com/sebdraven/mcp-misp/internal/config"
	"github.com/sebdraven/mcp-misp/internal/misp"
)

func writable(cfg *config.Config) { cfg.ReadOnly = false }

func writeStub() *stubMISP {
	return &stubMISP{
		orgs: defaultOrgs(),
		events: []map[string]any{{
			"id": "7", "uuid": "event-7", "info": "campaign", "date": "2026-01-15",
			"org_id": "1", "orgc_id": "2",
		}},
		attrByID:   map[string]map[string]any{"42": {"id": "42", "uuid": "attr-42", "value": "x"}},
		attachFail: map[string]bool{},
	}
}

func TestWriteToolsRefuseWhenReadOnly(t *testing.T) {
	svc := newService(t, writeStub())

	if _, err := svc.AddAttribute(context.Background(), AddAttributeInput{
		Event: "7", Type: "ip-dst", Value: "1.2.3.4",
	}); err == nil {
		t.Error("AddAttribute must refuse on a read-only server")
	}
	if _, err := svc.Tag(context.Background(), TagInput{Target: "event", ID: "7", Tags: []string{"x"}}); err == nil {
		t.Error("Tag must refuse on a read-only server")
	}
}

func TestAddAttributeCreatesAndTags(t *testing.T) {
	s := writeStub()
	svc := newService(t, s, writable)

	res, err := svc.AddAttribute(context.Background(), AddAttributeInput{
		Event: "event-7", Type: "ip-dst", Value: "203.0.113.5",
		Comment: "from report", Tags: []string{"type:OSINT"},
	})
	if err != nil {
		t.Fatalf("AddAttribute: %v", err)
	}
	if !res.Created || res.Attribute == nil {
		t.Fatalf("result = %+v", res)
	}
	if res.Attribute.UUID != "new-attr-uuid" {
		t.Errorf("attribute = %+v", res.Attribute)
	}
	if len(res.TagsApplied) != 1 || res.TagsApplied[0] != "type:OSINT" {
		t.Errorf("tags_applied = %v", res.TagsApplied)
	}
	if got := s.attachedTags(); len(got) != 1 {
		t.Errorf("attached = %v", got)
	}
}

// The value is checked before the write, not after.
func TestAddAttributeRefusesWarninglistedValue(t *testing.T) {
	s := writeStub()
	s.checkValue = map[string]any{
		"1.1.1.1": []map[string]any{{"id": "7", "name": "Public DNS resolvers", "type": "cidr"}},
	}
	svc := newService(t, s, writable)

	res, err := svc.AddAttribute(context.Background(), AddAttributeInput{
		Event: "7", Type: "ip-dst", Value: "1.1.1.1",
	})
	if err != nil {
		t.Fatalf("AddAttribute: %v", err)
	}
	if res.Created {
		t.Fatal("a warninglisted value must not be created by default")
	}
	if s.count("attributes/add") != 0 {
		t.Error("nothing should reach the instance when the value is refused")
	}
	if !strings.Contains(res.Refused, "Public DNS resolvers") {
		t.Errorf("the refusal must name the list: %s", res.Refused)
	}
	if !strings.Contains(res.Refused, "checkValue") {
		t.Errorf("the refusal must name the engine that decided: %s", res.Refused)
	}
	if !strings.Contains(res.Refused, "allow_warninglisted=true") {
		t.Errorf("the refusal must say how to override it: %s", res.Refused)
	}
}

// The local fallback applies valid_attributes, which the instance's own check
// does not, so it can refuse what the MISP web UI accepts. The message has to
// say which engine ruled, or the user has a value that works in one place and
// not the other with no way to tell why.
func TestRefusalNamesTheDecidingEngine(t *testing.T) {
	check := Check{Hit: true, Lists: []misp.WarninglistHit{{ID: "3", Name: "Public DNS resolvers", Type: "cidr"}}}

	instance := refusalMessage("1.1.1.1", check, Report{Engine: EngineInstance})
	for _, want := range []string{"Public DNS resolvers", "instance's own matching engine", "checkValue", "allow_warninglisted=true"} {
		if !strings.Contains(instance, want) {
			t.Errorf("instance refusal should mention %q: %s", want, instance)
		}
	}
	if strings.Contains(instance, "valid_attributes") {
		t.Error("the instance engine does not apply valid_attributes; saying it does would be wrong")
	}

	local := refusalMessage("1.1.1.1", check, Report{Engine: EngineLocal})
	for _, want := range []string{
		"Public DNS resolvers", "local fallback engine", "valid_attributes",
		"MISP web UI", "allow_warninglisted=true",
	} {
		if !strings.Contains(local, want) {
			t.Errorf("local refusal should mention %q: %s", want, local)
		}
	}
}

func TestAddAttributeOverride(t *testing.T) {
	s := writeStub()
	s.checkValue = map[string]any{
		"1.1.1.1": []map[string]any{{"id": "7", "name": "Public DNS resolvers"}},
	}
	svc := newService(t, s, writable)

	res, err := svc.AddAttribute(context.Background(), AddAttributeInput{
		Event: "7", Type: "ip-dst", Value: "1.1.1.1", AllowWarninglisted: true,
	})
	if err != nil {
		t.Fatalf("AddAttribute: %v", err)
	}
	if !res.Created {
		t.Fatal("allow_warninglisted should let it through")
	}
	if !res.Warninglist.Hit {
		t.Error("the hit is still reported on the created attribute")
	}
	if !contains(res.Flags, FlagWarninglisted) {
		t.Errorf("flags = %v", res.Flags)
	}
}

// A clean verdict from a check that did not cover every list is weaker than a
// clean verdict from one that did, and the write path has to say which it got.
func TestAddAttributeNotesDegradedCoverage(t *testing.T) {
	s := writeStub()
	s.checkValueStatus = 403
	svc := newService(t, s, writable)

	res, err := svc.AddAttribute(context.Background(), AddAttributeInput{
		Event: "7", Type: "ip-dst", Value: "203.0.113.5",
	})
	if err != nil {
		t.Fatalf("AddAttribute: %v", err)
	}
	if !res.Created {
		t.Fatal("an unavailable check must not block the write")
	}
	if !contains(res.Flags, FlagCheckUnavailable) {
		t.Errorf("flags = %v", res.Flags)
	}
	if !hasNote(res.Notes, "weaker than usual") {
		t.Errorf("notes = %v", res.Notes)
	}
}

func TestAddAttributeTagFailureDoesNotHideTheCreate(t *testing.T) {
	s := writeStub()
	s.attachFail = map[string]bool{"bad:tag": true}
	svc := newService(t, s, writable)

	res, err := svc.AddAttribute(context.Background(), AddAttributeInput{
		Event: "7", Type: "ip-dst", Value: "203.0.113.5",
		Tags: []string{"good:tag", "bad:tag"},
	})
	if err != nil {
		t.Fatalf("AddAttribute: %v", err)
	}
	if !res.Created {
		t.Fatal("the attribute was created; a tag failure must not undo that")
	}
	if len(res.TagsApplied) != 1 || len(res.TagFailures) != 1 {
		t.Errorf("applied = %v, failures = %v", res.TagsApplied, res.TagFailures)
	}
	if !hasNote(res.Notes, "was created") {
		t.Errorf("notes = %v", res.Notes)
	}
}

func TestAddAttributeRequiredFields(t *testing.T) {
	svc := newService(t, writeStub(), writable)
	if _, err := svc.AddAttribute(context.Background(), AddAttributeInput{Event: "7", Type: "ip-dst"}); err == nil {
		t.Error("value is required")
	}
}

func TestTagResolvesNumericIDsToUUIDs(t *testing.T) {
	s := writeStub()
	svc := newService(t, s, writable)

	res, err := svc.Tag(context.Background(), TagInput{Target: "event", ID: "7", Tags: []string{"tlp:amber"}})
	if err != nil {
		t.Fatalf("Tag: %v", err)
	}
	if res.UUID != "event-7" {
		t.Errorf("uuid = %q", res.UUID)
	}

	res, err = svc.Tag(context.Background(), TagInput{Target: "attribute", ID: "42", Tags: []string{"type:OSINT"}})
	if err != nil {
		t.Fatalf("Tag: %v", err)
	}
	if res.UUID != "attr-42" {
		t.Errorf("uuid = %q", res.UUID)
	}
	if s.count("attributes/view") != 1 {
		t.Error("a numeric attribute id has to be resolved before tagging")
	}
}

func TestTagPassesUUIDsStraightThrough(t *testing.T) {
	s := writeStub()
	svc := newService(t, s, writable)

	res, err := svc.Tag(context.Background(), TagInput{
		Target: "attribute", ID: "already-a-uuid", Tags: []string{"x"},
	})
	if err != nil {
		t.Fatalf("Tag: %v", err)
	}
	if res.UUID != "already-a-uuid" {
		t.Errorf("uuid = %q", res.UUID)
	}
	if s.count("attributes/view") != 0 {
		t.Error("no resolution call is needed for a uuid")
	}
}

func TestTagValidatesTarget(t *testing.T) {
	svc := newService(t, writeStub(), writable)
	if _, err := svc.Tag(context.Background(), TagInput{Target: "object", ID: "1", Tags: []string{"x"}}); err == nil {
		t.Error("only event and attribute are tag targets")
	}
	if _, err := svc.Tag(context.Background(), TagInput{Target: "event", ID: "7"}); err == nil {
		t.Error("at least one tag is required")
	}
}

func TestTagReportsPartialFailure(t *testing.T) {
	s := writeStub()
	s.attachFail = map[string]bool{"refused:tag": true}
	svc := newService(t, s, writable)

	res, err := svc.Tag(context.Background(), TagInput{
		Target: "event", ID: "event-7", Tags: []string{"ok:tag", "refused:tag"},
	})
	if err != nil {
		t.Fatalf("Tag: %v", err)
	}
	if len(res.Applied) != 1 || len(res.Failures) != 1 {
		t.Errorf("applied = %v, failures = %v", res.Applied, res.Failures)
	}
}
