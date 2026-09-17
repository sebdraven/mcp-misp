package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/mcp-misp/internal/config"
)

// fileTemplate and x509Template mirror the real misp-objects definitions:
// requiredOneOf only, no required, and no deduplication key anywhere.
func fileTemplate() map[string]any {
	return map[string]any{
		"name": "file", "uuid": "tpl-file", "version": "26", "meta-category": "file",
		"description":   "File object",
		"requiredOneOf": []string{"filename", "sha256", "md5"},
		"attributes": map[string]any{
			"filename":      map[string]any{"misp-attribute": "filename", "multiple": true, "description": "Filename on disk"},
			"sha256":        map[string]any{"misp-attribute": "sha256", "description": "SHA-256"},
			"md5":           map[string]any{"misp-attribute": "md5", "description": "MD5"},
			"size-in-bytes": map[string]any{"misp-attribute": "size-in-bytes", "description": "Size"},
			"text":          map[string]any{"misp-attribute": "text", "multiple": true, "description": "Free text"},
		},
	}
}

func x509Template() map[string]any {
	return map[string]any{
		"name": "x509", "uuid": "tpl-x509", "version": "14", "meta-category": "network",
		"description":   "x509 certificate",
		"required":      []string{"x509-fingerprint-sha1"},
		"requiredOneOf": []string{"x509-fingerprint-sha1", "issuer"},
		"attributes": map[string]any{
			"x509-fingerprint-sha1": map[string]any{"misp-attribute": "x509-fingerprint-sha1", "description": "SHA-1 fingerprint"},
			"issuer":                map[string]any{"misp-attribute": "text", "description": "Issuer"},
			"dns_names":             map[string]any{"misp-attribute": "hostname", "multiple": true, "description": "SAN DNS names"},
		},
	}
}

func objectsStub() *stubMISP {
	return &stubMISP{
		orgs: defaultOrgs(),
		events: []map[string]any{{
			"id": "7", "uuid": "event-7", "info": "campaign", "org_id": "1", "orgc_id": "2",
		}},
		templates: []map[string]any{
			{"id": "1", "name": "file", "uuid": "tpl-file", "version": "26", "meta-category": "file", "active": true,
				"description": "File object", "requirements": map[string]any{"requiredOneOf": []string{"filename", "sha256"}}},
			{"id": "2", "name": "x509", "uuid": "tpl-x509", "version": "14", "meta-category": "network", "active": true,
				"description": "x509 certificate", "requirements": map[string]any{"required": []string{"x509-fingerprint-sha1"}}},
		},
		templateDefs:   map[string]map[string]any{"file": fileTemplate(), "x509": x509Template()},
		objectOutcomes: map[string]string{},
		attachFail:     map[string]bool{},
		relStatus:      404,
	}
}

func writableObjects(t *testing.T, s *stubMISP) *Service {
	t.Helper()
	return newService(t, s, func(c *config.Config) {
		c.ReadOnly = false
		c.Warninglists = config.Warninglists{MaxEntries: 1000, TTL: time.Hour, LocalFallback: false}
	})
}

// The APK case: file, certificate, C2 domain and the links between them, in one
// call, with no uuid known in advance.
func TestAddObjectsLandsALinkedGraphInOneCall(t *testing.T) {
	s := objectsStub()
	svc := writableObjects(t, s)

	res, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event: "7",
		Objects: []ObjectSpec{
			{Ref: "apk", Template: "file", Values: map[string]any{
				"filename": "malware.apk",
				"sha256":   "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
			}},
			{Ref: "cert", Template: "x509", Values: map[string]any{
				"x509-fingerprint-sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
				"dns_names":             []any{"c2.example.org", "backup.example.org"},
			}},
		},
		References: []ReferenceSpec{
			{From: "apk", To: "cert", RelationshipType: "signed-by"},
		},
	})
	if err != nil {
		t.Fatalf("AddObjects: %v", err)
	}
	if !res.Validated || res.FailedAt != nil {
		t.Fatalf("result = %+v", res)
	}
	if len(res.CreatedObjects) != 2 || len(res.CreatedReferences) != 1 {
		t.Fatalf("created = %+v / %+v", res.CreatedObjects, res.CreatedReferences)
	}

	ref := res.CreatedReferences[0]
	if ref.FromUUID == "" || ref.ToUUID == "" || ref.FromUUID == ref.ToUUID {
		t.Errorf("local refs should have been resolved to distinct uuids: %+v", ref)
	}
	if got := s.refs()[0]["object_uuid"]; got != ref.FromUUID {
		t.Errorf("reference posted with %v, expected %s", got, ref.FromUUID)
	}

	// The template carries the payload shape, so the caller never names types.
	payload := s.objects()[0]
	if payload["template_uuid"] != "tpl-file" || payload["name"] != "file" {
		t.Errorf("object payload = %+v", payload)
	}
	attrs, _ := payload["Attribute"].([]any)
	if len(attrs) != 2 {
		t.Fatalf("attributes = %+v", attrs)
	}
	for _, a := range attrs {
		m := a.(map[string]any)
		if m["object_relation"] == "sha256" && m["type"] != "sha256" {
			t.Errorf("relation type should come from the template: %+v", m)
		}
	}
}

// Nothing may be written when any part of the batch is invalid.
func TestValidationRefusesTheWholeBatchBeforeWriting(t *testing.T) {
	s := objectsStub()
	svc := writableObjects(t, s)

	res, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event: "7",
		Objects: []ObjectSpec{
			{Ref: "good", Template: "file", Values: map[string]any{"filename": "ok.apk"}},
			{Ref: "bad", Template: "file", Values: map[string]any{"not-a-relation": "x"}},
		},
	})
	if err != nil {
		t.Fatalf("AddObjects: %v", err)
	}
	if res.Validated {
		t.Fatal("the batch is invalid")
	}
	if len(res.CreatedObjects) != 0 || s.count("objects/add") != 0 {
		t.Fatal("a refused batch must not reach the instance at all")
	}
	if !hasNote(res.Notes, "nothing was written") {
		t.Errorf("notes = %v", res.Notes)
	}
	found := false
	for _, e := range res.ValidationErrors {
		if e.Ref == "bad" && e.Relation == "not-a-relation" {
			found = true
		}
	}
	if !found {
		t.Errorf("the offending relation should be named: %+v", res.ValidationErrors)
	}
}

func TestValidationCoversTemplateConstraints(t *testing.T) {
	s := objectsStub()
	svc := writableObjects(t, s)

	cases := map[string]struct {
		spec ObjectSpec
		want string
	}{
		"required missing": {
			ObjectSpec{Template: "x509", Values: map[string]any{"issuer": "CN=x"}},
			"template requires this relation",
		},
		"required_one_of missing": {
			ObjectSpec{Template: "file", Values: map[string]any{"size-in-bytes": "42"}},
			"at least one of these relations",
		},
		"multiplicity violated": {
			ObjectSpec{Template: "file", Values: map[string]any{"sha256": []any{"a", "b"}}},
			"not multiple on this template",
		},
		"unknown template": {
			ObjectSpec{Template: "no-such-template", Values: map[string]any{"a": "b"}},
			"not on this instance",
		},
	}
	for name, tc := range cases {
		res, err := svc.AddObjects(context.Background(), AddObjectsInput{
			Event: "7", Objects: []ObjectSpec{tc.spec},
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Validated {
			t.Errorf("%s: should have been refused", name)
			continue
		}
		joined := ""
		for _, e := range res.ValidationErrors {
			joined += e.Problem + " | " + e.Expected + " ; "
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: want %q in %s", name, tc.want, joined)
		}
	}
}

// An IOC coerced to text is written and then invisible to every pivot, which is
// worse than refusing it.
func TestUnknownRelationsNeverCoerceAnIOCToText(t *testing.T) {
	s := objectsStub()
	svc := writableObjects(t, s)

	for name, value := range map[string]string{
		"sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
		"ip":     "203.0.113.5",
		"domain": "c2.example.org",
		"url":    "https://c2.example.org/gate.php",
		"email":  "operator@example.org",
	} {
		res, err := svc.AddObjects(context.Background(), AddObjectsInput{
			Event:                 "7",
			AllowUnknownRelations: true,
			Objects: []ObjectSpec{{
				Template: "file",
				Values:   map[string]any{"filename": "ok.apk", "invented-relation": value},
			}},
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Validated {
			t.Errorf("%s: a structured value must not be coerced to text", name)
			continue
		}
		if len(res.CoercedRelations) != 0 {
			t.Errorf("%s: nothing should have been coerced", name)
		}
		joined := ""
		for _, e := range res.ValidationErrors {
			joined += e.Problem + " | " + e.Expected + " ; "
		}
		if !strings.Contains(joined, "never correlates") {
			t.Errorf("%s: the refusal should say why: %s", name, joined)
		}
	}
}

// The refusal names the relation that would have worked, when one exists.
func TestCoercionRefusalSuggestsATemplateRelation(t *testing.T) {
	s := objectsStub()
	svc := writableObjects(t, s)

	res, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event: "7", AllowUnknownRelations: true,
		Objects: []ObjectSpec{{
			Template: "file",
			Values: map[string]any{
				"filename": "ok.apk",
				"digest":   "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
			},
		}},
	})
	if err != nil {
		t.Fatalf("AddObjects: %v", err)
	}
	joined := ""
	for _, e := range res.ValidationErrors {
		joined += e.Expected + " ; "
	}
	if !strings.Contains(joined, `"sha256"`) {
		t.Errorf("the template's sha256 relation should be suggested: %s", joined)
	}
}

// Free text through an unknown relation is allowed, and reported.
func TestUnknownRelationCoercionIsAllowedAndReported(t *testing.T) {
	s := objectsStub()
	svc := writableObjects(t, s)

	res, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event: "7", AllowUnknownRelations: true,
		Objects: []ObjectSpec{{
			Ref: "f", Template: "file",
			Values: map[string]any{"filename": "ok.apk", "analyst-note": "seen in campaign X"},
		}},
	})
	if err != nil {
		t.Fatalf("AddObjects: %v", err)
	}
	if !res.Validated {
		t.Fatalf("errors = %+v", res.ValidationErrors)
	}
	if len(res.CoercedRelations) != 1 || res.CoercedRelations[0].Relation != "analyst-note" {
		t.Errorf("coerced = %+v", res.CoercedRelations)
	}
	if res.CoercedRelations[0].WrittenAs != "text" {
		t.Errorf("coerced as %q", res.CoercedRelations[0].WrittenAs)
	}
}

func TestWarninglistHitRefusesTheBatchAndNamesTheEngine(t *testing.T) {
	s := objectsStub()
	s.checkValue = map[string]any{
		"1.1.1.1": []map[string]any{{"id": "7", "name": "Public DNS resolvers"}},
	}
	s.templateDefs["x509"] = x509Template()
	svc := writableObjects(t, s)

	res, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event: "7",
		Objects: []ObjectSpec{{
			Ref: "cert", Template: "x509",
			Values: map[string]any{"x509-fingerprint-sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "issuer": "1.1.1.1"},
		}},
	})
	if err != nil {
		t.Fatalf("AddObjects: %v", err)
	}
	if res.Validated {
		t.Fatal("a warninglisted value must refuse the batch")
	}
	if s.count("objects/add") != 0 {
		t.Error("the check happens before the write")
	}
	joined := ""
	for _, e := range res.ValidationErrors {
		joined += e.Problem + " ; "
	}
	if !strings.Contains(joined, "Public DNS resolvers") || !strings.Contains(joined, "checkValue") {
		t.Errorf("the refusal must name the list and the deciding engine: %s", joined)
	}

	res, err = svc.AddObjects(context.Background(), AddObjectsInput{
		Event: "7", AllowWarninglisted: true,
		Objects: []ObjectSpec{{
			Ref: "cert", Template: "x509",
			Values: map[string]any{"x509-fingerprint-sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "issuer": "1.1.1.1"},
		}},
	})
	if err != nil {
		t.Fatalf("override: %v", err)
	}
	if !res.Validated || len(res.CreatedObjects) != 1 {
		t.Errorf("allow_warninglisted should let it through: %+v", res)
	}
}

// breakOnDuplicate is sent on every call rather than left to the instance.
func TestDuplicatePolicyIsAlwaysExplicit(t *testing.T) {
	for policy, want := range map[string]string{"": "breakOnDuplicate:1", "reject": "breakOnDuplicate:1", "create": "breakOnDuplicate:0"} {
		s := objectsStub()
		svc := writableObjects(t, s)
		_, err := svc.AddObjects(context.Background(), AddObjectsInput{
			Event: "7", OnDuplicate: policy,
			Objects: []ObjectSpec{{Template: "file", Values: map[string]any{"filename": "a.apk"}}},
		})
		if err != nil {
			t.Fatalf("%q: %v", policy, err)
		}
		if got := s.breaks(); len(got) != 1 || got[0] != want {
			t.Errorf("on_duplicate=%q sent %v, want %s", policy, got, want)
		}
	}

	svc := writableObjects(t, objectsStub())
	if _, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event: "7", OnDuplicate: "merge",
		Objects: []ObjectSpec{{Template: "file", Values: map[string]any{"filename": "a.apk"}}},
	}); err == nil {
		t.Error("an unknown on_duplicate must be refused")
	}
}

// A duplicate is an expected outcome, not a failure: the batch carries on so a
// re-run creates what is still missing.
func TestDuplicateIsRecordedAndDoesNotStopTheBatch(t *testing.T) {
	s := objectsStub()
	s.objectOutcomes["file"] = "duplicate"
	svc := writableObjects(t, s)

	res, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event: "7",
		Objects: []ObjectSpec{
			{Ref: "apk", Template: "file", Values: map[string]any{"filename": "a.apk"}},
			{Ref: "cert", Template: "x509", Values: map[string]any{"x509-fingerprint-sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"}},
		},
		References: []ReferenceSpec{{From: "apk", To: "cert", RelationshipType: "signed-by"}},
	})
	if err != nil {
		t.Fatalf("AddObjects: %v", err)
	}
	if len(res.Duplicates) != 1 || res.Duplicates[0].Ref != "apk" {
		t.Fatalf("duplicates = %+v", res.Duplicates)
	}
	if res.FailedAt != nil {
		t.Errorf("a duplicate is not a write failure: %+v", res.FailedAt)
	}
	if len(res.CreatedObjects) != 1 || res.CreatedObjects[0].Ref != "cert" {
		t.Errorf("the rest of the batch should still be written: %+v", res.CreatedObjects)
	}
	if len(res.NotAttempted) != 1 || !strings.Contains(res.NotAttempted[0], "apk") {
		t.Errorf("the reference depending on the duplicate must be named: %v", res.NotAttempted)
	}
	if len(res.CreatedReferences) != 0 {
		t.Error("a reference to an object that was not created must not be invented")
	}
}

// There is no rollback, so the answer has to be exact about what exists.
func TestWriteFailureNamesWhatWasAndWasNotCreated(t *testing.T) {
	s := objectsStub()
	s.objectOutcomes["x509"] = "error"
	svc := writableObjects(t, s)

	res, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event: "7",
		Objects: []ObjectSpec{
			{Ref: "apk", Template: "file", Values: map[string]any{"filename": "a.apk"}},
			{Ref: "cert", Template: "x509", Values: map[string]any{"x509-fingerprint-sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"}},
			{Ref: "other", Template: "file", Values: map[string]any{"filename": "b.apk"}},
		},
		References: []ReferenceSpec{{From: "apk", To: "cert", RelationshipType: "signed-by"}},
	})
	if err != nil {
		t.Fatalf("AddObjects: %v", err)
	}
	if res.FailedAt == nil || res.FailedAt.Stage != "objects" || res.FailedAt.Ref != "cert" {
		t.Fatalf("failed_at = %+v", res.FailedAt)
	}
	if len(res.CreatedObjects) != 1 || res.CreatedObjects[0].Ref != "apk" {
		t.Errorf("created = %+v", res.CreatedObjects)
	}
	joined := strings.Join(res.NotAttempted, " | ")
	if !strings.Contains(joined, "other") || !strings.Contains(joined, "reference[0]") {
		t.Errorf("not_attempted must name the rest: %s", joined)
	}
	if !hasNote(res.Notes, "nothing is rolled back") {
		t.Errorf("notes = %v", res.Notes)
	}
}

// MISP stores relationship_type as free text, so an unvalidated value has to be
// echoed back exactly for a human to spot the typo.
func TestUnvalidatedRelationshipTypesAreEchoedEveryCall(t *testing.T) {
	s := objectsStub()
	svc := writableObjects(t, s)

	for range 2 {
		res, err := svc.AddObjects(context.Background(), AddObjectsInput{
			Event: "7",
			Objects: []ObjectSpec{
				{Ref: "a", Template: "file", Values: map[string]any{"filename": "a.apk"}},
				{Ref: "b", Template: "file", Values: map[string]any{"filename": "b.apk"}},
			},
			References: []ReferenceSpec{{From: "a", To: "b", RelationshipType: "contain"}},
		})
		if err != nil {
			t.Fatalf("AddObjects: %v", err)
		}
		if res.RelationshipTypesValidated {
			t.Fatal("the stub exposes no vocabulary")
		}
		if len(res.UnvalidatedRelationshipTypes) != 1 || res.UnvalidatedRelationshipTypes[0] != "contain" {
			t.Errorf("the exact written value must be echoed: %v", res.UnvalidatedRelationshipTypes)
		}
		if res.CreatedReferences[0].RelationshipType != "contain" || res.CreatedReferences[0].TypeValidated {
			t.Errorf("reference = %+v", res.CreatedReferences[0])
		}
		if !hasNote(res.Notes, "typo is accepted silently") {
			t.Errorf("the warning must appear on every call, not just the first: %v", res.Notes)
		}
	}
}

func TestRelationshipTypeIsValidatedWhenTheInstanceExposesIt(t *testing.T) {
	s := objectsStub()
	s.relStatus = 0
	s.relationships = []map[string]any{{"name": "contains"}, {"name": "signed-by"}}
	svc := writableObjects(t, s)

	res, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event: "7",
		Objects: []ObjectSpec{
			{Ref: "a", Template: "file", Values: map[string]any{"filename": "a.apk"}},
			{Ref: "b", Template: "file", Values: map[string]any{"filename": "b.apk"}},
		},
		References: []ReferenceSpec{{From: "a", To: "b", RelationshipType: "contain"}},
	})
	if err != nil {
		t.Fatalf("AddObjects: %v", err)
	}
	if res.Validated {
		t.Fatal("contain is not in the vocabulary; contains is")
	}
	if !res.RelationshipTypesValidated {
		t.Error("the vocabulary was available")
	}
}

func TestReferenceEndpointsMustResolve(t *testing.T) {
	s := objectsStub()
	svc := writableObjects(t, s)

	res, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event:      "7",
		Objects:    []ObjectSpec{{Ref: "a", Template: "file", Values: map[string]any{"filename": "a.apk"}}},
		References: []ReferenceSpec{{From: "a", To: "nowhere", RelationshipType: "contains"}},
	})
	if err != nil {
		t.Fatalf("AddObjects: %v", err)
	}
	if res.Validated {
		t.Fatal("an unresolvable endpoint must refuse the batch")
	}
	joined := ""
	for _, e := range res.ValidationErrors {
		joined += e.Problem + " ; "
	}
	if !strings.Contains(joined, "neither a ref declared in this batch nor a uuid") {
		t.Errorf("errors = %s", joined)
	}
}

// A reference may point at an object already in the event.
func TestReferenceAcceptsAnExistingUUID(t *testing.T) {
	s := objectsStub()
	svc := writableObjects(t, s)

	res, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event:   "7",
		Objects: []ObjectSpec{{Ref: "a", Template: "file", Values: map[string]any{"filename": "a.apk"}}},
		References: []ReferenceSpec{
			{From: "a", To: "6b2f1a7c-3d4e-4f50-8a9b-0c1d2e3f4a5b", RelationshipType: "contains"},
		},
	})
	if err != nil {
		t.Fatalf("AddObjects: %v", err)
	}
	if !res.Validated || len(res.CreatedReferences) != 1 {
		t.Fatalf("result = %+v", res)
	}
	if res.CreatedReferences[0].ToUUID != "6b2f1a7c-3d4e-4f50-8a9b-0c1d2e3f4a5b" {
		t.Errorf("reference = %+v", res.CreatedReferences[0])
	}
}

func TestDuplicateRefsAreRefused(t *testing.T) {
	svc := writableObjects(t, objectsStub())
	res, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event: "7",
		Objects: []ObjectSpec{
			{Ref: "same", Template: "file", Values: map[string]any{"filename": "a.apk"}},
			{Ref: "same", Template: "file", Values: map[string]any{"filename": "b.apk"}},
		},
	})
	if err != nil {
		t.Fatalf("AddObjects: %v", err)
	}
	if res.Validated {
		t.Fatal("two objects cannot share a ref; references would be ambiguous")
	}
}

func TestBatchCeilings(t *testing.T) {
	svc := newService(t, objectsStub(), func(c *config.Config) {
		c.ReadOnly = false
		c.Caps.ObjectsPerBatch = 2
		c.Caps.ValuesPerObject = 2
		c.Warninglists = config.Warninglists{MaxEntries: 1000, TTL: time.Hour}
	})

	three := []ObjectSpec{
		{Template: "file", Values: map[string]any{"filename": "a"}},
		{Template: "file", Values: map[string]any{"filename": "b"}},
		{Template: "file", Values: map[string]any{"filename": "c"}},
	}
	if _, err := svc.AddObjects(context.Background(), AddObjectsInput{Event: "7", Objects: three}); err == nil {
		t.Error("the batch ceiling must be enforced")
	}

	res, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event: "7",
		Objects: []ObjectSpec{{Template: "file", Values: map[string]any{
			"filename": []any{"a", "b", "c"},
		}}},
	})
	if err != nil {
		t.Fatalf("AddObjects: %v", err)
	}
	if res.Validated {
		t.Error("the per-object value ceiling must be enforced")
	}
}

func TestWriteToolsStillRefuseWhenReadOnly(t *testing.T) {
	svc := newService(t, objectsStub())
	if _, err := svc.AddObjects(context.Background(), AddObjectsInput{
		Event: "7", Objects: []ObjectSpec{{Template: "file", Values: map[string]any{"filename": "a"}}},
	}); err == nil {
		t.Error("AddObjects must refuse on a read-only server")
	}
	if _, err := svc.CreateEvent(context.Background(), CreateEventInput{
		Info: "x", Distribution: "this_community",
	}); err == nil {
		t.Error("CreateEvent must refuse on a read-only server")
	}
}
