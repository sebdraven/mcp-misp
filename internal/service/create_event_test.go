package service

import (
	"context"
	"strings"
	"testing"
)

// A caller passing 3 in the belief that it restricts sharing publishes to every
// connected community. Naming the level makes that impossible to do by accident.
func TestCreateEventDistributionIsNamedAndRequired(t *testing.T) {
	s := objectsStub()
	svc := writableObjects(t, s)

	if _, err := svc.CreateEvent(context.Background(), CreateEventInput{Info: "campaign"}); err == nil {
		t.Fatal("distribution must be required")
	} else if !strings.Contains(err.Error(), "your_organisation_only") {
		t.Errorf("the error should list the accepted names: %v", err)
	}

	if _, err := svc.CreateEvent(context.Background(), CreateEventInput{
		Info: "campaign", Distribution: "3",
	}); err == nil {
		t.Error("a numeric distribution must be refused")
	}

	res, err := svc.CreateEvent(context.Background(), CreateEventInput{
		Info: "campaign", Distribution: "this_community",
	})
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	if res.Distribution != "this_community" {
		t.Errorf("distribution = %q", res.Distribution)
	}
	if s.event()["distribution"] != float64(1) {
		t.Errorf("the instance should receive the numeric level: %v", s.event()["distribution"])
	}
}

func TestCreateEventSharingGroupPairing(t *testing.T) {
	svc := writableObjects(t, objectsStub())
	id := 4

	if _, err := svc.CreateEvent(context.Background(), CreateEventInput{
		Info: "x", Distribution: "sharing_group",
	}); err == nil {
		t.Error("sharing_group needs a sharing_group_id")
	}
	if _, err := svc.CreateEvent(context.Background(), CreateEventInput{
		Info: "x", Distribution: "this_community", SharingGroupID: &id,
	}); err == nil {
		t.Error("a sharing_group_id without sharing_group is a contradiction")
	}
	if _, err := svc.CreateEvent(context.Background(), CreateEventInput{
		Info: "x", Distribution: "sharing_group", SharingGroupID: &id,
	}); err != nil {
		t.Errorf("the valid pairing should be accepted: %v", err)
	}
}

// Publishing stays a human decision, so published is never sent.
func TestCreateEventNeverTouchesPublished(t *testing.T) {
	s := objectsStub()
	svc := writableObjects(t, s)

	res, err := svc.CreateEvent(context.Background(), CreateEventInput{
		Info: "campaign", Distribution: "your_organisation_only",
	})
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	if _, sent := s.event()["published"]; sent {
		t.Fatal("published must not appear in the payload at all")
	}
	if res.Published == nil || *res.Published {
		t.Errorf("the event should come back as a draft: %+v", res.Published)
	}
	if !hasNote(res.Notes, "publishing stays a human decision") {
		t.Errorf("notes = %v", res.Notes)
	}
}

func TestCreateEventNamedLevels(t *testing.T) {
	s := objectsStub()
	svc := writableObjects(t, s)

	if _, err := svc.CreateEvent(context.Background(), CreateEventInput{
		Info: "x", Distribution: "this_community", ThreatLevel: "medium", Analysis: "ongoing",
	}); err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	if s.event()["threat_level_id"] != float64(2) {
		t.Errorf("threat_level_id = %v, want 2", s.event()["threat_level_id"])
	}
	if s.event()["analysis"] != float64(1) {
		t.Errorf("analysis = %v, want 1", s.event()["analysis"])
	}

	if _, err := svc.CreateEvent(context.Background(), CreateEventInput{
		Info: "x", Distribution: "this_community", ThreatLevel: "critical",
	}); err == nil {
		t.Error("an unknown threat level must be refused rather than mapped to something")
	}
}

func TestCreateEventTagFailureDoesNotHideTheEvent(t *testing.T) {
	s := objectsStub()
	s.attachFail = map[string]bool{"bad:tag": true}
	svc := writableObjects(t, s)

	res, err := svc.CreateEvent(context.Background(), CreateEventInput{
		Info: "x", Distribution: "this_community", Tags: []string{"ok:tag", "bad:tag"},
	})
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	if res.UUID == "" {
		t.Fatal("the event was created")
	}
	if len(res.TagsApplied) != 1 || len(res.TagFailures) != 1 {
		t.Errorf("applied = %v, failures = %v", res.TagsApplied, res.TagFailures)
	}
}

func TestCreateEventRequiresInfo(t *testing.T) {
	svc := writableObjects(t, objectsStub())
	if _, err := svc.CreateEvent(context.Background(), CreateEventInput{Distribution: "this_community"}); err == nil {
		t.Error("info is required")
	}
}
