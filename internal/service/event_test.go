package service

import (
	"context"
	"strings"
	"testing"
)

func eventStub(attrCount string, attrs ...map[string]any) *stubMISP {
	return &stubMISP{
		orgs: defaultOrgs(),
		events: []map[string]any{{
			"id": "7", "uuid": "event-7", "info": "campaign", "date": "2026-01-15",
			"published": true, "threat_level_id": "1", "analysis": "2",
			"attribute_count": attrCount, "org_id": "1", "orgc_id": "2",
			"Tag": []map[string]any{{"id": "1", "name": "tlp:amber"}},
		}},
		attributes: attrs,
	}
}

func TestEventAcceptsIDOrUUID(t *testing.T) {
	for _, ref := range []string{"7", "event-7"} {
		s := eventStub("2", attr("1", "1.2.3.4", "ip-dst", "7", true, nil))
		svc := newService(t, s)

		res, err := svc.Event(context.Background(), EventInput{Event: ref})
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if res.Event.UUID != "event-7" {
			t.Errorf("%s: event = %+v", ref, res.Event)
		}
	}
}

func TestEventUnknownReferenceIsExplicit(t *testing.T) {
	svc := newService(t, eventStub("0"))
	_, err := svc.Event(context.Background(), EventInput{Event: "999"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "not visible to this API key") {
		t.Errorf("an empty result may be a permission problem, and the message should say so: %v", err)
	}
}

// /events/view on an event with tens of thousands of attributes serialises all
// of them. metadata=1 plus a paginated attribute search has a ceiling by
// construction.
func TestEventNeverFetchesTheWholeEvent(t *testing.T) {
	s := eventStub("40000", attr("1", "1.2.3.4", "ip-dst", "7", true, nil))
	svc := newService(t, s)

	res, err := svc.Event(context.Background(), EventInput{Event: "7", AttributeLimit: 1})
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if s.eventQuery()["metadata"] != float64(1) {
		t.Error("the event header must be fetched with metadata=1")
	}
	if q := s.attrQuery(); q["eventid"] != "7" {
		t.Errorf("attributes should be fetched separately by eventid, got %v", q["eventid"])
	}
	if !hasNote(res.Notes, "40000 attributes") {
		t.Errorf("the caller should be told the page is a fraction of the event: %v", res.Notes)
	}
}

// The header already carries the event; repeating it on every row of a
// thousand-attribute page is pure volume.
func TestEventAttributesDoNotRepeatTheHeader(t *testing.T) {
	s := eventStub("2", attr("1", "1.2.3.4", "ip-dst", "7", true, nil))
	svc := newService(t, s)

	res, err := svc.Event(context.Background(), EventInput{Event: "7"})
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	a := res.Attributes[0]
	if a.EventInfo != "" || a.Org != "" || a.Orgc != "" || a.EventDate != "" {
		t.Errorf("event context should not be repeated per attribute: %+v", a)
	}
	if a.Value == "" || a.Warninglist == nil {
		t.Errorf("the attribute itself should still be complete: %+v", a)
	}
	if res.Event.Info == "" {
		t.Error("the header carries the context")
	}
}

func TestEventAttributePagination(t *testing.T) {
	var attrs []map[string]any
	for i := range 3 {
		attrs = append(attrs, attr(string(rune('1'+i)), "10.0.0."+string(rune('1'+i)), "ip-dst", "7", false, nil))
	}
	s := eventStub("3", attrs...)
	svc := newService(t, s)

	first, err := svc.Event(context.Background(), EventInput{Event: "7", AttributeLimit: 2})
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if first.AttributesReturned != 2 || first.NextAttributeCursor == "" {
		t.Fatalf("first page = %+v", first)
	}

	second, err := svc.Event(context.Background(), EventInput{
		Event: "7", AttributeLimit: 2, AttributeCursor: first.NextAttributeCursor,
	})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if second.AttributePage != 2 || second.AttributesReturned != 1 {
		t.Errorf("second page = %+v", second)
	}
	if second.NextAttributeCursor != "" {
		t.Error("an exhausted set must not hand back a cursor")
	}
}

func TestEventToIDsOnlyReachesTheInstance(t *testing.T) {
	s := eventStub("2", attr("1", "1.2.3.4", "ip-dst", "7", true, nil))
	svc := newService(t, s)

	if _, err := svc.Event(context.Background(), EventInput{Event: "7", ToIDsOnly: true}); err != nil {
		t.Fatalf("Event: %v", err)
	}
	if q := s.attrQuery(); q["to_ids"] != float64(1) {
		t.Errorf("to_ids = %v, want 1", q["to_ids"])
	}
}

func TestEventSeparateFieldVocabularies(t *testing.T) {
	s := eventStub("2", attr("1", "1.2.3.4", "ip-dst", "7", true, nil))
	svc := newService(t, s)

	res, err := svc.Event(context.Background(), EventInput{
		Event: "7", Fields: []string{"uuid", "info"}, AttributeFields: []string{"value"},
	})
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if res.Event.UUID == "" || res.Event.Info == "" {
		t.Errorf("requested event fields should survive: %+v", res.Event)
	}
	if res.Event.ThreatLevel != "" || res.Event.Tags != nil {
		t.Errorf("unrequested event fields should be dropped: %+v", res.Event)
	}
	if res.Attributes[0].Value == "" || res.Attributes[0].Type != "" {
		t.Errorf("the attribute vocabulary is separate: %+v", res.Attributes[0])
	}

	if _, err := svc.Event(context.Background(), EventInput{Event: "7", Fields: []string{"value"}}); err == nil {
		t.Error("an attribute field name is not valid in the event vocabulary")
	}
}

// Events are read with metadata=1. Whether that carries the galaxy expansion
// depends on the MISP version and has not been verified against a live
// instance, so an empty list says which of the two it is.
func TestEventStatesTheGalaxyReservation(t *testing.T) {
	s := eventStub("1", attr("1", "1.2.3.4", "ip-dst", "7", true, nil))
	svc := newService(t, s)

	res, err := svc.Event(context.Background(), EventInput{
		Event: "7", Fields: []string{"uuid", "galaxies"},
	})
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if !hasNote(res.Notes, "metadata=1") {
		t.Errorf("an empty galaxy list must not be passed off as certainty: %v", res.Notes)
	}

	res, err = svc.Event(context.Background(), EventInput{Event: "7", Fields: []string{"uuid"}})
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if hasNote(res.Notes, "metadata=1") {
		t.Error("the reservation is only relevant when galaxies were asked for")
	}
}
