package misp

import (
	"encoding/json"
	"testing"
)

func TestStrAbsorbsBothScalarForms(t *testing.T) {
	var v struct {
		A Str `json:"a"`
		B Str `json:"b"`
		C Str `json:"c"`
	}
	if err := json.Unmarshal([]byte(`{"a":"12","b":34,"c":null}`), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v.A.String() != "12" || v.A.Int() != 12 {
		t.Errorf("a = %q", v.A)
	}
	if v.B.String() != "34" || v.B.Int() != 34 {
		t.Errorf("b = %q", v.B)
	}
	if v.C != "" {
		t.Errorf("c = %q", v.C)
	}
}

func TestBoolAbsorbsBothScalarForms(t *testing.T) {
	cases := map[string]bool{
		`true`: true, `"1"`: true, `1`: true, `"true"`: true,
		`false`: false, `"0"`: false, `0`: false, `null`: false,
	}
	for raw, want := range cases {
		var v struct {
			X Bool `json:"x"`
		}
		if err := json.Unmarshal([]byte(`{"x":`+raw+`}`), &v); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if v.X.Bool() != want {
			t.Errorf("%s = %v, want %v", raw, v.X.Bool(), want)
		}
	}
}

func TestDecodeCheckValueShapes(t *testing.T) {
	cases := map[string]string{
		"objects": `{"1.1.1.1":[{"id":"7","name":"List of known public DNS resolvers","type":"cidr","category":"false_positive"}]}`,
		"names":   `{"1.1.1.1":["List of known public DNS resolvers"]}`,
		"keyed":   `{"1.1.1.1":{"List of known public DNS resolvers":{"id":"7"}}}`,
	}
	for name, raw := range cases {
		got, err := decodeCheckValue(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		hits := got["1.1.1.1"]
		if len(hits) != 1 {
			t.Fatalf("%s: hits = %+v", name, hits)
		}
		if hits[0].Name != "List of known public DNS resolvers" {
			t.Errorf("%s: name = %q", name, hits[0].Name)
		}
	}
}

// A value with no hit must not appear as a key with an empty list: callers
// distinguish "absent from the map" from "checked and clean" by other means.
func TestDecodeCheckValueDropsEmptyHits(t *testing.T) {
	got, err := decodeCheckValue(json.RawMessage(`{"8.8.8.8":[],"1.1.1.1":["X"]}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := got["8.8.8.8"]; ok {
		t.Error("a clean value should not be keyed")
	}
	if len(got) != 1 {
		t.Errorf("got = %+v", got)
	}
}

func TestDecodeEventsBothEnvelopes(t *testing.T) {
	listed := `{"response":[{"Event":{"id":"7","uuid":"u-7","info":"campaign","attribute_count":"120","Org":{"id":"1","name":"CERT-X"}}}]}`
	grouped := `{"response":{"Event":[{"id":"7","uuid":"u-7","info":"campaign","attribute_count":120}]}}`

	c := New("http://x", testKey)
	for name, raw := range map[string]string{"listed": listed, "grouped": grouped} {
		evs, err := c.decodeEvents(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(evs) != 1 {
			t.Fatalf("%s: events = %d", name, len(evs))
		}
		if evs[0].ID != "7" || evs[0].UUID != "u-7" {
			t.Errorf("%s: %+v", name, evs[0])
		}
		if evs[0].AttributeCount.Int() != 120 {
			t.Errorf("%s: attribute_count = %q", name, evs[0].AttributeCount)
		}
	}
}

func TestAttributeCarriesEventStubAndInheritedTags(t *testing.T) {
	raw := `{"response":{"Attribute":[{
		"id":"3","uuid":"a-3","event_id":"7","type":"ip-dst","category":"Network activity",
		"value":"1.1.1.1","to_ids":"1","timestamp":"1700000000",
		"Event":{"id":"7","uuid":"u-7","info":"campaign","org_id":"1","orgc_id":"2"},
		"Tag":[{"id":"1","name":"tlp:clear","inherited":1},{"id":"2","name":"type:OSINT"}],
		"Sighting":[{"id":"9","type":"0","date_sighting":"1700000100"}]
	}]}}`

	var env struct {
		Response struct {
			Attribute []Attribute `json:"Attribute"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	a := env.Response.Attribute[0]
	if !a.ToIDs.Bool() {
		t.Error("to_ids should decode from \"1\"")
	}
	if a.Event == nil || a.Event.UUID != "u-7" || a.Event.OrgcID != "2" {
		t.Errorf("event stub = %+v", a.Event)
	}
	if !a.Tag[0].Inherited.Bool() {
		t.Error("tlp:clear is inherited from the event")
	}
	if a.Tag[1].Inherited.Bool() {
		t.Error("type:OSINT is attribute-level")
	}
	if len(a.Sighting) != 1 {
		t.Errorf("sightings = %+v", a.Sighting)
	}
}

func TestWarninglistEntryCountAcrossVersions(t *testing.T) {
	cases := map[string]int{
		`{"warninglist_entry_count":"4211"}`:                 4211,
		`{"entry_count":312}`:                                312,
		`{"WarninglistEntry":[{"value":"a"},{"value":"b"}]}`: 2,
		`{}`: 0,
	}
	for raw, want := range cases {
		var w Warninglist
		if err := json.Unmarshal([]byte(raw), &w); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got := w.EntryCount(); got != want {
			t.Errorf("%s: EntryCount = %d, want %d", raw, got, want)
		}
	}
}

func TestWarninglistMatchingAttributes(t *testing.T) {
	var w Warninglist
	if err := json.Unmarshal([]byte(`{"valid_attributes":"ip-src, ip-dst ,domain"}`), &w); err != nil {
		t.Fatal(err)
	}
	got := w.MatchingAttributes()
	want := []string{"ip-src", "ip-dst", "domain"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}

	// "ALL" and an empty value both mean unrestricted, not "a type called ALL".
	for _, raw := range []string{`{"valid_attributes":"ALL"}`, `{"valid_attributes":""}`, `{}`} {
		var u Warninglist
		if err := json.Unmarshal([]byte(raw), &u); err != nil {
			t.Fatal(err)
		}
		if len(u.MatchingAttributes()) != 0 {
			t.Errorf("%s: want unrestricted, got %v", raw, u.MatchingAttributes())
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	if d := parseRetryAfter("30"); d.Seconds() != 30 {
		t.Errorf("seconds form = %s", d)
	}
	if d := parseRetryAfter(""); d != 0 {
		t.Errorf("empty = %s", d)
	}
	if d := parseRetryAfter("Mon, 02 Jan 2006 15:04:05 GMT"); d != 0 {
		t.Errorf("a date in the past should yield no wait, got %s", d)
	}
}
