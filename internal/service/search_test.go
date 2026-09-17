package service

import (
	"context"
	"strings"
	"testing"
	"time"
)

func searchStub(attrs ...map[string]any) *stubMISP {
	return &stubMISP{attributes: attrs, orgs: defaultOrgs()}
}

// An attribute with no event context forces one misp_event call per result,
// which puts back exactly the volume this server exists to bound.
func TestSearchDefaultProjectionCarriesEventContext(t *testing.T) {
	s := searchStub(attr("1", "1.2.3.4", "ip-dst", "7", true, nil))
	svc := newService(t, s)

	res, err := svc.Search(context.Background(), SearchInput{Value: "1.2.3.4"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res.Attributes) != 1 {
		t.Fatalf("attributes = %+v", res.Attributes)
	}
	a := res.Attributes[0]
	for name, got := range map[string]string{
		"event_id": a.EventID, "event_uuid": a.EventUUID, "event_info": a.EventInfo,
		"event_date": a.EventDate, "org": a.Org, "orgc": a.Orgc,
		"value": a.Value, "type": a.Type,
	} {
		if got == "" {
			t.Errorf("%s should be in the default projection", name)
		}
	}
	if a.Org != "CERT-HOST" || a.Orgc != "CERT-PRODUCER" {
		t.Errorf("org ids should be resolved to names: %q / %q", a.Org, a.Orgc)
	}
	if a.ToIDs == nil || !*a.ToIDs {
		t.Error("to_ids should be in the default projection")
	}
	if a.Warninglist == nil {
		t.Error("the warninglist annotation is never optional")
	}
}

func TestSearchProjectionIsValidated(t *testing.T) {
	svc := newService(t, searchStub())
	_, err := svc.Search(context.Background(), SearchInput{Fields: []string{"value", "nope"}})
	if err == nil {
		t.Fatal("an unknown field must be an error, not a silent no-op")
	}
	if !strings.Contains(err.Error(), "nope") || !strings.Contains(err.Error(), "valid fields are") {
		t.Errorf("the error should name the offender and the vocabulary: %v", err)
	}
}

func TestSearchProjectionNarrows(t *testing.T) {
	s := searchStub(attr("1", "1.2.3.4", "ip-dst", "7", true, nil))
	svc := newService(t, s)

	res, err := svc.Search(context.Background(), SearchInput{Fields: []string{"value", "type"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	a := res.Attributes[0]
	if a.Value == "" || a.Type == "" {
		t.Error("requested fields should survive")
	}
	if a.EventInfo != "" || a.Org != "" || a.Comment != "" {
		t.Errorf("unrequested fields should be dropped: %+v", a)
	}
	if a.Warninglist == nil {
		t.Error("warninglist cannot be projected away")
	}
}

func TestSearchPaginationAndCursor(t *testing.T) {
	var attrs []map[string]any
	for i := range 5 {
		attrs = append(attrs, attr(string(rune('1'+i)), "10.0.0."+string(rune('1'+i)), "ip-dst", "7", false, nil))
	}
	s := searchStub(attrs...)
	svc := newService(t, s)

	first, err := svc.Search(context.Background(), SearchInput{Limit: 2})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if first.Returned != 2 {
		t.Fatalf("returned = %d, want 2", first.Returned)
	}
	if first.NextCursor == "" {
		t.Fatal("a full page with more behind it must hand back a cursor")
	}
	if q := s.attrQuery(); q["limit"] != float64(2) {
		t.Errorf("the instance must be asked for exactly limit, or page 2 skips a record: %v", q["limit"])
	}

	second, err := svc.Search(context.Background(), SearchInput{Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if second.Page != 2 || second.Returned != 2 {
		t.Errorf("page 2 = %+v", second)
	}

	last, err := svc.Search(context.Background(), SearchInput{Limit: 2, Cursor: second.NextCursor})
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	if last.Returned != 1 {
		t.Errorf("returned = %d, want 1", last.Returned)
	}
	if last.NextCursor != "" {
		t.Error("an exhausted set must not hand back a cursor")
	}
}

// A cursor carries a fingerprint of the query it was issued for, so it cannot
// be replayed against different filters and silently page through another set.
func TestCursorIsBoundToItsQuery(t *testing.T) {
	s := searchStub(
		attr("1", "a", "ip-dst", "7", false, nil),
		attr("2", "b", "ip-dst", "7", false, nil),
	)
	svc := newService(t, s)

	first, err := svc.Search(context.Background(), SearchInput{Value: "a", Limit: 1})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	_, err = svc.Search(context.Background(), SearchInput{Value: "different", Limit: 1, Cursor: first.NextCursor})
	if err == nil {
		t.Fatal("a cursor from another query must be refused")
	}
	if !strings.Contains(err.Error(), "different query") {
		t.Errorf("the error should say why: %v", err)
	}
}

func TestSearchAnnotatesWarninglistHits(t *testing.T) {
	s := searchStub(attr("1", "1.1.1.1", "ip-dst", "7", true, nil))
	s.checkValue = map[string]any{
		"1.1.1.1": []map[string]any{{"id": "7", "name": "Public DNS resolvers", "type": "cidr"}},
	}
	svc := newService(t, s)

	res, err := svc.Search(context.Background(), SearchInput{Value: "1.1.1.1"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	a := res.Attributes[0]
	if a.Warninglist == nil || !a.Warninglist.Hit {
		t.Fatalf("warninglist = %+v", a.Warninglist)
	}
	if a.Warninglist.Lists[0].Name != "Public DNS resolvers" {
		t.Errorf("lists = %+v", a.Warninglist.Lists)
	}
	if res.Warninglist.Engine != EngineInstance || res.Warninglist.Coverage != CoverageComplete {
		t.Errorf("report = %+v", res.Warninglist)
	}
	if res.Warninglist.ByList["Public DNS resolvers"] != 1 {
		t.Errorf("by_list = %+v", res.Warninglist.ByList)
	}
}

func TestSearchFlagsDegradedCoverage(t *testing.T) {
	s := searchStub(attr("1", "1.1.1.1", "ip-dst", "7", true, nil))
	s.checkValueStatus = 403
	svc := newService(t, s)

	res, err := svc.Search(context.Background(), SearchInput{Value: "1.1.1.1"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Warninglist.Coverage != CoverageUnavailable {
		t.Errorf("coverage = %q", res.Warninglist.Coverage)
	}
	if !contains(res.Flags, FlagCheckUnavailable) {
		t.Errorf("flags = %v", res.Flags)
	}
	a := res.Attributes[0]
	if a.Warninglist == nil || a.Warninglist.Hit {
		t.Error("an unchecked value must not be reported as a hit")
	}
}

func TestExcludeWarninglistedDelegatesAndSaysSo(t *testing.T) {
	s := searchStub(attr("1", "1.1.1.1", "ip-dst", "7", true, nil))
	svc := newService(t, s)

	res, err := svc.Search(context.Background(), SearchInput{Value: "1.1.1.1", ExcludeWarninglisted: true})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if q := s.attrQuery(); q["enforceWarninglist"] != float64(1) {
		t.Errorf("enforceWarninglist should reach the instance, got %v", q["enforceWarninglist"])
	}
	if !hasNote(res.Notes, "absent rather than flagged") {
		t.Errorf("filtering silently is the thing to warn about: %v", res.Notes)
	}
}

// MISP accepts relative windows on timestamp filters but not reliably on
// from/to, so "the last 30 days" is resolved here rather than left to the
// instance's version.
func TestSearchRelativeDatesBecomeAbsolute(t *testing.T) {
	s := searchStub()
	svc := newService(t, s)

	if _, err := svc.Search(context.Background(), SearchInput{From: "30d"}); err != nil {
		t.Fatalf("Search: %v", err)
	}
	from, _ := s.attrQuery()["from"].(string)
	if _, err := time.Parse("2006-01-02", from); err != nil {
		t.Errorf("from = %q, want an absolute YYYY-MM-DD date", from)
	}

	if _, err := svc.Search(context.Background(), SearchInput{From: "not-a-date"}); err == nil {
		t.Error("an unparseable date must be an error")
	}
}

func TestSearchEventsMode(t *testing.T) {
	s := &stubMISP{
		orgs: defaultOrgs(),
		events: []map[string]any{{
			"id": "7", "uuid": "event-7", "info": "campaign", "date": "2026-01-15",
			"published": true, "threat_level_id": "2", "analysis": "1",
			"attribute_count": "1200", "org_id": "1", "orgc_id": "2",
			"Tag": []map[string]any{{"id": "1", "name": "tlp:amber"}},
		}},
	}
	svc := newService(t, s)

	res, err := svc.Search(context.Background(), SearchInput{Returns: "events"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("events = %+v", res.Events)
	}
	e := res.Events[0]
	if e.ThreatLevel != "medium" || e.Analysis != "ongoing" {
		t.Errorf("MISP core enums should be decoded: %+v", e)
	}
	if e.AttributeCount != 1200 {
		t.Errorf("attribute_count = %d", e.AttributeCount)
	}
	if q := s.eventQuery(); q["metadata"] != float64(1) {
		t.Error("event mode must ask for metadata only, or the instance serialises every attribute")
	}
	if res.Warninglist.Note == "" {
		t.Error("event mode should say why there is no annotation rather than report a clean check")
	}
	if s.count("checkValue") != 0 {
		t.Error("there are no attribute values to check in event mode")
	}
}

func TestSearchRejectsUnknownReturns(t *testing.T) {
	svc := newService(t, searchStub())
	if _, err := svc.Search(context.Background(), SearchInput{Returns: "objects"}); err == nil {
		t.Fatal("returns=objects is not supported and must say so")
	}
}

func TestSearchSpillsToDisk(t *testing.T) {
	s := searchStub(attr("1", "1.2.3.4", "ip-dst", "7", true, nil))
	svc := newService(t, s)
	dir := svc.cfg.OutRoot + "/run1"

	res, err := svc.Search(context.Background(), SearchInput{Value: "1.2.3.4", OutDir: dir})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Spill == nil || len(res.Spill.Files) != 2 {
		t.Fatalf("spill = %+v", res.Spill)
	}
	if len(res.Attributes) != 0 {
		t.Error("with out_dir set the results go to disk, not into the response")
	}
	if res.Spill.Records != 1 {
		t.Errorf("records = %d", res.Spill.Records)
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func hasNote(notes []string, substr string) bool {
	for _, n := range notes {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}

// A full page yields a cursor even when nothing is behind it, because MISP's
// page x limit pagination gives no way to look ahead. The last page is then
// empty rather than missing.
func TestFullPageYieldsACursorAndTheNextPageMayBeEmpty(t *testing.T) {
	s := searchStub(
		attr("1", "a", "ip-dst", "7", false, nil),
		attr("2", "b", "ip-dst", "7", false, nil),
	)
	svc := newService(t, s)

	first, err := svc.Search(context.Background(), SearchInput{Limit: 2})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if first.Returned != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %+v", first)
	}

	second, err := svc.Search(context.Background(), SearchInput{Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if second.Returned != 0 {
		t.Errorf("returned = %d, want 0", second.Returned)
	}
	if second.NextCursor != "" {
		t.Error("an empty page ends the walk")
	}
}
