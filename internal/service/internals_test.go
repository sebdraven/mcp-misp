package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/mcp-misp/internal/misp"
)

// ---- cursor ------------------------------------------------------------------

func TestCursorRoundTrip(t *testing.T) {
	sig := fingerprint("q", "value")
	c := encodeCursor(3, 25, sig)

	page, limit, err := decodeCursor(c, sig)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if page != 3 || limit != 25 {
		t.Errorf("page/limit = %d/%d", page, limit)
	}
	if c == "3" {
		t.Error("a cursor is opaque, not a page number in disguise")
	}
}

func TestEmptyCursorIsFirstPage(t *testing.T) {
	page, _, err := decodeCursor("", "sig")
	if err != nil || page != 1 {
		t.Fatalf("page = %d, err = %v", page, err)
	}
}

func TestCursorRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"!!!!", "YWJj"} {
		if _, _, err := decodeCursor(bad, "sig"); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestFingerprintDistinguishesQueries(t *testing.T) {
	if fingerprint("a", 1) == fingerprint("a", 2) {
		t.Error("different queries must not share a fingerprint")
	}
	first, second := fingerprint("a", 1), fingerprint("a", 1)
	if first != second {
		t.Errorf("the same query must fingerprint identically: %s != %s", first, second)
	}
}

// ---- projection --------------------------------------------------------------

func TestResolveFieldsDefaults(t *testing.T) {
	got, err := resolveFields(nil, attributeFields, defaultAttributeFields)
	if err != nil {
		t.Fatalf("resolveFields: %v", err)
	}
	if !got["value"] || !got["event_info"] {
		t.Errorf("default set = %v", got)
	}
	if got["sightings"] {
		t.Error("sightings is not in the default set")
	}
}

func TestResolveFieldsRejectsUnknown(t *testing.T) {
	_, err := resolveFields([]string{"value", "bogus"}, attributeFields, defaultAttributeFields)
	if err == nil {
		t.Fatal("unknown fields must be an error")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("err = %v", err)
	}
}

func TestFitBudgetTrims(t *testing.T) {
	items := make([]AttributeView, 50)
	for i := range items {
		items[i] = AttributeView{Value: strings.Repeat("x", 100), Type: "ip-dst"}
	}
	kept, truncated := fitBudget(items, 1000)
	if !truncated {
		t.Fatal("the set should not fit in 1000 bytes")
	}
	if len(kept) == 0 || len(kept) >= len(items) {
		t.Errorf("kept %d of %d", len(kept), len(items))
	}
	b, _ := json.Marshal(kept)
	if len(b) > 1000 {
		t.Errorf("kept set is %d bytes, over budget", len(b))
	}

	if _, truncated := fitBudget(items[:1], 1<<20); truncated {
		t.Error("a small set must not be trimmed")
	}
}

// Older instances do not mark inherited tags. Guessing which tags came from the
// event would misattribute an event's TLP to a single attribute.
func TestSplitTagsReportsWhetherTheInstanceSaid(t *testing.T) {
	own, inherited, marked := splitTags([]misp.Tag{
		{Name: "tlp:amber", Inherited: true},
		{Name: "type:OSINT"},
	})
	if !marked || len(own) != 1 || len(inherited) != 1 {
		t.Errorf("own = %v, inherited = %v, marked = %v", own, inherited, marked)
	}

	own, inherited, marked = splitTags([]misp.Tag{{Name: "tlp:amber"}, {Name: "type:OSINT"}})
	if marked {
		t.Error("nothing was marked, so the instance did not say")
	}
	if len(own) != 2 || len(inherited) != 0 {
		t.Errorf("unmarked tags belong to the attribute until told otherwise: %v / %v", own, inherited)
	}
}

func TestCoreEnumsDecodeAndUnknownIDsSurvive(t *testing.T) {
	if label(threatLevels, "2") != "medium" {
		t.Error("threat level 2 is medium")
	}
	if label(analysisState, "9") != "9" {
		t.Error("an id this MISP version added must pass through, not vanish")
	}
	if label(distributions, "") != "" {
		t.Error("an absent id yields nothing")
	}
}

// ---- out_dir -----------------------------------------------------------------

func TestOutDirStaysUnderTheRoot(t *testing.T) {
	root := t.TempDir()

	got, err := resolveOutDir(root, filepath.Join(root, "run1"))
	if err != nil {
		t.Fatalf("a path under the root should be allowed: %v", err)
	}
	if got != filepath.Join(root, "run1") {
		t.Errorf("got %q", got)
	}
	if _, err := resolveOutDir(root, root); err != nil {
		t.Errorf("the root itself should be allowed: %v", err)
	}
}

// out_dir is supplied by a model acting on text it read somewhere; without this
// a crafted event description could get the server to write into ~/.ssh.
func TestOutDirRefusesEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	for _, bad := range []string{outside, filepath.Join(root, "..", "elsewhere"), "/etc"} {
		if _, err := resolveOutDir(root, bad); err == nil {
			t.Errorf("%q is outside the root and must be refused", bad)
		}
	}
	if _, err := resolveOutDir(root, ""); err == nil {
		t.Error("an empty out_dir is not a path")
	}
}

func TestOutDirRefusesSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := resolveOutDir(root, filepath.Join(link, "run")); err == nil {
		t.Fatal("a symlink planted inside the root must not be a way out of it")
	}
}

func TestSpillWritesRestrictedFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spill")
	items := []AttributeView{{Value: "1.2.3.4", Type: "ip-dst"}, {Value: "5.6.7.8", Type: "ip-src"}}

	path, err := spillJSONL(dir, "page1", items)
	if err != nil {
		t.Fatalf("spillJSONL: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := len(strings.Split(strings.TrimSpace(string(b)), "\n")); n != 2 {
		t.Errorf("want one JSON object per line, got %d lines", n)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600: spilled CTI is not world-readable", info.Mode().Perm())
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", di.Mode().Perm())
	}
}

// A directory of JSONL with no record of the query or the instance is unusable
// a week later.
func TestManifestRecordsProvenance(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spill")
	path, err := writeManifest(dir, "page1", map[string]any{
		"tool": "misp_search", "instance": "https://misp.example.org", "records": 2,
	})
	if err != nil {
		t.Fatalf("writeManifest: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("manifest is not JSON: %v", err)
	}
	if m["instance"] != "https://misp.example.org" || m["tool"] != "misp_search" {
		t.Errorf("manifest = %v", m)
	}
}

// ---- dates -------------------------------------------------------------------

func TestNormaliseDate(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

	cases := map[string]string{
		"":           "",
		"2026-01-15": "2026-01-15",
		"30d":        "2026-08-18",
		"12h":        "2026-09-17",
		"2w":         "2026-09-03",
		"1m":         "2026-08-18",
	}
	for in, want := range cases {
		got, err := normaliseDate(in, now)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}

	for _, bad := range []string{"yesterday", "30", "2026/01/15", "30x"} {
		if _, err := normaliseDate(bad, now); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

// ---- ceilings ----------------------------------------------------------------

func TestClampAppliesDefaultAndCeiling(t *testing.T) {
	if got := clamp(0, 50, 500); got != 50 {
		t.Errorf("unset should take the default, got %d", got)
	}
	if got := clamp(10_000, 50, 500); got != 500 {
		t.Errorf("an over-large request must be capped, got %d", got)
	}
	if got := clamp(-5, 50, 500); got != 50 {
		t.Errorf("a negative request takes the default, got %d", got)
	}
	if got := clamp(7, 50, 500); got != 7 {
		t.Errorf("a reasonable request passes, got %d", got)
	}
}
