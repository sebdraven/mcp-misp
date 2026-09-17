package mcptools

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sebdraven/mcp-misp/internal/config"
	"github.com/sebdraven/mcp-misp/internal/misp"
	"github.com/sebdraven/mcp-misp/internal/service"
)

var readToolNames = []string{
	"misp_search",
	"misp_event",
	"misp_ioc_context",
	"misp_warninglist_check",
	"misp_taxonomies",
	"misp_describe_instance",
}

var writeToolNames = []string{
	"misp_add_attribute",
	"misp_tag",
}

func registered(t *testing.T, readOnly bool) []*mcp.Tool {
	t.Helper()
	cfg := &config.Config{
		URL:      "https://misp.example.org",
		ReadOnly: readOnly,
		OutRoot:  t.TempDir(),
		Caps: config.Caps{
			SearchDefault: 50, SearchMax: 500,
			AttrDefault: 100, AttrMax: 1000,
			ContextDefault: 20, ContextMax: 200,
			CheckValues: 1000, ResponseBytes: 256 << 10,
		},
		Warninglists: config.Warninglists{MaxEntries: 1000, TTL: time.Hour},
	}
	svc := service.New(misp.New(cfg.URL, "key"), cfg)
	server := mcp.NewServer(&mcp.Implementation{Name: "mcp-misp", Version: "test"}, nil)
	return RegisterAll(server, svc)
}

func names(tools []*mcp.Tool) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, t.Name)
	}
	return out
}

// On a default deployment the write tools are not merely refused, they are
// absent: a client cannot offer what it never saw.
func TestWriteToolsAreAbsentWhenReadOnly(t *testing.T) {
	got := names(registered(t, true))

	if len(got) != len(readToolNames) {
		t.Fatalf("tools = %v, want exactly the %d read tools", got, len(readToolNames))
	}
	for _, want := range readToolNames {
		if !slices.Contains(got, want) {
			t.Errorf("%s is missing", want)
		}
	}
	for _, unwanted := range writeToolNames {
		if slices.Contains(got, unwanted) {
			t.Errorf("%s must not be registered on a read-only server", unwanted)
		}
	}
}

func TestWriteToolsAppearWhenWritable(t *testing.T) {
	got := names(registered(t, false))

	for _, want := range append(append([]string{}, readToolNames...), writeToolNames...) {
		if !slices.Contains(got, want) {
			t.Errorf("%s is missing", want)
		}
	}
	if len(got) != len(readToolNames)+len(writeToolNames) {
		t.Errorf("tools = %v", got)
	}
}

// No publish tool, no delete tool: the scope is read plus two additive writes.
func TestNoPublishOrDeleteToolExists(t *testing.T) {
	for _, name := range names(registered(t, false)) {
		for _, forbidden := range []string{"publish", "delete", "remove", "untag"} {
			if strings.Contains(name, forbidden) {
				t.Errorf("%s is out of scope for this server", name)
			}
		}
	}
}

func TestToolNamesAreNamespacedAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range names(registered(t, false)) {
		if !strings.HasPrefix(name, "misp_") {
			t.Errorf("%s should be namespaced", name)
		}
		if seen[name] {
			t.Errorf("%s registered twice", name)
		}
		seen[name] = true
	}
}

// The description is the only thing a model reads before choosing, so each one
// has to carry the contract that makes its results safe to act on.
func TestDescriptionsCarryTheContract(t *testing.T) {
	byName := map[string]string{}
	for _, tool := range registered(t, false) {
		byName[tool.Name] = tool.Description
	}

	must := map[string][]string{
		"misp_search":            {"warninglist", "next_cursor", "out_dir", "a measure of how often"},
		"misp_event":             {"attribute_count", "never returns the whole event", "next_attribute_cursor"},
		"misp_ioc_context":       {"warninglisted_and_to_ids", "no event at all", "aggregate"},
		"misp_warninglist_check": {"coverage=complete", "engine=local"},
		"misp_taxonomies":        {"assumes no taxonomy", "include_predicates"},
		"misp_describe_instance": {"read-only", "include_type_mapping"},
		"misp_add_attribute":     {"MISP_READONLY=false", "BEFORE anything is written", "allow_warninglisted", "valid_attributes"},
		"misp_tag":               {"MISP_READONLY=false", "no removal tool", "misp_taxonomies"},
	}
	for name, phrases := range must {
		desc, ok := byName[name]
		if !ok {
			t.Errorf("%s is not registered", name)
			continue
		}
		for _, p := range phrases {
			if !strings.Contains(desc, p) {
				t.Errorf("%s description should state %q", name, p)
			}
		}
	}
}

func TestDescriptionsAreNotStubs(t *testing.T) {
	for _, tool := range registered(t, false) {
		if len(tool.Description) < 200 {
			t.Errorf("%s has a %d-character description; it is the only thing a model reads before choosing",
				tool.Name, len(tool.Description))
		}
	}
}
