package misp

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// MISP is inconsistent about JSON scalars across versions and endpoints: an id
// is "12" in one payload and 12 in the next, to_ids is true here and "1" there.
// Str and Bool absorb that so every call site can stop caring.

type Str string

func (s *Str) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*s = ""
		return nil
	}
	if b[0] == '"' {
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*s = Str(v)
		return nil
	}
	*s = Str(strings.Trim(string(b), `"`))
	return nil
}

func (s Str) String() string { return string(s) }

func (s Str) Int() int {
	n, _ := strconv.Atoi(strings.TrimSpace(string(s)))
	return n
}

type Bool bool

func (v *Bool) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case len(b) == 0, bytes.Equal(b, []byte("null")):
		*v = false
	case bytes.Equal(b, []byte("true")), bytes.Equal(b, []byte(`"1"`)), bytes.Equal(b, []byte("1")):
		*v = true
	case bytes.Equal(b, []byte("false")), bytes.Equal(b, []byte(`"0"`)), bytes.Equal(b, []byte("0")):
		*v = false
	default:
		var s string
		if json.Unmarshal(b, &s) == nil {
			p, err := strconv.ParseBool(strings.TrimSpace(s))
			if err != nil {
				*v = false
				return nil
			}
			*v = Bool(p)
			return nil
		}
		*v = false
	}
	return nil
}

func (v Bool) Bool() bool { return bool(v) }

// Tag is a tag as it appears on an event or an attribute.
//
// Inherited marks a tag that MISP copied down from the parent event when
// includeEventTags was set. Older instances omit the field entirely, which is
// why callers must treat "no tag is inherited" as "this instance does not say"
// rather than as "all of these are attribute-level".
type Tag struct {
	ID         Str    `json:"id"`
	Name       string `json:"name"`
	Colour     string `json:"colour"`
	Exportable Bool   `json:"exportable"`
	LocalOnly  Bool   `json:"local_only"`
	Inherited  Bool   `json:"inherited"`
	Count      Str    `json:"count"`
}

// Sighting types, as MISP encodes them.
const (
	SightingTrue          = "0"
	SightingFalsePositive = "1"
	SightingExpiration    = "2"
)

type Sighting struct {
	ID           Str    `json:"id"`
	AttributeID  Str    `json:"attribute_id"`
	EventID      Str    `json:"event_id"`
	OrgID        Str    `json:"org_id"`
	DateSighting Str    `json:"date_sighting"`
	Type         Str    `json:"type"`
	Source       string `json:"source"`
	UUID         string `json:"uuid"`
}

// AttributeEvent is the event stub that /attributes/restSearch nests inside
// every attribute. It carries ids but no organisation names, which is why the
// service keeps an organisation index.
type AttributeEvent struct {
	ID           Str    `json:"id"`
	UUID         string `json:"uuid"`
	Info         string `json:"info"`
	OrgID        Str    `json:"org_id"`
	OrgcID       Str    `json:"orgc_id"`
	Date         string `json:"date"`
	Published    Bool   `json:"published"`
	Distribution Str    `json:"distribution"`
	Analysis     Str    `json:"analysis"`
	ThreatLevel  Str    `json:"threat_level_id"`
}

type Attribute struct {
	ID             Str             `json:"id"`
	UUID           string          `json:"uuid"`
	EventID        Str             `json:"event_id"`
	ObjectID       Str             `json:"object_id"`
	ObjectRelation string          `json:"object_relation"`
	Category       string          `json:"category"`
	Type           string          `json:"type"`
	Value          string          `json:"value"`
	ToIDs          Bool            `json:"to_ids"`
	Timestamp      Str             `json:"timestamp"`
	Comment        string          `json:"comment"`
	Distribution   Str             `json:"distribution"`
	Deleted        Bool            `json:"deleted"`
	FirstSeen      Str             `json:"first_seen"`
	LastSeen       Str             `json:"last_seen"`
	Tag            []Tag           `json:"Tag"`
	Event          *AttributeEvent `json:"Event"`
	Sighting       []Sighting      `json:"Sighting"`
}

type Organisation struct {
	ID    Str    `json:"id"`
	Name  string `json:"name"`
	UUID  string `json:"uuid"`
	Local Bool   `json:"local"`
}

type GalaxyCluster struct {
	UUID        string `json:"uuid"`
	Value       string `json:"value"`
	Type        string `json:"type"`
	TagName     string `json:"tag_name"`
	Description string `json:"description"`
}

type Galaxy struct {
	ID        Str             `json:"id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Namespace string          `json:"namespace"`
	Clusters  []GalaxyCluster `json:"GalaxyCluster"`
}

// Event is the metadata-only shape returned by /events/restSearch with
// metadata=1. Attributes are fetched separately and paginated.
type Event struct {
	ID             Str           `json:"id"`
	UUID           string        `json:"uuid"`
	Info           string        `json:"info"`
	Date           string        `json:"date"`
	Published      Bool          `json:"published"`
	ThreatLevelID  Str           `json:"threat_level_id"`
	Analysis       Str           `json:"analysis"`
	Distribution   Str           `json:"distribution"`
	Timestamp      Str           `json:"timestamp"`
	PublishTime    Str           `json:"publish_timestamp"`
	AttributeCount Str           `json:"attribute_count"`
	OrgID          Str           `json:"org_id"`
	OrgcID         Str           `json:"orgc_id"`
	Org            *Organisation `json:"Org"`
	Orgc           *Organisation `json:"Orgc"`
	Tag            []Tag         `json:"Tag"`
	Galaxy         []Galaxy      `json:"Galaxy"`
	Object         []Object      `json:"Object"`
	Attribute      []Attribute   `json:"Attribute"`
}

type Object struct {
	ID           Str         `json:"id"`
	UUID         string      `json:"uuid"`
	Name         string      `json:"name"`
	MetaCategory string      `json:"meta-category"`
	Comment      string      `json:"comment"`
	Attribute    []Attribute `json:"Attribute"`
}

// Warninglist is one entry of /warninglists/index. Entry counts are reported
// under different names across versions; EntryCount resolves them.
type Warninglist struct {
	ID               Str    `json:"id"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	Description      string `json:"description"`
	Version          Str    `json:"version"`
	Enabled          Bool   `json:"enabled"`
	Default          Bool   `json:"default"`
	Category         string `json:"category"`
	ValidAttributes  string `json:"valid_attributes"`
	EntryCountA      Str    `json:"warninglist_entry_count"`
	EntryCountB      Str    `json:"entry_count"`
	WarninglistEntry []struct {
		Value string `json:"value"`
	} `json:"WarninglistEntry"`
	WarninglistType []struct {
		Type string `json:"type"`
	} `json:"WarninglistType"`
}

func (w Warninglist) EntryCount() int {
	if n := w.EntryCountA.Int(); n > 0 {
		return n
	}
	if n := w.EntryCountB.Int(); n > 0 {
		return n
	}
	return len(w.WarninglistEntry)
}

// MatchingAttributes is the attribute-type allowlist the list applies to.
// Empty means the list is unrestricted.
func (w Warninglist) MatchingAttributes() []string {
	if len(w.WarninglistType) > 0 {
		out := make([]string, 0, len(w.WarninglistType))
		for _, t := range w.WarninglistType {
			if t.Type != "" && t.Type != "ALL" {
				out = append(out, t.Type)
			}
		}
		return out
	}
	v := strings.TrimSpace(w.ValidAttributes)
	if v == "" || v == "ALL" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type Taxonomy struct {
	ID          Str    `json:"id"`
	Namespace   string `json:"namespace"`
	Description string `json:"description"`
	Version     Str    `json:"version"`
	Enabled     Bool   `json:"enabled"`
	Exclusive   Bool   `json:"exclusive"`
	Required    Bool   `json:"required"`
}

type ServerVersion struct {
	Version      string `json:"version"`
	PermSync     Bool   `json:"perm_sync"`
	PermSighting Bool   `json:"perm_sighting"`
	PermAdmin    Bool   `json:"perm_admin"`
}

type DescribeTypes struct {
	Types           []string            `json:"types"`
	Categories      []string            `json:"categories"`
	CategoryToTypes map[string][]string `json:"category_type_mappings"`
}

// AttributeInput is the payload of POST /attributes/add/{event}.
type AttributeInput struct {
	Type         string   `json:"type"`
	Value        string   `json:"value"`
	Category     string   `json:"category,omitempty"`
	ToIDs        *bool    `json:"to_ids,omitempty"`
	Comment      string   `json:"comment,omitempty"`
	Distribution *int     `json:"distribution,omitempty"`
	Tags         []string `json:"-"`
}
