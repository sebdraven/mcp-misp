package service

import (
	"context"
	"net/url"
)

type DescribeInput struct {
	IncludeTypeMapping bool
}

type OrgView struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	UUID  string `json:"uuid,omitempty"`
	Local *bool  `json:"local,omitempty"`
}

type WarninglistInventory struct {
	Total   int `json:"total"`
	Enabled int `json:"enabled"`
}

type CapsView struct {
	SearchDefault  int `json:"search_limit_default"`
	SearchMax      int `json:"search_limit_max"`
	AttrDefault    int `json:"attribute_limit_default"`
	AttrMax        int `json:"attribute_limit_max"`
	ContextDefault int `json:"context_events_default"`
	ContextMax     int `json:"context_events_max"`
	CheckValues    int `json:"warninglist_check_values_max"`
	ResponseBytes  int `json:"response_bytes_max"`
}

type DescribeResult struct {
	Host                string               `json:"host"`
	MISPVersion         string               `json:"misp_version,omitempty"`
	ReadOnly            bool                 `json:"readonly"`
	WriteTools          bool                 `json:"write_tools_registered"`
	AttributeTypes      []string             `json:"attribute_types,omitempty"`
	AttributeCategories []string             `json:"attribute_categories,omitempty"`
	CategoryTypeMapping map[string][]string  `json:"category_type_mapping,omitempty"`
	Organisations       []OrgView            `json:"organisations,omitempty"`
	Warninglists        WarninglistInventory `json:"warninglists"`
	OutRoot             string               `json:"out_dir_root"`
	Caps                CapsView             `json:"limits"`
	Notes               []string             `json:"notes,omitempty"`
}

// Describe reports what this particular instance offers.
//
// It is what makes instance neutrality workable: without it a caller has to
// guess which attribute types and which organisation names are valid here, and
// guessing means hard-coding one deployment's conventions into every query.
func (s *Service) Describe(ctx context.Context, in DescribeInput) (*DescribeResult, error) {
	out := &DescribeResult{
		Host:       hostOnly(s.client.BaseURL()),
		ReadOnly:   s.cfg.ReadOnly,
		WriteTools: !s.cfg.ReadOnly,
		OutRoot:    s.cfg.OutRoot,
		Caps: CapsView{
			SearchDefault: s.cfg.Caps.SearchDefault, SearchMax: s.cfg.Caps.SearchMax,
			AttrDefault: s.cfg.Caps.AttrDefault, AttrMax: s.cfg.Caps.AttrMax,
			ContextDefault: s.cfg.Caps.ContextDefault, ContextMax: s.cfg.Caps.ContextMax,
			CheckValues: s.cfg.Caps.CheckValues, ResponseBytes: s.cfg.Caps.ResponseBytes,
		},
	}

	// Each lookup degrades on its own: a key without the permission for one of
	// them should still get the rest rather than an error for the whole tool.
	if v, err := s.serverVersion(ctx); err == nil {
		out.MISPVersion = v.Version
	} else {
		out.Notes = append(out.Notes, "server version unavailable: "+err.Error())
	}

	if d, err := s.describeTypes(ctx); err == nil {
		out.AttributeTypes = d.Types
		out.AttributeCategories = d.Categories
		if in.IncludeTypeMapping {
			out.CategoryTypeMapping = d.CategoryToTypes
		} else if len(d.CategoryToTypes) > 0 {
			out.Notes = append(out.Notes, "category_type_mapping omitted; pass include_type_mapping to get it")
		}
	} else {
		out.Notes = append(out.Notes, "attribute types unavailable: "+err.Error())
	}

	if orgs, err := s.client.Organisations(ctx); err == nil {
		for _, o := range orgs {
			out.Organisations = append(out.Organisations, OrgView{
				ID: o.ID.String(), Name: o.Name, UUID: o.UUID, Local: boolPtr(o.Local.Bool()),
			})
		}
	} else {
		out.Notes = append(out.Notes, "organisations unavailable: "+err.Error())
	}

	if lists, err := s.client.Warninglists(ctx); err == nil {
		out.Warninglists.Total = len(lists)
		for _, l := range lists {
			if l.Enabled.Bool() {
				out.Warninglists.Enabled++
			}
		}
	} else {
		out.Notes = append(out.Notes, "warninglist inventory unavailable: "+err.Error())
	}

	return out, nil
}

func hostOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}
