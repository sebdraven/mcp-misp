package service

import (
	"net/netip"
	"regexp"
	"strings"
)

// structuredKind is a value shape that must not be written as free text.
type structuredKind struct {
	Name  string
	Types []string
}

var (
	hexOnly     = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	emailShaped = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[A-Za-z]{2,}$`)
	hostShaped  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[A-Za-z]{2,24}$`)

	hashByLength = map[int]structuredKind{
		32:  {"md5", []string{"md5"}},
		40:  {"sha1", []string{"sha1"}},
		56:  {"sha224", []string{"sha224"}},
		64:  {"sha256", []string{"sha256"}},
		96:  {"sha384", []string{"sha384"}},
		128: {"sha512", []string{"sha512"}},
	}
)

// detectStructured reports whether a value carries a shape that correlation
// depends on.
//
// Coercing one of these to text produces an attribute MISP will never correlate
// on: the value is in the database and invisible to every pivot, which is worse
// than refusing to write it. Order matters — a hash is hex before it is
// anything else, and an IP is an address before it is a hostname.
func detectStructured(value string) (structuredKind, bool) {
	v := strings.TrimSpace(value)
	if v == "" {
		return structuredKind{}, false
	}
	if k, ok := hashByLength[len(v)]; ok && hexOnly.MatchString(v) {
		return k, true
	}
	if _, err := netip.ParseAddr(v); err == nil {
		return structuredKind{"ip", []string{"ip-src", "ip-dst", "ip"}}, true
	}
	if _, err := netip.ParsePrefix(v); err == nil {
		return structuredKind{"ip", []string{"ip-src", "ip-dst", "ip"}}, true
	}
	if i := strings.Index(v, "://"); i > 0 && !strings.ContainsAny(v, " \t") {
		return structuredKind{"url", []string{"url", "link", "uri"}}, true
	}
	if emailShaped.MatchString(v) {
		return structuredKind{"email", []string{"email", "email-src", "email-dst"}}, true
	}
	if len(v) <= 253 && hostShaped.MatchString(v) {
		return structuredKind{"domain or hostname", []string{"domain", "hostname"}}, true
	}
	return structuredKind{}, false
}

// suggestRelation finds a relation of the template whose attribute type fits the
// detected shape, so a refusal can name the relation that would have worked.
func suggestRelation(relations map[string]string, kind structuredKind) string {
	for _, want := range kind.Types {
		for relation, typ := range relations {
			if typ == want {
				return relation
			}
		}
	}
	return ""
}
