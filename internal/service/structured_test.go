package service

import "testing"

func TestDetectStructured(t *testing.T) {
	structured := map[string]string{
		"d41d8cd98f00b204e9800998ecf8427e":                                 "md5",
		"da39a3ee5e6b4b0d3255bfef95601890afd80709":                         "sha1",
		"a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90": "sha256",
		"203.0.113.5":                     "ip",
		"2001:db8::1":                     "ip",
		"10.0.0.0/8":                      "ip",
		"https://c2.example.org/gate.php": "url",
		"operator@example.org":            "email",
		"c2.example.org":                  "domain or hostname",
		"example.com":                     "domain or hostname",
	}
	for value, want := range structured {
		kind, ok := detectStructured(value)
		if !ok {
			t.Errorf("%q should be detected as %s", value, want)
			continue
		}
		if kind.Name != want {
			t.Errorf("%q detected as %s, want %s", value, kind.Name, want)
		}
	}

	free := []string{
		"", "seen in campaign X", "CN=Some Issuer, O=Corp",
		"Payload delivery", "1.0.3", "42", "zzzz",
		"a1b2c3", // too short to be any hash
	}
	for _, value := range free {
		if kind, ok := detectStructured(value); ok {
			t.Errorf("%q should be free text, detected as %s", value, kind.Name)
		}
	}
}

func TestSuggestRelation(t *testing.T) {
	relations := map[string]string{
		"filename": "filename",
		"sha256":   "sha256",
		"text":     "text",
	}
	if got := suggestRelation(relations, structuredKind{"sha256", []string{"sha256"}}); got != "sha256" {
		t.Errorf("got %q", got)
	}
	if got := suggestRelation(relations, structuredKind{"ip", []string{"ip-src", "ip-dst"}}); got != "" {
		t.Errorf("no relation carries an IP here, got %q", got)
	}
}
