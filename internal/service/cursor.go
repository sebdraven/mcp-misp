package service

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// A cursor is an opaque page marker rather than a bare page number.
//
// It carries a fingerprint of the query it was issued for, so a cursor replayed
// against different filters is refused instead of silently paging through a set
// that is not the one it came from.
type cursor struct {
	Page  int    `json:"p"`
	Limit int    `json:"l"`
	Sig   string `json:"s"`
}

func fingerprint(parts ...any) string {
	b, _ := json.Marshal(parts)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func encodeCursor(page, limit int, sig string) string {
	b, _ := json.Marshal(cursor{Page: page, Limit: limit, Sig: sig})
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor returns the page and limit a cursor was issued for. An empty
// cursor is the first page.
func decodeCursor(s, sig string) (page, limit int, err error) {
	if s == "" {
		return 1, 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, 0, fmt.Errorf("cursor is not a cursor issued by this server")
	}
	var c cursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return 0, 0, fmt.Errorf("cursor is not a cursor issued by this server")
	}
	if c.Sig != sig {
		return 0, 0, fmt.Errorf("cursor belongs to a different query; drop the cursor to start again from page 1 with the current filters")
	}
	if c.Page < 1 {
		return 0, 0, fmt.Errorf("cursor carries an invalid page")
	}
	return c.Page, c.Limit, nil
}
