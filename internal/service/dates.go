package service

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var relativeDate = regexp.MustCompile(`^(\d+)([dhwm])$`)

// normaliseDate turns a relative window into the absolute date MISP's from/to
// filters expect.
//
// MISP accepts relative forms on timestamp filters but not reliably on from/to,
// which are event dates. Resolving here makes "the last 30 days" mean the same
// thing on every instance rather than depending on its version.
func normaliseDate(v string, now time.Time) (string, error) {
	if v == "" {
		return "", nil
	}
	if _, err := time.Parse("2006-01-02", v); err == nil {
		return v, nil
	}
	if m := relativeDate.FindStringSubmatch(v); m != nil {
		n, _ := strconv.Atoi(m[1])
		var d time.Duration
		switch m[2] {
		case "h":
			d = time.Duration(n) * time.Hour
		case "d":
			d = time.Duration(n) * 24 * time.Hour
		case "w":
			d = time.Duration(n) * 7 * 24 * time.Hour
		case "m":
			d = time.Duration(n) * 30 * 24 * time.Hour
		}
		return now.UTC().Add(-d).Format("2006-01-02"), nil
	}
	return "", fmt.Errorf("date %q: want YYYY-MM-DD or a relative window such as 30d, 12h, 4w, 6m", v)
}
