package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Spill is what a tool returns instead of its results when out_dir is set.
type Spill struct {
	Dir     string   `json:"dir"`
	Files   []string `json:"files"`
	Records int      `json:"records"`
}

// resolveOutDir confines out_dir under MISP_OUT_ROOT.
//
// out_dir is caller-supplied, and the caller here is a language model acting on
// text it read somewhere. Without this, a crafted event description could get
// the server to write into ~/.ssh. Symlinks are resolved on the deepest
// existing ancestor, so a link planted inside the root cannot point out of it.
func resolveOutDir(root, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return "", fmt.Errorf("no out_dir given")
	}
	abs, err := filepath.Abs(requested)
	if err != nil {
		return "", fmt.Errorf("out_dir %q: %w", requested, err)
	}
	abs = filepath.Clean(abs)

	realRoot, err := realExistingPrefix(filepath.Clean(root))
	if err != nil {
		return "", err
	}
	realAbs, err := realExistingPrefix(abs)
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(realRoot, realAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("out_dir %q is outside the permitted root %q; set MISP_OUT_ROOT to allow another location", requested, root)
	}
	return abs, nil
}

func realExistingPrefix(p string) (string, error) {
	rest := ""
	cur := p
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(resolved, rest), nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("resolving %q: %w", p, err)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// spillJSONL writes items one JSON object per line and returns the path.
func spillJSONL[T any](dir, name string, items []T) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating out_dir: %w", err)
	}
	path := filepath.Join(dir, name+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, it := range items {
		if err := enc.Encode(it); err != nil {
			return "", fmt.Errorf("writing %s: %w", path, err)
		}
	}
	return path, nil
}

// writeManifest records what produced the files next to them. A directory of
// JSONL with no record of the query or the instance is unusable a week later.
func writeManifest(dir, name string, manifest any) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating out_dir: %w", err)
	}
	path := filepath.Join(dir, name+".manifest.json")
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}
