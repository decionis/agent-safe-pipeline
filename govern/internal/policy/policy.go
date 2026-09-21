// Package policy reads the repository's policy file and describes it for the
// intent: its path, its size and the SHA-256 of its bytes, which is the
// revision handle the Decision Dossier records. Nothing here evaluates the
// file: only Decionis decides, and this description is what binds the
// decision to the exact policy revision the repository carried.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// DefaultPath is the conventional file; its YAML siblings are tried after it.
const DefaultPath = "DECIONIS_POLICY.md"

// InlineLimit bounds what travels in the intent's context: a larger file is
// referenced by hash alone, never silently dropped.
const InlineLimit = 16 * 1024

// Source describes one policy file as the intent's context carries it.
type Source struct {
	Path      string
	SHA256    string
	Bytes     int
	Truncated bool
	// Content is the text when it fits the inline limit.
	Content string
}

// Context is the description under the reserved key `decionis_policy`.
func (s Source) Context() map[string]any {
	out := map[string]any{
		"type":      "decionis_policy_file",
		"path":      s.Path,
		"sha256":    s.SHA256,
		"bytes":     s.Bytes,
		"truncated": s.Truncated,
	}
	if !s.Truncated {
		out["content"] = s.Content
	}
	return out
}

// Load reads the policy file named, relative to the workspace root unless
// absolute. The default path also tries `DECIONIS_POLICY.yaml` and `.yml`.
// A missing or unreadable file is no policy, never an error: the gate must
// not fail because a repository has not written one.
func Load(path, workspace string) *Source {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil
	}
	candidates := []string{trimmed}
	if trimmed == DefaultPath {
		candidates = append(candidates, "DECIONIS_POLICY.yaml", "DECIONIS_POLICY.yml")
	}
	for _, candidate := range candidates {
		full := candidate
		if !filepath.IsAbs(full) {
			full = filepath.Join(workspace, candidate)
		}
		content, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		return Describe(candidate, content)
	}
	return nil
}

// Describe is the description of content found at a path.
func Describe(path string, content []byte) *Source {
	sum := sha256.Sum256(content)
	source := &Source{Path: path, SHA256: hex.EncodeToString(sum[:]), Bytes: len(content), Truncated: len(content) > InlineLimit}
	if !source.Truncated {
		source.Content = string(content)
	}
	return source
}
