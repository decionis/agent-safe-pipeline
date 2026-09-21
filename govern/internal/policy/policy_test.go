package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDescribesTheFileByHash(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "DECIONIS_POLICY.md"), []byte("# Policy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := Load(DefaultPath, dir)
	if source == nil || source.Path != DefaultPath || source.Bytes != 9 || source.Truncated || source.Content != "# Policy\n" {
		t.Fatalf("%+v", source)
	}
	if len(source.SHA256) != 64 || source.SHA256 != Describe("x", []byte("# Policy\n")).SHA256 {
		t.Fatalf("sha256 %q", source.SHA256)
	}
	context := source.Context()
	if context["type"] != "decionis_policy_file" || context["content"] != "# Policy\n" {
		t.Fatalf("%+v", context)
	}
}

func TestLoadTriesTheYamlSiblingsAndNeverFails(t *testing.T) {
	dir := t.TempDir()
	if Load(DefaultPath, dir) != nil {
		t.Fatal("a missing file is no policy")
	}
	if Load("", dir) != nil {
		t.Fatal("an empty path disables the file")
	}
	if err := os.WriteFile(filepath.Join(dir, "DECIONIS_POLICY.yml"), []byte("rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if source := Load(DefaultPath, dir); source == nil || source.Path != "DECIONIS_POLICY.yml" {
		t.Fatalf("%+v", source)
	}
	if Load("other/POLICY.md", dir) != nil {
		t.Fatal("an explicit path tries no sibling")
	}
}

func TestLargeFilesAreReferencedByHashOnly(t *testing.T) {
	source := Describe("big.md", []byte(strings.Repeat("x", InlineLimit+1)))
	if !source.Truncated || source.Content != "" {
		t.Fatalf("%+v", source)
	}
	if _, inline := source.Context()["content"]; inline {
		t.Fatal("content over the limit must not travel")
	}
}
