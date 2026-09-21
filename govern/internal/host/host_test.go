package host

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectReadsTheRunnersOwnVariables(t *testing.T) {
	cases := []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"GITHUB_ACTIONS": "true"}, GitHub},
		{map[string]string{"GITLAB_CI": "true"}, GitLab},
		{map[string]string{"JENKINS_URL": "https://ci.example/", "BUILD_NUMBER": "3"}, Jenkins},
		{map[string]string{"JENKINS_URL": "https://ci.example/"}, Generic},
		{map[string]string{"CI": "true"}, Generic},
	}
	for _, c := range cases {
		if got := Detect(func(k string) string { return c.env[k] }); got != c.want {
			t.Fatalf("%v → %s, want %s", c.env, got, c.want)
		}
	}
}

func TestDotenvWritesOneLinePerValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out", "govern.env")
	if err := (Dotenv{Path: path}).Write([]Output{{Name: "decision", Value: "ALLOW"}, {Name: "badge-markdown", Value: "line one\nline two"}}); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path)
	if string(content) != "GOVERN_DECISION=ALLOW\nGOVERN_BADGE_MARKDOWN=line one line two\n" {
		t.Fatalf("%q", content)
	}
	if err := (Dotenv{Path: path}).Write([]Output{{Name: "Bad Name", Value: "x"}}); err == nil {
		t.Fatal("an output name outside the shape was accepted")
	}
	if err := (Dotenv{}).Write([]Output{{Name: "decision", Value: "ALLOW"}}); err != nil {
		t.Fatal("no path, nothing written, no error")
	}
}

func TestFactsContextCarriesOnlyWhatIsPresent(t *testing.T) {
	context := Facts{System: GitLab, Repository: "decionis/example", SHA: "abc"}.Context()
	if context["runner"] != GitLab || context["repository"] != "decionis/example" || context["sha"] != "abc" {
		t.Fatalf("%+v", context)
	}
	if _, present := context["ref"]; present {
		t.Fatal("an unknown fact must be absent, not empty")
	}
}

func TestPlainLoggerKeepsOneLinePerMessage(t *testing.T) {
	var out bytes.Buffer
	p := Plain{Out: &out}
	p.Notice("a\nb")
	p.Warning("w")
	p.Error("e")
	p.Group("title", "body\nmore")
	if got := out.String(); !strings.HasPrefix(got, "govern: a b\ngovern: warning: w\ngovern: error: e\ngovern: title\n  body\n  more\n") {
		t.Fatalf("%q", got)
	}
}
