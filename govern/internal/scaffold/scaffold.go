// Package scaffold writes the starter files a repository needs to run its
// first governed step: a shadow-mode workflow for the runner the repository
// uses and a policy file at its root. It writes files and nothing else: no
// git, no network, no existing file overwritten unless asked, and it says
// what it wrote and what is left to a person (the key, the tenant, the
// commit).
package scaffold

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed templates/*
var templates embed.FS

// Hosts this scaffold knows a file layout for.
const (
	GitHub  = "github"
	GitLab  = "gitlab"
	Jenkins = "jenkins"
)

// PolicyFile is the policy file's conventional name at the repository root.
const PolicyFile = "DECIONIS_POLICY.md"

var (
	actionPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,119}$`)
	branchPattern = regexp.MustCompile(`^[\w./-]{1,200}$`)
)

// Options select what is written and how.
type Options struct {
	// Dir is the repository root; the current directory when empty.
	Dir string
	// Host is github, gitlab or jenkins; detected from the tree when empty.
	Host string
	// Mode is shadow (default) or enforce.
	Mode string
	// Action is the action type the starter step names.
	Action string
	// Branch is the default branch a GitHub workflow's push trigger names.
	Branch string
	// Version is the govern version the GitLab and Jenkins starters install.
	Version string
	// Policy is whether the policy file is written.
	Policy bool
	// Force overwrites files that exist.
	Force bool
	// DryRun prints what would be written and writes nothing.
	DryRun bool
}

// File is one file the scaffold wrote, or would write.
type File struct {
	Path    string
	Content string
	// Existed is true when a file was already there (overwritten with Force, kept otherwise).
	Existed bool
	Written bool
}

// Result is what happened and what is left to do.
type Result struct {
	Host  string
	Files []File
	Next  []string
}

// Detect names the runner a tree is set up for: GitHub when it has
// .github/workflows, GitLab when it has .gitlab-ci.yml, Jenkins when it has a
// Jenkinsfile, GitHub otherwise.
func Detect(dir string) string {
	exists := func(rel string) bool {
		_, err := os.Stat(filepath.Join(dir, rel))
		return err == nil
	}
	switch {
	case exists(filepath.Join(".github", "workflows")):
		return GitHub
	case exists(".gitlab-ci.yml"):
		return GitLab
	case exists("Jenkinsfile"):
		return Jenkins
	}
	return GitHub
}

// Run writes the starter files and returns what it did.
func Run(options Options, out io.Writer) (Result, error) {
	dir := options.Dir
	if dir == "" {
		dir = "."
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return Result{}, fmt.Errorf("DIRECTORY_INVALID: %s is not a directory", dir)
	}
	host := strings.ToLower(options.Host)
	if host == "" {
		host = Detect(dir)
	}
	if host != GitHub && host != GitLab && host != Jenkins {
		return Result{}, errors.New("HOST_INVALID: --host must be github, gitlab or jenkins")
	}
	mode := strings.ToLower(options.Mode)
	if mode == "" {
		mode = "shadow"
	}
	if mode != "shadow" && mode != "enforce" {
		return Result{}, errors.New("MODE_INVALID: --mode must be shadow or enforce")
	}
	action := options.Action
	if action == "" {
		action = "workflow.step"
	}
	if !actionPattern.MatchString(action) {
		return Result{}, fmt.Errorf("ACTION_INVALID: %q is not a lowercase action name ([a-z][a-z0-9._:-]*)", action)
	}
	branch := options.Branch
	if branch == "" {
		branch = defaultBranch(dir)
	}
	if !branchPattern.MatchString(branch) {
		return Result{}, fmt.Errorf("BRANCH_INVALID: %q", branch)
	}
	version := options.Version
	if version == "" {
		return Result{}, errors.New("VERSION_MISSING")
	}

	var files []File
	values := map[string]string{"MODE": mode, "ACTION": action, "BRANCH": branch, "VERSION": version}
	switch host {
	case GitHub:
		files = append(files, File{Path: filepath.Join(".github", "workflows", "decionis-govern.yml"), Content: render("templates/github.yml", values)})
	case GitLab:
		path := filepath.Join(".gitlab", "ci", "decionis-govern.yml")
		values["PATH"] = filepath.ToSlash(path)
		files = append(files, File{Path: path, Content: render("templates/gitlab.yml", values)})
	case Jenkins:
		files = append(files, File{Path: filepath.Join("jenkins", "decionis-govern.groovy"), Content: render("templates/jenkins.groovy", values)})
	}
	if options.Policy {
		files = append(files, File{Path: PolicyFile, Content: render("templates/DECIONIS_POLICY.md", values)})
	}

	for i := range files {
		full := filepath.Join(dir, files[i].Path)
		if _, err := os.Stat(full); err == nil {
			files[i].Existed = true
			if !options.Force {
				fmt.Fprintf(out, "govern init: %s exists; kept (pass --force to overwrite)\n", files[i].Path)
				continue
			}
		}
		if options.DryRun {
			fmt.Fprintf(out, "govern init: would write %s (%d bytes)\n", files[i].Path, len(files[i].Content))
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return Result{}, err
		}
		if err := os.WriteFile(full, []byte(files[i].Content), 0o644); err != nil {
			return Result{}, err
		}
		files[i].Written = true
		fmt.Fprintf(out, "govern init: wrote %s\n", files[i].Path)
	}

	next := nextSteps(host, files, mode)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Next:")
	for i, step := range next {
		fmt.Fprintf(out, "  %d. %s\n", i+1, step)
	}
	return Result{Host: host, Files: files, Next: next}, nil
}

func nextSteps(host string, files []File, mode string) []string {
	var steps []string
	switch host {
	case GitHub:
		steps = append(steps,
			"Add the secret DECIONIS_API_KEY and the variable DECIONIS_TENANT_ID to the repository (https://decionis.com/quickstart).",
			"Commit the files and open a pull request; the workflow runs on it and comments the verdict.",
		)
	case GitLab:
		for _, file := range files {
			if strings.HasSuffix(file.Path, "decionis-govern.yml") {
				steps = append(steps, fmt.Sprintf("Include the job from .gitlab-ci.yml: `include: [{ local: %s }]`.", filepath.ToSlash(file.Path)))
			}
		}
		steps = append(steps,
			"Add DECIONIS_API_KEY (masked) and DECIONIS_TENANT_ID to the project's CI variables (https://decionis.com/quickstart).",
			"Commit the files and open a merge request; the job runs on it.",
		)
	case Jenkins:
		steps = append(steps,
			"Paste the stage into the Jenkinsfile's `stages` and set DECIONIS_TENANT_ID to the workspace's id.",
			"Add the secret-text credential decionis-api-key (https://decionis.com/quickstart).",
			"Commit the files; the stage runs on the next build.",
		)
	}
	if mode == "shadow" {
		steps = append(steps, "Watch the verdicts, then set the mode to enforce and give the step the command it gates.")
	} else {
		steps = append(steps, "The step enforces from its first run: give it the command it gates, and start in shadow if that is too soon.")
	}
	return steps
}

// defaultBranch reads the branch the tree's origin points at, or the one
// checked out, and falls back to main.
func defaultBranch(dir string) string {
	if ref, err := os.ReadFile(filepath.Join(dir, ".git", "refs", "remotes", "origin", "HEAD")); err == nil {
		if name := strings.TrimPrefix(strings.TrimSpace(string(ref)), "ref: refs/remotes/origin/"); name != "" && !strings.Contains(name, " ") {
			return name
		}
	}
	if head, err := os.ReadFile(filepath.Join(dir, ".git", "HEAD")); err == nil {
		if name := strings.TrimPrefix(strings.TrimSpace(string(head)), "ref: refs/heads/"); name != "" && !strings.Contains(name, " ") && !strings.HasPrefix(name, "ref:") {
			return name
		}
	}
	return "main"
}

func render(name string, values map[string]string) string {
	content, err := templates.ReadFile(name)
	if err != nil {
		panic(err) // an embedded file that is not there is a build error, not a runtime one
	}
	text := string(content)
	for key, value := range values {
		text = strings.ReplaceAll(text, "{{"+key+"}}", value)
	}
	return text
}
