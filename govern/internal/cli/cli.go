// Package cli is the command line: `govern run` gates one command or one
// verdict, `govern version` prints the version. Settings come from flags, or
// from GOVERN_* and the DECIONIS_* variables the runtime uses, flags winning;
// the API key comes only from DECIONIS_API_KEY or DECIONIS_API_KEY_FILE, never
// from a flag a process listing could show.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/decionis/agent-safe-pipeline/govern/internal/authority"
	"github.com/decionis/agent-safe-pipeline/govern/internal/gate"
	"github.com/decionis/agent-safe-pipeline/govern/internal/host"
	"github.com/decionis/agent-safe-pipeline/govern/internal/host/generic"
	"github.com/decionis/agent-safe-pipeline/govern/internal/host/github"
	"github.com/decionis/agent-safe-pipeline/govern/internal/host/gitlab"
	"github.com/decionis/agent-safe-pipeline/govern/internal/host/jenkins"
)

// Exit codes the command itself uses; a gated command's own code passes through.
const (
	ExitOK    = 0
	ExitUsage = 2
)

// DefaultAPIURL is the hosted authority.
const DefaultAPIURL = "https://api.decionis.com"

// DefaultAction names a step that gave no action type.
const DefaultAction = "workflow.step"

// Process is what the command needs from the process it runs in.
type Process struct {
	Args    []string
	Env     host.Environment
	Stdout  io.Writer
	Stderr  io.Writer
	Version string
	// HTTPClient, when set, is used for the authority and the hosts (tests).
	HTTPClient *http.Client
	Now        func() time.Time
}

var uaToken = regexp.MustCompile(`^[\w.\-/@]{1,120}$`)

// Main runs the command line and returns the exit code.
func Main(ctx context.Context, p Process) int {
	if p.Stdout == nil {
		p.Stdout = os.Stdout
	}
	if p.Stderr == nil {
		p.Stderr = os.Stderr
	}
	if p.Env == nil {
		p.Env = os.Getenv
	}
	if len(p.Args) == 0 {
		fmt.Fprint(p.Stderr, usage)
		return ExitUsage
	}
	switch p.Args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(p.Stdout, "govern %s\n", p.Version)
		return ExitOK
	case "help", "--help", "-h":
		fmt.Fprint(p.Stdout, usage)
		return ExitOK
	case "run":
		return runCommand(ctx, p, p.Args[1:])
	}
	fmt.Fprintf(p.Stderr, "govern: unknown command %q\n\n%s", p.Args[0], usage)
	return ExitUsage
}

const usage = `govern — one verdict before a workflow step runs, with a signed record of it.

Usage:
  govern run [flags] [-- command [args...]]
  govern version

The gated command runs only on an ALLOW whose grant this process claimed
(enforcement), or runs at once while the verdict is recorded beside it
(shadow). Without a command, the step's exit code follows --fail-on.

Flags (each also reads a variable; flags win):
  --mode shadow|enforce         GOVERN_MODE            default enforce
  --action <type>               GOVERN_ACTION          the action's type, e.g. production-deploy
  --resource <text>             GOVERN_RESOURCE        what it acts on; default: the command
  --payload <json|@file>        GOVERN_PAYLOAD         the action's parameters, a JSON object
  --environment <name>          GOVERN_ENVIRONMENT     the deployment environment
  --run <line>                  GOVERN_RUN             the command as one shell line (or use --)
  --shell bash|sh               GOVERN_SHELL           default bash
  --fail-on block|escalate|block_or_escalate|never
                                GOVERN_FAIL_ON         verdict-only steps; default block
  --escalation none|managed     GOVERN_ESCALATION      hold an ESCALATE for Decionis' approval flow
  --approver <principal>        GOVERN_APPROVER        who approves a managed escalation
  --approver-role <ROLE>        GOVERN_APPROVER_ROLE   or which role does
  --policy-file <path>          GOVERN_POLICY_FILE     default DECIONIS_POLICY.md; "" disables
  --workspace <dir>             GOVERN_WORKSPACE       default: the runner's checkout, else .
  --comment                     GOVERN_COMMENT=true    post the verdict on the change request
  --no-attribution              GOVERN_ATTRIBUTION=false
  --report <path|->             GOVERN_REPORT          write the JSON record
  --host github|gitlab|jenkins|generic
                                GOVERN_HOST            default: detected
  --tenant <uuid>               DECIONIS_TENANT_ID     the workspace the key belongs to
  --api-url <url>               DECIONIS_API_URL       default https://api.decionis.com
  --timeout <duration>          GOVERN_TIMEOUT         per authority call; default 20s
  --intent-ttl <duration>       GOVERN_INTENT_TTL      how long the intent stays decidable; max 5m
  --actor-id / --actor-type     GOVERN_ACTOR_ID / GOVERN_ACTOR_TYPE
  --allow-insecure-loopback     DECIONIS_ALLOW_INSECURE_LOOPBACK=true (tests only)

The key is read from DECIONIS_API_KEY or the file DECIONIS_API_KEY_FILE names.
`

type stringFlag struct {
	value string
	set   bool
}

func (s *stringFlag) String() string     { return s.value }
func (s *stringFlag) Set(v string) error { s.value, s.set = v, true; return nil }

type boolFlag struct {
	value bool
	set   bool
}

func (b *boolFlag) String() string { return strconv.FormatBool(b.value) }
func (b *boolFlag) Set(v string) error {
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return err
	}
	b.value, b.set = parsed, true
	return nil
}
func (b *boolFlag) IsBoolFlag() bool { return true }

type settings struct {
	flags map[string]*stringFlag
	bools map[string]*boolFlag
	env   host.Environment
}

// value is the flag when given, else the first variable that is set.
func (s settings) value(name string, variables ...string) string {
	if f, ok := s.flags[name]; ok && f.set {
		return f.value
	}
	for _, variable := range variables {
		if v := s.env(variable); v != "" {
			return v
		}
	}
	return ""
}

func (s settings) boolean(name string, fallback bool, variables ...string) (bool, error) {
	if b, ok := s.bools[name]; ok && b.set {
		return b.value, nil
	}
	for _, variable := range variables {
		if v := strings.TrimSpace(strings.ToLower(s.env(variable))); v != "" {
			switch v {
			case "true", "1", "yes", "on":
				return true, nil
			case "false", "0", "no", "off":
				return false, nil
			}
			return false, fmt.Errorf("%s must be true or false, not %q", variable, v)
		}
	}
	return fallback, nil
}

func runCommand(ctx context.Context, p Process, args []string) int {
	fs := flag.NewFlagSet("govern run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	s := settings{flags: map[string]*stringFlag{}, bools: map[string]*boolFlag{}, env: p.Env}
	for _, name := range []string{"mode", "action", "resource", "payload", "environment", "run", "shell", "fail-on", "escalation", "approver", "approver-role", "policy-file", "workspace", "report", "host", "tenant", "api-url", "timeout", "intent-ttl", "actor-id", "actor-type"} {
		f := &stringFlag{}
		s.flags[name] = f
		fs.Var(f, name, "")
	}
	for _, name := range []string{"comment", "no-attribution", "allow-insecure-loopback"} {
		b := &boolFlag{}
		s.bools[name] = b
		fs.Var(b, name, "")
	}
	if err := fs.Parse(args); err != nil {
		return usageError(p, err.Error())
	}
	cfg, hostName, err := configure(s, fs.Args(), p)
	if err != nil {
		return usageError(p, err.Error())
	}
	h := selectHost(hostName, p)
	apiKey, err := readKey(p.Env)
	if err != nil {
		return usageError(p, err.Error())
	}
	cfg.Credentials = apiKey != "" && cfg.TenantID != ""
	if apiKey != "" && cfg.TenantID == "" {
		return usageError(p, "DECIONIS_TENANT_ID (or --tenant) names the workspace the key belongs to; it is required beside the key")
	}
	if cfg.Mode == authority.Enforcement && !cfg.Credentials {
		h.Error("Decionis enforcement needs DECIONIS_API_KEY and DECIONIS_TENANT_ID; shadow runs without them and records nothing.")
		return 1
	}
	deps := gate.Dependencies{Host: h, Version: p.Version, Stdout: p.Stdout, Stderr: p.Stderr, Now: p.Now}
	if cfg.Credentials {
		allowLoopback, err := s.boolean("allow-insecure-loopback", false, "DECIONIS_ALLOW_INSECURE_LOOPBACK")
		if err != nil {
			return usageError(p, err.Error())
		}
		apiURL := s.value("api-url", "DECIONIS_API_URL", "GOVERN_API_URL")
		if apiURL == "" {
			apiURL = DefaultAPIURL
		}
		client, err := authority.New(authority.Options{
			BaseURL:               apiURL,
			APIKey:                func() string { return apiKey },
			Timeout:               cfg.Timeout,
			UserAgent:             userAgent(p.Version, h),
			AllowInsecureLoopback: allowLoopback,
			HTTPClient:            p.HTTPClient,
			Now:                   p.Now,
		})
		if err != nil {
			return usageError(p, err.Error())
		}
		deps.Authority = client
	}
	return gate.Run(ctx, cfg, deps).Exit
}

func usageError(p Process, message string) int {
	fmt.Fprintf(p.Stderr, "govern: %s\n", message)
	return ExitUsage
}

// userAgent is what every hosted call carries: the product and version, where
// it runs, and the repository when the runner names one the header can carry.
func userAgent(version string, h host.Host) string {
	comment := []string{"example=govern@" + version, "surface=" + h.Name()}
	if repo := h.Facts().Repository; uaToken.MatchString(repo) {
		comment = append(comment, "repo="+repo)
	}
	return "govern/" + version + " (" + strings.Join(comment, "; ") + ")"
}

func selectHost(name string, p Process) host.Host {
	switch name {
	case host.GitHub, "github":
		return github.New(p.Env, p.Stdout, p.HTTPClient)
	case host.GitLab, "gitlab":
		return gitlab.New(p.Env, p.Stdout, p.HTTPClient)
	case host.Jenkins:
		return jenkins.New(p.Env, p.Stdout)
	}
	return generic.New(p.Env, p.Stdout)
}

func configure(s settings, rest []string, p Process) (gate.Config, string, error) {
	cfg := gate.Config{Attribution: true, Shell: "bash", FailOn: gate.FailOnBlock, IntentTTL: 5 * time.Minute, Timeout: 20 * time.Second}
	switch strings.ToLower(s.value("mode", "GOVERN_MODE", "DECIONIS_MODE")) {
	case "", "enforce", "enforcement":
		cfg.Mode = authority.Enforcement
	case "shadow":
		cfg.Mode = authority.Shadow
	default:
		return cfg, "", errors.New("--mode must be shadow or enforce")
	}
	cfg.ActionType = strings.TrimSpace(s.value("action", "GOVERN_ACTION"))
	if cfg.ActionType == "" {
		cfg.ActionType = DefaultAction
	}
	cfg.Resource = strings.TrimSpace(s.value("resource", "GOVERN_RESOURCE"))
	payload, err := parsePayload(s.value("payload", "GOVERN_PAYLOAD"))
	if err != nil {
		return cfg, "", err
	}
	cfg.Parameters = payload
	cfg.Environment = strings.TrimSpace(s.value("environment", "GOVERN_ENVIRONMENT"))
	line := s.value("run", "GOVERN_RUN")
	if len(rest) > 0 {
		if line != "" {
			return cfg, "", errors.New("give the command either as --run or after --, not both")
		}
		line = shellJoin(rest)
	}
	cfg.Command = strings.TrimSpace(line)
	switch shell := strings.ToLower(s.value("shell", "GOVERN_SHELL")); shell {
	case "", "bash":
		cfg.Shell = "bash"
	case "sh":
		cfg.Shell = "sh"
	default:
		return cfg, "", errors.New("--shell must be bash or sh")
	}
	switch failOn := gate.FailOn(strings.ToLower(s.value("fail-on", "GOVERN_FAIL_ON"))); failOn {
	case "":
	case gate.FailOnBlock, gate.FailOnEscalate, gate.FailOnBlockOrEscalate, gate.FailOnNever:
		cfg.FailOn = failOn
	default:
		return cfg, "", errors.New("--fail-on must be block, escalate, block_or_escalate or never")
	}
	approver := strings.TrimSpace(s.value("approver", "GOVERN_APPROVER"))
	role := strings.TrimSpace(s.value("approver-role", "GOVERN_APPROVER_ROLE"))
	switch escalation := strings.ToLower(s.value("escalation", "GOVERN_ESCALATION")); escalation {
	case "", "none":
		if approver != "" || role != "" {
			cfg.Managed = &authority.ManagedRequest{ApproverPrincipalID: approver, ApproverRoleID: role}
		}
	case "managed":
		cfg.Managed = &authority.ManagedRequest{ApproverPrincipalID: approver, ApproverRoleID: role}
	default:
		return cfg, "", errors.New("--escalation must be none or managed")
	}
	if cfg.Managed != nil && cfg.Mode == authority.Shadow {
		return cfg, "", errors.New("a managed escalation needs --mode enforce; shadow never holds a step")
	}
	if f, ok := s.flags["policy-file"]; ok && f.set {
		cfg.PolicyPath = f.value
	} else if v, set := lookup(s.env, "GOVERN_POLICY_FILE"); set {
		cfg.PolicyPath = v
	} else {
		cfg.PolicyPath = "DECIONIS_POLICY.md"
	}
	cfg.Workspace = s.value("workspace", "GOVERN_WORKSPACE", "GITHUB_WORKSPACE", "CI_PROJECT_DIR", "WORKSPACE")
	if cfg.Workspace == "" {
		cfg.Workspace = "."
	}
	comment, err := s.boolean("comment", false, "GOVERN_COMMENT")
	if err != nil {
		return cfg, "", err
	}
	cfg.Comment = comment
	if b, ok := s.bools["no-attribution"]; ok && b.set {
		cfg.Attribution = !b.value
	} else {
		attribution, err := s.boolean("no-attribution", true, "GOVERN_ATTRIBUTION")
		if err != nil {
			return cfg, "", err
		}
		cfg.Attribution = attribution
	}
	cfg.ReportPath = s.value("report", "GOVERN_REPORT")
	cfg.TenantID = strings.TrimSpace(s.value("tenant", "DECIONIS_TENANT_ID", "DECIONIS_ORG_ID", "GOVERN_TENANT"))
	if timeout := s.value("timeout", "GOVERN_TIMEOUT"); timeout != "" {
		d, err := parseDuration(timeout)
		if err != nil || d <= 0 {
			return cfg, "", errors.New("--timeout must be a duration such as 20s")
		}
		cfg.Timeout = d
	} else if ms := s.env("DECIONIS_TIMEOUT_MS"); ms != "" {
		n, err := strconv.Atoi(ms)
		if err != nil || n <= 0 {
			return cfg, "", errors.New("DECIONIS_TIMEOUT_MS must be a positive number of milliseconds")
		}
		cfg.Timeout = time.Duration(n) * time.Millisecond
	}
	if ttl := s.value("intent-ttl", "GOVERN_INTENT_TTL"); ttl != "" {
		d, err := parseDuration(ttl)
		if err != nil || d <= 0 {
			return cfg, "", errors.New("--intent-ttl must be a duration such as 5m")
		}
		cfg.IntentTTL = d
	}
	cfg.ActorID = strings.TrimSpace(s.value("actor-id", "GOVERN_ACTOR_ID"))
	cfg.ActorType = strings.TrimSpace(s.value("actor-type", "GOVERN_ACTOR_TYPE"))
	hostName := strings.ToLower(s.value("host", "GOVERN_HOST"))
	switch hostName {
	case "":
		hostName = host.Detect(p.Env)
	case host.GitHub, "github", host.GitLab, "gitlab", host.Jenkins, host.Generic, "generic":
	default:
		return cfg, "", errors.New("--host must be github, gitlab, jenkins or generic")
	}
	return cfg, hostName, nil
}

func lookup(env host.Environment, key string) (string, bool) {
	// An environment that distinguishes empty from unset is not available
	// through the lookup function, so the OS is asked when it is the source.
	if value, ok := os.LookupEnv(key); ok && env(key) == value {
		return value, true
	}
	value := env(key)
	return value, value != ""
}

func parsePayload(raw string) (map[string]any, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return map[string]any{}, nil
	}
	if strings.HasPrefix(trimmed, "@") {
		content, err := os.ReadFile(strings.TrimPrefix(trimmed, "@"))
		if err != nil {
			return nil, fmt.Errorf("--payload: %w", err)
		}
		trimmed = string(content)
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(trimmed)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("--payload must be a JSON object")
	}
	object, ok := value.(map[string]any)
	if !ok || decoder.More() {
		return nil, errors.New("--payload must be a JSON object")
	}
	return object, nil
}

func parseDuration(value string) (time.Duration, error) {
	if n, err := strconv.Atoi(value); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(value)
}

// shellJoin turns argv into one shell line, quoting what needs it, so that
// `govern run -- ./deploy.sh --env "prod us"` runs as typed.
func shellJoin(args []string) string {
	parts := make([]string, len(args))
	for i, arg := range args {
		parts[i] = shellQuote(arg)
	}
	return strings.Join(parts, " ")
}

var plainWord = regexp.MustCompile(`^[\w./:=@%+,-]+$`)

func shellQuote(arg string) string {
	if arg != "" && plainWord.MatchString(arg) {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

// readKey reads the credential from the environment or the file it names.
func readKey(env host.Environment) (string, error) {
	if key := strings.TrimSpace(env("DECIONIS_API_KEY")); key != "" {
		return key, nil
	}
	if path := env("DECIONIS_API_KEY_FILE"); path != "" {
		content, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("DECIONIS_API_KEY_FILE: %w", err)
		}
		key := strings.TrimSpace(string(content))
		if key == "" {
			return "", errors.New("DECIONIS_API_KEY_FILE names an empty file")
		}
		return key, nil
	}
	return "", nil
}
