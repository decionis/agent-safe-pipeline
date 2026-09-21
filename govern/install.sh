#!/usr/bin/env sh
# Decionis Govern installer — canonical source for https://decionis.com/govern/install.sh
#
#   curl -fsSL https://decionis.com/govern/install.sh | sh
#   curl -fsSL https://decionis.com/govern/install.sh | sh -s -- --pr
#   curl -fsSL https://decionis.com/govern/install.sh | sh -s -- --pr --inject
#
# Writes a shadow-mode governance workflow and a starter DECIONIS_POLICY.md,
# optionally injects an observe-only gate step into existing workflows
# (--inject), and optionally opens the onboarding pull request (--pr).
# POSIX sh — runs under dash, macOS bash 3.2, and busybox sh. No secrets are
# read, stored, or transmitted; the api-key is always a GitHub secrets ref.
set -eu

INSTALLER_VERSION="1.9.0"
BRANCH_NAME="feature/add-decionis-governance"
MARKER="# decionis-govern (auto)"
WORKFLOW_FILE=".github/workflows/decionis-govern.yml"
POLICY_FILE="DECIONIS_POLICY.md"

MODE="shadow"
WORKFLOW_KEY="github_pr_change_intent"
ORG_ID_REF='${{ secrets.DECIONIS_ORG_ID }}'
DO_INJECT=0
DO_PR=0
DRY_RUN=0
FORCE=0
CREATED=""
MODIFIED=""

usage() {
  cat <<'EOF'
Decionis Govern installer

Usage: install.sh [options]
  (no flags)            Write .github/workflows/decionis-govern.yml and a
                        starter DECIONIS_POLICY.md (each skipped if present).
  --inject              Also insert an observe-only Decionis shadow step as the
                        first step of every job in existing workflow files.
                        Insert-only and conservative: files/jobs it cannot edit
                        safely are skipped with a reason.
  --pr                  Create branch feature/add-decionis-governance, commit
                        the generated files, push, and open the PR (gh CLI if
                        available, otherwise prints the compare URL).
  --dry-run             Show every file and diff that would be written; write
                        nothing and run no git commands.
  --force               Proceed despite a dirty worktree or detached HEAD; with
                        --pr, use a timestamp-suffixed branch if the branch
                        already exists.
  --mode <m>            shadow (default) or enforce — mode for the generated
                        workflow. Injected steps are always shadow.
  --org-id <id>         Inline a literal Decionis org id instead of
                        ${{ secrets.DECIONIS_ORG_ID }} (org ids are not secret).
  --workflow-key <key>  Workflow key for generated and injected steps
                        (default: github_pr_change_intent).
  -h, --help            This help.

Exit codes: 0 ok/nothing-to-do · 2 not a git work tree · 3 detached HEAD
(--pr) · 4 dirty worktree (--pr) · 5 --pr without an origin remote · 64 bad flag
EOF
}

fail() {
  code=$1
  shift
  echo "install.sh: $*" >&2
  exit "$code"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --inject) DO_INJECT=1 ;;
    --pr) DO_PR=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --force) FORCE=1 ;;
    --mode)
      shift
      [ $# -gt 0 ] || fail 64 "--mode needs a value (shadow|enforce)"
      case "$1" in
        shadow | enforce) MODE=$1 ;;
        *) fail 64 "--mode must be 'shadow' or 'enforce' (got '$1')" ;;
      esac
      ;;
    --org-id)
      shift
      [ $# -gt 0 ] || fail 64 "--org-id needs a value"
      ORG_ID_REF=$1
      ;;
    --workflow-key)
      shift
      [ $# -gt 0 ] || fail 64 "--workflow-key needs a value"
      WORKFLOW_KEY=$1
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail 64 "unknown flag: $1"
      ;;
  esac
  shift
done

git rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
  fail 2 "not inside a git work tree — run this from your repository root"
cd "$(git rev-parse --show-toplevel)"

# Git-state gates apply only to --pr (which branches, commits, and pushes);
# plain runs merely add new files and are safe in any worktree state.
if [ "$DO_PR" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then
  if ! git symbolic-ref -q HEAD >/dev/null 2>&1; then
    [ "$FORCE" -eq 1 ] || fail 3 "detached HEAD — check out a branch or pass --force"
  fi
  if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    [ "$FORCE" -eq 1 ] || fail 4 "working tree is dirty — commit/stash first or pass --force"
  fi
fi

# ── Artifact generation ──────────────────────────────────────────────────────

# write_artifact <path> — content on stdin; skips existing files, honors --dry-run.
write_artifact() {
  wa_path=$1
  if [ -e "$wa_path" ]; then
    cat >/dev/null
    echo "skip:    $wa_path already exists"
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "would create: $wa_path"
    sed 's/^/  | /'
    return 0
  fi
  mkdir -p "$(dirname "$wa_path")"
  cat >"$wa_path"
  CREATED="$CREATED $wa_path"
  echo "created: $wa_path"
}

write_workflow() {
  write_artifact "$WORKFLOW_FILE" <<EOF
# decionis-govern (managed by install.sh) — safe to edit; delete to remove.
# Docs: https://github.com/decionis/govern
name: Decionis Governance ($MODE)

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  decionis-verdict:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Decionis verdict ($MODE)
        uses: decionis/govern@v1
        with:
          api-key: \${{ secrets.DECIONIS_API_KEY }}
          org-id: $ORG_ID_REF
          workflow-key: $WORKFLOW_KEY
          mode: $MODE
          comment-pr: "true"
EOF
}

write_policy() {
  write_artifact "$POLICY_FILE" <<'EOF'
# Decionis Policy

<!--
  DECIONIS_POLICY.md — your repo's governance policy, in plain Markdown.

  The Decionis Action reads this file, content-hashes it, evaluates the
  ```decionis rules block locally in microseconds, and records the revision on
  every signed Decision Dossier. Prose is documentation for humans; the rules
  block below is what evaluates. Change the file → new sha256 → new recorded
  policy revision.

  Rule tips:
  - Give every rule an explicit "priority" (higher evaluates first) and keep
    "domain": "*" so the rule applies to every decision this repo gates.
  - Fields match the decision payload you pass to the action: `context.<key>`
    reads payload keys; `decision_type` derives from the action label.
  - Verdicts: allow / block / restrain / escalate.
-->

## Scope

Applies to deploys, infrastructure changes, and AI-authored changes gated
through `decionis/govern` in this repository. Start in `mode: shadow`, review
the verdicts on your PRs, then switch to `enforce`.

## Rules

- **Block** deploys during a change freeze.
- **Escalate** anything that destroys infrastructure or touches secrets.
- **Restrain** (require human review) AI-authored changes to deploy paths.

## Enforced rules

```decionis
{
  "version": 1,
  "rules": [
    {
      "name": "Block deploys during a change freeze",
      "priority": 100,
      "domain": "*",
      "all": [{ "field": "context.change_freeze", "op": "eq", "value": true }],
      "action": "block"
    },
    {
      "name": "Escalate destructive or secret-touching changes",
      "priority": 90,
      "domain": "*",
      "any": [
        { "field": "context.destroys_resources", "op": "eq", "value": true },
        { "field": "context.touches_secrets", "op": "eq", "value": true }
      ],
      "action": "escalate"
    },
    {
      "name": "Restrain AI-authored deploy changes",
      "priority": 80,
      "domain": "*",
      "all": [{ "field": "context.agent_generated", "op": "eq", "value": true }],
      "action": "restrain"
    }
  ]
}
```
EOF
}

# ── Workflow injection (--inject) ────────────────────────────────────────────
# Single awk pass per file, insert-only: the shadow step is inserted as the
# FIRST step of each job (observe-only, no checkout dependency), re-indented to
# match the job's existing step items, with continue-on-error so it can never
# break the host job. Anything the parser is unsure about is skipped loudly.

inject_one() {
  in_file=$1
  if grep -q 'decionis/govern' "$in_file"; then
    echo "skip:    $in_file (already uses decionis/govern)"
    return 0
  fi
  if grep -q "$(printf '\t')" "$in_file"; then
    echo "skip:    $in_file (contains tabs — add the step manually)"
    return 0
  fi
  if ! grep -q '^jobs:' "$in_file"; then
    echo "skip:    $in_file (no top-level 'jobs:' key)"
    return 0
  fi

  in_tmp="$in_file.decionis-tmp"
  in_err="$in_file.decionis-err"
  awk -v org_ref="$ORG_ID_REF" -v wk="$WORKFLOW_KEY" -v marker="$MARKER" '
    function indent_of(line,  n) {
      n = 0
      while (substr(line, n + 1, 1) == " ") n++
      return n
    }
    function pad(n,  s, i) {
      s = ""
      for (i = 0; i < n; i++) s = s " "
      return s
    }
    function emit_step(n,  p) {
      p = pad(n)
      print p "- name: Decionis shadow verdict " marker
      print p "  uses: decionis/govern@v1"
      print p "  continue-on-error: true"
      print p "  with:"
      print p "    api-key: ${{ secrets.DECIONIS_API_KEY }}"
      print p "    org-id: " org_ref
      print p "    workflow-key: " wk
      print p "    mode: shadow"
    }
    BEGIN { in_jobs = 0; job_indent = -1; child_indent = -1; state = ""; steps_indent = -1 }
    {
      line = $0
      if (!in_jobs) {
        print line
        if (line ~ /^jobs:[ \t]*$/) in_jobs = 1
        next
      }
      if (line ~ /^[^ \t]/) { in_jobs = 0; print line; next } # jobs section over
      ind = indent_of(line)
      blank = (line ~ /^[ \t]*$/)
      comment = (line ~ /^[ ]*#/)

      if (!blank && !comment) {
        if (job_indent < 0 && line ~ /^[ ]+[^ ]/) job_indent = ind
        if (ind == job_indent && line ~ /^[ ]+[A-Za-z0-9_."'"'"'-]+:[ \t]*$/) {
          state = "in_job"; child_indent = -1; steps_indent = -1
        } else if (state != "" && child_indent < 0 && ind > job_indent) {
          child_indent = ind
        }
      }

      if (state == "in_job" && !blank && !comment && ind == child_indent) {
        if (line ~ /^[ ]+uses:/) {
          print "note: reusable-workflow job skipped" > "/dev/stderr"
          state = "skip_job"
        } else if (line ~ /^[ ]+steps:[ \t]*$/) {
          state = "await_item"; steps_indent = ind; print line; next
        } else if (line ~ /^[ ]+steps:[ \t]*[^ \t]/) {
          print "note: flow-style or anchored steps skipped" > "/dev/stderr"
          state = "skip_job"
        }
      }

      if (state == "await_item") {
        if (blank || comment) { print line; next }
        if (ind > steps_indent && line ~ /^[ ]*- /) {
          emit_step(ind)
          state = "done_job"
          print line
          next
        }
        print "note: job with empty or unrecognized steps skipped" > "/dev/stderr"
        state = "skip_job"
      }
      print line
    }
  ' "$in_file" >"$in_tmp" 2>"$in_err" || {
    rm -f "$in_tmp" "$in_err"
    echo "skip:    $in_file (could not parse)"
    return 0
  }

  while IFS= read -r note; do
    [ -n "$note" ] && echo "         $in_file: $note"
  done <"$in_err"
  rm -f "$in_err"

  added=$(grep -c "decionis-govern (auto)" "$in_tmp" || true)
  if [ "$added" -eq 0 ] || cmp -s "$in_file" "$in_tmp"; then
    rm -f "$in_tmp"
    echo "skip:    $in_file (no injectable jobs)"
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "would inject $added step(s) into $in_file:"
    diff -u "$in_file" "$in_tmp" || true
    rm -f "$in_tmp"
    return 0
  fi
  mv "$in_tmp" "$in_file"
  MODIFIED="$MODIFIED $in_file"
  echo "injected $added step(s) into $in_file"
}

inject_all() {
  ia_found=0
  for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
    [ -e "$wf" ] || continue
    case "$wf" in
      "$WORKFLOW_FILE") continue ;;
    esac
    ia_found=1
    inject_one "$wf"
  done
  [ "$ia_found" -eq 1 ] || echo "inject:  no existing workflow files found under .github/workflows/"
}

# ── Pull request (--pr) ──────────────────────────────────────────────────────

repo_web_url() {
  rwu_origin=$(git remote get-url origin 2>/dev/null) || return 1
  case "$rwu_origin" in
    git@*)
      echo "$rwu_origin" | sed -e 's/^git@//' -e 's/:/\//' -e 's/\.git$//' -e 's/^/https:\/\//'
      ;;
    http://* | https://*)
      echo "$rwu_origin" | sed -e 's/\.git$//'
      ;;
    *) return 1 ;;
  esac
}

open_pr() {
  git remote get-url origin >/dev/null 2>&1 ||
    fail 5 "--pr needs an 'origin' remote to push to"
  to_commit=$(echo "$CREATED $MODIFIED" | tr -s ' ' | sed 's/^ //;s/ $//')
  if [ -z "$to_commit" ]; then
    echo "--pr:    nothing new to commit; skipping PR"
    return 0
  fi

  base_branch=$(git rev-parse --abbrev-ref HEAD)
  target_branch=$BRANCH_NAME
  if git rev-parse --verify -q "$target_branch" >/dev/null 2>&1; then
    [ "$FORCE" -eq 1 ] || fail 1 "branch $target_branch already exists — pass --force for a suffixed branch"
    target_branch="$BRANCH_NAME-$(date +%s)"
  fi

  pr_title="Add Decionis governance gate ($MODE mode)"
  pr_body="## Governed by Decionis

This PR adds a **$MODE-mode** [decionis/govern](https://github.com/decionis/govern) gate:

- \`$WORKFLOW_FILE\` — records a signed verdict on every pull request$([ "$DO_INJECT" -eq 1 ] && printf '\n- observe-only shadow steps injected into existing workflows (`continue-on-error: true` — they can never break a build)' || true)
- \`$POLICY_FILE\` — the repo governance policy, evaluated locally in microseconds and recorded (by sha256) on every signed Decision Dossier

### Before merging
1. Add the \`DECIONIS_API_KEY\` secret (Settings → Secrets → Actions).$([ "$ORG_ID_REF" = '${{ secrets.DECIONIS_ORG_ID }}' ] && printf '\n2. Add the `DECIONIS_ORG_ID` secret (your Decionis org id).' || true)

Shadow mode **never fails a build** — merge, watch the verdicts on PRs, then flip \`mode: enforce\` when ready.

[![Governed by Decionis](https://img.shields.io/badge/Governed%20by-Decionis-6D28D9?logo=shield&logoColor=white)](https://github.com/decionis/govern)

---
Generated by \`install.sh\` v$INSTALLER_VERSION."

  echo "branch:  $target_branch (from $base_branch)"
  git checkout -q -b "$target_branch"
  # shellcheck disable=SC2086 — word splitting over the file list is intended
  git add -- $to_commit
  git commit -q -m "chore: add Decionis governance gate ($MODE mode)" \
    -m "Generated by decionis/govern install.sh v$INSTALLER_VERSION. Shadow mode records signed verdicts without failing builds."
  git push -u origin "$target_branch"

  if command -v gh >/dev/null 2>&1; then
    if gh pr create --title "$pr_title" --body "$pr_body" --base "$base_branch" --head "$target_branch"; then
      return 0
    fi
    echo "gh pr create failed — open it manually:" >&2
  fi
  web=$(repo_web_url) || {
    echo "pushed:  open a PR from $target_branch → $base_branch on your host"
    return 0
  }
  echo "Open the PR: $web/compare/$base_branch...$target_branch?expand=1"
}

# ── Main ─────────────────────────────────────────────────────────────────────

echo "Decionis Govern installer v$INSTALLER_VERSION (mode: $MODE$([ "$DRY_RUN" -eq 1 ] && printf ', dry run'))"
write_workflow
write_policy
[ "$DO_INJECT" -eq 1 ] && inject_all

if [ "$DRY_RUN" -eq 1 ]; then
  echo "dry run: nothing was written"
  exit 0
fi

if [ -z "$CREATED$MODIFIED" ]; then
  echo "All Decionis artifacts already present; nothing to do."
  exit 0
fi

if [ "$DO_PR" -eq 1 ]; then
  open_pr
else
  echo ""
  echo "Next steps:"
  echo "  1. Add the DECIONIS_API_KEY repo secret (and DECIONIS_ORG_ID unless --org-id was given)."
  echo "  2. Commit the changes — or re-run with --pr to open the onboarding pull request:"
  echo "       curl -fsSL https://decionis.com/govern/install.sh | sh -s -- --pr"
fi
