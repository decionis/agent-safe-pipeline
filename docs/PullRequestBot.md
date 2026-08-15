# Pull request bot

The repository uses a dedicated GitHub App to open pull requests without
rewriting commits. Existing commits retain their original author and committer
metadata. The App becomes the pull-request author, so `@ocularminds` can
provide the required CODEOWNER approval.

## Trust policy

The bot opens a pull request only when all of the following are true:

1. The head branch belongs to this repository and is ahead of `master`.
2. No pull request has previously targeted `master` from that branch.
3. Either:
   - GitHub recorded `@ocularminds` as the actor for the branch-creation
     event; or
   - every commit ahead of `master` is attributed by GitHub to
     `@ocularminds`.

Missing authorship, incomplete compare results, an untrusted creator, or mixed
commit authors fail closed. The bot can read Actions and repository contents
and create pull requests. It cannot push commits, approve reviews, merge pull
requests, or administer the repository. Each workflow token is narrowed to the
repository that requested it, even when the App installation includes another
repository.

API requests use bounded retry and timeout controls. Successful JSON responses
are streamed into a 100 KiB maximum buffer before parsing. Oversized or malformed
responses fail closed with stable error codes, and failed GitHub responses retain
only the HTTP status rather than a downstream response body.

`BranchCandidate.yml` records branch creation without using App credentials.
It dispatches `PullRequestBot.yml`, whose workflow and script are checked out
from the trusted default branch. A scheduled scan covers branches that were
created before the workflow existed or received commits after creation.

## GitHub App configuration

Create an organization-owned GitHub App named **Decionis Bot** with:

- Repository access: only `decionis/agent-safe-pipeline` and
  `decionis/steward`
- Actions: read
- Contents: read
- Pull requests: read and write
- Webhooks: disabled

Install the App on the two selected repositories, generate a private key, and
configure this repository:

```sh
gh variable set PR_BOT_CLIENT_ID \
  --repo decionis/agent-safe-pipeline \
  --body "<GitHub App client ID>"
gh secret set PR_BOT_PRIVATE_KEY \
  --repo decionis/agent-safe-pipeline \
  < "/secure/path/decionis-bot.pem"
gh variable set PR_BOT_ENABLED \
  --repo decionis/agent-safe-pipeline \
  --body "true"
```

The private key is never committed or stored as a repository variable. The
workflow requests a repository-scoped installation token, explicitly narrows
it to Actions read, Contents read, and Pull requests write, and lets the token
action revoke it when the job ends.

Installing the App on `decionis/steward` does not enable automation there.
Steward requires its own trusted workflow, repository variables, and encrypted
secret before it can request a repository-scoped token.

## Bootstrap and verification

1. Install and configure the App while `PR_BOT_ENABLED` remains absent or
   `false`.
2. Push the workflow implementation branch as `@ocularminds`.
3. Mint a one-time token from the installation and use it to open the bootstrap
   pull request. Do not rewrite the branch commits, and remove the downloaded
   private key after storing it as the Actions secret.
4. Confirm the PR author is `decionis-bot[bot]`, required CI runs, and
   `@ocularminds` can submit the counting CODEOWNER approval.
5. Merge the approved bootstrap pull request, then set `PR_BOT_ENABLED=true`.
6. Push a new branch created by `@ocularminds` with at least one commit ahead
   of `master` and verify the automated path end to end.
7. Remove the owner from the ruleset bypass list only after this path succeeds.

Rotate the App private key through GitHub App settings and update
`PR_BOT_PRIVATE_KEY` before revoking the old key. Set
`PR_BOT_ENABLED=false` before changing App permissions or installations.
