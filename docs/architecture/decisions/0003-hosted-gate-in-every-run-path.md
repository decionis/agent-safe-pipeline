# ADR 0003: the hosted gate in every example's run path, on one variable

Status: accepted, 2026-09-18.

## Problem

A fork of this repository ran every example against the in-process fixture and never touched
Decionis. Four examples could ask Decionis beside the fixture, but only with a key the developer
had already minted by hand and two variables set, and each run ended with a verdict and a dossier
identifier. The differentiator, a signed Decision Dossier anyone can verify, was two steps away
from the terminal the developer already trusted, and nothing measured which clones went on to
become organizations.

## Existing implementation

- `createGate` and `ShadowGate` (`packages/pipeline/src/decision/`): the hosted gate beside a
  local pair, `SHADOW` by default, never less restrictive than the local authority.
- `DecionisGate`: `POST /v1/authority/enforce-and-bind`, with client identification in the
  `User-Agent` (`repo`, `example`).
- `agentsafe login` and its credential file (`packages/agentsafe/src/cli/Credentials.ts`).
- `POST /v1/public/agents/provision` in the Decionis contract: a provisional workspace with no
  account, its key returned once, an allowance of governed decisions, and a `provisional_anonymous`
  issuer tier signed into every dossier it mints; its key carries `decision:run`, which the
  authority accepts on `enforce-and-bind` in `SHADOW` only.
- `scripts/VerifyDossier.mjs` (`pnpm decionis:verify`): fetches the signed record with the key
  and verifies it offline with `@decionis/verify`.
- The verification envelope (`verification_page_url` under a share-link capability) the authority
  attaches to `evaluate-decision`, declared open in the contract, and not yet attached to
  `enforce-and-bind` or to the dossier route.

## Options considered

1. **Keep two variables and a key minted by hand.** Rejected: the step that stops a fork is the
   step it has to take outside the terminal.
2. **A magic value in `DECIONIS_API_KEY`.** Rejected: a key variable that is not a key is a trap
   for every other consumer of the same variable.
3. **One switch, `DECIONIS_HOSTED=1`, that resolves a key: the environment, else the credential
   the user keeps, else a workspace provisioned in the run and kept for the next.** Chosen.

## Decision

`createHostedGate` (and `resolveHostedCredentials` for a process that is not a gate) is
`createGate` with the switch. A key in the environment still wins, in the mode asked for; no
variable is still the local pair; `DECIONIS_HOSTED=1` with no key reads the credential file
`agentsafe login` writes, and when it holds nothing for this authority, mints a provisional
workspace, stores it there, and says so on standard error once. A provisional key evaluates in
`SHADOW` only, because that is what its scope allows and because a workspace nobody has claimed
must not govern execution; an owned key set in the environment takes `ENFORCEMENT` when asked.
`NODE_ENV=production` refuses the switch as it refuses every stored login.

Every example ends with `printHostedOutcome`: a local run prints its verdict and one hint line; a
hosted run prints what Decionis decided, the dossier, the verification page when the authority
attached one, the offline verification command, and the signed record itself, fetched with the
run's own key and shown by its proof (algorithm, key, issued-at, artifacts, issuer tier). The
single-decision examples evaluate their proposal beside the fixture; the adversarial demos and the
escalation example keep their attempts local by design and end with the golden proposal evaluated
by Decionis; the trusted executor runs once more in shadow against Decionis; the two Presence
examples read the stored login and refuse a provisional workspace by name, because a ceremony
needs an owned organization with an enrolled person.

`DecionisGate` reads `verification.verification_page_url` from an `enforce-and-bind` response
when the authority attaches it; the block is declared open in the contract, so only the page is
read from it and the mirror stays strict everywhere else. Until the authority attaches it, the
line is absent and the offline command stands.

Client identification gains `surface` (`github` from the examples), so the authority can stamp an
organization it creates for such a caller with the surface, repository and example it came from.
The repository's own path is recorded daily by `scripts/CollectRepoMetrics.mjs` on the `metrics`
branch: clones and unique cloners, views and unique visitors, stars, forks, watchers, top
referrers and paths, and npm downloads per package, because GitHub keeps traffic for fourteen days
and nothing else keeps it.

## Reason

The moment a fork can point at production in ten seconds, inside the terminal, with the signed
record at the end, is the moment the repository is measured by. One variable is the smallest
possible step; a key issued in the run removes the step outside the terminal; the credential file
shared with `agentsafe login` means a developer has one Decionis identity on their machine, not
two; `SHADOW` for a provisional key keeps a working fork working whatever the hosted side says.

## Protocol impact

None. The provisioning route, the decision route and the dossier route are used as the contract
documents them. The verification envelope is read where the contract declares it open.

## Compatibility impact

`createGate` and `printDecision` are unchanged. `GateDecision` gains an optional
`verificationUrl`; `HostedEvaluation` gains `verificationUrl: string | null`. The credential file
gains an optional `provisional` field the CLI's reader ignores. New exports are pinned in the
packed-tarball consumer.

## Security impact

- The raw key is returned by the authority once and written to a file readable by its owner
  alone (`0600`, directory `0700`); the gate holds it in a closure and never on a returned object.
- Provisioning carries the client identification and nothing else about the machine, and needs
  no credential; the dossier fetch carries the key in the `Authorization` header alone.
- Every hosted call is bounded in time and in bytes and fails closed on anything but the
  documented answer; a provisioning refusal or limit is surfaced by code, never retried in a loop.
- A provisional key never governs execution.
- Metrics carry counts and public names only; the traffic token is used for the traffic routes
  and no other.

## Migration impact

None for consumers. A fork that set `DECIONIS_API_KEY` and `DECIONIS_TENANT_ID` runs exactly as
before.
