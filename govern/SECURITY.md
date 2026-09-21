# Security Policy

Decionis takes the security of the **Decionis Action Gate** (`decionis/govern`) and the platform it talks to seriously.

## Reporting a vulnerability

Please report security issues privately — do **not** open a public issue.

- Email **<security@decionis.com>** with a description, reproduction steps, and impact.
- Or use GitHub's [private vulnerability reporting](https://github.com/decionis/govern/security/advisories/new) on this repository.

We acknowledge reports within **2 business days** and aim to provide a remediation timeline within **5 business days**. Please allow reasonable time for a fix before any public disclosure; we're glad to credit reporters who coordinate disclosure.

## Scope

- The Action source (`src/`, `action.yml`) in this repository.
- The Decionis APIs the Action calls (`api.decionis.com`), including the evaluate-decision, execution-grant, and OIDC endpoints.

## What the Action handles

- Your `DECIONIS_API_KEY` is read only from the workflow input you provide and is sent solely to the configured `api-base-url` over HTTPS. It is never logged.
- Execution Grants are short-lived, single-use, and signed; they are verifiable against the published JWKS.
- The Action runs with zero third-party dependencies (Node 20 built-ins only), minimizing supply-chain surface.

## More

- Security overview: <https://decionis.com/security>
- Privacy: <https://decionis.com/privacy>
- Terms: <https://decionis.com/terms>
