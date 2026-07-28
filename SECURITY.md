# Security policy

intel2sigma generates detection content that other organisations may run
in production, and the hosted instance accepts untrusted rule input from
anyone. Both make it worth having a way to report problems privately.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting instead: go to the
[Security tab](https://github.com/davekindof/intel2sigma/security) and
choose "Report a vulnerability". That opens a private advisory visible
only to the maintainer, and it can be published as an advisory once a fix
ships.

Useful things to include, roughly in order of value:

- What an attacker gains, and what access they need to get it
- A rule, input, or request that reproduces it
- Which surface is affected — the hosted instance, the container image,
  or the library when imported directly

## Scope

The hosted instance at `intel2sigma.davidsharp.io` runs as a stateless
container with **no authentication and no user accounts** (an
architectural invariant, not an oversight — see CLAUDE.md I-3). It keeps
no database and no server-side per-user state, so there are no stored
credentials or persisted user data to compromise.

That shapes what is and is not interesting:

**In scope**

- Anything that leaks one user's rule content, field names, or inputs to
  another user. The server is single-process per replica and requests
  from different users share a replica, so cross-request state bleeding
  is a real class of bug here.
- Server-side request forgery, or any path that makes the server reach
  out to an attacker-controlled destination.
- Container escape, or reading files outside the application.
- Anything that gets code executing on the server.

**Out of scope**

- Absence of authentication or rate limiting in the application. TLS,
  WAF and rate limiting are edge concerns handled by Cloudflare, and the
  application is deliberately rate-limit-naive.
- A crafted rule causing a single request to fail or return a 500. These
  are robustness bugs — please do open a normal public issue for them.
- Findings against the SigmaHQ rule corpus itself. Report those upstream
  at https://github.com/SigmaHQ/sigma.

## Supported versions

Pre-1.0 and single-maintainer: fixes land on `main` and ship in the next
release. Older versions are not patched.
