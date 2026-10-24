# Security Policy

This is the Foxy fork of `cashucard/javacard`: a JavaCard applet that holds
ecash on a card, and the documents that go with it. A bug here can lose the
money on a card, so reports are welcome and taken seriously.

## Reporting a Vulnerability

Report it privately through this repository's security advisories:
<https://github.com/getfoxy/card/security/advisories/new> (the **Security** tab,
then **Report a vulnerability**). That makes a private advisory that only the
maintainers can see.

Please do **not** open a public GitHub issue, pull request or discussion for a
vulnerability.

Include as much of the following as you can:

- A description of the vulnerability and its potential impact
- Steps to reproduce (proof of concept, affected commit or command)
- Any suggested remediation

## What to Expect

- Every report is read, and we will keep you informed as we investigate and
  remediate.
- Please allow us a reasonable window to fix the issue before public disclosure.

## Scope

This policy applies to this repository: the applet in `applet/`, its tests, and
the documents. The Foxy app that talks to the card has its own policy in
[getfoxy/iOS](https://github.com/getfoxy/iOS) (`docs/SECURITY.md`).

Code that this fork took from upstream and did not change, and the host tools
in `tools/cardctl` and `tools/e2e-*` that describe upstream's wire, are
upstream's. For a problem that is in upstream's applet and not in this fork,
follow the policy of [cashucard/javacard](https://github.com/cashucard/javacard).
