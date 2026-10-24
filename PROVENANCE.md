# Provenance

Commits, tags and release files of this repository are signed with Jabari
Ennis's OpenPGP key:

```
ed25519 3139 A2E7 74DA F732 8533  D0EC 0A89 7098 CF0A 7E5B
Jabari Ennis (Dread) <dread@islandbitcoin.com>
```

The public key is [`signing-key.asc`](signing-key.asc), and GitHub serves the
same key at <https://github.com/islandbitcoin.gpg>.

Each release has a signed annotated tag beside its original tag, `signed/<tag>`, and a detached `.asc` signature beside each release file:

```bash
gpg --import signing-key.asc
gpg --verify cashu-javacard-applet-2.0.cap.asc cashu-javacard-applet-2.0.cap
```

`provenance/2026-10-24` is a signed tag on `main` as of this record. A signed
tag covers every commit before it, because each commit's hash includes its
parent's, so it vouches for the 149 commits on `main` that GitHub shows as
unsigned: direct pushes made before commits were signed. From 2026-10-24,
`main` requires signed commits.

The full record, and how to check each kind of signature, is in
[cashucard/cashucard's PROVENANCE.md](https://github.com/cashucard/cashucard/blob/main/docs/PROVENANCE.md).
