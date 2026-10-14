# cardctl — host-side driver for the Cashu card applet, protocol 2.0

A PC/SC command-line tool that speaks protocol 2.0 as
[`spec/APDU.md`](../../spec/APDU.md) has it, over either a contact or a
contactless reader: the reads, `AUTH`, the owner's commands (with a P-256
owner key, `p256.py`), the clock, loads and the PIN.

Until this existed there was **no way to talk to a card at all** — the applet
had been exercised only under jCardSim, which cannot surface EEPROM exhaustion,
ECDH output framing differences, or a card whose `getS` returns short. Those are
precisely the bugs that only appear on silicon.

## Install

```bash
cd tools/cardctl
pip install -r requirements.txt
```

- **macOS** — PC/SC ships with the OS. Do **not** install `pcsc-lite`; it
  conflicts with the built-in daemon.

  ⚠️ **Do not use the system Python** (`/usr/bin/python3`, 3.9). `pip install
  pyscard` appears to succeed there, then fails at import with:

  ```
  ImportError: dynamic module does not define module export function (PyInit__scard)
  ```

  which looks like a broken reader or a bad install and is neither — it is an
  ABI mismatch in the native `_scard` module. Use a Homebrew Python instead:

  ```bash
  brew install python@3.13          # or any recent 3.x
  python3.13 -m venv .venv && source .venv/bin/activate
  pip install -r requirements.txt
  ```

  Verified working on Homebrew Python 3.14.
- **Debian/Ubuntu** — `sudo apt install pcscd libpcsclite-dev` and make sure
  `pcscd` is running.

## Quick start

```bash
python3 cardctl.py readers      # is the reader visible?
python3 cardctl.py selftest     # the one that matters
```

`selftest` is the card-arrival test. It selects the applet, reads `GET_INFO`,
the public key and the record, asks the card to prove itself with `AUTH` over
random bytes of ours, and **verifies each signature against BIP-340** — then
checks that two `AUTH`s over the *same* bytes use different nonces, which is a
real security property rather than a nicety (a nonce that is a pure function of
`(d, msg)` lets a fault injector recover the private key from two signatures).
`AUTH` burns nothing and needs no PIN.

```
PASS  SELECT applet  — version 2.1
PASS  GET_INFO  — v2.1, 128 slots, PIN set, owner yes
PASS  format 4 (SIG_ALL pieces)  — format 4
PASS  Schnorr capability advertised  — caps=0xFF
PASS  GET_PUBKEY well-formed  — 02a1b2c3d4e5f60718…  (33 bytes)
PASS  AUTH + BIP-340 verify [1/3]
...
All 13 checks passed on physical hardware.
```

Pass `--pin` to check the PIN as well. A card that is not protocol 2.0 fails at
`SELECT applet` (a 0.x or Foxy 1.x card does not even answer the 2.0 AID: it
needs an update, and its balance is swept first). A card whose PIN is blocked
(`GET_INFO` byte 7 = 2) fails at `PIN state`: no payment signs until the owner's
`change-pin` sets a new PIN, which unblocks it (no PUK on 2.0: [D18](../../docs/DECISIONS.md#d18)).

`info` says the owner, the clock, the limits and the rollover budget
([D20](../../docs/DECISIONS.md#d20)): `rollover budget : 2 of 7 rolls since the
owner's last refresh`. At 7 of 7 the day's window stands until the owner's
`refresh` with the tip header.

## The owner key

The owner's commands (`set-owner` on an owned card, `set-card` on an owned card,
`set-limit`, `change-pin`, `refresh`, `load --owner`, `set-pin --owner`, `lock`)
sign a proof with `--owner-key`, a 32-byte P-256 private key in hex. Without it,
cardctl signs with its **TEST key** (`p256.TEST_OWNER_PRIVATE`, derived from a
fixed string in `p256.py`) and says so on stderr: anyone with this repository
holds it, so it is for bench cards only. A card handed to a person is owned by
the holder's phone.

## Loading the applet

`cardctl` talks to an applet that is already installed. To install it, build the
CAP and use [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro):

```bash
cd applet && ant clean cap
# three applets, the opener first: docs/HARDWARE_DEPLOYMENT.md has the commands
```

**The card must be JavaCard 3.0.5 or later** — the applet needs
`KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`, which does not exist in 3.0.4. JCOP4
works; JCOP3 / J3H145 / Feitian 3.0.4 cannot run this applet at all.

If loading over an ACR122U stalls part-way, suspect the interface before the
CAP: contactless loading is chattier and more fragile than contact. A contact
reader is the more reliable way to install, leaving NFC for tap testing.

## Commands

| Command | What it does |
|---|---|
| `readers` | list PC/SC readers |
| `-t`/`--timing` (any command) | time every APDU to stderr, summary table at exit |
| `selftest [--rounds N] [--pin P]` | full hardware check incl. BIP-340 verification of `AUTH` |
| `info` | version, slots, PIN, owner, record, clock, limits, rollover budget, balance |
| `pubkey` | 33-byte compressed public key |
| `balance` | sum of unspent proof amounts |
| `auth` | `AUTH`, then verify the signature |
| `slots [--all]` | per-slot status (128 slots) |
| `proof <slot>` | decode one 82-byte proof slot, with its date |
| `load --keyset ID --amount N [--nonce HEX] [--c HEX] [--date T] [--pin P \| --owner]` | `LOAD_PROOF`. `ID` is the full 16-hex-char NUT-02 keyset id. `--owner` loads under the owner's grant (`ALLOW_LOAD`), no PIN |
| `clear-spent [--pin P]` | free spent slots |
| `verify-pin PIN` | verify the PIN for this tap |
| `set-pin PIN [--owner]` | set the PIN on an open card; `--owner` adds one to an owned card with none (ADD PIN) |
| `change-pin NEW` | the owner sets a new PIN: no old PIN, any state; unblocks a blocked card |
| `set-card --mint URL [--refund HEX] [--pin P]` | write the record (the owner's proof on an owned card) |
| `set-owner [--anchor HEADER] [--old-owner-key HEX]` | give the card its owner (the public half of `--owner-key`), anchored at a block header |
| `set-limit --day N [--payment N --allowance N [--budget R]]` | the owner's limits; `--budget` (1–30) is the rollover budget, and needs the two before it; without it the card leaves the budget as it is ([D26](../../docs/DECISIONS.md#d26)) |
| `set-header --header HEX` | `SET_HEADER`: show the card a block header |
| `refresh --header HEX` | `REFRESH`: the owner's proof over the tip header; the rollover budget is full again |
| `lock --pin P [--yes]` | **irreversibly** disable writes: the PIN and the owner's proof |
| `dump --mint URL [--unit U] [--out PATH] [--force] [--unspent-only]` | **0.x cards only**: write the card's slots out as a card file. `--out` refuses to overwrite without `--force` |
| `load-file PATH [--pin P]` | **0.x cards only**: `LOAD_PROOF` every proof in a card file. Refuses a file for another card or too few free slots; re-runnable |
| `apdu <hex>` | send a raw APDU |

Gone with the 0.x wire ([D18](../../docs/DECISIONS.md#d18)): `sign`
(`SIGN_ARBITRARY`, which signed anything and burned nothing), `spend`
(`SPEND_PROOF`; a 2.0 payment is `SPEND_ALL_*` with a mint's outputs, which a
till drives), `clear-pin`, `set-puk` and `unblock-pin`. Their opcodes `43`, `44`,
`45` are `SET_OWNER`, `GET_NONCE` and `ALLOW_LOAD` on 2.0, so they must not come
back; `test_apdu.py` checks the parser refuses them.

Global flags: `-r/--reader N` to pick a reader, `-v/--verbose` to log every APDU
to stderr — use `-v` when a command misbehaves, since the raw exchange usually
makes it obvious whether the card rejected the command or never saw it.

## Timing a card

`--timing` goes before the command and times every APDU around the PC/SC
transmit call, so each figure is the full reader round trip, not just the
applet's own work. Per-APDU lines go to stderr as they happen and a per-command
table (count, min, median, max, total) follows at exit, even when the command
fails partway.

```bash
python3 cardctl.py --timing selftest --rounds 10    # 12 AUTH signatures, 1 table
python3 cardctl.py -t refresh --header <hex>         # GET_NONCE + one ECDSA verify + a header, timed
```

2.0 changed the field multiply ([D21](../../docs/DECISIONS.md#d21)): re-measure
`AUTH` on the J3R180 before a release.

Compare like with like: a contact reader, the ACR122U over RF and a phone over
NFC all give different numbers for the same card, and the phone adds field
discovery that none of these capture. The median is the figure to quote.

## A warning about `load`

`load` without `--c` inserts a random placeholder in place of the mint's
signature. That is fine for exercising storage and slot management, but such a
proof can never be redeemed at a mint. A 2.0 card signs only format-4 `SIG_ALL`
pieces locked to its key ([`spec/NUT-XX.md`](../../spec/NUT-XX.md)); `load`
writes whatever it is given, so a real top-up is a wallet's NUT-11 swap first.

## Card files (0.x cards only)

Card files describe the 0.x applet's pieces (no date, the 0.x secret), so `dump`
and `load-file` select the 0.x AID and refuse any other card
([`spec/CARD-FILE.md`](../../spec/CARD-FILE.md)): they are kept for the sweep of
0.x cards (docs/HARDWARE_DEPLOYMENT.md). They speak the interchange format in
[`spec/CARD-FILE.md`](../../spec/CARD-FILE.md), the intended contract with
cashu-client's `serializeCardFile` / `parseCardFile`. `test_card_file.py` parses
the spec and asserts this driver's parser and writer against the published field
tables, so a rename on this side fails in CI rather than at a card reader.

> **The two halves do not interoperate yet.** cashu-client (`lnflash/cashu-client#5`)
> does not know the `spent` field and rejects any key outside its allowlist, so
> today it refuses what `dump` writes and `load-file` refuses what it writes.
> The spec's status note has the details; the two changes must merge together.

Four things the format insists on, all because a card file is bearer money:

- **`spent` is required, not defaulted.** A file that omits it is not a file of
  unspent proofs, it is a file whose state is unknown — and guessing "unspent"
  turns settled money back into spendable balance on the next `load-file`.
- **Unknown fields are refused, not ignored.** At document and slot level. An
  unrecognised key means the writer added something without bumping `version`;
  dropping it silently is how the two sides drift apart in the first place.
- **Amounts are positive powers of two below 2^32,** and keyset ids are NUT-02
  v0 (`00` version byte). Both are enforced by `load` and `load-file` alike, so
  the tool cannot put a proof on a card that the file format then refuses to
  carry back off it.
- **`load-file` is re-runnable.** `LOAD_PROOF` commits one proof at a time with
  no transaction around the file, so a failure part-way through leaves half of
  it on the card. Re-running skips whatever is already there by nonce instead of
  writing duplicates, and everything checkable — capacity, amounts, points — is
  checked before the first write. A nonce the card has already *spent* is
  reported as spent, not as "already loaded".

`dump` validates the document it assembled before writing it, so a mistake like
`dump --mint "$UNSET_VAR"` fails loudly instead of leaving an unloadable backup.
The one exception is a spent slot that fails the slot checks, as a card pulled
mid-`CLEAR_SPENT` can leave one: `dump` skips it with a warning on stderr
(`half-cleared by an interrupted CLEAR_SPENT; run clear-spent`, once the card's
other spent slots have settled) and writes the rest. The slot checks catch a
zeroed amount and a `C` that is no longer a point. A tear that zeroed only
keyset or nonce bytes, or part of `C` whose x still lands on the curve, passes
them, and `dump` writes that slot as spent. An unspent slot that fails still
refuses the whole dump.

## Tests

```bash
python3 test_bip340.py            # verifier: spec vectors, reference round-trip, mutations
python3 test_p256.py              # the owner's ECDSA: RFC 6979 vectors and the card's own (spec/vectors/owner.json)
python3 test_apdu.py              # every command's bytes, against spec/APDU.md
python3 test_spec_consistency.py  # cardctl vs spec/APDU.md, NUT-XX.md and the applet, parsed
python3 test_card_file.py         # card file read/write, against spec/CARD-FILE.md
python3 test_hwtest_65byte_pubkey.py  # host-side pubkey normalisation used by hwtest_65byte_pubkey.py
```

All six run without a reader or a card. The BIP-340 tests matter more than they
look: `selftest`'s verdict is only as trustworthy as the verifier behind it, so
that verifier is checked against the specification's own vectors, round-tripped
against an independent reference signer, and mutation-tested to prove it can
say *no*.

`hwtest_65byte_pubkey.py` is the one script here that *does* need a card. It is
the check behind section 8 of
[`docs/HARDWARE_TEST_REPORT_2026-09-01.j3r452.md`](../../docs/HARDWARE_TEST_REPORT_2026-09-01.j3r452.md):
on a card whose `GET_PUBKEY` returns a 65-byte uncompressed point (the applet
before #23) it normalises the key on the host, confirms the point is on
secp256k1, and then runs the same sign/verify and nonce-freshness rounds as
`selftest`. It sends only SELECT, GET_PUBKEY and SIGN_ARBITRARY, so it is a
0.x tool: it selects the 0.x applet and refuses any other card.

```bash
python3 hwtest_65byte_pubkey.py -r 1   # reader index, as for cardctl
```
