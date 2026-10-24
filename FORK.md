# This is a fork

> **Merged into cashu-javacard as protocol 2.0 (ENG-673, [DECISIONS D18](docs/DECISIONS.md#d18)).** This
> document is Foxy's, as it stood at software 1.20, kept for its design and its
> reasons. On the 2.0 wire the AID is `F0 43 41 53 48 55 43 41 52 44` (not
> `F0 FOXYCARD`), `SELECT` answers `02 01`, every `FoxyCard/…` label is
> `CashuCard/…`, and D20 to D26 add to it (the rollover budget and `REFRESH`, the
> anchored owner, and the fixes). Where this and [`spec/APDU.md`](spec/APDU.md) differ, the
> spec is the 2.0 wire.

`getfoxy/card` is a fork of `cashucard/javacard` (applet 0.4, `c1f4580`,
MIT). The applet here is **not compatible on the wire** with
upstream's, and has an AID of its own (`F0 46 4F 58 59 43 41 52 44`) so that
neither can be mistaken for the other.

What changed and why is in [`docs/FOXY-CARD-SPEC.md`](docs/FOXY-CARD-SPEC.md),
section 4. In short:

- `SPEND_PROOF` takes no message. The card rebuilds the slot's own secret and
  signs its hash; nothing a reader sends reaches the signer.
- `SIGN_ARBITRARY` is removed. `AUTH` proves the card is the card, over a
  tagged hash no piece's secret can equal.
- Nothing is loaded onto a card with no owner, or onto a card with no PIN but by
  the owner's grant. (Software 1.16 makes the PIN optional. A card set up with
  none pays without one, under its limits. A card with a PIN has a no-PIN
  allowance: what it signs for in a day without the PIN, counted in the daily
  limit's window. Over it the card answers `6A94` and the PIN is asked for the
  whole payment.)
- The card keeps a daily limit in permanent memory: the most it will sign for in
  one day, in sats (0 is none, and a new card has none). It keeps the day itself:
  a clock that only moves forward, the time written in the newest Bitcoin block
  header the card has been shown (`SET_HEADER`, software 1.15), believed for the
  work in it and not for who brought it. What a payment takes off the card is
  added to what has been signed today, in the transaction that signs, and a
  payment that would take today past the limit is refused (`6A8F`). A terminal
  that has been handed the PIN can take one day's limit, and can end the day only
  by bringing a real block dated a day on. (Before 1.15 the clock was a time
  signed by a key built into the app, which was not secret, and so bound no
  terminal built to cheat. Earlier
  tries: a limit on one PIN entry, which a terminal that had the PIN walked
  round; then an allowance that only went down and only an owner's proof
  raised, which held against a terminal but stopped a card whose owner's phone
  was not at hand.)
- The card has an owner: a P-256 public key, worked out on the holder's phone
  from its seed and given to the card last in the set-up tap. No secret is on the
  card or in the air. `CHANGE_PIN` (which needs no old PIN and unblocks a blocked
  card), the owner's `SET_LIMIT`, `SET_OWNER`, `SET_CARD`, `ALLOW_LOAD` (adding
  funds with no PIN) and `LOCK_CARD` each need an ECDSA signature by the owner
  key over a label, a nonce from `GET_NONCE` and the value being set. `LOCK_CARD`
  also needs a PIN set and verified: on a card with no PIN any reader could once
  lock it for good.
- A card is cash. It holds what is put on it. A card with an owner is its owner's,
  empty or not; a card with none is open while it is empty and cannot be loaded.
  Lose the card and the money is gone; a forgotten PIN or a blocked card is put
  right from the owner's phone, and if the owner loses their twelve words the PIN
  and the limit can never be changed.
- A slot carries a date and the card a refund key, so the pieces of a lost or
  blocked card can be taken back by whoever loaded them.
- The card records the mint its pieces are at.
- The card keeps the mint's NUT-12 proof with each piece that comes with one, for a
  phone to read and check (software 1.20, `GET_DLEQ`); it checks nothing itself.
- 64 slots of 82 bytes.

The instructions and what each carries are in the spec's section 5.2, the owner
and its proofs in 5.6, and the daily limit and the clock in 5.7; the whole text
of those three is `docs/FOXY-CARD-DAILY-LIMIT.md`. The applet's version is 1.1
(`SELECT` answers `01 01`) and the format byte is 3: `GET_INFO` is 29 bytes (the
first 16 did not move), `CHANGE_PIN` and `LOCK_CARD` carry an owner's proof, and
`33`, `34`, `36`, `37`, `41`, `42`, `43`, `44` and `45` are the instructions of the
limit, the clock and the owner. The applet has run on a real card (below), but
only test cards, so none is expected in the field with an older shape.

## What is and is not up to date

| Part | State |
|---|---|
| `applet/` and its tests | the fork. `mvn -f applet/pom.xml test`, and `ant -f applet/build.xml cap -Djc.sdk=…/jc305u4_kit` |
| `docs/FOXY-CARD-SPEC.md` | the fork |
| `docs/FOXY-CARD-DAILY-LIMIT.md` | the daily limit, the clock and the owner key, in full; where it and the spec differ, this is what is built |
| `docs/FOXY-CARD-SCREENS.md` | the wallet's card screens, as built |
| `docs/CARD-DESIGNS.md` | the codes of the designs a card's face can have, and how one is added |
| `docs/FOR-LNFLASH.md` | the note to upstream: what changed, what was found, what has and has not been tested |
| `spec/`, `README.md`, the other `docs/` | upstream's, describing upstream's wire. Not yet rewritten |
| `tools/cardctl`, `tools/e2e-*` | upstream's host tools, for upstream's wire. They do not drive this applet |
| CI | `.github/workflows/ci.yml.disabled`: switched off, because it tests upstream's wire and would fail on this fork (see below) |
| `applet/target/` | build output, not tracked: build the CAP with `ant`. `docs/HARDWARE_DEPLOYMENT.md` is upstream's and names a tracked CAP and its sha256, which do not apply here |
| `tools/cardsim/` | new: the applet on a loopback port, for Foxy in the iOS Simulator (below) |

The applet has run on one real card (an NXP JCOP4 J3R180) with the Foxy app on
one iPhone: installed, every command sent through a reader, and a card set up,
loaded, paid from and given its change back over NFC. One card is not a batch.
Beyond that the applet has been converted to a CAP by the JavaCard 3.0.5 tools
and tested under jCardSim, which cannot reproduce EEPROM limits, torn writes or
write endurance.

About CI: `.github/workflows/ci.yml` is renamed `ci.yml.disabled`. Its jobs run
upstream's host tools (`tools/cardctl`, `tools/e2e-*`), which do not drive this
applet, and compare a tracked CAP with a fresh build, and the CAP is no longer
tracked. They would fail here. Rename it back when the host tools are ported; the
fork's own tests are `mvn -f applet/pom.xml test`.

## A card with no card

`sh tools/cardsim/run.sh` runs the applet in jCardSim and listens on
127.0.0.1:47431. Foxy's simulator build has no NFC and reaches a card there
instead, so the app's card screens, its bridge and a mint can be driven against
the applet's own class before a card exists. `sh tools/cardsim/ctl.sh off`
takes the card off the reader; `on`, `pull N` (let N more commands through,
then take it away), `new` and `show` are the others. The app's repository,
https://github.com/getfoxy/iOS, has `tests/flashcard-applet.js`, which drives
the wallet's flows over the same socket from Node.

What it holds lasts as long as the process, and no longer: a card server
that stops takes its card's contents with it. Stop one by its own process
number, never by a pattern that could match another, and read it first
(`ctl.sh <port> show`). Ecash put on a simulated card is not lost with it, as
long as the card had the simulator's fixed key (`run.sh <port> plain`): a new
server started the same way is the same card, and the wallet that loaded it
still holds the token it wrote. It prints each command's instruction and
status and never its data, because one command is the PIN.

## On a card

`docs/HARDWARE_DEPLOYMENT.md` is upstream's guide and its steps hold, with this
fork's names in place of upstream's:

    ant -q -f applet/build.xml cap -Djc.sdk=$HOME/.javacard/sdks/jc305u4_kit
    gp --list                                   # the card answers, with its default keys
    gp --install applet/target/<the cap file>
    gp --apdu 00A404000AF0464F58594341524401    # SELECT by the applet's name: 0101 9000
    gp --apdu B0010000                          # GET_INFO: 29 bytes, 9000

    gp --delete F0464F58594341524401            # to take it off again: the applet,
    gp --delete F0464F585943415244              # then its package

`gp` is GlobalPlatformPro. A card locks itself for good after a run of failed
key attempts, so a login with the card's default keys is tried once, and not
again if it fails. Upstream's report for the same chip is
`docs/HARDWARE_TEST_REPORT_2026-09-22.j3r180.md`: its 6F00 on install came from
a probe in the constructor, which is the first thing to suspect if an install
fails here. On the J3R180 used here the applet installed the first time.

A card straight from the install has no PIN and no owner. It holds nothing and
cannot be loaded, but any reader in range can give it a PIN and an owner of its
own choosing (`SET_PIN`, `SET_OWNER`). Set it up (the PIN, the record, then the
owner: spec 5.6) before it leaves your hands.

After that, the phone: Foxy (https://github.com/getfoxy/iOS) built with the NFC
entitlement (`tools/flashcard.entitlements` there), MENU, FLASHCARD, TAP CARD.

## Upstream

The spec's section 4 lists weaknesses found in upstream's applet 0.4, and what
this fork does about each. Upstream's own repository is
https://github.com/cashucard/javacard.
