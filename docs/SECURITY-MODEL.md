# Security model

What this card protects, what it does not, and which weaknesses are accepted
versus unresolved.

Written to be usable by an auditor. Where something is untested, it says so
rather than asserting a property nobody has measured.

## The one guarantee

**A proof cannot be redeemed without a signature from the card that holds it.**

Proofs are P2PK-locked ([NUT-11](https://github.com/cashubtc/nuts/blob/main/11.md))
to a secp256k1 key generated inside the secure element and never exported. Every
other property below is weaker than this one, and most attacks are attempts to
get around it rather than through it.

## Threat table

| # | Threat | Protected? | Notes |
|---|---|---|---|
| 1 | Passive read of card memory | **Partially** | An attacker gets keyset id, amount, nonce and `C` — the secret string is never stored on the card, but it is reconstructible from the nonce plus the card pubkey, so treat it as leaked too. What does not leak is the private key, so the proofs stay unspendable. Balance and history leak. From software 1.20 a reader also gets the mint's proof for each unspent piece that has one, and so its blinding factor (#16). |
| 2 | Hostile reader spends the card | **Up to the owner's limits** (2.0) | A payment (`SPEND_ALL_SIGN`) needs the PIN given in this tap, or fits the no-PIN allowance, or the card has no PIN; a failed PIN check ends the session. A blocked card has no allowance, by its state byte or by its counter ([D22](DECISIONS.md#d22)). What leaves the card is held to the daily limit, counted against a clock of Bitcoin block headers, and the window rolls at most the rollover budget's times between the owner's refreshes (#17, [D20](DECISIONS.md#d20)). A card with no PIN is cash to whoever holds it, under the same limits. |
| 3 | Card lost or destroyed | ❌ **By design** | No seed, no backup, no recovery. See [D5](DECISIONS.md#d5). |
| 4 | Cloning the chip | **Yes** | Cloning EEPROM copies the proofs but not the key; a clone cannot sign. Cards should be CC EAL 5+ to resist invasive extraction. |
| 5 | Offline double-spend from copied data | ❌ **No** | Fundamental. An offline merchant cannot know a proof was already melted. See below. |
| 6 | Replaying a signature on another proof | **Yes** | The card signs the NUT-11 `SIG_ALL` message of one payment: every input's secret and `C` and every output. A signature is good for that swap and no other, and the card rebuilds every secret from its own key and the slot, so a reader chooses nothing it signs. `AUTH` signs a tagged hash no secret can equal. There is no command that signs a reader's bytes (0.x's `SIGN_ARBITRARY` is gone, D18). |
| 7 | Malicious mint tagging users | **Yes** | NUT-12 DLEQ, verified client-side. See [D11](DECISIONS.md#d11). |
| 8 | Mint insolvency | **Monitored, not prevented** | The mint is trusted for solvency. See below. |
| 9 | Malicious terminal | **Partially** | Cannot forge proofs or spend them elsewhere. Can lie about the amount, or take the tap and never settle — ordinary merchant risk. |
| 10 | Fault injection to recover the key | **Mitigated** | Aux randomness in the nonce prevents the two-signatures-same-`k` recovery. See [D9](DECISIONS.md#d9). |
| 11 | Tear-off (card pulled mid-write) | **Yes, by write order**; not yet on silicon | Every multi-field persistent write commits a single byte last, or is one transaction ([D14](DECISIONS.md#d14)); every write outside a transaction is listed and reviewed in [D23](DECISIONS.md#d23), and a test fails on any new one. A torn `LOAD_PROOF` leaves the slot empty and a torn `CLEAR_SPENT` leaves it spent; neither is counted or signed for. A payment's places are burned by one committed byte (`burnPending`) and marked after it, at the next command if the card left. A torn `CHANGE_PIN` leaves the card blocked, not open (D22). The orders are scanned in the source and the torn states set by hand in jCardSim; no card has been pulled mid-write. |
| 12 | Counterfeit physical cards | **Not a concern** | Value is bound to the chip's key. A look-alike with no valid chip holds nothing. |
| 13 | Supply-chain / pre-personalised cards | ⚠️ **Unaddressed** | Nothing currently attests that a card's key was generated on-card by an untampered applet. |
| 14 | Hostile reader blocks the PIN (3 unauthenticated APDUs) | **Mitigated by the owner** (2.0) | `VERIFY_PIN` needs no authentication, so three wrong PINs from any reader in range block the card. The owner's phone unblocks it: `CHANGE_PIN` with the owner's proof sets a new PIN with no old one, any state, any funds, and a wrong proof costs no PIN try. A card whose owner has lost their seed cannot be unblocked; its balance is stranded. The same loss strands a card with a daily limit even if its PIN works: without `REFRESH` the window stops rolling after the rollover budget, and only about (budget + 1) daily limits can still be paid (#17, [D20](DECISIONS.md#d20)). An owner key kept only in one phone's Keychain (the architect's fallback for a user with no backed-up seed) is lost with that phone. (0.6's PUK is gone with the 0.x wire, D18.) |
| 15 | Reading the NFC tag (software 1.19) | **Nothing of the card to read** | Any reader, with no PIN, gets the same bytes from every card: one web address. It names no card, key, owner or balance. A card on factory keys can have the tag's applet replaced by one carrying another address; rotating the card manager keys closes that. See below. |
| 16 | A piece on the card that the mint never made (software 1.20) | **Checked by the reader, not by the card** | The card keeps the mint's NUT-12 proof for a piece and gives it back; it checks nothing. A reader that checks it, with the mint's keys, sees that a made-up `C` is not real, and a piece copied from another card is not real here. It does not show that a real piece is unspent. Reading the proof gives away `r`, which ties a piece to the request that made it if the mint is given it. See below. |
| 17 | A terminal with the PIN walks the card's clock with real block headers | **Bounded by the rollover budget** (2.0) | Real headers are free, so in 1.20 every header a day later began a new day and a new limit. In 2.0 the window rolls at most the rollover budget's times (default 7) between the owner's `REFRESH`es; past it the day stands. The no-PIN allowance renews only once per arming (a PIN or an owner's proof), so a reader with no PIN gets one allowance per arming. [D20](DECISIONS.md#d20). **The cost:** the bound also binds the holder. In 1.20 a holder who lost the owner key could still spend the card down a limit a day; in 2.0, with no owner's proof to refresh the budget, the window stays where it is after the budget's rolls, and a balance over about (budget + 1) daily limits is stranded for good. A card with no daily limit is not affected. |
| 18 | An unowned empty card is claimed by the first phone that sets it up | **Accepted for v1** | A card out of its packet has no owner and holds nothing, so any reader in range can give it a PIN, a record and an owner of its own (`SET_OWNER`, no proof). Nothing is lost: the card cannot be loaded until it has an owner. A card set up in its holder's hands, by the holder's phone ("Set up this card"), is that holder's; cards issued by Flash leave the issuer owned or are set up at hand-over. A claimed card is reset by its claimant only. |
| 19 | Timing the card's signatures to learn its key | **Partially**: the multiplies only; not measured | `AUTH` gives any reader as many timed signatures as it asks for. The two byte-array field multiplies on the nonce and the key have no secret-dependent branch ([D21](DECISIONS.md#d21)). The modular reductions on the same path still do (`reduce512toModN`, `addModN`, `reduceModN`, `sub32`, `cmp32`; open item 5). The chip's EC and RSA engines, which do the point multiply, are NXP's. No timing has been measured on silicon. |

## The offline double-spend problem (#5)

The card marks a proof `SPENT` before releasing a signature, and no APDU can
unmark it. **That stops the card from spending twice. It does not stop anything
else.**

If an attacker copies a proof's data and separately obtains a signature over it,
they can redeem at the mint while the card still shows the proof unspent — or,
more simply, spend at an offline merchant who cannot check, then redeem the same
proof online before that merchant settles.

**This is inherent to every offline bearer instrument.** Physical cash addresses
it with anti-counterfeiting rather than double-spend detection, and so must this.

Practical mitigations, none of them cryptographic:

- The **mint is the final authority** — the second redemption fails.
- **Terminals should settle promptly** on regaining connectivity. Settlement lag
  is exactly the exposure window.
- **Online terminals must call `checkProofStates`** before accepting. There is
  no excuse when connectivity exists, and `cashu-client` treats `PENDING` as
  not-spendable for the same reason.
- **Keep card balances small.** The loss ceiling is the card balance.

Any claim that this design has "zero double-spend risk" is false. One external
documentation contribution asserted exactly that, which is part of why this
document exists.

## Mint solvency (#8)

A bearer proof is a claim on the mint. If the mint cannot honour it, the proof
is worthless regardless of how sound the cryptography is.

This is not hypothetical here. Flash Forge was found **insolvent** — roughly
$831 of outstanding bearer promises against $0.13 of backing — because the
Lightning backends had been drained while the ecash stayed in circulation.

Current controls:

- **[Public reserves attestation](https://forge.flashapp.me/reserves)**, refreshed
  every 15 minutes, comparing outstanding liability against real backend balances.
- **Automated solvency monitoring** with alerting, per unit.
- The mint's sat reserve is a **self-hosted phoenixd node** rather than a
  third-party custodial account.

Honest limits: this is an **operator attestation**, not a trustless proof of
reserves. A holder cannot cryptographically verify it. Signed attestations from
the reserve wallets would be the next step.

## The PIN, the owner, and the blocked PIN (#2, #14)

**2.0's rule: the PIN spends, and the owner administers** (`FOXY-CARD-SPEC.md`
5.3 rule 7, [D18](DECISIONS.md#d18)). A payment is asked its PIN at the
signature (`SPEND_ALL_SIGN`), not when it is begun, because what leaves the card
is only known there. A card with a PIN signs without it only up to the no-PIN
allowance the owner has set, and answers `6A94` over it, for the whole payment. A
card with no PIN signs under its daily limit and its limit on one payment, and is
cash to whoever holds it. The PIN is asked before the limits, so a reader with no
PIN cannot fill the card's log. `FOXY-CARD-DAILY-LIMIT.md` 6f has the whole.

Everything else is the owner's: changing the PIN, the limits, the record or the
owner, adding funds with no PIN, refreshing the card, locking or resetting it. Each
needs an ECDSA proof by the owner's P-256 key over a label, a fresh nonce and the
value, which only the holder's phone can make. A terminal that has been handed the
PIN cannot set a PIN of its own, change a limit, or take the card over by emptying
it: a card with an owner is its owner's, empty or not.

**A blocked PIN is the owner's to unblock (#14).** Three wrong PINs, from any reader
in range, block the card; every PIN gate then refuses, and the card has no no-PIN
allowance. The owner's `CHANGE_PIN` sets a new PIN with no old one, which unblocks
it. The PIN state byte is the PIN's commit: a `CHANGE_PIN` torn between the PIN and
the byte leaves the card blocked, and the owner sends it again
([D22](DECISIONS.md#d22)). A card whose owner has lost the seed cannot be
unblocked, and its balance is stranded: nothing but the card key signs for its
pieces, and their dated refund path is switched off in the apps for now
(`FOXY-CARD-SPEC.md` 6).

**The ENG-615 lesson holds.** 0.x builds before 0.3 gated with `pinState == 1`, so
a blocked PIN *removed* the gate; and a failed check left a verified session
verified. 2.0 gates whenever a PIN exists in any state, refuses state 2 even under
a verified flag, and a failed check ends the session. Foxy's suite walks every gated
command through every PIN state.

**0.x cards.** A card on the 0.x applet (`SELECT` answers `00 0X` under
`D2 76 00 00 85 01 02`) does not answer the 2.0 AID; both apps show "This card
needs an update" and neither spends from it. Its balance is swept with the 0.x app
releases before it is reinstalled ([`HARDWARE_DEPLOYMENT.md`](HARDWARE_DEPLOYMENT.md)).
The 0.x threats (`SIGN_ARBITRARY`, the reader-chosen `SPEND_PROOF` message, the
PUK's custody) end with the 0.x wire.

## The NFC tag (#15, software 1.19)

From software 1.19 the card also answers as an NFC Forum Type 4 Tag carrying one web
address, so that a phone with its screen on offers to open it (`FOXY-CARD-SPEC.md` 5.8).

**What it reveals: nothing of the card.** The two files a reader can read are constants of
the applet, the same on every card (the capability container, and a message of 22 bytes
whose address is `https://getfoxy.io/card`). Nothing of the card's key, its owner, its PIN
state, its limits or its balance is in them or can be reached through them: the tag applet
holds no reference to the card's applet, keeps no state but the file chosen, and writes
nothing (every instruction that writes is `6982`). It asks the card's applet one question,
whether the tag is on, through a shareable interface of one method that answers a boolean
and is not exported to any other package. The address could not be per card without
becoming an identifier that anyone with a phone could read with no PIN; that is why it is
not, and a change that made it so would be a regression of this property.

What a reader does learn is that the card has a tag application and that its address is
Foxy's page: it is a card made for Foxy. Its other name, the card applet's, can be selected
by anyone as well and answers its version, so this adds little.

**Who holds the switch.** The owner, by the owner's proof under its own label
(`FoxyCard/tag`), with no PIN. A terminal that has been handed the PIN cannot turn the tag
off or on, and a wrong proof costs no PIN try. A locked card refuses the command, so a
locked card's tag stays as it was. `RESET_CARD` puts the tag back on. The switch is not a
security control for the money: it exists so that a card kept in a phone's wallet case does
not raise the offer every time the screen wakes. Off, the tag application refuses its
name, and nothing else about the card changes.

**A card left on factory keys.** Anyone with a reader and a card on factory keys can delete
the card's applet and the money with it (`FOXY-CARD-SPEC.md` 5.4). They can equally delete
the tag's applet and install another in its place, under the same name, carrying another
address, so that a phone that reads the card is sent somewhere else. Rotating the card
manager keys (or locking the issuer domain) closes both, and it is part of set-up for the
cards that are given to people.

## The mint's proof kept with each piece (#16, software 1.20)

From software 1.20 the card keeps, for a piece that is loaded with one, the mint's NUT-12
proof: `e`, `s` and the blinding factor `r`, 96 bytes. `GET_DLEQ` gives it back, with no
PIN, for an unspent piece (`FOXY-CARD-SPEC.md` 5.9, [D17](DECISIONS.md#d17)).

**What "real" rests on.** A phone that reads a piece and its proof can rebuild the piece's
secret, work out `C'` and `B'`, and check the proof against the mint's public key for the
amount. A piece that passes was signed by that key, over that secret. So "this piece is
real" rests on two things the reader has: the mint's keys, and the check it makes. It does
not rest on the card, which checks nothing and hands back what it was given, and it does not
rest on whoever loaded the card. A terminal that writes a piece with a made-up `C`, and any
proof it likes, makes a piece that fails the check: nobody without the mint's key can make a
proof that passes. A real piece copied from another card fails too, since its secret names
that card's key.

**What it does not show.**

- That the piece is unspent. Only the mint knows, and a copy of a real piece passes the
  check as the real piece does (#5).
- That the mint will honour it (#8).
- That a piece with no proof is fake. A piece put on plain, or a card of earlier software,
  is "not shown real", and the reader decides what that means to it.
- Anything, to a reader that does not check. The card does not refuse a piece whose proof
  fails or is missing, and a terminal with the PIN can still write a piece the mint will
  refuse (`FOXY-CARD-SPEC.md` 10). What changed is that a reader can now tell.

**What it costs: `r`.** The proof carries the blinding factor. The mint made its signature for
`B'`, and given `r`, whoever has the mint's record of that issue can recompute `B'` and `C'`
from the piece and tie the piece to the request that made it. That is so of any NUT-12 token
that carries `r`; here, any reader can read `r` for every unspent piece that has a proof,
with no PIN, as `GET_CHANGE` already gives it for the change the card made for itself. A
reader that hands `r` to the mint lets the mint make the tie; one that checks on its own
side and sends the proof nowhere does not. The money is as safe as it was: a piece is
spent only with the card's signature, and nothing here gives that.

**The store.** One persistent array of 12,288 bytes, reserved by the first `SET_CARD` and
not at install, because the chip will not install an applet that asks for that much more in
its constructor (`FOXY-CARD-HARDWARE.md`). A card that is refused it works without. A place
that is unspent holds its own proof or zeros and never another piece's: `LOAD_PROOF` writes
the record before the place's data and the status byte last, `CLEAR_SPENT` and the payment
commands write nothing to the store, and `RESET_CARD` zeros it. A card taken away in a load
leaves an empty place with a record beside it, which nothing serves.

## What has and has not been tested

**Verified in simulation (jCardSim) and by construction:**
- BIP-340 signatures verify against an independent verifier and the spec's own vectors
- Modular arithmetic matches `BigInteger` across random and edge inputs
- Slot lifecycle, PIN gating, APDU encodings
- The tag (1.19), byte for byte, the switch and its refusals, and that nothing the tag
  says differs between two cards
- The mint's proof kept with a piece (1.20): given back as it was loaded, never served for
  a spent, empty or plain place, and never another piece's through any long history of
  loads, payments and clears; every refusal of the load with nothing written; no payment
  command writing the store; the store null after install and made by the first
  `SET_CARD`; the order of the writes and the torn states. A reader's check of the proof is
  not the card's and is tested where the reader is
- The blocked PIN: every gated command refuses, before and after further PIN
  attempts, and a failed PIN check ends the session; the owner's `CHANGE_PIN`
  unblocks; a torn `CHANGE_PIN` stays blocked (2.0, D22)
- The clock walk (2.0, D20): along real mainnet headers, a terminal with the PIN
  gets the found day and the rollover budget's days and no more; `REFRESH` fills the
  budget; the no-PIN allowance renews once per arming; an anchored owner's clock is
  never 0; a payment that moves no value rolls nothing, and a `SET_LIMIT` without
  the budget's byte leaves the budget (2.1, D26)
- The field multiplies against `BigInteger` on operands full of zero bytes, and a
  source scan for secret-dependent branches in the two multiplies (2.0, D21); the
  reductions' branches are listed as open (item 5), and a scan holds the list to
  the source
- A `SIG_ALL` payment through the bridge, with the card's own change, swapped at a
  Nutshell 0.20.3 mint, with the mint's DLEQ checked from what the card keeps (CI),
  once on forge's keyset shape (an 8-byte id, no fee) and once on a v2 keyset (a
  33-byte id, a fee of 100), each length asserted
- DLEQ verification, including the tagging attack it exists to catch
- NUT-11 witness checks: wrong key, wrong proof, corrupted signature, `n_sigs`

**Run on silicon** (NXP JCOP4 J3R180, 2026-09-22/23, recorded in the
[hardware report](HARDWARE_TEST_REPORT_2026-09-22.j3r180.md); applet 0.1, then
0.2 for the D13 probes):
- `cardctl selftest`: card signatures verify under BIP-340, and two signatures
  over the same message use different nonces
- Load, spend, swap and NUT-05 melt against the project mint, and a spend from
  the merchant terminal
- `SET_PIN`, `VERIFY_PIN` (wrong, then right) and `CHANGE_PIN` with the right
  current PIN
- The unverified-session gate: `LOAD_PROOF` and `CLEAR_SPENT` refuse on 0.1,
  `SPEND_PROOF` refuses on 0.2
- The tag (1.19): installed under the NFC Forum's name beside the card's applet,
  read from outside as a phone reads it, and read by a phone, which offered its
  address
- The mint's proof (1.20): the build installs, the first `SET_CARD` is given the
  store after the install, a piece loaded with a proof gives the same 96 bytes
  back, a plain piece and a place used again read `00`, a payment and a reset go
  through, and `GET_INFO` is the length it was (`tools/chip/proofstore.sh`, 27
  checks). Not run there: a card pulled away during the first `SET_CARD` or a
  load with a proof, and the time a phone takes to load one piece a command

An earlier card, a J3R452 on applet 0.1, ran the read and sign path on
2026-09-01 ([its report](HARDWARE_TEST_REPORT_2026-09-01.j3r452.md)).

**Not yet run on silicon:**
- The tag's switch (1.19): `SET_TAG` on a card, and with it the shareable lookup
  between two applets of one package
- A blocked PIN on any build: neither ENG-615 nor its 0.3 fix (the
  blocked-state gate and the failed-check session rule) has run on a card
- The 2.1 build on a card: its load file is a size the J3R180 has not been
  tried at (the 2.0 build installed, [D25](DECISIONS.md#d25))
- `REFRESH`, the anchored `SET_OWNER` and the rollover budget on a card
- `LOCK_CARD`, deliberately not run on a card holding value
- EEPROM wear and lifetime
- A card pulled mid-write: the slot write order ([D14](DECISIONS.md#d14)) is
  scanned in the source and its torn states tested in jCardSim, but no card
  has been torn on purpose; power glitches short of a clean tear are
  unanalysed
- Timing/side-channel characteristics of the hand-rolled modular arithmetic
- RF range, and whether a drain attack is practical at distance

**Two bugs found in review were invisible to the simulator and would each have
been fatal in the field:** a dropped carry in the modular reduction that made
every signature invalid, and an EEPROM leak that would have bricked cards after
a few hundred taps. Treat simulator results accordingly — see
[D10](DECISIONS.md#d10).

## Open items

1. **2.0 on silicon** — install the 2.0 CAP on the J3R180, `cardctl selftest` and
   `--timing` (the multiply changed, D21), then the field-card sweep and reinstall
   (`HARDWARE_DEPLOYMENT.md`). Operator-run, with the card.
2. **Tear-off on silicon** (#11) — the write orders are analysed and enforced
   ([D14](DECISIONS.md#d14), [D23](DECISIONS.md#d23)); pulling a card mid-load,
   mid-clear, mid-payment and mid-`CHANGE_PIN` on hardware is still owed.
3. **Recovery** (#3) — the dated refund path is in the applet and switched off in
   the apps; see [D5](DECISIONS.md#d5) and `FOXY-CARD-SPEC.md` 6.
4. **Card attestation** (#13) — no proof a key was generated on-card by genuine
   firmware.
5. **Side-channel review** of `SchnorrHW` — the modular arithmetic was written
   for correctness. Since 2.0 the two byte-array multiplies (`mul256x256`,
   `mulByDelta`) have no secret-dependent branch ([D21](DECISIONS.md#d21)).
   The reductions on the signing path still branch on values derived from the
   key and the nonce, and are open:
   - `reduce512toModN`, over e·d: the carry fold's `while (carry != 0)` and the
     final `while (cmp32(out, N) >= 0)` subtract;
   - `addModN`, over k + e·d: the subtract of n on `carry != 0 || cmp32(out, N) >= 0`;
   - `reduceModN`, over k: the subtract of n on `cmp32(k, N) >= 0`;
   - `sub32`: a branch on each byte's borrow;
   - `cmp32`: returns at the first byte that differs;
   - `mulSmallByDelta`: an `if` on each byte of its overflow check (never taken
     for any input the reduction makes).

   The fix is a fixed-iteration reduction with masked subtracts, scanned in the
   source as the multiplies are (`SchnorrHWMathTest` holds this list to the
   source). Nothing has been measured on silicon, and the chip's own EC and RSA
   engines are not ours to analyse.
6. **Trustless proof of reserves** — upgrade the attestation to signed
   statements from the reserve wallets.

## Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md). Please do not open a public issue for
anything affecting funds.
