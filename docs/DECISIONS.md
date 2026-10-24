# Design decisions

Each entry records a call that was made, what was rejected, and why. If you are
about to change one of these, read the entry first — most were made against a
real alternative, and several were made *after* getting it wrong once.

Anchors are stable (`#d1` … `#d26`); other docs link to them. D15 and D16
are superseded by the 2.0 merge ([D18](#d18)) and kept for the record.

---

## <a id="d1"></a>D1 — Cashu ecash, not BoltCard

**Rejected:** NTAG 424 DNA + AES-128 CMAC, per **FIP-04 (Implemented)**.

A BoltCard authenticates *who is tapping* against a server-side balance. It
cannot work offline, because the terminal must reach the server to learn whether
the balance exists.

Cashu proofs are bearer tokens: valid because they carry the mint's blind
signature, verifiable by arithmetic rather than by asking a server. That is what
buys offline payment, and offline payment is the requirement that started the
project ([`VISION.md`](VISION.md)).

**Cost accepted:** a far more demanding chip (secp256k1 rather than AES), higher
unit cost (~$5 vs ~$1), and the offline double-spend exposure in
[`SECURITY-MODEL.md`](SECURITY-MODEL.md). `btcpayserver-flash-plugin` is being
decommissioned as a result (ENG-176).

---

## <a id="d2"></a>D2 — No cardholder identity, ever

**Rejected:** name, card number, PIN-on-spend by default, remote freeze, recovery.

The card is cash. Each of those features is individually reasonable and
collectively turns the product into a debit card with extra steps — at which
point Flash is custodial again and the reason to exist is gone.

This is why the physical card says **"BEARER CARD"** rather than leaving the
name field blank: it is a statement, not an omission
([`flash-card-assets`](https://github.com/lnflash/flash-card-assets)).

**Consequence to accept:** lost card = lost funds, and the card says so in plain
language on the back. That copy is deliberate and is not to be softened without
sign-off.

---

## <a id="d3"></a>D3 — The card does no BDHKE

**Rejected:** blinding/unblinding on-card.

JavaCard has no big integers, no `long`, and no garbage collector. Implementing
blinding on-card would multiply applet size and attack surface to protect
something that is not secret — and the host must know the blinding factor `r`
anyway in order to unblind.

The card holds the one thing that genuinely cannot live elsewhere: a private key
that has never existed outside the secure element. Everything else belongs on
the host.

---

## <a id="d4"></a>D4 — Proofs are P2PK-locked to the card key (NUT-11)

Without this, reading a card's memory would be equivalent to stealing its
balance — the proofs would be spendable by whoever copied them.

With [NUT-11](https://github.com/cashubtc/nuts/blob/main/11.md), a proof is
locked to a public key whose private half exists only inside the chip. A
passive dump yields proofs that cannot be redeemed.

**This is the decision that makes a bearer *card* possible** rather than merely
a bearer token. It is also why the provisioning host must know the card's public
key *before* minting: the lock is applied at issuance, not afterwards.

---

## <a id="d5"></a>D5 — No seed, no backup, no recovery

**Rejected:** BIP-39 seed derivation for the card key.

A recoverable card is a card whose funds exist somewhere other than the card,
which contradicts D2. It also means the recovery secret becomes the real
credential and the chip stops being the security boundary.

**This is the most-questioned decision, and the counter-proposal is good.**
[PR #4](https://github.com/cashucard/javacard/pull/4) proposed using NUT-11's
existing `refund` + `locktime` tags so a lost card's proofs can be swept to a
recovery key after a timeout — no applet key changes, no seed. It is the right
shape. It was closed unmerged on 2026-10-02, because it was written before
v0.2.0 and no longer applies, and because of a specific flaw: in NUT-11, once
locktime passes the *card's own key stops being valid*, so a short locktime
silently converts the card into a brick; and the card cannot enforce a timeout
because JavaCard has no clock, so a merchant would accept a tap that the mint
later refuses.

Since 0.3, a card whose PIN is blocked strands its balance too
([SECURITY-MODEL](SECURITY-MODEL.md) #14), so a refund path would rescue a
blocked card as well as a lost one.

If you want to solve recovery, start from that PR and that objection.

---

## <a id="d6"></a>D6 — JavaCard 3.0.5 is a hard floor

The Schnorr signer computes `k·G` using
`KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`. That constant **was introduced in
JavaCard 3.0.5 and does not exist in 3.0.4** — verified by inspecting the SDK
jars directly, not by reading a datasheet.

This invalidated the project's own prior documentation, which named Feitian
3.0.4 as the primary target and JCOP4 as a fallback. Every external
documentation contribution repeated that error, because the README told them to.

**Practical effect:** JCOP3, J3H145 and Feitian 3.0.4 parts cannot run this
applet at all. Confirm the platform version in writing before buying a tray.

---

## <a id="d7"></a>D7 — The client refuses locally rather than letting the mint refuse

`meltProofs` and `swapProofs` validate a proof's NUT-11 witness **before**
submitting, and return an error rather than forwarding a request the mint would
reject.

This looks like belt-and-braces. It is not. The ordering is asymmetric:

```
SPEND_PROOF  → card marks the slot SPENT, returns the signature   ← irreversible
meltProofs   → mint accepts or rejects                            ← too late
```

By the time a terminal is assembling a melt, **the card has already burned its
slot**. A mint-side rejection is not free — it costs the proof. Failing locally
leaves it intact.

The same reasoning drives `selectProofsForMelt` returning `null` rather than a
short selection, and the local witness check honouring `sigflag` and `n_sigs`:
**a check looser than the mint's passes locally and still burns the slot.**

---

## <a id="d8"></a>D8 — Melt and swap are not idempotent, and the API says so

There is no request-id or retry token. Inputs are consumed the moment the mint
accepts them, so a lost response is genuinely ambiguous.

The library does not paper over this. It documents that after a lost response
the correct move is `getMeltQuoteState` or `checkProofStates` — **never a
retry** — because a retry against a `PENDING` quote is how the same invoice gets
paid twice.

Related: `allProofsUnspent` returns `"UNSPENT" | "NOT_UNSPENT" | CashuMintError`
rather than a boolean. A boolean union fails open — `CashuMintError` is a truthy
object, so `if (await allProofsUnspent(...))` would read a mint timeout as
"safe to accept", inverting the double-spend check. This was a real bug, caught
in review.

---

## <a id="d9"></a>D9 — BIP-340 *default* signing, with auxiliary randomness

**Rejected:** a deterministic nonce derived purely from `(d, msg)`.

Deterministic nonces are attractive because they are testable against fixed
vectors. On a bearer card they are dangerous: a nonce that is a pure function of
key and message hands a fault-injection attacker two signatures over the same
`k`, and `d = (s₁−s₂)/(e₁−e₂)` falls straight out.

The signer therefore folds fresh aux randomness into the nonce, exactly as
BIP-340 specifies for default signing. **Signatures over the same message are
deliberately not reproducible**, which is why `cardctl selftest` checks that two
signatures over one message differ, and why the BIP-340 signing vectors cannot
be replayed against the card.

---

## <a id="d10"></a>D10 — Every buffer is allocated once, at install time

JavaCard Classic allocates `new` in **persistent EEPROM** and never collects it.
An allocation on the signing path is a permanent leak.

The original signer allocated 288 bytes per `sign()` call. A card would have run
out of persistent memory after a few hundred taps and been **permanently dead
for spending** — recoverable only by deleting the applet instance, which
destroys the stored proofs.

jCardSim cannot surface this: it runs on the JVM, with a heap and a garbage
collector. The suite was green. **A source-level scan now enforces the rule**,
because the runtime cannot.

The general lesson, which applies to every change in `applet/`: *a passing
simulator suite is not evidence about silicon.*

**One exception, since software 1.20 ([D17](#d17)):** the 12,288 bytes that hold
the mint's proofs are reserved by the first `SET_CARD`, not at install, because
the chip will not install an applet whose constructor asks for that much more.
The scan lets through that one statement and nothing beside it: it is guarded so
that it happens once in a card's life (`if (dleq == null)`), and a request the
card refuses allocates nothing, so it cannot leak a few dozen bytes a tap, which
is what the rule is for. A second allocation next to it, an unguarded one, and
the same statement in any other method are each still refused.

---

## <a id="d11"></a>D11 — DLEQ is verified client-side, and unlinkability is not assumed

A mint could sign one user's outputs with a key unique to them and recognise
those proofs on redemption, breaking the unlinkability that is the point of
ecash. [NUT-12](https://github.com/cashubtc/nuts/blob/main/12.md) DLEQ proves
the signature used the *published* key.

It is verified in `cashu-client`, in local arithmetic, with no mint contact —
which is what lets an **offline terminal** check a tap on arithmetic rather than
on faith.

The mint is trusted for solvency. It is explicitly *not* trusted for
unlinkability.

Since software 1.20 the card carries the proof with each piece ([D17](#d17)) so
that the check can be made on a piece read from the card. The card still checks
nothing: the verification is the reader's, as above.

---

## <a id="d12"></a>D12 — No PIN on spending, in the base profile (SUPERSEDED by D13)

`SPEND_PROOF` requires no authentication. `LOAD_PROOF`, `CLEAR_SPENT` and
`LOCK_CARD` are PIN-gated; spending is not.

That is bearer semantics: possession authorises payment, as with a banknote. It
is also the design's sharpest edge — **a hostile reader in range can drain a
card**, and the spec's Profile B+ (PIN-gated spending) is written but not
implemented.

This was a genuine open product decision, tracked against the same fraud
finding that covers the current Flashcard's re-link gap (ENG-209).
**Resolved by [`D13`](#d13): spending is PIN-gated when a PIN is set.**

---

## <a id="d13"></a>D13 — PIN-gated spending on personalised cards (supersedes D12)

`SPEND_PROOF` and `SIGN_ARBITRARY` are PIN-gated **when a PIN is set**;
`VERIFY_PIN` in the same NFC session authorises both. `LOAD_PROOF`,
`CLEAR_SPENT` and `LOCK_CARD` keep their existing gate. Cards provisioned
without a PIN keep the D12 tap-and-go behaviour.

This resolves the open decision D12 deferred (Profile B+; ENG-209): the pilot
chose Visa-style authorisation — possession **and** knowledge authorise
payment — because a hostile reader in the D12 model could drain a card it was
presented, and because POS cards now ship PIN-set by default.

Why `SIGN_ARBITRARY` is gated with it: the signature is a spend authorisation
under the card's key (it is the recovery path's witness material), so an
unverified session must not be able to mint one — otherwise the spend gate is
theatre.

Burn ordering is unaffected: the gate is the first statement of the spend
handler, so a wrong or missing PIN throws `6982` **before** the slot burn —
no proof is consumed on a failed authorisation.

**Lockout semantics (pilot):** `PIN_MAX_TRIES` (3) exhausted → `6983`, the
card's PIN-verified operations are dead, and there is **no unblock path** in
this profile — a blocked card is replaced at re-provisioning. An
`UNBLOCK_PIN` command gated by a provisioning PUK is the designated follow-up
**before volume issuance**; do not ship consumer cards at scale without it.

**Resolved by [`D16`](#d16): `UNBLOCK_PIN` gated by a provisioning PUK, applet 0.6.**
A card personalised with a PUK is no longer replaced when its PIN is blocked;
one without a PUK still is, and the lockout paragraph above describes it.

*Correction (ENG-615, after v0.2.0):* "dead" was not what the applet did. The
gate checked `pinState == 1`, and a blocked card has `pinState == 2`, so
exhausting the tries **removed** the gate: every PIN-gated command opened up
to whoever held the card, while `VERIFY_PIN` and `GET_INFO` kept reporting it
blocked. `CHANGE_PIN` had the mirror bug — its failed checks decremented the
counter without ever setting `pinState`, leaving a card that reported "set"
but could never verify. And no failed check ended the session, so a session
that had verified stayed verified through later wrong PINs, including the
ones that blocked the card. All three are fixed in applet 0.3: the gate fires
whenever a PIN exists in any state; one helper owns the blocked transition for
every PIN check; and a failed check ends the session's verification, as
`OwnerPIN.check` does for its own validated flag. That last rule also means
`CHANGE_PIN` can no longer exhaust the counter: it needs a verified session,
and the `VERIFY_PIN` that opens one resets the counter.

The fix changes wire behaviour, so the applet version moved to 0.3. Every 0.1
and 0.2 build has the same `pinState == 1` gate on `LOAD_PROOF`, `CLEAR_SPENT`
and `LOCK_CARD`, and 0.1 builds from before D13 gate no spend at all, so a card
whose `SELECT` answers anything below `00 03` (`00 01` or `00 02`) needs the
CAP reinstalled. There is no proof-preserving upgrade, so sweep first: the
reinstall regenerates the card key. [D14](#d14) later moved that floor to
`00 04`.

"Dead" also means **stranded**. Nothing but the card key can sign for the
card's P2PK-locked proofs, so a blocked card's balance is unrecoverable, and
`VERIFY_PIN` is unauthenticated: any reader in range can block a card with
three APDUs ([`SECURITY-MODEL.md`](SECURITY-MODEL.md) #14). That loss is what
`UNBLOCK_PIN` + PUK (ENG-617) had to remove, and [D16](#d16) does, for every
card that was given a PUK at personalisation.

Provisioning: POS cards are personalised with a PIN by default
(`cardctl set-pin` during personalisation; `fund-card --pin` when the funding
tool gains it). The merchant terminal prompts for the PIN only when
`GET_INFO.pinState` reports `set`, and refuses a card reporting `locked` (2)
outright: nothing can spend from it. Since applet 0.5 a holder can take the
PIN off again ([D15](#d15)), so the terminal reads `pinState` on every tap.

---

## <a id="d14"></a>D14 — A slot's status byte is its commit, written last

A proof slot is `status ‖ keyset ‖ amount ‖ nonce ‖ C`, and every reader trusts
the status byte: `GET_BALANCE` sums the UNSPENT slots and `SPEND_PROOF` signs
for them. So every write to a slot changes its data first and its status byte
last, as a single byte, which the JCRE writes atomically. A card that leaves
the field mid-write leaves the slot with its old status, never a new status
over old bytes:

- `LOAD_PROOF` copies the proof (`Util.arrayCopy`, atomic into persistent
  memory), then sets UNSPENT. Torn before the commit, the slot is still EMPTY:
  no command reads it, and the next `LOAD_PROOF` overwrites it.
- `CLEAR_SPENT` zeroes a spent slot's data, then sets EMPTY. Torn mid-fill (the
  fill is not atomic), the slot is still SPENT: never counted or signed for, and
  the next `CLEAR_SPENT` finishes it. Until then `GET_PROOF` still returns it,
  with some fields zeroed, and its data is not a proof: see
  [`spec/APDU.md`](../spec/APDU.md#clear_spent-0x31) for what a reader
  checks. An EMPTY slot never holds a spent proof's bytes.
- `SPEND_PROOF` writes only the status byte ([D7](#d7)).

**Rejected:** a `JCSystem` transaction around each write. The order alone gives
the guarantee, and a transaction around the old handlers would not have given
it: the old `CLEAR_SPENT` filled the whole slot, status byte included, with
`Util.arrayFillNonAtomic`, which does not use the transaction facility even
while a transaction is in progress. Torn inside a transaction as outside one,
that fill could leave an EMPTY status over a spent proof's bytes, the state
ENG-620's resurrection starts from. A transactional clear needs `Util.arrayFill`
(JC 3.0.5) in its place. Nor does the order keep `LOAD_PROOF` off the commit
buffer: its `Util.arrayCopy` is atomic into persistent memory and subject to the
same commit capacity a transaction uses (it can throw `TransactionException`).
The order does not rely on that atomicity, since a torn copy leaves the slot
EMPTY whatever its bytes hold, so `Util.arrayCopyNonAtomic` would be as safe
there.

*Found after v0.2.0 (ENG-620):* `LOAD_PROOF` set UNSPENT before it copied the
proof, and `CLEAR_SPENT` zero-filled from the status byte. A tear between
`LOAD_PROOF`'s two writes left an UNSPENT slot over the slot's old bytes:
usually zeros, a phantom proof of amount 0 that `CLEAR_SPENT` would not free
(it frees only SPENT slots) until a `SPEND_PROOF` burned it; after a torn
`CLEAR_SPENT` of the same slot, a spent proof's keyset, amount and C, which
`GET_BALANCE` counted and an offline terminal could accept and never settle.

jCardSim cannot tear a write, so `SlotWriteOrderTest` scans the source for the
order, as D10's allocation rule is scanned, and sets the torn states directly to
show what every command then does.

Outside a torn write nothing a reader sends or receives changes, but the applet
version moved to 0.4 anyway. No release carries the one 0.3 build with the old
order (`958a8baa…`), but it was `main`'s tracked CAP from `f889934` until this
fix, and whether a card was installed from it in that window could not be
confirmed. `SELECT`'s version is the only thing an installed card reports about
its build, so the 0.3 builds cannot be told apart: a card answering `00 03` may
run the old order. Keeping 0.3 and telling builds apart by the tracked CAP's
sha256 was rejected for that reason: the hash says which CAP to install, not
which one a card already runs. A card whose `SELECT` answers anything below
`00 04` needs the CAP reinstalled (sweep it first), and `cardctl selftest`
fails it ([`HARDWARE_DEPLOYMENT.md`](HARDWARE_DEPLOYMENT.md#install)).

---

## <a id="d15"></a>D15 — A holder can take the PIN off a personalised card (qualifies D13; SUPERSEDED by D18)

> **Superseded in 2.0 ([D18](#d18)).** `CLEAR_PIN` is gone with the 0.x wire.
> On the shared protocol the owner key is the authority above the PIN: the
> owner's proof changes or removes it. The entry below is the 0.5 record.

`CLEAR_PIN` (`0x43`, applet 0.5) removes the PIN from a card that has one.
The card goes back to where `SET_PIN` found it: `pinState` 0, a fresh try
counter, every gated command open with no PIN, `VERIFY_PIN` answering `6984`,
and `SET_PIN` allowed again. D13 stays the default — POS cards still ship
PIN-set, and nothing but this command, sent by someone who has verified the
PIN in the same session and presents it again, takes a PIN off. This adds an
explicit, PIN-authenticated way out; it does not reopen D12.

Why a holder wants it: the card is cash ([D2](#d2)), and the PIN is the
holder's choice of how much that cash should behave like a banknote. A card
handed to someone else, a small-balance card for a tap-and-go merchant, a
card whose holder decides the D13 prompt costs more than the D12 exposure
it closes — each is the holder's call, on their own money, and before 0.5
the only route was a reinstall, which regenerates the card key and strands
the balance ([D5](#d5)). An owner who can set a PIN and cannot remove it is
holding a card with a feature they cannot turn off.

**Rejected:**

- *`SET_PIN` re-callable, or `CHANGE_PIN` with an empty new PIN.* Both
  overload a command that means something else; a reader that sends one
  expects a PIN to exist afterwards. Clearing is its own instruction, with
  its own capability bit (byte 6 bit 3), so a reader can tell from `GET_INFO`
  whether the card answers it or `6D00`.
- *Clearing on the verified session alone, without the PIN in the data
  field.* The session flag is the card's own, but the command that removes
  the one gate on the money asks for the PIN again, as `CHANGE_PIN` does
  before it replaces it. A wrong PIN here costs a try through the same
  helper (`failPinCheck`), so `CLEAR_PIN` is no cheaper to guess against than
  `VERIFY_PIN`, and like `CHANGE_PIN` it cannot be the try that blocks the
  card: the failure ends the session, and the `VERIFY_PIN` that reopens one
  resets the counter.
- *Clearing a blocked PIN.* This is the ENG-615 lesson, and the line this
  command must not cross. State 2 is reached by three unauthenticated APDUs
  from any reader in range; a `CLEAR_PIN` that took a blocked card to state
  0 would be the unblock path D13 says does not exist, handed to whoever
  blocked it — three wrong PINs, then a clear, then a spend. The gate is
  `requirePinVerified`, which a blocked card can never pass, so state 2
  answers `6982` with the right PIN, in this session and the next. The test
  for it sends exactly that sequence. The stranded-balance problem ([D13](#d13),
  [SECURITY-MODEL #14](SECURITY-MODEL.md)) was `UNBLOCK_PIN` + PUK's
  (ENG-617) to solve, not this command's; [D16](#d16) solves it.

The write is one byte: `pinState` to 0, after the check — the byte `SET_PIN`
writes last, the other way. The JCRE writes a byte atomically, so a card pulled
mid-command is PIN-set or it is not; there is no state between. The try
counter needs no write of its own: `OwnerPIN.check`'s contract is that a
match sets the validated flag and resets the tries remaining, so the
successful check `CLEAR_PIN` runs just before the write has already left
the counter at its limit, and the card leaves as `SET_PIN` found it with
`pinState` the only persistent byte the command touches.

*Corrected before merge:* the first draft followed the byte with
`OwnerPIN.resetAndUnblock()` inside a `JCSystem` transaction and described
the order of the two as load-bearing, as [D14](#d14)'s is. It was not. The
reset re-filled a counter the check had already filled, so neither tear it
guarded against — state 0 over a stale counter, state 1 over a fresh one —
could happen; the "fresh counter" is one the holder had already earned by
verifying. A write order documented as a guarantee when it is not is worse
than none, since the next change protects the wrong thing, so both calls
went and `ClearPinTest` now scans for the opposite: the check precedes the
write, and the state byte is the only persistent write. The test still sets
`pinState` 0 over a partly spent counter and shows nothing reads it
(`VERIFY_PIN` stops at `6984`; the next `SET_PIN`'s `OwnerPIN.update`
starts its PIN at the full count), as a property of state 0 the applet must
keep, not a state `CLEAR_PIN` can leave.

Readers: `pinState` 1 is no longer a one-way state, so a terminal reads
`GET_INFO` byte 7 on every tap rather than remembering a card as PIN-set.
`cardctl clear-pin --pin` drives it (`VERIFY_PIN`, then `CLEAR_PIN`); `info`
names the capability. flash-mobile's card screen is the follow-up: a
"Remove PIN" action behind the PIN prompt, offered only when byte 6 bit 3 is
set.

The applet version moved to 0.5: a new instruction and a new capability bit
are wire-visible, and a 0.4 card answers `0x43` with `6D00`. A 0.4 card is
not vulnerable and need not be reinstalled; it lacks the feature. 0.5 is a
fresh install (delete + install, sweep first), as every applet version is —
there is no in-place upgrade.

---

## <a id="d16"></a>D16 — A provisioning PUK unblocks the PIN (resolves D13's lockout; SUPERSEDED by D18)

> **Superseded in 2.0 ([D18](#d18)).** The PUK is gone with the 0.x wire. A
> blocked card is unblocked by the owner's proof (`CHANGE_PIN`, which needs no
> old PIN), from the holder's phone. The entry below is the 0.6 record.

`SET_PUK` (`0x44`) gives a card a PUK, once, at personalisation. `UNBLOCK_PIN`
(`0x45`) replaces the PIN — blocked or forgotten — on presentation of that
PUK, with no session and without consuming it. Applet 0.6, capability bit 4,
GET_INFO byte 8 for the PUK state (0 unset, 1 set, 2 exhausted). This is the
follow-up D13 named before volume issuance: three unauthenticated APDUs no
longer destroy a card's balance, provided the card was given a PUK and the
PUK was recorded.

**The ENG-615 line holds.** A blocked PIN gates every command until
`UNBLOCK_PIN` succeeds, and `UNBLOCK_PIN` is the only path out of state 2.
`CLEAR_PIN` still refuses it ([D15](#d15)), `SET_PIN` still refuses it, and
a wrong PUK leaves it exactly as blocked. State 1 goes to 1 and state 2 to
1: to the holder a forgotten PIN and a blocked one are the same problem, so
the card does not tell them apart either.

**Custody is off the card, and not the applet's question.** The card never
reveals the PUK, so the personaliser generates it and records it at the
moment `SET_PUK` succeeds; the backend card registry (ENG-618) is its
designated home, releasing it to the card's owning account after
authentication. The applet assumes nothing about where the PUK lives, only
that `UNBLOCK_PIN` is answered by whoever presents it. That is the trade:
the PUK is a PIN bypass for that one card ([SECURITY-MODEL #16](SECURITY-MODEL.md)),
so the card's recovery is exactly as safe as the registry's custody, and a
PUK recorded nowhere is a card that is still a 0.5 card.

**Who may set it.** `SET_PUK` is free on a card with no PIN (the
personalisation order: `SET_PUK`, then `SET_PIN`), needs the holder's
verified session on a card with one (`SET_PIN`, `VERIFY_PIN`, `SET_PUK`),
and is refused on a blocked card in every session, because the session gate
is one a blocked card never passes. Without that, a reader in range could
attach a PUK of its own to a personalised card, block the PIN with three
guesses, and unblock it with the PUK it chose; or block first and attach
second. A PUK is set once: not changed, not replaced, not re-armed.

**Ten tries, then terminal.** The PUK is 8–12 digits, longer than the PIN
because it is the credential that replaces the PIN, and it has ten tries
because it is presented by a tool from a registry, not typed at a POS, so a
slip is cheap and a guess still has at most ten attempts at 10^8 or more
([SECURITY-MODEL #15](SECURITY-MODEL.md)). A wrong PUK answers `63 CX` with
the PUK tries left; the exhausting try answers `63 C0` (not `6983`, so a
reader counting down sees zero) and sets byte 8 to 2, after which
`UNBLOCK_PIN` is `6983` for good and `SET_PUK` is `6A89`. Exhaustion costs
the recovery path, not the balance: a card whose PUK was guessed at ten
times is a 0.5 card, stranded only if its PIN is then blocked. The
alternative — `SET_PUK` allowed again after exhaustion, in a verified
session — was rejected because the card cannot tell the holder re-arming
their own card from the thief who exhausted the PUK and then guessed the
PIN; a terminal state at least tells the holder, through byte 8, that this
card should be swept and replaced.

**Why state 0 is refused.** `UNBLOCK_PIN` on a card with no PIN answers
`6984`. There is nothing to unblock, `SET_PIN` is the way to a PIN there, and
letting the PUK set a first PIN would make `UNBLOCK_PIN` a second `SET_PIN`
with a different gate. One command per transition.

**Rejected:**

- *A PUK the holder chooses, or one the card shows once.* Either puts the
  PUK where the PIN is, on the holder, and a credential the holder loses
  with the PIN is no recovery. Generated by the personaliser, recorded by
  the registry.
- *Unblocking on the verified session, or `CHANGE_PIN` from a blocked
  state.* A blocked card grants no session; that is D13 and ENG-615. The
  PUK is a second credential precisely because the first is gone.
- *`UNBLOCK_PIN` opening a session.* It proves the PUK, not the new PIN. The
  holder's first `VERIFY_PIN` with the new PIN is the first time that PIN is
  known to work, and a terminal that got a session from the registry's
  credential rather than the holder's would be spending on the registry's
  authority.
- *`pin.resetAndUnblock()` before `pin.update()`.* `OwnerPIN.update` resets
  the try counter itself — the contract `SET_PIN` after `CLEAR_PIN` already
  rests on — so the reset would re-fill a counter the next call re-fills, and
  [D15](#d15) records why a redundant counter write is worse than none.
  `PukTest` scans for its absence.
- *A `JCSystem` transaction around the PIN write and the state byte.* The
  state byte is the commit ([D14](#d14)): `VERIFY_PIN` now refuses state 2 on
  its own, not only an empty counter, so a card torn between the two is
  state 2 over a fresh PIN, gated everywhere, and finished by the next
  `UNBLOCK_PIN`. The order gives the guarantee; a transaction would give the
  same one at the cost of commit-buffer space on every unblock.

**The write orders.** `SET_PUK`: PUK value, then byte 8 = 1. A tear leaves a
PUK nothing reads (`UNBLOCK_PIN` stops at state 0), overwritten by the next
`SET_PUK`. `UNBLOCK_PIN`: PUK check, then the new PIN with its full counter,
then byte 7 = 1. A tear leaves state 2 over the new PIN, refused by
`VERIFY_PIN` on the state byte, finished by the same PUK. `failPukCheck`:
the counter (decremented inside `OwnerPIN.check`), then byte 8 = 2. A tear
leaves state 1 over an empty counter, which the next `UNBLOCK_PIN` turns
into `63 C0` and the 2 — never a recovered try. `PukTest` scans the three
orders in the source and sets the three torn states directly.

Readers: byte 8 is read with byte 7 on every tap. A terminal shows a card
reporting `2 / 1` as recoverable and `2 / 0` or `2 / 2` as stranded.
`cardctl set-puk --puk [--pin]` and `cardctl unblock-pin --puk --new-pin`
drive the two commands; `info` names the capability and the PUK state;
`selftest` names `unblock-pin` on a blocked card whose PUK is set. The
follow-ups are the registry (ENG-618) and flash-mobile's unblock screen,
offered when byte 6 bit 4 is set and byte 8 is 1.

The applet version moved to 0.6: two new instructions, a capability bit and
a ninth GET_INFO byte are wire-visible, and a 0.5 card answers `0x44` and
`0x45` with `6D00`. A 0.5 card is not vulnerable and need not be reinstalled;
it lacks the feature, and so lacks the recovery. 0.6 is a fresh install
(delete + install, sweep first), as every applet version is — there is no
in-place upgrade, and so no way to add a PUK to a card in the field without
regenerating its key.

---


## <a id="d17"></a>D17 — The mint's proof is kept with each piece, reserved after install, one piece a command

**Decided:** from software 1.20 the card keeps, for each piece, the mint's NUT-12
proof as a later holder needs it: `e`, `s` and the blinding factor `r`, 96 bytes
(`GET_DLEQ`, `LOAD_PROOF` with `P1 = 1`: [`FOXY-CARD-SPEC.md`](FOXY-CARD-SPEC.md) 5.9).
The card does not check the proof and never uses it.

**Why the card carries it.** Without it a phone that reads the card can ask the
mint whether a piece is spent and cannot tell whether it is real: a made-up `C`
looks like any other until the mint is asked to take it. With it the phone checks
the piece itself, with the mint's keys, before it pays with the piece or takes it
in. The proof is made once, when the mint signs the piece, and the card is the one
place that can keep it with the piece.

**Why the card does not check it** ([D3](#d3), [D11](#d11)). The check needs the
mint's public key for the amount, which changes with every keyset, and the card
has no mint's keys and no room to keep a mint's directory. And a card that checked
would be one more thing to believe: a card that said yes is a card that could say
yes to anything. The reader that checks is the one that needs to know. So the card
stores the 96 bytes and gives them back, and a record of zeros means "no proof".

**Why after install and not in the constructor** ([D10](#d10)). The chip refused to
install a build whose constructor asked for 12,288 bytes more than 1.19's, and
installed one that asked for 300 more
([`FOXY-CARD-HARDWARE.md`](FOXY-CARD-HARDWARE.md)). The same bytes asked for by a
command after the install were given. No simulator has the limit, which is why it
is pinned by tests that read the source and look at the card (null after install,
reserved by the first `SET_CARD`). The reservation is guarded, so it happens once;
it is outside any transaction, so nothing can undo it; and if the card refuses it
the `SET_CARD` goes on and the card works as a card with no room for proofs. So
every use of the store is safe while it is null.

**Why one piece to a command.** A piece with its proof is 177 bytes, and a short
APDU carries 255. Two would not fit, and extended length is not something every
reader and phone will carry (the same reason a plain batch stops at three pieces
of 81 bytes). `LOAD_PROOF` with `P1 = 1` is one piece and its proof, and any
other P1 is the plain form it always was. A command to each piece is slower than
a batch of three (a batch took 0.19 s on the chip: [`FOXY-CARD-HARDWARE.md`](FOXY-CARD-HARDWARE.md));
the one-piece form has not been timed there.

**Why zeros are refused as a proof.** A record of zeros is how the card says "no
proof". If a load could store zeros and answer "kept", the answer would be false.
A proof of 96 zero bytes is `6A80`, as a `C` that is no point is.

**Why a piece's record is written first.** The rule is that a place that is
unspent holds its own proof or zeros and never another piece's. A freed place
keeps the record it had (`CLEAR_SPENT` and the payment commands write nothing to
the store: no write was added to a payment), so the next piece into it must write
its own record, or zeros, before anything else of the place, with the status byte
still last ([D14](#d14)). A tear then leaves an empty place with a record beside
it, which nothing serves.

**Why `GET_DLEQ` has no PIN, and gives nothing for a spent piece.** It gives what
the mint made for a piece that is already on the card for any reader to read
(`GET_PIECES` has the rest of the piece with no PIN). It gives the proof of an
unspent piece only: a spent piece's proof is of no use to anyone and is not given.

**Cost accepted:** `r` is in the proof, so a reader that hands the proof to the mint
lets the mint tie the piece to the request that made it, as with any NUT-12 token;
and the card gives `r` to any reader with no PIN
([`SECURITY-MODEL.md`](SECURITY-MODEL.md) #16). 12,288 bytes of the card's storage,
which the chip has.

---

## <a id="d18"></a>D18 — One card protocol with Foxy: their 1.20 is the base of 2.0

**Decided (ENG-673):** the applet in this repository is the Foxy wallet
project's fork ([getfoxy/card](https://github.com/getfoxy/card) at `88840aa`,
software 1.20), merged back with a real `git merge` so their history and
authorship stay in `git log`. Flash and Foxy speak one wire from here, called
**2.0**. The fork's applet, its tests, `spec/vectors/` and its documents
(`docs/FOXY-CARD-*.md`, `docs/FOR-LNFLASH.md`, `FORK.md`) came in as they were;
our `tools/cardsim` bridge and `tools/cardctl` were kept and ported to 2.0.

**Credit.** The fork's review of applet 0.4 (`docs/FOR-LNFLASH.md` section 3)
found the two weaknesses that mattered most here: `SPEND_PROOF` signed a hash
the reader chose, and `SIGN_ARBITRARY` signed anything without burning a slot,
so the card's SPENT flag protected nothing. Their applet fixes both (the card
builds and hashes each piece's secret itself; `AUTH` proves the card over a
tagged hash), adds an owner key, a daily limit with a clock taken from Bitcoin
block headers, NUT-11 SIG_ALL payments with change, and the mint's NUT-12 proof
kept with each piece. The design is theirs; the changes we made on top are D19
to D24.

**Superseded.** Our 0.5 `CLEAR_PIN` ([D15](#d15)) and 0.6 PUK ([D16](#d16)).
The owner key is the authority above the PIN: its proof changes the PIN with no
old PIN and unblocks a blocked card, from the holder's phone. A PUK in a
registry was a second bearer secret for the same job. Their suites are
ported to 2.0 under names for what they now test: `ClearPinTest` is
`OwnerPinRemovalTest` and `PukTest` is `OwnerUnblockTest` (D15 and D16 name
them as they were), and the cardsim's `VersionMaskTest` is `OldCardTest`.

**Rejected:** keeping 0.x and adding Foxy's fixes one by one. Two wires for one
kind of card, from two teams, would have stayed two; and the fixes are not
separable from the slot layout and the payment commands they change.

**Cost accepted.** 0.x cards cannot be updated in place: a card is reinstalled,
which makes a new key, so its balance is swept first (`HARDWARE_DEPLOYMENT.md`).
Both apps drop 0.x and say "This card needs an update" to a 0.x card.

**The hardware e2e tools stay 0.x.** The architect's decision 5 was to take
Foxy's `tools/e2e-melt.cjs` and `tools/e2e-redeem.cjs` as "already on their
wire" and delete ours. They are not on it: at `88840aa` both are byte-identical
to ours at `7a96102`, and both drive the 0.x applet's `SPEND_PROOF` through
cardctl's `spend`, which 2.0 removed. Neither tree has a 2.0 version. So they
are kept as 0.x tools for the one job left for them, the sweep of the funded
0.x field card before it is reinstalled (`HARDWARE_DEPLOYMENT.md`). Each
refuses to run unless `CARDCTL` points at a 0.x `cardctl.py`. The 2.0 e2e is
`tools/cardsim/e2e-swap.test.cjs`: one `SIG_ALL` signature and a swap at a real
mint, in CI. A 2.0 hardware e2e (melt and redeem over `SPEND_ALL_*`) is not in
this PR. It comes when a 2.0 card is on the bench.

---

## <a id="d19"></a>D19 — A neutral identity: AID F0 CASHUCARD, labels CashuCard/, version 2.0

**Decided (ENG-673):** the package AID is `F0 43 41 53 48 55 43 41 52 44`
("CASHUCARD" after the proprietary RID byte `F0`). Every instance AID derives
from it as Foxy's derived from `F0 FOXYCARD`: the opener `…4D`, the card's
applet `…01`, the tag's class `…54` (the tag is still instantiated under the
NFC Forum's own `D2 76 00 00 85 01 01`, which phones select). Every label and
tag that went into a hash or an owner's proof as `FoxyCard/…` is `CashuCard/…`:
`auth`, `seal`, `pinkey`, and the owner's `change-pin`, `set-limit`,
`set-owner`, `set-card`, `load`, `lock`, `reset` and `tag`. `SELECT` and
`GET_INFO` answer version `02 00`.

**Why a new AID and not either old one.** Our 0.x AID `D2 76 00 00 85 01 02`
sits under the NFC Forum's RID, which is not ours to allocate under; Foxy's
names one wallet. A proprietary `F0` AID that names the protocol belongs to
neither. And a new AID is what makes the change safe on the wire: a 0.x or 1.x
card does not answer it (`6A82` from a card's runtime), which is the signal both
apps read as "this card needs an update", rather than a card that answers and
then misreads every command.

**Why the labels change with it.** An owner's proof under `FoxyCard/set-limit`
is a proof for Foxy's cards; one protocol has one set of labels. The labels and
the AID change in one commit so that no build ever has one without the other.

**Why 2.0.** Our cards said 0.x and Foxy's 1.x. A major of 2 separates the
shared wire from both, for a reader that checks the version after the AID.

**The copy that fails silently.** `Tag.java` keeps its own copy of the card
applet's AID for `JCSystem.getAppletShareableInterfaceObject`. Left at the old
AID, the tag finds no card, takes itself to be on, and the owner's switch does
nothing. `TagLookupTest` holds the copy to `applet/build.xml`, and
`AidVersionTest` checks the build, the source and the old AIDs.

**Cost accepted.** The AID is one byte longer, which moves the CAP's size; the
size check (`tools/refcheck.py`) says whether the J3R180 has taken that size
before. The tag still carries Foxy's address (`https://getfoxy.io/card`); which
page a 2.0 card's tag opens is a product decision left open.

---

## <a id="d20"></a>D20 — The clock walk is bounded: a rollover budget, REFRESH, an armed allowance, an anchored owner

*Amended by [D26](#d26) (2.1): only a payment that moves value rolls the day, and
a `SET_LIMIT` without the budget's byte leaves the budget as it is. The text
below is 2.0's.*

**Found (Foxy's reply, question 3; our shelved 0.7 plan, its decision 9),
fixed (ENG-673, fix 4a).** In 1.20 the day's window rolls whenever a payment
finds the card's clock a day past the window's start, and the clock is any
block header with the work. The network makes a real header every ten minutes,
for free. So a terminal that has been handed the PIN, and keeps the card, takes
a day's limit for every day of headers it brings, and a reader with no PIN at
all takes the no-PIN allowance a day: the daily limit bounds a day, not a
visit. And a card whose owner was set before any header ran at `now = 0` and
spent its first day on trust.

**Decided:**

- **A rollover budget.** The window rolls only while the rolls since the
  owner's last `REFRESH` are fewer than the budget; past it, the window stays
  where it is and what was signed for in it still counts. Default 7, 1 to 30,
  set by a thirteenth byte on the owner's `SET_LIMIT` (`34`); a form without
  it (4, 8 or 12 bytes, and the PIN form `33`) sets the budget back to 7, as
  the architect's decision 2 (ENG-673) has it (2.0; since 2.1 it leaves the
  budget as it is, [D26](#d26)). The first window a card begins (a limit or an
  allowance set before any header, or an allowance set alone) is a beginning,
  not a roll. A terminal with the PIN that walks the clock now gets the found
  day and the budget's days, and no more until the owner's phone has seen the
  card: with a budget of 2, three limits along ten real headers
  (`ClockWalkTest`), where 1.20 gave eleven.
- **REFRESH (`53`).** The owner's proof, under `CashuCard/refresh`, over a
  block header; the header is held to every check `SET_HEADER` makes, taken as
  `SET_HEADER` takes it (an older one moves nothing), and the rolls go to 0, in
  one transaction. The owner's phone sends it with the tip whenever it is
  online. No PIN; any funds; a locked card too, since a locked card still pays.
  `53` was free at `88840aa`; Foxy signs off on the number in the PR.
- **The allowance renews only when armed.** At a roll the no-PIN count goes to
  nothing only if a PIN (`VERIFY_PIN`) or an owner's proof has been given since
  it last did, and the roll spends the arming. A reader with no PIN gets one
  allowance per arming, not one a day.
- **The anchor.** `SET_OWNER` may carry a block header after the key (65 + 80
  bytes). It is checked before anything is written (`6A93` refuses the owner
  as well) and taken in the owner's transaction, with the rolls at 0. A card
  set up so never runs at `now = 0`, never spends a first day on trust, and its
  clock never goes back past its owner's header. Without the header
  `SET_OWNER` is 1.20's: the wire Foxy's wallet already writes.

**Where it is kept.** Three bytes of the 29 the record left as zeros after the
last header's hash (`CARD_ROLLS_OFFSET` 156, `CARD_BUDGET_OFFSET` 157,
`CARD_ARMED_OFFSET` 158), so the constructor asks for nothing more (the chip's
install limit, [D17](#d17)), `RESET_CARD` clears them with the rest, a card's
transactions cover them, and `GET_CARD` shows them to any reader as its bytes
76, 77 and 78 (a budget of 0 there is the default, 7). `GET_INFO` is unchanged.

**Rejected:** counting rolls against the clock's own movement (a terminal
moves the clock); a roll per owner's proof of any kind (a proof for the load
grant is given at a till's top-up, which is not the owner looking at the card);
leaving the budget as it is when the byte is absent. That was this PR's first
version, so that a wallet that does not send the byte would not undo the
owner's choice; the architect's decision 2 had already settled "absent means
7", and both apps code to it. Under it every `SET_LIMIT` says what the budget
is afterwards, and the cost is the one below.

**Cost accepted.** A holder who is offline for longer than the budget, and
pays every day, finds the day's limit stops renewing; the app tells them to
open it online and tap the card. `REFRESH` and the anchor need the phone to
have a recent header (both apps: mempool.space, then blockstream.info; neither
reachable, no header and the card keeps its clock). A 1.x wallet never
sends a `SET_LIMIT` to a 2.0 card, because it does not find the 2.0 AID
([D19](#d19)). The wallet this rule reaches is one moved to the CashuCard AID
and labels that does not send the budget byte yet, which is the state Foxy's
wallet passes through on its way to 2.0. Each 4-, 8- or 12-byte `SET_LIMIT`
it sends puts the budget back to 7, in both directions:

- an owner's budget of 1 to 6 is loosened to 7, so a terminal with the PIN
  gets more days' limits out of a walk until a phone that sends the byte sets
  it again (2.0's `ClockWalkTest.aFormWithoutTheByteSetsTheBudgetBackToSeven`;
  2.1 holds the opposite, `aFormWithoutTheByteLeavesABudgetOfTwo`, [D26](#d26));
- an owner's budget of 8 to 30 is tightened to 7, so a holder the owner gave
  a longer budget because they are offline for weeks finds the day's limit
  stops renewing after a week, not a month, and has to come online and tap
  the card sooner (2.0's `ClockWalkTest.aFormWithoutTheByteTightensABudgetOfThirtyToSeven`;
  2.1: `aFormWithoutTheByteLeavesABudgetOfThirty`).

The second takes spending away from a holder. Foxy reviews both in the PR.

**And a new way to strand funds.** In 1.20 a holder who had lost the owner
key could still spend the card down, one daily limit a day; our reply to
Foxy (question 3, "Losing the owner's words") relied on that. In 2.0 only
the owner's proof refills the budget (`REFRESH`, or an anchored `SET_OWNER`,
which also needs the old owner's proof), and nothing else lifts the limit
(the owner's `SET_LIMIT`) or empties the card (`RESET_CARD`). So on a card
with a daily limit and no owner key, the window stops rolling after the
budget's rolls and stays where it is: what can still be paid is about
(budget + 1) daily limits after the owner's last proof, and anything above
that is stuck for good (`ClockWalkTest.aPinScriptGetsTheBudgetAndNoMore`
shows the stop: 3 of 12 pieces with a budget of 2). A card with no daily
limit is not affected. The architect's decision 14 falls back to a random
per-card owner key kept only in the phone's Keychain when a user has no
backed-up seed, so a lost or wiped phone is enough to cause this.
flash-mobile's "This card's owner key lives only on this phone" copy has to
say so, and an owner who cannot back the key up should be steered to no
daily limit or a small balance (SECURITY-MODEL #14, #17).

---

## <a id="d21"></a>D21 — The field multiply does the same work for every input

**Decided (ENG-673):** `SchnorrHW.mul256x256` and `mulByDelta` have no branch
and no loop whose length depends on a byte of an operand. The `if (ai == 0)
continue;` that skipped a row of zeros is gone from both, and so is the
`while (carry != 0 …)` that carried a row's overflow upward: the carry is
written into its column, which no earlier row has touched (rows run from the
low byte up; row `i` of the full product writes columns `i+1 … i+32`, and of
the product by DELTA columns `i+16 … i+32`), so the carry, at most 255, is the
whole of that column. The result is the same number; `SchnorrHWMathTest` holds
both products to `BigInteger` on operands full of zero bytes, and scans the two
bodies for `continue`, `if`, `while`, `break`, `return` and `?`.

**Why it matters here.** The operands of these products are the signing nonce
and the card key. A row skipped for a zero byte makes a signature measurably
faster for some nonces, and leaked nonce bytes are how ECDSA and Schnorr keys
are recovered with lattices. `AUTH` signs for any reader, with no PIN, as often
as it is asked: an unlimited supply of timed signatures. The 0.x applet had
the same early exit; it was never measured on silicon (SECURITY-MODEL, open
item 5).

**Cost accepted.** A zero row now costs what any row costs, about one row in
256 on random input; the carry write is cheaper than the loop it replaces.
Re-measure `cardctl --timing` on the J3R180 before release (`AUTH`, measured
under ENG-681: 833 to 854 ms a signature on an ACR122U, against 814 ms for 0.4,
about 3% more; [D25](#d25)). What this does not
reach: the modular reductions on the same signing path, which still branch on
values derived from the key and the nonce (`reduce512toModN` over e·d,
`addModN` over k + e·d, `reduceModN` over k, the `sub32` and `cmp32` they
call, and `mulSmallByDelta`'s overflow check; listed as open in SECURITY-MODEL item 5, and held to the source by
`SchnorrHWMathTest`): so the signing path as a whole is not free of
secret-dependent branches, and nothing in 2.0 says it is; the chip's own
`KeyAgreement` and RSA engines, which do the point multiply and the field
exponentiations, and whose timing is NXP's; and the JavaCard VM's own timing
of a multiply, which is not specified constant.

---

## <a id="d22"></a>D22 — The PIN's state byte is its commit: a torn CHANGE_PIN stays blocked

**Found (reply notes to Foxy), verified in 1.20, fixed (ENG-673, fix 4c).**
`CHANGE_PIN` writes the new PIN (`OwnerPIN.update`, which also refills the
tries) and then `pinState = 1`. On a blocked card, a tear between the two left
`pinState` 2 over a new PIN with three tries. `VERIFY_PIN` keyed on the counter
alone, so the new PIN verified; the payment gate keyed on the verified flag and
opened, while the load gate keyed on `pinState == 1` and refused. A card that
`GET_INFO` called blocked paid, and could not be loaded.

**Decided:** `pinState` is the PIN's commit byte, as a slot's status byte is
the slot's ([D14](#d14)). It is written last, and every PIN gate reads it:
`VERIFY_PIN` answers `6983` for state 2 before it checks anything (costing no
try), `requirePinIfSet` refuses state 2 even under a verified flag, and a
blocked card has no no-PIN allowance (`needsAllowance`). A card torn there is
blocked until the owner's `CHANGE_PIN` is sent again, which is what the owner's
phone does for a card that answers blocked. `SET_PIN` keeps the same order, for
an open card torn while being unblocked.

**And a transaction around both writes.** Java Card 3.0.5 does not say that
`OwnerPIN.update` takes part in a transaction (its try counter and validated
flag are specified not to), so the transaction may roll back only the state
byte. Nothing relies on it: the commit byte is the fix, and the transaction is
for a chip whose `OwnerPIN` does take part.

**The same rule, the other tear.** A failed check whose counter decrement
landed and whose `pinState = 2` did not (`failPinCheck` torn) leaves state 1
over no tries. `VERIFY_PIN` already answered `6983` on the counter; the
allowance now refuses it too, so a card blocked by its counter pays nothing
without the PIN. (Found in the tear review, [D23](#d23).)

**Tested** by setting the torn states directly (`ChangePinTearTest`, the
ExposedRuntime pattern of `SlotWriteOrderTest`) and by source scans of the
order; jCardSim cannot tear a write and its transactions do not roll back.

---

## <a id="d23"></a>D23 — The tear review of 2.0: every write outside a transaction, site by site

**Decided (ENG-673, fix 4d):** every persistent write in `CashuApplet` that is
not inside a `JCSystem` transaction was listed and reviewed against the
[D14](#d14) rule: a multi-field write commits a single byte last, or is one
transaction. The list is pinned by `SlotWriteOrderTest.everyWriteOutsideATransactionIsReviewed`,
which counts such writes per method and fails on any method that gains one
until it is reviewed here. One violation was found, and fixed in
[D22](#d22); the rest hold, for these reasons:

| Site | Writes outside | Why a tear there is safe |
|---|---|---|
| `loadOne` | the proof record, the hex text, the data, the status byte, then `changeDue` | Status byte last ([D14](#d14), [D17](#d17)): a tear leaves an EMPTY place, which nothing serves. `changeDue` is cleared after the commit: a tear leaves the change grant standing for one more tap, which opens loading only, never a payment (tested). |
| `freeSpent` | the data zeroed, then the status byte | D14: a tear leaves a SPENT place, never counted or signed for; the next `CLEAR_SPENT` finishes it. |
| `processSpendAllSign` | `burnList` | Written before the payment's transaction and read only while `burnPending` is set, which that transaction sets. A tear before it has burned nothing. |
| `finishBurn` | each place's status byte | After the payment's commit: idempotent (a byte written twice is the same byte), redone from the top at the next command, and `burnPending` is cleared in a transaction of its own after them. |
| `processSpendAllChange`, `blindChange` | an EMPTY opening's amount, keyset, date, nonce and `r`, then `openState` DRAFT | The state byte is the opening's commit: a torn opening stays EMPTY, which `GET_CHANGE` never serves, and the next change writes it whole (tested). |
| `processSpendAllBegin`, `processGetChange`, `clearOpening` | one state byte per opening | Single bytes, each atomic; a draft let go or a pending opening released is the same state at the next pass. |
| `failPinCheck` | `pinState` 2 | One byte, after the JCRE's own decrement of the counter. Torn between them, the card is state 1 over no tries: `VERIFY_PIN` and, since D22, the allowance read that as blocked. |
| `processSetPin` | the allowance and its count zeroed | On a card with no PIN, before the PIN's transaction: each copy atomic, and a card with no PIN has no allowance to lose. |
| `processResetCard` | the bulk wipes and the new keys | Then who the card is, in one transaction, last (Foxy's design): torn before it, the card is still its owner's, empty, and the owner resets it again. The wipe takes the rollover bytes ([D20](#d20)) with it. |
| `processLockCard`, `processSetTag`, `armAllowance` | one byte | Atomic. |
| `writeHeader`, `logEntry` | several | Helpers: every caller holds a transaction around them (pinned in `CashuAppletTest`). |
| `initCardKeypair`, `initPinKey` | the key pairs | Install time: no card exists until `install` returns. |

**What a scan cannot see.** The review is of the source. jCardSim cannot tear a
write, and no 2.0 card has been pulled away mid-command on purpose; the states
a tear leaves are set by hand in the tests and shown harmless, as in D14.

---

## <a id="d24"></a>D24 — FLOOR_BITS is a quarter of the work of the newest header in the vectors

**Decided (ENG-673):** `FLOOR_BITS`, the least work any block header must
show before a card that has taken none believes it, is four times the target
(a quarter of the work) of the newest mainnet header in
`spec/vectors/headers.json`. For 2.0 that header is height 971,100 (bits
`0x17021EF0`), and the floor is `0x17087BC0`: the same as Foxy's 1.15 value,
because the network's difficulty had not moved by a retarget's worth between
the two. `FloorBitsTest` works the floor out from the vectors and holds the
applet to it.

**The procedure, at each release** (v2.0.0 included): add the tip's header to
`spec/vectors/headers.json` (taken from a block explorer and checked: its hash
is the double SHA-256 of its 80 bytes), run `FloorBitsTest`, and set
`FLOOR_BITS` to what it asks for. A floor from the release's own time means a
card set up years later starts from its own era, and the ratchet (a quarter of
the hardest header taken) carries it from there.

**Why a quarter, and not the network's own target.** A header at the tip's
difficulty must always pass, and the difficulty moves by up to four times a
retarget; a quarter of the work leaves room for the network to fall and still
costs a forger a quarter of a block's work (about 2^77 hashes) per day it buys.

---

## <a id="d25"></a>D25 — Readers select the card's applet by its whole AID

**Decided (ENG-681):** a reader selects the card's applet by its whole instance
AID, `F0 43 41 53 48 55 43 41 52 44 01` (`00 A4 04 00 0B F0 43 41 53 48 55 43 41
52 44 01`), and answers `02 00` there. The package AID `F0 43 41 53 48 55 43 41 52
44` ([D19](#d19)) is not the SELECT AID. A reader may fall back to it after a
`6A82`, but takes a `90 00` that carries no version as no answer. `cardctl`, the
cardsim client, `spec/APDU.md`, `spec/NUT-XX.md` and
[`HARDWARE_DEPLOYMENT.md`](HARDWARE_DEPLOYMENT.md) say so.

**Why.** A SELECT by the package AID is a partial name: three of the package's
AIDs begin with it, the opener's (`…44 4D`), the card's applet's (`…44 01`) and the
tag's class (`…44 54`). The chip gives a partial name to the first instance it
made whose AID begins with the name, and the opener is made first, because the
J3R180 will not take the card's applet as the package's first instance
([FOXY-CARD-HARDWARE.md](FOXY-CARD-HARDWARE.md)). So on a chip the package AID
reaches the opener, which answers its SELECT with `90 00` and nothing else, and
`6D 00` to every command after. The suites run in jCardSim, where the package
AID reached the card's applet: jCardSim keeps its applets sorted by AID and gives
a partial name to the lowest that matches, and `…44 01` sorts before `…44 4D`.
So every suite passed a SELECT that the chip answers with the opener.

**The hardware evidence (2026-10-13).** v2.0.0-rc.1 (the tracked CAP, sha256
`59f66673…`) installed on the J3R180 per [`HARDWARE_DEPLOYMENT.md`](HARDWARE_DEPLOYMENT.md):
the opener `F0 CASHUCARD 4D` first, then the card's applet `F0 CASHUCARD 01`, then
the tag. It installed at 20,057 bytes as the install counted the load file (20,060 by
`tools/refcheck.py`'s measure, which had it as a size not yet tried; it is now in
refcheck's table as one that installs). A SELECT of `F0434153485543415244` answered
`9000` with no body, and the next command `6D00`; a SELECT of
`F043415348554341524401` answered `0200 9000`. `cardctl selftest`, which selected
the package AID first, failed; with the whole AID selected first it passed 12 of
12, `AUTH` taking 833 to 854 ms a signature on an ACR122U (0.4 took 814 ms: the
constant-time multiply of [D21](#d21) costs about 3%). Foxy's wallet already
selects by a whole AID only: today its 1.x card's ten bytes `F0 FOXYCARD 01`
(`00 A4 04 00 0A F0 46 4F 58 59 43 41 52 44 01 00`), never a package prefix; on
2.0 the whole AID is the eleven bytes above.

**Rejected: instantiate the card's applet first, or give the opener an AID that
the package AID does not begin.** The first is what the chip refuses (the reason
the opener exists). The second changes the CAP the 2.0 release candidate ships,
for a reader that has no reason to use a partial name: Foxy's wallet already
selects by a whole AID only. **Rejected: keep the package AID first and fall through on
a bare `90 00`.** It costs a SELECT on every tap of every 2.0 card, and leaves a
reader that does not know the rule on the opener.

**The simulator follows the chip.** `tools/cardsim` installs the opener first and
resolves a partial name itself, to the first instance installed whose AID begins
with it (`SimCard.resolveSelect`), so an app's e2e run against the bridge meets
the opener where a chip would put it. The applet's own suites install the card's
applet alone, where either SELECT reaches it.

---

## <a id="d26"></a>D26: Only a payment that moves value turns the day; a SET_LIMIT without the budget's byte leaves it (amends D20)

**Found (Mike Greff's review of 2.0, ENG-699), fixed in 2.1.** Each finding was
first written as a test that failed on 2.0; the names are `ClockWalkTest`'s.

1. **A payment of nothing spent a roll.** In 2.0 `SPEND_ALL_SIGN` rolled the day
   whenever the day was over and the budget lasted, whatever the payment came
   to. A payment whose change (`SPEND_ALL_CHANGE`) is the whole of its pieces
   leaves the card nothing poorer (`allNet` is 0), so it is within any
   allowance: on a card with a PIN and an allowance a reader with no PIN signs
   it, and on a card with no PIN anyone does. Seven taps of it along seven real
   headers spent the default budget of 7, and the owner then had one day's
   limit until the next `REFRESH`. Failing on 2.0:
   `aPaymentThatMovesNoValueRollsNothing` (a roll on the first day),
   `onACardWithNoPinAPaymentOfNothingRollsNothing` (two rolls of a budget of 2),
   `aPaymentOfNothingBeginsNoWindow` (it began the first window). One part of
   the finding does not hold: a card with a PIN and no allowance refuses such a
   payment from a reader with no PIN (`6A94`), as it refuses every payment
   without the PIN, so on that card it never rolled
   (`withNoAllowanceAReaderWithNoPinPaysNothingAtAll`, passing on 2.0 and 2.1).
2. **A form without the budget's byte reset the budget.** D20 had every
   4-, 8- or 12-byte `SET_LIMIT` (and the PIN's form) set it back to 7. Failing
   on 2.0: `aFormWithoutTheByteLeavesTheBudget`,
   `aFormWithoutTheByteLeavesABudgetOfTwo`, `aFormWithoutTheByteLeavesABudgetOfThirty`.
3. **A budget set under the rolls already spent.** It stops the day at once and
   until `REFRESH`, which empties the rolls. 2.0 already did this (`windowRolls`
   compares the rolls to the budget as it is now); the finding is held by a
   test that passes on both, `aBudgetUnderTheRollsSpentStopsTheDay`.

**Decided:**

- **What spends a roll.** A `SPEND_ALL_SIGN` that signs and commits, whose
  `allNet` (the pieces named at `SPEND_ALL_BEGIN` less the card's own change)
  is above 0, on a card with a daily limit or an allowance, that finds the day
  over (`now` at least 86,400 seconds past the window's start) and its rolls
  under the budget. A window not yet begun is begun by the same payment, and
  that is no roll. Nothing else spends one: `SET_HEADER`, `REFRESH` and the
  anchored `SET_OWNER` move the clock, `TELL_TIME` is a note, every `GET_*`
  only reads, `VERIFY_PIN` and an owner's proof arm the allowance, and a
  payment refused (`6A94`, `6A8F`, or given up before its signature) throws
  before its transaction (`nothingButAPaymentRolls`). A payment of nothing is
  signed as before and counted, as nothing, in the window as it stands.
- **One test, read three times.** The value check is in `windowRolls`, which
  the day's limit (`requireUnderLimits`), the allowance
  (`requireAllowanceOrPin`) and the commit all read. Were they to disagree, a
  payment would have been judged against a new day and written into the old
  one, and the day's count would have gone to nothing with no roll. The roll,
  the day's count and the burn stay in the payment's one transaction
  ([D23](#d23)); no write moved, and `SlotWriteOrderTest` holds the list.
- **The budget's byte, absent, leaves the budget.** A wallet that sets a limit
  and does not know the byte neither loosens nor tightens what the owner
  chose. The rolls are not touched by any `SET_LIMIT`.

**What still rolls with no PIN.** A payment of value within the allowance: one
sat a day from a reader with no PIN rolls the day as any payment does
(`aPaymentOfOneSatWithNoPinStillRolls`: seven rolls for seven sats). That walk
costs the reader a sat a roll from an allowance that does not begin again until
a PIN or the owner's proof arms it, so it is bounded by the allowance in sats;
the card's log has every one of them, and `REFRESH` ends it. **Rejected:** a
payment with no PIN rolls only when the allowance is armed. It closes this as
well, and it costs the holder: a payment with the PIN spends the arming at its
roll, so the next day's first payment with no PIN would be judged against the
day before's count, and refused for the daily limit after a full day. An owner
who sets an allowance accepts the sat-a-roll walk until that is decided.

**The version is 2.1.** `CashuApplet`'s rule: the version moves with every
wire-visible change of behaviour. Two answers change for the same commands
(`GET_CARD`'s byte 76 after a payment of nothing, its byte 77 after a short
`SET_LIMIT`), and v2.0.0 was released with the old ones. Nothing on the wire
is added or moved: no instruction, length or byte of `GET_INFO` or `GET_CARD`
has a new meaning. No card is in a holder's hands (the owner's statement), so
there is nothing to migrate; the minor is how a reader, and `cardctl
selftest`, tell a bench card left on v2.0.0 from the fixed build. flash-pos,
flash-mobile and Foxy's wallet check the major alone, and take `02 01` as they
took `02 00`. `cardctl selftest` passes 2.1 and later 2.x, and a 2.0 card is
swept and reinstalled. The CAP is `cashu-javacard-2.1.0.cap`.

**The size.** The load file is 20,068 bytes by refcheck's measure (100 past a
multiple of 256), 8 more than 2.0's 20,060. Refcheck accepts it: no size near
it has failed. It has not been tried on the J3R180; it is, with the opener
first, before a 2.1 card is handed out, and the answer goes into refcheck's
table. If the chip refuses it, `sizeTheFile` moves the build to a size that
installs.

**The vectors.** `spec/vectors/transcript.json` is recorded again. It selected
the package AID, which on a chip reaches the opener ([D25](#d25)); every
`SELECT` in it is now by the whole AID `F0 43 41 53 48 55 43 41 52 44 01`, and
it answers `02 01`. It ends with the rollover on the wire: an anchored
`SET_OWNER` (145 bytes, refused first for an anchor without the work), budgets
of 0 and 31 refused, the thirteen-byte `SET_LIMIT` with a budget of 1, the
four-byte form leaving it, a payment of nothing that rolls nothing, a roll
that spends the budget, a day that then stands (`6A8F`), `REFRESH` by the old
owner's key refused and by the owner's taken, and the day rolling again.
`owner.json` gains the thirteen-byte limit, `CashuCard/refresh` over a header
and the anchored `SET_OWNER`'s 145 bytes. `secret.json` and `headers.json` do
not depend on the AID or the rollover and are as they were.

**Cost accepted.** A `SET_LIMIT` says what the budget is afterwards only when
it carries the byte, which the architect's decision 2 had wanted of every one.
flash-mobile, Foxy's wallet, `cardctl --budget` and the bridge's fixtures send
the byte every time; a wallet that does not sends the limits it means and
leaves the budget to the owner.

---

Small changes: open a PR and reference the decision id (e.g. "revisits D5").

Changes that alter the product's shape — recovery, identity, custody, the
trust boundaries in [`ARCHITECTURE.md`](ARCHITECTURE.md) — warrant a **Flash
Improvement Proposal**. That process exists precisely for "large-scale or
cross-team changes", and this project does not yet have one of its own: the
closest is FIP-04, which describes the design being replaced. *(The FIP
repository is internal to Flash.)*
