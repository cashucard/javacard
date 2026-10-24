# APDU Command Reference — Cashu card protocol 2.1

The wire of the shared Cashu card protocol, version 2.1: the applet in this
repository (`applet/src/main/java/me/flashapp/cashu/CashuApplet.java`), which is
the Foxy wallet project's software 1.20 with a neutral identity and the fixes in
[`docs/DECISIONS.md`](../docs/DECISIONS.md) D18 to D26. 2.1 has 2.0's commands and
bytes; what moves the day and the rollover budget is D26's (below). Version 2.x is not
compatible with the 0.x applet that this file used to describe, nor with Foxy's
1.x: it has an AID of its own, so that neither can be mistaken for it.

Class `B0` for every applet command. Numbers are big-endian unless a row says
otherwise (a block header's own fields are little-endian, as the network carries
them). `cardctl.py` (`tools/cardctl`) drives the commands it names below, and
`test_spec_consistency.py` holds this file, `cardctl.py` and the applet to each
other on every push. The design and the reasons for it are in
[`docs/FOXY-CARD-SPEC.md`](../docs/FOXY-CARD-SPEC.md) section 5 and
[`docs/FOXY-CARD-DAILY-LIMIT.md`](../docs/FOXY-CARD-DAILY-LIMIT.md); where they
and this file differ, this file is the 2.0 wire.

---

## SELECT APPLICATION

| Field | Value |
|---|---|
| CLA | `00` |
| INS | `A4` |
| P1 | `04` (select by name) |
| P2 | `00` |
| Lc | `0B` |
| Data | `F0 43 41 53 48 55 43 41 52 44 01` (the card's applet: the package AID, "CASHUCARD" after the proprietary RID byte `F0`, and `01`) |
| Le | `00` |

**Response:** 2 bytes, the applet version: `02 01`. A reader takes any `02 xx`
as the shared protocol; `02 00` is the v2.0.0 release, whose rollover rules D26
replaced.

A reader selects the applet's whole AID ([D25](../docs/DECISIONS.md#d25)). The
package AID `F0 43 41 53 48 55 43 41 52 44` begins two instance AIDs, the
opener's (`F0 43 41 53 48 55 43 41 52 44 4D`) and the card's applet's (`…44 01`),
and the NFC tag's class AID (`F0 43 41 53 48 55 43 41 52 44 54`; the tag is
instantiated under the NFC Forum's own `D2 76 00 00 85 01 01`). On a chip, a SELECT by that partial name
reaches the first instance made whose AID begins with it, and the opener is made
first ([`HARDWARE_DEPLOYMENT.md`](../docs/HARDWARE_DEPLOYMENT.md)): it answers
`90 00` with no version, and `6D 00` to every command after. A reader that has
only the package AID to go on, or that gets `6A82` to the whole AID, may try it,
but takes a `90 00` without the two version bytes as no answer from the card's
applet.

A card that answers `6A82` (the card's runtime: no such application) to this
name is not a 2.0 card. The 0.x applet answered `D2 76 00 00 85 01 02` and Foxy's
1.x `F0 46 4F 58 59 43 41 52 44`; both are "this card needs an update", and an
app spends nothing from such a card.

---

## Commands, by INS

| INS | Command | Needs | Section |
|---|---|---|---|
| `01` | GET_INFO | nothing | [GET_INFO](#get_info-0x01) |
| `10` | GET_PUBKEY | nothing | [GET_PUBKEY](#get_pubkey-0x10) |
| `11` | GET_BALANCE | nothing | [GET_BALANCE](#get_balance-0x11) |
| `12` | GET_PROOF_COUNT | nothing | [GET_PROOF_COUNT](#get_proof_count-0x12) |
| `13` | GET_PROOF | nothing | [GET_PROOF](#get_proof-0x13) |
| `14` | GET_SLOT_STATUS | nothing | [GET_SLOT_STATUS](#get_slot_status-0x14) |
| `15` | AUTH | nothing | [AUTH](#auth-0x15) |
| `16` | GET_CARD | nothing | [GET_CARD](#get_card-0x16) |
| `17` | GET_PIECES | nothing | [GET_PIECES](#get_pieces-0x17) |
| `18` | GET_LOG | the PIN, or the owner's grant | [GET_LOG](#get_log-0x18) |
| `19` | GET_CHANGE | nothing | [GET_CHANGE](#get_change-0x19) |
| `1A` | GET_DLEQ | nothing | [GET_DLEQ](#get_dleq-0x1a) |
| `22` | SPEND_ALL_BEGIN | nothing | [SPEND_ALL_BEGIN](#spend_all_begin-0x22) |
| `23` | SPEND_ALL_OUTPUTS | a payment begun | [SPEND_ALL_OUTPUTS](#spend_all_outputs-0x23) |
| `24` | SPEND_ALL_SIGN | the PIN, or the no-PIN allowance, or no PIN set | [SPEND_ALL_SIGN](#spend_all_sign-0x24) |
| `25` | SPEND_ALL_AGAIN | the PIN, unless the last signature needed none | [SPEND_ALL_AGAIN](#spend_all_again-0x25) |
| `26` | SPEND_ALL_CHANGE | a payment begun | [SPEND_ALL_CHANGE](#spend_all_change-0x26) |
| `30` | LOAD_PROOF | an owner and a record; the PIN, or a grant | [LOAD_PROOF](#load_proof-0x30) |
| `31` | CLEAR_SPENT | the PIN, or a grant | [CLEAR_SPENT](#clear_spent-0x31) |
| `32` | SET_CARD | open card: the PIN; owned: the owner's proof | [SET_CARD](#set_card-0x32) |
| `33` | SET_LIMIT_PIN | open card, nothing unspent, the PIN | [SET_LIMIT_PIN](#set_limit_pin-0x33) |
| `34` | SET_LIMIT | the owner's proof | [SET_LIMIT](#set_limit-0x34) |
| `36` | SET_HEADER | nothing | [SET_HEADER](#set_header-0x36) |
| `37` | TELL_TIME | nothing | [TELL_TIME](#tell_time-0x37) |
| `40` | VERIFY_PIN | nothing | [VERIFY_PIN](#verify_pin-0x40) |
| `41` | SET_PIN | open card; or ADD PIN under the grant | [SET_PIN](#set_pin-0x41) |
| `42` | CHANGE_PIN | the owner's proof | [CHANGE_PIN](#change_pin-0x42) |
| `43` | SET_OWNER | open card; or the old owner's proof | [SET_OWNER](#set_owner-0x43) |
| `44` | GET_NONCE | an owner (P1 = 0) | [GET_NONCE](#get_nonce-0x44) |
| `45` | ALLOW_LOAD | the owner's proof | [ALLOW_LOAD](#allow_load-0x45) |
| `50` | LOCK_CARD | the PIN and the owner's proof | [LOCK_CARD](#lock_card-0x50) |
| `51` | RESET_CARD | the owner's proof | [RESET_CARD](#reset_card-0x51) |
| `52` | SET_TAG | the owner's proof | [SET_TAG](#set_tag-0x52) |
| `53` | REFRESH | the owner's proof | [REFRESH](#refresh-0x53) |

Not assigned, and answered `6D00`: `20` (0.x's `SPEND_PROOF`, gone with format 4),
`21` (0.x's `SIGN_ARBITRARY`, removed: it signed anything and burned nothing),
`35` (Foxy's `SET_TIME`, gone in 1.15). The 0.x `CLEAR_PIN`, `SET_PUK` and
`UNBLOCK_PIN` were `43`, `44` and `45`, which are `SET_OWNER`, `GET_NONCE` and
`ALLOW_LOAD` here; a 0.x reader's bytes there change nothing a PIN could gain
(D18).

---

## The owner's proof

A card with an owner holds a NIST P-256 public key (`SET_OWNER`). The owner's
commands carry an ECDSA signature (P-256, SHA-256, DER) by the owner's private key
over

    label (ASCII) ‖ nonce (16) ‖ value

where the nonce is the last `GET_NONCE` answer in this tap (one try per nonce,
right or wrong) and the value is exactly the bytes after the proof. The data of an
owner's command is `proof length (1) ‖ proof (DER, at most 72) ‖ value`.

| Command | Label | Value |
|---|---|---|
| `CHANGE_PIN` | `CashuCard/change-pin` | the new PIN's bytes |
| `SET_LIMIT` | `CashuCard/set-limit` | 4, 8, 12 or 13 bytes: see [SET_LIMIT](#set_limit-0x34) |
| `SET_OWNER` (on an owned card) | `CashuCard/set-owner` | the new owner key (65), and the anchor header (80) if sent |
| `SET_CARD` (on an owned card) | `CashuCard/set-card` | the record as sent |
| `ALLOW_LOAD` | `CashuCard/load` | nothing |
| `LOCK_CARD` | `CashuCard/lock` | nothing |
| `RESET_CARD` | `CashuCard/reset` | nothing |
| `SET_TAG` | `CashuCard/tag` | one byte: `00` on, `01` off |
| `REFRESH` | `CashuCard/refresh` | the block header (80) |

A missing, wrong or used proof is `6A91`; it costs no PIN try, changes nothing
and does not end the PIN session. A card with no owner answers `6A90`. A good
proof also arms the no-PIN allowance ([The clock and the limits](#the-clock-and-the-limits)).

Two more tags are hashed by the card: `CashuCard/auth` ([AUTH](#auth-0x15)) and
`CashuCard/seal`, `CashuCard/pinkey` (the sealed PIN, [VERIFY_PIN](#verify_pin-0x40)).
A phone derives a card's owner key as
`HMAC-SHA256(seed, "CashuCard/owner" ‖ 0x00 ‖ card key (33))` mod n
(`FOXY-CARD-SPEC.md` 5.6, with the 2.0 label); the card never sees it.

---

## Category 0x0x / 0x1x — Read (no authentication required)

### GET_INFO (0x01)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `01` |
| P1 | `00`, `01` or `02` |
| P2 | `00` |
| Lc | — |
| Le | `00` |

**Response:** 30 bytes with P1 = `00` (any P1 but 1 and 2), 42 with P1 = `01`, 43 with P1 = `02`.

| Byte | Field | Meaning |
|---|---|---|
| 0 | version major | `02` |
| 1 | version minor | `01` |
| 2 | max slots | 128 (`0x80`) |
| 3 | unspent | slots holding an unspent piece |
| 4 | spent | slots spent and not yet freed |
| 5 | empty | free slots |
| 6 | capabilities | `FF` |
| 7 | PIN state | 0 none, 1 set, 2 blocked |
| 8 | format | `04` (SIG_ALL pieces) |
| 9 | tries left | 0 to 3 |
| 10 | locked | 1 after `LOCK_CARD` |
| 11 | record set | 1 after `SET_CARD` |
| 12–15 | daily limit | sats; 0 is none |
| 16 | has owner | 1 after `SET_OWNER` |
| 17–20 | now | the card's clock: the newest block header's time, seconds; 0 before any |
| 21–24 | window start | when the day's window began |
| 25–28 | spent today | sats signed for in the window |
| 29 | change grant | 1 when this tap may load the change of the last payment with no PIN |
| 30–33 | payment limit | P1 ≥ 1: the limit on one payment, only with the owner's grant in this tap, zeros otherwise |
| 34–37 | no-PIN allowance | P1 ≥ 1: sats a day the card signs for without its PIN |
| 38–41 | no-PIN spent | P1 ≥ 1: what has been signed for without the PIN in the window |
| 42 | tag off | P1 = 2: `00` the NFC tag is on, `01` off |

Capability bits (byte 6), all set on 2.0: bit 0 secp256k1 key made on the card,
bit 1 BIP-340 signing, bit 2 a PIN, bit 3 the limit on one payment waits and does
not refuse, bit 4 several pieces to a `LOAD_PROOF` and `GET_PIECES` by name, bit 5
128 places, bit 6 a payment's places burned outside its transaction, bit 7 the PIN
taken sealed.

### GET_PUBKEY (0x10)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `10` |
| P1 | `00` |
| P2 | `00` |
| Le | `21` |

**Response:** the card's secp256k1 public key, 33 bytes compressed. Every piece on
the card is locked to it (NUT-11).

### GET_BALANCE (0x11)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `11` |
| P1 | `00` |
| P2 | `00` |
| Le | `04` |

**Response:** 4 bytes, the sum of the unspent pieces' amounts, in the card's unit.

### GET_PROOF_COUNT (0x12)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `12` |
| P1 | `00` |
| P2 | `00` |
| Le | `01` |

**Response:** 1 byte, the number of slots that are not empty (unspent or spent).

### GET_PROOF (0x13)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `13` |
| P1 | slot (0–127) |
| P2 | `00` |
| Le | `52` |

**Response:** 82 bytes, the slot as the [Proof Slot Layout](#proof-slot-layout)
has it.

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | Status — `00` empty, `01` unspent, `02` spent |
| 1 | 8 | Keyset ID — the NUT-02 id's first 8 bytes, raw (not ASCII) |
| 9 | 4 | Amount — uint32, big-endian |
| 13 | 32 | Nonce — the NUT-10 P2PK secret's nonce, raw (the card rebuilds the secret from it) |
| 45 | 33 | C — the mint's unblinded signature, a compressed point |
| 78 | 4 | Date — the piece's locktime, seconds; 0 for none |

`6A83` for a slot out of range. A spent slot whose `CLEAR_SPENT` was cut short
still answers, with some fields zeroed: its bytes are not a proof.

### GET_SLOT_STATUS (0x14)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `14` |
| P1 | `00` |
| P2 | `00` |
| Le | `80` |

**Response:** 128 bytes, one status byte per slot.

### AUTH (0x15)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `15` |
| P1 | `00` |
| P2 | `00` |
| Lc | `10` |
| Data | 16 random bytes of the reader's |
| Le | `50` |

**Response:** 80 bytes: 16 random bytes of the card's, then a BIP-340 signature
(64) by the card key over

    SHA-256( T ‖ T ‖ reader (16) ‖ card (16) ‖ card key (33, compressed) ),  T = SHA-256("CashuCard/auth")

It proves the reader holds the card that has that key. No PIN, and nothing is
burned: the message is 129 bytes behind a tag, and no piece's secret (text
beginning `["P2PK"`) hashes to it. `6700` for any length but 16.

### GET_CARD (0x16)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `16` |
| P1 | `00` |
| P2 | `00` |
| Le | `00` |

**Response:** 109 bytes and the mint.

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | format, `04` |
| 1 | 1 | record set |
| 2 | 1 | unit, `00` sat |
| 3 | 4 | daily limit |
| 7 | 33 | refund key, or zeros |
| 40 | 4 | the hardest header's `bits`, little-endian, as a header carries it; zeros before any |
| 44 | 32 | the hash of the last header taken, as Bitcoin shows a block hash |
| 76 | 1 | rolls: how often the day's window has rolled since the owner's last `REFRESH` |
| 77 | 1 | rollover budget: 1 to 30; `00` is the default, 7 |
| 78 | 1 | allowance armed: 1 when the no-PIN allowance may begin again at the next roll |
| 79 | 26 | zeros |
| 105 | 1 | mint length |
| 106 | n | mint, as text (at most 77) |
| 106 + n | 3 | the card's design, three characters, or zeros |

### GET_PIECES (0x17)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `17` |
| P1 | the first slot to report (0–127) |
| P2 | `00` pages; `02` named slots; `03` the short listing |
| Le | `00` |

**Response.** P2 = `00`: one page, at most 255 bytes: the first slot the page does
not cover (1; 128 is the end), then for each slot in range that is not empty a tag
(1: the slot, with `0x80` where it is spent) and, for an unspent slot, its 81 bytes
after the status. P2 = `02` with one to three slot numbers as data: each slot
whole (82), in the order asked. P2 = `03`: for each unspent slot its number (with
`0x80` where its keyset and date follow), then the power of two it is worth, or
`FF` and its amount (4). `FOXY-CARD-DAILY-LIMIT.md` 6d and 8.1 have the forms
byte for byte. `6A83` for a P1 of 128 or more; `6A86` for another P2.

### GET_LOG (0x18)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `18` |
| P1 | `00` the log; `01` the receipts |
| P2 | with P1 = 1, how many receipts back to begin |
| Le | `00` |

**Response.** P1 = `00`: 16 bytes of counts (taps, sats signed for, refusals,
tampers), then up to eight tap entries of 20 bytes, newest first: the clock (4),
sats signed for (4), pieces signed (1), refused (1), flags (1), pieces put on
(1), sats put on (4), the time the terminal told (4). P1 = `01`: the count of
payments (4), then up to three receipts of 77 bytes, newest first: the clock
(4), the time told (4), sats (4), the SHA-256 of the message signed (32), the
first output's blinded message (33). Needs the PIN verified in this tap or the
owner's grant (receipts: the grant only); on a card with no PIN, anyone. `6982`
otherwise.

### GET_CHANGE (0x19)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `19` |
| P1 | page, from 0 |
| P2 | `00` |
| Le | `00` |

**Response:** a count (1), then up to three openings of 80 bytes: the amount (4),
the keyset (8), the date (4), the nonce (32) and the blinding factor r (32) of a
change output the card made for itself (`SPEND_ALL_CHANGE`), signed for and not
yet back on the card. An opening whose piece is on the card is let go first. A
phone finishes the change piece from these and the mint's signature, and loads
it; the piece is locked to the card's key, so nothing else can spend it.

### GET_DLEQ (0x1A)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `1A` |
| P1 | a slot (0–127) |
| P2 | a second slot, or `FF` |
| Le | `00` |

**Response:** for each slot asked, in order: `01` and the 96 bytes `e ‖ s ‖ r` of
the mint's NUT-12 proof kept with an unspent piece, or `00` (empty, spent, loaded
without one, or no room for proofs). At most 194 bytes. `6A83` for a slot out of
range. The card checks nothing: the phone checks the proof with the mint's keys.

---

## Category 0x2x — Spend (one signature for a payment: NUT-11 SIG_ALL)

A payment is `SPEND_ALL_BEGIN`, the swap's outputs (`SPEND_ALL_OUTPUTS`), the
card's own change (`SPEND_ALL_CHANGE`, any number up to the openings free), then
`SPEND_ALL_SIGN`. Any other command in between gives the payment up. The one
signature is over the NUT-11 `SIG_ALL` message: every piece's secret and `C`,
then every output's amount and blinded message, in order. Every piece on a 2.0
card is a format-4 P2PK secret locked to the card key with `["sigflag","SIG_ALL"]`
(the [NUT-XX](NUT-XX.md) secret), so the mint takes this one signature for all of
them.

### SPEND_ALL_BEGIN (0x22)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `22` |
| P1 | `00` |
| P2 | `00` |
| Lc | the number of slots, 1–128 |
| Data | the slots, a byte each, in the order their pieces go into the message |
| Le | `04` |

**Response:** 4 bytes, what the pieces are worth together. `6700` for none;
`6A96` for more than 128; `6A83`, `6A88`, `6985` for a slot out of range, empty or
spent; `6A80` for a slot named twice or of another date than the first; `6A8F`
over the day's limit on the sum.

### SPEND_ALL_OUTPUTS (0x23)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `23` |
| P1 | `00` |
| P2 | `00` |
| Lc | a multiple of 37 |
| Data | for each output: amount (4) ‖ blinded message B_ (33) |

Hashed into the message as they come (the amount in decimal, then B_ in hex).
`6985` with no payment begun; `6700` for a length not a multiple of 37, and the
payment is dropped.

### SPEND_ALL_CHANGE (0x26)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `26` |
| P1 | `00` |
| P2 | `00` |
| Lc | `04` |
| Data | the change amount (4) |
| Le | `21` |

**Response:** 33 bytes, the blinded message of a change output the card makes for
itself: a fresh nonce, the secret in the card's own form (its key, the payment's
date and refund key, `SIG_ALL`), hashed to the curve as NUT-00 says and blinded
with a fresh r. The opening is kept ([GET_CHANGE](#get_change-0x19)). The day's
limit and the no-PIN allowance count what leaves the card: the pieces less this
change. `6985` with no payment begun; `6A80` for 0, or change past the pieces;
`6A84` with no opening free.

### SPEND_ALL_SIGN (0x24)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `24` |
| P1 | `00` |
| P2 | `00` |
| Le | `40` |

**Response:** the 64-byte BIP-340 signature over the whole payment; every slot named
is burned, the day's count charged and the log written in the same commit. While
the payment is over the limit on one payment the card answers `00 01` ("not yet")
and the terminal sends `SIGN` again; the wait is the card's own work and burns
nothing. `6985` with no payment begun; `6A94` with a PIN set and not given in this
tap and the no-PIN allowance not enough for the whole payment (nothing written,
the payment given up); `6A8F` over the day's limit; `6A96` if the commit cannot
hold it.

### SPEND_ALL_AGAIN (0x25)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `25` |
| P1 | `00` |
| P2 | `00` |
| Le | `40` |

**Response:** the last signature `SPEND_ALL_SIGN` gave, again, for an answer lost
on the air. The PIN if one is set, unless that signature was given with no PIN.
`6A88` if the card has never signed.

---

## Category 0x3x — Write

### LOAD_PROOF (0x30)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `30` |
| P1 | `00`; `01` with the mint's proof |
| P2 | `00` |
| Lc | `51` (81), or 162 or 243 for two or three pieces; `B1` (177) with P1 = 1 |
| Data | for each piece: keyset_id (8) ‖ amount (4) ‖ nonce (32) ‖ C (33) ‖ date (4); with P1 = 1, one piece then e ‖ s ‖ r (96) |
| Le | `01` per piece; `02` with P1 = 1 |

| Field | Size | |
|---|---|---|
| keyset_id | 8 | the NUT-02 id's first 8 bytes, raw |
| amount | 4 | uint32 |
| nonce | 32 | the P2PK secret's nonce |
| C | 33 | compressed point |
| date | 4 | locktime, seconds, or 0 |

**Response:** the slot of each piece stored; with P1 = 1, the slot and `01` where
the proof was kept (`00` with no room for proofs).

Needs, in this order: a PIN verified in this tap, or the owner's grant
(`ALLOW_LOAD`) in this tap, or this tap being the one after a payment (the change),
or a card with no PIN (`6982` otherwise, before anything else); an owner (`6A90`);
a record (`6A8C`); a refund key for a dated piece (`6A8E`); a nonce not already in
any slot, spent or not (`6A94`). `6A84` with no slot free; `6A80` for a C that is
not a point, or a proof of 96 zeros; `6700` for a bad length. The status byte is
written last ([D14](../docs/DECISIONS.md#d14)).

### CLEAR_SPENT (0x31)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `31` |
| P1 | `00` |
| P2 | `00` |
| Le | `01` |

**Response:** 1 byte, the number of slots freed. Every spent slot's data is zeroed,
then its status byte set empty, slot by slot ([D14](../docs/DECISIONS.md#d14)). A
card pulled away part way leaves a slot spent with any part of its data zeroed:
`GET_PROOF` still answers it, and its bytes are not a proof. Only the zeroed bytes
set such a slot apart, so a reader that uses a spent slot's data checks it first.
`cardctl dump` (0.x cards) skips a spent slot that fails the card file's slot
checks ([`CARD-FILE.md`](CARD-FILE.md#slot)). The slot checks catch a zeroed
amount and a `C` that is no longer a point. A tear that zeroed only keyset or
nonce bytes, or part of `C` whose x still lands on the curve, passes them, and
`dump` writes that slot as spent. The PIN if one is set, or either grant.

### SET_CARD (0x32)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `32` |
| P1 | `00` |
| P2 | `00` |
| Data | on an owned card: proof length (1) ‖ proof; then unit (1) ‖ refund key (33) ‖ 65 bytes not read ‖ mint length (1) ‖ mint ‖ [design (3)] |

Writes the record. Open card: the PIN if one is set; owned card: the owner's proof
over the record. Only with nothing unspent (`6A8D`). `6A80` for a bad refund key or
design; `6700` for a bad length. Never touches the limits or the clock. The first
`SET_CARD` reserves the store of the mints' proofs.

### SET_LIMIT_PIN (0x33)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `33` |
| P1 | `00` |
| P2 | `00` |
| Data | the day's limit (4), or eight bytes: the day's and the one payment's |

The PIN form, for an open card (no owner, nothing unspent, the PIN set and
verified). `6A91` on an owned card; `6A8D` with anything unspent; `6700` for
another length. It has no rollover budget, and leaves the card's as it is (D26).

### SET_LIMIT (0x34)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `34` |
| P1 | `00` |
| P2 | `00` |
| Data | proof length (1) ‖ proof ‖ value |

The owner's form; no PIN, any funds. The value:

| Bytes | Field | |
|---|---|---|
| 0–3 | daily limit | sats; 0 is none. A new number begins a window at `now` |
| 4–7 | payment limit | (8, 12 or 13 bytes) sats; a payment over it waits, by the card's own work, for every limit's worth past the first |
| 8–11 | no-PIN allowance | (12 or 13 bytes) sats a day signed for without the PIN; `6985` for a number on a card with no PIN |
| 12 | rollover budget | (13 bytes) 1 to 30: how often the window may roll between the owner's `REFRESH`es; `6A80` outside that. Absent (4, 8 or 12 bytes), the budget is left as it is (D26; 2.0 set it back to 7). A budget under the rolls already spent stops the day until `REFRESH` |

`6A90`, `6A91`; `6986` locked; `6700` for a length other than 4, 8, 12 or 13.

### SET_HEADER (0x36)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `36` |
| P1 | `00` |
| P2 | `00` |
| Lc | `50` |
| Data | a Bitcoin block header, 80 bytes, as the network carries it |
| Le | `04` |

**Response:** the card's `now`, 4 bytes. No PIN, no owner, any state. The card
hashes the header twice with SHA-256; the hash, read little-endian, must be at or
under the target its own `bits` name, at or under the floor built into the applet
(`bits` `0x17087BC0`, a quarter of the network's work at height 971,100: D24) and,
once a header has been taken, at or under four times the target of the hardest
taken (`6A93` otherwise; `6A80` for `bits` no header could carry; `6700` for any
length but 80). A later time moves `now` forward; an older header changes
nothing.

### TELL_TIME (0x37)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `37` |
| P1 | `00` |
| P2 | `00` |
| Lc | `04` |
| Data | the terminal's clock, seconds |

A note for the receipts and the log of this tap; trusted for nothing.

---

## Category 0x4x — Authentication

### VERIFY_PIN (0x40)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `40` |
| P1 | `00`; `01` sealed |
| P2 | `00` |
| Data | the PIN, 4–8 bytes; with P1 = 1, the PIN sealed (`FOXY-CARD-DAILY-LIMIT.md` 6e, under `CashuCard/seal` and `CashuCard/pinkey`) |

Success opens the PIN's commands for this tap and arms the no-PIN allowance.
Wrong: `63CX` with X tries left; the try that exhausts the counter blocks the card
(`6983`), and so does every `VERIFY_PIN` after it. `6984` with no PIN set. **A
card whose PIN state is 2 answers `6983` before it checks anything, whatever its
counter** ([D22](../docs/DECISIONS.md#d22)): the state byte is the PIN's commit.
Only the owner's `CHANGE_PIN` unblocks it.

### SET_PIN (0x41)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `41` |
| P1 | `00`; `01` sealed |
| P2 | `00` |
| Data | the PIN, 4–8 bytes |

Sets or replaces the PIN and unblocks, on an open card with nothing unspent; on an
owned card only when it has no PIN and the owner's grant is in this tap (ADD PIN).
`6A91` otherwise on an owned card; `6A8D` with anything unspent; `6986` locked;
`6700` for a PIN of another length.

### CHANGE_PIN (0x42)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `42` |
| P1 | `00`; `01` sealed |
| P2 | `00` |
| Data | proof length (1) ‖ proof ‖ the new PIN (4–8) |

The owner's proof over the new PIN; no old PIN, no session, any PIN state, any
funds. Sets the PIN, refills the tries, unblocks, and ends any verified session.
The PIN is written, then the PIN state, in one transaction: the state byte is the
commit, so a card torn between them is still blocked and the owner sends it again
(D22). `6A90`, `6A91`; `6986` locked; `6700` for a PIN of another length.

### SET_OWNER (0x43)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `43` |
| P1 | `00` |
| P2 | `00` |
| Data | on an owned card: proof length (1) ‖ proof; then the owner's P-256 key (65, `04 ‖ X ‖ Y`) ‖ [an anchor header (80)] |

Gives the card its owner, on a card with nothing unspent (`6A8D`): with no proof on
a card that has none, with the old owner's proof on one that has. **The anchor
(2.0, D20):** a block header after the key is held to `SET_HEADER`'s checks before
anything is written (`6A93` refuses the owner too) and taken in the same
transaction as the key, with the rollover count at 0. A card set up with one never
runs at `now = 0`. `6A80` for a key not beginning `04`; `6700` for a length other
than 65 or 145 after the proof; `6986` locked.

### GET_NONCE (0x44)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `44` |
| P1 | `00`; `01` the PIN key |
| P2 | `00` |
| Le | `10`; `71` with P1 = 1 |

**Response:** 16 fresh random bytes for one owner's proof (`6A90` with no owner).
With P1 = 1, on any card: the 16 bytes, the PIN key (33, compressed) and the card
key's BIP-340 signature over `SHA-256("CashuCard/pinkey" ‖ PIN key)` (64), 113 in
all, for sealing a PIN.

### ALLOW_LOAD (0x45)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `45` |
| P1 | `00` |
| P2 | `00` |
| Data | proof length (1) ‖ proof |

The owner's proof over `CashuCard/load`: for the rest of this tap, `LOAD_PROOF` and
`CLEAR_SPENT` need no PIN, `SET_PIN` may add one to a card with none, and
`GET_INFO` says the limit on one payment. Never a payment. `6A90`, `6A91`; `6986`
locked.

---

## Category 0x5x — Admin

### LOCK_CARD (0x50)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `50` |
| P1 | `00` |
| P2 | `DE` (the confirmation byte) |
| Data | proof length (1) ‖ proof |

For good: no more loads, clears, records, limits, PINs or owners. A PIN set and
verified, and the owner's proof over `CashuCard/lock`. `6982` without the PIN;
`6B00` for another P2; `6985` already locked.

### RESET_CARD (0x51)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `51` |
| P1 | `00` |
| P2 | `AD` (the confirmation byte) |
| Data | proof length (1) ‖ proof |

The owner's proof over `CashuCard/reset`, on a card with nothing unspent: the card
as out of its packet, with a new key, keeping its clock. A locked card also wants
the PIN in this tap (`6982`). `6B00`, `6A90`, `6A91`, `6700`, `6A8D`.

### SET_TAG (0x52)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `52` |
| P1 | `00` on; `01` off |
| P2 | `00` |
| Data | proof length (1) ‖ proof ‖ the byte P1 says |

The owner's proof over `CashuCard/tag` and the byte. Switches the card's NFC tag.
`6B00`, `6986` locked, `6A90`, `6A91`, `6700`.

### REFRESH (0x53)

| Field | Value |
|---|---|
| CLA | `B0` |
| INS | `53` |
| P1 | `00` |
| P2 | `00` |
| Lc | proof length + 81 |
| Data | proof length (1) ‖ proof ‖ a Bitcoin block header (80) |
| Le | `04` |

**Response:** the card's `now`, 4 bytes. 2.0 ([D20](../docs/DECISIONS.md#d20)): the
owner's proof over `CashuCard/refresh` and the header. The header is held to
everything `SET_HEADER` holds one to and taken as it takes one (an older header
moves nothing); then the rollover count goes to 0, in the same transaction. No
PIN; any funds; a locked card too. `6A90`, `6A91`, `6A93`, `6A80`; `6700` for a
header of another length.

---

## The NFC tag application

A third applet of the package, instantiated under the NFC Forum's
`D2 76 00 00 85 01 01`: a read-only NFC Forum Type 4 Tag carrying one web address,
the same on every card (`FOXY-CARD-SPEC.md` 5.8). It answers its own `SELECT`,
`SELECT` of files `E103` and `E104` and `READ BINARY`, and nothing else. It finds
the card's applet by the AID `F0 43 41 53 48 55 43 41 52 44 01` to ask whether the
owner has switched it off.

---

## The clock and the limits

The card's clock (`now`) is the time in the newest block header it has taken
([SET_HEADER](#set_header-0x36), [REFRESH](#refresh-0x53), the anchored
[SET_OWNER](#set_owner-0x43)), and it only moves forward. Three limits, all the
owner's ([SET_LIMIT](#set_limit-0x34)), all off on a new card:

- **The daily limit** bounds what leaves the card in the day's window: 86,400
  seconds from the window's start. A payment that would take the window past it is
  `6A8F`, with nothing signed or burned.
- **The limit on one payment** makes a larger payment wait, by the card's own work.
- **The no-PIN allowance**, on a card with a PIN, is what it signs for in the window
  without the PIN. Over it, `6A94`, and the PIN is asked for the whole payment.

**What bounds a walked clock (2.0, D20).** A payment that finds the day over begins
a new window, and that is a roll, only while the rolls since the owner's last
`REFRESH` (or anchored `SET_OWNER`) are fewer than the rollover budget (default 7,
1 to 30, `SET_LIMIT`'s thirteenth byte). Past it the window stays where it is, and
what was signed for in it still counts, until the owner's phone sends `REFRESH`.
The first window a card begins (its start still 0) is not a roll. At a roll the
no-PIN count begins again only if the allowance is armed, by a `VERIFY_PIN` or an
owner's proof since it last did, and the roll spends the arming. `GET_CARD` bytes
76 to 78 say the rolls, the budget and the arming.

**Only a payment that moves value rolls (2.1, D26).** A roll is spent only by a
`SPEND_ALL_SIGN` that is signed and commits with something leaving the card for
good: the pieces less the card's own change (`SPEND_ALL_CHANGE`) above 0. A payment
whose change is the whole of its pieces is signed, as ever, and counted as nothing
in the window as it stands: it begins no day, first or later, and spends no roll.
No other command spends one: a header (`SET_HEADER`, `REFRESH`, the anchor),
`TELL_TIME`, a read, a PIN, an owner's grant, or a payment refused (`6A94`, `6A8F`,
or given up before its signature). A window also begins, as in 2.0, at the first
header after a limit set with no clock and at a `SET_LIMIT` that changes the day's
number; neither is a roll. The roll, the day's count and the payment's burn are one
transaction.

---

## Error Code Summary

| SW | Meaning |
|---|---|
| 9000 | Success |
| 6700 | Wrong length |
| 6982 | Security status not satisfied: the PIN (or a grant) needed and not given in this tap |
| 6983 | PIN blocked: the counter spent, or the PIN state 2 |
| 6984 | PIN not set |
| 6985 | Conditions not satisfied: already spent, no payment begun, allowance on a card with no PIN, already locked |
| 6986 | Card locked |
| 6A80 | Wrong data: not a point, a bad refund key, bits no header could carry, a budget outside 1–30 |
| 6A82 | Not found (the card's runtime): no applet of this name — a 0.x or 1.x card |
| 6A83 | Slot out of range |
| 6A84 | No space: no slot, or no change opening, free |
| 6A86 | Incorrect P1 or P2 |
| 6A88 | Slot empty, or no signature to give again |
| 6A8C | No card record |
| 6A8D | Card in use: something unspent where only an empty card may be changed |
| 6A8E | A dated piece on a card with no refund key |
| 6A8F | Over the day's limit |
| 6A90 | No owner |
| 6A91 | The owner's proof missing, wrong or used, or a command not open to an owned card |
| 6A93 | Too little work in a block header |
| 6A94 | A piece already on the card (`LOAD_PROOF`); the PIN needed for this payment (`SPEND_ALL_SIGN`) |
| 6A96 | Too many places for one signature |
| 6B00 | Wrong P1/P2 (a missing confirmation byte) |
| 6D00 | Instruction not supported |
| 6E00 | Class not supported |
| 6F00 | Signing failed |
| 63CX | Wrong PIN, X tries left |

---

## Proof Slot Layout

```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────
0       1     status      (00 empty, 01 unspent, 02 spent; written last)
1       8     keyset_id   (raw, the NUT-02 id's first 8 bytes)
9       4     amount      (uint32, big-endian)
13      32    nonce       (raw; the card rebuilds the P2PK secret from it)
45      33    C           (compressed point)
78      4     date        (locktime, seconds; 0 for none)
──────  ────
Total:  82 bytes per slot × 128 slots
```

The secret the card rebuilds, and signs the hash of within the `SIG_ALL` message,
is [NUT-XX](NUT-XX.md)'s format-4 secret. A piece loaded with the mint's proof also
has 96 bytes (`e ‖ s ‖ r`) beside its slot ([GET_DLEQ](#get_dleq-0x1a)).

---

## Session State (Transient)

Gone with the tap (`CLEAR_ON_DESELECT`): the PIN verified, the owner's nonce and
whether it is live, the owner's load grant, the change grant taken at `SELECT`, a
payment begun and its places, sum and change. Gone with the power: the time the
terminal told, and whether this time in the field has paid.

---

## Personalisation

A 2.0 card is set up in one tap, owner last, so a set-up cut short is finished by
the next:

1. `SET_PIN` (or none: a card may have no PIN), `VERIFY_PIN`.
2. `SET_CARD`: unit, refund key, mint.
3. `SET_OWNER` with the tip header as its anchor.
4. `GET_NONCE`, `SET_LIMIT` (thirteen bytes, with the rollover budget), if the
   holder wants limits.

An unowned empty card may be claimed by the first phone that sets it up
([`SECURITY-MODEL.md`](../docs/SECURITY-MODEL.md)); a card leaves the issuer
owned, or is set up in the holder's hands.

## Provisioning Flow (Top-Up)

The owner's phone: `GET_NONCE`, `ALLOW_LOAD`, then `LOAD_PROOF` (P1 = 1 with the
mint's proof) for format-4 pieces locked to the card key, three to a command
without proofs or one with. When online, `REFRESH` with the tip.

## Payment Flow (Offline Spend)

A till: `SET_HEADER` with the tip when it has one; `GET_INFO` (P1 = 1: the no-PIN
allowance), `GET_PIECES` (P2 = 3), `AUTH`; `SPEND_ALL_BEGIN`, `SPEND_ALL_OUTPUTS`,
`SPEND_ALL_CHANGE`, `SPEND_ALL_SIGN` (with `VERIFY_PIN` first unless the
allowance covers the payment); swap at the mint; load the change in the next tap
(the change grant) or the same one.
