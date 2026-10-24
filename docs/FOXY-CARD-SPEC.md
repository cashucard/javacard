<a id="foxy-card-a-specification-for-forking-cashu-javacard"></a>

# Foxy card specification (historical)

> Historical Foxy design, recorded at software 1.20 and incorporated into
> shared protocol 2.0 ([D18](DECISIONS.md#d18)). The current applet wire is
> [protocol 2.1](../spec/APDU.md): readers SELECT the full applet AID
> `F043415348554341524401`, which answers `02 01`. Owner labels use
> `CashuCard/…`; [D20](DECISIONS.md#d20) through [D26](DECISIONS.md#d26)
> record the shared protocol changes. Use the current APDU reference when
> implementing a reader.

A card that holds ecash and pays a Foxy by a tap, and the changes to make in a
fork of `cashucard/javacard` and in Foxy to get there.

The card's daily limit, its owner and its clock are specified in full in
`FOXY-CARD-DAILY-LIMIT.md`. This document keeps the part of them that the rest
of the specification leans on, and refers to that one for the whole. An earlier
draft had an allowance that only went down and an owner secret given to the
card; both are gone, and where the two documents differ, that one is what is
built.

<a id="0-what-this-is-based-on"></a>

## 0. Source baseline

- `cashucard/javacard`, applet 0.4, commit `c1f4580`, MIT. Its `spec/APDU.md`,
  `spec/NUT-XX.md` (Profile B and B+), `docs/DECISIONS.md` and the J3R180
  hardware report.
- The review made of applet 0.2 and its terminal, read again against 0.4.
- Upstream has spent a real card from an iPhone over CoreNFC and settled it at
  a mint (their hardware report). The transport is proven; nothing here
  depends on something nobody has run.

## 1. Goals

1. A person taps a card on a Foxy that is asking to be paid, types the card's
   PIN on that phone, and the payment is made or it fails, with nothing left
   in doubt.
2. The card's holder can see what is on it, put money on it and take money
   off it from their own Foxy.
3. A wrong or blocked PIN opens nothing, and on a card with an owner the PIN
   alone changes nothing but what it spends. A terminal that has been handed
   the PIN, however it is built, can take no more than the card's daily limit
   in a day: the card counts its day by Bitcoin block headers, and a terminal
   cannot make one for nothing. Only the owner's phone can set, change or remove
   the limit (5.7). A blocked card is not lost money: its owner's phone unblocks
   it. A lost card is not lost money where the card was set up to be
   recoverable (6).
4. The receiver is never shown "paid" for money it does not hold.

Not goals of the first version: paying a receiver that has no connection,
cards from other issuers, a card without a PIN, units other than sats.

<a id="2-what-the-person-sees"></a>

## 2. User flow

### 2.1 Paying by card (receiver's phone, receive invoice screen)

1. The receive screen has a third way to be paid beside the code and TAP:
   **CARD**.
2. CARD opens the PIN pad, titled with the amount: `PAY 1,180 SATS · CARD PIN`.
   The payer types their PIN. Nothing is checked yet; the phone cannot check
   a PIN without the card.
3. iOS's own sheet asks for the card: `Hold the card to the top of the phone`.
4. The card is read, asked to sign, and the phone goes to the mint. The screen
   says `KEEP THE CARD THERE` until change, if any, is back on the card, then
   `REMOVE THE CARD`.
5. One of:
   - **PAID**, the usual confirmation, with `CARD` as how it came.
   - **WRONG PIN**: `2 tries left.` Back to step 2. Nothing was taken.
   - **CARD BLOCKED**: `Too many wrong PINs. This card can no longer pay until
     its owner sets a new PIN on it.` The owner's phone unblocks it (2.2).
   - **NOT ENOUGH ON THE CARD**: `It holds 900 sats.` Nothing was taken.
   - **OVER THE CARD'S DAILY LIMIT**: the card holds enough, but what is left
     of today's limit cannot cover the payment. The phone reads the limit, what
     has been spent today and the card's day from the card before it sends the
     PIN, and says in plain words how much the card can still spend today and
     when its day turns. Nothing was taken.
   - **A DIFFERENT MINT**: `This card's money is at <mint>. This phone is at
     <mint>.` (first version; see 8.4).
   - **TAP THE CARD AGAIN**: the card left the phone before its change was
     written back. The payment is made; `212 sats of change are waiting to go
     back on the card.` Shown until it is written. The receiver cannot spend
     that change.
   - **NOT PAID**: the mint refused or could not be reached before anything
     was signed. Nothing was taken.
   - **CHECKING**: the card signed and the mint has not answered. The phone
     keeps asking; it ends as PAID or as money to go back on the card.

### 2.2 Menu › Flashcard (the holder's own phone)

As built; the screens themselves are in `FOXY-CARD-SCREENS.md`.

What the card keeps is a daily limit: the most it will sign for in one day
(5.7). The screens call it the daily limit, or the limit, and its menu row
CHANGE LIMIT.

1. **FLASHCARD** goes straight to the iOS sheet; no PIN. The screen then
   shows:
   - how fresh the mint's word on the card is (`Verified Just Now`; on a
     phone with no connection, when it last was, for the same pieces);
   - the mint it is at and its balance, and under it the card's daily limit
     (`DAILY LIMIT`, or `NO LIMIT`) and, with a limit, what is left of it today
     (`LEFT TODAY`) and when the day turns (`THE DAY TURNS AT`);
   - on the card's face, what is not ordinary: no PIN yet, locked, blocked,
     or pieces the mint says are spent.
2. **SET UP THIS CARD**, the first time: a PIN typed twice (or NO PIN: since
   software 1.16 a card may have none, and then it pays without one), a notice
   that this phone will be the card's owner, and a tap. It asks for no limit and
   suggests no figure: a new card has none. The one tap gives the card its PIN
   (if any), its record and, last, its owner key (5.6). Nothing can be
   added to a card with no PIN by whoever holds it, and nothing to a card
   with no owner. Cards are set up as cash for now (6). A card with no PIN is
   given one later from ADD PIN; a card with a PIN may be given a no-PIN limit
   (5.7a).
3. **ADD FUNDS.** An amount and a tap. The owner's phone is not asked for the
   PIN: it gives the card the owner's proof, and the card lets the money in
   for that tap (5.6). Any other phone is asked for the card's PIN. The money
   leaves this phone's balance and is on the card when the screen says so. If
   the card leaves early the pieces wait for it, and the screen says so until a
   tap writes them. Putting money on a card does not touch its limit.
4. **WITHDRAW.** An amount or all of it, the PIN, a tap, and it is in this
   phone's balance. The owner's phone withdraws, renews and takes everything
   off a card whatever its limit: in the same tap it lifts the limit with the
   owner's proof, spends under the PIN, and puts the limit back with the
   owner's proof, even when the spending fails part way. If the card leaves
   before the limit can be put back, the phone has written the old limit down
   first and puts it back at the next tap. A phone that does not hold the
   card's words cannot lift the limit, and says so.
5. **CHANGE PIN.** The new PIN, typed twice, and a tap. No old PIN is asked:
   the owner's phone does not know it, and the card takes the owner's proof in
   its place (5.6), so it works only on a phone that holds the card's words; on
   any other it fails, and the screen says so in plain words. It is also how a
   blocked card is opened: a blocked card, on its owner's phone, offers
   UNBLOCK, which is CHANGE PIN, and the screen then says CARD UNBLOCKED.
6. **CHANGE LIMIT.** Three steps, then a tap. (1) A full-screen warning, titled
   `SET DAILY LIMIT`, that says what a daily limit is, that only this phone or
   a phone restored from its seed phrase can change or remove it, and that if
   the seed phrase is lost the PIN and the limit on the card can never be
   changed; CONTINUE or CANCEL. (2) The app's SET AMOUNT screen, dollars first:
   `What would you like the daily limit to be?`, with NO LIMIT under NEXT as
   the way to remove a limit. (3) A confirmation, `YOU ARE APPLYING A DAILY
   LIMIT OF:` and the amount, with what it means (the card will spend no more
   than that in one day; the limit starts again by itself each day; only this
   phone, or one restored from its seed phrase, can change or remove it), or,
   for NO LIMIT, `YOU ARE REMOVING THIS CARD'S DAILY LIMIT.` and that the card
   will be able to spend everything on it; CONFIRM or CANCEL. The tap writes it
   to the card with the owner's proof; no PIN is asked. The exact words are in
   B7 of `FOXY-CARD-SCREENS.md`. Nothing suggests a figure, and no screen says
   more of the limit than that it is the most the card will spend in one day.
7. **The card's history**: what this phone has done with it. A card keeps no
   list of its own.
8. **TAKE BACK A LOST CARD.** For a card this phone funded as recoverable:
   after its date, the money comes back with no card (see 6). Built, and on
   no screen while cards are cash.

<a id="3-who-is-trusted-with-what"></a>

## 3. Trust boundaries

| Party | Holds | Can do wrong |
|---|---|---|
| Card | its key, the pieces, the PIN, its owner's public key, its clock (the time and hash of the newest block header it has taken, the difficulty of the hardest), the day | nothing by itself; it signs what it is asked, under its rules, up to the day's limit |
| Cardholder | the card and the PIN | pay twice from a copied card, if a receiver ever accepts without the mint |
| Owner's phone | the twelve words, and from them the card's owner key | with the card in hand: change the PIN, set or remove the limit, add funds, and so take everything. Without the card: nothing. It is a trustee, held on a leash of two things: its words and the card itself. For a holder with no phone of their own it is a friend's |
| Receiving phone | sees the PIN, talks to the card | ask the card to sign more than the amount shown, up to what is left of today's limit; keep change; write pieces the mint will refuse |
| Mint | decides what is spent | what any Cashu mint can |
| Whoever shows the card a block header | a header | move the card's clock forward to the time the header carries, if it shows the work (5.7), and so end a day and begin the next, no sooner than that time. Never move a clock backward. A header dated later than the network's own time has to be forged, which costs work (`FOXY-CARD-DAILY-LIMIT.md` 5.2) |

Three things shape the design. The receiver always goes to the mint before
saying paid, so a copied or pretend card gains nothing. A terminal sees the
PIN and chooses what to ask the card for, so nothing the PIN alone can reach
may bound it or change it: the PIN spends and nothing else, and what bounds the
spending is a number in the card's permanent memory that only the owner's proof
sets (5.3, 5.7). And the one thing a terminal cannot manufacture is tomorrow:
it can fetch a true "now" from the network, but not a later one, because a
header dated later has to have its work done, and a terminal does not have a
block's worth of it. So a window that only a newer block can end is a bound it
cannot walk round (5.7). Up to software 1.14 the time was signed by a key built
into the app, which anyone could copy, and that last sentence was not true.

<a id="4-what-the-review-found-and-what-the-fork-does"></a>

## 4. Review findings and fork changes

| # | Found | In upstream 0.4 | The fork |
|---|---|---|---|
| 1 | A blocked PIN took the PIN gate away | fixed (a blocked PIN counts as set) | keep; add a test that every gated command refuses in every PIN state |
| 2 | `SPEND_PROOF` lets the reader choose the signed 32-byte message independently of the stored piece | still so | the card works the message out itself from the slot; the reader supplies nothing (5.2) |
| 3 | `SIGN_ARBITRARY` signs anything and burns no slot, so SPENT enforces nothing | still there, behind the PIN | removed. Proving the card is the card gets its own command, whose signature cannot be a spend (5.2) |
| 4 | No DLEQ on the card, so a piece cannot be checked without the mint | still so | not needed while the receiver is online. From software 1.20 the card keeps the mint's proof for each piece, for a phone to read and check; the card checks nothing (5.9) |
| 5 | Factory GlobalPlatform keys left on the card | provisioning responsibility | the provisioning steps set new keys, and say so (5.4) |
| 6 | The terminal showed paid when the swap had failed, and booked another's spend as settled | upstream terminal behavior | Foxy's own rule: paid only when the mint has given this phone its pieces (8) |
| 7 | Over-payment is the merchant's income; change is not returned in the payment | by design upstream | change goes back to the card in the same tap, or waits for it (8.2) |
| 8 | A terminal with the PIN can spend every slot | by design upstream | a daily limit in the card's permanent memory, counted against a day the card keeps from the Bitcoin block headers it is shown: every spend adds the whole piece signed to today's total, a piece that would take the day past the limit is refused, and only the owner's proof sets or removes the limit (5.3, 5.7). It bounds a terminal to one day's limit per visit, honest or not: a terminal cannot start another day without a header dated later, which has to be a real block or a forgery that costs work (5.7). Two earlier tries failed: a limit on one PIN entry was walked round by a terminal that had the PIN, and an allowance that only went down and only the owner's proof raised held against a terminal but stopped a card whose owner's phone was not at hand |
| 9 | A blocked or lost card strands its balance | acknowledged; no unblock | a blocked card is unblocked by its owner's phone (`CHANGE_PIN`, 5.6); for a lost card, a refund path the funding phone holds (6) |
| 10 | The card does not say which mint its pieces are at | open question upstream | the card records its mint (5.1) |
| 11 | The PIN crosses the air in the clear | so | phase 2: sent under a key agreed with the card. Nothing of the owner crosses the air: the card holds only the owner's public key, and a proof is a signature over a nonce the card has just given (5.6) |
| 12 | `CHANGE_PIN` needs a verified session and the old PIN, both of which a terminal handed the PIN has: it can set a PIN the holder does not know, and the holder's wrong tries then block the card for good | so | the owner's proof replaces both: `CHANGE_PIN` takes the proof and the new PIN only, no old PIN and no session, so the owner's phone can change the PIN, or unblock a blocked card, without knowing the PIN (5.6) |
| 13 | `LOCK_CARD` needs the PIN only if one is set: any reader can lock a card with no PIN for good, and a terminal that has the PIN can lock a funded card | so | a PIN set and verified, and the owner's proof (5.6); a card with no owner cannot be locked |
| 14 | A card with no PIN can be claimed by any reader: it can set the PIN, and in the fork the owner | so | a card with no owner is open while it is empty and cannot be loaded, so a claimed card holds nothing. A card with an owner is its owner's, empty or not: a terminal that holds the PIN and empties the card cannot then set its own PIN, owner, record or limit (5.3). A card still leaves the issuer's hands set up (5.4) |

## 5. The card

<a id="51-what-it-stores"></a>

### 5.1 Stored state

A card record. `SET_CARD` writes the unit, the refund key, the mint and the
flag that it has run, and never the limit, the day, `now` or the block fields.
The limit is written by `SET_LIMIT`; `now` and the block fields by
`SET_HEADER`; the window and what has been spent by `SET_LIMIT`, by `SPEND`, and
by `SET_HEADER` for the window of a limit set before the card had taken a
header.

| Field | Size | |
|---|---|---|
| format | 1 | 3 for this design |
| set | 1 | 1 once `SET_CARD` has run |
| unit | 1 | sats |
| limit | 4 | the most the card signs for in one day, in sats, big-endian; **0 is no limit, and is what a new card has** |
| refund key | 33 | the key that can take the pieces back after their date, or zeros for none |
| hardest bits | 4 | the difficulty of the hardest block header the card has taken, as the header carries it (`bits`, little-endian); zeros until it has taken one. Record offset 120. Written by `SET_HEADER`, and only upward |
| last header | 32 | the hash of the newest header taken, as Bitcoin shows a block hash. Offset 124. Written by `SET_HEADER` |
| (unused) | 29 | zeros. With the two rows above, the 65 bytes where the time key was up to software 1.14; `GET_CARD` still answers them, at offset 40 |
| now | 4 | the time of the newest block header the card has taken, seconds, big-endian; 0 until it has taken one. Written only by `SET_HEADER`, and by nothing that lowers it |
| window start | 4 | when the current day began; written by `SET_LIMIT`, by a `SPEND` that begins a new day, and by the first header taken after a limit was set while `now` was 0 |
| spent today | 4 | what the card has signed for since the window began |
| mint | 1 + up to 77 | the mint's address, as text |
| design | 3 | the card's face: a code of three characters, capital letters and digits, naming a design in docs/CARD-DESIGNS.md; zeros for none. Written by `SET_CARD` when given, cleared by one that is not (1.10) |

The mint is at most 77 characters (the earlier draft allowed 96; 80
before the design). The reason is one command: `SET_CARD` with the owner's
proof on a card that has an owner carries a proof of up to 72 bytes, 100 bytes
of record, the mint and the design, and a short APDU holds 255 data bytes in
all (1 + 72 + 100 + 77 + 3 = 253).

`GET_CARD` answers the record as the table has it, the mint and then the three
bytes of design; a phone that knows no design reads the mint by its length and
ignores what follows. `SET_CARD` takes the record with the design after the
mint, or without it, as a phone that knows none sends it: then the card has
none.

Kept apart from the record: the **owner key**, 65 bytes uncompressed, and a
flag that one has been given (`GET_INFO` byte 16). See 5.6. And, from software
1.12, the **openings of the card's own change**: eight places of 80 bytes (the
amount, the keyset, the date, the nonce and the blinding factor of a change
output the card made for itself at `SPEND_ALL_CHANGE`), each with a state
(empty; drafted for a payment not yet signed for, let go at the next
`SPEND_ALL_BEGIN`; pending, signed for and waiting for its piece), read by
`GET_CHANGE` and let go when a piece with that nonce is written on. Kept in RAM, gone
with the tap: the **nonce** the card last gave for an owner's proof and whether
it is still live, and whether `ALLOW_LOAD` has been given in this tap.

The owner key is a NIST P-256 (secp256r1) public key. Signatures are ECDSA with
SHA-256 in DER form, and the key is uncompressed (`04 ‖ X ‖ Y`, 65 bytes). It
has nothing to do with the card's own secp256k1 key or with Cashu. The applet
sets the curve's parameters on the key itself and relies on no default. Up to
software 1.14 a second key of the same kind, the time key, was in the record;
there is none now (5.7).

A slot, 82 bytes (upstream's 78 and a date):

| Field | Size | |
|---|---|---|
| status | 1 | empty, unspent, spent; written last, as upstream's D14 |
| keyset | 8 | raw |
| amount | 4 | |
| nonce | 32 | |
| C | 33 | |
| date | 4 | the locktime of this piece, 0 for none |

128 slots (10,496 bytes, and 130 more a slot for the text a payment hashes);
64 before software 1.7. From software 1.20 the card also keeps, for each place, 96
bytes of the mint's proof for the piece in it (e, s and r: 5.9), in a store of its
own that the first `SET_CARD` reserves, 12,288 bytes.

The text of a piece's secret, which is what the card signs the hash of, is
the text Foxy's Cashu library writes for a piece locked to one key:
`["P2PK",{"nonce":"…","data":"<card key>","tags":[]}]`, and with a date
`…"tags":[["locktime","<date>"],["refund","<refund key>"]]}]`. The card builds
what the library builds, so loading a card is an ordinary locked payment and
nothing is made specially for it. It is not upstream's text.

### 5.2 Commands

| Command | Upstream | Fork |
|---|---|---|
| SELECT | version | a new AID of our own, so the two applets cannot be mistaken for each other; answers its version (1.1 when first written, 1.20 now: `01 14`) |
| GET_INFO | 8 bytes | 29: adds the format, tries left, locked, record set, the daily limit, whether the card has an owner, and the day (`now`, window start, spent today). With P1 = 1, 42: the limit on one payment (to the owner's grant only), the no-PIN allowance and what is counted against it (to anyone; software 1.16). With P1 = 2 (software 1.19), 43: those 42 and whether the NFC tag is on (to anyone; 5.8) |
| GET_PUBKEY | as is | as is |
| **GET_DLEQ** (`1A`) | none | software 1.20: the mint's proof kept with an unspent piece, for one place or two. No PIN. The card does not check it (5.9) |
| GET_CARD | none | the card record, with the daily limit and, where the time key was, the clock's proof (the hardest `bits` and the newest header's hash) |
| GET_SLOT_STATUS, GET_PROOF | as is | the slot with its date |
| GET_BALANCE, GET_PROOF_COUNT | as is | as is |
| **SPEND** | takes a slot and 32 bytes from the reader | takes a slot only. The card builds the piece's secret from the slot and its own key, hashes it, and, when a daily limit is set, refuses (`6A8F`) a piece that would take today past the limit, with nothing signed and nothing burned. Otherwise it signs (in RAM), then marks the slot spent and adds the piece's whole amount to what has been signed today, in one transaction, and only then sends the signature: a card pulled away while it signs has burned and sent nothing, and no signature leaves for a piece not burned. No message comes from outside |
| **SIGN_ARBITRARY** | signs any 32 bytes | **removed** |
| **AUTH** | none | the reader sends 16 random bytes; the card answers 16 of its own and a signature over a tagged hash of both and its key. No PIN. It cannot be a spend: the tag makes the message one no secret hashes to |
| VERIFY_PIN | as is | as is. It changes nothing about spending: it can be sent as often as its sender likes |
| SET_PIN | sets a PIN once (`6985` if one exists) | sets or replaces the PIN, and unblocks, only on a card with no owner and nothing unspent. No PIN, no proof. A card with an owner refuses it (`6A91`), unless it has no PIN and the owner's grant is in this tap (ADD PIN, software 1.16) |
| CHANGE_PIN | the old PIN, in a verified session | the owner's proof and the new PIN only: no old PIN, no session, any PIN state, any funds. It sets the PIN, resets the tries and unblocks (5.6) |
| SET_CARD | none | writes the card record (unit, refund key, mint; the 65 bytes where the time key was are sent and not read). On a card with no owner under the PIN (or none, if it has no PIN: software 1.16), on a card with an owner under the owner's proof; only with nothing unspent. Never touches the limit or the clock |
| LOAD_PROOF | 77 bytes | 81 bytes, with the date; refused unless a PIN is set and verified or the owner has allowed loading for this tap (a card with no PIN, 1.16, takes a piece from whoever holds it); refused on a card with no owner. It asks nothing of the clock. Never touches the limit. With P1 = 1 (software 1.20), one piece and the mint's proof for it, 177 bytes (5.9) |
| CLEAR_SPENT | as is | as is, or under the owner's grant for this tap |
| LOCK_CARD | the PIN if one is set | a PIN set and verified, and the owner's proof (5.6) |
| **RESET_CARD** (`51`) | none | software 1.17: the owner's proof (and, on a locked card, the PIN given in this tap) wipes the card to what it was out of its packet, with a new key of its own, for another person to set up. Only with nothing unspent (5.6a) |
| **SET_TAG** (`52`) | none | software 1.19: the owner's proof switches the card's NFC tag off or on (5.8). No PIN, any funds. The tag itself is a third applet of the package, under the NFC Forum's own name |
| **SET_LIMIT** (`33`, `34`) | none | the daily limit (5.7): `34` by the owner's proof, on any card with an owner and any funds, with no PIN; `33` by the PIN, on a card with no owner while it is empty. 0 is no limit. Four bytes are the day's limit; eight are the day's and then the limit on ONE PAYMENT, which asks no clock and makes a larger payment wait (`FOXY-CARD-DAILY-LIMIT.md`, 6a); twelve (software 1.16) add the NO-PIN ALLOWANCE (5.7a), which a card with no PIN refuses (`6985`). None needs a clock to be set. (`33` was once a limit on one PIN entry, which a terminal that had the PIN walked round; it is not that) |
| ~~SET_TIME~~ (`35`) | none | gone in software 1.15 (`6D00`). It told the card a time under the time key's signature |
| **SET_HEADER** (`36`) | none | shows the card a Bitcoin block header (software 1.15). The card believes it for its work, and a later time in it moves the card's clock forward; it only moves forward (5.7) |
| **TELL_TIME** (`37`) | none | gives the card the terminal's own clock, as a note for its receipts and log (software 1.15). The card trusts it for nothing |
| **SET_OWNER** (`43`) | none | gives the card its owner's public key (5.6) |
| **GET_NONCE** (`44`) | none | a fresh 16 bytes for one owner's proof. No PIN (5.6) |
| **ALLOW_LOAD** (`45`) | none | the owner's proof lets `LOAD_PROOF` and `CLEAR_SPENT` through, with no PIN, for the rest of this tap (5.6) |

**The instructions of this fork, by byte** (class `B0`; `spec/vectors/transcript.json`
has most of them as commands and answers):

| INS | Command | Needs | Data sent | Answers |
|---|---|---|---|---|
| `01` | GET_INFO | | | 29 bytes: version (2), slots, unspent, spent, empty, capabilities, PIN state (0 none, 1 set, 2 blocked), format, tries left, locked, record set, limit (4), has owner (1); then `now` (4), window start (4), spent today (4); then whether this tap may put change on with no PIN (1), 30 bytes in all. With P1 = 1, 42: those thirty, then the limit on one payment (4, the owner's grant only, zeros to anyone else), the no-PIN allowance (4) and what has been signed for with no PIN in the window (4), both to anyone (software 1.16; zeros up to 1.15). With P1 = 2 (software 1.19), 43: those 42, then whether the NFC tag is on (1: `00` on, `01` off, to anyone) |
| `10` | GET_PUBKEY | | | the card's 33-byte compressed key |
| `11` `12` `13` `14` | GET_BALANCE, GET_PROOF_COUNT, GET_PROOF, GET_SLOT_STATUS | | | as upstream, except that GET_PROOF returns the 82-byte slot |
| `15` | AUTH | | 16 random bytes | 16 of the card's own and a signature |
| `16` | GET_CARD | | | format, record set, unit, limit (4), refund key (33), then 65 bytes at offset 40: the hardest header's `bits` (4), the newest header's hash (32) and 29 zeros (a time key up to software 1.14), mint length, mint |
| `17` | GET_PIECES | | P1 = the first slot to report | one page: the first slot the page does not cover (1), then for each slot in the range that is not empty a tag (1) and, for an unspent slot, its 81 bytes (FOXY-CARD-DAILY-LIMIT.md 8.1). `6A83` for a P1 of 64 or more |
| `18` | GET_LOG | the PIN verified in this tap, or the owner's grant; with P1 = 1 (receipts) the owner's grant only | with P1 = 1, P2: how many receipts back from the newest to begin | the card's own account of its taps (`FOXY-CARD-DAILY-LIMIT.md` 6b): 16 bytes of counts, then up to eight taps of 20 bytes (16 before software 1.15), newest first: the clock (4), sats signed for (4), pieces signed (1), refused (1), flags (1), pieces put on (1), sats put on (4), the time the terminal told (4). With P1 = 1: the count of payments (4), then up to three receipts of 77 bytes (73 before 1.15), newest first: the clock (4), the time the terminal told (4), the sats (4), SHA-256 of the message signed (32), the first output's blinded message (33). `6982` to anyone else |
| `20` | ~~SPEND_PROOF~~ | | | gone with format 4: `6D00`. Up to format 3 it signed for one slot, over that piece's secret alone |
| `22` `23` `24` | SPEND_ALL_BEGIN, SPEND_ALL_OUTPUTS, SPEND_ALL_SIGN | `24`: no PIN set, or the PIN, or the no-PIN allowance (5.7a); `22` and `23` ask nothing | the places of a payment; then the swap's outputs, 37 bytes each; then nothing | **one** 64-byte signature over every piece and every output (NUT-11 `SIG_ALL`), with every place burned in the same transaction. The limits are held to what leaves the card: the pieces less the card's own change (`26`), worked out at the first SIGN, where the day refuses (`6A8F`) and the wait begins (00 01, "not yet"). Not opened by `ALLOW_LOAD` (FOXY-CARD-DAILY-LIMIT.md 6c) |
| `26` | SPEND_ALL_CHANGE | as `22`; a payment begun, its outputs (`23`) all given | the amount (4) | one change output the card makes for itself (software 1.12): a fresh nonce, the secret in the card's own form (its key, the payment's date and refund key, `SIG_ALL`), hashed to the curve as NUT-00 says and blinded with a fresh factor; hashed into the message as an output, after the terminal's; the opening (amount, keyset, date, nonce, blinding factor) is kept until the piece is written back. Answers the blinded message, 33 bytes. At most 8 openings on a card. `6985` with no payment begun; `6A80` for nothing, or more change than the pieces come to; `6A84` with no opening free; the terminal's outputs after it are `6985`, and the payment is given up |
| `19` | GET_CHANGE | nothing | P1 = the page, from 0 | the openings of the change the card has made for itself and not yet been handed, three to a page: a count (1), then for each the amount (4), the keyset (8), the date (4), the nonce (32) and the blinding factor (32). An opening whose piece is on the card by now is let go first. The phone that owes the change finishes the pieces with these; the owner's phone finishes change a till never handed over (NUT-09 restore). What they say lets a reader finish a piece locked to the card's key, which nobody but the card can spend |
| `1A` | GET_DLEQ (software 1.20) | nothing: no PIN, any state, locked or not | P1 = a place (0 to 127); P2 = a second place, or `FF` for none | for each place asked, in the order asked: `01` and the 96 bytes e, s and r where the place is unspent and its record is not zero, and otherwise the single byte `00` (empty, spent, a piece that came with no proof, or a card with no room for proofs). At most 194 bytes. `6A83` for a P1 over 127, or a P2 over 127 and not `FF`, before anything is answered. The card does not check what it gives (5.9) |
| `25` | SPEND_ALL_AGAIN | PIN, if one is set, unless the last signature was given with no PIN (software 1.16) | | the last signature given, again, for a terminal that never heard it |
| `30` | LOAD_PROOF | an owner; a PIN set, and verified or `ALLOW_LOAD` given in this tap; a card record. No clock | 81 bytes; or two or three pieces end to end; or, with P1 = 1 (software 1.20), one piece and its proof, 177 bytes | `6982` with no verified PIN and no grant (the gate comes first); then `6A90` with no owner; `6A94` for a piece whose nonce is already in a slot, spent or not (checked last, before anything is written). The answer is the place of each piece stored; with P1 = 1, two bytes: the place, then `01` where the proof was kept and `00` where the card has no room for proofs. `6700` for any length but 177 with P1 = 1; `6A80` for a proof of 96 zero bytes (5.9) |
| `31` | CLEAR_SPENT | the PIN, if one is set, or `ALLOW_LOAD` given in this tap | | |
| `32` | SET_CARD | no owner: the PIN verified if one is set (software 1.16: none, open), nothing unspent. Owner: the owner's proof, nothing unspent | unit (1), refund key (33), 65 bytes the card does not read (zeros from a phone of software 1.15; a time key from an earlier one), mint length (1), mint; with an owner, proof length (1) and the proof first | `6A8D` if anything is unspent; `6A80` for a bad refund key; `6700` for a bad length. The clock, the window and what is spent are left as they are |
| `33` | SET_LIMIT, PIN form | a card with no owner: PIN set and verified; nothing unspent. No clock | limit (4), or eight bytes: the day's and then the one payment's | `6A91` on a card with an owner (use `34`); `6A8D` if anything is unspent |
| `34` | SET_LIMIT, owner's form | the owner's proof. No PIN, any funds. No clock | proof length (1), proof (DER), limit (4), or eight bytes, or twelve (software 1.16: the day's, the one payment's and the no-PIN allowance) | `6A90`, `6A91`; `6985` for a twelve-byte form with an allowance on a card with no PIN; `6700` for any other length; `6986` on a locked card |
| `35` | ~~SET_TIME~~ | | | gone in software 1.15: `6D00`, and the instruction stays unassigned. Up to 1.14: a time (4), a signature length (1) and a signature (DER) by the time key, answered with the card's `now` |
| `36` | SET_HEADER | nothing: no PIN, no owner, no record, any state | a Bitcoin block header, 80 bytes, as the network carries it | the card's `now` (4, big-endian), whether the header was taken or was no later than the clock. The card hashes the 80 bytes twice with SHA-256; the hash, read as a little-endian number, must be at or under the target the header's `bits` name, at or under the floor built into the applet (`bits` `0x17087BC0`) and, once a header has been taken, at or under four times the target of the hardest taken. `6A93` for too little work in any of the three senses; `6A80` for a `bits` no header could carry; `6700` for any length but 80. A header with a later time moves `now` to it, begins the window of a limit set before any header, and keeps the hardest `bits` and the newest hash. Drops a payment begun (`FOXY-CARD-DAILY-LIMIT.md` 5.1) |
| `37` | TELL_TIME | nothing: no PIN, no owner, no record, any state | the terminal's own clock, 4 bytes, big-endian seconds | nothing. `6700` for any length but 4. Kept in RAM for this time in the field, and written into the receipts and the log entries made in it; trusted for nothing (`FOXY-CARD-DAILY-LIMIT.md` 5.3). Drops a payment begun |
| `40` | VERIFY_PIN | | the PIN, 4 to 8 bytes | changes nothing about spending |
| `41` | SET_PIN | a card with no owner, nothing unspent. No PIN, no proof. Or (ADD PIN, software 1.16) a card with an owner and no PIN, with the owner's grant (`ALLOW_LOAD`) in this tap, any funds | the PIN | sets or replaces the PIN and unblocks; `6A91` on a card with an owner that has a PIN, or has none and no grant (use `42`); `6A8D` if anything is unspent on a card with no owner; `6986` locked. The allowance is nothing |
| `42` | CHANGE_PIN | the owner's proof. No PIN, no session, any PIN state, any funds | proof length (1), proof (DER), the new PIN | sets the PIN and resets the tries; ends any verified session; `6A90`, `6A91`; `6986` locked |
| `43` | SET_OWNER | no owner: nothing unspent. Owner: the owner's proof, nothing unspent | 65 bytes, the owner's public key, uncompressed; with an owner, proof length (1) and the proof first | sets or replaces the owner; `6A8D` if anything is unspent; `6A91` with an owner and no good proof; `6A80` for a key not beginning `04`; `6700` other length; `6986` locked |
| `44` | GET_NONCE | a card with an owner. No PIN | | 16 bytes, or `6A90` |
| `45` | ALLOW_LOAD | the owner's proof, over `FoxyCard/load` and no value | proof length (1), proof | for the rest of this tap: `LOAD_PROOF` and `CLEAR_SPENT` need no verified PIN. `6A90`, `6A91`; `6986` locked |
| `51` | RESET_CARD (software 1.17) | the owner's proof; on a locked card the PIN as well; nothing unspent | P1 = `00`, P2 = `AD`; proof length (1), proof (over `FoxyCard/reset` and no value), nothing after it | nothing. `6B00` for a P1 or P2 not those, before anything else; `6A90` with no owner; `6A91` with no good proof; `6700` for bytes after the proof; `6982` on a locked card whose PIN has not been given in this tap; `6A8D` with anything unspent. A blocked PIN is no bar |
| `52` | SET_TAG (software 1.19) | the owner's proof; no PIN, any funds | P1 = `00` tag on, `01` tag off; P2 = `00`; proof length (1), proof (over `FoxyCard/tag` and the one byte after it), then that one byte, the same as P1 | nothing. `6B00` for a P1 or P2 not those, before anything else; `6986` on a locked card; `6A90` with no owner; `6A91` with no good proof (no PIN try); `6700` for anything but one byte after the proof; `6B00` for a byte that is not P1. The state it already has is `9000` and writes nothing (5.8) |
| `50` | LOCK_CARD | PIN set and verified; the owner's proof | P2 = `DE`; proof length (1), proof | `6982` with no verified PIN; `6A90` with no owner; `6A91` with no good proof |

`21` (`SIGN_ARBITRARY`) stays unassigned. The applet's version is 1.1 and
`FORMAT` is 3; a phone that knows only an earlier format refuses the card, as it
does now for anything but its own. (That is how the rows not marked with a later
software version were first written. The applet is now at 1.20, `SELECT` answers
`01 14`, and `FORMAT` is 4; where this table and `FOXY-CARD-DAILY-LIMIT.md`
section 8 differ, that one is what is built.)

**Every command in every state.** "Open" means nothing is needed beyond what
the command's own row says; "refused" means `6A91` unless another word is given.

| Command | Card with **no owner** | Card **with an owner** |
|---|---|---|
| `GET_INFO`, `GET_PUBKEY`, `GET_BALANCE`, `GET_PROOF_COUNT`, `GET_PROOF`, `GET_SLOT_STATUS`, `GET_PIECES`, `GET_DLEQ` (1.20), `AUTH`, `GET_CARD` | open | open |
| `SET_HEADER`, `TELL_TIME` | open: any state, locked or blocked (a header must show its work) | same |
| `GET_NONCE` | `6A90` | open (it only gives a number) |
| `VERIFY_PIN` | as ever | as ever |
| `SPEND_ALL_BEGIN` | open (software 1.16) | open |
| `SPEND_ALL_SIGN`, `SPEND_ALL_AGAIN` | the PIN, if one is set (such a card holds nothing) | no PIN set: open, up to the limits; the PIN, or the no-PIN allowance (5.7a), up to the limits |
| `LOAD_PROOF` | refused `6A90` | PIN verified, or the `ALLOW_LOAD` grant in this tap |
| `CLEAR_SPENT` | the PIN, if one is set | the PIN, or the grant; with no PIN set (1.16), anyone |
| `SET_PIN` (`41`) | open while nothing is unspent (sets or replaces, unblocks) | refused, empty or not: the owner uses `CHANGE_PIN`; except a card with no PIN, under the owner's grant in this tap (ADD PIN) |
| `CHANGE_PIN` (`42`) | `6A90` | the owner's proof, empty or not, any PIN state |
| `SET_CARD` (`32`) | the PIN verified if one is set (none: open), while nothing is unspent | the owner's proof, and nothing unspent (`6A8D`) |
| `SET_LIMIT` (`33`, PIN form) | PIN set and verified, while nothing is unspent | refused |
| `SET_LIMIT` (`34`) | `6A90` | the owner's proof, empty or not |
| `SET_OWNER` (`43`) | open while nothing is unspent | the owner's proof, and nothing unspent |
| `ALLOW_LOAD` (`45`) | `6A90` | the owner's proof |
| `LOCK_CARD` (`50`) | `6A90` (after the PIN gate) | PIN set and verified, and the owner's proof |
| `RESET_CARD` (`51`, software 1.17) | `6A90` | the owner's proof, nothing unspent; on a locked card the PIN as well |
| `SET_TAG` (`52`, software 1.19) | `6A90` | the owner's proof, empty or not, no PIN; `6986` on a locked card |

So the one thing a terminal with the PIN and an emptied card can still do is
load pieces onto it (which the mint will refuse) and spend them. It cannot set
its own PIN, owner, record or limit.

Status words the fork added or moved, in a part of `6Axx` ISO 7816-4 leaves
unassigned:

| SW | Means |
|---|---|
| `6A8D` | card in use: a thing that is set only on an empty card, on a card with an unspent piece |
| `6A8F` | over the day: this piece would take today past its limit. Nothing signed, nothing burned |
| `6A90` | no owner: a command that needs the owner's proof, or `GET_NONCE`, or a load, on a card that has none |
| `6A91` | the owner's proof is missing or is not the owner's, or this command is not open to a card with an owner. Costs no PIN tries, changes nothing, does not end the PIN session |
| `6A92` | unused. It was "no time", for a card never told the time; since software 1.15 a card spends its first day on trust and nothing answers it |
| `6A93` | little work: a `SET_HEADER` whose work is not enough, whether not its own difficulty's, under the floor, or under a quarter of the hardest header taken. Nothing changes. (Up to 1.14: "not the time", a `SET_TIME` whose signature was not the time key's) |
| `6A94` | on the card already: a `LOAD_PROOF` of a piece whose 32-byte nonce is the nonce of any non-empty slot, spent or unspent. Nothing is written, and the amount stated is not looked at. A slot that `CLEAR_SPENT` has freed is empty, so that piece may be loaded again then. Also (software 1.16), from `SPEND_ALL_SIGN`: the PIN is needed, for the whole payment; the card has one that was not given and the no-PIN allowance does not cover the payment. Nothing is signed, burned, counted or logged, and the payment is given up (5.7a) |

`SET_HEADER` also answers `6A80` (ISO's own word for wrong data) for a `bits` no
header could carry: a size of 0 or of more than 32, or a mantissa with its top
bit set.

<a id="53-rules-the-applet-must-keep"></a>

### 5.3 Applet invariants

1. **No signature without a slot burned.** The only signing paths are SPEND
   and AUTH. SPEND marks the slot spent before the signature leaves, as now.
2. **The PIN gate is the first statement** of every gated command, in every
   PIN state, including blocked. One test walks every command through every
   state. (Since software 1.16 a spend's
   gate is at its signature, where the no-PIN allowance stands beside the PIN:
   5.7a.)
3. **A daily limit, counted against a day the card keeps.** The card keeps
   the most it will sign for in one day, in sats, in permanent memory (0 is no
   limit, and is what a new card has), and the day itself: `now`, the time in
   the newest Bitcoin block header it has been shown, which only moves forward;
   and a window, begun when the limit is set and ended only by a newer block.
   A `SPEND` that would take today's total past the limit is refused (`6A8F`)
   before anything is signed or burned; otherwise the total and the slot's
   status change in one transaction, and the signing comes after. Only the
   owner's proof sets, changes or removes the limit (on a card with no owner,
   the PIN does, while it is empty). `VERIFY_PIN`, a new SELECT, a reset,
   `SET_CARD` and loading pieces do not touch it, and nothing a terminal that
   has the PIN can send changes it except by spending.
   (A limit on one PIN entry, kept in RAM, was tried first: a terminal that
   had the PIN sent it again between spends, or set the limit to nothing. It
   is gone. The limit on one payment that the card has now is not that: it is
   a second number in permanent memory that refuses nothing and asks no clock;
   a payment over it waits, by the card's own work, for every limit's worth
   past the first.) The whole text is `FOXY-CARD-DAILY-LIMIT.md`, sections 3 and 6.
4. **Three tries**, then blocked, as upstream. The owner's proof unblocks it
   (`CHANGE_PIN`), and a wrong proof costs no tries. The refund path (6) is a
   second way out, for a card set up as recoverable.
5. **Nothing can be added without a PIN set, or the owner's grant.** Upstream
   ships cards with no PIN, on which any reader in range can write and spend.
   Since software 1.16 a card may have no PIN, and then it pays without one, but
   it is loaded only under the owner's grant (or, for change, in the tap after a
   payment): any reader in range can spend such a card up to its limits, and
   cannot write to it.
6. Every buffer allocated at install, and the status byte written last, as
   upstream's D10 and D14. One exception, since software 1.20: the store of the
   mint's proofs is reserved by the first `SET_CARD`, once, because the chip
   will not install an applet that asks for it in the constructor (5.9).
7. **The PIN spends and nothing else; the owner's proof administers.** On a
   card with an owner the PIN can `SPEND` (up to the day's limit),
   `LOAD_PROOF` (change written back) and `CLEAR_SPENT`, and changes nothing
   else: not the PIN, the limit, the record or the owner.
   `CHANGE_PIN`, the owner's `SET_LIMIT` (`34`), `SET_OWNER`, `SET_CARD`,
   `ALLOW_LOAD` and `LOCK_CARD` each need an ECDSA signature by the owner key
   over a label of the command, a nonce the card has just given and the value
   (5.6). They need no PIN, because the owner's phone does not know it
   (`LOCK_CARD` keeps its PIN as well). A wrong proof costs no PIN tries,
   changes nothing and does not end the PIN session.
8. **A card with an owner is its owner's, empty or not; a card with none is
   open while it is empty, and cannot be loaded.** A terminal that has the PIN
   can make a card empty whenever its balance fits within the day's limit, so
   on a card with an owner everything that sets or replaces the PIN, the owner,
   the card record or the limit needs the owner's proof whether or not the card
   holds anything; replacing the owner or the record needs the card to be empty
   as well. `LOAD_PROOF` is refused (`6A90`) on a card with no owner. It asks
   nothing of the clock: a card that has been shown no block header spends its
   first day on trust (5.7).
9. **The owner adds funds with no PIN.** `ALLOW_LOAD` lets `LOAD_PROOF` and
   `CLEAR_SPENT` through for the rest of that tap, and nothing else: it never
   opens `SPEND`. It is held in transient memory, so a new SELECT or a reset
   ends it.
10. **A place that is unspent holds its own proof, or zeros (software 1.20).** In
    the store of the mint's proofs a place that is unspent has the proof its piece
    came with, or 96 zero bytes if it came with none, and never another piece's.
    `LOAD_PROOF` writes the place's record before anything else of the place, and
    the status byte stays the last; nothing else writes the store but `RESET_CARD`,
    which zeros it. No payment command writes it (5.9).

### 5.4 Provisioning

- Card: NXP J3R180, dual interface, supplied with known keys.
- Build from the fork's tag; compare the CAP's hash with the one CI made
  before installing.
- After installing: put the card's GlobalPlatform keys to new random ones and
  write them down, or lock the issuer domain. A card left on factory keys can
  have the applet deleted, and the money with it, by anyone with a reader. It can
  also have the tag's applet deleted and another put in its place, carrying another
  address (5.8); rotating the keys closes both.
- The card's key is made on the card at install and never leaves it.
- The card's clock needs no provisioning: there is no key to write. A card
  begins with no header taken, and takes its first from whoever shows it one
  (5.7).
- **A card with no owner is open while it is empty, and cannot be loaded.** Any
  reader in range can give it a PIN, a record and an owner of the reader's
  choosing (`SET_PIN`, `SET_CARD`, `SET_OWNER`), and the holder's own set-up
  then finds it already taken. That is accepted: such a card holds nothing,
  `LOAD_PROOF` answers `6A90`, and so there is nothing on it to steal; and a
  card with an owner is its owner's, empty or not. A card still leaves the
  issuer's hands set up (PIN, record, then owner: 5.6), so that nobody has to
  think about it.

<a id="55-how-it-is-tested"></a>

### 5.5 Verification

- jCardSim: every command in every PIN state and, where it matters, in each
  owner state (none, one); SPEND's message against the secret Foxy builds for
  the same slot, byte for byte, for dates of zero and not; AUTH's signature
  never verifying as a spend; torn writes (the upstream slot-order tests,
  extended to the new fields).
- The daily limit, the clock, the owner key and its proofs, and the takeover of
  an emptied card, as `FOXY-CARD-DAILY-LIMIT.md` section 12 sets out. In short:
  a terminal that sends the PIN between four spends of one piece each, with a
  limit of one piece, takes one, however it is repeated, and takes a second only
  after a header a day later; exactly the limit goes and one sat more does
  not, with nothing burned; every command that needs the owner's proof is
  refused with the PIN alone, with a nonce and no proof, with another key's
  signature, with another command's label, for an earlier nonce, for another
  value, and for a proof that has worked once already, and is accepted with the
  right proof and no PIN; a card with an owner refuses `SET_PIN`, `SET_OWNER`,
  `SET_CARD` and the PIN form of `SET_LIMIT` without the proof even when it is
  empty; a wrong proof costs no PIN tries. A test reads the source and checks
  that what is spent today and the slot's status change between one
  `beginTransaction` and its commit, with the signing after.
- The tag (software 1.19), in its own class of tests with the three applets installed in the order the chip is given them: the phone's whole
  sequence byte for byte, both files, every offset and length, an unknown file, a read with no file chosen, every instruction that writes, and
  the same bytes from two cards; the switch (on by default; only the owner's proof, and nothing else, flips it; a refusal costs no PIN try;
  off makes the tag's name unselectable and on makes it selectable again; it survives a power cycle; `RESET_CARD` puts it back on; a payment
  works with it off); the instances deleted one by one; and no static field that refers to an object an instance made.
- The mint's proof kept with a piece (software 1.20), in a class of its own: a piece loaded with its proof is given back with it, e then s then r;
  a plain load reads `00`, and three plain pieces still answer three places; a place used again serves only its own proof (a plain piece into a
  freed place reads `00`, a new proof reads the new one); `GET_DLEQ` for a spent place, an empty one, two places in one command (both, mixed, the
  same twice), a place there is not, and before any `SET_CARD`; every refusal of the load, with the word a plain load gives, and nothing written
  after any of them; the load under the change grant alone, as a plain load; a piece with a proof paying with the same signature bytes as one
  without, and a payment, `CLEAR_SPENT` and a refused command writing nothing to the store; `RESET_CARD` zeroing it; the store null after install
  and made by the first `SET_CARD`; `GET_INFO` as it was; and a long random history of loads, batches, payments, clears and power-ups, after
  every step of which every unspent place holds its own record. The source is read for the order (the record before the place's data and its
  status byte, torn states set by hand), for the one allocation (guarded, in `SET_CARD`, none in the constructor, the constructors' arrays
  adding up to the build that installs) and for the methods that name the store (no payment command does).
- BIP-340 vectors, as upstream. In `spec/vectors/`: an owner key and a proof for
  each label, and the transcript.
- On a card, by hand: install, set up (PIN, record, owner), set a limit, load,
  spend, change written back, a day turned, wrong PIN three times and the
  owner's unblock, a tap pulled away at each step.
- Measured on the first card, because the design leans on it: how long one
  SPEND takes over NFC from an iPhone. It decides how many pieces one tap may
  sign and whether a withdrawal of a full card needs more than one tap. Also
  whether the J3R180's ECDSA verifier takes the DER form and the uncompressed
  key, and how long it takes (once for each owner command), how long
  `SET_HEADER` takes (two SHA-256 passes and a few compares), and what the third
  permanent write per spend (what is spent today, with the slot's status byte
  and, on a new day, the window start) does to the chip's write endurance, which
  has not been checked against its data sheet.

### 5.6 The owner key, and the owner's proof

The whole text is `FOXY-CARD-DAILY-LIMIT.md`, sections 7 and 8. An earlier draft
gave the card a 32-byte owner secret, once, in the clear, and compared a hash
against it. That is gone: nothing of the owner crosses the air now, and no
secret is on the card.

Three things can hurt a holder when a terminal has been handed the PIN: changing
what the card may sign for, changing the PIN, and locking the card. None of them
can be left to the PIN. So the card has an **owner**: a public key whose private
half only the holder's phone can work out.

**The owner key.** A NIST P-256 public key, 65 bytes uncompressed, given to the
card with `SET_OWNER` and kept apart from the record. The holder's phone works
the private half out for each card, in its native side only:

    k = HMAC-SHA256( key = the 64-byte BIP-39 seed,
                     message = "FoxyCard/owner" ‖ 0x00 ‖ the card's 33-byte compressed public key )
        taken mod n, n being the order of P-256

and, if the result is 0, made again with a counter byte (`0x01`, then `0x02`, and
so on) added to the end of the message. Restoring the twelve words on a new
phone makes the same key, so the new phone is the owner of every card the old
one was. The card's key is in the message, so two cards of one holder have two
keys. The private key is never sent anywhere, the page never sees it or the
seed, and the card reads out nobody's key: `GET_INFO` byte 16 says only whether
it has one (0 no, 1 yes).

**The proof** is challenge and response, checked by the card's own ECDSA
verifier.

1. `GET_NONCE` (no data, no PIN; `6A90` on a card with no owner) answers a fresh
   random 16 bytes, held in RAM. It is gone with the tap. Each nonce gets one
   try, right or wrong: a wrong proof uses it up. Asking again replaces it.
2. The proof is an ECDSA signature (P-256, SHA-256, DER) by the owner key over
   `label ‖ nonce (16) ‖ value`, with the label and value of the command:

| Command | Label (ASCII) | Value |
|---|---|---|
| `CHANGE_PIN` | `FoxyCard/change-pin` | the new PIN's bytes |
| `SET_LIMIT` (owner form, `34`) | `FoxyCard/set-limit` | the new limit, 4 bytes, big-endian; or 8, the day's and then the one payment's; or 12 (software 1.16), those and the no-PIN allowance |
| `SET_OWNER` (on a card that has an owner) | `FoxyCard/set-owner` | the new owner key, 65 bytes |
| `SET_CARD` (on a card that has an owner) | `FoxyCard/set-card` | the data sent: unit, refund key, the 65 bytes where the time key was (zeros from a phone of software 1.15; the card does not read them), mint length, mint |
| `ALLOW_LOAD` | `FoxyCard/load` | nothing |
| `LOCK_CARD` | `FoxyCard/lock` | nothing |
| `RESET_CARD` (software 1.17) | `FoxyCard/reset` | nothing |
| `SET_TAG` (software 1.19) | `FoxyCard/tag` | one byte: `00` tag on, `01` tag off |

So a proof for one command, or one value, is no proof for another, and an old or
used proof fails. The data of an owner's command is `proof length (1) ‖ proof
(DER) ‖ the value` (for `ALLOW_LOAD`, `LOCK_CARD` and `RESET_CARD`, the proof alone; for `SET_TAG`, the proof and then the one byte it was made over), so the
proof sits first and the value after it is exactly what the proof was made over.

**Refusal.** `6A91` when no nonce was asked for in this tap, or the signature is
not the owner's. A wrong proof costs no PIN tries, changes nothing and does not
end the PIN session. `6A90` when the card has no owner. `CHANGE_PIN`, the owner's
`SET_LIMIT`, `SET_OWNER`, `SET_CARD` and `ALLOW_LOAD` need no PIN and no old PIN:
the owner's phone does not know it, and the cards that most need an owner's
`CHANGE_PIN` are the blocked and the forgotten, where there is no old PIN to
give. `LOCK_CARD` needs a PIN that is set and verified as well; a card with no
PIN, or none verified in this tap, answers `6982`. The phone locks nothing:
`LOCK_CARD` is for a tool, and the phone's gate refuses to carry instruction
`50`.

**5.6a. RESET_CARD (software 1.17).** An owner can factory-reset a card so that
another person can set it up. `51`, P1 = `00`, P2 = `AD` (any other is `6B00`,
as `LOCK_CARD`'s `DE`), the data the owner's proof over `FoxyCard/reset` and no
value, and nothing after it (`6700`). It is refused in this order: the bytes;
no owner (`6A90`); the proof (`6A91`); a LOCKED card whose PIN has not been
given in this tap (`6982`: a locked card resets for the owner's proof and the
PIN, and a locked card whose PIN is blocked cannot be reset); anything
unspent on the card (`6A8D`, as `SET_CARD` refuses a record on a card that is
not empty). A blocked PIN on a card that is not locked is no bar: the owner is
authorizing a reset.

The card then reads as a card out of its packet: no PIN (`GET_INFO` PIN state
0, three tries), no owner, not locked, no record, no limits, no allowance, no
window or spending, no places in use, no log, no receipts, no change owed or
change note, no kept signature, its NFC tag on (5.8), and **a new key pair**: the card's own key
(`GET_PUBKEY`) and the PIN key (`GET_NONCE` P1 = 1, whose signature by the card
key is made again at the first asking). The old key would have tied one
owner's payments to the next one's. What it keeps is its clock (the time, and
the hash of the last block header it was shown; the ratchet's difficulty goes
to nothing, as `SET_CARD` does it) and its software. The old owner's proofs
fail (`6A90`), and set-up (`SET_PIN` or none, `SET_CARD`, `SET_OWNER`) is as on
a new card. An opening of change still owed to the card goes with the rest:
the pieces it would have come to are locked to the key that is gone, so the
owner's phone finishes any (`GET_CHANGE`) before it resets.

The wipe is one transaction of five bytes (the lock, the PIN state, the change
note, the owner, the NFC tag's switch), after the keys are drawn, with everything else written
outside any (a chip's commit buffer holds about a dozen writes). A card taken
away before it has the owner still and is reset again; one taken away after it
is a new card whose old PIN's bytes and tries may not be cleared yet, which
nothing reads with no PIN set and `SET_PIN` replaces.

**Who the owner is.** Whoever's words derived the key on the card: for a holder
with a phone, their own; for a holder without one, the friend whose phone set the
card up. That phone is a trustee who, with the card in hand, can do anything, and
without it, nothing. Set-up says so in as many words (`FOXY-CARD-SCREENS.md`
B3). An owner can be replaced only on a card with nothing unspent, and only with
the old owner's proof. A card whose owner has lost their words cannot be taken
over, empty or not.

**Setting a card up is one tap**, in this order: `SET_PIN`, `VERIFY_PIN`,
`SET_CARD` (the record), `SET_OWNER` last. The owner goes in
last so that no step needs a proof, and the card is open, and can be done again,
at every point before it: a set-up cut off anywhere is finished by the next. It
asks for no limit. The PIN is typed on the owner's phone once, here, and never
again for adding funds.

If the card in hand turns out to have no usable ECDSA verifier (not yet
measured; the J3R180 is expected to have one), the earlier draft's hash of an
owner secret stands in for the owner's proof.

### 5.7 The daily limit, the clock, and what they bound

The whole text is `FOXY-CARD-DAILY-LIMIT.md`, sections 5 and 6. A card is cash.
It holds what is put on it. The daily limit caps how much of it a terminal that
has been handed the PIN can take in a day, honest or built to cheat: the card
counts its day by Bitcoin block headers, which it believes for their work, and a
terminal cannot make one for nothing. It caps only where the owner has set a
limit, and a new card has none.

**The limit.** A number of sats in the card's permanent memory: the most the card
will sign for in one day. `GET_INFO` bytes 12 to 15 and `GET_CARD` bytes 3 to 6
carry it. 0 is no limit, and a new card has 0: set-up does not ask for one and
nothing suggests a figure. The owner sets one later from CHANGE LIMIT, to any
amount, and removes it the same way. `VERIFY_PIN`, a new SELECT, a reset,
`SET_CARD` and loading pieces do not touch it.

**The day.** The card keeps it, from the newest Bitcoin block header it has been
shown. `SET_HEADER` carries a header: the 80 bytes as the network carries them.
The card hashes them twice with SHA-256, and the hash, read as a little-endian
number, must be at or under the target the header's own `bits` name (the proof
of work). The target must also be at or under a floor built into the applet and,
once the card has taken a header, at or under four times the target of the
hardest it has taken, which is to say the header must show at least a quarter of
that work. A header that does not is `6A93`; a `bits` no header could carry is
`6A80`; any length but 80 is `6700`. A header whose time is later than `now`
moves `now` to it; an older or repeated one changes nothing (`9000`). No key, no
PIN, no owner and no state of the card refuses a good header. Setting the limit
begins a window at `now` with nothing spent in it. On `SPEND`, when the limit is
not 0: if `now` is a day (86,400 seconds) or more past the window's start, the
window is new and begins at `now`; a piece that would take what is spent today
past the limit is refused (`6A8F`) with nothing signed, burned or written;
otherwise the window start (if new), what is spent today and the slot's status
change in one transaction, and the signing comes after. `VERIFY_PIN`, a new
SELECT, a reset and a load preserve the current window. A limit of 0 skips all
of it and needs no clock. `now` only ever moves forward, and nothing sets it
back.

A card that has been shown no header (`now` is 0) spends its first day on trust.
It may be loaded and given a limit; its window has no start and cannot end, so
what leaves the card counts up to the limit and is then refused (`6A8F`) until a
header arrives; and the first header taken begins the window at its own time.

**Counted value.** The limit charges the value leaving the card. From software 1.12 a
payment's change is the card's own (`SPEND_ALL_CHANGE`): outputs the card
builds and locks to its own key, which no terminal can take, so the day is
charged the pieces less that change. Change a terminal writes back by other
means the card cannot check, and gives the day nothing back. A payment of 300
sats made with one piece of 1,000 and 700 of the card's own change costs the
day 300; before 1.12 it cost 1,000, and a till picks pieces as near the price
as it can either way (8.1). A window is a
fixed day from its start, so a terminal that straddles one boundary can take up
to two days' limit in a short span. That is the bound, and it is written down
and not hidden.

**The time.** The card believes a header for the work it would cost to make, and
for nothing else: no key, no signer, no phone's word. Two numbers of its own say
how much work is enough. The **floor** is built into the applet: `bits`
`0x17087BC0`, four times the target of the network's blocks when this version
was written, so a quarter of a block's work then. The **quarter** is a fourth of the hardest
header the card has itself taken: it climbs with the network, and nothing
lowers it. The floor matters for the first header only. A terminal built to
cheat cannot begin another day by telling the card it is later. It must bring a
header dated a day on from the window's start, which is a real block when the
world has made one, or a forgery that costs a quarter of a block's work (of the
blocks of this version's time, on a card that has taken none). The card's time is a
block's, and not the second: a block's time can lead the true time by up to two
hours, and the clock moves a block at a time, and only when someone shows the
card a header. The numbers, and the reasons for them, are in
`FOXY-CARD-DAILY-LIMIT.md` 5.2. `TELL_TIME` gives the card the terminal's own
clock as a note for its receipts and its log, and the card trusts it for
nothing (there, 5.3).

**What it bounds.**
- A terminal that has been handed the PIN can take at most one day's limit in a
  day, and up to two across a window's boundary, honest or not. That is not the
  price of this payment and not what the holder agreed to: the card cannot tell a
  holder's request from a hostile terminal's.
- The PIN alone protects a lost card whose PIN nobody knows: a wrong PIN opens
  nothing, and three block the card.
- Changing the PIN, the limit, the owner or the record, adding funds with no PIN,
  and unblocking the card need the owner's phone, or the twelve words on a new
  phone.

**What it costs.**
- A piece worth more than what is left of today cannot be spent today, whatever
  the payment: with one piece of 1,000 sats and 500 left, a 10-sat payment must
  wait until the day turns or the owner's phone changes the limit.
- A payment can be refused for the limit while the card holds enough: the till
  uses the OVER THE CARD'S DAILY LIMIT result.
- Every spend writes one more thing to permanent memory.
- The owner's phone taking money off the card lifts the limit and puts it back in
  the same tap. Putting it back starts a new window with nothing spent, so a
  withdrawal gives the day back its whole limit: one extra day's limit, at the
  moment the owner is holding the card.
- A card that is shown no newer block does not end its day. One whose network
  falls to under a quarter of the hardest header it has taken stops taking
  headers. Both fail closed, and the owner can give the card its limit again.
- If the owner loses the twelve words, the PIN and the limit on the card
  can never be changed, and a blocked card can never be unblocked.

What it does not do is listed in section 10.

### 5.7a The PIN is optional, and the no-PIN allowance (software 1.16)

The whole text is `FOXY-CARD-DAILY-LIMIT.md`, section 6f.

**A card may have no PIN.** It is set up with a record and an owner and no
`SET_PIN`, and it pays without one: its daily limit and its limit on one payment
still hold every payment, and the owner's proof still administers it. Such a card
is cash to whoever holds it. Nothing is loaded onto it but by the owner's grant
(or, for change, in the tap after a payment), and its log and receipts are the
owner's. The owner's phone gives it a PIN later (ADD PIN: `SET_PIN` under the
grant), and from then it is a card with a PIN.

**A card that has a PIN has a third limit, the NO-PIN ALLOWANCE:** how many sats a
day it will sign for without the PIN. Four bytes in the record (`GET_INFO` with
P1 = 1 says them, at bytes 34 to 37, to anyone, with what has been signed for with
no PIN at 38 to 41); 0 is none, and every payment then needs the PIN; a PIN just
added leaves it at 0. Only payments signed with no PIN count against it; one made
with the PIN counts for nothing here. It shares the day's window with the daily
limit, so a day turning takes both counts to 0, and a card that has seen no block
header counts it from set-up until one arrives. The owner sets it with `SET_LIMIT`
(`34`) in its twelve-byte form.

**At the signature.** `SPEND_ALL_BEGIN` asks for no PIN. `SPEND_ALL_SIGN` signs a
payment when there is no PIN, or the PIN was given in this tap, or what has been
signed for with no PIN in the window plus what leaves the card (the pieces less
the card's own change) is no more than the allowance. Otherwise it answers `6A94`
and gives the payment up: **the PIN is asked for the whole payment, never for part
of it**, and a till reads the answer, asks for the PIN, and taps again. The PIN is
asked before the limits and writes nothing in the log, so that a reader with no PIN
cannot fill it. A blocked card has no allowance. The daily limit and the limit on
one payment hold a payment made with no PIN as they hold any other.

**The log** marks a tap in which a payment was signed with no PIN (bit 3 of its
flags), so that the owner's phone can say so.

A card of software 1.12 to 1.15 keeps asking for its PIN at every payment, and a
phone must go on working with them.

### 5.8 The card as an NFC tag (software 1.19)

A phone with its screen on reads NFC tags by itself and offers to open the web
address a tag carries. From software 1.19 every card also answers as an NFC Forum
Type 4 Tag (mapping version 2.0), read only, carrying one address:

    https://getfoxy.io/card

so that a phone with Foxy opens the app and a phone without it opens that page.

**The same on every card.** There is nothing per card in the address and there never
will be: an address that named the card, its key, its owner or its balance would be an
identifier that anyone with a phone could read with no PIN. Two cards answer a reader
in the same bytes, and a card with money on it answers as one with none. What the tag
tells a reader is that this is a card made for Foxy, and nothing else
(`SECURITY-MODEL.md`, threat 15).

**The applet.** A third applet of the package, `Tag` (class AID `F0 46 4F 58 59 43 41
52 44 54`), listed after the opener and the card's applet, and instantiated on the card
under the NFC Forum's own name, `D2 76 00 00 85 01 01`, given as the instance AID at
install, since phones select the tag application by that name:

    gp --create D2760000850101 --package F0464F585943415244 --applet F0464F58594341524454

It keeps no secret and no state of its own but the file chosen (one byte of transient
memory, cleared on deselect and when the application is selected), and it allocates
nothing else. It answers exactly this, with class `00` (any other class is `6E00`):

| Command | Bytes | Answer |
|---|---|---|
| SELECT by name | `00 A4 04 00 07 D2 76 00 00 85 01 01 [00]` | `9000`, no data (the runtime's); `6999` when the tag is off |
| SELECT file | `00 A4 00 0C 02 E1 03`, or `... E1 04` | `9000`; any other file `6A82`; other P1 or P2 `6B00`; Lc not 2 `6700` |
| READ BINARY | `00 B0 <offset hi> <offset lo> <Le>` | the bytes of the file chosen from that offset, as many as asked and the file holds (an Le past the end is answered with what there is); an offset at or past the end `6B00`; no file chosen `6986` |
| UPDATE BINARY (`D6`), and the other instructions that write (`0E D0 D7 DA DB DC DD E2`) | | `6982` |
| any other instruction | | `6D00` |

The capability container (file `E103`, 15 bytes):

    00 0F 20 00 3B 00 34 04 06 E1 04 00 16 00 FF

its length (15), mapping version 2.0, MLe 59, MLc 52, and one NDEF file control TLV:
file `E104`, at most 22 bytes, read access free, write access never. The NDEF file
(`E104`, 22 bytes):

    00 14  D1 01 10 55 04  67 65 74 66 6F 78 79 2E 69 6F 2F 63 61 72 64

its message's length (20), then one short, well-known record of type `U` (a URI) whose
payload is the prefix code `04` (`https://`) and the 15 ASCII bytes of `getfoxy.io/card`.
A phone reads it by selecting the name, selecting `E103` and reading 15, selecting
`E104`, reading 2 (the length) and reading 20 from offset 2.

**The switch.** The card's owner can switch the tag off, and on again: a card kept in a
phone's wallet case would otherwise raise the offer every time the screen wakes. The
switch is one persistent byte of the card's applet. It is on for a new card, for a card
with no owner and for a card just reset (`RESET_CARD` puts it back on in its last
transaction, 5.6a), and off only when its owner has said so. The command is `SET_TAG`:

| Field | Value |
|---|---|
| CLA, INS | `B0 52` |
| P1 | `00` tag on, `01` tag off |
| P2 | `00` |
| Data | proof length (1), the owner's proof (DER), and one byte, the same as P1 |
| Proof | ECDSA (P-256, SHA-256, DER) by the owner's key over `FoxyCard/tag` (12 bytes, `46 6F 78 79 43 61 72 64 2F 74 61 67`), the 16-byte nonce the card gave, and that one byte |

It is refused in this order, with the words the neighbouring commands use: `6B00` for a
P1 or P2 not those, before anything else (the nonce is left unspent); `6986` on a locked
card; `6A90` with no owner; `6A91` when no nonce was asked for in this tap or the proof is
not the owner's for this label, this nonce and this byte (it costs no PIN try, and the
nonce is spent); `6700` for anything but one byte after the proof; `6B00` for a byte that is
not P1. Asking for the state the tag has answers `9000` and writes nothing. No PIN is asked
and none is spent: the owner's phone does not know it, and a terminal that has been handed
the PIN must not be able to turn the tag off or on. It is allowed with money on the card.

**GET_INFO.** The tag's state is said by a form of its own, P1 = 2: the 42 bytes that P1 = 1
answers, and then byte 42, `00` when the tag is on and `01` when it is off. It is said to
anyone (the tag shows as much to any reader). P1 = 0 is the thirty bytes and P1 = 1 the forty-two
bytes they were in software 1.18, whatever the tag's state: a wallet written for 1.18 asks with
P1 = 1 and takes the answer as the long form only when it is exactly 42 bytes, so growing that
answer would have made it misread a 1.19 card (no limit on one payment, no allowance). Any
other P1 is answered as it was, with the thirty bytes. Cards of software 1.18 and earlier have
no tag: they answer `6D00` to `52`, and give the thirty bytes to P1 = 2.

**How the tag knows.** At each selection the tag asks the card's applet whether it is on,
through a shareable interface (`TagSwitch`, one method, `tagIsOn`) that the card's applet
hands to any caller. The card's applet is looked up by its name (`JCSystem.lookupAID`,
`F0 46 4F 58 59 43 41 52 44 01`) and its interface asked for
(`getAppletShareableInterfaceObject`) then, and nothing of either is kept. When the tag is
off the tag's `select` answers false, so the card refuses the tag application's name
(`6999`) and a phone sees no tag. The card applet's own name is selectable whatever the
switch says, and a payment is made as ever. If the card's applet is not there the tag is
on. The interface is not exported: the two applets are of one package, and so of one
context.

**Deleting.** No static field of the package refers to an object an applet instance made,
which the chip would refuse to delete (the statics are constants made when the package is
loaded; the tag holds no reference to the card's applet). The instances are deleted one by
one, the tag (`D2760000850101`), the card's applet, the opener, and then the package
(`HARDWARE_DEPLOYMENT.md`).

**What a phone needs to know to speak to a card of software 1.19.** `SELECT` answers
`01 13`. `GET_INFO` with P1 = 1 is the 42 bytes it was; with P1 = 2 it is 43, the last `00` (tag on) or `01` (off). To switch the
tag: `GET_NONCE`, then `B0 52 <p> 00 <Lc> <proof length> <proof> <p>` with `p` = `00` or `01`,
the proof being the owner's signature over `"FoxyCard/tag" ‖ nonce ‖ <p>`, in the same tap as
the nonce; a phone's gate carries instruction `52`, and its signer the label `tag`.

### 5.9 The mint's proof, kept with each piece (software 1.20)

Up to software 1.19 the card kept for each piece only what it needs to pay with: the
keyset, the amount, the nonce, `C` and the date. A phone that read the card could ask the
mint whether a piece was spent. It could not tell whether the piece was real: a made-up `C`
looks like any other until the mint is asked to take it. From software 1.20 the card also
keeps, for each piece, the mint's NUT-12 proof as a later holder needs it:

| Field | Size | |
|---|---|---|
| e | 32 | the proof's challenge |
| s | 32 | its response |
| r | 32 | the blinding factor the piece was made with |

96 bytes. **The card does not check the proof and never uses it.** It keeps what it is given
and gives it back. Phones read it and check it. Paying is untouched: the secret the card
builds and the message it signs are what they were, and no payment command writes the proof.

**The store.** 128 records of 96 bytes, 12,288 in all, the record of place k at k * 96, as
`e ‖ s ‖ r`. A record of 96 zero bytes means "no proof": the piece came with none.

**It is reserved after install, by the first `SET_CARD`.** The chip will not install an applet
whose constructor asks for this much more (a build whose constructor asked for 300 bytes
more installed, and one that asked for 12,288 more did not), and it gave the same bytes
asked for by a command after the install (`FOXY-CARD-HARDWARE.md`). So the store is not
there at install. The first `SET_CARD` that goes through reserves it, once, before the record
is written and outside any transaction. If the card refuses the room, that `SET_CARD` goes
on without it and the card works as a card with no room for proofs: the load answers `00` for
the proof, `GET_DLEQ` answers `00`, and nothing else is different. Every use of the store is
safe while it is not there, and a later `SET_CARD` asks again. No simulator has the chip's
limit, so tests pin the rule: the store is null after install, no constructor names it, the
constructors' arrays come to the figure of the build that installs, and the one allocation is
the guarded one in `SET_CARD`.

**The rule.** A place that is unspent holds in the store its own proof, or 96 zero bytes, and
never another piece's. `LOAD_PROOF` keeps it by order. It writes the place's record, the
piece's proof or zeros for a piece that came with none (written only if the record is not
zero already), before anything else of the place, and the status byte stays the last write
and the commit (D14). A card taken away in between has an empty place with a record beside
it, which nothing serves, and the next piece into the place writes its own record over it.
`CLEAR_SPENT` and the payment commands do not touch the store, so a freed place keeps the
record it had until the next piece comes. `RESET_CARD` fills the store with zeros after the
places are freed, outside any transaction: a card taken away in the middle still has its
owner, who may reset it again.

**`LOAD_PROOF` with P1 = 1.** One piece and its proof. The data is exactly 81 + 96 = 177
bytes: the piece as a plain load has it, then `e ‖ s ‖ r`. Any other length is `6700`. A
proof of 96 zero bytes is `6A80`, since zeros are what "no proof" is kept as; the card looks
at the proof no further. Everything else is exactly a load of one piece: the same checks in
the same order, the same words, the same entry in the log, the same change-grant behaviour
(the tap after a payment may put the change on with no PIN, and a piece that is the card's
own change lets its opening go). The answer is two bytes: the place, then `01` where the proof
was kept and `00` where the card has no store. A P1 other than 1 is what it was in 1.19: one
to three pieces of 81 bytes, an answer of one place for each, and each piece stored that way
has its record made zero. It is one piece to a command because a piece and its proof are 177
bytes and a short APDU carries 255; two would not fit, and extended length is not something
every reader and phone will carry.

**`GET_DLEQ` (`1A`).** P1 = a place (0 to 127), P2 = a second place, or `FF` for none. No
data, no PIN, any state of the card. For each place asked, in the order asked, the answer is
`01` and the 96 bytes if the place is unspent and its record is not zero, and otherwise the
single byte `00`: the place is empty or spent, or holds a piece that came with no proof, or
the card has no store. The same place twice is answered twice. At most 194 bytes. `6A83` for
a P1 over 127, or a P2 over 127 and not `FF`, before anything is answered. It never gives the
proof of a spent piece.

**What a reader does.** The card gives `e`, `s` and `r`; the reader has the rest, from
`GET_PIECES` (keyset, amount, nonce, `C`, date), `GET_PUBKEY` and `GET_CARD` (the card's key
and refund key) and the mint's keys. For a place `GET_DLEQ` answers:

1. Rebuild the piece's secret, the NUT-10 text the card signs the hash of
   (`FOXY-CARD-DAILY-LIMIT.md` 6c).
2. `Y = hash_to_curve(secret)` (NUT-00).
3. `K` is the mint's public key for the piece's amount in the piece's keyset (NUT-01).
4. `C' = C + r*K`, and `B' = Y + r*G`.
5. Check the proof as NUT-12 has it: `R1 = s*G - e*K`, `R2 = s*B' - e*C'`, and `e` must be the
   hash NUT-12 names of `R1`, `R2`, `K` and `C'`.

**What it shows, and what it does not.**

- A piece whose proof checks is real: the mint's key for that amount signed this secret.
  Nobody without that key can make a proof that checks, so a piece with a made-up `C` fails,
  and so does a copy of a real piece from another card, since its secret names that card's
  key and not this one's.
- It does not show that the piece is unspent. The mint decides that, and the card cannot.
- What "real" rests on is the mint's keys the reader holds and the check the reader makes.
  It does not rest on the card, which checks nothing, or on whoever loaded the card.
- A `00` is "not shown real", and not "fake". A piece put on plain, or on a card of earlier
  software, cannot be checked this way, and the reader decides what that means to it.

**Privacy.** The proof carries `r`. The mint made its signature for `B'` and answered with
`C'`; given `r`, whoever has the mint's record of that issue can recompute `B'` and `C'` from
the piece and tie the piece to the request that made it. That is so of any NUT-12 token that
carries `r`, and a reader that hands `r` to the mint lets the mint make the tie. The card
gives `r`, with no PIN, to any reader, for every unspent piece that has a proof, as
`GET_CHANGE` already gives it for the change the card made for itself. A reader checks the
proof on its own side and sends it nowhere.

**What a phone needs to know to speak to a card of software 1.20.** `SELECT` answers `01 14`.
`GET_INFO` is the 30, 42 and 43 bytes it was, byte for byte but for the version, and nothing
in it says whether the card has its store: the answer to a load with P1 = 1 does, and so does
`GET_DLEQ`. To load a piece with its proof: `B0 30 01 00 B1 <piece (81)> <e> <s> <r>`; the
answer is `<place> 01`. To read: `B0 1A <place> FF 00` for one place, or the two places in P1
and P2. A phone's gate has to carry instruction `1A`. `spec/vectors/transcript.json` has both
commands as commands and answers.

<a id="6-a-lost-or-blocked-card-is-not-lost-money"></a>

## 6. Lost-card and blocked-PIN recovery proposal

Upstream's position is that a card is cash: lose it and it is gone, and a
blocked PIN strands it as well. Their own notes call a refund path "the right
shape" and name its flaw. This is that path, with the flaw answered.

- Every piece loaded onto a card is locked to the card's key **and** carries a
  date and a refund key: after the date, the refund key can spend it.
- The refund key is one the funding phone derives from its words, so it is
  recoverable wherever those words are.
- The date is a year after loading. Adding funds renews every piece on the
  card to a year from then (they are swapped anyway to make change).
- **The flaw upstream names:** once the date passes, a mint may stop taking
  the card's own signature, and the card does not know (the clock it keeps for
  its limit is not used for dates). So the date is on the slot where a reader
  can see it. Foxy, receiving, refuses a piece within a week of its date,
  before asking the card to sign, and says the card needs renewing by its
  owner. The holder's own phone shows the date and offers to renew from a month
  before.
- Privacy: the refund key is in each piece's secret, which the mint sees when
  the piece is spent. The card's own key is there too and already ties a
  card's pieces together, so this adds a tie between a card and the phone that
  funded it. A different refund key for each card keeps two cards from being
  tied to each other.

- **Mints differ on what a passed date does.** NUT-11 as it now reads lets
  the first key go on spending beside the refund key, and the Cashu library
  Foxy ships reads it that way (`tests/flashcard-vectors.js` in Foxy shows
  it); an older mint takes the refund key only. The rule above leans on
  neither, so it is right at both.

- **What can be taken back is what the loading phone knows of.** A piece's
  nonce is random, so the twelve words do not rebuild it: the phone keeps the
  pieces it loads and the pieces it sees whenever the card is read on it.
  Change a receiver wrote onto the card since the phone last read it is not
  known to the phone and does not come back. And if the phone's own data is
  lost with the card, the words alone bring back nothing of the card. A later
  version can make the nonces come from the words; this one does not.

- **The daily limit does not touch this path.** The refund key spends at the
  mint and the card is not asked. It comes from the same twelve words as the
  owner key, so a holder who loses the words loses both: the refund, and any
  change to the card's PIN, limit or blocked state.

A card can be made with no refund key, and is then cash, as upstream's.

## 7. Foxy: reading the card (Swift)

- CoreNFC, `NFCTagReaderSession` for ISO 7816. The fork's AID in
  `com.apple.developer.nfc.readersession.iso7816.select-identifiers`, the
  `NFCReaderUsageDescription`, and the NFC Tag Reading capability. **That
  capability is not offered to a free signing team**: this needs the paid
  developer membership.
- `Foxy/Card/CardLink.swift`: one session, a list of steps, each a command
  and what to do with its answer. `CardAPDU.swift`: building and reading the
  commands, with no NFC in it, so it is unit tested.
- The bridge gives the page three calls: read (no PIN), spend (PIN, slots),
  write (pieces, card record; the PIN, unless the owner's phone is adding
  funds). The PIN is sent to the card and wiped when the session ends. Storage and
  logs exclude it.
- The native side holds the owner key (5.6). The page never sees the twelve
  words, the seed or the owner's private key; native offers it exactly two
  things:
  - `cardOwnerKey`: the owner **public** key for the card with a given
    compressed public key (130 hex characters, uncompressed), for `SET_OWNER`;
  - `cardOwnerSign`: an ECDSA signature (DER, hex) by the owner key for that
    card, over `"FoxyCard/" + label ‖ nonce ‖ value`, where the label is one of
    `change-pin`, `set-limit`, `set-owner`, `set-card`, `load`, `tag` (software 1.19), the nonce is the
    16 bytes the card gave and the value has the shape that label takes. Native
    refuses every other label (in particular `lock`) and every other
    shape, before it reads the seed, and answers the signature and nothing
    else. A proof is made in the tap that uses it, since its nonce lives only as
    long as the tap.
- The phone's gate carries only the instructions the page uses: `01 10 11 13 14
  15 16 20 30 31 32 34 36 37 40 41 42 43 44 45` (and, to speak to a card of software
  1.19, `52`; and, to read the mint's proofs on a card of software 1.20, `1A`). `33` (the PIN form of the limit,
  for a card with no owner) is not used by the phone and is not carried; `50`
  (`LOCK_CARD`) stays out.
- Every tap that finds the card behind the network shows it the newest block
  header, before anything else is read from it that depends on the day. The
  phone fetches the header over Tor from two independent sources (mempool.space
  and Blockstream, each by its onion service), checks the work itself, that both
  name the same block and that its time is within a few hours of its own clock,
  and sends `SET_HEADER`, reading the card's `now` back from the answer. A till
  does the same before a payment. The phone's checks are its own good manners:
  the card checks the work again and depends on none of them. The phone also
  tells the card its own clock with `TELL_TIME`, a note for the receipts and the
  log.
- iOS ends a session after a minute and shows its own sheet throughout; the
  sheet's line of text is set at each step (`Hold the card`, `Keep it there`,
  `Remove the card`).
- A simulator has no NFC. A stand-in card over a local port, in simulator
  builds only, as the tap link has, so the flows can be driven without
  hardware. The Java applet under jCardSim can be that stand-in, which tests
  the real applet against the real page.

## 8. Foxy: the money (wallet)

### 8.1 Being paid by a card, same mint

1. Read: the clock (a header, if the card is behind), AUTH, card record,
   slots. Refuse here, with nothing signed, and before the PIN is sent, if the
   mint differs, the balance is short, a piece is near its date, a keyset is not
   this mint's, or what is left of today's limit is less than the worth of the
   pieces step 2 would sign. What is left is worked out from `GET_INFO` (the
   limit, `now`, the window start and what is spent today; a window whose day is
   over has the whole limit left).
2. Choose pieces: exact if the card has them, else the least over, and as close
   to the price as it can either way, because the day's limit is charged each
   piece's whole worth and not the price (5.7). Add the mint's fee for swapping
   them where it charges one; the payer's card pays it.
3. Write down, before asking the card for anything, the outputs of the swap
   to come: this phone's own for the amount, and the change locked to the
   card (new nonces, the card's key, date and refund key). A lost answer is
   then recovered from that record, as every swap here is.
4. VERIFY_PIN, then SPEND each piece. From here the card's slots are spent.
5. Swap at the mint, the card's signatures as each piece's witness.
6. Change: while the card is still there, LOAD_PROOF each piece and read it
   back. If it has gone, keep the change on file and show TAP THE CARD AGAIN.
7. PAID when step 5 has given this phone its pieces. One history entry, in,
   for the amount, marked as from a card.

As built: steps 3 and 5 are the wallet's ordinary receive of a token whose
pieces are already signed for, with its own record and recovery, and change
is a second swap, an ordinary locked send to the card's key, cut by what it
costs and settled on the payment's entry as any change here is. One swap for
both would save a sat or two at a mint that charges; it is not built.

<a id="82-what-is-this-phones-and-what-is-not"></a>

### 8.2 Merchant funds and card change

- The amount is this phone's when the swap answers.
- Change is never this phone's. It is locked to the card and kept in a store
  of its own (`foxy.cashu.cardchange`), outside the balance and outside the
  books, until it is written to the card. If it never is, it comes back to the
  card's funder at its date.
- Signed and not yet swapped (the mint did not answer): held, asked about
  until the mint says, exactly as a held swap is now. If the mint says the
  pieces are unspent and will not take them, they are swapped back into
  pieces locked to the card and wait for a tap like change.

### 8.3 The holder's own phone

- **Add funds:** swap from this phone's pile into pieces locked to the card,
  powers of two, as many as there are free slots; record them before the tap;
  write; read back. An out entry, `to card`, for the amount and the fee.
  Pieces made and not yet written are shown as on their way to the card and
  can be written on the next tap. On the owner's phone no PIN is asked:
  `GET_NONCE`, a signature over `load`, `ALLOW_LOAD`, then `CLEAR_SPENT` and
  `LOAD_PROOF`. Putting money on a card does not touch its limit.
- **Withdraw:** SPEND the pieces, swap into this phone's own. An in entry,
  `from card`. Renewing and taking everything off a card are the same. None of
  them stops at the limit: in the same tap the owner's phone lifts the limit
  with the owner's proof (`34`, limit 0), the PIN is typed and `SPEND` runs, and
  the old limit is put back with the owner's proof, restored even when the
  spending fails part way. Where the card leaves before it can be, the phone has
  written the old limit down first and puts it back at the next tap. Putting the
  limit back starts a new window with nothing spent, so a withdrawal gives the
  day back its whole limit (5.7). A phone that does not hold the card's words
  cannot lift the limit, and says so.
- **Change PIN, unblock, change limit:** `GET_NONCE`, a signature over
  `change-pin` and the new PIN, `42`; and `GET_NONCE`, a signature over
  `set-limit`, `34` (any amount, or none). No PIN is asked for either: the
  owner's phone does not know it.
- **Balance:** from the slots; with a connection, each piece's state asked of
  the mint. The card's daily limit, what is left of it today and when the day
  turns are shown with it.
- **Take back a lost card:** after the date, swap the pieces this phone
  recorded when it loaded them, signed with the refund key.

### 8.4 A card at another mint (second version)

The payment is made final for the payer by a swap at the card's mint, into
ecash this phone holds there; bringing it to this phone's own mint is then
this phone's business, by the road Foxy already has for moving between mints,
and its cost is shown to the receiver before the card is asked for anything.
Until then: A DIFFERENT MINT, and nothing is taken.

What is built of this is the holder's side: moving a card itself to another
mint. A card with nothing on it is told its new mint in one tap (`SET_CARD` under
the owner's proof, which leaves the card's clock as it is; the card refuses it
while it holds unspent pieces). One with money on it
takes two: the money comes off into the phone, crosses by Lightning with its
own fee paid out of it, and goes back on at the new mint. The fee shown before
the card is touched is the most it can cost; cut short anywhere, the money is
in the phone and the card is empty and still good. Run against CDK and
Nutshell with the applet as the card (`tools/live/flashcard-switch.js` in the
wallet repository, getfoxy/iOS, https://github.com/getfoxy/iOS). The app offers
the one-tap move to the owner's phone for a card with nothing on it (SWITCH TO
the phone's mint, on ADD FUNDS); it has no button for the move of a card that
holds money, and a card that holds money is told to withdraw it first.

## 9. Foxy: the screens (app)

`FOXY-CARD-SCREENS.md` lists them as built. In short:

- Receive: a CARD button beside TAP; the PIN pad with what is being paid
  under its title and on its button; the cards of 2.1.
- Menu › Flashcard: straight to the tap, then one screen in home's layout:
  the card, its balance and mint in home's own pill, and four buttons.
- Amounts are typed on the app's own amount screen. The PIN pad is the lock
  screen's, with its larger keys. A card PIN is 4 to 8 digits.
- The limit is set from CHANGE LIMIT in three steps: a warning, the amount
  screen, a confirmation (2.2; B7 of `FOXY-CARD-SCREENS.md`). Set-up asks for a
  PIN twice and shows a notice that this phone will be the owner, and asks for
  no limit.
- The card's screen shows the daily limit, what is left today and when the day
  turns.
- A card's face is drawn in its design, named by a code of three characters
  (`CARD-DESIGNS.md`; FL1 today). The card does not yet carry its code.
- Render snapshots for each state.

<a id="10-what-it-does-not-protect-against"></a>

## 10. Residual risks

A card is cash. It holds what is put on it. The daily limit bounds a terminal
that has been handed the PIN, honest or built to cheat, to one day's limit per
visit, where the owner has set one (5.7).

- **A terminal built to cheat is bound by the day.** It cannot start another by
  telling the card it is later: it must bring a header dated a day on, which is
  a real block or a forgery that costs work (5.7). Nothing is bound that the
  owner has not set: a new card has no limit, and a card with none has no day
  and no wait.
- A receiver's phone that has been altered can show one amount and ask the card
  for more, up to one day's limit per visit, and up to two across a window's
  boundary. The limit does not check a payment, and nothing on the card can.
  Looking at the card's balance afterwards finds out; it does not undo it. It is
  the position of any card and any terminal.
- The same terminal can write onto the card pieces the mint will refuse, made up
  with a nonce no mint ever signed. They take nothing from anyone, since the
  receiver always asks the mint, but a later payment that picks one burns slots
  and spends a day's limit on nothing, and while such a piece is on the card it is
  not empty, so the owner cannot replace its owner or record until it is spent. A
  fake piece looks unspent to a state check. From software 1.20 the card can keep the
  mint's proof for a piece, and a phone that reads it and checks it sees that a made-up
  piece is not real before it is paid with (5.9). The card checks nothing, so this is the
  phone's: a card loaded with no proofs, or by a terminal that gives the proofs it likes,
  is as it was to a phone that does not check.
- It cannot write a **copy** of a real piece. The card signs a piece's secret,
  which its nonce makes, and takes the amount on the terminal's word, so a copy
  stating an amount of 1 would have been spent for 1 and signed for the real
  piece. `LOAD_PROOF` refuses a nonce that is in any slot, spent or not (`6A94`).
  The card does not remember a nonce once `CLEAR_SPENT` has freed its slot (see
  `FOXY-CARD-DAILY-LIMIT.md`, section 13).
- Any reader in range can send three wrong PINs and block the card (upstream's
  threat 14). The owner's phone unblocks it with a new PIN (5.6); a card whose
  owner has lost their words stays blocked.
- A holder whose owner has lost their words can never change the PIN or the
  limit.
- Whoever has the owner's words and the card in hand has everything on it.
- Whoever spends the work of a block header can show the card any time: a
  quarter of a block's work (of the blocks of this version's time, on a card that
  has taken no header). It buys one more day's limit, or a clock frozen years ahead, after
  which the card signs for one more limit's worth until the owner sets the limit
  again. A card that has been shown no header spends its first day on trust, and
  a block's time can lead the true time by up to two hours
  (`FOXY-CARD-DAILY-LIMIT.md` 5, 6 and 13).
- A card with no owner can be claimed by any reader in range. It holds nothing and
  cannot be loaded (5.4).
- **The NFC tag (software 1.19) is read by any reader, with no PIN.** It says the same
  bytes on every card and nothing of the card, so it reveals that this is a card made
  for Foxy and nothing else (5.8). A card kept on factory keys can have the tag's
  applet replaced by one that carries another address; rotating the keys (5.4)
  closes that. The owner can switch the tag off; a terminal that has the PIN cannot
  switch it either way.
- A holder with no phone has no balance they can read that a terminal did not
  draw. That screen displays the stored values; clock validation follows the header rules.
- A pretend card can collect a PIN typed for it. AUTH lets a holder's own phone
  know its card; a receiver has no way to know a stranger's card is real, and
  loses nothing if it is not.
- The PIN is in the clear over a few centimetres of air until phase 2. Nothing of
  the owner crosses the air.
- Whoever holds the refund key's words can take a card's money after its date.

<a id="11-order-of-work-and-how-much"></a>

## 11. Implementation sequence and estimates

| Phase | What | Rough effort |
|---|---|---|
| 0 | Paid developer membership; cards and a reader in hand; fork made | yours |
| 1a | Applet: card record, slot date, SPEND from the slot, SIGN_ARBITRARY out, AUTH, the daily limit and the clock, the owner key and its proofs (`CHANGE_PIN`, `SET_LIMIT`, `SET_OWNER`, `SET_CARD`, `ALLOW_LOAD`, `LOCK_CARD`), no load without a PIN or an owner; jCardSim tests | 3 to 4 days |
| 1b | Swift: CoreNFC session, commands, bridge, the owner key and its signatures in the native side, stand-in for the simulator, unit tests | 2 to 3 days |
| 1c | Wallet: pay by card at the same mint, change, held and lost answers, add funds, withdraw, balance, the refund path, the till's check of what is left today, the owner's phone lifting and restoring the limit when it takes money off; suites against the stand-in | 4 to 5 days |
| 1d | Screens (the limit's three steps), wording, snapshots; documents; phone checks | 2 days |
| 1e | On real cards: install, timing, every flow, every pulled tap | 2 to 4 days, set by how many rounds the hardware needs |
| 2 | A card at another mint; the PIN under a key; unblock by a second code | 1 to 2 weeks |
| 3 | A receiver with no connection: DLEQ on the card (kept with each piece since software 1.20: 5.9), an issuer's certificate, a list of withdrawn cards | a design of its own; weeks |

Phase 1 is about three weeks of the way this project is worked now. The
applet and the wallet can be written and tested without a card; phases 1b and
1e cannot be finished without the membership and the hardware.

<a id="12-for-you-to-decide"></a>

## 12. Open decisions

1. **Recovery.** A refund key and a year's date on every piece (recommended),
   or cash-like cards with nothing behind them, or the choice per card.
2. **The limit at set-up.** Decided: a new card has no limit, set-up asks for
   none, and nothing suggests a figure. A limit is set later from CHANGE LIMIT,
   in the three steps of 2.2.
3. **Same mint first.** Agree that the first version refuses a card at
   another mint.
4. **Upstream.** Tell them what was found before the fork is public, and
   whether to offer the changes back. The fork changes the slot and the
   commands listed in 5.2, so an upstream card and a fork card do not work in
   each other's terminals.
5. **The name.** "Flashcard" is close to their product's. The menu can say
   CARD.
6. **The clock.** Decided (software 1.15): the card's clock is the time in the
   newest Bitcoin block header it has been shown, believed for its work and held
   to a floor and a quarter (5.7). There is no signer and no key. Open: when the
   floor is raised, how long `SET_HEADER` takes on the chip (not yet measured),
   and whether the ECDSA verifier on the first card behaves (5.6); see
   `FOXY-CARD-DAILY-LIMIT.md` section 14 for the rest of what is decided.
