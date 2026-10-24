# Foxy card: one PIN, a daily limit, an owner key

> Historical Foxy design, recorded at software 1.20 and incorporated into
> shared protocol 2.0 ([D18](DECISIONS.md#d18)). The current applet wire is
> [protocol 2.1](../spec/APDU.md): readers SELECT the full applet AID
> `F043415348554341524401`, which answers `02 01`. Owner labels use
> `CashuCard/…`; [D20](DECISIONS.md#d20) through [D26](DECISIONS.md#d26)
> record the shared protocol changes. Use the current APDU reference when
> implementing a reader.

The second design of the card's limit, replacing the allowance of
`FOXY-CARD-SPEC.md` 5.3 (rule 3), 5.6 and 5.7 as they stood in the working
tree, and the `SET_ALLOWANCE` and owner-secret rows of its 5.2. Everything else
in that specification stands: the slot, the secret text, `SPEND` from the slot,
`AUTH`, the gate in every PIN state, D10 and D14, provisioning, the phone's
side. Where this document is silent, that one speaks; where the two differ,
this one is what is built.

What is kept from the earlier draft, what is changed and what is dropped is
listed at the end (section 11), because the applet before this design
implemented the draft and the changes are easier to make from that list than
from the prose.

From software 1.15 the card's clock is the time written in the newest Bitcoin
block header the card has been shown (section 5). Up to 1.14 it was a time told
under a signature by a key in the card's record. This document is written for
the clock of 1.15; section 11 keeps the account of the first design and says
where 1.15 replaced it.

From software 1.16 the PIN is optional, and a card that has one has a third
limit, the no-PIN allowance: what it will sign for in a day without the PIN
(section 6f). Where an older paragraph below says that a spend needs the PIN, it
is describing a card of 1.15 or before, or a card with a PIN and no allowance;
section 6f says what 1.16 does.

From software 1.19 the card also answers as an NFC tag carrying one web address,
which its owner switches off and on with one more owner's command, `SET_TAG`
(`FOXY-CARD-SPEC.md` 5.8). It touches nothing of the limits, the day or the clock.

From software 1.20 the card also keeps the mint's NUT-12 proof with each piece that
comes with one, for a phone to read (`GET_DLEQ`) and check (`FOXY-CARD-SPEC.md` 5.9).
The card checks nothing and never uses it; a payment is what it was, and the limits,
the day and the clock are untouched.

<a id="0-why"></a>

## 0. Design rationale

The first limit was on one PIN entry, kept in RAM and reset by `VERIFY_PIN`.
A terminal that had been handed the PIN sent `VERIFY_PIN` again between
spends, or `SET_LIMIT 0`, and took the whole card in one tap; the limit bounded
nothing (the audit, with a jCardSim proof). The draft that followed put an
allowance in permanent memory that every spend lowered and only the holder's
phone could raise. That holds against a terminal, but a card whose allowance is
used up has stopped until its holder's phone has been to it, and some holders
will not have a phone. Their card is set up on a friend's, and should then work
on its own.

So the limit is **per day**, and the card keeps the day itself, from the time
written in the newest Bitcoin block header it has been shown. A terminal with
the PIN can take one day's limit per visit and nothing more, and the holder
never has to bring the card back to anything.

**Read section 5.2, and the first day in section 6, before relying on any of
this.** The card believes a header for the work it would have cost to make and
for nothing else: no key, no signer, no phone's word. A terminal built to cheat
cannot start another day by telling the card it is later. It has to bring a
header dated later, and a header costs work to make: the world's miners make
one every ten minutes, and anyone else would have to spend a good part of a
block's work on one. Up to software 1.14 the time was signed by a key inside the
app, which anyone could copy, and those versions bound an honest terminal and
not a cheating one.

## 1. Goals

1. A holder with no phone of their own carries a card that bounds, by itself,
   what any terminal can take from it, honest or built to cheat: one day's limit
   per visit.
2. Nothing about a funded card (its PIN, its limit, its mint, its owner) can be
   changed by anyone who merely holds the PIN.
3. The phone that set the card up (the **owner**: the holder's own, or a
   friend's for a holder who has none) can change the PIN and the limit at any
   time, without knowing the PIN, can add funds without the PIN, and can
   unblock a blocked card.
4. A card with **no owner** is nobody's and is open while it is empty, because
   there is nothing on it to protect; it cannot be loaded. A card **with** an
   owner is its owner's, empty or not.
5. The receiver's and holder's sides of `FOXY-CARD-SPEC.md` are unchanged in
   what they promise: paid only when the mint has given the phone its pieces;
   nothing signed when a refusal can be known beforehand.

Not goals: a limit that follows the price rather than the pieces signed
(section 6); a check, by the card, of pieces a terminal writes onto it (DLEQ: since
1.20 the card keeps the mint's proof for a phone to check, `FOXY-CARD-SPEC.md` 5.9); a balance the holder can read without a phone (a screen; a separate
question); recovery of a lost card (no refund key for now); a clock that is
exact (a block's time can lead the true time by up to two hours, 5.1).

<a id="2-who-is-trusted-with-what"></a>

## 2. Trust boundaries

| Party | Holds | Can do wrong |
|---|---|---|
| Card | its key, the pieces, the PIN, its owner's public key, its clock (the time and hash of the newest block header it has taken, the difficulty of the hardest), the day | nothing by itself; it signs what it is asked, under its rules, up to the day's limit |
| Cardholder | the card and the PIN | pay twice from a copied card, if a receiver ever accepts without the mint |
| Owner's phone | the twelve words, and from them the card's owner key | with the card in hand: change the PIN, set or remove the limit, add funds, and so take everything. Without the card: nothing. It is a trustee, held on a leash of two things: its words and the card itself |
| Receiving phone | sees the PIN, talks to the card | ask the card to sign more than the amount shown, up to what is left of today's limit; keep change; write pieces the mint will refuse |
| Mint | decides what is spent | what any Cashu mint can |
| Whoever shows the card a block header | a header | move the card's clock forward to the time the header carries, if it shows the work (5.1), and so end a day and begin the next, no sooner than that time. Never move a clock backward. A header dated later than the network's own time has to be forged, which costs work (5.2) |

Two consequences shape the design, as before, and one is new. The receiver
always goes to the mint before saying paid, so a copied or pretend card gains
nothing. A terminal sees the PIN and chooses what to ask the card for, so
nothing the PIN alone can reach may bound it or change it. And the one thing a
terminal cannot manufacture is tomorrow: it can fetch a true "now" from the
network, but not a later one, because a header dated later has to have its work
done, and a terminal does not have a block's worth of it. So a window that only
a newer block can end is a bound it cannot walk round (5).

## 3. The rules

1. **The PIN spends and nothing else.** With the PIN a terminal can `SPEND`
   (up to the day's limit), `LOAD_PROOF` (change written back) and
   `CLEAR_SPENT`. On a card with an owner, changing the
   PIN, limits, record or owner requires the owner's authority. (A card may have no PIN,
   and then it spends without one; a card with a PIN spends up to its no-PIN
   allowance without it. Section 6f.)
2. **The owner's proof administers.** `CHANGE_PIN`, the owner's `SET_LIMIT`
   (`34`), `SET_OWNER`, `SET_CARD`, `ALLOW_LOAD`, `LOCK_CARD` and `RESET_CARD`
   (1.17) need an ECDSA
   signature by the owner key over a label of the command, a nonce the card has
   just given, and the value. They need no PIN, because the owner's phone does
   not know it (`LOCK_CARD` keeps its PIN as well, and so does `RESET_CARD` on a
   locked card). The signature is checked by
   the card's native ECDSA verifier; the owner's private key never leaves the
   phone's native side.
3. **A card with an owner is not open, empty or not; a card with none is open
   while it is empty.** Everything that sets or replaces the PIN, the owner, the
   card record (mint, unit, refund key) or the limit needs, on a card with an
   owner, that owner's proof, whether or not the card holds anything.
   Replacing the owner, or the record, needs the card to be empty as well. A
   card with **no** owner is the factory-fresh card, and while it has no
   unspent piece those same things are set with no proof (the PIN where they
   need one). Why not "an empty card is open", as the first version of this
   design said: a terminal holding the PIN can make a card empty whenever its
   balance fits within the day's limit, and could then set its own PIN and owner
   and load a junk piece, taking the card over for good. The table in section 8
   is the rule worked through every command.
4. **The day is the card's.** The card keeps `now`, the time written in the
   newest Bitcoin block header it has taken (`SET_HEADER`, 5.1). `now` only
   ever moves forward, and **it stays monotonic** across `SET_CARD`,
   `SET_OWNER`, PIN changes and reset. Up to software 1.14 `SET_CARD` with
   a different time key cleared it, as the way out of a wrongly signed time.
   There is no signed time now, and so no such way out: a forged header dated
   far ahead would freeze the clock, and what the owner can do then is set the
   limit again, which gives the day its whole limit (5.2). A header that is not
   later than `now` is simply ignored, and one that shows too little work is
   refused; no header at all leaves the card in its old window. The design
   fails closed.
5. **The window is anchored by the limit, and reset only by a newer block.**
   Setting the limit starts a window at `now`. A `SPEND` that finds `now` a day
   or more past the window's start begins a new one at `now`. `VERIFY_PIN`, a new SELECT, reset and load preserve the current
   window. A
   limit set while `now` is still 0 starts a window with no start, which the
   first header taken then anchors (6).
6. **Refuse before burning; count and burn together.** A piece that would take
   the day past its limit is refused with nothing signed, nothing burned and
   nothing written. Otherwise the day's total and the slot's status change in
   one transaction, and the signing comes after.
7. **No money without an owner.** `LOAD_PROOF` is refused on a card that has no
   owner (`6A90`): there is nobody who could change its PIN or its limit, and no
   "plain cash card with a PIN and no owner" exists. It asks nothing of the
   clock: a card that has been shown no block yet may be loaded, and spends its
   first day on trust (6). Up to software 1.14 it could not be loaded, and this
   rule said so (`6A92`).
8. **Three tries, then blocked** and the owner unblocks it. A `CHANGE_PIN` with
   the owner's proof resets the tries and sets a new PIN, on any card with an
   owner, blocked or not.
9. **The owner adds funds with no PIN.** `ALLOW_LOAD` (owner's proof, label
   `FoxyCard/load`) lets `LOAD_PROOF` and `CLEAR_SPENT` through for the rest of
   that tap, without a verified PIN. It is held in transient memory, so a new
   SELECT or a reset ends it. It lets nothing else through: not `SPEND`, not
   anything the PIN opens. A till still writes change back under the verified
   PIN as before.
10. The rest of `FOXY-CARD-SPEC.md` 5.3: no signature without a slot burned;
    the PIN gate first in every state (since 1.16, at the signature, with the
    no-PIN allowance beside it: 6f); nothing loaded without a PIN set or the
    owner's grant (a card with no PIN is loaded by whoever holds it: 6f); every
    buffer at install and the status byte last.

## 4. What the card stores

The card record, extended. `SET_CARD` writes the unit, the refund key, the
mint and the set flag, and never the limit, the day, `now` or the block fields.
`SET_HEADER` writes `now` and the block fields (5.1):

| Field | Size | |
|---|---|---|
| format | 1 | **3** for this design (2 was the allowance draft and the first limit) |
| set | 1 | 1 once `SET_CARD` has run |
| unit | 1 | sats |
| limit | 4 | the most the card signs for in one day, in sats, big-endian; **0 is no limit, and is what a new card has** |
| refund key | 33 | zeros for now (no refund key) |
| hardest bits | 4 | the difficulty of the hardest block header the card has taken, as the header carries it (`bits`, little-endian); zeros until it has taken one. A later header must show at least a quarter of that work (5.2). Record offset 120. Written by `SET_HEADER`, and only upward |
| last header | 32 | the hash of the newest header taken, as Bitcoin shows a block hash, for the owner's screen. Offset 124. Written by `SET_HEADER` |
| (unused) | 29 | zeros. With the two rows above, the 65 bytes where the time key was up to software 1.14; `GET_CARD` still answers those 65 bytes at offset 40 |
| now | 4 | the time of the newest block header the card has taken, seconds, big-endian; 0 until it has taken one. Written only by `SET_HEADER`, and by nothing that lowers it |
| window start | 4 | when the current day began; written by `SET_LIMIT`, by a `SPEND` that begins a new day, and by the first header taken after a limit (or, since 1.16, an allowance) was set while `now` was 0 (6). The daily limit's window and the allowance's are this one |
| spent today | 4 | what the card has signed for since the window began |
| limit on one payment | 4 | the most the card signs for in one payment straight away, in sats, big-endian; **0 is no limit**. A larger payment waits (section 6a). Not in `GET_CARD`; `GET_INFO` with P1 = 1 says it |
| no-PIN allowance | 4 | **1.16.** The most the card signs for in one day without the PIN, in sats, big-endian, on a card that has a PIN; **0 is none**, and then every payment needs the PIN. Record offset 201. `GET_INFO` with P1 = 1 says it, to anyone (6f). It held when the tap began, when the limit above was counted against ten seconds of the clock, and was zeros from 1.5 to 1.15 |
| no-PIN spent | 4 | **1.16.** What the card has signed for with no PIN since the window began; goes to 0 when the day turns, and with a new number for the allowance. Offset 205. It held what had been signed for in that tap, and was zeros from 1.5 to 1.15 |
| mint | 1 + up to 80 | the mint's address, as text |

The mint length was reduced from 96 to 80 characters. The reason is one
command: `SET_CARD` with the owner's proof on a card that has an owner carries a
proof of up to 72 bytes, 100 bytes of record and the mint, and a short APDU
holds 255 data bytes in all (1 + 72 + 100 + 80 = 253).

Kept apart from the record, as the owner secret was: the **owner key**, 65
bytes uncompressed, and a flag that one has been given (`GET_INFO` byte 16).

Kept in RAM, gone with the tap: the **nonce** the card last gave for an
owner's proof and whether it is still live, and whether `ALLOW_LOAD` has been
given in this tap. There is no per-entry count any more; `VERIFY_PIN` changes
nothing about spending and can be sent as often as its sender likes. Kept in RAM,
gone with the power and not with a SELECT: the **time the terminal told** (5.3).

**The curve.** The owner key is a NIST P-256 (secp256r1) public key,
signatures are ECDSA with SHA-256 in DER form, and the key is uncompressed
(`04 ‖ X ‖ Y`, 65 bytes). It has nothing to do with the card's own secp256k1
key or with Cashu. The applet sets the curve's parameters on the key itself
(`p`, `a`, `b`, `G`, `n` and a cofactor of 1) and never relies on a default.
Up to software 1.14 a second key of the same kind, the time key, was kept in
the record; there is none now, and nobody signs the clock (section 5).

Why the key is uncompressed: the card's ECDSA verifier takes a public key
through `setW`, which wants `04 ‖ X ‖ Y`, and decompressing a point on the card
is a modular square root nobody should write. Sixty-five bytes is the whole
cost.

## 5. Time

<a id="51-what-the-card-accepts"></a>

### 5.1 Header validation

The card's clock is the time written in the newest Bitcoin block header it has
taken. `SET_HEADER` (`36`) carries one: the 80 bytes as the network carries
them, every number little-endian. They are the version (4), the hash of the
previous block (32), the merkle root (32), the time (4, at byte 68), the
difficulty as `bits` (4, at byte 72) and the nonce (4). The card does not ask
who brings it. Its trust check covers the work required to produce the header.
Previous-block linkage, the merkle root and version remain outside that check.

Three checks, in this order. A header that fails one is refused and nothing
changes:

1. **Its own work.** The card hashes the 80 bytes twice with SHA-256 and reads
   the hash as a little-endian number, as Bitcoin does. That number must be at
   or under the target the header's own `bits` name. This is the proof of work:
   `6A93` if it is not shown.
2. **The floor.** The target must also be at or under the floor built into the
   applet, `bits` `0x17087BC0` (5.2): `6A93` if it is over.
3. **The quarter.** Once the card has taken any header, the target must be at or
   under four times the target of the hardest header it has taken: the header
   must show at least a quarter of that work (5.2). `6A93` if it does not.

`bits` is Bitcoin's short form of a target: its last byte is a size and the
three bytes before it a mantissa, and the target is the mantissa times 256 to
the power of the size less three. A `bits` no header could carry (a size of 0 or
of more than 32, or a mantissa with its top bit set, which would be a negative
target) is `6A80`. Any length of data but 80 is `6700`.

A header that passes is **taken** if its time is later than `now`. The card then
writes, in one transaction: `now`, set to the header's time; the start of the
day's window, where a limit is set and the window has no start yet (6); the
header's `bits`, where they are the hardest yet (record offset 120, 4 bytes, as
the header carries them); and its hash, as Bitcoin shows a block hash (offset
124, 32 bytes), for the owner's screen. A header that is not later than `now`
passes the same checks, changes nothing and is answered `9000` as a taken one
is, so a terminal that brings the header it has is never in the wrong. Either
way the answer is the card's `now`, four bytes, big-endian, so that the phone
sees what the card believes.

No key, no PIN, no owner, no record and no state the card can be in refuses a
good header: a blocked or locked card takes one, and a till may send one. There
is no nonce and no freshness check, on purpose. An old header cannot help
anybody, since it moves nothing, and a newer one that shows the work is as good
as any. So a header is a **public broadcast**: anyone may fetch one and show it,
and nothing about a tap waits on a signer. Like any command that is not the next
step of a payment, it drops a payment begun and not yet signed (6c), so a till
shows its header before it begins one.

The card's time is a block's, and a block's time is not the second. The network
lets a block be dated up to two hours ahead of its own clock, so the card's
clock can lead the true time by that much. And the clock moves a block at a
time, about ten minutes, and only when someone shows the card a header: a card
that is shown none keeps its clock where it is, and its day does not end.

On the chip a header is two SHA-256 passes, one over 80 bytes and one over 32,
and a few compares of 32 bytes: expected to be well under 20 ms. It has not been
measured (`FOXY-CARD-HARDWARE.md`).

<a id="52-the-floor-and-the-quarter-and-why-those-numbers"></a>

### 5.2 Difficulty floor and relative target bound

The card cannot see the network, so it cannot know what a block's work is today.
It holds a header to two numbers of its own, and they do different jobs.

**The quarter.** Once the card has taken a header, every later one must show at
least a quarter of the work of the hardest it has taken (check 3). The card
keeps the hardest `bits` in its record and raises them whenever a harder header
is taken, so the bar climbs with the network and nothing lowers it. A card used
for years is held to the work of those years, and a forged header has to show a
quarter of that: about two and a half minutes of all the mining in the world, at
the work the network did when this version was written.

Why a quarter, and not all of it. The network's work is not steady. Its
difficulty fell by about a fifth, peak to trough, in the year before this
version, and by about half in 2021. A bar at the whole of the hardest header
would refuse honest blocks after any fall at all. A quarter lets the network
lose three parts in four of the work the card last saw before an honest block is
refused. If it ever did, the card would refuse every honest header: its clock
would stop and its day would not end, and nothing on the card sets the bar back
(`SET_HEADER` writes it, and only upward). That fails closed: the card signs for
no more than what is left of its day, and the owner can give it the limit again
(6).

**The floor.** The quarter needs something to be a quarter of, and the first
header a card takes has nothing before it. So the applet has a floor: `bits`
`0x17087BC0`, four times the target of the network's blocks when this version
was made (`0x17021EF0`), that is, a quarter of their work: a difficulty of about
3.3e13, about 2^77 hashes to find one header, two and a half minutes of all the
mining in the world. A header with less work than that is `6A93`, however little
the card has seen.

Why a quarter, and not less. Every card in use is already held to a quarter of
the hardest header it has itself taken, so for a card set up in this version's
time the floor and the ratchet are one bound: a new card's first header costs a
forger what every later one does. A lower floor would buy nothing but a cheaper
first header. A floor is a number fixed in the applet, and a card outlives the
year it was made in, so it could in principle be outgrown downwards: the
network's work would have to fall by three quarters from this version's time
before an honest first header was refused, which it never has (its fall in 2021
was about a half, and over the year before 1.15 about a fifth), and a fall that
deep would stall every used card's ratchet alike, which a new record remedies.
The floor does not climb with the network, so as the network grows it is a
smaller part of it: each version of the software sets it to a quarter of its own
time's, and a card made with that version starts from there.

**The floor matters for the first header only.** Once the card has taken a
header from the network, its quarter is far above the floor, and the floor has
nothing more to say. (It is the stricter of the two only until a header with more
than four times the floor's work has been taken.)

**What a forgery costs, and buys.** A header is believed for its work, whatever
else it says, so a forger pays the work and writes any time that fits in four
bytes. On a card that has taken a header from the network the work is a quarter
of a block's. On a card that has taken none it is the floor's. What it buys is
the clock moved forward to the time the forger chose. If that is a day past the
window's start, it is another day's limit, once for each header forged. If it is
years ahead, it freezes the clock: every real block is earlier than the clock
now, so none moves it, and the day does not end. The card fails closed. From then
on it signs for one more limit's worth in all, and no more, until the owner sets
the limit again, which begins a window at the clock's new time with nothing
spent (6).

The price is the same whatever the card holds. A limit worth little is far
beyond a forger's reach; one worth a great deal is only as strong as that price.
A card is better for having been shown a header at the start, because the floor's
work is the smaller of the two (the phone shows its card a block at each tap
where the card is behind it, section 9).

### 5.3 The time a terminal tells

`TELL_TIME` (`37`) carries four bytes: the terminal's own clock, seconds,
big-endian. The card keeps it in RAM for this time in the field (retained across
SELECT and cleared on power loss) and writes it into every receipt (6b) and into
the log entry for the time in the field (6b) as they are made, zeros where none
was told. A log entry takes the told time as it stands when the entry is begun,
by the first thing in the time in the field that is written down; a receipt,
when its payment is signed. So a terminal tells the time first.

It is trusted for nothing. It is not the day and it is not any limit, nothing on
the card is judged by it, and no key, PIN or state of the card refuses it. It is
a note, so that the owner's screen can say to the second when a payment was,
beside the block time that is the card's own: a terminal that lies here lies in
its own entries and nowhere else. It answers nothing, and is `6700` for any
length but four.

What the phone does with the clock is in section 9.

## 6. The day

**The window.** `SET_LIMIT`, by either path, writes the limit, sets the window
start to `now` and spent-today to 0. (Since 1.16 the no-PIN allowance, 6f, shares
this window and its day: it begins at the first payment when either limit is set,
and both counts go to 0 when the day turns.) It needs no clock: a card that has been
shown no block yet (`now` = 0) is given its limit like any other, and its window
has no start until a header gives it one (below). On `SPEND`, after the PIN gate
and the slot checks, when the limit is not 0:

1. If `now ≥ window start + 86 400`, the window is new: it will start at `now`
   with nothing spent.
2. spent today (0 in a new window) + the piece's amount, with its carry, over
   the limit → `6A8F`, nothing signed, nothing burned, nothing written.
3. Otherwise, in one transaction: the window start (if new) `= now`; spent today
   `+=` the amount; the slot's status `=` spent. Then the signature.

A limit of 0 is no limit: steps 1 to 3 are skipped, nothing is counted, and the
clock is not looked at. **A new card's limit is 0, and set-up does not ask for
one**; a limit is set later from CHANGE LIMIT, to any amount, and removed the
same way (section 10).

**The clock moves a block at a time.** `now` is the time in the newest header the
card has taken, so it moves only when someone shows the card a header, and then
to that header's time. The day ends when the card is shown a header a day or more
past the window's start, and not before; a card that is shown none does not end
its day. A terminal that has the PIN and wants a second day has to bring such a
header: a real block, when the world has made one, or a forgery (5.2). It cannot
end a day without a header dated a day on, and the next `SPEND` after that
header begins the new window at the header's time.

**The first day, on trust.** A card that has been shown no header yet may be
loaded, may be given a day's limit, and may pay under it. Its window has no start
and cannot end, so what leaves the card counts up to the limit, and then the
card refuses (`6A8F`) until a header arrives. The first header taken anchors the
window at its own time (5.1), and what was spent on trust counts in that window.
That is a day on trust and no more than the limit: the card does not need a
header to be of use.

What that day is worth to a bad terminal is one limit, and one more. The header
that anchors the window is the first one the terminal shows, and a terminal can
choose an old one: any real block with the work will do, and they are all public.
The window is then anchored at that old time, and the first current block ends
it; the card has spent one limit on trust and may spend another. That is once in
a card's life, and only for a card that was spent from before it had been shown a
block. A phone with a route shows its card a block at the first tap where the
card is behind (section 9), which closes it.

**Counted value.** The limit charges the value leaving the card. From software 1.12 a
payment's change is the card's own (`SPEND_ALL_CHANGE`, 6d): outputs the card
builds and locks to its own key, which no terminal can take, so the day is
charged the pieces less that change, and a 300-sat payment made with one
piece of 1,000 and 700 of the card's own change costs the day 300. Change a
terminal writes back by other means the card cannot check, as the draft's
allowance could not, and it gives the day nothing back: before 1.12 that
payment cost the day 1,000. A till picks pieces as near the price as it can
(`FOXY-CARD-SPEC.md` 8.1), and the holder's phone loads a card in pieces
small enough for the limit to be useful.

**The edge of a window.** A window is a fixed day from its start, so a terminal
that straddles one boundary can take up to two days' limit in a short span. That
is the bound, and it is written down rather than hidden. (Rolling windows need a
log of spends; a fixed one needs eight bytes.)

**What a day is worth to a bad terminal.** One visit, one day's limit, in one
tap if it likes, and nothing it can send changes the day's length, the limit, or
the clock, except forward, by a header that has the work. To begin a second day
inside the first it must bring a header dated a day on from the window's start: a
real block, once the world has made one, or a forgery that costs about a quarter
of a block's work (5.2). Holding the PIN and the card does not buy that.

**What the limits need.** The day, and the limit on one payment (6a; the per-tap
limit), each bound a terminal only where the owner has set them. A new card has
neither: set-up asks for no limit, and a card with none is bound by nothing but
its balance.

**What the owner's own withdrawal does to it.** The owner's phone taking money
off the card lifts the limit with its proof, spends, and puts the old limit back
in the same tap (section 9). Putting the limit back is a `SET_LIMIT`, which
starts a new window with nothing spent, so a withdrawal gives the day back its
whole limit. That is one extra day's limit, at the moment the owner is holding
the card, and no more.

## 6a. One payment

A second limit, and unlike the day's it asks no clock: **the most the card
signs for in one payment straight away.** The card refuses nothing over it. It
makes a larger payment *wait*.

Why not a window, which is what this was (ten seconds of the card's clock, and
`6A95` over it). The card has no clock that runs. Its "now" is the time of the
newest block header a terminal has shown it, which moves a block at a time,
about ten minutes, and only when someone shows it one: a window of ten seconds
on a clock like that does not end until the next block is shown, and a terminal
chooses when to show it. A limit that asks no clock has nothing to walk
forward.

**The rule.** With a limit of `L` sats and a payment of which `S` sats leave
the card for good, the pieces named at `SPEND_ALL_BEGIN`, less the change the
card makes for itself (`SPEND_ALL_CHANGE`, software 1.12; section 6d), worked
out at the first `SPEND_ALL_SIGN`, when the change is known, and shaped
(software 1.13) so that whoever holds the card can feel that a payment was over
the limit:

    S ≤ L                waits = 0                                                (change or no change)
    S > L                waits = WAIT_OVER_SIGNS + WAIT_MORE_SIGNS × (ceil(S / L) − 2)   (10 + 4 for each further limit's worth: about seven seconds, then three each; 1.13 to 1.17 had 3 for each further one, 1.13 to 1.16 had 7 for the first, about five seconds)

less the time the change outputs the card made in this payment took, two
waits for every three outputs (software 1.14; an output is about two thirds of
a signature's work: 0.4 s against 0.6 s on the chip), never below 0. So a
payment over the limit takes the same time in the hand with change as without,
and what is felt says how far over the limit it was, which a terminal cannot
shorten by asking for change outputs: each costs the holder's hand what it
takes off. (1.13 took one wait off for every output, more than an output costs,
and a terminal could buy the wait down with outputs of a sat.) The phone indicates that
change is due: the till's phone buzzes three
times as the first tap ends with change owed. "Within `L`" is `S ≤ L +
L/32`: a limit set in another money is so many sats at one moment and a price
in that money so many at another, so a payment of exactly the limit lands a
few sats over, and that is not "over the limit". So a payment within the
limit that makes no change goes at once (about two seconds in the hand, all of
it reading and signing, plus about half a second for each change output the
card makes); one over the limit about seven seconds longer, and three more for
every further limit's worth. `L` of 0 is no limit. Past 255 limits a payment waits
as 255 do (1022 waits), which is about twelve minutes and so never. (Before 1.13, 1.12
counted four signatures for every limit's worth, a part counting as one;
before 1.12 the first `L` was free and the pieces were counted whole.)

**One payment a tap at full speed.** A second payment signed in the same time
in the field waits as one over the limit does, about seven seconds, and three
more for every limit's worth of it, whether or not there is a limit, unless
the owner's grant (`ALLOW_LOAD`) is in the tap. A terminal that holds the PIN
could otherwise take a limit's worth a second for as long as the card is held,
each payment signed at once; now each costs it seven seconds, or a fresh tap,
which asks the PIN again. The owner's phone, which takes a whole card off in
more than one signature where its pieces have more than one date, gives its
grant first and is not slowed. The change tap and a refund are loads, not
payments, and are not touched by this.

**What a wait is.** The card cannot sleep and has no timer. The one thing on it
whose duration is the chip's own, and that no terminal can shorten, is a
signature: about three quarters of a second, measured, and very steady. So the
card waits by signing, over 32 bytes of its own choosing, and throwing the
signature away. One to a command: while waits remain, `SPEND_ALL_SIGN` does
one, and answers `9000` with **two bytes**, `00 01`, "not yet", in place of
the signature. The terminal sends `SPEND_ALL_SIGN` again. When none remain,
the next one burns the pieces and answers the signature (6c). The card does
not say how many are to come: that would say how many limits the payment is
over, and so what the limit is. No
command is longer than one signature, which matters to a phone that gives up
on a card that is silent for long.

**Nothing is burned, counted or written until the wait is done.** A card
lifted in the wait has lost nothing and the terminal holds nothing. Any other
command in the wait drops the payment, as it does at any point between
`BEGIN` and `SIGN` (6c), and so does a `SELECT` or a reset; `SPEND_ALL_SIGN`
then answers `6985`, and a new `BEGIN` waits in full again. The count of waits
is in RAM and cannot be set from outside.

**Nothing is remembered from one payment to the next.** Two payments of `L`,
one straight after the other, wait nothing. That is on purpose, and it is the
whole of what this limit is: a terminal that has the PIN can take `L` for each
signature it has the card make, a second or so apiece, for as long as the card
is held, by many small payments or by one large one that waits. It cannot go
faster, whatever it sends and whatever header it shows. The day's limit (6) is
the ceiling; this is the rate, and what it buys the holder is that money
leaves the card about as fast as an honest payment of that size would, so
that a card lifted when the payment ought to be over has lost about what it
ought to have paid.

The wait is charged on the value leaving the card: the pieces,
less the change the card makes for itself (6d; before 1.12 the pieces whole,
since change a terminal writes back is not something the card can check). A wallet
that wants the card held no longer than it must chooses the pieces that
overpay least.

**Setting it.** `SET_LIMIT` with eight bytes of limit (the day's, then this
one) sets both, and twelve (1.16) add the no-PIN allowance (6f); four bytes set
the day's and leave this one. It needs no clock,
and neither does the day's (up to software 1.14 the day's did, unless it was 0:
`6A92`). Bit 3 of `GET_INFO`'s capabilities byte says the card waits and does
not refuse. The owner's phone lifts it to 0 with its proof to take money off its
own card, and puts it back, as it does the day's.

**Who is told it.** The owner, and nobody else. `GET_INFO` with P1 = 1 answers
it at bytes 30 to 33 only when the owner's grant (`ALLOW_LOAD`) has been given
in this tap; to anyone else, the PIN verified or not, those bytes are zeros,
which is also what a card with no such limit says. (The eight bytes after
them, 34 to 41, were the window and its count and were zeros to everyone; since
1.16 they are the no-PIN allowance and what is counted against it, and are said
to anyone: 6f.) A terminal
that was told the limit would ask for just under it, again and again, and
never be made to wait.

What that buys is time, once. A terminal that has the PIN can still find the
limit by trying: a payment that is answered "not yet" is over it, one that is
signed is not, and each try is a second of the card being held. A dozen tries
close in on it. Nothing a card can do stops that short of charging for a
payment given up in the wait, which would charge a holder for lifting the
card, and lifting the card is the one thing a holder can do.

## 6b. The log

The card keeps its own account of what it has signed for and what it has
refused. It is the only record of a card's use that no terminal's honesty is
needed for, and it is what a holder reads to find out what a tap really took.

**Only the card writes it.** A `SPEND` writes it in the transaction that burns
the piece: no piece is burned that the log does not have. A `SPEND` refused for
being over the day's limit (`6A8F`) writes it and then refuses. No command sets
it, moves it back or clears it, for the PIN or for the owner, and `CLEAR_SPENT`,
`SET_LIMIT`, `CHANGE_PIN`, `SET_CARD` and `LOCK_CARD` leave it as it is. The
counts only go up, and stop at the top of four bytes.

**What it holds** (181 bytes, permanent; 149 before software 1.15):

| Field | Size | |
|---|---|---|
| taps | 4 | taps in which anything was signed for or refused, ever |
| sats | 4 | sats signed for, ever |
| refused | 4 | spends refused for being over a limit, ever |
| runs | 4 | times a third spend was refused inside ten seconds of the clock (below) |
| run start, run length | 4, 1 | the run of refusals in hand: the clock at its first, and how many |
| the last eight taps | 8 × 20 | a ring; the tap numbered n is at (n − 1) mod 8. Each: the clock when it began (4), sats signed for in it (4), pieces signed (1), spends refused in it (1), flags (1; bit 0 is the mark, bit 1 a payment that waited), pieces put on in it (1), sats put on in it (4), and the time the terminal told (4; 5.3) |

**A tap, here, is one time in a reader's field**: from the card being powered
to its being taken away (a byte of RAM that is gone with the power, and not
with a SELECT, says whether this one has an entry yet). The log counts by the
field, because that is what a person did. A tap in which a payment was over
the limit on one payment, and was waited for (6a), says so: bit 1 of its flags. A terminal that cuts the field to
begin again shows as more taps, and the counts count every one, so the ring
being pushed round hides nothing from a phone that remembers the counts it saw.

**Recorded value.** The log records the signed amount. The card does not know the
price. It cannot say that a payment was too much; it says what left, and when.

**The mark.** A terminal that keeps to the limits is never refused: `GET_INFO`
says what the day and the tap have left, before anything is asked for. A
refusal is therefore a terminal that asked for more than it was allowed. A run
of **three inside ten seconds of the card's clock** (from the run's first
refusal) is one trying the limit again and again: the count of runs goes up
once, at the third, and the tap in which the third or any later refusal of the
run falls is marked. Ten seconds of the clock, and not three in a row at any
distance: a terminal that does not know of a limit and is refused once at each
of three visits is not that. The clock is block time (5), which moves a block at
a time, so in practice a run is three refusals with no newer block shown between
them. Before the card has been shown any header the clock cannot tell visits
apart at all, and three refusals at three visits are one run there and mark the
tap; the first header ends it. A card with no limit refuses nothing, and so
marks nothing: the mark needs a limit to be set.

**What a mark is not.** It is not proof of theft, and its absence is not proof
of honesty. A terminal that takes what the limits allow is never refused and
leaves no mark; what it took is in the taps and the counts all the same.

**Reading it: `GET_LOG` (`18`).** Sixteen bytes of counts (taps, sats, refused,
runs), then the taps the ring holds, newest first, twenty bytes each: 176 bytes
at the most. For whoever the card is open to: the PIN verified in this tap, or
the owner's grant (`ALLOW_LOAD`), so the owner's phone reads it with no PIN. It
says when a card was used and for how much, which a stranger's reader is not
told (`6982`). A card with no PIN yet has an empty log, and answers anyone.


**What was put on, too.** A tap's entry is twenty bytes since 1.15 (sixteen
from 1.6): after what was signed for in it (clock 4, sats 4, pieces 1, refusals
1, flags 1) come the pieces put on in it (1, stops at 255), what they were worth
(4), and the time the terminal told (4, zeros where it told none: 5.3).
`LOAD_PROOF` writes it once for the command, after the pieces are stored. So
"taps" counts every time in the field in which anything was signed for,
refused or put on.

**The clock moved twice in a tap** (flag bit 2) is gone. Up to software 1.14 the
card marked a time in the field in which a signed time was told twice, more than
two minutes apart, because a terminal walking the clock forward to turn the day
did exactly that. A terminal cannot walk the clock now: it moves only by headers
that have the work (5). Bit 2 is never set, and the fourth count counts runs of
refusals and nothing else.

**Receipts** (`GET_LOG` with P1 = 1). For each payment the card signs, written
after the burn: the clock (4; the time of the newest block header the card has
taken), the time the terminal told (4; zeros where it told none, 5.3), what the
pieces were worth (4), SHA-256 of the message it signed (32), and the first
output's blinded message as the terminal gave it (33; zeros for a payment with
no outputs). 77 bytes each (73 before software 1.15). The last sixteen, in a
ring, after a count of every payment ever. Answered as the count (4) and up to
three receipts newest first, P2 back from the newest: 235 bytes at the most.
The first time is the card's own and a terminal cannot choose it; the second is
the terminal's and the card vouches for nothing in it. They are kept apart so
that the owner's screen can give the second beside the first.

The log says what left the card and when. A receipt says where it went, as far
as a card can know. Under SIG_ALL the message names every output of the one
swap the mint took the signature for, and an output is made from its
receiver's seed. Nobody can tell whose an output is by looking at it; anybody
who is later shown a wallet's seed can make that wallet's outputs again and
find this one among them, and the hash then pins the whole swap. It is what a
holder has to show for a payment they did not mean to make: it does not say
who took it, and it lets a wallet be shown to be the one, or not to be.

By the owner's grant given in this tap and nothing else: not the PIN, which a
till has. No command clears it. The card's ring is short, and a phone that
wants more than sixteen keeps what it reads.

## 6c. One signature for a payment

Up to format 3 the card signed for each piece it paid with, most of a second
apiece on the chip, and each signature was over that piece's secret and nothing
else (NUT-11's `SIG_INPUTS`). A payment of six pieces was six signatures and
about five seconds of holding the card still; and a signature for a piece was
good for any swap at all, so whoever held the signed pieces decided where the
money went.

Format 4 signs **once**, over the whole swap (NUT-11's `SIG_ALL`):

    secret_0 C_0 ... secret_n C_n  amount_0 B_0 ... amount_m B_m

as text with nothing between the parts: each piece's secret as the card builds
it, its `C` in lowercase hex, and for each output of the swap its amount in
decimal and its blinded message `B_` in lowercase hex. The card signs SHA-256
of that (BIP-340), and the signature is the witness of the first piece; the
others carry none. That is the message as NUT-11 now reads and as CDK and
Nutshell both check it: the same swaps were put to both, and they agree on
every one (one signature for the whole is taken; a signature for each piece, a
signature over other outputs, a piece that was not signed for, and pieces
whose tags differ are all refused).

**The secret.** A slot is the same 81 bytes. The text the card builds for it
ends with the flag as its last tag, which is where a wallet's library puts it:

    ["P2PK",{"nonce":"<64 hex>","data":"<card key>","tags":[["sigflag","SIG_ALL"]]}]
    ["P2PK",{"nonce":"<64 hex>","data":"<card key>","tags":[["locktime","<date>"],["refund","<refund key>"],["sigflag","SIG_ALL"]]}]

So a card of format 4 can sign for no piece locked without the flag, and a
piece locked with it is not one a format 3 card can sign for. A card is one or
the other for all it holds; the format byte says which.

**The commands.** A payment is three, in this order and with nothing between
them:

1. `SPEND_ALL_BEGIN` (`22`): the places it is made of, a byte each, in the order
   the mint will be shown them. The PIN first, as for any spending. One place
   or more, as many as the card has (`6700` for none, `6A96` for more; before
   1.7 it was thirty-two at the most); each a place the card has
   (`6A83`), unspent (`6A88` for an empty place, `6985` for a spent one), named
   once (`6A80`), and of the same date as the first (`6A80`): a mint takes one
   signature only for pieces whose secrets agree in everything but the nonce.
   The day's limit (6) is held to what the places are worth **together**
   (`6A8F` over the day, the refusal written to the log of 6b), and what the
   payment will wait (6a) is worked
   out from the same sum. The card hashes each
   place's secret and `C` itself, from the slot: the terminal names places and
   never supplies a secret. Answers what they are worth, 4 bytes.
2. `SPEND_ALL_OUTPUTS` (`23`): the swap's outputs, 37 bytes each (amount 4, `B_`
   33), as many to a command as fit and as many commands as it takes. Each is
   hashed as its amount in decimal and its `B_` in hex. `6985` with no payment
   begun; `6700` for a length that is not a multiple of 37, which also drops
   the payment.
3. `SPEND_ALL_SIGN` (`24`): `6985` with no payment begun. The PIN; then, while
   the payment has waits to do (6a), one of them and two bytes in answer, how
   many are still to come, with nothing burned; sent again until none are
   left. Then the day's limit again; then the signature is made, and in **one
   transaction** every place is marked spent, the day's count is charged, the note
   that the card has paid is set (8.2), the log gains the payment, and the
   signature is kept. `6A96` if the transaction cannot hold it, with nothing
   changed. Only then is the signature answered, 64 bytes.

Anything else sent between `BEGIN` and `SIGN` drops the payment, and `SIGN`
then answers `6985`: another command, another `BEGIN`, a `SELECT`, the card
leaving the field. Nothing can be read or changed under a payment that is
being hashed.

`SPEND_ALL_AGAIN` (`25`), under the PIN, answers the last signature the card
gave (`6A88` if it has given none). A card that is taken away as it answers
`SIGN` has burned the pieces, and the terminal never heard the signature: asked
again at its next tap, it gives it. The signature is over a swap only the
terminal that set it out can make, so giving it twice gives nobody anything
they did not have. It is kept until the next `SIGN` replaces it.

`SPEND_PROOF` (`20`) is gone: `6D00`. There is no command by which this card
signs for a piece alone.

**What it buys.** One signature whatever the number of pieces, so a payment
made of many small pieces costs the card no more than one made of one large
one, and a terminal can ask for pieces that come to exactly the price instead
of over-paying and writing change back at a second tap. And the signature
names where the money goes: signed pieces taken from a terminal, or seen on
the air, are worth nothing to anyone who cannot make those very outputs.

**What it does not.** The terminal chooses the outputs, and the card cannot
tell whose they are. A terminal built to cheat still takes what it asks the
card to sign for, up to the limits, exactly as before; the limits and the log
are what bound and show that, and they are held to the sum. And a signature
that binds its outputs is good only while the mint will still make that swap:
if the mint retires the keyset the outputs are on, or raises its fee, between
the signature and the swap, the pieces cannot be swapped by the card's
signature at all (a card with a refund key: its owner's phone takes them back
after their date, as section 6 of `FOXY-CARD-SPEC.md` has it).

Measured on the chip, with 1.7: its transaction held the burn of eleven
pieces and not of thirty-two (`SIGN` answered `6A96`, nothing burned, no
signature given). 1.8 takes the burn out of the transaction (6d). Not yet
measured: how long `BEGIN` takes for a hundred places (it is some kilobytes of
SHA-256) beside the one signature.

## 6d. Time on the card

How long a card has to be held is most of what a person knows of it, and
almost all of it is the card's own work: every command is a round trip of a
few hundredths of a second, and anything the applet does byte by byte in
bytecode is slow. Measured on the chip, through a phone: a signature is three
quarters of a second and cannot be made less; taking in a payment's pieces
(`SPEND_ALL_BEGIN`) was 79 ms a piece, two seconds for twenty-five; an output
was 34 ms; a load was 60 ms a piece; and reading every piece, three to a
command, was up to 0.7 s. Version 1.6 changes none of what the card does for
a piece and most of how long it takes.

- **The text of a piece is written once, at loading.** A payment's message is
  each piece's secret and its C as text, and the two parts of that which
  differ from piece to piece are its nonce and its C in hex. `LOAD_PROOF`
  writes those beside the slot (`slotHex`, 130 bytes a place), before the
  slot's data and its status byte, so a tear leaves the place empty as it
  always did. `SPEND_ALL_BEGIN` then turns nothing to hex for a piece: it
  builds the rest of the secret once (everything after the nonce is the same
  for every piece of one payment: the card's key, and the one date and refund
  key), and hands the hash four spans a piece.
- **An output is one span to the hash**, its amount in decimal ending where
  its `B_` in hex begins; an amount under 32,768 is divided as a short.
- **A brief listing** (`GET_PIECES`, P2 = 1): what a till needs to choose
  pieces is what each is worth, its date and its keyset, sixteen bytes, and
  not its nonce and its C. Fourteen places to a command where the whole form
  has three. The pieces it chooses it then asks for whole, by slot, three to
  a command (P2 = 2), and checks each against what the listing said.
- **Three pieces to one `LOAD_PROOF`.** Each is taken as one alone would be,
  in order (the rule is in section 8).

Loading is a little slower for a piece than it was (it now writes the hex)
and quicker in all (a third of the commands). Loading is done by a card's
holder at home; paying is done at a till.

**Version 1.7: 128 places, and a shorter listing.** A price typed in dollars
is an odd number of sats, so every payment needs small pieces of its own, and
a card that is to pay several prices in a row exactly has to hold several of
every small size: eight each of the eleven sizes from 1 to 1,024 are
eighty-eight pieces. Sixty-four places did not hold that and the rest of a
card's money, so there are 128. Three things follow, and nothing the card
signs or stores for a piece is different:

- **A place's number is seven bits.** The tag of `GET_PIECES` was
  `(state << 6) | place`; it is now the place, with `0x80` where the place is
  spent. `next` ends at 128.
- **The short listing** (`GET_PIECES`, P2 = 3) takes the place of the brief
  one (P2 = 1, which this card refuses with `6A86`: its tags could not name
  these places). A till reads what a card holds at every payment, and a deep
  drawer is a hundred pieces. For each unspent place: the place (1), with
  `0x80` where its keyset (8) and date (4) follow, which they do in the first
  entry of every answer and wherever they are not those of the entry before;
  then the power of two it is worth (1), or `FF` and its amount (4) where it
  is worth some other amount. Spent and empty places are not listed
  (`GET_INFO` counts them). A card whose pieces are of one keyset and one date
  and are powers of two is two bytes a piece after the first: all 128 places
  in two answers. The answer is gathered and sent at once, where the brief
  listing sent each entry by itself, which was most of what it took.
- **A payment may name every place the card has**, where it was thirty-two: a
  deep drawer holds its money in small pieces, and a payment of most of a
  small card is many of them. The burn is still one transaction.

Bit 5 of the capabilities byte says a card has more than sixty-four places,
seven-bit tags and the short listing; `GET_INFO`'s count of places is 128.

**Version 1.8: the burn is not in the transaction.** A payment burned its
pieces inside the transaction that committed it, a status byte for each. A
chip's transaction holds only so much, and how much is not something a
simulator has: jCardSim's has no size at all. On the card this runs on, a
payment of eleven pieces went through and one of thirty-two was refused
(`6A96`, by the `TransactionException` the code was already catching, with
nothing burned). A deep drawer is a hundred pieces, and taking a card's money
off is all of them.

So the transaction is now the same size whatever the payment:

1. The signature is made, into the answer's buffer. Nothing is written yet.
2. The places are written to `burnList` (how many, then a byte each), outside
   any transaction. Nothing reads that list unless `burnPending` is set.
3. One transaction: the day's charge, `burnPending = 1`, the note that the
   next tap may put change on, the log, and the signature kept for
   `SPEND_ALL_AGAIN`. **From the moment it commits, the pieces are spent.**
4. `finishBurn`: each place in the list has its status byte set to spent, one
   plain write each, and `burnPending` is cleared (from 1.9 in a transaction
   of its own, one byte: a commit is the one write a chip must have made
   lasting before it goes on, so the status bytes are in place before the
   note that they are owed is gone).
5. The receipt, in a transaction of its own, and then the answer.

A card that leaves the field before step 3 commits has a list nobody reads,
and has burned nothing. One that leaves after it, with some status bytes not
yet written, finishes step 4 at the start of its very next command, before
that command (or `SELECT`) looks at anything: `process` begins with it. A
byte written twice is the same byte, so step 4 may be cut short and begun
again any number of times. There is no state in which the payment is
committed and one of its pieces can still be read as unspent by a command,
and none in which a piece is marked spent for a payment that did not commit.

Bit 6 of the capabilities byte says a card burns so, and a terminal may then
name as many places in one payment as the card has. A terminal that reads a
card without it should name few: eight, by what was seen on the chip.

## 6e. The PIN, sealed

A PIN typed at a terminal crossed the air to the card as it was typed, and
whoever was listening to the tap had it; the PIN, and later the card, is all a
thief needs. A bank card's PIN is enciphered to a key of the card's. From 1.9
so is this one, and bit 7 of the capabilities byte says so.

**The PIN key.** A second secp256k1 key pair, made on the card at install and
used for this and nothing else. It is not the key the card signs payments
with: a terminal puts points of its own choosing to this key, and whatever
that could ever tell it, it tells it nothing of the key the money is locked
to. `GET_NONCE` with P1 = 1 answers, on any card and with no PIN,

    nonce (16)    fresh at every asking, and good once
    PIN key (33)  compressed
    signature (64) BIP-340, by the card's own key, over
                  SHA-256("FoxyCard/pinkey" || the PIN key)

A terminal that knows the card's key (it reads it at every tap, and the
owner's phone has it on file) holds the PIN key to it by the signature, which
is made once, at the first asking, and kept.

**A sealed command.** `VERIFY_PIN`, `SET_PIN` and `CHANGE_PIN` with P1 = 1
carry, in place of their clear data,

    E (65)        the sender's public key for this one message, 04 || X || Y
    ct (n)        the data under a keystream
    tag (16)

    secret      = the x of the point E and the PIN key share (32 bytes)
    block(i, m) = SHA-256("FoxyCard/seal" || i (1) || secret || E || nonce
                          || the instruction (1) || m)
    tag         = the first 16 bytes of block(0, ct)
    keystream   = block(1) || block(2) || ...

The card checks the tag before it opens anything. The sender makes a new key
pair for every message, so no two keystreams are the same; the nonce is the
card's, so what was recorded at one tap cannot be played to the card at
another; and the instruction is in the sum, so an envelope made for one
command is none for another.

**What is sealed** is the clear form's data with the PIN as a block of nine
bytes: its length (4 to 8), the PIN, and zeros to eight. An envelope is the
same length for a PIN of four digits as for one of eight. For `VERIFY_PIN`
and `SET_PIN` the block is all of it. For `CHANGE_PIN` it follows the owner's
proof, which is over the PIN itself and the same nonce, exactly as in the
clear form: one asking for a nonce serves the proof and the seal, the seal
leaves the nonce for the proof, and the proof uses it up.

**What a failure costs.** With no nonce asked for in this tap, `6985`, and
nothing else. An envelope that does not open (a point that is no point, a tag
that is not this sum's) has used the nonce up, and on `VERIFY_PIN` it **costs
a try of the PIN**, as a wrong PIN does: without that a terminal could put
points to the PIN key without end. On `SET_PIN` and `CHANGE_PIN` it is
`6A80` and changes nothing. Those two have no try to cost, which leaves a
terminal free to put points to the PIN key through them: were the chip's key
agreement not to check that a point is on the curve, enough askings could
find the PIN key, and with it the PIN of any tap that was also recorded. The
key the card signs with is another key, and nothing but a PIN is sealed to
this one. A block that is not a block is `6700`.

**Its working room is not its own.** A sealed command needs ninety-nine bytes
of working memory, and uses the first ninety-nine of the scratch the applet
already had; its key agreement is the signer's own. As first built it had an
array and a key agreement of its own, the applet then asked for 1,030 bytes of
memory that is cleared when another applet is chosen where it had asked for
931, and the chip would not install it (`6F00`). No simulator has a limit
there. A test now adds up every transient array and every crypto object the
two classes make, and fails on any more than the build that is known to
install.

**What it is for, and what it is not.** It keeps a PIN from somebody
listening to a tap, now or with a recording later. It does nothing about the
terminal the PIN was typed on, which has it; and a false card can still ask
for a PIN, signing a PIN key of its own with a key of its own. The clear forms
remain, for a terminal that knows no other: a card cannot unsend a PIN that
was sent to it in the clear, and refusing one would only add a failure to the
exposure. A phone that knows the sealed form uses no other with a card that
has it.

## 6f. The PIN is optional, and the no-PIN allowance (software 1.16)

**A card may have no PIN.** It is set up with a record and an owner and no
`SET_PIN`, and it pays without one. Its daily limit and its limit on one
payment hold every payment, PIN or not; the owner's proof still administers
everything. Such a card is cash to whoever holds it, up to those two limits, and
the screens say so where a PIN is offered (SCREENS, B3 and B6). There is no
allowance on a card with no PIN, because there is nothing for it to stand in
front of, and no screen mentions one.

**A card that has a PIN has a third limit, the no-PIN allowance:** how many sats
a day it will sign for *without* the PIN. Only payments signed with no PIN count
against it. With the PIN given in this tap a payment is as it was, bounded by the
daily limit and counted by nothing here. When a PIN is added (below) the allowance
is 0, so that every payment asks for the PIN until the owner sets one.

**The record.** Eight bytes that were a window and a count of the limit on one
payment until 1.5, and zeros from then to 1.15, are the allowance (offset 201,
four bytes, big-endian, sats) and what has been signed for with no PIN in the
current window (offset 205, four bytes). `GET_INFO` with P1 = 1 answers them at
bytes 34 to 37 and 38 to 41, **to anyone**: a till needs them to know whether to
ask for the PIN, and nothing is learned from them that trying would not tell. The
limit on one payment (bytes 30 to 33) is still the owner's alone.

**The window.** The allowance shares the day's window with the daily limit, whose
clock is the newest block header the card has been shown (5). The window begins
at the first payment when *either* the daily limit or the allowance is set; a day
turning sets both counts to 0 in the transaction that signs the first payment of
the new day, whether that payment is made with the PIN or without it. A card
that has been shown no header (`now` = 0) has no window start and it does not end,
as with the daily limit (6): what is signed for with no PIN counts from set-up
until a header arrives and anchors the window, and the count is kept through that.
That fails toward asking for the PIN.

**The gate.** `SPEND_ALL_BEGIN` asks nothing of the PIN: a payment begun is of no
use to anyone until it is signed. `SPEND_ALL_SIGN` asks, at its first answer, when
the card knows what leaves it for good (`net`: the pieces less the change the card
makes for itself, the figure the limits already use):

| PIN state | Signs when |
|---|---|
| none set | always, up to the daily limit and the wait |
| set, and given in this tap | always, up to the daily limit and the wait |
| set, not given, not blocked | the window is current (or has no start) and what has been signed for with no PIN in it, plus `net`, is no more than the allowance. The sum is `net` and not the sats burned, and a sum past what four bytes hold is over |
| set, not given, and the allowance is 0 | never, even for a payment that takes nothing |
| blocked | never: a blocked card has no allowance until the owner has unblocked it |

Otherwise the card answers **`6A94`**, gives the payment up (a `SPEND_ALL_SIGN`
after it is `6985`, as after a refusal for the day) and leaves everything as it
was. **Over the allowance the PIN is asked for the WHOLE payment**: a payment is
never split into what the allowance covers and what it does not. With the PIN the
payment is as it always was. A refusal for want of the PIN writes **nothing** in
the card's log: it is neither a refusal over a limit nor part of a run of them,
and three of them in ten seconds mark no tamper. The PIN is asked before the
limits, so that a reader with no PIN cannot fill the log with refusals; a payment
within the allowance and over the day's limit is refused `6A8F` and written down
as any other. The word `6A94` is also `LOAD_PROOF`'s (a piece already on the
card); the two commands are never confused. The daily limit and the limit on one
payment apply to every payment as they did: a payment signed with no PIN within
the limit on one payment waits for nothing, and one over it waits as ever; a
second payment in the same time in the field is slowed as ever.

The owner's grants (`ALLOW_LOAD` and the tap after a payment) sign nothing, as
they never did: a payment is the PIN's, or the allowance's. A spend with no PIN
whose sum wraps is `6A94` at `SPEND_ALL_BEGIN`, which is the one refusal that
command makes for the PIN.

**The last signature again.** `SPEND_ALL_AGAIN` gives the last signature to a
reader with no PIN if it was given with no PIN, so that a till whose answer was
lost does not need a PIN it never needed; one that was given with the PIN is still
the PIN's, and on a card with no PIN it is open.

**The log.** Bit 3 of a tap's flags (`0x08`) says a payment in the tap was signed
with no PIN under the allowance, so that the owner's phone can say "no PIN" beside
it. A payment on a card with no PIN is not marked: there is no PIN to be without.
Entries are twenty bytes still, and receipts are as they were.

**Setting it.** `SET_LIMIT`, the owner's form (`34`), takes twelve bytes: the
day's limit, the limit on one payment and the allowance, then the proof as ever. A
number that does not change keeps its window and its count, as eight bytes
already promised: a new allowance counts from nothing in the window as it stands;
a new day's limit begins the window again at `now` and takes both counts to 0,
as the four-byte form always did. The four- and eight-byte forms leave the
allowance as it is. On a card with no PIN a twelve-byte form with a number in the
allowance is `6985`; with a zero in it, it is the eight-byte form.

**Adding a PIN.** `SET_PIN` (`41`) on a card that has an owner and no PIN, with the
owner's grant (`ALLOW_LOAD`) given in this tap, sets the PIN, sealed or in the
clear exactly as at set-up, whatever the card holds. A card with a PIN refuses it
(`6A91`), grant or none, and the owner uses `CHANGE_PIN`. The sealed form takes a
nonce from `GET_NONCE` with P1 = 1 asked for after the grant (the grant's own
proof used up the first). A new PIN has not been typed, so no session is verified,
and the allowance is 0. `CHANGE_PIN`, whose proof is over the PIN itself, also gives a PIN to a card
that has none.

**A card with no PIN and an owner is the owner's.** Loading it (`LOAD_PROOF`,
`CLEAR_SPENT`) wants the owner's grant or the tap after a payment, in which the
change goes back; the log and the receipts want the grant. `LOCK_CARD` wants a
PIN, and a card with none cannot be locked. A card with no PIN and no owner is
open while it is empty, as any card with no owner is, and `SET_CARD` is written
to it by anyone.

**What it bounds.** A terminal that can tap the card with no PIN gets the allowance
a day, and the day's limit stays the ceiling for everything. It buys a till one
tap that pays, and a PIN pad only when a payment is over what the card will sign
for unasked. It does not stop a thief with the card from taking the allowance each
day until the holder has the card blocked or set the allowance to nothing; the
holder chooses the figure. A card of 1.12 to 1.15 keeps asking for its PIN, and a
phone must go on working with them: the software number says which is which.

## 7. The owner

### 7.1 The key

The owner's phone works out a private key from its words, per card, **in its
native side only**:

    k = HMAC-SHA256( key = the 64-byte BIP-39 seed,
                     message = "FoxyCard/owner" ‖ 0x00 ‖ the card's 33-byte compressed public key )
        taken mod n, n being the order of P-256

and if the result is 0, made again with a counter byte (`0x01`, then `0x02`, and
so on) added to the end of the message. It gives the card the public half,
uncompressed, with `SET_OWNER`. Restoring the twelve words on another phone makes
the same key, so that phone is the owner of every card this one was. The card's
key is in the message, so two cards of one owner have two keys. The private key
is never sent anywhere; the card holds only the public one and reads it out to
nobody (`GET_INFO` byte 16 says only whether it has one).

**The page never holds the key or any secret derived from the seed.** The
phone's native side offers the page exactly two things for an owner: the owner
**public** key for a card, and a signature for one of a fixed list of labels
over `label ‖ nonce ‖ value`. It signs nothing else (section 9). This is the
draft's derivation, kept, used as a key and kept native, where the draft handed
the page a secret.

### 7.2 The proof

Challenge and response, as the draft had it, with a signature where the draft
had a hash:

1. `GET_NONCE` (no data, no PIN; `6A90` on a card with no owner) answers a fresh
   random 16 bytes, held in RAM. It is gone with the tap. Each nonce gets one
   try, right or wrong: a wrong proof uses it up. Asking again replaces it.
2. The proof is an ECDSA (P-256, SHA-256, DER) signature by the owner key over

       label ‖ nonce (16) ‖ value

   verified on the card with `ALG_ECDSA_SHA_256` on the owner key, with the
   label and value of the command:

| Command | Label (ASCII) | Value |
|---|---|---|
| `CHANGE_PIN` | `FoxyCard/change-pin` | the new PIN's bytes |
| `SET_LIMIT` (owner form, `34`) | `FoxyCard/set-limit` | the new limit, 4 bytes, big-endian; or 8, the day's and then the tap's (6a); or 12, those and the no-PIN allowance (6f) |
| `SET_OWNER` (on a card that has an owner) | `FoxyCard/set-owner` | the new owner key, 65 bytes |
| `SET_CARD` (on a card that has an owner) | `FoxyCard/set-card` | the data sent: unit, refund key, the 65 bytes where the time key was, mint length, mint. A phone of software 1.15 sends those 65 bytes as zeros and the card ignores them; a phone of an earlier software sends a key, and the card ignores that too. The proof is over the bytes as sent, either way |
| `ALLOW_LOAD` | `FoxyCard/load` | nothing |
| `LOCK_CARD` | `FoxyCard/lock` | nothing |
| `RESET_CARD` (1.17) | `FoxyCard/reset` | nothing |
| `SET_TAG` (1.19) | `FoxyCard/tag` | one byte: `00` tag on, `01` tag off |

So a proof for one command, or one value, is no proof for another, and an old
or used proof fails.

The data of an owner's command is `proof length (1) ‖ proof (DER) ‖ the value`
(for `ALLOW_LOAD` and `LOCK_CARD`, the proof alone), so the proof sits first and
the value after it is exactly what the proof was made over.

**Refusal.** `6A91` when no nonce was asked for in this tap, or the signature is
not the owner's. A wrong proof costs no PIN tries, changes nothing and does not
end the PIN session. `6A90` when the card has no owner.

**No PIN.** `CHANGE_PIN`, the owner's `SET_LIMIT`, `SET_OWNER`, `SET_CARD` and
`ALLOW_LOAD` need no verified session and no old PIN: the owner's phone does not
know the PIN, and the cards that most need an owner's `CHANGE_PIN` are the
blocked and the forgotten, where there is no old PIN to give. `LOCK_CARD` keeps
the draft's rule (a PIN set and verified, and the proof), and the phone still
never carries instruction `50`.

**Fallback, documented and not built.** If the card in hand turns out to have no
usable ECDSA verifier (the J3R180 is expected to; it is not yet measured), the
draft's proof (a 32-byte owner secret given once at set-up, and
`SHA-256(label ‖ secret ‖ nonce ‖ value)` compared in constant time) stands in,
labels, nonce and all. (Up to software 1.14 the time signature had no such
fallback and had to verify. There is none now, and the owner's proof is the one
thing the verifier is for.)

<a id="73-who-is-the-owner"></a>

### 7.3 Owner custody

Whoever's words derived the key on the card. For a holder with a phone, their
own. For a holder without one, the friend whose phone set the card up: a trustee
who, with the card in hand, can do anything, and without it, nothing. Set-up says
so in as many words (section 10).

An owner can be replaced only on a card with nothing unspent, and only with the
old owner's proof (`SET_OWNER` refuses a funded one with `6A8D`, and refuses with
no proof `6A91`), because the only thing that could authorise a new owner is the
old one. A card whose owner has lost their words **cannot be taken over**, empty
or not: that is what the owner's words are for, and what the screen at set-up
says.

There is no card with a PIN and no owner that holds money. A card with no owner
cannot be loaded (rule 7), so such a card is only an unfinished set-up, and the
phone finishes it.

## 8. Commands

Class `B0`. The instructions of this design, by byte; a row in **bold** is new
or changed from `FOXY-CARD-SPEC.md` 5.2 and the allowance draft.

| INS | Command | Needs | Data sent | Answers |
|---|---|---|---|---|
| `01` | **GET_INFO** | | | 30 bytes: the draft's 17 (version 2, slots, unspent, spent, empty, capabilities, PIN state, format, tries left, locked, record set, limit 4, has owner 1), then `now` (4), window start (4), spent today (4), then whether this tap may load with no PIN (1; 8.2) With **P1 = 1**, 42 bytes: those thirty, then the limit on one payment (30 to 33), the no-PIN allowance (34 to 37) and what has been signed for with no PIN in the window (38 to 41), 4 each (6a, 6f). With **P1 = 2** (1.19), 43 bytes: those 42 and byte 42, `00` when the NFC tag is on, `01` when it is off, said to anyone (SPEC 5.8); the answer to P1 = 1 is the same whatever the tag's state. The limit on one payment (bytes 30 to 33) is said only with the owner's grant given in this tap, and is zeros to anyone else (6a); the allowance and its count are said to anyone (6f). Up to 1.15 bytes 34 to 41 were zeros |
| `10` | GET_PUBKEY | | | the card's 33-byte compressed key |
| `11` `12` `13` `14` | GET_BALANCE, GET_PROOF_COUNT, GET_PROOF, GET_SLOT_STATUS | | | as before |
| `15` | AUTH | | 16 random bytes | 16 of the card's own and a signature |
| `16` | **GET_CARD** | | | format, record set, unit, limit (4), refund key (33), then 65 bytes at offset 40: the hardest header's `bits` (4), the newest header's hash (32) and 29 zeros (a time key up to software 1.14), mint length, mint |
| `17` | **GET_PIECES** | | P1 = the first slot to report | one page: the first slot the page does not cover (1), then for each slot in the range that is not empty a tag (1) and, for an unspent slot, its 81 bytes (8.1). `6A83` for a P1 of 128 or more. With **P2 = 2** and one to three slot numbers as data: each of those slots whole (status and its 81 bytes), in the order asked; `6700` for none or more than three (8.1). With **P2 = 3**, the short listing: for each unspent slot its number (with `0x80` where its keyset and date follow), then the power of two it is worth or `FF` and its amount (6d). Any other P2 is `6A86` (P2 = 1 was the brief listing of a card of sixty-four places, 1.6) |
| `18` | **GET_LOG** | the PIN verified in this tap, or the owner's grant; on a card with no PIN (1.16) anyone who holds it. **P1 = 1 (receipts): the owner's grant only; with no PIN, anyone** | P2 with P1 = 1: how many receipts back from the newest to begin | the card's own log (6b): 16 bytes of counts, then up to eight taps of 20 bytes, newest first (16 bytes before software 1.15); bit 3 of an entry's flags (1.16) says a payment in the tap was signed with no PIN under the allowance. With P1 = 1: the count of payments (4), then up to three receipts of 77 bytes, newest first (73 before 1.15). `6982` to anyone else; `6A86` for another P1 |
| `1A` | GET_DLEQ (1.20) | nothing: no PIN, any state | P1 = a place (0 to 127); P2 = a second place, or `FF` for none | for each place asked, in order: `01` and the 96 bytes `e ‖ s ‖ r` of the mint's proof kept with the piece if the place is unspent and its record is not zero, otherwise the single byte `00`. At most 194 bytes. `6A83` for a place there is not. The card does not check what it gives (SPEC 5.9) |
| `20` | ~~SPEND_PROOF~~ | | | gone with format 4 (6c): `6D00`. Up to format 3: P1 = the slot, the 64-byte signature over that piece's secret alone |
| `22` | **SPEND_ALL_BEGIN** | nothing (since 1.16 the PIN is asked at `24`; up to 1.15 it was asked here) | the places, a byte each, 1 to 128 | what they are worth (4). `6700` none; `6A96` more than 128; `6A83`, `6A88`, `6985` for a place out of range, empty, spent; `6A80` named twice, or of another date than the first; `6A8F` as the day's limit has it, on the sum (6c); `6A94` for a sum that wraps, with a PIN set and not given (6f) |
| `23` | **SPEND_ALL_OUTPUTS** | a payment begun, and nothing sent since but these | 37 bytes for each output: amount (4), blinded message (33) | `6985` with no payment begun; `6700` for a length not a multiple of 37, and the payment is dropped |
| `24` | **SPEND_ALL_SIGN** | a payment begun; no PIN set, or the PIN given in this tap, or the no-PIN allowance enough for the whole payment (6f); the day's limit again | | while the payment is over the limit on one payment: two bytes, the waits still to come, and nothing burned (6a); sent again. Then the one 64-byte signature over every piece and every output; every place burned, the counts charged and the log written in the same transaction. `6985` with no payment begun; `6A94` (1.16) with a PIN set and not given and the allowance not enough, the payment given up and nothing written in the log (6f); `6A96` if the transaction cannot hold it. **Not** opened by `ALLOW_LOAD`, nor by the tap after a payment. Notes, in permanent memory, that the card has paid: the next tap may load with no PIN (8.2) |
| `25` | **SPEND_ALL_AGAIN** | the PIN, if one is set, unless the last signature was given with no PIN (1.16) | | the last signature `24` gave, again; `6A88` if none |
| `30` | **LOAD_PROOF** | an owner; a PIN set, and verified or `ALLOW_LOAD` given in this tap or this tap being the one after a payment (8.2); on a card with no PIN (1.16), whoever holds it; a card record. No clock | 81 bytes; or two or three pieces end to end, 162 or 243; or, with **P1 = 1** (1.20), one piece and the mint's proof for it, 177 bytes (SPEC 5.9) | `6982` with no verified PIN and no grant (the gate comes first); then `6A90` with no owner; `6A94` for a piece whose nonce is already in a slot, spent or not (checked last, after the length and the piece itself, and before anything is written) The answer is the slot of each piece stored, a byte each. Several pieces are taken in order, each as one alone would be: if the first cannot be stored the command is refused with its word; if a later one cannot, the ones before it stand and the answer is their slots only, and the terminal sends the rest again to hear why. With P1 = 1 the answer is two bytes, the slot and `01` where the proof was kept (`00` where the card has no room for proofs); any length but 177 is `6700`, a proof of 96 zero bytes is `6A80`, and the rest is a load of one piece |
| `31` | **CLEAR_SPENT** | the PIN, if one is set, or `ALLOW_LOAD` given in this tap, or the tap after a payment; a card with no PIN (1.16) frees them for whoever holds it | | |
| `32` | **SET_CARD** | no owner: the PIN verified, if one is set (1.16: a card with none is written by anyone while it has no owner), nothing unspent. Owner: the owner's proof, nothing unspent | unit (1), refund key (33), 65 bytes the card does not read (zeros from a phone of software 1.15; a time key from an earlier one), mint length (1), mint; with an owner, proof length (1) and the proof first | `6A8D` if anything is unspent; `6A80` for a bad refund key; `6700` for a bad length. The 65 bytes are not checked, and `SET_CARD` no longer clears the clock, the window or what is spent |
| `33` | **SET_LIMIT, PIN form** | **a card with no owner**: PIN set and verified; nothing unspent. No clock | limit (4) | `6A91` on a card with an owner (use `34`); `6A8D` if anything is unspent. Eight bytes set the limit on one payment as well (6a). |
| `34` | **SET_LIMIT, owner's form** | the owner's proof. **No PIN**, any funds. No clock | proof length (1), proof (DER), limit (4) | `6A90`, `6A91`; `6986` on a locked card. Eight bytes of limit (the day's, then the one payment's) set both (6a); **twelve** (1.16) add the no-PIN allowance (6f), and on a card with no PIN a number in it is `6985`. Any other length is `6700` |
| `35` | ~~SET_TIME~~ | | | gone in 1.15: `6D00`, and the instruction stays unassigned. Up to 1.14: a time (4), a signature length (1) and a signature (DER) by the time key, answered with the card's `now` |
| `36` | **SET_HEADER** | nothing: no PIN, no owner, no record, any state | a Bitcoin block header, 80 bytes, as the network carries it (5.1) | the card's `now` (4, big-endian), whether the header was taken or was no later than the clock. `6A93` for too little work (its own, the floor's, or a quarter of the hardest taken); `6A80` for a `bits` no header could carry; `6700` for any length but 80. Drops a payment begun |
| `37` | **TELL_TIME** | nothing: no PIN, no owner, no record, any state | the terminal's own clock, 4 bytes, big-endian seconds | nothing. `6700` for any length but 4. Kept for this time in the field and written into the receipts and the log entries made in it (5.3). Drops a payment begun |
| `40` | VERIFY_PIN | | the PIN, 4 to 8 bytes; or, with **P1 = 1**, the PIN sealed (6e) | changes nothing about spending. Sealed: `6985` with no nonce asked for; an envelope that does not open costs a try, as a wrong PIN does. Any other P1 is `6A86` |
| `41` | **SET_PIN** | **a card with no owner**, nothing unspent. No PIN, no proof. Or (**ADD PIN**, 1.16) **a card with an owner and no PIN**, the owner's grant (`ALLOW_LOAD`) given in this tap, any funds | the PIN; or, with **P1 = 1**, the PIN sealed (6e) | sets or replaces the PIN and unblocks; `6A91` on a card with an owner that has a PIN, or has none and no grant (use `42`); `6A8D` if anything is unspent on a card with no owner; `6986` locked. The allowance is nothing. Sealed: `6985` with no nonce, `6A80` for an envelope that does not open |
| `42` | **CHANGE_PIN** | the owner's proof. **No PIN, no session, any PIN state, any funds** | proof length (1), proof (DER), the new PIN; or, with **P1 = 1**, the same sealed, the PIN as its nine-byte block (6e) | sets the PIN and resets the tries; ends any verified session; `6A90`, `6A91`; `6986` locked. Sealed: the proof is over the PIN itself and the same nonce the seal is under; `6985` with no nonce, `6A80` for an envelope that does not open |
| `43` | **SET_OWNER** | no owner: nothing unspent. Owner: the owner's proof, nothing unspent | 65 bytes, the owner's public key, uncompressed; with an owner, proof length (1) and the proof first | sets or replaces the owner; `6A8D` if anything is unspent; `6A91` with an owner and no good proof; `6A80` for a key not beginning `04`; `6700` other length; `6986` locked |
| `44` | GET_NONCE | a card with an owner. No PIN | | 16 bytes, or `6A90`. With **P1 = 1**, on any card: the 16 bytes, the PIN key (33, compressed) and the card key's signature over it (64), for sealing a PIN (6e) |
| `45` | **ALLOW_LOAD** | the owner's proof, over `FoxyCard/load` and no value | proof length (1), proof | for the rest of this tap: `LOAD_PROOF` and `CLEAR_SPENT` need no verified PIN. `6A90`, `6A91`; `6986` locked |
| `50` | LOCK_CARD | PIN set and verified; the owner's proof | P2 = `DE`; proof length (1), proof | as the draft |
| `51` | RESET_CARD (1.17) | the owner's proof; a locked card also the PIN; nothing unspent | P1 = `00`, P2 = `AD`; proof length (1), proof over `FoxyCard/reset` | the card as out of its packet, with a new key (SPEC 5.6a); `6B00`, `6A90`, `6A91`, `6700`, `6982` locked and PIN not given, `6A8D` |
| `52` | SET_TAG (1.19) | the owner's proof; no PIN, any funds | P1 = `00` tag on, `01` off; P2 = `00`; proof length (1), proof over `FoxyCard/tag` and one byte, then that byte (the same as P1) | the NFC tag switched (SPEC 5.8); `6B00`, `6986` locked, `6A90`, `6A91`, `6700` |

`21` (`SIGN_ARBITRARY`) stays unassigned. The applet's version became 1.1 and
`FORMAT` 3 with this design; a phone that knows only format 2 refuses the card,
as it does for anything but its own. With one signature for a payment (6c) the
version is 1.4 and `FORMAT` 4: a phone that knows only format 3 refuses such a
card, and a phone that knows both pays with either. With the limit on one
payment a wait and not a window (6a) the version is 1.5, the format is still
4, and bit 3 of the capabilities byte says so. 1.6 is the same card made
quicker to hold (6d), and bit 4 says so. 1.7 is the same card with 128 places
(6d, 8.1), and bit 5 says so. 1.8 burns a payment's pieces outside its
transaction (6d), so that a payment may be of any number, and bit 6 says so.
1.9 takes its PIN sealed (6e), and bit 7 says so. 1.15 takes its clock from
Bitcoin block headers (5): `SET_TIME` and the time key are gone, `SET_HEADER` and
`TELL_TIME` are new, and a log entry and a receipt are four bytes longer for the
time a terminal tells. No capability bit says so, since all eight are taken; the
version does, and `SELECT` answers `01 0F`. 1.16 makes the PIN optional and
gives a card that has one the no-PIN allowance (6f): `SELECT` answers `01 10`,
no capability bit changes, and the wire is otherwise 1.15's. 1.17 adds
`RESET_CARD` (SPEC 5.6a), and `SELECT` answers `01 11`. 1.18 makes the wait for
each further limit's worth over the limit four signatures where it was three
(6a): `SELECT` answers `01 12`, no capability bit changes, and the wire is
otherwise 1.17's. 1.19 makes the card an NFC tag as well, which its owner can
switch off (SPEC 5.8): `SET_TAG` is new, `GET_INFO` has a form of its own, P1 = 2, one byte longer than P1 = 1's,
`SELECT` answers `01 13`, no capability bit changes, and the wire is otherwise 1.18's.
1.20 keeps the mint's proof with each piece (SPEC 5.9): `GET_DLEQ` (`1A`) is new,
`LOAD_PROOF` has a form of its own, P1 = 1, `SELECT` answers `01 14`, no capability bit
changes, `GET_INFO` is 1.19's to the byte but for the version, and the wire is otherwise
1.19's.

**Every command in every state: the rule of section 3 worked through.** "Open"
means nothing is needed beyond what the command's own row says; "refused" means
`6A91` unless another word is given.

| Command | Card with **no owner** | Card **with an owner** |
|---|---|---|
| `GET_INFO`, `GET_PUBKEY`, `GET_BALANCE`, `GET_PROOF_COUNT`, `GET_PROOF`, `GET_SLOT_STATUS`, `GET_PIECES`, `GET_DLEQ` (1.20), `AUTH`, `GET_CARD` | open | open |
| `SET_HEADER`, `TELL_TIME` | open: any state, locked or blocked (a header must show its work, 5.1) | same |
| `GET_NONCE` | `6A90` | open (it only gives a number) |
| `VERIFY_PIN` | as ever | as ever |
| `SPEND_ALL_BEGIN` | open (since 1.16) | open (since 1.16) |
| `SPEND_ALL_SIGN`, `SPEND_ALL_AGAIN` | the PIN, if one is set (such a card holds nothing) | no PIN set: open, up to the limits; the PIN, or the no-PIN allowance, up to the limits (6f) |
| `SPEND_ALL_OUTPUTS` | open to a payment begun; `6985` otherwise | same |
| `LOAD_PROOF` | **refused `6A90`** | PIN verified, or the `ALLOW_LOAD` grant in this tap, or this tap being the one after a payment (8.2); with no PIN set (1.16), whoever holds the card |
| `CLEAR_SPENT` | the PIN, if one is set | the PIN, or either grant; with no PIN set (1.16), anyone |
| `SET_PIN` (`41`) | **open while nothing is unspent** (sets or replaces, unblocks) | **refused**, empty or not (`6A91`), unless the card has no PIN and the owner's grant is in this tap (ADD PIN, 1.16): the owner otherwise uses `CHANGE_PIN` |
| `CHANGE_PIN` (`42`) | `6A90` | the owner's proof, empty or not, any PIN state |
| `SET_CARD` (`32`) | the PIN verified if one is set (none: open), **while nothing is unspent** | **the owner's proof, and nothing unspent** (`6A8D`) |
| `SET_LIMIT` (`33`, PIN form) | PIN set and verified, **while nothing is unspent** | **refused** |
| `SET_LIMIT` (`34`) | `6A90` | the owner's proof, empty or not |
| `SET_OWNER` (`43`) | **open while nothing is unspent** | **the owner's proof, and nothing unspent** |
| `ALLOW_LOAD` (`45`) | `6A90` | the owner's proof |
| `LOCK_CARD` (`50`) | `6A90` (after the PIN gate) | PIN set and verified, and the owner's proof |
| `RESET_CARD` (`51`, 1.17) | `6A90` | the owner's proof, nothing unspent (`6A8D`); on a locked card the PIN as well (`6982`) |
| `SET_TAG` (`52`, 1.19) | `6A90` | the owner's proof, empty or not, no PIN; `6986` on a locked card |

So the one thing an attacker with the PIN and an emptied card can still do is
load pieces onto it (which the mint will refuse) and spend them. It cannot set
its own PIN, owner, record or limit.

Status words, in the part of `6Axx` ISO 7816-4 leaves unassigned:

| SW | Means |
|---|---|
| `6A8D` | card in use: a thing that is set only on an empty card, on a card with an unspent piece |
| `6A8F` | over the day: this piece would take today past its limit. Nothing signed, nothing burned |
| `6A95` | unused. It was "over the limit on one tap", when that was a window and refused; a payment over the limit on one payment now waits (6a) |
| `6A90` | no owner: a command that needs the owner's proof, or `GET_NONCE`, or a load, on a card that has none |
| `6A91` | the owner's proof is missing or is not the owner's, or this command is not open to a card with an owner. Costs no PIN tries, changes nothing, does not end the PIN session |
| `6A92` | unused. It was "no time", for a card never told the time; since 1.15 a card spends its first day on trust (6) and nothing answers it |
| `6A93` | little work: a `SET_HEADER` whose work is not enough, whether not its own difficulty's, under the floor, or under a quarter of the hardest header taken (5.1). Nothing changes. (Up to 1.14: "not the time", a `SET_TIME` whose signature was not the time key's) |
| `6A94` | on the card already: a `LOAD_PROOF` of a piece whose 32-byte nonce is the nonce of any non-empty slot, spent or unspent. Nothing is written, and the amount stated is not looked at. A slot that `CLEAR_SPENT` has freed is empty, so that piece may be loaded again then. **Also, since 1.16, the PIN is needed** (`SPEND_ALL_SIGN`, and `SPEND_ALL_BEGIN` for a sum that wraps): a PIN is set and was not given in this tap, and the no-PIN allowance does not cover the whole payment. A different command answers the same word, and the two are never confused. Nothing is signed, burned or counted, the payment is given up, and nothing is written in the log (6f) |

`SET_HEADER` also answers `6A80` (ISO's own word for wrong data) for a `bits` no
header could carry: a size of 0 or of more than 32, or a mantissa with its top
bit set.

What `CardGate` carries: the instructions the page uses, `01 10 11 13 14 15 16
17 20 30 31 32 34 36 37 40 41 42 43 44 45`. `33` (the PIN form of the limit, for
an open card) is not used by the phone and is not carried; `50` stays out.

### 8.1 GET_PIECES: the whole card in a few answers

A tap used to read a card with one command for each of its states and one
for each piece on it, at a tenth of a second or so a command. `GET_PIECES`
(`17`) says what both of those say, in pages.

**The answer.** P1 is the first slot to report (0 to 127; `6A83` above that);
P2 is 0 and the data is not used (P2 = 2 and P2 = 3 are its other forms, 6d).
No PIN: it says what `GET_SLOT_STATUS` and `GET_PROOF` say, which need none.
The answer is

    next (1)     the first slot this page does not cover; 128 means the card has
                 no more to say, and anything else is the P1 to ask for next
    then, for each slot from P1 up to next that is not empty, in order:
      tag (1)    the slot, and 0x80 where it is spent (a card of sixty-four
                 places, before 1.7: (state << 6) | slot, state 1 for unspent
                 and 2 for spent, and next ends at 64)
      piece (81) only for an unspent slot: keyset (8), amount (4), nonce (32),
                 C (33), date (4), which is what `GET_PROOF` gives after its
                 status byte

A slot in the range with no entry is empty. A spent slot is listed by its tag
alone: its bytes stay on the card until `CLEAR_SPENT` frees the place, and
nothing that reads a card wants them. A page is at most 255 bytes, so three
unspent pieces (1 + 3 x 82 = 247) make a page, and spent slots, which cost a
byte, fill what is left of it. At least one entry always fits, so every answer
moves on. A card of 128 unspent pieces is forty-three pages; a card with
six is two. (A till that only wants to choose pieces reads the short listing,
6d, which is one answer for a hundred pieces.)

**Why pages, and not extended length.** 128 slots of 82 bytes are 10,496 bytes,
which a short APDU (256) does not hold. An extended-length answer would hold it,
and was not chosen: the card's support for extended APDUs was not measured, the
simulator's is not the card's, and every extra thing the reader and the phone
must carry is one more thing that can fail in the one tap that matters. A page
needs nothing but a short APDU, which every command here already is. What it
costs is a command for each three pieces, where extended length would be one:
for the cards this is for, with a dozen pieces at most, that is four commands
and not twelve, and more is saved by the commands not sent than by the one
that carries more. The pages are sent from where the slots sit
(`sendBytesLong` from the slot store), so the APDU buffer's size is not relied
on.

**On the phone.** `cardLook` asks for pages from slot 0 until `next` is 64, and
not at all when `GET_INFO` counts no unspent and no spent slot. A card that
answers the first page with anything but a page (an older applet answers
`6D00`) is read the old way: `GET_SLOT_STATUS`, then `GET_PROOF` for each slot
that is not empty. The old commands stay on the card and in the gate for that.
A read of a card holding six pieces is about eight commands (select, the clock,
info, key, proof of the key, record, two pages) where it was twelve.

### 8.2 The tap after a payment: change with no PIN

A till lets the card go as soon as it has signed, and asks the mint with the
card gone (9). Change, when there is any, is made after that and written at a
second tap. That tap used to need the PIN again, for one payment, which is
cumbersome at a counter.

**The rule.** The card keeps one bit in permanent memory, *change due*, set
by every `SPEND_PROOF` in the same transaction that burns the slot. At the next
`SELECT`, whichever reader's it is, the bit is taken into the tap (a transient
*change grant*) and cleared; a card pulled between the two still has the bit,
and the tap after gets the grant instead. For that one tap, `LOAD_PROOF` and
`CLEAR_SPENT` need no verified PIN, exactly as under `ALLOW_LOAD`. Spending,
PIN, record, limit and lock commands retain their existing gates. A locked card
still takes no load; a blocked PIN still waives nothing (`requireLoadAuthority`
asks for a PIN that is set, and a blocked one is not). A payment in the change
tap, which needs the PIN as any payment does, sets the bit again for the tap
after it.

`GET_INFO`'s last byte says whether this tap has the grant, so the phone can
tell before it writes.

**What it opens, and to whom.** One load, by the next reader to tap the card.
The reader that is meant is the till that took the payment a moment before, and
had the PIN typed on it for that. A different reader that taps first (the
holder's own phone, say, looking at the balance) uses the grant up by
selecting the applet, and the till asks for the PIN at its change tap after
all: nothing is lost, the change stays owed to the card on the till. A reader
that is a stranger's gets, at most, to put pieces on the card without the PIN,
once: the junk-piece nuisance of 13, which the PIN-holding terminal already
has. It takes nothing, and the day's limit is not touched by any load.

**On the phone.** A till that owes a card change, a refund of what it signed
and left with, or a payment put back after the mint refused it, taps first
with no PIN (`cardWrite` with `change`) and reads `GET_INFO`; a card whose
last byte is 0 is refused with 'pin-needed' before anything is sent, and the
PIN pad comes up for the next tap. The screen says `No PIN is needed.` on the
TAP THE CARD AGAIN card. Pieces owed for a top-up cut short are written as
before, with the PIN or the owner's proof.

<a id="9-what-the-phone-does"></a>

## 9. Phone responsibilities

**The clock.** The card cannot look at the network, so the phone does. It
fetches the newest block header over Tor from two independent sources
(mempool.space and Blockstream, each by its onion service) and checks it before
it shows it to anyone: the work itself, that both sources name the same block,
and that the block's time is within a few hours of the phone's own clock. Then,
in the tap, where the card's `now` (read in `GET_INFO`) is behind that block's
time, it shows the card the header with `SET_HEADER` and reads the card's `now`
back from the answer. A till does the same before it begins a payment (a payment
begun is dropped by any command that is not its next step, 6c). A phone with no
route has no newer header to show, and the card's day does not move. It also
tells the card its own clock with `TELL_TIME`, for the receipts and the log
(5.3).

The phone's checks are its own good manners. The card checks the work again and
depends on none of them: whatever is shown to it, it takes only a header that
has the work (5.1). Up to software 1.14 the page asked its native side for the
phone's clock signed with an interim key (`cardTime`) and sent it with
`SET_TIME`; there is nothing to sign now.

**A receiver (`cardTake`).** In the tap, after the clock and the reads, work out
what is left of today from `GET_INFO` (limit, `now`, window start, spent today;
a window whose day is over has the whole limit left) and refuse **before the PIN
is sent** a payment whose pieces would pass it (`worth > left today`).
OVER THE CARD'S DAILY LIMIT says what is left today and when the day turns.

**A loader.** Asks nothing of the clock: `LOAD_PROOF` is not held to it (rule 7),
and a card loaded before it has been shown a block spends its first day on trust
(6). A till writing change under the PIN is the same.

**The owner's phone.** The page never holds the owner key. Native offers the page:

- `cardOwnerKey {key}`: the owner **public** key for the card with that
  compressed public key: 130 hex characters, uncompressed. Used for `SET_OWNER`.
- `cardOwnerSign {key, label, nonce, value}`: an ECDSA signature (DER, hex) by the
  owner key for that card, over `"FoxyCard/" + label ‖ nonce ‖ value`, where `label`
  is one of `change-pin`, `set-limit`, `set-owner`, `set-card`, `load`, the nonce is
  the 16 bytes the card gave and the value has the shape that label takes. Native
  refuses every other label (in particular `lock`) and every other shape, before
  it reads the seed. It answers the signature and nothing else.

The owner's private key and the seed never leave native. The draft's action that
handed the page a secret is gone.

Set-up on a card with no owner, one tap, in this order: `SET_PIN`, `VERIFY_PIN`,
`SET_CARD` (the record; the 65 bytes where the time key was go as zeros),
`SET_OWNER` last. The owner goes in last so that no step needs a proof, and the
card is open, and can be done again, at every point before it: a set-up cut off
anywhere is finished by the next. It asks for no limit: the card starts with
none. The PIN is typed on the owner's phone once, here, and never again for
adding funds.

After set-up, on the owner's phone:

- **Add funds:** `GET_NONCE`, sign `load`, `ALLOW_LOAD`, then `CLEAR_SPENT` and
  `LOAD_PROOF`. No PIN is asked, and no clock.
- **CHANGE PIN:** `GET_NONCE`, sign `change-pin` over the new PIN, `42`. No old
  PIN is asked: the owner's phone does not know it. A blocked card on its
  owner's phone offers UNBLOCK, which is CHANGE PIN.
- **CHANGE LIMIT** (any amount, or none): `GET_NONCE`, sign `set-limit`, `34`.
  No PIN is asked, and no clock.
- **Taking money off** (withdraw, take back, renew, switching mint), in one tap:
  the limit is **lifted** with the owner's proof (`34`, limit 0), the PIN is
  typed and `SPEND` runs, and the old limit is **put back** with the owner's
  proof, **restored even when the spending fails part way**. Where the card
  leaves before it can be, the phone has written the old limit down first, and
  puts it back at the next tap. `SPEND` itself still needs the PIN.
- **Moving the card to another mint** (empty card): `SET_CARD` with the owner's
  proof. The card's clock stays as it is, since `SET_CARD` does not touch it.
- Whether this phone is a card's owner is found out by trying: after reading, the
  phone asks for a nonce and an `ALLOW_LOAD` it has signed. `9000` means the
  phone holds the words the card was set up with; `6A91` means it does not. It
  costs no PIN tries and changes nothing.

A card whose owner is somebody else's, empty or not, is not set up afresh: the
phone says it belongs to another phone's words.

**Screens.** Section 10, in words.

**What the phone leaves out, and what it does with change.**

- A till does not ask the card for `AUTH` (the slowest answer the card gives:
  its own Schnorr signature, most of a second). It is about to be paid in
  pieces the card signs, and a signature that is not good for the key in a
  piece's secret is refused before anything is kept; the mint's swap is what
  says paid. A pretend card gets nothing from that: one with a key of its own
  has pieces the mint did not issue for that key, and one that names the real
  card's key cannot sign for it. `AUTH` stays wherever the holder's phone reads a
  card to show it, and in a withdrawal, where the owner's key signs.
- A tap should take under three seconds, and the card signs a piece in most of
  a second, so an online payment signs as few pieces as it can: the one or two
  that cover the price (and the receiver's fee on them) with the least over,
  and where no two do, the fewest that do. What they come to over the price is
  change, made after the swap and written back at a second tap, with no PIN
  (`changeDue`). Every card payment is said as two taps, SEND and RECEIVE; one
  paid exactly is complete at the first. A till with no route takes only an
  exact set (below), found by search, fewest pieces first.
- What goes onto a card is cut like the float in a cash drawer: every power of
  two from 1 up to the largest that fits, once, then the rest of the amount in
  powers of two (every price up to the whole is exact then), and then, with the
  pieces left under the cap, the smallest rungs two or three deep, so that a
  run of offline payments finds the rungs the first took still there; never the
  small change the rest of the wallet keeps, no more than thirty-two pieces (half
  the card), and no more than the card has places for less a dozen kept for an
  online payment's change (an amount that needs
  more is rounded up, smallest pieces first, and the screen says by how much; a
  mint whose largest piece is small makes more of that piece). Change written
  back is cut the same way, filling the card's gaps. The card signs a piece in
  most of a second, so the pieces are what a withdrawal is made of: one cut
  short keeps what the card signed, in the phone, and the next tap takes the
  rest.
- A card of 128 places (1.7) is cut deep instead: eight of each size from 1 to
  1,024, smallest first as far as the money goes, and the rest of the amount
  in powers of two. Eight prices in a row are then paid exactly, whatever they
  are, up to 2,047 sats each: one tap, one signature and no change. What the
  card holds counts towards each size, so a top-up and the change of a payment
  fill what has been spent from (change in thirty-two pieces at the most, so
  that the tap that writes it stays short). Where no set of pieces makes a
  price exactly, the drawer is short of something small, and the set that
  overpays least would bring back a sat or two; so a till takes the cheapest
  set that brings back 256 sats or more, whose change fills the small sizes
  again. That set may be over a limit on one payment that the till is not
  told: the card then answers its first `SIGN` with "not yet", having signed
  nothing, and the till pays with the cheapest set after all. Nobody is made
  to wait for change. A payment is thirty-two pieces or fewer wherever such a
  set pays (with a larger piece and change, if need be), and more only where
  nothing that few does.
- A till with no route may take a card on trust, as plain ecash is taken: the
  HIGH RISK question is put to the person first, in front of the amount, and the
  owner's answer decides. Only an exact set of pieces is taken (a till with no route
  cannot give change), refused before the PIN is sent when the card has none; the
  day's limit is looked at as ever, by the card's own clock, which a phone with no
  route has no new block to move on. Every signature the card gives is checked on the phone
  before anything is kept. The pieces are kept as a trusted row, with a pending
  entry, and swapped in when there is a route; if the mint says they were spent
  meanwhile, the entry is marked taken back and the person is told. "Paid" is
  never said. A piece on a card of software before 1.20 carries no DLEQ proof, so
  offline the phone cannot check the mint's signature on it: that is the risk the
  question names. From 1.20 a card can keep the proof (`FOXY-CARD-SPEC.md` 5.9), and a
  phone that reads it and checks it can. A switch of its own turns this off; plain ecash between
  two offline phones has its own, as before.

**Tests on the phone.** The model in `tests/flashcard-card.js` grows the clock,
the window, the owner key and the proofs, with Node's own P-256; the page's tests
run against a fake native side that holds the same derivation;
`tests/flashcard-model.js` holds the model to the applet's transcript as before;
the money suites gain a day that turns and a terminal that re-sends the PIN and
gets one day; a test checks that the page never receives an owner secret.

<a id="10-set-up-and-what-is-said"></a>

## 10. Setup and holder notices

- A card is set up on a card with no owner, by the phone that will be its owner.
  The set-up asks for a PIN twice, or for none (1.16: a card with no PIN pays
  without one; 6f). **It does not ask for a limit and does not suggest one.** A
  new card has no limit.
- For a holder with no phone, the owner is the friend's phone. Set-up says, once,
  on the screen that makes this phone the owner: *This phone can reset this
  card's PIN and limit. Whoever holds the card and this phone's seed phrase holds
  its money.*
- `SET_PIN` once; the holder never types the PIN anywhere but a till and, once, at
  set-up. A changed PIN comes from the owner's phone. A card set up with none is
  given one later by the owner's phone (ADD PIN, `SET_PIN` under the owner's
  grant, 6f), and until then pays without one.
- No refund key for now: a lost card is cash gone. A blocked card is not, because
  the owner unblocks it.
- Any card with no owner can be claimed by any reader in range, and that is fine:
  it holds nothing and cannot be loaded. A card leaves the issuer's hands set up,
  as the draft's 5.4 says, so that nobody has to think about it.

**The words on the screens.** The screens say what the limit is, the most the
card will spend in one day, and promise nothing beyond it: a terminal that has
the PIN still takes a day's limit per visit, and a card with no limit has no day
to bound (13).

1. *Menu row on the card's screen:* CHANGE LIMIT.
2. *Step 1, the warning* (the app's warning card). Title: SET DAILY LIMIT. Body:
   "A daily limit is the most this card will spend in one day. It starts again by
   itself each day." / "Only this phone, or a phone restored from its seed
   phrase, can change or remove the limit." / "If you lose the seed phrase for
   this Foxy app, the PIN and the limit on this card can never be changed." /
   "Do you wish to continue?" Buttons: CONTINUE, CANCEL.
3. *Step 2, the amount screen* (the app's SET AMOUNT, dollars first), asking:
   "What would you like the daily limit to be?" It also offers NO LIMIT as the
   way to remove one.
4. *Step 3, the confirmation.* "You are applying a daily limit of: $20.00" (the
   amount chosen) / "This card will spend no more than this in one day. The limit
   starts again by itself each day." / "Only this phone, or a phone restored from
   its seed phrase, can change or remove it." Buttons: CONFIRM, CANCEL. For
   NO LIMIT the confirmation says: "You are removing this card's daily limit. It
   will be able to spend everything on it."
5. *Card set-up, once, on the screen that makes this phone the owner:* "This phone
   can reset this card's PIN and limit. Whoever holds the card and this phone's
   seed phrase holds its money."
6. *The card's screen* shows the daily limit (or NO LIMIT), what is left today, and
   when the day turns.
7. *A till refusing:* title OVER THE CARD'S DAILY LIMIT, saying how much the card
   can still spend today and when its day turns.
8. *A blocked card on its owner's phone* offers UNBLOCK, which is CHANGE PIN.

The allowance draft's screens and wording that no longer apply ("you will need to
connect to your foxy app to restart the limit", SET LIMIT, RAISE THE LIMIT) are
gone.

## 11. From the allowance draft: kept, changed, dropped

This is the account of the first design, as it was made for version 1.1. The
clock's part of it was replaced in 1.15; the last paragraph says how.

**Kept as drafted:** the instruction bytes `34`, `42`, `43`, `44`, `50` and their
categories; `GET_NONCE` and the nonce's life (RAM, one try, gone with the tap,
replaced by asking again); the `label ‖ nonce ‖ value` binding and the
per-command labels; `6A8F`, `6A90`, `6A91` and the rule that a wrong proof costs
no PIN tries and ends no session; the owner derivation from the seed and the
card's key; `GET_INFO`'s 17 bytes with byte 16 "has owner"; `LOCK_CARD` needing a
verified PIN and the proof, and the phone never carrying it; "the count is of
pieces signed, not the price paid"; the transaction that joins the count and the
status byte, with the signing after, and the test that reads the source to check
it; "`VERIFY_PIN` changes nothing about spending"; `SET_CARD` never touching the
limit.

**Changed:** the allowance becomes a **daily limit** with a window (section 6);
`0` defaults to **no limit**, allowing unrestricted value under this setting;
the owner secret becomes an owner **key** (65 bytes, uncompressed, P-256; the
proof is a DER ECDSA signature verified by the card; nothing of the owner
crosses the air, and the key never leaves native code); `CHANGE_PIN` takes the
proof and the new PIN only (**no old PIN, no session**) and resets the tries;
`SET_OWNER` works on a card with no owner while it is empty, and on a card with
an owner only with that owner's proof, and only while it is empty, replacing the
owner; `SET_PIN` works on a card with no owner while it is empty, replacing a
PIN, and not at all on a card with an owner; `SET_CARD` needs the owner's proof
on a card with an owner; `33` returns as `SET_LIMIT` by PIN, **for a card with
no owner, while it is empty**; `SET_CARD` carries the time key; the mint is at
most 80 characters; `GET_INFO` grows by twelve bytes and `GET_CARD` by
sixty-five; version 1.1, format 3.

**Dropped:** the allowance that only goes down and only the owner raises; the
rule that a card with no owner can never be given an allowance, and the card
with a PIN and no owner that holds money (it cannot be loaded); `6985` on
`SET_PIN` when a PIN exists; the owner secret's 32 bytes on the card and in the
air; any page-side secret.

**New:** `SET_TIME`, the time key, `now`, the window, `6A92`, `6A93`, rule 7 (no
money before a time and none without an owner), `ALLOW_LOAD` (`45`), the owner's
labels for `SET_OWNER`, `SET_CARD` and the load grant, the clock's one way back
(rule 4), and the interim signer (5.2).

**Replaced in 1.15:** `SET_TIME`, the time key, the clock's one way back, the
interim signer, `6A92` and rule 7's "no money without a time". The clock is now
the time in the newest Bitcoin block header the card has been shown (section 5),
so: `SET_HEADER` (`36`) and `TELL_TIME` (`37`) are new; `35` answers `6D00` and
stays unassigned; `SET_CARD` does not read the 65 bytes where the time key was,
and no longer clears the clock; a card that has been shown no block may be
loaded, may be given a limit and spends its first day on trust (6); `6A93` means
little work, and `6A92` is unused; a log entry is twenty bytes and a receipt
seventy-seven; the flag for a clock moved twice in a tap is never set.

<a id="12-how-it-is-tested"></a>

## 12. Verification

- jCardSim, the day: a limit of one piece and four pieces on the card, and a
  terminal that sends the PIN between every spend, takes one, however it is
  repeated, and takes a second only after a header a day later; a new SELECT, a
  reset, `CLEAR_SPENT` and a load leave today as it is; spent today carries
  across taps; exactly the limit goes and one sat more does not, with nothing
  burned; a sum that wraps is over any limit; limit 0 spends with no clock; the
  window turns at 86 400 seconds and not at 86 399; the two-days-at-a-boundary
  bound is pinned as what it is. The first day is on trust: a card that has been
  shown no header loads, is given a limit whose window has no start, and spends
  up to the limit, where a payment within it goes and counts and one past it is
  `6A8F` (never `6A92`) with nothing burned; the first header anchors the window
  at its time with what was spent kept.
- jCardSim, the clock: a header whose hash is over the target of its own `bits`
  is `6A93` and changes nothing, whatever its time and whoever brings it; one at
  exactly the floor is taken, and one a hair over it is `6A93` though its own
  work is done; once a header is taken, one whose target is over four times the
  hardest taken is `6A93`, and exactly four times is taken; `bits` no header
  could carry (a size of 0 or past 32, a mantissa with its top bit set) are
  `6A80`, and any length but 80 is `6700`; an older or repeated header is `9000`
  and changes nothing, a newer one is taken, and the answer is the card's clock
  in four bytes; no key, PIN, owner, record or state refuses a good header, and
  the hardest `bits` are raised only by a header that moves the clock; the
  clock survives `SET_CARD` (with any bytes where the time key was),
  `SET_OWNER`, `CHANGE_PIN`, a reset and an emptying and set-up again, so an old
  block offered to a card set up again is ignored; `35` answers `6D00`; and real
  blocks of the network, at the real floor, are taken or refused as above: the
  genesis block, which has its own work and a target far over the floor, is
  `6A93`, as is the tip with a nonce byte changed.
- jCardSim, the told time: `TELL_TIME` is written into every receipt (offset 4)
  and every log entry (offset 16) made after it, zeros where none was told, and
  a later telling replaces the earlier for what is written after; it needs no
  PIN, owner, record or state, and a length but four is `6700`; it moves nothing
  that lasts; it goes with the power and not with a SELECT; and no clock moved
  on is marked any more (`LOG_FLAG_CLOCK` is a word and is never set).
- jCardSim, the owner: every owner-proved command (`CHANGE_PIN`, `34`,
  `SET_OWNER`, `SET_CARD`, `ALLOW_LOAD`, `LOCK_CARD`) refused with the PIN alone,
  with a nonce and no proof, with another key's signature, with another command's
  label, with a proof for an earlier nonce, for another value, and with one that
  has worked once already, and accepted with the right proof and **no PIN**; a
  wrong proof costs no PIN tries, even five times; `CHANGE_PIN` unblocks a blocked
  card; a card with no owner refuses them with `6A90`.
- jCardSim, A1: a card with an owner refuses `SET_PIN`, `SET_OWNER`, `SET_CARD` and
  the PIN form of `SET_LIMIT` without the owner's proof **even when it is empty**;
  a card with no owner accepts them while empty (and refuses them `6A8D` with one
  unspent piece); the takeover (a terminal with the PIN empties the card, then
  tries to set its own PIN, owner and record) fails for the attacker at every step.
- jCardSim, A2 and A3: a card with no owner refuses `LOAD_PROOF` `6A90`; after
  `ALLOW_LOAD`, `LOAD_PROOF` and `CLEAR_SPENT` go with no PIN verified, `SPEND` does
  not, and a new SELECT ends the grant.
- jCardSim, the empty card: after `CLEAR_SPENT` of a fully spent card the open
  commands are allowed on a card with no owner.
- jCardSim, a piece is on the card once: a copy of an unspent piece that states
  an amount of 1 (and the piece itself, and the same nonce with a date or another
  keyset) is refused `6A94` with nothing written, nothing counted against the day
  and the real piece as it was; the same for a piece on a spent slot, which loads
  again after `CLEAR_SPENT` and is signed for and charged at its real worth; a nonce
  that differs in its first byte or its last is another piece; the owner's
  `ALLOW_LOAD` gets a copy no further than the PIN does.
- jCardSim, GET_PIECES: an empty card is one byte; up to three unspent pieces are one
  page, each the bytes `GET_PROOF` gives after its status byte; a spent slot is a tag
  alone and an empty one is left out; a page from the middle, and from an empty slot; a
  full card is forty-three pages, each within 255 bytes and each moving on; a page fills to
  255 bytes and not a byte over (three pieces and eight spent tags, then the next piece
  starts a page); it asks for no PIN and changes nothing; a slot there is not is `6A83`.
  The transcript has it, and the phone's model of the card is held to it.
- jCardSim, 128 places (1.7): the short listing is two bytes a piece after the first
  where keyset and date are shared, names them again where either differs and at the
  start of every answer, gives `FF` and four bytes for an amount that is no power of
  two and the size for every power from 1 to 2^31, skips spent and empty places, and
  takes two answers for a full card; the whole listing names places above 63 and marks
  a spent one by its high bit; every command that names a place takes 64 to 127 and
  refuses 128; a payment of 33, of 64 and of all 128 places signs once, burns exactly
  those, waits as its sum says, and is charged to the day whole; 129 is `6A96`; a burn
  that fails is `6A96` with nothing burned. Each was broken on purpose in a copy of the
  applet, one change at a time (74 changes), and every change was caught by a test.
- jCardSim, the PIN optional (1.16): a card set up with no PIN (record, owner, a
  load under the owner's grant, limits, a payment with its signature again, the
  change in the tap after, the log under the grant, a new record, a PIN added) and
  every stranger's command on it refused; ADD PIN, clear and sealed, with money on
  the card, refused with no grant, with a PIN, for a wrong length or an envelope
  that does not open; the twelve-byte limit (every other length refused, a number
  for the allowance on a card with no PIN `6985`, numbers that do not change keeping
  their count); the allowance to the sat (to its limit signs, one sat more is
  `6A94`; a payment is not split; a payment with the PIN counts for nothing; what
  leaves the card, with change, is what is counted; an allowance of 0 asks for the
  PIN even for a payment that takes nothing; a blocked card has none); the day
  turning both counts, by a payment with no PIN and by one with it; the window
  beginning on the allowance alone, and on a card that has seen no header and
  anchoring at the first one with the count kept; the PIN asked before the limits,
  so that a refusal for want of it writes nothing in the log and a run of them marks
  no tamper, and a payment within the allowance and over the day refused as ever;
  the wait and the second payment in a tap applying to a payment with no PIN; a sum
  that wraps; the log's flag; the last signature again. The transcript has the
  allowance, and the phone's model of the card is held to it.
- The source-reading test: spent today and the slot's status change between one
  `beginTransaction` and its commit, with the signing after.
- Vectors in `spec/vectors/`: an owner key and a proof for each label, and one for
  the limit's label over all twelve bytes
  (`owner.json`; ECDSA signatures are randomised, so each is one the card
  verified, and another implementation verifies it again); the transcript,
  extended (`transcript.json`), which the phone's JavaScript model of the card is
  held to command for command.
- On a card, by hand: the ECDSA verify on the J3R180 (that it takes the DER form and
  the uncompressed key, and how long it takes, once for each owner command);
  `SET_HEADER` (two SHA-256 passes and a few compares: expected well under 20 ms,
  not yet measured); set-up, a day's spending, a day turned by a block, a wrong PIN
  three times and an owner's unblock, a tap pulled away at each step; and the third
  permanent write per spend (spent today, with the status byte and, on a new day,
  the window start) against the chip's write endurance.

<a id="13-what-it-does-not-protect-against"></a>

## 13. Residual risks

- **A terminal built to cheat is bound by the day.** It cannot start another by
  telling the card it is later: the card's clock is the newest block header it
  has been shown, believed for its work and for nothing else. To end a day the
  terminal has to bring a header dated a day on from the window's start, which is
  a real block when the world has made one, or a forgery at about a quarter of a
  block's work (5.2). It cannot shorten the day any other way.
- A terminal that has been handed the PIN takes one day's limit per visit, and up to
  two across a window's boundary. It does not check a payment, and nothing on the
  card can.
- **Nothing is bound that the owner has not set.** The day, and the limit on one
  payment (6a; the per-tap limit), each need the owner to have set a number, and
  a new card has neither: set-up asks for none (section 10).
- **A card with no PIN is cash.** Whoever holds it can spend it, up to the day's
  limit and the limit on one payment if the owner has set them, and the owner's
  proof still administers it. A card with a PIN signs the no-PIN allowance a day
  to whoever taps it, and no more without the PIN; a thief with the card has that
  much a day until the holder sets the allowance to nothing or has the card
  blocked (6f).
- **A forged header.** Whoever spends the work of a header can show the card any
  time. On a card that has taken a header from the network the work is a quarter
  of a block's; on a card that has taken none it is the floor's, a quarter of a
  block's work in this version's time (5.2). It buys one more day's limit, or a clock frozen
  years ahead, after which the card signs for one more limit's worth in all until
  the owner sets the limit again. The price is the same whatever the card holds.
- **A card that has been shown no header** spends its first day on trust, up to
  its limit, and a terminal that chooses the first header it shows can make that
  two limits' worth, once (6).
- **A clock that is not the second.** A block's time can lead the true time by up
  to two hours (5.1), and the card's day moves only when it is shown a newer
  block: a card that is shown none does not end its day.
- **A network whose work falls** to under a quarter of the hardest header a card
  has taken stops that card taking headers. Its clock stops, and nothing resets
  the bar (5.2). It fails closed: the card signs for no more than what is left of
  its day, and the owner can give it the limit again.
- A terminal that has been handed the PIN can also write onto the card pieces the
  mint will refuse, made up with a nonce no mint ever signed. They take nothing from anyone, since the
  receiver always asks the mint, but a later payment that picks one burns slots and
  spends a day's limit on nothing, and while such a piece is on the card it is not
  empty, so the owner cannot replace its owner or record until it is spent. A fake
  piece looks unspent to a state check. From 1.20 the card can keep the mint's proof
  for a piece, and a phone that reads and checks it sees that a made-up piece is not
  real (`FOXY-CARD-SPEC.md` 5.9); the card checks nothing, so a card loaded with no
  proofs is as it was.
  Since 8.2, the reader that taps the card next after any payment can do the same
  once without the PIN: the nuisance is the same, and the reader is almost always
  the till that just had the PIN.
- It cannot write a **copy** of a real piece. The card signs a piece's secret, which
  its nonce makes, and takes the amount on the terminal's word, so a copy stating an
  amount of 1 would have been spent for 1 and signed for the real piece. `LOAD_PROOF`
  refuses a nonce that is in any slot, spent or not (`6A94`). What the card does not
  do is remember a nonce once `CLEAR_SPENT` has freed its slot: a piece that was
  burned and whose signature never reached the mint (a tap cut off at the wrong
  moment) can be read from its spent slot, cleared, loaded again with a small amount
  and signed for again, by a terminal that has the PIN. A signature that was handed
  over has already been paid for in full.
- A holder with no phone has no balance they can read that a terminal did not draw.
  That screen displays the stored values; clock validation follows the header rules.
- Whoever has the owner's words and the card in hand has everything on it.
- A holder whose owner has lost their words can never change the PIN or the limit.
- The PIN is in the clear over a few centimetres of air until phase 2.
- A lost card is cash gone; there is no refund key for now.

<a id="14-decided-and-left"></a>

## 14. Decisions and remaining work

Decided: no limit by default and none asked at set-up (A8); no loading of a card
with no owner (A2); the owner's phone adds funds without the PIN (A3); the owner
key is P-256 and ECDSA (A6), and stays in native code (A7); taking money off lifts
and restores the limit in one tap (A9); the owner's proof is ECDSA, with the hash
as a documented fallback only (A11); the clock is the newest Bitcoin block header
the card has been shown, believed for its work, held to a floor and to a quarter
of the hardest it has taken (1.15). The clock's one way back (A4) and the interim
signer (A10) went with the signed time.

Left: the time `SET_HEADER` takes on the chip (not yet measured, 5.1); when the
floor is raised (5.2); and whether the ECDSA verifier on the first card behaves
(7.2).
