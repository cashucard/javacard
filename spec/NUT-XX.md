# NUT-XX: Cashu NFC Card Protocol

`optional`

`depends on: NUT-00, NUT-01, NUT-02, NUT-03, NUT-07, NUT-09, NUT-10, NUT-11, NUT-12`

> **Status: Draft, protocol 2.0** — Reference implementation at
> [lnflash/cashu-javacard](https://github.com/lnflash/cashu-javacard), shared with
> the Foxy wallet project ([getfoxy/card](https://github.com/getfoxy/card)). Not yet
> submitted to cashubtc/nuts. The byte-level wire is [`APDU.md`](APDU.md); this
> document says what the bytes mean to a wallet and a mint.

---

This NUT defines how Cashu `Proof`s are held and spent by a smart card over NFC,
so that a card can pay a till that is offline at the moment of payment and the
card's holder never types a seed or carries a phone.

A card holds pieces (proofs) locked to a secp256k1 key it made itself and never
exports (NUT-11 P2PK). It pays by signing a swap for the pieces it is asked to
spend, burning each one as it signs, with one signature for the whole payment
(NUT-11 `SIG_ALL`), and makes its own change. It keeps the mint's DLEQ proof
(NUT-12) beside each piece for whoever reads the card to check. An owner key,
held by the holder's phone, administers the card; a daily limit, kept against a
clock taken from Bitcoin block headers, bounds what a terminal that has been
handed the PIN can take.

Protocol 2.0 replaces the draft's 0.x profiles (a reader-supplied message to
sign, a `SIGN_ARBITRARY` command, no owner, no limits), whose weaknesses are
listed in [`docs/FOR-LNFLASH.md`](../docs/FOR-LNFLASH.md) section 3.

---

## Definitions

- **Card**: an ISO 14443-4 NFC device running the applet, selected by the
  applet's whole AID `F0 43 41 53 48 55 43 41 52 44 01` (the package AID
  `F0 43 41 53 48 55 43 41 52 44`, "CASHUCARD" after the proprietary RID byte
  `F0`, and `01`), version `02 00`. A SELECT by the package AID alone is a
  partial name, and a chip gives it to the package's first instance, the opener,
  which answers `90 00` with no version (see [AID assignment](#aid-assignment)).
- **Card key** (`P_card`): a secp256k1 key pair made on the card at install. The
  private half never leaves it. `GET_PUBKEY` answers the public half, compressed.
- **Card piece**: a Cashu `Proof` whose `secret` is the NUT-10 P2PK secret below,
  with `data = hex(P_card)` and the `SIG_ALL` flag.
- **Owner key** (`P_owner`): a NIST P-256 key whose private half lives on the
  holder's phone. It signs the owner's commands; it can never spend.
- **Reader**: a till or a wallet speaking ISO 7816-4 APDUs to the card.

---

## The card piece

Every piece on a 2.0 card has this secret, as text, with no spaces, in this key
order, lowercase hex, the date in decimal:

```
["P2PK",{"nonce":"<64 hex>","data":"<66 hex P_card>","tags":[["sigflag","SIG_ALL"]]}]
```

and, for a piece with a date (a locktime and the card's refund key):

```
["P2PK",{"nonce":"<64 hex>","data":"<66 hex P_card>","tags":[["locktime","<decimal>"],["refund","<66 hex>"],["sigflag","SIG_ALL"]]}]
```

The card stores only what it cannot rebuild: the keyset id's first 8 bytes, the
amount, the 32-byte nonce, `C` and the date (82 bytes a slot with its status:
[`APDU.md`](APDU.md#proof-slot-layout)). It rebuilds the secret from the nonce, its
own key and the date, so a reader cannot make it sign for any other text.
[`vectors/secret.json`](vectors/secret.json) has slots, secrets, messages and the
card's signatures.

A wallet tops a card up with an ordinary NUT-11 locked swap to `P_card` with
`sigflag SIG_ALL`, then writes each piece's fields to the card. A keyset id longer
than 8 bytes (NUT-02 v1) is stored by its first 8; a reader expands it against the
mint's keysets and refuses an ambiguous one.

---

## Paying: one signature for the payment

The till names the pieces (`SPEND_ALL_BEGIN`), gives its swap outputs
(`SPEND_ALL_OUTPUTS`), asks the card for its change (`SPEND_ALL_CHANGE`), and asks
for the signature (`SPEND_ALL_SIGN`). The card signs, with BIP-340, the SHA-256 of
the NUT-11 `SIG_ALL` message:

```
msg = secret_0 ‖ C_0 ‖ … ‖ secret_n ‖ C_n ‖ amount_0 ‖ B_0 ‖ … ‖ amount_m ‖ B_m
```

each secret as its text, each `C` and `B_` in hex, each amount in decimal, inputs
in the order named and outputs in the order given (the card's own change after the
till's). The card burns every piece named in the commit that releases the
signature; a card lifted while it signs has burned nothing. The till swaps at the
mint with every input carrying the one witness, and only then says paid.

**The card's own change.** For `SPEND_ALL_CHANGE` the card makes an output locked
to its own key (a fresh nonce, the payment's date and refund key, `SIG_ALL`),
hashes it to the curve (NUT-00) and blinds it with a fresh `r`, and keeps the
opening (amount, keyset, date, nonce, `r`) until the piece is back on the card.
Whoever finishes the change (the till in the same or the next tap, or the owner's
phone later from `GET_CHANGE`, NUT-09 restore) unblinds the mint's signature and
loads the piece. Nothing a till names can take that change: it is locked to the
card.

**What a till must check before it signs anything off.** The secrets it rebuilds
are format-4; the pieces' keyset is a keyset of the mint it will swap at; and,
offline, each piece's DLEQ proof (below). A till that cannot reach the mint
accepts the risk of a piece already spent elsewhere (offline double spend: this
NUT does not prevent it).

---

## The mint's proof on the card (NUT-12)

A wallet that loads a piece with its DLEQ proof (`e`, `s` and the blinding factor
`r`: 96 bytes) gives it to the card with the piece (`LOAD_PROOF` P1 = 1). The card
keeps it and hands it back for any unspent piece (`GET_DLEQ`), and never checks it.
A reader rebuilds the secret, `Y = hash_to_curve(secret)`, `C' = C + r·K` and
`B' = Y + r·G`, and checks NUT-12's equation with the mint's key `K` for the
amount. A piece that passes was signed by the mint; a piece the card was given
by a terminal with a made-up `C` does not. It does not show that a real piece is
unspent.

---

## The owner

A card with an owner is its owner's, empty or not. The owner's commands carry an
ECDSA signature (P-256, SHA-256, DER) by `P_owner` over

```
label ‖ nonce (16, from GET_NONCE, one try) ‖ value
```

with a label of each command: `CashuCard/change-pin`, `CashuCard/set-limit`,
`CashuCard/set-owner`, `CashuCard/set-card`, `CashuCard/load`, `CashuCard/lock`,
`CashuCard/reset`, `CashuCard/tag`, `CashuCard/refresh`
([`APDU.md`](APDU.md#the-owners-proof)). A phone derives a card's owner key from
its wallet seed:

```
d = HMAC-SHA256(key = seed, message = "CashuCard/owner" ‖ 0x00 ‖ P_card (33)) mod n
```

re-made with a counter byte appended while `d = 0`. Restoring the seed restores
ownership of every card. [`vectors/owner.json`](vectors/owner.json) has proofs for
every label.

A card is set up in one tap, owner last: `SET_PIN` (or none), `SET_CARD` (the
mint), then `SET_OWNER` carrying the tip block header as its anchor. An unowned
empty card is open to the first phone that sets it up.

---

## The clock and the limits

A card's clock is the time in the newest Bitcoin block header it has been shown,
believed for its proof of work and only moving forward. A header must meet its own
target, a floor built into the applet (a quarter of the network's work at the
newest header in [`vectors/headers.json`](vectors/headers.json)), and a quarter of
the hardest header the card has taken. A forger must spend a quarter of a block's
work for every day it buys.

The owner sets, all off on a new card:

- a **daily limit**: what may leave the card in one day's window (86,400 seconds of
  the card's clock), counting the pieces less the card's own change;
- a **limit on one payment**: past it a payment waits, by the card's own work;
- a **no-PIN allowance**: what a card with a PIN signs for in the window without it.

**Bounds on a walked clock (2.0).** Real headers are free, so each day's limit
could be renewed by a terminal that keeps the card and brings a header a day. In
2.0 the window rolls at most the owner's **rollover budget** times (default 7,
1 to 30) between the owner's `REFRESH`es: an owner's proof over the tip header,
sent by the holder's phone whenever it is online. The no-PIN allowance begins
again at a roll only if a PIN or an owner's proof has armed it since it last did.
A card whose owner was set with an anchor header never runs on an unset clock.

---

## Security considerations

- **The card signs only what it burns.** Every signature is either a payment's
  (every piece named burned in the same commit) or `AUTH`'s (a tagged hash no
  secret text can equal). There is no command that signs a reader's bytes.
- **A terminal handed the PIN** takes at most the daily limit per window, the
  rollover budget's windows between the owner's refreshes, and nothing of the
  owner's: it cannot change the PIN, the limits, the record or the owner.
- **A lost card is lost cash**, up to its limits for whoever learns its PIN, and up
  to its no-PIN allowance (once per arming) for anyone.
- **Offline double spend.** A till that accepts offline trusts that no copy of a
  piece was spent first. The card cannot prevent a piece being spent twice by
  someone who obtained its signature twice; it can only refuse to sign twice.
- **Mint trust.** The mint is trusted for solvency (NUT-06 operators should
  publish reserves).
- **Side channels.** The two byte-array multiplies on the card's key and nonces
  (`mul256x256`, `mulByDelta`) have no secret-dependent branch (DECISIONS D21).
  The modular reductions on the same signing path still branch on values derived
  from the key and the nonce (`reduce512toModN`, `addModN`, `reduceModN`, `sub32`,
  `cmp32`); they are an open item (SECURITY-MODEL, open item 5), and no timing has
  been measured on silicon. The chip's EC and RSA engines are the vendor's.

---

## Mint support

A mint needs NUT-10 and NUT-11 with `SIG_ALL` on swaps, and NUT-12 for the DLEQ
proofs a card carries. Nutshell supports these; the reference implementation's
end-to-end tests run against Nutshell 0.20.3.

---

## AID assignment

`F0 43 41 53 48 55 43 41 52 44` is a proprietary AID (RID byte `F0`), naming the
protocol and no wallet. It is the package's AID; the card's applet is instantiated
under it and `01`, after an opener under it and `4D` that the chip needs made first.
A reader selects `F0 43 41 53 48 55 43 41 52 44 01`, the whole AID: a SELECT by
the package AID alone reaches the opener on a chip (`90 00` with no version, then
`6D 00` to every command), and a reader that tries it takes an answer without the
two version bytes as no answer. The 0.x draft's `D2 76 00 00 85 01 02` sat under
the NFC Forum's RID and is withdrawn. A card that does not answer the 2.0 AID is
not a 2.0 card, and a wallet treats it as one that needs an update.

---

## References

- [`APDU.md`](APDU.md): every command, byte for byte.
- [`docs/FOXY-CARD-SPEC.md`](../docs/FOXY-CARD-SPEC.md) and
  [`docs/FOXY-CARD-DAILY-LIMIT.md`](../docs/FOXY-CARD-DAILY-LIMIT.md): the design.
- [`docs/DECISIONS.md`](../docs/DECISIONS.md) D18 to D24: what 2.0 changed and why.
- [`docs/SECURITY-MODEL.md`](../docs/SECURITY-MODEL.md): threats and what is untested.
- NUT-10, NUT-11 (P2PK, `SIG_ALL`), NUT-12 (DLEQ), NUT-09 (restore).
