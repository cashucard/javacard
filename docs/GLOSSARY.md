# Glossary

Terms you will meet in this codebase, in the order they tend to confuse people.
Written for someone who knows software but not smartcards, or knows Bitcoin but
not Cashu.

## Cashu

**Cashu** — a Chaumian ecash protocol. A mint issues blind-signed tokens
("proofs") redeemable for Bitcoin. The mint cannot link issuance to redemption,
so the tokens behave like cash rather than like an account balance.

**Mint** — the server that issues and redeems proofs and holds the Lightning
reserve backing them. Ours is `forge.flashapp.me`, running Nutshell. Trusted for
solvency; not trusted for unlinkability.

**Proof** — one unit of ecash. Four fields: `id` (keyset), `amount`, `secret`,
`C` (the mint's unblinded signature). Possessing a valid proof *is* possessing
the money.

**Keyset** — a set of mint keys, one per denomination, identified by an 8-byte
hex id. Mints rotate keysets, so a long-lived card can hold proofs from more
than one — which is why input fees are declared per keyset.

**Denomination** — proof amounts are powers of two. Paying 375 means combining
proofs, and getting change means a swap. `splitIntoDenominations` does the
decomposition.

**BDHKE** — Blind Diffie-Hellman Key Exchange, the blinding scheme underneath
Cashu. The client blinds a secret, the mint signs the blinded value, the client
unblinds. The mint never sees what it signed. Done entirely on the *host*, never
on the card ([D3](DECISIONS.md#d3)).

**Blinding factor (`r`)** — the random scalar used to blind. The client must
keep it to unblind, and to verify DLEQ later. It is part of the DLEQ proof a
third party needs, so the card keeps it beside `e` and `s`; whoever hands `r` to the
mint lets the mint tie the piece to the request that made it.

**Mint / Melt / Swap** — the three mint operations. *Mint* = create proofs (pay
an invoice, get ecash). *Melt* = destroy proofs (spend ecash, pay an invoice).
*Swap* = exchange proofs for new ones of equal value (change, receiving,
unlocking).

**Y** — `hash_to_curve(secret)`, a proof's identifier at the mint. Used by
`checkstate` to ask whether a proof is spent, without revealing the signature.

### NUTs (Cashu spec documents)

| NUT | What it covers | Where it shows up |
|---|---|---|
| [00](https://github.com/cashubtc/nuts/blob/main/00.md) | Notation, `hash_to_curve`, token format | `crypto.ts` |
| [01](https://github.com/cashubtc/nuts/blob/main/01.md) | Mint public keys | `getMintKeysets` |
| [02](https://github.com/cashubtc/nuts/blob/main/02.md) | Keysets and **input fees** | `inputFee` |
| [03](https://github.com/cashubtc/nuts/blob/main/03.md) | Swap | `swap.ts` |
| [04](https://github.com/cashubtc/nuts/blob/main/04.md) | Minting | `mint.ts` |
| [05](https://github.com/cashubtc/nuts/blob/main/05.md) | Melting | `melt.ts` |
| [07](https://github.com/cashubtc/nuts/blob/main/07.md) | Proof state (double-spend check) | `state.ts` |
| [10](https://github.com/cashubtc/nuts/blob/main/10.md) | Well-known secrets | `parseP2PKSecret` |
| [11](https://github.com/cashubtc/nuts/blob/main/11.md) | **P2PK** — lock a proof to a pubkey | `witness.ts`, the applet |
| [12](https://github.com/cashubtc/nuts/blob/main/12.md) | **DLEQ** — prove the mint used its published key | `dleq.ts` |
| **NUT-XX** | *This project's own draft* — Cashu NFC cards | [`../spec/NUT-XX.md`](../spec/NUT-XX.md) |

**NUT-XX** is our proposal, not yet submitted upstream. Profile A is an online,
BoltCard-compatible mode; **Profile B** is the offline bearer card this repo
implements.

## Smartcards

**JavaCard** — a stripped-down Java for secure elements. No `long`, no big
integers, no garbage collector, no floating point, no `String` at runtime.
Reading it as ordinary Java is the most common source of bugs here.

**Applet** — the program on the card. Ours is `CashuApplet`.

**APDU** — the request/response unit of smartcard communication. Roughly:
`CLA INS P1 P2 [Lc data] [Le]`, answered with data plus a 2-byte **status word**
(`9000` = success). Our command set: [`../spec/APDU.md`](../spec/APDU.md).

**CAP file** — the compiled, converted applet, the thing actually loaded onto a
card. Produced by `ant cap`.

**AID** — Application Identifier, the applet's address. `SELECT` by AID picks
which applet a reader is talking to. Protocol 2.0: package AID
`F0434153485543415244` ("CASHUCARD" after `F0`), applet AID `…01`
([D19](DECISIONS.md#d19)). Readers select the applet AID whole; the package AID
alone reaches the opener on a chip ([D25](DECISIONS.md#d25)). 0.x used `D2760000850102` and Foxy's 1.x
`F0464F585943415244`; a 2.0 card answers neither.

**EEPROM** — the card's persistent memory. **`new` allocates here and is never
freed** — the reason for [D10](DECISIONS.md#d10).

**Transient memory** — RAM, cleared on deselect (`CLEAR_ON_DESELECT`). Where all
scratch buffers must live.

**GlobalPlatform / `gp`** — the standard (and the tool) for loading applets. A
card must be *unlocked* — supplied with known GlobalPlatform keys — or nothing
can be installed on it.

**PC/SC** — the OS-level smartcard API. `cardctl` talks PC/SC, which is why the
same code drives both contact and contactless readers.

**Dual-interface** — a card with both contact (ISO 7816) and contactless
(ISO 14443) interfaces. Load over contact, tap over contactless.

**ISO/IEC 7810 ID-1** — the credit-card form factor: 85.6 × 53.98 mm, 3.18 mm
corner radius.

**Tear-off** — pulling a card from the field mid-operation. A classic smartcard
attack. Every slot write here commits its status byte last, so a tear never
leaves a new status over old bytes ([D14](DECISIONS.md#d14)): analysed and
tested in jCardSim, not yet on a card ([`SECURITY-MODEL.md`](SECURITY-MODEL.md)).

**jCardSim** — a JavaCard simulator that runs on the JVM. Indispensable, and
structurally unable to reproduce EEPROM exhaustion or hardware crypto framing —
so a green suite is not evidence about silicon.

## Cryptography

**secp256k1** — Bitcoin's elliptic curve. The card generates a keypair on it at
install.

**BIP-340 / Schnorr** — the signature scheme. Keys are *x-only* (32 bytes,
implicitly even-y); signatures are 64 bytes, `R.x || s`.

**Auxiliary randomness** — fresh entropy folded into the nonce during signing.
Makes signatures over the same message differ, deliberately
([D9](DECISIONS.md#d9)).

**P2PK** — "pay to public key". A proof whose secret says only the holder of a
given key may spend it.

**Witness** — the signature attached to a P2PK proof to unlock it. On this card
it is the one `SIG_ALL` signature `SPEND_ALL_SIGN` gives for a whole payment,
carried in the first input's witness (0.x signed each piece with `SPEND_PROOF`).

**DLEQ** — discrete-log equality proof. Proves the mint signed with its
published key rather than a per-user one. From Foxy's software 1.20 the card keeps
the mint's proof (`e`, `s` and the blinding factor `r`, 96 bytes) with each piece
and gives it back (`GET_DLEQ`); the card never checks it, the reader does.

**`sigflag` / `n_sigs`** — NUT-11 tags controlling *what* is signed
(`SIG_INPUTS` vs `SIG_ALL`) and *how many* signatures are required. Both are
honoured locally, because a check looser than the mint's is worse than none
([D7](DECISIONS.md#d7)).

## Flash

**FIP** — Flash Improvement Proposal, the internal design-doc process
(repository is private). **FIP-04** covers the BoltCard/BTCPayServer design this
project replaces; **FIP-07** covers the API-key authentication used by the mint's
USD backend.

**Flash Forge** — the mint, `forge.flashapp.me`.

**Bearer instrument** — something whose value belongs to whoever physically
holds it. The entire product thesis ([`VISION.md`](VISION.md)).

**Profile B / B+** — the 0.x draft's offline bearer profile and its PIN-gated
variant. Protocol 2.0 replaces both: a PIN is optional, payments are bounded by
the owner's limits, and the owner administers the card ([D18](DECISIONS.md#d18)).

**Owner key** — a P-256 key whose private half lives on the holder's phone
(derived from its seed). Its ECDSA proofs, under `CashuCard/…` labels, change the
PIN (unblocking a blocked card), the limits, the record and the owner, add funds
with no PIN, and refresh the card. It can never spend.

**Rollover budget** — how many times the day's window may roll between the
owner's `REFRESH`es (default 7, 1 to 30): the bound on a terminal that walks the
card's clock with real block headers ([D20](DECISIONS.md#d20)). Only a payment
that moves value spends a roll, and a `SET_LIMIT` without the budget's byte leaves
the budget as it is ([D26](DECISIONS.md#d26)).

**PUK** — 0.6's provisioning unblock key ([D16](DECISIONS.md#d16)), superseded in
2.0 by the owner's `CHANGE_PIN`.
