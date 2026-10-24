# Glossary

Definitions for contributors working with Cashu, smartcards and the reference
implementations.

## Cashu

**Cashu**: a Chaumian ecash protocol. A mint issues blind-signed tokens
("proofs") redeemable for Bitcoin. Blind signatures separate issuance from
redemption. DLEQ verification and blinding-factor handling affect that privacy;
see [D11](DECISIONS.md#d11).

**Mint**: the server that issues and redeems proofs and holds the Lightning
reserve backing them. Flash Forge (`forge.flashapp.me`) is a Nutshell deployment
used in the dated hardware reports. A holder trusts the chosen mint for
solvency.

**Proof**: one unit of ecash. Four fields: `id` (keyset), `amount`, `secret`,
`C` (the mint's unblinded signature). A valid proof can be redeemed subject to
its spending conditions and mint state. Card proofs require the corresponding
spending-key signature.

**Keyset**: a set of mint keys, one per denomination, identified by a versioned hexadecimal id. The integrations cover both legacy
8-byte and v2 33-byte keyset IDs. Mints rotate keysets, so a long-lived card can
hold proofs from more than one. Input fees are declared per keyset.

**Denomination**: proof amounts are powers of two. Paying 375 means combining
proofs, and getting change means a swap. `splitIntoDenominations` does the
decomposition.

**BDHKE**: Blind Diffie-Hellman Key Exchange, the blinding scheme underneath
Cashu. The client blinds a secret, the mint signs the blinded value, the client
unblinds. The mint signs a blinded message. The card also constructs blinded
change outputs in the current protocol; [D3](DECISIONS.md#d3) records the
earlier host-side design, superseded by [D18](DECISIONS.md#d18).

**Blinding factor (`r`)**: the random scalar used to blind. The client must
keep it to unblind, and to verify DLEQ later. It is part of the DLEQ proof a
third party needs, so the card keeps it beside `e` and `s`; whoever hands `r` to the
mint lets the mint tie the piece to the request that made it.

**Mint / Melt / Swap**: the three mint operations. *Mint* = create proofs (pay
an invoice, get ecash). *Melt* = destroy proofs (spend ecash, pay an invoice).
*Swap* = exchange proofs for new ones of equal value (change, receiving,
unlocking).

**Y**: `hash_to_curve(secret)`, a proof's identifier at the mint. Used by
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
| [11](https://github.com/cashubtc/nuts/blob/main/11.md) | **P2PK**; lock a proof to a pubkey | `witness.ts`, the applet |
| [12](https://github.com/cashubtc/nuts/blob/main/12.md) | **DLEQ**; prove the mint used its published key | `dleq.ts` |
| **NUT-CCP** | *This project's own draft*; the Cashu Card Protocol | [cashucard/nut `CCP.md`](https://github.com/cashucard/nut/blob/main/CCP.md) |

**NUT-CCP** is the project draft in cashucard/nut. Upstream submission and a
Cashu-assigned NUT number remain pending. It specifies the core every card
and reader share. The profiles this applet adds (the owner, the clock and the
limits, the NFC tag) are in [`../spec/APDU.md`](../spec/APDU.md).

## Smartcards

**JavaCard**: a stripped-down Java for secure elements. No `long`, no big
integers, no garbage collector, no floating point, no `String` at runtime.
Reading it as ordinary Java is the most common source of bugs here.

**Applet**: the program on the card. Ours is `CashuApplet`.

**APDU**: the request/response unit of smartcard communication. Roughly:
`CLA INS P1 P2 [Lc data] [Le]`, answered with data plus a 2-byte **status word**
(`9000` = success). Our command set: [`../spec/APDU.md`](../spec/APDU.md).

**CAP file**: the compiled, converted applet, the thing actually loaded onto a
card. Produced by `ant cap`.

**AID**: Application Identifier, the applet's address. `SELECT` by AID picks
which applet a reader is talking to. Protocol 2.0: package AID
`F0434153485543415244` ("CASHUCARD" after `F0`), applet AID `…01`
([D19](DECISIONS.md#d19)). Readers select the applet AID whole; the package AID
alone reaches the opener on a chip ([D25](DECISIONS.md#d25)). 0.x used `D2760000850102` and Foxy's 1.x
`F0464F585943415244`; a 2.0 card answers neither.

**EEPROM**: the card's persistent memory. **`new` allocates here for the
lifetime of the applet**, which motivates [D10](DECISIONS.md#d10).

**Transient memory**: RAM, cleared on deselect (`CLEAR_ON_DESELECT`). Where all
scratch buffers must live.

**GlobalPlatform / `gp`**: the standard (and the tool) for loading applets. Installation requires
the correct card-manager keys and a manager state that permits loading.

**PC/SC**: the OS-level smartcard API. `cardctl` talks PC/SC, which is why the
same code drives both contact and contactless readers.

**Dual-interface**: a card with both contact (ISO 7816) and contactless
(ISO 14443) interfaces. Load over contact, tap over contactless.

**ISO/IEC 7810 ID-1**: the credit-card form factor: 85.6 × 53.98 mm, 3.18 mm
corner radius.

**Tear-off**: pulling a card from the field mid-operation. A classic smartcard
attack. Every slot write here commits its status byte last, so a tear never
leaves a new status over old bytes ([D14](DECISIONS.md#d14)): analysed and
tested in jCardSim; silicon write-order tear testing remains pending
([`SECURITY-MODEL.md`](SECURITY-MODEL.md)).

**jCardSim**: a JavaCard simulator that runs on the JVM. It exercises applet logic.
EEPROM exhaustion and hardware cryptographic framing require silicon tests.

## Cryptography

**secp256k1**: Bitcoin's elliptic curve. The card generates a keypair on it at
install.

**BIP-340 / Schnorr**: the signature scheme. Keys are *x-only* (32 bytes,
implicitly even-y); signatures are 64 bytes, `R.x || s`.

**Auxiliary randomness**: fresh entropy folded into the nonce during signing.
Makes signatures over the same message differ, deliberately
([D9](DECISIONS.md#d9)).

**P2PK**: "pay to public key". A proof whose secret says only the holder of a
given key may spend it.

**Witness**: the signature attached to a P2PK proof to unlock it. On this card
it is the one `SIG_ALL` signature `SPEND_ALL_SIGN` gives for a whole payment,
carried in the first input's witness (0.x signed each piece with `SPEND_PROOF`).

**DLEQ**: discrete-log equality proof. Proves the mint signed with its
published key rather than a per-user one. From Foxy's software 1.20 the card keeps
the mint's proof (`e`, `s` and the blinding factor `r`, 96 bytes) with each piece
and returns it through `GET_DLEQ`. The reader verifies that evidence.

**`sigflag` / `n_sigs`**: NUT-11 tags controlling *what* is signed
(`SIG_INPUTS` vs `SIG_ALL`) and *how many* signatures are required. Both are
honoured locally, because a check looser than the mint's is worse than none
([D7](DECISIONS.md#d7)).

## Flash

**FIP**: Flash Improvement Proposal, the internal design-doc process
(repository is private). **FIP-04** covers the BoltCard/BTCPayServer design this
project replaces; **FIP-07** covers the API-key authentication used by the mint's
USD backend.

**Flash Forge**: the mint, `forge.flashapp.me`.

**Bearer instrument**: something whose value belongs to whoever physically
holds it. The entire product thesis ([`VISION.md`](VISION.md)).

**Profile B / B+**: the 0.x draft's offline bearer profile and its PIN-gated
variant. Protocol 2.0 replaces both: a PIN is optional, payments are bounded by
the owner's limits, and the owner administers the card ([D18](DECISIONS.md#d18)).

**Owner key**: a holder-controlled P-256 key managed by the wallet. Flash's
tested setup derives it from the wallet recovery phrase; wallet implementations
must define their custody and recovery procedure. Its ECDSA proofs, under
`CashuCard/…` labels, change the PIN (unblocking a blocked card), the limits,
the record and the owner, add funds with no PIN, and refresh the card. Payment
signing uses the separate on-card secp256k1 key.

**Rollover budget**: how many times the day's window may roll between the
owner's `REFRESH`es (default 7, 1 to 30): the bound on a terminal that walks the
card's clock with real block headers ([D20](DECISIONS.md#d20)). Only a payment
that moves value spends a roll, and a `SET_LIMIT` without the budget's byte leaves
the budget as it is ([D26](DECISIONS.md#d26)).

**PUK**: 0.6's provisioning unblock key ([D16](DECISIONS.md#d16)), superseded in
2.0 by the owner's `CHANGE_PIN`.
