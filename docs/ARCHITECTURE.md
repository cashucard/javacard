# Architecture

> **Historical implementation snapshot.** This page records an earlier project
> milestone. Use the [current architecture](https://github.com/cashucard/cashucard/blob/main/docs/ARCHITECTURE.md)
> and [security model](https://github.com/cashucard/cashucard/blob/main/docs/SECURITY-MODEL.md)
> for current component boundaries, hardware evidence and outstanding work.

How the pieces fit together, what each does, and which parts remain to be built.

For *why* it is shaped this way, read [`VISION.md`](VISION.md) first. For the
specific engineering calls, [`DECISIONS.md`](DECISIONS.md).

## The system

Five components across four repositories plus a running mint:

| Component | Repo | Language | Status |
|---|---|---|---|
| **Applet: card firmware** | [`cashu-javacard`](https://github.com/cashucard/javacard) `applet/` | JavaCard | **Hardware-proven:** selftest 10/10; load/spend/melt/PIN all run on silicon (see the [test report](HARDWARE_TEST_REPORT_2026-09-22.j3r180.md)) |
| **cardctl: host driver** | [`cashu-javacard`](https://github.com/cashucard/javacard) `tools/cardctl/` | Python | Proven against a real card (ACR122U) |
| **cashu-client: mint protocol** | [`cashu-client`](https://github.com/cashucard/client) | TypeScript | Load + redeem implemented; both proven end-to-end on hardware via `tools/e2e-*.cjs` |
| **Card artwork: physical design** | [`flash-card-assets`](https://github.com/lnflash/flash-card-assets) | SVG/PDF | Draft v1; plate release pending |
| **Flash Forge: the mint** | `forge.flashapp.me` | Nutshell (Python) | **Live, solvent, in production** |
| **Merchant terminal** | [`flash-pos`](https://github.com/lnflash/flash-pos) | React Native | Read path (`SELECT/GET_INFO/GET_PUBKEY/GET_BALANCE`) **hardware-validated on iOS**; spend wiring pending, the offline settlement queue (#68) is merged and waiting for it |

The terminal gap is closing. flash-pos carries the Cashu card spike (#67:
IsoDep APDU transport) and the offline settlement queue for card payments
(#68); on 2026-09-23 its read path ran against a real card from an iPhone;
see the test report. What remains before a card can be *spent in the field* is
the spend wiring: the mint round-trip from `cashu-client` behind the
settlement queue, plus the top-up (PIN) path.

## Trust boundaries

This is the diagram that matters most, because almost every design decision
follows from where these lines sit.

```
┌──────────────────────────────────────────────────────────────┐
│ THE MINT (forge.flashapp.me)                                 │
│  · issues proofs, honours redemptions, holds the reserve     │
│  · is the ONLY authority on whether a proof is still unspent │
│  · trusted for solvency; NOT trusted for unlinkability       │
│    (that is what NUT-12 DLEQ checks)                         │
└──────────────────────────────────────────────────────────────┘
            ▲                                    ▲
   issue    │                                    │  redeem (melt)
            │                                    │
┌───────────┴────────────┐          ┌────────────┴───────────────┐
│ PROVISIONING HOST      │          │ MERCHANT TERMINAL          │
│  · does the BDHKE math │          │  · reads proofs off card   │
│  · knows blinding r    │          │  · asks card to sign       │
│  · loads proofs        │          │  · submits melt to mint    │
│  · NOT trusted by card │          │  · NOT trusted by card     │
└───────────┬────────────┘          └────────────┬───────────────┘
            │ APDU                               │ APDU
            ▼                                    ▼
┌──────────────────────────────────────────────────────────────┐
│ THE CARD                                                     │
│  · holds proofs + a secp256k1 key that NEVER leaves          │
│  · signs a 32-byte message on request                        │
│  · marks a slot SPENT before releasing the signature         │
│  · trusts nobody: it authorises, it does not authenticate    │
└──────────────────────────────────────────────────────────────┘
```

**The card trusts no one.** It does not verify that a terminal is a real
merchant, that a message is a real payment, or that a proof it is handed is
genuine. It does exactly one security-relevant thing: it will not produce a
second signature for a slot it has already marked spent.

**Assume the terminal is hostile.** It cannot forge proofs (it
lacks the mint's key) and it cannot spend a card's proofs elsewhere (they are
P2PK-locked to the card). It *can* refuse to settle, or lie to the customer
about the amount, which is ordinary merchant risk.

**The mint is trusted for solvency and nothing else.** Per-user signing keys
could tag users. [NUT-12 DLEQ](https://github.com/cashubtc/nuts/blob/main/12.md)
detects that, and `cashu-client` verifies it. Public reserve monitoring tracks
the risk of insolvency ([the reserve](https://forge.flashapp.me/reserves)).

## Division of labour: why the card does so little

The card **does not** do BDHKE. It never blinds, never unblinds, never talks to
a mint, and never sees a blinding factor. It stores proofs and it signs.

That is deliberate. JavaCard has no big-integer arithmetic, no `long`, and no
garbage collector; every byte of scratch space must be allocated once at install
time. Implementing blinding on-card would multiply the applet's size and its
attack surface. The blinding math is public, and the host must know `r` to
unblind.

So the split is:

| Concern | Where |
|---|---|
| Blinding, unblinding, denomination splitting | `cashu-client` (host) |
| Mint HTTP: quotes, mint, melt, swap, checkstate | `cashu-client` (host) |
| DLEQ verification | `cashu-client` (host) |
| Proof storage, slot lifecycle; from software 1.20 also the mint's DLEQ proof kept with each piece, which the applet stores and gives back and never checks | **Applet** |
| The private key, and BIP-340 signing | **Applet** |
| Single-spend enforcement (on-card) | **Applet** |
| APDU transport | `cardctl` (host) |

The card holds the one thing that cannot live anywhere else: **a private key
that has never existed outside the secure element.**

## On-card data model

Each proof occupies exactly 78 bytes of EEPROM:

```
Offset  Size  Field
0       1     status (0=empty, 1=unspent, 2=spent)
1       8     keyset_id (the NUT-02 keyset id as 8 RAW bytes = 16 hex chars)
9       4     amount (uint32, big-endian, in the keyset's base unit)
13      32    nonce (the 32-byte nonce from the NUT-10 P2PK secret)
45      33    C (compressed secp256k1 point representing the mint's unblinded signature)
```

Two fields here are easy to get wrong, and both make proofs unspendable:

- **`keyset_id` is raw bytes, not ASCII.** A NUT-02 keyset id is 16 hex
  characters. Stored raw it is exactly 8 bytes; stored as ASCII text only the
  first 8 hex characters fit, which is half an id and matches no keyset at the
  mint.
- **The 32 bytes are the *nonce*, not the secret.** A NUT-10 P2PK secret is a
  JSON string of roughly 150 bytes and cannot fit in a proof slot. The card
  stores only the nonce; a reader rebuilds the full secret from the nonce plus
  the card's public key. See NUT-CCP,
  [*The stored form*](https://github.com/cashucard/nut/blob/main/CCP.md#the-stored-form).

Protocol 2.0: 128 slots × 82 bytes (the 78 above and a 4-byte date) = **10,496
bytes** of proof storage, 130 bytes a slot more of the hex text a payment hashes,
and, reserved by the first `SET_CARD`, 96 bytes a slot for the mint's DLEQ proof.
The `amount` unit follows the keyset: sats for a `sat` keyset and cents for `usd`.

`MAX_PROOFS = 128` limits both the implementation and the balance a card can
hold. A Cashu balance is split into powers of two, so 128 slots comfortably holds a
useful balance but is not unlimited. `cashu-client`'s `splitIntoDenominations`
takes a `maxSlots` argument for exactly this reason.

## Key management

- The card keypair is generated **at install time**, on-card, via
  `KeyPair.genKeyPair()`.
- JavaCard keeps the private key in protected key storage. The applet never
  copies it into a `byte[]` or exports it through an APDU.
- `GET_PUBKEY` returns the 33-byte compressed public key. That is the card's
  identity and the key proofs are locked to.
- For [NUT-11](https://github.com/cashubtc/nuts/blob/main/11.md), the
  provisioning host puts this key in each proof's P2PK secret, so the mint will
  only redeem those proofs against a signature from this card.

**Consequence:** a card is unrecoverable by design. There is no seed, no backup,
no derivation path. Destroy the card and the key is gone, and with it any proofs
locked to it. See [`DECISIONS.md`](DECISIONS.md#d5) for why BIP-39 was rejected
and what the open alternative is.

## Spend protection

A 2.0 payment (`SPEND_ALL_SIGN`) signs in RAM, then commits one byte that burns
every place it names (with the day's count, the log and the signature kept for
`SPEND_ALL_AGAIN`), and only then answers; the places' status bytes are marked
after the commit, or at the next command if the card left the field. The card
exposes no command to reset a slot to unspent. `CLEAR_SPENT` zeroes
already-spent slots to reclaim space; it does not undo a spend.

Two honest caveats:

1. **This is a status byte, not a counter.** Earlier documentation called it a
   "non-resettable hardware spend counter", which overstates it.
2. **Tear-off is analysed, not yet tested on hardware.** No slot write is
   wrapped in a `JCSystem` transaction. Every slot write changes the data first
   and the status byte last ([D14](DECISIONS.md#d14)), and every write outside a
   transaction is reviewed in [D23](DECISIONS.md#d23). A card pulled as a
   payment's answer is on the air has burned the places and kept the signature:
   the terminal asks again with `SPEND_ALL_AGAIN`. No card has been pulled
   mid-write on purpose: see [`SECURITY-MODEL.md`](SECURITY-MODEL.md) #11.

## The two flows

### Loading a card (online)

```
1. cashu-client: requestMintQuote(mint, amount, unit)     → bolt11 invoice
2. (pay the invoice by any means)
3. wallet: split the amount into powers of two            → [64, 16, 4, …]
4. wallet: blind each format-4 secret, SIG_ALL, locked to the CARD's key
                 ↳ NUT-CCP, "Card proofs"
5. wallet: mint                                             → blind signatures with DLEQ
6. wallet: unblind, check the DLEQ                          → offline check
7. owner's phone: GET_NONCE, ALLOW_LOAD, LOAD_PROOF (P1 = 1) × n
                                                             → written to slots with the mint's proof
```

Step 4 is the pivot: the host locks each proof to a key it does not control.
From that moment the proof is only spendable by that card.

### Spending at a terminal

```
1. terminal: SET_HEADER (the tip), GET_INFO, GET_PIECES, GET_DLEQ, AUTH
                                                  → the card, its pieces checked offline
2. terminal: pick pieces, make the swap's outputs
3. card:     SPEND_ALL_BEGIN / OUTPUTS / CHANGE   → the card makes its own change outputs
4. card:     SPEND_ALL_SIGN (VERIFY_PIN first unless the allowance covers it)
                                                  → every place burned, one SIG_ALL signature
5. terminal: swap at the mint, the signature as the first input's witness
6. terminal: unblind the change, LOAD_PROOF it back (the tap after a payment needs no PIN)
```

Step 4 is the whole reason the card exists: the signature that unlocks the
pieces can only be produced by the chip, and only for the swap it was shown.

The ordering hazard is that **the card burns its places at step 4, before the mint
accepts anything at step 5.** That asymmetry is why `cashu-client` refuses
locally rather than optimistically submitting; see
[`DECISIONS.md`](DECISIONS.md#d7).

## Hardware floor

**JavaCard 3.0.5 or later is mandatory:** the Schnorr signer computes
`k·G` with `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`, a constant that **does not
exist in the 3.0.4 API**. Verified directly against the SDK jars. JCOP3, J3H145
and Feitian 3.0.4 parts cannot run this applet at all.

The card must also be **dual-interface** (contactless ISO/IEC 14443-4 for taps,
contact ISO/IEC 7816 for reliable applet loading) and supplied **unlocked**, with
known GlobalPlatform keys, or the applet can never be installed.

## Where to go next

| You want to… | Read |
|---|---|
| Understand a specific design call | [`DECISIONS.md`](DECISIONS.md) |
| Know what an attacker can do | [`SECURITY-MODEL.md`](SECURITY-MODEL.md) |
| Talk to a card | [`../tools/cardctl/README.md`](../tools/cardctl/README.md) |
| Load the applet onto silicon | [`HARDWARE_DEPLOYMENT.md`](HARDWARE_DEPLOYMENT.md) |
| Read the wire protocol | [`../spec/APDU.md`](../spec/APDU.md) |
| Read the protocol spec | [NUT-CCP](https://github.com/cashucard/nut/blob/main/CCP.md) |
| Look up a term | [`GLOSSARY.md`](GLOSSARY.md) |
