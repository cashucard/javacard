<a id="vision--why-a-cashu-bearer-card-exists"></a>

# Cashu bearer card vision

> **Historical design:** this page describes the early Cashu Card product and
> applet profile. See the [current Cashu Card guide](https://github.com/cashucard/cashucard#readme)
> for current product scope and supported workflows.

> **Read this first.** The rest of the documentation explains *how* the system
> works. This explains why it is shaped the way it is, and why several obvious
> alternatives were rejected. If you are about to propose a change that makes
> the card more like a debit card, the answer is probably here.

## The one-sentence version

**A physical card that holds Bitcoin-denominated ecash on its chip and pays by
tapping at the point of sale. The terminal settles the payment when it reconnects
to the mint. The card is worth exactly what it holds.**

## The problem this is for

Flash operates in the Caribbean. Three constraints shape everything:

**Connectivity is not a given.** A Lightning payment needs both parties online
at the moment of payment. Checkout connectivity fails often enough to affect
payments. Merchants need a payment method that remains usable during those gaps.

**Not every user wants an account.** Onboarding a person into a custodial wallet
means KYC, a phone that can run the app, a phone number that survives, and a
recovery story they will not follow. For a tourist buying a coconut, or someone
paid in cash who wants to hold value in Bitcoin, that is an enormous amount of
ceremony for a small transaction.

**Custody is a liability.** Flash currently holds customer funds. That carries
regulatory weight, operational risk, and a permanent obligation. This project
demonstrated that when the mint backing our ecash was found insolvent and had
to be re-funded. Every product that moves value *off* Flash's books and into the
user's own possession reduces that exposure.

A bearer card answers all three at once. It works offline because the value is
already on the card. It needs no account because it *is* the account. Flash
cannot spend the value on someone's card because Flash does not hold the key
that authorises it.

## What "bearer" actually means here

The bearer model needs a clear description:

**Whoever physically holds the card controls the funds on it.** The card carries
no cardholder name or number. The base profile lets the holder spend by
possession; it provides no remote freeze or recovery. Losing the card means
losing its funds, as with a banknote.

The bearer model is a deliberate product choice. The card is *cash*, and cash
has these properties. Each one is also a design constraint
that shows up later in the architecture: the applet is small because a bearer
instrument should be auditable; there is no personalisation because a card that
identifies you is not cash; the physical card carries a plain-language
disclaimer so holders understand the bearer model.

The Flash app provides a separate account-based option with recovery, freezing
and an identity.

## What this replaces

**[FIP-04: Flash BTCPayServer Plugin](https://github.com/lnflash/fips): implemented.** *(FIPs are internal to Flash; the repository is private.)*

The previous generation of Flash cards were **BoltCards**: NTAG 424 DNA tags
carrying an AES key, which authenticate a *server-side* balance over a
BTCPayServer plugin. That design works, and it shipped. It also has three
properties this project rejects:

| | BoltCard (FIP-04) | Cashu bearer card |
|---|---|---|
| Where the value lives | Server-side balance | **On the card's chip** |
| Works offline at POS | ✗: the terminal must reach the server | **✓** |
| Custody | Flash holds the funds | **The holder does** |
| Cryptographic operations on card | AES-128 CMAC (authentication) | **secp256k1 / BIP-340 (authorisation)** |

The BoltCard proves *who is tapping*. Cashu Card payments carry mint-issued
proofs locked to the card's spending key and a signature over the swap. A reader
can validate each proof's mint signature offline with its DLEQ data. The mint
confirms redemption and spent status when the terminal settles online.
`btcpayserver-flash-plugin` is being decommissioned (ENG-176).

## Why Cashu specifically

Cashu ecash gives three properties that together are unusual:

1. **Proofs are bearer tokens.** A Cashu proof carries the mint's blind
   signature and can be verified by arithmetic, offline.
2. **It is small enough to fit.** A proof is 78 bytes in our on-card layout. A
   32-slot card holds a useful balance in ~2.5 KB of EEPROM, well within a
   JavaCard's budget.
3. **[NUT-11 P2PK](https://github.com/cashubtc/nuts/blob/main/11.md) locks a
   proof to a public key.** This is the load-bearing piece: proofs are locked to
   a key that exists only inside the card's secure element and is never
   exported. Copying the data off a card gets you proofs you cannot spend.

That third property is what makes a bearer *card* possible rather than merely a
bearer *token*. Without it, reading a card's memory would be equivalent to
stealing its balance.

## The honest trade: offline double-spend

The card marks a proof `SPENT` before it releases a signature, and nothing in
the APDU set can unmark it. That stops *the card* from spending the same proof
twice.

An attacker with copied proof data can redeem it at the mint while the card
still believes it is unspent. **An
offline merchant cannot detect this.** Only the mint knows what has been melted.

Every offline bearer instrument has this property. Physical cash uses
anti-counterfeiting. For Cashu Card, the mint is the final authority and
rejects the second redemption, terminals settle promptly when they regain
connectivity, and cards hold small balances. Anyone claiming this design has
"zero double-spend risk" would be making an inaccurate claim; one of the
documentation contributions to this repo made that claim.

## Where this sits in Flash

```
Flash app (custodial, online, KYC'd)     ← accounts, Lightning, USD, cash-out
        │
        │  top up a card
        ▼
Flash Card (bearer, offline-capable)     ← this project
        │
        │  tap to pay
        ▼
Merchant terminal → mint redemption      ← settles back into the Flash rails
```

The card complements the app with small offline payments and low-friction
onboarding.

Related internal proposals for the surrounding context:
**FIP-05** (MonCash cross-border), **FIP-06** (phone-number Bitcoin sends):
both are about reaching people the app cannot, which is the same motivation.

<a id="status-the-milestone-is-behind-us--scale-is-ahead"></a>

## Status as of September 2026

The milestone this document set, *the first real signature off a JavaCard
3.0.5 chip*, has happened. As of this writing:

- The applet **runs on physical silicon** (NXP JCOP4 J3R180): selftest 10/10,
  and every command the applet advertises except `LOCK_CARD` has executed on
  hardware. Three bugs the simulator could not show were found and fixed on
  silicon, including a 65-byte `GET_PUBKEY` that would have failed every
  merchant reader in the field.
- **The whole money loop has run end to end**: fund → load → tap-to-spend →
  NUT-03 redemption → NUT-05 Lightning melt, twice over, against a live mint,
  and then again from the merchant terminal: `flash-pos` spent a real card
  over phone NFC and settled it at the mint (see the
  [hardware test report](HARDWARE_TEST_REPORT_2026-09-22.j3r180.md)).
- The settlement queue, spend orchestrator, and payout melt are implemented in
  `flash-pos` against the production mint.
- What is **still ahead**: the backend sweep that credits merchant balances
  from settled proofs, fleet provisioning, key-rotation policy, and the
  remaining PIN/top-up surface in the terminal.

The next milestone for this project is **a second card**. Everything above was proven
with one card, one reader and one phone.

## What would make this project fail

Worth naming, so contributors can push back early:

1. **Nobody builds the terminal.** Without a merchant-side reader, this is a
   card that can be loaded and never spent in the real world.
2. **The bearer model gets softened into a debit card.** Adding names, freezes
   and recovery re-introduces custody and the reason to exist evaporates.
3. **The mint stays fragile.** A bearer card is only as good as the mint that
   honours its proofs. See [`docs/SECURITY-MODEL.md`](SECURITY-MODEL.md).
4. **Hardware reality bites.** Chip position, EEPROM budget, module supply and
   card cost are all still unproven at volume.

---

**Next:** [`ARCHITECTURE.md`](ARCHITECTURE.md) for how the pieces fit together,
or [`DECISIONS.md`](DECISIONS.md) for the specific calls and their reasoning.
