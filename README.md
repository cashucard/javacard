# cashu-javacard

> **Historical implementation snapshot:** the hardware and integration status
> in this repository reflects an earlier milestone. See the [current Cashu Card
> guide](https://github.com/cashucard/cashucard#readme) for current behavior and
> deployment guidance.

A JavaCard applet implementing the [Cashu](https://cashu.space) ecash protocol
for NFC bearer payments. A physical card holds Bitcoin-denominated ecash on its
chip. Its holder pays by tapping the card; a merchant can accept payment offline
and settle with the mint when online.

This is the **shared Cashu card protocol, version 2.1**: one wire for Flash and
for the [Foxy](https://github.com/getfoxy/iOS) wallet. Reference implementation
of **NUT-CCP: Cashu Card Protocol**, the draft NUT in [cashucard/nut](https://github.com/cashucard/nut).

> ### Credit
>
> 2.0 is the Foxy wallet project's fork, [getfoxy/card](https://github.com/getfoxy/card)
> at software 1.20, merged back here with its history ([D18](docs/DECISIONS.md#d18)).
> Their review of our applet 0.4 ([`docs/FOR-LNFLASH.md`](docs/FOR-LNFLASH.md))
> found that it signed a hash the reader chose and could sign anything without
> burning a slot; their applet fixes both, and adds the owner key, the daily limit
> on a clock of Bitcoin block headers, one `SIG_ALL` signature per payment with the
> card's own change, and the mint's DLEQ proof kept with each piece. On top of it,
> 2.0 has a neutral identity ([D19](docs/DECISIONS.md#d19)) and our fixes
> ([D20](docs/DECISIONS.md#d20) to [D24](docs/DECISIONS.md#d24)).

> ### Status: 2.0 proven in simulation; 1.20 has run on one card
>
> Foxy's 1.20 has run on one NXP JCOP4 J3R180 with the Foxy iPhone app: installed,
> set up, loaded, paid from with change written back. Our 0.x applet ran the full
> money loop on a J3R180 against `forge.flashapp.me` (the
> [hardware test report](docs/HARDWARE_TEST_REPORT_2026-09-22.j3r180.md)). The 2.0
> build has run under jCardSim, through the bridge, and in a real `SIG_ALL` swap at
> a Nutshell 0.20.3 mint in CI; it has **not** yet been installed on silicon (its
> load file is a size the J3R180 has not been tried at:
> [`docs/HARDWARE_DEPLOYMENT.md`](docs/HARDWARE_DEPLOYMENT.md)). Read
> [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) before trusting anything here
> with real money at scale.

## Start here

| You are… | Read, in order |
|---|---|
| **Curious what this is** | [`docs/VISION.md`](docs/VISION.md) |
| **A developer joining the project** | [`VISION`](docs/VISION.md) → [`ARCHITECTURE`](docs/ARCHITECTURE.md) → [`DECISIONS`](docs/DECISIONS.md) → [`CONTRIBUTING`](CONTRIBUTING.md) |
| **Implementing a reader or wallet** | [NUT-CCP](https://github.com/cashucard/nut/blob/main/CCP.md) → [`spec/APDU.md`](spec/APDU.md) → [`spec/vectors/`](spec/vectors/) |
| **Reading the design in full** | [`docs/FOXY-CARD-SPEC.md`](docs/FOXY-CARD-SPEC.md) and [`docs/FOXY-CARD-DAILY-LIMIT.md`](docs/FOXY-CARD-DAILY-LIMIT.md) |
| **An AI agent working in this repo** | [`ARCHITECTURE`](docs/ARCHITECTURE.md) → [`DECISIONS`](docs/DECISIONS.md) → [`GLOSSARY`](docs/GLOSSARY.md). The decisions file exists so settled calls are not re-litigated. |
| **Auditing security** | [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) |
| **Holding a card and a reader** | [`tools/cardctl/README.md`](tools/cardctl/README.md), then [`docs/HARDWARE_DEPLOYMENT.md`](docs/HARDWARE_DEPLOYMENT.md) |
| **Testing an app without a card** | [Card simulator](#card-simulator) |

## What the card does

- **Holds pieces:** up to 128 slots of 82 bytes, with keyset, amount, the P2PK nonce,
  `C`, and a date. Every piece is a format-4 secret locked to the card's key with
  `SIG_ALL` (NUT-11); the card rebuilds the secret itself, so nothing a reader
  sends is ever what it signs.
- **Holds a secp256k1 key** generated on-card at install, never exported.
- **Pays with one signature:** `SPEND_ALL_*` names the places, a till's outputs, the
  card's own change (locked to its own key), then one BIP-340 signature over the
  NUT-11 `SIG_ALL` message, with every place burned in the commit that releases it.
- **Proves itself:** `AUTH` signs a tagged hash of the reader's and the card's
  random bytes; it cannot be a spend.
- **Has an owner:** a P-256 key on the holder's phone, whose ECDSA proofs (labels
  `CashuCard/…`) change the PIN, the limits, the record and the owner, add funds
  with no PIN, and refresh the card. A blocked PIN is unblocked by the owner.
- **Bounds a terminal:** a daily limit, a limit on one payment and a no-PIN
  allowance, counted against a clock that is the newest Bitcoin block header the
  card has been shown, with a rollover budget between the owner's refreshes
  ([D20](docs/DECISIONS.md#d20)).
- **Keeps the mint's DLEQ proof** beside each piece, for a reader to check offline.
- **Answers as an NFC tag** carrying one web address, which its owner can switch off.

The host handles BDHKE beyond making the card's change outputs, mint
communication, and checks of the DLEQ proofs the card keeps. See
[D3](docs/DECISIONS.md#d3).

**AID:** package `F0 43 41 53 48 55 43 41 52 44` ("CASHUCARD"), applet `…44 01`.
A reader selects the applet's whole AID, `F0 43 41 53 48 55 43 41 52 44 01`, and
`SELECT` answers `02 01`; the package AID alone reaches the opener on a chip
([D25](docs/DECISIONS.md#d25)). A card on the 0.x AID (`D2 76 00 00 85 01 02`) or Foxy's
1.x AID answers nothing to it: it needs an update.

## Supported hardware

| Chip | Status | Notes |
|---|---|---|
| NXP JCOP4 (SmartMX3, J3R180) | ✅ Target | JavaCard 3.0.5, CC EAL 5+ |
| Feitian / JCOP3 JavaCard 3.0.4 | ❌ | Requires `ALG_EC_SVDP_DH_PLAIN_XY`, available in 3.0.5+ |
| NXP NTAG 424 DNA | ❌ | Lacks the EC operations this applet requires; used by BoltCard |

**JavaCard 3.0.5 or later is a hard requirement** ([D6](docs/DECISIONS.md#d6)).
The card must also be supplied **unlocked** (known GlobalPlatform keys), and its
manager keys rotated before it is handed to a person.

## Build

Requires **JDK 11+**, Apache Ant, Python 3 and a JavaCard SDK **3.0.5 or later**.
The SDK is not downloaded for you:

```bash
git clone https://github.com/martinpaljak/oracle_javacard_sdks ~/.javacard/sdks

ant -f applet/build.xml cap
# → applet/target/cashu-javacard-2.1.0.cap   (three applets: the opener, the card's, then the NFC tag)
```

The build strips the Descriptor component and checks the load file's size against
what the J3R180 has installed (`tools/stripcap.py`, `tools/refcheck.py`;
[`docs/FOXY-CARD-HARDWARE.md`](docs/FOXY-CARD-HARDWARE.md)). Installing onto a
card: [`docs/HARDWARE_DEPLOYMENT.md`](docs/HARDWARE_DEPLOYMENT.md).

## Test

```bash
mvn -f applet/pom.xml test           # applet, jCardSim, no hardware needed
mvn -f tools/cardsim/pom.xml package # card simulator bridge, its suite, and the jar
node --test 'tools/**/*.test.cjs'    # client and Cashu arithmetic (bridge and mint cases skip)
cd tools/cardctl && for t in test_bip340 test_p256 test_apdu test_spec_consistency test_card_file test_hwtest_65byte_pubkey; do python3 $t.py; done
```

CI runs all of it on every push, plus the bridge's client cases against the jar
and a `SIG_ALL` swap at two Nutshell 0.20.3 mints (forge's shape, an 8-byte
keyset id with no fee, and a fresh v2 keyset, 33 bytes with a fee), and checks the tracked CAP is built
from this source. jCardSim runs on a JVM with a garbage collector, so it cannot
reproduce EEPROM exhaustion, torn writes or hardware cryptographic framing. Hardware
reports provide silicon evidence. See [D10](docs/DECISIONS.md#d10).

## Card simulator

`tools/cardsim/` serves the real applet, inside jCardSim, on
`http://127.0.0.1:9876` so an app's fake NFC transport can run end-to-end tests
on a simulator or emulator without a reader:

```bash
tools/cardsim/cardsim.sh                               # from source, via Maven
mvn -B -f tools/cardsim/pom.xml package && java -jar tools/cardsim/target/cardsim.jar
curl -s -X POST localhost:9876/apdu -d '{"hex":"00A404000BF043415348554341524401"}'   # {"hex":"02019000","sw":"9000"}
```

Endpoints: `POST /apdu` (raw bytes in, data‖SW out, never retried), `POST /reset`
(a brand-new card), `POST /fixture` (PIN, record, the deterministic test owner,
anchor and headers, format-4 pieces with dates and DLEQ, spent slots, limits with
the rollover budget, a blocked PIN), `GET /state`. `tools/cardsim/client.cjs` is a
zero-dependency Node client with the 2.0 command set and the owner's proofs, and
`tools/cardsim/cashu-crypto.cjs` the Cashu arithmetic a test needs. Two things a
loader has to know: SELECT starts a session, as a tap does; and the simulator's
card key is the same after every `/reset`, so mint pieces per run. The header of
`tools/cardsim/src/main/java/me/flashapp/cashu/cardsim/CardSim.java` is the
contract that flash-pos and flash-mobile pin.

Foxy's own simulator for its iOS build (`tools/cardsim/run.sh`, a line protocol on
port 47431) is kept beside it.

## Project layout

```
applet/src/main/java/   applet source (JavaCard 3.0.5+): CashuApplet, SchnorrHW, Opener, Tag
applet/src/test/java/   jCardSim test suite
tools/cardctl/          PC/SC host driver (2.0) + its own tests
tools/cardsim/          jCardSim card over localhost HTTP for app e2e, its client and e2e
tools/chip/             Foxy's bench scripts for a card on a reader
spec/                   APDU.md (wire format and profiles), vectors/,
                        CARD-FILE.md (0.x host↔mint interchange format)
docs/                   vision, architecture, decisions, security, glossary, Foxy's design
```

## Spec

The protocol's core is NUT-CCP, a draft NUT in [cashucard/nut](https://github.com/cashucard/nut),
written to be proposed to [cashubtc/nuts](https://github.com/cashubtc/nuts). A
change to the core starts there. [`spec/APDU.md`](spec/APDU.md) gives every
command byte for byte, with the profiles NUT-CCP leaves to implementations: the
owner, the clock and the limits, and the NFC tag. `spec/` is a copy of
[cashucard/cashucard](https://github.com/cashucard/cashucard)'s, made after each
spec change merges there.

## Related

- [getfoxy/card](https://github.com/getfoxy/card), Foxy's fork, the base of 2.0
- [cashu-client](https://github.com/cashucard/client), mint protocol, BDHKE, witnesses, DLEQ
- [flash-card-assets](https://github.com/lnflash/flash-card-assets), print-ready physical card design
- [forge.flashapp.me](https://forge.flashapp.me), the Flash Cashu mint ([reserves](https://forge.flashapp.me/reserves))
- [cashubtc/nuts](https://github.com/cashubtc/nuts), the Cashu specifications

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`docs/DECISIONS.md`](docs/DECISIONS.md) first; most of what looks like a
missing feature is a decision with reasoning behind it. A change to the wire is a
change to Foxy's too: agree it with them.

## License

MIT
