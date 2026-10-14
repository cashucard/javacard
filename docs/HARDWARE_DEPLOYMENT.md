# Hardware Deployment Guide

GlobalPlatform packaging and deployment for the Cashu card applet, protocol 2.1
([D18](DECISIONS.md#d18), [D19](DECISIONS.md#d19), [D26](DECISIONS.md#d26)).

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Java | 11+ | `brew install openjdk@17` |
| Apache Ant | 1.10+ | `brew install ant` |
| GlobalPlatformPro (gp) | 20.01.23+ | See below |
| JavaCard SDK | 3.0.5+ (`jc305u4_kit`) | See [Build the .cap file](#build-the-cap-file) |
| Python 3 | 3.9+ | for `tools/stripcap.py` and `tools/refcheck.py`, which the build runs |
| Physical card | NXP JCOP4 SmartMX3 (JavaCard 3.0.5+) | **Not** JavaCard 3.0.4 — see [Supported targets](#supported-targets) |
| PC/SC reader | Any ISO 7816-4 reader | `brew install pcsc-lite` |

### Install GlobalPlatformPro

```bash
# Download gp.jar
curl -L https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar \
     -o /usr/local/bin/gp.jar

# Create wrapper script
cat > /usr/local/bin/gp << 'EOF'
#!/bin/sh
exec java -jar /usr/local/bin/gp.jar "$@"
EOF
chmod +x /usr/local/bin/gp
```

---

## Build the .cap file

ant-javacard does **not** download JavaCard SDKs — you have to supply the kit
yourself and point `jc.sdk` at it. One clone covers every SDK version:

```bash
# One-time: fetch the JavaCard SDK kits (~200 MB, all versions)
git clone https://github.com/martinpaljak/oracle_javacard_sdks ~/.javacard/sdks
```

```bash
cd cashu-javacard/applet

# Build. jc.sdk defaults to ~/.javacard/sdks/jc305u4_kit; override if you
# cloned elsewhere. It must be a 3.0.5 (or later) kit — see below.
ant cap
ant cap -Djc.sdk=/path/to/jc305u4_kit   # explicit form

# Output: target/cashu-javacard-2.1.0.cap, one file with three applets in it: the opener, the card's, and the NFC tag
ls -lh target/cashu-javacard-2.1.0.cap
```

The build then takes the Descriptor component out (`tools/stripcap.py`: the chip
keeps nothing of it) and checks the load file's size against what the J3R180 has
been seen to install (`tools/refcheck.py`, from
[FOXY-CARD-HARDWARE.md](FOXY-CARD-HARDWARE.md)). The 2.1 build is **20,068 bytes**
by refcheck's measure (100 past a multiple of 256). It installed on a J3R180 with
the opener first, in the three steps below, on 2026-10-14, and refcheck's table has
it as a size that installs ([D26](DECISIONS.md#d26),
[the report](HARDWARE_TEST_REPORT_2026-10-14.j3r180-2.1.md)). The 2.0 build was 20,060 bytes;
v2.0.0-rc.1 (sha256 `59f66673…`) installed on the J3R180 with the opener first, at
20,057 bytes as the install counted the load file, and refcheck's table has it as a
size that installs ([D25](DECISIONS.md#d25)).
If a later build lands on a size the chip refuses, move it with
`CashuApplet.sizeTheFile` to a size known to install and add the answer to
refcheck's table.

> **Three applets, installed in order.** The chip refuses the card's applet as the
> first instantiated from its package (no answer, or `6F00`); it takes it once a
> small applet has been instantiated before it. So the file lists `Opener` first,
> and the install is three commands (below): the opener, the card's applet, and the
> NFC tag, which is `Tag`, listed last and made under the NFC Forum's own name,
> `D2760000850101`, given as the instance AID. Measurements and the rest of what
> the chip has room for: [FOXY-CARD-HARDWARE.md](FOXY-CARD-HARDWARE.md).

> **The mint's proofs are reserved after install.** The 12,288 bytes that hold
> them are not made at install: the chip would refuse the card's applet if its
> constructor asked for them. The first `SET_CARD` reserves them. A card that is
> refused them is set up all the same and works as a card with no room for proofs.

> **3.0.5 is a hard floor.** `SchnorrHW` performs the `k·G` scalar multiply with
> `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`, which was introduced in JavaCard 3.0.5
> and does not exist in 3.0.4. A 3.0.4 kit cannot convert this applet, and a
> 3.0.4 card cannot run it.

---

## Connect and verify card

```bash
# Insert card into reader, then:
gp --list

# Expected output (fresh card):
# ISD: A000000151000000 (OP_READY)
```

---

## Install

The CAP tracked in this repo is **applet version 2.1**, sha256
`f27d92ba99581f4e42abda0efc038b2c31128f9b405bcec6de52f6a12ae4c7e5`
(`applet/target/cashu-javacard-2.1.0.cap`). A CAP you build yourself hashes
differently even from identical source, because the converter writes a creation
timestamp into `META-INF/MANIFEST.MF`. Every other entry is byte-identical when
built with JDK 17 and the kit CI pins (`jc305u4_kit` at `oracle_javacard_sdks`
commit `6a75ec0d`), and CI checks exactly that on every push. So before
installing your own build, compare every entry except `META-INF/MANIFEST.MF`
against the tracked CAP:

```bash
# From applet/, after `ant cap` has overwritten target/cashu-javacard-2.1.0.cap
git show HEAD:applet/target/cashu-javacard-2.1.0.cap > /tmp/tracked.cap
rm -rf /tmp/cap-tracked /tmp/cap-built
unzip -q /tmp/tracked.cap -d /tmp/cap-tracked
unzip -q target/cashu-javacard-2.1.0.cap -d /tmp/cap-built
diff -r -x MANIFEST.MF /tmp/cap-tracked /tmp/cap-built && echo "same CAP as the tracked one"
```

Any output from `diff` means the two CAPs differ; do not install. After
installing, `SELECT` must answer `02 01` for the card's applet's whole AID (below).

```bash
# Load the file and instantiate the opener (gp installs one applet of a file at a time)...
gp --install target/cashu-javacard-2.1.0.cap --applet F04341534855434152444D
# ...then create the card's applet from the loaded package
gp --create F043415348554341524401 --package F0434153485543415244 --applet F043415348554341524401
# ...then the NFC tag, under the NFC Forum's own name as its instance AID
gp --create D2760000850101 --package F0434153485543415244 --applet F043415348554341524454

# Verify installation
gp --list
# Expected (among the rest):
#   APP: F04341534855434152444D (SELECTABLE)   ← the opener
#   APP: F043415348554341524401 (SELECTABLE)   ← the card's applet
#   APP: D2760000850101 (SELECTABLE)           ← the tag

# The tag, read as a phone reads it: its name, the capability container (15 bytes), the NDEF file (2, then 20 bytes)
gp -d -a 00A4040007D2760000850101 -a 00A4000C02E103 -a 00B000000F -a 00A4000C02E104 -a 00B0000002 -a 00B0000214
# Expected: 9000 / 9000 / 000F20003B00340406E104001600FF 9000 / 9000 / 0014 9000 / D101105504 + "getfoxy.io/card" 9000
```

### Setting a card up

A card straight from the install has no PIN, no record and no owner: it holds
nothing and cannot be loaded, and any reader in range can set it up. Set it up
before it leaves your hands, owner last, with the tip block header as the
anchor ([D20](DECISIONS.md#d20)):

```bash
cd tools/cardctl
python3 cardctl.py set-pin 1234
python3 cardctl.py verify-pin 1234
python3 cardctl.py set-card --mint https://forge.flashapp.me
python3 cardctl.py set-owner --owner-key <32-byte hex> --anchor <the tip header, 80 bytes hex>
python3 cardctl.py set-limit --owner-key <…> --day 50000 --payment 0 --allowance 0 --budget 7
python3 cardctl.py selftest
```

Without `--owner-key` cardctl signs with its TEST key, which anyone with this
repository holds: bench cards only. A card handed to a person is owned by the
holder's phone (flash-mobile's "Set up this card").

---

## Test install / select / deselect lifecycle

```bash
# SELECT the card's applet by its whole AID, F0 CASHUCARD 01
gp --apdu 00A404000BF043415348554341524401

# Response: 0201 9000  (applet version 2.1 + SW_OK = applet responding)
# A card that answers 6A82 has no 2.x applet: it is a 0.x or Foxy 1.x card and needs an update.
# Do not SELECT the package AID alone (00A404000AF0434153485543415244): on the chip that
# partial name reaches the opener, instantiated first, which answers 9000 with no version
# and 6D00 to every command after it (D25).

# GET_INFO (INS 0x01)
gp --apdu B0010000

# Response: 02 01 80 00 00 80 FF 00 04 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#   v2.1 | 128 slots | 0 unspent | 0 spent | 128 empty | caps=FF | PIN none | format 4 | 3 tries | not locked | no record | no limit | no owner | no clock | no window | 0 spent | no change grant
# SW: 9000

# GET_PUBKEY (INS 0x10)
gp --apdu B0100000

# Response: 33-byte compressed secp256k1 public key + SW 9000
```

`cardctl selftest` passes a card answering `02 01` (or a later 2.x) and fails any
other: a card on v2.0.0 is swept and reinstalled ([D26](DECISIONS.md#d26)). cardctl
selects the whole AID first and takes a `9000` without a version as no answer.

**On the chip (ENG-681, 2026-10-13).** v2.0.0-rc.1 installed on the J3R180 in the
order above (the opener, then the card's applet, then the tag), at 20,057 bytes.
`SELECT` of `F0 43 41 53 48 55 43 41 52 44 01` answered `02 00 9000`; `SELECT` of the
package AID `F0 43 41 53 48 55 43 41 52 44` answered `9000` with no body, and the next
command `6D00`: the opener. `cardctl selftest` passed 12 of 12 once it selected the
whole AID first, and `AUTH` took 833 to 854 ms a signature on an ACR122U (0.4 took
814 ms; the constant-time multiply of [D21](DECISIONS.md#d21) costs about 3%).

---

## Reinstall (delete + install)

```bash
# Delete the tag, the card's applet, the opener, then the package (that order)
gp --delete D2760000850101           # the tag
gp --delete F043415348554341524401   # the card's applet
gp --delete F04341534855434152444D   # the opener
gp --delete F0434153485543415244     # the package

# Re-install: the opener first, the tag last
gp --install target/cashu-javacard-2.1.0.cap --applet F04341534855434152444D
gp --create F043415348554341524401 --package F0434153485543415244 --applet F043415348554341524401
gp --create D2760000850101 --package F0434153485543415244 --applet F043415348554341524454
```

The chip refuses to delete an instance that something still refers to, which is why the
instances go one by one and in this order, and why no static field of the package refers
to an object an applet instance made (`Tag` holds no reference to the card's applet; it
asks for a shareable interface at each selection and keeps nothing of it).

---

## Upgrade from 0.x, and the field-card sweep

There is no in-place upgrade: 2.0 is a new AID and a new wire, and a reinstall
makes a new card key. **Every piece on a card is P2PK-locked to its key, so a
card is swept before it is deleted.** The v0.2 reinstall on the J3R180 stranded
5 sat this way (see the [hardware test report](HARDWARE_TEST_REPORT_2026-09-22.j3r180.md)).

The 0.x applet is sunset ([D18](DECISIONS.md#d18)). Both apps drop it: a card
on the 0.x AID (`D2 76 00 00 85 01 02`, `SELECT` answers `00 0X`) or on Foxy's
1.x AID shows "This card needs an update", and neither app spends from it or
loads it.

**The one funded field card (operator-run, a release precondition for both
apps):**

1. With the **current** (0.x-speaking) app releases, before the 2.0 apps ship,
   spend the card's whole balance to an account the operator controls (a
   payment at the till, or the holder's withdraw), and check at the mint that
   the swap settled.
2. `python3 tools/cardctl/cardctl.py dump --mint <mint> --out field-card.json`
   (it selects the 0.x applet) as a record of what was on it; every slot should
   now be spent.
3. Delete the 0.x applet (`gp --delete D276000085010201`, then
   `gp --delete D2760000850102`), install 2.0 as above, and set the card up.
4. Record the date, the card's old and new keys and the swept amount here.

| Date | Card | Old key | New key | Swept | By |
|---|---|---|---|---|---|
| (pending) | J3R180 field card | | | | |

For production cards, use a secure messaging channel (SCP02/SCP03) and rotate the
card manager keys: a card left on its factory keys can have the applet deleted,
and the money with it, by anyone with a reader.

---

## Schnorr hardware path (SchnorrHW)

`SchnorrHW.java` implements BIP-340 using only `javacard.security.*`:

| Step | API used |
|------|----------|
| SHA-256 | `MessageDigest.ALG_SHA_256` |
| k·G scalar multiply | `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` |
| BIP-340 aux randomness | `RandomData.ALG_SECURE_RANDOM` |
| 256-bit mulModN | Schoolbook 256×256, no secret-dependent branch ([D21](DECISIONS.md#d21)), + 2-level DELTA reduction (which still branches: SECURITY-MODEL open item 5) |
| 256-bit addModN | Carry-propagation + conditional subtract (a secret-dependent branch: open item 5) |

DELTA = 2^256 mod n = `0x00...01 45512319 50B75FC4 402DA173 2FC9BEBF`

The signing operation allocates **nothing** at runtime. JavaCard Classic puts
`new` in persistent EEPROM/Flash and never collects it, so an allocation on the
signing path would leak a few hundred bytes per tap until the card ran out of
persistent memory and every payment threw. All scratch is allocated once at
install time as `CLEAR_ON_DESELECT` transient arrays, threaded through the
arithmetic helpers as explicit `(work, workOff)` parameters.

D21 changes the multiply's timing: re-measure `cardctl --timing selftest` (AUTH)
and a payment's `SPEND_ALL_SIGN` on the J3R180 before release. AUTH is measured
(ENG-681, above: 833 to 854 ms, about 3% over 0.4); `SPEND_ALL_SIGN` is still to be.

### Install-time ECDH framing probe

`ALG_EC_SVDP_DH_PLAIN_XY` output framing is not uniform across implementations:
the applet reads a 65-byte `04 ‖ X ‖ Y`, and some parts return the bare 64-byte
`X ‖ Y` instead. `SchnorrHW.init()` therefore performs one throwaway `2·G` at
install time and refuses to install if the framing is not what `sign()` indexes
into. If `gp --install` fails with `6F00`, that probe is the first thing to
suspect, after the size of the load file (above).

---

## Supported targets

| Card | JC API | Notes |
|------|--------|-------|
| NXP JCOP4 SmartMX3 P71 (J3R180) | 3.0.5 | ✅ Primary target; secp256k1 custom curve supported |
| Feitian JavaCard 3.0.4 | 3.0.4 | ❌ No `ALG_EC_SVDP_DH_PLAIN_XY` (3.0.5+ only) — the CAP will not convert or load |
| Generic JC 3.0.5+ | 3.0.5 | ⚠️  May work; verify custom EC-FP curve + `ALG_EC_SVDP_DH_PLAIN_XY` support |
| JavaCard ≤ 3.0.4 | ≤ 3.0.4 | ❌ No ECDH plain-XY |
| JavaCard 2.2.x | 2.2 | ❌ No `int` type; no ECDH plain-XY |

---

## AID reference

Protocol 2.0 ([D19](DECISIONS.md#d19)):

| Element | AID (hex) |
|---------|-----------|
| Package | `F0 43 41 53 48 55 43 41 52 44` |
| Opener (instantiated first, does nothing) | `F0 43 41 53 48 55 43 41 52 44 4D` |
| Card's applet | `F0 43 41 53 48 55 43 41 52 44 01` |
| Tag, class (listed last in the file) | `F0 43 41 53 48 55 43 41 52 44 54` |
| Tag, instance (the NFC Forum's NDEF Tag Application; what a phone selects) | `D2 76 00 00 85 01 01` |
| SELECT (the card's applet, whole: what a reader sends, [D25](DECISIONS.md#d25)) | `00 A4 04 00 0B F0 43 41 53 48 55 43 41 52 44 01` |
| SELECT of the package AID alone (reaches the opener on the chip: `90 00`, no version) | `00 A4 04 00 0A F0 43 41 53 48 55 43 41 52 44` |

Withdrawn, and answered `6A82` by a 2.0 card: the 0.x applet's
`D2 76 00 00 85 01 02` (package) and `D2 76 00 00 85 01 02 01` (applet), and
Foxy's 1.x `F0 46 4F 58 59 43 41 52 44`.
