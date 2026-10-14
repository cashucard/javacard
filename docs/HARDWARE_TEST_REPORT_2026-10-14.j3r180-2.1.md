# On-silicon test report: 2.1 on an NXP JCOP4 J3R180 (2026-10-14), parts A and A2

ENG-699. Mike Greff's review of getfoxy/iOS #2 found that the 2.x applet's
payments, its PIN commands and the commands new in 2.0 and 2.1 had never run on a
chip. This report is part A: the 2.1 load installs on a J3R180, and the commands
`cardctl` drives (the owner, the PIN, the limits and the rollover budget, the
clock, the record, `AUTH`) run on it, from a Mac through an ACR122U. Part B, the
payments, is flash-mobile and flash-pos on phones, later
([Not covered here](#not-covered-here-part-b)). Part A2, run the same day on the
same card with the owner's go-ahead, is the lock, a locked card's `REFRESH` and
`RESET_CARD`, from an unlocked card and from a locked one
([Part A2](#part-a2-lock-refresh-on-a-locked-card-reset)).

## Card

| Item | Value |
|---|---|
| Chip | NXP JCOP4 J3R180 P71, a spare (not the card of the 2026-09-22 report) |
| CPLC | ICFabricator `4790`, ICType `D321`, ICSerialNumber `09336320`, ICFabricationDate `3041` (2023-02-10) |
| GlobalPlatform | 2.3, ISD `A000000151000000` (OP_READY), default keys |
| Interface | contactless (ACR122U PICC) |

## Environment

| Item | Value |
|---|---|
| Reader | ACS ACR122U PICC Interface |
| Host | macOS 26.5 (aarch64), OpenJDK 17.0.19 |
| GlobalPlatformPro | v25.10.20 |
| Applet CAP | `applet/target/cashu-javacard-2.1.0.cap` at `3876a11`, sha256 `f27d92ba99581f4e42abda0efc038b2c31128f9b405bcec6de52f6a12ae4c7e5` |
| Load file | 20,068 bytes by refcheck's measure (100 past a multiple of 256) |
| Tool | `tools/cardctl` (its `Card` class, driven from a script for the steps that have no subcommand) |
| Headers | real mainnet headers from mempool.space, blocks 971,425, 971,428, 971,431 and 971,437 (`bits` `0x17021EF0`) |

## The install

The three steps of [HARDWARE_DEPLOYMENT.md](HARDWARE_DEPLOYMENT.md#install), the
opener first: `gp --install` of the file with the opener
(`F04341534855434152444D`), then `gp --create` of the card's applet
(`F043415348554341524401`) and of the NFC tag (`D2760000850101`). Each succeeded.
`gp --list` shows all three `SELECTABLE` and the package `F0434153485543415244`
`LOADED`. `SELECT` of the whole AID answers `02 01 90 00`, and `cardctl selftest`
passed 12 of 12 on the empty card.

So 20,068 bytes is a size the J3R180 installs, with the opener first.
`tools/refcheck.py` now lists it.

## Part A results

Every step ran on the card above. A status is the card's answer; a time is the
round trip through the ACR122U, reader included. "State after" is from
`GET_INFO` (P1 = 2) and `GET_CARD` read straight after.

### 1. Baseline

| Command | SW | Read |
|---|---|---|
| `GET_INFO`, `GET_CARD` | `9000` | v2.1, 128 slots empty, PIN none (3 tries), no owner, no record, not locked, `now` 0, no limits; `GET_CARD` 109 bytes, format `04`, every other byte 0 (rolls 0, budget byte 0 = the default 7, not armed) |

PASS.

### 2. `SET_OWNER`

| # | Command | Expected | SW | State after | Verdict |
|---|---|---|---|---|---|
| 2a | 145 bytes: the owner key and block 971,425's header with one nonce byte flipped (hash over its target, checked on the host first) | `6A93`, nothing written | `6A93` (93 ms) | no owner, `now` 0, bits 0 | PASS |
| 2b | 145 bytes: the owner key and block 971,425's header (the D20 anchor) | `9000`; owner set, the clock at the header, rolls 0 | `9000` (113 ms) | owner yes, `now` 1791993096 (block 971,425's time), last header `00…f4da9191…f397f6`, bits `F01E0217`, rolls 0 | PASS |
| 2c | 65 bytes on the now-owned card, no proof | `6A91` | `6A91` | unchanged | PASS |
| 2d | 65 bytes on the owned card with the old owner's proof (the same key again) | `9000` | `9000` | owner unchanged, `now` unchanged, allowance armed (an owner's proof arms it) | PASS |

The owner key is a fresh P-256 key made on the host for this card and kept off
the repository.

### 3. The PIN

| # | Command | Expected | SW | State after | Verdict |
|---|---|---|---|---|---|
| 3a | `ALLOW_LOAD` (owner's proof), then `SET_PIN` (ADD PIN, no PIN to one) | `9000` | `9000` (181 ms, both) | PIN set, 3 tries | PASS |
| 3b | `VERIFY_PIN`, the PIN | `9000` | `9000` (25 ms) | 3 tries | PASS |
| 3c | `CHANGE_PIN` to a second PIN (owner's proof) | `9000` | `9000` (197 ms with `GET_NONCE`) | PIN set, 3 tries | PASS |
| 3d | `VERIFY_PIN`, the new PIN | `9000` | `9000` (26 ms) | 3 tries | PASS |
| 3e | `VERIFY_PIN`, the old PIN (the run's one wrong try) | `63C2` | `63C2` (23 ms) | 2 tries | PASS |
| 3f | `VERIFY_PIN`, the new PIN | `9000`, the tries refilled | `9000` (25 ms) | 3 tries | PASS |

3e shows that `CHANGE_PIN` replaced the old PIN. One wrong PIN was sent in the
whole run, on a card whose owner can unblock it (`CHANGE_PIN`, D22), with 3
tries allowed (`PIN_MAX_TRIES`).

### 4. `SET_LIMIT` and the rollover budget (D26 #2 on hardware)

| # | Command | Expected | SW | `GET_CARD` byte 77 after | Verdict |
|---|---|---|---|---|---|
| 4a | 13 bytes: day 1000, payment 0, allowance 100, budget 3 | `9000`, budget 3 | `9000` | `03` (window begun at `now`, day 1000, allowance 100) | PASS |
| 4b | 4 bytes: day 1000 | `9000`, budget left | `9000` | `03` | PASS |
| 4c | 8 bytes: day 1000, payment 0 | `9000`, budget left | `9000` | `03` | PASS |
| 4d | 12 bytes: day 1000, payment 0, allowance 100 | `9000`, budget left | `9000` | `03` | PASS |
| 4e | 13 bytes with budget 0 | `6A80` | `6A80` | `03` | PASS |
| 4f | 13 bytes with budget 31 | `6A80` | `6A80` | `03` | PASS |
| 4g | `VERIFY_PIN`, then the PIN form `SET_LIMIT_PIN` (`33`), 4 bytes, on the owned card | `6A91` (the PIN form is for an open card) | `6A91` | `03`, day still 1000 | PASS |

On 2.0, 4b to 4d would each have put byte 77 back to the default. On this chip
they leave it, as 2.1 says. The PIN form's own rule, that it leaves the budget,
can only be seen on an open card; an owned card refuses it outright, as here.

### 5. `SET_HEADER`

| # | Command | Expected | SW | Answer (`now`) | Verdict |
|---|---|---|---|---|---|
| 5a | block 971,431 (newer than the anchor) | the clock moves | `9000` (81 ms) | 1791994059, block 971,431's time | PASS |
| 5b | block 971,428 (older than `now`) | nothing moves | `9000` (70 ms) | 1791994059, unchanged | PASS |
| 5c | block 971,437 with one nonce byte flipped | `6A93`, nothing moves | `6A93` (58 ms) | unchanged | PASS |

### 6. `REFRESH` (`53`)

| Command | Expected | SW | Answer and state | Verdict |
|---|---|---|---|---|
| owner's proof over block 971,437, the tip at the time | `9000`, the card's `now`; rolls 0 | `9000` (251 ms with `GET_NONCE`) | `now` 1791996643 (block 971,437's time), last header `00…019576e3…bf8ced6`, rolls 0 | PASS |

The rolls were already 0: no payment ran, and in 2.1 nothing but a payment
rolls the day (D26). That nothing else did is itself seen here. Through steps 2
to 6 the clock moved from 0 to block 971,437's time, and byte 76 stayed 0.

### 7. `SET_CARD`

| # | Command | Expected | SW | State after | Verdict |
|---|---|---|---|---|---|
| 7a | owner's proof; unit sat, no refund key, mint `https://testnut.cashu.space`, no design | `9000` | `9000` (315 ms) | record set, mint shown, design `000000` | PASS |
| 7b | the same record with design `fl1` (lower case) | `6A80` | `6A80` | record as 7a | PASS |
| 7c | the same record with design `FL1` | `9000` | `9000` (241 ms) | design `FL1` | PASS |

`SET_CARD` also lets go of the header ratchet, by design: `GET_CARD` bytes 40 to
43 read 0 after it, while the clock and the last header's hash stay. The next
header newer than `now` sets the ratchet again. A header equal to the last one
taken, sent in the timing pass below, does not.

### 8. `LOCK_CARD`: refusals only

| # | Command | Expected | SW | Verdict |
|---|---|---|---|---|
| 8a | `LOCK_CARD` P2 `DE` with no PIN given in the tap | `6982` | `6982` (15 ms) | PASS |
| 8b | `VERIFY_PIN`, then `LOCK_CARD` P2 `00` | `6B00` | `6B00` (15 ms) | PASS |
| 8c | `VERIFY_PIN`, then `LOCK_CARD` P2 `DE` with a proof by a P-256 key that is not the owner's | `6A91` | `6A91` (155 ms) | PASS |

**The lock itself was not sent.** A locked card does not unlock. The only way
back is `RESET_CARD` (the owner's proof and the PIN), and that also gives the
card a new key and clears its owner, PIN and record. `RESET_CARD` has not run on
a chip either. A failed reset would leave this card locked for good. So what a
locked card still answers (`REFRESH` and payments, D20) has not been seen on
silicon. The way to run it is a `RESET_CARD` on an unlocked card first, then
`LOCK_CARD`, `REFRESH` on the locked card, and `RESET_CARD` to come back. That
needs a decision first, because it takes the card through its key change.
Part A2 below is that run.

### 9. `AUTH` and `selftest` at the end

| Command | Result | Verdict |
|---|---|---|
| `cardctl -t auth` | `9000`, BIP-340 valid (845 ms) | PASS |
| `cardctl -t selftest --rounds 10 --pin …` | 20 of 20, including `VERIFY_PIN`, `GET_CARD` (rolls 0 of 7, allowance armed), ten `AUTH` signatures verified and a fresh nonce across identical requests | PASS |

All 30 checks above passed. None failed.

## Timings

`cardctl --timing` figures (the PC/SC round trip, reader included). The owner's
commands are from a separate pass of five each, after the steps above: same
values sent again, so nothing on the card changed. Host-side ECDSA signing is
not in these figures.

| Command | n | min | median | max |
|---|---|---|---|---|
| `AUTH` (BIP-340 on the card) | 12 | 832.8 | **843.8** | 860.4 |
| `REFRESH` (ECDSA verify + a header) | 5 | 157.0 | **158.1** | 158.3 |
| `SET_LIMIT` (ECDSA verify) | 5 | 111.2 | 112.0 | 112.1 |
| `ALLOW_LOAD` (ECDSA verify) | 5 | 103.5 | 103.7 | 104.5 |
| `SET_HEADER` (two SHA-256 + the work check) | 5 | 63.7 | 63.8 | 63.9 |
| `GET_NONCE` | 15 | 21.5 | 21.8 | 21.9 |
| `GET_SLOT_STATUS` | 1 | | 80.4 | |
| `GET_CARD` | 1 | | 72.3 | |
| `GET_INFO` (P1 = 2) | 1 | | 45.5 | |
| `VERIFY_PIN` | 1 | | 25.5 | |
| `SELECT` | 1 | | 22.5 | |

All figures ms. `AUTH` is the constant-work multiply of D21 on this chip:
833 to 860 ms, the same range as the 2.0 measurement under ENG-681 (833 to
854 ms), and about 3.7% over 0.4's 813.7 ms median on the other J3R180. The
spread across twelve signatures is 28 ms, the same order as before. Nothing here
says the signing path is free of secret-dependent timing (D21 lists what is
still open). The owner's commands cost about 100 to 160 ms each on top of a
22 ms `GET_NONCE`: the P-256 verify runs on the chip's own `Signature` engine.

## The card as left after part A

Part A2 changed all of this; its own table is [below](#the-card-as-left-after-part-a2).

| Item | State |
|---|---|
| Applets | the three, `SELECTABLE`; version 2.1 |
| Owner | set, to the P-256 key made for this run (kept off the repository) |
| PIN | set (the second PIN of step 3), 3 tries, not blocked |
| Locked | no |
| Record | mint `https://testnut.cashu.space`, unit sat, no refund key, design `FL1` |
| Limits | none: day 0, payment 0, allowance 0; rollover budget 7 (byte 77 = `07`, set by a final 13-byte `SET_LIMIT`), rolls 0, allowance armed |
| Clock | `now` 1791996643, block 971,437; ratchet bits 0 (after `SET_CARD`) |
| Slots | 128 empty, balance 0 |
| Key | `0392932756f974da3bd61f7712f86cc092186fbe4a72c918eb976ce384bc2a33eb` |

## Part A2: lock, refresh on a locked card, reset

The run part A stopped short of. Before anything was sent, the applet's source
at `6812d06` was read for the way back: `processResetCard` takes the owner's
proof over `CashuCard/reset` with P2 `AD` on any card with an owner and nothing
unspent, and on a locked card also wants the PIN verified in the same tap
(`6982` otherwise, checked after the proof). So a locked card with its owner's
key and PIN in hand can always be reset.

All of it ran in one PC/SC connection, but for 5a, which needs a new tap. The
owner key is the one of part A, read from its file on the host. The headers are
blocks 971,437 and 971,438 from mempool.space, each checked against
blockstream.info and its own hash. Between the two runs the card had taken
block 971,438 (`now` 1791997403), so that is the baseline's clock. A time is
the round trip through the ACR122U; an owner's command is shown as its own
APDU, after a `GET_NONCE` of about 22 ms.

### 1. Baseline

| Command | SW | Read |
|---|---|---|
| `gp --list` | | the three applets `SELECTABLE`, package `F0434153485543415244` 2.1 `LOADED` |
| `GET_INFO`, `GET_CARD`, `GET_PUBKEY` | `9000` | as part A left it: owner set, PIN set (3 tries), unlocked, record `FL1`, 128 slots empty, balance 0, budget 7, allowance armed; `now` 1791997403 (block 971,438), ratchet bits `F01E0217`; key `0392932756…a33eb` |

### 2. `RESET_CARD` on an unlocked card

| # | Command | Expected | SW | Time | State after | Verdict |
|---|---|---|---|---|---|---|
| 2a | `RESET_CARD` P2 `AD`, the owner's proof, no PIN | `9000` | `9000` | 359.1 ms | below | PASS |
| 2b | `AUTH`, checked under the key `GET_PUBKEY` now gives | BIP-340 valid | `9000`, valid | 831.6 ms | | PASS |
| 2c | `GET_NONCE` | `6A90` (no owner) | `6A90` | 14.2 ms | | PASS |

What the reset cleared, against [RESET_CARD](../spec/APDU.md#reset_card-0x51)
("the card as out of its packet, with a new key, keeping its clock"):

| Item | Before | After 2a | Spec |
|---|---|---|---|
| Card key | `0392932756…a33eb` | `02dc6b8739…21d4741`, a new key | new key: yes |
| Owner | set | none | cleared: yes |
| PIN | set, 3 tries | none, 3 tries | cleared: yes |
| Locked | no | no | |
| Record | testnut, `FL1` | none; `GET_CARD` 109 bytes, mint and design empty | cleared: yes |
| Limits, window | none, window 1791996643 | none, window 0 | cleared: yes |
| Rollover | budget byte 7, rolls 0, armed | budget byte 0 (the default 7), rolls 0, not armed | cleared: yes |
| Clock | `now` 1791997403, last header block 971,438, bits `F01E0217` | `now` and last header kept, bits 0 | kept, ratchet let go: yes |
| Slots, balance | 128 empty, 0 | 128 empty, 0 | |
| Tag | on | on | on: yes |
| Version | 2.1 | 2.1 | kept: yes |

### 3. The card set up again for the lock

| # | Command | Expected | SW | Time | Verdict |
|---|---|---|---|---|---|
| 3a | `SET_OWNER`, 145 bytes: the same owner key and block 971,438's header (the anchor) | `9000` | `9000` | 100.2 ms | PASS |
| 3b | `ALLOW_LOAD`, then `SET_PIN` (a third PIN, kept off the repository) | `9000` | `9000` | 106.5, 27.6 ms | PASS |
| 3c | `VERIFY_PIN` | `9000` | `9000` | 25.5 ms | PASS |

After: owner set, PIN set (3 tries), unlocked, no record, same new key. The
anchor was the header the card already had, so the clock did not move and the
ratchet stayed 0, as part A saw for a header equal to the last one taken.

### 4. `LOCK_CARD`, and the locked card

| # | Command | Expected | SW | Time | Answer, state | Verdict |
|---|---|---|---|---|---|---|
| 4a | `VERIFY_PIN`, then `LOCK_CARD` P2 `DE` with the owner's proof | `9000` | `9000` | 25.5, 106.5 ms | `GET_INFO` locked 1; owner, PIN, key, slots as before | PASS |
| 4b | `REFRESH` with the owner's proof over block 971,438 (the tip) | `9000` (D20: a locked card refreshes) | `9000` | 157.9 ms | `now` 1791997403, rolls 0 | PASS |
| 4c | `SET_HEADER`, block 971,438 | `9000` (no state refuses a good header) | `9000` | 63.5 ms | `now` 1791997403 | PASS |
| 4d | `VERIFY_PIN` | `9000` | `9000` | 25.6 ms | 3 tries | PASS |
| 4e | `LOCK_CARD` again, PIN verified, owner's proof | `6985` (already locked) | `6985` | 43.9 ms | | PASS |
| 4f | `SET_LIMIT`, 13 bytes (day 0, payment 0, allowance 0, budget 7: what the card held), owner's proof | `6986` | `6986` | 49.2 ms | limits unchanged | PASS |
| 4g | `ALLOW_LOAD`, owner's proof | `6986` | `6986` | 44.9 ms | | PASS |
| 4h | `SPEND_ALL_BEGIN`, slot `00` (empty) | `6A88` (a locked card still pays; the empty slot is what refuses it) | `6A88` | 16.4 ms | | PASS |

The tip was still block 971,438 when the card was locked, so 4b took a header
equal to the one the card had. It shows that `REFRESH` is accepted on a locked
card and runs its transaction. A locked card's clock moved forward by `REFRESH`
is still to be seen.
4e to 4g answer in 44 to 49 ms, under the 100 ms of a P-256 verify: the lock is
checked before the proof, as the source has it. `LOAD_PROOF` was not sent to
the locked card: a piece that landed would leave something unspent, and
`RESET_CARD` refuses a card with anything unspent (`6A8D`). No wrong PIN was
sent in part A2.

### 5. `RESET_CARD` on the locked card

| # | Command | Expected | SW | Time | State after | Verdict |
|---|---|---|---|---|---|---|
| 5a | a new tap (`SELECT`), then `RESET_CARD` P2 `AD` with the owner's proof and no `VERIFY_PIN` | `6982` | `6982` | 104.4 ms | still locked, owner and PIN set | PASS |
| 5b | `VERIFY_PIN`, then `RESET_CARD` with the owner's proof | `9000` | `9000` | 25.7, 360.2 ms | unlocked, no owner, no PIN (3 tries), no record, a new key `0362149d2d…768f78`, clock kept, bits 0 | PASS |
| 5c | `AUTH` under the new key | BIP-340 valid | `9000`, valid | 846.2 ms | | PASS |

5a's 104 ms is the proof's verify: the reset checks the proof first and the PIN
after, so the refusal spent the nonce and changed nothing. Three keys in the
run, all different: part A's, the one after 2a and the one after 5b.

### 6. At the end

| Command | Result | Verdict |
|---|---|---|
| `cardctl -t selftest --rounds 10` | 19 of 19, `GET_CARD` rolls 0 of 7, allowance not armed, ten `AUTH` signatures verified | PASS |
| `cardctl info`, `GET_CARD`, `gp --list` | as in the table below; the three applets `SELECTABLE` | PASS |

All 20 checks of part A2 passed. The card answered every command with the
status the spec gives it.

### Timings (part A2)

| Command | n | min | median | max |
|---|---|---|---|---|
| `RESET_CARD`, accepted | 2 | 359.1 | 359.7 | 360.2 |
| `RESET_CARD`, refused `6982` | 1 | | 104.4 | |
| `LOCK_CARD`, accepted | 1 | | 106.5 | |
| `LOCK_CARD`, refused `6985` | 1 | | 43.9 | |
| `REFRESH` on the locked card | 1 | | 157.9 | |
| `SET_HEADER` on the locked card | 1 | | 63.5 | |
| `SET_LIMIT`, `ALLOW_LOAD` refused `6986` | 2 | 44.9 | | 49.2 |
| `SET_OWNER`, 145 bytes | 1 | | 100.2 | |
| `SET_PIN` | 1 | | 27.6 | |
| `AUTH` (run and selftest) | 12 | 831.6 | 845.0 | 855.4 |

All figures ms. A reset costs about 360 ms: the wipe of the slots, the log and
the receipts, and two new key pairs, then the five-byte transaction.

### The card as left after part A2

| Item | State |
|---|---|
| Applets | the three, `SELECTABLE`; version 2.1 |
| Owner | none: open to the first phone that sets it up |
| PIN | none, 3 tries |
| Locked | no |
| Record | none |
| Limits | none; rollover budget byte 0 (the default 7), rolls 0, allowance not armed |
| Clock | `now` 1791997403, block 971,438; ratchet bits 0 |
| Slots | 128 empty, balance 0 |
| Tag | on |
| Key | `0362149d2dfae9264ce8137889f13637190892b07af161f4d19c4a180389768f78` |

## Not covered here (part B)

Parts A and A2 ran no payment and loaded nothing. These have still not run on
a chip under 2.x:

- **Payments.** `SPEND_ALL_BEGIN`, `_OUTPUTS`, `_CHANGE`, `_SIGN` and `_AGAIN`.
  That includes a payment with change, the change loaded back under the change
  grant, the limit on one payment's wait (`00 01`), and the refusals `6A94` and
  `6A8F`.
- **`LOAD_PROOF` of real pieces** (format 4, locked to the card key, with and
  without the mint's DLEQ proof). Placeholder pieces would have left unspent
  slots that only a payment or a reset clears.
- **The day rolled by a payment** (D20, D26), and a payment of nothing that
  rolls nothing. Nothing above moved byte 76.
- **A locked card's payment**, and `REFRESH` moving a locked card's clock
  forward (4b took a header equal to the card's).
- **Torn writes**: no card has been pulled mid-write.
- `SET_TAG`, `GET_LOG`, `GET_CHANGE`, `GET_DLEQ`, `TELL_TIME`, `VERIFY_PIN`
  sealed (P1 = 1) and `GET_NONCE` P1 = 1.

Part B covers the payments, loads, change and the day's roll with flash-mobile
and flash-pos on phones (iPhone and Pixel) against this card. The test mint's
sats are fake.
