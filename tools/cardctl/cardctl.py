#!/usr/bin/env python3
"""
cardctl — host-side PC/SC driver for the Cashu card applet, protocol 2.0.

Speaks spec/APDU.md over either interface: a contact reader (ACR39U and
friends) or a contactless one (ACR122U). PC/SC hides the difference, so the
same commands work for both — which matters, because CAP loading over
contactless is the flaky path and you will want to know quickly whether a
failure is the card or the interface.

The command that earns this tool its keep is `selftest`: it selects the applet,
reads the card's public key, asks the card to prove itself with AUTH, and
verifies those BIP-340 signatures here. jCardSim cannot surface EEPROM
exhaustion, ECDH output framing, or a card whose getS returns short;
`selftest` is the evidence from silicon.

A 2.0 card has an owner (a P-256 key) whose proofs administer it: set-owner,
set-limit, change-pin, refresh, load (the owner's grant) and lock sign them
with `--owner-key`, a 32-byte private key in hex, or, by default, the fixed
TEST key in p256.py, which anyone with this repository holds. Use the test
key on bench cards only.

    python3 cardctl.py readers
    python3 cardctl.py selftest
    python3 cardctl.py info
    python3 cardctl.py set-owner --anchor <80-byte header hex>

`dump` and `load-file` are the 0.x card file tools (spec/CARD-FILE.md): they
select the 0.x AID and refuse any other card.

Requires: pip install -r requirements.txt   (pyscard)
"""

import argparse
import binascii
import json
import hashlib
import os
import secrets
import statistics
import sys
import time
from typing import List, Optional, Tuple

import bip340
import p256

# ── Applet identity ───────────────────────────────────────────────────────────
# Protocol 2.0 (DECISIONS D19): the 10-byte package AID, "CASHUCARD" after the
# proprietary RID byte F0, and the card's applet under it and 01. A reader
# selects the applet's whole AID (D25). On a chip a SELECT by the package AID
# alone is a partial name, and the chip gives it to the first instance whose
# AID begins with it: the opener (…44 4D), instantiated first, which answers
# 9000 with no version and 6D00 to everything after. The package AID is only
# the fallback, and a 9000 to it without a version is not the card's applet.
PACKAGE_AID = bytes.fromhex("F0434153485543415244")
APPLET_AID = PACKAGE_AID + b"\x01"
SELECT_AIDS = (APPLET_AID, PACKAGE_AID)

# The 0.x applet's AID, under the NFC Forum's RID. Only the 0.x card file
# tools (`dump`, `load-file`) select it; every other command speaks 2.0.
LEGACY_PACKAGE_AID = bytes.fromhex("D2760000850102")
LEGACY_APPLET_AID = LEGACY_PACKAGE_AID + b"\x01"

CLA = 0xB0

INS_GET_INFO = 0x01
INS_GET_PUBKEY = 0x10
INS_GET_BALANCE = 0x11
INS_GET_PROOF_COUNT = 0x12
INS_GET_PROOF = 0x13
INS_GET_SLOT_STATUS = 0x14
INS_AUTH = 0x15
INS_GET_CARD = 0x16
INS_GET_PIECES = 0x17
INS_GET_LOG = 0x18
INS_GET_CHANGE = 0x19
INS_GET_DLEQ = 0x1A
INS_SPEND_ALL_BEGIN = 0x22
INS_SPEND_ALL_OUTPUTS = 0x23
INS_SPEND_ALL_SIGN = 0x24
INS_SPEND_ALL_AGAIN = 0x25
INS_SPEND_ALL_CHANGE = 0x26
INS_LOAD_PROOF = 0x30
INS_CLEAR_SPENT = 0x31
INS_SET_CARD = 0x32
INS_SET_LIMIT_PIN = 0x33
INS_SET_LIMIT = 0x34
INS_SET_HEADER = 0x36
INS_TELL_TIME = 0x37
INS_VERIFY_PIN = 0x40
INS_SET_PIN = 0x41
INS_CHANGE_PIN = 0x42
INS_SET_OWNER = 0x43
INS_GET_NONCE = 0x44
INS_ALLOW_LOAD = 0x45
INS_LOCK_CARD = 0x50
INS_RESET_CARD = 0x51
INS_SET_TAG = 0x52
INS_REFRESH = 0x53

# GET_INFO byte 6 (spec/APDU.md, GET_INFO): every bit is set on 2.0.
CAP_SECP256K1_NATIVE = 0x01
CAP_SCHNORR = 0x02
CAP_PIN = 0x04
CAP_PAYMENT_LIMIT_WAITS = 0x08
CAP_PIECES_BY_NAME = 0x10
CAP_128_PLACES = 0x20
CAP_BURN_OUTSIDE_TRANSACTION = 0x40
CAP_SEALED_PIN = 0x80

PIN_STATE_NAMES = {0: "none", 1: "set", 2: "blocked"}

# The lowest applet version selftest passes: the shared protocol (D18) as 2.1
# has it (D26: a payment of nothing spends no roll, and SET_LIMIT without the
# budget's byte leaves the budget). A 2.0 card is swept and reinstalled. A 0.x
# or Foxy 1.x card does not answer the 2.x AID at all.
SELFTEST_MIN_VERSION = (2, 1)
FORMAT = 4

LOCK_CONFIRM_BYTE = 0xDE

# The owner's proof labels (spec/APDU.md, "The owner's proof"; DECISIONS D19).
LABEL_CHANGE_PIN = "CashuCard/change-pin"
LABEL_SET_LIMIT = "CashuCard/set-limit"
LABEL_SET_OWNER = "CashuCard/set-owner"
LABEL_SET_CARD = "CashuCard/set-card"
LABEL_LOAD = "CashuCard/load"
LABEL_LOCK = "CashuCard/lock"
LABEL_RESET = "CashuCard/reset"
LABEL_TAG = "CashuCard/tag"
LABEL_REFRESH = "CashuCard/refresh"
AUTH_TAG = "CashuCard/auth"

HEADER_LEN = 80
OWNER_KEY_LEN = 65
AUTH_NONCE_LEN = 16
ROLL_BUDGET_DEFAULT = 7
ROLL_BUDGET_MOST = 30

PROOF_SIZE = 82
LEGACY_PROOF_SIZE = 78
# Slot count the applet allocates (CashuApplet.MAX_PROOFS). GET_SLOT_STATUS
# returns one byte per slot, so this is also that command's Le.
MAX_PROOFS = 128
LEGACY_MAX_PROOFS = 32
STATUS_NAMES = {0x00: "empty", 0x01: "unspent", 0x02: "spent"}

PIN_MIN_LEN = 4
PIN_MAX_LEN = 8

# The card's amount field is a 4-byte unsigned integer (spec/APDU.md,
# LOAD_PROOF). Anything at or above this bound makes `amount.to_bytes(4, "big")`
# raise a bare OverflowError — and on the file path that happens mid-load, after
# earlier proofs are already committed. Bound it before the first write.
MAX_SLOT_AMOUNT = 2 ** 32

SW_MEANINGS = {
    0x9000: "success",
    0x6700: "wrong length",
    0x6982: "security condition not satisfied (the PIN, or the owner's grant, not given in this tap)",
    0x6983: "PIN blocked — the owner's change-pin unblocks it",
    0x6984: "PIN not set",
    0x6985: "conditions not satisfied (already spent / no payment begun / already locked / an allowance on a card with no PIN)",
    0x6986: "card locked by LOCK_CARD — writes disabled",
    0x6A80: "wrong data (not a point, a bad refund key, bits no header carries, a budget outside 1-30)",
    0x6A82: "not found — no 2.0 applet on this card (a 0.x or 1.x card needs an update)",
    0x6A83: "slot index out of range",
    0x6A84: "no space — all slots occupied",
    0x6A86: "incorrect P1/P2",
    0x6A88: "slot is empty",
    0x6A8C: "no card record — run set-card first",
    0x6A8D: "card in use — something unspent where only an empty card may be changed",
    0x6A8E: "a dated piece on a card with no refund key",
    0x6A8F: "over the day's limit",
    0x6A90: "no owner — run set-owner first",
    0x6A91: "the owner's proof is missing or not the owner's (wrong --owner-key?), or not open to an owned card",
    0x6A93: "too little work in the block header",
    0x6A94: "already on the card (LOAD_PROOF) / the PIN needed for this payment (SPEND_ALL_SIGN)",
    0x6A96: "too many places for one signature",
    0x6B00: "wrong P1/P2 (a missing confirmation byte)",
    0x6D00: "instruction not supported",
    0x6E00: "class not supported",
    0x6F00: "signing failed (hardware error)",
}


def describe_sw(sw: int, context: str = "") -> str:
    if sw in SW_MEANINGS:
        return SW_MEANINGS[sw]
    if (sw & 0xFFF0) == 0x63C0:
        return f"wrong PIN — {sw & 0x0F} retries remaining"
    return "unknown status word"


class CardError(Exception):
    def __init__(self, sw: int, context: str = ""):
        self.sw = sw
        where = f" during {context}" if context else ""
        super().__init__(f"card returned {sw:04X}{where}: {describe_sw(sw, context)}")


# ── APDU timing ───────────────────────────────────────────────────────────────
# One (context, milliseconds) row per APDU, measured around the PC/SC transmit
# call — so the figure is the full reader round trip the card sees, not just
# the applet's own work. `--timing` prints each row as it happens and a
# per-command summary at exit. Always collected; printing is what the flag
# gates, and collecting a float per APDU costs nothing against a 60 ms tap.
TIMING_ENABLED = False
TIMINGS: List[Tuple[str, float]] = []


def record_timing(context: str, ms: float) -> None:
    TIMINGS.append((context, ms))
    if TIMING_ENABLED:
        print(f"  ⏱ {context:<16} {ms:8.1f} ms", file=sys.stderr)


def summarize_timings(rows: List[Tuple[str, float]]) -> str:
    """
    Per-command table in first-seen order, then the whole session.

    Median rather than mean: a single retried or torn APDU should not drag
    the figure for every other command of its kind with it.
    """
    if not rows:
        return "no APDUs sent"
    by_ctx: dict = {}
    for ctx, ms in rows:
        by_ctx.setdefault(ctx, []).append(ms)
    width = max(len(ctx) for ctx in by_ctx)
    lines = [f"{'command':<{width}}  {'n':>3}  {'min':>8}  {'median':>8}  {'max':>8}  {'total':>9}"]
    for ctx, xs in by_ctx.items():
        lines.append(
            f"{ctx:<{width}}  {len(xs):>3}  {min(xs):8.1f}  {statistics.median(xs):8.1f}"
            f"  {max(xs):8.1f}  {sum(xs):9.1f}"
        )
    total = sum(ms for _, ms in rows)
    lines.append(f"{len(rows)} APDU(s), {total:.1f} ms on the wire (all figures ms)")
    return "\n".join(lines)


def _hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()


def validate_slot_amount(value, where: str = "") -> int:
    """
    A Cashu denomination that the card's 4-byte field can hold.

    Two rules, both of which cost nothing here and cost a burned slot anywhere
    else:

    * **A positive power of two.** A mint keyset has no key for amount 3, so a
      proof carrying one is rejected on redemption — after the slot is gone.
      This is the same rule cashu-client's `requireAmount` enforces on the other
      side of the card file; a value it refuses is a value this tool must never
      write, or the two halves disagree about what a valid proof is.
    * **Below `2**32`.** The APDU field is a 4-byte unsigned integer, so
      anything larger makes `amount.to_bytes(4, "big")` raise a bare
      OverflowError part-way through a load, after earlier proofs have already
      committed.

    Lives here rather than in the file parser because both entry points to
    LOAD_PROOF — `cardctl load` and `cardctl load-file` — must agree on what a
    valid amount is. They did not, and `load --amount 5` wrote a proof that the
    file format then refused to carry back off the card.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        # Reported before the range check so a string "8" out of an untyped
        # reader bridge does not render as `got 8` — a message that looks like a
        # valid value and hides the type error.
        raise SystemExit(
            f"{where}amount must be a positive integer, got "
            f"{type(value).__name__} {value!r}"
        )
    if not 0 < value < MAX_SLOT_AMOUNT:
        raise SystemExit(
            f"{where}amount must be a positive integer below 2**32 "
            f"(the card's amount field is a 4-byte uint), got {value!r}"
        )
    if value & (value - 1) != 0:
        raise SystemExit(
            f"{where}amount must be a positive power of two — a mint keyset has "
            f"no key for other denominations, so the proof is rejected on "
            f"redemption after the slot is already burned. Got {value!r}."
        )
    return value


# ── PC/SC transport ───────────────────────────────────────────────────────────
def _load_pyscard():
    try:
        from smartcard.System import readers  # noqa
        from smartcard.util import toHexString  # noqa
        return readers
    except ImportError:
        sys.exit(
            "pyscard is not installed.\n"
            "  pip install -r requirements.txt\n"
            "On macOS PC/SC ships with the OS — do NOT install pcsc-lite.\n"
            "On Debian/Ubuntu you also need: sudo apt install pcscd libpcsclite-dev"
        )



class Card:
    """A connected card with the Cashu applet selected."""

    # The 0.x applet's encodings, for the card file tools only (select(legacy=True)).
    legacy = False

    def __init__(self, reader_index: int = 0, verbose: bool = False):
        readers_fn = _load_pyscard()
        available = readers_fn()
        if not available:
            sys.exit(
                "No PC/SC readers found.\n"
                "  - Is the reader plugged in?\n"
                "  - Linux: is pcscd running? (sudo systemctl start pcscd)\n"
                "  - macOS: the daemon is built in; try replugging the reader."
            )
        if reader_index >= len(available):
            sys.exit(f"Reader index {reader_index} out of range ({len(available)} found)")
        self.reader = available[reader_index]
        self.verbose = verbose
        try:
            self.connection = self.reader.createConnection()
            self.connection.connect()
        except Exception as exc:  # noqa: BLE001 — surface the driver's own words
            sys.exit(f"Could not connect to a card on {self.reader}: {exc}\nIs a card on the reader?")

    # ── raw APDU ──────────────────────────────────────────────────────────────
    def transmit(self, apdu: bytes, context: str = "") -> bytes:
        if self.verbose:
            print(f"  > {_hex(apdu)}", file=sys.stderr)
        started = time.perf_counter()
        data, sw1, sw2 = self.connection.transmit(list(apdu))
        record_timing(context or "APDU", (time.perf_counter() - started) * 1000.0)
        sw = (sw1 << 8) | sw2
        body = bytes(data)
        if self.verbose:
            print(f"  < {_hex(body)} {sw:04X}", file=sys.stderr)
        if sw != 0x9000:
            raise CardError(sw, context)
        return body

    def send(self, ins: int, p1: int = 0, p2: int = 0,
             data: bytes = b"", le: Optional[int] = None, context: str = "") -> bytes:
        apdu = bytes([CLA, ins, p1, p2])
        if data:
            apdu += bytes([len(data)]) + data
        if le is not None:
            apdu += bytes([le])
        return self.transmit(apdu, context or f"INS {ins:02X}")

    # ── selection ─────────────────────────────────────────────────────────────
    def select(self, legacy: bool = False) -> bytes:
        """SELECT by AID. Returns the 2-byte applet version.

        2.0 selects the applet's whole AID first (D25). An answer of 9000
        with no version is some other applet of the package (the opener, on
        a chip that gave it a partial name) and counts as no answer: the next
        AID is tried, as after an error.
        """
        self.legacy = legacy
        aids = (LEGACY_PACKAGE_AID, LEGACY_APPLET_AID) if legacy else SELECT_AIDS
        last: object = None
        for aid in aids:
            apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid
            try:
                version = self.transmit(apdu, "SELECT")
            except CardError as exc:
                last = exc
                continue
            if len(version) >= 2:
                return version
            last = f"SELECT {_hex(aid)} answered 9000 with no version (not the card's applet)"
        if legacy:
            raise SystemExit(f"SELECT of the 0.x applet failed: {last}\n"
                             "This card has no 0.x applet; card files are 0.x-only (spec/CARD-FILE.md).")
        raise SystemExit(
            f"SELECT failed: {last}\n"
            "No 2.0 applet answers on this card. A card on the 0.x or Foxy 1.x applet needs an\n"
            "update (sweep it first, then reinstall: docs/HARDWARE_DEPLOYMENT.md):\n"
            "  applet/target/cashu-javacard-2.1.0.cap"
        )

    # ── read commands ─────────────────────────────────────────────────────────
    def get_info(self) -> dict:
        """GET_INFO, the long form (P1 = 2, 43 bytes) on 2.0; the 0.x answer (8 or 9 bytes) in legacy mode."""
        if self.legacy:
            b = self.send(INS_GET_INFO, le=0x00, context="GET_INFO")
            if len(b) < 8:
                raise SystemExit(f"GET_INFO returned {len(b)} bytes, expected 8 or 9: {_hex(b)}")
            return {"version": f"{b[0]}.{b[1]}", "max_slots": b[2], "unspent": b[3], "spent": b[4],
                    "empty": b[5], "caps_raw": b[6], "pin_state": PIN_STATE_NAMES.get(b[7], f"unknown({b[7]})")}
        b = self.send(INS_GET_INFO, p1=0x02, le=0x00, context="GET_INFO")
        if len(b) < 30:
            raise SystemExit(f"GET_INFO returned {len(b)} bytes, expected 43: {_hex(b)}")
        return decode_info(b)

    def get_pubkey(self, raw: bool = False) -> bytes:
        """The card's secp256k1 public key, normalised to 33-byte compressed.

        spec/APDU.md fixes the wire format at 33 bytes; an applet that answered
        ECPublicKey.getW()'s 65-byte point is compressed here, at the single
        ingress, so every consumer sees the same 33-byte key. `raw=True` returns
        the bytes as the card sent them, for `selftest` to report the encoding.
        """
        pk = self.send(INS_GET_PUBKEY, le=0x21, context="GET_PUBKEY")
        if raw:
            return pk
        try:
            return bip340.compress(pk)
        except ValueError as exc:
            raise SystemExit(f"GET_PUBKEY: {exc}")

    def get_balance(self) -> int:
        return int.from_bytes(self.send(INS_GET_BALANCE, le=0x04, context="GET_BALANCE"), "big")

    def get_proof_count(self) -> int:
        return self.send(INS_GET_PROOF_COUNT, le=0x01, context="GET_PROOF_COUNT")[0]

    def get_slot_status(self) -> bytes:
        return self.send(INS_GET_SLOT_STATUS, le=(LEGACY_MAX_PROOFS if self.legacy else MAX_PROOFS),
                         context="GET_SLOT_STATUS")

    def get_proof(self, slot: int) -> dict:
        size = LEGACY_PROOF_SIZE if self.legacy else PROOF_SIZE
        b = self.send(INS_GET_PROOF, p1=slot, le=size, context=f"GET_PROOF slot {slot}")
        proof = {
            "slot": slot,
            "status": STATUS_NAMES.get(b[0], f"unknown({b[0]})"),
            # Raw bytes -> hex gives the full 16-char NUT-02 id. Decoding these
            # as ASCII would yield only 8 hex chars: half an id, matching no
            # keyset at the mint.
            "keyset_id": b[1:9].hex(),
            "amount": int.from_bytes(b[9:13], "big"),
            # The 32 bytes are the P2PK *nonce*, not the secret string.
            "nonce": b[13:45],
            "c": b[45:78],
        }
        if not self.legacy:
            proof["date"] = int.from_bytes(b[78:82], "big")
        return proof

    def get_card(self) -> dict:
        """GET_CARD: the record, the clock's proof and (2.0, D20) the rollover bytes."""
        return decode_card(self.send(INS_GET_CARD, le=0x00, context="GET_CARD"))

    def auth(self, reader_nonce: bytes) -> Tuple[bytes, bytes]:
        """AUTH: the card's 16 bytes and its BIP-340 signature over the tagged hash (spec/APDU.md, AUTH)."""
        if len(reader_nonce) != AUTH_NONCE_LEN:
            raise SystemExit(f"AUTH takes {AUTH_NONCE_LEN} bytes of the reader's, got {len(reader_nonce)}")
        b = self.send(INS_AUTH, data=reader_nonce, le=0x50, context="AUTH")
        if len(b) != AUTH_NONCE_LEN + 64:
            raise SystemExit(f"AUTH returned {len(b)} bytes, expected 80: {_hex(b)}")
        return b[:AUTH_NONCE_LEN], b[AUTH_NONCE_LEN:]

    def get_nonce(self) -> bytes:
        b = self.send(INS_GET_NONCE, le=0x10, context="GET_NONCE")
        if len(b) != 16:
            raise SystemExit(f"GET_NONCE returned {len(b)} bytes, expected 16")
        return b

    # ── the owner's commands ──────────────────────────────────────────────────
    def owner_command(self, ins: int, label: str, value: bytes, owner: int,
                      p1: int = 0, p2: int = 0, le: Optional[int] = None, context: str = "") -> bytes:
        """GET_NONCE, then the command with the owner's proof over label || nonce || value."""
        nonce = self.get_nonce()
        proof = p256.owner_proof(owner, label, nonce, value)
        return self.send(ins, p1=p1, p2=p2, data=p256.owner_data(proof, value), le=le, context=context)

    def set_owner(self, owner_pub: bytes, anchor: Optional[bytes] = None, old_owner: Optional[int] = None) -> None:
        """SET_OWNER: the key, and the anchor header after it (D20); the old owner's proof on an owned card."""
        if len(owner_pub) != OWNER_KEY_LEN or owner_pub[0] != 0x04:
            raise SystemExit("an owner key is 65 bytes beginning 04")
        if anchor is not None and len(anchor) != HEADER_LEN:
            raise SystemExit(f"the anchor is a block header, {HEADER_LEN} bytes; got {len(anchor)}")
        value = owner_pub + (anchor or b"")
        if old_owner is None:
            self.send(INS_SET_OWNER, data=value, context="SET_OWNER")
        else:
            self.owner_command(INS_SET_OWNER, LABEL_SET_OWNER, value, old_owner, context="SET_OWNER")

    def set_card(self, mint: str, refund: bytes = bytes(33), unit: int = 0, owner: Optional[int] = None) -> None:
        """SET_CARD: unit, refund key, 65 bytes the card does not read, the mint."""
        m = mint.encode("ascii")
        if not 1 <= len(m) <= 77:
            raise SystemExit("the mint is 1 to 77 characters")
        if len(refund) != 33:
            raise SystemExit("a refund key is 33 bytes (or 33 zeros for none)")
        record = bytes([unit]) + refund + bytes(65) + bytes([len(m)]) + m
        if owner is None:
            self.send(INS_SET_CARD, data=record, context="SET_CARD")
        else:
            self.owner_command(INS_SET_CARD, LABEL_SET_CARD, record, owner, context="SET_CARD")

    def set_limit(self, owner: int, day: int, payment: Optional[int] = None,
                  allowance: Optional[int] = None, budget: Optional[int] = None) -> None:
        """SET_LIMIT (34): 4, 8, 12 or 13 bytes; each longer form needs every field before it."""
        value = limit_value(day, payment, allowance, budget)
        self.owner_command(INS_SET_LIMIT, LABEL_SET_LIMIT, value, owner, context="SET_LIMIT")

    def change_pin(self, owner: int, new_pin: bytes) -> None:
        """CHANGE_PIN: the owner's proof over the new PIN. No old PIN; unblocks a blocked card."""
        check_pin(new_pin)
        self.owner_command(INS_CHANGE_PIN, LABEL_CHANGE_PIN, new_pin, owner, context="CHANGE_PIN")

    def allow_load(self, owner: int) -> None:
        self.owner_command(INS_ALLOW_LOAD, LABEL_LOAD, b"", owner, context="ALLOW_LOAD")

    def refresh(self, owner: int, header: bytes) -> int:
        """REFRESH (53, D20): the owner's proof over the tip header; the rollover budget is full again. Answers the clock."""
        if len(header) != HEADER_LEN:
            raise SystemExit(f"a block header is {HEADER_LEN} bytes; got {len(header)}")
        b = self.owner_command(INS_REFRESH, LABEL_REFRESH, header, owner, le=0x04, context="REFRESH")
        return int.from_bytes(b, "big")

    def lock_card(self, owner: int) -> None:
        self.owner_command(INS_LOCK_CARD, LABEL_LOCK, b"", owner, p2=LOCK_CONFIRM_BYTE, context="LOCK_CARD")

    # ── the clock ─────────────────────────────────────────────────────────────
    def set_header(self, header: bytes) -> int:
        if len(header) != HEADER_LEN:
            raise SystemExit(f"a block header is {HEADER_LEN} bytes; got {len(header)}")
        return int.from_bytes(self.send(INS_SET_HEADER, data=header, le=0x04, context="SET_HEADER"), "big")

    # ── write commands ────────────────────────────────────────────────────────
    def load_proof(self, keyset_id: bytes, amount: int, nonce: bytes, c: bytes, date: int = 0) -> int:
        if len(keyset_id) != 8:
            raise SystemExit(f"keyset_id must be 8 raw bytes, got {len(keyset_id)}")
        # Every caller goes through here, so this is the one place that cannot be
        # bypassed. `cardctl load --amount 4294967296` used to reach
        # `amount.to_bytes(4, "big")` and die on a bare OverflowError traceback;
        # `--amount 0` used to burn a slot on a worthless proof.
        validate_slot_amount(amount)
        if len(nonce) != 32:
            raise SystemExit(f"nonce must be 32 bytes, got {len(nonce)}")
        if len(c) != 33:
            raise SystemExit(f"C must be 33 bytes, got {len(c)}")
        payload = keyset_id + amount.to_bytes(4, "big") + nonce + c
        if not self.legacy:
            if not 0 <= date < 2 ** 32:
                raise SystemExit(f"date must fit four bytes, got {date}")
            payload += date.to_bytes(4, "big")
        elif date:
            raise SystemExit("a 0.x card has no date in its slot")
        return self.send(INS_LOAD_PROOF, data=payload, le=0x01, context="LOAD_PROOF")[0]

    def clear_spent(self) -> int:
        return self.send(INS_CLEAR_SPENT, le=0x01, context="CLEAR_SPENT")[0]

    # ── the PIN ───────────────────────────────────────────────────────────────
    def verify_pin(self, pin: bytes) -> None:
        self.send(INS_VERIFY_PIN, data=pin, context="VERIFY_PIN")

    def set_pin(self, pin: bytes) -> None:
        check_pin(pin)
        self.send(INS_SET_PIN, data=pin, context="SET_PIN")


def check_pin(pin: bytes) -> None:
    if not PIN_MIN_LEN <= len(pin) <= PIN_MAX_LEN:
        raise SystemExit(f"a PIN is {PIN_MIN_LEN} to {PIN_MAX_LEN} bytes, got {len(pin)}")


def limit_value(day: int, payment: Optional[int] = None, allowance: Optional[int] = None,
                budget: Optional[int] = None) -> bytes:
    """
    SET_LIMIT's value (spec/APDU.md, SET_LIMIT): the day's limit (4), then the
    limit on one payment (4), the no-PIN allowance (4) and the rollover budget
    (1). A longer form sets every field before it, so each needs the ones
    before it given: a budget alone would quietly set the other two to 0.
    """
    for name, v in (("day", day), ("payment", payment), ("allowance", allowance)):
        if v is not None and not 0 <= v < 2 ** 32:
            raise SystemExit(f"--{name} must fit four bytes, got {v}")
    if budget is not None and (payment is None or allowance is None):
        raise SystemExit("--budget is the thirteenth byte: give --payment and --allowance too (0 for none)")
    if allowance is not None and payment is None:
        raise SystemExit("--allowance is bytes 8 to 11: give --payment too (0 for none)")
    if budget is not None and not 1 <= budget <= ROLL_BUDGET_MOST:
        raise SystemExit(f"--budget is 1 to {ROLL_BUDGET_MOST} rolls between the owner's refreshes, got {budget}")
    value = day.to_bytes(4, "big")
    if payment is not None:
        value += payment.to_bytes(4, "big")
    if allowance is not None:
        value += allowance.to_bytes(4, "big")
    if budget is not None:
        value += bytes([budget])
    return value


def decode_info(b: bytes) -> dict:
    """GET_INFO's answer (spec/APDU.md, GET_INFO), 30, 42 or 43 bytes."""
    caps = b[6]
    info = {
        "version": f"{b[0]}.{b[1]}",
        "version_tuple": (b[0], b[1]),
        "max_slots": b[2],
        "unspent": b[3],
        "spent": b[4],
        "empty": b[5],
        "caps_raw": caps,
        "secp256k1_native": bool(caps & CAP_SECP256K1_NATIVE),
        "schnorr": bool(caps & CAP_SCHNORR),
        "pin_state": PIN_STATE_NAMES.get(b[7], f"unknown({b[7]})"),
        "format": b[8],
        "tries": b[9],
        "locked": bool(b[10]),
        "record_set": bool(b[11]),
        "daily_limit": int.from_bytes(b[12:16], "big"),
        "has_owner": bool(b[16]),
        "now": int.from_bytes(b[17:21], "big"),
        "window_start": int.from_bytes(b[21:25], "big"),
        "spent_today": int.from_bytes(b[25:29], "big"),
        "change_grant": bool(b[29]),
    }
    if len(b) >= 42:
        info["payment_limit"] = int.from_bytes(b[30:34], "big")
        info["allowance"] = int.from_bytes(b[34:38], "big")
        info["nopin_spent"] = int.from_bytes(b[38:42], "big")
    if len(b) >= 43:
        info["tag_off"] = bool(b[42])
    return info


def decode_card(b: bytes) -> dict:
    """GET_CARD's answer (spec/APDU.md, GET_CARD)."""
    if len(b) < 106:
        raise SystemExit(f"GET_CARD returned {len(b)} bytes, expected at least 106: {_hex(b)}")
    mint_len = b[105]
    budget = b[77]
    return {
        "format": b[0],
        "record_set": bool(b[1]),
        "unit": b[2],
        "daily_limit": int.from_bytes(b[3:7], "big"),
        "refund_key": b[7:40],
        "hardest_bits": b[40:44],
        "last_header": b[44:76].hex(),
        "rolls": b[76],
        "budget_raw": budget,
        "budget": budget or ROLL_BUDGET_DEFAULT,
        "armed": bool(b[78]),
        "mint": b[106:106 + mint_len].decode("ascii", errors="replace"),
        "design": b[106 + mint_len:109 + mint_len],
    }


def auth_message(reader_nonce: bytes, card_nonce: bytes, card_key: bytes) -> bytes:
    """What AUTH signs: SHA-256(T || T || reader (16) || card (16) || card key (33)), T = SHA-256("CashuCard/auth")."""
    return bip340.tagged_hash(AUTH_TAG, reader_nonce + card_nonce + card_key)


# ── helpers ───────────────────────────────────────────────────────────────────
def parse_hex(value: str, expected_len: Optional[int] = None, what: str = "value") -> bytes:
    # spec/CARD-FILE.md: hex is case-insensitive on read and `0x` prefixes are
    # tolerated. That has to include `0X` — a prefix check that is itself
    # case-sensitive would make the spec's claim false for exactly the values
    # the case-insensitivity claim invites.
    stripped = value[2:] if value[:2].lower() == "0x" else value
    try:
        b = bytes.fromhex(stripped)
    except ValueError:
        raise SystemExit(f"{what} is not valid hex: {value!r}")
    if expected_len is not None and len(b) != expected_len:
        raise SystemExit(f"{what} must be {expected_len} bytes ({expected_len*2} hex chars), got {len(b)}")
    return b


def connect(args) -> Card:
    """
    A card with the applet selected. The card file tools ask for the 0.x applet
    (`legacy`) and refuse a card that answers any other major version; every
    other command speaks 2.0 and refuses any other.
    """
    legacy = bool(getattr(args, "legacy", False))
    card = Card(reader_index=args.reader, verbose=args.verbose)
    version = card.select(legacy=legacy)
    major = version[0] if version else None
    if legacy and major != 0:
        raise SystemExit(f"this card answers version {_version_text(version)}; card files are 0.x-only (spec/CARD-FILE.md)")
    if not legacy and major != 2:
        raise SystemExit(f"this card answers version {_version_text(version)}; cardctl speaks protocol 2.0")
    return card


def _version_text(version: bytes) -> str:
    return f"{version[0]}.{version[1]}" if len(version) >= 2 else (_hex(version) or "nothing")


def owner_key(args) -> int:
    """
    The owner's private key for the owner's commands: `--owner-key HEX` (32
    bytes), or the fixed TEST key (p256.TEST_OWNER_PRIVATE) when none is given,
    with a warning: anyone with this repository holds that key.
    """
    value = getattr(args, "owner_key", None)
    if not value or value == "test":
        print("note: signing with cardctl's TEST owner key — bench cards only; anyone with this "
              "repository can administer a card owned by it", file=sys.stderr)
        return p256.TEST_OWNER_PRIVATE
    d = int.from_bytes(parse_hex(value, 32, "--owner-key"), "big")
    if not 0 < d < p256.N:
        raise SystemExit("--owner-key is not a P-256 private key (0 < d < n)")
    return d


def parse_header(value: str, what: str = "--header") -> bytes:
    return parse_hex(value, HEADER_LEN, what)


def check_signature(pubkey: bytes, message: bytes, sig: bytes) -> bool:
    return bip340.verify(bip340.x_only(pubkey), message, sig)



# ── commands ──────────────────────────────────────────────────────────────────
def cmd_readers(args) -> int:
    readers_fn = _load_pyscard()
    found = readers_fn()
    if not found:
        print("No PC/SC readers found.")
        return 1
    for i, r in enumerate(found):
        print(f"[{i}] {r}")
    return 0


def cmd_info(args) -> int:
    card = connect(args)
    i = card.get_info()
    c = card.get_card()
    print(f"applet version   : {i['version']} (format {i['format']})")
    print(f"slots            : {i['max_slots']} total — "
          f"{i['unspent']} unspent, {i['spent']} spent, {i['empty']} empty")
    print(f"capabilities     : 0x{i['caps_raw']:02X} "
          f"(secp256k1 native={i['secp256k1_native']}, schnorr={i['schnorr']})")
    print(f"PIN              : {i['pin_state']} ({i['tries']} tries left)")
    print(f"owner            : {'yes' if i['has_owner'] else 'none — open to the first phone that sets it up'}")
    print(f"record           : {'set, mint ' + c['mint'] if i['record_set'] else 'not set'}")
    print(f"locked           : {'yes' if i['locked'] else 'no'}")
    print(f"clock            : {i['now'] or 'no block header taken yet'}")
    print(f"daily limit      : {i['daily_limit'] or 'none'} (window from {i['window_start']}, "
          f"{i['spent_today']} signed for in it)")
    if "allowance" in i:
        print(f"no-PIN allowance : {i['allowance'] or 'none'} ({i['nopin_spent']} signed for without the PIN)")
    print(f"rollover budget  : {c['rolls']} of {c['budget']} rolls since the owner's last refresh"
          f"{' (spent: the day stands until a refresh)' if c['rolls'] >= c['budget'] else ''}; "
          f"allowance {'armed' if c['armed'] else 'not armed'}")
    print(f"balance          : {card.get_balance()}")
    return 0


def cmd_pubkey(args) -> int:
    card = connect(args)
    pk = card.get_pubkey()
    print(_hex(pk))
    if args.verbose:
        print(f"x-only: {_hex(bip340.x_only(pk))}", file=sys.stderr)
    return 0


def cmd_balance(args) -> int:
    print(connect(args).get_balance())
    return 0


def cmd_slots(args) -> int:
    card = connect(args)
    status = card.get_slot_status()
    print(f"{len(status)} slots ({card.get_proof_count()} non-empty)")
    for i, s in enumerate(status):
        if s != 0x00 or args.all:
            print(f"  [{i:3}] {STATUS_NAMES.get(s, f'unknown({s})')}")
    return 0


def cmd_proof(args) -> int:
    p = connect(args).get_proof(args.slot)
    print(f"slot      : {p['slot']}")
    print(f"status    : {p['status']}")
    print(f"keyset_id : {p['keyset_id']}")
    print(f"amount    : {p['amount']}")
    print(f"nonce     : {_hex(p['nonce'])}")
    print(f"C         : {_hex(p['c'])}")
    print(f"date      : {p.get('date', 0) or 'none'}")
    return 0


def cmd_auth(args) -> int:
    """AUTH: the card proves it holds its key, over 16 random bytes of ours; the BIP-340 signature is checked here."""
    card = connect(args)
    reader = secrets.token_bytes(AUTH_NONCE_LEN)
    card_nonce, sig = card.auth(reader)
    pk = card.get_pubkey()
    ok = check_signature(pk, auth_message(reader, card_nonce, pk), sig)
    print(f"card key  : {_hex(pk)}")
    print(f"signature : {_hex(sig)}")
    print(f"BIP-340   : {'VALID ✅' if ok else 'INVALID ❌'}")
    return 0 if ok else 1


def parse_keyset_id(value: str, what: str = "--keyset") -> bytes:
    """
    A NUT-02 keyset id is 16 hex characters, which is 8 bytes raw.

    Earlier versions accepted an 8-character value and ASCII-encoded it. That
    silently stored half an id — the resulting proof matches no keyset at the
    mint and the funds are stranded on the card. Reject it loudly instead.

    The truncation message only fires for a value that is plausibly half an id,
    i.e. actually hex. Anything else falls through to parse_hex's "not valid
    hex" error rather than sending the operator hunting for a truncation that
    never happened.

    `what` names the thing the operator has to go and fix. The same id arrives
    from two places — the `--keyset` flag and a card file's `keysetId` field —
    and pointing at a CLI flag that the failing command does not even have
    sends them looking in the wrong file.
    """
    v = value.strip().lower()
    if len(v) == 8 and all(c in "0123456789abcdef" for c in v):
        raise SystemExit(
            f"{what} {value!r} is 8 hex chars, but a NUT-02 keyset id is 16 "
            f"(e.g. 0059534ce0bfa19a). Eight characters is half an id; a proof "
            f"loaded with it cannot be spent. Pass the full id."
        )
    raw = parse_hex(v, 8, what.lstrip("-"))
    # NUT-02 v0 ids begin with a 0x00 version byte. cashu-client runs the same
    # check (`requireKeysetV0`) on both the card path and the file path, so an id
    # this tool accepts and writes but the other half refuses is a proof that
    # dies at the boundary — after the slot is spent.
    if raw[0] != 0x00:
        raise SystemExit(
            f"{what} {value!r} must be a NUT-02 v0 keyset id (00 version byte), "
            f"got 0x{raw[0]:02x}"
        )
    return raw



def cmd_load(args) -> int:
    # Parse every argument before touching the reader. VERIFY_PIN decrements the
    # card's retry counter, so running it ahead of validation means a typo'd
    # --keyset costs a PIN attempt on a command that could never have succeeded.
    # Pure argument validation must never require a card tap.
    keyset = parse_keyset_id(args.keyset)
    validate_slot_amount(args.amount)
    nonce = parse_hex(args.nonce, 32, "nonce") if args.nonce else secrets.token_bytes(32)
    if args.c:
        # An explicit --c is claimed to be a real mint signature, so it gets the
        # same check the file path (`_slot_from_json`) runs: a C that is not a
        # compressed on-curve point is an unspendable proof, and LOAD_PROOF has
        # no undo.
        c = parse_hex(args.c, 33, "C")
        if c[0] not in (0x02, 0x03):
            raise SystemExit(
                f"--c must be a compressed secp256k1 point (02/03 prefix), "
                f"got 0x{c[0]:02x}"
            )
        if bip340.lift_x(int.from_bytes(c[1:], "big")) is None:
            raise SystemExit(f"--c is not on the secp256k1 curve: {_hex(c)}")
    else:
        # The random placeholder is deliberately exempt — it is documented as
        # "not a real mint signature" and exists for storage testing, where an
        # off-curve x is fine because nothing will ever try to spend it.
        c = b"\x02" + secrets.token_bytes(32)
    if not 0 <= args.date < 2 ** 32:
        raise SystemExit(f"--date must fit four bytes, got {args.date}")
    owner = owner_key(args) if args.owner else None
    card = connect(args)
    if args.pin:
        card.verify_pin(args.pin.encode())
    if owner is not None:
        # the owner's grant (ALLOW_LOAD): loads in this tap need no PIN
        card.allow_load(owner)
    slot = card.load_proof(keyset, args.amount, nonce, c, args.date)
    print(f"loaded into slot {slot}")
    if not args.nonce:
        print(f"nonce  : {_hex(nonce)}")
    if not args.c:
        print(f"C      : {_hex(c)}  (placeholder, not a real mint signature)")
    return 0


# ── card file (interchange with cashu-client) ─────────────────────────────────
#
# The mint protocol lives in TypeScript (lnflash/cashu-client) and this driver
# is Python, so proofs cross the boundary as a file. The schema is defined once,
# in cashu-client's `src/cardFile.ts`; this is the other half of it.
#
# The field names are the card's own vocabulary — `nonce`, not `secret`, and a
# 16-hex-char `keysetId`. A file that says `secret` was written against a wrong
# model: a NUT-10 P2PK secret is ~150 bytes of JSON and cannot live in a slot.
#
# The schema is published in spec/CARD-FILE.md and test_card_file.py asserts
# this parser against it, the same way test_spec_consistency.py asserts the APDU
# encodings against spec/APDU.md.

CARD_FILE_VERSION = 1

# The published field lists, mirroring cashu-client's SLOT_FIELDS / FILE_FIELDS.
# Kept as the exact names in spec/CARD-FILE.md's tables — test_card_file.py
# parses the document and asserts these against it, so a rename fails in CI.
SLOT_FIELDS = ("keysetId", "amount", "nonce", "C", "spent")
FILE_FIELDS = ("version", "mint", "unit", "cardPubkey", "slots", "note")


def _reject_unknown_fields(raw: dict, known, where: str) -> None:
    """
    Refuse a field this version does not know about.

    The format's whole claim is that a field which drifts fails at the boundary.
    Silently ignoring an unrecognised key is that drift: a future writer adds
    one, forgets to bump `version`, and this side discards it without a word —
    the failure then surfaces at the mint, or as money that quietly went
    nowhere. `version` exists precisely so an additive change announces itself.

    Strict on both sides on purpose: cashu-client's `rejectUnknownFields` does
    exactly this, and a format whose two halves disagree about forward
    compatibility is not one format.
    """
    extra = [k for k in raw if k not in known]
    if extra:
        raise SystemExit(
            f"{where}unknown field(s): {', '.join(sorted(extra))} — bump the "
            f"card file version rather than adding fields silently"
        )


def _slot_from_json(entry, index: int) -> dict:
    """Validate one slot from a card file. Mirrors parseCardSlot in cashu-client."""
    where = f"slot {index}: "
    if not isinstance(entry, dict):
        raise SystemExit(f"{where}expected an object, got {type(entry).__name__}")

    # A file that spells this `secret` was written against the wrong mental
    # model. Say so, rather than reporting it as an unknown field.
    if "nonce" not in entry and "secret" in entry:
        raise SystemExit(
            f'{where}has "secret" but no "nonce" — the card stores the 32-byte '
            f"P2PK nonce, not the secret string (~150 bytes of JSON). See NUT-XX."
        )
    _reject_unknown_fields(entry, SLOT_FIELDS, where)

    amount = validate_slot_amount(entry.get("amount"), where)

    keyset = entry.get("keysetId")
    if not isinstance(keyset, str):
        raise SystemExit(f"{where}keysetId must be a hex string")
    c_hex = entry.get("C")
    if not isinstance(c_hex, str):
        raise SystemExit(f"{where}C must be a hex string")
    nonce_hex = entry.get("nonce")
    if not isinstance(nonce_hex, str):
        raise SystemExit(f"{where}nonce must be a hex string")

    # Required, never defaulted. A file that omits it is not a file of unspent
    # proofs, it is a file whose state is unknown — and guessing "unspent"
    # resurrects settled money as spendable balance. See spec/CARD-FILE.md.
    spent = entry.get("spent")
    if not isinstance(spent, bool):
        raise SystemExit(
            f"{where}spent must be a boolean — without it there is no way to "
            f"tell an unspent proof from one the card already burned, and "
            f"loading the file back would resurrect the spent ones. "
            f"Got {spent!r}."
        )

    try:
        keyset_id = parse_keyset_id(keyset, what="keysetId")
        nonce = parse_hex(nonce_hex, 32, f"{where}nonce")
        c = parse_hex(c_hex, 33, f"{where}C")
    except SystemExit as exc:
        raise SystemExit(f"{where}{exc}" if not str(exc).startswith(where) else str(exc))

    # Same guard cardPubkey gets. A C that is not a compressed point is an
    # unspendable proof, which is the whole reason this validator exists.
    if c[0] not in (0x02, 0x03):
        raise SystemExit(
            f"{where}C must be a compressed secp256k1 point (02/03 prefix), "
            f"got 0x{c[0]:02x}"
        )
    # The prefix alone accepts ~half of all random x values. cashu-client's
    # parseCardFile checks curve membership too, so without this the two halves
    # disagree about one file — and load-file would burn a slot on money nothing
    # can ever spend. lift_x returns None for off-curve x and for x >= p.
    if bip340.lift_x(int.from_bytes(c[1:], "big")) is None:
        raise SystemExit(f"{where}C is not on the secp256k1 curve: {_hex(c)}")

    return {
        "keyset": keyset_id,
        "amount": amount,
        "nonce": nonce,
        "c": c,
        "spent": spent,
    }


def validate_card_doc(doc) -> dict:
    """
    Validate an already-decoded card file document.

    Split out of `read_card_file` so the *writer* can run it too: `cardctl dump`
    used to emit whatever it was handed — `dump --mint ""` exited 0, printed
    "wrote 2 slot(s)", and produced a file this same module refuses. The only
    off-card record of a card's proofs is not a thing to discover is unloadable
    later, possibly after the card has been re-provisioned. cashu-client's
    `serializeCardFile` round-trips through `parseCardFile` for the same reason.
    """
    if not isinstance(doc, dict):
        raise SystemExit("card file must be a JSON object")
    version = doc.get("version")
    # JSON has one number type: JSON.parse turns `1.0` into the number 1, so
    # cashu-client's `!== 1` accepts those bytes and refusing them here would
    # be the two halves disagreeing about one file — the same drift, in the
    # other direction. Integral floats collapse to their integer value; a
    # non-integral version (1.5) stays refused, on both sides.
    if isinstance(version, float) and version.is_integer():
        version = int(version)
    # The bool guard matters: True == 1 in Python, so `!= CARD_FILE_VERSION`
    # alone accepts `"version": true` — a file TypeScript's `!== 1` refuses.
    # Two halves disagreeing about one file is the drift this format exists to
    # prevent. Same trap validate_slot_amount already guards.
    if not isinstance(version, int) or isinstance(version, bool) \
            or version != CARD_FILE_VERSION:
        raise SystemExit(
            f"unsupported card file version {version!r}, "
            f"expected {CARD_FILE_VERSION}"
        )
    _reject_unknown_fields(doc, FILE_FIELDS, "card file: ")
    for field in ("mint", "unit"):
        if not isinstance(doc.get(field), str) or not doc[field]:
            raise SystemExit(f"card file {field} must be a non-empty string")
    pub = doc.get("cardPubkey")
    if not isinstance(pub, str):
        raise SystemExit("card file cardPubkey must be a hex string")
    card_pubkey = parse_hex(pub, 33, "cardPubkey")
    if card_pubkey[0] not in (0x02, 0x03):
        raise SystemExit(
            f"card file cardPubkey must be a compressed secp256k1 point "
            f"(02/03 prefix), got 0x{card_pubkey[0]:02x}"
        )
    if bip340.lift_x(int.from_bytes(card_pubkey[1:], "big")) is None:
        raise SystemExit(
            f"card file cardPubkey is not on the secp256k1 curve: {_hex(card_pubkey)}"
        )
    slots = doc.get("slots")
    if not isinstance(slots, list):
        raise SystemExit("card file slots must be an array")
    parsed_slots = [_slot_from_json(e, i) for i, e in enumerate(slots)]

    # A nonce identifies one proof, and C is the mint's signature over one
    # proof. A file carrying either twice — a hand-merge of two dumps, a
    # corrupted file — would make cmd_load_file write the first and report the
    # second as "already loaded, skipping" (nonce) or burn a slot on a proof
    # the mint rejects as already spent (C): the operator is told a proof is
    # safely on the card that was never written, or loses the slot outright.
    # cashu-client's parseCardFile refuses both kinds in the same pass
    # (seenNonce and seenC); refusing only one here would let the two halves
    # disagree about one file — the drift this format exists to prevent.
    seen = {}
    seen_c = {}
    for i, slot in enumerate(parsed_slots):
        nonce = slot["nonce"]
        if nonce in seen:
            raise SystemExit(
                f"slot {i}: duplicate nonce {_hex(nonce)} (also in slot "
                f"{seen[nonce]}) — a nonce identifies one proof; this file "
                f"claims two"
            )
        seen[nonce] = i
        c = slot["c"]
        if c in seen_c:
            raise SystemExit(
                f"slot {i}: duplicate C {_hex(c)} (also in slot {seen_c[c]}) "
                f"— C is the mint's signature over one proof; a repeat is "
                f"never a coincidence"
            )
        seen_c[c] = i

    return {
        "mint": doc["mint"],
        "unit": doc["unit"],
        "card_pubkey": card_pubkey,
        "slots": parsed_slots,
    }


def read_card_file(path: str) -> dict:
    """Parse and validate a card file. Refuses anything malformed."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        raise SystemExit(f"no such card file: {path}")
    except OSError as exc:
        # A directory, a permission problem, or any other unreadable path gets
        # the same clean exit a missing file does — not a raw traceback.
        raise SystemExit(f"cannot read card file {path}: {exc}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path} is not valid JSON: {exc}")

    return validate_card_doc(doc)


def _nonces_on_card(card) -> dict:
    """
    {nonce: (slot index, status byte)} for every occupied slot.

    This is what makes `load-file` re-runnable. LOAD_PROOF commits one proof at
    a time with no transaction around the file, so any mid-file failure leaves
    part of it on the card; without this, the obvious recovery — run it again —
    writes the already-loaded proofs a second time into fresh slots, inflating
    the on-card balance with duplicates the mint rejects on redemption.

    The status byte comes back with the index because "already there" and
    "already burned" are different answers. A file slot marked unspent whose
    nonce the card has already spent used to be reported as "already loaded,
    skipping" — which reads as "your proof is safely on the card" when the truth
    is the opposite, and the money is gone.
    """
    found = {}
    for index, status in enumerate(card.get_slot_status()):
        if status == 0x00:
            continue
        found.setdefault(card.get_proof(index)["nonce"], (index, status))
    return found


def cmd_load_file(args) -> int:
    """Load every proof in a card file, in order."""
    doc = read_card_file(args.path)

    card = connect(args)
    on_card = card.get_pubkey()
    if on_card != doc["card_pubkey"]:
        # Proofs are P2PK-locked to one card. Loading them onto a different card
        # writes money nothing can ever spend. Checked before the PIN and before
        # any write: there is nothing to undo yet.
        raise SystemExit(
            f"card file is for {_hex(doc['card_pubkey'])}\n"
            f"but this card is  {_hex(on_card)}\n"
            "These proofs are locked to a different card and could never be spent."
        )
    if args.pin:
        card.verify_pin(args.pin.encode())

    # A spent proof has already been burned by the card. LOAD_PROOF has no spent
    # bit, so writing one back returns it as unspent — balance the holder cannot
    # actually move. Dump keeps them because they are still owed at the mint;
    # load must not put them back on a card.
    settled = [s for s in doc["slots"] if s["spent"]]
    loadable = [s for s in doc["slots"] if not s["spent"]]

    # Pre-flight. Everything checkable before the first write happens before the
    # first write, because after it there is no rollback.
    already = _nonces_on_card(card)
    pending = [s for s in loadable if s["nonce"] not in already]
    empty = card.get_info()["empty"]
    if len(pending) > empty:
        raise SystemExit(
            f"card file needs {len(pending)} free slot(s) but this card has "
            f"{empty}. Nothing was written. Free space with `cardctl clear-spent` "
            f"or split the file across cards."
        )

    total = 0
    loaded = 0
    burned = 0
    for slot in doc["slots"]:
        if slot["spent"]:
            continue
        if slot["nonce"] in already:
            index, status = already[slot["nonce"]]
            if status == 0x02:
                # The file says unspent, the card says burned. Reporting this as
                # "already loaded" tells the operator their money is safely on
                # the card when it is already gone — and the summary counts
                # would fold it in with the genuinely-present proofs.
                burned += 1
                print(f"slot {index}: already SPENT on this card, skipping "
                      f"({slot['amount']} {doc['unit']} — the file is stale)")
            else:
                print(f"slot {index}: already loaded, skipping")
            continue
        index = card.load_proof(slot["keyset"], slot["amount"], slot["nonce"], slot["c"])
        already[slot["nonce"]] = (index, 0x01)
        loaded += 1
        total += slot["amount"]
        print(f"slot {index}: {slot['amount']} {doc['unit']}")

    skipped = len(loadable) - loaded - burned
    print(f"loaded {loaded} proof(s), {total} {doc['unit']} total"
          + (f"; {skipped} already on the card" if skipped else "")
          + (f"; {burned} already SPENT on the card" if burned else "")
          + (f"; {len(settled)} spent slot(s) not loaded" if settled else ""))
    return 0


def cmd_dump(args) -> int:
    """
    Write every non-empty slot to a card file for the mint side to redeem,
    except a spent slot whose data fails the slot checks (most likely
    half-cleared by an interrupted CLEAR_SPENT).
    """
    card = connect(args)
    pubkey = card.get_pubkey()
    statuses = card.get_slot_status()

    slots = []
    half_cleared = []
    for index, status in enumerate(statuses):
        if status == 0x00:
            continue
        if status not in (0x01, 0x02):
            # A status byte this tool does not recognise — a newer applet
            # revision, or a corrupted read. Folding it through the spent check
            # below would write it into the file as `spent: false`: unknown
            # state recorded as spendable money, resurrected by the next
            # load-file. Unknown state is refused, never guessed at — the same
            # rule the reader applies to an unknown version. Checked before
            # --unspent-only so the flag cannot silently drop it either.
            raise SystemExit(
                f"slot {index}: unknown status byte 0x{status:02x} — this tool "
                f"knows unspent (0x01) and spent (0x02), and the v1 card file "
                f"cannot represent anything else. Nothing was written. Read "
                f"the slot out with `cardctl proof {index}`."
            )
        if args.unspent_only and status != 0x01:
            continue
        p = card.get_proof(index)
        entry = {
            "keysetId": p["keyset_id"],
            "amount": p["amount"],
            "nonce": _hex(p["nonce"]),
            "C": _hex(p["c"]),
            # The bit that says whether this money still moves. Dropping it
            # keeps the proof and loses the state needed to act on it: the mint
            # side gets N indistinguishable proofs, and a reload resurrects the
            # spent ones as spendable. See spec/CARD-FILE.md.
            "spent": p["status"] == "spent",
        }
        if entry["spent"]:
            # CLEAR_SPENT zeroes a spent slot's data before it marks the slot
            # empty (D14), and the fill is not atomic, so a card pulled
            # mid-CLEAR_SPENT leaves the slot spent with any part of its data
            # zeroed. GET_PROOF still returns it, but its bytes are no longer a
            # proof (spec/APDU.md, CLEAR_SPENT): an amount of 0, or a C that is
            # no longer a point, would make the round-trip check below refuse
            # the whole card over a slot the operator was already clearing.
            # Skip it and say so. A spent slot that fails for another reason (a
            # placeholder C from `load` without --c, a denomination an older
            # cardctl allowed) cannot be redeemed either, so skipping it loses
            # nothing. The slot checks catch a zeroed amount and a C that is
            # no longer a point. A tear that zeroed only keyset or nonce bytes,
            # or part of C whose x still lands on the curve, passes them, and
            # dump writes that slot as spent. Spent slots only: an unspent slot
            # that fails is money, and still refuses the dump.
            try:
                _slot_from_json(entry, index)
            except SystemExit as exc:
                reason = str(exc)
                if reason.startswith(f"slot {index}: "):
                    reason = reason[len(f"slot {index}: "):]
                half_cleared.append(index)
                # CLEAR_SPENT frees every spent slot on the card, so the advice
                # waits for the rest of them to settle: a spent slot is owed
                # until the mint has seen its proof.
                print(
                    f"slot {index}: skipped: spent, and its data is not a proof "
                    f"({reason}); most likely half-cleared by an interrupted "
                    f"CLEAR_SPENT; run clear-spent to free it once every other "
                    f"spent slot in this dump has settled at the mint. "
                    f"`cardctl proof {index}` prints what is left of it.",
                    file=sys.stderr,
                )
                continue
        slots.append(entry)

    note = f"dumped by cardctl from {len(slots)} slot(s)"
    if half_cleared:
        note += (
            f"; skipped spent slot(s) {', '.join(str(i) for i in half_cleared)}, "
            f"whose data is not a proof (most likely half-cleared by an "
            f"interrupted CLEAR_SPENT)"
        )
    doc = {
        "version": CARD_FILE_VERSION,
        "mint": args.mint,
        "unit": args.unit,
        "cardPubkey": _hex(pubkey),
        "slots": slots,
        "note": note,
    }

    # Never emit a document this module would refuse to read back. `dump --mint
    # ""` used to exit 0 and report success while producing an unloadable file —
    # and this file is the card's only off-card record, so the operator finds out
    # long after the card has moved on. The same round-trip cashu-client's
    # `serializeCardFile` does through `parseCardFile`.
    try:
        validate_card_doc(doc)
    except SystemExit as exc:
        # The failure can come from the arguments (fixable: pass a real --mint)
        # or from the card itself, if it was provisioned by an older cardctl that
        # allowed a denomination v1 cannot carry. Say which, and point at the
        # command that still gets the bytes out slot by slot.
        raise SystemExit(
            f"refusing to write a card file this tool could not read back: {exc}\n"
            f"Nothing was written. If the card holds a proof the v1 format "
            f"cannot represent, read it out with `cardctl proof <slot>`."
        )

    text = json.dumps(doc, indent=2)
    if args.out:
        # A card file is a bearer-money artifact and the only off-card record of
        # these proofs. Shell clobber semantics are the wrong default: dumping a
        # second card over card1.json would destroy the first card's only backup.
        if os.path.exists(args.out) and not args.force:
            raise SystemExit(
                f"{args.out} already exists; pass --force to overwrite. "
                f"(It may be the only copy of another card's proofs.)"
            )
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"wrote {len(slots)} slot(s) to {args.out}")
    else:
        print(text)
    return 0


def cmd_clear_spent(args) -> int:
    card = connect(args)
    if args.pin:
        card.verify_pin(args.pin.encode())
    print(f"freed {card.clear_spent()} slot(s)")
    return 0


def cmd_verify_pin(args) -> int:
    connect(args).verify_pin(args.pin.encode())
    print("PIN verified")
    return 0


def cmd_set_pin(args) -> int:
    pin = args.pin.encode()
    check_pin(pin)
    card = connect(args)
    if args.owner:
        # ADD PIN: a card with an owner and no PIN takes one under the owner's grant
        card.allow_load(owner_key(args))
    card.set_pin(pin)
    print("PIN set")
    return 0


def cmd_change_pin(args) -> int:
    """CHANGE_PIN, 2.0: the owner's proof and the new PIN. No old PIN; it unblocks a blocked card."""
    new = args.new.encode()
    check_pin(new)
    owner = owner_key(args)
    connect(args).change_pin(owner, new)
    print("PIN changed (the tries are full, and a blocked card is unblocked)")
    return 0


def cmd_set_owner(args) -> int:
    """SET_OWNER with the anchor header (D20); with --old-owner-key on a card that has an owner."""
    anchor = parse_header(args.anchor, "--anchor") if args.anchor else None
    owner = owner_key(args)
    old = None
    if args.old_owner_key:
        old = int.from_bytes(parse_hex(args.old_owner_key, 32, "--old-owner-key"), "big")
    card = connect(args)
    card.set_owner(p256.public_key(owner), anchor, old)
    print("owner set" + (f"; the clock is anchored at {card.get_info()['now']}" if anchor else
                         " (no anchor: the card's clock is as it was; pass --anchor with the tip header)"))
    return 0


def cmd_set_card(args) -> int:
    refund = parse_hex(args.refund, 33, "--refund") if args.refund else bytes(33)
    card = connect(args)
    info = card.get_info()
    if args.pin:
        card.verify_pin(args.pin.encode())
    card.set_card(args.mint, refund, owner=owner_key(args) if info["has_owner"] else None)
    print("record set")
    return 0


def cmd_set_limit(args) -> int:
    value = limit_value(args.day, args.payment, args.allowance, args.budget)  # checked before the reader
    owner = owner_key(args)
    card = connect(args)
    card.set_limit(owner, args.day, args.payment, args.allowance, args.budget)
    print(f"limits set ({len(value)} bytes)")
    return 0


def cmd_set_header(args) -> int:
    header = parse_header(args.header)
    print(f"clock: {connect(args).set_header(header)}")
    return 0


def cmd_refresh(args) -> int:
    header = parse_header(args.header)
    owner = owner_key(args)
    card = connect(args)
    now = card.refresh(owner, header)
    print(f"refreshed: the rollover budget is full; clock {now}")
    return 0


def cmd_lock(args) -> int:
    owner = owner_key(args)
    card = connect(args)
    if not args.yes:
        print("LOCK_CARD permanently and irreversibly disables all write operations.")
        if input("Type 'lock' to confirm: ").strip() != "lock":
            print("aborted")
            return 1
    if not args.pin:
        raise SystemExit("LOCK_CARD needs the PIN verified in this tap: pass --pin")
    card.verify_pin(args.pin.encode())
    card.lock_card(owner)
    print("card locked (irreversible)")
    return 0


def cmd_apdu(args) -> int:
    card = Card(reader_index=args.reader, verbose=True)
    if not args.no_select:
        card.select()
    try:
        body = card.transmit(parse_hex(args.apdu, None, "apdu"), "raw APDU")
        print(_hex(body) if body else "(no data)")
        return 0
    except CardError as exc:
        print(exc, file=sys.stderr)
        return 1


def cmd_selftest(args) -> int:
    """
    The card-arrival test. Everything the applet claims, proven on real silicon.
    """
    results: List[Tuple[str, bool, str]] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        results.append((name, ok, detail))
        print(f"{'PASS' if ok else 'FAIL'}  {name}{'  — ' + detail if detail else ''}")

    card = Card(reader_index=args.reader, verbose=args.verbose)
    print(f"reader: {card.reader}\n")

    version = card.select()
    record("SELECT applet", *_select_verdict(version))

    info = card.get_info()
    record("GET_INFO", len(info) > 0 and info["max_slots"] == MAX_PROOFS,
           f"v{info['version']}, {info['max_slots']} slots, PIN {info['pin_state']}, "
           f"owner {'yes' if info['has_owner'] else 'none'}")
    record("format 4 (SIG_ALL pieces)", info["format"] == FORMAT, f"format {info['format']}")
    record("Schnorr capability advertised", info["schnorr"], f"caps=0x{info['caps_raw']:02X}")

    # A blocked PIN (GET_INFO byte 7 = 2) pays nothing until the owner's
    # change-pin; AUTH needs no PIN, so the signing rounds still run.
    if info["pin_state"] == "blocked":
        record("PIN state", False, _blocked_pin_detail(info))
    elif info["pin_state"] == "set":
        if getattr(args, "pin", None):
            try:
                card.verify_pin(args.pin.encode())
                record("VERIFY_PIN", True, "the PIN verifies")
            except CardError as exc:
                record("VERIFY_PIN", False, str(exc))
        else:
            print("note  the card has a PIN; pass --pin to check it (AUTH needs none)")

    # Conformance, not mere parseability: spec/APDU.md fixes the wire format at
    # 33-byte compressed. selftest reads the raw bytes so an off-spec applet is
    # a FAIL rather than silently papered over.
    pk_raw = card.get_pubkey(raw=True)
    pk_spec = len(pk_raw) == 33 and pk_raw[0] in (0x02, 0x03)
    pk_form = {33: "compressed", 65: "uncompressed"}.get(len(pk_raw), "unknown")
    record("GET_PUBKEY well-formed", pk_spec,
           f"{_hex(pk_raw)[:20]}… ({len(pk_raw)} bytes, {pk_form})")
    try:
        pk = bip340.compress(pk_raw)
    except ValueError:
        pk = None

    record("GET_BALANCE", True, str(card.get_balance()))

    status = card.get_slot_status()
    record("GET_SLOT_STATUS", len(status) == info["max_slots"],
           f"{len(status)} status bytes")

    c = card.get_card()
    record("GET_CARD", c["format"] == FORMAT,
           f"rolls {c['rolls']} of {c['budget']}, allowance {'armed' if c['armed'] else 'not armed'}")

    def verdict() -> int:
        failed = [n for n, ok, _ in results if not ok]
        print()
        if failed:
            print(f"{len(failed)} check(s) FAILED: {', '.join(failed)}")
            return 1
        print(f"All {len(results)} checks passed on physical hardware.")
        return 0

    # The whole point: does a signature off this card verify against BIP-340?
    all_sigs_ok = True
    for i in range(args.rounds):
        reader = secrets.token_bytes(AUTH_NONCE_LEN)
        card_nonce, sig = card.auth(reader)
        ok = pk is not None and check_signature(pk, auth_message(reader, card_nonce, pk), sig)
        all_sigs_ok &= ok
        record(f"AUTH + BIP-340 verify [{i + 1}/{args.rounds}]", ok,
               "" if ok else f"reader={_hex(reader)} card={_hex(card_nonce)} sig={_hex(sig)}")

    # A fresh nonce per signature is a BIP-340 requirement and a real security
    # property here: a nonce that is a pure function of (d, msg) leaks the key
    # to anyone who can fault-inject two signatures over the same message. The
    # same reader bytes twice must still give two R.
    if args.rounds >= 2:
        fixed = secrets.token_bytes(AUTH_NONCE_LEN)
        (n1, s1), (n2, s2) = card.auth(fixed), card.auth(fixed)
        record("fresh nonce across identical requests", s1[:32] != s2[:32] and n1 != n2,
               "R reused — aux randomness is not working" if s1[:32] == s2[:32] else "")

    rc = verdict()
    return rc if all_sigs_ok else 1


def _select_verdict(version: bytes) -> Tuple[bool, str]:
    """
    Whether the applet version SELECT answered is a build selftest can pass:
    protocol 2.1 or a later 2.x. The 2.x AID answers nothing below 2.0, and a
    2.0 card is the v2.0.0 release, which D26 replaced: it is reinstalled.
    """
    if len(version) < 2:
        return False, "SELECT returned no applet version"
    ver = tuple(version[:2])
    if ver[0] != SELFTEST_MIN_VERSION[0] or ver < SELFTEST_MIN_VERSION:
        return False, (f"applet {ver[0]}.{ver[1]} is not protocol 2.1 or a later 2.x: sweep the balance, then "
                       f"reinstall the tracked CAP (docs/HARDWARE_DEPLOYMENT.md)")
    return True, f"version {ver[0]}.{ver[1]}"


def _blocked_pin_detail(info: dict) -> str:
    """What a blocked PIN (GET_INFO byte 7 = 2) means on a 2.0 card."""
    if info.get("has_owner"):
        return ("blocked (GET_INFO byte 7 = 2): no payment signs until the owner's phone, "
                "or `cardctl change-pin --owner-key …`, sets a new PIN (CHANGE_PIN unblocks)")
    return ("blocked (GET_INFO byte 7 = 2) on a card with no owner: it holds nothing, "
            "and `cardctl set-pin` sets a new PIN")


# ── argument parsing ──────────────────────────────────────────────────────────
def _owner_arg(s, required: bool = False) -> None:
    s.add_argument("--owner-key", required=required,
                   help="the owner's P-256 private key, 32 bytes hex (default: cardctl's TEST key)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cardctl",
        description="PC/SC driver for the Cashu card applet, protocol 2.0 (spec/APDU.md).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Start with:  cardctl readers   then   cardctl selftest",
    )
    p.add_argument("-r", "--reader", type=int, default=0, help="reader index (default 0)")
    p.add_argument("-v", "--verbose", action="store_true", help="log APDUs to stderr")
    p.add_argument("-t", "--timing", action="store_true",
                   help="time every APDU (reader round trip) to stderr, with a summary at exit")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("readers", help="list PC/SC readers").set_defaults(func=cmd_readers)
    sub.add_parser("info", help="version, slots, PIN, owner, clock, limits, rollover budget").set_defaults(func=cmd_info)
    sub.add_parser("pubkey", help="card's compressed secp256k1 public key").set_defaults(func=cmd_pubkey)
    sub.add_parser("balance", help="sum of unspent proof amounts").set_defaults(func=cmd_balance)
    sub.add_parser("auth", help="AUTH: the card proves its key; the signature is verified here").set_defaults(func=cmd_auth)

    s = sub.add_parser("slots", help="per-slot status")
    s.add_argument("--all", action="store_true", help="include empty slots")
    s.set_defaults(func=cmd_slots)

    s = sub.add_parser("proof", help="read a proof slot")
    s.add_argument("slot", type=int)
    s.set_defaults(func=cmd_proof)

    s = sub.add_parser("load", help="LOAD_PROOF into the next free slot")
    s.add_argument("--keyset", required=True,
                   help="NUT-02 keyset id, 16 hex chars (e.g. 0059534ce0bfa19a)")
    s.add_argument("--amount", type=int, required=True)
    s.add_argument("--nonce", help="32-byte P2PK nonce as hex (random if omitted)")
    s.add_argument("--c", help="33-byte C point as hex (placeholder if omitted)")
    s.add_argument("--date", type=int, default=0, help="the piece's locktime, seconds (default 0: none)")
    s.add_argument("--pin", help="verify this PIN first")
    s.add_argument("--owner", action="store_true", help="load under the owner's grant (ALLOW_LOAD), no PIN")
    _owner_arg(s)
    s.set_defaults(func=cmd_load)

    s = sub.add_parser("load-file", help="0.x only: LOAD_PROOF every proof in a card file (spec/CARD-FILE.md)")
    s.add_argument("path", help="card file written by cashu-client")
    s.add_argument("--pin", help="verify this PIN first")
    s.set_defaults(func=cmd_load_file, legacy=True)

    s = sub.add_parser("dump", help="0.x only: write the card's slots out as a card file (spec/CARD-FILE.md)")
    s.add_argument("--mint", required=True, help="mint URL these proofs belong to")
    s.add_argument("--unit", default="sat", help="keyset unit (default: sat)")
    s.add_argument("--out", help="write here instead of stdout")
    s.add_argument("--force", action="store_true",
                   help="overwrite --out if it already exists")
    s.add_argument("--unspent-only", action="store_true",
                   help="skip spent slots (they are still readable, and still owed)")
    s.set_defaults(func=cmd_dump, legacy=True)

    s = sub.add_parser("clear-spent", help="free all spent slots")
    s.add_argument("--pin")
    s.set_defaults(func=cmd_clear_spent)

    s = sub.add_parser("verify-pin", help="verify the PIN for this session")
    s.add_argument("pin")
    s.set_defaults(func=cmd_verify_pin)

    s = sub.add_parser("set-pin", help="set the PIN: an open card, or ADD PIN under the owner's grant (--owner)")
    s.add_argument("pin")
    s.add_argument("--owner", action="store_true", help="the owner's grant first, for a card with an owner and no PIN")
    _owner_arg(s)
    s.set_defaults(func=cmd_set_pin)

    s = sub.add_parser("change-pin", help="the owner sets a new PIN: no old PIN, unblocks a blocked card")
    s.add_argument("new")
    _owner_arg(s)
    s.set_defaults(func=cmd_change_pin)

    s = sub.add_parser("set-owner", help="give the card its owner key, anchored at a block header")
    s.add_argument("--anchor", help="the tip block header, 80 bytes hex (the clock is anchored at it)")
    s.add_argument("--old-owner-key", help="the current owner's private key, on a card that has one")
    _owner_arg(s)
    s.set_defaults(func=cmd_set_owner)

    s = sub.add_parser("set-card", help="write the card record (the mint)")
    s.add_argument("--mint", required=True)
    s.add_argument("--refund", help="33-byte refund key hex (default: none)")
    s.add_argument("--pin", help="verify this PIN first (an open card with a PIN)")
    _owner_arg(s)
    s.set_defaults(func=cmd_set_card)

    s = sub.add_parser("set-limit", help="the owner's limits: day, one payment, no-PIN allowance, rollover budget")
    s.add_argument("--day", type=int, required=True, help="sats a day (0: none)")
    s.add_argument("--payment", type=int, help="sats one payment may take without waiting (0: none)")
    s.add_argument("--allowance", type=int, help="sats a day signed for without the PIN (0: none)")
    s.add_argument("--budget", type=int, help=f"rolls between the owner's refreshes, 1-{ROLL_BUDGET_MOST} (default {ROLL_BUDGET_DEFAULT})")
    _owner_arg(s)
    s.set_defaults(func=cmd_set_limit)

    s = sub.add_parser("set-header", help="SET_HEADER: show the card a block header (its clock moves forward)")
    s.add_argument("--header", required=True, help="80 bytes hex")
    s.set_defaults(func=cmd_set_header)

    s = sub.add_parser("refresh", help="REFRESH: the owner's proof over the tip header; the rollover budget is full again")
    s.add_argument("--header", required=True, help="the tip block header, 80 bytes hex")
    _owner_arg(s)
    s.set_defaults(func=cmd_refresh)

    s = sub.add_parser("lock", help="permanently disable writes (IRREVERSIBLE): the PIN and the owner's proof")
    s.add_argument("--pin")
    s.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    _owner_arg(s)
    s.set_defaults(func=cmd_lock)

    s = sub.add_parser("apdu", help="send a raw APDU (hex)")
    s.add_argument("apdu")
    s.add_argument("--no-select", action="store_true", help="skip SELECT first")
    s.set_defaults(func=cmd_apdu)

    s = sub.add_parser("selftest", help="full hardware check incl. BIP-340 verification of AUTH signatures")
    s.add_argument("--rounds", type=int, default=3, help="AUTH rounds (default 3)")
    s.add_argument("--pin", help="verify this PIN as well (AUTH needs none)")
    s.set_defaults(func=cmd_selftest)

    return p


def main() -> int:
    global TIMING_ENABLED
    args = build_parser().parse_args()
    TIMING_ENABLED = bool(getattr(args, "timing", False))
    try:
        return args.func(args)
    except CardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        # Summarise even on a CardError: the APDUs before the failure are the
        # ones worth knowing about.
        if TIMING_ENABLED and TIMINGS:
            print("\napdu timing (reader round trip):", file=sys.stderr)
            print(summarize_timings(TIMINGS), file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
