"""
APDU encoding tests for cardctl.

These assert the exact bytes cardctl puts on the wire against spec/APDU.md
(protocol 2.0).
Worth having because the alternative is discovering an off-by-one in P1 or a
missing Le byte while hunched over a card reader, where every iteration costs a
re-tap and the failure looks identical to a hardware problem.

No reader and no card required — the PC/SC connection is faked.

Run:  python3 -m pytest test_apdu.py -q     (or: python3 test_apdu.py)
"""

import contextlib
import io
import secrets
import sys
import traceback
import types

import bip340
import cardctl


class FakeConnection:
    """Records transmitted APDUs and replays canned responses."""

    def __init__(self, responses=None):
        self.sent = []
        self.responses = list(responses or [])

    def connect(self):
        pass

    def transmit(self, apdu):
        self.sent.append(bytes(apdu))
        if self.responses:
            data, sw = self.responses.pop(0)
            return list(data), sw >> 8, sw & 0xFF
        return [], 0x90, 0x00

    @property
    def last(self):
        return self.sent[-1]


def make_card(responses=None):
    """A Card wired to a FakeConnection, bypassing PC/SC discovery."""
    card = cardctl.Card.__new__(cardctl.Card)
    card.connection = FakeConnection(responses)
    card.verbose = False
    card.reader = "fake"
    return card


import p256

# A GET_INFO answer of 2.0 (P1 = 2, 43 bytes): version 2.0, 128 slots, 3 unspent,
# 1 spent, 124 empty, caps FF, PIN set, format 4, 3 tries, not locked, record set,
# a daily limit of 5000, an owner, now 1791814824, window 1791800000, 100 spent
# today, no change grant; payment limit 0, allowance 250, 50 signed without the
# PIN; the tag on.
INFO_43 = (bytes([2, 0, 128, 3, 1, 124, 0xFF, 1, 4, 3, 0, 1]) + (5000).to_bytes(4, "big") + b"\x01"
           + (1791814824).to_bytes(4, "big") + (1791800000).to_bytes(4, "big") + (100).to_bytes(4, "big")
           + b"\x00" + (0).to_bytes(4, "big") + (250).to_bytes(4, "big") + (50).to_bytes(4, "big") + b"\x00")
assert len(INFO_43) == 43

# A GET_CARD answer: format 4, record set, sat, limit 5000, no refund key, the
# hardest bits, a header hash, 2 rolls, budget byte 0 (the default, 7), armed,
# 26 zeros, the mint, no design.
_MINT = b"https://forge.flashapp.me"
CARD_ANSWER = (bytes([4, 1, 0]) + (5000).to_bytes(4, "big") + bytes(33) + bytes.fromhex("f01e0217")
               + bytes(range(32)) + bytes([2, 0, 1]) + bytes(26) + bytes([len(_MINT)]) + _MINT + bytes(3))


# ── selection ─────────────────────────────────────────────────────────────────
def test_select_uses_the_11_byte_applet_aid_first():
    # D25: a reader selects the card's applet by its whole AID, F0 CASHUCARD 01.
    card = make_card([(b"\x02\x00", 0x9000)])
    assert card.select() == b"\x02\x00"
    assert card.connection.sent == [bytes.fromhex("00A404000BF043415348554341524401")], \
        [a.hex() for a in card.connection.sent]
    assert cardctl.PACKAGE_AID == b"\xF0" + b"CASHUCARD"
    assert cardctl.APPLET_AID == cardctl.PACKAGE_AID + b"\x01"
    assert cardctl.SELECT_AIDS == (cardctl.APPLET_AID, cardctl.PACKAGE_AID)


def test_select_falls_back_to_the_10_byte_package_aid():
    # The whole AID fails (6A82); the second SELECT is by the package AID.
    card = make_card([(b"", 0x6A82), (b"\x02\x00", 0x9000)])
    assert card.select() == b"\x02\x00"
    assert len(card.connection.sent) == 2
    assert card.connection.sent[1] == bytes.fromhex("00A404000AF0434153485543415244")


class ChipConnection(FakeConnection):
    """A J3R180 as v2.0.0-rc.1 left it (ENG-681): the opener (F0 CASHUCARD 4D)
    instantiated first, then the card's applet (F0 CASHUCARD 01). The chip
    gives a partial name to the first instance whose AID begins with it, so a
    SELECT by the package AID reaches the opener: 9000 with no body, and 6D00
    to the next command. The whole AID reaches the card's applet: 02 00."""

    OPENER = bytes.fromhex("F04341534855434152444D")
    CARD = bytes.fromhex("F043415348554341524401")
    INSTANCES = (OPENER, CARD)  # in the order the chip made them

    def __init__(self):
        super().__init__()
        self.selected = None

    def transmit(self, apdu):
        apdu = bytes(apdu)
        self.sent.append(apdu)
        if apdu[:4] == bytes.fromhex("00A40400"):
            name = apdu[5:5 + apdu[4]]
            match = next((aid for aid in self.INSTANCES if aid.startswith(name)), None)
            if match is None:
                return [], 0x6A, 0x82
            self.selected = match
            return ([0x02, 0x00] if match == self.CARD else []), 0x90, 0x00
        if self.selected == self.CARD and apdu[:2] == bytes([cardctl.CLA, cardctl.INS_GET_INFO]):
            return list(INFO_43), 0x90, 0x00
        return [], 0x6D, 0x00


def chip_card():
    card = make_card()
    card.connection = ChipConnection()
    return card


def test_on_the_chip_select_reaches_the_card_applet_not_the_opener():
    """The ENG-681 failure: selecting the package AID first took the opener's
    9000 for the card, and every command after it answered 6D00. Selecting the
    whole AID first answers 02 00, and GET_INFO then reaches the card."""
    card = chip_card()
    assert card.select() == b"\x02\x00"
    assert card.connection.selected == ChipConnection.CARD
    assert card.connection.sent == [bytes.fromhex("00A404000BF043415348554341524401")]
    assert card.get_info()["version"] == "2.0"

    # The order this replaced, against the same chip: the package AID's 9000
    # was returned as the version, and the opener was what answered next.
    old = chip_card()
    old_order_version = old.transmit(bytes.fromhex("00A404000AF0434153485543415244"), "SELECT")
    assert old_order_version == b"" and old.connection.selected == ChipConnection.OPENER
    try:
        old.get_info()
    except cardctl.CardError as exc:
        assert exc.sw == 0x6D00, exc
    else:
        raise AssertionError("the opener answered GET_INFO")


def test_a_package_aid_9000_with_no_version_falls_through():
    # The whole AID is not answered (6A82) and the package AID reaches the opener
    # (9000, no body): no 2.0 applet answered, so cardctl says the card needs an update
    # rather than returning an empty version.
    card = make_card([(b"", 0x6A82), (b"", 0x9000)])
    try:
        card.select()
    except SystemExit as exc:
        assert "no version" in str(exc) and "update" in str(exc), str(exc)
    else:
        raise AssertionError("a 9000 with no version was taken for the card's applet")
    # and an empty 9000 to the whole AID is passed over too, for the package AID's answer
    card = make_card([(b"", 0x9000), (b"\x02\x00", 0x9000)])
    assert card.select() == b"\x02\x00"
    assert [a[4] for a in card.connection.sent] == [11, 10]


def test_select_names_a_card_that_needs_an_update():
    card = make_card([(b"", 0x6A82), (b"", 0x6A82)])
    try:
        card.select()
    except SystemExit as exc:
        assert "needs an" in str(exc) and "update" in str(exc), str(exc)
    else:
        raise AssertionError("a card with no 2.0 applet was selected")


def test_the_card_file_tools_select_the_0x_aid_and_refuse_any_other_version():
    """dump and load-file are 0.x-only (spec/CARD-FILE.md): they select the 0.x AID,
    and refuse a card that answers it with any major version but 0."""
    card = make_card([(b"\x00\x06", 0x9000)])
    assert card.select(legacy=True) == b"\x00\x06"
    assert card.connection.last == bytes.fromhex("00A4040007D2760000850102")
    for sub, extra in (("dump", ["--mint", "https://forge.flashapp.me"]), ("load-file", ["x.json"])):
        args = cardctl.build_parser().parse_args([sub, *extra])
        assert args.legacy is True, sub
    for sub in ("info", "selftest", "load", "set-owner"):
        flags = {"load": ["--keyset", "0059534ce0bfa19a", "--amount", "1"]}.get(sub, [])
        assert getattr(cardctl.build_parser().parse_args([sub, *flags]), "legacy", False) is False, sub


def test_connect_refuses_a_card_of_the_wrong_major_version():
    class Args:
        reader = 0
        verbose = False
        legacy = False
    real = cardctl.Card
    for legacy, answer, ok in ((False, b"\x02\x00", True), (False, b"\x01\x14", False),
                                (True, b"\x00\x06", True), (True, b"\x02\x00", False)):
        card = make_card([(answer, 0x9000)])
        cardctl.Card = lambda *a, **kw: card
        Args.legacy = legacy
        try:
            try:
                cardctl.connect(Args)
            except SystemExit as exc:
                assert not ok, (legacy, answer, str(exc))
            else:
                assert ok, (legacy, answer)
        finally:
            cardctl.Card = real


# ── read commands: exact bytes from spec/APDU.md ─────────────────────────────
def test_read_command_encodings():
    # Each canned response is long enough not to trip length checks; get_pubkey
    # additionally validates the point encoding, so its reply must parse.
    cases = [
        ("get_info", (), "B0010200 00", INFO_43),
        ("get_pubkey", (), "B0100000 21", b"\x02" + b"\x00" * 32),
        ("get_balance", (), "B0110000 04", b"\x00" * 40),
        ("get_proof_count", (), "B0120000 01", b"\x00" * 40),
        ("get_slot_status", (), "B0140000 80", b"\x00" * 128),
        ("get_card", (), "B0160000 00", CARD_ANSWER),
        ("get_nonce", (), "B0440000 10", bytes(16)),
    ]
    for method, args, expected, response in cases:
        card = make_card([(response, 0x9000)])
        getattr(card, method)(*args)
        assert card.connection.last == bytes.fromhex(expected.replace(" ", "")), \
            f"{method}: {card.connection.last.hex()} != {expected}"


def test_get_pubkey_normalises_a_65_byte_card_to_33_bytes():
    # An applet built before GET_PUBKEY was fixed returns getW()'s 65-byte
    # uncompressed point on real silicon. Every consumer (sign, dump, load-file)
    # goes through Card.get_pubkey(), so the normalisation has to live there —
    # not in the verifier alone, or `dump` would write a 65-byte lock into the
    # card file that validate_card_doc then refuses to read back.
    x = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    y = bytes.fromhex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    uncompressed = b"\x04" + x + y
    card = make_card([(uncompressed, 0x9000), (uncompressed, 0x9000)])
    assert card.get_pubkey() == b"\x02" + x
    assert card.get_pubkey(raw=True) == uncompressed

    compressed = b"\x03" + x
    card = make_card([(compressed, 0x9000)])
    assert card.get_pubkey() == compressed

    card = make_card([(b"\x05" + x + y, 0x9000)])
    try:
        card.get_pubkey()
    except SystemExit as exc:
        assert "GET_PUBKEY" in str(exc)
    else:
        raise AssertionError("get_pubkey accepted a 65-byte blob without 0x04")


def test_get_proof_puts_slot_in_p1_and_asks_for_82_bytes():
    card = make_card([(b"\x01" + b"\x00" * 81, 0x9000)])
    card.get_proof(100)
    assert card.connection.last == bytes.fromhex("B0136400" + "52")


def test_get_proof_parses_the_slot_layout_with_its_date():
    body = (
        b"\x01"                                   # status: unspent
        + bytes.fromhex("0059534ce0bfa19a")       # keyset id (8 RAW bytes)
        + (1234).to_bytes(4, "big")               # amount
        + bytes(range(32))                        # nonce
        + b"\x02" + bytes(range(32))              # C
        + (1900000000).to_bytes(4, "big")         # date
    )
    assert len(body) == 82
    card = make_card([(body, 0x9000)])
    p = card.get_proof(0)
    assert p["status"] == "unspent"
    assert p["amount"] == 1234
    assert p["nonce"] == bytes(range(32))
    assert p["c"][0] == 0x02 and len(p["c"]) == 33
    assert p["date"] == 1900000000


def test_get_proof_on_a_0x_card_asks_for_78_bytes_and_has_no_date():
    body = b"\x01" + bytes.fromhex("0059534ce0bfa19a") + (8).to_bytes(4, "big") + bytes(32) + b"\x02" + bytes(32)
    card = make_card([(b"\x00\x06", 0x9000), (body, 0x9000)])
    card.select(legacy=True)
    p = card.get_proof(3)
    assert card.connection.last == bytes.fromhex("B0130300" + "4E")
    assert "date" not in p and p["amount"] == 8


def test_get_proof_returns_the_full_16_char_keyset_id():
    """
    A NUT-02 keyset id is 16 hex chars. Decoding the 8 stored bytes as ASCII
    would yield only 8 chars — half an id, matching no keyset at the mint.
    """
    body = (
        b"\x01"
        + bytes.fromhex("0059534ce0bfa19a")
        + (1).to_bytes(4, "big")
        + bytes(32)
        + b"\x02" + bytes(32)
        + bytes(4)
    )
    p = make_card([(body, 0x9000)]).get_proof(0)
    assert p["keyset_id"] == "0059534ce0bfa19a", p["keyset_id"]
    assert len(p["keyset_id"]) == 16


def test_parse_keyset_id_rejects_a_half_length_id():
    """Eight hex chars used to be ASCII-encoded, silently stranding the funds."""
    try:
        cardctl.parse_keyset_id("0059534c")
    except SystemExit as exc:
        assert "16" in str(exc), str(exc)
    else:
        raise AssertionError("expected SystemExit for a truncated keyset id")


def test_parse_keyset_id_accepts_a_full_id():
    assert cardctl.parse_keyset_id("0059534ce0bfa19a") == bytes.fromhex("0059534ce0bfa19a")
    # case-insensitive
    assert cardctl.parse_keyset_id("0059534CE0BFA19A") == bytes.fromhex("0059534ce0bfa19a")


def test_parse_keyset_id_does_not_claim_truncation_for_non_hex():
    """An 8-char value that is not hex was never half an id. Saying so sends the
    operator hunting for a truncation that never happened."""
    try:
        cardctl.parse_keyset_id("hellooo1")
    except SystemExit as exc:
        assert "not valid hex" in str(exc), str(exc)
    else:
        raise AssertionError("expected SystemExit for a non-hex keyset id")


def test_get_info_decodes_the_43_byte_answer():
    i = make_card([(INFO_43, 0x9000)]).get_info()
    assert i["version"] == "2.0" and i["version_tuple"] == (2, 0) and i["max_slots"] == 128
    assert i["unspent"] == 3 and i["spent"] == 1 and i["empty"] == 124
    assert i["secp256k1_native"] and i["schnorr"] and i["caps_raw"] == 0xFF
    assert i["pin_state"] == "set" and i["format"] == 4 and i["tries"] == 3
    assert i["locked"] is False and i["record_set"] is True and i["has_owner"] is True
    assert i["daily_limit"] == 5000
    assert i["now"] == 1791814824 and i["window_start"] == 1791800000 and i["spent_today"] == 100
    assert i["change_grant"] is False
    assert i["payment_limit"] == 0 and i["allowance"] == 250 and i["nopin_spent"] == 50
    assert i["tag_off"] is False
    # the three PIN states (byte 7), and a blocked one is "blocked", never "none"
    for state, name in ((0, "none"), (1, "set"), (2, "blocked")):
        body = bytearray(INFO_43)
        body[7] = state
        assert make_card([(bytes(body), 0x9000)]).get_info()["pin_state"] == name
    # thirty bytes (a reader that asked P1 = 0) decodes without the long fields
    short = make_card([(INFO_43[:30], 0x9000)]).get_info()
    assert "allowance" not in short and short["daily_limit"] == 5000


def test_get_card_decodes_the_rollover_bytes():
    c = make_card([(CARD_ANSWER, 0x9000)]).get_card()
    assert c["format"] == 4 and c["record_set"] is True and c["daily_limit"] == 5000
    assert c["rolls"] == 2 and c["budget_raw"] == 0 and c["budget"] == 7, "0 is the default, 7"
    assert c["armed"] is True
    assert c["mint"] == "https://forge.flashapp.me"
    assert c["last_header"] == bytes(range(32)).hex()
    body = bytearray(CARD_ANSWER)
    body[77] = 30
    assert make_card([(bytes(body), 0x9000)]).get_card()["budget"] == 30


def test_cmd_info_says_the_owner_the_clock_and_the_rollover_budget():
    card = make_card([(INFO_43, 0x9000), (CARD_ANSWER, 0x9000), (bytes(4), 0x9000)])
    args = cardctl.build_parser().parse_args(["info"])
    with stubbed_connect(card) as out:
        assert args.func(args) == 0
    text = out.getvalue()
    assert "applet version   : 2.0 (format 4)" in text, text
    assert "owner            : yes" in text, text
    assert "1791814824" in text, text
    assert "rollover budget  : 2 of 7 rolls" in text, text
    assert "allowance armed" in text, text
    assert "no-PIN allowance : 250" in text, text


# ── AUTH ─────────────────────────────────────────────────────────────────────
def test_auth_encoding_and_the_message_it_signs():
    reader = bytes(range(16))
    card = make_card([(bytes(16) + bytes(64), 0x9000)])
    card_nonce, sig = card.auth(reader)
    assert card.connection.last == bytes.fromhex("B0150000") + bytes([16]) + reader + bytes([0x50])
    assert card_nonce == bytes(16) and sig == bytes(64)
    # SHA-256(T || T || reader || card || key), T = SHA-256("CashuCard/auth"): the vector the applet's suite wrote
    import json, pathlib
    vec = json.loads((pathlib.Path(__file__).resolve().parents[2] / "spec" / "vectors" / "secret.json").read_text())
    a = vec["auth"]
    assert a["tag"] == cardctl.AUTH_TAG == "CashuCard/auth"
    msg = cardctl.auth_message(bytes.fromhex(a["readerNonce"]), bytes.fromhex(a["cardNonce"]), bytes.fromhex(vec["cardKey"]))
    assert msg.hex() == a["message"], msg.hex()
    assert cardctl.check_signature(bytes.fromhex(vec["cardKey"]), msg, bytes.fromhex(a["signature"]))


def test_auth_refuses_a_short_reader_nonce_before_sending():
    card = make_card()
    try:
        card.auth(bytes(15))
    except SystemExit:
        pass
    else:
        raise AssertionError("AUTH sent 15 bytes")
    assert card.connection.sent == []


# ── write commands ───────────────────────────────────────────────────────────
def test_load_proof_builds_an_81_byte_payload_with_the_date():
    card = make_card([(b"\x07", 0x9000)])
    keyset = bytes.fromhex("0059534ce0bfa19a")
    slot = card.load_proof(keyset, 4096, bytes(range(32)), b"\x02" + bytes(range(32)), 1900000000)
    assert slot == 7
    sent = card.connection.last
    assert sent[:4] == bytes.fromhex("B0300000")
    assert sent[4] == 0x51, f"Lc should be 81, got {sent[4]}"
    payload = sent[5:5 + 81]
    assert payload[:8] == keyset
    assert int.from_bytes(payload[8:12], "big") == 4096
    assert payload[12:44] == bytes(range(32))
    assert payload[44:77] == b"\x02" + bytes(range(32))
    assert int.from_bytes(payload[77:81], "big") == 1900000000
    assert sent[-1] == 0x01  # Le


def test_load_proof_on_a_0x_card_builds_77_bytes_and_takes_no_date():
    card = make_card([(b"\x00\x06", 0x9000), (b"\x02", 0x9000)])
    card.select(legacy=True)
    card.load_proof(bytes.fromhex("0059534ce0bfa19a"), 8, bytes(32), b"\x02" + bytes(32))
    assert card.connection.last[4] == 0x4D
    try:
        card.load_proof(bytes.fromhex("0059534ce0bfa19a"), 8, bytes(32), b"\x02" + bytes(32), 5)
    except SystemExit:
        pass
    else:
        raise AssertionError("a date was sent to a 0.x card")


def test_load_proof_round_trips_the_keyset_id_through_get_proof():
    """What load writes must be what get_proof reads back — the seam that
    decides whether a proof can be matched to a keyset at the mint."""
    keyset_hex = "008288762774ace1"
    keyset = cardctl.parse_keyset_id(keyset_hex)
    card = make_card([(b"\x00", 0x9000)])
    card.load_proof(keyset, 8, bytes(32), b"\x02" + bytes(32))
    written = card.connection.last[5:5 + 8]

    body = b"\x01" + written + (8).to_bytes(4, "big") + bytes(32) + b"\x02" + bytes(32) + bytes(4)
    read_back = make_card([(body, 0x9000)]).get_proof(0)
    assert read_back["keyset_id"] == keyset_hex, read_back["keyset_id"]


def test_clear_spent_encoding():
    card = make_card([(b"\x04", 0x9000)])
    assert card.clear_spent() == 4
    assert card.connection.last == bytes.fromhex("B0310000" + "01")


def test_set_header_encoding_answers_the_clock():
    header = bytes(range(80))
    card = make_card([((1791814824).to_bytes(4, "big"), 0x9000)])
    assert card.set_header(header) == 1791814824
    assert card.connection.last == bytes.fromhex("B0360000") + bytes([80]) + header + bytes([4])


def test_set_card_record_layout():
    card = make_card()
    card.set_card("https://forge.flashapp.me", bytes([2]) + bytes(32))
    sent = card.connection.last
    assert sent[:4] == bytes.fromhex("B0320000")
    data = sent[5:]
    m = b"https://forge.flashapp.me"
    assert data == bytes([0]) + bytes([2]) + bytes(32) + bytes(65) + bytes([len(m)]) + m, data.hex()


# ── the owner's proof ────────────────────────────────────────────────────────
OWNER = p256.TEST_OWNER_PRIVATE
NONCE = bytes(range(100, 116))


def _owner_card():
    """A card whose first answer is GET_NONCE's sixteen bytes, then 9000s."""
    return make_card([(NONCE, 0x9000)])


def _check_owner_command(card, ins, label, value, p2=0):
    """The last two APDUs are GET_NONCE, then the command with a proof over label || nonce || value."""
    assert card.connection.sent[-2] == bytes.fromhex("B0440000") + bytes([0x10]), card.connection.sent[-2].hex()
    sent = card.connection.sent[-1]
    assert sent[:4] == bytes([0xB0, ins, 0, p2]), sent[:4].hex()
    data = sent[5:5 + sent[4]]
    n = data[0]
    proof, rest = data[1:1 + n], data[1 + n:]
    assert rest == value, (rest.hex(), value.hex())
    assert p256.verify(p256.public_key(OWNER), label.encode() + NONCE + value, proof), label
    return sent


def test_change_pin_is_the_owners_proof_over_the_new_pin_and_no_old_pin():
    card = _owner_card()
    card.change_pin(OWNER, b"567890")
    _check_owner_command(card, 0x42, "CashuCard/change-pin", b"567890")


def test_set_limit_forms_4_8_12_and_13_bytes():
    for kwargs, value in (
        ({}, (5000).to_bytes(4, "big")),
        ({"payment": 1000}, (5000).to_bytes(4, "big") + (1000).to_bytes(4, "big")),
        ({"payment": 0, "allowance": 250}, (5000).to_bytes(4, "big") + bytes(4) + (250).to_bytes(4, "big")),
        ({"payment": 0, "allowance": 250, "budget": 7}, (5000).to_bytes(4, "big") + bytes(4) + (250).to_bytes(4, "big") + b"\x07"),
    ):
        card = _owner_card()
        card.set_limit(OWNER, 5000, **kwargs)
        _check_owner_command(card, 0x34, "CashuCard/set-limit", value)


def test_set_limit_refuses_a_form_that_would_zero_what_it_was_not_given():
    for kwargs in ({"budget": 7}, {"allowance": 5}, {"payment": 0, "budget": 7},
                   {"payment": 0, "allowance": 0, "budget": 0}, {"payment": 0, "allowance": 0, "budget": 31}):
        card = make_card()
        try:
            card.set_limit(OWNER, 5000, **kwargs)
        except SystemExit:
            pass
        else:
            raise AssertionError(f"set_limit accepted {kwargs}")
        assert card.connection.sent == [], f"{kwargs} reached the card"


def test_set_owner_with_and_without_the_anchor_and_the_old_owners_proof():
    pub = p256.public_key(OWNER)
    header = bytes(range(80))
    card = make_card()
    card.set_owner(pub)
    assert card.connection.last == bytes.fromhex("B0430000") + bytes([65]) + pub
    card = make_card()
    card.set_owner(pub, header)
    assert card.connection.last == bytes.fromhex("B0430000") + bytes([145]) + pub + header
    card = _owner_card()
    card.set_owner(pub, header, old_owner=OWNER)
    _check_owner_command(card, 0x43, "CashuCard/set-owner", pub + header)
    for bad in ((pub[:64], None), (pub, header[:79])):
        card = make_card()
        try:
            card.set_owner(*bad)
        except SystemExit:
            pass
        else:
            raise AssertionError("a bad key or anchor was sent")


def test_refresh_is_the_owners_proof_over_the_header_and_answers_the_clock():
    header = bytes(range(80))
    card = make_card([(NONCE, 0x9000), ((1791814824).to_bytes(4, "big"), 0x9000)])
    assert card.refresh(OWNER, header) == 1791814824
    sent = _check_owner_command(card, 0x53, "CashuCard/refresh", header)
    assert sent[-1] == 0x04, "Le 4: the clock"


def test_allow_load_and_lock_are_proofs_over_nothing():
    card = _owner_card()
    card.allow_load(OWNER)
    _check_owner_command(card, 0x45, "CashuCard/load", b"")
    card = _owner_card()
    card.lock_card(OWNER)
    _check_owner_command(card, 0x50, "CashuCard/lock", b"", p2=0xDE)


def test_verify_pin_and_set_pin_encodings():
    card = make_card()
    card.verify_pin(b"1234")
    assert card.connection.last == bytes.fromhex("B0400000") + bytes([4]) + b"1234"
    card.set_pin(b"12345678")
    assert card.connection.last == bytes.fromhex("B0410000") + bytes([8]) + b"12345678"
    for bad in (b"123", b"123456789"):
        try:
            make_card().set_pin(bad)
        except SystemExit:
            pass
        else:
            raise AssertionError(f"a PIN of {len(bad)} bytes was sent")


def test_the_owner_key_defaults_to_the_test_key_with_a_warning():
    class Args:
        owner_key = None
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        assert cardctl.owner_key(Args) == p256.TEST_OWNER_PRIVATE
    assert "TEST owner key" in err.getvalue(), err.getvalue()
    Args.owner_key = "11" * 32
    assert cardctl.owner_key(Args) == int("11" * 32, 16)
    for bad in ("11" * 31, "00" * 32, "ff" * 32):
        Args.owner_key = bad
        try:
            cardctl.owner_key(Args)
        except SystemExit:
            pass
        else:
            raise AssertionError(f"--owner-key {bad} accepted")


# ── CLI wiring ───────────────────────────────────────────────────────────────
# The bug this file exists to prevent lived in cmd_load, not in the helpers it
# calls. Testing parse_keyset_id and Card.load_proof in isolation leaves the one
# line that carried the defect uncovered: a rename of --nonce, or a restored
# `args.keyset.encode()`, keeps every other test green while every loaded proof
# goes back to being unspendable. These drive the real parser into the real
# command, with only the PC/SC connection faked.

@contextlib.contextmanager
def stubbed_connect(card):
    """Point cardctl.connect at a FakeConnection-backed Card.

    Captures the command's own stdout — so the standalone runner's PASS/FAIL
    lines stay readable — and yields the buffer, so a test that cares what the
    command printed can assert on it.
    """
    real = cardctl.connect
    cardctl.connect = lambda args: card
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            yield buf
    finally:
        cardctl.connect = real


def test_cmd_load_puts_the_raw_16_char_keyset_id_on_the_wire():
    card = make_card([(b"\x03", 0x9000)])
    args = cardctl.build_parser().parse_args(
        ["load", "--keyset", "0059534ce0bfa19a", "--amount", "16"]
    )
    with stubbed_connect(card):
        assert args.func(args) == 0
    sent = card.connection.last
    assert sent[:4] == bytes.fromhex("B0300000")
    assert sent[5:13] == bytes.fromhex("0059534ce0bfa19a"), sent[5:13].hex()
    assert int.from_bytes(sent[13:17], "big") == 16, sent[13:17].hex()
    assert sent[4] == 81 and sent[5 + 77:5 + 81] == bytes(4), "a date of 0 by default"


def test_cmd_load_with_the_owners_grant_sends_allow_load_first_and_no_pin():
    card = make_card([(NONCE, 0x9000), (b"", 0x9000), (b"\x03", 0x9000)])
    args = cardctl.build_parser().parse_args(
        ["load", "--keyset", "0059534ce0bfa19a", "--amount", "16", "--owner", "--date", "1900000000"]
    )
    err = io.StringIO()
    with stubbed_connect(card), contextlib.redirect_stderr(err):
        assert args.func(args) == 0
    ins = [apdu[1] for apdu in card.connection.sent]
    assert ins == [cardctl.INS_GET_NONCE, cardctl.INS_ALLOW_LOAD, cardctl.INS_LOAD_PROOF], ins
    assert int.from_bytes(card.connection.last[5 + 77:5 + 81], "big") == 1900000000


def test_cmd_load_accepts_an_on_curve_explicit_c_and_keeps_the_placeholder():
    """The curve check on --c must not break either legitimate path."""
    on_curve = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    card = make_card([(b"\x03", 0x9000)])
    args = cardctl.build_parser().parse_args(
        ["load", "--keyset", "0059534ce0bfa19a", "--amount", "16",
         "--c", on_curve]
    )
    with stubbed_connect(card):
        assert args.func(args) == 0
    assert card.connection.last[5 + 44:5 + 77] == bytes.fromhex(on_curve), \
        card.connection.last.hex()

    card = make_card([(b"\x03", 0x9000)])
    args = cardctl.build_parser().parse_args(
        ["load", "--keyset", "0059534ce0bfa19a", "--amount", "16"]
    )
    with stubbed_connect(card):
        assert args.func(args) == 0, "placeholder default must still load"


def test_cmd_load_rejects_a_half_length_keyset_id():
    card = make_card([(b"\x03", 0x9000)])
    args = cardctl.build_parser().parse_args(
        ["load", "--keyset", "0059534c", "--amount", "16"]
    )
    with stubbed_connect(card):
        try:
            args.func(args)
        except SystemExit as exc:
            assert "16" in str(exc), str(exc)
        else:
            raise AssertionError("cmd_load accepted a half-length keyset id")
    assert card.connection.sent == [], "nothing should reach the card"


def test_cmd_load_validates_arguments_before_opening_the_reader():
    """A bad --keyset must cost nothing — not even a PIN attempt.

    VERIFY_PIN decrements the card's retry counter and locks the card after a
    few misses. If cmd_load connects and verifies before parsing, then
    `load --keyset 0059534c --pin 4321` burns a retry on a command that could
    never have succeeded. The previous test only proves this by accident: it
    passes no --pin, so the VERIFY_PIN branch is never reached regardless of
    ordering. This one passes one, and also asserts the reader was never opened
    — the transmit log alone cannot distinguish "did not connect" from
    "connected and sent nothing".
    """
    bad = [
        # a half-length keyset id, and a nonce that is 31 bytes instead of 32
        ["--keyset", "0059534c", "--amount", "16", "--pin", "4321"],
        ["--keyset", "0059534ce0bfa19a", "--amount", "16", "--pin", "4321",
         "--nonce", "00" * 31],
        # ...and a C that is 32 bytes instead of the compressed-point 33
        ["--keyset", "0059534ce0bfa19a", "--amount", "16", "--pin", "4321",
         "--c", "00" * 32],
        # ...and a 33-byte C with a bad prefix, and one whose x is not on the
        # curve. The file path (`_slot_from_json`) refuses both; an explicit
        # --c must be held to the same rule, or a typo burns a slot on money
        # nothing can spend and `dump` then refuses the whole card.
        ["--keyset", "0059534ce0bfa19a", "--amount", "16", "--pin", "4321",
         "--c", "05" + "cd" * 32],
        ["--keyset", "0059534ce0bfa19a", "--amount", "16", "--pin", "4321",
         "--c", "02" + "cd" * 32],
        # ...and the three amounts the card's 4-byte field or a mint keyset
        # cannot represent. These used to reach the card: 2**32 died on a bare
        # OverflowError out of load_proof, and 0 burned a slot on a worthless
        # proof, both after VERIFY_PIN had already spent a retry.
        ["--keyset", "0059534ce0bfa19a", "--amount", "4294967296", "--pin", "4321"],
        ["--keyset", "0059534ce0bfa19a", "--amount", "0", "--pin", "4321"],
        ["--keyset", "0059534ce0bfa19a", "--amount", "5", "--pin", "4321"],
    ]
    for flags in bad:
        card = make_card([(b"\x03", 0x9000)])
        args = cardctl.build_parser().parse_args(["load", *flags])
        connects = []
        real = cardctl.connect
        cardctl.connect = lambda a: (connects.append(a), card)[1]
        try:
            try:
                args.func(args)
            except SystemExit:
                pass
            else:
                raise AssertionError(f"cmd_load accepted bad arguments: {flags}")
        finally:
            cardctl.connect = real
        assert connects == [], f"cmd_load opened the reader before validating: {flags}"
        assert card.connection.sent == [], \
            f"cmd_load transmitted before validating {flags}: " \
            f"{[a.hex() for a in card.connection.sent]}"


def test_cmd_load_reads_the_nonce_flag_it_declares():
    """cmd_load reads args.nonce; build_parser must declare --nonce."""
    nonce = bytes(range(32))
    card = make_card([(b"\x00", 0x9000)])
    args = cardctl.build_parser().parse_args(
        ["load", "--keyset", "0059534ce0bfa19a", "--amount", "1", "--nonce", nonce.hex()]
    )
    with stubbed_connect(card):
        assert args.func(args) == 0
    assert card.connection.last[17:49] == nonce, card.connection.last[17:49].hex()


def test_cmd_load_generates_a_fresh_nonce_per_proof():
    """A constant nonce makes every rebuilt P2PK secret identical: the card
    refuses the second (6A94), and the mint would see one secret twice."""
    seen = []
    for _ in range(2):
        card = make_card([(b"\x00", 0x9000)])
        args = cardctl.build_parser().parse_args(
            ["load", "--keyset", "0059534ce0bfa19a", "--amount", "1"]
        )
        with stubbed_connect(card):
            assert args.func(args) == 0
        seen.append(card.connection.last[17:49])
    assert seen[0] != seen[1], f"nonce is not fresh per proof: {seen[0].hex()}"
    assert seen[0] != bytes(32), "nonce is all zeros"


def test_load_parser_no_longer_accepts_keyset_hex():
    """--keyset-hex selected the ASCII path this PR deleted. It must stay gone,
    or a stale runbook silently re-enables half-id encoding.

    A bare `except SystemExit: pass` would not prove that: argparse exits 2 for
    any parser failure, so renaming --keyset would keep this green while saying
    nothing about --keyset-hex. Assert on the message argparse actually wrote.
    """
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        try:
            cardctl.build_parser().parse_args(
                ["load", "--keyset", "0059534ce0bfa19a", "--amount", "1", "--keyset-hex"]
            )
        except SystemExit:
            pass
        else:
            raise AssertionError("--keyset-hex is still accepted")
    assert "unrecognized arguments: --keyset-hex" in buf.getvalue(), buf.getvalue()


def test_cmd_proof_prints_the_full_keyset_id_the_nonce_and_the_date():
    nonce = bytes(range(32, 64))
    body = (
        b"\x01"
        + bytes.fromhex("0059534ce0bfa19a")
        + (4242).to_bytes(4, "big")
        + nonce
        + b"\x02" + bytes(range(32))
        + (1900000000).to_bytes(4, "big")
    )
    assert len(body) == 82
    card = make_card([(body, 0x9000)])
    args = cardctl.build_parser().parse_args(["proof", "0"])
    with stubbed_connect(card) as out:
        assert args.func(args) == 0
    printed = out.getvalue()
    assert "0059534ce0bfa19a" in printed, printed
    assert nonce.hex() in printed.lower(), printed
    assert "4242" in printed, printed
    assert "1900000000" in printed, printed


def test_the_0x_commands_are_gone_from_the_parser():
    """SPEND_PROOF, SIGN_ARBITRARY, CLEAR_PIN, SET_PUK and UNBLOCK_PIN are not in
    2.0 (D18). Their subcommands must not come back: each would send a 2.0 card
    an opcode that now means something else (0x43 is SET_OWNER, 0x44 GET_NONCE,
    0x45 ALLOW_LOAD)."""
    for gone in ("spend", "sign", "clear-pin", "set-puk", "unblock-pin"):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            try:
                cardctl.build_parser().parse_args([gone])
            except SystemExit:
                pass
            else:
                raise AssertionError(f"`{gone}` still parses")
        assert "invalid choice" in err.getvalue(), err.getvalue()
    for name in ("INS_SPEND_PROOF", "INS_SIGN_ARBITRARY", "INS_CLEAR_PIN", "INS_SET_PUK", "INS_UNBLOCK_PIN"):
        assert not hasattr(cardctl, name), name


# ── selftest against a model of the 2.0 applet ───────────────────────────────
# selftest decides its next APDU from the last answer, so a list of canned
# responses cannot drive it. These tests run the real command against a small
# model of the applet: GET_INFO's PIN state, VERIFY_PIN's counter, and AUTH,
# which signs for real (BIP-340) over the tagged message.

_CARD_SECKEY = 0x1F0E2D3C4B5A69788796A5B4C3D2E1F00112233445566778899AABBCCDDEEFF0


def _bip340_sign(seckey: int, msg: bytes) -> bytes:
    """BIP-340 signing with fresh aux randomness, standing in for the card."""
    n = bip340.N
    pub = bip340._point_mul(bip340.G, seckey)
    d = seckey if pub[1] % 2 == 0 else n - seckey
    px = pub[0].to_bytes(32, "big")
    aux = bip340.tagged_hash("BIP0340/aux", secrets.token_bytes(32))
    t = (d ^ int.from_bytes(aux, "big")).to_bytes(32, "big")
    k0 = int.from_bytes(bip340.tagged_hash("BIP0340/nonce", t + px + msg), "big") % n
    r = bip340._point_mul(bip340.G, k0)
    k = k0 if r[1] % 2 == 0 else n - k0
    rx = r[0].to_bytes(32, "big")
    e = int.from_bytes(bip340.tagged_hash("BIP0340/challenge", rx + px + msg), "big") % n
    return rx + ((k + e * d) % n).to_bytes(32, "big")


class FakeApplet:
    """A PC/SC connection answering like the 2.0 applet, as far as selftest goes."""

    def __init__(self, version=(2, 0), pin_state=1, pin=b"1234", has_owner=True, fixed_aux=False):
        self.version = bytes(version)
        self.pin_state = pin_state
        self.pin = pin
        self.tries = 3 if pin_state == 1 else 0
        self.has_owner = has_owner
        self.fixed_aux = fixed_aux
        self.sent = []
        pub = bip340._point_mul(bip340.G, _CARD_SECKEY)
        self.pubkey = bytes([2 | (pub[1] & 1)]) + pub[0].to_bytes(32, "big")

    def connect(self):
        pass

    @property
    def ins_sent(self):
        """INS of every APDU after SELECT, in order."""
        return [apdu[1] for apdu in self.sent if apdu[:2] != b"\x00\xA4"]

    def transmit(self, apdu):
        apdu = bytes(apdu)
        self.sent.append(apdu)
        body, sw = self._answer(apdu)
        return list(body), sw >> 8, sw & 0xFF

    def _answer(self, apdu):
        if apdu[:2] == b"\x00\xA4":
            return self.version, 0x9000
        ins = apdu[1]
        if ins == cardctl.INS_GET_INFO:
            body = bytearray(INFO_43)
            body[0:2] = self.version
            body[7] = self.pin_state
            body[9] = self.tries
            body[16] = 1 if self.has_owner else 0
            return bytes(body), 0x9000
        if ins == cardctl.INS_GET_PUBKEY:
            return self.pubkey, 0x9000
        if ins == cardctl.INS_GET_BALANCE:
            return (21).to_bytes(4, "big"), 0x9000
        if ins == cardctl.INS_GET_SLOT_STATUS:
            return bytes(128), 0x9000
        if ins == cardctl.INS_GET_CARD:
            return CARD_ANSWER, 0x9000
        if ins == cardctl.INS_VERIFY_PIN:
            if self.pin_state == 0:
                return b"", 0x6984
            if self.pin_state == 2 or self.tries == 0:
                return b"", 0x6983
            if apdu[5:5 + apdu[4]] == self.pin:
                self.tries = 3
                return b"", 0x9000
            self.tries -= 1
            if self.tries == 0:
                self.pin_state = 2
                return b"", 0x6983
            return b"", 0x63C0 | self.tries
        if ins == cardctl.INS_AUTH:
            reader = apdu[5:5 + 16]
            card = bytes(16) if self.fixed_aux else secrets.token_bytes(16)
            msg = cardctl.auth_message(reader, card, self.pubkey)
            sig = _bip340_sign(_CARD_SECKEY, msg) if not self.fixed_aux else _bip340_sign_fixed(_CARD_SECKEY, msg)
            return card + sig, 0x9000
        return b"", 0x6D00


def _bip340_sign_fixed(seckey: int, msg: bytes) -> bytes:
    """BIP-340 with a constant aux and a constant card nonce: what a card with broken randomness would give."""
    n = bip340.N
    pub = bip340._point_mul(bip340.G, seckey)
    d = seckey if pub[1] % 2 == 0 else n - seckey
    px = pub[0].to_bytes(32, "big")
    t = (d ^ int.from_bytes(bip340.tagged_hash("BIP0340/aux", bytes(32)), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(bip340.tagged_hash("BIP0340/nonce", t + px + msg), "big") % n
    r = bip340._point_mul(bip340.G, k0)
    k = k0 if r[1] % 2 == 0 else n - k0
    rx = r[0].to_bytes(32, "big")
    e = int.from_bytes(bip340.tagged_hash("BIP0340/challenge", rx + px + msg), "big") % n
    return rx + ((k + e * d) % n).to_bytes(32, "big")


def run_selftest(applet, *flags):
    """Run `cardctl selftest <flags>` against `applet`; (exit code, stdout)."""
    card = cardctl.Card.__new__(cardctl.Card)
    card.connection = applet
    card.verbose = False
    card.reader = "fake"
    args = cardctl.build_parser().parse_args(["selftest", *flags])
    real = cardctl.Card
    cardctl.Card = lambda *a, **kw: card
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = args.func(args)
    finally:
        cardctl.Card = real
    return rc, buf.getvalue()


def test_selftest_passes_a_2_0_card_and_verifies_every_auth_signature():
    """Also proves the model signs for real, which the tests below rely on."""
    applet = FakeApplet(pin_state=1)
    rc, out = run_selftest(applet, "--pin", "1234")
    assert rc == 0, out
    assert "All 13 checks passed" in out, out
    ins = applet.ins_sent
    assert ins.count(cardctl.INS_AUTH) == 5, ins
    assert cardctl.INS_VERIFY_PIN in ins


def test_selftest_needs_no_pin_for_auth():
    applet = FakeApplet(pin_state=1)
    rc, out = run_selftest(applet)
    assert rc == 0, out
    assert cardctl.INS_VERIFY_PIN not in applet.ins_sent
    assert "pass --pin to check it" in out, out


def test_selftest_fails_a_blocked_pin_and_names_the_owners_change_pin():
    """GET_INFO byte 7 = 2 is a PIN that exists and cannot verify. selftest must
    not send VERIFY_PIN (it cannot succeed), must fail the card, and must say
    what unblocks it on 2.0: the owner's CHANGE_PIN. AUTH still runs."""
    applet = FakeApplet(pin_state=2)
    rc, out = run_selftest(applet, "--pin", "1234")
    assert rc == 1, out
    assert cardctl.INS_VERIFY_PIN not in applet.ins_sent, "VERIFY_PIN cannot succeed on a blocked card"
    assert "FAIL  PIN state" in out and "change-pin" in out and "CHANGE_PIN unblocks" in out, out
    assert "1 check(s) FAILED: PIN state" in out, out
    for ins in (cardctl.INS_GET_PUBKEY, cardctl.INS_GET_BALANCE, cardctl.INS_GET_SLOT_STATUS, cardctl.INS_AUTH):
        assert ins in applet.ins_sent, f"INS {ins:02X} was not sent"


def test_selftest_fails_a_card_that_is_not_2_0():
    for version in ((1, 20), (0, 6), (3, 0)):
        rc, out = run_selftest(FakeApplet(version=version, pin_state=0))
        assert rc == 1, (version, out)
        assert "FAIL  SELECT applet" in out, out


def test_selftest_fails_a_card_whose_signatures_repeat_their_nonce():
    rc, out = run_selftest(FakeApplet(pin_state=0, fixed_aux=True))
    assert rc == 1, out
    assert "FAIL  fresh nonce across identical requests" in out, out


def test_select_verdict_passes_only_2_x_at_or_over_2_0():
    assert cardctl._select_verdict(bytes([2, 0])) == (True, "version 2.0")
    assert cardctl._select_verdict(bytes([2, 3]))[0] is True
    for version in (bytes([1, 20]), bytes([0, 6]), bytes([3, 0])):
        ok, detail = cardctl._select_verdict(version)
        assert ok is False and "not protocol 2.0" in detail and "reinstall the tracked CAP" in detail, detail
    ok, detail = cardctl._select_verdict(b"")
    assert ok is False and "no applet version" in detail, detail


# ── error handling ───────────────────────────────────────────────────────────
def test_status_words_are_translated():
    assert "already spent" in cardctl.describe_sw(0x6985)
    assert "slot is empty" in cardctl.describe_sw(0x6A88)
    assert "needs an update" in cardctl.describe_sw(0x6A82)
    assert "PIN blocked" in cardctl.describe_sw(0x6983) and "change-pin" in cardctl.describe_sw(0x6983)
    assert "2 retries remaining" in cardctl.describe_sw(0x63C2)
    assert "0 retries remaining" in cardctl.describe_sw(0x63C0)
    assert "LOCK_CARD" in cardctl.describe_sw(0x6986)
    assert "owner's grant" in cardctl.describe_sw(0x6982)
    assert "day's limit" in cardctl.describe_sw(0x6A8F)
    assert "no owner" in cardctl.describe_sw(0x6A90)
    assert "owner's proof" in cardctl.describe_sw(0x6A91)
    assert "work" in cardctl.describe_sw(0x6A93)
    assert "PIN needed" in cardctl.describe_sw(0x6A94)
    for sw in (0x6A8C, 0x6A8D, 0x6A8E, 0x6A96, 0x6B00, 0x6A86, 0x6A80):
        assert cardctl.describe_sw(sw) != "unknown status word", hex(sw)
    assert "PUK" not in " ".join(cardctl.SW_MEANINGS.values())


def test_non_9000_raises_carderror_with_context():
    card = make_card([(b"", 0x6A8F)])
    try:
        card.send(cardctl.INS_SPEND_ALL_SIGN, le=0x40, context="SPEND_ALL_SIGN")
    except cardctl.CardError as exc:
        assert exc.sw == 0x6A8F
        assert "SPEND_ALL_SIGN" in str(exc) and "day's limit" in str(exc)
    else:
        raise AssertionError("expected CardError")


# ── APDU timing (--timing) ───────────────────────────────────────────────────
def test_transmit_records_one_timing_row_per_apdu_named_by_context():
    cardctl.TIMINGS.clear()
    card = make_card([(b"\x02\x00", 0x9000), (INFO_43, 0x9000)])
    card.select()
    card.get_info()
    contexts = [ctx for ctx, _ in cardctl.TIMINGS]
    assert contexts == ["SELECT", "GET_INFO"], contexts
    assert all(ms >= 0.0 for _, ms in cardctl.TIMINGS)


def test_a_failed_apdu_is_still_timed():
    # The row lands before the status word is judged: a 6982 that took 700 ms
    # is exactly the kind of number a timing run exists to show.
    cardctl.TIMINGS.clear()
    card = make_card([(b"", 0x6982)])
    try:
        card.send(cardctl.INS_SPEND_ALL_SIGN, le=0x40, context="SPEND_ALL_SIGN")
    except cardctl.CardError:
        pass
    assert [ctx for ctx, _ in cardctl.TIMINGS] == ["SPEND_ALL_SIGN"]


def test_timing_flag_prints_each_apdu_only_when_enabled():
    cardctl.TIMINGS.clear()
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        make_card([(b"\x02\x00", 0x9000)]).select()
    assert "⏱" not in err.getvalue()

    cardctl.TIMING_ENABLED = True
    try:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            make_card([(b"\x02\x00", 0x9000)]).select()
    finally:
        cardctl.TIMING_ENABLED = False
    assert "⏱ SELECT" in err.getvalue(), err.getvalue()
    assert err.getvalue().rstrip().endswith("ms")


def test_summarize_timings_groups_by_command_with_median_not_mean():
    rows = [("SELECT", 60.0),
            ("SPEND_ALL_SIGN", 700.0), ("SPEND_ALL_SIGN", 740.0), ("SPEND_ALL_SIGN", 3000.0)]
    text = cardctl.summarize_timings(rows)
    lines = text.splitlines()
    assert lines[0].split() == ["command", "n", "min", "median", "max", "total"]
    spend = next(l for l in lines if l.startswith("SPEND_ALL_SIGN")).split()
    # n=3, min 700, median 740 (a mean would say 1480), max 3000, total 4440
    assert spend[1:] == ["3", "700.0", "740.0", "3000.0", "4440.0"], spend
    assert lines[-1].startswith("4 APDU(s), 4500.0 ms")


def test_summarize_timings_with_no_rows_does_not_crash():
    assert cardctl.summarize_timings([]) == "no APDUs sent"


def test_timing_flag_is_global_and_off_by_default():
    parser = cardctl.build_parser()
    assert parser.parse_args(["info"]).timing is False
    assert parser.parse_args(["--timing", "selftest", "--rounds", "5"]).timing is True
    assert parser.parse_args(["-t", "auth"]).timing is True

if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and isinstance(fn, types.FunctionType):
            try:
                fn()
                print(f"PASS  {name}")
            # Not just AssertionError. cardctl reports operator errors by raising
            # SystemExit, and a parser/command mismatch surfaces as AttributeError
            # — both were verified to escape an AssertionError-only handler, kill
            # the run with no summary line, and silently skip every later test.
            # A detected regression must read as a FAIL, not as a crash.
            # SystemExit is spelled out because it derives from BaseException, not
            # Exception; everything else a test can raise is already covered.
            except (SystemExit, Exception) as exc:
                failures += 1
                print(f"FAIL  {name}: {type(exc).__name__}: {exc}")
                if not isinstance(exc, (AssertionError, SystemExit)):
                    traceback.print_exc()
    print(f"\n{'all tests passed' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)

