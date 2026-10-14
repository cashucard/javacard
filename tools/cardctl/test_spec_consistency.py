#!/usr/bin/env python3
"""
Asserts that spec/APDU.md, spec/NUT-XX.md, cardctl.py and CashuApplet.java
still agree, for protocol 2.0.

This repo's characteristic bug is not a crash — it is a document and an
implementation drifting apart while both look fine on their own. It happened
three times on the 0.x wire:

  * `keyset_id` documented as ASCII bytes, so the driver ASCII-encoded it and
    stored half a NUT-02 id. Every test passed; every loaded proof was
    unspendable.
  * the 32-byte field documented as the "secret", which cannot fit — it is the
    nonce.
  * `SPEND_PROOF`'s message documented as something other than what NUT-XX
    specified.

Each one was found by a human reading two files side by side. These tests do
it on every push, for the 2.0 wire.

Three artefacts have to agree, so all three are read here:

  * spec/APDU.md (and NUT-XX.md) is *parsed*, never imported from — a shared
    constant cannot catch a doc that lies, and the doc is what implementers read.
  * cardctl.py is *driven*, not read: the documented header, Lc/Le, response
    sizes and field order are checked against the bytes the real encoder puts
    on the wire. Completeness ratchets fail the day a command cardctl drives is
    added to the doc and to cardctl but not to the case tables here.
  * CashuApplet.java's constants are scraped with a regex — no JVM needed —
    because the applet is the copy that writes EEPROM.

docs/HARDWARE_DEPLOYMENT.md is read for the version a good card answers.

Runs with no card, no reader and no pyscard.
"""
import json
import pathlib
import re
import sys
import traceback

import cardctl
import p256
from test_apdu import make_card, INFO_43, CARD_ANSWER

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC_DIR = ROOT / "spec"
APDU_MD = SPEC_DIR / "APDU.md"
NUT_XX_MD = SPEC_DIR / "NUT-XX.md"
SECRET_JSON = SPEC_DIR / "vectors" / "secret.json"
APPLET_JAVA = ROOT / "applet" / "src" / "main" / "java" / "me" / "flashapp" / "cashu" / "CashuApplet.java"
DEPLOYMENT_MD = ROOT / "docs" / "HARDWARE_DEPLOYMENT.md"

_FIELD_KEYWORDS = (
    ("status", r"status"),
    ("keyset_id", r"keyset"),
    ("amount", r"amount"),
    ("nonce", r"nonce"),
    ("date", r"date"),
    ("c", r"\bc\b"),
)


def _apdu_text() -> str:
    return APDU_MD.read_text(encoding="utf-8")


def _applet_text() -> str:
    return APPLET_JAVA.read_text(encoding="utf-8")


def _heading_body(pattern: str) -> str:
    """The body of the first `##`/`###` heading matching `pattern`."""
    m = re.search(rf"^#{{2,3}} {pattern}\s*$(.*?)(?=^#{{2,3}} |\Z)", _apdu_text(), re.M | re.S)
    assert m, f"APDU.md has no section whose heading matches /{pattern}/"
    return m.group(1)


def _section(name: str) -> str:
    """The body of `### NAME (0xII)`, the opcode matched as a wildcard."""
    m = re.search(
        rf"^### {name} \(0x[0-9A-Fa-f]{{2}}\)\s*$(.*?)(?=^#{{2,3}} |\Z)",
        _apdu_text(), re.M | re.S,
    )
    assert m, f"APDU.md has no ### {name} section"
    return m.group(1)


def _row(section: str, field: str) -> str:
    """The value of `| field | value |` in a command's header table, backticks stripped."""
    m = re.search(rf"^\| {re.escape(field)} \| (.+?) \|$", section, re.M)
    assert m, f"no `{field}` row"
    return m.group(1).replace("`", "").strip()


def _hex_spans(text: str) -> list:
    """Every backticked run of hex pairs in `text`, as bytes."""
    spans = []
    for span in re.findall(r"`([0-9A-Fa-f][0-9A-Fa-f ]*)`", text):
        cleaned = span.replace(" ", "")
        if cleaned and len(cleaned) % 2 == 0:
            spans.append(bytes.fromhex(cleaned))
    return spans


def _command_headings() -> list:
    """Every `### NAME (0xII)` as (name, opcode). SELECT is a `##` heading."""
    headings = re.findall(r"^### ([A-Z_]+) \(0x([0-9A-Fa-f]{2})\)", _apdu_text(), re.M)
    assert headings, "no command headings found — did APDU.md's format change?"
    return headings


def _applet_ins() -> dict:
    return {n: int(v, 16) for n, v in re.findall(r"static final byte INS_(\w+)\s*=\s*\(byte\)\s*0x([0-9A-Fa-f]{2})", _applet_text())}


def _applet_shorts() -> dict:
    return {n: int(v) for n, v in re.findall(r"static final short (\w+)\s*=\s*\(short\)\s*(\d+)\s*;", _applet_text())}


def _applet_label(name: str) -> str:
    """A label byte array in the applet, as text: LABEL_X = { 'C','a', ... }."""
    m = re.search(rf"(?:static final byte\[\] {name}) = \{{(.*?)\}};", _applet_text(), re.S)
    assert m, f"no {name} in {APPLET_JAVA.name}"
    return "".join(re.findall(r"'(.)'", m.group(1)))


def _canonical(description: str, where: str) -> str:
    text = description.lower()
    for name, pattern in _FIELD_KEYWORDS:
        if re.search(pattern, text):
            return name
    raise AssertionError(f"{where}: cannot tell which field {description!r} describes")


# ── the command set ───────────────────────────────────────────────────────────
def test_every_documented_command_matches_its_ins_constant():
    """`### GET_PROOF (0x13)` must equal `INS_GET_PROOF = 0x13` in cardctl."""
    for name, hex_value in _command_headings():
        const = f"INS_{name}"
        assert hasattr(cardctl, const), f"{APDU_MD.name} documents {name} but cardctl has no {const}"
        assert getattr(cardctl, const) == int(hex_value, 16), (
            f"{name}: spec says 0x{hex_value}, cardctl.{const} is 0x{getattr(cardctl, const):02X}"
        )


def test_every_ins_constant_is_documented():
    """The other direction: an undocumented command is how a spec goes stale."""
    documented = {n for n, _ in _command_headings()}
    implemented = {n[4:] for n in dir(cardctl) if n.startswith("INS_")}
    missing = implemented - documented
    assert not missing, f"cardctl has undocumented commands: {sorted(missing)}"


def test_the_applet_opcodes_match_the_spec_and_the_driver():
    """
    The applet's INS constants, by opcode, against the spec's headings. Names may
    differ only where the applet says SET_LIMIT_OWNER for the owner's form, which
    the spec and cardctl call SET_LIMIT (and SET_LIMIT_PIN for the open card's).
    """
    applet = _applet_ins()
    rename = {"SET_LIMIT": "SET_LIMIT_PIN", "SET_LIMIT_OWNER": "SET_LIMIT"}
    applet = {rename.get(n, n): v for n, v in applet.items()}
    documented = {n: int(v, 16) for n, v in _command_headings()}
    assert applet == documented, (
        f"applet and spec disagree: only in applet {sorted(set(applet.items()) - set(documented.items()))}, "
        f"only in spec {sorted(set(documented.items()) - set(applet.items()))}"
    )


def test_the_ins_summary_table_matches_the_headings():
    body = _heading_body("Commands, by INS")
    rows = re.findall(r"^\| `([0-9A-F]{2})` \| ([A-Z_]+) \|", body, re.M)
    assert rows, "could not parse the INS summary table"
    assert sorted((n, int(v, 16)) for v, n in rows) == sorted((n, int(v, 16)) for n, v in _command_headings()), rows


def test_the_unassigned_opcodes_are_documented_and_absent():
    """0x.20 SPEND_PROOF, 0x21 SIGN_ARBITRARY and 0x35 SET_TIME are gone: documented as 6D00, in no constant anywhere."""
    body = _heading_body("Commands, by INS")
    for gone in ("`20`", "`21`", "`35`"):
        assert gone in body.split("Not assigned")[1], f"{gone} is not documented as unassigned"
    assert "6D00" in body
    used = set(_applet_ins().values()) | {getattr(cardctl, n) for n in dir(cardctl) if n.startswith("INS_")}
    assert not ({0x20, 0x21, 0x35} & used), sorted(hex(x) for x in {0x20, 0x21, 0x35} & used)


def test_the_cla_is_stated_and_every_command_table_repeats_it_and_its_ins():
    assert f"Class `{cardctl.CLA:02X}`" in _apdu_text(), "APDU.md no longer states the class byte"
    for name, hex_value in _command_headings():
        section = _section(name)
        assert int(_row(section, "CLA"), 16) == cardctl.CLA, f"{name}: wrong CLA"
        assert int(_row(section, "INS"), 16) == int(hex_value, 16), f"{name}: heading and table disagree"


# ── SELECT and the version ────────────────────────────────────────────────────
def test_select_application_matches_the_apdu_the_driver_sends():
    """
    SELECT is the one command that has to work before any other. A single wrong
    AID byte in this table selects nothing, and the driver then reports a card
    that needs an update.
    """
    body = _heading_body("SELECT APPLICATION")
    fields = {f: int(_row(body, f).split()[0], 16) for f in ("CLA", "INS", "P1", "P2", "Lc")}
    data = re.search(r"^\| Data \| `([0-9A-Fa-f ]+)`", body, re.M)
    assert data, "SELECT APPLICATION's table has no parsable Data row"
    aid = bytes.fromhex(data.group(1).replace(" ", ""))
    # D25: the table's AID is the applet's whole AID, the one cardctl selects first
    assert aid == cardctl.APPLET_AID, f"spec's AID {aid.hex()} != cardctl's {cardctl.APPLET_AID.hex()}"
    assert fields["Lc"] == len(cardctl.APPLET_AID)
    card = make_card([(b"\x02\x00", 0x9000)])
    card.select()
    documented = bytes([fields["CLA"], fields["INS"], fields["P1"], fields["P2"], fields["Lc"]]) + aid
    assert card.connection.sent == [documented], f"spec {documented.hex()} != cardctl {card.connection.last.hex()}"
    # the fallback cardctl tries, the opener a partial name reaches, and the withdrawn AIDs, are documented
    spans = _hex_spans(body)
    assert cardctl.PACKAGE_AID in spans, "the package AID (the fallback) is not documented"
    assert cardctl.PACKAGE_AID + b"\x4D" in spans, "the opener, which a SELECT by the package AID reaches on a chip, is not named"
    assert cardctl.LEGACY_PACKAGE_AID in spans, "the 0.x AID is not named as withdrawn"
    # and the build installs the card's applet under that AID
    build = (ROOT / "applet" / "build.xml").read_text(encoding="utf-8")
    assert 'aid="' + ":".join(f"{b:02X}" for b in cardctl.APPLET_AID) + '"' in build


def test_the_applet_version_is_the_one_the_spec_the_guide_and_selftest_expect():
    """
    SELECT's version is all an installed card reports about its build, so every
    copy of it must agree: the applet's, the spec's SELECT response, the guide's
    answers for a good card, and `cardctl selftest`'s floor, which passes it and
    nothing below.
    """
    version = dict(re.findall(r"static final byte VERSION_(MAJOR|MINOR)\s*=\s*\(byte\)\s*0x([0-9A-Fa-f]{2})", _applet_text()))
    major, minor = int(version["MAJOR"], 16), int(version["MINOR"], 16)
    assert (major, minor) == (2, 1)
    assert f"`{major:02X} {minor:02X}`" in _heading_body("SELECT APPLICATION"), "the spec's SELECT response"
    guide = DEPLOYMENT_MD.read_text(encoding="utf-8")
    tracked = re.search(r"The CAP tracked in this repo is \*\*applet version (\d+)\.(\d+)\*\*", guide)
    assert tracked and (int(tracked.group(1)), int(tracked.group(2))) == (major, minor), "the guide's tracked version"
    answers = re.findall(r"`SELECT` must answer `([0-9A-F]{2}) ([0-9A-F]{2})`", guide)
    answers += re.findall(r"^# Response: ([0-9A-F]{2})([0-9A-F]{2}) 9000\b", guide, re.M)
    answers += re.findall(r"^# Response: ([0-9A-F]{2}) ([0-9A-F]{2})(?: [0-9A-F]{2}){28}\s*$", guide, re.M)
    assert len(answers) == 3, f"expected the guide's three version answers, found {answers}"
    for hi, lo in answers:
        assert (int(hi, 16), int(lo, 16)) == (major, minor), f"the guide shows {hi} {lo}"
    ok, detail = cardctl._select_verdict(bytes([major, minor]))
    assert ok and detail == f"version {major}.{minor}", detail
    assert cardctl.SELFTEST_MIN_VERSION == (major, minor)
    assert not cardctl._select_verdict(bytes([1, 20]))[0], "selftest passes Foxy's 1.20"


# ── the slot ──────────────────────────────────────────────────────────────────
def _proof_layout() -> dict:
    rows = re.findall(r"^\| (\d+) \| (\d+) \| (.+?) \|$", _section("GET_PROOF"), re.M)
    assert rows, "could not parse the GET_PROOF response table"
    return {int(off): (int(ln), desc) for off, ln, desc in rows}


def _proof_slot_layout_block() -> dict:
    body = _heading_body("Proof Slot Layout")
    fence = re.search(r"```\n(.*?)```", body, re.S)
    assert fence, "the Proof Slot Layout section no longer contains a fenced layout block"
    rows = re.findall(r"^(\d+)\s+(\d+)\s+(.+)$", fence.group(1), re.M)
    return {int(off): (int(ln), desc.strip()) for off, ln, desc in rows}


def test_the_proof_layout_matches_the_parser_the_applet_and_its_other_copy():
    """
    The offsets the spec publishes must be the offsets get_proof slices and the
    applet writes. A symmetric offset change inside the applet passes the Java
    suite, so the applet is scraped here too.
    """
    table, block = _proof_layout(), _proof_slot_layout_block()
    expected = {0: 1, 1: 8, 9: 4, 13: 32, 45: 33, 78: 4}
    assert {o: l for o, (l, _) in table.items()} == expected, sorted(table.items())
    assert {o: l for o, (l, _) in block.items()} == expected, sorted(block.items())
    for layout, where in ((table, "GET_PROOF table"), (block, "slot layout block")):
        assert "raw" in layout[1][1].lower() and "ascii" not in layout[1][1].lower().replace("not ascii", ""), where
        assert "nonce" in layout[13][1].lower(), f"{where}: the 32-byte field is the nonce"
        assert "date" in layout[78][1].lower(), f"{where}: offset 78 is the date"
    body = (bytes([0x01]) + bytes.fromhex("0059534ce0bfa19a") + (1234).to_bytes(4, "big") + bytes(range(32))
            + b"\x02" + bytes(range(1, 33)) + (1900000000).to_bytes(4, "big"))
    assert len(body) == cardctl.PROOF_SIZE == 82
    p = make_card([(body, 0x9000)]).get_proof(0)
    assert (p["keyset_id"], p["amount"], p["nonce"], p["c"], p["date"]) == (
        "0059534ce0bfa19a", 1234, bytes(range(32)), b"\x02" + bytes(range(1, 33)), 1900000000)
    consts = _applet_shorts()
    java = {"status": "PROOF_STATUS_OFFSET", "keyset_id": "PROOF_KEYSET_OFFSET", "amount": "PROOF_AMOUNT_OFFSET",
            "nonce": "PROOF_NONCE_OFFSET", "c": "PROOF_C_OFFSET", "date": "PROOF_DATE_OFFSET"}
    for offset, (_, desc) in table.items():
        const = java[_canonical(desc, "GET_PROOF table")]
        assert consts[const] == offset, f"applet {const} is {consts[const]}, spec {offset}"
    assert consts["PROOF_SIZE"] == cardctl.PROOF_SIZE and consts["PROOF_DATA_LEN"] == cardctl.PROOF_SIZE - 1
    assert consts["MAX_PROOFS"] == cardctl.MAX_PROOFS == 128
    assert f"{cardctl.PROOF_SIZE} bytes per slot × {cardctl.MAX_PROOFS} slots" in _heading_body("Proof Slot Layout")


def test_load_proof_documents_the_fields_in_the_order_it_sends_them():
    """A misordered load strands money on a card for good."""
    section = _section("LOAD_PROOF")
    rows = re.findall(r"^\| (keyset_id|amount|nonce|C|date) \| (\d+) \|", section, re.M)
    assert [r[0] for r in rows] == ["keyset_id", "amount", "nonce", "C", "date"], rows
    sizes = [int(r[1]) for r in rows]
    assert sum(sizes) == cardctl.PROOF_SIZE - 1 == int(re.search(r"^51 \((\d+)\)", _row(section, "Lc")).group(1))
    card = make_card([(b"\x00", 0x9000)])
    card.load_proof(bytes.fromhex("0059534ce0bfa19a"), 4, bytes(range(32)), b"\x03" + bytes(range(32)), 7)
    data = card.connection.last[5:5 + 81]
    at = 0
    sent = {}
    for (name, _), size in zip(rows, sizes):
        sent[name] = data[at:at + size]
        at += size
    assert sent["keyset_id"] == bytes.fromhex("0059534ce0bfa19a") and int.from_bytes(sent["amount"], "big") == 4
    assert sent["nonce"] == bytes(range(32)) and sent["C"] == b"\x03" + bytes(range(32))
    assert int.from_bytes(sent["date"], "big") == 7


# ── the secret, which the card signs ────────────────────────────────────────
def _applet_secret_parts() -> dict:
    out = {}
    for name in ("SECRET_1", "SECRET_2", "SECRET_3", "SECRET_DATE", "SECRET_REFUND", "SECRET_END_DATED", "SECRET_END"):
        out[name] = _applet_label(name)
    return out


def test_the_nut_xx_secret_is_the_one_the_applet_builds_and_the_vectors_sign():
    """
    The secret text is the wire between the card and every wallet that loads it:
    the card signs the hash of exactly this. NUT-XX's text, the applet's byte
    arrays and the vectors the applet's suite wrote must be one text.
    """
    parts = _applet_secret_parts()
    nonce, key, refund, date = "ab" * 32, "02" + "cd" * 32, "03" + "ef" * 32, "1900000000"
    plain = parts["SECRET_1"] + nonce + parts["SECRET_2"] + key + parts["SECRET_3"] + parts["SECRET_END"]
    dated = (parts["SECRET_1"] + nonce + parts["SECRET_2"] + key + parts["SECRET_3"] + parts["SECRET_DATE"] + date
             + parts["SECRET_REFUND"] + refund + parts["SECRET_END_DATED"])
    nut = NUT_XX_MD.read_text(encoding="utf-8")
    nut_plain = re.search(r'^(\["P2PK",\{"nonce":"<64 hex>","data":"<66 hex P_card>","tags":\[\["sigflag","SIG_ALL"\]\]\}\])$', nut, re.M)
    nut_dated = re.search(r'^(\["P2PK",\{"nonce":"<64 hex>","data":"<66 hex P_card>","tags":\[\["locktime","<decimal>"\],\["refund","<66 hex>"\],\["sigflag","SIG_ALL"\]\]\}\])$', nut, re.M)
    assert nut_plain and nut_dated, "NUT-XX no longer states the two secret forms"
    assert nut_plain.group(1).replace("<64 hex>", nonce).replace("<66 hex P_card>", key) == plain
    assert (nut_dated.group(1).replace("<64 hex>", nonce, 1).replace("<66 hex P_card>", key)
            .replace("<decimal>", date).replace("<66 hex>", refund)) == dated
    vectors = json.loads(SECRET_JSON.read_text(encoding="utf-8"))
    for piece in vectors["pieces"]:
        if piece["date"]:
            want = (parts["SECRET_1"] + piece["nonce"] + parts["SECRET_2"] + vectors["cardKey"] + parts["SECRET_3"]
                    + parts["SECRET_DATE"] + str(piece["date"]) + parts["SECRET_REFUND"] + vectors["refundKey"] + parts["SECRET_END_DATED"])
        else:
            want = parts["SECRET_1"] + piece["nonce"] + parts["SECRET_2"] + vectors["cardKey"] + parts["SECRET_3"] + parts["SECRET_END"]
        assert piece["secret"] == want, piece["secret"]


def test_the_sig_all_message_is_stated_as_the_card_hashes_it():
    nut = NUT_XX_MD.read_text(encoding="utf-8")
    assert "msg = secret_0 ‖ C_0 ‖ … ‖ secret_n ‖ C_n ‖ amount_0 ‖ B_0 ‖ … ‖ amount_m ‖ B_m" in nut
    assert "signature is over the NUT-11 `SIG_ALL` message: every piece's secret and `C`," in " ".join(_apdu_text().split()), \
        "APDU.md no longer says what the one signature is over"


# ── GET_INFO and GET_CARD ─────────────────────────────────────────────────────
def _byte_table(section: str) -> list:
    """`| 12–15 | name | meaning |` rows as (first, last, name)."""
    rows = []
    for a, b, name in re.findall(r"^\| (\d+)(?:[–-](\d+))? \| ([^|]+?) \|", section, re.M):
        rows.append((int(a), int(b) if b else int(a), name.strip()))
    assert rows, "no byte table"
    return rows


def test_get_info_response_table_matches_the_decoder():
    """
    Every documented byte of GET_INFO is driven through decode_info with a body
    whose fields are all different, and each field must land where the table
    puts it: a swap of two rows (unspent and spent, say) fails here.
    """
    rows = _byte_table(_section("GET_INFO"))
    covered = sorted({i for a, b, _ in rows for i in range(a, b + 1)})
    assert covered == list(range(43)), f"GET_INFO's table covers {covered}"
    sizes = re.findall(r"(\d+) bytes with P1 = `00`.*?(\d+) with P1 = `01`, (\d+) with P1 = `02`", _section("GET_INFO"))
    assert sizes == [("30", "42", "43")], sizes
    info = cardctl.decode_info(INFO_43)
    expect = {
        "version major": info["version_tuple"][0], "version minor": info["version_tuple"][1],
        "max slots": info["max_slots"], "unspent": info["unspent"], "spent": info["spent"], "empty": info["empty"],
        "capabilities": info["caps_raw"], "PIN state": 1 if info["pin_state"] == "set" else None,
        "format": info["format"], "tries left": info["tries"], "locked": int(info["locked"]),
        "record set": int(info["record_set"]), "daily limit": info["daily_limit"], "has owner": int(info["has_owner"]),
        "now": info["now"], "window start": info["window_start"], "spent today": info["spent_today"],
        "change grant": int(info["change_grant"]), "payment limit": info["payment_limit"],
        "no-PIN allowance": info["allowance"], "no-PIN spent": info["nopin_spent"], "tag off": int(info["tag_off"]),
    }
    for a, b, name in rows:
        assert name in expect, f"GET_INFO documents {name!r}, which decode_info does not decode"
        assert int.from_bytes(INFO_43[a:b + 1], "big") == expect[name], f"{name} at {a}..{b}"
    # the applet answers the documented sizes
    src = _applet_text()
    assert "p1 == (byte) 2 ? (short) 43 : (short) 42" in src and "apdu.setOutgoingAndSend((short) 0, (short) 30);" in src


def test_get_card_table_matches_the_decoder_and_the_applets_rollover_bytes():
    rows = {(a, b): name for a, b, name in
            [(int(o), int(o) + int(l) - 1, n.strip()) for o, l, n in
             re.findall(r"^\| (\d+) \| (\d+) \| ([^|]+?) \|", _section("GET_CARD"), re.M)]}
    assert rows[(76, 76)].startswith("rolls") and rows[(77, 77)].startswith("rollover budget") and rows[(78, 78)].startswith("allowance armed"), rows
    card = cardctl.decode_card(CARD_ANSWER)
    assert (CARD_ANSWER[76], CARD_ANSWER[77], CARD_ANSWER[78]) == (card["rolls"], card["budget_raw"], int(card["armed"]))
    consts = _applet_shorts()
    # GET_CARD's byte 40 is the record's CARD_BITS_OFFSET: its 65 bytes are copied whole
    shift = consts["CARD_BITS_OFFSET"] - 40
    assert consts["CARD_ROLLS_OFFSET"] - shift == 76
    assert consts["CARD_BUDGET_OFFSET"] - shift == 77
    assert consts["CARD_ARMED_OFFSET"] - shift == 78
    assert "Util.arrayCopyNonAtomic(cardRecord, CARD_BITS_OFFSET, buf, (short) 40, (short) 65);" in _applet_text()


# ── the owner's proof ─────────────────────────────────────────────────────────
def test_the_owner_labels_match_the_applet_and_the_driver():
    body = _heading_body("The owner's proof")
    rows = re.findall(r"^\| `([A-Z_]+)`[^|]*\| `(CashuCard/[a-z-]+)` \|", body, re.M)
    documented = {cmd: label for cmd, label in rows}
    expect = {"CHANGE_PIN": "CHANGE_PIN", "SET_LIMIT": "SET_LIMIT", "SET_OWNER": "SET_OWNER", "SET_CARD": "SET_CARD",
              "ALLOW_LOAD": "LOAD", "LOCK_CARD": "LOCK", "RESET_CARD": "RESET", "SET_TAG": "TAG", "REFRESH": "REFRESH"}
    assert set(documented) == set(expect), sorted(documented)
    for command, short in expect.items():
        label = documented[command]
        assert _applet_label(f"LABEL_{short}") == label, f"applet's LABEL_{short} is not {label}"
        assert getattr(cardctl, f"LABEL_{short}") == label, f"cardctl.LABEL_{short} is not {label}"
    assert _applet_label("AUTH_TAG") == cardctl.AUTH_TAG == "CashuCard/auth"
    assert _applet_label("SEAL_LABEL") == "CashuCard/seal" and _applet_label("PINKEY_LABEL") == "CashuCard/pinkey"
    for tag in ("`CashuCard/auth`", "`CashuCard/seal`", "`CashuCard/pinkey`"):
        assert tag in body, tag


def test_owner_commands_send_proof_length_proof_then_value():
    """The data layout the spec states for every owner's command, through the real encoder."""
    assert "proof length (1) ‖ proof (DER, at most 72) ‖ value" in _heading_body("The owner's proof")
    nonce = bytes(range(16))
    card = make_card([(nonce, 0x9000)])
    card.set_limit(p256.TEST_OWNER_PRIVATE, 100, 0, 0, 7)
    data = card.connection.last[5:]
    n = data[0]
    assert n <= 72 and data[1 + n:] == (100).to_bytes(4, "big") + bytes(8) + b"\x07"
    assert p256.verify(p256.public_key(p256.TEST_OWNER_PRIVATE), b"CashuCard/set-limit" + nonce + data[1 + n:], data[1:1 + n])


def test_set_limit_forms_and_the_budget_range_match_the_applet():
    section = _section("SET_LIMIT")
    assert "4, 8, 12 or 13" in section and "1 to 30" in section
    src = _applet_text()
    assert "len != (short) 4 && len != (short) 8 && len != (short) 12 && len != (short) 13" in src
    most = re.search(r"static final byte\s+ROLL_BUDGET_MOST\s*=\s*\(byte\)\s*(\d+);", src)
    default = re.search(r"static final byte\s+ROLL_BUDGET_DEFAULT\s*=\s*\(byte\)\s*(\d+);", src)
    assert int(most.group(1)) == cardctl.ROLL_BUDGET_MOST == 30
    assert int(default.group(1)) == cardctl.ROLL_BUDGET_DEFAULT == 7
    assert "default 7" in _heading_body("The clock and the limits")
    assert [len(cardctl.limit_value(1)), len(cardctl.limit_value(1, 0)), len(cardctl.limit_value(1, 0, 0)),
            len(cardctl.limit_value(1, 0, 0, 7))] == [4, 8, 12, 13]


def test_refresh_and_the_anchor_take_an_80_byte_header():
    assert int(_row(_section("SET_HEADER"), "Lc"), 16) == cardctl.HEADER_LEN == 80
    assert "a Bitcoin block header (80)" in _row(_section("REFRESH"), "Data")
    assert "an anchor header (80)" in _row(_section("SET_OWNER"), "Data")
    assert _applet_shorts()["HEADER_LEN"] == 80
    card = make_card([(bytes(16), 0x9000), (bytes(4), 0x9000)])
    card.refresh(p256.TEST_OWNER_PRIVATE, bytes(80))
    sent = card.connection.last
    assert sent[1] == 0x53 and sent[-1] == int(_row(_section("REFRESH"), "Le"), 16)


def test_the_floor_the_spec_states_is_the_applets():
    m = re.search(r"FLOOR_BITS = \{ \(byte\) 0x([0-9A-F]{2}), \(byte\) 0x([0-9A-F]{2}), \(byte\) 0x([0-9A-F]{2}), \(byte\) 0x([0-9A-F]{2}) \}", _applet_text())
    bits = "".join(reversed(m.groups()))
    assert f"`0x{bits}`" in _section("SET_HEADER"), bits


# ── the bytes cardctl sends, against the tables ──────────────────────────────
# Every command cardctl drives, as (spec section, Card method, arguments, the
# answer to give it). The completeness ratchet below fails the day a Card
# method that sends a documented command is not in this table.
_DRIVEN = [
    ("GET_INFO", "get_info", (), [INFO_43]),
    ("GET_PUBKEY", "get_pubkey", (), [b"\x02" + bytes(32)]),
    ("GET_BALANCE", "get_balance", (), [bytes(4)]),
    ("GET_PROOF_COUNT", "get_proof_count", (), [b"\x00"]),
    ("GET_PROOF", "get_proof", (0,), [bytes(82)]),
    ("GET_SLOT_STATUS", "get_slot_status", (), [bytes(128)]),
    ("AUTH", "auth", (bytes(16),), [bytes(80)]),
    ("GET_CARD", "get_card", (), [CARD_ANSWER]),
    ("GET_NONCE", "get_nonce", (), [bytes(16)]),
    ("SET_HEADER", "set_header", (bytes(80),), [bytes(4)]),
    ("LOAD_PROOF", "load_proof", (bytes(8), 1, bytes(32), b"\x02" + bytes(32)), [b"\x00"]),
    ("CLEAR_SPENT", "clear_spent", (), [b"\x00"]),
    ("VERIFY_PIN", "verify_pin", (b"1234",), [b""]),
    ("SET_PIN", "set_pin", (b"1234",), [b""]),
    ("SET_CARD", "set_card", ("https://m",), [b""]),
    ("SET_OWNER", "set_owner", (p256.public_key(p256.TEST_OWNER_PRIVATE),), [b""]),
    ("CHANGE_PIN", "change_pin", (p256.TEST_OWNER_PRIVATE, b"1234"), [bytes(16), b""]),
    ("SET_LIMIT", "set_limit", (p256.TEST_OWNER_PRIVATE, 1), [bytes(16), b""]),
    ("ALLOW_LOAD", "allow_load", (p256.TEST_OWNER_PRIVATE,), [bytes(16), b""]),
    ("REFRESH", "refresh", (p256.TEST_OWNER_PRIVATE, bytes(80)), [bytes(16), bytes(4)]),
    ("LOCK_CARD", "lock_card", (p256.TEST_OWNER_PRIVATE,), [bytes(16), b""]),
]


def _drive(method, args, answers):
    card = make_card([(a, 0x9000) for a in answers])
    getattr(card, method)(*args)
    return card.connection.last


def test_every_driven_command_matches_its_header_table():
    """CLA, INS, a fixed P1/P2, a fixed Lc and the Le, each as the table has it."""
    for name, method, args, answers in _DRIVEN:
        section = _section(name)
        sent = _drive(method, args, answers)
        assert sent[0] == cardctl.CLA and sent[1] == getattr(cardctl, f"INS_{name}"), name
        for field, at in (("P1", 2), ("P2", 3)):
            value = _row(section, field)
            fixed = re.match(r"^([0-9A-F]{2})(?:;|$| \()", value)
            if fixed and name != "GET_INFO":
                assert sent[at] == int(fixed.group(1), 16), f"{name}: {field} is {sent[at]:02X}, table says {value}"
        if name == "GET_INFO":
            assert sent[2] == 0x02, "cardctl asks for the long form, P1 = 2"
        le_row = re.search(r"^\| Le \| (.+?) \|$", section, re.M)
        if le_row:
            le = re.match(r"^`([0-9A-F]{2})`", le_row.group(1))
            if le:
                assert sent[-1] == int(le.group(1), 16), f"{name}: Le {sent[-1]:02X}, table says {le_row.group(1)}"


def test_every_command_cardctl_sends_is_in_the_driven_table():
    """The ratchet: a Card method that sends an instruction must be driven above."""
    import inspect
    driven = {m for _, m, _, _ in _DRIVEN}
    src = inspect.getsource(cardctl.Card)
    senders = set(re.findall(r"\n    def (\w+)\(self[^)]*\)[^:]*:(?:(?!\n    def ).)*?(?:self\.send\(INS_|owner_command\(INS_|self\.send\(\s*INS_)", src, re.S))
    senders -= {"owner_command", "send", "transmit", "select"}
    missing = senders - driven
    assert not missing, f"Card methods that send a command but are not driven here: {sorted(missing)}"


def test_pin_length_ranges_match_the_applet():
    shorts = _applet_shorts()
    assert (shorts["PIN_MIN_LEN"], shorts["PIN_MAX_LEN"]) == (cardctl.PIN_MIN_LEN, cardctl.PIN_MAX_LEN) == (4, 8)
    for name in ("VERIFY_PIN", "SET_PIN"):
        assert "4–8 bytes" in _row(_section(name), "Data"), name
    assert "the new PIN (4–8)" in _row(_section("CHANGE_PIN"), "Data")


def test_lock_card_p2_is_the_confirmation_byte():
    assert int(_row(_section("LOCK_CARD"), "P2").split()[0], 16) == cardctl.LOCK_CONFIRM_BYTE == 0xDE
    assert "static final byte LOCK_CONFIRM_BYTE = (byte) 0xDE;" in _applet_text()


# ── status words ──────────────────────────────────────────────────────────────
def test_every_documented_status_word_is_translated_by_cardctl():
    documented = {first + second for first, second in
                  re.findall(r"^\| (6[0-9A-F]|90) ?([0-9A-F]{2}|CX) \|", _heading_body("Error Code Summary"), re.M)}
    assert {"9000", "63CX", "6982", "6983", "6986", "6A88", "6A8F", "6A90", "6A91", "6A93", "6A94"} <= documented, sorted(documented)
    for sw in sorted(documented):
        if sw == "63CX":
            for tries in range(4):
                assert f"{tries} retries remaining" in cardctl.describe_sw(0x63C0 | tries)
            continue
        assert cardctl.describe_sw(int(sw, 16)) != "unknown status word", f"cardctl cannot translate {sw}"
    undocumented = {f"{sw:04X}" for sw in cardctl.SW_MEANINGS} - documented
    assert not undocumented, f"cardctl translates status words the spec does not document: {sorted(undocumented)}"


def test_every_applet_status_word_is_documented():
    words = {v.upper() for v in re.findall(r"static final short SW_\w+\s*=\s*\(short\)\s*0x([0-9A-Fa-f]{4})", _applet_text())}
    words -= {"63C2", "63C1", "63C0"}   # 63CX
    words -= {"6A92", "6A95"}           # unused: never answered (CashuAppletTest checks)
    documented = {first + second for first, second in
                  re.findall(r"^\| (6[0-9A-F]|90) ?([0-9A-F]{2}|CX) \|", _heading_body("Error Code Summary"), re.M)}
    missing = words - documented
    assert not missing, f"the applet answers status words the spec does not document: {sorted(missing)}"


if __name__ == "__main__":
    import types

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and isinstance(fn, types.FunctionType):
            try:
                fn()
                print(f"PASS  {name}")
            except (SystemExit, Exception) as exc:
                failures += 1
                print(f"FAIL  {name}: {type(exc).__name__}: {exc}")
                if not isinstance(exc, (AssertionError, SystemExit)):
                    traceback.print_exc()
    print(f"\n{'all tests passed' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)
