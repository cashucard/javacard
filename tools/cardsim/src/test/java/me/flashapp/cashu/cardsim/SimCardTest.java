package me.flashapp.cashu.cardsim;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SimCard against the real 2.0 applet. Every assertion is about bytes the app would see over the bridge, so the
 * raw-byte path (Simulator.transmitCommand on a byte[]) is checked against what the applet suite reports.
 */
class SimCardTest {

    static final String KEYSET = "0059534ce0bfa19a";
    static final String NONCE_A = "ab".repeat(32);
    static final String NONCE_B = "cd".repeat(32);
    static final String NONCE_C = "ef".repeat(32);
    static final String C_A = "02" + "11".repeat(32);
    static final String C_B = "03" + "22".repeat(32);
    static final String C_C = "02" + "33".repeat(32);
    static final String MINT = "http://127.0.0.1:3338";
    static final String SETUP = "\"pin\":\"1234\",\"mint\":\"" + MINT + "\",\"owner\":true";

    static final byte[] GET_INFO_LE00 = Hex.parse("B001000000");
    static final byte[] GET_INFO_LONG = Hex.parse("B001020000");
    static final byte[] GET_PUBKEY_LE21 = Hex.parse("B010000021");
    static final byte[] GET_PUBKEY_LE00 = Hex.parse("B010000000");
    static final byte[] GET_BALANCE = Hex.parse("B011000004");
    static final byte[] GET_SLOT_STATUS = Hex.parse("B014000080");
    static final byte[] CLEAR_SPENT = Hex.parse("B031000001");
    static final byte[] GET_LOG = Hex.parse("B018000000");
    static final byte[] VERIFY_1234 = SimCard.apdu(0x40, 0, 0, "1234".getBytes(), -1);

    /** Real mainnet headers (spec/vectors/headers.json): the floor built into the applet takes nothing else. */
    static final List<String> HEADERS = new ArrayList<>();
    static final List<Long> TIMES = new ArrayList<>();
    static {
        try {
            String json = new String(Files.readAllBytes(Paths.get("../../spec/vectors/headers.json")), "UTF-8");
            Matcher m = Pattern.compile("\"time\": (\\d+), \"bits\": \"[0-9a-f]{8}\", \"header\": \"([0-9a-f]{160})\"").matcher(json);
            while (m.find()) {
                TIMES.add(Long.parseLong(m.group(1)));
                HEADERS.add(m.group(2));
            }
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    SimCard card;

    @BeforeEach
    void fresh() {
        card = new SimCard();
    }

    static String proof(String nonce, String c, long amount) {
        return "{\"keysetId\":\"" + KEYSET + "\",\"amount\":" + amount + ",\"nonce\":\"" + nonce + "\",\"C\":\"" + c + "\"}";
    }

    static String threeProofs() {
        return "[" + proof(NONCE_A, C_A, 8) + "," + proof(NONCE_B, C_B, 16) + "," + proof(NONCE_C, C_C, 32) + "]";
    }

    Fixture fixture(String json) {
        return Fixture.parse(json, card.context());
    }

    void apply(String json) throws FixtureException {
        card.applyFixture(fixture(json));
    }

    static byte[] data(byte[] resp) {
        return Arrays.copyOf(resp, resp.length - 2);
    }

    // ── fresh card ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("a fresh card answers SELECT by the card's applet's whole AID, F0 CASHUCARD 01, with 02 00 9000")
    void selectAnswersVersion() {
        assertEquals("02009000", Hex.format(card.transmit(SimCard.SELECT)));
        assertEquals("00A404000BF043415348554341524401", Hex.format(SimCard.SELECT));
        assertEquals("2.0", card.state().get("version").getAsString());
    }

    @Test
    @DisplayName("SELECT by the package AID alone reaches the opener, as on the chip: 9000 with no version, then 6D00 (ENG-681)")
    void packageAidReachesTheOpener() {
        assertEquals("00A404000AF0434153485543415244", Hex.format(SimCard.SELECT_PACKAGE));
        assertEquals("9000", Hex.format(card.transmit(SimCard.SELECT_PACKAGE)), "the opener answers its SELECT, no body");
        assertEquals("6D00", Hex.format(card.transmit(GET_INFO_LONG)), "and refuses the next command");
        assertEquals("9000", Hex.format(card.transmit(Hex.parse("00A404000AF043415348554341524400"))), "with an Le as well");
        assertEquals("6D00", Hex.format(card.transmit(GET_PUBKEY_LE21)));
        // the whole AID then reaches the card's applet, and the card answers again
        assertEquals("02009000", Hex.format(card.transmit(SimCard.SELECT)));
        assertEquals(43, data(card.transmit(GET_INFO_LONG)).length);
        // the opener by its own whole AID is the same applet
        assertEquals("9000", Hex.format(card.transmit(Hex.parse("00A404000B" + SimCard.OPENER_HEX))));
        assertEquals("6D00", Hex.format(card.transmit(GET_INFO_LONG)));
    }

    @Test
    @DisplayName("with the opener or the tag selected, state() still reads the card, and the app's selection is kept")
    void stateReadsTheCardWhereverTheSelectionIs() {
        assertEquals(SimCard.AID_HEX, card.selected());
        assertEquals("9000", Hex.format(card.transmit(SimCard.SELECT_PACKAGE)));
        assertEquals(SimCard.OPENER_HEX, card.selected(), "the package AID selected the opener");
        assertEquals("2.0", card.state().get("version").getAsString());
        assertEquals(SimCard.OPENER_HEX, card.selected());
        assertEquals("6D00", Hex.format(card.transmit(GET_INFO_LONG)), "the opener is still what the app reaches");

        assertEquals(0x9000, SimCard.sw(card.transmit(Hex.parse("00A4040007" + SimCard.TAG_HEX + "00"))));
        assertEquals(SimCard.TAG_HEX, card.selected());
        assertEquals("2.0", card.state().get("version").getAsString());
        assertEquals(SimCard.TAG_HEX, card.selected());
        // a SELECT that finds nothing leaves the selection where it was
        card.transmit(Hex.parse("00A4040007D2760000850102"));
        assertEquals(SimCard.TAG_HEX, card.selected());
    }

    static final byte[] SELECT_TAG = Hex.parse("00A4040007" + SimCard.TAG_HEX + "00");
    static final byte[] SELECT_NDEF_FILE = Hex.parse("00A4000C02E104");
    static final byte[] READ_NDEF = Hex.parse("00B0000016");

    @Test
    @DisplayName("with a file chosen on the tag, state() keeps it chosen: the app's next READ BINARY reads the same bytes")
    void stateKeepsTheTagsChosenFile() {
        assertEquals(0x9000, SimCard.sw(card.transmit(SELECT_TAG)));
        assertEquals("9000", Hex.format(card.transmit(SELECT_NDEF_FILE)));
        byte[] before = card.transmit(READ_NDEF);
        assertEquals(0x9000, SimCard.sw(before));
        assertEquals(24, before.length, "the NDEF file's 22 bytes and the status word");

        assertEquals("2.0", card.state().get("version").getAsString());
        assertEquals(SimCard.TAG_HEX, card.selected());
        assertArrayEquals(before, card.transmit(READ_NDEF), "the file the app chose is still chosen after /state");

        // and a fixture's check (context()) does the same
        card.context();
        assertArrayEquals(before, card.transmit(READ_NDEF), "and after the fixture's read of the card");
    }

    @Test
    @DisplayName("with no file chosen on the tag, state() chooses none: READ BINARY is refused before it and after it")
    void stateChoosesNoFileOnTheTag() {
        assertEquals(0x9000, SimCard.sw(card.transmit(SELECT_TAG)));
        assertEquals("6986", Hex.format(card.transmit(READ_NDEF)), "no file chosen yet");
        card.state();
        assertEquals("6986", Hex.format(card.transmit(READ_NDEF)), "still none after /state");

        // a file chosen in an earlier selection of the tag is not brought back: a new SELECT cleared it on the chip
        assertEquals("9000", Hex.format(card.transmit(SELECT_NDEF_FILE)));
        assertEquals(0x9000, SimCard.sw(card.transmit(SELECT_TAG)));
        card.state();
        assertEquals("6986", Hex.format(card.transmit(READ_NDEF)), "the tag selected again has no file chosen");

        // nor across a stay on another instance
        assertEquals("9000", Hex.format(card.transmit(SELECT_NDEF_FILE)));
        assertEquals("02009000", Hex.format(card.transmit(SimCard.SELECT)));
        assertEquals(0x9000, SimCard.sw(card.transmit(SELECT_TAG)));
        card.state();
        assertEquals("6986", Hex.format(card.transmit(READ_NDEF)));

        // a refused SELECT of a file leaves the chosen file as it was, as the tag does
        assertEquals("9000", Hex.format(card.transmit(SELECT_NDEF_FILE)));
        assertEquals("6A82", Hex.format(card.transmit(Hex.parse("00A4000C02E105"))));
        card.state();
        assertEquals(24, card.transmit(READ_NDEF).length, "E104 is still the file chosen");
    }

    @Test
    @DisplayName("a fixture refused partway through, applied with a file chosen on the tag, leaves the card's applet selected, and state() keeps it so")
    void refusedFixtureWithTheTagSelected() throws FixtureException {
        apply("{\"pin\":\"1234\"}");
        assertEquals(0x9000, SimCard.sw(card.transmit(SELECT_TAG)));
        assertEquals("9000", Hex.format(card.transmit(SELECT_NDEF_FILE)));
        assertEquals(SimCard.TAG_HEX, card.selected());

        FixtureException e = assertThrows(FixtureException.class, () -> apply("{\"pin\":\"9999\"}"), "VERIFY_PIN of another PIN");
        assertEquals("VERIFY_PIN", e.step);
        assertEquals(0x63C2, e.sw);
        assertEquals(SimCard.AID_HEX, card.selected(), "the fixture's SELECT moved the selection to the card's applet");

        byte[] before = card.transmit(READ_NDEF);
        assertEquals("6E00", Hex.format(before), "READ BINARY reaches the card's applet, which has no such class");
        assertEquals(SimCard.AID_HEX, card.selected());
        card.state();
        assertArrayEquals(before, card.transmit(READ_NDEF), "state() does not move the app back onto the tag");
        assertEquals(SimCard.AID_HEX, card.selected());
    }

    @Test
    @DisplayName("a fixture applied with the opener selected sets the card up and leaves the card's applet selected")
    void fixtureWithTheOpenerSelected() throws FixtureException {
        assertEquals("9000", Hex.format(card.transmit(SimCard.SELECT_PACKAGE)));
        apply("{" + SETUP + "}");
        assertEquals(SimCard.AID_HEX, card.selected());
        assertEquals(1, card.state().get("pinState").getAsInt());
        assertEquals(43, data(card.transmit(GET_INFO_LONG)).length, "the app's next command reaches the card");
    }

    @Test
    @DisplayName("jCardSim alone gives the package AID to the card's applet (it sorts AIDs), which is why the bridge resolves it")
    void jCardSimAloneDoesNotMatchTheChip() {
        com.licel.jcardsim.smartcardio.CardSimulator raw = new com.licel.jcardsim.smartcardio.CardSimulator();
        raw.installApplet(com.licel.jcardsim.utils.AIDUtil.create(SimCard.OPENER_HEX), me.flashapp.cashu.Opener.class);
        raw.installApplet(com.licel.jcardsim.utils.AIDUtil.create(SimCard.AID_HEX), me.flashapp.cashu.CashuApplet.class);
        assertEquals("02009000", Hex.format(raw.transmitCommand(SimCard.SELECT_PACKAGE)),
            "if jCardSim ever gives the first instance the partial name itself, SimCard.resolveSelect can go");
        // the bridge, with the opener made first, answers as the chip does (a new SimCard: jCardSim's runtime is per
        // simulator, and the one made last is the current one)
        assertEquals("9000", Hex.format(new SimCard().transmit(SimCard.SELECT_PACKAGE)));
    }

    @Test
    @DisplayName("resolveSelect: a partial name becomes the whole AID of the first instance made; everything else passes through")
    void resolveSelectRewritesOnlyPartialNames() {
        assertEquals("00A404000B" + SimCard.OPENER_HEX, Hex.format(SimCard.resolveSelect(SimCard.SELECT_PACKAGE)));
        assertEquals("00A404000B" + SimCard.OPENER_HEX + "00",
            Hex.format(SimCard.resolveSelect(Hex.parse("00A404000A" + SimCard.PACKAGE_HEX + "00"))), "Le kept");
        assertEquals("00A404000B" + SimCard.OPENER_HEX, Hex.format(SimCard.resolveSelect(Hex.parse("00A4040005F043415348"))),
            "a shorter prefix too");
        assertEquals("00A4040007" + SimCard.TAG_HEX + "00",
            Hex.format(SimCard.resolveSelect(Hex.parse("00A4040006D2760000850100"))), "the tag, the only instance it begins");
        for (String same : new String[] {
                "00A404000B" + SimCard.AID_HEX,             // a whole AID
                "00A404000B" + SimCard.OPENER_HEX,
                "00A4040007" + SimCard.TAG_HEX + "00",
                "00A4040007D2760000850102",                 // the 0.x AID: begins no instance
                "00A4040009F0464F585943415244",             // Foxy's
                "00A404020A" + SimCard.PACKAGE_HEX,         // next occurrence
                "00A4040004F0434153",                       // shorter than an AID may be
                "00A4000C02E103",                           // SELECT by file id
                "B001020000" }) {
            assertEquals(same, Hex.format(SimCard.resolveSelect(Hex.parse(same))), same);
        }
    }

    @Test
    @DisplayName("GET_PUBKEY answers 33 bytes under jCardSim")
    void pubkeyIs33Bytes() {
        byte[] resp = card.transmit(GET_PUBKEY_LE21);
        assertEquals(0x9000, SimCard.sw(resp));
        assertEquals(33, data(resp).length);
        int prefix = resp[0] & 0xFF;
        assertTrue(prefix == 0x02 || prefix == 0x03, "compressed prefix, got " + prefix);
    }

    @Test
    @DisplayName("raw-byte Le handling: GET_INFO 30 and 43 bytes, 128 slot statuses")
    void rawByteLeHandling() {
        assertEquals(33, data(card.transmit(GET_PUBKEY_LE21)).length, "Le 21");
        assertEquals(33, data(card.transmit(GET_PUBKEY_LE00)).length, "Le 00");
        assertEquals(30, data(card.transmit(GET_INFO_LE00)).length, "GET_INFO is 30 bytes");
        assertEquals(43, data(card.transmit(GET_INFO_LONG)).length, "and 43 with P1 = 2");
        assertEquals(128, data(card.transmit(GET_SLOT_STATUS)).length, "GET_SLOT_STATUS is one byte per slot");
        assertEquals(0x9000, SimCard.sw(card.transmit(GET_BALANCE)));
    }

    @Test
    @DisplayName("an APDU shorter than a header is refused before it reaches the simulator")
    void shortApduRefused() {
        assertThrows(IllegalArgumentException.class, () -> card.transmit(Hex.parse("B001")));
    }

    @Test
    @DisplayName("the NFC tag is installed beside the card: its name answers 9000 while the owner leaves it on")
    void theTagIsInstalled() {
        assertEquals(0x9000, SimCard.sw(card.transmit(Hex.parse("00A4040007D276000085010100"))));
        assertEquals("02009000", Hex.format(card.transmit(SimCard.SELECT)));
    }

    // ── pieces ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("{pin, mint, owner, proofs x3, spentSlots:[1]} → status 01 02 01, balance excludes slot 1, CLEAR_SPENT under the PIN frees 1")
    void proofsAndSpentSlots() throws FixtureException {
        apply("{" + SETUP + ",\"proofs\":" + threeProofs() + ",\"spentSlots\":[1]}");

        byte[] status = data(card.transmit(GET_SLOT_STATUS));
        assertEquals("010201", Hex.format(status, 0, 3));
        for (int i = 3; i < 128; i++) assertEquals(0, status[i], "slot " + i + " empty");
        assertEquals(8 + 32, SimCard.readUint32(data(card.transmit(GET_BALANCE)), 0), "balance is the unspent slots only");

        JsonObject s = card.state();
        assertEquals(40, s.get("balance").getAsLong());
        JsonObject counts = s.getAsJsonObject("counts");
        assertEquals(2, counts.get("unspent").getAsInt());
        assertEquals(1, counts.get("spent").getAsInt());
        assertEquals(125, counts.get("empty").getAsInt());
        JsonArray slots = s.getAsJsonArray("slots");
        assertEquals(128, slots.size(), "/state shows 128 slots");
        JsonObject slot1 = slots.get(1).getAsJsonObject();
        assertEquals("spent", slot1.get("status").getAsString());
        assertEquals(KEYSET, slot1.get("keysetId").getAsString());
        assertEquals(16, slot1.get("amount").getAsLong());
        assertEquals(NONCE_B, slot1.get("nonce").getAsString());
        assertEquals(C_B, slot1.get("C").getAsString());
        assertEquals(0, slot1.get("date").getAsLong());
        assertFalse(slots.get(3).getAsJsonObject().has("nonce"), "empty slots carry no proof fields");

        // the fixture's payment left the change note: the tap after a payment may load and free with no PIN (spec 8.2)
        assertEquals(1, data(card.transmit(Hex.parse("B001000000")))[29], "GET_INFO byte 29: the change grant is in this tap");
        byte[] cleared = card.transmit(CLEAR_SPENT);
        assertEquals(0x9000, SimCard.sw(cleared));
        assertEquals(1, cleared[0], "CLEAR_SPENT frees the one spent slot");
        assertEquals("010001", Hex.format(data(card.transmit(GET_SLOT_STATUS)), 0, 3));
    }

    @Test
    @DisplayName("spentSlots index into the fixture's proofs, not into card slots, on an additive fixture (the pin verifies on a card that has one)")
    void spentSlotsIndexTheFixturesProofs() throws FixtureException {
        apply("{" + SETUP + ",\"proofs\":[" + proof(NONCE_A, C_A, 8) + "]}");
        apply("{\"pin\":\"1234\",\"proofs\":[" + proof(NONCE_B, C_B, 16) + "," + proof(NONCE_C, C_C, 32) + "],\"spentSlots\":[0]}");

        assertEquals("010201", Hex.format(data(card.transmit(GET_SLOT_STATUS)), 0, 3));
        JsonArray slots = card.state().getAsJsonArray("slots");
        assertEquals(NONCE_A, slots.get(0).getAsJsonObject().get("nonce").getAsString());
        assertEquals("unspent", slots.get(0).getAsJsonObject().get("status").getAsString());
        assertEquals(NONCE_B, slots.get(1).getAsJsonObject().get("nonce").getAsString());
        assertEquals("spent", slots.get(1).getAsJsonObject().get("status").getAsString());
        assertEquals(8 + 32, card.state().get("balance").getAsLong());
    }

    @Test
    @DisplayName("a card with no PIN is loaded under the owner's grant, and its pieces are spent with no PIN")
    void aNoPinCard() throws FixtureException {
        apply("{\"mint\":\"" + MINT + "\",\"owner\":true,\"proofs\":" + threeProofs() + ",\"spentSlots\":[2]}");
        JsonObject s = card.state();
        assertEquals(0, s.get("pinState").getAsInt());
        assertEquals(24, s.get("balance").getAsLong());
    }

    @Test
    @DisplayName("128 pieces fill the card; a 129th LOAD_PROOF answers 6A84")
    void fullCardRefusesLoad() throws FixtureException {
        StringBuilder proofs = new StringBuilder("[");
        for (int i = 0; i < 128; i++) {
            if (i > 0) proofs.append(',');
            proofs.append(proof(String.format("%02x", i).repeat(32), "02" + String.format("%02x", i).repeat(32), 1L << (i % 20)));
        }
        proofs.append(']');
        apply("{" + SETUP + ",\"proofs\":" + proofs + "}");

        byte[] status = data(card.transmit(GET_SLOT_STATUS));
        for (int i = 0; i < 128; i++) assertEquals(1, status[i], "slot " + i + " unspent");
        assertEquals(128, card.state().getAsJsonObject("counts").get("unspent").getAsInt());

        assertEquals(0x9000, SimCard.sw(card.transmit(VERIFY_1234)));
        byte[] extra = fixture("{\"proofs\":[" + proof("ff".repeat(32), C_A, 2) + "]}").proofs.get(0).payload();
        assertEquals(0x6A84, SimCard.sw(card.transmit(SimCard.apdu(0x30, 0, 0, extra, 0x01))));
    }

    @Test
    @DisplayName("a 129-piece fixture is refused before any APDU")
    void tooManyProofsRefused() throws FixtureException {
        StringBuilder proofs = new StringBuilder("[");
        for (int i = 0; i < 129; i++) {
            if (i > 0) proofs.append(',');
            proofs.append(proof(String.format("%02x", i % 256).repeat(32), C_A, 1));
        }
        proofs.append(']');
        assertThrows(IllegalArgumentException.class, () -> fixture("{" + SETUP + ",\"proofs\":" + proofs + "}"));
        assertEquals(0, card.state().get("balance").getAsLong());
    }

    @Test
    @DisplayName("a piece with the mint's proof is loaded with P1 = 1: /state and GET_DLEQ give the proof back; a dated piece with the record's refund key")
    void dleqAndDate() throws FixtureException {
        String e = "01".repeat(32), sProof = "02".repeat(32), r = "03".repeat(32);
        apply("{" + SETUP + ",\"refundKey\":\"02" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\","
            + "\"proofs\":[{\"keysetId\":\"" + KEYSET + "\",\"amount\":8,\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A
            + "\",\"date\":1900000000,\"dleq\":{\"e\":\"" + e + "\",\"s\":\"" + sProof + "\",\"r\":\"" + r + "\"}},"
            + proof(NONCE_B, C_B, 16) + "]}");
        JsonArray slots = card.state().getAsJsonArray("slots");
        JsonObject s0 = slots.get(0).getAsJsonObject();
        assertEquals(1900000000L, s0.get("date").getAsLong());
        assertEquals(e, s0.getAsJsonObject("dleq").get("e").getAsString());
        assertEquals(sProof, s0.getAsJsonObject("dleq").get("s").getAsString());
        assertEquals(r, s0.getAsJsonObject("dleq").get("r").getAsString());
        assertFalse(slots.get(1).getAsJsonObject().has("dleq"), "a piece loaded plain has none");
        byte[] dleq = data(card.transmit(SimCard.apdu(0x1A, 0, 1, null, 0x00)));
        assertEquals(1 + 96 + 1, dleq.length, "GET_DLEQ: 01 and the proof, then 00 for the plain piece");
        assertEquals(1, dleq[0]);
        assertEquals(0, dleq[97]);
    }

    // ── the owner, the clock and the limits ─────────────────────────────────

    @Test
    @DisplayName("{owner, anchor, headers, limits}: the TEST owner key, the clock at the anchor then the headers, the limits and the rollover budget")
    void ownerClockAndLimits() throws FixtureException {
        apply("{" + SETUP + ",\"anchor\":\"" + HEADERS.get(2) + "\",\"headers\":[\"" + HEADERS.get(3) + "\",\"" + HEADERS.get(4) + "\"],"
            + "\"limits\":{\"day\":5000,\"payment\":1000,\"allowance\":250,\"rollBudget\":3}}");
        JsonObject s = card.state();
        assertTrue(s.get("hasOwner").getAsBoolean());
        assertTrue(s.get("testOwner").getAsBoolean());
        assertEquals(Hex.formatLower(OwnerKey.TEST.pub), s.get("ownerKey").getAsString());
        assertEquals(TIMES.get(4).longValue(), s.get("now").getAsLong(), "the anchor, then two later headers");
        assertEquals(5000, s.get("dailyLimit").getAsLong());
        assertEquals(250, s.get("allowance").getAsLong());
        assertEquals(3, s.get("rollBudget").getAsInt());
        assertEquals(0, s.get("rolls").getAsInt());
        assertTrue(s.get("allowanceArmed").getAsBoolean(), "armed by the PIN and the owner's proofs");
        assertEquals(MINT, s.get("mint").getAsString());
    }

    @Test
    @DisplayName("a card with no rollover budget set reads the default, 7")
    void theDefaultBudget() throws FixtureException {
        apply("{" + SETUP + "}");
        assertEquals(7, card.state().get("rollBudget").getAsInt());
    }

    @Test
    @DisplayName("the TEST owner key is cardctl's: SHA-256 of the same string, mod n")
    void theTestOwnerKeyIsShared() throws Exception {
        java.math.BigInteger d = new java.math.BigInteger(1, java.security.MessageDigest.getInstance("SHA-256")
            .digest("cashu-javacard/cardctl test owner key".getBytes("US-ASCII"))).mod(OwnerKey.N);
        assertEquals(d, OwnerKey.TEST.d);
        String p256 = new String(Files.readAllBytes(Paths.get("../cardctl/p256.py")), "UTF-8");
        assertTrue(p256.contains("TEST_OWNER_SEED = b\"cashu-javacard/cardctl test owner key\""), "cardctl's seed is the same string");
    }

    // ── PIN ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("{pin, owner, blockedPin} → pinState 2, VERIFY 6983; the owner's CHANGE_PIN unblocks, and the new PIN verifies")
    void blockedPinAndTheOwnersChangePin() throws FixtureException {
        apply("{" + SETUP + ",\"blockedPin\":true}");
        assertEquals(2, card.state().get("pinState").getAsInt());
        assertEquals(0x6983, SimCard.sw(card.transmit(VERIFY_1234)), "the right PIN is refused: blocked");

        byte[] nonce = data(card.transmit(Hex.parse("B044000010")));
        byte[] change = OwnerKey.TEST.data("CashuCard/change-pin", nonce, "5678".getBytes());
        assertEquals(0x9000, SimCard.sw(card.transmit(SimCard.apdu(0x42, 0, 0, change, -1))), "CHANGE_PIN");
        assertEquals(1, card.state().get("pinState").getAsInt());
        assertEquals(0x9000, SimCard.sw(card.transmit(SimCard.apdu(0x40, 0, 0, "5678".getBytes(), -1))), "new PIN verifies");
    }

    @Test
    @DisplayName("blockedPin with PIN 0000 uses a different wrong PIN")
    void blockedPinZeroZeroZeroZero() throws FixtureException {
        apply("{\"pin\":\"0000\",\"blockedPin\":true}");
        assertEquals(2, card.state().get("pinState").getAsInt());
    }

    @Test
    @DisplayName("after any fixture the session is fresh: the PIN set in it is not verified")
    void fixtureEndsSession() throws FixtureException {
        apply("{" + SETUP + "}");
        assertEquals(0x6982, SimCard.sw(card.transmit(GET_LOG)), "no PIN in this tap");
        assertEquals(0x9000, SimCard.sw(card.transmit(VERIFY_1234)));
        assertEquals(0x9000, SimCard.sw(card.transmit(GET_LOG)), "verified");
        apply("{}");
        assertEquals(0x6982, SimCard.sw(card.transmit(GET_LOG)), "an empty fixture still ends with SELECT");
    }

    @Test
    @DisplayName("a piece loaded twice is refused at LOAD_PROOF with 6A94; fixtureError set, generation bumped, the card intact")
    void fixtureTwice() throws FixtureException {
        apply("{" + SETUP + ",\"proofs\":[" + proof(NONCE_A, C_A, 8) + "]}");
        long gen = card.generation();

        FixtureException e = assertThrows(FixtureException.class, () -> apply("{\"proofs\":[" + proof(NONCE_A, C_A, 8) + "]}"));
        assertEquals("LOAD_PROOF", e.step);
        assertEquals(0x6A94, e.sw);
        assertEquals(gen + 1, card.generation(), "generation moves on failure too");

        JsonObject err = card.state().getAsJsonObject("fixtureError");
        assertEquals("LOAD_PROOF", err.get("step").getAsString());
        assertEquals("6A94", err.get("sw").getAsString());
        assertEquals(8, card.state().get("balance").getAsLong(), "the first fixture's card is intact");

        card.reset();
        assertFalse(card.state().has("fixtureError"), "reset clears the error");
    }

    @Test
    @DisplayName("a fixture refused mid-way keeps fixtureError until the next fixture")
    void fixtureErrorClearedByNextFixture() throws FixtureException {
        apply("{\"pin\":\"1234\"}");
        assertThrows(FixtureException.class, () -> apply("{\"pin\":\"5678\"}"), "VERIFY_PIN of another PIN");
        assertTrue(card.state().has("fixtureError"));
        apply("{}");
        assertFalse(card.state().has("fixtureError"));
    }

    // ── validation ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("invalid fixtures are refused with the card untouched")
    void invalidFixturesRefused() {
        String before = card.state().toString();
        String[] bad = {
            "{" + SETUP + ",\"proofs\":[" + proof(NONCE_A, "05" + "11".repeat(32), 8) + "]}",       // C prefix 05
            "{" + SETUP + ",\"proofs\":[" + proof(NONCE_A, C_A, 1L << 32) + "]}",                  // amount 2^32
            "{" + SETUP + ",\"proofs\":[" + proof(NONCE_A, C_A, 0) + "]}",                         // amount 0
            "{" + SETUP + ",\"proofs\":[" + proof(NONCE_A, C_A, 8) + "," + proof(NONCE_A, C_B, 8) + "]}", // a nonce twice
            "{" + SETUP + ",\"proofs\":[" + proof(NONCE_A, C_A, 8) + "],\"spentSlots\":[7]}",      // slot 7 of 1
            "{" + SETUP + ",\"proofs\":" + threeProofs() + ",\"spentSlots\":[1,1]}",               // repeated slot
            "{\"spentSlots\":[0]}",                                                                // no proofs
            "{\"mint\":\"" + MINT + "\",\"proofs\":" + threeProofs() + "}",                       // no owner
            "{\"owner\":true,\"proofs\":" + threeProofs() + "}",                                  // no record
            "{" + SETUP + ",\"proofs\":[{\"keysetId\":\"" + KEYSET + "\",\"amount\":8,\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A + "\",\"date\":5}]}", // dated, no refund key
            "{" + SETUP + ",\"proofs\":[{\"keysetId\":\"" + KEYSET + "\",\"amount\":8,\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A + "\",\"dleq\":{\"e\":\"" + "00".repeat(32) + "\",\"s\":\"" + "00".repeat(32) + "\",\"r\":\"" + "00".repeat(32) + "\"}}]}", // zero proof
            "{" + SETUP + ",\"proofs\":[{\"keysetId\":\"" + KEYSET + "\",\"amount\":8,\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A + "\",\"dleq\":{\"e\":\"" + "01".repeat(32) + "\"}}]}", // half a proof
            "{\"limits\":{\"day\":100}}",                                                          // no owner
            "{\"mint\":\"" + MINT + "\",\"owner\":true,\"limits\":{\"allowance\":100}}",           // allowance, no PIN
            "{" + SETUP + ",\"limits\":{\"rollBudget\":0}}",                                       // budget 0
            "{" + SETUP + ",\"limits\":{\"rollBudget\":31}}",                                      // budget 31
            "{" + SETUP + ",\"limits\":{\"week\":1}}",                                             // unknown limit
            "{\"anchor\":\"" + HEADERS.get(0) + "\"}",                                             // anchor, no owner
            "{\"headers\":[\"" + HEADERS.get(0).substring(2) + "\"]}",                            // 79 bytes
            "{\"owner\":true,\"ownerKey\":\"" + "11".repeat(32) + "\"}",                          // both
            "{\"ownerKey\":\"" + "00".repeat(32) + "\"}",                                         // d = 0
            "{\"mint\":\"" + "m".repeat(78) + "\"}",                                              // mint too long
            "{\"refundKey\":\"02" + "11".repeat(32) + "\"}",                                       // refund, no mint
            "{\"puk\":\"12345678\"}",                                                              // gone in 2.0
            "{\"appletVersion\":\"0.6\"}",                                                         // gone in 2.0
            "{\"blockedPin\":true}",                                                               // needs pin
            "{\"pin\":\"123\"}",                                                                   // too short
            "{\"pin\":\"123456789\"}",                                                             // too long
            "{\"bogus\":1}",                                                                       // unknown key
            "{" + SETUP + ",\"proofs\":[{\"keysetId\":\"" + KEYSET + "\",\"amount\":8,\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A + "\",\"spent\":false}]}", // unknown slot key
            "{" + SETUP + ",\"proofs\":[{\"keysetId\":\"0059534c\",\"amount\":8,\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A + "\"}]}",  // half keyset
            "{" + SETUP + ",\"proofs\":[{\"keysetId\":\"" + KEYSET + "\",\"amount\":8.5,\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A + "\"}]}", // fractional
            "{" + SETUP + ",\"proofs\":[{\"keysetId\":\"" + KEYSET + "\",\"amount\":\"8\",\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A + "\"}]}", // string amount
            "[]",
            "not json",
        };
        for (String json : bad) {
            assertThrows(IllegalArgumentException.class, () -> fixture(json), json);
        }
        assertEquals(before, card.state().toString(), "nothing reached the card");
    }

    @Test
    @DisplayName("a fixture is checked against the card as it is: a PIN set earlier lets an allowance through, an owner set earlier lets limits through")
    void validationReadsTheCard() throws FixtureException {
        apply("{" + SETUP + "}");
        fixture("{\"limits\":{\"day\":100,\"allowance\":50}}");
        assertThrows(IllegalArgumentException.class, () -> fixture("{\"proofs\":[" + proof(NONCE_A, C_A, 8) + "],\"spentSlots\":[0]}"),
            "spending on a card with a PIN needs the pin in the fixture");
    }

    @Test
    @DisplayName("JSON 8.0 is the integer 8")
    void integralFloatIsInteger() {
        Fixture f = fixture("{" + SETUP + ",\"proofs\":[{\"keysetId\":\"" + KEYSET + "\",\"amount\":8.0,\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A + "\"}]}");
        assertEquals(8, f.proofs.get(0).amount);
    }

    @Test
    @DisplayName("hex is case-insensitive and 0x-tolerant in fixtures, lower case in state")
    void hexLeniency() throws FixtureException {
        apply("{" + SETUP + ",\"proofs\":[{\"keysetId\":\"0x0059534CE0BFA19A\",\"amount\":8,\"nonce\":\"" + NONCE_A.toUpperCase()
            + "\",\"C\":\"" + C_A + "\"}]}");
        JsonObject slot0 = card.state().getAsJsonArray("slots").get(0).getAsJsonObject();
        assertEquals(KEYSET, slot0.get("keysetId").getAsString());
        assertEquals(NONCE_A, slot0.get("nonce").getAsString());
    }

    // ── reads a till makes ──────────────────────────────────────────────────

    @Test
    @DisplayName("GET_PIECES, AUTH and GET_DLEQ answer on a loaded card, with no PIN")
    void theTillsReads() throws FixtureException {
        apply("{" + SETUP + ",\"proofs\":" + threeProofs() + "}");
        byte[] pieces = card.transmit(SimCard.apdu(0x17, 0, 0, null, 0x00));
        assertEquals(0x9000, SimCard.sw(pieces));
        assertEquals((byte) 128, pieces[0], "one page covers the card");
        byte[] auth = card.transmit(SimCard.apdu(0x15, 0, 0, new byte[16], 0x50));
        assertEquals(0x9000, SimCard.sw(auth));
        assertEquals(80, data(auth).length, "16 bytes of the card's and a signature");
        assertEquals(0x9000, SimCard.sw(card.transmit(SimCard.apdu(0x1A, 0, 0xFF, null, 0x00))));
    }

    // ── reset ───────────────────────────────────────────────────────────────

    @Test
    @DisplayName("reset: generation + 1, slots empty, no PIN, no owner")
    void resetIsAFreshCard() throws FixtureException {
        apply("{" + SETUP + ",\"proofs\":" + threeProofs() + "}");
        long gen = card.generation();
        card.reset();
        assertEquals(gen + 1, card.generation());
        JsonObject s = card.state();
        assertEquals(0, s.get("pinState").getAsInt());
        assertFalse(s.get("hasOwner").getAsBoolean());
        assertEquals(0, s.get("balance").getAsLong());
        for (int i = 0; i < 128; i++) {
            assertEquals("empty", s.getAsJsonArray("slots").get(i).getAsJsonObject().get("status").getAsString());
        }
        assertEquals("02009000", Hex.format(card.transmit(SimCard.SELECT)));
    }

    @Test
    @DisplayName("the key is deterministic: every reset yields the same pubkey (jCardSim's unseeded generator)")
    void resetYieldsTheSameDeterministicKey() {
        String first = card.state().get("pubkey").getAsString();
        card.reset();
        assertEquals(first, card.state().get("pubkey").getAsString());
        assertEquals(first, new SimCard().state().get("pubkey").getAsString(), "and across instances");
        assertTrue(card.state().get("deterministicKey").getAsBoolean());
    }

    @Test
    @DisplayName("state starts at generation 0 and does not touch the session")
    void stateIsReadOnly() throws FixtureException {
        assertEquals(0, card.generation());
        apply("{" + SETUP + "}");
        assertEquals(0x9000, SimCard.sw(card.transmit(VERIFY_1234)));
        card.state();
        assertEquals(0x9000, SimCard.sw(card.transmit(GET_LOG)), "still verified after a state read");
    }
}
