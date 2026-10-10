package me.flashapp.cashu.cardsim;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SimCard against the real applet. Every assertion is about bytes the app
 * would see over the bridge, so the raw-byte path (Simulator.transmitCommand
 * on a byte[]) is checked against what the applet suite's CommandAPDU path
 * reports in CashuAppletTest.
 */
class SimCardTest {

    static final String KEYSET = "0059534ce0bfa19a";
    static final String NONCE_A = "ab".repeat(32);
    static final String NONCE_B = "cd".repeat(32);
    static final String NONCE_C = "ef".repeat(32);
    static final String C_A = "02" + "11".repeat(32);
    static final String C_B = "03" + "22".repeat(32);
    static final String C_C = "02" + "33".repeat(32);

    static final byte[] GET_INFO_LE00 = Hex.parse("B001000000");
    static final byte[] GET_PUBKEY_LE21 = Hex.parse("B010000021");
    static final byte[] GET_PUBKEY_LE00 = Hex.parse("B010000000");
    static final byte[] GET_BALANCE = Hex.parse("B011000004");
    static final byte[] GET_SLOT_STATUS = Hex.parse("B014000020");
    static final byte[] CLEAR_SPENT = Hex.parse("B031000001");
    static final byte[] SIGN_ZERO = SimCard.apdu(0x21, 0, 0, new byte[32], 0x40);

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
        return Fixture.parse(json, card.real());
    }

    void apply(String json) throws FixtureException {
        card.applyFixture(fixture(json));
    }

    static byte[] data(byte[] resp) {
        return Arrays.copyOf(resp, resp.length - 2);
    }

    // ── fresh card ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("a fresh card answers SELECT with 00 06 9000")
    void selectAnswersVersion() {
        assertEquals("00069000", Hex.format(card.transmit(SimCard.SELECT)));
        assertEquals("0.6", card.real().version());
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
    @DisplayName("raw-byte Le handling matches the applet suite's CommandAPDU path")
    void rawByteLeHandling() {
        // cardctl sends Le 21 for GET_PUBKEY; CashuAppletTest sends Le 256 (00).
        assertEquals(33, data(card.transmit(GET_PUBKEY_LE21)).length, "Le 21");
        assertEquals(33, data(card.transmit(GET_PUBKEY_LE00)).length, "Le 00");
        assertEquals(9, data(card.transmit(GET_INFO_LE00)).length, "GET_INFO is 9 bytes on 0.6");
        assertEquals(32, data(card.transmit(GET_SLOT_STATUS)).length, "GET_SLOT_STATUS is one byte per slot");
        assertEquals(0x9000, SimCard.sw(card.transmit(GET_BALANCE)));
    }

    @Test
    @DisplayName("an APDU shorter than a header is refused before it reaches the simulator")
    void shortApduRefused() {
        assertThrows(IllegalArgumentException.class, () -> card.transmit(Hex.parse("B001")));
    }

    // ── proofs ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("{proofs x3, spentSlots:[1]} → status 01 02 01, balance excludes slot 1, CLEAR_SPENT frees 1")
    void proofsAndSpentSlots() throws FixtureException {
        apply("{\"proofs\":" + threeProofs() + ",\"spentSlots\":[1]}");

        byte[] status = data(card.transmit(GET_SLOT_STATUS));
        assertEquals("010201", Hex.format(status, 0, 3));
        for (int i = 3; i < 32; i++) assertEquals(0, status[i], "slot " + i + " empty");

        assertEquals(8 + 32, SimCard.readUint32(data(card.transmit(GET_BALANCE)), 0),
            "balance is the unspent slots only");

        JsonObject s = card.state();
        assertEquals(40, s.get("balance").getAsLong());
        JsonArray slots = s.getAsJsonArray("slots");
        assertEquals(32, slots.size());
        JsonObject slot1 = slots.get(1).getAsJsonObject();
        assertEquals("spent", slot1.get("status").getAsString());
        assertEquals(KEYSET, slot1.get("keysetId").getAsString());
        assertEquals(16, slot1.get("amount").getAsLong());
        assertEquals(NONCE_B, slot1.get("nonce").getAsString());
        assertEquals(C_B, slot1.get("C").getAsString());
        assertEquals("unspent", slots.get(0).getAsJsonObject().get("status").getAsString());
        assertEquals("empty", slots.get(3).getAsJsonObject().get("status").getAsString());
        assertFalse(slots.get(3).getAsJsonObject().has("nonce"), "empty slots carry no proof fields");

        byte[] cleared = card.transmit(CLEAR_SPENT);
        assertEquals(0x9000, SimCard.sw(cleared));
        assertEquals(1, cleared[0], "CLEAR_SPENT frees the one spent slot");
        assertEquals("010001", Hex.format(data(card.transmit(GET_SLOT_STATUS)), 0, 3));
    }

    @Test
    @DisplayName("32 proofs fill the card; a 33rd LOAD_PROOF answers 6A84")
    void fullCardRefusesLoad() throws FixtureException {
        StringBuilder proofs = new StringBuilder("[");
        for (int i = 0; i < 32; i++) {
            if (i > 0) proofs.append(',');
            proofs.append(proof(String.format("%02x", i).repeat(32), "02" + String.format("%02x", 0x40 + i).repeat(32), 1L << (i % 20)));
        }
        proofs.append(']');
        apply("{\"proofs\":" + proofs + "}");

        byte[] status = data(card.transmit(GET_SLOT_STATUS));
        for (int i = 0; i < 32; i++) assertEquals(1, status[i], "slot " + i + " unspent");

        byte[] extra = Fixture.parse("{\"proofs\":[" + proof("ff".repeat(32), C_A, 2) + "]}", card.real())
            .proofs.get(0).payload();
        assertEquals(0x6A84, SimCard.sw(card.transmit(SimCard.apdu(0x30, 0, 0, extra, 0x01))));
    }

    @Test
    @DisplayName("a 33-proof fixture is refused before any APDU")
    void thirtyThreeProofsRefused() {
        StringBuilder proofs = new StringBuilder("[");
        for (int i = 0; i < 33; i++) {
            if (i > 0) proofs.append(',');
            proofs.append(proof(String.format("%02x", i).repeat(32), C_A, 1));
        }
        proofs.append(']');
        assertThrows(IllegalArgumentException.class, () -> fixture("{\"proofs\":" + proofs + "}"));
        assertEquals("empty", card.state().getAsJsonArray("slots").get(0).getAsJsonObject().get("status").getAsString());
    }

    // ── PIN / PUK ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("{pin, puk, blockedPin} → pinState 2, pukState 1, VERIFY 6983, UNBLOCK_PIN 9000, new PIN verifies")
    void blockedPinWithPuk() throws FixtureException {
        apply("{\"pin\":\"1234\",\"puk\":\"12345678\",\"blockedPin\":true}");

        JsonObject s = card.state();
        assertEquals(2, s.get("pinState").getAsInt());
        assertEquals(1, s.get("pukState").getAsInt());

        byte[] pin = "1234".getBytes();
        assertEquals(0x6983, SimCard.sw(card.transmit(SimCard.apdu(0x40, 0, 0, pin, -1))), "the right PIN is refused: blocked");
        assertEquals(0x6982, SimCard.sw(card.transmit(SIGN_ZERO)), "gated while blocked");

        byte[] unblock = Hex.parse("08" + Hex.format("12345678".getBytes()) + "04" + Hex.format("5678".getBytes()));
        assertEquals(0x9000, SimCard.sw(card.transmit(SimCard.apdu(0x45, 0, 0, unblock, -1))), "UNBLOCK_PIN");
        assertEquals(1, card.state().get("pinState").getAsInt());
        assertEquals(0x9000, SimCard.sw(card.transmit(SimCard.apdu(0x40, 0, 0, "5678".getBytes(), -1))), "new PIN verifies");
        assertEquals(0x9000, SimCard.sw(card.transmit(SIGN_ZERO)), "and the session is open");
    }

    @Test
    @DisplayName("blockedPin with PIN 0000 uses a different wrong PIN")
    void blockedPinZeroZeroZeroZero() throws FixtureException {
        apply("{\"pin\":\"0000\",\"blockedPin\":true}");
        assertEquals(2, card.state().get("pinState").getAsInt());
    }

    @Test
    @DisplayName("after any fixture the session is unverified")
    void fixtureEndsSession() throws FixtureException {
        apply("{\"pin\":\"1234\"}");
        assertEquals(0x6982, SimCard.sw(card.transmit(SIGN_ZERO)), "SET_PIN alone opens no session");

        assertEquals(0x9000, SimCard.sw(card.transmit(SimCard.apdu(0x40, 0, 0, "1234".getBytes(), -1))));
        assertEquals(0x9000, SimCard.sw(card.transmit(SIGN_ZERO)), "verified");

        apply("{}");
        assertEquals(0x6982, SimCard.sw(card.transmit(SIGN_ZERO)), "an empty fixture still ends with SELECT");
    }

    @Test
    @DisplayName("a fixture applied twice is refused at LOAD_PROOF with 6982; fixtureError set, generation bumped")
    void fixtureTwice() throws FixtureException {
        String f = "{\"pin\":\"1234\",\"proofs\":[" + proof(NONCE_A, C_A, 8) + "]}";
        apply(f);
        long gen = card.generation();

        FixtureException e = assertThrows(FixtureException.class, () -> apply(f));
        assertEquals("LOAD_PROOF", e.step);
        assertEquals(0x6982, e.sw);
        assertEquals(gen + 1, card.generation(), "generation moves on failure too");

        JsonObject s = card.state();
        JsonObject err = s.getAsJsonObject("fixtureError");
        assertEquals("LOAD_PROOF", err.get("step").getAsString());
        assertEquals("6982", err.get("sw").getAsString());
        assertEquals(1, card.state().get("pinState").getAsInt(), "the first fixture's card is intact");

        card.reset();
        assertFalse(card.state().has("fixtureError"), "reset clears the error");
    }

    @Test
    @DisplayName("a fixture refused mid-way keeps fixtureError until the next fixture")
    void fixtureErrorClearedByNextFixture() throws FixtureException {
        apply("{\"pin\":\"1234\"}");
        assertThrows(FixtureException.class, () -> apply("{\"pin\":\"5678\"}"));
        assertTrue(card.state().has("fixtureError"));
        apply("{}");
        assertFalse(card.state().has("fixtureError"));
    }

    // ── validation ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("invalid fields are refused with the card untouched")
    void invalidFixturesRefused() {
        String before = card.state().toString();
        String[] bad = {
            "{\"proofs\":[" + proof(NONCE_A, "05" + "11".repeat(32), 8) + "]}",        // C prefix 05
            "{\"proofs\":[" + proof(NONCE_A, C_A, 1L << 32) + "]}",                   // amount 2^32
            "{\"proofs\":[" + proof(NONCE_A, C_A, 0) + "]}",                          // amount 0
            "{\"proofs\":[" + proof(NONCE_A, C_A, 8) + "],\"spentSlots\":[7]}",       // slot 7 of 1
            "{\"proofs\":" + threeProofs() + ",\"spentSlots\":[7]}",                  // slot 7 of 3
            "{\"proofs\":" + threeProofs() + ",\"spentSlots\":[1,1]}",                // repeated slot
            "{\"spentSlots\":[0]}",                                                   // no proofs
            "{\"puk\":\"12345678\",\"appletVersion\":\"0.4\"}",                       // 0.4 has no PUK
            "{\"puk\":\"12345678\",\"appletVersion\":\"0.5\"}",                       // 0.5 has no PUK
            "{\"blockedPin\":true}",                                                  // needs pin
            "{\"pin\":\"123\"}",                                                      // too short
            "{\"pin\":\"123456789\"}",                                                // too long
            "{\"puk\":\"1234567\"}",                                                  // too short
            "{\"puk\":\"1234567890123\"}",                                            // too long
            "{\"appletVersion\":\"0.7\"}",                                            // newer than the applet
            "{\"appletVersion\":\"0.3\"}",                                            // unknown
            "{\"appletVersion\":\"six\"}",                                            // not a version
            "{\"bogus\":1}",                                                          // unknown key
            "{\"proofs\":[{\"keysetId\":\"" + KEYSET + "\",\"amount\":8,\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A + "\",\"spent\":false}]}", // unknown slot key
            "{\"proofs\":[{\"keysetId\":\"0059534c\",\"amount\":8,\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A + "\"}]}",  // half keyset
            "{\"proofs\":[{\"keysetId\":\"" + KEYSET + "\",\"amount\":8.5,\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A + "\"}]}", // fractional
            "{\"proofs\":[{\"keysetId\":\"" + KEYSET + "\",\"amount\":\"8\",\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A + "\"}]}", // string amount
            "[]",
            "not json",
        };
        for (String json : bad) {
            assertThrows(IllegalArgumentException.class, () -> fixture(json), json);
        }
        assertEquals(before, card.state().toString(), "nothing reached the card");
    }

    @Test
    @DisplayName("JSON 8.0 is the integer 8")
    void integralFloatIsInteger() {
        Fixture f = fixture("{\"proofs\":[{\"keysetId\":\"" + KEYSET + "\",\"amount\":8.0,\"nonce\":\"" + NONCE_A + "\",\"C\":\"" + C_A + "\"}]}");
        assertEquals(8, f.proofs.get(0).amount);
    }

    @Test
    @DisplayName("hex is case-insensitive and 0x-tolerant in fixtures, lower case in state")
    void hexLeniency() throws FixtureException {
        apply("{\"proofs\":[{\"keysetId\":\"0x0059534CE0BFA19A\",\"amount\":8,\"nonce\":\"" + NONCE_A.toUpperCase()
            + "\",\"C\":\"" + C_A + "\"}]}");
        JsonObject slot0 = card.state().getAsJsonArray("slots").get(0).getAsJsonObject();
        assertEquals(KEYSET, slot0.get("keysetId").getAsString());
        assertEquals(NONCE_A, slot0.get("nonce").getAsString());
    }

    // ── reset ───────────────────────────────────────────────────────────────

    @Test
    @DisplayName("reset: generation + 1, slots empty, mask back to real")
    void resetIsAFreshCard() throws FixtureException {
        apply("{\"pin\":\"1234\",\"proofs\":" + threeProofs() + ",\"appletVersion\":\"0.4\"}");
        assertEquals("00049000", Hex.format(card.transmit(SimCard.SELECT)), "masked to 0.4");
        long gen = card.generation();

        card.reset();
        assertEquals(gen + 1, card.generation());
        JsonObject s = card.state();
        assertEquals("0.6", s.get("appletVersion").getAsString());
        assertEquals("0.6", s.get("realVersion").getAsString());
        assertEquals(0, s.get("pinState").getAsInt());
        assertEquals(0, s.get("balance").getAsLong());
        for (int i = 0; i < 32; i++) {
            assertEquals("empty", s.getAsJsonArray("slots").get(i).getAsJsonObject().get("status").getAsString());
        }
        assertEquals("00069000", Hex.format(card.transmit(SimCard.SELECT)), "mask is real again");
    }

    @Test
    @DisplayName("the key is deterministic: every reset yields the same pubkey (jCardSim's unseeded generator)")
    void resetYieldsTheSameDeterministicKey() {
        // Documented in CardSim's header and announced by /state.deterministicKey.
        // If a jCardSim bump makes this fail, the header and the loaders'
        // mint-per-run rule both need a second look.
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
        apply("{\"pin\":\"1234\"}");
        assertEquals(0x9000, SimCard.sw(card.transmit(SimCard.apdu(0x40, 0, 0, "1234".getBytes(), -1))));
        card.state();
        assertEquals(0x9000, SimCard.sw(card.transmit(SIGN_ZERO)), "still verified after a state read");
    }
}
