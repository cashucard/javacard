package me.flashapp.cashu.cardsim;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class VersionMaskTest {

    static final byte[] GET_INFO = Hex.parse("B001000000");
    static final byte[] CLEAR_PIN = Hex.parse("B0430000 05 04 31323334"); // [len][pin] framing, any PIN
    // SET_PUK [08]"12345678"; UNBLOCK_PIN [08]"12345678"[04]"1234" (cardctl framing)
    static final byte[] SET_PUK = Hex.parse("B0440000 09 08 3132333435363738");
    static final byte[] UNBLOCK_PIN = Hex.parse("B0450000 0E 08 3132333435363738 04 31323334");
    static final byte[] CLA00_CLEAR_PIN = Hex.parse("00430000");

    SimCard card;

    @BeforeEach
    void fresh() {
        card = new SimCard();
    }

    void mask(String version) throws FixtureException {
        card.applyFixture(Fixture.parse("{\"appletVersion\":\"" + version + "\"}", card.real(), card.mask()));
    }

    byte[] data(byte[] resp) {
        return Arrays.copyOf(resp, resp.length - 2);
    }

    @Test
    @DisplayName("0.4: SELECT 00 04, GET_INFO 8 bytes with caps 07, INS 43/44/45 answer 6D00")
    void version04() throws FixtureException {
        mask("0.4");
        assertEquals("00049000", Hex.format(card.transmit(SimCard.SELECT)));
        byte[] info = data(card.transmit(GET_INFO));
        assertEquals(8, info.length);
        assertEquals(0x00, info[0]);
        assertEquals(0x04, info[1]);
        assertEquals(0x07, info[6]);
        assertEquals(0x6D00, SimCard.sw(card.transmit(CLEAR_PIN)));
        assertEquals(0x6D00, SimCard.sw(card.transmit(SET_PUK)));
        assertEquals(0x6D00, SimCard.sw(card.transmit(UNBLOCK_PIN)));
        assertEquals("0.4", card.state().get("appletVersion").getAsString());
        assertEquals("0.6", card.state().get("realVersion").getAsString());
    }

    @Test
    @DisplayName("0.5: caps 0F, CLEAR_PIN reaches the applet, 44/45 answer 6D00")
    void version05() throws FixtureException {
        mask("0.5");
        assertEquals("00059000", Hex.format(card.transmit(SimCard.SELECT)));
        byte[] info = data(card.transmit(GET_INFO));
        assertEquals(8, info.length);
        assertEquals(0x0F, info[6]);
        // No PIN, no session: the applet answers 6982, which proves the mask let it through.
        assertEquals(0x6982, SimCard.sw(card.transmit(CLEAR_PIN)));
        assertEquals(0x6D00, SimCard.sw(card.transmit(SET_PUK)));
        assertEquals(0x6D00, SimCard.sw(card.transmit(UNBLOCK_PIN)));
    }

    @Test
    @DisplayName("0.6 is passthrough: caps 1F, 9 bytes, every INS reaches the applet")
    void version06() throws FixtureException {
        mask("0.6");
        assertEquals("00069000", Hex.format(card.transmit(SimCard.SELECT)));
        byte[] info = data(card.transmit(GET_INFO));
        assertEquals(9, info.length);
        assertEquals(0x1F, info[6]);
        assertEquals(0x6982, SimCard.sw(card.transmit(CLEAR_PIN)));
        assertEquals(0x9000, SimCard.sw(card.transmit(SET_PUK)), "SET_PUK on a no-PIN card");
        assertEquals(0x6984, SimCard.sw(card.transmit(UNBLOCK_PIN)), "UNBLOCK_PIN with a PUK but no PIN");
    }

    @Test
    @DisplayName("the mask is read unmasked by state: a 0.4 card still reports its PUK state to the bridge")
    void stateIsUnmasked() throws FixtureException {
        // PUK first, mask second: legal on purpose (CardSim.java, "Version
        // masks"); the reverse order is refused by Fixture.parse.
        card.applyFixture(Fixture.parse("{\"puk\":\"12345678\"}", card.real(), card.mask()));
        mask("0.4");
        assertEquals(1, card.state().get("pukState").getAsInt(), "state reads the real 9-byte GET_INFO");
        assertEquals(8, data(card.transmit(GET_INFO)).length, "the app sees 8");
    }

    @Test
    @DisplayName("CLA 00 is never masked: a non-SELECT CLA 00 command reaches the applet's 6E00")
    void cla00NotMasked() throws FixtureException {
        mask("0.4");
        assertEquals(0x6E00, SimCard.sw(card.transmit(CLA00_CLEAR_PIN)));
    }

    @Test
    @DisplayName("errors pass through unrewritten: a masked GET_INFO with a bad CLA keeps its SW")
    void errorsNotRewritten() {
        VersionMask m = VersionMask.forVersion("0.4", card.real());
        byte[] cmd = Hex.parse("B001000000");
        byte[] errResp = Hex.parse("6E00");
        assertArrayEquals(errResp, m.rewrite(cmd, errResp));
        byte[] shortSelect = Hex.parse("9000"); // a SELECT with no data stays as is
        assertArrayEquals(shortSelect, m.rewrite(SimCard.SELECT, shortSelect));
    }

    @Test
    @DisplayName("a version above the real applet, or unknown, is refused")
    void unknownOrNewerRefused() {
        VersionMask real = card.real();
        assertThrows(IllegalArgumentException.class, () -> VersionMask.forVersion("0.7", real));
        assertThrows(IllegalArgumentException.class, () -> VersionMask.forVersion("1.0", real));
        assertThrows(IllegalArgumentException.class, () -> VersionMask.forVersion("0.3", real));
        assertThrows(IllegalArgumentException.class, () -> VersionMask.forVersion("0", real));
        assertThrows(IllegalArgumentException.class, () -> VersionMask.forVersion("", real));
        assertThrows(IllegalArgumentException.class, () -> VersionMask.forVersion(null, real));
        assertThrows(IllegalArgumentException.class, () -> VersionMask.forVersion("0.6.1", real));
    }

    @Test
    @DisplayName("every version from 0.4 to the applet's own has a mask entry")
    void coverage() {
        // A 0.7 applet whose VersionMask table was not extended fails here
        // rather than quietly serving 0.6 behaviour under a 0.7 label.
        VersionMask real = card.real();
        assertEquals(0, real.major);
        List<String> known = VersionMask.known();
        for (int minor = 4; minor <= real.minor; minor++) {
            String v = "0." + minor;
            assertTrue(known.contains(v), "no VersionMask entry for " + v);
            assertEquals(v, VersionMask.forVersion(v, real).version());
        }
        assertEquals(real.version(), known.get(known.size() - 1), "the newest entry is the real applet");
    }

    @Test
    @DisplayName("real() refuses a SELECT answer the table does not know")
    void realRefusesUnknown() {
        assertThrows(IllegalStateException.class, () -> VersionMask.real(Hex.parse("0007")));
        assertThrows(IllegalStateException.class, () -> VersionMask.real(Hex.parse("0106")));
        assertThrows(IllegalStateException.class, () -> VersionMask.real(Hex.parse("06")));
        assertEquals("0.6", VersionMask.real(Hex.parse("0006")).version());
    }

    @Test
    @DisplayName("hasPuk follows capability bit 4")
    void hasPuk() {
        VersionMask real = card.real();
        assertFalse(VersionMask.forVersion("0.4", real).hasPuk());
        assertFalse(VersionMask.forVersion("0.5", real).hasPuk());
        assertTrue(VersionMask.forVersion("0.6", real).hasPuk());
    }
}
