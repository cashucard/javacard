package me.flashapp.cashu.cardsim;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The 0.x bridge could mask its card as applet 0.4 or 0.5, so the apps could test their old-card paths. On 2.0 the
 * masks are gone (D18): a 0.x or Foxy 1.x card does not answer the 2.0 AID at all, and an app shows "This card needs
 * an update". What the masks were for is asked of the 2.0 bridge here: the old card is told apart by its AID, the old
 * opcodes reach 2.0 commands that refuse them, and the fixture refuses the old keys by name. It was VersionMaskTest
 * until the review of PR #34; it is named for what it tests now.
 */
class OldCardTest {

    static final byte[] SELECT_0X = Hex.parse("00A4040007D2760000850102");
    static final byte[] SELECT_FOXY = Hex.parse("00A4040009F0464F585943415244");
    static final byte[] GET_INFO = Hex.parse("B001000000");
    // 0.x's CLEAR_PIN [len][pin], SET_PUK [08]"12345678", UNBLOCK_PIN [08]"12345678"[04]"1234" (cardctl framing)
    static final byte[] CLEAR_PIN = Hex.parse("B0430000 05 04 31323334");
    static final byte[] SET_PUK = Hex.parse("B0440000 09 08 3132333435363738");
    static final byte[] UNBLOCK_PIN = Hex.parse("B0450000 0E 08 3132333435363738 04 31323334");

    SimCard card;

    @BeforeEach
    void fresh() {
        card = new SimCard();
    }

    byte[] data(byte[] resp) {
        return Arrays.copyOf(resp, resp.length - 2);
    }

    @Test
    @DisplayName("the 0.x AID and Foxy's 1.x AID select nothing on a 2.0 card: the needs-an-update signal")
    void oldAidsAreNotFound() {
        // A card's runtime answers 6A82. jCardSim, with no applet of that name, hands the SELECT to the applet already
        // selected, which refuses class 00 (6E00), or answers 6999 with none selected: an app reads any SELECT answer but
        // 9000 with version 02 as "this card needs an update".
        for (byte[] select : new byte[][] { SELECT_0X, SELECT_FOXY }) {
            int sw = SimCard.sw(card.transmit(select));
            assertTrue(sw == 0x6A82 || sw == 0x6999 || sw == 0x6E00, "not found, got " + Hex.sw(sw));
        }
        assertEquals("02019000", Hex.format(card.transmit(SimCard.SELECT)), "the 2.x AID answers 02 01");
    }

    @Test
    @DisplayName("GET_INFO answers version 2.1, thirty bytes, capabilities FF and format 4: no masked 8-byte answer")
    void getInfoIsTwoZero() {
        byte[] info = data(card.transmit(GET_INFO));
        assertEquals(30, info.length);
        assertEquals(2, info[0]);
        assertEquals(1, info[1]);
        assertEquals((byte) 0xFF, info[6]);
        assertEquals(4, info[8]);
        assertEquals("2.1", card.state().get("version").getAsString());
        assertFalse(card.state().has("appletVersion"), "no masked version in state");
        assertFalse(card.state().has("realVersion"));
        assertFalse(card.state().has("pukState"));
    }

    @Test
    @DisplayName("0x43, 0x44, 0x45 were CLEAR_PIN, SET_PUK, UNBLOCK_PIN; on 2.0 they refuse a 0.x reader's bytes and change nothing")
    void oldOpcodesChangeNothing() throws FixtureException {
        card.applyFixture(Fixture.parse("{\"pin\":\"1234\",\"mint\":\"http://m\",\"owner\":true}", card.context()));
        String before = card.state().toString();
        assertEquals(0x6A91, SimCard.sw(card.transmit(CLEAR_PIN)), "SET_OWNER on an owned card: no proof in a PIN");
        byte[] nonce = card.transmit(SET_PUK);
        assertEquals(0x9000, SimCard.sw(nonce), "GET_NONCE reads no data");
        assertEquals(16, data(nonce).length);
        assertEquals(0x6A91, SimCard.sw(card.transmit(UNBLOCK_PIN)), "ALLOW_LOAD takes a PUK and a PIN as no proof");
        assertEquals(before, card.state().toString(), "nothing a 0.x reader sent was written");
    }

    @Test
    @DisplayName("the fixture refuses the 0.x keys by name: puk and appletVersion are 400s, the card untouched")
    void oldFixtureKeysRefused() {
        String before = card.state().toString();
        IllegalArgumentException puk = assertThrows(IllegalArgumentException.class,
            () -> Fixture.parse("{\"puk\":\"12345678\"}", card.context()));
        assertTrue(puk.getMessage().contains("no PUK"), puk.getMessage());
        IllegalArgumentException version = assertThrows(IllegalArgumentException.class,
            () -> Fixture.parse("{\"appletVersion\":\"0.4\"}", card.context()));
        assertTrue(version.getMessage().contains("version masks are gone"), version.getMessage());
        assertEquals(before, card.state().toString());
    }

    @Test
    @DisplayName("there is no mask class left to drift from the applet")
    void noMaskClass() {
        assertThrows(ClassNotFoundException.class, () -> Class.forName("me.flashapp.cashu.cardsim.VersionMask"));
    }
}
