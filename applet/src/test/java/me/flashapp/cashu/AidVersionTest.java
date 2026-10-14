package me.flashapp.cashu;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The shared protocol's identity (D19): the package AID F0 43 41 53 48 55 43 41 52 44 ("CASHUCARD" after a
 * proprietary F0), the applet's instance AID the same and 01, version 2.1 (D26) in SELECT and GET_INFO, and the labels
 * "CashuCard/...". The two AIDs that went before, cashu-javacard 0.x's D2 76 00 00 85 01 02 (which was under the NFC
 * Forum's RID, never ours) and Foxy's F0 FOXYCARD, select nothing: that 6A82 is what a phone reads as "this card needs
 * an update".
 */
class AidVersionTest {

    static final String PACKAGE = "F0434153485543415244";
    static final String APPLET = PACKAGE + "01";
    static final String OLD_UPSTREAM = "D2760000850102";
    static final String OLD_FOXY = "F0464F585943415244";
    static final String OLD_FOXY_APPLET = OLD_FOXY + "01";
    /** Every label and tag the applet hashes or verifies under, after "CashuCard/". */
    static final String[] LABELS = { "auth", "change-pin", "set-limit", "set-owner", "set-card", "load", "lock", "reset", "tag", "refresh", "seal", "pinkey" };

    private CardSimulator sim;

    @BeforeEach
    void install() {
        sim = new CardSimulator(new CashuAppletTest.ExposedRuntime());
        sim.installApplet(AIDUtil.create(APPLET), CashuApplet.class);
    }

    private ResponseAPDU select(String aid) {
        return sim.transmitCommand(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, CashuAppletTest.hexToBytes(aid), 256));
    }

    @Test
    @DisplayName("the package AID is F0 then ASCII CASHUCARD, ten bytes, and the tests and the build use it")
    void theAidIsCashuCard() {
        assertEquals(PACKAGE, "F0" + CashuAppletTest.toHex("CASHUCARD".getBytes(StandardCharsets.US_ASCII)).toUpperCase());
        assertEquals(10, CashuAppletTest.hexToBytes(PACKAGE).length);
        assertEquals(PACKAGE, CashuAppletTest.AID_STR);
        assertEquals(APPLET, CashuAppletTest.AID_HEX);
    }

    @Test
    @DisplayName("SELECT by the package AID and by the applet's whole AID both answer 02 01")
    void selectAnswersTwoZero() {
        ResponseAPDU byPackage = select(PACKAGE);
        assertEquals(CashuAppletTest.SW_OK, byPackage.getSW());
        assertArrayEquals(new byte[] { 0x02, 0x01 }, byPackage.getData(), "2.1 by the package's name");
        ResponseAPDU whole = select(APPLET);
        assertEquals(CashuAppletTest.SW_OK, whole.getSW());
        assertArrayEquals(new byte[] { 0x02, 0x01 }, whole.getData(), "2.1 by the applet's");
    }

    @Test
    @DisplayName("GET_INFO's first two bytes are the version, 02 01")
    void getInfoSaysTwoZero() {
        assertEquals(CashuAppletTest.SW_OK, select(PACKAGE).getSW());
        ResponseAPDU info = sim.transmitCommand(new CommandAPDU(CashuAppletTest.CLA, CashuAppletTest.INS_GET_INFO, 0, 0, 256));
        assertEquals(CashuAppletTest.SW_OK, info.getSW());
        assertEquals(2, info.getData()[0], "major 2: the shared protocol");
        assertEquals(1, info.getData()[1], "minor 1: D26's rollover rules (ENG-699)");
        assertEquals(2, CashuApplet.VERSION_MAJOR);
        assertEquals(1, CashuApplet.VERSION_MINOR);
    }

    @Test
    @DisplayName("the 0.x AID D2 76 00 00 85 01 02 and Foxy's F0 FOXYCARD select nothing: 6A82, the needs-an-update signal")
    void theOldAidsAreNotFound() {
        assertNotFound(select(OLD_UPSTREAM).getSW(), "cashu-javacard 0.x's AID");
        assertNotFound(select(OLD_FOXY).getSW(), "Foxy's package AID");
        assertNotFound(select(OLD_FOXY_APPLET).getSW(), "Foxy's applet AID");
        assertEquals(CashuAppletTest.SW_OK, select(PACKAGE).getSW(), "and the card is still there under its own");
    }

    @Test
    @DisplayName("applet/build.xml converts under the same AIDs: package F0 CASHUCARD, opener 4D, card 01, tag 54, in cap and cap-debug")
    void theBuildUsesTheSameAids() throws Exception {
        String xml = new String(Files.readAllBytes(buildXml()), StandardCharsets.UTF_8);
        assertFalse(xml.toUpperCase().contains("F0:46:4F:58:59"), "no Foxy AID is left in the build");
        assertFalse(xml.toUpperCase().contains("F0464F5859"), "nor in its gp commands");
        for (String target : new String[] { "\"cap\"", "\"cap-debug\"" }) {
            int at = xml.indexOf("<target name=" + target);
            assertTrue(at >= 0, "target " + target);
            String body = xml.substring(at, xml.indexOf("</target>", at));
            assertTrue(body.contains("aid=\"F0:43:41:53:48:55:43:41:52:44\""), target + ": the package");
            Matcher m = Pattern.compile("class=\"me\\.flashapp\\.cashu\\.(\\w+)\"\\s+aid=\"([0-9A-F:]+)\"").matcher(body);
            int seen = 0;
            while (m.find()) {
                String aid = m.group(2).replace(":", "");
                switch (m.group(1)) {
                    case "Opener": assertEquals(PACKAGE + "4D", aid, target); seen++; break;
                    case "CashuApplet": assertEquals(APPLET, aid, target); seen++; break;
                    case "Tag": assertEquals(PACKAGE + "54", aid, target); seen++; break;
                    default: throw new AssertionError("an applet the test does not know: " + m.group(1));
                }
            }
            assertEquals(3, seen, target + ": three applets");
        }
    }

    @Test
    @DisplayName("no Foxy label, AID or byte array is left in the applet's source: every tag and label is CashuCard/")
    void noFoxyIdentityInTheSource() throws Exception {
        for (String file : new String[] { "CashuApplet.java", "Tag.java", "Opener.java", "TagSwitch.java", "SchnorrHW.java" }) {
            String src = new String(Files.readAllBytes(SchnorrHWMathTest.mainSourceDir().resolve(file)), StandardCharsets.UTF_8);
            assertFalse(src.contains("'F','o','x','y'") || src.contains("'F', 'o', 'x', 'y'"), file + ": a FoxyCard label");
            assertFalse(src.contains("'F', 'O', 'X', 'Y'") || src.contains("'F','O','X','Y'"), file + ": the FOXYCARD AID");
            assertFalse(src.contains("FoxyCard/"), file + ": a FoxyCard/ label in text");
            assertFalse(Pattern.compile("0x46,\\s*0x4F,\\s*0x58,\\s*0x59", Pattern.CASE_INSENSITIVE).matcher(src).find(), file + ": FOXY as hex bytes");
        }
        String applet = new String(Files.readAllBytes(SchnorrHWMathTest.mainSourceDir().resolve("CashuApplet.java")), StandardCharsets.UTF_8)
            .replaceAll("\\s+", "");
        for (String label : LABELS) {
            assertTrue(applet.contains(chars("CashuCard/" + label)), "the label CashuCard/" + label + " as the applet writes it");
        }
    }

    /**
     * A SELECT of an AID no applet on the card has. A card's runtime (the card manager on a JCOP) answers 6A82, file or
     * application not found; jCardSim answers 6999, selection failed. Either is "no such applet", and neither selects
     * anything: the next command still reaches the applet that was selected before, or none.
     */
    private static void assertNotFound(int sw, String what) {
        assertTrue(sw == 0x6A82 || sw == 0x6999, what + ": not found, got " + Integer.toHexString(sw));
    }

    /** A label as the applet's source writes it: a byte array of characters, 'C','a',... with or without spaces. */
    private static String chars(String label) {
        StringBuilder b = new StringBuilder();
        for (char c : label.toCharArray()) {
            if (b.length() > 0) b.append(",");
            b.append('\'').append(c).append('\'');
        }
        return b.toString();
    }

    static Path buildXml() throws java.io.IOException {
        // mainSourceDir is <applet>/src/main/java/me/flashapp/cashu, relative or not: six levels up is the applet's directory
        Path main = SchnorrHWMathTest.mainSourceDir().toAbsolutePath().normalize();
        for (int i = 0; i < 6; i++) main = main.getParent();
        return main.resolve("build.xml");
    }
}
