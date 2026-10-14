package me.flashapp.cashu;

import static me.flashapp.cashu.CashuAppletTest.CLA;
import static me.flashapp.cashu.CashuAppletTest.INS_GET_INFO;
import static me.flashapp.cashu.CashuAppletTest.INS_GET_NONCE;
import static me.flashapp.cashu.CashuAppletTest.INS_LOAD_PROOF;
import static me.flashapp.cashu.CashuAppletTest.INS_LOCK_CARD;
import static me.flashapp.cashu.CashuAppletTest.INS_RESET_CARD;
import static me.flashapp.cashu.CashuAppletTest.INS_SET_TAG;
import static me.flashapp.cashu.CashuAppletTest.INS_SPEND_ALL_BEGIN;
import static me.flashapp.cashu.CashuAppletTest.INS_SPEND_ALL_SIGN;
import static me.flashapp.cashu.CashuAppletTest.KEYSET;
import static me.flashapp.cashu.CashuAppletTest.L_LOCK;
import static me.flashapp.cashu.CashuAppletTest.L_RESET;
import static me.flashapp.cashu.CashuAppletTest.L_TAG;
import static me.flashapp.cashu.CashuAppletTest.OTHER_OWNER;
import static me.flashapp.cashu.CashuAppletTest.OWNER;
import static me.flashapp.cashu.CashuAppletTest.OWNER_LABELS;
import static me.flashapp.cashu.CashuAppletTest.RESET_CONFIRM;
import static me.flashapp.cashu.CashuAppletTest.SW_NOT_ALLOWED;
import static me.flashapp.cashu.CashuAppletTest.SW_NO_OWNER;
import static me.flashapp.cashu.CashuAppletTest.SW_OK;
import static me.flashapp.cashu.CashuAppletTest.SW_OWNER_PROOF;
import static me.flashapp.cashu.CashuAppletTest.SW_WRONG_LENGTH;
import static me.flashapp.cashu.CashuAppletTest.TEST_PIN;
import static me.flashapp.cashu.CashuAppletTest.buildProof;
import static me.flashapp.cashu.CashuAppletTest.concat;
import static me.flashapp.cashu.CashuAppletTest.hexToBytes;
import static me.flashapp.cashu.CashuAppletTest.ownerData;
import static me.flashapp.cashu.CashuAppletTest.ownerProof;
import static me.flashapp.cashu.CashuAppletTest.readyOn;
import static me.flashapp.cashu.CashuAppletTest.setTagCommand;
import static me.flashapp.cashu.CashuAppletTest.toHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.Applet;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The card as an NFC tag (software 1.19), and the switch its owner holds.
 *
 * The three applets of the package are installed in the order the chip is given them: the opener, the card's applet and the tag,
 * the tag under the NFC Forum's own name (D2 76 00 00 85 01 01) as the install command gives it. What a phone does with a tag is
 * run byte for byte, and the two files it reads are held to the bytes the specification of the card lists.
 */
class TagTest {

    static final String OPENER_HEX = "F04341534855434152444D";
    static final String CARD_HEX = "F043415348554341524401";
    static final String TAG_HEX = "D2760000850101";
    /** What the install command carries for the tag: the instance AID's length and the AID, then no privileges and no parameters. */
    static final byte[] TAG_INSTALL = hexToBytes("07" + TAG_HEX + "0000");

    /** The capability container (file E103), as the card's specification lists it. */
    static final byte[] CC = hexToBytes("000f20003b00340406e104001600ff");
    /** The NDEF file (E104): NLEN, then one well-known URI record with prefix code 04 and "getfoxy.io/card". */
    static final byte[] NDEF = hexToBytes("0014d101105504" + "676574666f78792e696f2f63617264");
    static final String ADDRESS = "https://getfoxy.io/card";
    static { if (!toHex("getfoxy.io/card".getBytes(StandardCharsets.US_ASCII)).equals("676574666f78792e696f2f63617264")) throw new IllegalStateException("the address's hex"); }

    private CashuAppletTest.ExposedRuntime runtime;
    private CardSimulator sim;

    @BeforeEach
    void install() {
        sim = freshCardWithTheTag();
    }

    /** A card as the chip has it: the opener, the card's applet and the tag installed, the card's applet selected by its whole name. */
    private CardSimulator freshCardWithTheTag() {
        runtime = new CashuAppletTest.ExposedRuntime();
        CardSimulator s = new CardSimulator(runtime);
        s.installApplet(AIDUtil.create(OPENER_HEX), Opener.class);
        s.installApplet(AIDUtil.create(CARD_HEX), CashuApplet.class);
        s.installApplet(AIDUtil.create(TAG_HEX), Tag.class, TAG_INSTALL, (short) 0, (byte) TAG_INSTALL.length);
        ResponseAPDU r = s.transmitCommand(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(CARD_HEX), 256));
        assertEquals(SW_OK, r.getSW());
        return s;
    }

    // ---- what a phone sends ---------------------------------------------------------------------------------------------

    private ResponseAPDU send(CommandAPDU c) { return sim.transmitCommand(c); }
    private int sw(CommandAPDU c) { return send(c).getSW(); }
    /** SELECT by name, as a phone sends it to the tag application: case 4, the name and a zero Le. */
    private ResponseAPDU selectTag() { return send(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(TAG_HEX), 256)); }
    private ResponseAPDU selectCard() { return send(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(CARD_HEX), 256)); }
    private ResponseAPDU selectFile(int fid) { return send(new CommandAPDU(0x00, 0xA4, 0x00, 0x0C, new byte[] { (byte) (fid >> 8), (byte) fid })); }
    private ResponseAPDU read(int offset, int le) { return send(new CommandAPDU(0x00, 0xB0, offset >> 8, offset & 0xFF, le)); }
    private ResponseAPDU infoTap() { return send(new CommandAPDU(CLA, INS_GET_INFO, 1, 0, 256)); }
    /** GET_INFO with P1 = 2 (1.19): the 42 bytes of P1 = 1 and then one that says whether the tag is on. */
    private ResponseAPDU infoTag() { return send(new CommandAPDU(CLA, INS_GET_INFO, 2, 0, 256)); }
    private ResponseAPDU info() { return send(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256)); }

    private byte[] nonce() {
        ResponseAPDU r = send(new CommandAPDU(CLA, INS_GET_NONCE, 0, 0, 16));
        assertEquals(SW_OK, r.getSW());
        return r.getData();
    }

    /** The owner's phone switching the tag: a nonce, a proof by the owner's key over "CashuCard/tag" and the byte, the command. */
    private int switchTag(boolean off) {
        byte[] value = { (byte) (off ? 1 : 0) };
        return sw(setTagCommand(ownerProof(L_TAG, OWNER, nonce(), value), off ? 1 : 0));
    }

    /** A card set up as the phone sets one up: a PIN, a record, the owner and a clock; the PIN verified. */
    private void owned() {
        readyOn(sim, 0);
    }

    /** Whether a phone gets the tag: the tag application's name selected, and so a card that answers it. */
    private boolean tagIsSelectable() {
        int answered = selectTag().getSW();
        assertTrue(answered == SW_OK || answered == 0x6999, "the tag's name is answered 9000, or refused 6999 (selection failed): " + Integer.toHexString(answered));
        selectCard();
        return answered == SW_OK;
    }

    /** The tag application, read as a phone reads it: select the name, E103 and 15 bytes, E104, its 2 bytes of length, and the message. */
    private byte[][] aPhoneReadsTheTag() {
        assertEquals(SW_OK, selectTag().getSW());
        assertEquals(SW_OK, selectFile(0xE103).getSW());
        ResponseAPDU cc = read(0, 15);
        assertEquals(SW_OK, cc.getSW());
        assertEquals(SW_OK, selectFile(0xE104).getSW());
        ResponseAPDU nlen = read(0, 2);
        assertEquals(SW_OK, nlen.getSW());
        int length = ((nlen.getData()[0] & 0xFF) << 8) | (nlen.getData()[1] & 0xFF);
        ResponseAPDU message = read(2, length);
        assertEquals(SW_OK, message.getSW());
        return new byte[][] { cc.getData(), nlen.getData(), message.getData() };
    }

    // =========================================================================
    // The tag
    // =========================================================================

    @Test
    @DisplayName("The tag: the whole sequence a phone runs, byte for byte: select the name, select E103, read 15, select E104, read 2, read 20")
    void testThePhonesSequence() {
        ResponseAPDU name = selectTag();
        assertEquals(SW_OK, name.getSW(), "SELECT by name");
        assertEquals(0, name.getData().length, "and no data");
        assertEquals(SW_OK, send(new CommandAPDU(hexToBytes("00A4000C02E103"))).getSW(), "SELECT E103, the capability container");
        ResponseAPDU cc = send(new CommandAPDU(hexToBytes("00B000000F")));
        assertEquals(SW_OK, cc.getSW());
        assertEquals("000f20003b00340406e104001600ff", toHex(cc.getData()), "READ BINARY, 15 bytes of the capability container");
        assertEquals(SW_OK, send(new CommandAPDU(hexToBytes("00A4000C02E104"))).getSW(), "SELECT E104, the NDEF file");
        ResponseAPDU nlen = send(new CommandAPDU(hexToBytes("00B0000002")));
        assertEquals(SW_OK, nlen.getSW());
        assertEquals("0014", toHex(nlen.getData()), "READ BINARY, 2 bytes: the message is 20 bytes");
        ResponseAPDU message = send(new CommandAPDU(hexToBytes("00B0000214")));
        assertEquals(SW_OK, message.getSW());
        assertEquals("d101105504" + "676574666f78792e696f2f63617264", toHex(message.getData()), "READ BINARY from offset 2, 20 bytes: the message");
        assertEquals(ADDRESS, decodeUriRecord(message.getData()), "which is one URI record, and the address it carries is the card's address");
    }

    /** One short, well-known URI record, decoded as the NFC Forum's specifications read it: the address, or a failure. */
    static String decodeUriRecord(byte[] message) {
        assertTrue(message.length >= 5, "a record has its header, type length, payload length and type");
        int header = message[0] & 0xFF;
        assertEquals(0x80, header & 0x80, "MB: the first record");
        assertEquals(0x40, header & 0x40, "ME: and the last");
        assertEquals(0x00, header & 0x20, "CF: not chunked");
        assertEquals(0x10, header & 0x10, "SR: a short record, a payload length of one byte");
        assertEquals(0x00, header & 0x08, "IL: no identifier");
        assertEquals(0x01, header & 0x07, "TNF 1: a well-known type");
        int typeLength = message[1] & 0xFF, payloadLength = message[2] & 0xFF;
        assertEquals(1, typeLength);
        assertEquals('U', message[3], "the type is U: a URI");
        assertEquals(3 + typeLength + payloadLength, message.length, "and nothing follows the record");
        String[] prefixes = { "", "http://www.", "https://www.", "http://", "https://" };
        int code = message[4] & 0xFF;
        assertTrue(code < prefixes.length, "a prefix code the specification names");
        return prefixes[code] + new String(message, 5, payloadLength - 1, StandardCharsets.US_ASCII);
    }

    @Test
    @DisplayName("The tag's two files are exactly the bytes the specification lists: 15 and 22, the capability container and the NDEF file, and the NLEN of the second is the record's length")
    void testTheTwoFiles() {
        byte[][] read = aPhoneReadsTheTag();
        assertArrayEquals(CC, read[0], "the capability container");
        assertEquals(15, CC.length);
        assertEquals(CC[1] & 0xFF, CC.length, "whose length says so");
        assertEquals(0x20, CC[2] & 0xFF, "mapping version 2.0");
        assertEquals(59, ((CC[3] & 0xFF) << 8) | (CC[4] & 0xFF), "MLe");
        assertEquals(52, ((CC[5] & 0xFF) << 8) | (CC[6] & 0xFF), "MLc");
        assertArrayEquals(hexToBytes("0406e1040016"), Arrays.copyOfRange(CC, 7, 13), "the NDEF file control TLV: file E104, at most 22 bytes");
        assertEquals(0x00, CC[13], "read access: free");
        assertEquals((byte) 0xFF, CC[14], "write access: never");
        assertArrayEquals(Arrays.copyOf(NDEF, 2), read[1]);
        assertArrayEquals(Arrays.copyOfRange(NDEF, 2, NDEF.length), read[2]);
        assertEquals(22, NDEF.length, "and the NDEF file is the 22 bytes the capability container says it may be");
        assertEquals(NDEF.length - 2, ((NDEF[0] & 0xFF) << 8) | (NDEF[1] & 0xFF), "its NLEN is the message's length");
        assertEquals(ADDRESS, decodeUriRecord(read[2]));
        // each file whole, in one READ BINARY
        assertEquals(SW_OK, selectFile(0xE103).getSW());
        assertArrayEquals(CC, read(0, 256).getData(), "the capability container, whole, with an Le of 256");
        assertEquals(SW_OK, selectFile(0xE104).getSW());
        assertArrayEquals(NDEF, read(0, 256).getData(), "the NDEF file, whole");
    }

    @Test
    @DisplayName("READ BINARY: every offset and every length, the bytes of the file chosen from that offset, as many as asked and the file holds; an Le past the end is answered with what there is; an offset at or past the end is 6B00")
    void testReadsByOffsetAndLength() {
        assertEquals(SW_OK, selectTag().getSW());
        byte[][] files = { CC, NDEF };
        int[] fids = { 0xE103, 0xE104 };
        for (int f = 0; f < 2; f++) {
            assertEquals(SW_OK, selectFile(fids[f]).getSW());
            byte[] file = files[f];
            for (int offset = 0; offset < file.length; offset++) {
                for (int le = 1; le <= 30; le++) {
                    ResponseAPDU r = read(offset, le);
                    assertEquals(SW_OK, r.getSW(), "offset " + offset + ", Le " + le);
                    assertArrayEquals(Arrays.copyOfRange(file, offset, Math.min(file.length, offset + le)), r.getData(), "file " + f + ", offset " + offset + ", Le " + le);
                }
                assertArrayEquals(Arrays.copyOfRange(file, offset, file.length), read(offset, 256).getData(), "an Le of 0 asks for all it holds from offset " + offset);
            }
            for (int offset : new int[] { file.length, file.length + 1, 255, 256, 0x7FFF, 0x8000, 0xFFFF }) {
                assertEquals(0x6B00, read(offset, 1).getSW(), "an offset of " + offset + " is at or past the end of " + file.length);
            }
        }
        // a short read, and the one after it, are the file from where each says
        assertEquals(SW_OK, selectFile(0xE104).getSW());
        assertEquals("0014", toHex(read(0, 2).getData()));
        assertEquals("d1", toHex(read(2, 1).getData()));
        assertEquals("64", toHex(read(21, 1).getData()), "the last byte, the d of card");
        assertEquals(1, read(21, 59).getData().length, "an Le of the most the capability container allows, past the end: what there is");
    }

    @Test
    @DisplayName("SELECT file: E103 and E104 only; any other file 6A82; P1 not 00 or P2 not 0C 6B00; Lc not 2 6700")
    void testSelectFile() {
        assertEquals(SW_OK, selectTag().getSW());
        for (int fid : new int[] { 0xE105, 0xE102, 0xE100, 0x3F00, 0x0000, 0xE203, 0xE304, 0xFFFF, 0x03E1, 0x04E1 }) {
            assertEquals(0x6A82, selectFile(fid).getSW(), "file " + Integer.toHexString(fid));
        }
        for (int[] p : new int[][] { { 0x00, 0x00 }, { 0x00, 0x04 }, { 0x00, 0x0D }, { 0x02, 0x0C }, { 0x08, 0x0C }, { 0x01, 0x0C }, { 0x80, 0x0C }, { 0x00, 0x8C } }) {
            assertEquals(0x6B00, sw(new CommandAPDU(0x00, 0xA4, p[0], p[1], new byte[] { (byte) 0xE1, 0x03 })), "P1 " + p[0] + ", P2 " + p[1]);
        }
        assertEquals(0x6700, sw(new CommandAPDU(0x00, 0xA4, 0x00, 0x0C, new byte[] { (byte) 0xE1 })), "one byte of file identifier");
        assertEquals(0x6700, sw(new CommandAPDU(0x00, 0xA4, 0x00, 0x0C, new byte[] { (byte) 0xE1, 0x03, 0x00 })), "three");
        assertEquals(0x6700, sw(new CommandAPDU(0x00, 0xA4, 0x00, 0x0C, new byte[0])), "none");
        assertEquals(SW_OK, sw(new CommandAPDU(hexToBytes("00A4000C02E103"))), "and the right one is still taken");
    }

    @Test
    @DisplayName("READ BINARY with no file chosen is 6986, after SELECT by name and after it again; a file chosen is forgotten by the next selection")
    void testNoFileChosen() {
        assertEquals(SW_OK, selectTag().getSW());
        assertEquals(0x6986, read(0, 15).getSW(), "nothing chosen yet");
        assertEquals(SW_OK, selectFile(0xE103).getSW());
        assertEquals(SW_OK, read(0, 15).getSW());
        assertEquals(SW_OK, selectTag().getSW(), "the name again");
        assertEquals(0x6986, read(0, 15).getSW(), "a new selection chooses no file");
        assertEquals(SW_OK, selectFile(0xE104).getSW());
        selectCard();
        assertEquals(SW_OK, selectTag().getSW());
        assertEquals(0x6986, read(0, 2).getSW(), "nor does a selection after the card's applet was chosen");
    }

    @Test
    @DisplayName("Nothing writes: UPDATE BINARY (D6), and the other instructions that write, are 6982, with a file chosen or not, and both files are as they were")
    void testNothingWrites() {
        assertEquals(SW_OK, selectTag().getSW());
        int[] writers = { 0xD6, 0xD7, 0xD0, 0x0E, 0xDA, 0xDB, 0xDC, 0xDD, 0xE2 };
        for (int ins : writers) {
            assertEquals(0x6982, sw(new CommandAPDU(0x00, ins, 0x00, 0x00, new byte[] { 1, 2, 3 })), "INS " + Integer.toHexString(ins) + ", no file chosen");
        }
        for (int fid : new int[] { 0xE103, 0xE104 }) {
            assertEquals(SW_OK, selectFile(fid).getSW());
            for (int ins : writers) {
                assertEquals(0x6982, sw(new CommandAPDU(0x00, ins, 0x00, 0x00, new byte[] { (byte) 0xFF, (byte) 0xFF })), "INS " + Integer.toHexString(ins) + ", file " + Integer.toHexString(fid));
            }
            assertEquals(0x6982, sw(new CommandAPDU(0x00, 0xD6, 0x00, 0x02, new byte[20])), "UPDATE BINARY of the whole message");
            assertEquals(0x6982, sw(new CommandAPDU(0x00, 0xD6, 0x00, 0x00, new byte[0])), "UPDATE BINARY of nothing");
        }
        byte[][] after = aPhoneReadsTheTag();
        assertArrayEquals(CC, after[0], "the capability container is as it was");
        assertArrayEquals(NDEF, concat(after[1], after[2]), "and so is the NDEF file");
    }

    @Test
    @DisplayName("Any other instruction is 6D00, any class but 00 is 6E00, and the card's own instructions are not the tag's to answer")
    void testNothingElseIsAnswered() {
        assertEquals(SW_OK, selectTag().getSW());
        for (int ins : new int[] { 0x01, 0x10, 0x20, 0x44, 0x51, 0x52, 0x84, 0x88, 0xA0, 0xA2, 0xB1, 0xB2, 0xCA, 0xCB, 0xF0, 0xFF }) {
            assertEquals(0x6D00, sw(new CommandAPDU(0x00, ins, 0x00, 0x00)), "INS " + Integer.toHexString(ins));
        }
        assertEquals(SW_OK, selectFile(0xE104).getSW());
        for (int cla : new int[] { 0x01, 0x04, 0x08, 0x10, 0x40, 0x80, 0x84, 0xB0, 0xFF }) {
            assertEquals(0x6E00, sw(new CommandAPDU(cla, 0xB0, 0x00, 0x00, 2)), "CLA " + Integer.toHexString(cla));
        }
        assertEquals(0x6E00, sw(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256)), "the card's GET_INFO is not answered by the tag");
        assertEquals(0x6E00, sw(new CommandAPDU(CLA, INS_SET_TAG, 0, 0, new byte[8])), "nor SET_TAG");
        selectCard();
        assertEquals(0x6E00, sw(new CommandAPDU(0x00, 0xB0, 0x00, 0x00, 2)), "and the card's applet answers none of the tag's");
    }

    @Test
    @DisplayName("There is nothing per card in the tag: two cards, one set up with an owner and money and one new, answer the phone's whole sequence in the same bytes")
    void testTheSameOnEveryCard() {
        owned();
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 16, 1), 1)));
        byte[][] mine = aPhoneReadsTheTag();
        selectCard();
        byte[] myKey = send(new CommandAPDU(CLA, 0x10, 0, 0, 256)).getData();
        assertEquals(33, myKey.length);
        sim = freshCardWithTheTag();
        byte[][] theirs = aPhoneReadsTheTag();
        for (int i = 0; i < 3; i++) assertArrayEquals(mine[i], theirs[i], "part " + i);
        // (jCardSim draws the same card key every time; the point is that nothing the card holds is in what the tag says)
        String said = toHex(concat(mine[0], mine[1], mine[2]));
        assertFalse(said.contains(toHex(myKey).substring(2)), "the card's key is not in it");
        assertFalse(said.contains(toHex(OWNER.pub).substring(2, 40)), "nor the owner's");
    }

    @Test
    @DisplayName("The tag keeps no state but the file chosen: one byte of transient memory cleared on deselect, and nothing is static but constants")
    void testTheTagKeepsNothing() throws Exception {
        SimulatorRuntime fresh = new CashuAppletTest.ExposedRuntime();
        long[] before = transientHeldOnDeselect(fresh);
        CardSimulator s = new CardSimulator(fresh);
        s.installApplet(AIDUtil.create(TAG_HEX), Tag.class, TAG_INSTALL, (short) 0, (byte) TAG_INSTALL.length);
        long[] after = transientHeldOnDeselect(fresh);
        assertEquals(1, after[0] - before[0], "one byte of transient memory that is cleared on deselect");
        assertEquals(1, after[1] - before[1], "in one array");
        for (java.lang.reflect.Field f : Tag.class.getDeclaredFields()) {
            if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
            assertEquals(byte[].class, f.getType(), "an instance field of the tag is an array of bytes and holds no applet, no interface, no AID: " + f.getName());
        }
        assertEquals(1, Arrays.stream(Tag.class.getDeclaredFields()).filter(f -> !java.lang.reflect.Modifier.isStatic(f.getModifiers())).count(), "and there is the one");
    }

    /** { bytes, arrays } this runtime holds as transient arrays cleared on deselect. */
    private static long[] transientHeldOnDeselect(SimulatorRuntime rt) throws Exception {
        com.licel.jcardsim.base.TransientMemory memory = rt.getTransientMemory();
        java.lang.reflect.Field f = com.licel.jcardsim.base.TransientMemory.class.getDeclaredField("clearOnDeselect");
        f.setAccessible(true);
        long[] held = new long[2];
        for (Object o : (java.util.List<?>) f.get(memory)) {
            if (o instanceof byte[]) { held[0] += ((byte[]) o).length; held[1]++; }
        }
        return held;
    }

    // =========================================================================
    // The switch
    // =========================================================================

    @Test
    @DisplayName("The tag is on by default: a new card, and a card with an owner; GET_INFO with P1 = 2 is 43 bytes whose last is 00, and says it to a reader with no PIN and no grant")
    void testOnByDefault() {
        assertTrue(tagIsSelectable(), "a new card, with no owner");
        ResponseAPDU i = infoTag();
        assertEquals(SW_OK, i.getSW());
        assertEquals(43, i.getData().length);
        assertEquals(0, i.getData()[42], "the tag is on");
        owned();
        selectCard();
        assertTrue(tagIsSelectable(), "a card with an owner and a PIN");
        assertEquals(0, infoTag().getData()[42], "and no PIN was given or grant needed to be told");
        assertEquals(0, tagOffInTheCard(), "the persistent byte is 0");
    }

    private byte tagOffInTheCard() {
        try {
            Applet card = runtime.appletAt(AIDUtil.create(CARD_HEX));
            java.lang.reflect.Field f = CashuApplet.class.getDeclaredField("tagOff");
            f.setAccessible(true);
            return ((byte[]) f.get(card))[0];
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    @DisplayName("SET_TAG is 0x52 and its label is CashuCard/tag: P1 = 00 on, 01 off, P2 = 00, the owner's proof, and then the byte again, which the proof is over")
    void testTheCommand() {
        assertEquals(0x52, CashuApplet.INS_SET_TAG);
        assertEquals(0x52, INS_SET_TAG);
        assertEquals("4361736875436172642f746167", toHex("CashuCard/tag".getBytes(StandardCharsets.US_ASCII)), "the label's thirteen bytes");
        owned();
        // the proof is made here from the description and nothing in the applet: label || nonce || the byte
        byte[] n = nonce();
        byte[] proof = ownerProof(L_TAG, OWNER, n, new byte[] { 1 });
        CommandAPDU c = new CommandAPDU(CLA, 0x52, 0x01, 0x00, concat(new byte[] { (byte) proof.length }, proof, new byte[] { 0x01 }));
        assertEquals(SW_OK, sw(c));
        assertEquals(1, infoTag().getData()[42]);
        assertEquals(1, tagOffInTheCard());
        assertEquals(SW_OK, switchTag(false));
        assertEquals(0, infoTag().getData()[42]);
    }

    @Test
    @DisplayName("Only the owner's proof flips it: no nonce asked for, a proof for another label, another nonce, another key, another byte, or one already used is 6A91, costs no PIN try, and leaves the tag as it was")
    void testOnlyTheOwnersProofFlipsIt() {
        owned();
        assertEquals(SW_OWNER_PROOF, sw(setTagCommand(new byte[8], 1)), "no nonce asked for in this tap");
        nonce();
        assertEquals(SW_OWNER_PROOF, sw(setTagCommand(new byte[] { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 }, 1)), "a proof of nothing");
        for (String label : OWNER_LABELS) {
            if (label.equals(L_TAG)) continue;
            assertEquals(SW_OWNER_PROOF, sw(setTagCommand(ownerProof(label, OWNER, nonce(), new byte[] { 1 }), 1)), "a proof under " + label);
        }
        assertEquals(SW_OWNER_PROOF, sw(setTagCommand(ownerProof(L_TAG, OTHER_OWNER, nonce(), new byte[] { 1 }), 1)), "another owner's key");
        assertEquals(SW_OWNER_PROOF, sw(setTagCommand(ownerProof(L_TAG, OWNER, nonce(), new byte[] { 0 }), 1)), "a proof for the other byte");
        byte[] older = nonce();
        byte[] forOlder = ownerProof(L_TAG, OWNER, older, new byte[] { 1 });
        nonce();
        assertEquals(SW_OWNER_PROOF, sw(setTagCommand(forOlder, 1)), "a proof for an earlier nonce");
        byte[] m = nonce();
        byte[] right = ownerProof(L_TAG, OWNER, m, new byte[] { 1 });
        assertEquals(SW_OWNER_PROOF, sw(setTagCommand(ownerProof(L_TAG, OTHER_OWNER, m, new byte[] { 1 }), 1)), "a wrong proof uses the nonce up");
        assertEquals(SW_OWNER_PROOF, sw(setTagCommand(right, 1)), "and the right one for it is no good after that");
        // the same, for the state it already has: the proof is looked at before it is seen that nothing would change
        assertEquals(SW_OWNER_PROOF, sw(setTagCommand(ownerProof(L_TAG, OTHER_OWNER, nonce(), new byte[] { 0 }), 0)), "another key's proof for the state the tag has");
        assertEquals(3, info().getData()[9], "no PIN try was spent");
        assertEquals(1, info().getData()[7], "and the PIN is not blocked");
        assertEquals(0, tagOffInTheCard(), "the tag is on, as it was");
        assertTrue(tagIsSelectable());
        // and the right one, with no PIN verified in this tap, is taken
        selectCard();
        assertEquals(SW_OK, switchTag(true), "the owner's proof, and no PIN");
        assertEquals(1, tagOffInTheCard());
        byte[] used = ownerProof(L_TAG, OWNER, nonce(), new byte[] { 0 });
        assertEquals(SW_OK, sw(setTagCommand(used, 0)));
        assertNotEquals(SW_OK, sw(setTagCommand(used, 0)), "a proof that has worked once");
    }

    @Test
    @DisplayName("Wrong P1 or P2 is 6B00 before the owner is looked at and with the nonce left unspent; a byte that is not P1 is 6B00; no byte after the proof, or two, is 6700; none of them changes the tag")
    void testRefusedForItsBytes() {
        owned();
        byte[] n = nonce();
        byte[] two = ownerProof(L_TAG, OWNER, n, new byte[] { 2 });
        assertEquals(0x6B00, sw(new CommandAPDU(CLA, INS_SET_TAG, 2, 0, ownerData(two, new byte[] { 2 }))), "P1 = 2");
        assertEquals(0x6B00, sw(new CommandAPDU(CLA, INS_SET_TAG, 0x80, 0, ownerData(two, new byte[] { 2 }))), "P1 = 80");
        byte[] one = ownerProof(L_TAG, OWNER, n, new byte[] { 1 });
        assertEquals(0x6B00, sw(new CommandAPDU(CLA, INS_SET_TAG, 1, 1, ownerData(one, new byte[] { 1 }))), "P2 = 1");
        assertEquals(0x6B00, sw(new CommandAPDU(CLA, INS_SET_TAG, 1, 0xAD, ownerData(one, new byte[] { 1 }))), "P2 = AD, which is RESET_CARD's");
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SET_TAG, 1, 0, ownerData(one, new byte[] { 1 }))), "the same nonce was not spent by any of them");
        assertEquals(1, tagOffInTheCard());
        assertEquals(SW_OK, switchTag(false));
        // the byte after the proof is not P1
        byte[] zero = ownerProof(L_TAG, OWNER, nonce(), new byte[] { 0 });
        assertEquals(0x6B00, sw(new CommandAPDU(CLA, INS_SET_TAG, 1, 0, ownerData(zero, new byte[] { 0 }))), "a proof for 0 sent with P1 = 1");
        byte[] oneOne = ownerProof(L_TAG, OWNER, nonce(), new byte[] { 1 });
        assertEquals(0x6B00, sw(new CommandAPDU(CLA, INS_SET_TAG, 0, 0, ownerData(oneOne, new byte[] { 1 }))), "and for 1 sent with P1 = 0");
        // the length
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_SET_TAG, 1, 0, ownerData(ownerProof(L_TAG, OWNER, nonce(), new byte[0]), new byte[0]))), "nothing after the proof");
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_SET_TAG, 1, 0, ownerData(ownerProof(L_TAG, OWNER, nonce(), new byte[] { 1, 1 }), new byte[] { 1, 1 }))), "two bytes");
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_SET_TAG, 1, 0, ownerData(ownerProof(L_TAG, OWNER, nonce(), new byte[] { 1, 0, 0, 0 }), new byte[] { 1, 0, 0, 0 }))), "four");
        assertEquals(0, tagOffInTheCard(), "and the tag is on, as it was");
        assertEquals(3, info().getData()[9], "no PIN try was spent");
    }

    @Test
    @DisplayName("A card with no owner answers SET_TAG 6A90 and a locked card 6986, each with the tag as it was; money on the card is no bar")
    void testNoOwnerAndLockedCard() {
        assertEquals(SW_NO_OWNER, sw(setTagCommand(new byte[8], 1)), "a card with no owner");
        assertEquals(SW_NO_OWNER, sw(setTagCommand(new byte[8], 0)));
        assertEquals(0, tagOffInTheCard());
        assertTrue(tagIsSelectable(), "and its tag is on");
        sim = freshCardWithTheTag();
        owned();
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 16, 1), 1)), "money on the card");
        assertEquals(SW_OK, switchTag(true), "the owner's proof, with money on the card");
        assertEquals(SW_OK, switchTag(false), "and again");
        assertEquals(SW_OK, switchTag(true));
        // lock it (the PIN is verified in this tap, and the owner's proof is over the lock's label)
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_LOCK_CARD, 0, 0xDE, ownerData(ownerProof(L_LOCK, OWNER, nonce(), new byte[0]), new byte[0]))));
        assertEquals(1, info().getData()[10], "locked");
        assertEquals(SW_NOT_ALLOWED, sw(setTagCommand(ownerProof(L_TAG, OWNER, nonce(), new byte[] { 0 }), 0)), "a locked card");
        assertEquals(SW_NOT_ALLOWED, sw(setTagCommand(new byte[8], 1)));
        assertEquals(1, tagOffInTheCard(), "the tag is as it was");
        assertFalse(tagIsSelectable(), "off, for good");
    }

    @Test
    @DisplayName("Off makes the tag's name unselectable (6999, selection failed) and on makes it selectable again; the card's own name is selectable whatever the switch says")
    void testOffAndOn() {
        owned();
        assertTrue(tagIsSelectable());
        assertEquals(SW_OK, switchTag(true));
        assertEquals(0x6999, selectTag().getSW(), "the tag application refuses its name");
        ResponseAPDU card = selectCard();
        assertEquals(SW_OK, card.getSW(), "the card's own name is selected");
        assertArrayEquals(new byte[] { 0x02, 0x01 }, card.getData(), "and answers its version, 2.1");
        assertEquals(1, infoTag().getData()[42], "and says the tag is off");
        assertEquals(0x6999, selectTag().getSW(), "the tag asks at each selection, and it is still off");
        selectCard();
        assertEquals(SW_OK, switchTag(false));
        assertEquals(SW_OK, selectTag().getSW(), "on again, the name is taken");
        assertEquals(SW_OK, selectFile(0xE104).getSW());
        assertEquals(ADDRESS, decodeUriRecord(read(2, 20).getData()), "and it answers as it did");
        selectCard();
        assertEquals(SW_OK, selectCard().getSW(), "the card's own name, even when it is selected already");
        assertEquals(SW_OK, switchTag(true));
        assertEquals(SW_OK, selectCard().getSW(), "off: still selectable");
        assertEquals(0x6999, selectTag().getSW());
        assertEquals(0x6999, selectTag().getSW(), "and again, one after the other");
    }

    @Test
    @DisplayName("Asking for the state it already has answers 9000 and changes nothing: off twice, on when on")
    void testTheSameStateAgain() {
        owned();
        assertEquals(SW_OK, switchTag(false), "on, when on");
        assertEquals(0, tagOffInTheCard());
        assertEquals(SW_OK, switchTag(true));
        assertEquals(SW_OK, switchTag(true), "off, when off");
        assertEquals(1, tagOffInTheCard());
        assertEquals(SW_OK, switchTag(true));
        assertFalse(tagIsSelectable());
        assertEquals(SW_OK, switchTag(false));
        assertEquals(SW_OK, switchTag(false));
        assertTrue(tagIsSelectable());
    }

    @Test
    @DisplayName("The switch survives a power cycle and a new SELECT, off or on")
    void testSurvivesAPowerCycle() {
        owned();
        assertEquals(SW_OK, switchTag(true));
        sim.reset();
        assertEquals(0x6999, selectTag().getSW(), "after a power cycle, off");
        assertEquals(SW_OK, selectCard().getSW());
        assertEquals(1, infoTag().getData()[42]);
        assertEquals(1, tagOffInTheCard());
        assertEquals(SW_OK, switchTag(false));
        sim.reset();
        assertEquals(SW_OK, selectTag().getSW(), "after another, on");
        selectCard();
        assertEquals(0, infoTag().getData()[42]);
        // and the card's other state is not the tag's: a new SELECT of the card does not put it back
        assertEquals(SW_OK, switchTag(true));
        for (int i = 0; i < 3; i++) selectCard();
        assertEquals(1, infoTag().getData()[42], "three SELECTs of the card's applet later");
    }

    @Test
    @DisplayName("RESET_CARD puts the tag back on with the rest of its wipe: off, reset, on, and a new card with no owner")
    void testResetPutsItBackOn() {
        owned();
        assertEquals(SW_OK, switchTag(true));
        assertFalse(tagIsSelectable());
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_RESET_CARD, 0, RESET_CONFIRM, ownerData(ownerProof(L_RESET, OWNER, nonce(), new byte[0]), new byte[0]))), "RESET_CARD by the owner's proof");
        assertEquals(0, info().getData()[16], "a card with no owner");
        assertEquals(0, infoTag().getData()[42], "its tag is on");
        assertEquals(0, tagOffInTheCard());
        assertTrue(tagIsSelectable(), "and a phone gets it");
        // a reset that is refused leaves the tag as it was: money on the card
        sim = freshCardWithTheTag();
        owned();
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 16, 1), 1)));
        assertEquals(SW_OK, switchTag(true));
        assertEquals(0x6A8D, sw(new CommandAPDU(CLA, INS_RESET_CARD, 0, RESET_CONFIRM, ownerData(ownerProof(L_RESET, OWNER, nonce(), new byte[0]), new byte[0]))), "a piece unspent: refused");
        assertEquals(1, tagOffInTheCard(), "and the tag is as it was");
    }

    @Test
    @DisplayName("GET_INFO says it in the 43rd byte of the answer to P1 = 2, 00 on and 01 off; P1 = 0 is the 30 bytes and P1 = 1 the 42 bytes they always were, to the byte, whatever the tag's state; any other P1 is answered as it was, with the thirty bytes")
    void testGetInfo() {
        owned();
        byte[] thirtyOn = info().getData(), longOn = infoTap().getData(), tagOn = infoTag().getData();
        assertEquals(30, thirtyOn.length);
        assertEquals(42, longOn.length, "P1 = 1 is exactly 42 bytes");
        assertEquals(43, tagOn.length, "P1 = 2 is 43");
        assertEquals(0, tagOn[42], "the tag is on");
        assertArrayEquals(longOn, Arrays.copyOf(tagOn, 42), "and its first 42 are the 42 of P1 = 1");
        assertEquals(SW_OK, switchTag(true));
        byte[] thirtyOff = info().getData(), longOff = infoTap().getData(), tagOff = infoTag().getData();
        assertArrayEquals(thirtyOn, thirtyOff, "the 30 bytes are the same with the tag off");
        assertEquals(42, longOff.length);
        assertArrayEquals(longOn, longOff, "and so are the 42 of P1 = 1, to the byte");
        assertEquals(43, tagOff.length);
        assertArrayEquals(longOff, Arrays.copyOf(tagOff, 42), "P1 = 2 begins with them");
        assertEquals(1, tagOff[42], "and the tag is off");
        assertArrayEquals(thirtyOn, Arrays.copyOf(tagOff, 30), "the 30 are the first of the 43");
        for (int p1 : new int[] { 3, 4, 0x10, 0x7F, 0x80, 0xFF }) {
            ResponseAPDU other = send(new CommandAPDU(CLA, INS_GET_INFO, p1, 0, 256));
            assertEquals(SW_OK, other.getSW(), "P1 = " + p1);
            assertArrayEquals(thirtyOff, other.getData(), "any other P1 is answered as it was: the thirty bytes (P1 = " + p1 + ")");
        }
        assertEquals(SW_OK, switchTag(false));
        assertArrayEquals(longOn, infoTap().getData(), "on again, the 42 bytes are the same");
        assertEquals(0, infoTag().getData()[42]);
    }

    /** What a reader written for 1.18 does with the answers: the thirty bytes with P1 = 0; with P1 = 1 the long form only when the answer is exactly 42 bytes. */
    private static long[] readAsAWalletOf118Does(byte[] thirty, byte[] longForm) {
        assertEquals(30, thirty.length, "the short form is the thirty bytes");
        if (longForm.length != 42) return null;
        return new long[] { CashuAppletTest.readUint32(longForm, 30), CashuAppletTest.readUint32(longForm, 34), CashuAppletTest.readUint32(longForm, 38) };
    }

    @Test
    @DisplayName("A reader of software 1.18 sees nothing new: it takes the answer to P1 = 1 as the long form because it is exactly 42 bytes, with the tag on or off, and reads the limit on one payment (with the owner's grant) and the no-PIN allowance as it did")
    void testAReaderOfSoftware118SeesNothingNew() {
        owned();
        byte[] limits = concat(CashuAppletTest.u32(1000), CashuAppletTest.u32(100), CashuAppletTest.u32(50));
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, 0x34, 0, 0, ownerData(ownerProof("CashuCard/set-limit", OWNER, nonce(), limits), limits))), "the owner sets all three limits");
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, 0x45, 0, 0, ownerData(ownerProof("CashuCard/load", OWNER, nonce(), new byte[0]), new byte[0]))), "and gives the grant, so that the limit on one payment is said");
        long[] on = readAsAWalletOf118Does(info().getData(), infoTap().getData());
        assertNotNull(on, "with the tag on, the long form is taken");
        assertArrayEquals(new long[] { 100, 50, 0 }, on, "the limit on one payment, the allowance, and nothing counted against it");
        assertEquals(SW_OK, switchTag(true));
        long[] off = readAsAWalletOf118Does(info().getData(), infoTap().getData());
        assertNotNull(off, "with the tag off as well");
        assertArrayEquals(on, off, "and it reads the same");
        assertEquals(42, infoTap().getData().length, "exactly 42 bytes, which is what such a reader checks for");
        assertEquals(43, infoTag().getData().length, "(P1 = 2 is the form it does not ask for)");
    }

    @Test
    @DisplayName("A payment works with the tag off, and with money on the card the switch works")
    void testAPaymentWorksWithTheTagOff() {
        owned();
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 16, 1), 1)));
        assertEquals(SW_OK, switchTag(true));
        // the PIN again (switching the tag is not a payment, and SELECTs end the tap), then one signature for the one piece
        selectCard();
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, 0x40, 0, 0, TEST_PIN)));
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_BEGIN, 0, 0, new byte[] { 0 }, 4)), "a payment begun");
        ResponseAPDU signed = send(new CommandAPDU(CLA, INS_SPEND_ALL_SIGN, 0, 0, 64));
        assertEquals(SW_OK, signed.getSW(), "signed, with the tag off");
        assertEquals(64, signed.getData().length, "one signature");
        assertEquals(1, tagOffInTheCard(), "and the tag is as it was");
    }

    @Test
    @DisplayName("The tag asks at each selection: where the card's applet is not there the tag is on, and where it is, the switch is the answer")
    void testTheTagAsksTheCardsApplet() {
        owned();
        assertEquals(SW_OK, switchTag(true));
        assertFalse(tagIsSelectable());
        sim.deleteApplet(AIDUtil.create(CARD_HEX));
        assertEquals(SW_OK, selectTag().getSW(), "the card's applet gone: the tag is on");
        assertEquals(SW_OK, selectFile(0xE103).getSW());
        assertArrayEquals(CC, read(0, 15).getData());
    }

    @Test
    @DisplayName("The instances can be deleted one by one, the tag, the card's applet and the opener, in that order, and each of the others answers until its turn")
    void testDeletedOneByOne() {
        assertEquals(SW_OK, selectCard().getSW());
        assertEquals(SW_OK, selectTag().getSW());
        assertEquals(SW_OK, send(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(OPENER_HEX), 256)).getSW());
        selectCard();
        owned();
        assertEquals(SW_OK, switchTag(true));
        sim.deleteApplet(AIDUtil.create(TAG_HEX));
        assertNotEquals(SW_OK, selectTag().getSW(), "the tag is gone");
        assertEquals(SW_OK, selectCard().getSW(), "the card's applet answers");
        assertEquals(1, infoTag().getData()[42], "and still holds the switch");
        assertEquals(SW_OK, send(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(OPENER_HEX), 256)).getSW(), "so does the opener");
        sim.deleteApplet(AIDUtil.create(CARD_HEX));
        assertNotEquals(SW_OK, selectCard().getSW(), "the card's applet is gone");
        assertEquals(SW_OK, send(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(OPENER_HEX), 256)).getSW(), "the opener answers");
        sim.deleteApplet(AIDUtil.create(OPENER_HEX));
        assertNotEquals(SW_OK, send(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(OPENER_HEX), 256)).getSW(), "and it is gone");
    }

    @Test
    @DisplayName("No static field of the package refers to an object an applet instance made (the chip refuses to delete an instance so referred to): every static is a constant, a number or an array of bytes made when the package is loaded")
    void testNoStaticReferencesAnInstanceObject() {
        for (Class<?> c : new Class<?>[] { Tag.class, TagSwitch.class, Opener.class, CashuApplet.class, SchnorrHW.class }) {
            for (java.lang.reflect.Field f : c.getDeclaredFields()) {
                if (!java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
                assertTrue(java.lang.reflect.Modifier.isFinal(f.getModifiers()), c.getSimpleName() + "." + f.getName() + " is static and not final");
                assertTrue(f.getType().isPrimitive() || f.getType() == byte[].class, c.getSimpleName() + "." + f.getName() + " is " + f.getType().getSimpleName());
            }
        }
        // and the tag's source: the card's applet is looked up once, in select, into locals, and nothing of it is kept
        String code = tagSource();
        assertEquals(1, count(code, "JCSystem.lookupAID("), "the card's applet is looked up once");
        assertEquals(1, count(code, "JCSystem.getAppletShareableInterfaceObject("), "and its interface asked for once");
        String select = code.substring(code.indexOf("public boolean select()"), code.indexOf("public void process("));
        assertTrue(select.contains("AID card = JCSystem.lookupAID(") && select.contains("Shareable s = JCSystem.getAppletShareableInterfaceObject("), "both in select, into locals");
        assertFalse(code.contains("this.card") || code.contains("private AID") || code.contains("private Shareable") || code.contains("private TagSwitch"), "and it keeps neither");
    }

    @Test
    @DisplayName("The source of the switch: SET_TAG writes the byte only when it would change, in no transaction, after the proof; RESET_CARD writes it in its own; the interface answers any caller, for the one parameter 0")
    void testSwitchSource() throws Exception {
        String code = new String(java.nio.file.Files.readAllBytes(SchnorrHWMathTest.mainSourceDir().resolve("CashuApplet.java")), StandardCharsets.UTF_8);
        int from = code.indexOf("private void processSetTag("), to = code.indexOf("public boolean tagIsOn()");
        assertTrue(from > 0 && to > from);
        String body = code.substring(from, to);
        int[] order = { body.indexOf("OFFSET_P1]"), body.indexOf("requireNotLocked()"), body.indexOf("ownerSet[0] != (byte) 1"), body.indexOf("requireOwnerProof(LABEL_TAG"),
            body.indexOf("SW_WRONG_LENGTH"), body.indexOf("buf[at] != want"), body.indexOf("if (tagOff[0] != want) tagOff[0] = want;") };
        for (int i = 0; i < order.length; i++) {
            assertTrue(order[i] > 0, "step " + i + " is there");
            if (i > 0) assertTrue(order[i - 1] < order[i], "step " + i + " follows step " + (i - 1));
        }
        assertEquals(2, count(body, "tagOff["), "the byte is read once and written once in it");
        assertFalse(body.contains("beginTransaction"), "a single byte is written atomically, and no transaction is needed");
        assertFalse(body.contains("pinVerifiedFlag") || body.contains("pinState") || body.contains("pin."), "it asks no PIN");
        assertTrue(code.contains("case INS_SET_TAG:          processSetTag(apdu);         break;"), "it is dispatched");
        String shared = code.substring(code.indexOf("public Shareable getShareableInterfaceObject("), code.indexOf("// Guard helpers"));
        assertTrue(shared.contains("parameter == (byte) 0 ? this : null"), "any caller, the one parameter");
        assertFalse(shared.contains("clientAID."), "the caller is not looked at");
        java.util.regex.Matcher writes = java.util.regex.Pattern.compile("tagOff\\[0\\] =(?!=)").matcher(code);
        int assigned = 0;
        while (writes.find()) assigned++;
        assertEquals(2, assigned, "tagOff[0] is assigned in two places only: SET_TAG and RESET_CARD");
    }

    private static String tagSource() {
        try {
            return new String(java.nio.file.Files.readAllBytes(SchnorrHWMathTest.mainSourceDir().resolve("Tag.java")), StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static int count(String s, String what) {
        int n = 0;
        for (int at = s.indexOf(what); at >= 0; at = s.indexOf(what, at + 1)) n++;
        return n;
    }
}
