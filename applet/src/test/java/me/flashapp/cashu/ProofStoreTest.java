package me.flashapp.cashu;

import static me.flashapp.cashu.CashuAppletTest.AID_HEX;
import static me.flashapp.cashu.CashuAppletTest.AID_STR;
import static me.flashapp.cashu.CashuAppletTest.CLA;
import static me.flashapp.cashu.CashuAppletTest.INS_ALLOW_LOAD;
import static me.flashapp.cashu.CashuAppletTest.INS_CLEAR_SPENT;
import static me.flashapp.cashu.CashuAppletTest.INS_GET_BALANCE;
import static me.flashapp.cashu.CashuAppletTest.INS_GET_CHANGE;
import static me.flashapp.cashu.CashuAppletTest.INS_GET_INFO;
import static me.flashapp.cashu.CashuAppletTest.INS_GET_LOG;
import static me.flashapp.cashu.CashuAppletTest.INS_GET_NONCE;
import static me.flashapp.cashu.CashuAppletTest.INS_GET_PROOF;
import static me.flashapp.cashu.CashuAppletTest.INS_GET_PROOF_COUNT;
import static me.flashapp.cashu.CashuAppletTest.INS_GET_PUBKEY;
import static me.flashapp.cashu.CashuAppletTest.INS_GET_SLOT_STATUS;
import static me.flashapp.cashu.CashuAppletTest.INS_LOAD_PROOF;
import static me.flashapp.cashu.CashuAppletTest.INS_LOCK_CARD;
import static me.flashapp.cashu.CashuAppletTest.INS_RESET_CARD;
import static me.flashapp.cashu.CashuAppletTest.INS_SET_CARD;
import static me.flashapp.cashu.CashuAppletTest.INS_SET_OWNER;
import static me.flashapp.cashu.CashuAppletTest.INS_SET_PIN;
import static me.flashapp.cashu.CashuAppletTest.INS_SPEND_ALL_BEGIN;
import static me.flashapp.cashu.CashuAppletTest.INS_SPEND_ALL_CHANGE;
import static me.flashapp.cashu.CashuAppletTest.INS_SPEND_ALL_OUTPUTS;
import static me.flashapp.cashu.CashuAppletTest.INS_SPEND_ALL_SIGN;
import static me.flashapp.cashu.CashuAppletTest.INS_VERIFY_PIN;
import static me.flashapp.cashu.CashuAppletTest.KEYSET;
import static me.flashapp.cashu.CashuAppletTest.L_CARD;
import static me.flashapp.cashu.CashuAppletTest.L_LOAD;
import static me.flashapp.cashu.CashuAppletTest.L_LOCK;
import static me.flashapp.cashu.CashuAppletTest.L_RESET;
import static me.flashapp.cashu.CashuAppletTest.MAX_PROOFS;
import static me.flashapp.cashu.CashuAppletTest.MINT;
import static me.flashapp.cashu.CashuAppletTest.NO_REFUND;
import static me.flashapp.cashu.CashuAppletTest.OWNER;
import static me.flashapp.cashu.CashuAppletTest.REFUND;
import static me.flashapp.cashu.CashuAppletTest.RESET_CONFIRM;
import static me.flashapp.cashu.CashuAppletTest.SW_CARD_IN_USE;
import static me.flashapp.cashu.CashuAppletTest.SW_NOT_ALLOWED;
import static me.flashapp.cashu.CashuAppletTest.SW_NO_CARD_RECORD;
import static me.flashapp.cashu.CashuAppletTest.SW_NO_OWNER;
import static me.flashapp.cashu.CashuAppletTest.SW_NO_REFUND_KEY;
import static me.flashapp.cashu.CashuAppletTest.SW_NO_SPACE;
import static me.flashapp.cashu.CashuAppletTest.SW_OK;
import static me.flashapp.cashu.CashuAppletTest.SW_PIECE_ON_CARD;
import static me.flashapp.cashu.CashuAppletTest.SW_SECURITY_NOT_SATIS;
import static me.flashapp.cashu.CashuAppletTest.SW_SLOT_OUT_OF_RANGE;
import static me.flashapp.cashu.CashuAppletTest.SW_WRONG_DATA;
import static me.flashapp.cashu.CashuAppletTest.SW_WRONG_LENGTH;
import static me.flashapp.cashu.CashuAppletTest.TEST_PIN;
import static me.flashapp.cashu.CashuAppletTest.WAITS_MOST;
import static me.flashapp.cashu.CashuAppletTest.WRONG_PIN;
import static me.flashapp.cashu.CashuAppletTest.allMessage;
import static me.flashapp.cashu.CashuAppletTest.asSlot;
import static me.flashapp.cashu.CashuAppletTest.buildProof;
import static me.flashapp.cashu.CashuAppletTest.concat;
import static me.flashapp.cashu.CashuAppletTest.dleqHeld;
import static me.flashapp.cashu.CashuAppletTest.dleqProof;
import static me.flashapp.cashu.CashuAppletTest.extractPubkeyX;
import static me.flashapp.cashu.CashuAppletTest.getDleqCommand;
import static me.flashapp.cashu.CashuAppletTest.hexToBytes;
import static me.flashapp.cashu.CashuAppletTest.loadWithProofCommand;
import static me.flashapp.cashu.CashuAppletTest.output;
import static me.flashapp.cashu.CashuAppletTest.ownerData;
import static me.flashapp.cashu.CashuAppletTest.ownerProof;
import static me.flashapp.cashu.CashuAppletTest.readUint32;
import static me.flashapp.cashu.CashuAppletTest.readyOn;
import static me.flashapp.cashu.CashuAppletTest.record;
import static me.flashapp.cashu.CashuAppletTest.schnorrVerify;
import static me.flashapp.cashu.CashuAppletTest.sha256;
import static me.flashapp.cashu.CashuAppletTest.u32;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.TreeSet;

/**
 * The mint's proof kept with each piece (software 1.20).
 *
 * LOAD_PROOF with P1 = 1 takes one piece and, after its 81 bytes, the proof the mint made for it (NUT-12: e, s and the blinding
 * factor r, 96 bytes); GET_DLEQ gives it back for an unspent place. The card never checks the proof and never uses it, and a payment
 * is what it was. The 12,288 bytes that hold the proofs are not made at install, which the chip refuses with so much more in the
 * constructor, but by the first SET_CARD; every use of them is safe while they are not there.
 *
 * The rule these tests hold the applet to: a place that is UNSPENT holds in the store its own proof or 96 zero bytes, never another
 * piece's, whatever the place held before.
 */
class ProofStoreTest {

    private static final byte[] NONE = { 0 };

    /** Every persistent array a command could change, by the applet's name for it (the store, `dleq`, is null until the first SET_CARD). */
    private static final String[] PERSISTENT = { "proofStorage", "slotHex", "dleq", "cardLocked", "pinState", "cardRecord", "ownerSet", "changeDue",
        "cardLog", "cardReceipts", "lastSig", "burnList", "burnPending", "changeOpen", "openState" };

    /** A card in a simulator of its own, and what a test does to it. */
    private static final class Card {
        final CashuAppletTest.ExposedRuntime runtime = new CashuAppletTest.ExposedRuntime();
        final CardSimulator sim = new CardSimulator(runtime);
        final AID aid = AIDUtil.create(AID_HEX);

        /** A card as it comes out of the install: the applet made and selected, nothing set up. */
        Card() {
            sim.installApplet(aid, CashuApplet.class);
            select();
        }

        ResponseAPDU send(CommandAPDU c) { return sim.transmitCommand(c); }
        int sw(CommandAPDU c) { return send(c).getSW(); }
        void select() { assertEquals(SW_OK, sw(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(AID_STR)))); }
        /** Taken out of the field and put back: a new tap, with no PIN given and none of the owner's grants. */
        void power() { sim.reset(); select(); }
        void pin() { assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN))); }

        /** Set up as the phone sets a card up: a PIN, a record, the owner and a clock; the PIN verified. */
        Card ready() { readyOn(sim, 0); return this; }
        void setPin() { assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, TEST_PIN))); }
        int setCard(byte[] refund) { return sw(new CommandAPDU(CLA, INS_SET_CARD, 0, 0, record(MINT, refund))); }
        int setOwner() { return sw(new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, OWNER.pub)); }

        ResponseAPDU loadPlain(byte[]... pieces) { return send(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, concat(pieces), 256)); }
        ResponseAPDU loadProof(byte[] piece, byte[] proof) { return send(loadWithProofCommand(piece, proof)); }
        ResponseAPDU dleq(int first, int second) { return send(getDleqCommand(first, second)); }
        /** What GET_DLEQ answers for one place. */
        byte[] dleqOf(int place) {
            ResponseAPDU r = dleq(place, 255);
            assertEquals(SW_OK, r.getSW());
            return r.getData();
        }
        ResponseAPDU proofAt(int place) { return send(new CommandAPDU(CLA, INS_GET_PROOF, place, 0, 256)); }
        int count() { return send(new CommandAPDU(CLA, INS_GET_PROOF_COUNT, 0, 0, 1)).getData()[0] & 0xFF; }
        byte[] statuses() { return send(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData(); }
        long balance() { return readUint32(send(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4)).getData(), 0); }
        byte[] key() { return send(new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256)).getData(); }
        byte[] info(int p1) { return send(new CommandAPDU(CLA, INS_GET_INFO, p1, 0, 256)).getData(); }
        int clearSpent() { return sw(new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1)); }

        ResponseAPDU begin(int... places) {
            byte[] list = new byte[places.length];
            for (int i = 0; i < places.length; i++) list[i] = (byte) places[i];
            return send(new CommandAPDU(CLA, INS_SPEND_ALL_BEGIN, 0, 0, list, 4));
        }
        /** SPEND_ALL_SIGN, again for as long as the card says "not yet" (9000 and two bytes), so: the signature, or what refused. */
        ResponseAPDU sign() {
            for (int i = 0; i <= WAITS_MOST; i++) {
                ResponseAPDU r = send(new CommandAPDU(CLA, INS_SPEND_ALL_SIGN, 0, 0, 64));
                if (!(r.getSW() == SW_OK && r.getData().length == 2)) return r;
            }
            fail("a payment still waiting past the most");
            return null;
        }
        /** A payment of those places into those outputs: the signature, or what refused it. */
        ResponseAPDU pay(int[] places, byte[]... outputs) {
            ResponseAPDU begun = begin(places);
            if (begun.getSW() != SW_OK) return begun;
            if (outputs.length > 0) {
                ResponseAPDU o = send(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, concat(outputs)));
                if (o.getSW() != SW_OK) return o;
            }
            return sign();
        }
        /** A payment of those places, alone, as the first of a new tap with the PIN: the signature. */
        ResponseAPDU payInANewTap(int... places) {
            power();
            pin();
            return pay(places);
        }

        /** One of the applet's persistent arrays, live, or null where it is not there. */
        byte[] field(String name) throws Exception {
            java.lang.reflect.Field f = CashuApplet.class.getDeclaredField(name);
            f.setAccessible(true);
            return (byte[]) f.get(runtime.appletAt(aid));
        }
        /** The store of the mint's proofs, live: null until the first SET_CARD. */
        byte[] store() throws Exception { return field("dleq"); }
        /** The record of a place in the store, as the card holds it. */
        byte[] recordOf(int place) throws Exception { return Arrays.copyOfRange(store(), place * 96, place * 96 + 96); }
        /** A place's status as the card holds it: 0 empty, 1 unspent, 2 spent. */
        int statusOf(int place) throws Exception { return field("proofStorage")[place * 82]; }
        void setField(String name, byte[] value) throws Exception {
            java.lang.reflect.Field f = CashuApplet.class.getDeclaredField(name);
            f.setAccessible(true);
            f.set(runtime.appletAt(aid), value);
        }

        /** All of what lasts, copied (a store that is not there, as null). */
        Map<String, byte[]> snapshot() throws Exception {
            Map<String, byte[]> m = new LinkedHashMap<>();
            for (String name : PERSISTENT) {
                byte[] a = field(name);
                m.put(name, a == null ? null : a.clone());
            }
            return m;
        }
        void assertSameAs(Map<String, byte[]> before, String what) throws Exception {
            for (String name : PERSISTENT) assertArrayEquals(before.get(name), field(name), what + ": " + name);
        }
        /** The owner's proof for a command that carries it alone, after a nonce asked for in this tap. */
        byte[] proofFor(String label, byte[] value) {
            ResponseAPDU n = send(new CommandAPDU(CLA, INS_GET_NONCE, 0, 0, 16));
            assertEquals(SW_OK, n.getSW());
            return ownerProof(label, OWNER, n.getData(), value);
        }
        int allowLoad() { return sw(new CommandAPDU(CLA, INS_ALLOW_LOAD, 0, 0, ownerData(proofFor(L_LOAD, new byte[0]), new byte[0]))); }
        int lock() { return sw(new CommandAPDU(CLA, INS_LOCK_CARD, 0, 0xDE, ownerData(proofFor(L_LOCK, new byte[0]), new byte[0]))); }
        int reset() { return sw(new CommandAPDU(CLA, INS_RESET_CARD, 0, RESET_CONFIRM, ownerData(proofFor(L_RESET, new byte[0]), new byte[0]))); }
    }

    private static byte[] piece(long amount, int seed) { return buildProof(KEYSET, amount, seed); }
    /** A piece whose nonce is its own for any number of them: the first four bytes of the nonce say which. */
    private static byte[] uniquePiece(long amount, int n) {
        byte[] p = buildProof(KEYSET, amount, n & 0xFF);
        System.arraycopy(u32(n), 0, p, 12, 4);
        return p;
    }
    private static byte[] zeros(int n) { return new byte[n]; }
    private static boolean allZero(byte[] a) {
        for (byte b : a) if (b != 0) return false;
        return true;
    }
    /** A 33-byte blinded message for an output: any point's bytes will do, the card hashes them as text. */
    private static byte[] blinded(int seed) {
        byte[] b = new byte[33];
        b[0] = 0x02;
        for (int i = 1; i < 33; i++) b[i] = (byte) (seed + i);
        return b;
    }

    // =========================================================================
    // Loading with a proof, and reading it back
    // =========================================================================

    @Test
    @DisplayName("A piece loaded with its proof (P1 = 1) answers its place and 01, and GET_DLEQ gives back 01 and the same 96 bytes, e then s then r; the place is the piece as a plain load makes it, and the proof is kept in the record the place's number says")
    void aPieceLoadedWithItsProofIsGivenBackWithIt() throws Exception {
        Card c = new Card().ready();
        byte[] p0 = piece(1000, 1), proof0 = dleqProof(1);
        ResponseAPDU loaded = c.loadProof(p0, proof0);
        assertEquals(SW_OK, loaded.getSW());
        assertArrayEquals(new byte[] { 0, 1 }, loaded.getData(), "its place, and 01: the proof is kept");
        ResponseAPDU got = c.dleq(0, 255);
        assertEquals(SW_OK, got.getSW());
        assertEquals(97, got.getData().length, "01 and 96 bytes");
        assertArrayEquals(dleqHeld(proof0), got.getData());
        assertEquals(1, got.getData()[0]);
        assertArrayEquals(Arrays.copyOfRange(proof0, 0, 32), Arrays.copyOfRange(got.getData(), 1, 33), "e first");
        assertArrayEquals(Arrays.copyOfRange(proof0, 32, 64), Arrays.copyOfRange(got.getData(), 33, 65), "then s");
        assertArrayEquals(Arrays.copyOfRange(proof0, 64, 96), Arrays.copyOfRange(got.getData(), 65, 97), "then r");
        assertArrayEquals(proof0, c.recordOf(0), "and the store holds it where place 0's record is");
        // the piece itself is what a plain load makes of it
        ResponseAPDU slot = c.proofAt(0);
        assertEquals(SW_OK, slot.getSW());
        assertArrayEquals(asSlot(p0), slot.getData());
        assertEquals(1000, c.balance());
        // a second piece, another proof, the next place and the next record
        byte[] p1 = piece(500, 2), proof1 = dleqProof(2);
        assertArrayEquals(new byte[] { 1, 1 }, c.loadProof(p1, proof1).getData());
        assertArrayEquals(dleqHeld(proof1), c.dleqOf(1));
        assertArrayEquals(proof1, c.recordOf(1));
        assertArrayEquals(dleqHeld(proof0), c.dleqOf(0), "the first is where it was");
        assertEquals(1500, c.balance());
        // the proofs outlast the power
        c.power();
        c.pin();
        assertArrayEquals(dleqHeld(proof0), c.dleqOf(0));
        assertArrayEquals(dleqHeld(proof1), c.dleqOf(1));
    }

    @Test
    @DisplayName("A plain load reads 00, and three plain pieces in one command still answer three places")
    void aPlainLoadReadsNoneAndABatchStillAnswersItsPlaces() throws Exception {
        Card c = new Card().ready();
        assertArrayEquals(new byte[] { 0 }, c.loadPlain(piece(10, 1)).getData());
        assertArrayEquals(NONE, c.dleqOf(0), "a piece that came with no proof reads 00");
        assertTrue(allZero(c.recordOf(0)), "and its record is zeros");
        ResponseAPDU batch = c.loadPlain(piece(10, 2), piece(20, 3), piece(30, 4));
        assertEquals(SW_OK, batch.getSW());
        assertArrayEquals(new byte[] { 1, 2, 3 }, batch.getData(), "three pieces, three places, and no flag among them");
        ResponseAPDU two = c.dleq(1, 3);
        assertArrayEquals(new byte[] { 0, 0 }, two.getData());
        assertEquals(4, c.count());
        // the batch stops at a piece that cannot go on, as it always did: the places of the ones before it are the answer
        byte[] notAPoint = piece(5, 9);
        notAPoint[44] = 0x04;
        ResponseAPDU stopped = c.loadPlain(piece(1, 10), notAPoint, piece(1, 11));
        assertEquals(SW_OK, stopped.getSW());
        assertArrayEquals(new byte[] { 4 }, stopped.getData());
        // a P1 that is not 1 is the plain form whatever it is: 1.19 did not look at it
        for (int p1 : new int[] { 0, 2, 3, 0x7F, 0x80, 0xFE, 0xFF }) {
            ResponseAPDU r = c.send(new CommandAPDU(CLA, INS_LOAD_PROOF, p1, 0, piece(1, 20 + p1), 256));
            assertEquals(SW_OK, r.getSW(), "P1 = " + p1);
            assertEquals(1, r.getData().length, "P1 = " + p1 + ": one place, as it was");
            assertArrayEquals(NONE, c.dleqOf(r.getData()[0] & 0xFF), "P1 = " + p1 + ": no proof");
        }
        // and 177 bytes under any of them are not whole pieces
        assertEquals(SW_WRONG_LENGTH, c.sw(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, concat(piece(1, 40), dleqProof(4)), 256)), "P1 = 0 with a piece and a proof");
        assertEquals(SW_WRONG_LENGTH, c.sw(new CommandAPDU(CLA, INS_LOAD_PROOF, 2, 0, concat(piece(1, 40), dleqProof(4)), 256)), "P1 = 2 with a piece and a proof");
    }

    @Test
    @DisplayName("A place used again serves only its own proof: with a proof, spent, CLEAR_SPENT, a plain load into the same place reads 00; and a piece with a different proof reads the new one")
    void aPlaceUsedAgainServesOnlyItsOwnProof() throws Exception {
        Card c = new Card().ready();
        byte[] a = dleqProof(10), b = dleqProof(11);
        assertArrayEquals(new byte[] { 0, 1 }, c.loadProof(piece(100, 1), a).getData());
        assertArrayEquals(dleqHeld(a), c.dleqOf(0));
        assertEquals(SW_OK, c.pay(new int[] { 0 }).getSW());
        assertArrayEquals(NONE, c.dleqOf(0), "a spent place gives no proof");
        assertArrayEquals(a, c.recordOf(0), "though the store still holds it: a payment does not touch the store");
        assertEquals(SW_OK, c.clearSpent());
        assertArrayEquals(NONE, c.dleqOf(0), "nor does an empty one");
        assertArrayEquals(a, c.recordOf(0), "CLEAR_SPENT does not touch the store either: the freed place's record is what it was");
        // a plain piece into the same place: the old proof is not served
        assertArrayEquals(new byte[] { 0 }, c.loadPlain(piece(100, 2)).getData());
        assertEquals(1, c.statusOf(0));
        assertArrayEquals(NONE, c.dleqOf(0), "no stale proof is served for the piece that came with none");
        assertTrue(allZero(c.recordOf(0)), "the place's record was made zero before the piece went on");
        // and a piece with a different proof reads its own
        assertEquals(SW_OK, c.payInANewTap(0).getSW());
        assertEquals(SW_OK, c.clearSpent());
        assertArrayEquals(new byte[] { 0, 1 }, c.loadProof(piece(100, 3), b).getData());
        assertArrayEquals(dleqHeld(b), c.dleqOf(0), "the new proof, and not the old");
        assertArrayEquals(b, c.recordOf(0));
        // a different proof straight over the first, with no plain piece between
        assertEquals(SW_OK, c.payInANewTap(0).getSW());
        assertEquals(SW_OK, c.clearSpent());
        assertArrayEquals(new byte[] { 0, 1 }, c.loadProof(piece(100, 4), a).getData());
        assertArrayEquals(dleqHeld(a), c.dleqOf(0));
    }

    // =========================================================================
    // GET_DLEQ
    // =========================================================================

    @Test
    @DisplayName("GET_DLEQ: a spent place is 00, an empty one is 00, two places come in the order asked (both, mixed, the same twice), the most is 194 bytes, and a place there is not is 6A83")
    void getDleqAnswersForEveryKindOfPlace() throws Exception {
        Card c = new Card().ready();
        byte[] a = dleqProof(20), b = dleqProof(21);
        assertEquals(SW_OK, c.loadProof(piece(10, 1), a).getSW());        // 0: a proof
        assertEquals(SW_OK, c.loadProof(piece(20, 2), b).getSW());        // 1: another
        assertEquals(SW_OK, c.loadPlain(piece(30, 3)).getSW());           // 2: none
        assertEquals(SW_OK, c.loadProof(piece(40, 4), dleqProof(22)).getSW());   // 3: to be spent
        assertEquals(SW_OK, c.pay(new int[] { 3 }).getSW());
        // one place
        assertArrayEquals(dleqHeld(a), c.dleq(0, 255).getData());
        assertArrayEquals(NONE, c.dleq(2, 255).getData(), "a piece that came with none");
        assertArrayEquals(NONE, c.dleq(3, 255).getData(), "a spent place");
        assertArrayEquals(NONE, c.dleq(4, 255).getData(), "an empty place");
        assertArrayEquals(NONE, c.dleq(127, 255).getData(), "the last place, empty");
        // two places: both, in the order asked
        ResponseAPDU both = c.dleq(0, 1);
        assertEquals(SW_OK, both.getSW());
        assertEquals(194, both.getData().length, "the most an answer is");
        assertArrayEquals(concat(dleqHeld(a), dleqHeld(b)), both.getData());
        assertArrayEquals(concat(dleqHeld(b), dleqHeld(a)), c.dleq(1, 0).getData(), "the order asked");
        // mixed
        assertArrayEquals(concat(dleqHeld(a), NONE), c.dleq(0, 2).getData(), "a proof and a plain piece");
        assertArrayEquals(concat(NONE, dleqHeld(b)), c.dleq(4, 1).getData(), "an empty place and a proof");
        assertArrayEquals(concat(NONE, NONE), c.dleq(3, 4).getData(), "a spent place and an empty one");
        assertArrayEquals(concat(NONE, NONE), c.dleq(2, 2).getData(), "the same place twice, none");
        // the same place twice
        assertArrayEquals(concat(dleqHeld(b), dleqHeld(b)), c.dleq(1, 1).getData());
        assertEquals(194, c.dleq(1, 1).getData().length);
        // a place there is not: 128 and past, in either
        assertEquals(SW_SLOT_OUT_OF_RANGE, c.dleq(128, 255).getSW());
        assertEquals(SW_SLOT_OUT_OF_RANGE, c.dleq(0, 128).getSW());
        assertEquals(SW_SLOT_OUT_OF_RANGE, c.dleq(255, 255).getSW(), "255 as the first place is no place: only P2 may be FF");
        assertEquals(SW_SLOT_OUT_OF_RANGE, c.dleq(129, 0).getSW());
        assertEquals(SW_SLOT_OUT_OF_RANGE, c.dleq(0, 254).getSW());
        assertEquals(SW_SLOT_OUT_OF_RANGE, c.dleq(200, 200).getSW());
        assertEquals(0, c.dleq(128, 255).getData().length, "and nothing is answered with it");
        // 127 is a place, in either
        assertArrayEquals(concat(NONE, NONE), c.dleq(127, 127).getData());
        // the command takes no PIN, no owner and no grant
        c.power();
        assertArrayEquals(dleqHeld(a), c.dleqOf(0), "a new tap with no PIN given");
        // and changes nothing
        Map<String, byte[]> before = c.snapshot();
        for (int p = 0; p < 128; p += 2) c.dleq(p, p + 1);
        c.assertSameAs(before, "reading the proofs");
    }

    @Test
    @DisplayName("GET_DLEQ before any SET_CARD (the store not yet reserved) answers 00 for each place asked, and an exception for none; 6A83 still for a place there is not")
    void getDleqBeforeAnySetCardAnswersNone() throws Exception {
        Card c = new Card();
        assertNull(c.store(), "nothing is reserved at install");
        assertArrayEquals(NONE, c.dleq(0, 255).getData());
        assertEquals(SW_OK, c.dleq(0, 255).getSW());
        assertArrayEquals(concat(NONE, NONE), c.dleq(0, 127).getData());
        assertArrayEquals(concat(NONE, NONE), c.dleq(5, 5).getData());
        assertEquals(SW_SLOT_OUT_OF_RANGE, c.dleq(128, 255).getSW());
        assertEquals(SW_SLOT_OUT_OF_RANGE, c.dleq(0, 128).getSW());
        c.setPin();
        c.pin();
        assertNull(c.store(), "a PIN reserves nothing");
        assertArrayEquals(NONE, c.dleq(0, 255).getData());
        // a card that was refused the room (the store null after set-up) works as a card with no room for proofs
        Card r = new Card().ready();
        assertNotNull(r.store());
        r.setField("dleq", null);
        assertNull(r.store());
        ResponseAPDU loaded = r.loadProof(piece(10, 1), dleqProof(1));
        assertEquals(SW_OK, loaded.getSW(), "the piece goes on all the same");
        assertArrayEquals(new byte[] { 0, 0 }, loaded.getData(), "its place, and 00: there is no room for its proof");
        assertEquals(10, r.balance(), "and it is a piece");
        assertArrayEquals(NONE, r.dleqOf(0));
        assertEquals(SW_OK, r.loadPlain(piece(10, 2)).getSW());
        assertArrayEquals(concat(NONE, NONE), r.dleq(0, 1).getData());
        assertEquals(SW_OK, r.pay(new int[] { 0, 1 }).getSW(), "and it pays");
        assertEquals(SW_OK, r.clearSpent());
        assertNull(r.store(), "none of that reserved it");
        // the next SET_CARD (the owner's form, the card having an owner) tries again, and a card that can has it from then on
        r.power();
        r.pin();
        byte[] rec = record(MINT, REFUND);
        assertEquals(SW_OK, r.sw(new CommandAPDU(CLA, INS_SET_CARD, 0, 0, ownerData(r.proofFor(L_CARD, rec), rec))));
        assertNotNull(r.store(), "the room is reserved by the next SET_CARD");
        assertArrayEquals(new byte[] { 0, 1 }, r.loadProof(piece(10, 9), dleqProof(9)).getData(), "and proofs are kept from then on");
        assertArrayEquals(dleqHeld(dleqProof(9)), r.dleqOf(0));
    }

    // =========================================================================
    // What the load refuses, and that it writes nothing when it does
    // =========================================================================

    @Test
    @DisplayName("P1 = 1: a length of 0, 81, 162, 176, 178, 243 or 254 is 6700; a proof of 96 zero bytes is 6A80 (one non-zero byte is a proof); and after each refusal nothing was written, the count is the same and GET_DLEQ reads 00")
    void theProofFormRefusesTheWrongLengthAndAZeroProofAndWritesNothing() throws Exception {
        Card c = new Card().ready();
        assertEquals(SW_OK, c.loadProof(piece(7, 1), dleqProof(1)).getSW());
        byte[] fill = new byte[255];
        Arrays.fill(fill, (byte) 0x5A);
        Map<String, byte[]> before = c.snapshot();
        for (int len : new int[] { 0, 1, 80, 81, 82, 96, 162, 176, 178, 243, 254 }) {
            ResponseAPDU r = c.send(new CommandAPDU(CLA, INS_LOAD_PROOF, 1, 0, Arrays.copyOf(fill, len), 256));
            assertEquals(SW_WRONG_LENGTH, r.getSW(), len + " bytes");
            assertEquals(0, r.getData().length);
            c.assertSameAs(before, len + " bytes");
            assertEquals(1, c.count(), len + " bytes: the count is the same");
            assertArrayEquals(NONE, c.dleqOf(1), len + " bytes: nothing in the next place");
        }
        // a proof of nothing is not a piece's proof
        ResponseAPDU zero = c.loadProof(piece(7, 2), zeros(96));
        assertEquals(SW_WRONG_DATA, zero.getSW(), "96 zero bytes");
        assertEquals(0, zero.getData().length);
        c.assertSameAs(before, "a zero proof");
        assertEquals(1, c.count());
        assertArrayEquals(NONE, c.dleqOf(1));
        // the card does not check a proof: one byte that is not zero is one
        byte[] faint = zeros(96);
        faint[95] = 1;
        assertArrayEquals(new byte[] { 1, 1 }, c.loadProof(piece(7, 3), faint).getData());
        assertArrayEquals(dleqHeld(faint), c.dleqOf(1));
        byte[] first = zeros(96);
        first[0] = (byte) 0x80;
        assertArrayEquals(new byte[] { 2, 1 }, c.loadProof(piece(7, 4), first).getData());
        assertArrayEquals(dleqHeld(first), c.dleqOf(2));
        // the piece is looked at as it always was, with a good proof beside it: not a point, worth nothing, a date with no refund key
        before = c.snapshot();
        byte[] notAPoint = piece(7, 5);
        notAPoint[44] = 0x04;
        assertEquals(SW_WRONG_DATA, c.loadProof(notAPoint, dleqProof(5)).getSW(), "a C that is not a point");
        assertEquals(SW_WRONG_DATA, c.loadProof(piece(0, 6), dleqProof(6)).getSW(), "worth nothing");
        c.assertSameAs(before, "a bad piece");
        assertEquals(3, c.count());
    }

    @Test
    @DisplayName("P1 = 1 is refused as a plain load is, with the same words in the same order: no card record 6A8C, no owner 6A90, no PIN given 6982, a locked card 6986, a piece already on the card 6A94 (spent or not), a full card 6A84, a date with no refund key 6A8E; and nothing is written")
    void theProofFormIsRefusedAsAPlainLoadIs() throws Exception {
        byte[] p = piece(10, 1), proof = dleqProof(1);
        // no card record: a PIN and an owner, and no SET_CARD
        Card noRecord = new Card();
        noRecord.setPin();
        noRecord.pin();
        assertEquals(SW_OK, noRecord.setOwner());
        Map<String, byte[]> snap = noRecord.snapshot();
        assertEquals(SW_NO_CARD_RECORD, noRecord.loadPlain(p).getSW());
        assertEquals(SW_NO_CARD_RECORD, noRecord.loadProof(p, proof).getSW(), "no card record");
        noRecord.assertSameAs(snap, "no card record");
        assertNull(noRecord.store(), "and the refusal reserved nothing");
        // no owner: a PIN and a record
        Card noOwner = new Card();
        noOwner.setPin();
        noOwner.pin();
        assertEquals(SW_OK, noOwner.setCard(REFUND));
        snap = noOwner.snapshot();
        assertEquals(SW_NO_OWNER, noOwner.loadPlain(p).getSW());
        assertEquals(SW_NO_OWNER, noOwner.loadProof(p, proof).getSW(), "no owner");
        noOwner.assertSameAs(snap, "no owner");
        assertArrayEquals(NONE, noOwner.dleqOf(0));
        // a PIN set and not given, no grant: as a plain load refuses
        Card c = new Card().ready();
        c.power();
        snap = c.snapshot();
        assertEquals(SW_SECURITY_NOT_SATIS, c.loadPlain(p).getSW());
        assertEquals(SW_SECURITY_NOT_SATIS, c.loadProof(p, proof).getSW(), "no load authority");
        c.assertSameAs(snap, "no load authority");
        assertEquals(0, c.count());
        // a date, and a card with no refund key
        Card noRefund = new Card();
        noRefund.setPin();
        noRefund.pin();
        assertEquals(SW_OK, noRefund.setCard(NO_REFUND));
        assertEquals(SW_OK, noRefund.setOwner());
        snap = noRefund.snapshot();
        assertEquals(SW_NO_REFUND_KEY, noRefund.loadPlain(buildProof(KEYSET, 10, 1, 1900000000L)).getSW());
        assertEquals(SW_NO_REFUND_KEY, noRefund.loadProof(buildProof(KEYSET, 10, 1, 1900000000L), proof).getSW(), "a date with no refund key");
        noRefund.assertSameAs(snap, "a date with no refund key");
        assertEquals(SW_OK, noRefund.loadProof(p, proof).getSW(), "undated, the same card takes it");
        // a piece on the card already: unspent, then spent; another proof does not replace the first
        Card d = new Card().ready();
        byte[] first = dleqProof(30), other = dleqProof(31);
        assertEquals(SW_OK, d.loadProof(p, first).getSW());
        snap = d.snapshot();
        assertEquals(SW_PIECE_ON_CARD, d.loadProof(p, other).getSW(), "the same piece again, with another proof");
        assertEquals(SW_PIECE_ON_CARD, d.loadProof(buildProof(KEYSET, 1, 1), other).getSW(), "a copy that states another amount");
        assertEquals(SW_PIECE_ON_CARD, d.loadPlain(p).getSW(), "as a plain load of it is");
        d.assertSameAs(snap, "a piece on the card");
        assertArrayEquals(dleqHeld(first), d.dleqOf(0), "its own proof is the one it has");
        assertEquals(SW_OK, d.pay(new int[] { 0 }).getSW());
        snap = d.snapshot();
        assertEquals(SW_PIECE_ON_CARD, d.loadProof(p, other).getSW(), "spent, it is still on the card");
        d.assertSameAs(snap, "a spent piece");
        assertEquals(SW_OK, d.clearSpent());
        assertEquals(SW_OK, d.loadProof(p, other).getSW(), "freed, it may be loaded again, with whatever proof");
        assertArrayEquals(dleqHeld(other), d.dleqOf(0));
        // a full card says so whatever it is sent, as a plain load's word, before the length or the piece is looked at
        Card full = new Card().ready();
        for (int i = 0; i < 126; i += 3) assertEquals(SW_OK, full.loadPlain(piece(1, 100 + i), piece(1, 101 + i), piece(1, 102 + i)).getSW());
        assertEquals(SW_OK, full.loadPlain(piece(1, 300), piece(1, 301)).getSW());
        assertEquals(128, full.count());
        snap = full.snapshot();
        assertEquals(SW_NO_SPACE, full.loadPlain(p).getSW());
        assertEquals(SW_NO_SPACE, full.loadProof(p, proof).getSW(), "a full card");
        assertEquals(SW_NO_SPACE, full.send(new CommandAPDU(CLA, INS_LOAD_PROOF, 1, 0, new byte[10], 256)).getSW(), "whatever the length: full is said first");
        full.assertSameAs(snap, "a full card");
        assertEquals(128, full.count());
        // a locked card takes no writes, this one among them; and it still reads
        Card locked = new Card().ready();
        assertEquals(SW_OK, locked.loadProof(p, proof).getSW());
        assertEquals(SW_OK, locked.lock());
        snap = locked.snapshot();
        assertEquals(SW_NOT_ALLOWED, locked.loadPlain(piece(1, 2)).getSW());
        assertEquals(SW_NOT_ALLOWED, locked.loadProof(piece(1, 2), proof).getSW(), "locked");
        locked.assertSameAs(snap, "locked");
        assertArrayEquals(dleqHeld(proof), locked.dleqOf(0), "and a locked card gives back what it holds");
    }

    @Test
    @DisplayName("P1 = 1 is let through by the same authority as a plain load: the PIN verified, the owner's grant for the tap, a card with no PIN at all; not a blocked PIN; and GET_DLEQ asks for none of them")
    void theProofFormNeedsTheAuthorityAPlainLoadNeeds() throws Exception {
        byte[] proof = dleqProof(40);
        // the owner's grant, with no PIN
        Card c = new Card().ready();
        c.power();
        assertEquals(SW_SECURITY_NOT_SATIS, c.loadProof(piece(1, 1), proof).getSW(), "no PIN, no grant");
        assertEquals(SW_OK, c.allowLoad());
        assertArrayEquals(new byte[] { 0, 1 }, c.loadProof(piece(1, 1), proof).getData(), "the grant");
        assertArrayEquals(dleqHeld(proof), c.dleqOf(0));
        c.power();
        assertArrayEquals(dleqHeld(proof), c.dleqOf(0), "a reader with no PIN and no grant reads it");
        assertEquals(SW_SECURITY_NOT_SATIS, c.loadProof(piece(1, 2), proof).getSW(), "the grant went with the tap");
        // a blocked PIN waives nothing, and still lets the proof be read
        for (int i = 0; i < 3; i++) c.sw(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, WRONG_PIN));
        assertEquals(2, c.info(0)[7], "the PIN is blocked");
        assertEquals(SW_SECURITY_NOT_SATIS, c.loadProof(piece(1, 3), proof).getSW());
        assertArrayEquals(dleqHeld(proof), c.dleqOf(0));
        // a card set up with no PIN is loaded by whoever holds it
        Card noPin = new Card();
        assertEquals(SW_OK, noPin.setCard(REFUND));
        assertEquals(SW_OK, noPin.setOwner());
        assertEquals(0, noPin.info(0)[7], "no PIN");
        assertArrayEquals(new byte[] { 0, 1 }, noPin.loadProof(piece(1, 1), proof).getData(), "whoever holds it");
        assertArrayEquals(dleqHeld(proof), noPin.dleqOf(0));
    }

    // =========================================================================
    // Where the load and the payment leave the rest of the card
    // =========================================================================

    @Test
    @DisplayName("A P1 = 1 load under the change grant alone behaves as a plain load does: the note is spent, the opening is let go, the same log entry is written, and the tap's later change still goes on")
    void aProofLoadUnderTheChangeGrantAloneBehavesAsAPlainOneDoes() throws Exception {
        Card[] twins = { new Card().ready(), new Card().ready() };
        for (int variant = 0; variant < 2; variant++) {
            Card c = twins[variant];
            boolean withProof = variant == 1;
            assertEquals(SW_OK, c.loadPlain(piece(100, 1)).getSW());
            // a payment of the piece, 40 of it kept as the card's own change
            c.power();
            c.pin();
            assertEquals(SW_OK, c.begin(0).getSW());
            ResponseAPDU change = c.send(new CommandAPDU(CLA, INS_SPEND_ALL_CHANGE, 0, 0, u32(40), 33));
            assertEquals(SW_OK, change.getSW());
            assertEquals(SW_OK, c.sign().getSW());
            assertEquals(1, c.field("changeDue")[0], "a note that the card has paid");
            ResponseAPDU opened = c.send(new CommandAPDU(CLA, INS_GET_CHANGE, 0, 0, 256));
            assertEquals(1, opened.getData()[0], "one opening, pending");
            byte[] opening = Arrays.copyOfRange(opened.getData(), 1, 81);
            // the next tap, with no PIN: the change goes on under the change grant
            c.power();
            byte[] back = piece(40, 2);
            System.arraycopy(opening, 16, back, 12, 32);
            ResponseAPDU loaded = withProof ? c.loadProof(back, dleqProof(50)) : c.loadPlain(back);
            assertEquals(SW_OK, loaded.getSW(), "the change, with no PIN, under the change grant");
            assertArrayEquals(withProof ? new byte[] { 1, 1 } : new byte[] { 1 }, loaded.getData());
            assertEquals(0, c.field("changeDue")[0], "the note is spent");
            assertEquals(0, c.send(new CommandAPDU(CLA, INS_GET_CHANGE, 0, 0, 256)).getData()[0], "and the opening is let go");
            assertTrue(allZero(c.field("openState")), "every opening is empty");
            // the rest of the change of the same tap goes on, as the grant is the tap's
            ResponseAPDU more = withProof ? c.loadProof(piece(1, 3), dleqProof(51)) : c.loadPlain(piece(1, 3));
            assertEquals(SW_OK, more.getSW(), "the grant stands for the rest of the tap");
            // and the next tap has none
            c.power();
            assertEquals(SW_SECURITY_NOT_SATIS, (withProof ? c.loadProof(piece(1, 4), dleqProof(52)) : c.loadPlain(piece(1, 4))).getSW(), "nor a new tap");
            c.pin();
            assertArrayEquals(withProof ? dleqHeld(dleqProof(50)) : NONE, c.dleqOf(1));
        }
        // the twins differ in the store alone: the same places, the same texts, the same log, the same note, the same openings
        for (String name : new String[] { "proofStorage", "slotHex", "cardLog", "cardRecord", "changeDue", "changeOpen", "openState", "cardReceipts", "lastSig", "burnList", "burnPending", "pinState" }) {
            assertArrayEquals(twins[0].field(name), twins[1].field(name), name + " is the same whether the piece came with a proof or not");
        }
        assertFalse(Arrays.equals(twins[0].store(), twins[1].store()), "and the store is what differs");
        ResponseAPDU logA = twins[0].send(new CommandAPDU(CLA, INS_GET_LOG, 0, 0, 256)), logB = twins[1].send(new CommandAPDU(CLA, INS_GET_LOG, 0, 0, 256));
        assertEquals(SW_OK, logA.getSW());
        assertArrayEquals(logA.getData(), logB.getData(), "and the card's own account of the loads is the same");
    }

    @Test
    @DisplayName("A piece with a proof pays exactly as one without: the same signature bytes for the same pieces and outputs, over the same message, again for SPEND_ALL_AGAIN, and the payment writes nothing to the store")
    void aPieceWithAProofPaysAsOneWithoutDoes() throws Exception {
        Card plain = new Card().ready(), proofed = new Card().ready();
        byte[] x = piece(100, 1), y = piece(50, 2), z = piece(25, 3);
        assertEquals(SW_OK, plain.loadPlain(x, y, z).getSW());
        assertEquals(SW_OK, proofed.loadProof(x, dleqProof(60)).getSW());
        assertEquals(SW_OK, proofed.loadProof(y, dleqProof(61)).getSW());
        assertEquals(SW_OK, proofed.loadProof(z, dleqProof(62)).getSW());
        assertArrayEquals(plain.key(), proofed.key(), "the twins have one key (the simulator draws the same)");
        byte[] storeBefore = proofed.store().clone();
        byte[][] outputs = { output(90, blinded(1)), output(60, blinded(2)) };
        ResponseAPDU a = plain.pay(new int[] { 0, 1, 2 }, outputs);
        ResponseAPDU b = proofed.pay(new int[] { 0, 1, 2 }, outputs);
        assertEquals(SW_OK, a.getSW());
        assertEquals(SW_OK, b.getSW());
        assertEquals(64, b.getData().length);
        assertArrayEquals(a.getData(), b.getData(), "the same signature bytes for the same pieces and outputs");
        byte[] message = sha256(allMessage(proofed.key(), REFUND, new byte[][] { asSlot(x), asSlot(y), asSlot(z) }, outputs).getBytes(StandardCharsets.UTF_8));
        assertTrue(schnorrVerify(extractPubkeyX(proofed.key()), message, b.getData()), "over the text of the pieces and the outputs, which has no proof in it");
        assertArrayEquals(storeBefore, proofed.store(), "a payment writes nothing to the store");
        // the signature is given again, and the store is the same
        proofed.power();
        proofed.pin();
        ResponseAPDU again = proofed.send(new CommandAPDU(CLA, CashuAppletTest.INS_SPEND_ALL_AGAIN, 0, 0, 64));
        assertArrayEquals(b.getData(), again.getData());
        // everything else that lasts is the same on the two cards, the store apart
        for (String name : PERSISTENT) {
            if (name.equals("dleq")) continue;
            assertArrayEquals(plain.field(name), proofed.field(name), name);
        }
        // the paid places give no proof, though the store keeps what it had; CLEAR_SPENT frees them and leaves it
        for (int p = 0; p < 3; p++) assertArrayEquals(NONE, proofed.dleqOf(p));
        assertEquals(SW_OK, proofed.clearSpent());
        assertArrayEquals(storeBefore, proofed.store(), "CLEAR_SPENT writes nothing to the store");
    }

    @Test
    @DisplayName("RESET_CARD zeros the store: a plain load after the set-up reads 00, proofs work again, the store is the same array and is not made twice, and a card with no store resets without trouble")
    void aResetZerosTheStoreAndProofsWorkAgain() throws Exception {
        Card c = new Card().ready();
        for (int i = 0; i < 5; i++) assertEquals(SW_OK, c.loadProof(piece(10 + i, 1 + i), dleqProof(70 + i)).getSW());
        assertFalse(allZero(c.store()), "proofs are in the store");
        assertEquals(SW_OK, c.pay(new int[] { 0, 1, 2, 3, 4 }).getSW());
        assertFalse(allZero(c.store()), "and a payment leaves them");
        byte[] store = c.store();
        assertEquals(SW_OK, c.reset());
        assertSame(store, c.store(), "the same array: it is not made again");
        assertEquals(12288, c.store().length);
        assertTrue(allZero(c.store()), "RESET_CARD fills the store with zeros");
        // set up again, as another person does
        readyOn(c.sim, 0);
        assertSame(store, c.store(), "set up again, the room is not reserved a second time");
        assertArrayEquals(new byte[] { 0 }, c.loadPlain(piece(10, 1)).getData());
        assertArrayEquals(NONE, c.dleqOf(0), "a plain load reads 00");
        assertArrayEquals(new byte[] { 1, 1 }, c.loadProof(piece(11, 2), dleqProof(80)).getData());
        assertArrayEquals(dleqHeld(dleqProof(80)), c.dleqOf(1), "and proofs work again");
        assertEquals(SW_CARD_IN_USE, c.reset(), "(a piece on the card: not now)");
        assertArrayEquals(dleqHeld(dleqProof(80)), c.dleqOf(1), "and a refused reset leaves the store alone");
        // a card that never had the room resets as any
        Card none = new Card().ready();
        none.setField("dleq", null);
        assertEquals(SW_OK, none.reset());
        assertNull(none.store(), "and does not make it");
        // a second SET_CARD, owner's form, does not touch the store
        Card d = new Card().ready();
        assertEquals(SW_OK, d.loadProof(piece(10, 1), dleqProof(90)).getSW());
        assertEquals(SW_OK, d.pay(new int[] { 0 }).getSW());
        byte[] kept = d.store().clone();
        byte[] rec = record("https://other.example.com", REFUND);
        assertEquals(SW_OK, d.sw(new CommandAPDU(CLA, INS_SET_CARD, 0, 0, ownerData(d.proofFor(L_CARD, rec), rec))));
        assertArrayEquals(kept, d.store(), "SET_CARD leaves what the store holds");
    }

    @Test
    @DisplayName("The store is not made at install and is made by the first SET_CARD that goes through: null after install, after a PIN and after a SET_CARD that is refused; 12,288 zero bytes after one that is not, and the same array after every one that follows; and it is the only array the install leaves out")
    void theStoreIsNullAfterInstallAndNotNullAfterSetCard() throws Exception {
        Card c = new Card();
        assertNull(c.store(), "the chip refuses an applet whose constructor makes it: it is not made at install");
        // the only persistent array of the applet that is not there after install is the store
        TreeSet<String> missing = new TreeSet<>();
        for (java.lang.reflect.Field f : CashuApplet.class.getDeclaredFields()) {
            if (java.lang.reflect.Modifier.isStatic(f.getModifiers()) || f.getType() != byte[].class) continue;
            f.setAccessible(true);
            if (f.get(c.runtime.appletAt(c.aid)) == null) missing.add(f.getName());
        }
        assertEquals(new TreeSet<>(Arrays.asList("dleq")), missing, "every other array of the applet is made at install, the store alone after it");
        c.setPin();
        c.pin();
        assertNull(c.store(), "a PIN does not reserve it");
        assertEquals(SW_WRONG_LENGTH, c.sw(new CommandAPDU(CLA, INS_SET_CARD, 0, 0, new byte[10])), "a SET_CARD that is refused");
        assertNull(c.store(), "reserves nothing");
        assertEquals(SW_WRONG_DATA, c.sw(new CommandAPDU(CLA, INS_SET_CARD, 0, 0, record(MINT, concat(new byte[] { 4 }, new byte[32])))), "nor does one with a refund key that is no point");
        assertNull(c.store());
        assertEquals(SW_OK, c.setCard(REFUND));
        byte[] store = c.store();
        assertNotNull(store, "the first SET_CARD that goes through reserves it");
        assertEquals(12288, store.length, "128 records of 96 bytes");
        assertTrue(allZero(store), "all zeros: no place has a proof");
        assertEquals(SW_OK, c.setCard(NO_REFUND), "a second SET_CARD");
        assertSame(store, c.store(), "does not make another");
        assertEquals(SW_OK, c.setOwner());
        assertSame(store, c.store());
    }

    @Test
    @DisplayName("GET_INFO is as it was but for the version: 01 14, 30 bytes for P1 = 0 (and any P1 but 1 and 2), 42 for P1 = 1, 43 for P1 = 2, byte for byte the same whether pieces came with proofs or not")
    void getInfoIsAsItWasButForTheVersion() throws Exception {
        Card c = new Card();
        for (int p1 : new int[] { 0, 3, 4, 0x7F, 0xFF }) {
            byte[] d = c.info(p1);
            assertEquals(30, d.length, "P1 = " + p1);
            assertEquals(2, d[0]);
            assertEquals(0x01, d[1], "version 2.1");
            assertEquals((byte) 0xFF, d[6], "capabilities as they were");
            assertEquals(4, d[8], "format 4");
        }
        assertEquals(42, c.info(1).length);
        assertEquals(43, c.info(2).length);
        assertArrayEquals(c.info(1), Arrays.copyOf(c.info(2), 42));
        assertEquals(0, c.info(2)[42], "the tag is on");
        assertArrayEquals(new byte[] { 0x02, 0x01 }, c.send(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(AID_STR))).getData(), "SELECT says 2.1");
        // with pieces on, the same on a card whose pieces came with proofs and one whose did not
        Card plain = new Card().ready(), proofed = new Card().ready();
        for (int i = 0; i < 4; i++) {
            assertEquals(SW_OK, plain.loadPlain(piece(10 + i, 1 + i)).getSW());
            assertEquals(SW_OK, proofed.loadProof(piece(10 + i, 1 + i), dleqProof(i + 1)).getSW());
        }
        assertEquals(SW_OK, plain.pay(new int[] { 1 }).getSW());
        assertEquals(SW_OK, proofed.pay(new int[] { 1 }).getSW());
        for (int p1 : new int[] { 0, 1, 2 }) {
            assertArrayEquals(plain.info(p1), proofed.info(p1), "GET_INFO P1 = " + p1);
        }
        assertEquals(30, proofed.info(0).length);
        assertEquals(42, proofed.info(1).length);
        assertEquals(43, proofed.info(2).length);
        assertEquals(3, proofed.info(0)[3], "three unspent");
        assertEquals(1, proofed.info(0)[4], "one spent");
        // the log is the same too: a load of a piece with a proof is one load of its amount
        assertArrayEquals(plain.send(new CommandAPDU(CLA, INS_GET_LOG, 0, 0, 256)).getData(), proofed.send(new CommandAPDU(CLA, INS_GET_LOG, 0, 0, 256)).getData());
    }

    // =========================================================================
    // The rule, held to any history
    // =========================================================================

    @Test
    @DisplayName("Through a long history of loads with and without proofs, batches, payments, CLEAR_SPENT and power-ups, every UNSPENT place holds its own proof or zeros and never another piece's, in the store and as GET_DLEQ gives it, and a place that is not unspent gives 00")
    void theStoreFollowsThePiecesThroughAnyHistory() throws Exception {
        Card c = new Card().ready();
        Random rnd = new Random(0x1D1E0L);
        byte[][] expected = new byte[128][];      // the proof the piece now in a place came with, or null for none
        int seed = 1;
        int loadedWithProof = 0, loadedPlain = 0, paid = 0, cleared = 0;
        for (int step = 0; step < 500; step++) {
            byte[] st = c.statuses();
            int unspent = 0, empty = 0;
            for (int i = 0; i < 128; i++) { if (st[i] == 1) unspent++; if (st[i] == 0) empty++; }
            int op = rnd.nextInt(12);
            if (op < 4) {
                byte[] proof = new byte[96];
                rnd.nextBytes(proof);
                if (allZero(proof)) proof[95] = 1;
                ResponseAPDU r = c.loadProof(uniquePiece(1 + rnd.nextInt(500), seed++), proof);
                if (empty == 0) {
                    assertEquals(SW_NO_SPACE, r.getSW());
                } else {
                    assertEquals(SW_OK, r.getSW(), "step " + step);
                    assertEquals(2, r.getData().length);
                    assertEquals(1, r.getData()[1]);
                    expected[r.getData()[0] & 0xFF] = proof;
                    loadedWithProof++;
                }
            } else if (op < 6) {
                ResponseAPDU r = c.loadPlain(uniquePiece(1 + rnd.nextInt(500), seed++));
                if (empty == 0) {
                    assertEquals(SW_NO_SPACE, r.getSW());
                } else {
                    assertEquals(SW_OK, r.getSW());
                    expected[r.getData()[0] & 0xFF] = null;
                    loadedPlain++;
                }
            } else if (op < 7) {
                int n = 2 + rnd.nextInt(2);
                byte[][] pieces = new byte[n][];
                for (int i = 0; i < n; i++) pieces[i] = uniquePiece(1 + rnd.nextInt(500), seed++);
                ResponseAPDU r = c.loadPlain(pieces);
                if (empty == 0) {
                    assertEquals(SW_NO_SPACE, r.getSW());
                } else {
                    assertEquals(SW_OK, r.getSW());
                    assertTrue(r.getData().length >= 1 && r.getData().length <= n);
                    for (byte place : r.getData()) { expected[place & 0xFF] = null; loadedPlain++; }
                }
            } else if (op < 9) {
                if (unspent > 0) {
                    java.util.List<Integer> live = new java.util.ArrayList<>();
                    for (int i = 0; i < 128; i++) if (st[i] == 1) live.add(i);
                    java.util.Collections.shuffle(live, rnd);
                    int take = 1 + rnd.nextInt(Math.min(live.size(), 6));
                    int[] places = new int[take];
                    for (int i = 0; i < take; i++) places[i] = live.get(i);
                    assertEquals(SW_OK, c.payInANewTap(places).getSW(), "step " + step);
                    paid += take;
                }
            } else if (op < 10) {
                assertEquals(SW_OK, c.clearSpent());
                cleared++;
            } else if (op < 11) {
                c.power();
                c.pin();
            } else {
                // reading is no write
                Map<String, byte[]> before = c.snapshot();
                c.dleq(rnd.nextInt(128), rnd.nextBoolean() ? 255 : rnd.nextInt(128));
                c.assertSameAs(before, "a read");
            }
            // the rule, in the store itself
            byte[] after = c.statuses();
            for (int i = 0; i < 128; i++) {
                if (after[i] == 1) {
                    assertArrayEquals(expected[i] == null ? zeros(96) : expected[i], c.recordOf(i), "step " + step + ": place " + i + " is unspent and holds its own record");
                }
            }
            // and on the wire, for a pair of places every step and for every place now and then
            int first = rnd.nextInt(128), second = rnd.nextInt(128);
            byte[] pair = c.dleq(first, second).getData();
            assertArrayEquals(concat(answerFor(after, expected, first), answerFor(after, expected, second)), pair, "step " + step + ": places " + first + " and " + second);
            if (step % 25 == 0) {
                for (int i = 0; i < 128; i += 2) {
                    assertArrayEquals(concat(answerFor(after, expected, i), answerFor(after, expected, i + 1)), c.dleq(i, i + 1).getData(), "step " + step + ": places " + i + " and " + (i + 1));
                }
            }
        }
        assertTrue(loadedWithProof > 50 && loadedPlain > 30 && paid > 30 && cleared > 10, "the history was a long one: " + loadedWithProof + " with a proof, " + loadedPlain + " plain, " + paid + " paid, " + cleared + " cleared");
    }

    /** What GET_DLEQ should say for a place, given the statuses and the proof each piece came with. */
    private static byte[] answerFor(byte[] statuses, byte[][] expected, int place) {
        if (statuses[place] == 1 && expected[place] != null) return dleqHeld(expected[place]);
        return NONE;
    }

    // =========================================================================
    // What the source does
    // =========================================================================

    private static String appletCode() throws Exception {
        String src = new String(java.nio.file.Files.readAllBytes(SchnorrHWMathTest.mainSourceDir().resolve("CashuApplet.java")), StandardCharsets.UTF_8);
        return SchnorrHWMathTest.stripCommentsAndCharLiterals(src);
    }

    /** The names of the methods whose bodies name `word`. */
    private static TreeSet<String> methodsNaming(String src, String word) {
        int[] depth = SchnorrHWMathTest.braceDepths(src);
        TreeSet<String> names = new TreeSet<>();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\b" + word + "\\b").matcher(src);
        while (m.find()) {
            int at = m.start();
            if (depth[at] < 2) { names.add("(class body)"); continue; }
            int open = at;
            while (open > 0 && !(src.charAt(open) == '{' && depth[open] == 2)) open--;
            int from = Math.max(src.lastIndexOf(';', open), src.lastIndexOf('}', open)) + 1;
            java.util.regex.Matcher name = java.util.regex.Pattern.compile("(\\w+)\\s*\\(").matcher(src.substring(from, open));
            assertTrue(name.find(), "a method before " + src.substring(open, Math.min(src.length(), open + 40)));
            names.add(name.group(1));
        }
        return names;
    }

    @Test
    @DisplayName("Only LOAD_PROOF (and the one step of it), GET_DLEQ, SET_CARD's reservation and RESET_CARD name the store: no payment command, CLEAR_SPENT or burn does, and so no write is added to one")
    void noPaymentCommandNamesTheStore() throws Exception {
        String code = appletCode();
        TreeSet<String> names = methodsNaming(code, "dleq");
        assertEquals(new TreeSet<>(Arrays.asList("(class body)", "processGetDleq", "processLoadProof", "loadOne", "processSetCard", "processResetCard")), names,
            "the methods that name the store");
        // the writes: the one step of a load and the reset's fill (the reservation is an assignment, which the scan of the allocations holds to SET_CARD)
        TreeSet<String> writers = new TreeSet<>();
        int[] depth = SchnorrHWMathTest.braceDepths(code);
        for (String pattern : new String[] {
            "Util\\.arrayFill(?:NonAtomic)?\\s*\\(\\s*dleq\\b",                        // a fill: the first argument is written
            "Util\\.arrayCopy(?:NonAtomic)?\\s*\\(\\s*[^,]+,\\s*[^,]+,\\s*dleq\\b"     // a copy: the third is
        }) {
            java.util.regex.Matcher writes = java.util.regex.Pattern.compile(pattern).matcher(code);
            while (writes.find()) {
                int open = writes.start();
                while (open > 0 && !(code.charAt(open) == '{' && depth[open] == 2)) open--;
                int from = Math.max(code.lastIndexOf(';', open), code.lastIndexOf('}', open)) + 1;
                java.util.regex.Matcher name = java.util.regex.Pattern.compile("(\\w+)\\s*\\(").matcher(code.substring(from, open));
                assertTrue(name.find());
                writers.add(name.group(1));
            }
        }
        assertEquals(new TreeSet<>(Arrays.asList("loadOne", "processResetCard")), writers, "the store is written by a load, and zeroed by a reset");
        for (String untouched : new String[] { "processClearSpent", "freeSpent", "finishBurn", "processSpendAllBegin", "processSpendAllOutputs", "processSpendAllChange", "processSpendAllSign",
            "processSpendAllAgain", "requireNothingUnspent", "processGetPieces", "processGetChange", "processGetInfo", "processGetProof", "processAuth", "processSetLimit", "processAllowLoad" }) {
            assertFalse(names.contains(untouched), untouched + " does not name the store");
        }
    }

    @Test
    @DisplayName("GET_DLEQ is not a step of a payment: begun, then GET_DLEQ, then SIGN is 6985 and the payment is given up, as with any other command")
    void getDleqGivesUpAPaymentBegun() throws Exception {
        Card c = new Card().ready();
        assertEquals(SW_OK, c.loadProof(piece(10, 1), dleqProof(1)).getSW());
        assertEquals(SW_OK, c.begin(0).getSW());
        assertEquals(SW_OK, c.dleq(0, 255).getSW());
        assertEquals(0x6985, c.send(new CommandAPDU(CLA, INS_SPEND_ALL_SIGN, 0, 0, 64)).getSW(), "nothing is signed");
        assertEquals(10, c.balance(), "and nothing is burned");
        assertEquals(SW_OK, c.pay(new int[] { 0 }).getSW(), "begun again it is a payment");
    }
}
