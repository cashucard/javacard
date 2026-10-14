package me.flashapp.cashu;

import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * jCardSim tests for the Foxy fork of the applet (docs/FOXY-CARD-SPEC.md and
 * docs/FOXY-CARD-DAILY-LIMIT.md).
 *
 * Upstream's tests were of another wire format: a 78-byte slot, a SPEND_PROOF
 * that signed the reader's bytes, SIGN_ARBITRARY, and cards loaded with no PIN.
 * These are of this one. The helpers at the end (the BIP-340 verifier and its
 * arithmetic) are upstream's, and the Schnorr tests beside this file still use
 * them.
 *
 * The owner is a P-256 key made here with the JDK's own provider, and the proofs
 * it signs are checked by the card's verifier, so the card's ECDSA is held to an
 * implementation that is not its own.
 *
 * The card's clock (1.15) is Bitcoin block headers, and the headers the tests
 * give it are made here: mined to a floor of the tests' own (`blockAt`, at bits
 * 0x207FFFFF, where half of all hashes will do), with the double SHA-256 and the
 * target worked out by the JDK and BigInteger, and not by the card's code. The
 * floor built into the applet (FLOOR_BITS) is set to that cheap one for every
 * test (`useTheTestFloor`), and put back for the few that bring the network's
 * own headers (TIP, OLD and GENESIS, below), which no one could mine here.
 */
class CashuAppletTest {

    static final String AID_HEX = "F043415348554341524401";  // the applet's, for AIDUtil
    static final String AID_STR = "F0434153485543415244";      // the package's: SELECT matches by prefix
    static final String UPSTREAM_AID = "D2760000850102";
    static final byte   CLA     = (byte) 0xB0;

    static final byte INS_GET_INFO         = (byte) 0x01;
    static final byte INS_GET_PUBKEY       = (byte) 0x10;
    static final byte INS_GET_BALANCE      = (byte) 0x11;
    static final byte INS_GET_PROOF_COUNT  = (byte) 0x12;
    static final byte INS_GET_PROOF        = (byte) 0x13;
    static final byte INS_GET_SLOT_STATUS  = (byte) 0x14;
    static final byte INS_AUTH             = (byte) 0x15;
    static final byte INS_GET_CARD         = (byte) 0x16;
    static final byte INS_GET_PIECES       = (byte) 0x17;
    static final byte INS_SPEND_PROOF      = (byte) 0x20;   // gone in format 4: answers 6D00
    static final byte INS_SPEND_ALL_BEGIN   = (byte) 0x22;
    static final byte INS_SPEND_ALL_OUTPUTS = (byte) 0x23;
    static final byte INS_SPEND_ALL_SIGN    = (byte) 0x24;
    static final byte INS_SPEND_ALL_AGAIN   = (byte) 0x25;
    static final byte INS_SIGN_ARBITRARY   = (byte) 0x21;   // upstream's; gone
    static final byte INS_LOAD_PROOF       = (byte) 0x30;
    static final byte INS_CLEAR_SPENT      = (byte) 0x31;
    static final byte INS_SET_CARD         = (byte) 0x32;
    static final byte INS_GET_LOG          = (byte) 0x18;
    static final byte INS_GET_CHANGE        = (byte) 0x19;
    /** GET_DLEQ (1.20): the mint's proof kept with an unspent piece, for the place P1 and, unless P2 is FF, the place P2. */
    static final byte INS_GET_DLEQ          = (byte) 0x1A;
    static final byte INS_SPEND_ALL_CHANGE  = (byte) 0x26;
    static final byte INS_SET_LIMIT        = (byte) 0x33;   // by PIN: an open card only
    static final byte INS_SET_LIMIT_OWNER  = (byte) 0x34;
    /** SET_TIME, a time under a key's signature: gone in 1.15. It answers 6D00 and stays unassigned. */
    static final byte INS_WAS_SET_TIME     = (byte) 0x35;
    /** A Bitcoin block header: its proof of work moves the card's clock forward (1.15). */
    static final byte INS_SET_HEADER       = (byte) 0x36;
    /** The terminal's own clock, a note for receipts and the log and trusted for nothing (1.15). */
    static final byte INS_TELL_TIME        = (byte) 0x37;
    static final byte INS_VERIFY_PIN       = (byte) 0x40;
    static final byte INS_SET_PIN          = (byte) 0x41;
    static final byte INS_CHANGE_PIN       = (byte) 0x42;
    static final byte INS_SET_OWNER        = (byte) 0x43;
    static final byte INS_GET_NONCE        = (byte) 0x44;
    static final byte INS_ALLOW_LOAD       = (byte) 0x45;
    static final byte INS_LOCK_CARD        = (byte) 0x50;
    static final byte INS_RESET_CARD       = (byte) 0x51;
    static final int RESET_CONFIRM         = 0xAD;
    /** SET_TAG (1.19): the owner's proof switches the card's NFC tag off (P1 = 1) or on (P1 = 0). */
    static final byte INS_SET_TAG          = (byte) 0x52;
    static final byte INS_REFRESH          = (byte) 0x53;

    static final int SW_OK                  = 0x9000;
    static final int SW_WRONG_LENGTH        = 0x6700;
    static final int SW_SECURITY_NOT_SATIS  = 0x6982;
    static final int SW_PIN_BLOCKED         = 0x6983;
    static final int SW_PIN_NOT_SET         = 0x6984;
    static final int SW_CONDITIONS_NOT_SATIS = 0x6985;
    static final int SW_NOT_ALLOWED         = 0x6986;
    static final int SW_WRONG_DATA          = 0x6A80;
    static final int SW_SLOT_OUT_OF_RANGE   = 0x6A83;
    static final int SW_NO_SPACE            = 0x6A84;
    static final int SW_SLOT_EMPTY          = 0x6A88;
    static final int SW_NO_CARD_RECORD      = 0x6A8C;
    static final int SW_CARD_IN_USE         = 0x6A8D;
    static final int SW_NO_REFUND_KEY       = 0x6A8E;
    static final int SW_OVER_LIMIT          = 0x6A8F;
    static final int SW_NO_OWNER            = 0x6A90;
    static final int SW_OWNER_PROOF         = 0x6A91;
    // 6A92 was "never told the time". Since 1.15 a card spends its first day on trust, and nothing answers it: every test is
    // checked for it at the end (noPaymentLimitRefusal), and the applet's source for the word.
    static final int SW_WAS_NO_TIME         = 0x6A92;
    // 6A95 was "over the limit on one tap". The limit on one payment is waited for and never refused, so nothing answers it
    // any more: every test is checked for it at the end (noPaymentLimitRefusal), and the applet's source for the word.
    static final int SW_NO_LONGER_ANSWERED  = 0x6A95;
    static final int SW_TOO_MANY            = 0x6A96;
    /** The wait (6a) in answers of SPEND_ALL_SIGN: the applet's two sizes, for the first limit's worth over the limit and for every further one. */
    static final int WAIT_OVER_SIGNS = 10, WAIT_MORE_SIGNS = 4;
    /** The most limits' worth a payment is counted for: the applet's WAIT_UNITS_MOST. */
    static final int WAIT_UNITS_MOST = 255;
    /**
     * The rule of 1.14: what a payment of which `net` sats leave the card waits under a limit of `limit`, having made `made`
     * change outputs. Within the limit, or within a thirty-second over it (a price pegged in another money), change or no
     * change: nothing; over it, WAIT_OVER_SIGNS and WAIT_MORE_SIGNS for every further limit's worth, whole or in part, 255
     * limits' worth at most; less the time the change outputs took, two waits for every three of them (1.13 took one off for
     * each, which was more than an output costs, and a terminal could buy the wait down with outputs of a sat), never below 0.
     */
    static int waitsRule(long limit, long net, int made) { return waitsRule(limit, net, made, false); }
    /** What `made` change outputs count for against the wait: an output is about two thirds of a signature's work. */
    static int changeCredit(int made) { return (2 * made) / 3; }
    /** The same, for a payment that is the `second` (or later) signed in its tap without the owner's grant: at least one over the limit, limit or no limit. */
    static int waitsRule(long limit, long net, int made, boolean second) {
        if (limit <= 0) return second ? Math.max(0, WAIT_OVER_SIGNS - changeCredit(made)) : 0;
        long units = net <= limit + limit / 32 ? 1 : Math.min(WAIT_UNITS_MOST, (net + limit - 1) / limit);
        if (second && units <= 1) units = 2;
        if (units <= 1) return 0;
        return Math.max(0, WAIT_OVER_SIGNS + WAIT_MORE_SIGNS * (int)(units - 2) - changeCredit(made));
    }
    /** So the most a payment waits: 1022 answers before the signature (ten for the first limit's worth over, and four for each of the 253 after it). */
    static final int WAITS_MOST = WAIT_OVER_SIGNS + WAIT_MORE_SIGNS * (WAIT_UNITS_MOST - 2);
    // ten seconds of the card's own clock: how long a run of refusals is in the log (the applet's TAP_SECONDS).
    // It is no longer how long anything is signed for: the limit on one payment counts nothing by a clock.
    static final long TAP = 10L;
    /** SET_HEADER whose work is not enough: not its own difficulty's, under the floor, or under a quarter of the best seen. */
    static final int SW_LITTLE_WORK         = 0x6A93;
    static final int SW_PIECE_ON_CARD       = 0x6A94;
    /** SPEND_ALL_SIGN with a PIN set and not given, and the no-PIN allowance not enough (1.16): the PIN, for the whole payment. The word LOAD_PROOF answers for a piece on the card; a different command. */
    static final int SW_PIN_NEEDED          = 0x6A94;
    static final int SW_INS_NOT_SUPPORTED   = 0x6D00;
    static final int SW_CLA_NOT_SUPPORTED   = 0x6E00;

    static final int MAX_PROOFS = 128;
    static final int SLOT = 82;
    static final int MINT_MAX = 77;   // 80 before the design (1.10): the proof, the record, the mint and it in one short APDU

    static final byte[] TEST_PIN  = { 0x31, 0x32, 0x33, 0x34 };
    static final byte[] WRONG_PIN = { 0x39, 0x39, 0x39, 0x39 };
    static final byte[] NEW_PIN   = { 0x35, 0x36, 0x37, 0x38 };

    /** The time of the block the tests start a card's clock at, in seconds: a day in 2027. */
    static final long T0 = 1_800_000_000L;
    static final long DAY = 86_400L;

    /**
     * A P-256 key pair, for an owner: the JDK makes it and signs with it
     * (ECDSA, SHA-256, DER), and the card verifies.
     */
    static final class Key {
        final java.security.KeyPair pair;
        /** 04 || X || Y */
        final byte[] pub = new byte[65];

        Key() {
            try {
                java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("EC");
                g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
                pair = g.generateKeyPair();
            } catch (java.security.GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
            java.security.spec.ECPoint w = ((java.security.interfaces.ECPublicKey) pair.getPublic()).getW();
            pub[0] = 0x04;
            put32(w.getAffineX(), 1);
            put32(w.getAffineY(), 33);
        }

        private void put32(java.math.BigInteger n, int at) {
            byte[] b = n.toByteArray();
            int len = Math.min(b.length, 32);
            System.arraycopy(b, b.length - len, pub, at + 32 - len, len);
        }

        byte[] sign(byte[] message) {
            try {
                java.security.Signature s = java.security.Signature.getInstance("SHA256withECDSA");
                s.initSign(pair.getPrivate());
                s.update(message);
                return s.sign();
            } catch (java.security.GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /** The owner's key, and another phone's. */
    static final Key OWNER = new Key();
    static final Key OTHER_OWNER = new Key();
    /**
     * A time signer's key, as a phone of software before 1.15 still sends it in the 65 bytes of a record that held one. It is no
     * key the card knows (the card ignores those bytes since 1.15); a test uses it to show that.
     */
    static final Key FORMER_TIME_KEY = new Key();

    static final String KEYSET = "0059534ce0bfa19a";
    // two pieces the write-order tests load (SlotWriteOrderTest)
    static final byte[] PROOF_1 = buildProof("0059534ce0bfa19a", 1000, 1);
    static final byte[] PROOF_2 = buildProof("008288762774ace1", 500, 2);
    static final String MINT = "https://mint.example.com/Bitcoin";
    /** A refund key: the curve's generator, compressed. Any point will do. */
    static final byte[] REFUND = hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    static final byte[] NO_REFUND = new byte[33];

    static final String L_PIN = "CashuCard/change-pin", L_LIMIT = "CashuCard/set-limit", L_LOCK = "CashuCard/lock",
        L_LOAD = "CashuCard/load", L_OWNER = "CashuCard/set-owner", L_CARD = "CashuCard/set-card", L_RESET = "CashuCard/reset", L_TAG = "CashuCard/tag",
        L_REFRESH = "CashuCard/refresh";
    static final String[] OWNER_LABELS = { L_PIN, L_LIMIT, L_LOCK, L_LOAD, L_OWNER, L_CARD, L_RESET, L_TAG };

    /** A runtime that hands the test its applet, so what a command cannot reach can be set or read directly. */
    static final class ExposedRuntime extends SimulatorRuntime {
        Applet appletAt(AID aid) {
            return getApplet(aid);
        }
        /**
         * A transaction already in progress when the applet begins its own. jCardSim's transactions have no buffer to fill and
         * no rollback, but beginTransaction while one is in progress throws the TransactionException a card whose commit buffer is
         * full throws, and that is the path the applet's burn has to answer 6A96.
         */
        void leaveATransactionOpen() {
            transactionDepth = 1;
        }

        /**
         * How many transactions are to commit before the card is taken out of the field, the instant after the last of them has:
         * 0 is never. The commit is made, and what the applet does next is not done: an exception it does not know unwinds it, as
         * a power loss would end it, and nothing is answered.
         */
        int commitsUntilTear;
        /** Every transaction the applet has committed, ever, in this runtime. */
        int commits;

        @Override
        public void commitTransaction() {
            super.commitTransaction();
            commits++;
            if (commitsUntilTear > 0 && --commitsUntilTear == 0) throw new IllegalStateException("the card left the field after this commit");
        }
    }

    private ExposedRuntime runtime;
    private CardSimulator simulator;

    @BeforeEach
    void setup() {
        useTheTestFloor();
        simulator = freshCard();
    }

    /** The floor built into the applet is put back as it was built for whatever runs after this class. */
    @AfterAll
    static void putTheBuiltFloorBack() {
        useFloor(BUILT_FLOOR);
    }

    // ---- what the tests do to a card -------------------------------------

    private int sw(CommandAPDU c) { return transmit(c).getSW(); }
    private int setPin(byte[] pin) { return sw(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, pin)); }
    private int verify(byte[] pin) { return sw(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, pin)); }
    private ResponseAPDU nonce() { return transmit(new CommandAPDU(CLA, INS_GET_NONCE, 0, 0, 16)); }
    private byte[] nonceBytes() {
        ResponseAPDU r = nonce();
        assertEquals(SW_OK, r.getSW());
        assertEquals(16, r.getData().length);
        return r.getData();
    }

    static byte[] concat(byte[]... parts) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (byte[] p : parts) out.write(p, 0, p.length);
        return out.toByteArray();
    }
    static byte[] u32(long v) { byte[] b = new byte[4]; putUint32(b, 0, v); return b; }

    /** The owner's proof for one command: an ECDSA signature by `key` over label || nonce || value. */
    static byte[] ownerProof(String label, Key key, byte[] nonce, byte[] value) {
        return key.sign(concat(label.getBytes(StandardCharsets.US_ASCII), nonce, value));
    }
    /** An owner's command's data: the proof's length, the proof, then the value it was made over. */
    static byte[] ownerData(byte[] proof, byte[] value) {
        return concat(new byte[] { (byte) proof.length }, proof, value);
    }

    /** SET_CARD's data: unit, refund key, the 65 bytes that held a time key until 1.15 (zeros now: the card ignores them), mint length, mint. */
    static byte[] record(String mint, byte[] refund) {
        return recordWithKeyBytes(mint, refund, new byte[65]);
    }
    /** The same, with the card's design after the mint (1.10): three characters, or three zeros for none. */
    static byte[] record(String mint, byte[] refund, String design) {
        return concat(record(mint, refund), design.getBytes(StandardCharsets.US_ASCII));
    }
    /** The same, with whatever a phone of earlier software would put where the time key went: the card does not read those bytes. */
    static byte[] recordWithKeyBytes(String mint, byte[] refund, byte[] formerTimeKey) {
        byte[] m = mint.getBytes(StandardCharsets.US_ASCII);
        return concat(new byte[] { 0 }, refund, formerTimeKey, new byte[] { (byte) m.length }, m);
    }

    private static CommandAPDU changePinCommand(byte[] proof, byte[] newPin) {
        return new CommandAPDU(CLA, INS_CHANGE_PIN, 0, 0, ownerData(proof, newPin));
    }
    private static CommandAPDU setLimitCommand(byte[] proof, long sats) {
        return new CommandAPDU(CLA, INS_SET_LIMIT_OWNER, 0, 0, ownerData(proof, u32(sats)));
    }
    /** Both limits in one command: the day's, then the tap's. */
    private static CommandAPDU setLimitsCommand(byte[] proof, long day, long tap) {
        return new CommandAPDU(CLA, INS_SET_LIMIT_OWNER, 0, 0, ownerData(proof, concat(u32(day), u32(tap))));
    }
    private static CommandAPDU setLimitByPinCommand(long sats) {
        return new CommandAPDU(CLA, INS_SET_LIMIT, 0, 0, u32(sats));
    }
    private static CommandAPDU lockCommand(byte[] proof) {
        return new CommandAPDU(CLA, INS_LOCK_CARD, 0, 0xDE, ownerData(proof, new byte[0]));
    }
    private static CommandAPDU allowLoadCommand(byte[] proof) {
        return new CommandAPDU(CLA, INS_ALLOW_LOAD, 0, 0, ownerData(proof, new byte[0]));
    }
    private static CommandAPDU setOwnerOpenCommand(Key newOwner) {
        return new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, newOwner.pub);
    }
    private static CommandAPDU setOwnerCommand(byte[] proof, Key newOwner) {
        return new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, ownerData(proof, newOwner.pub));
    }
    /** REFRESH (0x53, D20): the owner's proof over a block header, then the header; answers the card's clock. */
    private static CommandAPDU refreshCommand(byte[] proof, byte[] header) {
        return new CommandAPDU(CLA, INS_REFRESH, 0, 0, ownerData(proof, header), 4);
    }
    private static CommandAPDU setCardOpenCommand(byte[] record) {
        return new CommandAPDU(CLA, INS_SET_CARD, 0, 0, record);
    }
    private static CommandAPDU setCardCommand(byte[] proof, byte[] record) {
        return new CommandAPDU(CLA, INS_SET_CARD, 0, 0, ownerData(proof, record));
    }

    // ---- the clock: Bitcoin block headers (1.15) ----------------------------------------------------------------------

    /** SET_HEADER: the 80 bytes of a block header as the network carries them. It answers the card's clock, four bytes. */
    static CommandAPDU setHeaderCommand(byte[] header) {
        return new CommandAPDU(CLA, INS_SET_HEADER, 0, 0, header, 4);
    }
    /** SET_HEADER with the block whose time is `t`, mined at the tests' floor: the card's clock goes to `t` if that is forward. */
    static CommandAPDU setTimeCommand(long t) {
        return setHeaderCommand(blockAt(t));
    }
    /** TELL_TIME: the terminal's own clock, four bytes big-endian. It answers nothing. */
    static CommandAPDU tellTimeCommand(long t) {
        return new CommandAPDU(CLA, INS_TELL_TIME, 0, 0, u32(t));
    }

    /** A number as four bytes, little-endian: the way a header carries them. */
    static byte[] le32(long v) {
        return new byte[] { (byte) v, (byte) (v >> 8), (byte) (v >> 16), (byte) (v >> 24) };
    }
    static byte[] reversed(byte[] b) {
        byte[] r = new byte[b.length];
        for (int i = 0; i < b.length; i++) r[i] = b[b.length - 1 - i];
        return r;
    }
    /**
     * The 80 bytes of a block header as the network carries them: the version (4), the previous block's hash (32), the merkle root (32),
     * the time (4), the difficulty as `bits` (4) and the nonce (4). Every number is little-endian; the two hashes are put as they are given.
     */
    static byte[] header(long version, byte[] prevHash, byte[] merkle, long time, long bits, long nonce) {
        assertEquals(32, prevHash.length, "a previous hash is 32 bytes");
        assertEquals(32, merkle.length, "a merkle root is 32 bytes");
        return concat(le32(version), prevHash, merkle, le32(time), le32(bits), le32(nonce));
    }
    /** What a block's hash is as a number: the header hashed twice with SHA-256 and the 32 bytes read little-endian, as Bitcoin reads them. */
    static java.math.BigInteger hashOf(byte[] header) {
        return new java.math.BigInteger(1, reversed(sha256(sha256(header))));
    }
    /** The hash as Bitcoin shows a block hash: the same 32 bytes turned round, in hex. */
    static String blockHash(byte[] header) {
        return toHex(reversed(sha256(sha256(header))));
    }
    /** The target the compact form `bits` names: the mantissa (23 bits) placed `exponent` less three bytes up. (Whether bits are fit to carry is the card's to say.) */
    static java.math.BigInteger targetOf(long bits) {
        int exponent = (int) ((bits >>> 24) & 0xFF);
        java.math.BigInteger mantissa = java.math.BigInteger.valueOf(bits & 0x007FFFFFL);
        return exponent <= 3 ? mantissa.shiftRight(8 * (3 - exponent)) : mantissa.shiftLeft(8 * (exponent - 3));
    }
    /** The previous hash and the merkle root of a header made here: both worked out from the time and a salt, so that headers of the same time may be told apart. */
    private static byte[] filler(String what, long time, int salt) {
        return sha256((what + " " + time + "/" + salt).getBytes(StandardCharsets.US_ASCII));
    }
    /** A header of that time and difficulty whose hash is at or under the target of its own bits, found by trying nonces from 0. */
    static byte[] mine(long time, long bits, int salt) {
        java.math.BigInteger target = targetOf(bits);
        byte[] prev = filler("previous block", time, salt), merkle = filler("transactions", time, salt);
        for (long nonce = 0; nonce < (1L << 32); nonce++) {
            byte[] h = header(0x20000000L, prev, merkle, time, bits, nonce);
            if (hashOf(h).compareTo(target) <= 0) return h;
        }
        throw new IllegalStateException("no nonce under the target of " + Long.toHexString(bits));
    }
    /** A header of that time and difficulty whose hash is over the target of its own bits: one made without the work. */
    static byte[] unmined(long time, long bits) {
        java.math.BigInteger target = targetOf(bits);
        byte[] prev = filler("previous block", time, -1), merkle = filler("transactions", time, -1);
        for (long nonce = 0; nonce < (1L << 32); nonce++) {
            byte[] h = header(0x20000000L, prev, merkle, time, bits, nonce);
            if (hashOf(h).compareTo(target) > 0) return h;
        }
        throw new IllegalStateException("every nonce is under the target of " + Long.toHexString(bits));
    }
    /** The difficulty the tests' own blocks are mined at: a target of about 2^255, where half of all hashes will do. */
    static final long TEST_BITS = 0x207FFFFFL;
    /** A block of that time, mined at the tests' floor. The same time is always the same block. */
    static byte[] blockAt(long t) {
        return mine(t, TEST_BITS, 0);
    }

    /** The applet's floor (FLOOR_BITS) as a header carries bits: 0x17087BC0, four times the target of the network's blocks when 1.15 was made (a quarter of their work, about 2^77 hashes a block), which no one could mine to here. */
    static final byte[] REAL_FLOOR = { (byte) 0xC0, (byte) 0x7B, (byte) 0x08, (byte) 0x17 };
    /** The tests' own: 0x207FFFFF. */
    static final byte[] TEST_FLOOR = le32(TEST_BITS);
    /** What the applet was built with: read once, before any test has changed it (this class's initialiser runs before any helper of it does). */
    static final byte[] BUILT_FLOOR = floorNow();
    private static byte[] floorNow() {
        try {
            java.lang.reflect.Field f = CashuApplet.class.getDeclaredField("FLOOR_BITS");
            f.setAccessible(true);
            return ((byte[]) f.get(null)).clone();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }
    /** The floor the applet holds headers to, its four bytes written (a private static final array has no other way to change). */
    static void useFloor(byte[] bits) {
        try {
            java.lang.reflect.Field f = CashuApplet.class.getDeclaredField("FLOOR_BITS");
            f.setAccessible(true);
            System.arraycopy(bits, 0, (byte[]) f.get(null), 0, 4);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }
    static void useTheTestFloor() { useFloor(TEST_FLOOR); }
    static void useTheRealFloor() { useFloor(REAL_FLOOR); }

    // Real blocks of the network, mined by it: none could be made here at the floor built into the applet.
    /** Height 970,736: the tip when these vectors were taken. */
    static final String TIP = "00c02133b973a14eab498ae41fd2054685e7250b36c4bd758ca801000000000000000000ba4fd6d57bfebf73fcf0552a92d5430b78b735cf59c6c58243b2fc48d4669b5a75dcc96af01e021736a8ee8c";
    static final long TIP_TIME = 1791614069L, TIP_BITS = 0x17021ef0L;
    static final String TIP_HASH = "00000000000000000001fa7ca83e1eb90d5a1865d8db9684f3f03ca64ccaec8a";
    /** Height 970,586: 92,419 seconds before it, at the same difficulty. */
    static final String OLD = "00e0ff3f5c9163e913a6431d7ef2fce013c71bc6a96a9fdaad1a020000000000000000000db1148f11b5c527caef5a8f54ed8bab7a2096b40d2a204b5c8e7f38d3501c5f7273c86af01e02177f6bf671";
    static final long OLD_TIME = 1791521650L;
    static final String OLD_HASH = "000000000000000000016d1284d0c5c14f42cdb4f6ee7c596c70d1d70cc5f177";
    /** The first block of all: real, and mined at a difficulty far below the floor. */
    static final String GENESIS = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

    /** SET_CARD on an open card (no owner): the PIN form. */
    private int setCardOpen(String mint, byte[] refund) {
        return sw(setCardOpenCommand(record(mint, refund)));
    }
    /** The owner's phone: a nonce, a proof by the owner's key over this record, SET_CARD. */
    private int ownerSetCard(String mint, byte[] refund) {
        byte[] data = record(mint, refund);
        return sw(setCardCommand(ownerProof(L_CARD, OWNER, nonceBytes(), data), data));
    }
    /** SET_CARD as whichever form this card takes: the owner's when it has an owner, the PIN's when it has none. */
    private int setCard(String mint, byte[] refund) {
        return info()[16] == 1 ? ownerSetCard(mint, refund) : setCardOpen(mint, refund);
    }
    private int setOwner(Key owner) { return sw(setOwnerOpenCommand(owner)); }
    /** The owner's phone, as it does it: a nonce, a proof, the command. */
    private int changePin(byte[] newPin) {
        return sw(changePinCommand(ownerProof(L_PIN, OWNER, nonceBytes(), newPin), newPin));
    }
    private int setLimit(long sats) {
        return sw(setLimitCommand(ownerProof(L_LIMIT, OWNER, nonceBytes(), u32(sats)), sats));
    }
    private int allowLoad() {
        return sw(allowLoadCommand(ownerProof(L_LOAD, OWNER, nonceBytes(), new byte[0])));
    }
    private int lock() {
        return sw(lockCommand(ownerProof(L_LOCK, OWNER, nonceBytes(), new byte[0])));
    }
    /** RESET_CARD (1.17): P1 = 0, P2 = the confirming byte, and the owner's proof over its label and no value. */
    private static CommandAPDU resetCommand(byte[] proof) {
        return new CommandAPDU(CLA, INS_RESET_CARD, 0, RESET_CONFIRM, ownerData(proof, new byte[0]));
    }
    /** The owner's phone resetting the card: a nonce, a proof, the command. */
    private int resetCard() {
        return sw(resetCommand(ownerProof(L_RESET, OWNER, nonceBytes(), new byte[0])));
    }
    /** SET_TAG (1.19): P1 = 0 the tag on, P1 = 1 off, P2 = 0; the proof's length, the proof, then the byte P1 says again, which the proof is over. */
    static CommandAPDU setTagCommand(byte[] proof, int p1) {
        return new CommandAPDU(CLA, INS_SET_TAG, p1, 0, ownerData(proof, new byte[] { (byte) p1 }));
    }
    /**
     * The mint's proof for a piece (1.20), as a later holder needs it: e, s and the blinding factor r, 96 bytes. Made from a seed so
     * that two seeds make two proofs and none is all zeros. The card never checks it.
     */
    static byte[] dleqProof(int seed) {
        byte[] p = new byte[96];
        for (int i = 0; i < 96; i++) p[i] = (byte) (seed * 3 + i + 1);
        return p;
    }
    /** LOAD_PROOF with P1 = 1 (1.20): the piece's 81 bytes and then its proof's 96. The answer is the place and 01 (kept) or 00 (the card has no room for proofs). */
    static CommandAPDU loadWithProofCommand(byte[] piece, byte[] proof) {
        return new CommandAPDU(CLA, INS_LOAD_PROOF, 1, 0, concat(piece, proof), 256);
    }
    /** GET_DLEQ (1.20): the place P1 and the place P2, or FF (255) for no second. */
    static CommandAPDU getDleqCommand(int first, int second) {
        return new CommandAPDU(CLA, INS_GET_DLEQ, first, second, 256);
    }
    /** What GET_DLEQ answers for a place that holds an unspent piece with a proof: 01 and the proof. */
    static byte[] dleqHeld(byte[] proof) {
        return concat(new byte[] { 1 }, proof);
    }
    /** The owner's phone switching the tag: a nonce, a proof over "CashuCard/tag" and the byte, the command. */
    private int setTag(boolean off) {
        byte[] value = { (byte) (off ? 1 : 0) };
        return sw(setTagCommand(ownerProof(L_TAG, OWNER, nonceBytes(), value), off ? 1 : 0));
    }
    /** The owner's phone setting both limits: a nonce, a proof over the eight bytes, the command. */
    private int setLimits(long day, long tap) {
        return sw(setLimitsCommand(ownerProof(L_LIMIT, OWNER, nonceBytes(), concat(u32(day), u32(tap))), day, tap));
    }
    /** GET_LOG: the four counts, then the last taps, newest first, twenty bytes each (1.15; sixteen before it). */
    private ResponseAPDU logAnswer() { return transmit(new CommandAPDU(CLA, INS_GET_LOG, 0, 0, 256)); }
    private byte[] log() { ResponseAPDU r = logAnswer(); assertEquals(SW_OK, r.getSW()); return r.getData(); }
    private long logTaps() { return readUint32(log(), 0); }
    private long logSats() { return readUint32(log(), 4); }
    private long logRefused() { return readUint32(log(), 8); }
    private long logTampers() { return readUint32(log(), 12); }
    private int logHeld() { return (log().length - 16) / 20; }
    /** The tap `k` back from the newest: { the clock when it began, sats signed for, pieces, refused, flags }. */
    private long[] logTap(int k) {
        byte[] d = log();
        int at = 16 + 20 * k;
        return new long[] { readUint32(d, at), readUint32(d, at + 4), d[at + 8] & 0xFF, d[at + 9] & 0xFF, d[at + 10] & 0xFF };
    }
    /** What was put on in the tap `k` back from the newest: { pieces, sats }. */
    private long[] logLoaded(int k) {
        byte[] d = log();
        int at = 16 + 20 * k;
        return new long[] { d[at + 11] & 0xFF, readUint32(d, at + 12) };
    }
    /** The time the terminal told (TELL_TIME) in the tap `k` back from the newest, at the entry's offset 16: zeros where it told none. */
    private long logTold(int k) {
        return readUint32(log(), 16 + 20 * k + 16);
    }
    /** The card taken out of the field and put back: a new tap, selected, with the PIN. */
    private void newTap() {
        simulator.reset();
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
    }
    /**
     * GET_INFO asked for the limit on one payment as well (P1 = 1): forty-two bytes, as it has been since 1.16 and whatever the NFC tag's
     * state. (A command, like any: it gives up a payment that is waiting.)
     */
    private byte[] infoTap() { return transmit(new CommandAPDU(CLA, INS_GET_INFO, 1, 0, 256)).getData(); }
    /**
     * GET_INFO with P1 = 2 (1.19): the same forty-two bytes as P1 = 1 and, after them, one that says whether the NFC tag is on: 00 on,
     * 01 off.
     */
    private byte[] infoTag() { return transmit(new CommandAPDU(CLA, INS_GET_INFO, 2, 0, 256)).getData(); }
    /**
     * The most the card signs for in one payment without making the terminal wait, as the holder reads it: bytes 30..33 of
     * GET_INFO asked for with P1 = 1, which the card gives only with the owner's grant in this tap, so the grant is given
     * first (ALLOW_LOAD; it needs an owner, and a card that is not locked). 0 is none.
     */
    private long paymentLimit() {
        assertEquals(SW_OK, allowLoad(), "the owner's grant, to read the limit on one payment");
        return readUint32(infoTap(), 30);
    }
    /** The limit on one payment as the record holds it, read without a command: for a card with no owner, which can give nobody the grant. */
    private long paymentLimitInTheRecord() throws Exception { return readUint32(field("cardRecord"), CashuApplet.CARD_TAP_LIMIT_OFFSET); }
    /** The same four bytes as a terminal gets them, under the PIN or not: without the owner's grant they are zeros. */
    private long paymentLimitAsATerminalSeesIt() { return readUint32(infoTap(), 30); }
    /** What the card remembers of that limit: bytes 34..41. It remembers nothing, so these are always zero. */
    private byte[] remembered() { return Arrays.copyOfRange(infoTap(), 34, 42); }
    private void assertNothingRemembered(String why) {
        assertArrayEquals(new byte[8], remembered(), "GET_INFO's bytes 34..41, which held a window and a count: " + why);
    }
    /** The same eight bytes in the card's record itself, where no command reads them but GET_INFO. */
    private void assertRecordRemembersNothing(String why) throws Exception {
        assertArrayEquals(new byte[8], Arrays.copyOfRange(field("cardRecord"), CashuApplet.CARD_NOPIN_LIMIT_OFFSET, CashuApplet.CARD_NOPIN_LIMIT_OFFSET + 8),
            "the record's window and count of the limit on one payment: " + why);
    }
    /** The card's clock is moved to `t`, by the block of that time (mined at the tests' floor): the status word. */
    private int setTime(long t) { return sw(setTimeCommand(t)); }
    /** TELL_TIME: the terminal's own clock, as a note: the status word. */
    private int tell(long t) { return sw(tellTimeCommand(t)); }
    /** The hardest difficulty of any header the card has taken (bits as a header carries them, little-endian), from GET_CARD's bytes 40..43: zeros until one. */
    private byte[] headerBits() { return Arrays.copyOfRange(cardRecord(), 40, 44); }
    /** The hash of the last header the card took, as Bitcoin shows a block hash, from GET_CARD's bytes 44..75: zeros until one. */
    private byte[] headerHash() { return Arrays.copyOfRange(cardRecord(), 44, 76); }

    /** What the card says it will sign for in a day: GET_CARD's four bytes after the unit, as GET_INFO's say it too. */
    private long limit() {
        long viaCard = readUint32(transmit(new CommandAPDU(CLA, INS_GET_CARD, 0, 0, 256)).getData(), 3);
        assertEquals(viaCard, readUint32(info(), 12), "GET_INFO and GET_CARD say the same");
        return viaCard;
    }
    /** The card's clock, and the window and what it has signed for, from GET_INFO. */
    private long now() { return readUint32(info(), 17); }
    private long windowStart() { return readUint32(info(), 21); }
    private long spentToday() { return readUint32(info(), 25); }

    private ResponseAPDU load(byte[] proof) { return transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, proof, 1)); }
    /**
     * One piece paid with: a payment of that one place and no outputs. The signature, or whatever refused it. A payment
     * over the limit on one payment is waited for first (see signAll), and the waits it took are waitsTaken().
     */
    private ResponseAPDU spend(int slot) { return spendAll(new int[] { slot }, new byte[0][]); }
    private static CommandAPDU beginCommand(int... slots) {
        byte[] list = new byte[slots.length];
        for (int i = 0; i < slots.length; i++) list[i] = (byte) slots[i];
        return new CommandAPDU(CLA, INS_SPEND_ALL_BEGIN, 0, 0, list, 4);
    }
    private static final CommandAPDU SIGN_ALL = new CommandAPDU(CLA, INS_SPEND_ALL_SIGN, 0, 0, 64);
    /** An output as SPEND_ALL_OUTPUTS takes it: the amount (4) and the blinded message (33). */
    static byte[] output(long amount, byte[] blinded) { return concat(u32(amount), blinded); }
    /**
     * A payment with one signature: SPEND_ALL_BEGIN naming the places, the outputs six to a command, SPEND_ALL_SIGN
     * (as often as the card makes it wait). Answers the signature, or the answer of whichever step refused.
     */
    private ResponseAPDU spendAll(int[] slots, byte[][] outputs) {
        waitAnswers.clear();
        ResponseAPDU begun = transmit(beginCommand(slots));
        if (begun.getSW() != SW_OK) return begun;
        for (int at = 0; at < outputs.length; at += 6) {
            ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, concat(Arrays.copyOfRange(outputs, at, Math.min(outputs.length, at + 6)))));
            if (r.getSW() != SW_OK) return r;
        }
        return signAll();
    }

    /**
     * The two-byte answers SPEND_ALL_SIGN gave in the last payment spendAll (or signAll) ran, as the number they say: while a
     * payment waits the card answers "not yet", 00 01, every time, and never how many are left. Empty for a payment that was
     * not waited for, and for one refused before it was signed.
     */
    private final java.util.List<Integer> waitAnswers = new java.util.ArrayList<>();
    /** How many times the last payment was made to wait: the two-byte answers it was given before its signature. */
    private int waitsTaken() { return waitAnswers.size(); }
    /** What a payment that waits is answered, each time: 00 01. */
    static final byte[] NOT_YET = { 0x00, 0x01 };
    /** Whether this is the card saying a payment is waiting: 9000 and two bytes, where a signature is 64. */
    private static boolean isWait(ResponseAPDU r) { return r.getSW() == SW_OK && r.getData().length == 2; }
    /** That this is the card's "not yet": 9000 and 00 01, the same whatever the limit is or how much is left. */
    private static void assertNotYet(ResponseAPDU r, String why) {
        assertEquals(SW_OK, r.getSW(), why);
        assertArrayEquals(NOT_YET, r.getData(), why);
    }

    /**
     * SPEND_ALL_SIGN, sent again for as long as the card answers "not yet". Answers what ends it: the signature, or a
     * refusal. Every wait is checked to be exactly 00 01 and so to say nothing of how many are left; how many there were is
     * waitsTaken().
     */
    private ResponseAPDU signAll() {
        waitAnswers.clear();
        for (int sent = 0; sent <= WAITS_MOST; sent++) {
            ResponseAPDU r = transmit(SIGN_ALL);
            if (!isWait(r)) return r;
            assertNotYet(r, "wait " + (waitAnswers.size() + 1) + ": not yet, and not how many are still to come");
            waitAnswers.add(1);
        }
        fail("the card is still making a payment wait after " + (WAITS_MOST + 1) + " answers, which is more than its most");
        return null;
    }

    /** The statuses the card has answered in this test, for the check at the end that no limit on one payment is ever refused. */
    private final java.util.Set<Integer> answered = new java.util.HashSet<>();

    @AfterEach
    void noPaymentLimitRefusal() {
        assertFalse(answered.contains(SW_NO_LONGER_ANSWERED),
            "6A95 was the limit on one tap refusing a spend; the limit on one payment is waited for and refuses nothing");
        assertFalse(answered.contains(SW_WAS_NO_TIME),
            "6A92 was a card that had never been told the time refusing a load or a limit; since 1.15 a card spends its first day on trust, and nothing answers it");
    }
    /** The text a payment's one signature is over: each input's secret and C, then each output's amount and blinded message. */
    static String allMessage(byte[] cardKey, byte[] refund, byte[][] slotData, byte[][] outputs) {
        StringBuilder m = new StringBuilder();
        for (byte[] d : slotData) {
            m.append(secretText(Arrays.copyOfRange(d, 13, 45), cardKey, readUint32(d, 78), refund)).append(toHex(Arrays.copyOfRange(d, 45, 78)));
        }
        for (byte[] o : outputs) m.append(readUint32(o, 0)).append(toHex(Arrays.copyOfRange(o, 4, 37)));
        return m.toString();
    }
    private int clearSpent() { return sw(new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1)); }
    private byte[] info() { return transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256)).getData(); }
    private byte[] cardRecord() { return transmit(new CommandAPDU(CLA, INS_GET_CARD, 0, 0, 256)).getData(); }
    private byte[] cardKey() { return transmit(new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256)).getData(); }
    private byte[] slot(int i) { return transmit(new CommandAPDU(CLA, INS_GET_PROOF, i, 0, 256)).getData(); }
    private long balance() { return readUint32(transmit(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4)).getData(), 0); }
    private void reselect() {
        assertEquals(SW_OK, sw(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(AID_STR))));
    }

    /**
     * A card as its holder leaves it: set up by an open card's steps, as the
     * phone does them (PIN, record, and the owner last), the PIN verified, and
     * given a block header whose time is T0. No limit.
     */
    private void ready() {
        readyOn(simulator, 0);
    }

    /** The same, with a daily limit set by the owner. */
    private void readyWithLimit(long limit) {
        readyOn(simulator, limit);
    }

    /**
     * The same, and the card has seen no block header: its clock is 0, and it spends its first day on trust (1.15). With a limit
     * set, its window waits for the first header.
     */
    private void readyWithoutAHeader(long limit) {
        readyOn(simulator, limit, false);
    }

    /**
     * A card in another test class's hands: set up as the phone sets one up
     * (PIN, verify, record, owner), given a block header, and given a limit if
     * one is asked for. Leaves the PIN verified. (The floor built into the
     * applet is the tests' own cheap one while the header is mined.)
     */
    static void readyOn(CardSimulator sim, long limit) {
        readyOn(sim, limit, true);
    }

    static void readyOn(CardSimulator sim, long limit, boolean withAHeader) {
        byte[] floorBefore = floorNow();
        useTheTestFloor();
        try {
            assertEquals(SW_OK, sim.transmitCommand(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, TEST_PIN)).getSW());
            assertEquals(SW_OK, sim.transmitCommand(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN)).getSW());
            assertEquals(SW_OK, sim.transmitCommand(setCardOpenCommand(record(MINT, REFUND))).getSW());
            assertEquals(SW_OK, sim.transmitCommand(setOwnerOpenCommand(OWNER)).getSW());
            if (withAHeader) assertEquals(SW_OK, sim.transmitCommand(setTimeCommand(T0)).getSW());
            if (limit > 0) {
                byte[] n = sim.transmitCommand(new CommandAPDU(CLA, INS_GET_NONCE, 0, 0, 16)).getData();
                assertEquals(SW_OK, sim.transmitCommand(setLimitCommand(ownerProof(L_LIMIT, OWNER, n, u32(limit)), limit)).getSW());
            }
        } finally {
            useFloor(floorBefore);      // the floor is left as the caller had it: a test that holds the card to the network's own keeps doing so
        }
    }

    /** Whether `sig` is the card's for a payment of that one piece and no outputs. */
    private boolean signedFor(byte[] sig, byte[] slotData, byte[] refund) throws Exception {
        return signedForAll(sig, new byte[][] { slotData }, new byte[0][], refund);
    }
    /** Whether `sig` is the card's for a payment of those pieces, in that order, into those outputs. */
    private boolean signedForAll(byte[] sig, byte[][] slotData, byte[][] outputs, byte[] refund) throws Exception {
        byte[] msg = sha256(allMessage(cardKey(), refund, slotData, outputs).getBytes(StandardCharsets.UTF_8));
        return schnorrVerify(extractPubkeyX(cardKey()), msg, sig);
    }

    /** One of the applet's persistent arrays, live, for what no command can reach. */
    private byte[] field(String name) throws Exception {
        java.lang.reflect.Field f = CashuApplet.class.getDeclaredField(name);
        f.setAccessible(true);
        return (byte[]) f.get(runtime.appletAt(AIDUtil.create(AID_HEX)));
    }

    // =========================================================================
    // What the card is
    // =========================================================================

    @Test
    @DisplayName("SELECT by the applet's whole name answers, as by its package's ten bytes")
    void testSelectByTheWholeName() {
        // what a phone sends (D25): iOS chooses by the name in the app's Info.plist, and Foxy's wallet by a whole AID
        // too (today its 1.x card's ten bytes, F0 FOXYCARD 01); on 2.0 the whole AID is these eleven
        ResponseAPDU whole = transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(AID_HEX), 256));
        assertEquals(SW_OK, whole.getSW());
        assertArrayEquals(new byte[] { 0x02, 0x01 }, whole.getData(), "the same answer either way: version 2.1");
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256)), "and its instructions follow");
    }

    @Test
    @DisplayName("SELECT answers its version, and not to upstream's AID")
    void testSelect() {
        ResponseAPDU resp = transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(AID_STR)));
        assertEquals(SW_OK, resp.getSW());
        assertArrayEquals(new byte[] { 0x02, 0x01 }, resp.getData(), "version 2.1: the shared protocol (D18), Foxy's 1.20 under the neutral AID with the fixes of D19 to D24, and D26's rollover rules (1.20: the card keeps the mint's proof with each piece, which it does not check and a phone reads back (1.19: the card answers as an NFC tag, which its owner switches off and on; 1.18: four waits for each limit's worth over the limit past the first; 1.17: a card can be reset; 1.16: the PIN is optional, and a card with one has a no-PIN allowance; 1.15 was the clock: the time written in the newest Bitcoin block header the card has taken)");
        assertNotEquals(SW_OK, sw(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(UPSTREAM_AID))),
            "an upstream reader must not find this applet under upstream's AID: the wire is not the same");
    }

    @Test
    @DisplayName("GET_INFO on a new card: 30 bytes: version 2.1, 128 empty slots, no PIN, three tries, format 4, capabilities FF, no record, no limit, no owner, no block header seen, no change due")
    void testInfoFresh() {
        byte[] d = info();
        assertEquals(30, d.length);
        assertEquals(2, d[0]); assertEquals(1, d[1]);
        assertEquals(MAX_PROOFS, d[2] & 0xFF);
        assertEquals(0, d[3]); assertEquals(0, d[4]);
        assertEquals(MAX_PROOFS, d[5] & 0xFF);
        assertEquals((byte) 0xFF, d[6], "secp256k1, Schnorr, PIN, the limit on one payment waited for and not refused, the 1.6 forms (several pieces to a LOAD_PROOF, GET_PIECES by name), more than sixty-four places with the short listing, a payment's pieces burned outside its transaction so that it may be of any number, and the PIN taken sealed (it was 7F, 3F, 1F, 0F and 07 before)");
        assertEquals(0, d[7], "no PIN");
        assertEquals(4, d[8], "format");
        assertEquals(3, d[9], "tries");
        assertEquals(0, d[10], "not locked");
        assertEquals(0, d[11], "no card record");
        assertEquals(0, readUint32(d, 12), "no limit: zero is none, and is what a new card has");
        assertEquals(0, d[16], "no owner");
        assertEquals(0, readUint32(d, 17), "the card has seen no block header, and so has no time");
        assertEquals(0, readUint32(d, 21), "no window");
        assertEquals(0, readUint32(d, 25), "and has signed for nothing today");
    }

    @Test
    @DisplayName("GET_PUBKEY is a 33-byte compressed key")
    void testPubkey() {
        byte[] k = cardKey();
        assertEquals(33, k.length);
        assertTrue(k[0] == 0x02 || k[0] == 0x03);
    }

    @Test
    @DisplayName("A class other than B0, and an instruction nobody defined, are refused")
    void testUnknown() {
        assertEquals(SW_CLA_NOT_SUPPORTED, sw(new CommandAPDU(0x80, INS_GET_INFO, 0, 0, 256)));
        assertEquals(SW_INS_NOT_SUPPORTED, sw(new CommandAPDU(CLA, 0x7F, 0, 0, 256)));
        assertEquals(SW_INS_NOT_SUPPORTED, sw(new CommandAPDU(CLA, 0x38, 0, 0, 256)), "nothing sits between TELL_TIME and VERIFY_PIN");
        assertEquals(SW_INS_NOT_SUPPORTED, sw(new CommandAPDU(CLA, INS_WAS_SET_TIME, 0, 0, 256)), "and SET_TIME, which was 35, is gone for good");
        assertEquals(SW_INS_NOT_SUPPORTED, sw(new CommandAPDU(CLA, 0x46, 0, 0, 256)), "or after ALLOW_LOAD");
    }

    @Test
    @DisplayName("The P-256 constants the owner key is set up with are the curve's, to the byte")
    void testTheCurveIsP256() throws Exception {
        java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("EC");
        params.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
        java.security.spec.ECParameterSpec spec = params.getParameterSpec(java.security.spec.ECParameterSpec.class);
        java.security.spec.ECFieldFp field = (java.security.spec.ECFieldFp) spec.getCurve().getField();
        assertArrayEquals(unsigned32(field.getP()), constant("P256_P"), "the field prime");
        assertArrayEquals(unsigned32(spec.getCurve().getA()), constant("P256_A"), "a");
        assertArrayEquals(unsigned32(spec.getCurve().getB()), constant("P256_B"), "b");
        assertArrayEquals(unsigned32(spec.getOrder()), constant("P256_N"), "the order");
        byte[] g = new byte[65];
        g[0] = 0x04;
        System.arraycopy(unsigned32(spec.getGenerator().getAffineX()), 0, g, 1, 32);
        System.arraycopy(unsigned32(spec.getGenerator().getAffineY()), 0, g, 33, 32);
        assertArrayEquals(g, constant("P256_G"), "the generator, uncompressed");
        assertEquals(1, spec.getCofactor());
        // and the card's own key and these have nothing in common
        assertFalse(Arrays.equals(constant("P256_P"), constant("SECP256K1_P")));
    }

    private static byte[] unsigned32(java.math.BigInteger n) {
        byte[] b = n.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(b.length, 32);
        System.arraycopy(b, b.length - len, out, 32 - len, len);
        return out;
    }

    private static byte[] constant(String name) throws Exception {
        java.lang.reflect.Field f = CashuApplet.class.getDeclaredField(name);
        f.setAccessible(true);
        return (byte[]) f.get(null);
    }

    // =========================================================================
    // SIGN_ARBITRARY is gone
    // =========================================================================

    @Test
    @DisplayName("SIGN_ARBITRARY does not exist: with no PIN, with the PIN, and with pieces on the card")
    void testNoSignArbitrary() {
        byte[] msg = new byte[32];
        assertEquals(SW_INS_NOT_SUPPORTED, sw(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, msg, 64)));
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        assertEquals(SW_INS_NOT_SUPPORTED, sw(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, msg, 64)));
        assertEquals(16, balance(), "and nothing was burned by asking");
    }

    // =========================================================================
    // Loading
    // =========================================================================

    @Test
    @DisplayName("Nothing is loaded onto a card with no owner, PIN or no PIN: a card with no PIN (1.16) is loaded by whoever holds it once it has an owner")
    void testNoLoadWithoutOwner() {
        assertEquals(SW_NO_OWNER, load(buildProof(KEYSET, 16, 1)).getSW(), "no record, no owner: nothing loads");
        assertEquals(SW_OK, setCard(MINT, REFUND), "its record is written: a card is set up with no PIN, and with none is open while it is set up (1.16)");
        assertEquals(SW_NO_OWNER, load(buildProof(KEYSET, 16, 1)).getSW(), "a record and still no owner: nothing loads");
        assertEquals(0, info()[3], "no slot was taken");
    }

    @Test
    @DisplayName("Nothing is loaded with the PIN set and not verified, onto a card with no owner, or before it knows its mint; a card that has seen no block header loads all the same (its first day is on trust), and a header changes nothing about that")
    void testLoadNeedsEverything() {
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_SECURITY_NOT_SATIS, load(buildProof(KEYSET, 16, 1)).getSW(), "the PIN, not verified");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_NO_OWNER, load(buildProof(KEYSET, 16, 1)).getSW(), "no owner");
        assertEquals(SW_OK, setCard(MINT, REFUND));
        assertEquals(SW_NO_OWNER, load(buildProof(KEYSET, 16, 1)).getSW(), "a record, and still no owner");
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(0, now(), "an owner and a record, and the card has seen no block header");
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW(), "and it loads: nothing answers 6A92 since 1.15");
        assertEquals(1, info()[3]);
        assertEquals(0, now(), "loading asked for no time");
        assertEquals(SW_OK, setTime(T0));
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 2)).getSW(), "with one it loads as it did");
    }

    @Test
    @DisplayName("Nothing is loaded before the card knows its mint")
    void testLoadNeedsARecord() {
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(SW_NO_CARD_RECORD, load(buildProof(KEYSET, 16, 1)).getSW());
        assertEquals(SW_OK, setTime(T0), "(a header asks for no record: there is no time key to check against, since 1.15)");
        assertEquals(SW_NO_CARD_RECORD, load(buildProof(KEYSET, 16, 1)).getSW(), "and it did not give the card a record");
    }

    @Test
    @DisplayName("LOAD_PROOF takes 81 bytes, a C that is a point and an amount that is not nothing")
    void testLoadShape() {
        ready();
        assertEquals(SW_WRONG_LENGTH, load(new byte[77]).getSW(), "upstream's 77 bytes are not a piece here");
        assertEquals(SW_WRONG_LENGTH, load(new byte[82]).getSW());
        byte[] notPoint = buildProof(KEYSET, 16, 1);
        notPoint[44] = 0x04;
        assertEquals(SW_WRONG_DATA, load(notPoint).getSW());
        assertEquals(SW_WRONG_DATA, load(buildProof(KEYSET, 0, 1)).getSW());
        assertEquals(0, info()[3], "none of them took a slot");
        ResponseAPDU ok = load(buildProof(KEYSET, 16, 1, 1900000000L));
        assertEquals(SW_OK, ok.getSW());
        assertEquals(0, ok.getData()[0], "the first slot");
        byte[] s = slot(0);
        assertEquals(SLOT, s.length);
        assertEquals(1, s[0]);
        assertEquals(16, readUint32(s, 9));
        assertEquals(1900000000L, readUint32(s, 78), "the date is kept with the piece");
    }

    @Test
    @DisplayName("A dated piece needs a refund key on the card; an undated one does not")
    void testDatedNeedsRefundKey() {
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setCard(MINT, NO_REFUND));
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(SW_OK, setTime(T0));
        assertEquals(SW_NO_REFUND_KEY, load(buildProof(KEYSET, 16, 1, 1900000000L)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1, 0)).getSW());
    }

    @Test
    @DisplayName("A hundred and twenty-eight pieces fit, and the hundred and twenty-ninth is refused with no space (6A84); GET_SLOT_STATUS says 128 places, GET_BALANCE sums them all, and place 128 is not a place (6A83)")
    void testFull() {
        ready();
        for (int i = 0; i < MAX_PROOFS; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 1, i)).getSW(), "slot " + i);
        assertEquals(SW_NO_SPACE, load(buildProof(KEYSET, 1, 999)).getSW());
        assertEquals(MAX_PROOFS, balance());
        assertEquals(MAX_PROOFS, transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData().length);
        assertEquals(SW_SLOT_OUT_OF_RANGE, sw(new CommandAPDU(CLA, INS_GET_PROOF, MAX_PROOFS, 0, 256)));
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_GET_PROOF, MAX_PROOFS - 1, 0, 256)), "127 is the last place");
    }

    // =========================================================================
    // Reading the whole card in a few answers (GET_PIECES)
    // =========================================================================

    private ResponseAPDU pieces(int from) { return transmit(new CommandAPDU(CLA, INS_GET_PIECES, from, 0, 256)); }

    /**
     * One page of the whole listing as the phone reads it: the next slot to ask for, then the entries as
     * { slot, state, the piece or null, the tag byte }. A tag is the place's number (0 to 127) with 0x80 set where the place
     * is spent; an unspent place is followed by its 81 bytes.
     */
    private static final class Page {
        final int next, length;
        final java.util.List<Object[]> entries = new java.util.ArrayList<>();
        Page(byte[] d) {
            length = d.length;
            next = d[0] & 0xFF;
            int at = 1;
            while (at < d.length) {
                int tag = d[at++] & 0xFF;
                int state = (tag & 0x80) != 0 ? 2 : 1, slot = tag & 0x7F;
                byte[] piece = null;
                if (state == 1) { piece = Arrays.copyOfRange(d, at, at + 81); at += 81; }
                entries.add(new Object[] { slot, state, piece, tag });
            }
            assertEquals(d.length, at, "the answer is made of whole entries");
        }
    }

    @Test
    @DisplayName("GET_PIECES on an empty card is one byte: nothing more to ask for")
    void testPiecesEmpty() {
        ready();
        ResponseAPDU r = pieces(0);
        assertEquals(SW_OK, r.getSW());
        assertArrayEquals(new byte[] { (byte) 0x80 }, r.getData(), "next is 128: the end");
        assertEquals(SW_SLOT_OUT_OF_RANGE, pieces(MAX_PROOFS).getSW());
        assertEquals(SW_SLOT_OUT_OF_RANGE, pieces(MAX_PROOFS + 1).getSW());
        assertEquals(SW_SLOT_OUT_OF_RANGE, pieces(255).getSW());
    }

    @Test
    @DisplayName("GET_PIECES gives each unspent piece as GET_PROOF does, in one answer for up to three, and asks for no PIN")
    void testPiecesOnePage() {
        ready();
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 100 + i, i + 1, i == 1 ? 1900000000L : 0)).getSW());
        reselect();     // a new tap: the PIN is not verified, and nothing here asks for it
        ResponseAPDU r = pieces(0);
        assertEquals(SW_OK, r.getSW());
        Page page = new Page(r.getData());
        assertEquals(1 + 3 * 82, page.length);
        assertEquals(128, page.next);
        assertEquals(3, page.entries.size());
        for (int i = 0; i < 3; i++) {
            assertEquals(i, page.entries.get(i)[0]);
            assertEquals(1, page.entries.get(i)[1]);
            // the same bytes GET_PROOF gives, after its status byte
            assertArrayEquals(Arrays.copyOfRange(slot(i), 1, 82), (byte[]) page.entries.get(i)[2], "slot " + i);
        }
    }

    @Test
    @DisplayName("GET_PIECES lists a spent slot by its tag alone, leaves an empty one out, and starts where it is asked to")
    void testPiecesStates() {
        ready();
        for (int i = 0; i < 6; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 10 + i, i + 1)).getSW());
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(SW_OK, spend(2).getSW());
        assertEquals(SW_OK, spend(4).getSW());
        Page all = new Page(pieces(0).getData());
        assertEquals(128, all.next);
        assertEquals(6, all.entries.size());
        int[] states = { 1, 2, 2, 1, 2, 1 };
        for (int i = 0; i < 6; i++) {
            assertEquals(i, all.entries.get(i)[0]);
            assertEquals(states[i], all.entries.get(i)[1], "slot " + i);
            assertEquals(states[i] == 1, all.entries.get(i)[2] != null);
        }
        assertEquals(1 + 3 * 82 + 3, all.length);
        // a page from the middle, and from an empty slot
        Page mid = new Page(pieces(3).getData());
        assertEquals(3, mid.entries.size());
        assertEquals(3, mid.entries.get(0)[0]);
        Page empty = new Page(pieces(20).getData());
        assertEquals(0, empty.entries.size());
        assertEquals(128, empty.next);
        // a freed place is not listed
        assertEquals(SW_OK, clearSpent());
        Page freed = new Page(pieces(0).getData());
        assertEquals(3, freed.entries.size());
        // and the same states GET_SLOT_STATUS gives
        byte[] status = transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData();
        for (Object[] e : freed.entries) assertEquals(status[(int) e[0]], (int) e[1]);
    }

    @Test
    @DisplayName("GET_PIECES on a full card: pages of three pieces, every one within a short APDU, every one moving on")
    void testPiecesFullCard() {
        ready();
        for (int i = 0; i < MAX_PROOFS; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 1 + i, i + 1)).getSW());
        int from = 0, pages = 0, seen = 0;
        while (from < MAX_PROOFS) {
            ResponseAPDU r = pieces(from);
            assertEquals(SW_OK, r.getSW());
            assertTrue(r.getData().length <= 255, "within what a short APDU carries");
            Page page = new Page(r.getData());
            assertTrue(page.next > from, "every answer moves on");
            assertTrue(page.entries.size() <= 3);
            for (Object[] e : page.entries) {
                int i = (int) e[0];
                assertEquals(seen, i, "in order, none missed");
                assertArrayEquals(Arrays.copyOfRange(slot(i), 1, 82), (byte[]) e[2]);
                seen++;
            }
            from = page.next;
            pages++;
        }
        assertEquals(MAX_PROOFS, seen);
        assertEquals(43, pages, "a hundred and twenty-eight pieces are forty-three answers, not a hundred and twenty-eight");
    }

    @Test
    @DisplayName("GET_PIECES fills a page to 255 bytes and not a byte over: three pieces and eight spent tags, then the next piece starts a page")
    void testPiecesPageEdge() {
        ready();
        for (int i = 0; i < 12; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 5 + i, i + 1)).getSW());
        for (int i = 3; i <= 10; i++) assertEquals(SW_OK, spend(i).getSW());
        Page one = new Page(pieces(0).getData());
        assertEquals(255, one.length);
        assertEquals(11, one.next);
        assertEquals(11, one.entries.size());
        Page two = new Page(pieces(one.next).getData());
        assertEquals(128, two.next);
        assertEquals(1, two.entries.size());
        assertEquals(11, two.entries.get(0)[0]);
        // one spent tag more would be 256: with slot 11 spent too, its tag is left for the next page
        assertEquals(SW_OK, spend(11).getSW());
        Page nine = new Page(pieces(0).getData());
        assertEquals(255, nine.length);
        assertEquals(11, nine.next);
        Page rest = new Page(pieces(nine.next).getData());
        assertEquals(1, rest.entries.size());
        assertEquals(11, rest.entries.get(0)[0]);
        assertEquals(2, rest.entries.get(0)[1]);
    }

    @Test
    @DisplayName("GET_PIECES changes nothing: not the day, not the slots, not the PIN's state")
    void testPiecesReadOnly() {
        ready();
        for (int i = 0; i < 4; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 20 + i, i + 1)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        byte[] infoBefore = info();
        byte[] statusBefore = transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData();
        byte[] first = pieces(0).getData();
        assertArrayEquals(first, pieces(0).getData(), "asking twice says the same");
        assertArrayEquals(infoBefore, info());
        assertArrayEquals(statusBefore, transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData());
        // a locked or blocked card still tells what it holds, as GET_PROOF does
        assertEquals(SW_OK, lock());
        assertEquals(SW_OK, pieces(0).getSW());
    }

    // =========================================================================
    // Version 1.6: the text kept beside each place, several pieces to a command, the short listings
    // =========================================================================

    /** A piece as LOAD_PROOF takes it, 81 bytes, with the nonce and the C asked for: keyset (8), amount (4), nonce (32), C (33), date (4). */
    static byte[] proofOf(byte[] nonce, byte[] c, long amount, long date) {
        assertEquals(32, nonce.length);
        assertEquals(33, c.length);
        byte[] p = new byte[81];
        System.arraycopy(hexToBytes(KEYSET), 0, p, 0, 8);
        putUint32(p, 8, amount);
        System.arraycopy(nonce, 0, p, 12, 32);
        System.arraycopy(c, 0, p, 44, 33);
        putUint32(p, 77, date);
        return p;
    }

    /** A piece as GET_PROOF gives it while it is unspent, and as allMessage reads a place: a status byte, then the 81 bytes that were sent. */
    static byte[] asSlot(byte[] proof) { return concat(new byte[] { 1 }, proof); }

    /** Bytes that are every edge of a hex digit pair: leading zeros, a zero nibble either side, all ones, a high bit. */
    private static final int[] EDGE_BYTES = { 0x00, 0x0f, 0xf0, 0xff, 0x80, 0x08, 0x01, 0x10, 0x7f, 0xa5 };

    private static byte[] edgeBytes(int len, int zeroLead, int shift) {
        byte[] b = new byte[len];
        for (int i = zeroLead; i < len; i++) b[i] = (byte) EDGE_BYTES[(i + shift) % EDGE_BYTES.length];
        return b;
    }

    /** One of six pieces whose nonces and Cs are all edge cases of hex text, with that date; k = 0..5, and 1 << k sats. */
    static byte[] edgeProof(int k, long date) {
        byte[] nonce, c;
        switch (k % 6) {
            case 0:  nonce = new byte[32]; c = new byte[33]; c[0] = 0x02; break;
            case 1:  nonce = new byte[32]; Arrays.fill(nonce, (byte) 0xff); c = new byte[33]; Arrays.fill(c, (byte) 0xff); c[0] = 0x03; break;
            case 2:  nonce = edgeBytes(32, 0, 0); c = edgeBytes(33, 1, 3); c[0] = 0x02; break;
            case 3:  nonce = edgeBytes(32, 5, 1); c = edgeBytes(33, 1, 7); c[0] = 0x03; break;
            case 4:  nonce = edgeBytes(32, 0, 5); nonce[31] = 0; c = edgeBytes(33, 1, 2); c[0] = 0x02; c[32] = 0; break;
            default: nonce = edgeBytes(32, 0, 8); nonce[0] = (byte) 0x80; nonce[1] = 0x08; c = edgeBytes(33, 1, 4); c[0] = 0x03; c[1] = 0x0f; break;
        }
        return proofOf(nonce, c, 1L << (k % 6), date);
    }

    /** Several pieces end to end in one LOAD_PROOF: the places they went to, a byte each, or the word that refused the first. */
    private ResponseAPDU loadBatch(byte[]... proofs) { return loadRaw(concat(proofs)); }
    private ResponseAPDU loadRaw(byte[] data) { return transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, data, 3)); }
    private int placeStatus(int place) { return transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData()[place]; }

    @Test
    @DisplayName("A payment's signature is over the text of each piece as it was sent, however it was loaded (singly, two to a command, three to a command), dated or not, with nonces and Cs of every edge of hex: for one piece, for several, and in the order named")
    void testTheStoredHexIsWhatIsHashed() throws Exception {
        long[] dates = { 0L, 7L, 1900000000L, 4294967295L };
        for (int mode = 1; mode <= 3; mode++) {
            for (long date : dates) {
                String what = (mode == 1 ? "loaded singly" : "loaded " + mode + " to a command") + ", date " + date;
                simulator = freshCard();
                ready();
                byte[][] sent = new byte[6][];
                for (int k = 0; k < 6; k++) sent[k] = edgeProof(k, date);
                for (int at = 0; at < 6; at += mode) {
                    byte[][] group = Arrays.copyOfRange(sent, at, at + mode);
                    ResponseAPDU r = mode == 1 ? load(group[0]) : loadBatch(group);
                    assertEquals(SW_OK, r.getSW(), what);
                    assertEquals(mode, r.getData().length, what + ": a place for each");
                    for (int j = 0; j < mode; j++) assertEquals(at + j, r.getData()[j] & 0xFF, what + ": in order");
                }
                // what is kept beside each place is the text of what was sent: the nonce's 64 hex characters and the C's 66
                byte[] kept = field("slotHex");
                for (int k = 0; k < 6; k++) {
                    String expected = toHex(Arrays.copyOfRange(sent[k], 12, 44)) + toHex(Arrays.copyOfRange(sent[k], 44, 77));
                    assertEquals(expected, new String(kept, k * 130, 130, StandardCharsets.US_ASCII), what + ": the text kept beside place " + k);
                    assertArrayEquals(asSlot(sent[k]), slot(k), what + ": and the slot is what was sent");
                }
                newTap();
                // one piece alone
                ResponseAPDU alone = spend(0);
                assertEquals(SW_OK, alone.getSW(), what);
                assertTrue(signedForAll(alone.getData(), new byte[][] { asSlot(sent[0]) }, new byte[0][], REFUND), what + ": one piece alone");
                byte[] wrong = sent[0].clone();
                wrong[43] ^= 0x01;
                assertFalse(signedForAll(alone.getData(), new byte[][] { asSlot(wrong) }, new byte[0][], REFUND), what + ": and the check can say no, for one nibble of the nonce");
                // two pieces, into outputs
                byte[][] outs = { output(2, blinded(1)), output(1, blinded(2)) };
                ResponseAPDU two = spendAll(new int[] { 1, 2 }, outs);
                assertEquals(SW_OK, two.getSW(), what);
                assertTrue(signedForAll(two.getData(), new byte[][] { asSlot(sent[1]), asSlot(sent[2]) }, outs, REFUND), what + ": two pieces");
                assertFalse(signedForAll(two.getData(), new byte[][] { asSlot(sent[2]), asSlot(sent[1]) }, outs, REFUND), what + ": in the order named");
                // three, named out of their order
                byte[][] outs3 = { output(4, blinded(3)) };
                ResponseAPDU three = spendAll(new int[] { 5, 3, 4 }, outs3);
                assertEquals(SW_OK, three.getSW(), what);
                assertTrue(signedForAll(three.getData(), new byte[][] { asSlot(sent[5]), asSlot(sent[3]), asSlot(sent[4]) }, outs3, REFUND), what + ": three pieces");
                assertEquals(0, balance(), what);
            }
        }
    }

    @Test
    @DisplayName("A place that is spent, freed with CLEAR_SPENT and loaded again with a different piece hashes the new piece's text and never the old one's: another nonce only, another C only, both; and the same in a batch")
    void testAFreedPlaceHashesItsNewPiece() throws Exception {
        ready();
        byte[] bystander = edgeProof(5, 0);
        byte[] old = edgeProof(2, 0);
        // the places: 0 is to be spent, freed and used again; 1 holds a piece that is never touched
        assertEquals(SW_OK, load(old).getSW());
        assertEquals(SW_OK, load(bystander).getSW());
        byte[] nonceOnly = old.clone();   nonceOnly[43] ^= 0xff; putUint32(nonceOnly, 8, 3);     // another last byte of the nonce, the same C
        byte[] cOnly = nonceOnly.clone(); cOnly[76] ^= 0x01; putUint32(cOnly, 8, 5);             // the same nonce, another C
        byte[] both = proofOf(edgeBytes(32, 3, 6), edgeBytes(33, 1, 9), 9, 0);                  // another of each
        both[44] = 0x03;
        byte[][] rounds = { old, nonceOnly, cOnly, both };
        for (int i = 0; i < rounds.length; i++) {
            if (i > 0) {
                ResponseAPDU again = load(rounds[i]);
                assertEquals(SW_OK, again.getSW(), "round " + i);
                assertEquals(0, again.getData()[0], "round " + i + ": the same place number, 0, the first that is empty");
            }
            assertArrayEquals(asSlot(rounds[i]), slot(0), "round " + i);
            ResponseAPDU r = spend(0);
            assertEquals(SW_OK, r.getSW(), "round " + i);
            assertTrue(signedForAll(r.getData(), new byte[][] { asSlot(rounds[i]) }, new byte[0][], REFUND), "round " + i + ": the text of the piece that is there");
            for (int before = 0; before < i; before++) {
                assertFalse(signedForAll(r.getData(), new byte[][] { asSlot(rounds[before]) }, new byte[0][], REFUND), "round " + i + ": and not the text of the piece that was there in round " + before);
            }
            assertEquals(SW_OK, clearSpent(), "round " + i);
            assertEquals(0, placeStatus(0), "round " + i + ": freed");
        }
        // the bystander, which was never touched, still hashes as itself
        ResponseAPDU by = spend(1);
        assertTrue(signedForAll(by.getData(), new byte[][] { asSlot(bystander) }, new byte[0][], REFUND), "the piece beside it, untouched");

        // a batch into freed places: 0 and 2 are freed and used again, with the old nonce at 0 and a new one at 2
        simulator = freshCard();
        ready();
        byte[][] first = { edgeProof(0, 0), edgeProof(1, 0), edgeProof(2, 0), edgeProof(3, 0) };
        ResponseAPDU a = loadBatch(first[0], first[1], first[2]);
        assertEquals(SW_OK, a.getSW());
        assertEquals(SW_OK, load(first[3]).getSW());
        ResponseAPDU paid = spendAll(new int[] { 0, 2 }, new byte[0][]);
        assertEquals(SW_OK, paid.getSW());
        assertEquals(SW_OK, clearSpent());
        byte[] reused0 = first[0].clone(); reused0[76] ^= 0x10;     // the nonce that was at place 0, another C
        byte[] new2 = edgeProof(4, 0);
        byte[] new4 = edgeProof(5, 0);
        ResponseAPDU filled = loadBatch(reused0, new2, new4);
        assertEquals(SW_OK, filled.getSW());
        assertArrayEquals(new byte[] { 0, 2, 4 }, filled.getData(), "the freed places first, in order, then the next that is empty");
        ResponseAPDU all = spendAll(new int[] { 0, 2, 4, 1, 3 }, new byte[0][]);
        assertEquals(SW_OK, all.getSW());
        assertTrue(signedForAll(all.getData(), new byte[][] { asSlot(reused0), asSlot(new2), asSlot(new4), asSlot(first[1]), asSlot(first[3]) }, new byte[0][], REFUND),
            "the new pieces' text where they went, and the old pieces' that stayed");
        assertFalse(signedForAll(all.getData(), new byte[][] { asSlot(first[0]), asSlot(first[2]), asSlot(new4), asSlot(first[1]), asSlot(first[3]) }, new byte[0][], REFUND),
            "and not the text that was in those places before");
    }

    /** Pay `output` amounts out of one place and check the signature against the message the test builds itself. */
    private void assertOutputsSigned(String what, byte[] piece, int place, byte[][] outputs, int[] groups) throws Exception {
        assertEquals(SW_OK, sw(beginCommand(place)), what);
        int at = 0, g = 0;
        while (at < outputs.length) {
            int n = Math.min(groups[g++ % groups.length], outputs.length - at);
            assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, concat(Arrays.copyOfRange(outputs, at, at + n)))), what + ": outputs " + at + " to " + (at + n - 1));
            at += n;
        }
        ResponseAPDU r = signAll();
        assertEquals(SW_OK, r.getSW(), what);
        assertTrue(signedForAll(r.getData(), new byte[][] { asSlot(piece) }, outputs, REFUND), what + ": signed over the amounts as decimal text");
    }

    @Test
    @DisplayName("Every output's amount is hashed as its decimal text, by the short division and by the long one: 0, 1, 9, 10, 99, 100, 255, 256, 32766, 32767, 32768, 32769, 65535, 65536, 1000000, 4294967295 and more; each alone, six to a command, one to a command, and in groups of every size")
    void testOutputAmountsAreHashedAsDecimal() throws Exception {
        long[] amounts = { 0, 1, 9, 10, 11, 99, 100, 101, 255, 256, 1000, 9999, 10000, 12345, 32766, 32767, 32768, 32769, 40000, 65535, 65536, 65537,
                           99999, 100000, 1000000, 16777215, 16777216, 999999999L, 1000000000L, 2147483647L, 2147483648L, 4294967294L, 4294967295L };
        byte[][] outputs = new byte[amounts.length][];
        for (int i = 0; i < amounts.length; i++) {
            byte[] b = blinded(i + 1);
            if (i % 5 == 1) { b = new byte[33]; b[0] = 0x02; }                       // a B_ of 02 and zeros
            if (i % 5 == 3) { b = new byte[33]; Arrays.fill(b, (byte) 0xff); b[0] = 0x03; }   // a B_ of 03 and ones
            outputs[i] = output(amounts[i], b);
        }
        simulator = freshCard();
        ready();
        byte[][] pieces = new byte[amounts.length + 6][];
        for (int i = 0; i < pieces.length; i++) pieces[i] = buildProof(KEYSET, 50 + i, i + 1);
        for (int at = 0; at < pieces.length; at += 3) {
            ResponseAPDU r = loadBatch(Arrays.copyOfRange(pieces, at, Math.min(pieces.length, at + 3)));
            assertEquals(SW_OK, r.getSW());
        }
        newTap();
        int place = 0;
        // each amount alone, as the only output of a payment
        for (int i = 0; i < amounts.length; i++) {
            assertOutputsSigned("amount " + amounts[i] + " alone", pieces[place], place, new byte[][] { outputs[i] }, new int[] { 1 });
            place++;
        }
        // every amount in one payment: six to a command (the most a command takes), then one to a command, then groups of every size
        assertOutputsSigned("all of them, six to a command", pieces[place], place, outputs, new int[] { 6 });
        place++;
        assertOutputsSigned("all of them, one to a command", pieces[place], place, outputs, new int[] { 1 });
        place++;
        assertOutputsSigned("all of them, in groups of 1 to 6", pieces[place], place, outputs, new int[] { 1, 2, 3, 4, 5, 6, 3, 2 });
        place++;
        // and over two pieces at once, the outputs following both pieces' text
        ResponseAPDU both = spendAll(new int[] { place, place + 1 }, Arrays.copyOfRange(outputs, 14, 24));
        assertEquals(SW_OK, both.getSW());
        assertTrue(signedForAll(both.getData(), new byte[][] { asSlot(pieces[place]), asSlot(pieces[place + 1]) }, Arrays.copyOfRange(outputs, 14, 24), REFUND), "ten outputs after two pieces");
    }

    // ---- the listings and the places named (GET_PIECES, P2 = 0, 3 and 2) -----------------------------------

    /** A second keyset, and a third that differs from the first in its last byte only. */
    static final String KEYSET_B = "00ab12cd34ef5678";
    static final String KEYSET_A2 = "0059534ce0bfa19b";

    private ResponseAPDU shortPieces(int from) { return transmit(new CommandAPDU(CLA, INS_GET_PIECES, from, 3, 256)); }
    private ResponseAPDU somePieces(byte[] places) { return transmit(new CommandAPDU(CLA, INS_GET_PIECES, 0, 2, places, 256)); }

    /** Every place as the card holds it: null where it is empty, and its slot as GET_PROOF gives it where it is not. */
    private byte[][] allSlots() {
        byte[] status = transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData();
        assertEquals(MAX_PROOFS, status.length);
        byte[][] s = new byte[MAX_PROOFS][];
        for (int i = 0; i < MAX_PROOFS; i++) s[i] = status[i] == 0 ? null : slot(i);
        return s;
    }

    /**
     * The whole listing a card is to give from P1 = `from`, worked out from the slots by the rule alone and not by asking the
     * card: next (1), then for each place that is not empty its tag, the place's number with 0x80 set where it is spent, and
     * for an unspent one its 81 bytes. A page is at most 255 bytes, and holds places while the next entry still fits; an
     * empty place costs nothing.
     */
    private static byte[] listingFrom(byte[][] slots, int from) {
        java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
        int length = 1, next = from;
        while (next < MAX_PROOFS) {
            int state = slots[next] == null ? 0 : slots[next][0];
            int cost = state == 1 ? 82 : state == 2 ? 1 : 0;
            if (length + cost > 255) break;
            if (state != 0) {
                body.write(state == 2 ? (0x80 | next) : next);
                if (state == 1) body.write(slots[next], 1, 81);
            }
            length += cost;
            next++;
        }
        return concat(new byte[] { (byte) next }, body.toByteArray());
    }

    /** A piece's keyset and date as the short listing names them: 8 and 4 bytes. */
    private static byte[] keysetAndDate(String keysetHex, long date) { return concat(hexToBytes(keysetHex), u32(date)); }

    /**
     * One entry of the short listing, written out by hand from the rule: the place (with 0x80 where its keyset and date follow),
     * those twelve bytes where `named` is given, and the size, or 0xFF and the amount where the amount is no power of two.
     */
    private static byte[] shortEntry(int place, byte[] named, long amount) {
        boolean power = amount != 0 && (amount & (amount - 1)) == 0;
        return concat(new byte[] { (byte) (place | (named != null ? 0x80 : 0)) }, named != null ? named : new byte[0],
            power ? new byte[] { (byte) Long.numberOfTrailingZeros(amount) } : concat(new byte[] { (byte) 0xFF }, u32(amount)));
    }

    /**
     * The short listing a card is to give from P1 = `from`, worked out from the slots by the rule alone: next, then for each
     * UNSPENT place in order its entry, naming the keyset and date where they are not those of the entry before it in this
     * answer (the first always names them); an answer is at most 255 bytes.
     */
    private static byte[] shortListingFrom(byte[][] slots, int from) {
        java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
        int length = 1, next = from;
        byte[] previous = null;
        while (next < MAX_PROOFS) {
            if (slots[next] != null && slots[next][0] == 1) {
                byte[] s = slots[next];
                byte[] kd = concat(Arrays.copyOfRange(s, 1, 9), Arrays.copyOfRange(s, 78, 82));
                boolean named = previous == null || !Arrays.equals(kd, previous);
                byte[] entry = shortEntry(next, named ? kd : null, readUint32(s, 9));
                if (length + entry.length > 255) break;
                body.write(entry, 0, entry.length);
                length += entry.length;
                previous = kd;
            }
            next++;
        }
        return concat(new byte[] { (byte) next }, body.toByteArray());
    }

    /** One entry of a short listing as a reader decodes it: the place, whether it named its keyset and date, and what it is worth. */
    private static final class ShortEntry {
        int place;
        boolean named;
        byte[] keyset, date;
        long amount;
        boolean power;
    }

    /** One answer of the short listing as a reader decodes it. The first entry must name its keyset and date; the rest carry the one before. */
    private static final class ShortAnswer {
        int next, length;
        final java.util.List<ShortEntry> entries = new java.util.ArrayList<>();
    }

    private static ShortAnswer decodeShort(byte[] d) {
        ShortAnswer a = new ShortAnswer();
        a.length = d.length;
        a.next = d[0] & 0xFF;
        int at = 1;
        byte[] keyset = null, date = null;
        while (at < d.length) {
            ShortEntry e = new ShortEntry();
            int b = d[at++] & 0xFF;
            e.place = b & 0x7F;
            e.named = (b & 0x80) != 0;
            if (e.named) {
                keyset = Arrays.copyOfRange(d, at, at + 8);
                date = Arrays.copyOfRange(d, at + 8, at + 12);
                at += 12;
            }
            assertNotNull(keyset, "the first entry of an answer names its keyset and date");
            e.keyset = keyset;
            e.date = date;
            int size = d[at++] & 0xFF;
            if (size == 0xFF) {
                e.amount = readUint32(d, at);
                at += 4;
            } else {
                assertTrue(size <= 31, "a size is a power of two from 0 to 31: " + size);
                e.amount = 1L << size;
                e.power = true;
            }
            a.entries.add(e);
        }
        assertEquals(d.length, at, "the answer is made of whole entries");
        return a;
    }

    /** The short listing read from place 0 to its end, as a phone reads it: every entry in order, and how many answers it took. */
    private java.util.List<ShortEntry> readShortListing(int[] answersOut) {
        java.util.List<ShortEntry> all = new java.util.ArrayList<>();
        int from = 0, answers = 0;
        while (from < MAX_PROOFS) {
            ResponseAPDU r = shortPieces(from);
            assertEquals(SW_OK, r.getSW(), "from " + from);
            assertTrue(r.getData().length <= 255, "an answer is at most 255 bytes: " + r.getData().length);
            ShortAnswer a = decodeShort(r.getData());
            assertTrue(a.next > from, "every answer moves on");
            if (!a.entries.isEmpty()) assertTrue(a.entries.get(0).named, "and begins with the twelve bytes");
            all.addAll(a.entries);
            from = a.next;
            answers++;
        }
        if (answersOut != null) answersOut[0] = answers;
        return all;
    }

    /** `n` pieces loaded three to a command, from place 0 on: piece i is `make(i)`. */
    private byte[][] loadMany(int n, java.util.function.IntFunction<byte[]> make) {
        byte[][] sent = new byte[n][];
        for (int i = 0; i < n; i++) sent[i] = make.apply(i);
        for (int at = 0; at < n; at += 3) {
            byte[][] group = Arrays.copyOfRange(sent, at, Math.min(n, at + 3));
            ResponseAPDU r = loadBatch(group);
            assertEquals(SW_OK, r.getSW(), "load from " + at);
            assertEquals(group.length, r.getData().length);
        }
        return sent;
    }

    /**
     * A card with empty, unspent and spent places: forty pieces (a few of them dated) loaded three to a command, ten of them
     * paid and freed, which leaves holes, two new ones put into the first two holes, and seven more paid and left spent.
     * Places 4, 9, 10, 17, 18, 19, 20, 33 and 40 to 127 are empty; 0, 5, 6, 12, 25, 26, 38 are spent; the rest are unspent.
     */
    private void mixedCard() {
        ready();
        byte[][] sent = new byte[40][];
        for (int i = 0; i < 40; i++) sent[i] = buildProof(KEYSET, 100 + i, i + 1, i % 7 == 3 ? 1900000000L : 0);
        for (int at = 0; at < 40; at += 3) {
            byte[][] group = Arrays.copyOfRange(sent, at, Math.min(40, at + 3));
            ResponseAPDU r = loadBatch(group);
            assertEquals(SW_OK, r.getSW());
            assertEquals(group.length, r.getData().length);
        }
        for (int h : new int[] { 2, 3, 4, 9, 10, 17, 18, 19, 20, 33 }) assertEquals(SW_OK, spend(h).getSW(), "paid " + h);
        assertEquals(SW_OK, clearSpent());
        ResponseAPDU filled = loadBatch(buildProof(KEYSET, 500, 61), buildProof(KEYSET, 501, 62, 1900000000L));
        assertArrayEquals(new byte[] { 2, 3 }, filled.getData());
        for (int s : new int[] { 0, 5, 6, 12, 25, 26, 38 }) assertEquals(SW_OK, spend(s).getSW(), "paid " + s);
    }

    /**
     * A card with places on both sides of 64: a hundred and twenty pieces of two keysets, now and then dated, mostly powers of
     * two and now and then not, loaded three to a command; eight paid and freed (holes below and above 64), three new ones put
     * into the first holes, and six more paid and left spent. Places 65, 66, 100, 101, 119 and 120 to 127 are empty; 0, 63, 67,
     * 99, 110 and 118 are spent; the rest (109 places) are unspent.
     */
    private void bigMixedCard() {
        ready();
        loadMany(120, i -> buildProof((i / 7) % 2 == 0 ? KEYSET : KEYSET_B, i % 5 == 3 ? 100 + i : 1L << (i % 12), i + 1, i % 17 == 5 ? 1900000000L : 0));
        for (int h : new int[] { 2, 3, 64, 65, 66, 100, 101, 119 }) assertEquals(SW_OK, spend(h).getSW(), "paid " + h);
        assertEquals(SW_OK, clearSpent());
        ResponseAPDU filled = loadBatch(buildProof(KEYSET, 4096, 131), buildProof(KEYSET_B, 777, 132, 1900000000L), buildProof(KEYSET_B, 2, 133));
        assertArrayEquals(new byte[] { 2, 3, 64 }, filled.getData());
        for (int s : new int[] { 0, 63, 67, 99, 110, 118 }) assertEquals(SW_OK, spend(s).getSW(), "paid " + s);
        byte[] d = info();
        assertEquals(109, d[3] & 0xFF);
        assertEquals(6, d[4] & 0xFF);
        assertEquals(13, d[5] & 0xFF);
    }

    @Test
    @DisplayName("GET_PIECES P2 = 0 and P2 = 3: from every starting place, on a card of empty, unspent and spent places on both sides of 64, each answer is what the rule gives from the slots, by a model built here from GET_PROOF; no PIN is asked for")
    void testTheListingsAreWhatTheRuleGives() {
        bigMixedCard();
        reselect();     // a new tap: the PIN is not verified, and neither listing asks for it
        byte[][] slots = allSlots();
        for (int from = 0; from < MAX_PROOFS; from++) {
            ResponseAPDU whole = pieces(from);
            assertEquals(SW_OK, whole.getSW(), "from " + from);
            assertArrayEquals(listingFrom(slots, from), whole.getData(), "whole page from place " + from);
            ResponseAPDU shortAnswer = shortPieces(from);
            assertEquals(SW_OK, shortAnswer.getSW(), "from " + from);
            assertArrayEquals(shortListingFrom(slots, from), shortAnswer.getData(), "short page from place " + from);
        }
        // walked to the end, the short listing names every unspent place once, in order, with what it is worth
        int[] answers = new int[1];
        java.util.List<ShortEntry> entries = readShortListing(answers);
        int k = 0;
        for (int i = 0; i < MAX_PROOFS; i++) {
            if (slots[i] == null || slots[i][0] != 1) continue;
            ShortEntry e = entries.get(k++);
            assertEquals(i, e.place);
            assertArrayEquals(Arrays.copyOfRange(slots[i], 1, 9), e.keyset, "place " + i + ": its keyset");
            assertArrayEquals(Arrays.copyOfRange(slots[i], 78, 82), e.date, "place " + i + ": its date");
            assertEquals(readUint32(slots[i], 9), e.amount, "place " + i + ": its worth");
        }
        assertEquals(109, k);
        assertEquals(k, entries.size());
        assertTrue(answers[0] < 43, "the short listing is far fewer answers than the whole form's: " + answers[0]);
    }

    @Test
    @DisplayName("The short listing of one keyset and one date is two bytes a piece after the first: next, then the first entry with 0x80 on its place, its keyset, its date and its size, and then the place and the size of each piece")
    void testTheShortListingIsTwoBytesAPieceAfterTheFirst() {
        ready();
        long[] amounts = { 1, 2, 4, 8, 1024 };
        for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        byte[] expected = concat(new byte[] { (byte) 0x80 },
            new byte[] { (byte) 0x80 }, hexToBytes(KEYSET), new byte[4], new byte[] { 0 },
            new byte[] { 1, 1 }, new byte[] { 2, 2 }, new byte[] { 3, 3 }, new byte[] { 4, 10 });
        ResponseAPDU r = shortPieces(0);
        assertEquals(SW_OK, r.getSW());
        assertArrayEquals(expected, r.getData());
        assertEquals(1 + 14 + 4 * 2, r.getData().length, "14 for the first, 2 for each of the four after it");
    }

    @Test
    @DisplayName("A second keyset or a second date in the middle of an answer brings the twelve bytes back, for that entry only: compared with the entry before it and with none other, whole (a keyset or a date that differs in its last byte counts)")
    void testASecondKeysetOrDateBringsTheTwelveBytesBack() {
        ready();
        long d1 = 1900000000L;
        Object[][] pieces = {
            // keyset, date, amount
            { KEYSET, 0L, 1L },        // 0: named (the first)
            { KEYSET, 0L, 2L },        // 1: as the one before
            { KEYSET_B, 0L, 4L },      // 2: another keyset: named
            { KEYSET_B, 0L, 8L },      // 3: as the one before
            { KEYSET_B, d1, 8L },      // 4: another date: named
            { KEYSET_B, d1, 16L },     // 5: as the one before
            { KEYSET, 0L, 1L },        // 6: back to the first keyset and no date: named again, since the entry before is not it
            { KEYSET_A2, 0L, 1L },     // 7: a keyset that differs in its last byte: named
            { KEYSET_A2, 1L, 1L },     // 8: a date that differs in its last byte: named
            { KEYSET_A2, 1L, 32L },    // 9: as the one before
        };
        for (int i = 0; i < pieces.length; i++) assertEquals(SW_OK, load(buildProof((String) pieces[i][0], (Long) pieces[i][2], i + 1, (Long) pieces[i][1])).getSW());
        byte[] expected = concat(new byte[] { (byte) 0x80 },
            shortEntry(0, keysetAndDate(KEYSET, 0), 1), shortEntry(1, null, 2),
            shortEntry(2, keysetAndDate(KEYSET_B, 0), 4), shortEntry(3, null, 8),
            shortEntry(4, keysetAndDate(KEYSET_B, d1), 8), shortEntry(5, null, 16),
            shortEntry(6, keysetAndDate(KEYSET, 0), 1),
            shortEntry(7, keysetAndDate(KEYSET_A2, 0), 1),
            shortEntry(8, keysetAndDate(KEYSET_A2, 1), 1), shortEntry(9, null, 32));
        assertArrayEquals(expected, shortPieces(0).getData());
        // the explicit bytes of two of them, for a reader to check its decoder against: place 2 and place 3
        byte[] two = shortEntry(2, keysetAndDate(KEYSET_B, 0), 4);
        assertEquals(1 + 12 + 1, two.length);
        assertEquals((byte) 0x82, two[0]);
        assertEquals(2, two[13]);
    }

    @Test
    @DisplayName("A new answer always starts with the twelve bytes, though the piece has the keyset and date of the one before it in the last answer, or of the place before the first one asked for")
    void testANewAnswerAlwaysStartsWithTheTwelveBytes() {
        ready();
        for (int i = 0; i < 6; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 1L << i, i + 1)).getSW());
        // from place 0, from the middle of a run of one keyset, and from an empty place after the pieces
        ResponseAPDU middle = shortPieces(3);
        assertArrayEquals(concat(new byte[] { (byte) 0x80 }, shortEntry(3, keysetAndDate(KEYSET, 0), 8), shortEntry(4, null, 16), shortEntry(5, null, 32)), middle.getData(),
            "from place 3: the first entry of the answer names them, though place 2 is the same");
        ResponseAPDU last = shortPieces(5);
        assertArrayEquals(concat(new byte[] { (byte) 0x80 }, shortEntry(5, keysetAndDate(KEYSET, 0), 32)), last.getData());
        // a full answer ends before a piece, and the next begins with it, named
        simulator = freshCard();
        ready();
        loadMany(128, i -> buildProof(KEYSET, 1L << (i % 32), i + 1));
        ShortAnswer first = decodeShort(shortPieces(0).getData());
        ShortAnswer second = decodeShort(shortPieces(first.next).getData());
        assertTrue(first.entries.get(0).named);
        assertFalse(first.entries.get(1).named);
        assertTrue(second.entries.get(0).named, "the second answer begins with the twelve bytes, though its first piece is the one the last answer ended with");
        assertFalse(second.entries.get(1).named);
    }

    @Test
    @DisplayName("An amount that is not a power of two gives 0xFF and the amount in four bytes, big-endian, in place of a size: 3, 1000, 0x01000001 and the rest; a power of two among them still gives its size; a named entry carries the amount too")
    void testAnAmountThatIsNoPowerOfTwoGivesFFAndFourBytes() {
        ready();
        long[] amounts = { 3, 1000, 0x01000001L, 5, 2, 6, 7, 0x80000001L, 4294967295L, 0x00FF0000L, 0x00010100L, 0x03000000L, 8, 12, 4294967294L, 2147483648L };
        for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        java.io.ByteArrayOutputStream expected = new java.io.ByteArrayOutputStream();
        expected.write(0x80);
        for (int i = 0; i < amounts.length; i++) {
            byte[] e = shortEntry(i, i == 0 ? keysetAndDate(KEYSET, 0) : null, amounts[i]);
            expected.write(e, 0, e.length);
        }
        ResponseAPDU r = shortPieces(0);
        assertArrayEquals(expected.toByteArray(), r.getData());
        // by hand: place 0 (3): 80 | keyset | date | FF 00 00 00 03, and place 1 (1000): 01 FF 00 00 03 E8
        byte[] d = r.getData();
        assertEquals((byte) 0x80, d[1]);
        assertEquals((byte) 0xFF, d[1 + 1 + 12]);
        assertArrayEquals(new byte[] { 0, 0, 0, 3 }, Arrays.copyOfRange(d, 15, 19));
        assertArrayEquals(new byte[] { 1, (byte) 0xFF, 0, 0, 3, (byte) 0xE8 }, Arrays.copyOfRange(d, 19, 25));
        assertArrayEquals(new byte[] { 2, (byte) 0xFF, 1, 0, 0, 1 }, Arrays.copyOfRange(d, 25, 31), "0x01000001");
        assertArrayEquals(new byte[] { 3, (byte) 0xFF, 0, 0, 0, 5 }, Arrays.copyOfRange(d, 31, 37));
        assertArrayEquals(new byte[] { 4, 1 }, Arrays.copyOfRange(d, 37, 39), "2 is a power of two: place 4, size 1");
    }

    @Test
    @DisplayName("Every power of two from 1 to 2^31 gives its size, 0 to 31, and its neighbours (one less, one more) give 0xFF and their amounts")
    void testEveryPowerOfTwoGivesItsSize() {
        ready();
        for (int k = 0; k < 32; k++) assertEquals(SW_OK, load(buildProof(KEYSET, 1L << k, k + 1)).getSW(), "2^" + k);
        byte[] d = shortPieces(0).getData();
        assertEquals(128, d[0] & 0xFF);
        assertEquals(1 + 14 + 31 * 2, d.length);
        assertEquals(0, d[14], "1 is size 0");
        for (int k = 1; k < 32; k++) {
            assertEquals(k, d[15 + 2 * (k - 1)] & 0xFF, "place number of 2^" + k);
            assertEquals(k, d[16 + 2 * (k - 1)] & 0xFF, "size of 2^" + k);
        }
        assertEquals(31, d[d.length - 1], "2^31 is size 31");
        // the neighbours: none is a power of two, and each says what it is worth
        simulator = freshCard();
        ready();
        java.util.List<Long> amounts = new java.util.ArrayList<>();
        for (int k = 2; k < 32; k++) { amounts.add((1L << k) - 1); amounts.add(1L << k); amounts.add((1L << k) + 1); }
        loadMany(amounts.size(), i -> buildProof(KEYSET, amounts.get(i), i + 1));
        java.util.List<ShortEntry> entries = readShortListing(null);
        assertEquals(amounts.size(), entries.size());
        for (int i = 0; i < amounts.size(); i++) {
            ShortEntry e = entries.get(i);
            assertEquals(i, e.place);
            assertEquals((long) amounts.get(i), e.amount, "place " + i);
            assertEquals(i % 3 == 1, e.power, "place " + i + " (" + amounts.get(i) + ") is " + (i % 3 == 1 ? "" : "not ") + "a power of two");
        }
    }

    @Test
    @DisplayName("Spent and empty places have no entry in the short listing, and a spent place between two of one keyset does not bring the twelve bytes back, nor does the keyset it had")
    void testTheShortListingSkipsSpentAndEmpty() {
        ready();
        String[] keysets = { KEYSET, KEYSET, KEYSET_B, KEYSET, KEYSET, KEYSET, KEYSET, KEYSET };
        for (int i = 0; i < keysets.length; i++) assertEquals(SW_OK, load(buildProof(keysets[i], 1L << i, i + 1)).getSW());
        assertEquals(SW_OK, spend(2).getSW(), "the piece of the other keyset, between two of the first");
        assertEquals(SW_OK, spend(5).getSW());
        byte[] expected = concat(new byte[] { (byte) 0x80 },
            shortEntry(0, keysetAndDate(KEYSET, 0), 1), shortEntry(1, null, 2), shortEntry(3, null, 8), shortEntry(4, null, 16),
            shortEntry(6, null, 64), shortEntry(7, null, 128));
        assertArrayEquals(expected, shortPieces(0).getData(), "places 2 and 5 are spent, 8 and on are empty: none is listed");
        // freed, they are empty, and still not listed
        assertEquals(SW_OK, clearSpent());
        assertArrayEquals(expected, shortPieces(0).getData());
        // listing from a spent place begins at the next piece, named
        assertArrayEquals(concat(new byte[] { (byte) 0x80 }, shortEntry(3, keysetAndDate(KEYSET, 0), 8), shortEntry(4, null, 16), shortEntry(6, null, 64), shortEntry(7, null, 128)),
            shortPieces(2).getData());
    }

    @Test
    @DisplayName("An empty card answers the single byte 0x80 (next: 128, nothing more to ask for); so does a start past the last piece; P1 of 128 or more is 6A83")
    void testAnEmptyCardAnswersTheSingleByte80() {
        ready();
        assertArrayEquals(new byte[] { (byte) 0x80 }, shortPieces(0).getData());
        assertArrayEquals(new byte[] { (byte) 0x80 }, shortPieces(127).getData());
        assertEquals(SW_OK, load(buildProof(KEYSET, 5, 1)).getSW());
        assertArrayEquals(new byte[] { (byte) 0x80 }, shortPieces(1).getData(), "after the only piece");
        for (int p1 : new int[] { 128, 129, 200, 255 }) {
            ResponseAPDU r = shortPieces(p1);
            assertEquals(SW_SLOT_OUT_OF_RANGE, r.getSW(), "P1 = " + p1);
            assertEquals(0, r.getData().length);
        }
    }

    @Test
    @DisplayName("A full card of one keyset and one date and powers of two takes exactly two answers: 121 pieces (255 bytes) and then 7, which together name every place once, in order")
    void testAFullCardOfPowersOfTwoTakesTwoAnswers() {
        ready();
        loadMany(128, i -> buildProof(KEYSET, 1L << (i % 32), i + 1));
        ResponseAPDU a = shortPieces(0);
        assertEquals(SW_OK, a.getSW());
        assertEquals(255, a.getData().length, "1 + 14 + 120 * 2");
        ShortAnswer first = decodeShort(a.getData());
        assertEquals(121, first.entries.size());
        assertEquals(121, first.next);
        ResponseAPDU b = shortPieces(first.next);
        assertEquals(SW_OK, b.getSW());
        ShortAnswer second = decodeShort(b.getData());
        assertEquals(7, second.entries.size());
        assertEquals(128, second.next);
        assertEquals(1 + 14 + 6 * 2, b.getData().length);
        int expected = 0;
        for (ShortEntry e : first.entries) { assertEquals(expected, e.place); assertEquals(1L << (expected % 32), e.amount); expected++; }
        for (ShortEntry e : second.entries) { assertEquals(expected, e.place); assertEquals(1L << (expected % 32), e.amount); expected++; }
        assertEquals(128, expected, "every place once, in order");
        int[] answers = new int[1];
        readShortListing(answers);
        assertEquals(2, answers[0]);
    }

    @Test
    @DisplayName("A full card of amounts that are no power of two, with the keyset changing at every place, pages correctly: every answer is at most 255 bytes and moves on, 14 pieces of 18 bytes to an answer, ten answers, every place once and as it is")
    void testAFullCardOfNonPowersWithAlternatingKeysetsPages() {
        ready();
        byte[][] sent = loadMany(128, i -> buildProof(i % 2 == 0 ? KEYSET : KEYSET_B, 1000 + 7L * i, i + 1, i % 3 == 0 ? 1900000000L : 0));
        int from = 0, answers = 0, seen = 0;
        while (from < MAX_PROOFS) {
            ResponseAPDU r = shortPieces(from);
            assertEquals(SW_OK, r.getSW());
            assertTrue(r.getData().length <= 255, "at most 255 bytes: " + r.getData().length);
            ShortAnswer a = decodeShort(r.getData());
            assertTrue(a.next > from, "moves on");
            assertEquals(a.next < MAX_PROOFS ? 1 + 14 * 18 : r.getData().length, r.getData().length, "14 entries of 18 bytes to an answer, but the last");
            for (ShortEntry e : a.entries) {
                assertEquals(seen, e.place, "every place once, in order");
                assertTrue(e.named, "the keyset changes at every place: every entry names them");
                assertArrayEquals(Arrays.copyOfRange(sent[seen], 0, 8), e.keyset);
                assertArrayEquals(Arrays.copyOfRange(sent[seen], 77, 81), e.date);
                assertEquals(1000 + 7L * seen, e.amount);
                assertFalse(e.power);
                seen++;
            }
            from = a.next;
            answers++;
        }
        assertEquals(128, seen);
        assertEquals(10, answers, "128 pieces at 14 to an answer");
    }

    @Test
    @DisplayName("The short listing asks for no PIN, changes nothing (not the slots, the log, the record or the PIN's state), says the same twice, and a locked card still gives it")
    void testTheShortListingNeedsNoPinAndChangesNothing() throws Exception {
        mixedCard();
        byte[] infoBefore = info();
        byte[] first = shortPieces(0).getData();
        assertArrayEquals(first, shortPieces(0).getData(), "asking twice says the same");
        assertArrayEquals(infoBefore, info());
        reselect();
        byte[] storage = field("proofStorage").clone(), record = field("cardRecord").clone(), cardLog = field("cardLog").clone();
        assertEquals(SW_OK, shortPieces(0).getSW(), "no PIN verified in this tap");
        assertEquals(SW_OK, shortPieces(77).getSW());
        assertArrayEquals(first, shortPieces(0).getData());
        assertArrayEquals(storage, field("proofStorage"));
        assertArrayEquals(record, field("cardRecord"));
        assertArrayEquals(cardLog, field("cardLog"));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, lock());
        assertArrayEquals(first, shortPieces(0).getData(), "a locked card still tells what it holds");
    }

    @Test
    @DisplayName("The short listing is gathered in the APDU buffer in one pass and sent once: an entry's cost is tested against the page before it is written, the place the next answer starts at is written first when the entries are known, no entry is sent by itself, nothing is measured in a pass of its own, and the chip's own compare says whether a place is named")
    void testTheShortListingIsOnePassAndOneSend() throws Exception {
        String code = appletCode();
        String shortBody = body(code, "private void processGetShort(", "private boolean shortNamed(");
        assertEquals(128, CashuApplet.MAX_PROOFS);
        assertEquals(255, CashuApplet.PAGE_MAX);
        assertEquals(18, CashuApplet.SHORT_MOST, "place, keyset (8), date (4), 0xFF, amount (4)");
        int start = shortBody.indexOf("short at = (short) 1;");
        int cost = shortBody.indexOf("short cost = (short)(2 + (named ? 12 : 0) + (size < 0 ? 4 : 0));");
        int fits = shortBody.indexOf("if ((short)(at + cost) > PAGE_MAX) break;");
        int firstWrite = shortBody.indexOf("buf[at++]");
        int next = shortBody.indexOf("buf[0] = (byte) next;");
        int outgoing = shortBody.indexOf("apdu.setOutgoing();");
        int length = shortBody.indexOf("apdu.setOutgoingLength(at);");
        int send = shortBody.indexOf("apdu.sendBytes((short) 0, at);");
        assertTrue(start > 0 && start < cost && cost < fits && fits < firstWrite && firstWrite < next && next < outgoing && outgoing < length && length < send,
            "the answer begins at 1; an entry's cost is known and tested against the page before it is written; the place the next answer starts at is written at 0 after the loop; the answer is sent once, after everything");
        assertEquals(1, count(shortBody, "apdu.sendBytes("), "one send: no entry is sent by itself");
        assertEquals(1, count(shortBody, "apdu.setOutgoingLength("), "one length, the answer's own, set once it is gathered");
        assertFalse(shortBody.contains("room") || shortBody.contains("length + cost") || shortBody.contains("SHORT_MOST"), "no flush and no measuring pass");
        assertTrue(shortBody.contains("(byte)(next | (short) 0x80)"), "0x80 on a place whose keyset and date follow");
        String named = body(code, "private boolean shortNamed(", "private short sizeOf(");
        assertEquals(2, count(named, "Util.arrayCompare("), "the keyset and the date compared by the chip");
        assertFalse(named.contains("sameBytes("), "and not by a loop in bytecode");
    }

    @Test
    @DisplayName("GET_PIECES P2 = 1, the brief listing of the sixty-four-place card, is gone: refused (6A86) like any form the card does not have")
    void testTheBriefListingIsGone() {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 5, 1)).getSW());
        for (int p1 : new int[] { 0, 1, 63, 64, 127 }) {
            ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_GET_PIECES, p1, 1, 256));
            assertEquals(SW_INCORRECT_P1P2, r.getSW(), "P1 = " + p1);
            assertEquals(0, r.getData().length);
        }
    }

    @Test
    @DisplayName("The whole listing names places above 63: a plain tag for an unspent place (0x40 for 64, 0x7E for 126), a spent place's number with 0x80 set (0xC6 for 70, 0xE4 for 100, 0xFF for 127), next is 128 at the end, and a full card pages in forty-three answers")
    void testTheWholeListingNamesPlacesAbove63() {
        ready();
        byte[][] sent = loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
        for (int p : new int[] { 3, 70, 100, 127 }) assertEquals(SW_OK, spend(p).getSW(), "paid " + p);
        reselect();
        // from 63: places 63, 64 and 65 are unspent, with their numbers for tags
        Page from63 = new Page(pieces(63).getData());
        assertEquals(63, from63.entries.get(0)[0]);
        assertEquals(0x3F, from63.entries.get(0)[3]);
        assertEquals(0x40, from63.entries.get(1)[3], "place 64: its number");
        assertEquals(0x41, from63.entries.get(2)[3]);
        assertEquals(1 + 3 * 82, from63.length);
        assertEquals(66, from63.next);
        assertArrayEquals(Arrays.copyOfRange(asSlot(sent[64]), 1, 82), (byte[]) from63.entries.get(1)[2], "and the piece of place 64");
        // walked from 0 to the end
        java.util.Map<Integer, Integer> tags = new java.util.HashMap<>();
        int from = 0, answers = 0;
        while (from < MAX_PROOFS) {
            Page page = new Page(pieces(from).getData());
            assertTrue(page.next > from);
            assertTrue(page.length <= 255);
            for (Object[] e : page.entries) tags.put((Integer) e[0], (Integer) e[3]);
            from = page.next;
            answers++;
        }
        assertEquals(128, tags.size(), "every place once");
        assertEquals(0x83, (int) tags.get(3), "a spent place below 64: its number and 0x80");
        assertEquals(0xC6, (int) tags.get(70));
        assertEquals(0xE4, (int) tags.get(100));
        assertEquals(0xFF, (int) tags.get(127));
        assertEquals(0x7E, (int) tags.get(126), "an unspent place: its number and nothing more");
        assertEquals(0x40, (int) tags.get(64));
        // the last page ends at 128, and a page may start on a spent place at the end
        Page last = new Page(pieces(127).getData());
        assertEquals(128, last.next);
        assertEquals(2, last.length);
        assertEquals(1, last.entries.size());
        assertEquals(0xFF, last.entries.get(0)[3]);
        assertEquals(2, last.entries.get(0)[1]);
        // the answers are as the rule says, from every page's start to the end
        byte[][] slots = allSlots();
        int count = 0;
        for (int f = 0; f < MAX_PROOFS; ) {
            byte[] expected = listingFrom(slots, f);
            assertArrayEquals(expected, pieces(f).getData());
            f = expected[0] & 0xFF;
            count++;
        }
        assertEquals(answers, count);
    }

    @Test
    @DisplayName("GET_PROOF names places 64 to 127 and answers them as it does the others; place 128 is not a place (6A83)")
    void testGetProofNamesPlacesAbove63() {
        ready();
        byte[][] sent = loadMany(128, i -> buildProof(KEYSET, 3 + i, i + 1, i % 9 == 0 ? 1900000000L : 0));
        for (int p : new int[] { 63, 64, 65, 100, 126, 127 }) {
            ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_GET_PROOF, p, 0, 256));
            assertEquals(SW_OK, r.getSW(), "place " + p);
            assertArrayEquals(asSlot(sent[p]), r.getData(), "place " + p);
        }
        assertEquals(SW_OK, spend(100).getSW());
        assertEquals(2, slot(100)[0], "a spent place above 63 reads as spent");
        assertEquals(SW_SLOT_OUT_OF_RANGE, sw(new CommandAPDU(CLA, INS_GET_PROOF, 128, 0, 256)));
        assertEquals(SW_SLOT_OUT_OF_RANGE, sw(new CommandAPDU(CLA, INS_GET_PROOF, 255, 0, 256)));
    }

    @Test
    @DisplayName("GET_PIECES P2 = 2 names places above 63, with repeats and in any order, answered as GET_PROOF gives them; place 128 among them is 6A83 and nothing is answered")
    void testSomePiecesAbove63() throws Exception {
        bigMixedCard();
        reselect();
        byte[] storage = field("proofStorage");
        int[][] asked = { { 64 }, { 65 }, { 127 }, { 100 }, { 63 }, { 67 }, { 99 }, { 70, 64, 63 }, { 127, 127, 100 }, { 65, 67, 70 }, { 110, 111, 112 } };
        for (int[] places : asked) {
            byte[] request = new byte[places.length];
            for (int i = 0; i < places.length; i++) request[i] = (byte) places[i];
            ResponseAPDU r = somePieces(request);
            String what = "places " + Arrays.toString(places);
            assertEquals(SW_OK, r.getSW(), what);
            assertEquals(82 * places.length, r.getData().length, what);
            for (int i = 0; i < places.length; i++) {
                byte[] got = Arrays.copyOfRange(r.getData(), 82 * i, 82 * i + 82);
                assertArrayEquals(Arrays.copyOfRange(storage, places[i] * 82, places[i] * 82 + 82), got, what + ": place " + places[i]);
                if (placeStatus(places[i]) != 0) assertArrayEquals(slot(places[i]), got, what + ": place " + places[i] + " as GET_PROOF gives it");
            }
        }
        assertEquals(SW_SLOT_OUT_OF_RANGE, somePieces(new byte[] { (byte) 128 }).getSW());
        assertEquals(SW_SLOT_OUT_OF_RANGE, somePieces(new byte[] { 1, 127, (byte) 128 }).getSW());
        assertEquals(0, somePieces(new byte[] { 1, (byte) 128, 2 }).getData().length, "and none of the others is answered");
        assertEquals(SW_OK, somePieces(new byte[] { 127 }).getSW(), "127 is the last place");
    }

    @Test
    @DisplayName("GET_PIECES P2 = 2: one, two or three places, in any order and repeated, each answered as GET_PROOF gives it (status, then 81 bytes), whatever its state; 6700 for none and for four; 6A83 for place 128")
    void testSomePieces() throws Exception {
        mixedCard();
        reselect();
        byte[] storage = field("proofStorage");
        // 1 unspent; 0 spent; 4 empty after being freed; 50 never used; 3 dated and unspent (loaded into a hole)
        int[][] asked = { { 1 }, { 0 }, { 4 }, { 50 }, { 3 }, { 63 }, { 1, 0 }, { 0, 1 }, { 4, 3 }, { 1, 0, 4 }, { 4, 0, 1 }, { 3, 50, 0 },
                          { 1, 1 }, { 0, 0, 0 }, { 3, 1, 3 }, { 7, 7, 7 }, { 12, 12 }, { 63, 0, 63 }, { 64 }, { 127 }, { 127, 64, 0 } };
        for (int[] places : asked) {
            byte[] request = new byte[places.length];
            for (int i = 0; i < places.length; i++) request[i] = (byte) places[i];
            ResponseAPDU r = somePieces(request);
            String what = "places " + Arrays.toString(places);
            assertEquals(SW_OK, r.getSW(), what);
            assertEquals(82 * places.length, r.getData().length, what);
            for (int i = 0; i < places.length; i++) {
                byte[] got = Arrays.copyOfRange(r.getData(), 82 * i, 82 * i + 82);
                int status = placeStatus(places[i]);
                if (status != 0) assertArrayEquals(slot(places[i]), got, what + ": place " + places[i] + " as GET_PROOF gives it");
                assertArrayEquals(Arrays.copyOfRange(storage, places[i] * 82, places[i] * 82 + 82), got, what + ": place " + places[i] + ", the slot itself, in the order asked");
                assertEquals(status, got[0], what + ": its state, whatever it is");
            }
        }
        assertArrayEquals(new byte[82], Arrays.copyOfRange(somePieces(new byte[] { 4 }).getData(), 0, 82), "an empty place is nothing: a status of 0 and zeros");
        // the wrong number of places
        assertEquals(SW_WRONG_LENGTH, transmit(new CommandAPDU(CLA, INS_GET_PIECES, 0, 2, 256)).getSW(), "none: no data");
        assertEquals(SW_WRONG_LENGTH, somePieces(new byte[0]).getSW(), "none: empty data");
        assertEquals(SW_WRONG_LENGTH, somePieces(new byte[] { 0, 1, 2, 3 }).getSW(), "four");
        assertEquals(SW_WRONG_LENGTH, somePieces(new byte[] { 1, 1, 1, 1 }).getSW(), "four, the same one");
        assertEquals(SW_WRONG_LENGTH, somePieces(new byte[40]).getSW(), "forty");
        assertEquals(0, somePieces(new byte[] { 0, 1, 2, 3 }).getData().length, "and nothing is answered with a refusal");
        // a place that is not one
        assertEquals(SW_SLOT_OUT_OF_RANGE, somePieces(new byte[] { (byte) 128 }).getSW());
        assertEquals(SW_SLOT_OUT_OF_RANGE, somePieces(new byte[] { 0, (byte) 128 }).getSW(), "anywhere among them");
        assertEquals(SW_SLOT_OUT_OF_RANGE, somePieces(new byte[] { 1, 2, (byte) 255 }).getSW());
        assertEquals(0, somePieces(new byte[] { 1, (byte) 128, 2 }).getData().length, "and none of the others is answered");
        // it asks for no PIN and changes nothing
        byte[] before = storage.clone();
        assertEquals(SW_OK, somePieces(new byte[] { 1, 2, 3 }).getSW());
        assertArrayEquals(before, field("proofStorage"));
    }

    // ---- places 64 to 127 in every command that names a place ------------------------------

    @Test
    @DisplayName("A payment made of places above 63 signs and burns them: places 64, 100 and 127 with one below 64, into an output, signed over their own text, each burned and no other; a place 128 anywhere in the list is 6A83 and burns nothing")
    void testAPaymentOfPlacesAbove63SignsAndBurnsThem() throws Exception {
        ready();
        byte[][] sent = loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
        byte[][] outputs = { output(300, blinded(7)) };
        int[] places = { 127, 64, 100, 3 };
        byte[][] named = new byte[places.length][];
        long worth = 0;
        for (int i = 0; i < places.length; i++) { named[i] = asSlot(sent[places[i]]); worth += 1 + places[i]; }
        ResponseAPDU r = spendAll(places, outputs);
        assertEquals(SW_OK, r.getSW());
        assertTrue(signedForAll(r.getData(), named, outputs, REFUND), "signed over the text of those pieces, in the order named");
        for (int p = 0; p < MAX_PROOFS; p++) {
            boolean burned = p == 127 || p == 64 || p == 100 || p == 3;
            assertEquals(burned ? 2 : 1, slot(p)[0], "place " + p);
        }
        assertEquals(128 * 129 / 2 - worth, balance());
        // a place that is not one, among places that are
        assertEquals(SW_SLOT_OUT_OF_RANGE, sw(beginCommand(5, 128)), "place 128");
        assertEquals(SW_SLOT_OUT_OF_RANGE, sw(beginCommand(128)));
        assertEquals(SW_SLOT_OUT_OF_RANGE, sw(beginCommand(66, 255, 67)));
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "and no payment is begun by any of them");
        assertEquals(1, slot(5)[0]);
        // a spent place above 63 is spent, and an empty one is empty
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(beginCommand(100)), "spent");
        // the receipts and the log count the pieces: four
        assertArrayEquals(new long[] { T0, worth, 4, 0, 0 }, logTap(0));
    }

    @Test
    @DisplayName("CLEAR_SPENT frees spent places above 63 as it does the others, and says how many; the places are then empty, and the next pieces go to the first empty places in order, 70, 100 and 127 among them")
    void testClearSpentFreesPlacesAbove63() {
        ready();
        loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
        for (int p : new int[] { 70, 100, 127, 5 }) assertEquals(SW_OK, spend(p).getSW(), "paid " + p);
        ResponseAPDU cleared = transmit(new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1));
        assertEquals(SW_OK, cleared.getSW());
        assertEquals(4, cleared.getData()[0], "four places freed: 5, 70, 100 and 127");
        assertEquals(0, transmit(new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1)).getData()[0], "and a second finds none");
        byte[] status = transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData();
        for (int p : new int[] { 70, 100, 127, 5 }) assertEquals(0, status[p], "place " + p + " is empty");
        assertEquals(124, info()[3] & 0xFF);
        assertEquals(0, info()[4] & 0xFF);
        assertEquals(4, info()[5] & 0xFF);
        ResponseAPDU put = loadBatch(buildProof(KEYSET, 9, 501), buildProof(KEYSET, 9, 502), buildProof(KEYSET, 9, 503));
        assertArrayEquals(new byte[] { 5, 70, 100 }, put.getData(), "the first empty places, in order");
        assertArrayEquals(new byte[] { 127 }, load(buildProof(KEYSET, 9, 504)).getData());
        assertEquals(SW_NO_SPACE, load(buildProof(KEYSET, 9, 505)).getSW());
        // the count freed is a byte: all hundred and twenty-eight at once is 0x80, read as unsigned
        simulator = freshCard();
        ready();
        loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
        for (int at = 0; at < 128; at += 32) {
            int[] group = new int[32];
            for (int j = 0; j < 32; j++) group[j] = at + j;
            assertEquals(SW_OK, spendAll(group, new byte[0][]).getSW(), "places " + at + " to " + (at + 31));
        }
        ResponseAPDU all = transmit(new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1));
        assertEquals(SW_OK, all.getSW());
        assertEquals(128, all.getData()[0] & 0xFF, "128 freed at once");
    }

    @Test
    @DisplayName("GET_INFO counts to 128 in each of its three counts, as unsigned bytes: 128 unspent is 0x80, 128 spent is 0x80, 128 empty is 0x80, and a mixed card's three add up to 128")
    void testTheInfoCountsGoTo128() {
        assertEquals(128, info()[5] & 0xFF, "128 empty");
        assertEquals((byte) 0x80, info()[5]);
        ready();
        loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
        byte[] d = info();
        assertEquals(128, d[2] & 0xFF, "places");
        assertEquals(128, d[3] & 0xFF, "128 unspent");
        assertEquals(0, d[4]);
        assertEquals(0, d[5]);
        assertEquals((byte) 0x80, d[3]);
        // 8 paid and freed, 20 paid and left: 100 unspent, 20 spent, 8 empty
        int[] eight = new int[8], twenty = new int[20];
        for (int i = 0; i < 8; i++) eight[i] = 100 + i;
        for (int i = 0; i < 20; i++) twenty[i] = 8 + i;
        assertEquals(SW_OK, spendAll(eight, new byte[0][]).getSW());
        assertEquals(SW_OK, clearSpent());
        assertEquals(SW_OK, spendAll(twenty, new byte[0][]).getSW());
        d = info();
        assertEquals(100, d[3] & 0xFF);
        assertEquals(20, d[4] & 0xFF);
        assertEquals(8, d[5] & 0xFF);
        assertEquals(128, (d[3] & 0xFF) + (d[4] & 0xFF) + (d[5] & 0xFF));
        assertEquals(128 - 8, transmit(new CommandAPDU(CLA, INS_GET_PROOF_COUNT, 0, 0, 1)).getData()[0] & 0xFF, "GET_PROOF_COUNT counts every place that is not empty");
        byte[] status = transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData();
        assertEquals(128, status.length, "GET_SLOT_STATUS gives 128 bytes");
        for (int p = 0; p < 128; p++) assertEquals(p >= 100 && p < 108 ? 0 : p >= 8 && p < 28 ? 2 : 1, status[p], "place " + p);
        // all spent
        simulator = freshCard();
        ready();
        loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
        for (int at = 0; at < 128; at += 32) {
            int[] group = new int[32];
            for (int j = 0; j < 32; j++) group[j] = at + j;
            assertEquals(SW_OK, spendAll(group, new byte[0][]).getSW());
        }
        d = info();
        assertEquals(0, d[3]);
        assertEquals(128, d[4] & 0xFF, "128 spent");
        assertEquals(0, d[5]);
        assertEquals(128, transmit(new CommandAPDU(CLA, INS_GET_PROOF_COUNT, 0, 0, 1)).getData()[0] & 0xFF);
        assertEquals(0, balance());
        assertEquals(SW_OK, clearSpent());
        d = info();
        assertEquals(128, d[5] & 0xFF, "and 128 empty again");
        assertEquals(0, d[3]);
        assertEquals(0, d[4]);
    }

    @Test
    @DisplayName("GET_BALANCE sums all hundred and twenty-eight pieces, those above 63 included (1 + 2 + ... + 128 = 8256, and with large ones a total past a short); the places above 63 count when unspent and not when spent")
    void testTheBalanceSums128Pieces() {
        ready();
        loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
        assertEquals(8256, balance());
        assertEquals(SW_OK, spend(127).getSW());
        assertEquals(8256 - 128, balance(), "a spent place above 63 is not counted");
        simulator = freshCard();
        ready();
        loadMany(128, i -> buildProof(KEYSET, 33_000_000L + i, i + 1));
        assertEquals(128 * 33_000_000L + 8128, balance(), "a total that needs more than three bytes");
    }

    @Test
    @DisplayName("Places above 63 are looked at when a piece is loaded and when anything asks if the card is in use: a copy of a piece at place 100 is refused as on the card already (6A94), and a card whose only unspent piece is above 63 is in use (6A8D)")
    void testPlacesAbove63AreLookedAt() {
        ready();
        loadMany(101, i -> buildProof(KEYSET, 1 + i, i + 1));
        assertEquals(SW_PIECE_ON_CARD, load(buildProof(KEYSET, 5, 101)).getSW(), "the nonce of the piece at place 100, with another amount");
        assertEquals(101, info()[3] & 0xFF, "and it was not stored");
        // everything but the piece at place 100 is paid and freed: the card is in use
        for (int at = 0; at < 100; at += 32) {
            int n = Math.min(32, 100 - at);
            int[] group = new int[n];
            for (int j = 0; j < n; j++) group[j] = at + j;
            assertEquals(SW_OK, spendAll(group, new byte[0][]).getSW());
        }
        assertEquals(SW_OK, clearSpent());
        assertEquals(1, info()[3] & 0xFF, "one unspent piece, at place 100");
        assertEquals(1, slot(100)[0]);
        assertEquals(SW_CARD_IN_USE, ownerSetCard(MINT, REFUND), "in use, though every place below 100 is empty");
        assertEquals(SW_OK, spend(100).getSW());
        assertEquals(SW_OK, clearSpent());
        assertEquals(SW_OK, ownerSetCard(MINT, REFUND), "and not in use when it is paid and freed");
    }

    // ---- a payment may name every place the card has -----------------------------------------

    /** All the places 0 to n-1 of the card, in an order that is not the order they lie in: (5k + 3) mod 128, which is a permutation of the 128. */
    private static int[] scrambled(int n) {
        int[] places = new int[n];
        for (int k = 0; k < n; k++) places[k] = (5 * k + 3) % 128;
        return places;
    }

    @Test
    @DisplayName("A payment of 33 places, of 64 and of all 128 on a full card each sign once, over the text of every place named in the order named and then the outputs; every place named is burned and no other; the balance, the counts, the log entry and a receipt are right; SPEND_ALL_AGAIN gives the signature again; and the pieces count, a byte, stops at 255")
    void testAPaymentOfManyPlacesSignsOnce() throws Exception {
        for (int n : new int[] { 33, 64, 128 }) {
            String what = n + " places";
            simulator = freshCard();
            ready();
            byte[][] sent = loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
            int[] places = scrambled(n);
            byte[][] named = new byte[n][];
            boolean[] burned = new boolean[128];
            long worth = 0;
            for (int k = 0; k < n; k++) {
                named[k] = asSlot(sent[places[k]]);
                burned[places[k]] = true;
                worth += 1 + places[k];
            }
            byte[][] outputs = { output(3, blinded(1)), output(5, blinded(2)) };
            ResponseAPDU begun = transmit(beginCommand(places));
            assertEquals(SW_OK, begun.getSW(), what);
            assertEquals(worth, readUint32(begun.getData(), 0), what + ": BEGIN answers what the places are worth, together");
            assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, concat(outputs))), what);
            ResponseAPDU r = transmit(SIGN_ALL);
            assertEquals(SW_OK, r.getSW(), what);
            assertEquals(64, r.getData().length, what + ": a signature, and no wait: there is no limit on a payment");
            byte[] sig = r.getData();
            assertTrue(signedForAll(sig, named, outputs, REFUND), what + ": signed over secret and C of every place named, in order, and then the outputs");
            byte[][] swapped = named.clone();
            swapped[0] = named[n - 1];
            swapped[n - 1] = named[0];
            assertFalse(signedForAll(sig, swapped, outputs, REFUND), what + ": in the order named");
            assertFalse(signedForAll(sig, Arrays.copyOf(named, 32), outputs, REFUND), what + ": and not the first 32 alone");
            assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), what + ": one signature for one beginning");
            // every place named is burned, and no other
            byte[] status = transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData();
            for (int p = 0; p < 128; p++) assertEquals(burned[p] ? 2 : 1, status[p], what + ": place " + p);
            assertEquals(8256 - worth, balance(), what);
            byte[] d = info();
            assertEquals(128 - n, d[3] & 0xFF, what + ": unspent");
            assertEquals(n, d[4] & 0xFF, what + ": spent");
            assertEquals(0, d[5] & 0xFF, what + ": empty");
            assertArrayEquals(new long[] { T0, worth, n, 0, 0 }, logTap(0), what + ": the log's entry: the sats and the number of pieces, a byte");
            assertArrayEquals(new long[] { 128, 8256 }, logLoaded(0), what + ": beside what was put on");
            assertEquals(SW_OK, allowLoad());
            Held held = heldReceipts();
            assertEquals(1, held.count, what + ": a receipt");
            assertArrayEquals(receiptFor(T0, worth, named, outputs), held.receipts.get(0), what + ": of that payment");
            assertEquals(SW_OK, verify(TEST_PIN));
            ResponseAPDU again = transmit(new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64));
            assertEquals(SW_OK, again.getSW(), what);
            assertArrayEquals(sig, again.getData(), what + ": SPEND_ALL_AGAIN gives that signature again");
            assertEquals(SW_OK, allowLoad());
            assertEquals(1, heldReceipts().count, what + ": and that is not a payment");
            if (n == 128) {
                // a second payment of all 128 in the same tap: the pieces count stops at 255, the sats add up
                assertEquals(SW_OK, clearSpent());
                loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
                ResponseAPDU second = spendAll(places, new byte[0][]);
                assertEquals(SW_OK, second.getSW());
                assertArrayEquals(new long[] { T0, 2 * worth, 255, 0, 0 }, logTap(0), "128 and 128 pieces in one tap are 255, the most a byte holds");
                assertArrayEquals(new long[] { 255, 2 * 8256 }, logLoaded(0), "as the pieces put on");
                assertEquals(2 * worth, logSats());
            }
        }
    }

    @Test
    @DisplayName("More than 128 bytes to SPEND_ALL_BEGIN is 6A96 whatever they say (before the places are looked at), burns nothing and begins no payment: 129, 130, 200 and 255 bytes; 128 are a payment")
    void testMoreThan128PlacesIsTooMany() {
        ready();
        loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
        for (int len : new int[] { 129, 130, 200, 255 }) {
            byte[] places = new byte[len];
            for (int k = 0; k < len; k++) places[k] = (byte) (k % 128);
            // 255 bytes with an Le byte after them is more than jCardSim's buffer takes (it answers 6F00, as it does for GET_PIECES P2 = 2): no Le there
            ResponseAPDU r = transmit(len == 255 ? new CommandAPDU(CLA, INS_SPEND_ALL_BEGIN, 0, 0, places) : new CommandAPDU(CLA, INS_SPEND_ALL_BEGIN, 0, 0, places, 4));
            assertEquals(SW_TOO_MANY, r.getSW(), len + " bytes");
            assertEquals(0, r.getData().length, len + " bytes");
            assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), len + " bytes: no payment is begun");
            assertEquals(128, info()[3] & 0xFF, len + " bytes: nothing burned");
            assertEquals(8256, balance());
        }
        // not even places that are not places: the count is looked at first
        byte[] nonsense = new byte[129];
        Arrays.fill(nonsense, (byte) 200);
        assertEquals(SW_TOO_MANY, sw(new CommandAPDU(CLA, INS_SPEND_ALL_BEGIN, 0, 0, nonsense, 4)));
        // 128 are a payment
        int[] all = new int[128];
        for (int i = 0; i < 128; i++) all[i] = i;
        ResponseAPDU r = spendAll(all, new byte[0][]);
        assertEquals(SW_OK, r.getSW());
        assertEquals(0, balance());
        assertEquals(128, info()[4] & 0xFF);
    }

    @Test
    @DisplayName("The checks hold for every place named, however far down the list: a place named twice, a spent one, an empty one, one that is not a place (128), and one of another date, at the 41st or the 100th place of the list, each refused with its own word and nothing burned")
    void testTheChecksHoldForEveryPlaceNamedUpTo128() {
        ready();
        // places 0 to 125 hold pieces; 125 is dated; 124 is paid; 126 and 127 are empty
        loadMany(126, i -> buildProof(KEYSET, 1 + i, i + 1, i == 125 ? 1900000000L : 0));
        assertEquals(SW_OK, spend(124).getSW());
        assertEquals(125, info()[3] & 0xFF);
        Object[][] cases = {
            { "a place named twice", 5, SW_WRONG_DATA },
            { "a spent place", 124, SW_CONDITIONS_NOT_SATIS },
            { "an empty place", 126, SW_SLOT_EMPTY },
            { "a place that is not one", 128, SW_SLOT_OUT_OF_RANGE },
            { "a piece of another date", 125, SW_WRONG_DATA },
        };
        for (int at : new int[] { 40, 99 }) {
            for (Object[] c : cases) {
                int[] named = new int[100];
                for (int i = 0; i < 100; i++) named[i] = i;
                named[at] = (Integer) c[1];
                assertEquals((int) (Integer) c[2], sw(beginCommand(named)), c[0] + " at the " + (at + 1) + "th of a hundred");
                assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), c[0] + ": no payment is begun");
                assertEquals(125, info()[3] & 0xFF, c[0] + ": nothing burned");
            }
        }
        // and a hundred good ones are a payment
        int[] good = new int[100];
        for (int i = 0; i < 100; i++) good[i] = i;
        assertEquals(SW_OK, spendAll(good, new byte[0][]).getSW());
        assertEquals(25, info()[3] & 0xFF);
    }

    @Test
    @DisplayName("A payment of 128 pieces that is over the limit on one payment waits as its sum says (1280 under 100: 13 limits' worth, 54 answers of 00 01) and burns nothing until the last SPEND_ALL_SIGN, which gives the one signature and burns all 128 at once")
    void testAPaymentOf128PlacesWaitsAsItsSumSays() throws Exception {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 100));
        byte[][] sent = loadMany(128, i -> buildProof(KEYSET, 10, i + 1));
        newTap();
        int[] all = new int[128];
        byte[][] named = new byte[128][];
        for (int i = 0; i < 128; i++) { all[i] = i; named[i] = asSlot(sent[i]); }
        byte[] storage = field("proofStorage").clone();
        ResponseAPDU begun = transmit(beginCommand(all));
        assertEquals(SW_OK, begun.getSW());
        assertEquals(1280, readUint32(begun.getData(), 0));
        for (int k = 1; k <= 54; k++) {
            assertNotYet(transmit(SIGN_ALL), "wait " + k + " of 54");
            assertArrayEquals(storage, field("proofStorage"), "nothing burned in wait " + k);
        }
        ResponseAPDU sig = transmit(SIGN_ALL);
        assertEquals(SW_OK, sig.getSW());
        assertEquals(64, sig.getData().length, "the one signature, after the 54th");
        assertTrue(signedForAll(sig.getData(), named, new byte[0][], REFUND));
        for (int p = 0; p < 128; p++) assertEquals(2, slot(p)[0], "place " + p + " is burned by the last SIGN");
        assertArrayEquals(new long[] { T0, 1280, 128, 0, 2 }, logTap(0), "128 pieces, 1280 sats, and the flag that it was waited for");
        // a limit lower or higher: the wait is as the sum says
        for (long c : new long[] { 1280, 1279, 1243, 1242, 1241, 640, 639, 10 }) {
            assertEquals(waitsRule(c, 1280, 0), payWaitsOf128(c), "1280 under a limit of " + c);
        }
    }

    @Test
    @DisplayName("A payment's wait is its own sum's and nothing left over from the one before it in the same tap: two payments of 64 places of 10 under a limit on one payment of 500 are each 640, one limit past the first, 4 answers of 00 01 each")
    void testAPaymentWaitsForItsOwnSumNotForTheOneBefore() throws Exception {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 500));
        loadMany(128, i -> buildProof(KEYSET, 10, i + 1));
        newTap();
        int[] firstHalf = new int[64], secondHalf = new int[64];
        for (int i = 0; i < 64; i++) { firstHalf[i] = i; secondHalf[i] = 64 + i; }
        ResponseAPDU a = spendAll(firstHalf, new byte[0][]);
        assertEquals(SW_OK, a.getSW());
        assertEquals(64, a.getData().length, "the first payment's one signature");
        assertEquals(waitsRule(500, 640, 0), waitsTaken(), "640 under 500: two limits' worth");
        ResponseAPDU b = spendAll(secondHalf, new byte[0][]);
        assertEquals(SW_OK, b.getSW());
        assertEquals(64, b.getData().length, "the second payment's one signature");
        assertEquals(waitsRule(500, 640, 0), waitsTaken(), "the second is waited for by its own sum, as the first was, in the same tap");
        assertEquals(0, balance());
        // and a small one after a large one is not made to wait for the large one's count of places
        simulator = freshCard();
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 500));
        loadMany(128, i -> buildProof(KEYSET, 10, i + 1));
        newTap();
        int[] big = new int[100];
        for (int i = 0; i < 100; i++) big[i] = i;
        assertEquals(SW_OK, spendAll(big, new byte[0][]).getSW());
        assertEquals(waitsRule(500, 1000, 0), waitsTaken(), "1000 under 500: two limits' worth");
        assertEquals(SW_OK, spendAll(new int[] { 100, 101 }, new byte[0][]).getSW());
        assertEquals(waitsRule(500, 20, 0, true), waitsTaken(), "20 sats is under the limit, but it is the tap's second payment: the five seconds, and not the large one's count");
    }

    /** A full card of 128 pieces of 10, under a limit on one payment of `limit`, paid all at once: how many waits. */
    private int payWaitsOf128(long limit) throws Exception {
        simulator = freshCard();
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, limit));
        loadMany(128, i -> buildProof(KEYSET, 10, i + 1));
        newTap();
        int[] all = new int[128];
        for (int i = 0; i < 128; i++) all[i] = i;
        ResponseAPDU r = spendAll(all, new byte[0][]);
        assertEquals(SW_OK, r.getSW());
        assertEquals(64, r.getData().length);
        assertEquals(0, balance());
        return waitsTaken();
    }

    @Test
    @DisplayName("The day's limit is charged the whole sum of the places named: 128 pieces of 10 are 1280, refused (6A8F, nothing burned) under a day of 1000, the first hundred are exactly 1000 and go, one more is refused, and a day of 1280 takes all 128 and counts 1280")
    void testTheDaysLimitIsChargedTheWholeSumOfManyPlaces() {
        readyWithLimit(1000);
        loadMany(128, i -> buildProof(KEYSET, 10, i + 1));
        newTap();
        int[] all = new int[128], hundred = new int[100];
        for (int i = 0; i < 128; i++) all[i] = i;
        for (int i = 0; i < 100; i++) hundred[i] = i;
        assertEquals(SW_OK, sw(beginCommand(all)), "1280 is begun: the day is asked about at SIGN, when the payment's change is known");
        assertEquals(SW_OVER_LIMIT, sw(SIGN_ALL), "1280 is over a day of 1000");
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "and refused, the payment is gone");
        assertEquals(128, info()[3] & 0xFF, "nothing burned");
        assertEquals(1, logRefused(), "written down once, for the one payment");
        assertEquals(SW_OK, spendAll(hundred, new byte[0][]).getSW(), "100 pieces are 1000, the limit exactly");
        assertEquals(1000, spentToday(), "charged the whole sum");
        assertEquals(SW_OVER_LIMIT, spend(100).getSW(), "and one piece more is over");
        assertEquals(28, info()[3] & 0xFF);
        // a day of 1280 takes all 128
        simulator = freshCard();
        readyWithLimit(1280);
        loadMany(128, i -> buildProof(KEYSET, 10, i + 1));
        newTap();
        ResponseAPDU r = spendAll(all, new byte[0][]);
        assertEquals(SW_OK, r.getSW());
        assertEquals(1280, spentToday());
        assertEquals(0, balance());
    }

    @Test
    @DisplayName("A payment of 128 places with the card pulled before SPEND_ALL_SIGN burns nothing: the SIGN that follows is 6985, every place is still unspent, the log, the receipts and the last signature are as they were; and the payment begun again goes through")
    void testAPaymentOf128PlacesWithTheCardPulledBurnsNothing() throws Exception {
        ready();
        loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
        int[] all = new int[128];
        for (int i = 0; i < 128; i++) all[i] = i;
        byte[] storage = field("proofStorage").clone(), receipts = field("cardReceipts").clone(), cardLog = field("cardLog").clone(), lastSig = field("lastSig").clone();
        assertEquals(SW_OK, sw(beginCommand(all)));
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, output(9, blinded(3)))));
        simulator.reset();
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "the payment went with the power");
        assertArrayEquals(storage, field("proofStorage"));
        assertArrayEquals(receipts, field("cardReceipts"));
        assertArrayEquals(cardLog, field("cardLog"));
        assertArrayEquals(lastSig, field("lastSig"));
        assertEquals(8256, balance());
        // begun again, it is a payment
        ResponseAPDU r = spendAll(all, new byte[][] { output(9, blinded(3)) });
        assertEquals(SW_OK, r.getSW());
        assertEquals(0, balance());
    }

    @Test
    @DisplayName("A transaction that cannot be begun at the burn (jCardSim can leave one in progress; a card whose commit buffer is full throws the same TransactionException) is 6A96, nothing burned, no signature sent and no receipt, the card still works, and the payment begun again is a payment")
    void testAFailedBurnIs6A96AndBurnsNothing() throws Exception {
        ready();
        loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
        int[] all = new int[128];
        for (int i = 0; i < 128; i++) all[i] = i;
        byte[] storage = field("proofStorage").clone(), receipts = field("cardReceipts").clone(), cardLog = field("cardLog").clone(), lastSig = field("lastSig").clone();
        assertEquals(SW_OK, sw(beginCommand(all)));
        runtime.leaveATransactionOpen();        // the applet's own beginTransaction at the burn now throws TransactionException
        ResponseAPDU r = transmit(SIGN_ALL);
        assertEquals(SW_TOO_MANY, r.getSW(), "the terminal names fewer");
        assertEquals(0, r.getData().length, "and no signature leaves the card");
        assertEquals(0, runtime.getTransactionDepth(), "the card is out of the transaction it was left in");
        assertArrayEquals(storage, field("proofStorage"), "nothing burned");
        assertArrayEquals(receipts, field("cardReceipts"), "no receipt");
        assertArrayEquals(cardLog, field("cardLog"), "nothing in the log");
        assertArrayEquals(lastSig, field("lastSig"), "no signature kept");
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "the payment is over");
        assertEquals(8256, balance());
        // fewer, and then all of them, once the card can
        ResponseAPDU again = spendAll(all, new byte[0][]);
        assertEquals(SW_OK, again.getSW());
        assertEquals(0, balance());
    }

    @Test
    @DisplayName("A payment of any number of places is committed by one transaction of the same size, and its places are marked after it: ALL_MOST is MAX_PROOFS (128) and allSlots is that long; the count is looked at before the places are copied; the signature is made first, burnList is written before the transaction and outside it, the transaction sets burnPending together with the day, changeDue, the log and the last signature and writes no place, finishBurn follows the commit and comes before the receipt and the answer; a transaction that cannot be had is aborted and is 6A96 and sets nothing; process() finishes a pending burn before it looks at anything, SELECT included")
    void testTheBurnIsOneTransactionOfEveryPlaceNamed() throws Exception {
        assertEquals(128, CashuApplet.ALL_MOST);
        assertEquals(CashuApplet.MAX_PROOFS, CashuApplet.ALL_MOST);
        String code = appletCode();
        String flat = code.replaceAll("\\s+", " ");
        assertTrue(flat.contains("allSlots = JCSystem.makeTransientByteArray(ALL_MOST, JCSystem.CLEAR_ON_DESELECT)"), "RAM for every place the card has");
        String begin = body(code, "private void processSpendAllBegin(", "private void processSpendAllOutputs(");
        assertTrue(begin.indexOf("if (n > ALL_MOST) ISOException.throwIt(SW_TOO_MANY);") > 0
            && begin.indexOf("if (n > ALL_MOST) ISOException.throwIt(SW_TOO_MANY);") < begin.indexOf("arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, allSlots"),
            "more than that is refused before the places are copied");
        assertTrue(begin.contains("allState[1] = (byte) n;"));

        // the two fields that carry the burn last: a power loss must not clear them
        assertTrue(flat.contains("private byte[] burnList;") && flat.contains("private byte[] burnPending;"));
        assertTrue(flat.contains("burnList = new byte[(short)(MAX_PROOFS + 1)];"), "the count, and a byte for each place the card has");
        assertTrue(flat.contains("burnPending = new byte[1];"), "one byte");
        assertFalse(flat.contains("burnList = JCSystem") || flat.contains("burnPending = JCSystem"), "and neither is RAM");

        String sign = body(code, "private void processSpendAllSign(", "private void finishBurn(");
        String finish = body(code, "private void finishBurn(", "private void processSpendAllAgain(");
        String process = body(code, "public void process(", "private void processGetInfo(");

        // ---- SPEND_ALL_SIGN: the order
        assertTrue(sign.contains("short n = (short)(allState[1] & 0xFF);"), "128 is read as 128, and not as a negative byte");
        int signed = sign.indexOf("short sigLen = schnorrHW.sign(");
        int listCount = sign.indexOf("burnList[0] = (byte) n;");
        int listCopy = sign.indexOf("Util.arrayCopyNonAtomic(allSlots, (short) 0, burnList, (short) 1, n);");
        int tryAt = sign.indexOf("try {", listCopy);
        int begins = sign.indexOf("JCSystem.beginTransaction();", tryAt);
        int pending = sign.indexOf("burnPending[0] = (byte) 1;", begins);
        int commit = sign.indexOf("JCSystem.commitTransaction();", pending);
        int caught = sign.indexOf("} catch (TransactionException e) {", commit);
        int abort = sign.indexOf("JCSystem.abortTransaction();", caught);
        int refused = sign.indexOf("ISOException.throwIt(SW_TOO_MANY);", abort);
        int finishes = sign.indexOf("finishBurn();", refused);
        int receiptBegins = sign.indexOf("JCSystem.beginTransaction();", finishes);
        int answer = sign.lastIndexOf("apdu.setOutgoingAndSend((short) 0, sigLen);");
        assertTrue(signed > 0 && signed < listCount && listCount < listCopy && listCopy < tryAt && tryAt < begins && begins < pending
                && pending < commit && commit < caught && caught < abort && abort < refused && refused < finishes
                && finishes < receiptBegins && receiptBegins < answer,
            "the signature first; the list written, outside the transaction and before it; the transaction, with burnPending set in it; its commit; a failure aborted and refused; "
            + "finishBurn after all that and before the receipt's transaction; the answer last");
        assertEquals("ISOException.throwIt(SW_TOO_MANY);}", sign.substring(refused, finishes).replaceAll("\\s+", ""), "a failed transaction is refused there and then: nothing runs between the refusal and the end of the catch");

        // ---- the transaction: the payment itself, and no place in it
        String tx = sign.substring(begins, commit);
        assertTrue(tx.contains("burnPending[0] = (byte) 1;") && tx.contains("changeDue[0] = (byte) 1;") && tx.contains("CARD_SPENT_OFFSET") && tx.contains("logEntry()")
                && tx.contains("addUint32Stop(cardLog, LOG_SATS_OFFSET") && tx.contains("lastSig[0] = noPin ? (byte) 2 : (byte) 1;") && tx.contains("LOG_FLAG_NOPIN") && tx.contains("CARD_NOPIN_SPENT_OFFSET") && tx.contains(", lastSig, (short) 1, (short) 64)"),
            "burnPending is set in it with the day's count, changeDue, the log and the last signature");
        assertFalse(tx.contains("proofStorage") || tx.contains("STATUS_SPENT") || tx.contains("allSlots") || tx.contains("burnList")
                || tx.contains("finishBurn") || tx.contains("for (") || tx.contains("while ("),
            "no place is written in it, no list is read in it and it has no loop: it is the same size whatever the number of places");
        assertFalse(sign.contains("STATUS_SPENT") || sign.contains("proofStorage"), "SPEND_ALL_SIGN names no place's status at all: finishBurn does");
        assertEquals(1, count(sign, "burnPending"), "SPEND_ALL_SIGN names burnPending once, to set it, and never to clear it");
        assertEquals(2, count(sign, "burnList"), "and burnList twice, to write the count and the places, both before the transaction");
        assertEquals(1, count(sign, "finishBurn()"), "and finishBurn once");
        assertEquals(2, count(sign, "beginTransaction"), "the payment's transaction and the receipt's");
        String failure = sign.substring(caught, refused);
        assertFalse(failure.contains("burnPending") || failure.contains("burnList") || failure.contains("finishBurn") || failure.contains("setOutgoingAndSend"),
            "a failed transaction sets no note, marks nothing and answers nothing but 6A96");

        // ---- finishBurn
        String f = finish.replaceAll("\\s+", " ");
        assertTrue(f.contains("short n = (short)(burnList[0] & 0xFF);"), "the count is read as a number, so that 128 and more are not negative");
        assertTrue(f.contains("if (n > MAX_PROOFS) n = MAX_PROOFS;"), "and is held to the places there are");
        assertTrue(f.contains("for (short i = 0; i < n; i++) {"), "every place in the list, from the first");
        assertTrue(f.contains("short idx = (short)(burnList[(short)(i + 1)] & 0xFF);"), "the place numbers follow the count");
        assertTrue(f.contains("if (idx >= MAX_PROOFS) continue;"), "a number that is no place is passed over");
        assertTrue(f.contains("short at = (short)(idx * PROOF_SIZE + PROOF_STATUS_OFFSET);"), "the place's status byte");
        assertTrue(f.contains("if (proofStorage[at] != STATUS_SPENT) proofStorage[at] = STATUS_SPENT;"), "marked spent");
        int loop = finish.indexOf("for (short i = 0; i < n; i++) {");
        int mark = finish.indexOf("proofStorage[at] = STATUS_SPENT;");
        int loopEnd = finish.indexOf("}", mark);
        int clearBegins = finish.indexOf("JCSystem.beginTransaction();");
        int clear = finish.indexOf("burnPending[0] = (byte) 0;");
        int clearCommits = finish.indexOf("JCSystem.commitTransaction();");
        assertTrue(loop > 0 && loop < mark && mark < loopEnd && loopEnd < clearBegins && clearBegins < clear && clear < clearCommits,
            "the places are marked in the loop, and after the loop the note is taken down in a transaction of its own: begun, one byte, committed");
        assertEquals("JCSystem.beginTransaction();burnPending[0]=(byte)0;JCSystem.commitTransaction();}", finish.substring(clearBegins).replaceAll("\\s+", ""),
            "and that transaction is the last thing finishBurn does, and holds the one byte and nothing else: the commit is the barrier between the status bytes and the note");
        assertEquals(1, count(finish, "beginTransaction"), "one transaction");
        assertEquals(1, count(finish, "commitTransaction"), "committed once");
        assertEquals(0, count(finish, "abortTransaction"), "and not aborted: there is nothing in it to fail");
        assertEquals(1, count(finish, "burnPending"), "finishBurn names burnPending once, to clear it");
        assertEquals(2, count(finish, "STATUS_SPENT"), "and writes only that one status, in that one place");
        assertFalse(finish.contains("burnList[0] =") || finish.contains("cardLog") || finish.contains("lastSig") || finish.contains("changeDue")
                || finish.contains("cardRecord") || finish.contains("STATUS_EMPTY") || finish.contains("STATUS_UNSPENT"),
            "it writes only statuses to spent and the note to 0, and never the list");

        // ---- process(): a pending burn is finished before anything else
        int gets = process.indexOf("byte[] buf = apdu.getBuffer();");
        int checks = process.indexOf("if (burnPending[0] != (byte) 0) finishBurn();");
        int selecting = process.indexOf("selectingApplet()");
        int classByte = process.indexOf("OFFSET_CLA");
        int givesUp = process.indexOf("allState[0] = (byte) 0");
        int dispatch = process.indexOf("switch");
        assertTrue(gets >= 0 && gets < checks && checks < selecting && selecting < classByte && classByte < givesUp && givesUp < dispatch,
            "process() finishes a pending burn before the SELECT test, the class byte, the giving up of a payment and any dispatch");
        assertEquals(1, count(process, "finishBurn"), "once");
        assertEquals(1, count(process, "burnPending"), "and burnPending is read there and not written");
        assertFalse(process.contains("burnList"), "process() does not look at the list");
        // and nothing else in the applet names either field, or calls finishBurn
        String rest = code.replace(sign, "").replace(finish, "").replace(process, "");
        assertEquals(2, count(rest, "burnPending"), "elsewhere, the declaration and the allocation: nothing else reads or writes the note");
        assertEquals(2, count(rest, "burnList"), "elsewhere, the declaration and the allocation: nothing else reads or writes the list");
        assertEquals(0, count(rest, "finishBurn"), "and nothing else calls finishBurn");
    }

    // ---- 1.8: a payment's places are marked after the transaction that commits it ---------------------

    /**
     * Every persistent array a command could change, by the applet's name for it. `dleq` (1.20), the mint's proof for each place, is
     * null until the first SET_CARD reserves it, so a copy of it is null then, and null is what it is compared with.
     */
    private static final String[] PERSISTENT = { "proofStorage", "slotHex", "dleq", "cardLocked", "pinState", "cardRecord", "ownerSet", "changeDue",
        "cardLog", "cardReceipts", "lastSig", "burnList", "burnPending" };

    /** All of what lasts, copied. */
    private java.util.Map<String, byte[]> persistent() throws Exception {
        java.util.Map<String, byte[]> m = new java.util.LinkedHashMap<>();
        for (String name : PERSISTENT) {
            byte[] a = field(name);
            m.put(name, a == null ? null : a.clone());
        }
        return m;
    }
    /** All of what lasts, put back as it was copied (a store that was not yet there is left as it is, but zeroed). */
    private void putPersistent(java.util.Map<String, byte[]> m) throws Exception {
        for (java.util.Map.Entry<String, byte[]> e : m.entrySet()) {
            byte[] live = field(e.getKey());
            if (e.getValue() == null) {
                if (live != null) Arrays.fill(live, (byte) 0);
            } else {
                System.arraycopy(e.getValue(), 0, live, 0, e.getValue().length);
            }
        }
    }
    private void assertPersistent(java.util.Map<String, byte[]> want, String what) throws Exception {
        for (String name : PERSISTENT) assertArrayEquals(want.get(name), field(name), what + ": " + name);
    }
    /** A place's status as the applet holds it, read where no command is spent on it: 0 empty, 1 unspent, 2 spent. */
    private int statusOf(int place) throws Exception {
        return field("proofStorage")[place * CashuApplet.PROOF_SIZE + CashuApplet.PROOF_STATUS_OFFSET];
    }
    private void setStatusOf(int place, int status) throws Exception {
        field("proofStorage")[place * CashuApplet.PROOF_SIZE + CashuApplet.PROOF_STATUS_OFFSET] = (byte) status;
    }
    /**
     * A card as a tear leaves it between a payment's commit and the marking of its places: the payment is made (the day, the log,
     * the signature and changeDue are as the commit left them), burnPending says so, and of the places named the ones `marked`
     * says are spent and the others are not.
     */
    private void tornAfterTheCommit(int[] places, boolean[] marked) throws Exception {
        for (int k = 0; k < places.length; k++) setStatusOf(places[k], marked[k] ? 2 : 1);
        field("burnPending")[0] = 1;
    }
    private static boolean[] all(int n, boolean value) {
        boolean[] b = new boolean[n];
        Arrays.fill(b, value);
        return b;
    }

    /**
     * A card that has paid, and what a tear test starts from. Pieces 0 to pop-1 are loaded, piece i worth 1 + i. Places n+left on
     * are paid in a payment of their own first (`before`, and spent), places n to n+left-1 are left unspent, and the places
     * 0 to n-1 are paid in one payment, named from the last to the first. Places past the pieces are empty.
     */
    private static final class Paid {
        int pop;
        int[] places, before, left;
        byte[] signature;
        long worthLeft;
        java.util.Map<String, byte[]> after;
    }

    private Paid paidCard(int n, int beforeCount, int leftCount) throws Exception {
        Paid p = new Paid();
        simulator = freshCard();
        ready();
        p.pop = n + leftCount + beforeCount;
        loadMany(p.pop, i -> buildProof(KEYSET, 1 + i, i + 1));
        p.places = new int[n];
        for (int k = 0; k < n; k++) p.places[k] = n - 1 - k;
        p.left = new int[leftCount];
        for (int k = 0; k < leftCount; k++) { p.left[k] = n + k; p.worthLeft += 1 + n + k; }
        p.before = new int[beforeCount];
        for (int k = 0; k < beforeCount; k++) p.before[k] = n + leftCount + k;
        if (beforeCount > 0) assertEquals(SW_OK, spendAll(p.before, new byte[0][]).getSW());
        ResponseAPDU r = spendAll(p.places, new byte[][] { output(3, blinded(1)) });
        assertEquals(SW_OK, r.getSW());
        assertEquals(64, r.getData().length);
        p.signature = r.getData();
        // the payment is made and its places are marked with no command after it: the signing marked them itself
        assertEquals(0, field("burnPending")[0], "the note is cleared when the signing ends");
        for (int place : p.places) assertEquals(2, statusOf(place), "place " + place + " is spent when the signing ends");
        p.after = persistent();
        return p;
    }

    /** The card as the payment and its marking left it, taken out of the field and put back; with a SELECT and the PIN, unless the first command is to be the SELECT. */
    private void prepare(Paid p, boolean theFirstCommandIsTheSelect) throws Exception {
        putPersistent(p.after);
        simulator.reset();
        if (!theFirstCommandIsTheSelect) {
            reselect();
            assertEquals(SW_OK, verify(TEST_PIN));
        }
    }

    /** Commands to be the first the card is sent after a tear, each by the name it goes by in a message. */
    private java.util.LinkedHashMap<String, java.util.function.Supplier<ResponseAPDU>> firstCommands(Paid p) {
        java.util.LinkedHashMap<String, java.util.function.Supplier<ResponseAPDU>> c = new java.util.LinkedHashMap<>();
        int place = p.places[0];
        byte[] newPiece = buildProof(KEYSET, 7, 200);
        c.put("SELECT", () -> transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(AID_STR))));
        c.put("GET_INFO", () -> transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256)));
        c.put("GET_INFO asked for the limit on one payment", () -> transmit(new CommandAPDU(CLA, INS_GET_INFO, 1, 0, 256)));
        c.put("GET_BALANCE", () -> transmit(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4)));
        c.put("GET_PROOF_COUNT", () -> transmit(new CommandAPDU(CLA, INS_GET_PROOF_COUNT, 0, 0, 256)));
        c.put("GET_PIECES whole", () -> pieces(0));
        c.put("GET_PIECES named", () -> somePieces(new byte[] { (byte) place }));
        c.put("GET_PIECES short", () -> shortPieces(0));
        c.put("GET_PROOF of a place paid with", () -> transmit(new CommandAPDU(CLA, INS_GET_PROOF, place, 0, 256)));
        c.put("GET_SLOT_STATUS", () -> transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)));
        c.put("SPEND_ALL_BEGIN naming a place paid with", () -> transmit(beginCommand(place)));
        c.put("LOAD_PROOF", () -> load(newPiece));
        c.put("CLEAR_SPENT", () -> transmit(new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1)));
        c.put("SPEND_ALL_AGAIN", () -> transmit(new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64)));
        c.put("GET_LOG", () -> logAnswer());
        c.put("GET_PUBKEY", () -> transmit(new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256)));
        c.put("VERIFY_PIN", () -> transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN)));
        c.put("an instruction the card does not know", () -> transmit(new CommandAPDU(CLA, 0x7E, 0, 0)));
        c.put("a class the card does not know", () -> transmit(new CommandAPDU(0x80, INS_GET_INFO, 0, 0, 256)));
        return c;
    }

    @Test
    @DisplayName("Committed, not yet marked: a card taken away after a payment's transaction and before its places were marked (burnPending 1, the places still unspent) has them marked as the first thing done by whatever command comes next - SELECT, GET_INFO, GET_BALANCE, GET_PROOF_COUNT, GET_PIECES whole, named and short, GET_PROOF, GET_SLOT_STATUS, SPEND_ALL_BEGIN (6985), LOAD_PROOF, CLEAR_SPENT, SPEND_ALL_AGAIN, GET_LOG, VERIFY_PIN and those the card refuses - for payments of 1, 12, 64 and 128 places: the answer and everything that lasts are those of the same command after a payment that was marked, and burnPending is 0")
    void testACommittedPaymentIsMarkedBeforeAnyCommandLooksAtAPlace() throws Exception {
        for (int n : new int[] { 1, 12, 64, 128 }) {
            int others = n == 128 ? 0 : 5;
            Paid p = paidCard(n, others, others);
            java.util.LinkedHashMap<String, java.util.function.Supplier<ResponseAPDU>> commands = firstCommands(p);
            for (String name : commands.keySet()) {
                String what = n + " places, " + name;
                boolean select = name.equals("SELECT");
                // the control: the same command after a payment that was marked
                prepare(p, select);
                ResponseAPDU control = commands.get(name).get();
                java.util.Map<String, byte[]> controlState = persistent();
                // and after a tear: the places as they were before the payment, and the note that it was made.
                // Where the first command is the SELECT, the card is taken out of the field with the note in it, as a tear does
                // it; for the others a SELECT and the PIN have had to come first, and the tear is after them
                if (select) {
                    putPersistent(p.after);
                    tornAfterTheCommit(p.places, all(n, false));
                    simulator.reset();
                } else {
                    prepare(p, false);
                    tornAfterTheCommit(p.places, all(n, false));
                }
                for (int place : p.places) assertEquals(1, statusOf(place), what + ": unspent, as the tear left place " + place);
                assertEquals(1, field("burnPending")[0], what + ": the payment is noted");
                ResponseAPDU torn = commands.get(name).get();
                assertEquals(control.getSW(), torn.getSW(), what + ": the same status as after a payment that was marked");
                assertArrayEquals(control.getData(), torn.getData(), what + ": the same answer");
                assertPersistent(controlState, what + ": everything that lasts");
                assertEquals(0, field("burnPending")[0], what + ": the note is cleared");
                int want = name.equals("CLEAR_SPENT") ? 0 : 2;
                for (int place : p.places) assertEquals(want, statusOf(place), what + ": place " + place);
                // and the answer says what the marked places make it say
                byte[] d = torn.getData();
                if (name.equals("SELECT")) {
                    assertArrayEquals(new byte[] { 0x02, 0x01 }, d, what);
                } else if (name.equals("GET_INFO")) {
                    assertEquals(others, d[3] & 0xFF, what + ": unspent");
                    assertEquals(n + others, d[4] & 0xFF, what + ": spent");
                    assertEquals(128 - p.pop, d[5] & 0xFF, what + ": empty");
                } else if (name.equals("GET_BALANCE")) {
                    assertEquals(p.worthLeft, readUint32(d, 0), what);
                } else if (name.equals("GET_PROOF_COUNT")) {
                    assertEquals(p.pop, d[0] & 0xFF, what + ": places in use, spent or not");
                } else if (name.equals("GET_SLOT_STATUS")) {
                    for (int place : p.places) assertEquals(2, d[place], what + ": place " + place);
                    for (int place : p.left) assertEquals(1, d[place], what + ": place " + place + " was not paid with");
                } else if (name.equals("GET_PROOF of a place paid with")) {
                    assertEquals(2, d[0], what);
                } else if (name.startsWith("SPEND_ALL_BEGIN")) {
                    assertEquals(SW_CONDITIONS_NOT_SATIS, torn.getSW(), what + ": spent");
                } else if (name.equals("CLEAR_SPENT")) {
                    assertEquals(n + others, d[0] & 0xFF, what + ": every spent place freed, the payment's among them");
                } else if (name.equals("SPEND_ALL_AGAIN")) {
                    assertArrayEquals(p.signature, d, what + ": the payment's signature");
                } else if (name.equals("LOAD_PROOF")) {
                    assertEquals(n == 128 ? SW_NO_SPACE : SW_OK, torn.getSW(), what);
                } else if (name.startsWith("an instruction")) {
                    assertEquals(SW_INS_NOT_SUPPORTED, torn.getSW(), what);
                } else if (name.startsWith("a class")) {
                    assertEquals(SW_CLA_NOT_SUPPORTED, torn.getSW(), what);
                }
            }
        }
    }

    @Test
    @DisplayName("Marked part way: a card taken away while the places were being marked (some of the listed places spent, some not, burnPending 1) has the rest marked by the next command and nothing else touched - not an unspent place the list does not name, nor a spent one, nor an empty one; the same again changes nothing; for 12, 64 and 128 places with the first marked, the last, the first half, every other one, all but the middle one, all (taken away just before the note was cleared) and none")
    void testAPartlyMarkedPaymentIsFinishedAndNothingElseIsTouched() throws Exception {
        for (int n : new int[] { 12, 64, 128 }) {
            int others = n == 128 ? 0 : 5;
            Paid p = paidCard(n, others, others);
            for (int pattern = 0; pattern < 7; pattern++) {
                boolean[] marked = new boolean[n];
                for (int k = 0; k < n; k++) {
                    marked[k] = pattern == 0 ? k == 0 : pattern == 1 ? k == n - 1 : pattern == 2 ? k < n / 2 : pattern == 3 ? k % 2 == 0 : pattern == 4 ? k != n / 2 : pattern == 5;
                }
                String what = n + " places, pattern " + pattern;
                putPersistent(p.after);
                tornAfterTheCommit(p.places, marked);
                assertEquals(1, field("burnPending")[0], what);
                assertEquals(p.worthLeft, balance(), what + ": the next command, whatever it is, finishes the marking before it answers");
                assertPersistent(p.after, what + ": every place named is spent, and everything else is as it was");
                // taken away again before the note was cleared: finished already, and finishing again changes nothing
                field("burnPending")[0] = 1;
                assertEquals(p.worthLeft, balance(), what + ": again");
                assertPersistent(p.after, what + ": the same again changes nothing");
                // and the same tear with the power gone: the SELECT that follows finishes it
                putPersistent(p.after);
                tornAfterTheCommit(p.places, marked);
                simulator.reset();
                reselect();
                assertPersistent(p.after, what + ": after a power loss, the SELECT finishes the marking");
                for (int place : p.left) assertEquals(1, statusOf(place), what + ": place " + place + " is not in the list and is unspent");
                for (int place : p.before) assertEquals(2, statusOf(place), what + ": place " + place + " is not in the list and is spent");
                for (int place = p.pop; place < 128; place++) assertEquals(0, statusOf(place), what + ": place " + place + " is not in the list and is empty");
            }
        }
    }

    /** That every one of the first `pop` places is unspent, the rest empty, nothing is noted and the list is as it was. */
    private void assertUntouched(int pop, byte[] list, String what) throws Exception {
        for (int place = 0; place < 128; place++) assertEquals(place < pop ? 1 : 0, statusOf(place), what + ": place " + place);
        assertEquals(0, field("burnPending")[0], what + ": nothing is noted");
        assertArrayEquals(list, field("burnList"), what + ": the list is as it was");
    }

    @Test
    @DisplayName("A list nobody reads: burnPending 0 with burnList naming unspent places (as a card that was taken away before the payment's transaction committed has) burns nothing, whatever is sent - SELECT, a power-up, a begun payment, a refused signing, every instruction byte from 00 to FF; a payment made then overwrites the list and burns its own places, and what lies in the list past its count is never read")
    void testAListNobodyReadsBurnsNothing() throws Exception {
        ready();
        loadMany(40, i -> buildProof(KEYSET, 1 + i, i + 1));
        int[] stale = { 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
        byte[] list = field("burnList");
        list[0] = (byte) stale.length;
        for (int k = 0; k < stale.length; k++) list[1 + k] = (byte) stale[k];
        byte[] listBefore = list.clone();
        assertEquals(0, field("burnPending")[0]);
        assertUntouched(40, listBefore, "to begin with");
        reselect();
        assertUntouched(40, listBefore, "after SELECT");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertUntouched(40, listBefore, "after VERIFY_PIN");
        CommandAPDU[] some = {
            new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256), new CommandAPDU(CLA, INS_GET_INFO, 1, 0, 256), new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256),
            new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4), new CommandAPDU(CLA, INS_GET_PROOF_COUNT, 0, 0, 256), new CommandAPDU(CLA, INS_GET_PROOF, 5, 0, 256),
            new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256), new CommandAPDU(CLA, INS_GET_CARD, 0, 0, 256),
            new CommandAPDU(CLA, INS_GET_PIECES, 0, 0, 256), new CommandAPDU(CLA, INS_GET_PIECES, 0, 2, new byte[] { 5, 6 }, 256), new CommandAPDU(CLA, INS_GET_PIECES, 0, 3, 256),
            new CommandAPDU(CLA, INS_GET_LOG, 0, 0, 256), new CommandAPDU(CLA, INS_GET_LOG, 1, 0, 256), new CommandAPDU(CLA, INS_GET_NONCE, 0, 0, 16),
            beginCommand(5, 6), new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, output(3, blinded(1))), new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256),
            SIGN_ALL, new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64), new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1),
            new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 7, 200), 1), setTimeCommand(T0 + 5),
            new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN), new CommandAPDU(CLA, 0x7E, 0, 0), new CommandAPDU(0x80, INS_GET_INFO, 0, 0, 256) };
        for (int k = 0; k < some.length; k++) {
            transmit(some[k]);
            assertUntouched(k >= 20 ? 41 : 40, listBefore, "after command " + k + " (INS " + String.format("%02X", some[k].getINS()) + ")");
        }
        int pop = 41;       // the piece loaded above
        for (int ins = 0; ins < 256; ins++) {
            transmit(new CommandAPDU(CLA, ins, 0, 0));
            assertUntouched(pop, listBefore, "after INS " + String.format("%02X", ins) + " with nothing else");
        }
        simulator.reset();
        assertUntouched(pop, listBefore, "after a power loss");
        reselect();
        assertUntouched(pop, listBefore, "and a SELECT");
        // a payment made now writes its own list, and burns what it names
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spendAll(new int[] { 20, 21, 22 }, new byte[0][]).getSW());
        assertEquals(0, field("burnPending")[0]);
        byte[] listNow = field("burnList");
        assertArrayEquals(new byte[] { 3, 20, 21, 22 }, Arrays.copyOf(listNow, 4), "the payment's count and its places, in the order named");
        for (int place = 0; place < pop; place++) assertEquals(place >= 20 && place <= 22 ? 2 : 1, statusOf(place), "place " + place + ": only the payment's own are burned, and not those the old list named");
        // a tear in its marking: the three are finished and the old list's places, which may lie past the count, are not
        tornAfterTheCommit(new int[] { 20, 21, 22 }, all(3, false));
        balance();
        for (int place = 0; place < pop; place++) assertEquals(place >= 20 && place <= 22 ? 2 : 1, statusOf(place), "place " + place + " after finishing: nothing past the count is read");
        assertEquals(0, field("burnPending")[0]);
    }

    @Test
    @DisplayName("A transaction that fails sets no note: SPEND_ALL_SIGN answers 6A96 with no data and burns nothing, burnPending stays 0 though burnList now names the places (written before the transaction), no place changes and nothing that lasts but the list does, and the next command - or a power-up and a SELECT - burns nothing; the payment begun again goes through and burns its own, for 1, 12 and 128 places")
    void testAFailedTransactionSetsNoNoteAndTheListIsNeverRead() throws Exception {
        for (int n : new int[] { 1, 12, 128 }) {
            String what = n + " places";
            simulator = freshCard();
            ready();
            loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
            int[] places = scrambled(n);
            assertEquals(SW_OK, sw(beginCommand(places)), what);
            java.util.Map<String, byte[]> before = persistent();
            runtime.leaveATransactionOpen();
            ResponseAPDU r = transmit(SIGN_ALL);
            assertEquals(SW_TOO_MANY, r.getSW(), what + ": the terminal names fewer");
            assertEquals(0, r.getData().length, what + ": and no signature leaves the card");
            assertEquals(0, runtime.getTransactionDepth(), what + ": out of the transaction it was left in");
            assertEquals(0, field("burnPending")[0], what + ": nothing was committed, so nothing is noted");
            for (int place = 0; place < 128; place++) assertEquals(1, statusOf(place), what + ": place " + place + " is unspent");
            for (String name : PERSISTENT) {
                if (!name.equals("burnList")) assertArrayEquals(before.get(name), field(name), what + ": " + name + " is as it was");
            }
            byte[] list = field("burnList");
            assertEquals(n, list[0] & 0xFF, what + ": the list was written before the transaction was begun, with the count");
            for (int k = 0; k < n; k++) assertEquals(places[k], list[1 + k] & 0xFF, what + ": and the places");
            // the next command, and a power-up and a SELECT, burn nothing
            assertEquals(8256, balance(), what);
            for (int place = 0; place < 128; place++) assertEquals(1, statusOf(place), what + ": place " + place + " after the next command");
            simulator.reset();
            reselect();
            assertEquals(SW_OK, verify(TEST_PIN));
            assertEquals(8256, balance(), what);
            for (int place = 0; place < 128; place++) assertEquals(1, statusOf(place), what + ": place " + place + " after a power-up");
            assertEquals(0, field("burnPending")[0], what);
            // begun again, it is a payment, and it burns its own places
            ResponseAPDU again = spendAll(places, new byte[0][]);
            assertEquals(SW_OK, again.getSW(), what);
            assertEquals(8256 - Arrays.stream(places).mapToLong(x -> 1 + x).sum(), balance(), what);
            assertEquals(0, field("burnPending")[0], what);
        }
    }

    @Test
    @DisplayName("A list the applet could not have written is read safely: burnPending 1 with a count over 128 (129, 130, 200, 255), a place number of 128 or more, or a count of 0, and the next command raises nothing, marks the places in range and no others, and clears the note; 128 places at their largest are marked all of them")
    void testAListOutOfRangeIsReadSafely() throws Exception {
        ready();
        loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
        java.util.Map<String, byte[]> start = persistent();
        // { count, then (place, entry) pairs to put in the list; every other entry is out of range }
        int[][] cases = {
            { 129, 1, 4, 2, 9, 3, 127 },
            { 130, 1, 4, 2, 9, 3, 127 },
            { 200, 1, 4, 2, 9, 3, 127 },
            { 255, 1, 4, 2, 9, 3, 127 },
            { 255, 1, 0, 128, 77 },
            { 128, 128, 77 },
            { 128, 1, 128, 2, 255, 3, 200 },
            { 3, 1, 128, 2, 200, 3, 255 },
            { 0, 1, 1, 2, 2, 3, 3 },
            { 2, 1, 1, 2, 2, 3, 3 } };
        for (int c = 0; c < cases.length; c++) {
            int[] spec = cases[c];
            putPersistent(start);
            byte[] list = field("burnList");
            list[0] = (byte) spec[0];
            for (int i = 1; i < list.length; i++) list[i] = (byte) (128 + (i % 128));
            boolean[] expect = new boolean[128];
            int reads = Math.min(spec[0], 128);
            for (int k = 1; k + 1 < spec.length; k += 2) {
                list[spec[k]] = (byte) spec[k + 1];
                if (spec[k] <= reads && spec[k + 1] < 128) expect[spec[k + 1]] = true;
            }
            field("burnPending")[0] = 1;
            String what = "case " + c + " (count " + spec[0] + ")";
            ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256));
            assertEquals(SW_OK, r.getSW(), what + ": no exception");
            assertEquals(0, field("burnPending")[0], what + ": the note is cleared");
            int spent = 0;
            for (int place = 0; place < 128; place++) {
                assertEquals(expect[place] ? 2 : 1, statusOf(place), what + ": place " + place);
                if (expect[place]) spent++;
            }
            assertEquals(spent, r.getData()[4] & 0xFF, what + ": GET_INFO counts them");
        }
        // the largest honest list: 128 places, every one of them
        putPersistent(start);
        byte[] list = field("burnList");
        list[0] = (byte) 128;
        for (int k = 0; k < 128; k++) list[1 + k] = (byte) (127 - k);
        field("burnPending")[0] = 1;
        assertEquals(0, balance());
        for (int place = 0; place < 128; place++) assertEquals(2, statusOf(place), "128 places: place " + place);
    }

    @Test
    @DisplayName("After a payment burnPending is 0 and burnList holds the count and then the places in the order named, every place named is spent and no other, changeDue is set, the last signature is the one given, and the log, the day's charge and the receipt are the payment's, for 1, 33 and 128 places; a second payment in the same tap replaces the list (5 places then 3, 3 then 5)")
    void testAfterAPaymentTheListIsWhatWasNamedAndNothingIsPending() throws Exception {
        for (int n : new int[] { 1, 33, 128 }) {
            String what = n + " places";
            simulator = freshCard();
            readyWithLimit(100000);
            byte[][] sent = loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
            int[] places = scrambled(n);
            byte[][] named = new byte[n][];
            boolean[] burned = new boolean[128];
            long worth = 0;
            for (int k = 0; k < n; k++) { named[k] = asSlot(sent[places[k]]); burned[places[k]] = true; worth += 1 + places[k]; }
            byte[][] outputs = { output(3, blinded(1)), output(5, blinded(2)) };
            ResponseAPDU r = spendAll(places, outputs);
            assertEquals(SW_OK, r.getSW(), what);
            // with no command after it
            assertEquals(0, field("burnPending")[0], what + ": nothing is pending");
            byte[] list = field("burnList");
            assertEquals(n, list[0] & 0xFF, what + ": the count");
            for (int k = 0; k < n; k++) assertEquals(places[k], list[1 + k] & 0xFF, what + ": the place named " + (k + 1) + "th");
            for (int place = 0; place < 128; place++) assertEquals(burned[place] ? 2 : 1, statusOf(place), what + ": place " + place);
            assertEquals(1, field("changeDue")[0], what + ": the next tap may put the change on");
            assertEquals(1, field("lastSig")[0], what + ": there has been a signature");
            assertArrayEquals(r.getData(), Arrays.copyOfRange(field("lastSig"), 1, 65), what + ": and it is the one given");
            assertEquals(worth, spentToday(), what + ": the day's charge is the whole sum");
            assertArrayEquals(new long[] { T0, worth, n, 0, 0 }, logTap(0), what + ": the log");
            assertEquals(SW_OK, allowLoad());
            Held held = heldReceipts();
            assertEquals(1, held.count, what + ": one receipt");
            assertArrayEquals(receiptFor(T0, worth, named, outputs), held.receipts.get(0), what + ": the payment's");
        }
        for (int[] sizes : new int[][] { { 5, 3 }, { 3, 5 } }) {
            String what = sizes[0] + " places then " + sizes[1];
            simulator = freshCard();
            ready();
            loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
            int[] first = new int[sizes[0]], second = new int[sizes[1]];
            for (int k = 0; k < first.length; k++) first[k] = 100 - 3 * k;
            for (int k = 0; k < second.length; k++) second[k] = 10 + 7 * k;
            assertEquals(SW_OK, spendAll(first, new byte[0][]).getSW(), what);
            byte[] firstList = Arrays.copyOf(field("burnList"), 1 + first.length);
            assertEquals(first.length, firstList[0], what);
            ResponseAPDU r = spendAll(second, new byte[0][]);
            assertEquals(SW_OK, r.getSW(), what);
            byte[] list = field("burnList");
            assertEquals(second.length, list[0] & 0xFF, what + ": the second payment's count replaces the first's");
            for (int k = 0; k < second.length; k++) assertEquals(second[k], list[1 + k] & 0xFF, what + ": the second payment's place " + (k + 1));
            assertEquals(0, field("burnPending")[0], what);
            for (int place = 0; place < 128; place++) {
                final int named = place;
                boolean spent = Arrays.stream(first).anyMatch(x -> x == named) || Arrays.stream(second).anyMatch(x -> x == named);
                assertEquals(spent ? 2 : 1, statusOf(place), what + ": place " + place);
            }
            assertArrayEquals(r.getData(), Arrays.copyOfRange(field("lastSig"), 1, 65), what + ": the last signature is the second's");
            assertArrayEquals(new long[] { T0, Arrays.stream(first).mapToLong(x -> 1 + x).sum() + Arrays.stream(second).mapToLong(x -> 1 + x).sum(), first.length + second.length, 0, 2 },
                logTap(0), what + ": one tap, both payments, the second slowed as the tap's second and the tap flagged for it");
        }
    }

    /** SPEND_ALL_SIGN, with the card to leave the field as the runtime says; what it answered, or null where nothing was. */
    private ResponseAPDU signAndLose() {
        try {
            return transmit(SIGN_ALL);
        } catch (RuntimeException e) {
            return null;
        } finally {
            runtime.commitsUntilTear = 0;
        }
    }

    @Test
    @DisplayName("A card taken out of the field the instant after one of a payment's three commits has paid, and is left as that commit leaves it. After the payment's (the note set, the places not marked): the day, the log, the last signature and the change note are the payment's, the receipt is not written, and the next command, SELECT or any other, marks every place before it looks at one. After the note's clearing (places marked, note cleared): only the receipt is missing. After the receipt's: nothing is missing but the answer. SPEND_ALL_AGAIN gives the signature in all three, and the places cannot be paid with again; for 1, 12, 64 and 128 places")
    void testACardTornAtTheCommitHasPaidAndFinishesAtItsNextCommand() throws Exception {
        for (int n : new int[] { 1, 12, 64, 128 }) {
            for (int tearAfter = 1; tearAfter <= 3; tearAfter++) {
                String what = n + " places, taken away after commit " + tearAfter + (tearAfter == 1 ? " (the payment's)" : tearAfter == 2 ? " (the note's clearing)" : " (the receipt's)");
                simulator = freshCard();
                readyWithLimit(100000);
                byte[][] sent = loadMany(128, i -> buildProof(KEYSET, 1 + i, i + 1));
                int[] places = scrambled(n);
                byte[][] named = new byte[n][];
                boolean[] burned = new boolean[128];
                long worth = 0;
                for (int k = 0; k < n; k++) { named[k] = asSlot(sent[places[k]]); burned[places[k]] = true; worth += 1 + places[k]; }
                byte[][] outputs = { output(3, blinded(1)) };
                assertEquals(SW_OK, sw(beginCommand(places)), what);
                assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, concat(outputs))), what);
                runtime.commitsUntilTear = tearAfter;
                ResponseAPDU lost = signAndLose();
                assertTrue(lost == null || (lost.getSW() != SW_OK && lost.getData().length == 0), what + ": nothing is answered");
                // the card as it was left, read where no command is spent
                assertEquals(tearAfter == 1 ? 1 : 0, field("burnPending")[0], what + ": the note");
                for (int place = 0; place < 128; place++) {
                    assertEquals(burned[place] && tearAfter >= 2 ? 2 : 1, statusOf(place), what + ": place " + place + " as the tear left it");
                }
                assertEquals(1, field("changeDue")[0], what + ": the change note is in the payment's transaction");
                assertEquals(1, field("lastSig")[0], what + ": and so is the signature");
                assertEquals(tearAfter == 3 ? 1 : 0, readUint32(field("cardReceipts"), 0), what + ": the receipt is the third transaction");
                // the card goes out of the field and comes back
                simulator.reset();
                reselect();
                assertEquals(0, field("burnPending")[0], what + ": the SELECT has finished it");
                for (int place = 0; place < 128; place++) assertEquals(burned[place] ? 2 : 1, statusOf(place), what + ": place " + place + " after the SELECT");
                assertEquals(SW_OK, verify(TEST_PIN));
                assertEquals(8256 - worth, balance(), what);
                assertEquals(worth, spentToday(), what + ": the day was charged in the transaction");
                assertArrayEquals(new long[] { T0, worth, n, 0, 0 }, logTap(0), what + ": and so was the log");
                ResponseAPDU again = transmit(new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64));
                assertEquals(SW_OK, again.getSW(), what);
                assertEquals(64, again.getData().length, what);
                assertTrue(signedForAll(again.getData(), named, outputs, REFUND), what + ": the signature of the payment that was made");
                assertEquals(SW_OK, allowLoad());
                assertEquals(tearAfter == 3 ? 1 : 0, heldReceipts().count, what + ": a payment taken away before its receipt has none");
                // a place paid with cannot be paid with again, and one not paid with can
                assertEquals(SW_CONDITIONS_NOT_SATIS, sw(beginCommand(places[0])), what);
                if (n < 128) {
                    int other = -1;
                    for (int place = 0; place < 128 && other < 0; place++) if (!burned[place]) other = place;
                    assertEquals(SW_OK, spendAll(new int[] { other }, new byte[0][]).getSW(), what + ": place " + other + " was not part of it");
                }
            }
        }
    }

    @Test
    @DisplayName("Three pieces to one LOAD_PROOF are three places, a byte each in the answer, and are all there; the card is as if they had been loaded one at a time, slots and text; a batch of one is the form it always was")
    void testABatchOfThreeIsThreePieces() throws Exception {
        byte[][] sent = new byte[9][];
        for (int i = 0; i < 6; i++) sent[i] = edgeProof(i, 0);
        for (int i = 6; i < 9; i++) sent[i] = buildProof(KEYSET, 40 + i, 60 + i, i == 7 ? 1900000000L : 0);
        // one at a time
        simulator = freshCard();
        ready();
        for (int i = 0; i < 9; i++) assertEquals(i, load(sent[i]).getData()[0]);
        byte[] storageAlone = field("proofStorage").clone(), hexAlone = field("slotHex").clone();
        // and the same nine as 3, 2, 3 and 1
        simulator = freshCard();
        ready();
        ResponseAPDU a = loadBatch(sent[0], sent[1], sent[2]);
        assertEquals(SW_OK, a.getSW());
        assertArrayEquals(new byte[] { 0, 1, 2 }, a.getData(), "three pieces, three places");
        ResponseAPDU b = loadBatch(sent[3], sent[4]);
        assertEquals(SW_OK, b.getSW());
        assertArrayEquals(new byte[] { 3, 4 }, b.getData());
        ResponseAPDU c = loadBatch(sent[5], sent[6], sent[7]);
        assertArrayEquals(new byte[] { 5, 6, 7 }, c.getData());
        ResponseAPDU d = loadBatch(sent[8]);
        assertEquals(SW_OK, d.getSW());
        assertArrayEquals(new byte[] { 8 }, d.getData(), "one piece, one byte, as it always was");
        assertArrayEquals(storageAlone, field("proofStorage"), "the slots are as if they had been loaded one at a time");
        assertArrayEquals(hexAlone, field("slotHex"), "and so is the text kept beside them");
        assertEquals(9, info()[3]);
        long total = 0;
        for (int i = 0; i < 9; i++) {
            total += readUint32(sent[i], 8);
            assertArrayEquals(asSlot(sent[i]), slot(i), "GET_PROOF gives the 81 bytes that were sent, place " + i);
        }
        assertEquals(total, balance());
        Page all = new Page(pieces(0).getData());
        for (int i = 0; i < all.entries.size(); i++) {
            assertArrayEquals(sent[(int) all.entries.get(i)[0]], (byte[]) all.entries.get(i)[2], "the whole listing gives them as sent");
        }
        // into holes: the freed places first, in order, and the answer says which
        ResponseAPDU paid = spendAll(new int[] { 1, 4, 6 }, new byte[0][]);
        assertEquals(SW_OK, paid.getSW());
        assertEquals(SW_OK, clearSpent());
        ResponseAPDU holes = loadBatch(buildProof(KEYSET, 7, 71), buildProof(KEYSET, 8, 72), buildProof(KEYSET, 9, 73));
        assertArrayEquals(new byte[] { 1, 4, 6 }, holes.getData(), "the places that were free, in the order they were sent");
        ResponseAPDU next = loadBatch(buildProof(KEYSET, 7, 74), buildProof(KEYSET, 8, 75));
        assertArrayEquals(new byte[] { 9, 10 }, next.getData());
    }

    private static final String[] BAD_PIECES = { "a C that is not a point", "an amount of nothing", "a dated piece on a card with no refund key", "a piece that is on the card already" };
    private static final int[] BAD_WORDS = { SW_WRONG_DATA, SW_WRONG_DATA, SW_NO_REFUND_KEY, SW_PIECE_ON_CARD };

    private static byte[] badPiece(int kind) {
        switch (kind) {
            case 0:  { byte[] p = buildProof(KEYSET, 5, 71); p[44] = 0x04; return p; }
            case 1:  return buildProof(KEYSET, 0, 72);
            case 2:  return buildProof(KEYSET, 5, 73, 1900000000L);
            default: return buildProof(KEYSET, 4, 90);        // the nonce of the piece in place 0, with another amount
        }
    }

    /** A card for the stop rule: PIN, record (with a refund key or without), owner, time; and in place 0 a piece, which `badPiece(3)` is a copy of. */
    private void stopCard(boolean refundKey) {
        simulator = freshCard();
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setCard(MINT, refundKey ? REFUND : NO_REFUND));
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(SW_OK, setTime(T0));
        assertEquals(SW_OK, load(buildProof(KEYSET, 9, 90)).getSW());
    }

    @Test
    @DisplayName("A batch stops at the first piece that cannot be stored: if that is the first, the command is refused with that piece's own word and nothing is stored; if a later one, the earlier ones stay, the answer is their places alone (9000), the ones after it are not stored, and sent alone the bad one gives its word")
    void testABatchStopsAtTheFirstBadPiece() {
        byte[][] good = { buildProof(KEYSET, 1, 81), buildProof(KEYSET, 2, 82), buildProof(KEYSET, 4, 83) };
        for (int kind = 0; kind < BAD_PIECES.length; kind++) {
            for (int position = 0; position < 3; position++) {
                String what = BAD_PIECES[kind] + ", " + (position == 0 ? "first" : position == 1 ? "second" : "third") + " of three";
                stopCard(kind != 2);
                byte[] bad = badPiece(kind);
                byte[][] batch = new byte[3][];
                for (int i = 0, g = 0; i < 3; i++) batch[i] = i == position ? bad : good[g++];
                long balanceBefore = balance();
                ResponseAPDU r = loadBatch(batch);
                if (position == 0) {
                    assertEquals(BAD_WORDS[kind], r.getSW(), what + ": refused with the piece's own word");
                    assertEquals(0, r.getData().length, what);
                    assertEquals(1, info()[3], what + ": nothing stored, not the good pieces after it");
                    assertEquals(balanceBefore, balance(), what);
                    continue;
                }
                assertEquals(SW_OK, r.getSW(), what + ": the ones before it went on, and that is 9000");
                assertEquals(position, r.getData().length, what + ": a byte for each that was stored, and fewer than were sent");
                for (int j = 0; j < position; j++) {
                    assertEquals(1 + j, r.getData()[j] & 0xFF, what + ": the place of piece " + j);
                    assertArrayEquals(asSlot(batch[j]), slot(1 + j), what + ": piece " + j + " is there");
                }
                assertEquals(1 + position, info()[3], what + ": and nothing after the bad one");
                assertEquals(SW_SLOT_EMPTY, sw(new CommandAPDU(CLA, INS_GET_PROOF, 1 + position, 0, 256)), what + ": its place is empty");
                ResponseAPDU alone = load(bad);
                assertEquals(BAD_WORDS[kind], alone.getSW(), what + ": sent alone, the bad one gives its word");
                assertEquals(1 + position, info()[3], what + ": and still stores nothing");
                if (position == 1) {
                    ResponseAPDU rest = load(batch[2]);
                    assertEquals(SW_OK, rest.getSW(), what + ": the one after it, sent again, is stored");
                    assertEquals(2, rest.getData()[0]);
                }
            }
        }
    }

    @Test
    @DisplayName("A piece repeated within one command is refused as on the card already (6A94), because the first copy is in a place by then: the first copy is stored and the answer is its place; the repeat sent alone gives 6A94")
    void testABatchWithARepeat() {
        ready();
        byte[] p = buildProof(KEYSET, 8, 5);
        byte[] q = buildProof(KEYSET, 2, 5);        // the same nonce, another amount
        byte[] g = buildProof(KEYSET, 1, 6);
        ResponseAPDU r = loadBatch(p, q, g);
        assertEquals(SW_OK, r.getSW());
        assertArrayEquals(new byte[] { 0 }, r.getData(), "the first copy only, and not the piece after the repeat");
        assertEquals(SW_SLOT_EMPTY, sw(new CommandAPDU(CLA, INS_GET_PROOF, 1, 0, 256)));
        assertEquals(SW_PIECE_ON_CARD, load(q).getSW(), "the repeat, alone");
        assertEquals(8, balance());
        // the very same bytes three times
        simulator = freshCard();
        ready();
        ResponseAPDU same = loadBatch(p, p, p);
        assertEquals(SW_OK, same.getSW());
        assertArrayEquals(new byte[] { 0 }, same.getData());
        assertEquals(SW_PIECE_ON_CARD, load(p).getSW());
        // a repeat of an earlier piece of the same command, after others
        simulator = freshCard();
        ready();
        byte[] g2 = buildProof(KEYSET, 3, 7);
        ResponseAPDU late = loadBatch(g, g2, g);
        assertEquals(SW_OK, late.getSW());
        assertArrayEquals(new byte[] { 0, 1 }, late.getData(), "the third is a repeat of the first");
        assertEquals(SW_PIECE_ON_CARD, load(g).getSW());
        // and a repeat of a piece that is on the card from an earlier command is refused first
        ResponseAPDU first = loadBatch(g2, g);
        assertEquals(SW_PIECE_ON_CARD, first.getSW(), "when it is the first of the batch");
        assertEquals(0, first.getData().length);
        assertEquals(2, info()[3]);
    }

    @Test
    @DisplayName("A card with room for only one or two of three stores those and answers their places (9000); the rest, sent alone, is 6A84; a full card of 128 answers 6A84 whatever it is sent")
    void testABatchOnACardThatIsNearlyFull() {
        ready();
        loadMany(125, i -> buildProof(KEYSET, 1 + i, i + 1));
        assertEquals(125, info()[3] & 0xFF);
        // room for three
        ResponseAPDU three = loadBatch(buildProof(KEYSET, 1, 1001), buildProof(KEYSET, 1, 1002), buildProof(KEYSET, 1, 1003));
        assertArrayEquals(new byte[] { 125, 126, 127 }, three.getData(), "exactly full");
        assertEquals(128, info()[3] & 0xFF);
        // a full card says so whatever it is sent: a batch, one piece, and data that is not a piece at all
        assertEquals(SW_NO_SPACE, loadBatch(buildProof(KEYSET, 1, 1004), buildProof(KEYSET, 1, 1005), buildProof(KEYSET, 1, 1006)).getSW());
        assertEquals(SW_NO_SPACE, load(buildProof(KEYSET, 1, 1007)).getSW());
        assertEquals(SW_NO_SPACE, loadRaw(new byte[80]).getSW(), "before the data is looked at");
        assertEquals(SW_NO_SPACE, loadRaw(new byte[0]).getSW(), "even none");

        // room for two of three
        simulator = freshCard();
        ready();
        loadMany(126, i -> buildProof(KEYSET, 1 + i, i + 1));
        byte[] x = buildProof(KEYSET, 1, 2001), y = buildProof(KEYSET, 2, 2002), z = buildProof(KEYSET, 4, 2003);
        ResponseAPDU two = loadBatch(x, y, z);
        assertEquals(SW_OK, two.getSW());
        assertArrayEquals(new byte[] { 126, 127 }, two.getData(), "two of three");
        assertEquals(128, info()[3] & 0xFF);
        assertEquals(SW_NO_SPACE, load(z).getSW(), "the third, alone, hears why");

        // room for one of three
        simulator = freshCard();
        ready();
        loadMany(127, i -> buildProof(KEYSET, 1 + i, i + 1));
        ResponseAPDU one = loadBatch(x, y, z);
        assertEquals(SW_OK, one.getSW());
        assertArrayEquals(new byte[] { 127 }, one.getData(), "one of three");
        assertArrayEquals(asSlot(x), slot(127));
        assertEquals(SW_NO_SPACE, load(y).getSW());
        // the refusal of a later piece for want of room is a piece's, not the command's: with a place freed, they go on
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(SW_OK, clearSpent());
        ResponseAPDU again = loadBatch(y, z);
        assertEquals(SW_OK, again.getSW());
        assertArrayEquals(new byte[] { 0 }, again.getData(), "one place was freed: one of two");
    }

    @Test
    @DisplayName("LOAD_PROOF takes 81, 162 or 243 bytes and nothing else: 0, 1, 80, 82, 161, 163, 242, 244 and 324 are 6700, and store nothing")
    void testLoadLengths() {
        ready();
        for (int n : new int[] { 0, 1, 77, 80, 82, 161, 163, 242, 244, 324 }) {
            ResponseAPDU r = loadRaw(new byte[n]);
            assertEquals(SW_WRONG_LENGTH, r.getSW(), n + " bytes");
            assertEquals(0, r.getData().length, n + " bytes");
        }
        // good pieces in a wrong total: 81 + 80, and four whole pieces
        assertEquals(SW_WRONG_LENGTH, loadRaw(concat(buildProof(KEYSET, 1, 1), new byte[80])).getSW());
        assertEquals(SW_WRONG_LENGTH, loadRaw(concat(buildProof(KEYSET, 1, 1), buildProof(KEYSET, 1, 2), buildProof(KEYSET, 1, 3), buildProof(KEYSET, 1, 4))).getSW(), "four pieces are 324 bytes");
        assertEquals(0, info()[3], "none of them stored anything");
        assertEquals(0, balance());
        for (int n : new int[] { 81, 162, 243 }) {
            byte[][] pieces = new byte[n / 81][];
            for (int j = 0; j < pieces.length; j++) pieces[j] = buildProof(KEYSET, 1, 10 * n + j);
            ResponseAPDU r = loadBatch(pieces);
            assertEquals(SW_OK, r.getSW(), n + " bytes");
            assertEquals(n / 81, r.getData().length);
        }
    }

    @Test
    @DisplayName("A batch meets the gates before its data is read, as one piece does: the PIN or the grant, an owner, a record, a place free, and a locked card first of all; each answered whatever the length, and nothing stored; no clock is among them")
    void testABatchMeetsTheGatesFirst() {
        byte[][] three = { buildProof(KEYSET, 4, 1), buildProof(KEYSET, 2, 2), buildProof(KEYSET, 1, 3) };
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_SECURITY_NOT_SATIS, loadBatch(three).getSW(), "the PIN, not verified");
        assertEquals(SW_SECURITY_NOT_SATIS, loadRaw(new byte[80]).getSW(), "whatever the length");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_NO_OWNER, loadBatch(three).getSW(), "no owner");
        assertEquals(SW_NO_OWNER, loadRaw(new byte[80]).getSW());
        assertEquals(SW_OK, setCard(MINT, REFUND));
        assertEquals(SW_NO_OWNER, loadBatch(three).getSW(), "a record, and still no owner");
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(SW_WRONG_LENGTH, loadRaw(new byte[80]).getSW(), "an owner and a record, and the gates are all open: a length that is no piece's is the word now, whatever the clock");
        assertEquals(0, now(), "no block header seen");
        assertEquals(0, info()[3], "nothing was loaded by it");
        assertArrayEquals(new byte[] { 0, 1, 2 }, loadBatch(three).getData(), "a batch loads on a card that has seen no header: the first day is on trust");
        assertEquals(0, now());

        // no record at all
        simulator = freshCard();
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(SW_NO_CARD_RECORD, loadBatch(three).getSW());
        assertEquals(SW_NO_CARD_RECORD, loadRaw(new byte[80]).getSW());

        // a new tap: the PIN is not verified, and the owner's grant opens it
        simulator = freshCard();
        ready();
        reselect();
        assertEquals(SW_SECURITY_NOT_SATIS, loadBatch(three).getSW(), "no PIN in this tap");
        assertEquals(SW_OK, allowLoad());
        ResponseAPDU granted = loadBatch(three);
        assertEquals(SW_OK, granted.getSW(), "the owner's grant");
        assertArrayEquals(new byte[] { 0, 1, 2 }, granted.getData());

        // a locked card takes no writes, and says so before anything else, with the PIN verified or not
        simulator = freshCard();
        ready();
        assertEquals(SW_OK, lock());
        assertEquals(SW_NOT_ALLOWED, loadBatch(three).getSW(), "locked");
        assertEquals(SW_NOT_ALLOWED, loadRaw(new byte[80]).getSW(), "locked, whatever the length");
        reselect();
        assertEquals(SW_NOT_ALLOWED, loadBatch(three).getSW(), "locked, and no PIN");
        assertEquals(0, info()[3]);
    }

    /** A card that has paid: 16 and 8 loaded, the 16 spent, and a new tap begun with no PIN, so that the change may go on. */
    private void paidCard() {
        simulator = freshCard();
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 2)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        reselect();
        assertEquals(1, info()[29], "the tap after a payment may load");
    }

    @Test
    @DisplayName("The change grant (the tap after a payment may load with no PIN) loads a batch and is used up as one piece uses it: by the first piece stored and not by one that is refused; a verified PIN or the owner's grant leaves it standing")
    void testTheChangeGrantLoadsABatch() {
        paidCard();
        assertEquals(SW_OK, clearSpent(), "the burned place is freed, with no PIN");
        ResponseAPDU change = loadBatch(buildProof(KEYSET, 4, 3), buildProof(KEYSET, 2, 4));
        assertEquals(SW_OK, change.getSW(), "the change, two pieces to a command, with no PIN");
        assertArrayEquals(new byte[] { 0, 2 }, change.getData());
        assertEquals(1, info()[29], "the same tap may still load the rest of the change");
        assertEquals(SW_OK, loadBatch(buildProof(KEYSET, 1, 5), buildProof(KEYSET, 1, 6), buildProof(KEYSET, 1, 7)).getSW(), "three more, still no PIN");
        assertEquals(8 + 4 + 2 + 3, balance());
        assertEquals(SW_PIN_NEEDED, spend(1).getSW(), "and nothing else the PIN opens");
        reselect();
        assertEquals(0, info()[29], "the change landed: the next fresh tap has no grant");
        assertEquals(SW_SECURITY_NOT_SATIS, loadBatch(buildProof(KEYSET, 1, 8), buildProof(KEYSET, 1, 9)).getSW(), "and loads nothing with no PIN");
        assertEquals(SW_SECURITY_NOT_SATIS, loadRaw(new byte[80]).getSW());

        // a batch whose first piece is refused leaves the note standing, as a refused piece alone does
        paidCard();
        assertEquals(SW_OK, clearSpent());
        byte[] notPoint = buildProof(KEYSET, 4, 11);
        notPoint[44] = 0x04;
        assertEquals(SW_WRONG_DATA, loadBatch(notPoint, buildProof(KEYSET, 2, 12)).getSW());
        assertEquals(1, info()[29], "still in this tap");
        reselect();
        assertEquals(1, info()[29], "and the next: nothing landed, so the note stands");
        assertEquals(SW_OK, loadBatch(buildProof(KEYSET, 4, 11), buildProof(KEYSET, 2, 12)).getSW());
        reselect();
        assertEquals(0, info()[29], "the change landing used it up");

        // a later piece refused: the first landed and used it up
        paidCard();
        assertEquals(SW_OK, clearSpent());
        ResponseAPDU some = loadBatch(buildProof(KEYSET, 4, 21), notPoint, buildProof(KEYSET, 2, 22));
        assertEquals(SW_OK, some.getSW());
        assertArrayEquals(new byte[] { 0 }, some.getData());
        reselect();
        assertEquals(0, info()[29], "the first piece landed, and the note is gone");

        // a verified PIN or the owner's grant is not the change grant: the note stays
        paidCard();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, loadBatch(buildProof(KEYSET, 4, 31), buildProof(KEYSET, 2, 32)).getSW());
        reselect();
        assertEquals(1, info()[29], "loaded with the PIN: the note is not used");
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_OK, loadBatch(buildProof(KEYSET, 1, 33), buildProof(KEYSET, 1, 34)).getSW());
        reselect();
        assertEquals(1, info()[29], "loaded with the owner's grant: nor is it");
        assertEquals(SW_OK, loadBatch(buildProof(KEYSET, 1, 35), buildProof(KEYSET, 1, 36)).getSW(), "the change grant, then");
        reselect();
        assertEquals(0, info()[29]);
    }

    @Test
    @DisplayName("The text kept beside a place is written once, in LOAD_PROOF's one-piece step, before that piece's data and long before its status byte, and is read only for a place named in a payment; SPEND_ALL_BEGIN converts nothing per piece")
    void testTheKeptTextIsWrittenFirstAndReadByNothingElse() throws Exception {
        String code = appletCode();
        String loadOne = body(code, "private short loadOne(", "private void processClearSpent(");
        int hexFirst = loadOne.indexOf("slotHex");
        int hexLast = loadOne.lastIndexOf("slotHex");
        int data = loadOne.indexOf("Util.arrayCopy(buf, in, proofStorage");
        int status = loadOne.indexOf("STATUS_UNSPENT", data);
        assertTrue(hexFirst > 0 && hexFirst < hexLast && hexLast < data && data < status,
            "both halves of the text are written before the piece's data, and the status byte is last");
        assertEquals(2, count(loadOne, "slotHex"), "two writes: the nonce's hex and the C's");
        String secretInto = body(code, "private void secretInto(", "private void processAuth(");
        assertEquals(2, count(secretInto, "slotHex"), "and read in two places, to the hash");
        assertFalse(secretInto.contains("beginTransaction") || secretInto.contains("arrayCopy"), "reading it writes nothing");
        // no other method names it: the declaration and the allocation are all that is left
        String rest = code.replace(loadOne, "").replace(secretInto, "");
        assertEquals(2, count(rest, "slotHex"), "the declaration and the allocation");
        // a payment is begun without turning anything to hex per piece
        String begin = body(code, "private void processSpendAllBegin(", "private void processSpendAllOutputs(");
        assertFalse(begin.contains("toHex(") || begin.contains("toDecimal(") || begin.contains("hexInto("), "BEGIN converts nothing per piece");
        assertEquals(1, count(begin, "secretTail("), "the part of the secret that is the same for every piece is built once");
        assertTrue(begin.indexOf("secretTail(") < begin.indexOf("secretInto("), "before the pieces are hashed");
        // the places read are unspent ones: BEGIN refuses an empty or a spent one first
        assertTrue(begin.indexOf("SW_SLOT_EMPTY") < begin.indexOf("secretInto(") && begin.indexOf("SW_ALREADY_SPENT") < begin.indexOf("secretInto("),
            "the text of a place is hashed only after it has been seen to be unspent");
    }

    // =========================================================================
    // The limit on a payment hidden, the log's account of what was put on and of the clock, the receipts
    // =========================================================================

    /** What the applet answers for a P1 or a P2 it does not have: ISO7816.SW_INCORRECT_P1P2. (6B00 is SW_WRONG_P1P2, which it does not use.) */
    static final int SW_INCORRECT_P1P2 = 0x6A86;
    /** A receipt (1.15): the block time (4), the time the terminal told (4), the sats (4), the message's digest (32), the first output (33). 73 before. */
    static final int RECEIPT_LEN = 77;

    /** An answer as one run of bytes, its status word first: for comparing what two cards said. */
    private static byte[] bytesOf(ResponseAPDU r) { return concat(new byte[] { (byte) (r.getSW() >> 8), (byte) r.getSW() }, r.getData()); }
    private ResponseAPDU receipts(int back) { return transmit(new CommandAPDU(CLA, INS_GET_LOG, 1, back, 256)); }

    /** What GET_LOG P1 = 1 holds: the count of payments ever, and the receipts, newest first, read three at a time. */
    private static final class Held {
        long count;
        final java.util.List<byte[]> receipts = new java.util.ArrayList<>();
    }

    /** All the receipts the card holds, read with the owner's grant, which the caller has given in this tap. */
    private Held heldReceipts() {
        Held held = new Held();
        for (int back = 0; ; back += 3) {
            ResponseAPDU r = receipts(back);
            assertEquals(SW_OK, r.getSW(), "receipts from " + back);
            byte[] d = r.getData();
            if (back == 0) held.count = readUint32(d, 0);
            else assertEquals(held.count, readUint32(d, 0), "the count is the same on every page");
            assertEquals(0, (d.length - 4) % RECEIPT_LEN, "whole receipts");
            int n = (d.length - 4) / RECEIPT_LEN;
            assertTrue(n <= 3, "three at most");
            for (int k = 0; k < n; k++) held.receipts.add(Arrays.copyOfRange(d, 4 + RECEIPT_LEN * k, 4 + RECEIPT_LEN * (k + 1)));
            if (n < 3) return held;
        }
    }

    /**
     * A receipt as it is to be: the card's clock when the payment was signed, the time of the newest block it had taken (4), the
     * time the terminal told in that time in the field, zeros if it told none (4), what its pieces were worth (4), SHA-256 of the
     * message that was signed, built here from the pieces and the outputs and not asked of the card (32), and the first output's
     * blinded message as it was given (33), or zeros where there was no output.
     */
    private byte[] receiptFor(long clock, long told, long worth, byte[][] slotData, byte[][] outputs) {
        byte[] hash = sha256(allMessage(cardKey(), REFUND, slotData, outputs).getBytes(StandardCharsets.UTF_8));
        byte[] first = outputs.length == 0 ? new byte[33] : Arrays.copyOfRange(outputs[0], 4, 37);
        return concat(u32(clock), u32(told), u32(worth), hash, first);
    }
    /** A receipt of a payment made in a time in the field in which the terminal told no time: the told time is zeros. */
    private byte[] receiptFor(long clock, long worth, byte[][] slotData, byte[][] outputs) {
        return receiptFor(clock, 0, worth, slotData, outputs);
    }

    /** A payment of those places whose outputs are sent in commands of the sizes given (cycled): the signature, or whatever refused it. */
    private ResponseAPDU payGrouped(int[] slots, byte[][] outputs, int... groups) {
        waitAnswers.clear();
        ResponseAPDU begun = transmit(beginCommand(slots));
        if (begun.getSW() != SW_OK) return begun;
        int at = 0, g = 0;
        while (at < outputs.length) {
            int n = Math.min(groups[g++ % groups.length], outputs.length - at);
            ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, concat(Arrays.copyOfRange(outputs, at, at + n))));
            if (r.getSW() != SW_OK) return r;
            at += n;
        }
        return signAll();
    }

    // ---- 1: the limit on one payment is the holder's to read ------------------------------

    @Test
    @DisplayName("GET_INFO asked for with P1 = 1 says the limit on one payment (bytes 30..33) only with the owner's grant given in this tap: to everyone else, under a verified PIN too, those four bytes are zeros, which is what a card with no such limit says; bytes 34..41 are zeros whoever asks; a terminal cannot give itself the grant; and the limit holds for whoever pays")
    void testTheLimitOnAPaymentIsSaidToTheGrantAlone() throws Exception {
        // a card with no such limit, asked under the PIN, and with the grant
        readyWithLimit(0);
        byte[] noLimit = infoTap();
        assertEquals(SW_OK, allowLoad());
        assertArrayEquals(noLimit, infoTap(), "with the grant a card with no limit says zeros, which is true");
        // a card with one
        simulator = freshCard();
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 100));
        byte[] plain = info();
        byte[] under = infoTap();
        assertEquals(42, under.length);
        assertArrayEquals(plain, Arrays.copyOf(under, 30), "the thirty bytes are as they were");
        assertArrayEquals(new byte[12], Arrays.copyOfRange(under, 30, 42), "under the PIN, which a till has: the limit and the eight bytes after it are zeros");
        assertArrayEquals(under, Arrays.copyOf(infoTag(), 42), "P1 = 2 (1.19) gives the same forty-two bytes first, and says no more of the limit");
        assertArrayEquals(noLimit, under, "a terminal under the PIN cannot tell this card from one with no limit by asking");
        // with the owner's grant, in this tap
        assertEquals(SW_OK, allowLoad());
        byte[] granted = infoTap();
        assertEquals(100, readUint32(granted, 30), "the limit, to the owner");
        assertArrayEquals(Arrays.copyOf(under, 30), Arrays.copyOf(granted, 30), "the thirty bytes are the same");
        assertArrayEquals(new byte[8], Arrays.copyOfRange(granted, 34, 42), "and the eight bytes after it are zeros still");
        assertArrayEquals(plain, info(), "asked for without P1 = 1 the answer is the thirty bytes it always was");
        // the grant goes with the tap; the PIN is not the grant
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(0, paymentLimitAsATerminalSeesIt(), "a new SELECT takes the grant away, and a verified PIN is not one");
        assertEquals(SW_OK, allowLoad());
        assertEquals(100, readUint32(infoTap(), 30));
        simulator.reset();
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(0, paymentLimitAsATerminalSeesIt(), "nor does it outlast the card's leaving the field");
        reselect();
        assertEquals(0, paymentLimitAsATerminalSeesIt(), "and with no PIN in this tap, nothing");
        // a terminal cannot give itself the grant
        assertEquals(SW_OWNER_PROOF, sw(allowLoadCommand(new byte[8])), "no nonce asked for");
        assertEquals(SW_OWNER_PROOF, sw(allowLoadCommand(ownerProof(L_LOAD, OTHER_OWNER, nonceBytes(), new byte[0]))), "another key's proof");
        assertEquals(SW_OWNER_PROOF, sw(allowLoadCommand(ownerProof(L_PIN, OWNER, nonceBytes(), new byte[0]))), "another command's proof");
        assertEquals(0, paymentLimitAsATerminalSeesIt());
        // and the limit holds for whoever pays, as it always did
        assertEquals(SW_OK, verify(TEST_PIN));
        long[] amounts = { 100, 100, 50 };
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        ResponseAPDU r = spendAll(new int[] { 0, 1, 2 }, new byte[0][]);
        assertEquals(SW_OK, r.getSW());
        assertEquals(waitsRule(100, 250, 0), waitsTaken(), "250 under a limit of 100, which the terminal was never told");
    }

    /** What a terminal under the PIN, with no grant, can read of a card with that limit on a payment, and how many waits a payment of 250 takes. */
    private java.util.List<byte[]> whatATerminalSees(long limit, int[] waitsOut) {
        simulator = freshCard();
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, limit));
        long[] amounts = { 100, 100, 50 };
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        newTap();       // the PIN verified, and no grant
        java.util.List<byte[]> seen = new java.util.ArrayList<>();
        seen.add(bytesOf(transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256))));
        seen.add(bytesOf(transmit(new CommandAPDU(CLA, INS_GET_INFO, 1, 0, 256))));
        seen.add(bytesOf(transmit(new CommandAPDU(CLA, INS_GET_CARD, 0, 0, 256))));
        seen.add(bytesOf(transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256))));
        seen.add(bytesOf(transmit(new CommandAPDU(CLA, INS_GET_PIECES, 0, 0, 256))));
        seen.add(bytesOf(transmit(new CommandAPDU(CLA, INS_GET_PIECES, 0, 3, 256))));
        seen.add(bytesOf(transmit(new CommandAPDU(CLA, INS_GET_PIECES, 0, 2, new byte[] { 0, 1, 2 }, 256))));
        seen.add(bytesOf(transmit(new CommandAPDU(CLA, INS_GET_PROOF, 1, 0, 256))));
        seen.add(bytesOf(transmit(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4))));
        seen.add(bytesOf(transmit(new CommandAPDU(CLA, INS_GET_PROOF_COUNT, 0, 0, 1))));
        seen.add(bytesOf(transmit(new CommandAPDU(CLA, INS_GET_LOG, 0, 0, 256))));
        seen.add(bytesOf(transmit(new CommandAPDU(CLA, INS_GET_LOG, 1, 0, 256))));
        seen.add(bytesOf(transmit(beginCommand(0, 1, 2))));
        ResponseAPDU first = transmit(SIGN_ALL);
        seen.add(bytesOf(first));
        assertNotYet(first, "250 is over both limits");
        signAll();
        waitsOut[0] = 1 + waitsTaken();
        return seen;
    }

    @Test
    @DisplayName("Nothing a terminal without the grant can read reveals the limit on a payment: two cards that differ only in that limit (100 and 150) and the same payment of 250 over both give every answer up to and including the first wait byte for byte alike; only the number of waits differs")
    void testNothingATerminalCanReadRevealsTheLimit() {
        int[] a = new int[1], b = new int[1];
        java.util.List<byte[]> seenA = whatATerminalSees(100, a);
        java.util.List<byte[]> seenB = whatATerminalSees(150, b);
        String[] names = { "GET_INFO", "GET_INFO P1=1", "GET_CARD", "GET_SLOT_STATUS", "GET_PIECES", "GET_PIECES short", "GET_PIECES some", "GET_PROOF", "GET_BALANCE",
                           "GET_PROOF_COUNT", "GET_LOG", "GET_LOG receipts (refused under the PIN)", "SPEND_ALL_BEGIN's answer", "the first SPEND_ALL_SIGN's answer" };
        assertEquals(names.length, seenA.size());
        for (int i = 0; i < names.length; i++) {
            assertArrayEquals(seenA.get(i), seenB.get(i), names[i] + " is the same for a limit of 100 and a limit of 150");
        }
        assertEquals(0x6982, ((seenA.get(11)[0] & 0xFF) << 8) | (seenA.get(11)[1] & 0xFF), "the receipts are refused under the PIN, to both");
        assertEquals(waitsRule(100, 250, 0), a[0], "250 under 100: three limits' worth");
        assertEquals(waitsRule(150, 250, 0), b[0], "250 under 150: two limits' worth");
        // a card with no limit at all says the same of what it is asked before the payment; the wait is where a limit is found out, by trying
        simulator = freshCard();
        readyWithLimit(0);
        long[] amounts = { 100, 100, 50 };
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        newTap();
        assertArrayEquals(seenA.get(0), bytesOf(transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256))), "GET_INFO, on a card with no limit at all");
        assertArrayEquals(seenA.get(1), bytesOf(transmit(new CommandAPDU(CLA, INS_GET_INFO, 1, 0, 256))), "GET_INFO P1=1, on a card with no limit at all");
        assertArrayEquals(seenA.get(2), bytesOf(transmit(new CommandAPDU(CLA, INS_GET_CARD, 0, 0, 256))), "GET_CARD, on a card with no limit at all");
        ResponseAPDU none = spendAll(new int[] { 0, 1, 2 }, new byte[0][]);
        assertEquals(SW_OK, none.getSW());
        assertEquals(0, waitsTaken(), "and the payment goes at once");
    }

    @Test
    @DisplayName("A payment that waits answers 00 01 every time it is asked, however many waits it has: 42 of them, and 1022, and never how many are left; the signature follows the last, and not before")
    void testTheWaitNeverSaysHowManyAreLeft() throws Exception {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 100));
        assertEquals(SW_OK, load(buildProof(KEYSET, 1000, 1)).getSW());
        byte[] named = slot(0);
        newTap();
        // the whole count, from a beginning: 42 answers of 00 01 and then the signature
        assertEquals(SW_OK, sw(beginCommand(0)));
        for (int i = 1; i <= 42; i++) assertNotYet(transmit(SIGN_ALL), "wait " + i + " of 42");
        ResponseAPDU sig = transmit(SIGN_ALL);
        assertEquals(SW_OK, sig.getSW());
        assertEquals(64, sig.getData().length, "after the 42nd, the signature");
        assertTrue(signedForAll(sig.getData(), new byte[][] { named }, new byte[0][], REFUND));
        // the most it can be asked to wait: 1022, each of them the same
        simulator = freshCard();
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 1));
        assertEquals(SW_OK, load(buildProof(KEYSET, 300, 1)).getSW());
        newTap();
        ResponseAPDU r = spend(0);
        assertEquals(SW_OK, r.getSW());
        assertEquals(WAITS_MOST, waitsTaken(), "all 1022 were 00 01: signAll checks each");
        assertEquals(64, r.getData().length);
    }

    // ---- 3: the log's entries are twenty bytes, and LOAD_PROOF writes them ------------------

    @Test
    @DisplayName("A log entry is twenty bytes: the clock when the tap's first entry was made (4), sats signed for (4), pieces signed (1), refused (1), flags (1), pieces put on (1), sats put on (4), and the time the terminal told (4); the answer is 16 bytes of counts and the entries, 176 at most; one entry holds a tap's loads and its payments")
    void testTheLogEntryIsTwentyBytes() {
        ready();        // the card's set-up writes nothing: the tap is put on by the first piece
        assertEquals(16, log().length, "four counts and no taps");
        assertEquals(SW_OK, tell(T0 + 9), "the terminal's own clock, a few seconds ahead of the block's: a note");
        ResponseAPDU put = loadBatch(buildProof(KEYSET, 10, 1), buildProof(KEYSET, 20, 2), buildProof(KEYSET, 30, 3));
        assertArrayEquals(new byte[] { 0, 1, 2 }, put.getData());
        assertEquals(SW_OK, spendAll(new int[] { 0, 1 }, new byte[0][]).getSW());
        byte[] d = log();
        assertEquals(16 + 20, d.length, "sixteen bytes of counts and one entry of twenty");
        assertEquals(1, readUint32(d, 0), "one tap, with a load and a payment in it");
        assertEquals(30, readUint32(d, 4), "sats signed for, ever");
        assertEquals(0, readUint32(d, 8), "refused");
        assertEquals(0, readUint32(d, 12), "runs");
        assertEquals(T0, readUint32(d, 16), "the entry: the clock");
        assertEquals(30, readUint32(d, 20), "sats signed for in it");
        assertEquals(2, d[24], "pieces signed");
        assertEquals(0, d[25], "refused");
        assertEquals(0, d[26], "flags");
        assertEquals(3, d[27], "pieces put on");
        assertEquals(60, readUint32(d, 28), "sats put on");
        assertEquals(T0 + 9, readUint32(d, 32), "and the time the terminal told, which the card took on trust and trusts for nothing");
        assertEquals(T0 + 9, logTold(0));
        // a refusal in the same tap goes into the same entry
        assertEquals(SW_OK, setLimits(20, 0));
        assertEquals(SW_OVER_LIMIT, spend(2).getSW(), "30 is over a day of 20");
        d = log();
        assertEquals(36, d.length, "still one tap");
        assertEquals(1, d[25], "one refused");
        assertEquals(3, d[27], "the loads are as they were");
        assertEquals(60, readUint32(d, 28));
        assertEquals(T0 + 9, readUint32(d, 32));
        // a time told after the entry was begun is for the next entry: the entry keeps what was told when it was made
        assertEquals(SW_OK, tell(T0 + 99));
        assertEquals(T0 + 9, logTold(0), "this tap's entry is as it was");
    }

    @Test
    @DisplayName("LOAD_PROOF writes the log once for a command, after the pieces are stored: the pieces and the sats of those that were stored, in this tap's entry, which it begins if the tap had none; one piece, a batch, a batch that stops, the change loaded with no PIN, and a load in a tap that paid are all in the entry; a command that stores nothing writes nothing")
    void testLoadsAreInTheLog() throws Exception {
        ready();
        assertEquals(0, logTaps());
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 1)).getSW());
        assertEquals(1, logTaps(), "a tap in which anything was put on is a tap in the log");
        assertArrayEquals(new long[] { T0, 0, 0, 0, 0 }, logTap(0));
        assertEquals(0, logTold(0), "the terminal told no time: zeros");
        assertArrayEquals(new long[] { 1, 10 }, logLoaded(0), "one piece, 10 sats");
        // a second command and a batch, in the same tap: the same entry, the pieces and sats added up
        assertEquals(SW_OK, load(buildProof(KEYSET, 20, 2)).getSW());
        assertEquals(SW_OK, loadBatch(buildProof(KEYSET, 1, 3), buildProof(KEYSET, 2, 4), buildProof(KEYSET, 4, 5)).getSW());
        assertEquals(1, logTaps(), "one tap, however many commands");
        assertArrayEquals(new long[] { 5, 37 }, logLoaded(0), "five pieces, 10 + 20 + 1 + 2 + 4");
        // a batch that stops: the pieces that were stored are counted and the one that was refused is not, nor those after it
        byte[] notAPoint = buildProof(KEYSET, 4, 9);
        notAPoint[44] = 0x04;
        ResponseAPDU stopped = loadBatch(buildProof(KEYSET, 8, 6), notAPoint, buildProof(KEYSET, 16, 7));
        assertArrayEquals(new byte[] { 5 }, stopped.getData());
        assertArrayEquals(new long[] { 6, 45 }, logLoaded(0), "6 pieces; the 8 was stored and the 4 and the 16 were not");
        // a command that stores nothing writes nothing: not an entry, not a tap, in a tap of its own
        newTap();
        byte[] before = log();
        assertEquals(SW_WRONG_DATA, loadBatch(notAPoint, buildProof(KEYSET, 16, 7)).getSW());
        assertEquals(SW_WRONG_DATA, load(notAPoint).getSW());
        assertEquals(SW_PIECE_ON_CARD, load(buildProof(KEYSET, 1, 1)).getSW());
        assertEquals(SW_WRONG_LENGTH, loadRaw(new byte[80]).getSW());
        assertArrayEquals(before, log(), "none of them wrote the log");
        reselect();     // no PIN: the gate refuses
        assertEquals(SW_SECURITY_NOT_SATIS, loadBatch(buildProof(KEYSET, 16, 7), buildProof(KEYSET, 16, 8)).getSW());
        assertEquals(SW_OK, verify(TEST_PIN));
        assertArrayEquals(before, log(), "nor a load that was refused at the gate");
        // a payment and a load in the same tap are one entry
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 7, 20)).getSW());
        assertEquals(2, logTaps());
        assertArrayEquals(new long[] { T0, 10, 1, 0, 0 }, logTap(0), "the payment");
        assertArrayEquals(new long[] { 1, 7 }, logLoaded(0), "and the load, in the same entry");
        assertArrayEquals(new long[] { 6, 45 }, logLoaded(1), "the tap before it is as it was");

        // the change, loaded in the tap after a payment with no PIN, is a tap in the log
        simulator = freshCard();
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 2)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        simulator.reset();
        reselect();
        assertEquals(1, info()[29], "the tap after a payment may load with no PIN");
        assertEquals(SW_OK, clearSpent());
        ResponseAPDU change = loadBatch(buildProof(KEYSET, 4, 3), buildProof(KEYSET, 2, 4));
        assertArrayEquals(new byte[] { 0, 2 }, change.getData());
        assertEquals(SW_OK, verify(TEST_PIN), "the PIN, to read the log");
        assertEquals(2, logTaps());
        assertArrayEquals(new long[] { T0, 0, 0, 0, 0 }, logTap(0), "the tap of the change: nothing signed for");
        assertArrayEquals(new long[] { 2, 6 }, logLoaded(0), "two pieces, 4 + 2");
        assertArrayEquals(new long[] { T0, 16, 1, 0, 0 }, logTap(1), "after the tap that paid");
        assertArrayEquals(new long[] { 2, 24 }, logLoaded(1), "which had put 16 and 8 on");

        // what is put on stops at 255 pieces and at the top of four bytes of sats
        simulator = freshCard();
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 5, 1)).getSW());
        int entryAt = 21 + (int) (((logTaps() - 1) & 7) * 20);
        field("cardLog")[entryAt + 11] = (byte) 253;
        Arrays.fill(field("cardLog"), entryAt + 12, entryAt + 16, (byte) 0xFF);
        field("cardLog")[entryAt + 15] = (byte) 0xF0;
        assertEquals(SW_OK, loadBatch(buildProof(KEYSET, 5, 2), buildProof(KEYSET, 4, 3)).getSW());
        assertArrayEquals(new long[] { 255, 0xFFFFFFF0L + 9 }, logLoaded(0), "two pieces on 253 are 255 and 9 on the top less 15 is 4294967289");
        assertEquals(SW_OK, load(buildProof(KEYSET, 100, 4)).getSW());
        assertArrayEquals(new long[] { 255, 4294967295L }, logLoaded(0), "one more piece stops at 255 and the sats at the top of four bytes");
        assertEquals(SW_OK, loadBatch(buildProof(KEYSET, 4294967295L, 5), buildProof(KEYSET, 5, 6)).getSW());
        assertArrayEquals(new long[] { 255, 4294967295L }, logLoaded(0), "a batch worth more than four bytes holds is the top of them, and no wrap");
    }

    @Test
    @DisplayName("The eight-entry ring is right with twenty-byte entries: twenty taps of loads, a payment and, in most, a time the terminal told, and after each the whole answer is the counts and the last eight taps newest first, every field")
    void testTheLogRingHoldsEightOfTwentyBytes() {
        ready();
        long taps = 0, sats = 0, marks = 0;
        java.util.LinkedList<byte[]> entries = new java.util.LinkedList<>();     // newest first
        java.util.LinkedList<long[]> unspent = new java.util.LinkedList<>();     // { place, amount }, oldest first
        for (int i = 1; i <= 20; i++) {
            newTap();
            long time = T0 + 1000L * i;
            assertEquals(SW_OK, setTime(time), "a block in this power-up, a thousand seconds on");
            long flags = 0;
            long told = i % 5 == 0 ? 0 : time + 3 + i;      // every fifth tap the terminal tells no time at all
            if (told != 0) assertEquals(SW_OK, tell(told), "the terminal's own clock, a few seconds past the block's");
            if (i % 4 == 0) {
                assertEquals(SW_OK, setTime(time + 500), "a second block 500 seconds on: the clock moves, and the entry this tap gets begins at it; nothing is marked");
                time += 500;
            }
            int k = 1 + i % 3;
            long amount = 5 + i;
            byte[][] batch = new byte[k][];
            for (int j = 0; j < k; j++) batch[j] = buildProof(KEYSET, amount, 100 * i + j);
            ResponseAPDU put = loadBatch(batch);
            assertEquals(SW_OK, put.getSW());
            assertEquals(k, put.getData().length);
            for (int j = 0; j < k; j++) unspent.add(new long[] { put.getData()[j] & 0xFF, amount });
            long[] oldest = unspent.removeFirst();
            assertEquals(SW_OK, spend((int) oldest[0]).getSW());
            taps++;
            sats += oldest[1];
            byte[] entry = concat(u32(time), u32(oldest[1]), new byte[] { 1, 0, (byte) flags, (byte) k }, u32(k * amount), u32(told));
            assertEquals(20, entry.length);
            entries.addFirst(entry);
            while (entries.size() > 8) entries.removeLast();
            byte[] expected = concat(u32(taps), u32(sats), u32(0), u32(marks), concat(entries.toArray(new byte[0][])));
            assertArrayEquals(expected, log(), "the log after tap " + i);
        }
        assertEquals(16 + 8 * 20, log().length);
        assertEquals(0, logTampers(), "no clock moved on in a tap is marked: the count of marked things is the runs of refusals alone");
    }

    @Test
    @DisplayName("GET_LOG with a P1 other than 0 or 1 is refused (the applet's word is 6A86, ISO7816.SW_INCORRECT_P1P2), before the PIN is looked at, and answers nothing")
    void testGetLogRefusesAP1ItDoesNotHave() {
        ready();
        for (int p1 : new int[] { 2, 3, 0x10, 0x7f, 0x80, 0xff }) {
            ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_GET_LOG, p1, 0, 256));
            assertEquals(SW_INCORRECT_P1P2, r.getSW(), "P1 = " + p1);
            assertEquals(0, r.getData().length);
        }
        reselect();     // no PIN: the refusal is the same, and not a demand for the PIN
        assertEquals(SW_INCORRECT_P1P2, sw(new CommandAPDU(CLA, INS_GET_LOG, 2, 0, 256)));
        assertEquals(SW_SECURITY_NOT_SATIS, sw(new CommandAPDU(CLA, INS_GET_LOG, 0, 0, 256)), "P1 = 0 still wants the PIN or the grant");
        assertEquals(SW_SECURITY_NOT_SATIS, sw(new CommandAPDU(CLA, INS_GET_LOG, 1, 0, 256)), "and so do the receipts");
    }

    @Test
    @DisplayName("GET_PIECES with a P2 other than 0, 2 or 3 is refused (the applet's word is 6A86, ISO7816.SW_INCORRECT_P1P2) and not answered as the whole listing: 1, the brief listing of the sixty-four-place card, among them; 0, 2 and 3 are answered")
    void testGetPiecesRefusesAFormItDoesNotHave() {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 5, 1)).getSW());
        for (int p2 : new int[] { 1, 4, 5, 0x10, 0x7f, 0x80, 0xff }) {
            ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_GET_PIECES, 0, p2, 256));
            assertEquals(SW_INCORRECT_P1P2, r.getSW(), "P2 = " + p2);
            assertEquals(0, r.getData().length);
            assertEquals(SW_INCORRECT_P1P2, transmit(new CommandAPDU(CLA, INS_GET_PIECES, 0, p2, new byte[] { 0 }, 256)).getSW(), "P2 = " + p2 + " with data");
        }
        assertEquals(SW_OK, pieces(0).getSW());
        assertEquals(SW_OK, shortPieces(0).getSW());
        assertEquals(SW_OK, somePieces(new byte[] { 0 }).getSW());
    }

    // ---- 4: the terminal's own time (TELL_TIME), and no mark of a clock moved on twice ----------

    @Test
    @DisplayName("The layouts of 1.15: a receipt is 77 bytes (block time, told time, sats, digest, output) in a ring of sixteen after a count of four, 1,236 bytes; a log entry is 20 bytes (the old 16, then the told time) in a ring of eight after a head of 21, 181 bytes; the record's clock proof is bits (4), hash (32) and zeros (29) at 120, and the clock follows at 185")
    void testTheLayoutsOfTheLogAndTheReceipts() throws Exception {
        assertEquals(RECEIPT_LEN, CashuApplet.RECEIPT_LEN);
        assertEquals(77, CashuApplet.RECEIPT_LEN);
        assertEquals(4 + 16 * 77, CashuApplet.RECEIPTS_LEN);
        assertEquals(1236, CashuApplet.RECEIPTS_LEN);
        assertEquals(1236, field("cardReceipts").length);
        assertEquals(20, CashuApplet.LOG_ENTRY_LEN);
        assertEquals(16, CashuApplet.LOG_E_TOLD, "the told time follows the old sixteen bytes of an entry");
        assertEquals(CashuApplet.LOG_E_TOLD + 4, CashuApplet.LOG_ENTRY_LEN);
        assertEquals(21 + 8 * 20, CashuApplet.LOG_LEN);
        assertEquals(181, CashuApplet.LOG_LEN);
        assertEquals(181, field("cardLog").length);
        assertEquals(120, CashuApplet.CARD_BITS_OFFSET);
        assertEquals(124, CashuApplet.CARD_HEADER_OFFSET);
        assertEquals(CashuApplet.CARD_BITS_OFFSET + 4 + 32 + 29, CashuApplet.CARD_NOW_OFFSET, "bits, hash and 29 zeros take the 65 bytes the time key had, and the clock is where it was");
        assertEquals(185, CashuApplet.CARD_NOW_OFFSET);
        assertEquals(0x02, CashuApplet.VERSION_MAJOR);
        assertEquals(0x01, CashuApplet.VERSION_MINOR);
        assertEquals(212, CashuApplet.CARD_RECORD_LEN, "and the record is the length it was");
        assertEquals(212, field("cardRecord").length);
    }

    @Test
    @DisplayName("TELL_TIME is a note: the time the terminal told in this time in the field is written into every receipt made in it (offset 4) and every log entry made in it (offset 16), zeros where none was told; a later telling replaces the earlier for what is written after it, and the entries already made keep the time they were made with")
    void testTellTimeIsANoteForTheReceiptsAndTheLog() throws Exception {
        readyWithLimit(0);
        byte[][] sent = new byte[5][];
        for (int i = 0; i < sent.length; i++) {
            sent[i] = buildProof(KEYSET, 10 + i, i + 1);
            assertEquals(SW_OK, load(sent[i]).getSW());
        }
        assertEquals(0, logTold(0), "the set-up told no time: the entry the first load began has zeros");
        // a tap in which the terminal tells its time before the payment
        newTap();
        long told = T0 + 12345;
        assertEquals(SW_OK, tell(told));
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(told, logTold(0), "the log entry, at 16");
        assertEquals(T0, logTap(0)[0], "beside the card's own time, which is the block's");
        assertEquals(0, logTold(1), "the tap before it is as it was");
        // told again, after the entry was made, and then a second payment in the same tap: the entry keeps the first, and the receipt has the second
        assertEquals(SW_OK, tell(told + 77));
        assertEquals(told, logTold(0), "an entry already made keeps what it was made with");
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(told, logTold(0), "and a payment added to it does not change it");
        // a tap in which the terminal tells nothing
        newTap();
        assertEquals(SW_OK, spend(2).getSW());
        assertEquals(0, logTold(0), "none told in this power-up: zeros, and not the last one's");
        assertEquals(told, logTold(1));
        // the receipts
        assertEquals(SW_OK, allowLoad());
        Held held = heldReceipts();
        assertEquals(3, held.count);
        assertEquals(0, readUint32(held.receipts.get(0), 4), "the third payment: no time told");
        assertEquals(told + 77, readUint32(held.receipts.get(1), 4), "the second: the time told when it was made");
        assertEquals(told, readUint32(held.receipts.get(2), 4), "the first");
        for (int k = 0; k < 3; k++) assertEquals(T0, readUint32(held.receipts.get(k), 0), "and the card's own time, the block's, at 0: the told time is a note beside it");
        assertArrayEquals(receiptFor(T0, told + 77, 11, new byte[][] { asSlot(sent[1]) }, new byte[0][]), held.receipts.get(1), "whole: block time, told time, sats, digest, output");
        // a load begins an entry too, and takes the told time as it is then
        newTap();
        assertEquals(SW_OK, tell(T0 + 500));
        assertEquals(SW_OK, load(buildProof(KEYSET, 3, 40)).getSW());
        assertEquals(T0 + 500, logTold(0), "a load's entry");
        // a refusal begins one as well
        newTap();
        assertEquals(SW_OK, setLimits(1, 0));
        assertEquals(SW_OK, tell(T0 + 600));
        assertEquals(SW_OVER_LIMIT, spend(3).getSW());
        assertEquals(T0 + 600, logTold(0), "a refusal's entry");
        assertEquals(T0 + 600, readUint32(field("cardLog"), 21 + (int) (((logTaps() - 1) & 7) * 20) + 16), "at 16 of the entry, in the card's own memory");
    }

    @Test
    @DisplayName("TELL_TIME needs no PIN, no owner, no record and no state: a card with nothing set up, blocked or locked takes it, answers 9000 and nothing, and a length that is not four bytes is 6700 and tells nothing")
    void testTellTimeNeedsNothing() throws Exception {
        // a card with nothing at all set up
        ResponseAPDU r = transmit(tellTimeCommand(T0 + 5));
        assertEquals(SW_OK, r.getSW());
        assertEquals(0, r.getData().length, "it answers nothing");
        assertEquals(0, now(), "and it is no clock: it moves nothing the card counts the day by");
        for (int n : new int[] { 0, 1, 3, 5, 8, 80 }) {
            assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_TELL_TIME, 0, 0, new byte[n])), n + " bytes");
        }
        // told through a card that is set up, blocked, and locked
        simulator = freshCard();
        ready();
        reselect();
        assertEquals(SW_OK, tell(T0 + 1), "no PIN verified");
        verify(WRONG_PIN); verify(WRONG_PIN); verify(WRONG_PIN);
        assertEquals(2, info()[7]);
        assertEquals(SW_OK, tell(T0 + 2), "a blocked card");
        assertEquals(SW_OK, changePin(NEW_PIN));
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, lock());
        assertEquals(1, info()[10]);
        assertEquals(SW_OK, tell(T0 + 3), "a locked card");
        assertEquals(T0, now());
        // a wrong length changed nothing, and a locked card takes no writes: TELL_TIME is none
        assertEquals(SW_OK, tell(T0 + 4444));
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_TELL_TIME, 0, 0, new byte[3])));
        assertArrayEquals(u32(T0 + 4444), field("tapTime"), "the wrong length told nothing: the time is the last good one");
        assertEquals(SW_NOT_ALLOWED, load(buildProof(KEYSET, 5, 1)).getSW(), "(a locked card takes no load)");
    }

    @Test
    @DisplayName("TELL_TIME moves nothing that lasts: not the clock, the window, what was spent, the limits, the log, the receipts, the record or a piece; a reading of the whole card before and after is byte for byte the same")
    void testTellTimeMovesNothing() throws Exception {
        readyWithLimit(500);
        assertEquals(SW_OK, setLimits(500, 100));
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 50, i + 1)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        newTap();
        byte[] record = field("cardRecord").clone(), log = field("cardLog").clone(), receipts = field("cardReceipts").clone(), storage = field("proofStorage").clone();
        byte[] infoBefore = info();
        for (long t : new long[] { 0, 1, T0, T0 - 5 * DAY, T0 + 400 * DAY, 4294967295L }) {
            assertEquals(SW_OK, tell(t), "told " + t);
            assertArrayEquals(record, field("cardRecord"), "the record, told " + t);
            assertArrayEquals(log, field("cardLog"), "the log, told " + t);
            assertArrayEquals(receipts, field("cardReceipts"), "the receipts, told " + t);
            assertArrayEquals(storage, field("proofStorage"), "the pieces, told " + t);
            assertArrayEquals(infoBefore, info(), "and what the card says of itself, told " + t);
        }
        // a terminal's lie about the time cannot turn the day: the day is the block headers'
        assertEquals(SW_OK, tell(T0 + 400 * DAY));
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(SW_OK, spend(2).getSW(), "(the day's limit is 500: three payments of 50 are within it, whatever the terminal says the time is)");
        assertEquals(T0, windowStart(), "the window did not turn for a time told");
        assertEquals(150, spentToday());
        assertEquals(T0, now());
    }

    @Test
    @DisplayName("The told time goes with the power and not with a SELECT: tap() (the card out of the field) clears it, a new SELECT does not, and a reset in between is a new time in the field with none told")
    void testTheToldTimeGoesWithThePowerNotWithASelect() throws Exception {
        readyWithLimit(0);
        for (int i = 0; i < 4; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 10, i + 1)).getSW());
        newTap();
        assertEquals(SW_OK, tell(T0 + 70));
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(T0 + 70, logTold(0), "a SELECT did not make the card forget what the terminal told");
        simulator.reset();
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(0, logTold(0), "the power went: the next time in the field has been told nothing");
        assertEquals(T0 + 70, logTold(1));
        // told again after a SELECT replaces it, and the receipts say so
        assertEquals(SW_OK, tell(T0 + 80));
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, tell(T0 + 90));
        assertEquals(SW_OK, spend(2).getSW());
        assertEquals(SW_OK, allowLoad());
        Held held = heldReceipts();
        assertEquals(T0 + 90, readUint32(held.receipts.get(0), 4), "the last telling before the payment, across a SELECT");
        assertEquals(0, readUint32(held.receipts.get(1), 4));
        assertEquals(T0 + 70, readUint32(held.receipts.get(2), 4));
        // the array is the applet's RAM that is cleared on reset: it lies in the transient arrays of that kind
        byte[] tapTime = field("tapTime");
        assertEquals(4, tapTime.length);
        assertArrayEquals(u32(T0 + 90), tapTime);
        simulator.reset();
        assertArrayEquals(new byte[4], field("tapTime"), "gone with the power");
    }

    @Test
    @DisplayName("No clock moved on is marked any more: headers a day, ten days and a year on, in one time in the field or across several, raise no count of marked things and flag no entry; LOG_FLAG_CLOCK is still a word and is never set")
    void testNoClockMovedOnIsMarked() throws Exception {
        readyWithLimit(0);
        assertEquals(0x04, CashuApplet.LOG_FLAG_CLOCK, "the word is kept, so that a log read from a card of earlier software is read right");
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 1)).getSW());
        for (int i = 0; i < 4; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 10, 2 + i)).getSW());
        newTap();
        long t1 = T0 + 10 * DAY;
        assertEquals(SW_OK, setTime(t1), "ten days on, in the first header of the time in the field");
        assertEquals(SW_OK, setTime(t1 + 121), "121 seconds past it, which was a mark when the clock was told");
        assertEquals(SW_OK, setTime(t1 + 99999));
        assertEquals(SW_OK, setTime(t1 + 365 * DAY));
        assertEquals(t1 + 365 * DAY, now());
        assertEquals(0, logTampers(), "nothing was marked");
        assertEquals(1, logTaps(), "and no entry was begun for a header: only the tap that put the pieces on");
        assertEquals(SW_OK, spend(0).getSW());
        assertArrayEquals(new long[] { t1 + 365 * DAY, 10, 1, 0, 0 }, logTap(0), "the entry a payment begins has no flag 04, and is at the clock as it stands");
        // a header after the entry exists flags nothing
        assertEquals(SW_OK, setTime(t1 + 366 * DAY));
        assertArrayEquals(new long[] { t1 + 365 * DAY, 10, 1, 0, 0 }, logTap(0), "the entry is as it was");
        assertEquals(0, logTampers());
        // across power-ups
        for (int i = 0; i < 3; i++) {
            newTap();
            assertEquals(SW_OK, setTime(t1 + (400 + i) * DAY));
            assertEquals(SW_OK, setTime(t1 + (400 + i) * DAY + 5000));
            assertEquals(SW_OK, spend(1 + i).getSW());
            assertEquals(0, logTap(0)[4] & 4, "no clock flag in tap " + i);
        }
        assertEquals(0, logTampers());
        // the word is no longer used anywhere in the applet but where it is defined
        assertEquals(1, count(appletCode(), "LOG_FLAG_CLOCK"), "defined, and used nowhere");
    }

    @Test
    @DisplayName("A terminal that walks the clock a day on to turn the day's window can do so only with block headers that carry their work: it is not marked, and it is not refused; one that has no such header cannot")
    void testAClockWalkedForwardTurnsTheDayOnlyWithRealHeaders() {
        readyWithLimit(100);
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 100, i + 1)).getSW());
        newTap();
        assertEquals(SW_OK, spend(0).getSW(), "the day's limit");
        assertEquals(SW_OVER_LIMIT, spend(1).getSW(), "the day is full");
        // a time told is a note: it turns nothing
        assertEquals(SW_OK, tell(T0 + 2 * DAY));
        assertEquals(T0, windowStart(), "told a day and more on, the window is where it was");
        assertEquals(100, spentToday());
        // a header with no work is refused, and turns nothing either
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(unmined(T0 + 2 * DAY, TEST_BITS))));
        assertEquals(T0, now(), "a header made without the work, a day on, is refused: the clock is where it was");
        assertEquals(T0, windowStart());
        // one with the work turns it
        assertEquals(SW_OK, setTime(T0 + DAY));
        assertEquals(SW_OK, spend(1).getSW(), "a day on by a block: the window turns, and the card does not refuse");
        assertEquals(0, logTampers(), "it is not marked: one refusal is no run, and the clock was moved on by blocks");
        assertEquals(T0 + DAY, windowStart());
        assertArrayEquals(new long[] { T0, 200, 2, 1, 2 }, logTap(0), "(one refusal, and the second payment of the tap was slowed: 02; no flag of a clock)");
    }

    // ---- 5: the receipts ------------------------------------------------------------------

    @Test
    @DisplayName("A payment leaves a receipt: the clock when it was signed, what its pieces were worth, SHA-256 of the message that was signed (built here, independently), and the first output's blinded message as it was given; the signature verifies over that same digest; read with the owner's grant, count first")
    void testAPaymentLeavesAReceipt() throws Exception {
        readyWithLimit(0);
        byte[][] sent = { buildProof(KEYSET, 40, 1), buildProof(KEYSET, 25, 2), buildProof(KEYSET, 8, 3, 1900000000L), buildProof(KEYSET, 8, 4, 1900000000L) };
        for (byte[] p : sent) assertEquals(SW_OK, load(p).getSW());
        assertEquals(SW_OK, allowLoad());
        ResponseAPDU none = receipts(0);
        assertEquals(SW_OK, none.getSW());
        assertArrayEquals(new byte[4], none.getData(), "no payment yet: the count alone");
        newTap();
        assertEquals(SW_OK, setTime(T0 + 77));
        byte[][] outputs = { output(60, blinded(11)), output(5, blinded(12)) };
        ResponseAPDU first = spendAll(new int[] { 1, 0 }, outputs);
        assertEquals(SW_OK, first.getSW());
        // a payment of dated pieces, with no outputs
        ResponseAPDU second = spendAll(new int[] { 3, 2 }, new byte[0][]);
        assertEquals(SW_OK, second.getSW());
        assertEquals(SW_OK, allowLoad());
        Held held = heldReceipts();
        assertEquals(2, held.count);
        assertEquals(2, held.receipts.size());
        byte[] expectedSecond = receiptFor(T0 + 77, 16, new byte[][] { asSlot(sent[3]), asSlot(sent[2]) }, new byte[0][]);
        byte[] expectedFirst = receiptFor(T0 + 77, 65, new byte[][] { asSlot(sent[1]), asSlot(sent[0]) }, outputs);
        assertArrayEquals(expectedSecond, held.receipts.get(0), "newest first: the payment of the dated pieces, with no outputs (33 zeros)");
        assertArrayEquals(expectedFirst, held.receipts.get(1), "and the payment with outputs: its clock, 65 sats, the digest of its message, and the first output's blinded message");
        assertArrayEquals(Arrays.copyOfRange(outputs[0], 4, 37), Arrays.copyOfRange(held.receipts.get(1), 44, 77), "the first output, as it was given");
        assertArrayEquals(new byte[33], Arrays.copyOfRange(held.receipts.get(0), 44, 77), "and zeros where there were no outputs");
        // the signature the terminal was given verifies over the digest in the receipt
        byte[] pubX = extractPubkeyX(cardKey());
        assertTrue(schnorrVerify(pubX, Arrays.copyOfRange(held.receipts.get(1), 12, 44), first.getData()), "the receipt's digest is what was signed");
        assertTrue(schnorrVerify(pubX, Arrays.copyOfRange(held.receipts.get(0), 12, 44), second.getData()));
        assertFalse(schnorrVerify(pubX, Arrays.copyOfRange(held.receipts.get(0), 12, 44), first.getData()), "and the other payment's digest is not");
        // asking for the last signature again is not a payment
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64)));
        assertEquals(SW_OK, allowLoad());
        assertEquals(2, heldReceipts().count, "SPEND_ALL_AGAIN writes no receipt");
    }

    @Test
    @DisplayName("The receipts are the owner's grant's alone: a verified PIN is not enough (6982), nor is no PIN; the grant goes with the tap; a card with no PIN set has signed nothing and answers freely")
    void testTheReceiptsAreTheGrantsAlone() {
        // a card with no PIN has signed nothing: it answers anyone
        ResponseAPDU free = receipts(0);
        assertEquals(SW_OK, free.getSW());
        assertArrayEquals(new byte[4], free.getData());
        assertEquals(SW_OK, receipts(5).getSW());
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_SECURITY_NOT_SATIS, receipts(0).getSW(), "a PIN set, and no owner to give the grant: nobody reads them");
        // a card that has paid
        simulator = freshCard();
        readyWithLimit(0);
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 1)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        for (int back : new int[] { 0, 1, 2, 15, 16, 200 }) {
            ResponseAPDU r = receipts(back);
            assertEquals(SW_SECURITY_NOT_SATIS, r.getSW(), "a verified PIN, P2 = " + back);
            assertEquals(0, r.getData().length);
        }
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_GET_LOG, 0, 0, 256)), "the log itself is the PIN's, as it was");
        reselect();
        assertEquals(SW_SECURITY_NOT_SATIS, receipts(0).getSW(), "no PIN either");
        assertEquals(SW_OK, allowLoad());
        ResponseAPDU granted = receipts(0);
        assertEquals(SW_OK, granted.getSW(), "the owner's grant");
        assertEquals(4 + RECEIPT_LEN, granted.getData().length);
        assertEquals(1, readUint32(granted.getData(), 0));
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_SECURITY_NOT_SATIS, receipts(0).getSW(), "the grant went with the tap, and the PIN again is not it");
        // a terminal cannot give itself the grant
        assertEquals(SW_OWNER_PROOF, sw(allowLoadCommand(ownerProof(L_LOAD, OTHER_OWNER, nonceBytes(), new byte[0]))));
        assertEquals(SW_SECURITY_NOT_SATIS, receipts(0).getSW());
    }

    @Test
    @DisplayName("The receipt's first output is the first of the first SPEND_ALL_OUTPUTS command of the payment, however the outputs are split between commands, and is not carried to the next payment")
    void testTheFirstOutputIsTheFirstOfTheFirstCommand() throws Exception {
        readyWithLimit(0);
        int[][] splits = { { 1, 6 }, { 6, 1 }, { 2, 1, 4 }, { 3, 4 }, { 5, 2 }, { 1 } };
        byte[][] sent = new byte[splits.length + 1][];
        for (int i = 0; i < sent.length; i++) {
            sent[i] = buildProof(KEYSET, 10 + i, i + 1);
            assertEquals(SW_OK, load(sent[i]).getSW());
        }
        for (int i = 0; i < splits.length; i++) {
            byte[][] outputs = new byte[7][];
            for (int k = 0; k < 7; k++) outputs[k] = output(1 + k, blinded(50 * i + k + 1));
            assertEquals(SW_OK, payGrouped(new int[] { i }, outputs, splits[i]).getSW(), "split " + Arrays.toString(splits[i]));
            assertEquals(SW_OK, allowLoad());
            Held held = heldReceipts();
            assertEquals(i + 1, held.count);
            assertArrayEquals(receiptFor(T0, 10 + i, new byte[][] { asSlot(sent[i]) }, outputs), held.receipts.get(0), "split " + Arrays.toString(splits[i]));
            assertArrayEquals(Arrays.copyOfRange(outputs[0], 4, 37), Arrays.copyOfRange(held.receipts.get(0), 44, 77), "the first output of the first command");
            assertFalse(Arrays.equals(Arrays.copyOfRange(outputs[splits[i][0]], 4, 37), Arrays.copyOfRange(held.receipts.get(0), 44, 77)), "and not the first of the second command");
        }
        // a payment with no outputs after payments that had them: zeros, and not the last one's
        int last = splits.length;
        assertEquals(SW_OK, spend(last).getSW());
        assertEquals(SW_OK, allowLoad());
        Held held = heldReceipts();
        assertArrayEquals(receiptFor(T0, 10 + last, new byte[][] { asSlot(sent[last]) }, new byte[0][]), held.receipts.get(0));
        assertArrayEquals(new byte[33], Arrays.copyOfRange(held.receipts.get(0), 44, 77), "zeros: the first output of an earlier payment is not carried over");
    }

    /** `n` payments on a card of its own, one piece and one or two outputs each, the clock 100 seconds on for each: what the receipts should then be, newest first. */
    private java.util.List<byte[]> payAndExpect(int n) throws Exception {
        simulator = freshCard();
        readyWithLimit(0);
        byte[][] sent = new byte[n][];
        for (int i = 0; i < n; i++) sent[i] = buildProof(KEYSET, 3 + i, 1000 + i);
        for (int at = 0; at < n; at += 3) assertEquals(SW_OK, loadBatch(Arrays.copyOfRange(sent, at, Math.min(n, at + 3))).getSW());
        assertEquals(SW_OK, allowLoad());
        java.util.LinkedList<byte[]> expected = new java.util.LinkedList<>();
        for (int j = 1; j <= n; j++) {
            assertEquals(SW_OK, setTime(T0 + 100L * j), "100 seconds on, which is not a jump");
            byte[][] outputs = j % 2 == 0 ? new byte[][] { output(2, blinded(j)), output(1, blinded(j + 100)) } : new byte[][] { output(3 + j - 1, blinded(j)) };
            ResponseAPDU r = spendAll(new int[] { j - 1 }, outputs);
            assertEquals(SW_OK, r.getSW(), "payment " + j);
            expected.addFirst(receiptFor(T0 + 100L * j, 3 + j - 1, new byte[][] { asSlot(sent[j - 1]) }, outputs));
        }
        return expected;
    }

    @Test
    @DisplayName("The receipts ring holds the last 16 payments and the count of all of them: after 1, 16, 17, 18 and 33 payments the count is right, the receipts are the newest, in order, newest first, and the older ones are gone")
    void testTheReceiptsRingWraps() throws Exception {
        for (int n : new int[] { 1, 15, 16, 17, 18, 33 }) {
            java.util.List<byte[]> expected = payAndExpect(n);
            assertEquals(SW_OK, allowLoad());
            Held held = heldReceipts();
            assertEquals(n, held.count, "after " + n + " payments");
            int kept = Math.min(n, 16);
            assertEquals(kept, held.receipts.size(), "after " + n + " payments, the ring holds " + kept);
            for (int k = 0; k < kept; k++) {
                assertArrayEquals(expected.get(k), held.receipts.get(k), "after " + n + " payments, " + k + " back (payment " + (n - k) + ")");
            }
            if (n > 16) {
                for (int j = 1; j <= n - 16; j++) {
                    byte[] gone = expected.get(n - j);
                    for (byte[] h : held.receipts) assertFalse(Arrays.equals(gone, h), "payment " + j + " is gone");
                }
            }
        }
    }

    @Test
    @DisplayName("GET_LOG P1 = 1 pages by P2: P2 = 0 is the newest, three receipts at most to an answer, and a P2 at or past what the ring holds answers the count alone: P2 = 0, 1, 2, 3, 13, 15, 16 and 200 on a full ring, on five receipts, and on none")
    void testReceiptPaging() throws Exception {
        int[] backs = { 0, 1, 2, 3, 13, 15, 16, 200 };
        for (int n : new int[] { 20, 5, 0 }) {
            java.util.List<byte[]> expected = n == 0 ? new java.util.ArrayList<>() : payAndExpect(n);
            if (n == 0) { simulator = freshCard(); readyWithLimit(0); }
            int kept = Math.min(n, 16);
            for (int back : backs) {
                assertEquals(SW_OK, allowLoad());
                ResponseAPDU r = receipts(back);
                assertEquals(SW_OK, r.getSW(), n + " payments, P2 = " + back);
                byte[] d = r.getData();
                int returned = Math.max(0, Math.min(3, kept - back));
                assertEquals(4 + RECEIPT_LEN * returned, d.length, n + " payments held " + kept + ", P2 = " + back);
                assertEquals(n, readUint32(d, 0), "the count first");
                for (int k = 0; k < returned; k++) {
                    assertArrayEquals(expected.get(back + k), Arrays.copyOfRange(d, 4 + RECEIPT_LEN * k, 4 + RECEIPT_LEN * (k + 1)), n + " payments, P2 = " + back + ", receipt " + k);
                }
            }
        }
    }

    @Test
    @DisplayName("A payment that waited leaves one receipt, once it is signed; one given up in the wait, one refused (over the day, a place spent or empty), and asking for the last signature again leave none; nothing in the wait writes the receipts")
    void testAWaitedPaymentLeavesOneReceiptAndOthersLeaveNone() throws Exception {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(250, 100));
        byte[][] sent = { buildProof(KEYSET, 300, 1), buildProof(KEYSET, 200, 2), buildProof(KEYSET, 120, 3), buildProof(KEYSET, 120, 4) };
        for (byte[] p : sent) assertEquals(SW_OK, load(p).getSW());
        newTap();
        assertEquals(SW_OVER_LIMIT, spend(0).getSW(), "300 is over the day");
        assertEquals(0, readUint32(field("cardReceipts"), 0), "refused: no receipt");
        // a payment given up in its wait: 200 under 100 is seven waits
        assertEquals(SW_OK, sw(beginCommand(1)));
        byte[] receiptsBefore = field("cardReceipts").clone();
        for (int i = 1; i <= waitsRule(100, 200, 0); i++) {
            assertNotYet(transmit(SIGN_ALL), "wait " + i);
            assertArrayEquals(receiptsBefore, field("cardReceipts"), "nothing is written while it waits");
        }
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4)));
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL));
        assertArrayEquals(receiptsBefore, field("cardReceipts"), "given up, with every wait done: no receipt");
        // a place that is empty
        assertEquals(SW_SLOT_EMPTY, sw(beginCommand(9)));
        assertArrayEquals(receiptsBefore, field("cardReceipts"));
        // paid, whole
        ResponseAPDU paid = spend(1);
        assertEquals(SW_OK, paid.getSW());
        assertEquals(waitsRule(100, 200, 0), waitsTaken(), "200 under 100: two limits' worth");
        assertEquals(1, readUint32(field("cardReceipts"), 0), "one receipt, once it is signed");
        // a place that is spent, and a payment over what is left of the day
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(beginCommand(1)), "spent");
        assertEquals(SW_OVER_LIMIT, spendAll(new int[] { 2, 3 }, new byte[0][]).getSW(), "240 more is over what the day has left of 250");
        assertEquals(SW_OK, allowLoad());
        Held held = heldReceipts();
        assertEquals(1, held.count, "one payment was made, and none of the others left anything");
        assertArrayEquals(receiptFor(T0, 200, new byte[][] { asSlot(sent[1]) }, new byte[0][]), held.receipts.get(0));
        assertTrue(schnorrVerify(extractPubkeyX(cardKey()), Arrays.copyOfRange(held.receipts.get(0), 12, 44), paid.getData()), "and its digest is what was signed");
        // asking for the last signature again is not another payment
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64)));
        assertEquals(1, readUint32(field("cardReceipts"), 0));
    }

    @Test
    @DisplayName("Nothing clears the receipts: not CLEAR_SPENT, not SET_CARD with other bytes where the time key was, not a new owner, not a new PIN, not a limit, not the lock; they are read afterwards as they were")
    void testNothingClearsTheReceipts() throws Exception {
        readyWithLimit(0);
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 5 + i, 1 + i)).getSW());
        assertEquals(SW_OK, spendAll(new int[] { 0, 1 }, new byte[][] { output(9, blinded(1)) }).getSW());
        assertEquals(SW_OK, spend(2).getSW());
        byte[] kept = field("cardReceipts").clone();
        assertEquals(2, readUint32(kept, 0));
        assertEquals(SW_OK, clearSpent());
        assertArrayEquals(kept, field("cardReceipts"), "CLEAR_SPENT");
        byte[] withOtherBytes = recordWithKeyBytes(MINT, REFUND, FORMER_TIME_KEY.pub);
        assertEquals(SW_OK, sw(setCardCommand(ownerProof(L_CARD, OWNER, nonceBytes(), withOtherBytes), withOtherBytes)));
        assertArrayEquals(kept, field("cardReceipts"), "SET_CARD with other bytes where the time key was");
        assertEquals(SW_OK, changePin(NEW_PIN));
        assertArrayEquals(kept, field("cardReceipts"), "CHANGE_PIN");
        assertEquals(SW_OK, setLimits(0, 50));
        assertArrayEquals(kept, field("cardReceipts"), "SET_LIMIT");
        assertEquals(SW_OK, sw(setOwnerCommand(ownerProof(L_OWNER, OWNER, nonceBytes(), OTHER_OWNER.pub), OTHER_OWNER)));
        assertArrayEquals(kept, field("cardReceipts"), "SET_OWNER");
        // and they are read, by the new owner's grant, as they were
        reselect();
        assertEquals(SW_OK, sw(allowLoadCommand(ownerProof(L_LOAD, OTHER_OWNER, nonceBytes(), new byte[0]))));
        Held held = heldReceipts();
        assertEquals(2, held.count);
        assertEquals(2, held.receipts.size());
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, sw(lockCommand(ownerProof(L_LOCK, OTHER_OWNER, nonceBytes(), new byte[0]))));
        assertArrayEquals(kept, field("cardReceipts"), "LOCK_CARD");
    }

    @Test
    @DisplayName("A withdrawal with the limits lifted by the owner: a payment that was to wait 22 times goes at once once the owner has set (0, 0), is one signature of everything, and leaves one receipt of its whole worth")
    void testAWithdrawalWithTheLimitsLifted() throws Exception {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(1000, 100));
        byte[][] sent = new byte[10][];
        for (int i = 0; i < 10; i++) {
            sent[i] = buildProof(KEYSET, 50, 1 + i);
            assertEquals(SW_OK, load(sent[i]).getSW());
        }
        int[] all = new int[10];
        for (int i = 0; i < 10; i++) all[i] = i;
        byte[][] slots = new byte[10][];
        for (int i = 0; i < 10; i++) slots[i] = asSlot(sent[i]);
        newTap();
        // under the limits, 500 is five limits' worth: 22 waits; the terminal gives it up
        assertEquals(SW_OK, sw(beginCommand(all)));
        assertNotYet(transmit(SIGN_ALL), "the first of twenty-two");
        // the owner sets both to none
        assertEquals(SW_OK, setLimits(0, 0));
        assertEquals(SW_OK, verify(TEST_PIN));
        byte[][] outputs = { output(500, blinded(77)) };
        ResponseAPDU r = spendAll(all, outputs);
        assertEquals(SW_OK, r.getSW());
        assertEquals(0, waitsTaken(), "no limit on a payment: no wait");
        assertTrue(signedForAll(r.getData(), slots, outputs, REFUND));
        assertEquals(0, balance());
        assertEquals(0, spentToday(), "no limit on the day: nothing counted");
        assertArrayEquals(new long[] { T0, 500, 10, 0, 0 }, logTap(0), "ten pieces, 500 sats, nothing waited for");
        assertEquals(SW_OK, allowLoad());
        Held held = heldReceipts();
        assertEquals(1, held.count);
        assertArrayEquals(receiptFor(T0, 500, slots, outputs), held.receipts.get(0));
    }

    @Test
    @DisplayName("A payment whose pieces add up past 2^32: under a day's limit BEGIN refuses it (6A8F) and leaves no receipt; with no day limit it is signed, and its receipt says the worth the card saturates to, 4294967295")
    void testAPaymentPastTwoToTheThirtyTwoHasNoReceiptWhereItIsRefused() throws Exception {
        readyWithLimit(4294967295L);
        assertEquals(SW_OK, load(buildProof(KEYSET, 4294967295L, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 5, 2)).getSW());
        assertEquals(SW_OVER_LIMIT, sw(beginCommand(0, 1)), "the sum wraps: past any limit");
        assertEquals(0, readUint32(field("cardReceipts"), 0), "refused: no receipt");
        // with no limit on the day nothing refuses it
        simulator = freshCard();
        ready();
        byte[] big = buildProof(KEYSET, 4294967295L, 1), five = buildProof(KEYSET, 5, 2);
        assertEquals(SW_OK, load(big).getSW());
        assertEquals(SW_OK, load(five).getSW());
        ResponseAPDU r = spendAll(new int[] { 0, 1 }, new byte[0][]);
        assertEquals(SW_OK, r.getSW(), "nothing refuses a sum that wraps where there is no limit on the day");
        assertEquals(SW_OK, allowLoad());
        Held held = heldReceipts();
        assertEquals(1, held.count);
        assertArrayEquals(receiptFor(T0, 4294967295L, new byte[][] { asSlot(big), asSlot(five) }, new byte[0][]), held.receipts.get(0), "the worth is the top of four bytes, and not the true sum, which they cannot hold");
    }

    // =========================================================================
    // The card record
    // =========================================================================

    @Test
    @DisplayName("SET_CARD is read back by GET_CARD, whole, with the clock's proof where the time key was (the hardest bits, the last header's hash, zeros), and does not touch the limit")
    void testCardRecord() {
        ready();
        assertEquals(SW_OK, setLimit(5000));
        byte[] c = cardRecord();
        assertEquals(109 + MINT.length(), c.length, "the record, the mint, and three bytes of design after it");
        assertEquals(4, c[0]); assertEquals(1, c[1]); assertEquals(0, c[2]);
        assertEquals(5000, readUint32(c, 3));
        assertArrayEquals(REFUND, Arrays.copyOfRange(c, 7, 40));
        assertArrayEquals(le32(TEST_BITS), Arrays.copyOfRange(c, 40, 44), "the hardest difficulty of any header taken, as a header carries it");
        assertEquals(blockHash(blockAt(T0)), toHex(Arrays.copyOfRange(c, 44, 76)), "the hash of the last header taken, as Bitcoin shows a block hash");
        // 2.0 (D20): the rolls since the owner's last REFRESH, the rollover budget (0: the default, 7) and whether the allowance is armed
        // (the PIN verified in ready() armed it), then 26 zeros
        assertArrayEquals(new byte[] { 0, 0, 1 }, Arrays.copyOfRange(c, 76, 79), "no roll, the default budget, armed");
        assertArrayEquals(new byte[26], Arrays.copyOfRange(c, 79, 105), "and zeros after");
        assertEquals(MINT.length(), c[105] & 0xFF);
        assertEquals(MINT, new String(Arrays.copyOfRange(c, 106, 106 + MINT.length()), StandardCharsets.US_ASCII));
        assertArrayEquals(new byte[3], Arrays.copyOfRange(c, c.length - 3, c.length), "a record given without a design has none: three zeros");
        assertEquals(1, info()[11]);
        assertEquals(5000, readUint32(info(), 12));
        assertEquals(1, info()[16], "and it has an owner");
        // SET_CARD writes the record and not the limit, which is the owner's to set
        assertEquals(SW_OK, setCard("https://other.example.com", NO_REFUND));
        assertEquals(5000, limit(), "a new record leaves the limit as it was");
    }

    @Test
    @DisplayName("The card's design: three characters after the mint, written by SET_CARD when given, zeros when not, refused when not a code")
    void testCardDesign() {
        ready();
        byte[] withDesign = record(MINT, REFUND, "FX1");
        assertEquals(SW_OK, sw(setCardCommand(ownerProof(L_CARD, OWNER, nonceBytes(), withDesign), withDesign)));
        byte[] c = cardRecord();
        assertEquals("FX1", new String(Arrays.copyOfRange(c, c.length - 3, c.length), StandardCharsets.US_ASCII), "the design, after the mint");
        assertEquals(MINT, new String(Arrays.copyOfRange(c, 106, c.length - 3), StandardCharsets.US_ASCII), "and the mint where it was");
        byte[] bad = record(MINT, REFUND, "fx1");
        assertEquals(SW_WRONG_DATA, sw(setCardCommand(ownerProof(L_CARD, OWNER, nonceBytes(), bad), bad)), "lower case is not a code");
        assertEquals("FX1", new String(Arrays.copyOfRange(cardRecord(), c.length - 3, c.length), StandardCharsets.US_ASCII), "and the record is as it was");
        byte[] two = concat(record(MINT, REFUND), "FX".getBytes(StandardCharsets.US_ASCII));
        assertEquals(SW_WRONG_LENGTH, sw(setCardCommand(ownerProof(L_CARD, OWNER, nonceBytes(), two), two)), "two characters are no length a record has");
        byte[] zeros = record(MINT, REFUND, "\0\0\0");
        assertEquals(SW_OK, sw(setCardCommand(ownerProof(L_CARD, OWNER, nonceBytes(), zeros), zeros)), "three zeros are none, and taken");
        assertArrayEquals(new byte[3], Arrays.copyOfRange(cardRecord(), c.length - 3, c.length));
        byte[] none = record(MINT, REFUND, "FX1");
        assertEquals(SW_OK, sw(setCardCommand(ownerProof(L_CARD, OWNER, nonceBytes(), none), none)));
        none = record(MINT, REFUND);
        assertEquals(SW_OK, sw(setCardCommand(ownerProof(L_CARD, OWNER, nonceBytes(), none), none)), "the record as a phone that knows no design sends it");
        assertArrayEquals(new byte[3], Arrays.copyOfRange(cardRecord(), c.length - 3, c.length), "which clears the design");
    }

    @Test
    @DisplayName("SET_CARD refuses a record that is not one, and leaves the old one")
    void testCardRecordShape() {
        ready();
        byte[] bad = REFUND.clone(); bad[0] = 0x04;
        assertEquals(SW_WRONG_DATA, setCard(MINT, bad), "a refund key that is not a compressed point");
        byte[] half = new byte[33]; half[5] = 1;
        assertEquals(SW_WRONG_DATA, setCard(MINT, half), "zeros with something in them");
        assertEquals(SW_WRONG_LENGTH, setCard("", REFUND), "no mint");
        assertEquals(SW_WRONG_LENGTH, setCard("x".repeat(MINT_MAX + 1), REFUND), "a mint too long to keep");
        byte[] lying = record("0123456789", REFUND);
        lying[99] = 20;
        byte[] n = nonceBytes();
        assertEquals(SW_WRONG_LENGTH, sw(setCardCommand(ownerProof(L_CARD, OWNER, n, lying), lying)), "a length that is not the mint's");
        byte[] c = cardRecord();
        assertEquals(MINT, new String(Arrays.copyOfRange(c, 106, c.length - 3), StandardCharsets.US_ASCII));
        assertArrayEquals(le32(TEST_BITS), Arrays.copyOfRange(c, 40, 44), "the clock's proof is as it was");
        assertEquals(SW_OK, setCard("x".repeat(MINT_MAX), REFUND), "seventy-seven is kept");
        // the longest a record and its proof can be: one short APDU of 255 data bytes
        byte[] longest = record("x".repeat(MINT_MAX), REFUND);
        assertEquals(100 + MINT_MAX, longest.length);
        assertTrue(1 + 72 + longest.length <= 255, "a proof of 72 bytes and the longest record fit one command");
    }

    @Test
    @DisplayName("The mint and the refund key cannot change under pieces that are still unspent")
    void testCardRecordInUse() throws Exception {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1, 1900000000L)).getSW());
        assertEquals(SW_CARD_IN_USE, setCard("https://other.example.com", NO_REFUND));
        // the piece is still signed for with the key it was made with
        ResponseAPDU r = spend(0);
        assertEquals(SW_OK, r.getSW());
        assertTrue(signedFor(r.getData(), slot(0), REFUND));
        assertEquals(SW_OK, setCard("https://other.example.com", NO_REFUND), "with nothing unspent it may");
    }

    // =========================================================================
    // Spending
    // =========================================================================

    @Test
    @DisplayName("SPEND_PROOF signs the slot's own secret, as the wallet's library writes one")
    void testSpendSignsTheSlot() throws Exception {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 7)).getSW());
        byte[] before = slot(0);
        ResponseAPDU r = spend(0);
        assertEquals(SW_OK, r.getSW());
        assertEquals(64, r.getData().length);
        assertTrue(signedFor(r.getData(), before, REFUND), "a BIP-340 signature over SHA-256 of the piece's secret");
        // spelt out: a piece locked to one key and flagged SIG_ALL, as cashu-ts writes it, and then its C in hex
        String plain = "[\"P2PK\",{\"nonce\":\"" + toHex(Arrays.copyOfRange(before, 13, 45)) + "\",\"data\":\""
            + toHex(cardKey()) + "\",\"tags\":[[\"sigflag\",\"SIG_ALL\"]]}]";
        String c = toHex(Arrays.copyOfRange(before, 45, 78));
        assertTrue(schnorrVerify(extractPubkeyX(cardKey()), sha256((plain + c).getBytes(StandardCharsets.UTF_8)), r.getData()));
        // not the secret alone (a signature a mint would take for a piece without the flag), and not a piece without the flag
        assertFalse(schnorrVerify(extractPubkeyX(cardKey()), sha256(plain.getBytes(StandardCharsets.UTF_8)), r.getData()));
        String unflagged = plain.replace("\"tags\":[[\"sigflag\",\"SIG_ALL\"]]", "\"tags\":[]");
        assertFalse(schnorrVerify(extractPubkeyX(cardKey()), sha256((unflagged + c).getBytes(StandardCharsets.UTF_8)), r.getData()));
        assertEquals(2, slot(0)[0], "and the slot is spent");
        assertEquals(0, balance());
    }

    @Test
    @DisplayName("A dated piece's secret names its date in decimal and the card's refund key")
    void testSpendDated() throws Exception {
        ready();
        long[] dates = { 1L, 9L, 10L, 99L, 100L, 65535L, 65536L, 1700000000L, 1900000000L, 4294967295L };
        for (int i = 0; i < dates.length; i++) {
            assertEquals(SW_OK, load(buildProof(KEYSET, 16, 20 + i, dates[i])).getSW());
        }
        for (int i = 0; i < dates.length; i++) {
            byte[] before = slot(i);
            ResponseAPDU r = spend(i);
            assertEquals(SW_OK, r.getSW(), "date " + dates[i]);
            assertTrue(signedFor(r.getData(), before, REFUND), "date " + dates[i] + " as text in the secret");
            // and not the same piece with no date, or with another refund key
            byte[] undated = before.clone();
            putUint32(undated, 78, 0);
            assertFalse(signedFor(r.getData(), undated, REFUND));
            byte[] other = REFUND.clone(); other[0] = 0x03;
            assertFalse(signedFor(r.getData(), before, other));
        }
    }

    @Test
    @DisplayName("Nothing the reader sends in place of the pieces is signed: 32 bytes offered with SPEND_ALL_SIGN change nothing, and SPEND_PROOF is gone")
    void testSpendTakesNoMessage() throws Exception {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 32, 2)).getSW());
        byte[] a = slot(0), b = slot(1);
        assertEquals(0x6D00, sw(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, 64)), "one piece, one signature over its secret alone: gone");
        assertEquals(0x6D00, sw(new CommandAPDU(CLA, 0x21, 0, 0, new byte[32], 64)), "as SIGN_ARBITRARY is");
        // upstream's attack: have slot 0 burned for slot 1's message
        byte[] bMsg = sha256(allMessage(cardKey(), REFUND, new byte[][] { b }, new byte[0][]).getBytes(StandardCharsets.UTF_8));
        assertEquals(SW_OK, transmit(beginCommand(0)).getSW());
        ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_SPEND_ALL_SIGN, 0, 0, bMsg, 64));
        assertEquals(SW_OK, r.getSW());
        assertFalse(schnorrVerify(extractPubkeyX(cardKey()), bMsg, r.getData()), "not the message that was offered");
        assertTrue(signedFor(r.getData(), a, REFUND), "the slot's own");
        assertFalse(signedFor(r.getData(), b, REFUND), "and no other slot's");
        assertEquals(1, slot(1)[0], "slot 1 is untouched");
    }

    @Test
    @DisplayName("A slot is signed for once")
    void testSpendOnce() {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(SW_CONDITIONS_NOT_SATIS, spend(0).getSW());
        assertEquals(SW_SLOT_EMPTY, spend(1).getSW());
        assertEquals(SW_SLOT_OUT_OF_RANGE, spend(MAX_PROOFS).getSW());
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_CONDITIONS_NOT_SATIS, spend(0).getSW(), "and not in a later tap either");
    }

    @Test
    @DisplayName("CLEAR_SPENT frees what was spent, and only that")
    void testClearSpent() {
        ready();
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 8, i)).getSW());
        assertEquals(SW_OK, spend(1).getSW());
        ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1));
        assertEquals(SW_OK, r.getSW());
        assertEquals(1, r.getData()[0]);
        assertEquals(SW_SLOT_EMPTY, sw(new CommandAPDU(CLA, INS_GET_PROOF, 1, 0, 256)));
        assertEquals(16, balance());
        assertEquals(1, load(buildProof(KEYSET, 4, 9)).getData()[0], "the freed slot is the next one used");
    }

    // =========================================================================
    // The PIN
    // =========================================================================

    /** Every command that needs the PIN first, as (name, command): each is refused with 6982 until it has been verified. (A spend is asked for the PIN at its signature, 1.16: see assertAllGatedRefuse.) */
    private Object[][] gated() {
        return new Object[][] {
            { "LOAD_PROOF",  new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 4, 50), 1) },
            { "CLEAR_SPENT", new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1) },
            { "SET_LIMIT (PIN form)", setLimitByPinCommand(1) },
            { "LOCK_CARD",   lockCommand(new byte[72]) },
        };
    }

    private void assertAllGatedRefuse(String when) {
        long before = balance();
        long limit = limit();
        byte[] status = transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData();
        for (Object[] g : gated()) {
            assertEquals(SW_SECURITY_NOT_SATIS, sw((CommandAPDU) g[1]), g[0] + " " + when);
        }
        // and a spend: begun (it asks nothing of the PIN), refused at its signature (the allowance is none), nothing burned
        assertEquals(SW_PIN_NEEDED, spend(0).getSW(), "SPEND_ALL_SIGN " + when);
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "and the payment is gone " + when);
        assertEquals(before, balance(), "nothing was spent or added " + when);
        assertEquals(limit, limit(), "and the limit is as it was " + when);
        assertArrayEquals(status, transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData());
        assertEquals(0, info()[10], "and the card was not locked " + when);
    }

    @Test
    @DisplayName("Every gated command refuses: PIN set and not verified, after a wrong PIN, and once blocked, for good")
    void testGateInEveryState() {
        readyWithLimit(100000);
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        reselect();
        assertAllGatedRefuse("with the PIN set and not verified");

        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertAllGatedRefuse("after a wrong PIN ended the session");

        assertEquals(0x63C1, verify(WRONG_PIN));
        assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN));
        assertEquals(2, info()[7], "blocked");
        assertEquals(0, info()[9], "no tries left");
        assertAllGatedRefuse("once the PIN is blocked");
        assertEquals(SW_PIN_BLOCKED, verify(TEST_PIN), "the right PIN no longer opens it");
        assertAllGatedRefuse("after the right PIN was tried on a blocked card");
        reselect();
        assertAllGatedRefuse("in a later tap of a blocked card");
        assertEquals(SW_OWNER_PROOF, setPin(NEW_PIN), "and a blocked card cannot be given a new PIN by whoever is at the reader");
        assertEquals(16, balance(), "the piece is still there, for its refund key");
    }

    @Test
    @DisplayName("The PIN is for one tap")
    void testPinIsForOneTap() {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        reselect();
        assertEquals(SW_PIN_NEEDED, spend(0).getSW(), "a PIN set and not given, and no allowance: the PIN is asked for, at the signature");
        assertEquals(1, slot(0)[0], "a refused spend burns nothing");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(0).getSW());
    }

    @Test
    @DisplayName("A right PIN gives the tries back; VERIFY_PIN before a PIN exists says so; an open card's PIN can be set again")
    void testTries() {
        assertEquals(SW_PIN_NOT_SET, verify(TEST_PIN));
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, setPin(NEW_PIN), "a card with no owner has nobody's PIN to protect");
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(2, info()[9]);
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(3, info()[9]);
        assertEquals(SW_WRONG_LENGTH, verify(new byte[] { 1, 2, 3 }));
        assertEquals(SW_WRONG_LENGTH, verify(new byte[9]));
        assertEquals(SW_WRONG_LENGTH, setPin(new byte[] { 1, 2, 3 }));
        assertEquals(SW_WRONG_LENGTH, setPin(new byte[9]));
    }

    @Test
    @DisplayName("SET_PIN on an open card replaces the PIN, unblocks it and ends the session")
    void testSetPinOnAnOpenCard() {
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        reselect();
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(0x63C1, verify(WRONG_PIN));
        assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN));
        assertEquals(2, info()[7]);
        assertEquals(SW_OK, setPin(NEW_PIN), "an open card needs nobody's say to be given a PIN again");
        assertEquals(1, info()[7], "unblocked");
        assertEquals(3, info()[9]);
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_SECURITY_NOT_SATIS, sw(setLimitByPinCommand(0)), "and the session that verified the old one is over");
    }

    // =========================================================================
    // The owner
    // =========================================================================

    @Test
    @DisplayName("GET_NONCE gives 16 new bytes each time and needs an owner; nothing else says the owner's key")
    void testNonce() {
        assertEquals(SW_NO_OWNER, nonce().getSW(), "a card with no owner has no use for one");
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setCard(MINT, REFUND));
        assertEquals(SW_OK, setOwner(OWNER));
        byte[] a = nonceBytes(), b = nonceBytes();
        assertFalse(Arrays.equals(a, b), "new each time");
        // the key is in nothing the card says
        String said = toHex(info()) + toHex(cardRecord()) + toHex(cardKey()) + toHex(a) + toHex(b)
            + toHex(transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData());
        assertFalse(said.contains(toHex(OWNER.pub)), "the owner's public key is not read out");
        assertFalse(said.contains(toHex(OWNER.pub).substring(2)), "not without its prefix either");
    }

    @Test
    @DisplayName("The owner survives a new SELECT and a reset")
    void testOwnerSurvives() {
        ready();
        reselect();
        assertEquals(1, info()[16]);
        simulator.reset();
        reselect();
        assertEquals(1, info()[16]);
        assertEquals(SW_OK, setLimit(7), "and the card still knows its owner's key");
    }

    @Test
    @DisplayName("SET_OWNER takes 65 bytes beginning 04, on an open card and, with a proof, on an owned one")
    void testSetOwnerShape() {
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, new byte[32])));
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, new byte[64])));
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, new byte[66])));
        byte[] compressed = new byte[65]; compressed[0] = 0x02;
        assertEquals(SW_WRONG_DATA, sw(new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, compressed)), "04 is the first byte of an uncompressed key");
        assertEquals(0, info()[16], "none of them was kept");
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(1, info()[16]);
        // an owned card takes a new key only with a proof, and the same shapes
        byte[] bad = OTHER_OWNER.pub.clone(); bad[0] = 0x02;
        byte[] n = nonceBytes();
        assertEquals(SW_WRONG_DATA, sw(new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, ownerData(ownerProof(L_OWNER, OWNER, n, bad), bad))));
        byte[] shortKey = Arrays.copyOf(OTHER_OWNER.pub, 64);
        n = nonceBytes();
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, ownerData(ownerProof(L_OWNER, OWNER, n, shortKey), shortKey))));
        assertEquals(SW_OK, setLimit(0), "the owner is still the first");
    }

    /**
     * An owner's command, as the tests below take it through every refusal and
     * one acceptance: its label, the value its proof covers, how to build it
     * from a proof, and how to see that it worked.
     */
    private interface OwnerCommand {
        String label();
        byte[] value();
        CommandAPDU build(byte[] proof);
        void assertDone(CashuAppletTest t);
        /** Whether the command also wants a verified PIN (LOCK_CARD does, as it always did). */
        default boolean wantsPin() { return false; }
    }

    private OwnerCommand[] ownerCommands() {
        return new OwnerCommand[] {
            new OwnerCommand() {
                public String label() { return L_PIN; }
                public byte[] value() { return NEW_PIN; }
                public CommandAPDU build(byte[] proof) { return changePinCommand(proof, NEW_PIN); }
                public void assertDone(CashuAppletTest t) { t.reselect(); assertEquals(SW_OK, t.verify(NEW_PIN)); }
                public String toString() { return "CHANGE_PIN"; }
            },
            new OwnerCommand() {
                public String label() { return L_LIMIT; }
                public byte[] value() { return u32(777); }
                public CommandAPDU build(byte[] proof) { return setLimitCommand(proof, 777); }
                public void assertDone(CashuAppletTest t) { assertEquals(777, t.limit()); }
                public String toString() { return "SET_LIMIT (owner's form)"; }
            },
            new OwnerCommand() {
                public String label() { return L_OWNER; }
                public byte[] value() { return OTHER_OWNER.pub; }
                public CommandAPDU build(byte[] proof) { return setOwnerCommand(proof, OTHER_OWNER); }
                public void assertDone(CashuAppletTest t) {
                    // the new owner can now be proved, and the old one cannot
                    assertEquals(SW_OK, sw2(t, setLimitCommand(ownerProof(L_LIMIT, OTHER_OWNER, t.nonceBytes(), u32(9)), 9)));
                    assertEquals(SW_OWNER_PROOF, sw2(t, setLimitCommand(ownerProof(L_LIMIT, OWNER, t.nonceBytes(), u32(10)), 10)));
                }
                public String toString() { return "SET_OWNER (replacing one)"; }
            },
            new OwnerCommand() {
                private final byte[] data = record("https://other.example.com", NO_REFUND);
                public String label() { return L_CARD; }
                public byte[] value() { return data; }
                public CommandAPDU build(byte[] proof) { return setCardCommand(proof, data); }
                public void assertDone(CashuAppletTest t) {
                    byte[] c = t.cardRecord();
                    assertEquals("https://other.example.com", new String(Arrays.copyOfRange(c, 106, c.length - 3), StandardCharsets.US_ASCII));
                    assertArrayEquals(new byte[4], Arrays.copyOfRange(c, 40, 44), "and a new record lets the ratchet go: the hardest bits are nothing again, for the next header to set");
                }
                public String toString() { return "SET_CARD"; }
            },
            new OwnerCommand() {
                public String label() { return L_LOAD; }
                public byte[] value() { return new byte[0]; }
                public CommandAPDU build(byte[] proof) { return allowLoadCommand(proof); }
                public void assertDone(CashuAppletTest t) { assertEquals(SW_OK, t.load(buildProof(KEYSET, 8, 70)).getSW(), "loaded with no PIN"); }
                public String toString() { return "ALLOW_LOAD"; }
            },
            new OwnerCommand() {
                public String label() { return L_LOCK; }
                public byte[] value() { return new byte[0]; }
                public CommandAPDU build(byte[] proof) { return lockCommand(proof); }
                public void assertDone(CashuAppletTest t) { assertEquals(1, t.info()[10], "locked"); }
                public boolean wantsPin() { return true; }
                public String toString() { return "LOCK_CARD"; }
            },
            new OwnerCommand() {
                public String label() { return L_RESET; }
                public byte[] value() { return new byte[0]; }
                public CommandAPDU build(byte[] proof) { return resetCommand(proof); }
                public void assertDone(CashuAppletTest t) {
                    assertEquals(0, t.info()[16], "no owner now");
                    assertEquals(0, t.info()[11], "and no record");
                }
                public String toString() { return "RESET_CARD"; }
            },
            new OwnerCommand() {
                public String label() { return L_TAG; }
                public byte[] value() { return new byte[] { 1 }; }
                public CommandAPDU build(byte[] proof) { return setTagCommand(proof, 1); }
                public void assertDone(CashuAppletTest t) {
                    assertEquals(1, t.infoTag()[42], "the tag is off now (1.19)");
                    assertEquals(SW_OK, t.setTag(false), "and on again");
                }
                public String toString() { return "SET_TAG"; }
            },
        };
    }

    private static int sw2(CashuAppletTest t, CommandAPDU c) { return t.sw(c); }

    @Test
    @DisplayName("Every owner's command is refused with the PIN alone, with a nonce and no proof, with another key's signature, with another command's label, with an earlier nonce's proof, with a proof for another value, and with a proof that has worked once; and is accepted with the right proof and no PIN")
    void testEveryOwnerCommandNeedsItsProof() {
        for (OwnerCommand c : ownerCommands()) {
            simulator = freshCard();
            ready();
            // the PIN is verified, the card is empty, nothing is on it: a terminal that holds the PIN has all it can have
            byte[] proof = ownerProof(c.label(), OWNER, new byte[16], c.value());
            long limitBefore = limit();
            byte[] recordBefore = cardRecord();
            String name = c.toString();

            assertEquals(SW_OWNER_PROOF, sw(c.build(proof)), name + ": the PIN alone, no nonce asked for");
            nonceBytes();
            assertEquals(SW_OWNER_PROOF, sw(c.build(new byte[] { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 })), name + ": a nonce, and a proof of nothing");
            byte[] n = nonceBytes();
            assertEquals(SW_OWNER_PROOF, sw(c.build(ownerProof(c.label(), OTHER_OWNER, n, c.value()))), name + ": another key's signature");
            for (String other : OWNER_LABELS) {
                if (other.equals(c.label())) continue;
                n = nonceBytes();
                assertEquals(SW_OWNER_PROOF, sw(c.build(ownerProof(other, OWNER, n, c.value()))), name + ": a proof under " + other);
            }
            n = nonceBytes();
            byte[] wrongValue = c.value().length == 0 ? new byte[] { 1 } : flip(c.value());
            assertEquals(SW_OWNER_PROOF, sw(c.build(ownerProof(c.label(), OWNER, n, wrongValue))), name + ": a proof for another value");
            byte[] older = nonceBytes();
            byte[] forOlder = ownerProof(c.label(), OWNER, older, c.value());
            nonceBytes();
            assertEquals(SW_OWNER_PROOF, sw(c.build(forOlder)), name + ": a proof for an earlier nonce");
            byte[] m = nonceBytes();
            byte[] right = ownerProof(c.label(), OWNER, m, c.value());
            assertEquals(SW_OWNER_PROOF, sw(c.build(ownerProof(c.label(), OTHER_OWNER, m, c.value()))), name + ": a wrong proof uses the nonce up");
            assertEquals(SW_OWNER_PROOF, sw(c.build(right)), name + ": and the right proof for it is no good after that");
            // nothing happened, and no PIN try was spent, and the session was not ended
            assertEquals(limitBefore, limit(), name);
            assertArrayEquals(recordBefore, cardRecord(), name);
            assertEquals(3, info()[9], name + ": a wrong proof costs no PIN tries");
            assertEquals(0, info()[10], name + ": not locked");
            assertEquals(1, info()[7], name + ": not blocked");
            assertEquals(SW_OK, verify(TEST_PIN), name + ": the session was not ended and the PIN is the old one");

            // and the right one, with no PIN verified, is taken
            reselect();
            if (c.wantsPin()) {
                assertEquals(SW_SECURITY_NOT_SATIS, sw(c.build(ownerProof(c.label(), OWNER, nonceBytes(), c.value()))), name + ": needs the PIN as well, as it always did");
                assertEquals(SW_OK, verify(TEST_PIN));
            }
            n = nonceBytes();
            byte[] good = ownerProof(c.label(), OWNER, n, c.value());
            assertEquals(SW_OK, sw(c.build(good)), name + ": the owner's proof" + (c.wantsPin() ? "" : ", and no PIN"));
            c.assertDone(this);
            // used: the same proof cannot be sent again
            assertNotEquals(SW_OK, sw(c.build(good)), name + ": a proof that has worked once");
        }
    }

    private static byte[] flip(byte[] b) {
        byte[] c = b.clone();
        c[c.length - 1] ^= 1;
        return c;
    }

    @Test
    @DisplayName("A wrong proof costs no PIN tries, even sent five times by a terminal with the PIN, and does not end its session")
    void testWrongProofsCostNothing() {
        ready();
        for (int i = 0; i < 5; i++) {
            byte[] n = nonceBytes();
            assertEquals(SW_OWNER_PROOF, sw(changePinCommand(ownerProof(L_PIN, OTHER_OWNER, n, NEW_PIN), NEW_PIN)), "a wrong proof, " + i);
        }
        assertEquals(3, info()[9], "the PIN's tries are as they were");
        assertEquals(1, info()[7], "and the card is not blocked");
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 1)).getSW(), "the session still stands");
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(0x63C2, verify(NEW_PIN), "the PIN never changed");
    }

    @Test
    @DisplayName("CHANGE_PIN: the old PIN stops working, the session ends, a PIN's length is the PIN's, and it works with no PIN and any funds")
    void testChangePin() {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        assertEquals(SW_OK, changePin(NEW_PIN), "a funded card, the old PIN verified");
        assertEquals(SW_PIN_NEEDED, spend(0).getSW(), "the session that verified the old PIN is over");
        assertEquals(0x63C2, verify(TEST_PIN));
        assertEquals(SW_OK, verify(NEW_PIN));
        reselect();
        assertEquals(SW_OK, changePin(TEST_PIN), "with no PIN verified in this tap");
        assertEquals(SW_OK, verify(TEST_PIN));
        byte[] n = nonceBytes();
        assertEquals(SW_WRONG_LENGTH, sw(changePinCommand(ownerProof(L_PIN, OWNER, n, new byte[] { 1, 2, 3 }), new byte[] { 1, 2, 3 })));
        n = nonceBytes();
        assertEquals(SW_WRONG_LENGTH, sw(changePinCommand(ownerProof(L_PIN, OWNER, n, new byte[9]), new byte[9])));
        assertEquals(SW_OK, verify(TEST_PIN), "the PIN is the one it was");
    }

    @Test
    @DisplayName("CHANGE_PIN unblocks a blocked card: with the owner's proof, no old PIN, and a funded card")
    void testChangePinUnblocks() {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        reselect();
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(0x63C1, verify(WRONG_PIN));
        assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN));
        assertEquals(2, info()[7]);
        assertEquals(SW_PIN_BLOCKED, verify(TEST_PIN));
        assertEquals(SW_PIN_NEEDED, spend(0).getSW(), "blocked: nothing spends");
        reselect();
        assertEquals(SW_OK, changePin(NEW_PIN), "the owner's phone, which does not know the PIN");
        assertEquals(1, info()[7], "set, not blocked");
        assertEquals(3, info()[9], "the tries are back");
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, spend(0).getSW(), "and the card pays again");
        // and a card whose PIN somebody forgot is the same
        reselect();
        assertEquals(SW_OK, changePin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
    }

    @Test
    @DisplayName("A card with no owner refuses everything that needs one with 6A90, and the PIN gate comes first for LOCK_CARD")
    void testNoOwnerRefusesWhatNeedsOne() {
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setCard(MINT, REFUND));
        assertEquals(SW_NO_OWNER, nonce().getSW());
        assertEquals(SW_NO_OWNER, sw(changePinCommand(new byte[8], NEW_PIN)));
        assertEquals(SW_NO_OWNER, sw(setLimitCommand(new byte[8], 100)));
        assertEquals(SW_NO_OWNER, sw(allowLoadCommand(new byte[8])));
        assertEquals(SW_NO_OWNER, sw(lockCommand(new byte[8])));
        assertEquals(SW_NO_OWNER, sw(resetCommand(new byte[8])), "RESET_CARD (1.17): a card with no owner has nothing to reset by");
        assertEquals(SW_NO_OWNER, sw(setTagCommand(new byte[8], 1)), "SET_TAG (1.19): nor has it an owner to switch the tag, which is on");
        assertEquals(0, infoTag()[42], "the tag of a card with no owner is on");
        assertEquals(3, info()[9]);
        assertEquals(0, info()[10], "not locked");
        assertEquals(0, limit());
        assertEquals(SW_NO_OWNER, load(buildProof(KEYSET, 16, 1)).getSW(), "and no money can go on");
        assertEquals(0, balance());
    }

    // =========================================================================
    // An owned card is not open, empty or not (A1); no money without an owner (A2); the owner adds funds with no PIN (A3)
    // =========================================================================

    /**
     * The open commands, as an attacker with nothing but the PIN sends them:
     * each is refused on a card that has an owner, and nothing it would have
     * set is set.
     */
    private void assertTheOpenCommandsAreRefused(String when) {
        byte[] recordBefore = cardRecord();
        byte[] infoBefore = info();
        Key attacker = new Key();
        assertEquals(SW_OWNER_PROOF, setPin(NEW_PIN), "SET_PIN " + when);
        assertEquals(SW_OWNER_PROOF, setOwner(attacker), "SET_OWNER, the open form " + when);
        assertNotEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, ownerData(new byte[8], attacker.pub))), "SET_OWNER, with a proof of nothing " + when);
        assertEquals(SW_OWNER_PROOF, setCardOpen("https://attacker.example.com", NO_REFUND), "SET_CARD, the open form " + when);
        // the PIN's own gate comes first: refused for want of the PIN, or, with it, for want of the owner
        int pinForm = sw(setLimitByPinCommand(0));
        assertTrue(pinForm == SW_OWNER_PROOF || pinForm == SW_SECURITY_NOT_SATIS, "SET_LIMIT, the PIN form " + when + ": " + Integer.toHexString(pinForm));
        pinForm = sw(setLimitByPinCommand(4294967295L));
        assertTrue(pinForm == SW_OWNER_PROOF || pinForm == SW_SECURITY_NOT_SATIS, "and with a limit " + when + ": " + Integer.toHexString(pinForm));
        assertArrayEquals(recordBefore, cardRecord(), "the record is as it was " + when);
        assertArrayEquals(infoBefore, info(), "and so is everything the card says about itself " + when);
    }

    @Test
    @DisplayName("A1: a card with an owner refuses SET_PIN, SET_OWNER, SET_CARD and the PIN form of SET_LIMIT without the owner's proof, even when it is empty, funded, blocked or has the PIN verified")
    void testAnOwnedCardIsNotOpen() {
        ready();
        assertEquals(0, info()[3], "empty");
        assertTheOpenCommandsAreRefused("on an empty card, the PIN verified");
        reselect();
        assertTheOpenCommandsAreRefused("on an empty card, the PIN not verified");
        // SET_LIMIT's PIN form is gated by the PIN first; with it verified it is the owner it wants
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        assertTheOpenCommandsAreRefused("on a funded card");
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(SW_OK, clearSpent());
        assertTheOpenCommandsAreRefused("on a card a terminal has just emptied");
        reselect();
        verify(WRONG_PIN); verify(WRONG_PIN); verify(WRONG_PIN);
        assertEquals(2, info()[7]);
        assertTheOpenCommandsAreRefused("on a blocked card");
        simulator.reset();
        reselect();
        assertTheOpenCommandsAreRefused("after a reset");
        // and what the owner can do is as it was
        assertEquals(SW_OK, changePin(NEW_PIN));
        assertEquals(SW_OK, verify(NEW_PIN));
    }

    @Test
    @DisplayName("A1: a card with no owner accepts them while it is empty, and refuses them 6A8D with one unspent piece")
    void testAnOpenCardTakesThemWhileEmpty() throws Exception {
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setCard(MINT, REFUND));
        assertEquals(SW_OK, setCard("https://other.example.com", NO_REFUND), "a record can be written again, with no proof");
        assertEquals(SW_OK, sw(setLimitByPinCommand(500)), "a limit needs no block header to be set: the card spends its first day on trust");
        assertEquals(500, limit());
        assertEquals(0, windowStart(), "its window has no start until the first header arrives");
        assertEquals(SW_OK, sw(setLimitByPinCommand(0)), "none needs none");
        assertEquals(SW_OK, setTime(T0));
        assertEquals(SW_OK, sw(setLimitByPinCommand(500)));
        assertEquals(500, limit());
        assertEquals(T0, windowStart());
        assertEquals(SW_OK, setPin(NEW_PIN), "and the PIN replaced");
        assertEquals(SW_OK, setOwner(OWNER), "and the owner given");
        // from there it is the owner's: the same four are refused
        assertEquals(SW_OWNER_PROOF, setPin(TEST_PIN));
        assertEquals(SW_OWNER_PROOF, setOwner(OTHER_OWNER));

        // one unspent piece: not on any command's account, since no command can put one on an open card,
        // but a card could hold one (a card that was loaded, then lost its owner some other way)
        simulator = freshCard();
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setCard(MINT, REFUND));
        assertEquals(SW_OK, setTime(T0));
        byte[] storage = field("proofStorage");
        System.arraycopy(buildProof(KEYSET, 10, 3), 0, storage, 1, 81);
        storage[0] = 1;
        assertEquals(SW_CARD_IN_USE, setPin(NEW_PIN), "SET_PIN");
        assertEquals(SW_CARD_IN_USE, setOwner(OWNER), "SET_OWNER");
        assertEquals(SW_CARD_IN_USE, setCard("https://other.example.com", NO_REFUND), "SET_CARD");
        assertEquals(SW_CARD_IN_USE, sw(setLimitByPinCommand(0)), "SET_LIMIT, the PIN form");
        assertEquals(0, info()[16], "no owner was given");
        storage[0] = 2;   // spent, and not yet cleared: nothing unspent
        assertEquals(SW_OK, setPin(NEW_PIN), "a spent slot is not an unspent piece");
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, setOwner(OWNER));
    }

    /** A card whose terminal has emptied it, as far as the card can know. */
    @Test
    @DisplayName("A1: the takeover. A terminal with the PIN empties a card that fits within its limit, then tries to make the card its own: it fails at every step, in any order")
    void testTheTakeoverFails() {
        for (long limit : new long[] { 0, 100 }) {
            simulator = freshCard();
            readyWithLimit(limit);
            assertEquals(SW_OK, load(buildProof(KEYSET, 100, 1)).getSW(), "a piece within the day's limit");
            // the terminal: the PIN, a spend (what the day allows), and the used slot cleared: the card is empty
            reselect();
            assertEquals(SW_OK, verify(TEST_PIN));
            assertEquals(SW_OK, spend(0).getSW());
            assertEquals(SW_OK, clearSpent());
            assertEquals(0, info()[3], "the card is empty: it holds nothing a terminal could lose");
            byte[] recordBefore = cardRecord();
            byte[] infoBefore = info();

            // it now tries to take the card over, in each order: its own PIN, its own owner, its own record, its own limit
            Key attacker = new Key();
            assertEquals(SW_OWNER_PROOF, setPin(NEW_PIN), "its own PIN");
            assertEquals(SW_OWNER_PROOF, setOwner(attacker), "its own owner");
            assertEquals(SW_OWNER_PROOF, setCardOpen("https://attacker.example.com", NO_REFUND), "its own record");
            assertEquals(SW_OWNER_PROOF, sw(setLimitByPinCommand(0)), "its own limit");
            // and with a proof by its own key, which the card has no reason to take
            byte[] n = nonceBytes();
            assertEquals(SW_OWNER_PROOF, sw(setOwnerCommand(ownerProof(L_OWNER, attacker, n, attacker.pub), attacker)), "its own owner, signed by itself");
            byte[] data = record("https://attacker.example.com", NO_REFUND);
            n = nonceBytes();
            assertEquals(SW_OWNER_PROOF, sw(setCardCommand(ownerProof(L_CARD, attacker, n, data), data)), "its own record, signed by itself");
            n = nonceBytes();
            assertEquals(SW_OWNER_PROOF, sw(changePinCommand(ownerProof(L_PIN, attacker, n, NEW_PIN), NEW_PIN)), "its own PIN, signed by itself");
            n = nonceBytes();
            assertEquals(SW_OWNER_PROOF, sw(setLimitCommand(ownerProof(L_LIMIT, attacker, n, u32(0)), 0)), "its own limit, signed by itself");
            // a header it made itself, to move the clock: with none of the work in it, which is all that is asked of a header
            assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(unmined(T0 + 5 * DAY, TEST_BITS))), "its own header");
            assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(unmined(T0 + 9 * DAY, TEST_BITS))), "and another");
            assertEquals(T0, now(), "and the clock is where it was");
            // the same after the tap, after a reset
            simulator.reset();
            reselect();
            assertEquals(SW_OK, verify(TEST_PIN));
            assertEquals(SW_OWNER_PROOF, setPin(NEW_PIN));
            assertEquals(SW_OWNER_PROOF, setOwner(attacker));
            assertEquals(SW_OWNER_PROOF, setCardOpen("https://attacker.example.com", NO_REFUND));

            assertArrayEquals(recordBefore, cardRecord(), "the record, its clock's proof and its limit are as they were");
            assertArrayEquals(Arrays.copyOf(infoBefore, 29), Arrays.copyOf(info(), 29), "and the card says what it said");
            assertEquals(1, info()[29], "but for the note that it paid, which the tap after a payment has (8.2)");
            // the card is still the owner's and the holder's: their PIN, their owner's proof
            reselect();
            assertEquals(SW_OK, verify(TEST_PIN), "the PIN is the holder's");
            assertEquals(SW_OK, setLimit(1234), "and the owner's proof still works");
            assertEquals(1234, limit());
            // all the terminal can do with an emptied card is put pieces on it, which the mint will refuse
            assertEquals(SW_OK, load(buildProof(KEYSET, 1, 9)).getSW());
        }
    }

    @Test
    @DisplayName("A2: a card with no owner cannot be loaded, whatever else is done to it; with an owner it can")
    void testNoLoadWithoutAnOwner() {
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setCard(MINT, REFUND));
        assertEquals(SW_OK, setTime(T0));
        assertEquals(SW_OK, sw(setLimitByPinCommand(1_000_000)));
        assertEquals(SW_NO_OWNER, load(buildProof(KEYSET, 16, 1)).getSW(), "PIN verified, record, time, a limit: and still no owner");
        assertEquals(SW_NO_OWNER, load(buildProof(KEYSET, 16, 1, 1900000000L)).getSW());
        assertEquals(0, info()[3], "nothing is on the card");
        assertEquals(0, balance());
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW(), "with an owner it can");
    }

    @Test
    @DisplayName("A piece whose nonce is already on an unspent slot is refused, so a terminal with only the PIN cannot load a copy with a false amount, spend the copy for a small charge and hold a signature for the real piece")
    void testACopyOfAPieceOnTheCardIsRefused() throws Exception {
        readyWithLimit(250);
        // the owner's phone has put one real piece worth 1000 on the card, and the day's limit is 250
        byte[] real = buildProof(KEYSET, 1000, 7);
        assertEquals(SW_OK, load(real).getSW());
        assertEquals(SW_OVER_LIMIT, spend(0).getSW(), "honestly, the piece is over the day's limit and cannot be spent");
        byte[] infoBefore = info();
        byte[] slotsBefore = transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 64)).getData();
        // the terminal reads slot 0 and writes the same piece back, stating an amount of 1: the amount is not in what the card signs
        byte[] slot0 = slot(0);
        byte[] copy = Arrays.copyOfRange(slot0, 1, 82);
        putUint32(copy, 8, 1);
        assertEquals(SW_PIECE_ON_CARD, load(copy).getSW(), "the copy is refused");
        assertEquals(SW_SLOT_EMPTY, spend(1).getSW(), "so there is no second slot to spend");
        assertEquals(SW_OVER_LIMIT, spend(0).getSW(), "and the real piece is still over the limit");
        // whatever else is stated about the same nonce, it is the same piece
        putUint32(copy, 8, 1000);
        assertEquals(SW_PIECE_ON_CARD, load(copy).getSW(), "the piece itself, loaded twice");
        byte[] dated = buildProof(KEYSET, 1, 7, 1900000000L);
        assertEquals(SW_PIECE_ON_CARD, load(dated).getSW(), "the same nonce with a date and another amount");
        byte[] otherKeyset = buildProof("0123456789abcdef", 1, 7);
        assertEquals(SW_PIECE_ON_CARD, load(otherKeyset).getSW(), "and of another keyset");
        assertArrayEquals(infoBefore, info(), "nothing was counted, burned or written");
        assertArrayEquals(slotsBefore, transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 64)).getData());
        assertArrayEquals(slot0, slot(0), "and the real piece is as it was");
        assertEquals(0, spentToday());
        assertEquals(1000, balance());
    }

    @Test
    @DisplayName("A piece whose nonce is on a spent slot is refused as well, and loads again once CLEAR_SPENT has freed that slot")
    void testAPieceOnASpentSlotWaitsForClearSpent() throws Exception {
        readyWithLimit(250);
        byte[] piece = buildProof(KEYSET, 100, 7);
        assertEquals(SW_OK, load(piece).getSW());
        ResponseAPDU first = spend(0);
        assertEquals(SW_OK, first.getSW());
        byte[] spentSlot = slot(0);
        assertTrue(signedFor(first.getData(), spentSlot, REFUND));
        assertEquals(100, spentToday());
        // spent, the slot still holds the piece: a copy with another amount is not written beside it
        byte[] copy = buildProof(KEYSET, 1, 7);
        assertEquals(SW_PIECE_ON_CARD, load(copy).getSW(), "a copy of a spent piece");
        assertEquals(SW_PIECE_ON_CARD, load(piece).getSW(), "nor the piece itself");
        assertEquals(SW_SLOT_EMPTY, spend(1).getSW());
        assertEquals(100, spentToday());
        // freed, the slot holds nothing, and the piece may be loaded again: its signature may have been lost with the tap
        assertEquals(SW_OK, clearSpent());
        assertEquals(SW_SLOT_EMPTY, sw(new CommandAPDU(CLA, INS_GET_PROOF, 0, 0, 256)));
        ResponseAPDU again = load(piece);
        assertEquals(SW_OK, again.getSW(), "a re-load after CLEAR_SPENT is allowed");
        assertEquals(0, again.getData()[0], "into the freed slot");
        assertEquals(100, balance());
        ResponseAPDU second = spend(0);
        assertEquals(SW_OK, second.getSW(), "and it can be spent again, and is charged as the piece is worth");
        assertTrue(signedFor(second.getData(), slot(0), REFUND));
        assertEquals(200, spentToday());
        // and once it is back on the card, it is refused again
        assertEquals(SW_PIECE_ON_CARD, load(copy).getSW());
    }

    @Test
    @DisplayName("Only the whole nonce makes a piece the same: one that differs in its first byte or its last is another piece")
    void testNearlyTheSameNonceIsAnotherPiece() {
        ready();
        byte[] piece = buildProof(KEYSET, 16, 7);
        assertEquals(SW_OK, load(piece).getSW());
        byte[] first = piece.clone();
        first[12] ^= 1;
        byte[] last = piece.clone();
        last[43] ^= 1;
        assertEquals(SW_OK, load(first).getSW(), "the first byte of the nonce differs");
        assertEquals(SW_OK, load(last).getSW(), "the last byte differs");
        assertEquals(SW_PIECE_ON_CARD, load(first).getSW());
        assertEquals(SW_PIECE_ON_CARD, load(last).getSW());
        assertEquals(48, balance());
    }

    @Test
    @DisplayName("The owner's grant gets no piece past the refusal: a copy is refused without the PIN as with it")
    void testACopyIsRefusedUnderTheOwnersGrantToo() {
        readyWithLimit(1000);
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 7)).getSW());
        reselect();
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_PIECE_ON_CARD, load(buildProof(KEYSET, 1, 7)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 1, 9)).getSW(), "another piece goes in under it as before");
    }

    @Test
    @DisplayName("The owner replaces the owner or the record only on an empty card, proof or no proof; the PIN, the limit and the grant it changes on a funded one")
    void testTheOwnerNeedsAnEmptyCardForTheOwnerAndTheRecord() {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        byte[] n = nonceBytes();
        assertEquals(SW_CARD_IN_USE, sw(setOwnerCommand(ownerProof(L_OWNER, OWNER, n, OTHER_OWNER.pub), OTHER_OWNER)), "a new owner, with the old one's proof, over a piece");
        assertEquals(SW_OK, setLimit(0), "but the limit may be changed under it");
        assertEquals(SW_OK, changePin(NEW_PIN), "and the PIN");
        assertEquals(SW_OK, allowLoad(), "and loading allowed");
        assertEquals(SW_OK, setTime(T0 + 5));
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(SW_OK, clearSpent());
        n = nonceBytes();
        assertEquals(SW_OK, sw(setOwnerCommand(ownerProof(L_OWNER, OWNER, n, OTHER_OWNER.pub), OTHER_OWNER)), "emptied, it may");
    }

    @Test
    @DisplayName("A3: the owner's grant lets LOAD_PROOF and CLEAR_SPENT through with no PIN, for the rest of that tap, and nothing else; a new SELECT ends it")
    void testAllowLoad() {
        readyWithLimit(100000);
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        reselect();
        // the payment left a change note (8.2); spend it with one no-PIN load so the rest of this test runs with no authority of any kind
        assertEquals(SW_OK, load(buildProof(KEYSET, 1, 9)).getSW(), "the change note allows one no-PIN load");
        reselect();
        // no PIN in this tap
        assertEquals(SW_SECURITY_NOT_SATIS, load(buildProof(KEYSET, 8, 2)).getSW());
        assertEquals(SW_SECURITY_NOT_SATIS, clearSpent());
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 2)).getSW(), "a load, with no PIN");
        assertEquals(SW_OK, load(buildProof(KEYSET, 4, 3, 1900000000L)).getSW());
        assertEquals(SW_OK, clearSpent(), "and the used slots cleared");
        assertEquals(13, balance());
        // and nothing else the PIN opens
        assertEquals(SW_PIN_NEEDED, spend(2).getSW(), "not a spend: the grant signs nothing, and the PIN is asked for (the allowance is none)");
        assertEquals(SW_PIN_NEEDED, spend(1).getSW());
        assertEquals(SW_OWNER_PROOF, setPin(NEW_PIN), "not the PIN");
        assertEquals(SW_OWNER_PROOF, setCardOpen("https://x.example.com", NO_REFUND), "not the record");
        assertEquals(SW_SECURITY_NOT_SATIS, sw(setLimitByPinCommand(1)), "not the limit by PIN");
        assertEquals(SW_SECURITY_NOT_SATIS, lock(), "not the lock");
        assertEquals(0, info()[10]);
        assertEquals(13, balance(), "nothing was spent");
        // the grant is for this tap
        reselect();
        assertEquals(SW_SECURITY_NOT_SATIS, load(buildProof(KEYSET, 8, 4)).getSW(), "a new SELECT ends it");
        assertEquals(SW_SECURITY_NOT_SATIS, clearSpent());
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 4)).getSW());
        simulator.reset();
        reselect();
        assertEquals(SW_SECURITY_NOT_SATIS, load(buildProof(KEYSET, 8, 5)).getSW(), "and so does a reset");
        // a wrong PIN in the same tap does not take it back, and does not give a spend
        assertEquals(SW_OK, allowLoad());
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 5)).getSW());
        assertEquals(SW_PIN_NEEDED, spend(2).getSW());
    }

    @Test
    @DisplayName("8.2: the tap that writes the change loads with no PIN and frees the burned places, and nothing else; the load closes the window")
    void testChangeTapNeedsNoPin() {
        readyWithLimit(100000);
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 2)).getSW());
        assertEquals(0, info()[29], "nothing is due before a payment");
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(0, info()[29], "the note is for the next tap, not the one that paid");
        reselect();
        assertEquals(1, info()[29], "the tap after a payment says it may load");
        assertEquals(SW_OK, clearSpent(), "the place the payment burned is freed, with no PIN");
        assertEquals(1, info()[29], "freeing a place did not close the window");
        assertEquals(SW_OK, load(buildProof(KEYSET, 4, 3)).getSW(), "the change, with no PIN");
        assertEquals(1, info()[29], "the same tap may still load the rest of the change");
        assertEquals(SW_OK, load(buildProof(KEYSET, 2, 4)).getSW(), "a second piece of the change, still no PIN");
        assertEquals(14, balance());
        // and nothing else the PIN opens
        assertEquals(SW_PIN_NEEDED, spend(1).getSW(), "not a spend");
        assertEquals(SW_OWNER_PROOF, setPin(NEW_PIN), "not the PIN");
        assertEquals(SW_OWNER_PROOF, setCardOpen("https://x.example.com", NO_REFUND), "not the record");
        assertEquals(SW_SECURITY_NOT_SATIS, sw(setLimitByPinCommand(1)), "not the limit by PIN");
        assertEquals(SW_SECURITY_NOT_SATIS, lock(), "not the lock");
        assertEquals(14, balance(), "nothing was spent");
        reselect();
        assertEquals(0, info()[29], "the load closed the window: the next fresh tap has no grant");
        assertEquals(SW_SECURITY_NOT_SATIS, load(buildProof(KEYSET, 4, 5)).getSW(), "and loads nothing with no PIN");
        assertEquals(SW_SECURITY_NOT_SATIS, clearSpent());
    }

    @Test
    @DisplayName("8.2: the note survives a glance, a cut-short tap and a fresh session, and closes only when the change lands")
    void testChangeNoteSurvivesUntilLoaded() {
        readyWithLimit(100000);
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 2)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 4, 3)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        simulator.reset();      // the card left the field: the note is in permanent memory
        reselect();
        assertEquals(1, info()[29], "the next tap, after the card has been away, has the grant");
        reselect();             // a tap that only reads the card
        assertEquals(1, info()[29], "a glance that writes nothing leaves the note standing");
        simulator.reset();      // the phone opens a fresh session for the write itself
        reselect();
        assertEquals(1, info()[29], "and so does a cut-short tap and a fresh session");
        assertEquals(SW_OK, load(buildProof(KEYSET, 4, 4)).getSW(), "the change goes on at last, with no PIN");
        reselect();
        assertEquals(0, info()[29], "and now, the change on, the window is closed");
        assertEquals(SW_SECURITY_NOT_SATIS, load(buildProof(KEYSET, 2, 5)).getSW(), "a stranger's later tap gets nothing");
        // a payment in a later tap makes a new note
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(1).getSW(), "a payment, with the PIN");
        reselect();
        assertEquals(1, info()[29], "makes a note for the tap after it");
        assertEquals(SW_OK, load(buildProof(KEYSET, 2, 5)).getSW(), "its change, with no PIN");
        reselect();
        assertEquals(0, info()[29]);
    }

    @Test
    @DisplayName("8.2: the note opens nothing on a locked card or under a blocked PIN")
    void testChangeNoteOpensNothingLockedOrBlocked() {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 2)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        reselect();
        assertEquals(1, info()[29]);
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(0x63C1, verify(WRONG_PIN));
        assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN));
        assertEquals(SW_SECURITY_NOT_SATIS, load(buildProof(KEYSET, 4, 3)).getSW(), "a blocked PIN waives nothing");
        // unblocked by the owner, and paid from again, then locked in the paying tap
        byte[] n = nonceBytes();
        assertEquals(SW_OK, sw(changePinCommand(ownerProof(L_PIN, OWNER, n, TEST_PIN), TEST_PIN)));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(SW_OK, lock());
        reselect();
        assertEquals(1, info()[29], "the note is there");
        assertEquals(SW_NOT_ALLOWED, load(buildProof(KEYSET, 4, 3)).getSW(), "and a locked card takes no load for it");
        assertEquals(SW_NOT_ALLOWED, clearSpent());
    }

    @Test
    @DisplayName("A3: the grant needs the owner's proof, is refused on a card with no owner and on a locked card, and does not load onto a blocked PIN")
    void testAllowLoadIsTheOwners() {
        ready();
        reselect();
        assertEquals(SW_OWNER_PROOF, sw(allowLoadCommand(new byte[8])), "no nonce asked for");
        assertEquals(SW_SECURITY_NOT_SATIS, load(buildProof(KEYSET, 8, 1)).getSW(), "so no grant");
        byte[] n = nonceBytes();
        assertEquals(SW_OWNER_PROOF, sw(allowLoadCommand(ownerProof(L_PIN, OWNER, n, new byte[0]))), "a proof for another command");
        assertEquals(SW_SECURITY_NOT_SATIS, load(buildProof(KEYSET, 8, 1)).getSW());
        // a blocked PIN waives nothing: the owner unblocks it first
        verify(WRONG_PIN); verify(WRONG_PIN); verify(WRONG_PIN);
        assertEquals(2, info()[7]);
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_SECURITY_NOT_SATIS, load(buildProof(KEYSET, 8, 1)).getSW(), "a blocked card is unblocked before it is loaded");
        assertEquals(SW_OK, changePin(NEW_PIN));
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 1)).getSW());
        // locked
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, lock());
        reselect();
        assertEquals(SW_NOT_ALLOWED, sw(allowLoadCommand(ownerProof(L_LOAD, OWNER, nonceBytes(), new byte[0]))), "a locked card takes no writes");
    }

    @Test
    @DisplayName("A3: loading with the grant needs a record, as with the PIN, and no clock: a card that has seen no block header loads under the owner's grant, its first day on trust")
    void testAllowLoadNeedsARecordAndNoClock() throws Exception {
        readyWithoutAHeader(0);
        reselect();
        assertEquals(SW_OK, allowLoad());
        assertEquals(0, now(), "the card has seen no block header");
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 1)).getSW(), "and it loads, under the grant: nothing answers 6A92 since 1.15");
        assertEquals(0, now(), "loading asked for no clock");
        assertEquals(SW_OK, setTime(T0));
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 2)).getSW(), "with a header it loads as it did");
        // and no record is still the word for no record
        simulator = freshCard();
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, setOwner(OWNER));
        reselect();
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_NO_CARD_RECORD, load(buildProof(KEYSET, 8, 1)).getSW());
    }

    // =========================================================================
    // The time: Bitcoin block headers (1.15)
    // =========================================================================

    @Test
    @DisplayName("SET_HEADER: an older or repeated header is 9000 and changes nothing; a newer one is taken; the answer is the card's clock, four bytes, big-endian; 2^32 - 1 is a time like any other, and the greatest")
    void testSetHeader() {
        ready();
        assertEquals(T0, now(), "given a block at set-up");
        byte[] recordBefore = cardRecord();
        byte[] infoBefore = info();
        ResponseAPDU older = transmit(setTimeCommand(T0 - 1000));
        assertEquals(SW_OK, older.getSW(), "an old header is harmless");
        assertEquals(4, older.getData().length);
        assertEquals(T0, readUint32(older.getData(), 0), "and is answered with the card's own clock");
        assertArrayEquals(recordBefore, cardRecord(), "nothing is changed, the hash of the last header taken included");
        assertArrayEquals(infoBefore, info());
        ResponseAPDU same = transmit(setTimeCommand(T0));
        assertEquals(SW_OK, same.getSW());
        assertEquals(T0, readUint32(same.getData(), 0));
        assertArrayEquals(recordBefore, cardRecord());
        ResponseAPDU twin = transmit(setHeaderCommand(mine(T0, TEST_BITS, 7)));
        assertEquals(SW_OK, twin.getSW(), "another block of the same time, with the work");
        assertEquals(T0, readUint32(twin.getData(), 0));
        assertArrayEquals(recordBefore, cardRecord(), "an equal time changes nothing: the hash kept is the first block's");
        ResponseAPDU newer = transmit(setTimeCommand(T0 + 3600));
        assertEquals(SW_OK, newer.getSW());
        assertEquals(T0 + 3600, readUint32(newer.getData(), 0));
        assertEquals(T0 + 3600, now());
        assertEquals(blockHash(blockAt(T0 + 3600)), toHex(headerHash()), "and the card keeps the hash of the header it took");
        // 2^32 - 1 is a time like any other, and the greatest
        assertEquals(SW_OK, setTime(4294967295L));
        assertEquals(4294967295L, now());
        assertEquals(SW_OK, setTime(T0 + 7200));
        assertEquals(4294967295L, now(), "and nothing is later than it: the clock never goes back");
    }

    @Test
    @DisplayName("SET_HEADER wants the 80 bytes of a header and no other length: 0, 1, 4, 79, 81, 84 and 255 are 6700, answer nothing and change nothing, though the hash of the first 80 would have done")
    void testSetHeaderLengths() {
        ready();
        byte[] block = blockAt(T0 + 500);
        byte[] recordBefore = cardRecord();
        for (int n : new int[] { 0, 1, 4, 79, 81, 84, 255 }) {
            byte[] data = n <= 80 ? Arrays.copyOf(block, n) : Arrays.copyOf(concat(block, new byte[n]), n);
            ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_SET_HEADER, 0, 0, data));
            assertEquals(SW_WRONG_LENGTH, r.getSW(), n + " bytes");
            assertEquals(0, r.getData().length, n + " bytes");
        }
        assertArrayEquals(recordBefore, cardRecord(), "none of them changed anything");
        assertEquals(SW_OK, sw(setHeaderCommand(block)), "the 80 bytes themselves go");
        assertEquals(T0 + 500, now());
    }

    @Test
    @DisplayName("SET_HEADER needs no key, no PIN, no owner, no record and no state: a card with nothing set up, one with no PIN verified, a blocked card and a locked card all take a header")
    void testSetHeaderNeedsNothing() {
        // a card with nothing at all set up: no PIN, no owner, no record
        assertEquals(0, info()[11], "no record");
        assertEquals(SW_OK, setTime(T0));
        assertEquals(T0, now());
        assertEquals(0, info()[11], "and still none");
        assertEquals(0, info()[7], "no PIN");
        // a card that is set up, with no PIN verified in this tap
        simulator = freshCard();
        ready();
        reselect();
        assertEquals(SW_OK, setTime(T0 + 1), "no PIN verified");
        assertEquals(T0 + 1, now());
        verify(WRONG_PIN); verify(WRONG_PIN); verify(WRONG_PIN);
        assertEquals(2, info()[7]);
        assertEquals(SW_OK, setTime(T0 + 2), "a blocked card");
        assertEquals(SW_OK, changePin(NEW_PIN));
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, lock());
        assertEquals(1, info()[10]);
        assertEquals(SW_OK, setTime(T0 + 3), "a locked card");
        assertEquals(T0 + 3, now());
        // it is not a write that a locked card refuses, and it asks for no proof of anyone
        assertEquals(SW_OK, sw(setHeaderCommand(blockAt(T0 + 4))));
        assertEquals(T0 + 4, now());
    }

    @Test
    @DisplayName("SET_HEADER believes the work and not who brings it: a header whose hash is over the target of its own bits is 6A93 and changes nothing, whatever its time, with no PIN or with the owner's proof; the answer says nothing of the clock")
    void testSetHeaderWantsItsWork() {
        ready();
        byte[] recordBefore = cardRecord();
        byte[] infoBefore = info();
        for (long time : new long[] { T0 - 10, T0, T0 + 1, T0 + 365 * DAY, 4294967295L }) {
            ResponseAPDU r = transmit(setHeaderCommand(unmined(time, TEST_BITS)));
            assertEquals(SW_LITTLE_WORK, r.getSW(), "a header of time " + time + " made without the work");
            assertEquals(0, r.getData().length, "and it says nothing of the clock");
        }
        assertArrayEquals(recordBefore, cardRecord(), "none of them changed anything");
        assertArrayEquals(infoBefore, info());
        assertEquals(0, logTampers());
        assertEquals(0, logTaps(), "and none is written in the log: it is no tap's business");
        // with the PIN given up and with the owner's grant: the same, and the same answer
        reselect();
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(unmined(T0 + 5, TEST_BITS))), "no PIN");
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(unmined(T0 + 5, TEST_BITS))), "the owner's grant is no help to it");
        // a header that has the work is taken in the same tap
        assertEquals(SW_OK, setTime(T0 + 5));
        assertEquals(T0 + 5, now());
        // the hash is a number read as Bitcoin reads it (little-endian): a header whose hash is under the target only read the other way is none
        byte[] block = blockAt(T0 + 100);
        java.math.BigInteger target = targetOf(TEST_BITS);
        assertTrue(hashOf(block).compareTo(target) <= 0);
        // find a header that is good as Bitcoin reads it and not as the bytes read big-endian, or the other way round: both exist at half
        byte[] goodOnlyHere = null;
        for (long nonce = 0; nonce < 1000 && goodOnlyHere == null; nonce++) {
            byte[] h = header(0x20000000L, new byte[32], new byte[32], T0 + 200, TEST_BITS, nonce);
            java.math.BigInteger little = hashOf(h), big = new java.math.BigInteger(1, sha256(sha256(h)));
            if (little.compareTo(target) > 0 && big.compareTo(target) <= 0) goodOnlyHere = h;
        }
        assertNotNull(goodOnlyHere, "a header whose hash is under the target only when read big-endian was found");
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(goodOnlyHere)), "read the wrong way round, the work is not there");
        assertEquals(T0 + 5, now());
    }

    @Test
    @DisplayName("Bits no header could carry are 6A80, before the hash is looked at: an exponent of 0 or past 32, a mantissa with its top bit set (a negative target); a target of nothing, or of less than a byte, is 6A93, as no hash is at or under it; and the length is looked at before the bits")
    void testSetHeaderBitsThatAreNone() {
        ready();
        byte[] recordBefore = cardRecord();
        long[] none = { 0x00123456L, 0x00000000L, 0x00FFFFFFL, 0x2100FFFFL, 0x21000001L, 0x22000001L, 0xFF00FFFFL, 0xFF7FFFFFL,
                        0x1D800000L, 0x1D800001L, 0x1F8FFFFFL, 0x20FFFFFFL, 0x20800000L, 0x03800000L, 0x01FEDCBAL };
        for (long bits : none) {
            // whatever the hash is, so a header that is mined for those bits does not exist: the header is simply the one with those bits and a nonce of 0
            byte[] h = header(0x20000000L, new byte[32], new byte[32], T0 + 10, bits, 0);
            ResponseAPDU r = transmit(setHeaderCommand(h));
            assertEquals(SW_WRONG_DATA, r.getSW(), "bits " + Long.toHexString(bits));
            assertEquals(0, r.getData().length);
        }
        // the largest exponent, the largest mantissa that is not negative: a fine form, refused only for want of work
        assertEquals(SW_OK, sw(setHeaderCommand(mine(T0 + 11, 0x207FFFFFL, 3))), "the floor of these tests is exactly that");
        // a target of nothing: not a form that is refused, a target no hash is under
        for (long bits : new long[] { 0x1D000000L, 0x20000000L, 0x01003456L, 0x02000012L, 0x03000000L }) {
            byte[] h = header(0x20000000L, new byte[32], new byte[32], T0 + 20, bits, 0);
            assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(h)), "bits " + Long.toHexString(bits) + ": a target of " + targetOf(bits));
        }
        // exponents 1 and 2 place the mantissa's top bytes in the bottom of the number, as Bitcoin does
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(header(0x20000000L, new byte[32], new byte[32], T0 + 20, 0x01123456L, 0))));
        assertEquals(T0 + 11, now(), "none of them moved the clock");
        // the length first: an impossible `bits` in 79 bytes is the length's word
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_SET_HEADER, 0, 0, Arrays.copyOf(header(0x20000000L, new byte[32], new byte[32], T0 + 10, 0x2100FFFFL, 0), 79))));
        // the targets this test worked out for those forms are Bitcoin's
        assertEquals(new java.math.BigInteger("12", 16), targetOf(0x01123456L), "exponent 1: the mantissa's top byte");
        assertEquals(new java.math.BigInteger("1234", 16), targetOf(0x02123456L), "exponent 2: its top two bytes");
        assertEquals(new java.math.BigInteger("123456", 16), targetOf(0x03123456L), "exponent 3: the mantissa");
        assertEquals(new java.math.BigInteger("123456", 16).shiftLeft(8), targetOf(0x04123456L), "exponent 4: a byte up");
    }

    @Test
    @DisplayName("The floor built into the applet: a header whose target is over it is 6A93 though its hash is under its own target, one at exactly the floor is taken, and the floor is looked at every time")
    void testTheFloor() {
        readyWithoutAHeader(0);
        useFloor(le32(0x1F0FFFFFL));            // 2^244 less a little: a floor that a header can be mined to here
        byte[] over = mine(T0, 0x1F100000L, 0);    // 2^244 exactly: a hair over the floor, and its own work is done
        assertTrue(hashOf(over).compareTo(targetOf(0x1F100000L)) <= 0, "its work is done");
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(over)), "a target over the floor is refused though it is the header's own");
        assertEquals(0, now());
        assertArrayEquals(new byte[4], headerBits(), "and the card remembers no bits for it");
        byte[] easy = mine(T0, TEST_BITS, 0);
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(easy)), "nor one at the tests' floor, which is the easiest there is");
        byte[] at = mine(T0, 0x1F0FFFFFL, 0);
        assertEquals(SW_OK, sw(setHeaderCommand(at)), "exactly the floor is taken");
        assertEquals(T0, now());
        assertArrayEquals(le32(0x1F0FFFFFL), headerBits());
        // harder than the floor, as much as it likes
        assertEquals(SW_OK, sw(setHeaderCommand(mine(T0 + 1, 0x1F0F0000L, 0))));
        // the floor is read at every header: raised back, the easy one goes
        useTheTestFloor();
        simulator = freshCard();
        readyWithoutAHeader(0);
        assertEquals(SW_OK, sw(setHeaderCommand(easy)));
        assertEquals(T0, now());
        // the floor in the source is the network's own, as it was built
        assertArrayEquals(REAL_FLOOR, BUILT_FLOOR, "FLOOR_BITS is 0x17087BC0, four times the target of the blocks of 1.15's time, as the specification has it");
        assertEquals(java.math.BigInteger.valueOf(0x087BC0).shiftLeft(8 * 20), targetOf(0x17087BC0L));
        assertEquals(java.math.BigInteger.valueOf(0x021EF0).shiftLeft(8 * 20).shiftLeft(2), targetOf(0x17087BC0L), "exactly four times the tip's target");
    }

    @Test
    @DisplayName("A quarter of the best: once the card has taken a header, one whose target is over four times the target of the hardest taken is 6A93 (exactly four times is taken); a header 2^248 after one of 2^244 is refused, one of 2^243 is taken and is the best; the best is raised only by a header that moves the clock forward")
    void testTheQuarterRule() {
        readyWithoutAHeader(0);
        // the first header is held to the floor alone
        byte[] first = mine(T0, 0x1F0FFFFFL, 0);
        assertEquals(SW_OK, sw(setHeaderCommand(first)));
        assertArrayEquals(le32(0x1F0FFFFFL), headerBits());
        // more than four times: refused, whatever its work for its own target and whatever its time
        byte[] easy = mine(T0 + 10, 0x20010000L, 0);
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(easy)), "2^248 against 2^244");
        assertEquals(T0, now());
        assertArrayEquals(le32(0x1F0FFFFFL), headerBits());
        assertEquals(blockHash(first), toHex(headerHash()), "nothing of it was kept");
        // exactly four times is taken, one more is not
        byte[] four = mine(T0 + 20, 0x1F3FFFFCL, 0);
        assertEquals(java.math.BigInteger.valueOf(0x0FFFFF).shiftLeft(8 * 28).shiftLeft(2), targetOf(0x1F3FFFFCL), "this test's own working: 4 x the best's target");
        assertEquals(SW_OK, sw(setHeaderCommand(four)), "exactly a quarter of the work");
        assertEquals(T0 + 20, now());
        assertArrayEquals(le32(0x1F0FFFFFL), headerBits(), "an easier header does not lower the best");
        assertEquals(blockHash(four), toHex(headerHash()), "but it is the last header taken");
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(mine(T0 + 30, 0x1F3FFFFDL, 0))), "one more is over");
        assertEquals(T0 + 20, now());
        // a harder header raises the best, and the bound follows it
        byte[] harder = mine(T0 + 40, 0x20000800L, 0);
        assertEquals(SW_OK, sw(setHeaderCommand(harder)), "2^243");
        assertEquals(T0 + 40, now());
        assertArrayEquals(le32(0x20000800L), headerBits(), "now the best");
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(mine(T0 + 50, 0x1F3FFFFCL, 1))), "four times the old best is over four times the new");
        assertEquals(SW_OK, sw(setHeaderCommand(mine(T0 + 50, 0x1F1FFFFFL, 1))), "(2^245 less a little is within 4 x 2^243 = 2^245)");
        assertArrayEquals(le32(0x20000800L), headerBits());
        // the best is raised only by a header that moves the clock forward: an equal or older one that is harder changes nothing
        long clock = now();
        byte[] harderStill = mine(clock, 0x20000400L, 0);
        byte[] harderStillOlder = mine(clock - 1, 0x20000400L, 1);
        byte[] recordBefore = cardRecord();
        assertEquals(SW_OK, sw(setHeaderCommand(harderStill)), "a harder header of the same time");
        assertEquals(SW_OK, sw(setHeaderCommand(harderStillOlder)), "and of an older");
        assertArrayEquals(recordBefore, cardRecord(), "changes nothing: not the best, not the hash");
        assertEquals(SW_OK, sw(setHeaderCommand(mine(clock + 1, 0x20000400L, 2))));
        assertArrayEquals(le32(0x20000400L), headerBits(), "a later one raises it");
        assertEquals(clock + 1, now());
        // the work is looked at before the time, so an older header that is over four times easier than the best is 6A93 and not the 9000 that an old
        // header with the work gets: harmless (it would have changed nothing), and pinned as what it is
        byte[] recordNow = cardRecord();
        assertEquals(SW_OK, sw(setHeaderCommand(mine(T0 - 100, 0x1F0FFFFFL, 7))), "an old header within a quarter of the best: taken for nothing");
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(mine(T0 - 100, 0x20010000L, 7))), "an old header over four times easier: refused");
        assertArrayEquals(recordNow, cardRecord());
    }

    @Test
    @DisplayName("SET_HEADER is judged before anything is written and writes in one transaction: the length, the double hash turned round, the bits (6A80), the hash against its own target, the floor, a quarter of the best, then whether it is later than the clock; and then the clock, the window's anchor, the hardest bits and the last hash together; no PIN, owner, lock, record or log is looked at")
    void testSetHeaderIsJudgedBeforeItMoves() throws Exception {
        String code = appletCode();
        // 2.0 (D20): the checks are `checkHeader`, which SET_HEADER, REFRESH and an anchored SET_OWNER share, and the writes `writeHeader`, inside
        // each caller's transaction. The order and the writes are pinned in each part.
        String h = body(code, "private void processSetHeader(", "private short checkHeader(");
        String c = body(code, "private short checkHeader(", "private void writeHeader(");
        String w = body(code, "private void writeHeader(", "private static void targetOf(");
        int length = h.indexOf("SW_WRONG_LENGTH");
        int checked = h.indexOf("checkHeader(buf, at)");
        int hashed = c.indexOf("sha.doFinal(buf, at, HEADER_LEN, scratch, X_MSG)");
        int again = c.indexOf("sha.doFinal(scratch, X_MSG, (short) 32, scratch, X_MSG)");
        int turned = c.indexOf("scratch[(short)(X_OUT + i)] = scratch[(short)(X_MSG + 31 - i)]");
        int bits = c.indexOf("targetOf(buf, (short)(at + 72), scratch, (short)(X_OUT + 32))");
        int own = c.indexOf("cmp256(scratch, X_OUT, scratch, (short)(X_OUT + 32)) > 0");
        int floor = c.indexOf("targetOf(FLOOR_BITS, (short) 0, scratch, X_HEX)");
        int overFloor = c.indexOf("cmp256(scratch, (short)(X_OUT + 32), scratch, X_HEX) > 0");
        int quarter = c.indexOf("timesFour(scratch, X_HEX)");
        int later = c.indexOf("cmpUint32(scratch, X_NUM, cardRecord, CARD_NOW_OFFSET) <= 0) return (short) 0");
        int begin = h.indexOf("JCSystem.beginTransaction()");
        int written = h.indexOf("writeHeader(buf, at, how)");
        int commit = h.indexOf("JCSystem.commitTransaction()");
        int answer = h.indexOf("apdu.setOutgoingAndSend");
        assertTrue(hashed > 0 && hashed < again && again < turned && turned < bits && bits < own && own < floor && floor < overFloor
            && overFloor < quarter && quarter < later,
            "checkHeader: the 80 bytes hashed and the hash hashed again and turned round; the bits worked out (6A80); the hash against them; the floor; the quarter of the best; whether it is later");
        assertTrue(length > 0 && length < checked && checked < begin && begin < written && written < commit && commit < answer,
            "SET_HEADER: the length; the checks; then one transaction, the header written in it; then the answer");
        assertTrue(h.contains("if (how != (short) 0) {"), "SET_HEADER opens no transaction for a header that changes nothing");
        assertEquals(3, count(c, "SW_LITTLE_WORK"), "6A93 is the answer to the hash over its own target, to a target over the floor, and to one over four times the best, and to nothing else");
        assertEquals(0, count(h + c, "Util.arrayCopy("), "nothing that lasts is written by SET_HEADER or the checks themselves");
        assertEquals(0, count(h + c, "arrayFill"), "nor filled (the helpers that work out a target write scratch, which is RAM)");
        assertFalse(c.contains("beginTransaction") || c.contains("commitTransaction"), "the checks are outside any transaction");
        assertTrue(w.contains("CARD_NOW_OFFSET") && w.contains("CARD_WINDOW_OFFSET") && w.contains("CARD_BITS_OFFSET") && w.contains("CARD_HEADER_OFFSET"),
            "the clock, the window's anchor, the hardest bits and the last hash are written together");
        assertEquals(4, count(w, "Util.arrayCopy("), "four writes, and no more");
        assertFalse(w.contains("beginTransaction") || w.contains("commitTransaction"), "writeHeader is inside its caller's transaction, and opens none of its own");
        assertTrue(w.contains("if (how == (short) 0) return;"), "and writes nothing for a header that is not later");
        assertTrue(w.indexOf("CARD_NOW_OFFSET") < w.indexOf("CARD_WINDOW_OFFSET"), "the clock first: the window is anchored at the time it has just taken");
        for (String gate : new String[] { "requirePin", "pinVerifiedFlag", "ownerSet", "requireOwnerProof", "requireNotLocked", "cardLocked", "CARD_SET_OFFSET", "loadGrant", "changeGrant", "logEntry", "cardLog", "tapOpen" }) {
            assertFalse((h + c + w).contains(gate), "SET_HEADER looks at no " + gate + ": no key, PIN, owner or record, and it writes no log");
        }
        // every caller of writeHeader runs the checks first and writes inside a transaction: SET_HEADER, REFRESH and an anchored SET_OWNER
        assertEquals(4, count(code, "writeHeader("), "its declaration and three callers");
        assertEquals(4, count(code, "checkHeader("), "its declaration and three callers");
        for (String[] caller : new String[][] { { "private void processRefresh(", "private void processSetHeader(" }, { "private void processSetOwner(", "private void processGetNonce(" } }) {
            String b = body(code, caller[0], caller[1]);
            int ch = b.indexOf("checkHeader("), bg = b.indexOf("JCSystem.beginTransaction()"), wr = b.indexOf("writeHeader("), cm = b.indexOf("JCSystem.commitTransaction()");
            assertTrue(ch > 0 && ch < bg && bg < wr && wr < cm, caller[0] + ": the checks, then the header written inside one transaction");
            assertTrue(b.indexOf("cardRecord[CARD_ROLLS_OFFSET] = (byte) 0;") > wr && b.indexOf("cardRecord[CARD_ROLLS_OFFSET] = (byte) 0;") < cm, caller[0] + ": and the rollover budget full again, in the same transaction");
        }
        // targetOf and timesFour are the card's own arithmetic and write only RAM they are given
        String target = body(code, "private static void targetOf(", "private static void timesFour(");
        assertFalse(target.contains("cardRecord") || target.contains("cardLog"), "targetOf reads the bits it is given and writes the target it is given");
        assertTrue(target.contains("exponent < 1 || exponent > 32") && target.contains("& 0x80) != 0") && target.contains("SW_WRONG_DATA"), "and refuses a size no header carries, and a negative target, with 6A80");
        String four = body(code, "private static void timesFour(", "private void processTellTime(");
        assertTrue(four.contains("(byte) 0xFF"), "timesFour saturates at the greatest number there is and does not wrap");
    }

    @Test
    @DisplayName("Four times a target that cannot be held saturates, and does not wrap: after a header at 2^254 the card takes one at the floor of the tests (2^255), whose four times would have wrapped to nothing")
    void testTheQuarterRuleDoesNotWrap() {
        readyWithoutAHeader(0);
        assertEquals(SW_OK, sw(setHeaderCommand(mine(T0, 0x20400000L, 0))), "2^254");
        assertArrayEquals(le32(0x20400000L), headerBits());
        assertEquals(SW_OK, sw(setHeaderCommand(mine(T0 + 1, 0x207FFFFFL, 0))), "four times 2^254 is past 2^256: it is the greatest number there is, and everything is under it");
        assertEquals(T0 + 1, now());
        assertArrayEquals(le32(0x20400000L), headerBits(), "(and 2^255 is not harder than 2^254)");
        // just under the wrap: a best of 0x1FFFFF x 2^232 has four times of 0x7FFFFC x 2^232, which fits, and a header over that is refused
        simulator = freshCard();
        readyWithoutAHeader(0);
        assertEquals(SW_OK, sw(setHeaderCommand(mine(T0, 0x201FFFFFL, 0))), "a little under 2^253");
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(mine(T0 + 1, 0x207FFFFFL, 0))), "2^255 is over four times that");
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(mine(T0 + 1, 0x207FFFFDL, 0))), "one more than four times");
        assertEquals(SW_OK, sw(setHeaderCommand(mine(T0 + 1, 0x207FFFFCL, 0))), "four times, exactly");
        assertEquals(T0 + 1, now());
    }

    @Test
    @DisplayName("A header whose time is 0 is no later than a card that has seen none: the answer is 0, nothing is kept, and the next header is still the first")
    void testAHeaderOfTimeZeroIsNoLaterThanNothing() {
        readyWithoutAHeader(0);
        ResponseAPDU r = transmit(setHeaderCommand(mine(0, TEST_BITS, 0)));
        assertEquals(SW_OK, r.getSW());
        assertEquals(0, readUint32(r.getData(), 0));
        assertEquals(0, now());
        assertArrayEquals(new byte[4], headerBits(), "no bits are kept for it");
        assertArrayEquals(new byte[32], headerHash(), "nor its hash");
        // had it counted as a header the card had seen, a header 16 times easier would be over four times its difficulty
        ResponseAPDU zeroHard = transmit(setHeaderCommand(mine(0, 0x1F00FFFFL, 0)));
        assertEquals(SW_OK, zeroHard.getSW());
        assertEquals(0, now());
        assertArrayEquals(new byte[4], headerBits(), "a harder header of time 0 is no better a record");
        assertEquals(SW_OK, sw(setHeaderCommand(mine(T0, 0x1F0FFFFFL, 0))), "the first header taken is still held to the floor alone");
        assertEquals(T0, now());
        assertArrayEquals(le32(0x1F0FFFFFL), headerBits());
    }

    @Test
    @DisplayName("GET_CARD's bytes 40..104 are the clock's proof: the hardest difficulty of any header taken (4, as a header carries it), the hash of the last header that moved the clock (32, as Bitcoin shows it) and 29 zeros; zeros until a header is taken")
    void testTheRecordKeepsTheHardestBitsAndTheLastHash() {
        readyWithoutAHeader(0);
        byte[] c = cardRecord();
        assertEquals(109 + MINT.length(), c.length, "the record's length is what it was");
        assertArrayEquals(new byte[38], Arrays.copyOfRange(c, 40, 78), "no header yet: bits, hash, the rolls and the budget are all zeros");
        assertEquals(1, c[78], "the allowance armed by the PIN verified at set-up (2.0, D20)");
        assertArrayEquals(new byte[26], Arrays.copyOfRange(c, 79, 105), "and zeros after");
        byte[] a = mine(T0 + 10, 0x1F0FFFFFL, 0);
        assertEquals(SW_OK, sw(setHeaderCommand(a)));
        c = cardRecord();
        assertArrayEquals(le32(0x1F0FFFFFL), Arrays.copyOfRange(c, 40, 44), "bits as the header carries them, little-endian");
        assertEquals(blockHash(a), toHex(Arrays.copyOfRange(c, 44, 76)), "the hash as Bitcoin shows it, big-endian: the double SHA-256 turned round");
        assertEquals(toHex(reversed(sha256(sha256(a)))), toHex(Arrays.copyOfRange(c, 44, 76)));
        assertArrayEquals(new byte[] { 0, 0, 1 }, Arrays.copyOfRange(c, 76, 79), "the rolls, the budget and the arming (2.0, D20): a header changes none of them");
        assertArrayEquals(new byte[26], Arrays.copyOfRange(c, 79, 105), "and 26 zeros");
        assertEquals(MINT, new String(Arrays.copyOfRange(c, 106, c.length - 3), StandardCharsets.US_ASCII), "the mint is where it was");
        // the hash is of the last header that moved the clock; the bits are of the hardest
        byte[] b = mine(T0 + 20, 0x1F3FFFFCL, 0);
        assertEquals(SW_OK, sw(setHeaderCommand(b)));
        c = cardRecord();
        assertArrayEquals(le32(0x1F0FFFFFL), Arrays.copyOfRange(c, 40, 44));
        assertEquals(blockHash(b), toHex(Arrays.copyOfRange(c, 44, 76)));
        byte[] older = mine(T0 + 5, 0x1F0FFFFFL, 1);
        assertEquals(SW_OK, sw(setHeaderCommand(older)));
        assertEquals(blockHash(b), toHex(headerHash()), "an older header leaves the hash of the later one");
        // GET_INFO's clock is the time the header carries, little-endian at 68
        assertEquals(T0 + 20, now());
        assertEquals(T0 + 20, readUint32(reversed(Arrays.copyOfRange(b, 68, 72)), 0));
    }

    @Test
    @DisplayName("Real blocks, at the real floor: the tip and an older block of the same difficulty are taken; the genesis block, which has its own work and a target far over the floor, is 6A93; the tip with a nonce byte changed is 6A93; 79 or 81 bytes are 6700; a mantissa with its top bit set or an exponent of 0x21 is 6A80; an easier difficulty written over the real one is 6A93; and an older block after the tip changes nothing")
    void testRealHeaders() {
        readyWithoutAHeader(0);
        useTheRealFloor();
        byte[] tip = hexToBytes(TIP), old = hexToBytes(OLD), genesis = hexToBytes(GENESIS);
        // the vectors are what they are said to be, worked out here and not by the card
        assertEquals(80, tip.length); assertEquals(80, old.length); assertEquals(80, genesis.length);
        assertEquals(TIP_HASH, blockHash(tip));
        assertEquals(OLD_HASH, blockHash(old));
        assertEquals("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", blockHash(genesis));
        assertEquals(TIP_TIME, readUint32(reversed(Arrays.copyOfRange(tip, 68, 72)), 0));
        assertEquals(OLD_TIME, readUint32(reversed(Arrays.copyOfRange(old, 68, 72)), 0));
        assertEquals(TIP_BITS, readUint32(reversed(Arrays.copyOfRange(tip, 72, 76)), 0));
        assertEquals(TIP_BITS, readUint32(reversed(Arrays.copyOfRange(old, 72, 76)), 0));
        assertEquals(0x1D00FFFFL, readUint32(reversed(Arrays.copyOfRange(genesis, 72, 76)), 0));
        assertEquals(92_419, TIP_TIME - OLD_TIME);
        for (byte[] h : new byte[][] { tip, old, genesis }) {
            long bits = readUint32(reversed(Arrays.copyOfRange(h, 72, 76)), 0);
            assertTrue(hashOf(h).compareTo(targetOf(bits)) <= 0, "each of them has the work its own bits name");
        }
        assertTrue(targetOf(TIP_BITS).compareTo(targetOf(0x17087BC0L)) < 0, "the tip is harder than the floor, by four");
        assertTrue(targetOf(0x1D00FFFFL).compareTo(targetOf(0x17087BC0L)) > 0, "and the genesis block far easier");
        // the genesis block: its own work, and far under the floor's
        byte[] recordBefore = cardRecord();
        ResponseAPDU g = transmit(setHeaderCommand(genesis));
        assertEquals(SW_LITTLE_WORK, g.getSW(), "the first block of all");
        assertEquals(0, g.getData().length);
        assertArrayEquals(recordBefore, cardRecord());
        // the tip with a nonce byte changed: not the block it was
        for (int at : new int[] { 76, 77, 78, 79 }) {
            byte[] spoiled = tip.clone();
            spoiled[at] ^= 1;
            assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(spoiled)), "nonce byte " + (at - 76) + " changed");
        }
        for (int at : new int[] { 0, 4, 35, 36, 67, 68, 70 }) {
            byte[] spoiled = tip.clone();
            spoiled[at] ^= 0x10;
            assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(spoiled)), "byte " + at + " changed: version, previous hash, merkle root or time, each is part of what was worked on");
        }
        // an easier difficulty written over the tip's own: the work is for the bytes that were hashed
        byte[] easier = tip.clone();
        System.arraycopy(REAL_FLOOR, 0, easier, 72, 4);
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(easier)), "the floor's bits in place of its own");
        // lengths
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_SET_HEADER, 0, 0, Arrays.copyOf(tip, 79))), "79 bytes");
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_SET_HEADER, 0, 0, concat(tip, new byte[1]))), "81 bytes");
        // bits that no header could carry
        byte[] huge = tip.clone(); huge[75] = 0x21;
        assertEquals(SW_WRONG_DATA, sw(setHeaderCommand(huge)), "an exponent of 0x21");
        byte[] zero = tip.clone(); zero[75] = 0x00;
        assertEquals(SW_WRONG_DATA, sw(setHeaderCommand(zero)), "an exponent of 0");
        byte[] negative = tip.clone(); negative[74] |= (byte) 0x80;
        assertEquals(SW_WRONG_DATA, sw(setHeaderCommand(negative)), "a mantissa with its top bit set");
        assertArrayEquals(recordBefore, cardRecord(), "all of those changed nothing");
        assertEquals(0, now());
        // SET_TIME is gone
        assertEquals(SW_INS_NOT_SUPPORTED, sw(new CommandAPDU(CLA, INS_WAS_SET_TIME, 0, 0, concat(u32(TIP_TIME), new byte[] { 2, 0x30, 0 }), 4)), "0x35");
        // the tip, then
        ResponseAPDU taken = transmit(setHeaderCommand(tip));
        assertEquals(SW_OK, taken.getSW());
        assertEquals(TIP_TIME, readUint32(taken.getData(), 0));
        assertEquals(1791614069L, now());
        byte[] c = cardRecord();
        assertEquals("f01e0217", toHex(Arrays.copyOfRange(c, 40, 44)), "its bits, as the header carries them");
        assertEquals("00000000000000000001fa7ca83e1eb90d5a1865d8db9684f3f03ca64ccaec8a", toHex(Arrays.copyOfRange(c, 44, 76)), "and its hash, as Bitcoin shows it");
        // the older block after it: 9000, nothing changes
        byte[] afterTip = cardRecord();
        byte[] infoAfterTip = info();
        ResponseAPDU o = transmit(setHeaderCommand(old));
        assertEquals(SW_OK, o.getSW());
        assertEquals(TIP_TIME, readUint32(o.getData(), 0), "it answers the clock as it is");
        assertArrayEquals(afterTip, cardRecord(), "and changes nothing, not the hash of the last block");
        assertArrayEquals(infoAfterTip, info());
        // the tip again
        assertEquals(SW_OK, sw(setHeaderCommand(tip)));
        assertArrayEquals(afterTip, cardRecord());
    }

    @Test
    @DisplayName("Real blocks and a day: the older block first, then a day's limit and a payment; the tip, 92,419 seconds later, turns the window, which begins at the clock with the next payment")
    void testRealHeadersTurnTheDay() {
        readyWithoutAHeader(0);
        useTheRealFloor();
        assertEquals(SW_OK, sw(setHeaderCommand(hexToBytes(OLD))));
        assertEquals(OLD_TIME, now());
        assertEquals("000000000000000000016d1284d0c5c14f42cdb4f6ee7c596c70d1d70cc5f177", toHex(headerHash()));
        assertEquals(SW_OK, setLimit(100));
        assertEquals(OLD_TIME, windowStart(), "a limit set under a clock begins its window at the clock");
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 100, i + 1)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(100, spentToday());
        assertEquals(SW_OVER_LIMIT, spend(1).getSW(), "the day is full");
        assertEquals(SW_OK, sw(setHeaderCommand(hexToBytes(TIP))));
        assertEquals(TIP_TIME, now());
        assertEquals(OLD_TIME, windowStart(), "the window is turned by a payment, and not by the clock");
        assertEquals(SW_OK, spend(1).getSW(), "92,419 seconds later is a new day");
        assertEquals(TIP_TIME, windowStart(), "begun at the clock");
        assertEquals(100, spentToday(), "with nothing carried over but this payment");
        assertEquals(SW_OVER_LIMIT, spend(2).getSW());
        // the same blocks the other way round: the tip first, and the older block is no clock at all
        simulator = freshCard();
        readyWithoutAHeader(0);
        useTheRealFloor();
        assertEquals(SW_OK, setLimit(100));
        assertEquals(0, windowStart(), "no clock, no window");
        assertEquals(SW_OK, sw(setHeaderCommand(hexToBytes(TIP))));
        assertEquals(TIP_TIME, windowStart(), "the first block anchors the window of a limit that was set before it");
        assertEquals(SW_OK, sw(setHeaderCommand(hexToBytes(OLD))));
        assertEquals(TIP_TIME, now());
        assertEquals(TIP_TIME, windowStart());
    }

    @Test
    @DisplayName("The first day is on trust: a card that has seen no block header loads, sets a day's limit whose window has no start, and spends up to the limit and no more; the first header anchors the window at its time, and the second, a day later, begins a new one")
    void testTheFirstDayIsOnTrust() throws Exception {
        readyWithoutAHeader(0);
        assertEquals(0, now());
        assertEquals(SW_OK, setLimit(500), "a limit with no clock");
        assertEquals(500, limit());
        assertEquals(0, windowStart(), "its window has no start");
        assertEquals(0, spentToday());
        long[] amounts = { 300, 200, 1, 150 };
        for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW(), "a load with no clock");
        assertEquals(0, now(), "none of it asked for the time");
        assertEquals(SW_OK, spend(0).getSW(), "300 of 500");
        assertEquals(300, spentToday());
        assertEquals(0, windowStart(), "a payment under a limit begins no window at a clock of 0: it has none to begin at");
        assertEquals(SW_OK, spend(1).getSW(), "the limit exactly");
        assertEquals(500, spentToday());
        ResponseAPDU over = spend(2);
        assertEquals(SW_OVER_LIMIT, over.getSW(), "past the limit it is refused: 6A8F, and never 6A92");
        assertEquals(0, over.getData().length);
        assertEquals(1, logRefused(), "and written down");
        assertEquals(500, spentToday());
        assertEquals(0, now());
        // however long the card waits and however often it is tapped: with no header the window never ends
        for (int round = 0; round < 3; round++) {
            newTap();
            assertEquals(SW_OVER_LIMIT, spend(2).getSW(), "tap " + round + ": still the first day");
            assertEquals(SW_OVER_LIMIT, spend(3).getSW());
        }
        assertEquals(0, windowStart());
        // the first header anchors the window at its time, and keeps what was spent
        assertEquals(SW_OK, setTime(T0 + 5));
        assertEquals(T0 + 5, now());
        assertEquals(T0 + 5, windowStart(), "the window begins at the block's time");
        assertEquals(500, spentToday(), "and the first day's spending is counted in it");
        assertEquals(SW_OVER_LIMIT, spend(2).getSW(), "still the day it was");
        // a header a second short of a day later is the same day, and one a day later is the next
        assertEquals(SW_OK, setTime(T0 + 5 + DAY - 1));
        assertEquals(SW_OVER_LIMIT, spend(2).getSW(), "86,399 seconds on");
        assertEquals(T0 + 5, windowStart());
        assertEquals(SW_OK, setTime(T0 + 5 + DAY));
        assertEquals(T0 + 5, windowStart(), "(a payment begins the new window, and not the header)");
        assertEquals(SW_OK, spend(2).getSW(), "86,400 seconds on: a new day");
        assertEquals(T0 + 5 + DAY, windowStart(), "begun at the clock");
        assertEquals(1, spentToday(), "with nothing carried over but this piece");
        assertEquals(SW_OK, spend(3).getSW());
        assertEquals(151, spentToday());
    }

    @Test
    @DisplayName("A header anchors only a window that waits for one: a card with no limit gets no window from a header, a window that has begun is not moved by a later header, a limit taken off before the first header leaves nothing to anchor, and a limit set after the first header begins its window at the clock")
    void testTheFirstHeaderAnchorsOnlyAWindowThatWaits() {
        // no limit: a header begins no window
        readyWithoutAHeader(0);
        assertEquals(SW_OK, setTime(T0));
        assertEquals(0, windowStart(), "no limit, no window");
        assertEquals(0, spentToday());
        assertEquals(SW_OK, setLimit(100));
        assertEquals(T0, windowStart(), "a limit set under a clock begins its window there");
        // a window that has a start is not moved by a header: only a payment turns it
        assertEquals(SW_OK, setTime(T0 + 3 * DAY));
        assertEquals(T0, windowStart(), "a later header does not move a window that began");
        assertEquals(SW_OK, setTime(T0 + 4 * DAY));
        assertEquals(T0, windowStart());
        // a limit set with no clock, and the limit changed before the first header: the window still waits for it
        simulator = freshCard();
        readyWithoutAHeader(0);
        assertEquals(SW_OK, setLimit(100));
        assertEquals(SW_OK, setLimit(200));
        assertEquals(0, windowStart());
        assertEquals(SW_OK, setLimit(0));
        assertEquals(SW_OK, setTime(T0 + 9));
        assertEquals(0, windowStart(), "a limit taken off before the header: nothing to anchor");
        // the limit on one payment asks no clock and has no window
        simulator = freshCard();
        readyWithoutAHeader(0);
        assertEquals(SW_OK, setLimits(0, 50));
        assertEquals(SW_OK, setTime(T0));
        assertEquals(0, windowStart());
        assertEquals(50, paymentLimit());
    }

    @Test
    @DisplayName("SET_CARD ignores the 65 bytes where the time key was: a record with a key, with zeros, with 0xFF and with a point that is none is taken alike, and the card keeps its clock, window, counts and hardest bits through it; what GET_CARD gives there is the clock's proof and not what was sent")
    void testSetCardIgnoresTheFormerTimeKeyBytes() throws Exception {
        readyWithLimit(100);
        assertEquals(SW_OK, load(buildProof(KEYSET, 100, 1)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(SW_OK, clearSpent());
        long now = now(), window = windowStart(), spent = spentToday();
        assertEquals(T0, now);
        assertEquals(100, spent);
        byte[] proofBefore = Arrays.copyOfRange(cardRecord(), 40, 105);
        byte[] ff = new byte[65]; Arrays.fill(ff, (byte) 0xFF);
        byte[] four = new byte[65]; four[0] = 0x04;
        byte[] compressed = FORMER_TIME_KEY.pub.clone(); compressed[0] = 0x02;
        byte[] junk = new byte[65]; new java.util.Random(7).nextBytes(junk);
        byte[][] sent = { FORMER_TIME_KEY.pub, new byte[65], ff, four, compressed, junk, new Key().pub };
        for (int i = 0; i < sent.length; i++) {
            byte[] data = recordWithKeyBytes(MINT, REFUND, sent[i]);
            assertEquals(SW_OK, sw(setCardCommand(ownerProof(L_CARD, OWNER, nonceBytes(), data), data)), "bytes " + i + " where the time key went");
            assertEquals(now, now(), "the clock is as it was (a different time key used to clear it)");
            assertEquals(window, windowStart(), "and the window");
            assertEquals(spent, spentToday(), "and what was spent in it");
            assertArrayEquals(new byte[4], Arrays.copyOfRange(cardRecord(), 40, 44), "the ratchet is let go: a new record sets the hardest bits to nothing, so a card its network has left behind takes real headers again");
            assertArrayEquals(Arrays.copyOfRange(proofBefore, 4, 65), Arrays.copyOfRange(cardRecord(), 44, 105), "and the last header's hash is as it was, and not what was sent");
            assertEquals(100, limit());
        }
        // the open form on a card with no owner takes them alike
        simulator = freshCard();
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setTime(T0 + 1));
        for (byte[] s : sent) {
            assertEquals(SW_OK, sw(setCardOpenCommand(recordWithKeyBytes(MINT, REFUND, s))));
            assertEquals(T0 + 1, now());
            assertEquals(blockHash(blockAt(T0 + 1)), toHex(headerHash()));
        }
    }

    @Test
    @DisplayName("Nothing lowers the clock, and a header dated far on freezes it for the work it cost: the card believes a header for its work and not for its date, so a header of ten years on, at the tests' cheap floor, is taken and later honest blocks are older than it; at the floor built in, the network's own, no such header can be made")
    void testAHeaderFromTheFutureIsTakenForItsWork() throws Exception {
        readyWithLimit(100);
        long farFuture = T0 + 3650 * DAY;
        assertEquals(SW_OK, setTime(farFuture));
        assertEquals(farFuture, now());
        assertEquals(SW_OK, load(buildProof(KEYSET, 100, 1)).getSW());
        assertEquals(SW_OK, spend(0).getSW(), "the day's limit");
        assertEquals(farFuture, windowStart(), "the window began at the clock, which is the fault");
        // the card's day is frozen: it is not a day later than the fault, whatever the real time is
        assertEquals(SW_OK, setTime(T0 + DAY + 5), "an honest block, a day on");
        assertEquals(farFuture, now(), "is behind the fault, and ignored");
        assertEquals(SW_OK, load(buildProof(KEYSET, 100, 2)).getSW());
        assertEquals(SW_OVER_LIMIT, spend(1).getSW(), "and the window cannot turn");
        // and nothing lowers it: not an emptying and a record, not a new owner, not a new PIN, not the card leaving the field, not the lock
        assertEquals(SW_OK, setLimit(0));
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(SW_OK, clearSpent());
        byte[] data = recordWithKeyBytes("https://other.example.com", NO_REFUND, FORMER_TIME_KEY.pub);
        assertEquals(SW_OK, sw(setCardCommand(ownerProof(L_CARD, OWNER, nonceBytes(), data), data)), "an empty card, any record");
        assertEquals(farFuture, now());
        assertEquals(SW_OK, sw(setOwnerCommand(ownerProof(L_OWNER, OWNER, nonceBytes(), OTHER_OWNER.pub), OTHER_OWNER)));
        assertEquals(farFuture, now());
        simulator.reset();
        reselect();
        assertEquals(farFuture, now());
        assertEquals(SW_OK, setTime(T0 + 2 * DAY));
        assertEquals(farFuture, now(), "there is no way back: the cost of the work is what keeps a header from the future out");
    }

    @Test
    @DisplayName("SET_TIME is gone: 0x35 answers 6D00 whatever it is sent - a time under a signature of the old form, nothing, any P1 and P2 - and moves nothing")
    void testSetTimeIsGone() throws Exception {
        ready();
        byte[] sig = FORMER_TIME_KEY.sign(concat("CashuCard/time".getBytes(StandardCharsets.US_ASCII), u32(T0 + 10)));
        byte[] old = concat(u32(T0 + 10), new byte[] { (byte) sig.length }, sig);
        assertEquals(SW_INS_NOT_SUPPORTED, sw(new CommandAPDU(CLA, INS_WAS_SET_TIME, 0, 0, old, 4)), "a signed time of the old form");
        assertEquals(SW_INS_NOT_SUPPORTED, sw(new CommandAPDU(CLA, INS_WAS_SET_TIME, 0, 0, 256)), "nothing");
        assertEquals(SW_INS_NOT_SUPPORTED, sw(new CommandAPDU(CLA, INS_WAS_SET_TIME, 1, 1, new byte[80], 4)), "eighty bytes");
        assertEquals(SW_INS_NOT_SUPPORTED, sw(new CommandAPDU(CLA, INS_WAS_SET_TIME, 0, 0, blockAt(T0 + 10), 4)), "a header, to the wrong instruction");
        assertEquals(T0, now(), "and the clock is where it was");
        // and the card does not name 6A92 any more, nor the time key, nor anything that judged a clock told twice
        String code = appletCode();
        for (String gone : new String[] { "processSetTime", "INS_SET_TIME", "LABEL_TIME", "CLOCK_JUMP", "timeTold", "SW_NO_TIME", "SW_NOT_THE_TIME", "timeKey", "CARD_TIMEKEY_OFFSET", "CashuCard/time" }) {
            assertFalse(code.contains(gone), gone + " is gone from the applet's code");
        }
        assertFalse(code.toLowerCase().contains("6a92"), "and nothing names 6A92");
    }

    @Test
    @DisplayName("The clock survives SET_CARD, SET_OWNER, CHANGE_PIN, a reset, and an emptying and set-up again, so an old block offered to a card just set up again is ignored")
    void testNowOnlyMovesForward() {
        readyWithLimit(1000);
        assertEquals(SW_OK, setTime(T0 + 5 * DAY));
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 1)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(SW_OK, clearSpent());
        long before = now();
        long start = windowStart();
        assertEquals(T0 + 5 * DAY, before);
        assertEquals(before, start, "the day began at the clock");
        assertEquals(SW_OK, setCard("https://other.example.com", NO_REFUND), "SET_CARD");
        assertEquals(before, now());
        assertEquals(SW_OK, changePin(NEW_PIN));
        assertEquals(before, now());
        byte[] n = nonceBytes();
        assertEquals(SW_OK, sw(setOwnerCommand(ownerProof(L_OWNER, OWNER, n, OTHER_OWNER.pub), OTHER_OWNER)), "a new owner");
        assertEquals(before, now());
        simulator.reset();
        reselect();
        assertEquals(before, now(), "a reset");
        assertEquals(1000, limit(), "and the limit, and the window it began");
        assertEquals(start, windowStart());
        assertEquals(10, spentToday());
        // set up again, from the owner's side, and the card offered last week's block
        assertEquals(SW_OK, setTime(T0), "an old block: harmless");
        assertEquals(before, now());
        assertEquals(SW_OK, setTime(T0 - 7 * DAY));
        assertEquals(before, now(), "so last week's block offered to a card that has just been set up again is ignored");
    }

    @Test
    @DisplayName("A4: the clock is cleared by nothing: not SET_CARD with the same bytes or others, not a refused SET_CARD, not the PIN form, not a funded card's refusal")
    void testNothingClearsTheClock() {
        ready();
        assertEquals(SW_OK, setTime(T0 + 99));
        assertEquals(SW_OK, ownerSetCard(MINT, REFUND), "the same record");
        assertEquals(T0 + 99, now());
        byte[] other = recordWithKeyBytes(MINT, REFUND, FORMER_TIME_KEY.pub);
        assertEquals(SW_OK, sw(setCardCommand(ownerProof(L_CARD, OWNER, nonceBytes(), other), other)), "a key where the time key went");
        assertEquals(T0 + 99, now());
        assertEquals(SW_OWNER_PROOF, sw(setCardOpenCommand(record(MINT, REFUND))), "the PIN form on an owned card");
        assertEquals(T0 + 99, now());
        byte[] wrong = ownerProof(L_CARD, OWNER, nonceBytes(), record(MINT, REFUND));
        assertEquals(SW_OWNER_PROOF, sw(setCardCommand(wrong, record("https://x.example.com", REFUND))), "a proof for another record");
        assertEquals(T0 + 99, now());
        assertEquals(SW_OK, load(buildProof(KEYSET, 5, 1)).getSW());
        assertEquals(SW_CARD_IN_USE, ownerSetCard(MINT, REFUND), "a funded card");
        assertEquals(T0 + 99, now());
    }

    // =========================================================================
    // The limit on one payment
    // =========================================================================

    @Test
    @DisplayName("GET_INFO with P1 = 1 adds the limit on one payment: 42 bytes (P1 = 2, from 1.19, is those and one that says whether the tag is on), the first thirty as they are without it; a new card has none, and the eight bytes after it, that once held a window and a count, are zero")
    void testInfoWithTheTap() {
        byte[] plain = info();
        byte[] more = infoTap();
        assertEquals(30, plain.length);
        assertEquals(42, more.length);
        byte[] tag = infoTag();
        assertEquals(43, tag.length, "P1 = 2 (1.19) is one byte longer");
        assertArrayEquals(more, Arrays.copyOf(tag, 42), "and its first 42 are the 42 of P1 = 1");
        assertEquals(0, tag[42], "the tag is on in a new card");
        assertArrayEquals(plain, Arrays.copyOf(more, 30), "nothing before it moved");
        assertEquals(0, readUint32(more, 30), "no limit on a payment");
        assertEquals(0, readUint32(more, 34), "no window: the card keeps none");
        assertEquals(0, readUint32(more, 38), "and counts nothing signed for in it");
    }

    @Test
    @DisplayName("A terminal that sends the PIN again, selects again or resets the card gets no payment over the limit without its wait: each gives the payment up and the wait begins again; a limit's worth at a time costs no wait and is remembered by nothing")
    void testTerminalIsWaitedForPastTheLimit() throws Exception {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 100));
        assertEquals(100, paymentLimit());
        assertEquals(0, limit(), "and no limit on the day");
        for (int i = 0; i < 9; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 50, i + 1)).getSW());
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        // 150 in one payment is over the limit: four waits. The PIN presented again, a new SELECT and a reset in the middle of
        // them are no way round: each gives the payment up, and beginning again is the whole wait again
        Runnable[] tricks = {
            () -> assertEquals(SW_OK, verify(TEST_PIN)),
            () -> { reselect(); assertEquals(SW_OK, verify(TEST_PIN)); },
            () -> { simulator.reset(); reselect(); assertEquals(SW_OK, verify(TEST_PIN)); },
        };
        String[] names = { "the PIN again", "a new SELECT", "a reset of the card" };
        for (int t = 0; t < tricks.length; t++) {
            assertEquals(SW_OK, sw(beginCommand(0, 1, 2)));
            ResponseAPDU first = transmit(SIGN_ALL);
            assertTrue(isWait(first), "begun, 150 is over a limit of 100, and the card says so");
            assertNotYet(first, "the first of seven waits: not yet, and not how many are left");
            tricks[t].run();
            assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), names[t] + " gave the payment up");
            assertEquals(450, balance(), "and burned nothing");
        }
        ResponseAPDU r = spendAll(new int[] { 0, 1, 2 }, new byte[0][]);
        assertEquals(SW_OK, r.getSW());
        assertEquals(waitsRule(100, 150, 0), waitsTaken(), "and beginning again, it is signed after the seven waits, as if nothing had come before");
        assertEquals(300, balance());
        // within the limit, a payment at a time, in one tap: each after the first costs the five seconds, however small (6a: one
        // payment a tap at full speed). Pinned as what it is: it is the rate this limit holds a terminal that has the PIN to.
        int taken = 0;
        for (int i = 3; i < 9; i += 2) {
            assertEquals(SW_OK, verify(TEST_PIN));
            assertEquals(SW_OK, spendAll(new int[] { i, i + 1 }, new byte[0][]).getSW());
            assertEquals(waitsRule(100, 100, 0, true), waitsTaken(), "100 is the limit exactly, and a second payment in the tap: the five seconds, as often as it is asked for");
            taken += 100;
        }
        assertEquals(300, taken);
        assertEquals(0, balance());
        assertNothingRemembered("none of it was counted");
        // the owner's proof is what changes it, and a terminal has none
        byte[] terminalProof = new byte[8];
        nonceBytes();
        assertEquals(SW_OWNER_PROOF, sw(setLimitsCommand(terminalProof, 0, 0)));
        assertEquals(SW_OWNER_PROOF, sw(new CommandAPDU(CLA, INS_SET_LIMIT, 0, 0, concat(u32(0), u32(0)))), "nor does the PIN, on a card with an owner");
        assertEquals(100, paymentLimit());
    }

    @Test
    @DisplayName("The limit on one payment: exactly the limit is signed at once, one sat more costs a wait, a piece larger than the limit is waited for and then signed, and a payment leaves nothing against the next")
    void testExactlyThePaymentLimit() throws Exception {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 64));
        long[] amounts = { 128, 64, 1, 1, 64 };
        for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(1).getSW(), "64 is the limit, and is signed");
        assertEquals(0, waitsTaken(), "at once");
        newTap();
        assertEquals(SW_OK, spend(2).getSW(), "and then one sat in a payment of its own, in a tap of its own: the limit was not used up by the first");
        assertEquals(0, waitsTaken());
        newTap();
        ResponseAPDU over = spendAll(new int[] { 4, 3 }, new byte[0][]);
        assertEquals(SW_OK, over.getSW(), "64 and 1 in one payment is not refused");
        assertEquals(0, waitsTaken(), "one sat over a limit of 64 is within the thirty-second the limit allows a price pegged in another money: no wait");
        byte[] large = slot(0);
        newTap();
        ResponseAPDU r = spend(0);
        assertEquals(SW_OK, r.getSW(), "128 is over a limit of 64 on its own, and is not refused");
        assertEquals(waitsRule(64, 128, 0), waitsTaken(), "it is two limits' worth");
        assertTrue(signedFor(r.getData(), large, REFUND), "and it is signed for in the end");
        assertEquals(2, slot(0)[0], "and burned");
        assertEquals(0, balance());
        assertNothingRemembered("the limit counts nothing");
    }

    @Test
    @DisplayName("The two limits side by side: the day refuses in its own name (6A8F) and the limit on one payment never refuses, it makes the payment wait; a waited payment is counted in the day as any other, and a wait does not turn the day")
    void testTheDayAndThePaymentLimit() {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(250, 100));
        assertEquals(250, limit());
        assertEquals(100, paymentLimit());
        for (int i = 0; i < 6; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 50, i + 1)).getSW());
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spendAll(new int[] { 0, 1, 2 }, new byte[0][]).getSW());
        assertEquals(waitsRule(100, 150, 0), waitsTaken(), "150 is over a limit of 100 on a payment, and waits: it is not refused");
        assertEquals(150, spentToday(), "and the whole of it is counted in the day, to the sat");
        newTap();
        assertEquals(SW_OK, spendAll(new int[] { 3, 4 }, new byte[0][]).getSW());
        assertEquals(0, waitsTaken(), "100 is the limit exactly, in a tap of its own");
        assertEquals(250, spentToday());
        assertEquals(SW_OVER_LIMIT, spend(5).getSW(), "the limit on a payment has room; the day has none");
        assertEquals(0, waitsTaken(), "and a payment refused for the day is not waited for");
        assertEquals(SW_OK, setTime(T0 + 20));
        assertEquals(SW_OVER_LIMIT, spend(5).getSW(), "a later time inside the day gives the day no more");
        assertEquals(SW_OK, setTime(T0 + DAY));
        assertEquals(SW_OK, spend(5).getSW(), "a day on, the day's window turns");
        assertEquals(waitsRule(100, 50, 0, true), waitsTaken(), "slowed as the tap's later payment; the day's turn is what this is about");
        assertEquals(50, spentToday());
        assertEquals(0, balance());
        assertNothingRemembered("only the day is counted");
    }

    @Test
    @DisplayName("SET_LIMIT with eight bytes sets both; the day's, with a number that does not change, keeps its window and its count, and the limit on a payment has no window to begin; four bytes are the day's alone and leave the payment limit; neither needs a clock, and the day's, set before any block header, begins a window that has no start")
    void testSettingTheTwoLimits() {
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setCard(MINT, REFUND));
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(SW_OK, setLimits(0, 500), "a limit on one payment asks no clock, and the card has seen no block header");
        assertEquals(500, paymentLimit());
        assertEquals(0, now(), "and sets none");
        assertEquals(SW_OK, setLimits(1000, 500), "the day's asks none either: its window has no start until a header arrives (the first day is on trust)");
        assertEquals(1000, limit());
        assertEquals(0, windowStart());
        assertEquals(500, paymentLimit());
        assertEquals(SW_OK, setLimits(0, 0), "no limits need none");
        assertEquals(0, paymentLimit());
        assertEquals(SW_OK, setTime(T0));
        assertEquals(SW_OK, setLimits(1000, 500));
        assertEquals(1000, limit());
        assertEquals(500, paymentLimit());
        assertEquals(SW_OK, load(buildProof(KEYSET, 100, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 100, 2)).getSW());
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(100, spentToday());
        // the payment limit changed, the day's the same: the day keeps its window and its count, and nothing begins for the payment limit
        assertEquals(SW_OK, setTime(T0 + 5));
        assertEquals(SW_OK, setLimits(1000, 300));
        assertEquals(300, paymentLimit());
        assertNothingRemembered("a limit on a payment has no window to begin at the clock");
        assertEquals(T0, windowStart(), "the day does not begin again");
        assertEquals(100, spentToday());
        // the day's changed, the payment limit's the same
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(200, spentToday());
        assertEquals(SW_OK, setLimits(2000, 300));
        assertEquals(2000, limit());
        assertEquals(0, spentToday(), "the day begins again");
        assertEquals(T0 + 5, windowStart(), "at the clock");
        assertEquals(300, paymentLimit(), "the payment limit is as it was");
        // four bytes: the day's alone, as it always was
        assertEquals(SW_OK, setLimit(700));
        assertEquals(700, limit());
        assertEquals(300, paymentLimit(), "the limit on a payment is left as it is");
        // both removed, for a withdrawal, and put back
        assertEquals(SW_OK, setLimits(0, 0));
        assertEquals(0, limit());
        assertEquals(0, paymentLimit());
        assertEquals(SW_OK, setLimits(700, 300));
        assertEquals(300, paymentLimit());
        assertNothingRemembered("through all of it");
        // a length that is neither
        byte[] six = new byte[6];
        assertEquals(0x6700, sw(new CommandAPDU(CLA, INS_SET_LIMIT_OWNER, 0, 0, ownerData(ownerProof(L_LIMIT, OWNER, nonceBytes(), six), six))));
        // and a new SELECT and a reset leave both
        reselect();
        simulator.reset();
        reselect();
        assertEquals(700, limit());
        assertEquals(300, paymentLimit());
    }

    @Test
    @DisplayName("The limit on one payment asks no clock: it is set on a card that has seen no block header, by the owner and by the PIN, such a card spends and waits as any other, and another record leaves it as it was; the day's limit asks none either (the first day is on trust)")
    void testThePaymentLimitNeedsNoTime() throws Exception {
        // set up as the phone does, and never given a block header; first the PIN's form, on a card with no owner
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setCard(MINT, REFUND));
        assertEquals(0, now());
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SET_LIMIT, 0, 0, concat(u32(0), u32(100)))), "by the PIN: none on the day and 100 on a payment, with no time");
        // a card with no owner can give nobody the grant that GET_INFO wants for it, so it is read from the record itself
        assertEquals(100, paymentLimitInTheRecord());
        assertEquals(0, paymentLimitAsATerminalSeesIt(), "and a terminal under the PIN is told nothing of it");
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SET_LIMIT, 0, 0, concat(u32(50), u32(100)))), "a limit on the day needs no clock, either: its window waits for the first header");
        assertEquals(50, limit());
        assertEquals(0, windowStart());
        assertEquals(SW_OK, sw(setLimitByPinCommand(0)), "(taken off again)");
        assertEquals(SW_OK, sw(setLimitByPinCommand(60)), "in four bytes as well");
        assertEquals(60, limit());
        assertEquals(100, paymentLimitInTheRecord(), "and the limit on a payment is as it was");
        assertEquals(SW_OK, sw(setLimitByPinCommand(0)));
        // and the owner's
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(SW_OK, setLimits(0, 250), "by the owner, with no clock");
        assertEquals(250, paymentLimit());
        assertEquals(SW_OK, setLimits(1000, 250), "the day's as well");
        assertEquals(250, paymentLimit());
        assertEquals(0, now(), "no limit gave the card a clock");
        assertEquals(0, windowStart(), "and none began a window");

        // a card with money and no clock (it has seen no block header, so it spends its first day on trust)
        simulator = freshCard();
        readyWithoutAHeader(0);
        assertEquals(SW_OK, setLimits(0, 100));
        for (int i = 0; i < 6; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 50, i + 1)).getSW());
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(0, now());
        byte[][] named = { slot(0), slot(1), slot(2) };
        ResponseAPDU r = spendAll(new int[] { 0, 1, 2 }, new byte[0][]);
        assertEquals(SW_OK, r.getSW(), "a card that has no clock spends under a limit on one payment");
        assertEquals(waitsRule(100, 150, 0), waitsTaken(), "and waits for 150, as a card that knows the time does");
        assertTrue(signedForAll(r.getData(), named, new byte[0][], REFUND));
        assertEquals(0, now(), "it did not ask for the time");
        assertEquals(0, windowStart(), "and began no window");
        assertEquals(0, spentToday());
        assertNothingRemembered("the payment was counted by nothing");
        // another record has nothing of the payment limit to clear with it: it stays
        assertEquals(SW_CARD_IN_USE, ownerSetCard(MINT, REFUND), "not while it holds money");
        newTap();
        assertEquals(SW_OK, spendAll(new int[] { 3, 4 }, new byte[0][]).getSW());
        assertEquals(0, waitsTaken(), "100 is the limit, in a tap of its own");
        assertEquals(SW_OK, spend(5).getSW());
        assertEquals(SW_OK, ownerSetCard(MINT, REFUND));
        assertEquals(0, now());
        assertEquals(100, paymentLimit(), "the limit stays");
        assertNothingRemembered("a new record had nothing to clear");
        assertRecordRemembersNothing("nor did it leave anything");
        assertEquals(SW_OK, load(buildProof(KEYSET, 50, 7)).getSW(), "and it loads again with no clock: nothing goes on only for want of a header");
    }

    // =========================================================================
    // The wait
    // =========================================================================

    // ---------------------------------------------------------------------------------------------
    // 1.12: the change a payment makes for itself
    // ---------------------------------------------------------------------------------------------

    /** SPEND_ALL_CHANGE: one change output of `amount`. */
    private ResponseAPDU change(long amount) { return transmit(new CommandAPDU(CLA, INS_SPEND_ALL_CHANGE, 0, 0, u32(amount), 33)); }
    /** GET_CHANGE: one page. */
    private byte[] changePage(int page) { return transmit(new CommandAPDU(CLA, INS_GET_CHANGE, page, 0, 256)).getData(); }
    /** The openings the card lists, every page, each 80 bytes: amount (4), keyset (8), date (4), nonce (32), r (32). */
    private List<byte[]> openings() {
        List<byte[]> out = new ArrayList<>();
        for (int page = 0; ; page++) {
            byte[] d = changePage(page);
            int n = d[0] & 0xFF;
            assertEquals(1 + 80 * n, d.length, "a count, then " + n + " openings of 80 bytes");
            for (int i = 0; i < n; i++) out.add(Arrays.copyOfRange(d, 1 + 80 * i, 81 + 80 * i));
            if (n < 3) return out;
        }
    }
    /** NUT-00: the point a secret hashes to, with the even y. */
    static java.math.BigInteger[] hashToCurve(byte[] secret) throws Exception {
        byte[] msgHash = sha256(concat("Secp256k1_HashToCurve_Cashu_".getBytes(StandardCharsets.US_ASCII), secret));
        for (long counter = 0; ; counter++) {
            byte[] x = sha256(concat(msgHash, new byte[] { (byte) counter, (byte)(counter >> 8), (byte)(counter >> 16), (byte)(counter >> 24) }));
            java.math.BigInteger[] pt = liftX(new java.math.BigInteger(1, x));
            if (pt != null) return pt;
        }
    }
    /** The blinded message of a change output, compressed: hash_to_curve(secret) + r*G. */
    static byte[] blindedFor(byte[] secret, byte[] r) throws Exception {
        java.math.BigInteger[] y = hashToCurve(secret);
        java.math.BigInteger[] rg = ecMulTest(new java.math.BigInteger(1, r), SECP_GX, SECP_GY);
        return compressed(ecAddTest(y[0], y[1], rg[0], rg[1]));
    }
    /** The secret of a change output, as the card builds it from its opening: the nonce, the card's key, the date and the refund key. */
    private byte[] changeSecret(byte[] opening, byte[] refund) {
        return secretText(Arrays.copyOfRange(opening, 16, 48), cardKey(), readUint32(opening, 12), refund).getBytes(StandardCharsets.UTF_8);
    }
    /** An output as the message has it, from what the card answered. */
    static byte[] changeOutput(long amount, ResponseAPDU made) { return output(amount, made.getData()); }

    @Test
    @DisplayName("NUT-00's hash to the curve, as these tests work it out: the vector of thirty-two zero bytes")
    void testHashToCurveVector() throws Exception {
        assertEquals("024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725",
            toHex(compressed(hashToCurve(hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")))));
    }

    @Test
    @DisplayName("SPEND_ALL_CHANGE: the card makes a change output for itself: a secret of its own form with a fresh nonce, hashed to the curve as the mint will, blinded with a fresh factor; the blinded message is what it answers and what the signature is over, and the opening it keeps opens exactly that; the day and the log count what leaves the card")
    void testTheCardMakesItsOwnChange() throws Exception {
        readyWithLimit(1000);
        assertEquals(SW_OK, load(buildProof(KEYSET, 100, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 50, 2)).getSW());
        byte[][] named = { slot(0), slot(1) };
        newTap();
        assertEquals(SW_OK, sw(beginCommand(0, 1)));
        byte[] tills = output(90, blinded(1));
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, tills)));
        ResponseAPDU a = change(40);
        assertEquals(SW_OK, a.getSW(), "a change output of 40");
        assertEquals(33, a.getData().length, "the blinded message, compressed");
        assertTrue(a.getData()[0] == 0x02 || a.getData()[0] == 0x03, "a point");
        ResponseAPDU b = change(20);
        assertEquals(SW_OK, b.getSW(), "and one of 20");
        ResponseAPDU signed = signAll();
        assertEquals(SW_OK, signed.getSW());
        assertEquals(64, signed.getData().length);
        assertEquals(0, waitsTaken(), "no limit on a payment: no wait");
        byte[][] outputs = { tills, changeOutput(40, a), changeOutput(20, b) };
        assertTrue(signedForAll(signed.getData(), named, outputs, REFUND), "one signature over the pieces, the terminal's output and the card's two change outputs, in that order");
        assertFalse(signedForAll(signed.getData(), named, new byte[][] { tills }, REFUND), "and not over the terminal's output alone");
        assertEquals(90, spentToday(), "the day is charged what leaves the card: 150 less 60 of change");
        assertArrayEquals(new long[] { T0, 90, 2, 0, 0 }, logTap(0), "and so is the log");
        assertEquals(2, slot(0)[0]); assertEquals(2, slot(1)[0]);
        // the openings, now that the payment is signed for
        List<byte[]> open = openings();
        assertEquals(2, open.size(), "two openings, the payment's");
        long[] amounts = { 40, 20 };
        ResponseAPDU[] made = { a, b };
        for (int i = 0; i < 2; i++) {
            byte[] o = open.get(i);
            assertEquals(amounts[i], readUint32(o, 0), "its amount");
            assertEquals(KEYSET, toHex(Arrays.copyOfRange(o, 4, 12)), "the pieces' keyset");
            assertEquals(readUint32(named[0], 78), readUint32(o, 12), "the pieces' date");
            assertArrayEquals(made[i].getData(), blindedFor(changeSecret(o, REFUND), Arrays.copyOfRange(o, 48, 80)),
                "opening " + i + " opens the blinded message the card answered: the secret in the card's own form, hashed to the curve, plus r*G");
        }
        assertFalse(Arrays.equals(Arrays.copyOfRange(open.get(0), 16, 48), Arrays.copyOfRange(open.get(1), 16, 48)), "two nonces");
        assertFalse(Arrays.equals(Arrays.copyOfRange(open.get(0), 48, 80), Arrays.copyOfRange(open.get(1), 48, 80)), "two blinding factors");
        // they outlive the tap
        newTap();
        assertEquals(2, openings().size(), "the openings are kept while the pieces are not back");
    }

    @Test
    @DisplayName("An opening is let go when its piece is written back (the tap after the payment takes it with no PIN); an opening of a payment that was never signed for is a draft, listed by nothing and let go at the next beginning; eight openings in all, pending or drafted")
    void testOpeningsAreLetGoWhenThePiecesAreBack() throws Exception {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 100, 1)).getSW());
        newTap();
        assertEquals(SW_OK, sw(beginCommand(0)));
        assertEquals(SW_OK, change(30).getSW());
        assertEquals(SW_OK, change(20).getSW());
        assertEquals(SW_OK, signAll().getSW());
        List<byte[]> open = openings();
        assertEquals(2, open.size());
        // the change, back: a piece with the opening's nonce, written in the tap after the payment with no PIN
        reselect();
        byte[] piece = buildProof(KEYSET, 30, 9);
        System.arraycopy(open.get(0), 16, piece, 12, 32);
        assertEquals(SW_OK, load(piece).getSW(), "the change goes on with no PIN, the tap after the payment");
        assertEquals(1, openings().size(), "and its opening is gone");
        assertArrayEquals(open.get(1), openings().get(0), "the other is as it was");
        // the same piece again is on the card already: refused, and nothing else changes
        assertEquals(SW_PIECE_ON_CARD, load(piece).getSW());
        assertEquals(1, openings().size());
        // a payment with change that is never signed for: its openings are drafts, listed by nothing, and let go by the next beginning
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, load(buildProof(KEYSET, 64, 3)).getSW());
        newTap();
        assertEquals(SW_OK, sw(beginCommand(2)));
        for (int k = 0; k < 7; k++) assertEquals(SW_OK, change(1).getSW(), "change output " + (k + 1) + ": seven drafts and one pending fill the eight");
        assertEquals(SW_NO_SPACE, change(1).getSW(), "the ninth has no opening free");
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "and that refusal gave the payment up");
        assertEquals(1, openings().size(), "the drafts are listed by nothing");
        assertEquals(SW_OK, sw(beginCommand(2)));
        for (int k = 0; k < 7; k++) assertEquals(SW_OK, change(1).getSW(), "begun again, the places of the drafts are free again");
        assertEquals(SW_OK, signAll().getSW());
        assertEquals(8, openings().size(), "eight pending now");
        assertEquals(SW_OK, load(buildProof(KEYSET, 64, 4)).getSW());
        newTap();
        assertEquals(SW_OK, sw(beginCommand(3)));
        assertEquals(SW_NO_SPACE, change(1).getSW(), "no change can be made while eight are pending");
    }

    @Test
    @DisplayName("What SPEND_ALL_CHANGE refuses: no payment begun (6985); nothing, or more change than the pieces come to, by one output or by several (6A80), which gives the payment up; the terminal's outputs after the card's change (6985), the same; a wrong length (6700)")
    void testWhatChangeRefuses() throws Exception {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 100, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 50, 2)).getSW());
        newTap();
        assertEquals(SW_CONDITIONS_NOT_SATIS, change(10).getSW(), "no payment begun");
        assertEquals(SW_OK, sw(beginCommand(0, 1)));
        assertEquals(SW_WRONG_DATA, change(0).getSW(), "nothing is no change");
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "and the payment is given up");
        assertEquals(SW_OK, sw(beginCommand(0, 1)));
        assertEquals(SW_WRONG_DATA, change(151).getSW(), "more than the pieces come to");
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL));
        assertEquals(SW_OK, sw(beginCommand(0, 1)));
        assertEquals(SW_OK, change(100).getSW());
        assertEquals(SW_WRONG_DATA, change(51).getSW(), "100 and 51 come to more than 150");
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL));
        assertEquals(SW_OK, sw(beginCommand(0, 1)));
        assertEquals(SW_OK, change(150).getSW(), "all of it as change is allowed: nothing leaves the card");
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, output(1, blinded(1)))), "no output of the terminal's after the card's change");
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL));
        assertEquals(SW_OK, sw(beginCommand(0, 1)));
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_SPEND_ALL_CHANGE, 0, 0, new byte[] { 0, 0, 1 }, 33)), "three bytes are not an amount");
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL));
        assertEquals(150, balance(), "nothing was burned by any of it");
        assertTrue(openings().isEmpty(), "and nothing is pending");
    }

    @Test
    @DisplayName("The limits are held to what leaves the card: a piece larger than the day's limit pays a small price with change, and the limit on a payment waits by the net; a payment within it that makes change waits nothing: that change is coming is the phone's to say")
    void testTheLimitsAreHeldToWhatLeavesTheCard() throws Exception {
        readyWithLimit(100);
        assertEquals(SW_OK, setLimits(100, 100));
        assertEquals(SW_OK, load(buildProof(KEYSET, 150, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 50, 2)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 300, 3)).getSW());
        newTap();
        assertEquals(SW_OVER_LIMIT, spend(0).getSW(), "150 whole is over a day of 100");
        assertEquals(SW_OK, sw(beginCommand(0)));
        assertEquals(SW_OK, change(60).getSW());
        assertEquals(SW_OK, signAll().getSW(), "150 less 60 is 90: within the day");
        assertEquals(0, waitsTaken(), "90 is within the limit on a payment: no wait, change or no change");
        assertEquals(90, spentToday());
        assertEquals(SW_OK, sw(beginCommand(1)));
        assertEquals(SW_OK, change(39).getSW());
        assertEquals(SW_OVER_LIMIT, sw(SIGN_ALL), "50 less 39 is 11, and 90 and 11 are over the day");
        assertEquals(SW_OK, sw(beginCommand(1)));
        assertEquals(SW_OK, change(40).getSW());
        assertEquals(SW_OK, signAll().getSW(), "50 less 40 is 10: the day exactly");
        assertEquals(100, spentToday());
        assertEquals(2, openings().size(), "the change of both payments is pending");
        // the limit on a payment, by the net
        assertEquals(SW_OK, setLimits(0, 100));
        assertEquals(SW_OK, sw(beginCommand(2)));
        assertEquals(SW_OK, change(10).getSW());
        assertEquals(SW_OK, signAll().getSW());
        assertEquals(waitsRule(100, 290, 1), waitsTaken(), "300 less 10 is 290: three limits' worth, less the change's own work");
    }


    @Test
    @DisplayName("One payment a tap at full speed: the second payment signed in a time in the field waits as one over the limit (seven, limit or no limit; its own count where that is more), a payment begun and given up does not count, a new SELECT is the same tap, a reset is a new one, the owner's grant in the tap lifts it, and loading is not a payment")
    void testOnePaymentATapAtFullSpeed() throws Exception {
        ready();
        for (int i = 0; i < 6; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 10, i + 1)).getSW());
        newTap();
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(0, waitsTaken(), "no limit: the first payment of the tap goes at once");
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(WAIT_OVER_SIGNS, waitsTaken(), "and the second waits as one over the limit, with no limit set");
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(2).getSW());
        assertEquals(WAIT_OVER_SIGNS, waitsTaken(), "a new SELECT is the same time in the field");
        newTap();
        assertEquals(SW_OK, sw(beginCommand(3)));
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4)), "a payment begun and given up");
        assertEquals(SW_OK, spend(3).getSW());
        assertEquals(0, waitsTaken(), "is not a payment: the first signed in the tap goes at once");
        // the owner's grant lifts it: a whole card taken off in more than one signature is the owner's phone's doing
        newTap();
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_OK, spend(4).getSW());
        assertEquals(0, waitsTaken());
        assertEquals(SW_OK, spend(5).getSW());
        assertEquals(0, waitsTaken(), "the second payment of a tap with the owner's grant in it is not slowed");
        // with a limit: a second payment within it waits the seven; one over it waits its own count, which is at least that
        simulator = freshCard();
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 100));
        long[] amounts = { 50, 50, 250, 50 };
        for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        newTap();
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(0, waitsTaken());
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(waitsRule(100, 50, 0, true), waitsTaken(), "50 within the limit, the tap's second: seven");
        assertEquals(WAIT_OVER_SIGNS, waitsRule(100, 50, 0, true));
        assertEquals(SW_OK, spend(2).getSW());
        assertEquals(waitsRule(100, 250, 0, true), waitsTaken(), "250 is three limits' worth whether first or second: fourteen");
        assertEquals(WAIT_OVER_SIGNS + WAIT_MORE_SIGNS, waitsRule(100, 250, 0, true));
        // loading is not a payment, and the tap after a payment takes the change with no PIN as before
        assertEquals(SW_OK, load(buildProof(KEYSET, 7, 9)).getSW());
        assertEquals(SW_OK, spend(4).getSW());
        assertEquals(waitsRule(100, 7, 0, true), waitsTaken(), "a load between does not start the tap afresh");
        newTap();
        assertEquals(SW_OK, spend(3).getSW());
        assertEquals(0, waitsTaken(), "a new tap");
    }

    /**
     * A payment of pieces of these amounts, on a card of its own that has a limit on one payment of `limit` (0 is none):
     * how many times the card made it wait. It is signed for in the end, for those pieces and no others, and every one is burned.
     */
    private int payWaits(long limit, long... amounts) throws Exception {
        simulator = freshCard();
        ready();
        if (limit > 0) assertEquals(SW_OK, setLimits(0, limit));
        int[] slots = new int[amounts.length];
        byte[][] named = new byte[amounts.length][];
        for (int i = 0; i < amounts.length; i++) {
            assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
            slots[i] = i;
            named[i] = slot(i);
        }
        newTap();
        ResponseAPDU r = spendAll(slots, new byte[0][]);
        String what = "a payment of " + Arrays.toString(amounts) + " under a limit of " + limit;
        assertEquals(SW_OK, r.getSW(), what + " is never refused");
        assertEquals(64, r.getData().length, what + " ends in a signature");
        assertTrue(signedForAll(r.getData(), named, new byte[0][], REFUND), what + " is signed for those pieces");
        for (int i = 0; i < amounts.length; i++) assertEquals(2, slot(i)[0], "piece " + i + " of " + what + " is burned once it is signed");
        return waitsTaken();
    }

    @Test
    @DisplayName("A payment worth S under a limit L waits nothing within it or within a thirty-second over it; over that, 10 for the first limit's worth and 4 for every further one: S = L waits 0, L + L/32 waits 0, 2L waits 10, 2L + 1 waits 14; one large piece waits as many times as many small ones of the same worth")
    void testAPaymentWaitsByWhatItIsWorth() throws Exception {
        long[][] cases = {
            // the limit, the waits, then the pieces
            { 100, 0, 100 },
            { 100, 0, 60, 40 },
            { 100, 0, 1 },
            { 100, 0, 101 },
            { 100, 0, 100, 1 },
            { 100, 10, 200 },
            { 100, 10, 100, 100 },
            { 100, 10, 150, 50 },
            { 100, 10, 70, 70, 60 },
            { 100, 14, 201 },
            { 100, 14, 100, 100, 1 },
            { 100, 14, 300 },
            { 100, 18, 301 },
            { 100, 42, 1000 },
            { 100, 46, 1001 },
            { 1, 0, 1 },
            { 1, 10, 2 },
            { 1, 14, 3 },
            { 1, 14, 1, 1, 1 },
            { 7, 0, 7 },
            { 7, 10, 8 },
            { 7, 10, 14 },
            { 7, 14, 15 },
            { 255, 0, 255 },
            { 255, 0, 256 },
            { 256, 0, 256 },
            { 256, 0, 257 },
            { 65536, 0, 65536 },
            { 65536, 0, 65537 },
            { 16777216L, 0, 16777217L },
            { 2147483647L, 14, 2147483647L, 2147483647L, 1 },
            { 4294967295L, 0, 4294967295L },
            { 2147483648L, 0, 2147483648L },
            { 2147483648L, 0, 2147483649L },
        };
        for (long[] c : cases) {
            long[] pieces = Arrays.copyOfRange(c, 2, c.length);
            long worth = Arrays.stream(pieces).sum();
            assertEquals((int) c[1], waitsRule(c[0], worth, 0), "the table is the rule, for " + Arrays.toString(pieces) + " under " + c[0]);
            assertEquals((int) c[1], payWaits(c[0], pieces), "waits for pieces " + Arrays.toString(pieces) + " under a limit of " + c[0]);
        }
    }

    @Test
    @DisplayName("The wait is a count: W waits are W two-byte answers, W-1 down to 0, and only after the one that says 0 does SPEND_ALL_SIGN burn the pieces and give the 64-byte signature; one signature for one beginning")
    void testTheWaitCountsDownAndTheSignatureComesLast() throws Exception {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 100));
        long[] amounts = { 100, 100, 1 };    // 201: three limits' worth, which is fourteen waits
        for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        byte[][] named = { slot(0), slot(1), slot(2) };
        newTap();
        ResponseAPDU begun = transmit(beginCommand(0, 1, 2));
        assertEquals(SW_OK, begun.getSW());
        assertEquals(4, begun.getData().length, "the beginning answers what the pieces are worth, and says nothing of the wait");
        assertEquals(201, readUint32(begun.getData(), 0));
        byte[] storage = field("proofStorage").clone();
        for (int left = 13; left >= 0; left--) {
            ResponseAPDU r = transmit(SIGN_ALL);
            assertNotYet(r, "wait " + (14 - left) + " of 14: 00 01 every time, whatever is left");
            assertArrayEquals(storage, field("proofStorage"), "and it burned nothing");
        }
        ResponseAPDU sig = transmit(SIGN_ALL);
        assertEquals(SW_OK, sig.getSW());
        assertEquals(64, sig.getData().length, "after the one that said 0, the signature");
        assertTrue(signedForAll(sig.getData(), named, new byte[0][], REFUND));
        for (int i = 0; i < 3; i++) assertEquals(2, slot(i)[0], "and only then are the pieces burned");
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "one signature for one beginning: another SIGN is not another wait");
        assertEquals(0, balance());
    }

    @Test
    @DisplayName("While a payment waits nothing is burned, counted or written: the slots stay unspent and the card's record and log are as they were; a card lifted away in the wait has lost nothing, and the log has no trace of it")
    void testNothingChangesWhileAPaymentWaits() throws Exception {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(1000, 100));
        long[] amounts = { 100, 100, 50, 25 };    // 275: 8 waits
        for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        byte[][] named = { slot(0), slot(1), slot(2), slot(3) };
        // a tap that has signed for something already, so that there is a log to leave alone
        newTap();
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 9)).getSW());
        assertEquals(SW_OK, spend(4).getSW());
        assertEquals(0, waitsTaken());
        long balance = balance(), today = spentToday(), taps = logTaps(), sats = logSats();
        byte[] logBefore = log();
        assertEquals(275, balance);
        assertEquals(10, today);
        // RAM and EEPROM as they stand, read without a command, which would end the wait
        byte[] storage = field("proofStorage").clone(), record = field("cardRecord").clone();
        byte[] cardLog = field("cardLog").clone(), lastSig = field("lastSig").clone();
        assertEquals(SW_OK, sw(beginCommand(0, 1, 2, 3)));
        for (int left = 7; left >= 0; left--) {
            ResponseAPDU r = transmit(SIGN_ALL);
            assertNotYet(r, "a wait");
            assertArrayEquals(storage, field("proofStorage"), "the slots, with " + left + " waits still to come");
            assertArrayEquals(record, field("cardRecord"), "the record: the day's count, window and clock, with " + left + " still to come");
            assertArrayEquals(cardLog, field("cardLog"), "the log, with " + left + " still to come");
            assertArrayEquals(lastSig, field("lastSig"), "and the last signature the card gave, with " + left + " still to come");
        }
        // every wait done and the signature not yet asked for: the card is lifted away
        simulator.reset();
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "the signature is not there for the asking after the card has gone");
        for (int i = 0; i < 4; i++) assertEquals(1, slot(i)[0], "piece " + i + " is unspent");
        assertEquals(balance, balance());
        assertEquals(today, spentToday(), "the day's count is as it was");
        assertEquals(taps, logTaps());
        assertEquals(sats, logSats());
        assertArrayEquals(logBefore, log(), "a payment lifted away in its wait is not in the log at all");
        // and it can be paid, whole, in a tap of its own
        ResponseAPDU r = spendAll(new int[] { 0, 1, 2, 3 }, new byte[0][]);
        assertEquals(SW_OK, r.getSW());
        assertEquals(waitsRule(100, 275, 0), waitsTaken());
        assertTrue(signedForAll(r.getData(), named, new byte[0][], REFUND));
        assertEquals(285, spentToday(), "now it is counted: 275 more");
        assertEquals(3, logTaps(), "the tap that put the four on, the one that paid 10, and this one");
        assertArrayEquals(new long[] { T0, 275, 4, 0, 2 }, logTap(0), "and written down, with the mark that it was waited for");
        assertArrayEquals(new long[] { T0, 10, 1, 0, 0 }, logTap(1), "beside the tap before it, untouched");
        assertArrayEquals(new long[] { 1, 10 }, logLoaded(1), "which put one piece on");
        assertArrayEquals(new long[] { 4, 275 }, logLoaded(2), "and the tap before that, which put four on, as it was");
    }

    @Test
    @DisplayName("Anything but the next step gives a waiting payment up: another command, a SELECT, the card leaving the field; SPEND_ALL_SIGN then answers 6985, nothing is burned, and beginning again waits the whole wait again")
    void testAnythingElseInTheWaitDropsThePayment() throws Exception {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 100));
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 50, i + 1)).getSW());
        newTap();
        byte[] storage = field("proofStorage").clone();
        CommandAPDU[] others = {
            new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4),
            new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256),
            new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256),
            new CommandAPDU(CLA, INS_GET_PROOF_COUNT, 0, 0, 1),
            new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256),
            new CommandAPDU(CLA, INS_GET_PROOF, 0, 0, 256),
            new CommandAPDU(CLA, INS_GET_CARD, 0, 0, 256),
            new CommandAPDU(CLA, INS_GET_PIECES, 0, 0, 256),
            new CommandAPDU(CLA, INS_GET_LOG, 0, 0, 256),
            new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN),
            new CommandAPDU(CLA, INS_AUTH, 0, 0, new byte[16], 80),
            new CommandAPDU(CLA, INS_GET_NONCE, 0, 0, 16),
            new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64),
            setTimeCommand(T0 + 1),
            tellTimeCommand(T0 + 2),
            new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1),
            new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, new byte[32], 64),
            new CommandAPDU(CLA, 0x7F, 0, 0, 256),
        };
        for (CommandAPDU c : others) {
            String what = "INS " + Integer.toHexString(c.getINS() & 0xFF);
            assertEquals(SW_OK, sw(beginCommand(0, 1, 2)), what);
            ResponseAPDU first = transmit(SIGN_ALL);
            assertTrue(isWait(first), "begun, 150 is over a limit of 100, and the card says so");
            assertNotYet(first, "the first of four waits");
            transmit(c);
            assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "the payment is given up by " + what);
            assertArrayEquals(storage, field("proofStorage"), "and " + what + " burned nothing");
        }
        // a SELECT, with the PIN presented again after it
        assertEquals(SW_OK, sw(beginCommand(0, 1, 2)));
        assertNotYet(transmit(SIGN_ALL), "a wait");
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "a new SELECT");
        // the card leaving the field
        assertEquals(SW_OK, sw(beginCommand(0, 1, 2)));
        assertNotYet(transmit(SIGN_ALL), "a wait");
        simulator.reset();
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "the card leaving the field");
        // even when every wait is done and nothing is left but the signature
        assertEquals(SW_OK, sw(beginCommand(0, 1, 2)));
        for (int i = 1; i <= 7; i++) assertNotYet(transmit(SIGN_ALL), "wait " + i + " of 7");
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4)));
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "even with the last wait done: the signature is not given");
        assertArrayEquals(storage, field("proofStorage"), "and nothing was burned by any of it");
        // a beginning again is the whole wait again, however far the one before had got: seven more answers before the signature
        assertEquals(SW_OK, sw(beginCommand(0, 1, 2)));
        assertNotYet(transmit(SIGN_ALL), "wait 1");
        assertNotYet(transmit(SIGN_ALL), "wait 2");
        assertEquals(SW_OK, sw(beginCommand(0, 1, 2)));
        // and the payment, given up and begun again, is paid whole and once
        ResponseAPDU r = signAll();
        assertEquals(SW_OK, r.getSW());
        assertEquals(64, r.getData().length);
        assertEquals(waitsRule(100, 150, 0), waitsTaken(), "begun again, it waits all seven again, and not the five that were left");
        assertEquals(0, balance());
    }

    @Test
    @DisplayName("One payment a tap at full speed: payments of the limit, one after another in one tap, wait nothing for the first and the five seconds for each after it, whatever its size, and a new SELECT is not a new tap; across resets each is the first of its tap again; a waited payment leaves nothing against the next beyond that")
    void testNothingIsRememberedBetweenPayments() {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 100));
        long[] amounts = { 100, 100, 100, 100, 200, 100, 200, 200, 100, 100 };
        for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        newTap();
        for (int i = 0; i < 4; i++) {
            assertEquals(SW_OK, spend(i).getSW());
            assertEquals(i == 0 ? 0 : waitsRule(100, 100, 0, true), waitsTaken(), "payment " + (i + 1) + " of a limit's worth in one tap: the first at once, each after it the five seconds");
        }
        assertNothingRemembered("four payments of a limit's worth");
        assertEquals(SW_OK, spend(4).getSW());
        assertEquals(waitsRule(100, 200, 0, true), waitsTaken(), "200 is two limits' worth: the same five seconds, since one over is one over");
        assertEquals(SW_OK, spend(5).getSW());
        assertEquals(waitsRule(100, 100, 0, true), waitsTaken(), "and the payment after it, within the limit, is slowed as the tap's later payment, not for the one before");
        assertEquals(SW_OK, spend(6).getSW());
        assertEquals(waitsRule(100, 200, 0, true), waitsTaken());
        assertEquals(SW_OK, spend(7).getSW());
        assertEquals(waitsRule(100, 200, 0, true), waitsTaken(), "two payments of 200 wait the same, and not more for the second: nothing came with the first");
        // another SELECT is the same tap; a reset is a new one, and so is a later time in a new one
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(8).getSW());
        assertEquals(waitsRule(100, 100, 0, true), waitsTaken(), "a new SELECT is not a new tap: still slowed");
        newTap();
        assertEquals(SW_OK, setTime(T0 + 3600));
        assertEquals(SW_OK, spend(9).getSW());
        assertEquals(0, waitsTaken(), "a new tap, an hour on: the first of its tap");
        assertEquals(0, balance());
        assertNothingRemembered("through all of it");
    }

    @Test
    @DisplayName("The wait is the same whatever the card's clock says, and with no block header ever seen: 250 under a limit of 100 waits the same at any clock, and the clock is not moved by it")
    void testTheWaitIsTheSameWhateverTheClockSays() throws Exception {
        long[] clocks = { T0, T0 + 1, T0 + DAY, T0 + 400 * DAY, 4294967295L, 0 };    // 0: the card has seen no block header
        for (long clock : clocks) {
            simulator = freshCard();
            if (clock == 0) readyWithoutAHeader(0); else ready();
            assertEquals(SW_OK, setLimits(0, 100));
            if (clock != 0) assertEquals(SW_OK, setTime(clock));
            long[] amounts = { 100, 100, 50 };
            for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
            byte[][] named = { slot(0), slot(1), slot(2) };
            newTap();
            long clockBefore = now();
            assertEquals(clock == 0 ? 0 : clock, clockBefore);
            ResponseAPDU r = spendAll(new int[] { 0, 1, 2 }, new byte[0][]);
            assertEquals(SW_OK, r.getSW(), "at clock " + clock);
            assertEquals(waitsRule(100, 250, 0), waitsTaken(), "at clock " + clock);
            assertTrue(signedForAll(r.getData(), named, new byte[0][], REFUND), "at clock " + clock);
            assertEquals(clockBefore, now(), "the wait did not move the clock, at " + clock);
            assertNothingRemembered("at clock " + clock);
        }
    }

    @Test
    @DisplayName("A limit of 0 is no limit on a payment: no wait for any size, a sum that wraps included, with or without a limit on the day")
    void testNoLimitMeansNoWait() throws Exception {
        assertEquals(0, payWaits(0, 1));
        assertEquals(0, payWaits(0, 1_000_000));
        assertEquals(0, payWaits(0, 4294967295L));
        assertEquals(0, payWaits(0, 4294967295L, 5), "a sum that wraps is past any limit that there is, but with none there is nothing to be past");
        long[] many = new long[32];
        Arrays.fill(many, 1_000_000L);
        assertEquals(0, payWaits(0, many), "thirty-two pieces at once");
        // a limit on the day alone is not a limit on a payment
        simulator = freshCard();
        readyWithLimit(1000);
        assertEquals(SW_OK, load(buildProof(KEYSET, 900, 1)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(0, waitsTaken(), "900 under a day of 1000 and no limit on a payment");
        assertEquals(900, spentToday());
        assertEquals(0, paymentLimit());
    }

    @Test
    @DisplayName("The day is still checked first, at the beginning: a payment over the day is refused 6A8F whole, written down, with no wait, with a clock or without one (the first day is on trust); only a payment within the day is waited for")
    void testTheDayIsCheckedFirstAndIsNotWaitedFor() throws Exception {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(250, 100));
        long[] amounts = { 300, 200, 120, 120 };
        for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        newTap();
        assertEquals(SW_OVER_LIMIT, spend(0).getSW(), "300 is over the day and over the limit on a payment: refused as the day's, and not made to wait");
        assertEquals(0, waitsTaken(), "not one wait before the refusal");
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "refused, the payment is gone: there is no wait to answer");
        assertEquals(1, logRefused(), "and it is written down");
        assertEquals(1, slot(0)[0], "nothing burned");
        assertEquals(SW_OK, spendAll(new int[] { 1 }, new byte[0][]).getSW());
        assertEquals(waitsRule(100, 200, 0), waitsTaken(), "200 is within the day and over the limit on a payment: waited for, not refused");
        assertEquals(200, spentToday());
        assertEquals(SW_OVER_LIMIT, spendAll(new int[] { 2, 3 }, new byte[0][]).getSW(), "240 would take the day to 440: refused, however little it would wait");
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL));
        assertEquals(2, logRefused());
        assertEquals(0, logTampers());
        assertEquals(SW_OVER_LIMIT, spendAll(new int[] { 2, 3 }, new byte[0][]).getSW());
        assertEquals(3, logRefused());
        assertEquals(1, logTampers(), "the third inside ten seconds of the clock marks the tap: runs and marks come from the day's limit");
        assertArrayEquals(new long[] { T0, 200, 1, 3, 3 }, logTap(0), "refused three times, and marked 01 for that and 02 for the waited payment in the same tap");
        // and with no clock, the day is held just the same, and first: on trust, up to the limit
        simulator = freshCard();
        readyWithoutAHeader(0);
        assertEquals(SW_OK, setLimits(250, 100));
        for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        newTap();
        assertEquals(SW_OVER_LIMIT, spend(0).getSW(), "300 is over the day, though the card has no clock: refused whole, and never 6A92");
        assertEquals(0, waitsTaken(), "not one wait before the refusal");
        assertEquals(1, logRefused(), "and written down");
        assertEquals(1, slot(0)[0], "nothing burned");
        assertEquals(SW_OK, spendAll(new int[] { 1 }, new byte[0][]).getSW());
        assertEquals(waitsRule(100, 200, 0), waitsTaken(), "200 is within the day and over the limit on a payment: waited for");
        assertEquals(200, spentToday());
        assertEquals(0, now());
        assertEquals(0, windowStart());
        assertEquals(SW_OVER_LIMIT, spendAll(new int[] { 2, 3 }, new byte[0][]).getSW(), "240 would take the day to 440");
        assertEquals(2, logRefused());
    }

    @Test
    @DisplayName("The owner takes the wait off with SET_LIMIT to (day, 0): a large payment goes through with no wait, with the day's limit set or not, and the day's count is kept")
    void testTheOwnerTakesTheWaitOff() {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 100));
        for (int i = 0; i < 4; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 1000, i + 1)).getSW());
        newTap();
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(waitsRule(100, 1000, 0), waitsTaken(), "1000 under a limit of 100: ten limits' worth");
        assertEquals(SW_OK, setLimits(0, 0));
        assertEquals(0, paymentLimit());
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(0, waitsTaken(), "the same payment, with the limit taken off, goes at once");
        // with a limit on the day
        assertEquals(SW_OK, setLimits(5000, 100));
        assertEquals(SW_OK, spend(2).getSW());
        assertEquals(waitsRule(100, 1000, 0), waitsTaken());
        assertEquals(1000, spentToday());
        assertEquals(SW_OK, setLimits(5000, 0));
        assertEquals(5000, limit());
        assertEquals(1000, spentToday(), "the day's number did not change, so the day's count is kept");
        assertEquals(SW_OK, spend(3).getSW());
        assertEquals(0, waitsTaken(), "the day's limit stays, and the payment goes at once");
        assertEquals(2000, spentToday());
        assertEquals(0, balance());
    }

    @Test
    @DisplayName("The log: a tap with a payment that was waited for has the flag 02, and one without does not; the flag is of the tap, joins the tamper mark, and a payment given up in its wait leaves none")
    void testTheLogSaysAPaymentWaited() {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 100));
        long[] amounts = { 100, 150, 100, 100, 300 };
        for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        newTap();
        assertEquals(SW_OK, setTime(T0 + 5));
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(0, waitsTaken());
        assertArrayEquals(new long[] { T0 + 5, 100, 1, 0, 0 }, logTap(0), "a payment within the limit: no flag");
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(waitsRule(100, 150, 0), waitsTaken());
        assertArrayEquals(new long[] { T0 + 5, 250, 2, 0, 2 }, logTap(0), "one that was waited for: the flag 02");
        assertEquals(SW_OK, spend(2).getSW());
        assertEquals(waitsRule(100, 100, 0, true), waitsTaken(), "the tap's third payment: slowed as a second is");
        assertArrayEquals(new long[] { T0 + 5, 350, 3, 0, 2 }, logTap(0), "and a payment after it keeps the flag on the tap");
        // the next tap, with a payment that is not waited for
        newTap();
        assertEquals(SW_OK, setTime(T0 + 60));
        assertEquals(SW_OK, spend(3).getSW());
        assertEquals(0, waitsTaken());
        assertArrayEquals(new long[] { T0 + 60, 100, 1, 0, 0 }, logTap(0), "no flag");
        assertArrayEquals(new long[] { T0 + 5, 350, 3, 0, 2 }, logTap(1), "and the tap before keeps its own");
        assertEquals(0, logRefused(), "nothing is refused for the limit on a payment");
        assertEquals(0, logTampers());
        // a payment that begins to wait and is given up
        newTap();
        assertEquals(SW_OK, setTime(T0 + 90));
        assertEquals(SW_OK, sw(beginCommand(4)));
        assertNotYet(transmit(SIGN_ALL), "the first of eight waits");
        newTap();
        assertEquals(3, logTaps(), "a payment given up in its wait is not a tap in the log: the tap that put the pieces on and two that paid");
        assertArrayEquals(new long[] { T0 + 60, 100, 1, 0, 0 }, logTap(0));
        assertEquals(450, logSats(), "450 signed for in all, and not the 300 that was begun and given up");
    }

    @Test
    @DisplayName("GET_INFO: byte 1 is 9 and byte 6 is FF, and bytes 34..41 asked for with P1 = 1 are zero, as is the record behind them, however the limit on a payment has been used; nothing ever answers 6A95")
    void testTheCardRemembersNothingOfThePaymentLimit() throws Exception {
        readyWithLimit(0);
        byte[] more = infoTap();
        assertEquals(2, more[0]);
        assertEquals(1, more[1], "version 2.1");
        assertEquals((byte) 0xFF, more[6], "capabilities FF: the limit on one payment is waited for, not refused, the 1.6 forms are there, so are 128 places with the short listing, a payment burned outside its transaction, and the PIN taken sealed");
        assertEquals(SW_OK, setLimits(1000, 100));
        assertEquals(100, paymentLimit());
        assertNothingRemembered("a limit set");
        assertRecordRemembersNothing("a limit set");
        long[] amounts = { 60, 100, 150, 250, 700 };
        for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        newTap();
        int[] waits = { 0, waitsRule(100, 100, 0, true), waitsRule(100, 150, 0, true), waitsRule(100, 250, 0, true) };
        for (int i = 0; i < 4; i++) {
            assertEquals(SW_OK, spend(i).getSW());
            assertEquals(waits[i], waitsTaken(), "payment " + i);
            assertNothingRemembered("after payment " + i);
            assertRecordRemembersNothing("after payment " + i);
        }
        assertEquals(560, spentToday());
        assertEquals(SW_OVER_LIMIT, spend(4).getSW(), "700 more is over the day");
        assertNothingRemembered("after a refusal");
        assertRecordRemembersNothing("after a refusal");
        // a payment given up in its wait, a reset, and a day on
        assertEquals(SW_OK, setTime(T0 + DAY));
        assertEquals(SW_OK, sw(beginCommand(4)));
        assertNotYet(transmit(SIGN_ALL), "700 under 100: seven limits' worth, 30 waits, and 00 01 is all the first says");
        assertNothingRemembered("after a payment given up");
        simulator.reset();
        reselect();
        assertNothingRemembered("after a reset");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(4).getSW());
        assertEquals(waitsRule(100, 700, 0), waitsTaken());
        assertNothingRemembered("after a day on, and a payment");
        assertRecordRemembersNothing("after a day on, and a payment");
        assertEquals(100, paymentLimit());
    }

    @Test
    @DisplayName("A payment is counted for 255 limits' worth at most: it never waits more than 1022 times, however large, and every wait says only 00 01")
    void testTheWaitHasAMost() throws Exception {
        assertEquals(1022, WAITS_MOST, "the most a payment waits is pinned: ten for the first limit's worth over, and four for each of the 253 after it");
        assertEquals(WAITS_MOST, CashuApplet.WAIT_SIGNS_MOST, "and it is the applet's own most, the wait of a sum that wraps");
        assertEquals(waitsRule(1, 254, 0), payWaits(1, 254), "254 limits' worth");
        assertEquals(WAITS_MOST, payWaits(1, 255), "255 is the most");
        assertEquals(WAITS_MOST, payWaits(1, 256), "256 would be one more, and is not counted");
        assertEquals(WAITS_MOST, payWaits(1, 257), "256 would be one more, and is not counted");
        assertEquals(WAITS_MOST, payWaits(1, 1_000_000), "nor is a million");
        assertEquals(WAITS_MOST, payWaits(4294967295L, 4294967295L, 5), "a sum that wraps is past any limit, the largest included, and waits the most");
        // and the first of the 1022 says no more than the first of four: 00 01
        simulator = freshCard();
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 1));
        assertEquals(SW_OK, load(buildProof(KEYSET, 300, 1)).getSW());
        newTap();
        assertEquals(SW_OK, sw(beginCommand(0)));
        ResponseAPDU first = transmit(SIGN_ALL);
        assertEquals(SW_OK, first.getSW());
        assertArrayEquals(NOT_YET, first.getData(), "not yet: 1021 still to come is not said");
        assertEquals(1, slot(0)[0], "and nothing burned");
    }

    @Test
    @DisplayName("A payment that waited is signed over its pieces and its outputs as any other, whether the outputs come before the waits or among them; the signature can be asked for again; a payment given up leaves the last signature as it was")
    void testAWaitedPaymentIsSignedOverItsOutputs() throws Exception {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(0, 100));
        for (int i = 0; i < 9; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 100, i + 1)).getSW());
        byte[][] before = new byte[9][];
        for (int i = 0; i < 9; i++) before[i] = slot(i);
        newTap();
        // the outputs first, then the waits
        byte[][] outputs = { output(200, blinded(1)), output(100, blinded(2)) };
        ResponseAPDU a = spendAll(new int[] { 2, 0, 1 }, outputs);
        assertEquals(SW_OK, a.getSW());
        assertEquals(waitsRule(100, readUint32(before[2], 9) + readUint32(before[0], 9) + readUint32(before[1], 9), 0), waitsTaken());
        assertTrue(signedForAll(a.getData(), new byte[][] { before[2], before[0], before[1] }, outputs, REFUND), "one signature over the pieces and the outputs, the waits having changed neither");
        assertFalse(signedForAll(a.getData(), new byte[][] { before[2], before[0], before[1] }, new byte[][] { outputs[0], output(100, blinded(9)) }, REFUND), "those outputs, and not others");
        ResponseAPDU again = transmit(new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64));
        assertEquals(SW_OK, again.getSW());
        assertArrayEquals(a.getData(), again.getData(), "asked for again, it is the signature and not a wait");
        // the outputs among the waits: OUTPUTS is a next step, as SIGN is, and does not give the payment up
        byte[][] later = { output(300, blinded(3)) };
        int w2 = waitsRule(100, readUint32(before[3], 9) + readUint32(before[4], 9) + readUint32(before[5], 9), 0);
        assertEquals(SW_OK, sw(beginCommand(3, 4, 5)));
        assertNotYet(transmit(SIGN_ALL), "the first of " + w2 + " waits");
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, later[0])));
        for (int left = w2 - 2; left >= 0; left--) {
            ResponseAPDU r = transmit(SIGN_ALL);
            assertNotYet(r, "still waiting");
        }
        ResponseAPDU b = transmit(SIGN_ALL);
        assertEquals(SW_OK, b.getSW());
        assertEquals(64, b.getData().length);
        assertTrue(signedForAll(b.getData(), new byte[][] { before[3], before[4], before[5] }, later, REFUND), "over the outputs that came in the middle of the wait");
        // a payment given up in its wait leaves the last signature as it was
        assertEquals(SW_OK, sw(beginCommand(6, 7, 8)));
        assertNotYet(transmit(SIGN_ALL), "the first of eight waits");
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4)));
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL));
        ResponseAPDU last = transmit(new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64));
        assertArrayEquals(b.getData(), last.getData(), "still the last signature that was given");
        assertEquals(300, balance(), "and the pieces of the payment given up are on the card");
    }

    // =========================================================================
    // One signature for a payment
    // =========================================================================

    /** A blinded message as a swap would carry it: 33 bytes, a compressed point's shape. The card does not look inside. */
    private static byte[] blinded(int seed) {
        byte[] b = new byte[33];
        b[0] = (byte)(seed % 2 == 0 ? 0x02 : 0x03);
        for (int i = 1; i < 33; i++) b[i] = (byte)(seed * 7 + i);
        return b;
    }

    @Test
    @DisplayName("One signature for a payment of many pieces: over each piece's secret and C in the order named, then each output's amount and blinded message; every piece named is burned, and no other")
    void testOneSignatureForManyPieces() throws Exception {
        ready();
        long[] amounts = { 64, 32, 16, 8, 4, 2, 1 };
        for (int i = 0; i < amounts.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, amounts[i], i + 1)).getSW());
        byte[][] before = new byte[amounts.length][];
        for (int i = 0; i < amounts.length; i++) before[i] = slot(i);
        byte[][] outputs = { output(64, blinded(1)), output(16, blinded(2)), output(4, blinded(3)), output(1, blinded(4)),
                             output(1024, blinded(5)), output(2, blinded(6)), output(4294967295L, blinded(7)) };
        newTap();
        ResponseAPDU begun = transmit(beginCommand(4, 0, 2, 6));
        assertEquals(SW_OK, begun.getSW());
        assertEquals(4 + 64 + 16 + 1, readUint32(begun.getData(), 0), "the beginning answers what the pieces are worth");
        // seven outputs: six in one command and the seventh in another
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, concat(Arrays.copyOfRange(outputs, 0, 6)))));
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, outputs[6])));
        ResponseAPDU r = transmit(SIGN_ALL);
        assertEquals(SW_OK, r.getSW());
        assertEquals(64, r.getData().length);
        byte[][] named = { before[4], before[0], before[2], before[6] };
        assertTrue(signedForAll(r.getData(), named, outputs, REFUND), "one BIP-340 signature over the whole message");
        assertFalse(signedForAll(r.getData(), new byte[][] { before[0], before[2], before[4], before[6] }, outputs, REFUND), "the order named, and not another");
        assertFalse(signedForAll(r.getData(), named, Arrays.copyOfRange(outputs, 0, 6), REFUND), "every output, and not fewer");
        byte[][] elsewhere = outputs.clone();
        elsewhere[0] = output(64, blinded(9));
        assertFalse(signedForAll(r.getData(), named, elsewhere, REFUND), "those outputs, and not others: the signature says where the money goes");
        assertFalse(signedForAll(r.getData(), new byte[][] { before[4], before[0], before[2], before[6], before[1] }, outputs, REFUND), "and no piece that was not named");
        for (int i = 0; i < amounts.length; i++) {
            assertEquals(i == 0 || i == 2 || i == 4 || i == 6 ? 2 : 1, slot(i)[0], "place " + i);
        }
        assertEquals(32 + 8 + 2, balance());
        assertArrayEquals(new long[] { T0, 85, 4, 0, 0 }, logTap(0), "one tap in the log: what was signed for, and four pieces");
    }

    @Test
    @DisplayName("The card builds the pieces' half of the message itself: a terminal that names one small piece gets a signature for that piece, whatever it sends beside it")
    void testThePiecesAreTheCardsOwn() throws Exception {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 1, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 100000, 2)).getSW());
        byte[] small = slot(0), large = slot(1);
        byte[][] outputs = { output(100000, blinded(1)) };
        // the terminal burns the 1 and wants a signature good for the 100,000
        byte[] wanted = sha256(allMessage(cardKey(), REFUND, new byte[][] { large }, outputs).getBytes(StandardCharsets.UTF_8));
        assertEquals(SW_OK, transmit(beginCommand(0)).getSW());
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, outputs[0])));
        ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_SPEND_ALL_SIGN, 0, 0, wanted, 64));
        assertEquals(SW_OK, r.getSW());
        assertTrue(signedForAll(r.getData(), new byte[][] { small }, outputs, REFUND), "it signed for the piece it burned");
        assertFalse(signedForAll(r.getData(), new byte[][] { large }, outputs, REFUND), "and not for the one it did not");
        assertFalse(signedForAll(r.getData(), new byte[][] { small, large }, outputs, REFUND));
        assertEquals(1, slot(1)[0], "which is still on the card");
        assertEquals(100000, balance());
        /* An output cannot stand in for a piece: its amount is hashed as decimal digits and its blinded message as hex,
         * so nothing a terminal sends as outputs can spell a secret. The same bytes sent as the outputs of a payment of
         * the small piece sign for a message that is not a payment of the large one. */
        assertEquals(SW_OK, load(buildProof(KEYSET, 1, 3)).getSW());
        byte[] secretBytes = secretText(Arrays.copyOfRange(large, 13, 45), cardKey(), 0, REFUND).getBytes(StandardCharsets.UTF_8);
        assertEquals(SW_OK, transmit(beginCommand(2)).getSW());
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, Arrays.copyOf(secretBytes, 37))));
        ResponseAPDU crafted = signAll();
        assertEquals(SW_OK, crafted.getSW());
        assertFalse(signedForAll(crafted.getData(), new byte[][] { large }, new byte[0][], REFUND));
        assertEquals(1, slot(1)[0]);
    }

    @Test
    @DisplayName("A payment is one beginning, its outputs and one signature, with nothing between: anything else gives it up, and nothing is burned")
    void testAPaymentIsOneBeginning() throws Exception {
        ready();
        for (int i = 0; i < 4; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 10, i + 1)).getSW());
        assertEquals(0x6985, sw(SIGN_ALL), "no signature with no payment begun");
        assertEquals(0x6985, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, output(1, blinded(1)))), "nor outputs");
        // another command between the beginning and the signature
        CommandAPDU[] between = { new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256), new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN),
                                  new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4), setTimeCommand(T0 + 1), tellTimeCommand(T0 + 2) };
        for (CommandAPDU c : between) {
            assertEquals(SW_OK, transmit(beginCommand(0, 1)).getSW());
            assertEquals(SW_OK, sw(c));
            assertEquals(0x6985, sw(SIGN_ALL), "given up by INS " + Integer.toHexString(c.getINS()));
            assertEquals(40, balance());
        }
        // a new SELECT gives it up too
        assertEquals(SW_OK, transmit(beginCommand(0, 1)).getSW());
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(0x6985, sw(SIGN_ALL));
        // outputs of a length that is not outputs give it up
        assertEquals(SW_OK, transmit(beginCommand(0, 1)).getSW());
        assertEquals(0x6700, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, new byte[36])));
        assertEquals(0x6985, sw(SIGN_ALL));
        assertEquals(40, balance(), "and nothing has been burned by any of it");
        // a second beginning replaces the first
        byte[] two = slot(2);
        assertEquals(SW_OK, transmit(beginCommand(0, 1)).getSW());
        assertEquals(SW_OK, transmit(beginCommand(2)).getSW());
        ResponseAPDU r = transmit(SIGN_ALL);
        assertEquals(SW_OK, r.getSW());
        assertTrue(signedFor(r.getData(), two, REFUND), "the last beginning is the payment");
        assertEquals(30, balance());
        // and one signature for one beginning
        assertEquals(0x6985, sw(SIGN_ALL), "a second signature needs a second beginning");
        assertEquals(30, balance());
    }

    @Test
    @DisplayName("What a payment may name: each place once, holding an unspent piece, all of one date, no more than thirty-two; a refusal burns nothing")
    void testWhatAPaymentMayName() {
        ready();
        for (int i = 0; i < 35; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 1, i + 1, i == 33 ? 1900000000L : 0)).getSW());
        assertEquals(SW_OK, spend(5).getSW());
        assertEquals(0x6700, sw(new CommandAPDU(CLA, INS_SPEND_ALL_BEGIN, 0, 0, 4)), "none");
        assertEquals(0x6A80, sw(beginCommand(0, 1, 0)), "a place named twice");
        assertEquals(0x6985, sw(beginCommand(0, 5)), "a spent one");
        assertEquals(SW_SLOT_EMPTY, sw(beginCommand(0, 40)), "an empty one");
        assertEquals(SW_SLOT_OUT_OF_RANGE, sw(beginCommand(0, 128)), "one that is not a place: 64 is one now");
        assertEquals(0x6A80, sw(beginCommand(0, 33)), "pieces of two dates: their lock conditions differ, and a mint takes no one signature for them");
        // thirty-three places, one of them the dated one: refused for the date, as two places would be
        int[] many = new int[33];
        for (int i = 0; i < 33; i++) many[i] = i < 5 ? i : i + 1;
        assertEquals(0x6A80, sw(beginCommand(many)), "thirty-three places, the last of another date");
        // more than every place the card has is too many, however few of them are good
        byte[] hundred29 = new byte[129];
        for (int i = 0; i < 129; i++) hundred29[i] = (byte) (i % 35);
        assertEquals(SW_TOO_MANY, sw(new CommandAPDU(CLA, INS_SPEND_ALL_BEGIN, 0, 0, hundred29, 4)), "129 places");
        assertEquals(34, balance(), "none of which burned anything");
        assertEquals(0x6985, sw(SIGN_ALL), "or left a payment begun");
        // thirty-three places of one date is a payment now: places 0 to 4, 6 to 32 and 34
        int[] thirtyThree = new int[33];
        for (int i = 0; i < 32; i++) thirtyThree[i] = i < 5 ? i : i + 1;
        thirtyThree[32] = 34;
        ResponseAPDU r = spendAll(thirtyThree, new byte[0][]);
        assertEquals(SW_OK, r.getSW());
        assertEquals(64, r.getData().length);
        assertEquals(1, balance(), "thirty-three burned at once, and the dated piece is left");
        assertEquals(33 + 1, logTap(0)[2], "and the log has them, with the one before");
    }

    @Test
    @DisplayName("The last signature is kept, for a terminal whose answer was lost on the air: asked for again it is the same 64 bytes, with the PIN, until the next payment; and it is good for nothing but that payment")
    void testTheLastSignatureAgain() throws Exception {
        ready();
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 8, i + 1)).getSW());
        CommandAPDU again = new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64);
        assertEquals(SW_SLOT_EMPTY, sw(again), "a card that has never signed has none");
        byte[] a = slot(0), b = slot(1);
        byte[][] outputs = { output(16, blinded(3)) };
        ResponseAPDU first = spendAll(new int[] { 0, 1 }, outputs);
        assertEquals(SW_OK, first.getSW());
        assertArrayEquals(first.getData(), transmit(again).getData(), "the same signature, asked for again in the same tap");
        // the card taken away as its answer was on the air: the pieces are burned, and the next tap can still have it
        simulator.reset();
        reselect();
        assertEquals(SW_SECURITY_NOT_SATIS, sw(again), "with the PIN, as a spend");
        assertEquals(SW_OK, verify(TEST_PIN));
        ResponseAPDU later = transmit(again);
        assertEquals(SW_OK, later.getSW());
        assertArrayEquals(first.getData(), later.getData(), "and in the next");
        assertTrue(signedForAll(later.getData(), new byte[][] { a, b }, outputs, REFUND), "good for the payment it was made for");
        assertEquals(8, balance(), "and it burns nothing more");
        assertEquals(1, logTaps(), "nor is it a tap in the log");
        // the next payment's replaces it
        byte[] c = slot(2);
        ResponseAPDU next = spend(2);
        assertEquals(SW_OK, next.getSW());
        assertArrayEquals(next.getData(), transmit(again).getData());
        assertTrue(signedFor(next.getData(), c, REFUND));
        assertFalse(Arrays.equals(first.getData(), next.getData()));
    }

    @Test
    @DisplayName("The limits are held to what a payment's pieces are worth together, at the beginning: over the day it is refused whole, written down once, and nothing is burned; over the limit on one payment it is waited for by the sum, and not piece by piece")
    void testTheLimitsCountThePayment() {
        readyWithLimit(0);
        assertEquals(SW_OK, setLimits(250, 100));
        for (int i = 0; i < 8; i++) assertEquals(SW_OK, load(buildProof(KEYSET, new long[] { 60, 60, 40, 30, 30, 30, 30, 30 }[i], i + 1)).getSW());
        newTap();
        assertEquals(SW_OK, spendAll(new int[] { 0, 1 }, new byte[0][]).getSW(), "60 and 60 are over a limit of 100 on a payment, though neither is alone: not refused");
        assertEquals(waitsRule(100, 120, 0), waitsTaken(), "the sum is what is waited for");
        assertEquals(120, spentToday());
        newTap();
        assertEquals(SW_OK, spendAll(new int[] { 2, 3 }, new byte[0][]).getSW());
        assertEquals(0, waitsTaken(), "40 and 30 are within it, in a tap of their own, and the waited payment before left nothing against this one");
        assertEquals(190, spentToday());
        assertEquals(0, logRefused(), "nothing has been refused");
        assertEquals(SW_OVER_LIMIT, spendAll(new int[] { 4, 5, 6 }, new byte[0][]).getSW(), "90 more would be 280, over a day of 250: refused whole, as over the day");
        assertEquals(1, logRefused(), "one refusal for the one payment");
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "refused, the payment is gone: there is nothing to wait for");
        assertEquals(SW_OK, spendAll(new int[] { 4, 5 }, new byte[0][]).getSW(), "60 more is the day's limit exactly");
        assertEquals(waitsRule(100, 60, 0, true), waitsTaken(), "the tap's second payment: slowed, within the limit or not");
        assertEquals(250, spentToday());
        assertEquals(60, balance());
        assertEquals(SW_OVER_LIMIT, spendAll(new int[] { 6, 7 }, new byte[0][]).getSW(), "and 60 more is over the day");
        assertEquals(2, logRefused());
        assertNothingRemembered("only the day is counted");
    }

    // =========================================================================
    // The card's own log
    // =========================================================================

    @Test
    @DisplayName("The log: a new card's is empty; a tap is one time in the field, however often the applet is selected in it; each has when, how much and how many pieces; the counts add up")
    void testTheLogIsTheCardsOwn() {
        assertArrayEquals(new byte[16], log(), "a new card: four counts of nothing, and no taps");
        ready();
        for (int i = 0; i < 4; i++) assertEquals(SW_OK, load(buildProof(KEYSET, new long[] { 100, 50, 25, 7 }[i], i + 1)).getSW());
        assertEquals(1, logTaps(), "loading is written down: a tap in which anything was put on is a tap in the log");
        assertEquals(0, logSats(), "though nothing was signed for");
        assertArrayEquals(new long[] { T0, 0, 0, 0, 0 }, logTap(0), "the clock, and nothing signed for, refused or marked");
        assertArrayEquals(new long[] { 4, 182 }, logLoaded(0), "four pieces and 182 sats put on");
        newTap();
        assertEquals(SW_OK, setTime(T0 + 5));
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(2, logTaps());
        assertEquals(150, logSats());
        assertArrayEquals(new long[] { T0 + 5, 150, 2, 0, 2 }, logTap(0), "one tap: the clock, 150 sats, two pieces, nothing refused, flagged for the second payment's wait");
        assertArrayEquals(new long[] { 0, 0 }, logLoaded(0), "nothing put on in it");
        assertArrayEquals(new long[] { 4, 182 }, logLoaded(1), "and the tap before it is as it was");
        // the applet selected again and the PIN again, in the same time in the field: the same tap
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(2).getSW());
        assertEquals(2, logTaps(), "a new SELECT is not a new tap");
        assertArrayEquals(new long[] { T0 + 5, 175, 3, 0, 2 }, logTap(0), "the flag of the second payment's wait stays on the tap");
        // taken away and brought back: the next tap
        newTap();
        assertEquals(SW_OK, setTime(T0 + 60));
        assertEquals(2, logTaps(), "a tap in which nothing is signed for, refused or put on is not written down");
        assertEquals(SW_OK, spend(3).getSW());
        assertEquals(3, logTaps());
        assertEquals(182, logSats());
        assertEquals(3, logHeld());
        assertArrayEquals(new long[] { T0 + 60, 7, 1, 0, 0 }, logTap(0), "newest first");
        assertArrayEquals(new long[] { T0 + 5, 175, 3, 0, 2 }, logTap(1), "the tap before, with its later payments' wait flagged");
        assertArrayEquals(new long[] { T0, 0, 0, 0, 0 }, logTap(2), "and the tap that put the pieces on, the oldest");
        assertEquals(0, logRefused());
        assertEquals(0, logTampers());
    }

    @Test
    @DisplayName("The log is for whoever the card is open to: the PIN verified in this tap, or the owner's grant; and nothing a terminal or the owner can send clears it")
    void testTheLogIsKept() {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 64, 1)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        byte[] before = log();
        simulator.reset();
        reselect();
        assertEquals(SW_SECURITY_NOT_SATIS, logAnswer().getSW(), "not to a reader with no PIN");
        assertEquals(SW_OK, allowLoad());
        assertArrayEquals(before, log(), "to the owner's phone, with its proof and no PIN");
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertArrayEquals(before, log(), "and to the PIN");
        // everything that can be sent: none of it is the log's to obey
        assertEquals(SW_OK, clearSpent());
        assertEquals(SW_OK, setLimits(0, 0));
        assertEquals(SW_OK, setLimits(500, 100));
        assertEquals(SW_OK, changePin(NEW_PIN));
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, ownerSetCard(MINT, REFUND));
        assertEquals(0x6D00, sw(new CommandAPDU(CLA, 0x1B, 0, 0, 256)), "there is no command beside it to write one with (0x1A, which was unassigned, is GET_DLEQ since 1.20, a read: the byte after it is the one tried)");
        transmit(new CommandAPDU(CLA, INS_GET_LOG, 1, 1, new byte[117], 256));
        assertArrayEquals(before, log(), "cleared slots, new limits, a new PIN, a new record, bytes sent with the command: the log is as it was");
    }

    @Test
    @DisplayName("A spend over the day's limit is written down before it is refused; the third inside ten seconds of the clock marks the tap and counts once; three visits, one refusal each, mark nothing; the limit on a payment refuses, and writes, nothing")
    void testRefusalsAreWrittenDown() {
        readyWithLimit(100);
        for (int i = 0; i < 8; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 100, i + 1)).getSW());
        newTap();
        assertEquals(SW_OK, spend(0).getSW(), "the day's limit exactly");
        assertEquals(SW_OVER_LIMIT, spend(1).getSW());
        assertEquals(1, logRefused());
        assertArrayEquals(new long[] { T0, 100, 1, 1, 0 }, logTap(0), "one refusal: written down, not marked");
        assertEquals(SW_OVER_LIMIT, spend(1).getSW());
        assertEquals(0, logTampers(), "nor two");
        assertEquals(SW_OVER_LIMIT, spend(1).getSW());
        assertEquals(1, logTampers(), "the third inside ten seconds of the clock: a terminal trying the limit");
        assertArrayEquals(new long[] { T0, 100, 1, 3, 1 }, logTap(0), "and the tap is marked");
        assertEquals(SW_OVER_LIMIT, spend(2).getSW());
        assertEquals(1, logTampers(), "a fourth and a fifth are the same run, counted once");
        assertEquals(4, logRefused());
        assertEquals(700, balance(), "and nothing was burned by any of them");
        // the card cut out of the field and put back, inside the same ten seconds: the run goes on, in a tap of its own
        newTap();
        assertEquals(SW_OK, setTime(T0 + 9));
        assertEquals(SW_OVER_LIMIT, spend(1).getSW());
        assertEquals(3, logTaps(), "the tap that put the pieces on, the one that paid and was refused, and this one");
        assertArrayEquals(new long[] { T0 + 9, 0, 0, 1, 1 }, logTap(0), "a tap of refusals alone is written down too, and marked: the run reached three before it");
        assertEquals(1, logTampers());
        // ten seconds on from the run's first refusal: a refusal begins a new run, and is not marked
        newTap();
        assertEquals(SW_OK, setTime(T0 + 20));
        assertEquals(SW_OVER_LIMIT, spend(2).getSW());
        assertArrayEquals(new long[] { T0 + 20, 0, 0, 1, 0 }, logTap(0), "one refusal in a later tap is one, and is not marked");
        assertEquals(1, logTampers());
        // a terminal that does not know of the limit, refused once at each of three visits a minute apart: no run
        for (int visit = 1; visit <= 3; visit++) {
            newTap();
            assertEquals(SW_OK, setTime(T0 + 20 + 60 * visit));
            assertEquals(SW_OVER_LIMIT, spend(7).getSW());
            assertArrayEquals(new long[] { T0 + 20 + 60 * visit, 0, 0, 1, 0 }, logTap(0), "visit " + visit + ": one refusal, no mark");
        }
        assertEquals(1, logTampers(), "three refusals a minute apart are not a run");
        assertEquals(9, logRefused());
        // the limit on one payment refuses nothing, and so writes no refusal: it is waited for
        newTap();
        assertEquals(SW_OK, setTime(T0 + 400));
        assertEquals(SW_OK, setLimits(500, 100));
        assertEquals(SW_OK, load(buildProof(KEYSET, 600, 20)).getSW());
        long refusedBefore = logRefused();
        assertEquals(SW_OVER_LIMIT, spend(8).getSW(), "600 is over a day of 500");
        assertEquals(refusedBefore + 1, logRefused(), "a spend over the day is a refusal in the log as well");
        assertEquals(SW_OK, setLimits(100000, 100));
        assertEquals(SW_OK, spend(8).getSW(), "600 is over a limit of 100 on a payment, and under a day of 100000: it waits, and goes");
        assertEquals(waitsRule(100, 600, 0), waitsTaken(), "six limits' worth");
        assertEquals(refusedBefore + 1, logRefused(), "and that is no refusal");
        assertEquals(1, logTampers(), "and no run");
        assertArrayEquals(new long[] { T0 + 400, 600, 1, 1, 2 }, logTap(0), "one refusal, the waited payment marked 02, and no mark of a run");
    }

    @Test
    @DisplayName("The log keeps the last eight taps, newest first, and the counts keep all of them")
    void testTheLogKeepsEight() {
        ready();
        long total = 0;
        for (int i = 0; i < 11; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 10 + i, i + 1)).getSW());
        // the tap that put the eleven pieces on is the first of the taps in the log
        assertEquals(1, logTaps());
        for (int i = 0; i < 11; i++) {
            newTap();
            assertEquals(SW_OK, setTime(T0 + 100 * (i + 1)));
            assertEquals(SW_OK, spend(i).getSW());
            total += 10 + i;
            assertEquals(i + 2, logTaps());
            assertEquals(Math.min(i + 2, 8), logHeld());
            assertEquals(total, logSats());
            if (i == 0) assertArrayEquals(new long[] { 11, 165 }, logLoaded(1), "the tap before it, which put on eleven pieces worth 165");
        }
        for (int k = 0; k < 8; k++) {
            assertArrayEquals(new long[] { T0 + 100 * (11 - k), 10 + (10 - k), 1, 0, 0 }, logTap(k), "tap " + k + " back");
            assertArrayEquals(new long[] { 0, 0 }, logLoaded(k), "tap " + k + " back put nothing on");
        }
        assertEquals(8 * 20 + 16, log().length, "sixteen bytes of counts and eight entries of twenty: 176 at most");
    }

    // =========================================================================
    // The day
    // =========================================================================

    @Test
    @DisplayName("SET_LIMIT begins a window at the card's clock with nothing spent (a window with no start, before any block header has been taken); it needs no time, for a limit or for none; a limit survives a new SELECT, a reset, VERIFY_PIN")
    void testSetLimitBeginsAWindow() {
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setCard(MINT, REFUND));
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(SW_OK, setLimit(500), "no block header seen: the limit is set, and its window has no start");
        assertEquals(500, limit());
        assertEquals(0, windowStart());
        assertEquals(0, spentToday());
        assertEquals(SW_OK, setLimit(0), "no limit needs none");
        assertEquals(0, limit());
        assertEquals(SW_OK, setTime(T0));
        assertEquals(SW_OK, setLimit(500));
        assertEquals(500, limit());
        assertEquals(T0, windowStart());
        assertEquals(0, spentToday());
        assertEquals(SW_OK, setTime(T0 + 3600));
        assertEquals(SW_OK, setLimit(600), "set again: a new window, from the clock");
        assertEquals(T0 + 3600, windowStart());
        assertEquals(SW_OK, setLimit(0), "removed");
        assertEquals(0, limit());
        assertEquals(SW_OK, setLimit(4294967295L), "and any amount");
        assertEquals(4294967295L, limit());
        for (int i = 0; i < 4; i++) assertEquals(SW_OK, verify(TEST_PIN));
        reselect();
        simulator.reset();
        reselect();
        assertEquals(4294967295L, limit(), "a new SELECT and a reset leave it");
        assertEquals(T0 + 3600, windowStart());
    }

    @Test
    @DisplayName("The day: a terminal that sends the PIN between every spend takes one day's limit, however it is repeated, and a second only after a later block")
    void testTerminalTakesOneDay() {
        readyWithLimit(100);
        for (int i = 0; i < 4; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 100, i + 1)).getSW());
        reselect();
        int taken = 0;
        for (int i = 0; i < 4; i++) {
            assertEquals(SW_OK, verify(TEST_PIN));
            if (spend(i).getSW() == SW_OK) taken += 100;
        }
        assertEquals(100, taken, "one piece of four, with the PIN presented four times");
        assertEquals(300, balance());
        assertEquals(100, spentToday());
        // everything else the PIN opens
        byte[] terminalProof = new byte[8];
        nonceBytes();
        assertEquals(SW_OWNER_PROOF, sw(setLimitCommand(terminalProof, 0)));
        assertEquals(SW_OWNER_PROOF, sw(changePinCommand(terminalProof, NEW_PIN)));
        assertEquals(SW_OWNER_PROOF, sw(lockCommand(terminalProof)));
        assertEquals(SW_OWNER_PROOF, sw(setLimitByPinCommand(0)));
        assertEquals(SW_OWNER_PROOF, sw(setLimitByPinCommand(4294967295L)));
        // and a new tap, a power cycle, the same time again, and the PIN again take nothing more
        for (int round = 0; round < 3; round++) {
            if (round == 1) simulator.reset();
            reselect();
            assertEquals(SW_OK, verify(TEST_PIN));
            assertEquals(SW_OK, setTime(T0 + 60 * round), "a minute on, and another");
            for (int i = 0; i < 4; i++) {
                assertEquals(SW_OK, verify(TEST_PIN));
                if (slot(i)[0] == 1) assertEquals(SW_OVER_LIMIT, spend(i).getSW());
            }
        }
        assertEquals(300, balance());
        assertEquals(100, spentToday());
        // a later block, a day on: a second
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setTime(T0 + DAY));
        int second = 0;
        for (int i = 0; i < 4; i++) {
            assertEquals(SW_OK, verify(TEST_PIN));
            if (slot(i)[0] == 1 && spend(i).getSW() == SW_OK) second += 100;
        }
        assertEquals(100, second, "a second, and no more, after a later block");
        assertEquals(200, balance());
        assertEquals(T0 + DAY, windowStart());
    }

    @Test
    @DisplayName("The window turns at 86,400 seconds from its start and not at 86,399")
    void testTheWindowTurnsAtADay() {
        readyWithLimit(100);
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 100, i + 1)).getSW());
        assertEquals(SW_OK, spend(0).getSW(), "the first, at the set-up clock");
        assertEquals(T0, windowStart());
        assertEquals(SW_OK, setTime(T0 + 86_399));
        assertEquals(SW_OVER_LIMIT, spend(1).getSW(), "86,399 seconds on: the same day");
        assertEquals(T0, windowStart(), "and the refusal wrote nothing");
        assertEquals(100, spentToday());
        assertEquals(SW_OK, setTime(T0 + 86_400));
        assertEquals(SW_OK, spend(1).getSW(), "86,400 seconds on: the next");
        assertEquals(T0 + 86_400, windowStart(), "begun at the clock");
        assertEquals(100, spentToday(), "with nothing carried over but this piece");
        assertEquals(SW_OVER_LIMIT, spend(2).getSW());
        // the next day is a day from the clock, and not from the old window
        assertEquals(SW_OK, setTime(T0 + 86_400 + 86_399));
        assertEquals(SW_OVER_LIMIT, spend(2).getSW());
        assertEquals(SW_OK, setTime(T0 + 2 * 86_400));
        assertEquals(SW_OK, spend(2).getSW());
        assertEquals(T0 + 2 * 86_400, windowStart());
    }

    @Test
    @DisplayName("A new SELECT, a reset, CLEAR_SPENT and a load leave today as it is, and spent today carries across taps")
    void testTodayIsNotReset() {
        readyWithLimit(300);
        for (int i = 0; i < 5; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 100, i + 1)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(100, spentToday());
        reselect();
        assertEquals(100, spentToday(), "a new SELECT");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, clearSpent());
        assertEquals(100, spentToday(), "CLEAR_SPENT");
        assertEquals(SW_OK, load(buildProof(KEYSET, 100, 9)).getSW());
        assertEquals(100, spentToday(), "a load, and change loaded is not a refill");
        simulator.reset();
        reselect();
        assertEquals(100, spentToday(), "a reset");
        assertEquals(T0, windowStart());
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(1).getSW());
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(2).getSW(), "the third of a limit of 300, in three taps");
        assertEquals(300, spentToday());
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OVER_LIMIT, spend(3).getSW(), "and the fourth is over");
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(300, spentToday(), "a wrong PIN and a right one change nothing");
    }

    @Test
    @DisplayName("Exactly the limit goes and one sat more does not, with nothing burned, nothing signed and nothing written")
    void testExactlyTheLimit() {
        readyWithLimit(1000);
        assertEquals(SW_OK, load(buildProof(KEYSET, 600, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 400, 2)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 1, 3)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 1001, 4)).getSW());
        byte[] before = slot(3);
        ResponseAPDU r = spend(3);
        assertEquals(SW_OVER_LIMIT, r.getSW(), "a piece over the whole limit by itself");
        assertEquals(0, r.getData().length, "no signature came with it");
        assertArrayEquals(before, slot(3), "the slot is as it was");
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(600, spentToday(), "counted by the whole piece, to the sat");
        assertEquals(SW_OK, spend(1).getSW(), "exactly what is left is within it");
        assertEquals(1000, spentToday());
        byte[] oneMore = slot(2);
        byte[] infoBefore = info();
        r = spend(2);
        assertEquals(SW_OVER_LIMIT, r.getSW(), "and one sat more is not");
        assertEquals(0, r.getData().length);
        assertArrayEquals(oneMore, slot(2), "not burned");
        assertArrayEquals(infoBefore, info(), "and nothing about the day was written");
        assertEquals(1002, balance());
    }

    @Test
    @DisplayName("A sum that wraps is over any limit, and the largest limit counts up without wrapping")
    void testASumThatWrapsIsOver() {
        readyWithLimit(4294967295L);
        assertEquals(SW_OK, load(buildProof(KEYSET, 4294967294L, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 5, 2)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 1, 3)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(4294967294L, spentToday());
        assertEquals(SW_OVER_LIMIT, spend(1).getSW(), "4294967294 and 5 wrap to 3, which is under any limit, and must not be");
        assertEquals(4294967294L, spentToday());
        assertEquals(1, slot(1)[0], "nothing burned");
        assertEquals(SW_OK, spend(2).getSW(), "one more is exactly the largest number there is");
        assertEquals(4294967295L, spentToday());
    }

    @Test
    @DisplayName("A limit of 0 is no limit: it spends with no time, counts nothing, and never refuses for the day")
    void testNoLimitSpendsWithNoTime() throws Exception {
        readyWithoutAHeader(0);
        assertEquals(0, limit());
        for (int i = 0; i < 4; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 1_000_000, i + 1)).getSW());
        // a card that has seen no block header, and has no clock
        assertEquals(0, now());
        assertEquals(SW_OK, spend(0).getSW(), "spends with no time");
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(SW_OK, spend(2).getSW(), "and as much as it has");
        assertEquals(0, spentToday(), "nothing is counted when there is no limit");
        assertEquals(0, windowStart());
        assertEquals(0, now(), "and it does not ask for the time");
    }

    @Test
    @DisplayName("A limit with no block header seen is held on trust: a payment within it goes and counts toward it, one past it is 6A8F (never 6A92) and burns nothing, and a header lets the window begin, with what was spent kept")
    void testALimitWithNoTimeIsHeldOnTrust() throws Exception {
        readyWithoutAHeader(1000);
        assertEquals(0, now());
        assertEquals(0, windowStart(), "a limit set before any header: its window has no start");
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 995, 2)).getSW());
        assertEquals(SW_OK, spend(0).getSW(), "10 of 1000, on trust");
        assertEquals(10, spentToday());
        byte[] before = slot(1);
        ResponseAPDU r = spend(1);
        assertEquals(SW_OVER_LIMIT, r.getSW(), "995 more is past it");
        assertEquals(0, r.getData().length);
        assertArrayEquals(before, slot(1), "nothing burned");
        assertEquals(10, spentToday(), "and nothing counted");
        assertEquals(1, logRefused(), "but the refusal is written down");
        assertEquals(0, now(), "none of it asked for a clock");
        assertEquals(SW_OK, setTime(T0 + 1));
        assertEquals(T0 + 1, windowStart(), "the first header anchors the window at its time");
        assertEquals(10, spentToday(), "keeping what the first day spent");
        assertEquals(SW_OVER_LIMIT, spend(1).getSW(), "and it is still that day");
        assertEquals(SW_OK, setTime(T0 + 1 + DAY));
        assertEquals(SW_OK, spend(1).getSW(), "a day on, it goes");
        assertEquals(995, spentToday());
    }

    @Test
    @DisplayName("Refusals before any block header are each their own run: the card's clock cannot tell the visits apart, and a false mark is worse than none, so three at three visits mark nothing; with a clock, three a minute apart are three runs of one, and the first header ends the card's run of zeros")
    void testRefusalsBeforeAnyHeaderAreNoRun() throws Exception {
        readyWithoutAHeader(10);
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 2)).getSW());
        assertEquals(SW_OK, spend(0).getSW(), "the day's limit, on trust");
        for (int visit = 0; visit < 3; visit++) {
            newTap();
            assertEquals(SW_OVER_LIMIT, spend(1).getSW(), "visit " + visit);
            assertEquals(1, logTap(0)[3], "one refusal in the tap");
        }
        assertEquals(0, logTampers(), "three refusals at three visits are no run: with no clock the card cannot tell the visits apart, and marks nothing");
        assertEquals(0, logTap(0)[4] & 1, "and no visit is marked");
        // with a clock the same three visits, a minute apart, are no run
        simulator = freshCard();
        readyWithLimit(10);
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 2)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        for (int visit = 0; visit < 3; visit++) {
            newTap();
            assertEquals(SW_OK, setTime(T0 + 60 * (visit + 1)));
            assertEquals(SW_OVER_LIMIT, spend(1).getSW());
        }
        assertEquals(0, logTampers(), "a minute apart, they are three runs of one");
        // and the first header ends the card's run of zeros
        simulator = freshCard();
        readyWithoutAHeader(10);
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 2)).getSW());
        assertEquals(SW_OK, spend(0).getSW());
        newTap();
        assertEquals(SW_OVER_LIMIT, spend(1).getSW());
        assertEquals(SW_OVER_LIMIT, spend(1).getSW());
        assertEquals(SW_OK, setTime(T0));
        assertEquals(SW_OVER_LIMIT, spend(1).getSW());
        assertEquals(0, logTampers(), "the third is a run of one, begun at the clock once there is one");
    }

    @Test
    @DisplayName("At the edge of a window a terminal can take up to two days' limit in a short span: pinned as what it is")
    void testTwoDaysAtABoundary() {
        readyWithLimit(100);
        for (int i = 0; i < 4; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 100, i + 1)).getSW());
        assertEquals(SW_OK, setTime(T0 + 86_399));
        assertEquals(SW_OK, spend(0).getSW(), "the last second of the first day");
        assertEquals(SW_OVER_LIMIT, spend(1).getSW());
        assertEquals(SW_OK, setTime(T0 + 86_400));
        assertEquals(SW_OK, spend(1).getSW(), "and the first second of the next");
        assertEquals(SW_OVER_LIMIT, spend(2).getSW());
        assertEquals(200, 400 - balance(), "two days' limit, a second apart");
    }

    @Test
    @DisplayName("A window whose end would pass what four bytes hold never ends: begun within a day of 2^32 (the year 2106), the day is the last the card has, whatever block headers follow")
    void testAWindowThatWouldEndPastTheTopNeverEnds() {
        readyWithLimit(100);
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 100, i + 1)).getSW());
        assertEquals(SW_OK, setTime(4294967295L - 1000));
        assertEquals(SW_OK, spend(0).getSW(), "the day's limit: the window begins at the clock, a thousand seconds short of the top");
        assertEquals(4294967295L - 1000, windowStart());
        assertEquals(SW_OK, setTime(4294967295L));
        assertEquals(SW_OVER_LIMIT, spend(1).getSW(), "the greatest time there is does not end it: its end is past what four bytes can say");
        assertEquals(100, spentToday());
        assertEquals(4294967295L - 1000, windowStart());
    }

    @Test
    @DisplayName("The window of a limit that was set a long time ago still turns; a limit set under a time far on turns a day after it")
    void testWindowFromSetLimit() {
        readyWithLimit(100);
        for (int i = 0; i < 2; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 100, i + 1)).getSW());
        assertEquals(SW_OK, setTime(T0 + 400 * DAY));
        assertEquals(SW_OK, spend(0).getSW(), "a year on, the first spend begins a window at the clock");
        assertEquals(T0 + 400 * DAY, windowStart());
        assertEquals(SW_OK, setLimit(100), "set again: a window from the clock");
        assertEquals(0, spentToday());
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(100, spentToday());
    }

    // =========================================================================
    // What the source does, read from the source
    // =========================================================================

    private static String appletCode() throws Exception {
        String src = new String(java.nio.file.Files.readAllBytes(
            SchnorrHWMathTest.mainSourceDir().resolve("CashuApplet.java")), StandardCharsets.UTF_8);
        return SchnorrHWMathTest.stripCommentsAndCharLiterals(src);
    }

    /** The body of a method, from its declaration to the next one's. */
    private static String body(String code, String from, String to) {
        int start = code.indexOf(from);
        int end = code.indexOf(to, start + 1);
        assertTrue(start > 0 && end > start, "found " + from);
        return code.substring(start, end);
    }

    @Test
    @DisplayName("The payment's one transaction counts the day and sets burnPending, changeDue, the log and the last signature and writes no place; it refuses before anything is changed and is begun after the signature is made; the places are marked after it commits and before the receipt and the answer; the wait before it burns, counts and writes nothing; the receipt is a second transaction, after the payment's and before the answer")
    void testSpendIsOneTransaction() throws Exception {
        String code = appletCode();
        String body = body(code, "private void processSpendAllSign(", "private void finishBurn(");
        // the refusal (over the day) is the limits' own, asked for before anything is signed or changed; no time is asked for:
        // a card with no clock spends its first day on trust (1.15), so there is no word for a payment's want of one;
        // the limit on one payment is not among them: it is waited for, and nothing names a refusal for it
        String limits = body(code, "private void requireUnderLimits(", "private short waitsFor(");
        assertTrue(limits.contains("SW_OVER_LIMIT") && !limits.contains("SW_NO_TIME") && !limits.contains("CARD_NOW_OFFSET")
            && !limits.contains("beginTransaction") && !limits.contains("STATUS_SPENT"), "the limits refuse, ask for no clock, and change nothing themselves");
        assertFalse(limits.contains("CARD_TAP_") || limits.contains("OVER_TAP"), "and the limit on one payment is no part of them");
        assertFalse(code.contains("SW_OVER_TAP_LIMIT") || code.toLowerCase().contains("6a95"), "nothing in the applet names a refusal for the limit on one payment");

        /* The wait is its own branch, first in the signing: work (a signature over bytes of its own, thrown away), and
         * the number still to come as the answer. It changes nothing that lasts. */
        int waiting = body.indexOf("if (waits > 0) {");
        int waitEnd = body.indexOf("return;", waiting);
        assertTrue(waiting > 0 && waitEnd > waiting, "the wait is a branch of its own, and it returns");
        String wait = body.substring(waiting, waitEnd);
        assertTrue(wait.contains("schnorrHW.sign") && wait.contains("setOutgoingAndSend"), "it is a signature's work, and it answers 'not yet'");
        assertTrue(wait.contains("Util.setShort(buf, (short) 0, (short) 1)"), "with the two bytes 00 01 and not how many are left");
        assertFalse(wait.contains("Util.setShort(buf, (short) 0, waits)"), "the count is not what it answers");
        assertFalse(wait.contains("beginTransaction") || wait.contains("STATUS_SPENT") || wait.contains("cardLog") || wait.contains("cardRecord")
            || wait.contains("lastSig") || wait.contains("changeDue") || wait.contains("tapOpen") || wait.contains("proofStorage") || wait.contains("logEntry"),
            "a wait burns nothing, counts nothing, writes no log and keeps no signature");

        int refuse = body.indexOf("requireUnderLimits(", waitEnd);
        int begin = body.indexOf("beginTransaction");
        int window = body.indexOf("CARD_WINDOW_OFFSET");
        int charge = body.indexOf("CARD_SPENT_OFFSET", begin);
        int pending = body.indexOf("burnPending[0] = (byte) 1;");
        int commit = body.indexOf("commitTransaction");
        int finish = body.indexOf("finishBurn();", commit);
        int sign = body.indexOf("schnorrHW.sign", waitEnd);
        int send = body.indexOf("setOutgoingAndSend", commit);
        assertTrue(refuse > waitEnd && refuse < begin, "the day is asked about again, as it stands, after the wait and before anything is changed");
        assertFalse(body.contains("CARD_TAP"), "the limit on one payment is not read, counted or written when the payment is signed for");
        /* Signed into RAM first, then committed, then answered: a card pulled away while it signs (most of
         * a second) has burned nothing and sent nothing, and no signature leaves before the payment is
         * committed. Burned first, a pull-away in that time lost the piece with no signature anywhere.
         * The payment is the one transaction: the day's window and count, the note that it is made
         * (burnPending), and then, after it has committed, the places are marked (finishBurn). */
        assertTrue(sign > 0 && sign < begin && begin < window && window < charge && charge < pending && pending < commit && commit < finish && finish < send,
            "signed first; the window, what the day has signed for and the note that the payment is made come between begin and commit; the places are marked after the commit; and only then the answer");
        assertFalse(body.contains("STATUS_SPENT") || body.contains("proofStorage"), "no place is written in the signing: the places are marked by finishBurn, outside the transaction");
        assertEquals(2, count(body, "setOutgoingAndSend"), "'not yet' leaves the card in one place, in the wait, and the signature in one place, after both commits");
        assertEquals(send, body.lastIndexOf("setOutgoingAndSend"), "and the last is the signature's");

        /* The receipt (6c): a second transaction, begun after the payment's has committed (and its places are marked) and
         * committed before the signature is answered. What it says is true only of a payment that was made, and it is kept
         * out of the payment's own transaction, which is kept small. */
        assertEquals(2, count(body, "beginTransaction"), "two transactions: the payment's and the receipt's");
        assertEquals(2, count(body, "commitTransaction"));
        int receiptBegin = body.indexOf("beginTransaction", commit);
        int receiptCommit = body.indexOf("commitTransaction", receiptBegin);
        assertTrue(receiptBegin > finish && receiptCommit > receiptBegin && receiptCommit < send, "the receipt is written after the payment commits and its places are marked, and before the signature is answered");
        assertFalse(body.substring(commit, receiptBegin).contains("setOutgoingAndSend"), "and nothing is answered between them");
        String burnPart = body.substring(0, receiptBegin);
        String receipt = body.substring(receiptBegin, receiptCommit);
        assertEquals(1, count(burnPart, "Util.arrayCopy(cardRecord"), "a spend begins the day's window by copying the clock, in the payment's transaction, and writes no other part of the record");
        assertFalse(receipt.contains("proofStorage") || receipt.contains("STATUS_SPENT") || receipt.contains("cardLog") || receipt.contains("lastSig")
            || receipt.contains("changeDue") || receipt.contains("CARD_SPENT_OFFSET") || receipt.contains("CARD_WINDOW_OFFSET"), "the receipt's transaction burns and counts nothing");
        java.util.regex.Matcher writes = java.util.regex.Pattern.compile("Util\\.arrayCopy(?:NonAtomic)?\\([^,]*,[^,]*,\\s*([A-Za-z]+)|Util\\.arrayFillNonAtomic\\(([A-Za-z]+),|addUint32Stop\\(([A-Za-z]+),").matcher(receipt);
        int found = 0;
        while (writes.find()) {
            String destination = writes.group(1) != null ? writes.group(1) : writes.group(2) != null ? writes.group(2) : writes.group(3);
            assertEquals("cardReceipts", destination, "every write in the receipt's transaction is to the receipts: " + writes.group());
            found++;
        }
        assertTrue(found >= 5, "the clock, the worth, the hash, the first output and the count: " + found);
        assertTrue(receipt.contains("cardRecord, CARD_NOW_OFFSET, cardReceipts") && receipt.contains("allNet, (short) 0, cardReceipts"), "the clock and what the pieces were worth");
        // the hash in the receipt is the one the signature was made over: the same place in scratch
        assertTrue(body.contains("shaAll.doFinal(buf, (short) 0, (short) 0, scratch, X_MSG)") && body.contains("schnorrHW.sign(cardPrivKey, cardPubKey, scratch, X_MSG, buf, (short) 0)")
            && receipt.contains("scratch, X_MSG, cardReceipts"), "the hash that is signed is the hash that is kept");
        assertTrue(receipt.contains("allOut") && receipt.contains("allState[5]"), "and the first output, as it was given, if there was one");
        assertTrue(burnPart.indexOf("cardReceipts[3]") > sign, "the place in the ring is found after the signature is made");
    }

    @Test
    @DisplayName("The wait is worked out at the first SIGN, after the day has been asked, from what leaves the card and the limit alone: no clock is read, nothing is remembered, nothing is written; the beginning works out nothing, since the change is not known yet")
    void testTheWaitIsWorkedOutFromThePaymentAlone() throws Exception {
        String code = appletCode();
        assertEquals(WAIT_OVER_SIGNS, CashuApplet.WAIT_OVER_SIGNS, "these tests count in the applet's sizes: ten signatures for the first limit's worth over");
        assertEquals(WAIT_MORE_SIGNS, CashuApplet.WAIT_MORE_SIGNS, "four for every further one");
        assertEquals(WAIT_UNITS_MOST, CashuApplet.WAIT_UNITS_MOST, "and stop where it stops: 255 limits' worth");
        String begin = body(code, "private void processSpendAllBegin(", "private void processSpendAllOutputs(");
        assertFalse(begin.contains("waitsFor("), "the beginning works out no wait: the change is not known yet");
        assertTrue(begin.contains("Util.setShort(allState, (short) 2, (short) -1);"), "and leaves it to be worked out");
        String sign = body(code, "private void processSpendAllSign(", "private void finishBurn(");
        int net = sign.indexOf("subUint32(allNet, (short) 0, allChange, (short) 0);");
        int day = sign.indexOf("requireUnderLimits(allNet, (short) 0, (short) 0);");
        int wait = sign.indexOf("waitsFor(allNet, (short) 0, (short)(allState[6] & 0xFF), allState[7] != (byte) 0,");
        int work = sign.indexOf("if (waits > 0) {");
        assertTrue(net > 0 && net < day && day < wait && wait < work,
            "what leaves the card first; the day (and the time it needs) is asked about before the wait is worked out; both before any work is done");
        assertTrue(sign.indexOf("if (waits < 0) {") < day, "and once, at the first SIGN");
        String waits = body(code, "private short waitsFor(", "private static void subUint32(");
        assertTrue(waits.contains("CARD_TAP_LIMIT_OFFSET") && waits.contains("sum") && waits.contains("WAIT_OVER_SIGNS") && waits.contains("WAIT_UNITS_MOST"),
            "from the limit, what leaves the card, and the two numbers that make it a time");
        assertFalse(waits.contains("CARD_NOW_OFFSET") || waits.contains("CARD_WINDOW_OFFSET") || waits.contains("CARD_SPENT_OFFSET")
            || waits.contains("CARD_NOPIN_LIMIT_OFFSET") || waits.contains("CARD_NOPIN_SPENT_OFFSET") || waits.contains("windowIsOver") || waits.contains("dayIsOver"),
            "no clock and no count is read");
        assertFalse(waits.contains("beginTransaction") || waits.contains("arrayCopy(cardRecord") || waits.contains("arrayFill(cardRecord") || waits.contains("cardLog"),
            "and nothing that lasts is written");
        // anything but the payment's own next steps gives it up: the check is on the instruction, before the dispatch
        String process = body(code, "public void process(", "private void processGetInfo(");
        assertTrue(process.indexOf("INS_SPEND_ALL_OUTPUTS") < process.indexOf("allState[0] = (byte) 0")
            && process.indexOf("INS_SPEND_ALL_CHANGE") < process.indexOf("allState[0] = (byte) 0")
            && process.indexOf("allState[0] = (byte) 0") < process.indexOf("switch"), "a payment is given up by every instruction but OUTPUTS, CHANGE and SIGN, before any of them is looked at");
    }

    private static int count(String s, String what) {
        int n = 0;
        for (int at = s.indexOf(what); at >= 0; at = s.indexOf(what, at + 1)) n++;
        return n;
    }

    @Test
    @DisplayName("The grant is read only by loading and clearing, never by a spend; nothing in the applet resets what a spend has used; the clock is written only by SET_HEADER, and the told time is written only by TELL_TIME")
    void testWhatReadsWhat() throws Exception {
        String code = appletCode();
        // where the grant is read
        String spend = body(code, "private void processSpendAllBegin(", "private void secretInto(");
        assertEquals(1, count(spend, "loadGrant"), "a spend looks at the grant once: whether the owner's phone is in the tap, which is not slowed for a second payment (6a)");
        assertTrue(spend.contains("tapOpen[1] == (byte) 1 && loadGrant[0] != (byte) 1"), "and only for that");
        String verify = body(code, "private void processVerifyPin(", "private void failPinCheck(");
        assertFalse(verify.contains("arrayFill"), "VERIFY_PIN fills nothing");
        assertFalse(verify.contains("cardRecord"), "and does not touch the record");
        assertFalse(verify.contains("scratch"));
        assertFalse(verify.contains("loadGrant"));
        int uses = count(code, "loadGrant[0]");
        // set once in ALLOW_LOAD; read in GET_INFO (the limit on one payment, asked for with P1 = 1, is said to the owner's grant and nobody else),
        // in the load authority, in CLEAR_SPENT, in LOAD_PROOF (where a load with no PIN and no grant clears the change note), in GET_LOG
        // (the owner's phone may read the card's log with no PIN), in GET_LOG's receipts (which are the grant's alone), and in SPEND_ALL_SIGN
        // (the owner's phone, taking a whole card off in more than one signature, is not slowed for a second payment in the tap); and nowhere else
        // and, since 1.16, in SET_PIN (ADD PIN: a card with an owner and no PIN is given one under the owner's grant)
        assertEquals(10, uses, "loadGrant is set by ALLOW_LOAD and read by GET_INFO, requireLoadAuthority, CLEAR_SPENT, loadOne, GET_LOG, its receipts, SPEND_ALL_SIGN and SET_PIN, and let go by RESET_CARD (1.17): " + uses);
        String getInfo = body(code, "private void processGetInfo(", "private void processGetPubkey(");
        assertEquals(1, count(getInfo, "loadGrant[0]"), "GET_INFO reads the grant once: for the limit on one payment");
        assertFalse(getInfo.contains("pinVerifiedFlag"), "and not the PIN: a till has that");
        assertEquals(1, count(getInfo, "CARD_TAP_LIMIT_OFFSET"), "the limit is copied out in one place");
        assertTrue(getInfo.indexOf("loadGrant[0]") < getInfo.indexOf("CARD_TAP_LIMIT_OFFSET"), "and only under the grant");
        assertTrue(getInfo.contains("arrayFillNonAtomic(buf, (short) 30, (short) 4, (byte) 0)"), "to anyone else those four bytes are zeros");
        String getLog = body(code, "private void processGetLog(", "private void processGetReceipts(");
        assertTrue(getLog.contains("loadGrant[0]") && !getLog.contains("cardLog[(short)(LOG_TAPS_OFFSET + 3)] ="), "GET_LOG reads the grant, and writes nothing to the log");
        String getReceipts = body(code, "private void processGetReceipts(", "private boolean dayIsOver(");
        assertTrue(getReceipts.contains("loadGrant[0]") && !getReceipts.contains("pinVerifiedFlag"), "the receipts are read with the owner's grant and not with the PIN");
        assertFalse(getReceipts.contains("beginTransaction") || getReceipts.contains("cardReceipts[") && getReceipts.contains("cardReceipts[3] ="), "and reading them writes nothing");
        // the log is written in three places: the spend, the refusal of one, and the putting on of pieces (a clock moved on twice in a tap was a fourth, before 1.15)
        assertEquals(1, count(code, "private short logEntry("));
        assertEquals(4, count(code, "logEntry()"), "its declaration, and the three that ask for it: the spend, the refusal and LOAD_PROOF, and nowhere else");
        assertTrue(body(code, "private void processSpendAllSign(", "private void processSpendAllAgain(").contains("logEntry()"));
        assertTrue(body(code, "private void refuseOverLimit(", "private void processGetLog(").contains("logEntry()"));
        assertTrue(body(code, "private void processLoadProof(", "private short emptySlot(").contains("logEntry()"));
        assertFalse(body(code, "private void processSetHeader(", "private static void targetOf(").contains("logEntry()"), "SET_HEADER, which needs no PIN, begins no entry: nobody near the card can push its eight taps out of the ring");
        assertFalse(body(code, "private void processTellTime(", "private void processVerifyPin(").contains("logEntry()"), "nor does TELL_TIME");
        // the receipts are written by the spend and read by GET_LOG's receipts, and nothing else names them: nothing clears them
        String withoutThose = code.replace(body(code, "private void processSpendAllSign(", "private void processSpendAllAgain("), "").replace(getReceipts, "");
        assertEquals(3, count(withoutThose, "cardReceipts"), "outside those two, the declaration, the allocation and RESET_CARD (1.17, which makes the card a new one) are all there is: CLEAR_SPENT, SET_CARD, SET_OWNER and CHANGE_PIN do not touch them");
        // the time the terminal told is RAM that a reset clears and a SELECT does not, written only by TELL_TIME and read only by the receipt and the log's entry
        assertTrue(code.contains("tapTime         = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_RESET)"), "tapTime goes with the power and not with a SELECT: four bytes");
        String tellTime = body(code, "private void processTellTime(", "private void processVerifyPin(");
        String signing = body(code, "private void processSpendAllSign(", "private void processSpendAllAgain(");
        String entry = body(code, "private short logEntry(", "private void refuseOverLimit(");
        String withoutToldTime = code.replace(tellTime, "").replace(signing, "").replace(entry, "");
        assertEquals(2, count(withoutToldTime, "tapTime"), "outside TELL_TIME, the receipt and logEntry, the declaration and the allocation");
        assertEquals(1, count(tellTime, "tapTime"), "TELL_TIME writes it, once");
        assertTrue(tellTime.contains("Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, tapTime, (short) 0, (short) 4)"), "the four bytes it was told, and nothing else of the command");
        assertEquals(1, count(signing, "tapTime"), "the receipt reads it, once");
        assertEquals(1, count(entry, "tapTime"), "and logEntry, once");
        assertFalse(tellTime.contains("cardRecord") || tellTime.contains("cardLog") || tellTime.contains("beginTransaction") || tellTime.contains("pinVerifiedFlag") || tellTime.contains("ownerSet"),
            "and TELL_TIME touches nothing that lasts, and asks for no PIN and no owner");
        assertEquals(1, count(code, "arrayFillNonAtomic(cardLog, (short) 0"), "nothing clears the log but RESET_CARD (1.17)");
        assertTrue(body(code, "private void processResetCard(", "private void requireNotLocked(").contains("arrayFillNonAtomic(cardLog, (short) 0"), "and it is there");
        assertFalse(code.contains("cardLog = new byte[LOG_LEN];\n        cardLog"), "nor is it made again");
        assertTrue(body(code, "private void processAllowLoad(", "private short requireOwnerProof(").contains("loadGrant[0] = (byte) 1"));
        assertTrue(body(code, "private void requireLoadAuthority(", "private void requireNothingUnspent(").contains("loadGrant[0]"));
        assertTrue(body(code, "private void processClearSpent(", "private void processSetCard(").contains("loadGrant[0]"));
        // the clock: written by SET_HEADER, and by nothing else
        int at = 0, writes = 0;
        while ((at = code.indexOf("CARD_NOW_OFFSET", at)) >= 0) {
            int lineStart = code.lastIndexOf('\n', at) + 1;
            int lineEnd = code.indexOf('\n', at);
            String line = code.substring(lineStart, lineEnd);
            // a write has the clock as the destination: the second range of an arrayCopy, or the first of a fill
            if (line.matches(".*Util\\.arrayCopy(?:NonAtomic)?\\([^,]*,[^,]*,\\s*cardRecord,\\s*CARD_NOW_OFFSET.*")
                || line.contains("arrayFillNonAtomic(cardRecord, CARD_NOW_OFFSET")
                || line.contains("arrayFill(cardRecord, CARD_NOW_OFFSET")) writes++;
            at = lineEnd;
        }
        assertEquals(1, writes, "one place writes the clock: " + writes);
        // since 2.0 (D20) the one place is writeHeader, which writes nothing for a header checkHeader did not find later than the clock
        String checkHeader = body(code, "private short checkHeader(", "private void writeHeader(");
        String writeHeader = body(code, "private void writeHeader(", "private static void targetOf(");
        assertTrue(checkHeader.contains("cmpUint32(scratch, X_NUM, cardRecord, CARD_NOW_OFFSET) <= 0) return (short) 0;")
            && writeHeader.contains("if (how == (short) 0) return;") && writeHeader.contains("Util.arrayCopy(scratch, X_NUM, cardRecord, CARD_NOW_OFFSET"),
            "SET_HEADER writes it only for a later time");
        String setCard = body(code, "private void processSetCard(", "private void processSetLimit(");
        assertFalse(setCard.contains("CARD_NOW_OFFSET") || setCard.contains("CARD_WINDOW_OFFSET") || setCard.contains("CARD_SPENT_OFFSET") || setCard.contains("newKey"),
            "and SET_CARD no longer clears it, or the window, or what was spent, whatever bytes it is sent where the time key was");
    }

    @Test
    @DisplayName("The refusals that gate a command come first: the PIN, then the owner, then the shape; a limit is read, not set, by a spend")
    void testGatesComeFirst() throws Exception {
        String code = appletCode();
        String spend = body(code, "private void processSpendAllBegin(", "private void processSpendAllOutputs(");
        assertFalse(spend.contains("requirePinIfSet()") || spend.contains("pinVerifiedFlag"), "a payment is begun without asking the PIN anything (1.16): it is the signature that asks, when it is known what leaves the card");
        assertTrue(spend.contains("if (carry != 0 && needsAllowance()) ISOException.throwIt(SW_PIN_NEEDED);"), "except a sum that wraps, which is past any allowance: with a PIN not given it is the PIN's to ask for, and no refusal is logged");
        assertTrue(spend.indexOf("needsAllowance()") < spend.indexOf("requireUnderLimits("), "and before the limit would be refused and written down");
        String signing = body(code, "private void processSpendAllSign(", "private void processSpendAllAgain(");
        assertFalse(signing.contains("requirePinIfSet()"), "the signature's gate is the PIN or the allowance");
        assertEquals(2, count(signing, "requireAllowanceOrPin()"), "asked at the first SIGN, and again at the last, as the limits are");
        assertTrue(signing.indexOf("requireAllowanceOrPin()") < signing.indexOf("requireUnderLimits("), "before the limits: a reader that has not the PIN writes nothing in the log");
        assertTrue(signing.indexOf("requireAllowanceOrPin()") < signing.indexOf("if (waits > 0) {"), "and before the wait: a wait is not given to a terminal that has not the PIN");
        assertTrue(signing.lastIndexOf("requireAllowanceOrPin()") < signing.indexOf("short sigLen = schnorrHW.sign("), "and the last stands before the signature");
        String load = body(code, "private void processLoadProof(", "private void processClearSpent(");
        assertTrue(load.indexOf("requireLoadAuthority()") < load.indexOf("SW_NO_OWNER")
            && load.indexOf("SW_NO_OWNER") < load.indexOf("SW_NO_CARD_RECORD")
            && load.indexOf("SW_NO_CARD_RECORD") < load.indexOf("SW_NO_SPACE"), "load: the PIN or the grant, an owner, a record, a place free");
        assertFalse(load.contains("SW_NO_TIME") || load.contains("CARD_NOW_OFFSET"), "and no time: a card with no clock loads (the first day is on trust)");
    }

    // =========================================================================
    // AUTH
    // =========================================================================

    private byte[] authMessage(byte[] reader, byte[] card, byte[] key) throws Exception {
        byte[] tag = sha256("CashuCard/auth".getBytes(StandardCharsets.US_ASCII));
        java.security.MessageDigest d = java.security.MessageDigest.getInstance("SHA-256");
        d.update(tag); d.update(tag); d.update(reader); d.update(card); d.update(key);
        return d.digest();
    }

    @Test
    @DisplayName("AUTH signs the reader's nonce and the card's own under a tag, with no PIN, and never the same twice")
    void testAuth() throws Exception {
        byte[] reader = hexToBytes("000102030405060708090a0b0c0d0e0f");
        ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_AUTH, 0, 0, reader, 80));
        assertEquals(SW_OK, r.getSW());
        assertEquals(80, r.getData().length);
        byte[] cardNonce = Arrays.copyOfRange(r.getData(), 0, 16);
        byte[] sig = Arrays.copyOfRange(r.getData(), 16, 80);
        byte[] key = cardKey();
        assertTrue(schnorrVerify(extractPubkeyX(key), authMessage(reader, cardNonce, key), sig));
        byte[] other = reader.clone(); other[0] ^= 1;
        assertFalse(schnorrVerify(extractPubkeyX(key), authMessage(other, cardNonce, key), sig), "another reader's nonce is not answered by it");
        ResponseAPDU again = transmit(new CommandAPDU(CLA, INS_AUTH, 0, 0, reader, 80));
        assertFalse(Arrays.equals(cardNonce, Arrays.copyOfRange(again.getData(), 0, 16)), "the card's nonce is new each time");
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_AUTH, 0, 0, new byte[32], 80)), "32 bytes are not taken: that was SIGN_ARBITRARY");
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_AUTH, 0, 0, new byte[15], 80)));
    }

    @Test
    @DisplayName("AUTH's signature is not a spend: it verifies for no piece on the card, and burns none")
    void testAuthIsNotASpend() throws Exception {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 2, 1900000000L)).getSW());
        reselect();
        ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_AUTH, 0, 0, new byte[16], 80));
        assertEquals(SW_OK, r.getSW(), "it needs no PIN");
        byte[] sig = Arrays.copyOfRange(r.getData(), 16, 80);
        assertFalse(signedFor(sig, slot(0), REFUND));
        assertFalse(signedFor(sig, slot(1), REFUND));
        assertEquals(32, balance());
    }

    // =========================================================================
    // Vectors for the other side of the wire
    // =========================================================================

    /** The applet's folder in the build that is running: where target/ is. */
    private static java.nio.file.Path appletFolder() throws Exception {
        java.nio.file.Path target = SchnorrHWMathTest.mainSourceDir().toAbsolutePath().normalize();
        while (target != null && !target.endsWith("applet")) target = target.getParent();
        assertNotNull(target, "the applet folder");
        return target;
    }

    /**
     * What the card signed, written down for whoever makes the pieces: the
     * card's key, each piece as it was loaded, the secret text this test says
     * it is, and the signature the card gave for it. A wallet that builds the
     * same text from the same fields, and finds the signature good, agrees
     * with the card byte for byte. Written to target/secret-vectors.json;
     * spec/vectors/secret.json is one run of it, kept.
     */
    @Test
    @DisplayName("The card's signatures, as vectors for a wallet to check its secrets against")
    void testWriteVectors() throws Exception {
        ready();
        long[] dates = { 0L, 1L, 1700000000L, 1900000000L, 4294967295L };
        StringBuilder out = new StringBuilder();
        byte[] key = cardKey();
        out.append("{\n \"cardKey\": \"").append(toHex(key)).append("\",\n \"refundKey\": \"").append(toHex(REFUND))
           .append("\",\n \"mint\": \"").append(MINT).append("\",\n \"pieces\": [\n");
        for (int i = 0; i < dates.length; i++) {
            long amount = 1L << (i + 3);
            assertEquals(SW_OK, load(buildProof(KEYSET, amount, 0x40 + 7 * i, dates[i])).getSW());
            byte[] before = slot(i);
            ResponseAPDU r = spend(i);
            assertEquals(SW_OK, r.getSW());
            byte[] nonce = Arrays.copyOfRange(before, 13, 45);
            String secret = secretText(nonce, key, dates[i], REFUND);
            // the message of a payment of this one piece into no outputs: its secret, and its C in hex
            byte[] msg = sha256((secret + toHex(Arrays.copyOfRange(before, 45, 78))).getBytes(StandardCharsets.UTF_8));
            assertTrue(schnorrVerify(extractPubkeyX(key), msg, r.getData()));
            out.append("  {\"keyset\": \"").append(KEYSET).append("\", \"amount\": ").append(amount)
               .append(", \"nonce\": \"").append(toHex(nonce))
               .append("\", \"C\": \"").append(toHex(Arrays.copyOfRange(before, 45, 78)))
               .append("\", \"date\": ").append(dates[i])
               .append(",\n   \"slot\": \"").append(toHex(before))
               .append("\",\n   \"secret\": ").append(jsonString(secret))
               .append(",\n   \"message\": \"").append(toHex(msg))
               .append("\",\n   \"signature\": \"").append(toHex(r.getData())).append("\"}")
               .append(i + 1 < dates.length ? ",\n" : "\n");
        }
        // AUTH, for the same reason
        byte[] reader = hexToBytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        byte[] auth = transmit(new CommandAPDU(CLA, INS_AUTH, 0, 0, reader, 80)).getData();
        byte[] cardNonce = Arrays.copyOfRange(auth, 0, 16);
        out.append(" ],\n \"auth\": {\"tag\": \"CashuCard/auth\", \"readerNonce\": \"").append(toHex(reader))
           .append("\", \"cardNonce\": \"").append(toHex(cardNonce))
           .append("\", \"message\": \"").append(toHex(authMessage(reader, cardNonce, key)))
           .append("\", \"signature\": \"").append(toHex(Arrays.copyOfRange(auth, 16, 80))).append("\"}\n}\n");
        java.nio.file.Path target = SchnorrHWMathTest.mainSourceDir().toAbsolutePath().normalize();
        while (target != null && !target.endsWith("applet")) target = target.getParent();
        assertNotNull(target, "the applet folder");
        java.nio.file.Files.createDirectories(target.resolve("target"));
        java.nio.file.Files.write(target.resolve("target").resolve("secret-vectors.json"),
            out.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Owner vectors, for whoever builds the other side of the owner's proof: the
     * owner key and one proof for each label over a nonce and a value; the limit's
     * label twice, once over the four bytes of a day's limit and once over the
     * twelve bytes of all three limits (1.16); and, from 1.19, the tag's label over
     * the one byte that switches it off. (Until
     * 1.15 there were also a time key and a signed time; the clock is block
     * headers now, and there is neither.) ECDSA signatures are randomised, so
     * each is one the card has verified, and the other side verifies it again
     * with its own implementation. Written to target/owner-vectors.json;
     * spec/vectors/owner.json is one run of it, kept.
     */
    @Test
    @DisplayName("The owner's proofs, as vectors for another implementation to verify")
    void testWriteOwnerVectors() throws Exception {
        StringBuilder out = new StringBuilder("{\n");
        out.append(" \"curve\": \"P-256 (secp256r1)\",\n \"signature\": \"ECDSA, SHA-256, DER\",\n");
        out.append(" \"ownerKey\": \"").append(toHex(OWNER.pub)).append("\",\n \"proofs\": [\n");
        // 2.0 (D20): the limit's label over thirteen bytes (the rollover budget last), REFRESH's over a block header, and
        // SET_OWNER's over a key and the header that anchors the clock (145 bytes)
        byte[] tip = hexToBytes(TIP);
        byte[] thirteen = concat(u32(5000), u32(100), u32(50), new byte[] { 7 });
        String[] labels = { L_PIN, L_LIMIT, L_LOAD, L_CARD, L_OWNER, L_LOCK, L_LIMIT, L_RESET, L_TAG, L_LIMIT, L_REFRESH, L_OWNER };
        byte[][] values = { NEW_PIN, u32(5000), new byte[0], record(MINT, REFUND), OTHER_OWNER.pub, new byte[0], concat(u32(5000), u32(100), u32(50)), new byte[0], new byte[] { 1 },
            thirteen, tip, concat(OTHER_OWNER.pub, tip) };
        for (int i = 0; i < labels.length; i++) {
            simulator = freshCard();
            ready();
            byte[] n = nonceBytes();
            byte[] proof = ownerProof(labels[i], OWNER, n, values[i]);
            CommandAPDU[] commands = { changePinCommand(proof, NEW_PIN), setLimitCommand(proof, 5000), allowLoadCommand(proof),
                setCardCommand(proof, values[3]), setOwnerCommand(proof, OTHER_OWNER), lockCommand(proof), setLimits3Command(proof, 5000, 100, 50), resetCommand(proof), setTagCommand(proof, 1),
                new CommandAPDU(CLA, INS_SET_LIMIT_OWNER, 0, 0, ownerData(proof, thirteen)), refreshCommand(proof, tip),
                new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, ownerData(proof, values[11])) };
            assertEquals(SW_OK, sw(commands[i]), labels[i] + " is the owner's proof, to the card");
            out.append("  {\"label\": \"").append(labels[i]).append("\", \"nonce\": \"").append(toHex(n))
               .append("\", \"value\": \"").append(toHex(values[i])).append("\", \"signature\": \"").append(toHex(proof))
               .append("\"}").append(i + 1 < labels.length ? ",\n" : "\n");
        }
        out.append(" ]\n}\n");
        java.nio.file.Path target = appletFolder();
        java.nio.file.Files.createDirectories(target.resolve("target"));
        java.nio.file.Files.write(target.resolve("target").resolve("owner-vectors.json"), out.toString().getBytes(StandardCharsets.UTF_8));
    }

    // =========================================================================
    // The PIN, sealed (1.9)
    // =========================================================================
    //
    // The envelope is built here from its description, and not from the applet: the secp256k1 arithmetic is this file's own
    // (ecMulTest and liftX, BigInteger, at the end of it) and the hash is the JDK's SHA-256. BouncyCastle is not on the test
    // classpath. A sealed command's data is E (65, 04 || X || Y) || the clear data under a keystream || a tag (16), where
    //
    //   shared    = the x of (the sender's scalar) times (the card's PIN key)
    //   block(i, more) = SHA-256("CashuCard/seal" || i (1) || shared (32) || E (65) || nonce (16) || INS (1) || more)
    //   tag       = the first 16 bytes of block(0, ct)
    //   keystream = block(1) || block(2) || ...      clear = ct XOR keystream
    //
    // and the clear data ends in a PIN block: its length (4 to 8), the PIN, zeros to eight.

    /** The scalar these tests give a card's PIN key (ownPinKey), so that it is not the card's signing key as well. */
    static final java.math.BigInteger PIN_D = new java.math.BigInteger("3141592653589793238462643383279502884197169399375105820974944592", 16);
    /** The sender's one-message scalars, the private halves of E: an envelope uses one of them. */
    static final java.math.BigInteger[] EPH = {
        new java.math.BigInteger("1111111111111111111111111111111111111111111111111111111111111111", 16),
        new java.math.BigInteger("2222222222222222222222222222222222222222222222222222222222222222", 16),
        new java.math.BigInteger("3333333333333333333333333333333333333333333333333333333333333333", 16),
        new java.math.BigInteger("4444444444444444444444444444444444444444444444444444444444444444", 16),
        new java.math.BigInteger("5555555555555555555555555555555555555555555555555555555555555555", 16),
        new java.math.BigInteger("6666666666666666666666666666666666666666666666666666666666666666", 16) };
    static final byte[] PIN5 = { 0x35, 0x36, 0x37, 0x38, 0x39 };
    static final byte[] PIN8 = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };

    /** A compressed secp256k1 point, 02/03 || X. */
    static byte[] compressed(java.math.BigInteger[] w) {
        byte[] c = new byte[33];
        c[0] = (byte) (w[1].testBit(0) ? 3 : 2);
        System.arraycopy(unsigned32(w[0]), 0, c, 1, 32);
        return c;
    }
    /** The point a compressed key stands for; null where its X is on no point. */
    static java.math.BigInteger[] decompressed(byte[] key33) {
        java.math.BigInteger[] even = liftX(new java.math.BigInteger(1, Arrays.copyOfRange(key33, 1, 33)));
        if (even == null) return null;
        return key33[0] == 3 ? new java.math.BigInteger[] { even[0], SECP_P.subtract(even[1]) } : even;
    }
    /** A PIN key that is not the card's, to seal to: seven times the generator. */
    static byte[] anotherPinKey() {
        return compressed(ecMulTest(java.math.BigInteger.valueOf(7), SECP_GX, SECP_GY));
    }

    private static final java.util.Map<String, byte[][]> AGREED = new java.util.HashMap<>();
    /** { E (65), the shared x (32) } for the sender's scalar and a PIN key (33). Worked out once: the arithmetic is slow. */
    static byte[][] agreed(java.math.BigInteger e, byte[] pinKey33) {
        return AGREED.computeIfAbsent(e.toString(16) + "/" + toHex(pinKey33), id -> {
            java.math.BigInteger[] eg = ecMulTest(e, SECP_GX, SECP_GY);
            java.math.BigInteger[] p = decompressed(pinKey33);
            java.math.BigInteger[] s = ecMulTest(e, p[0], p[1]);
            return new byte[][] { concat(new byte[] { 4 }, unsigned32(eg[0]), unsigned32(eg[1])), unsigned32(s[0]) };
        });
    }
    static byte[] sealBlock(int i, byte[] shared, byte[] e, byte[] nonce, int ins, byte[] more) {
        try {
            java.security.MessageDigest d = java.security.MessageDigest.getInstance("SHA-256");
            d.update("CashuCard/seal".getBytes(StandardCharsets.US_ASCII));
            d.update((byte) i);
            d.update(shared);
            d.update(e);
            d.update(nonce);
            d.update((byte) ins);
            d.update(more);
            return d.digest();
        } catch (java.security.NoSuchAlgorithmException x) {
            throw new IllegalStateException(x);
        }
    }
    /** The envelope for `clear`, to the PIN key (33), under the nonce, for the instruction, with the sender's scalar. */
    static byte[] envelope(java.math.BigInteger e, byte[] pinKey33, byte[] nonce, int ins, byte[] clear) {
        byte[][] ks = agreed(e, pinKey33);
        byte[] ct = new byte[clear.length];
        for (int i = 0; i * 32 < clear.length; i++) {
            byte[] block = sealBlock(i + 1, ks[1], ks[0], nonce, ins, new byte[0]);
            for (int k = 0; k < 32 && i * 32 + k < clear.length; k++) ct[i * 32 + k] = (byte) (clear[i * 32 + k] ^ block[k]);
        }
        byte[] tag = Arrays.copyOf(sealBlock(0, ks[1], ks[0], nonce, ins, ct), 16);
        return concat(ks[0], ct, tag);
    }
    /** An envelope spoiled: "tag" the last byte of the tag, "tagfirst" its first, "body" the first byte of ct, "last" the last byte of ct, "x" a bit of E's X,
     *  "minusE" E's Y negated (the same shared secret), "02" "03" "00" E's first byte, "point" E replaced by 04 and 64 zeros,
     *  "y" a bit of E's Y, "big" X and Y both 2^256 - 1 (no field element). */
    static byte[] spoiled(byte[] env, String how) {
        byte[] e = env.clone();
        switch (how) {
            case "": break;
            case "tag": e[e.length - 1] ^= 1; break;
            case "tagfirst": e[e.length - 16] ^= 0x80; break;
            case "body": e[65] ^= 1; break;
            case "last": e[e.length - 17] ^= 1; break;
            case "x": e[1] ^= 1; break;
            case "minusE": {
                byte[] y = unsigned32(SECP_P.subtract(new java.math.BigInteger(1, Arrays.copyOfRange(e, 33, 65))));
                System.arraycopy(y, 0, e, 33, 32);
                break;
            }
            case "02": e[0] = 2; break;
            case "03": e[0] = 3; break;
            case "00": e[0] = 0; break;
            case "point": Arrays.fill(e, 1, 65, (byte) 0); e[0] = 4; break;
            case "y": e[33] ^= 1; break;
            case "big": Arrays.fill(e, 1, 65, (byte) 0xFF); break;
            default: throw new IllegalArgumentException(how);
        }
        return e;
    }
    /** The nine-byte PIN block: its length, the PIN, zeros to eight. */
    static byte[] pinBlock(byte[] pin) {
        byte[] b = new byte[9];
        b[0] = (byte) pin.length;
        System.arraycopy(pin, 0, b, 1, pin.length);
        return b;
    }

    /** What GET_NONCE with P1 = 1 said. */
    private static final class PinKey {
        byte[] nonce, key, sig, all;
    }
    private static PinKey splitPinKey(byte[] answer) {
        PinKey k = new PinKey();
        k.all = answer;
        k.nonce = Arrays.copyOfRange(answer, 0, 16);
        k.key = Arrays.copyOfRange(answer, 16, 49);
        k.sig = Arrays.copyOfRange(answer, 49, 113);
        return k;
    }
    private PinKey askPinKey() {
        ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_GET_NONCE, 1, 0, 256));
        assertEquals(SW_OK, r.getSW());
        assertEquals(113, r.getData().length);
        return splitPinKey(r.getData());
    }

    private Object appletObject(String name) throws Exception {
        java.lang.reflect.Field f = CashuApplet.class.getDeclaredField(name);
        f.setAccessible(true);
        return f.get(runtime.appletAt(AIDUtil.create(AID_HEX)));
    }
    /**
     * Gives the card's PIN key a scalar of this file's choosing (PIN_D), so that it is not the card's signing key. jCardSim seeds its key
     * generator the same for every key pair, so on an untouched card the PIN key made at install has the card key's value; a chip's does
     * not. The key objects are the applet's own and the applet reads them where it always does; only their value is set.
     * Call it before the card is first asked for its PIN key, which is when the card signs it.
     */
    private void ownPinKey() throws Exception {
        javacard.security.ECPrivateKey priv = (javacard.security.ECPrivateKey) appletObject("pinPrivKey");
        javacard.security.ECPublicKey pub = (javacard.security.ECPublicKey) appletObject("pinPubKey");
        priv.setS(unsigned32(PIN_D), (short) 0, (short) 32);
        java.math.BigInteger[] w = ecMulTest(PIN_D, SECP_GX, SECP_GY);
        byte[] w65 = concat(new byte[] { 4 }, unsigned32(w[0]), unsigned32(w[1]));
        pub.setW(w65, (short) 0, (short) 65);
    }
    /** A card with a PIN key of its own value, an open one (no owner), TEST_PIN set; taken out of the field and put back: not verified, three tries. */
    private void openPinCard() throws Exception {
        simulator = freshCard();
        ownPinKey();
        assertEquals(SW_OK, setPin(TEST_PIN));
        simulator.reset();
        reselect();
    }
    /** The same with an owner, a record and the time (ready()), TEST_PIN set; put back: not verified, three tries. */
    private void ownedPinCard() throws Exception {
        simulator = freshCard();
        ownPinKey();
        ready();
        simulator.reset();
        reselect();
    }
    private int tries() { return info()[9] & 0xFF; }
    private boolean verified() throws Exception { return field("pinVerifiedFlag")[0] == 1; }
    private boolean nonceLive() throws Exception { return field("nonceLive")[0] == 1; }
    private ResponseAPDU sendSealed(int ins, byte[] envelope) { return transmit(new CommandAPDU(CLA, ins, 1, 0, envelope)); }
    /** CHANGE_PIN's clear data: the proof's length, the proof (over the label, the nonce and the PIN itself), the PIN block. */
    private static byte[] changeClear(byte[] nonce, byte[] pin) {
        byte[] proof = ownerProof(L_PIN, OWNER, nonce, pin);
        return concat(new byte[] { (byte) proof.length }, proof, pinBlock(pin));
    }
    /** The clear data of a sealed command of this kind, for this PIN. */
    private static byte[] clearFor(int ins, PinKey k, byte[] pin) {
        return ins == (INS_CHANGE_PIN & 0xFF) ? changeClear(k.nonce, pin) : pinBlock(pin);
    }
    private static final int VERIFY_INS = INS_VERIFY_PIN & 0xFF, SET_INS = INS_SET_PIN & 0xFF, CHANGE_INS = INS_CHANGE_PIN & 0xFF;

    @Test
    @DisplayName("GET_NONCE with P1 = 1 answers 113 bytes: the nonce (16), the PIN key as a compressed secp256k1 point (33) and the card key's BIP-340 signature (64) over SHA-256(\"CashuCard/pinkey\" || those 33 bytes); the key is a point on the curve, and is not the card's signing key")
    void testGetNonceWithP1Of1GivesTheNonceThePinKeyAndTheCardsSignature() throws Exception {
        simulator = freshCard();
        ownPinKey();
        ResponseAPDU r = transmit(new CommandAPDU(CLA, INS_GET_NONCE, 1, 0, 256));
        assertEquals(SW_OK, r.getSW());
        assertEquals(113, r.getData().length);
        PinKey k = splitPinKey(r.getData());
        assertTrue(k.key[0] == 2 || k.key[0] == 3, "a compressed point");
        assertNotNull(decompressed(k.key), "and on the curve");
        assertArrayEquals(compressed(ecMulTest(PIN_D, SECP_GX, SECP_GY)), k.key, "it is the key the applet holds");
        assertFalse(Arrays.equals(k.key, cardKey()), "and not the card's signing key");
        byte[] digest = sha256(concat("CashuCard/pinkey".getBytes(StandardCharsets.US_ASCII), k.key));
        assertTrue(schnorrVerify(extractPubkeyX(cardKey()), digest, k.sig), "the card key's signature over SHA-256(label || key)");
        assertFalse(schnorrVerify(extractPubkeyX(cardKey()), sha256(concat("CashuCard/pinkey".getBytes(StandardCharsets.US_ASCII), anotherPinKey())), k.sig), "and over no other key");
        assertFalse(schnorrVerify(extractPubkeyX(cardKey()), sha256(concat("CashuCard/seal".getBytes(StandardCharsets.US_ASCII), k.key)), k.sig), "nor under another label");
        assertFalse(schnorrVerify(extractPubkeyX(k.key), digest, k.sig), "and it is not the PIN key's signature");
        assertArrayEquals(k.nonce, field("ownerNonce"), "the nonce is the one the owner's proof is over: the same buffer");
        assertTrue(nonceLive(), "and it is live");
    }

    @Test
    @DisplayName("The PIN key is a key pair of the applet's own, not the card's signing key reused: separate KeyPair, private and public key objects; jCardSim seeds its generator the same for every pair, so on an untouched card the two have the same value, which a chip's do not")
    void testThePinKeyIsAKeyPairOfItsOwn() throws Exception {
        simulator = freshCard();
        assertNotSame(appletObject("cardKeyPair"), appletObject("pinKeyPair"));
        assertNotSame(appletObject("cardPrivKey"), appletObject("pinPrivKey"));
        assertNotSame(appletObject("cardPubKey"), appletObject("pinPubKey"));
        assertSame(((javacard.security.KeyPair) appletObject("pinKeyPair")).getPrivate(), appletObject("pinPrivKey"));
        assertSame(((javacard.security.KeyPair) appletObject("pinKeyPair")).getPublic(), appletObject("pinPubKey"));
        // setting the PIN key's value moves the PIN key and leaves the card key where it was (which is what tells the two apart in these tests)
        byte[] cardBefore = cardKey();
        ownPinKey();
        assertArrayEquals(cardBefore, cardKey(), "the card key did not move");
        assertFalse(Arrays.equals(cardBefore, askPinKey().key), "and the PIN key did");
    }

    @Test
    @DisplayName("Asked again, GET_NONCE P1 = 1 gives a new nonce every time and the same key and the same signature, which are made once, at the first asking, and kept (pinKeySig)")
    void testThePinKeyAndItsSignatureAreTheSameEveryTimeAndOnlyTheNonceChanges() throws Exception {
        simulator = freshCard();
        ownPinKey();
        assertEquals(0, field("pinKeySig")[0], "not yet signed");
        PinKey a = askPinKey();
        assertEquals(1, field("pinKeySig")[0], "signed at the first asking");
        assertArrayEquals(a.sig, Arrays.copyOfRange(field("pinKeySig"), 1, 65), "and kept");
        PinKey b = askPinKey(), c = askPinKey();
        assertFalse(Arrays.equals(a.nonce, b.nonce) || Arrays.equals(b.nonce, c.nonce) || Arrays.equals(a.nonce, c.nonce), "a new nonce each time");
        assertArrayEquals(a.key, b.key); assertArrayEquals(b.key, c.key);
        assertArrayEquals(a.sig, b.sig); assertArrayEquals(b.sig, c.sig);
        assertArrayEquals(c.nonce, field("ownerNonce"), "and the nonce the card holds is the last one given");
    }

    @Test
    @DisplayName("GET_NONCE P1 = 1 needs no PIN and no owner: a card with neither, with a PIN not given, with an owner and a PIN not given, and a locked card all answer it; P1 = 0 still needs an owner")
    void testThePinKeyNeedsNeitherOwnerNorPin() throws Exception {
        simulator = freshCard();
        assertEquals(SW_NO_OWNER, nonce().getSW(), "P1 = 0 on a card with no owner, as before");
        assertEquals(113, askPinKey().all.length, "P1 = 1 on a card with no owner and no PIN");
        assertEquals(SW_OK, setPin(TEST_PIN));
        simulator.reset(); reselect();
        assertEquals(113, askPinKey().all.length, "with a PIN set and not given");
        assertEquals(SW_NO_OWNER, nonce().getSW());
        ownedPinCard();
        assertEquals(113, askPinKey().all.length, "with an owner and a PIN not given");
        assertEquals(16, nonceBytes().length, "and P1 = 0 with the owner");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, lock());
        simulator.reset(); reselect();
        assertEquals(113, askPinKey().all.length, "a locked card says its PIN key as well");
    }

    @Test
    @DisplayName("One nonce serves the owner's proof and the sealing: a P1 = 1 nonce is the nonce an owner's proof is over (and is used up by it), a P1 = 0 nonce is the nonce a sealed command is sealed under, and each asking replaces the one before, of either kind")
    void testOneNonceServesAnOwnersProofAndASealedCommand() throws Exception {
        ownedPinCard();
        PinKey k = askPinKey();
        assertEquals(SW_OK, sw(allowLoadCommand(ownerProof(L_LOAD, OWNER, k.nonce, new byte[0]))), "an owner's proof over a P1 = 1 nonce");
        assertFalse(nonceLive(), "and it is used up by the proof");
        assertEquals(SW_OWNER_PROOF, sw(allowLoadCommand(ownerProof(L_LOAD, OWNER, k.nonce, new byte[0]))), "once");
        // a P1 = 0 nonce, sealed under
        PinKey key = askPinKey();
        byte[] zero = nonceBytes();
        assertArrayEquals(zero, field("ownerNonce"), "the P1 = 0 asking replaced the P1 = 1 nonce");
        assertEquals(SW_OK, sendSealed(VERIFY_INS, envelope(EPH[0], key.key, zero, VERIFY_INS, pinBlock(TEST_PIN))).getSW(), "a command sealed under the P1 = 0 nonce opens");
        assertTrue(verified());
        // and the one before was replaced
        PinKey older = askPinKey();
        PinKey newer = askPinKey();
        assertEquals(0x63C2, sendSealed(VERIFY_INS, envelope(EPH[0], older.key, older.nonce, VERIFY_INS, pinBlock(TEST_PIN))).getSW(), "sealed under the nonce before the last: it does not open");
        assertEquals(SW_OWNER_PROOF, sw(allowLoadCommand(ownerProof(L_LOAD, OWNER, newer.nonce, new byte[0]))), "the nonce the failed envelope used up is gone for the owner's proof too");
        PinKey last = askPinKey();
        byte[] after = nonceBytes();
        assertEquals(SW_OK, sw(allowLoadCommand(ownerProof(L_LOAD, OWNER, after, new byte[0]))), "a P1 = 0 asking after a P1 = 1 one: its nonce is the live one");
        last = askPinKey();
        after = nonceBytes();
        assertEquals(SW_OWNER_PROOF, sw(allowLoadCommand(ownerProof(L_LOAD, OWNER, last.nonce, new byte[0]))), "and the P1 = 1 nonce before it is gone");
    }

    @Test
    @DisplayName("Sealed VERIFY_PIN with the right PIN verifies as the clear one does, for PINs of 4, 5 and 8 bytes: 90 bytes on the wire whatever the PIN's length, the tries back to three, the session verified, and a payment can be begun")
    void testASealedVerifyOfTheRightPinVerifies() throws Exception {
        for (byte[] pin : new byte[][] { TEST_PIN, PIN5, PIN8 }) {
            String what = pin.length + "-byte PIN";
            simulator = freshCard();
            ownPinKey();
            ready();
            assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW(), what);
            assertEquals(SW_OK, changePin(pin), what);
            simulator.reset(); reselect();
            assertEquals(0x63C2, verify(WRONG_PIN), what + ": a try gone");
            assertEquals(2, tries(), what);
            PinKey k = askPinKey();
            byte[] env = envelope(EPH[1], k.key, k.nonce, VERIFY_INS, pinBlock(pin));
            assertEquals(90, env.length, what + ": ninety bytes on the wire, E and the block and the tag");
            assertFalse(verified(), what);
            assertEquals(SW_OK, sendSealed(VERIFY_INS, env).getSW(), what);
            assertTrue(verified(), what + ": verified");
            assertEquals(3, tries(), what + ": the tries are back");
            assertEquals(SW_OK, spend(0).getSW(), what + ": and a payment can be begun and signed");
            assertFalse(nonceLive(), what + ": the nonce is used up");
        }
    }

    @Test
    @DisplayName("Sealed VERIFY_PIN with a wrong PIN costs a try as a clear one does: 63C2, 63C1, then 6983 with the card blocked (pinState 2, no tries); the session is not verified; a blocked card says 6983 before it looks at the envelope, and leaves the nonce as it was")
    void testASealedWrongPinCostsATryAndBlocksAtTheThird() throws Exception {
        openPinCard();
        PinKey k = askPinKey();
        assertEquals(SW_OK, sendSealed(VERIFY_INS, envelope(EPH[0], k.key, k.nonce, VERIFY_INS, pinBlock(TEST_PIN))).getSW());
        assertTrue(verified());
        k = askPinKey();
        assertEquals(0x63C2, sendSealed(VERIFY_INS, envelope(EPH[0], k.key, k.nonce, VERIFY_INS, pinBlock(WRONG_PIN))).getSW());
        assertFalse(verified(), "a wrong PIN ends the session, sealed as clear");
        assertEquals(2, tries());
        k = askPinKey();
        assertEquals(0x63C1, sendSealed(VERIFY_INS, envelope(EPH[0], k.key, k.nonce, VERIFY_INS, pinBlock(PIN5))).getSW(), "a wrong PIN of another length");
        assertEquals(1, tries());
        k = askPinKey();
        assertEquals(SW_PIN_BLOCKED, sendSealed(VERIFY_INS, envelope(EPH[0], k.key, k.nonce, VERIFY_INS, pinBlock(WRONG_PIN))).getSW());
        assertEquals(2, info()[7], "blocked");
        assertEquals(0, tries());
        k = askPinKey();
        assertEquals(SW_PIN_BLOCKED, sendSealed(VERIFY_INS, envelope(EPH[0], k.key, k.nonce, VERIFY_INS, pinBlock(TEST_PIN))).getSW(), "the right PIN no longer opens it");
        assertTrue(nonceLive(), "and the envelope was not looked at: the nonce is as it was");
    }

    @Test
    @DisplayName("An envelope is good once: sent a second time it is 6985 and costs nothing and leaves the session as it was; sent after a fresh GET_NONCE P1 = 1 it does not open and costs a try; sent after the card was taken out of the field and put back (no nonce) it is 6985 and costs nothing; and the same for SET_PIN")
    void testASealedCommandCannotBeSentTwice() throws Exception {
        openPinCard();
        PinKey k = askPinKey();
        byte[] env = envelope(EPH[0], k.key, k.nonce, VERIFY_INS, pinBlock(TEST_PIN));
        assertEquals(SW_OK, sendSealed(VERIFY_INS, env).getSW());
        assertEquals(SW_CONDITIONS_NOT_SATIS, sendSealed(VERIFY_INS, env).getSW(), "the second time");
        assertEquals(3, tries(), "at no cost");
        assertTrue(verified(), "and the session that the first verified is as it was");
        askPinKey();
        assertEquals(0x63C2, sendSealed(VERIFY_INS, env).getSW(), "after a fresh nonce it does not open");
        assertEquals(2, tries(), "and it costs a try");
        assertFalse(verified());
        simulator.reset(); reselect();
        assertEquals(SW_CONDITIONS_NOT_SATIS, sendSealed(VERIFY_INS, env).getSW(), "after the card was out of the field there is no nonce");
        assertEquals(2, tries(), "and that costs nothing");
        // SET_PIN
        openPinCard();
        k = askPinKey();
        env = envelope(EPH[0], k.key, k.nonce, SET_INS, pinBlock(NEW_PIN));
        assertEquals(SW_OK, sendSealed(SET_INS, env).getSW());
        assertEquals(SW_CONDITIONS_NOT_SATIS, sendSealed(SET_INS, env).getSW(), "SET_PIN the second time");
        assertEquals(SW_OK, verify(NEW_PIN), "the PIN is the one the first set");
        askPinKey();
        assertEquals(SW_WRONG_DATA, sendSealed(SET_INS, env).getSW(), "after a fresh nonce it does not open: SET_PIN says 6A80");
        assertEquals(3, tries(), "and costs no try");
    }

    @Test
    @DisplayName("No nonce asked, no sealing: a good envelope, a bad one and a short one for a nonce nobody gave are 6985 (6700 where the length is short: that is looked at first) with the tries and the PIN untouched, for VERIFY_PIN, SET_PIN and CHANGE_PIN")
    void testNoNonceIsNoSealing() throws Exception {
        for (int ins : new int[] { VERIFY_INS, SET_INS, CHANGE_INS }) {
            String what = String.format("%02X", ins);
            if (ins == CHANGE_INS) ownedPinCard(); else openPinCard();
            PinKey k = askPinKey();
            byte[] good = envelope(EPH[0], k.key, k.nonce, ins, clearFor(ins, k, NEW_PIN));
            simulator.reset(); reselect();
            assertFalse(nonceLive(), what);
            assertEquals(SW_CONDITIONS_NOT_SATIS, sendSealed(ins, good).getSW(), what + ": an envelope for a nonce the card no longer holds");
            assertEquals(SW_CONDITIONS_NOT_SATIS, sendSealed(ins, new byte[90]).getSW(), what + ": nothing of an envelope");
            assertEquals(SW_CONDITIONS_NOT_SATIS, sendSealed(ins, new byte[82]).getSW(), what + ": the shortest");
            assertEquals(SW_WRONG_LENGTH, sendSealed(ins, new byte[81]).getSW(), what + ": one byte shorter, which is looked at first");
            assertEquals(3, tries(), what + ": no try is cost");
            assertEquals(SW_OK, verify(TEST_PIN), what + ": the PIN is the old one");
        }
    }

    /** Whether an envelope's E (04 || X || Y) is a point of secp256k1. */
    static boolean pointIsOnTheCurve(byte[] env) {
        java.math.BigInteger x = new java.math.BigInteger(1, Arrays.copyOfRange(env, 1, 33)), y = new java.math.BigInteger(1, Arrays.copyOfRange(env, 33, 65));
        return x.compareTo(SECP_P) < 0 && y.compareTo(SECP_P) < 0
            && y.multiply(y).mod(SECP_P).equals(x.pow(3).add(java.math.BigInteger.valueOf(7)).mod(SECP_P));
    }

    private static final String[] SPOILS = { "tag", "tagfirst", "body", "last", "x", "y", "minusE", "02", "03", "00", "point", "big" };

    /** One tampered envelope for this command, and what the card does with it. */
    private void tamperedEnvelope(int ins, String how) throws Exception {
        String what = String.format("%02X sealed, %s", ins, how);
        if (ins == CHANGE_INS) ownedPinCard(); else openPinCard();
        PinKey old = askPinKey();
        PinKey k = how.equals("earlier nonce") ? askPinKey() : old;
        int sealedFor = how.startsWith("for ") ? Integer.parseInt(how.substring(4), 16) : ins;
        byte[] pin = ins == VERIFY_INS ? TEST_PIN : NEW_PIN;
        byte[] clear = ins == CHANGE_INS ? changeClear(old.nonce, pin) : pinBlock(pin);
        byte[] key = how.equals("another key") ? anotherPinKey() : k.key;
        byte[] env = envelope(EPH[2], key, old.nonce, sealedFor, clear);
        for (String s : SPOILS) if (s.equals(how)) env = spoiled(env, how);
        // the spoils that leave the curve do, and the one that does not, does not: so that what is tried here is what its name says
        if (how.equals("x") || how.equals("y") || how.equals("point") || how.equals("big")) assertTrue(env[0] == 4 && !pointIsOnTheCurve(env), what + ": E is no point");
        if (how.equals("minusE") || how.equals("another key") || how.equals("tag") || how.equals("body")) assertTrue(env[0] == 4 && pointIsOnTheCurve(env), what + ": E is a point");
        java.util.Map<String, byte[]> before = persistent();
        ResponseAPDU r = sendSealed(ins, env);
        if (ins == VERIFY_INS) {
            assertEquals(0x63C2, r.getSW(), what + ": a wrong PIN, as far as the card can tell");
            assertEquals(2, tries(), what + ": costs a try");
            assertFalse(verified(), what);
        } else {
            assertEquals(SW_WRONG_DATA, r.getSW(), what + ": 6A80");
            assertEquals(3, tries(), what + ": costs no try");
            assertPersistent(before, what + ": and changes nothing");
        }
        assertEquals(0, r.getData().length, what);
        assertFalse(nonceLive(), what + ": an envelope that does not open has used the nonce up");
        // and the good envelope under that nonce is too late
        byte[] fine = envelope(EPH[2], k.key, k.nonce, ins, ins == CHANGE_INS ? changeClear(k.nonce, pin) : pinBlock(pin));
        assertEquals(SW_CONDITIONS_NOT_SATIS, sendSealed(ins, fine).getSW(), what + ": the good one is 6985 after it");
        assertEquals(SW_OK, verify(TEST_PIN), what + ": the PIN is the old one");
    }

    @Test
    @DisplayName("A tampered sealed VERIFY_PIN costs a try, as a wrong PIN does, and uses the nonce up: one bit of the tag (its first byte and its last), of the ciphertext (first and last byte), of E's X or Y; E negated (the same shared secret); E starting 02, 03 or 00; E off the curve (04 and zeros, 04 and ones, one bit of X or Y); an envelope sealed to another key, under the nonce before, or for SET_PIN or CHANGE_PIN")
    void testATamperedSealedVerifyCostsATry() throws Exception {
        String[] hows = { "tag", "tagfirst", "body", "last", "x", "y", "minusE", "02", "03", "00", "point", "big", "another key", "earlier nonce", "for 41", "for 42" };
        for (String how : hows) tamperedEnvelope(VERIFY_INS, how);
    }

    @Test
    @DisplayName("A tampered sealed SET_PIN is 6A80 and changes nothing and costs no try: every spoil and every wrong key, nonce or instruction a sealed VERIFY_PIN has")
    void testATamperedSealedSetPinChangesNothing() throws Exception {
        String[] hows = { "tag", "tagfirst", "body", "last", "x", "y", "minusE", "02", "03", "00", "point", "big", "another key", "earlier nonce", "for 40", "for 42" };
        for (String how : hows) tamperedEnvelope(SET_INS, how);
    }

    @Test
    @DisplayName("A tampered sealed CHANGE_PIN is 6A80 and changes nothing and costs no try, and the nonce is gone with it: every spoil and every wrong key, nonce or instruction a sealed VERIFY_PIN has")
    void testATamperedSealedChangePinChangesNothing() throws Exception {
        String[] hows = { "tag", "tagfirst", "body", "last", "x", "y", "minusE", "02", "03", "00", "point", "big", "another key", "earlier nonce", "for 40", "for 41" };
        for (String how : hows) tamperedEnvelope(CHANGE_INS, how);
    }

    @Test
    @DisplayName("Lc below 82 (E, one byte and the tag) is 6700 for all three commands and uses nothing: no try, the nonce is as it was, and the envelope that follows under the same nonce opens; with 82 the envelope opens and a clear length of one is 6700")
    void testAnEnvelopeShorterThanItsParts() throws Exception {
        for (int ins : new int[] { VERIFY_INS, SET_INS, CHANGE_INS }) {
            for (int len : new int[] { 0, 1, 16, 65, 80, 81 }) {
                String what = String.format("%02X with %d bytes", ins, len);
                if (ins == CHANGE_INS) ownedPinCard(); else openPinCard();
                PinKey k = askPinKey();
                assertEquals(SW_WRONG_LENGTH, sendSealed(ins, new byte[len]).getSW(), what);
                assertEquals(3, tries(), what);
                assertTrue(nonceLive(), what + ": the nonce was not used");
                byte[] pin = ins == VERIFY_INS ? TEST_PIN : NEW_PIN;
                assertEquals(SW_OK, sendSealed(ins, envelope(EPH[3], k.key, k.nonce, ins, clearFor(ins, k, pin))).getSW(), what + ": the nonce is still good");
            }
        }
        openPinCard();
        PinKey k = askPinKey();
        assertEquals(SW_WRONG_LENGTH, sendSealed(VERIFY_INS, envelope(EPH[3], k.key, k.nonce, VERIFY_INS, new byte[] { 4 })).getSW(), "82 bytes open, and one byte of data is no PIN block");
        assertEquals(3, tries());
        assertFalse(nonceLive(), "the nonce was used by the opening");
    }

    @Test
    @DisplayName("The data that opens from a sealed VERIFY_PIN or SET_PIN is exactly a nine-byte block: 1, 8, 10, 41 and 80 bytes are 6700 even where a good PIN block ends them (the longer ones take a second and a third block of keystream to open) at no cost in tries, with the PIN as it was and the nonce used")
    void testTheClearDataOfAPinCommandIsNineBytes() throws Exception {
        for (int ins : new int[] { VERIFY_INS, SET_INS }) {
            for (int len : new int[] { 1, 8, 10, 41, 80 }) {
                String what = String.format("%02X with %d bytes of clear data", ins, len);
                openPinCard();
                PinKey k = askPinKey();
                // a good PIN block at the end of it, so that a card that read the last nine bytes and not the whole would take it
                byte[] pin = ins == VERIFY_INS ? TEST_PIN : NEW_PIN;
                byte[] clear = new byte[len];
                Arrays.fill(clear, (byte) 0xEE);
                System.arraycopy(pinBlock(pin), 0, clear, Math.max(0, len - 9), Math.min(9, len));
                assertEquals(SW_WRONG_LENGTH, sendSealed(ins, envelope(EPH[4], k.key, k.nonce, ins, clear)).getSW(), what);
                assertEquals(3, tries(), what + ": no try");
                assertFalse(nonceLive(), what + ": the nonce is used");
                assertEquals(SW_OK, verify(TEST_PIN), what + ": the PIN is as it was");
            }
        }
    }

    @Test
    @DisplayName("A PIN block whose length byte is not 4 to 8 (0, 3, 9, 255) is 6700, for all three commands, with nothing changed and no try cost; for VERIFY_PIN and SET_PIN the nonce is used by the opening, for CHANGE_PIN it is left for the proof")
    void testAPinBlockOfTheWrongLengthIsRefused() throws Exception {
        for (int ins : new int[] { VERIFY_INS, SET_INS, CHANGE_INS }) {
            for (int length : new int[] { 0, 3, 9, 255 }) {
                String what = String.format("%02X with a block of length %d", ins, length);
                if (ins == CHANGE_INS) ownedPinCard(); else openPinCard();
                PinKey k = askPinKey();
                byte[] block = pinBlock(NEW_PIN);
                block[0] = (byte) length;
                byte[] clear;
                if (ins == CHANGE_INS) {
                    byte[] proof = ownerProof(L_PIN, OWNER, k.nonce, NEW_PIN);
                    clear = concat(new byte[] { (byte) proof.length }, proof, block);
                } else {
                    clear = block;
                }
                java.util.Map<String, byte[]> before = persistent();
                assertEquals(SW_WRONG_LENGTH, sendSealed(ins, envelope(EPH[4], k.key, k.nonce, ins, clear)).getSW(), what);
                assertEquals(3, tries(), what + ": no try");
                assertPersistent(before, what + ": nothing changed");
                assertEquals(ins == CHANGE_INS, nonceLive(), what + ": the nonce");
                assertEquals(SW_OK, verify(TEST_PIN), what + ": the PIN is as it was");
            }
        }
    }

    @Test
    @DisplayName("What follows the PIN in its block is not looked at: a block of 4, the PIN and four bytes that are not zeros verifies")
    void testThePaddingOfThePinBlockIsNotLookedAt() throws Exception {
        openPinCard();
        PinKey k = askPinKey();
        byte[] block = pinBlock(TEST_PIN);
        Arrays.fill(block, 5, 9, (byte) 0xAA);
        assertEquals(SW_OK, sendSealed(VERIFY_INS, envelope(EPH[5], k.key, k.nonce, VERIFY_INS, block)).getSW());
        assertTrue(verified());
    }

    @Test
    @DisplayName("Sealed SET_PIN on an open card sets the PIN (4, 5 and 8 bytes), the clear and the sealed VERIFY_PIN both take it and the old one is a wrong PIN; it ends the session, gives the tries back and unblocks a blocked card")
    void testASealedSetPinOnAnOpenCardSetsThePin() throws Exception {
        simulator = freshCard();
        ownPinKey();
        for (byte[] pin : new byte[][] { NEW_PIN, PIN5, PIN8, TEST_PIN }) {
            String what = pin.length + "-byte PIN";
            PinKey k = askPinKey();
            assertEquals(SW_OK, sendSealed(SET_INS, envelope(EPH[0], k.key, k.nonce, SET_INS, pinBlock(pin))).getSW(), what);
            assertEquals(1, info()[7], what + ": set");
            assertEquals(3, tries(), what);
            assertFalse(verified(), what + ": no session verified");
            assertEquals(SW_OK, verify(pin), what + ": the clear VERIFY_PIN takes it");
            assertTrue(verified());
            k = askPinKey();
            assertEquals(SW_OK, sendSealed(SET_INS, envelope(EPH[0], k.key, k.nonce, SET_INS, pinBlock(pin))).getSW(), what + ": again");
            assertFalse(verified(), what + ": a new PIN has not been typed: the session that verified the old one is over");
            simulator.reset(); reselect();
            k = askPinKey();
            assertEquals(SW_OK, sendSealed(VERIFY_INS, envelope(EPH[1], k.key, k.nonce, VERIFY_INS, pinBlock(pin))).getSW(), what + ": the sealed VERIFY_PIN takes it too");
            simulator.reset(); reselect();
            assertEquals(0x63C2, verify(pin[0] == WRONG_PIN[0] ? NEW_PIN : WRONG_PIN), what + ": and another is wrong");
        }
        // a blocked card
        simulator.reset(); reselect();
        assertEquals(SW_OK, verify(TEST_PIN), "(the tries back)");
        assertEquals(0x63C2, verify(WRONG_PIN)); assertEquals(0x63C1, verify(WRONG_PIN)); assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN));
        assertEquals(2, info()[7]);
        PinKey k = askPinKey();
        assertEquals(SW_OK, sendSealed(SET_INS, envelope(EPH[0], k.key, k.nonce, SET_INS, pinBlock(NEW_PIN))).getSW(), "an open card may be given a PIN again, sealed");
        assertEquals(1, info()[7], "unblocked");
        assertEquals(3, tries());
        assertEquals(SW_OK, verify(NEW_PIN));
    }

    @Test
    @DisplayName("Sealed SET_PIN is refused in the order locked (6986), owned (6A91), something unspent (6A8D), before the envelope is looked at: with a good envelope, with nothing of one and with no nonce asked at all, the nonce is as it was and the PIN is as it was")
    void testASealedSetPinIsRefusedAsTheClearOneIsAndBeforeTheEnvelope() throws Exception {
        // something unspent on an open card (no command can put it there: LOAD_PROOF wants an owner)
        openPinCard();
        setStatusOf(0, 1);
        PinKey k = askPinKey();
        byte[] good = envelope(EPH[0], k.key, k.nonce, SET_INS, pinBlock(NEW_PIN));
        assertEquals(SW_CARD_IN_USE, sendSealed(SET_INS, good).getSW(), "unspent");
        assertEquals(SW_CARD_IN_USE, sendSealed(SET_INS, new byte[90]).getSW(), "unspent, and nothing of an envelope");
        assertTrue(nonceLive(), "the nonce was not used");
        assertEquals(SW_OK, verify(TEST_PIN), "the PIN is as it was");
        // owned, and unspent as well
        ownedPinCard();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        reselect();
        k = askPinKey();
        good = envelope(EPH[0], k.key, k.nonce, SET_INS, pinBlock(NEW_PIN));
        assertEquals(SW_OWNER_PROOF, sendSealed(SET_INS, good).getSW(), "owned, though something is unspent as well");
        assertEquals(SW_OWNER_PROOF, sendSealed(SET_INS, new byte[90]).getSW(), "nothing of an envelope");
        assertTrue(nonceLive());
        simulator.reset(); reselect();
        assertEquals(SW_OWNER_PROOF, sendSealed(SET_INS, good).getSW(), "no nonce at all");
        // locked, and owned
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, lock());
        simulator.reset(); reselect();
        k = askPinKey();
        good = envelope(EPH[0], k.key, k.nonce, SET_INS, pinBlock(NEW_PIN));
        assertEquals(SW_NOT_ALLOWED, sendSealed(SET_INS, good).getSW(), "locked, and owned");
        assertEquals(SW_NOT_ALLOWED, sendSealed(SET_INS, new byte[90]).getSW());
        assertTrue(nonceLive());
        assertEquals(SW_OK, verify(TEST_PIN), "the PIN is as it was");
    }

    @Test
    @DisplayName("Sealed CHANGE_PIN by the owner: the proof is over the label, the P1 = 1 nonce and the PIN itself, and the data spans three blocks of keystream; it sets the PIN, ends the session, gives the tries back and unblocks a blocked card on which the old PIN is not given, and the old one is a wrong PIN")
    void testASealedChangePinByTheOwnerSetsThePin() throws Exception {
        for (byte[] pin : new byte[][] { NEW_PIN, PIN5, PIN8 }) {
            String what = pin.length + "-byte PIN";
            ownedPinCard();
            assertEquals(SW_OK, verify(TEST_PIN), what);
            assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW(), what + ": a funded card");
            assertTrue(verified());
            PinKey k = askPinKey();
            byte[] clear = changeClear(k.nonce, pin);
            assertTrue(clear.length > 64 && clear.length <= 96, what + ": three blocks of keystream: " + clear.length);
            assertEquals(SW_OK, sendSealed(CHANGE_INS, envelope(EPH[0], k.key, k.nonce, CHANGE_INS, clear)).getSW(), what);
            assertEquals(1, info()[7], what);
            assertEquals(3, tries(), what);
            assertFalse(verified(), what + ": the session that verified the old PIN is over");
            assertFalse(nonceLive(), what + ": the proof used the nonce up");
            assertEquals(SW_PIN_NEEDED, spend(0).getSW(), what);
            simulator.reset(); reselect();
            assertEquals(0x63C2, verify(TEST_PIN), what + ": the old PIN is wrong");
            assertEquals(SW_OK, verify(pin), what + ": the new one is right");
            assertEquals(SW_OK, spend(0).getSW(), what);
        }
        // a blocked card
        ownedPinCard();
        assertEquals(0x63C2, verify(WRONG_PIN)); assertEquals(0x63C1, verify(WRONG_PIN)); assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN));
        assertEquals(2, info()[7]);
        PinKey k = askPinKey();
        assertEquals(SW_OK, sendSealed(CHANGE_INS, envelope(EPH[0], k.key, k.nonce, CHANGE_INS, changeClear(k.nonce, NEW_PIN))).getSW());
        assertEquals(1, info()[7], "unblocked");
        assertEquals(3, tries());
        assertEquals(SW_OK, verify(NEW_PIN));
    }

    @Test
    @DisplayName("Sealed CHANGE_PIN with a proof over the PIN block instead of the PIN, with a wrong key's proof, or with a proof for another nonce is 6A91 and changes nothing; the nonce is used up whichever it was, a second CHANGE_PIN under it is 6985, and an envelope that does not open is 6A80 with the nonce gone")
    void testASealedChangePinWithABadProofIsRefused() throws Exception {
        ownedPinCard();
        PinKey k = askPinKey();
        byte[] overBlock = ownerProof(L_PIN, OWNER, k.nonce, pinBlock(NEW_PIN));
        java.util.Map<String, byte[]> before = persistent();
        assertEquals(SW_OWNER_PROOF, sendSealed(CHANGE_INS, envelope(EPH[0], k.key, k.nonce, CHANGE_INS,
            concat(new byte[] { (byte) overBlock.length }, overBlock, pinBlock(NEW_PIN)))).getSW(), "a proof over the block");
        assertPersistent(before, "and nothing changed");
        assertFalse(nonceLive(), "the proof was tried and the nonce is used");
        assertEquals(SW_OK, verify(TEST_PIN), "the PIN is as it was");
        // another key's proof, and another label's
        k = askPinKey();
        byte[] other = OTHER_OWNER.sign(concat(L_PIN.getBytes(StandardCharsets.US_ASCII), k.nonce, NEW_PIN));
        assertEquals(SW_OWNER_PROOF, sendSealed(CHANGE_INS, envelope(EPH[0], k.key, k.nonce, CHANGE_INS,
            concat(new byte[] { (byte) other.length }, other, pinBlock(NEW_PIN)))).getSW(), "another phone's proof");
        k = askPinKey();
        byte[] label = ownerProof(L_LIMIT, OWNER, k.nonce, NEW_PIN);
        assertEquals(SW_OWNER_PROOF, sendSealed(CHANGE_INS, envelope(EPH[0], k.key, k.nonce, CHANGE_INS,
            concat(new byte[] { (byte) label.length }, label, pinBlock(NEW_PIN)))).getSW(), "another command's proof");
        PinKey old = askPinKey();
        k = askPinKey();
        assertEquals(0x63C2, sendSealed(VERIFY_INS, envelope(EPH[0], k.key, k.nonce, VERIFY_INS, pinBlock(WRONG_PIN))).getSW(), "(a try gone, to be given back)");
        k = askPinKey();
        byte[] forOld = ownerProof(L_PIN, OWNER, old.nonce, NEW_PIN);
        assertEquals(SW_OWNER_PROOF, sendSealed(CHANGE_INS, envelope(EPH[0], k.key, k.nonce, CHANGE_INS,
            concat(new byte[] { (byte) forOld.length }, forOld, pinBlock(NEW_PIN)))).getSW(), "a proof for an earlier nonce");
        assertEquals(2, tries(), "no try cost by any of them");
        assertEquals(SW_OK, verify(TEST_PIN));
        // good once, then 6985
        k = askPinKey();
        byte[] env = envelope(EPH[0], k.key, k.nonce, CHANGE_INS, changeClear(k.nonce, NEW_PIN));
        assertEquals(SW_OK, sendSealed(CHANGE_INS, env).getSW());
        assertEquals(SW_CONDITIONS_NOT_SATIS, sendSealed(CHANGE_INS, env).getSW(), "a second CHANGE_PIN under the nonce is 6985");
        assertEquals(SW_OK, verify(NEW_PIN));
        // an envelope that does not open
        k = askPinKey();
        assertEquals(SW_WRONG_DATA, sendSealed(CHANGE_INS, spoiled(envelope(EPH[0], k.key, k.nonce, CHANGE_INS, changeClear(k.nonce, TEST_PIN)), "tag")).getSW());
        assertFalse(nonceLive(), "and the nonce is gone");
        assertEquals(SW_OWNER_PROOF, sw(changePinCommand(ownerProof(L_PIN, OWNER, k.nonce, TEST_PIN), TEST_PIN)), "for the clear form's proof as well");
    }

    @Test
    @DisplayName("The clear forms of VERIFY_PIN, SET_PIN and CHANGE_PIN with P1 = 0 are untouched by the sealed ones: each is sent after a sealed command on the same card and does what it did, and the clear form of CHANGE_PIN works under a P1 = 1 nonce")
    void testTheClearFormsStillWork() throws Exception {
        ownedPinCard();
        PinKey k = askPinKey();
        assertEquals(SW_OK, sendSealed(VERIFY_INS, envelope(EPH[0], k.key, k.nonce, VERIFY_INS, pinBlock(TEST_PIN))).getSW());
        assertEquals(SW_OK, verify(TEST_PIN), "clear VERIFY_PIN");
        assertEquals(0x63C2, verify(WRONG_PIN), "and clear, wrong");
        k = askPinKey();
        assertEquals(SW_OK, sw(changePinCommand(ownerProof(L_PIN, OWNER, k.nonce, NEW_PIN), NEW_PIN)), "clear CHANGE_PIN under a P1 = 1 nonce");
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OWNER_PROOF, setPin(TEST_PIN), "clear SET_PIN on an owned card");
        openPinCard();
        assertEquals(SW_OK, setPin(NEW_PIN), "clear SET_PIN on an open card");
        assertEquals(SW_OK, verify(NEW_PIN));
    }

    @Test
    @DisplayName("A P1 other than 0 or 1 (2, 0x80, 0xFF) on VERIFY_PIN, SET_PIN, CHANGE_PIN and GET_NONCE is 6A86, before anything else is looked at: on a card with no PIN, no owner, a locked card, a blocked one; nothing changes, no try is cost and the nonce is as it was")
    void testAnyOtherP1IsRefusedBeforeAnythingIsLooked() throws Exception {
        int[] inses = { VERIFY_INS, SET_INS, CHANGE_INS, INS_GET_NONCE & 0xFF };
        for (int variant = 0; variant < 3; variant++) {
            String state;
            if (variant == 0) { simulator = freshCard(); state = "no PIN, no owner"; }
            else if (variant == 1) { ownedPinCard(); askPinKey(); state = "an owner, a PIN, a nonce live"; }
            else {
                ownedPinCard();
                assertEquals(SW_OK, verify(TEST_PIN));
                assertEquals(SW_OK, lock());
                simulator.reset(); reselect();
                assertEquals(0x63C2, verify(WRONG_PIN)); assertEquals(0x63C1, verify(WRONG_PIN)); assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN));
                askPinKey();
                state = "locked and blocked, a nonce live";
            }
            for (int ins : inses) {
                for (int p1 : new int[] { 2, 0x80, 0xFF }) {
                    String what = String.format("%s, INS %02X, P1 %02X", state, ins, p1);
                    java.util.Map<String, byte[]> before = persistent();
                    byte[] nonceBefore = field("ownerNonce").clone(), liveBefore = field("nonceLive").clone(), verifiedBefore = field("pinVerifiedFlag").clone();
                    int triesBefore = tries();
                    ResponseAPDU r = transmit(ins == (INS_GET_NONCE & 0xFF) ? new CommandAPDU(CLA, ins, p1, 0, 256) : new CommandAPDU(CLA, ins, p1, 0, new byte[90]));
                    assertEquals(SW_INCORRECT_P1P2, r.getSW(), what);
                    assertEquals(0, r.getData().length, what);
                    assertPersistent(before, what);
                    assertArrayEquals(nonceBefore, field("ownerNonce"), what + ": the nonce");
                    assertArrayEquals(liveBefore, field("nonceLive"), what + ": and whether it is live");
                    assertArrayEquals(verifiedBefore, field("pinVerifiedFlag"), what + ": and the session");
                    assertEquals(triesBefore, tries(), what + ": no try");
                }
            }
        }
    }

    @Test
    @DisplayName("The PIN key and its signature survive the card leaving the field and are the same after it (the nonce is new); pinKeySig is persistent and the working room of a sealed command is RAM that holds the shared secret until the card is deselected")
    void testThePinKeyAndItsSignatureSurviveAReset() throws Exception {
        openPinCard();
        PinKey a = askPinKey();
        simulator.reset(); reselect();
        PinKey b = askPinKey();
        assertArrayEquals(a.key, b.key);
        assertArrayEquals(a.sig, b.sig);
        assertFalse(Arrays.equals(a.nonce, b.nonce));
        assertEquals(1, field("pinKeySig")[0]);
        assertEquals(SW_OK, sendSealed(VERIFY_INS, envelope(EPH[0], b.key, b.nonce, VERIFY_INS, pinBlock(TEST_PIN))).getSW());
        assertFalse(isAllZeros(field("seal")), "after a sealed command the shared secret and the last block are in RAM");
        reselect();
        assertTrue(isAllZeros(field("seal")), "and a SELECT clears them");
        PinKey c = askPinKey();
        assertArrayEquals(a.sig, c.sig, "and the signature is still the first one");
        String code = appletCode();
        String flat = code.replaceAll("\\s+", " ");
        assertTrue(flat.contains("pinKeySig = new byte[(short) 65];"), "pinKeySig is a persistent array");
        assertTrue(flat.contains("seal = scratch;"), "and seal is the applet's scratch by another name, RAM that a SELECT clears, and not an array of its own");
        assertFalse(flat.contains("seal = JCSystem.makeTransientByteArray"), "which would be 99 more bytes of the memory the chip limits");
        assertSame(appletObject("scratch"), appletObject("seal"), "the same array");
        assertTrue(flat.contains("pinKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);"), "the PIN key is a KeyPair made of its own");
    }

    /** The APDU buffer as the applet left it: the command as it came, and what the card did to it. */
    private byte[] leftInTheBuffer(int length) {
        return Arrays.copyOf(runtime.getCurrentAPDU().getBuffer(), length);
    }

    @Test
    @DisplayName("The clear text of a sealed command arrives at OFFSET_CDATA whole, whatever its length (1, 9, 32, 33, 64, 65 and 81 bytes, either side of the 65 that E takes and of the 32 of a block), and nothing past its end is written: the buffer is the command as it came, with the clear text where the ciphertext was, and that moved down over the start of E, byte for byte")
    void testTheClearTextArrivesAtTheDataWholeAndNothingIsWrittenPastIt() throws Exception {
        for (int n : new int[] { 1, 9, 32, 33, 64, 65, 81 }) {
            String what = n + " bytes of clear text";
            openPinCard();
            PinKey k = askPinKey();
            byte[] clear = new byte[n];
            for (int i = 0; i < n; i++) clear[i] = (byte) (0x41 + i);
            if (n == 9) clear[0] = 0;       // a block of length 0, which unblockPin refuses before it moves anything
            byte[] env = envelope(EPH[1], k.key, k.nonce, VERIFY_INS, clear);
            assertEquals(SW_WRONG_LENGTH, sendSealed(VERIFY_INS, env).getSW(), what + ": opened, and refused for its length");
            byte[] want = concat(new byte[] { CLA, (byte) VERIFY_INS, 1, 0, (byte) env.length }, Arrays.copyOfRange(env, 0, 65), clear, Arrays.copyOfRange(env, env.length - 16, env.length));
            for (int i = 0; i < n; i++) want[5 + i] = want[5 + 65 + i];
            assertArrayEquals(want, leftInTheBuffer(want.length), what + ": exactly n bytes moved, from the ciphertext's place to the data's, and the rest as it was");
            assertArrayEquals(clear, Arrays.copyOfRange(leftInTheBuffer(5 + n), 5, 5 + n), what + ": and the clear text is at OFFSET_CDATA");
        }
    }

    @Test
    @DisplayName("unblockPin moves exactly the PIN (4 to 8 bytes) down over its length byte and touches nothing else: after a sealed CHANGE_PIN the buffer is the clear text with the PIN one byte down, byte for byte, and the owner's proof before the block verified")
    void testUnblockPinLeavesEverythingBeforeTheBlockAlone() throws Exception {
        byte[][] pins = { TEST_PIN, PIN5, { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 }, { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 }, PIN8 };
        for (byte[] pin : pins) {
            String what = pin.length + "-byte PIN";
            ownedPinCard();
            PinKey k = askPinKey();
            byte[] clear = changeClear(k.nonce, pin);
            byte[] env = envelope(EPH[1], k.key, k.nonce, CHANGE_INS, clear);
            assertEquals(SW_OK, sendSealed(CHANGE_INS, env).getSW(), what + ": the proof, before the block, is as it was sent");
            byte[] want = concat(new byte[] { CLA, (byte) CHANGE_INS, 1, 0, (byte) env.length }, Arrays.copyOfRange(env, 0, 65), clear, Arrays.copyOfRange(env, env.length - 16, env.length));
            for (int i = 0; i < clear.length; i++) want[5 + i] = want[5 + 65 + i];
            int block = 5 + clear.length - 9;
            for (int i = 0; i < pin.length; i++) want[block + i] = want[block + 1 + i];
            assertArrayEquals(want, leftInTheBuffer(want.length), what + ": the PIN moved down one byte, and nothing past it");
            assertArrayEquals(pin, Arrays.copyOfRange(leftInTheBuffer(block + pin.length), block, block + pin.length), what);
            assertEquals(SW_OK, verify(pin) , what + ": and it is the PIN");
        }
    }

    @Test
    @DisplayName("GET_NONCE with P1 = 1 compresses the PIN key in the sealing room and copies it from there: the answer is the nonce, then the key at byte 16, then the signature; the room holds the key and nothing an opening trips over (its first byte is 02 or 03, not the 04 an opening looks for), and a command sealed straight after opens, as does one after a failed opening")
    void testTheKeyAskedForLeavesNothingInTheSealingRoomThatAnOpeningTripsOver() throws Exception {
        openPinCard();
        PinKey k = askPinKey();
        assertArrayEquals(concat(k.nonce, k.key, k.sig), k.all, "nonce || key || signature");
        assertArrayEquals(Arrays.copyOfRange(k.all, 16, 49), k.key, "the key is at 16");
        assertArrayEquals(k.key, Arrays.copyOf(field("seal"), 33), "and was compressed in the room");
        assertTrue(field("seal")[0] == 2 || field("seal")[0] == 3, "which leaves 02 or 03 where the shared point's 04 is looked for");
        assertEquals(SW_OK, sendSealed(VERIFY_INS, envelope(EPH[0], k.key, k.nonce, VERIFY_INS, pinBlock(TEST_PIN))).getSW(), "a command sealed straight after opens");
        k = askPinKey();
        assertEquals(0x63C2, sendSealed(VERIFY_INS, spoiled(envelope(EPH[0], k.key, k.nonce, VERIFY_INS, pinBlock(TEST_PIN)), "point")).getSW(), "a point that is no point, straight after the key was asked, does not open");
        k = askPinKey();
        assertEquals(SW_OK, sendSealed(VERIFY_INS, envelope(EPH[0], k.key, k.nonce, VERIFY_INS, pinBlock(TEST_PIN))).getSW(), "and the asking and the sealing after a failed opening are as before");
        assertEquals(3, tries());
    }

    /** { bytes, arrays } of byte arrays this runtime holds as transient, by kind: { CLEAR_ON_DESELECT, CLEAR_ON_RESET }. */
    private static long[][] transientHeld(SimulatorRuntime rt) throws Exception {
        com.licel.jcardsim.base.TransientMemory memory = rt.getTransientMemory();
        long[][] held = new long[2][2];
        String[] lists = { "clearOnDeselect", "clearOnReset" };
        for (int k = 0; k < 2; k++) {
            java.lang.reflect.Field f = com.licel.jcardsim.base.TransientMemory.class.getDeclaredField(lists[k]);
            f.setAccessible(true);
            for (Object o : (java.util.List<?>) f.get(memory)) {
                if (o instanceof byte[]) { held[k][0] += ((byte[]) o).length; held[k][1]++; }
            }
        }
        return held;
    }

    @Test
    @DisplayName("jCardSim's own count: what installing the applet adds to the transient byte arrays the simulator holds as cleared on deselect is 941 bytes in 14 arrays (CashuApplet's 12 and SchnorrHW's 2), the figure of the build that installs on the chip; the two it clears on reset are 6 bytes (the time the terminal told, 4, and the tap's two flags). A larger build has to be measured on a card to exceed it")
    void testInstallingAsksForNoMoreTransientMemoryThanTheBuildThatInstalls() throws Exception {
        ExposedRuntime fresh = new ExposedRuntime();
        long[][] before = transientHeld(fresh);
        CardSimulator sim = new CardSimulator(fresh);
        sim.installApplet(AIDUtil.create(AID_HEX), CashuApplet.class);
        long[][] after = transientHeld(fresh);
        long deselect = after[0][0] - before[0][0], arrays = after[0][1] - before[0][1];
        String why = " These are the figures of 1.12 (941 bytes cleared on deselect, 8 on reset, 16 arrays in all: 1.11's 931 and 14, and the change and the net of a payment); 1.15 asks for 6 on reset (the told time is 4 where the clock's flags were 6); a larger figure has to be measured on a card first.";
        assertTrue(deselect <= 941, "installing holds " + deselect + " bytes that are cleared on deselect, over 941." + why);
        assertTrue(arrays <= 14, "installing makes " + arrays + " arrays that are cleared on deselect, over 14." + why);
        // the arrays the applet clears on reset are two of the simulator's list of such, which also holds what its own crypto and PIN objects keep (not the chip's count)
        Applet installed = fresh.appletAt(AIDUtil.create(AID_HEX));
        java.lang.reflect.Field fTold = CashuApplet.class.getDeclaredField("tapTime"), fOpen = CashuApplet.class.getDeclaredField("tapOpen");
        fTold.setAccessible(true); fOpen.setAccessible(true);
        byte[] tapTime = (byte[]) fTold.get(installed), tapOpen = (byte[]) fOpen.get(installed);
        assertEquals(6, tapTime.length + tapOpen.length, "the applet's own arrays that are cleared on reset: 4 and 2");
        com.licel.jcardsim.base.TransientMemory memory = fresh.getTransientMemory();
        java.lang.reflect.Field onReset = com.licel.jcardsim.base.TransientMemory.class.getDeclaredField("clearOnReset");
        onReset.setAccessible(true);
        boolean a = false, b = false;
        for (Object o : (java.util.List<?>) onReset.get(memory)) { a |= o == tapTime; b |= o == tapOpen; }
        assertTrue(a && b, "and both are in the simulator's list");
        // a count that found nothing would prove nothing, and the source's figure is the simulator's
        assertEquals(941, deselect, "the simulator holds what the source asks for");
        assertEquals(14, arrays);
        assertEquals(SchnorrHWMathTest.transientMemoryAskedFor()[0], (int) deselect, "and the source's sum is the simulator's count");
    }

    // ---- the sealing room is the scratch (1.9): what that may and may not touch ----------------------------------

    @Test
    @DisplayName("A sealed command between the steps of a payment drops the payment (SPEND_ALL_SIGN is then 6985) and leaves the next one sound: a sealed VERIFY_PIN, a sealed CHANGE_PIN (three blocks of keystream) and GET_NONCE with P1 = 1 each, then a payment that signs and verifies, with the log and the receipt as they should be")
    void testASealedCommandBetweenThePaymentsStepsDropsItAndLeavesTheNextOneSound() throws Exception {
        for (int variant = 0; variant < 3; variant++) {
            String what = new String[] { "a sealed VERIFY_PIN", "a sealed CHANGE_PIN", "GET_NONCE P1 = 1" }[variant];
            simulator = freshCard();
            ownPinKey();
            ready();
            byte[][] sent = loadMany(6, i -> buildProof(KEYSET, 10 + i, i + 1));
            PinKey k = variant == 2 ? null : askPinKey();
            byte[][] outputs = { output(3, blinded(1)) };
            assertEquals(SW_OK, sw(beginCommand(0, 1, 2)), what);
            assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, concat(outputs))), what);
            if (variant == 0) assertEquals(SW_OK, sendSealed(VERIFY_INS, envelope(EPH[0], k.key, k.nonce, VERIFY_INS, pinBlock(TEST_PIN))).getSW(), what);
            if (variant == 1) assertEquals(SW_OK, sendSealed(CHANGE_INS, envelope(EPH[0], k.key, k.nonce, CHANGE_INS, changeClear(k.nonce, NEW_PIN))).getSW(), what);
            if (variant == 2) askPinKey();
            assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), what + ": the payment was dropped");
            assertEquals(6 * 10 + 15, balance() + 0, what + ": nothing burned");
            if (variant == 1) assertEquals(SW_OK, verify(NEW_PIN), what + ": the new PIN");
            else if (variant == 0) assertTrue(verified());
            // a fresh payment of other places, with one output
            ResponseAPDU r = spendAll(new int[] { 3, 4, 5 }, outputs);
            assertEquals(SW_OK, r.getSW(), what);
            byte[][] named = { asSlot(sent[3]), asSlot(sent[4]), asSlot(sent[5]) };
            assertTrue(signedForAll(r.getData(), named, outputs, REFUND), what + ": the signature is over the places named");
            assertEquals(75 - 13 - 14 - 15, balance(), what);
            assertArrayEquals(new long[] { T0, 13 + 14 + 15, 3, 0, 0 }, logTap(0), what + ": the log");
            assertEquals(SW_OK, allowLoad(), what);
            Held held = heldReceipts();
            assertEquals(1, held.count, what + ": one receipt, the dropped payment's is none");
            assertArrayEquals(receiptFor(T0, 13 + 14 + 15, named, outputs), held.receipts.get(0), what + ": the receipt");
        }
    }

    @Test
    @DisplayName("GET_NONCE with P1 = 1 between LOAD_PROOFs, and a sealed VERIFY_PIN right before a LOAD_PROOF of three pieces, leave the hex text in slotHex and everything else a load writes as a load with nothing between writes them, and the pieces pay and verify")
    void testTheSealingRoomDoesNotTouchWhatALoadWrites() throws Exception {
        java.util.Map<String, byte[]> reference = null;
        for (boolean interleaved : new boolean[] { false, true }) {
            simulator = freshCard();
            ownPinKey();
            ready();
            byte[][] pieces = new byte[7][];
            for (int i = 0; i < 7; i++) pieces[i] = buildProof(KEYSET, 20 + i, i + 1, i == 2 ? 1900000000L : 0);
            for (int i = 0; i < 4; i++) {
                if (interleaved) askPinKey();
                assertEquals(i, load(pieces[i]).getData()[0], "piece " + i);
            }
            if (interleaved) {
                PinKey k = askPinKey();
                assertEquals(SW_OK, sendSealed(VERIFY_INS, envelope(EPH[1], k.key, k.nonce, VERIFY_INS, pinBlock(TEST_PIN))).getSW());
            }
            ResponseAPDU batch = loadBatch(pieces[4], pieces[5], pieces[6]);
            assertEquals(SW_OK, batch.getSW());
            assertArrayEquals(new byte[] { 4, 5, 6 }, batch.getData());
            byte[][] outputs = { output(5, blinded(2)) };
            ResponseAPDU r = spendAll(new int[] { 0, 1, 3, 4, 5, 6 }, outputs);
            assertEquals(SW_OK, r.getSW());
            byte[][] named = new byte[7][];
            for (int i = 0; i < 7; i++) named[i] = asSlot(pieces[i]);
            assertTrue(signedForAll(r.getData(), new byte[][] { named[0], named[1], named[3], named[4], named[5], named[6] }, outputs, REFUND), "the payment, which hashes the hex text of the places, is signed over the text as it was sent");
            ResponseAPDU dated = spendAll(new int[] { 2 }, outputs);
            assertEquals(SW_OK, dated.getSW());
            assertTrue(signedForAll(dated.getData(), new byte[][] { named[2] }, outputs, REFUND), "and so is the one piece with a date, which a payment of its own has to be");
            java.util.Map<String, byte[]> state = persistent();
            if (!interleaved) {
                reference = state;
            } else {
                for (String name : new String[] { "proofStorage", "slotHex", "cardLog", "cardReceipts", "cardRecord", "burnList" }) {
                    assertArrayEquals(reference.get(name), state.get(name), name + ": the same with the sealing room used between the loads");
                }
            }
        }
    }

    /** One conversation that uses every kind of scratch, with sealed commands among it; answers written down, and what lasts at the end. */
    private java.util.List<String> aConversationInTheScratch(long poisonSeed) throws Exception {
        simulator = freshCard();
        scratchPoison = poisonSeed < 0 ? null : new java.util.Random(poisonSeed);
        answersRecorded = new java.util.ArrayList<>();
        ownPinKey();
        ready();
        byte[][] pieces = new byte[9][];
        for (int i = 0; i < 9; i++) pieces[i] = buildProof(KEYSET, 30 + 7 * i, i + 1, i == 1 || i == 7 ? 1900000000L : 0);
        assertEquals(0, load(pieces[0]).getData()[0]);
        PinKey k = askPinKey();
        assertEquals(1, load(pieces[1]).getData()[0]);
        assertEquals(SW_OK, loadBatch(pieces[2], pieces[3], pieces[4]).getSW());
        assertEquals(SW_OK, sendSealed(VERIFY_INS, envelope(EPH[0], k.key, k.nonce, VERIFY_INS, pinBlock(TEST_PIN))).getSW());
        assertEquals(SW_OK, loadBatch(pieces[5], pieces[6], pieces[7]).getSW());
        info(); infoTap(); pieces(0); shortPieces(0); somePieces(new byte[] { 1, 2 }); slot(3); balance();
        transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256));
        assertEquals(SW_OK, spendAll(new int[] { 0, 2 }, new byte[][] { output(9, blinded(1)) }).getSW());
        transmit(new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64));
        assertEquals(SW_OK, spendAll(new int[] { 1 }, new byte[][] { output(2, blinded(5)) }).getSW());
        transmit(new CommandAPDU(CLA, INS_AUTH, 0, 0, hexToBytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"), 80));
        assertEquals(SW_OK, setTime(T0 + 5));
        // the clock's commands use the scratch for their arithmetic (the hash, the targets, four times the best), and read nothing an earlier command left in it
        assertEquals(SW_OK, tell(T0 + 6));
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(unmined(T0 + 9, TEST_BITS))));
        assertEquals(SW_WRONG_DATA, sw(setHeaderCommand(header(0x20000000L, new byte[32], new byte[32], T0 + 9, 0x2100FFFFL, 0))));
        assertEquals(SW_OK, sw(setHeaderCommand(mine(T0 + 7, 0x1F0FFFFFL, 4))), "a harder header than the best: its bits are kept");
        assertEquals(SW_LITTLE_WORK, sw(setHeaderCommand(mine(T0 + 8, 0x20010000L, 4))), "and one over four times it is refused");
        cardRecord();
        k = askPinKey();
        assertEquals(0x63C2, sendSealed(VERIFY_INS, spoiled(envelope(EPH[1], k.key, k.nonce, VERIFY_INS, pinBlock(TEST_PIN)), "point")).getSW());
        assertEquals(SW_OK, verify(TEST_PIN));
        k = askPinKey();
        assertEquals(SW_OK, sendSealed(CHANGE_INS, envelope(EPH[2], k.key, k.nonce, CHANGE_INS, changeClear(k.nonce, NEW_PIN))).getSW());
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, spendAll(new int[] { 3, 4, 5 }, new byte[][] { output(4, blinded(2)), output(6, blinded(3)) }).getSW());
        logAnswer();
        assertEquals(SW_OK, allowLoad());
        heldReceipts();
        assertEquals(SW_OK, clearSpent());
        assertEquals(SW_OK, load(pieces[8]).getSW());
        assertEquals(SW_OK, setLimits(0, 40));
        ResponseAPDU waited = spendAll(new int[] { 6, 0 }, new byte[][] { output(7, blinded(4)) });   // the piece loaded last lies in the first place CLEAR_SPENT freed
        assertEquals(SW_OK, waited.getSW());
        assertTrue(waitsTaken() > 0, "a payment that waits uses the scratch for the work of every wait");
        k = askPinKey();
        assertEquals(SW_OK, sendSealed(VERIFY_INS, envelope(EPH[3], k.key, k.nonce, VERIFY_INS, pinBlock(NEW_PIN))).getSW());
        transmit(new CommandAPDU(CLA, INS_AUTH, 0, 0, hexToBytes("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"), 80));
        logAnswer();
        java.util.List<String> said = answersRecorded;
        java.util.Map<String, byte[]> state = persistent();
        for (java.util.Map.Entry<String, byte[]> e : state.entrySet()) said.add(e.getKey() + "=" + toHex(e.getValue()));
        scratchPoison = null;
        answersRecorded = null;
        return said;
    }

    @Test
    @DisplayName("Nothing reads what an earlier command left in the scratch: one conversation of every kind of command, with sealed ones among them, is answered byte for byte the same, signatures and all, and leaves the card in the same state, with the whole scratch filled with other rubbish before every command (three different kinds) as with it as it was")
    void testNoCommandReadsWhatAnEarlierOneLeftInTheScratch() throws Exception {
        java.util.List<String> clean = aConversationInTheScratch(-1);
        assertTrue(clean.size() > 60, "the conversation is long: " + clean.size());
        for (long seed : new long[] { 1, 2, 3 }) {
            java.util.List<String> poisoned = aConversationInTheScratch(seed);
            assertEquals(clean.size(), poisoned.size(), "seed " + seed);
            for (int i = 0; i < clean.size(); i++) assertEquals(clean.get(i), poisoned.get(i), "seed " + seed + ": answer or state " + i);
        }
    }

    @Test
    @DisplayName("Sealed VERIFY_PIN, sealed CHANGE_PIN and a point that is no point, alternated with payments over and over, never spoil a signature: SchnorrHW.agree sets its key for the key agreement and the signer sets its own before every use; and AUTH, which signs from the same scratch, verifies after each")
    void testSigningAfterAKeyAgreementStillVerifies() throws Exception {
        simulator = freshCard();
        ownPinKey();
        ready();
        byte[][] sent = loadMany(12, i -> buildProof(KEYSET, 10 + i, i + 1));
        for (int round = 0; round < 6; round++) {
            String what = "round " + round;
            PinKey k = askPinKey();
            if (round % 3 == 0) assertEquals(SW_OK, sendSealed(VERIFY_INS, envelope(EPH[round % 6], k.key, k.nonce, VERIFY_INS, pinBlock(TEST_PIN))).getSW(), what + ": a sealed VERIFY_PIN");
            else if (round % 3 == 1) assertEquals(0x63C2, sendSealed(VERIFY_INS, spoiled(envelope(EPH[round % 6], k.key, k.nonce, VERIFY_INS, pinBlock(TEST_PIN)), "point")).getSW(), what + ": a point that is no point");
            else assertEquals(SW_OK, sendSealed(CHANGE_INS, envelope(EPH[round % 6], k.key, k.nonce, CHANGE_INS, changeClear(k.nonce, TEST_PIN))).getSW(), what + ": a sealed CHANGE_PIN");
            assertEquals(SW_OK, verify(TEST_PIN), what);
            byte[][] outputs = { output(1 + round, blinded(round)) };
            ResponseAPDU r = spendAll(new int[] { 2 * round, 2 * round + 1 }, outputs);
            assertEquals(SW_OK, r.getSW(), what);
            assertTrue(signedForAll(r.getData(), new byte[][] { asSlot(sent[2 * round]), asSlot(sent[2 * round + 1]) }, outputs, REFUND), what + ": the payment's signature verifies");
            byte[] reader = new byte[16];
            reader[0] = (byte) round;
            ResponseAPDU auth = transmit(new CommandAPDU(CLA, INS_AUTH, 0, 0, reader, 80));
            assertEquals(SW_OK, auth.getSW(), what);
            byte[] key = cardKey();
            assertTrue(schnorrVerify(extractPubkeyX(key), authMessage(reader, Arrays.copyOfRange(auth.getData(), 0, 16), key), Arrays.copyOfRange(auth.getData(), 16, 80)), what + ": and so does AUTH's");
        }
    }

    /** The method bodies of a stripped source, by name. */
    private static java.util.Map<String, String> methodBodies(String code) {
        java.util.Map<String, String> bodies = new java.util.LinkedHashMap<>();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?m)^    (?:(?:public|private|protected|static|final)\\s+)+[\\w.\\[\\]]+\\s+(\\w+)\\s*\\([^)]*\\)\\s*\\{").matcher(code);
        while (m.find()) {
            int depth = 1, at = m.end();
            while (depth > 0) {
                char c = code.charAt(at++);
                if (c == '{') depth++; else if (c == '}') depth--;
            }
            bodies.put(m.group(1), code.substring(m.start(), at));
        }
        return bodies;
    }

    /** Every method a command can reach, by name, itself included. */
    private static java.util.Set<String> reached(String entry, java.util.Map<String, String> bodies) {
        java.util.Set<String> seen = new java.util.LinkedHashSet<>();
        java.util.ArrayDeque<String> todo = new java.util.ArrayDeque<>();
        todo.add(entry);
        while (!todo.isEmpty()) {
            String name = todo.poll();
            if (!seen.add(name)) continue;
            java.util.regex.Matcher c = java.util.regex.Pattern.compile("(?<![.\\w])(\\w+)\\s*\\(").matcher(bodies.get(name));
            while (c.find()) if (bodies.containsKey(c.group(1)) && !seen.contains(c.group(1))) todo.add(c.group(1));
        }
        return seen;
    }

    private static int shortConstant(String name) throws Exception {
        java.lang.reflect.Field f = CashuApplet.class.getDeclaredField(name);
        f.setAccessible(true);
        return f.getShort(null);
    }

    @Test
    @DisplayName("The sealing room in the source: it is the first 99 bytes of the scratch and no more (S_LEN <= X_LEN), its parts are disjoint, X_NUM, X_SUM, X_TAP and X_OUT lie past it; only VERIFY_PIN, SET_PIN, CHANGE_PIN and GET_NONCE reach it, none of the first three reaches any scratch offset at all, and GET_NONCE's key leaves the room before the digest writes X_MSG, which does not overlap what the key occupied")
    void testWhoUsesTheSealingRoomAndWhatElseLivesWhereItIs() throws Exception {
        // ---- the layout
        int sPoint = shortConstant("S_POINT"), sHash = shortConstant("S_HASH"), sI = shortConstant("S_I"), sIns = shortConstant("S_INS"), sLen = shortConstant("S_LEN"), xLen = shortConstant("X_LEN");
        assertEquals(0, sPoint);
        assertEquals(sPoint + 65, sHash, "the shared point (65 bytes) then a block of the hash (32)");
        assertEquals(sHash + 32, sI, "then the counter");
        assertEquals(sI + 1, sIns, "then the instruction");
        assertEquals(sIns + 1, sLen, "and that is the room");
        assertEquals(99, sLen);
        assertTrue(sLen <= xLen, "the room is within the scratch");
        int xHex = shortConstant("X_HEX"), xMsg = shortConstant("X_MSG"), xDec = shortConstant("X_DEC"), xNum = shortConstant("X_NUM"), xSum = shortConstant("X_SUM"), xTap = shortConstant("X_TAP"), xOut = shortConstant("X_OUT");
        for (int x : new int[] { xNum, xSum, xTap, xOut }) assertTrue(x >= sLen, "an offset the room does not reach: " + x);
        assertTrue(xHex < sLen && xMsg < sLen && xDec < sLen, "the hex text, the message and a date's digits are the offsets the room does overlap");
        // ---- who reaches the room, and what else they reach
        String code = appletCode();
        java.util.Map<String, String> bodies = methodBodies(code);
        java.util.Set<String> inRoom = new java.util.TreeSet<>(), commands = new java.util.TreeSet<>();
        java.util.regex.Matcher dispatched = java.util.regex.Pattern.compile("case INS_\\w+:\\s*(process\\w+)\\(apdu\\)").matcher(bodies.get("process"));
        while (dispatched.find()) commands.add(dispatched.group(1));
        assertTrue(commands.size() >= 25, "the commands found in the dispatch: " + commands.size());
        for (String command : commands) {
            boolean seals = false, scratches = false;
            for (String name : reached(command, bodies)) {
                String body = bodies.get(name);
                if (java.util.regex.Pattern.compile("\\bseal\\b|\\bS_(?:POINT|HASH|I|INS|LEN)\\b").matcher(body).find()) seals = true;
                if (java.util.regex.Pattern.compile("\\bscratch\\b|\\bX_[A-Z]+\\b").matcher(body).find()) scratches = true;
            }
            if (seals) inRoom.add(command);
            if (seals && !command.equals("processGetNonce")) assertFalse(scratches, command + " uses the room and must use no scratch offset at all");
        }
        assertEquals(new java.util.TreeSet<>(Arrays.asList("processVerifyPin", "processSetPin", "processChangePin", "processGetNonce")), inRoom, "the commands that reach the room");
        // ---- GET_NONCE's key, and the digest
        String pk = bodies.get("processGetPinKey").replaceAll("\\s+", " ");
        int keyOut = pk.indexOf("Util.arrayCopyNonAtomic(seal, (short) 0, buf, at, len);"), digest = pk.indexOf("sha.doFinal(buf, at, len, scratch, X_MSG);"), signs = pk.indexOf("schnorrHW.sign(cardPrivKey, cardPubKey, scratch, X_MSG, buf, sigAt);");
        assertTrue(pk.indexOf("short len = toCompressed(seal, pinPubKey.getW(seal, (short) 0));") >= 0 && keyOut > 0 && keyOut < digest && digest < signs, "the key is compressed in the room and copied out of it before the digest is written to X_MSG, and signed after");
        assertTrue(xMsg >= 33, "and the digest's place, " + xMsg + " to " + (xMsg + 32) + ", is past the 33 bytes the key took");
        java.util.Set<String> scratchInGetPinKey = new java.util.TreeSet<>();
        java.util.regex.Matcher tokens = java.util.regex.Pattern.compile("\\bX_[A-Z]+\\b").matcher(pk);
        while (tokens.find()) scratchInGetPinKey.add(tokens.group());
        assertEquals(new java.util.TreeSet<>(Arrays.asList("X_MSG")), scratchInGetPinKey, "GET_NONCE's key uses X_MSG of the scratch and no other part");
        assertEquals(2, count(pk, "scratch,"), "and passes the scratch twice, to the digest and to the signer");
    }

    @Test
    @DisplayName("The sealed path in the source: the length, then the nonce (spent where the caller says so, refused where it is not live), then the tag against block 0 before anything is opened, and a failed opening uses the nonce up and returns -1 before the first XOR; the keystream counter begins at 1 and the tag block is 0; the sum has the label, the counter, the shared x, E, the nonce and the instruction; the three callers; GET_NONCE's two forms")
    void testTheSealedPathIsInTheSourceWhatItsDescriptionSays() throws Exception {
        String code = appletCode();
        assertEquals(16, CashuApplet.SEAL_TAG_LEN);
        assertEquals(9, CashuApplet.PIN_BLOCK_LEN);
        assertEquals(113, CashuApplet.PIN_KEY_ANSWER);
        // ---- unseal
        String u = body(code, "private short unseal(", "private static void moveDown(").replaceAll("\\s+", " ");
        int[] at = new int[14];
        String[] steps = {
            "if (len < (short)(EC_POINT_LEN + 1 + SEAL_TAG_LEN)) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);",
            "boolean live = nonceLive[0] == (byte) 1;",
            "if (spend) nonceLive[0] = (byte) 0;",
            "if (!live) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);",
            "seal[S_INS] = buf[ISO7816.OFFSET_INS];",
            "if (buf[e] == (byte) 0x04) {",
            "short got = schnorrHW.agree(pinPrivKey, buf, e, EC_POINT_LEN, seal, S_POINT);",
            "sealBlock(buf, e, (byte) 0, buf, ct, n);",
            "good = sameBytes(seal, S_HASH, buf, tag, SEAL_TAG_LEN);",
            "if (!good) { nonceLive[0] = (byte) 0; return (short) -1; }",
            "short i = 1;",
            "buf[(short)(ct + at + k)] ^= seal[(short)(S_HASH + k)];",
            "moveDown(buf, ct, e, n);" };
        int from = 0;
        for (int s = 0; s < steps.length; s++) {
            at[s] = u.indexOf(steps[s], from);
            assertTrue(at[s] >= 0, "unseal has, in this order: " + steps[s]);
            from = at[s];
        }
        assertEquals(1, count(u, "^="), "one XOR in all, after the tag is checked");
        assertTrue(u.contains("} catch (RuntimeException x) { good = false; } if (!good) {"), "whatever the key agreement throws, the envelope does not open, and the very next thing is the test of whether it did");
        assertFalse(u.contains("CryptoException"), "the catch is not narrowed to one platform's exception");
        assertEquals(3, java.util.regex.Pattern.compile("\\bgood\\s*=").matcher(u).results().count(), "good is set three times: false to begin with, false in the catch, and by the tag's comparison");
        assertFalse(u.contains("good = true"), "and never to true but by the comparison of the tag");
        assertTrue(u.contains("good = sameBytes(seal, S_HASH, buf, tag, SEAL_TAG_LEN);"), "which is the one place it takes another value");
        assertEquals(0, count(u, "arrayCopy"), "unseal moves its clear text with moveDown and nothing else");
        assertTrue(u.contains("if (got == EC_POINT_LEN && seal[S_POINT] == (byte) 0x04) {"), "and so is an answer that is not a point");
        assertTrue(u.contains("sealBlock(buf, e, (byte) i, buf, (short) 0, (short) 0);"), "the keystream block i, with nothing more");
        assertTrue(u.contains("for (short at = 0; at < n; at += (short) 32) {") && u.contains("k < (short) 32 && (short)(at + k) < n"), "thirty-two bytes a block, to the end of the data");
        assertTrue(u.contains("short n = (short)(len - EC_POINT_LEN - SEAL_TAG_LEN);") && u.contains("short ct = (short)(e + EC_POINT_LEN);") && u.contains("short tag = (short)(ct + n);"), "E, the data, the tag");
        assertEquals(1, count(u, "i++"), "the counter goes up by one a block");
        // ---- the sum
        String b = body(code, "private void sealBlock(", "private short unblockPin(").replaceAll("\\s+", " ");
        String[] sum = { "seal[S_I] = i;", "sha.reset();", "sha.update(SEAL_LABEL, (short) 0, (short) SEAL_LABEL.length);", "sha.update(seal, S_I, (short) 1);",
            "sha.update(seal, (short)(S_POINT + 1), (short) 32);", "sha.update(buf, e, EC_POINT_LEN);", "sha.update(ownerNonce, (short) 0, OWNER_NONCE_LEN);",
            "sha.update(seal, S_INS, (short) 1);", "sha.doFinal(more, moreAt, moreLen, seal, S_HASH);" };
        from = 0;
        for (String s : sum) {
            int found = b.indexOf(s, from);
            assertTrue(found >= 0, "the sum, in this order: " + s);
            from = found;
        }
        assertTrue(code.contains("S_POINT = (short) 0;") && code.contains("S_HASH  = (short) 65;"), "the shared point first, 04 || x || y, and the block after its 65 bytes");
        // ---- the block
        String ub = body(code, "private short unblockPin(", "private void processAllowLoad(").replaceAll("\\s+", " ");
        assertTrue(ub.contains("if (len < PIN_BLOCK_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);") && ub.contains("short block = (short)(ISO7816.OFFSET_CDATA + len - PIN_BLOCK_LEN);")
            && ub.contains("short pinLen = (short)(buf[block] & 0xFF);") && ub.contains("if (pinLen < PIN_MIN_LEN || pinLen > PIN_MAX_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);")
            && ub.contains("moveDown(buf, (short)(block + 1), block, pinLen);") && ub.contains("return (short)(len - PIN_BLOCK_LEN + pinLen);"),
            "the block is the last nine bytes, its length is 4 to 8, and the PIN is moved down over it");
        assertEquals(0, count(ub, "arrayCopy"), "unblockPin moves the PIN with moveDown too");
        String md = body(code, "private static void moveDown(", "private void sealBlock(").replaceAll("\\s+", " ");
        assertTrue(md.contains("for (short k = 0; k < len; k++) { buf[(short)(to + k)] = buf[(short)(from + k)]; }"), "moveDown: len bytes, from the front, from + k to to + k");
        assertEquals(1, count(md, "for ("), "one loop");
        assertEquals(3, count(code, "moveDown("), "its declaration and its two callers");
        assertTrue(code.contains("moveDown(buf, ct, e, n);") && code.contains("moveDown(buf, (short)(block + 1), block, pinLen);"), "the clear text down over E, and the PIN down over its length byte");
        // ---- who calls it
        assertEquals(4, count(code, "unseal("), "its declaration and three callers");
        assertEquals(2, count(code, "unseal(buf, pinLen, true)"), "VERIFY_PIN and SET_PIN spend the nonce");
        assertEquals(1, count(code, "unseal(buf, dataLen, false)"), "CHANGE_PIN leaves it for the proof");
        assertEquals(2, count(code, "nonceLive[0] = (byte) 1;"), "the nonce is made live by GET_NONCE's two forms and nowhere else");
        assertEquals(3, count(code, "nonceLive[0] = (byte) 0;"), "and used up by unseal (twice) and by the owner's proof");
        // ---- VERIFY_PIN, SET_PIN, CHANGE_PIN
        String v = body(code, "private void processVerifyPin(", "private void failPinCheck(").replaceAll("\\s+", " ");
        String[] verify = { "boolean sealed = sealedForm(buf);", "if (pinState[0] == (byte) 0) ISOException.throwIt(SW_PIN_NOT_SET);", "if (pinState[0] == (byte) 2 || pin.getTriesRemaining() == 0) ISOException.throwIt(SW_PIN_BLOCKED);",
            "short pinLen = apdu.setIncomingAndReceive();", "pinLen = unseal(buf, pinLen, true);", "if (pinLen < 0) {", "rng.generateData(seal, S_HASH, (short) 8);",
            "pin.check(seal, S_HASH, (byte) 8);", "failPinCheck();", "if (pinLen != PIN_BLOCK_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);", "pinLen = unblockPin(buf, pinLen);",
            "if (pinLen < PIN_MIN_LEN || pinLen > PIN_MAX_LEN) {", "boolean ok = pin.check(buf, ISO7816.OFFSET_CDATA, (byte) pinLen);", "if (!ok) failPinCheck();", "pinVerifiedFlag[0] = (byte) 1;" };
        from = 0;
        for (String s : verify) {
            int found = v.indexOf(s, from);
            assertTrue(found >= 0, "VERIFY_PIN, in this order: " + s);
            from = found;
        }
        String sp = body(code, "private void processSetPin(", "private void processChangePin(").replaceAll("\\s+", " ");
        String[] set = { "boolean sealed = sealedForm(buf);", "requireNotLocked();", "if (ownerSet[0] == (byte) 1) {", "if (pinState[0] != (byte) 0 || loadGrant[0] != (byte) 1) ISOException.throwIt(SW_OWNER_PROOF);", "requireNothingUnspent();",
            "short pinLen = apdu.setIncomingAndReceive();", "pinLen = unseal(buf, pinLen, true);", "if (pinLen < 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);",
            "if (pinLen != PIN_BLOCK_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);", "pinLen = unblockPin(buf, pinLen);", "pin.update(buf, ISO7816.OFFSET_CDATA, (byte) pinLen);" };
        from = 0;
        for (String s : set) {
            int found = sp.indexOf(s, from);
            assertTrue(found >= 0, "SET_PIN, in this order: " + s);
            from = found;
        }
        String ch = body(code, "private void processChangePin(", "private void processSetOwner(").replaceAll("\\s+", " ");
        String[] change = { "boolean sealed = sealedForm(buf);", "requireNotLocked();", "if (ownerSet[0] != (byte) 1) ISOException.throwIt(SW_NO_OWNER);",
            "short dataLen = apdu.setIncomingAndReceive();", "dataLen = unseal(buf, dataLen, false);", "if (dataLen < 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);",
            "dataLen = unblockPin(buf, dataLen);", "short at = requireOwnerProof(LABEL_CHANGE_PIN, buf, dataLen);", "pin.update(buf, at, (byte) newLen);" };
        from = 0;
        for (String s : change) {
            int found = ch.indexOf(s, from);
            assertTrue(found >= 0, "CHANGE_PIN, in this order: " + s);
            from = found;
        }
        String sf = body(code, "private static boolean sealedForm(", "private short unseal(").replaceAll("\\s+", " ");
        assertTrue(sf.contains("byte p1 = buf[ISO7816.OFFSET_P1];") && sf.contains("if (p1 != (byte) 0 && p1 != (byte) 1) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);") && sf.contains("return p1 == (byte) 1;"),
            "P1 is 0 or 1 and 1 is sealed");
        // ---- GET_NONCE
        String n = body(code, "private void processGetNonce(", "private void processGetPinKey(").replaceAll("\\s+", " ");
        int one = n.indexOf("if (buf[ISO7816.OFFSET_P1] == (byte) 1) { processGetPinKey(apdu); return; }");
        int other = n.indexOf("if (buf[ISO7816.OFFSET_P1] != (byte) 0) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);");
        int owner = n.indexOf("if (ownerSet[0] != (byte) 1) ISOException.throwIt(SW_NO_OWNER);");
        assertTrue(one >= 0 && one < other && other < owner, "GET_NONCE: P1 = 1 is the PIN key's, any other but 0 is refused, then P1 = 0 wants an owner");
        String pk = body(code, "private void processGetPinKey(", "private static boolean sealedForm(").replaceAll("\\s+", " ");
        assertTrue(pk.contains("short len = toCompressed(seal, pinPubKey.getW(seal, (short) 0));") && pk.contains("Util.arrayCopyNonAtomic(seal, (short) 0, buf, at, len);"), "the key is the PIN key's public half, compressed in the sealing room and copied from it into the answer");
        assertFalse(pk.contains("Util.arrayCopyNonAtomic(buf, (short) 0, buf, at"), "and no copy overlaps itself");
        assertTrue(pk.contains("schnorrHW.sign(cardPrivKey, cardPubKey, scratch, X_MSG, buf, sigAt)"), "signed by the card key");
        assertTrue(pk.contains("sha.update(PINKEY_LABEL, (short) 0, (short) PINKEY_LABEL.length); sha.doFinal(buf, at, len, scratch, X_MSG);"), "over the label and the key");
        assertTrue(pk.indexOf("pinKeySig[0] != (byte) 1") < pk.indexOf("schnorrHW.sign") && pk.indexOf("pinKeySig[0] = (byte) 1;") > pk.indexOf("JCSystem.beginTransaction();")
            && pk.indexOf("pinKeySig[0] = (byte) 1;") < pk.indexOf("JCSystem.commitTransaction();"), "signed once, and kept in a transaction");
        assertTrue(pk.indexOf("rng.generateData(ownerNonce, (short) 0, OWNER_NONCE_LEN);") < pk.indexOf("nonceLive[0] = (byte) 1;") && pk.indexOf("nonceLive[0] = (byte) 1;") < pk.indexOf("apdu.setOutgoingAndSend((short) 0, (short)(sigAt + 64));"),
            "the nonce is made, made live, and then answered");
        // ---- the PIN key
        String init = body(code, "private void initPinKey(", "private static ECPublicKey newP256Key(").replaceAll("\\s+", " ");
        assertTrue(init.contains("pinKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);") && init.contains("pinPrivKey = (ECPrivateKey) pinKeyPair.getPrivate();")
            && init.contains("pinPubKey = (ECPublicKey) pinKeyPair.getPublic();") && init.contains("setSecp256k1Params(pinPubKey, pinPrivKey);") && init.contains("pinKeyPair.genKeyPair();"), "a key pair of its own on secp256k1");
        assertFalse(init.contains("KeyAgreement"), "and no key agreement of its own");
        assertFalse(init.contains("cardKeyPair") || init.contains("cardPrivKey") || init.contains("cardPubKey"), "made of nothing the card key is");
        assertEquals(0, count(code, "KeyAgreement"), "the applet makes no key agreement: the signer's is the one on the card");
        assertEquals(0, count(code, "pinEcdh"));
        assertEquals(1, count(code, "schnorrHW.agree("), "it agrees with the PIN key's private half, in unseal and nowhere else");
        assertFalse(code.contains("agree(cardPrivKey"));
        String hw = new String(java.nio.file.Files.readAllBytes(SchnorrHWMathTest.mainSourceDir().resolve("SchnorrHW.java")), StandardCharsets.UTF_8);
        String hwCode = SchnorrHWMathTest.stripCommentsAndCharLiterals(hw).replaceAll("\\s+", " ");
        int agree = hwCode.indexOf("short agree(ECPrivateKey priv, byte[] pub, short pubOff, short pubLen, byte[] out, short outOff) {");
        assertTrue(agree > 0 && hwCode.indexOf("ecdh.init(priv); return ecdh.generateSecret(pub, pubOff, pubLen, out, outOff); }", agree) == hwCode.indexOf("ecdh.init(priv);", agree), "SchnorrHW.agree: sets the given key, then agrees, and does no more");
        assertEquals(2, count(hwCode, "ecdh.init("), "the signer's agreement is initialised in sign (its own key, every time) and in agree");
        assertTrue(hwCode.indexOf("tmpPriv.setS(sc, SC_K, (short)32); ecdh.init(tmpPriv);") > 0, "sign sets its own key and initialises the agreement with it before every use, so that agree leaves nothing behind");
    }

    // ---- the transcript ------------------------------------------------------

    /** One command, written down with what it answered, and checked against what it was meant to answer. */
    private ResponseAPDU say(StringBuilder out, String name, String kind, int expected, CommandAPDU cmd) {
        ResponseAPDU r = transmit(cmd);
        assertEquals(expected, r.getSW(), name);
        if (kind.equals("sigall")) assertEquals(64, r.getData().length, name + ": a signature, and not a wait taken for one");
        out.append("  {\"name\": ").append(jsonString(name)).append(", \"kind\": \"").append(kind)
           .append("\", \"apdu\": \"").append(toHex(cmd.getBytes()))
           .append("\", \"sw\": \"").append(String.format("%04x", r.getSW()))
           .append("\", \"data\": \"").append(toHex(r.getData())).append("\"},\n");
        return r;
    }

    /** The card taken out of the field and put back, written down as that: a model is to do the same, and send nothing. */
    private void sayReset(StringBuilder out, String name) {
        simulator.reset();
        out.append("  {\"name\": ").append(jsonString(name)).append(", \"kind\": \"reset\", \"apdu\": \"\", \"sw\": \"\", \"data\": \"\"},\n");
    }

    /**
     * A payment of one piece, written down: SPEND_ALL_BEGIN naming it, which is what refuses where it is refused, and
     * then SPEND_ALL_SIGN. The signature's kind is `sigall`: a model checks it against the message of the places named.
     */
    private void saySpend(StringBuilder out, String name, int expected, int slot) {
        sayPay(out, name, expected, -1, slot);
    }

    /**
     * A payment of those places, written down: SPEND_ALL_BEGIN, then SPEND_ALL_SIGN as many times as the payment waits,
     * each two-byte answer ("not yet", 00 01) an `exact` one, and then the signature, which is `sigall`.
     * `waits` is what the card is expected to make it wait; a payment the day refuses is refused at SIGN, with the places
     * named and nothing waited.
     */
    private void sayPay(StringBuilder out, String name, int expected, int waits, int... slots) {
        boolean atSign = expected == SW_OVER_LIMIT || expected == SW_PIN_NEEDED;
        say(out, atSign || expected == SW_OK ? name + ": the places named" : name, "exact", atSign ? SW_OK : expected, beginCommand(slots));
        if (expected != SW_OK) {
            if (atSign) say(out, name, "exact", expected, SIGN_ALL);
            return;
        }
        /* SIGN for as long as the card says "not yet", each written down; `waits` is what it is expected to say so, or
         * -1 for whatever the tap makes of it (a second payment in a tap is slowed, 6a). The first command that is not a
         * wait is the signature. */
        int k = 0;
        ResponseAPDU signed;
        while (true) {
            ResponseAPDU r = transmit(SIGN_ALL);
            if (!isWait(r)) { signed = r; break; }
            k++;
            assertTrue(k <= WAITS_MOST, name + ": still waiting past the most");
            assertNotYet(r, name + ": the answer is 00 01 every time, and never how many are left");
            out.append("  {\"name\": ").append(jsonString(name + ": wait " + k + ": not yet")).append(", \"kind\": \"exact\", \"apdu\": \"")
               .append(toHex(SIGN_ALL.getBytes())).append("\", \"sw\": \"9000\", \"data\": \"0001\"},\n");
        }
        if (waits >= 0) assertEquals(waits, k, name + ": the waits");
        assertEquals(SW_OK, signed.getSW(), name);
        out.append("  {\"name\": ").append(jsonString(name)).append(", \"kind\": \"sigall\", \"apdu\": \"").append(toHex(SIGN_ALL.getBytes()))
           .append("\", \"sw\": \"").append(String.format("%04x", signed.getSW())).append("\", \"data\": \"").append(toHex(signed.getData())).append("\"},\n");
        assertEquals(64, signed.getData().length, name + ": and then the signature");
    }

    /**
     * A payment with outputs, written down: SPEND_ALL_BEGIN, the outputs in commands of the sizes given (cycled), SPEND_ALL_SIGN
     * as many times as the payment waits ("not yet" each time, `exact`), and the signature, which is `sigall`.
     */
    private void sayPayWith(StringBuilder out, String name, int waits, int[] slots, byte[][] outputs, int... groups) {
        say(out, name + ": the places named", "exact", SW_OK, beginCommand(slots));
        int at = 0, g = 0;
        while (at < outputs.length) {
            int n = Math.min(groups[g++ % groups.length], outputs.length - at);
            say(out, name + ": outputs " + (at + 1) + " to " + (at + n), "exact", SW_OK,
                new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, concat(Arrays.copyOfRange(outputs, at, at + n))));
            at += n;
        }
        int k = 0;
        ResponseAPDU signed;
        while (true) {
            ResponseAPDU r = transmit(SIGN_ALL);
            if (!isWait(r)) { signed = r; break; }
            k++;
            assertTrue(k <= WAITS_MOST, name + ": still waiting past the most");
            assertNotYet(r, name + ": the answer is 00 01 every time, and never how many are left");
            out.append("  {\"name\": ").append(jsonString(name + ": wait " + k + ": not yet")).append(", \"kind\": \"exact\", \"apdu\": \"")
               .append(toHex(SIGN_ALL.getBytes())).append("\", \"sw\": \"9000\", \"data\": \"0001\"},\n");
        }
        if (waits >= 0) assertEquals(waits, k, name + ": the waits");
        assertEquals(SW_OK, signed.getSW(), name);
        out.append("  {\"name\": ").append(jsonString(name)).append(", \"kind\": \"sigall\", \"apdu\": \"").append(toHex(SIGN_ALL.getBytes()))
           .append("\", \"sw\": \"").append(String.format("%04x", signed.getSW())).append("\", \"data\": \"").append(toHex(signed.getData())).append("\"},\n");
        assertEquals(64, signed.getData().length, name + ": and then the signature");
    }

    private byte[] sayNonce(StringBuilder out) {
        return say(out, "GET_NONCE", "nonce", SW_OK, new CommandAPDU(CLA, INS_GET_NONCE, 0, 0, 16)).getData();
    }

    /** GET_NONCE with P1 = 1, written down as `pinkey`: 113 bytes, the nonce, the PIN key and the card key's signature over it. */
    private PinKey sayPinKey(StringBuilder out, String name) {
        ResponseAPDU r = say(out, name, "pinkey", SW_OK, new CommandAPDU(CLA, INS_GET_NONCE, 1, 0, 256));
        assertEquals(113, r.getData().length, name);
        return splitPinKey(r.getData());
    }

    /** The envelope of the last sealed command said. */
    private byte[] lastEnvelope;

    /**
     * A sealed VERIFY_PIN, SET_PIN or CHANGE_PIN, written down as `sealed`: `apdu` is what the card was sent, and `clear` is the data that
     * was sealed, which a model seals for itself, under the nonce of the `pinkey` entry before it. `spoil` is what is done to the envelope
     * once it is sealed ("" nothing, "tag" the last byte of the tag XOR 01, "body" the first byte of the ciphertext XOR 01), and `forIns`
     * (-1 for none) is the instruction it was sealed for, where that is not its own.
     */
    private ResponseAPDU saySealed(StringBuilder out, String name, int ins, int expected, PinKey k, int eph, byte[] clear, String spoil, int forIns) {
        byte[] env = spoiled(envelope(EPH[eph], k.key, k.nonce, forIns >= 0 ? forIns : ins, clear), spoil);
        lastEnvelope = env;
        CommandAPDU cmd = new CommandAPDU(CLA, ins, 1, 0, env);
        ResponseAPDU r = transmit(cmd);
        assertEquals(expected, r.getSW(), name);
        out.append("  {\"name\": ").append(jsonString(name)).append(", \"kind\": \"sealed\", \"apdu\": \"").append(toHex(cmd.getBytes()))
           .append("\", \"sw\": \"").append(String.format("%04x", r.getSW())).append("\", \"data\": \"").append(toHex(r.getData()))
           .append("\", \"clear\": \"").append(toHex(clear)).append("\", \"spoil\": \"").append(spoil).append("\"");
        if (forIns >= 0) out.append(", \"for\": \"").append(String.format("%02x", forIns)).append("\"");
        out.append("},\n");
        return r;
    }

    /** A nonce, a proof by `key` over `value` under `label`, and the command built with it. */
    private ResponseAPDU owner(StringBuilder out, String name, int expected, String label, Key key, byte[] value,
                               java.util.function.Function<byte[], CommandAPDU> build) {
        byte[] n = sayNonce(out);
        return say(out, name, "exact", expected, build.apply(ownerProof(label, key, n, value)));
    }

    /** A block header given to the card, written down: SET_HEADER, which answers the card's clock (four bytes). */
    private ResponseAPDU block(StringBuilder out, String name, int expected, byte[] header) {
        return say(out, name, "exact", expected, setHeaderCommand(header));
    }

    /** The terminal's own clock told to the card, written down: TELL_TIME, which answers nothing. */
    private ResponseAPDU told(StringBuilder out, String name, long t) {
        return say(out, name, "exact", SW_OK, tellTimeCommand(t));
    }

    /**
     * A whole conversation with the card, written down: every command, what it
     * was sent and what came back. A model of the card (Foxy's tests have one,
     * so a wallet can be tested with no card and no Java) is held to this,
     * command for command. `kind` says how an answer may be compared: `exact`
     * to the byte; `key`, `sig` and `auth` hold a key or a signature, which is
     * another card's to differ in and the reader's to verify; `nonce` is 16
     * bytes the card made up, which the model is told, so that the owner's
     * proofs that follow (made from it here) are proofs to it as well. The
     * owner's key is in the command that gives it to the card; the model
     * verifies what is signed with it. The card's clock is block headers
     * (1.15), and the headers in the conversation are the network's own: the
     * recording is of a card that holds a header to the floor built into the
     * applet, which no header made here could meet. The time the terminal tells
     * (TELL_TIME) is a note, and the model keeps it as one.
     * Written to target/transcript.json; spec/vectors/transcript.json is one
     * run of it, kept.
     */
    @Test
    @DisplayName("A conversation with the card, as a transcript for a model of it to be held to")
    void testWriteTranscript() throws Exception {
        ownPinKey();    // a chip's PIN key is not its signing key; jCardSim's, left alone, has the same value
        useTheRealFloor();      // the floor of the network: only its own headers meet it (TIP, OLD and the first block of all, below)
        byte[] tip = hexToBytes(TIP), old = hexToBytes(OLD), genesis = hexToBytes(GENESIS);
        StringBuilder out = new StringBuilder("[\n");
        byte[] badRefund = REFUND.clone(); badRefund[0] = 0x04;
        byte[] formerKey = FORMER_TIME_KEY.pub.clone(); formerKey[0] = 0x02;      // anything at all: since 1.15 the card does not read the 65 bytes where the time key was
        byte[] lyingRecord = record("0123456789", REFUND); lyingRecord[99] = 20;
        byte[] notPoint = buildProof(KEYSET, 16, 5); notPoint[44] = 0x04;
        // the card's applet by its whole AID, as a reader selects it (D25): on a chip the package's ten bytes reach the opener
        CommandAPDU select = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(AID_HEX));
        CommandAPDU info = new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256);
        CommandAPDU getCard = new CommandAPDU(CLA, INS_GET_CARD, 0, 0, 256);
        CommandAPDU verifyOk = new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN);
        CommandAPDU clear = new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1);
        byte[] oneKey = new byte[65]; oneKey[0] = 0x02;

        say(out, "select", "exact", SW_OK, select);
        say(out, "a new card says what it is", "exact", SW_OK, info);
        say(out, "its key", "key", SW_OK, new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256));
        say(out, "its record, not yet written", "exact", SW_OK, getCard);
        say(out, "nothing loads onto a card with no owner (a card with no PIN is loaded by whoever holds it, once it has one)", "exact", SW_NO_OWNER, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 16, 1), 1));
        // 1.15: the clock is block headers. A card with nothing set up asks no key, PIN, owner or record of a header, and refuses one that has not the work
        block(out, "a header of 79 bytes is not a header", SW_WRONG_LENGTH, Arrays.copyOf(tip, 79));
        block(out, "nor is one of 81", SW_WRONG_LENGTH, concat(tip, new byte[1]));
        block(out, "the first block of all has the work its own difficulty names, and a target far over the floor built into the card", SW_LITTLE_WORK, genesis);
        byte[] spoiled = tip.clone(); spoiled[79] ^= 1;
        block(out, "the tip with a nonce byte changed is not the block it was", SW_LITTLE_WORK, spoiled);
        byte[] easier = tip.clone(); System.arraycopy(REAL_FLOOR, 0, easier, 72, 4);
        block(out, "nor is the tip with the floor's difficulty written over its own", SW_LITTLE_WORK, easier);
        byte[] huge = tip.clone(); huge[75] = 0x21;
        block(out, "bits whose exponent is past 32 name no target: 6A80, before the work is looked at", SW_WRONG_DATA, huge);
        byte[] negative = tip.clone(); negative[74] |= (byte) 0x80;
        block(out, "nor does a mantissa with its top bit set", SW_WRONG_DATA, negative);
        say(out, "SET_TIME, which was 35, is gone", "exact", SW_INS_NOT_SUPPORTED, new CommandAPDU(CLA, INS_WAS_SET_TIME, 0, 0, concat(u32(OLD_TIME), new byte[] { 2, 0x30, 0 }), 4));
        say(out, "TELL_TIME wants four bytes", "exact", SW_WRONG_LENGTH, new CommandAPDU(CLA, INS_TELL_TIME, 0, 0, new byte[3]));
        told(out, "TELL_TIME takes the terminal's own clock with no PIN, no owner and no record: a note, which the card trusts for nothing", OLD_TIME - 500);
        say(out, "the info: the card has no clock of its own yet", "exact", SW_OK, info);
        say(out, "a card with no owner has no nonce to give", "exact", SW_NO_OWNER, new CommandAPDU(CLA, INS_GET_NONCE, 0, 0, 16));
        say(out, "nor an ALLOW_LOAD", "exact", SW_NO_OWNER, allowLoadCommand(new byte[8]));
        say(out, "nor a limit by an owner", "exact", SW_NO_OWNER, setLimitCommand(new byte[8], 100));
        say(out, "nor a CHANGE_PIN", "exact", SW_NO_OWNER, changePinCommand(new byte[8], NEW_PIN));
        say(out, "nor a SET_TAG (1.19)", "exact", SW_NO_OWNER, setTagCommand(new byte[8], 1));
        say(out, "nor can it be locked, by a reader with no PIN", "exact", SW_SECURITY_NOT_SATIS, lockCommand(new byte[8]));
        say(out, "a PIN of the wrong length", "exact", SW_WRONG_LENGTH, new CommandAPDU(CLA, INS_SET_PIN, 0, 0, new byte[] { 1, 2, 3 }));
        say(out, "SET_PIN", "exact", SW_OK, new CommandAPDU(CLA, INS_SET_PIN, 0, 0, NEW_PIN));
        say(out, "SET_PIN again: an open card has nobody's PIN to protect", "exact", SW_OK, new CommandAPDU(CLA, INS_SET_PIN, 0, 0, TEST_PIN));

        /* 1.9: the PIN, sealed. The card is open (no owner, nothing on it) and has TEST_PIN. A sealed command's data is E (65) || the data under
         * a keystream || a tag (16), under the nonce of the last GET_NONCE with P1 = 1, which is good once. */
        say(out, "GET_NONCE with P1 = 2 is refused", "exact", SW_INCORRECT_P1P2, new CommandAPDU(CLA, INS_GET_NONCE, 2, 0, 256));
        sayPinKey(out, "GET_NONCE with P1 = 1: a nonce, the PIN key and the card key's signature over it, with no owner and no PIN given");
        PinKey sk = sayPinKey(out, "asked again: a new nonce, and the same key and signature");
        saySealed(out, "SET_PIN sealed on an open card: the new PIN as a PIN block, under the second nonce", INS_SET_PIN, SW_OK, sk, 0, pinBlock(NEW_PIN), "", -1);
        say(out, "the clear VERIFY_PIN takes the new PIN", "exact", SW_OK, new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, NEW_PIN));
        sk = sayPinKey(out, "a nonce for VERIFY_PIN");
        saySealed(out, "VERIFY_PIN sealed, the right PIN", INS_VERIFY_PIN, SW_OK, sk, 1, pinBlock(NEW_PIN), "", -1);
        say(out, "the same envelope again: its nonce is spent", "exact", SW_CONDITIONS_NOT_SATIS, new CommandAPDU(CLA, INS_VERIFY_PIN, 1, 0, lastEnvelope));
        sk = sayPinKey(out, "a nonce for a wrong PIN");
        saySealed(out, "VERIFY_PIN sealed, a wrong PIN: a try gone", INS_VERIFY_PIN, 0x63C2, sk, 1, pinBlock(WRONG_PIN), "", -1);
        sk = sayPinKey(out, "a nonce for an envelope with its tag spoiled");
        saySealed(out, "VERIFY_PIN sealed, the last byte of the tag changed: a wrong PIN as far as the card can tell", INS_VERIFY_PIN, 0x63C1, sk, 1, pinBlock(NEW_PIN), "tag", -1);
        sk = sayPinKey(out, "a nonce for the right PIN");
        saySealed(out, "VERIFY_PIN sealed, the right PIN: the tries are back", INS_VERIFY_PIN, SW_OK, sk, 1, pinBlock(NEW_PIN), "", -1);
        sk = sayPinKey(out, "a nonce for an envelope with its body spoiled");
        saySealed(out, "VERIFY_PIN sealed, the first byte of the ciphertext changed", INS_VERIFY_PIN, 0x63C2, sk, 1, pinBlock(NEW_PIN), "body", -1);
        sk = sayPinKey(out, "a nonce for an envelope sealed for another instruction");
        saySealed(out, "VERIFY_PIN sent, sealed for SET_PIN", INS_VERIFY_PIN, 0x63C1, sk, 1, pinBlock(NEW_PIN), "", INS_SET_PIN & 0xFF);
        sk = sayPinKey(out, "a nonce for the right PIN");
        saySealed(out, "VERIFY_PIN sealed, the right PIN: the tries are back", INS_VERIFY_PIN, SW_OK, sk, 1, pinBlock(NEW_PIN), "", -1);
        sk = sayPinKey(out, "a nonce for an envelope whose E is no point");
        saySealed(out, "VERIFY_PIN sealed, E replaced by 04 and zeros: it does not open, and costs a try as a wrong PIN does", INS_VERIFY_PIN, 0x63C2, sk, 1, pinBlock(NEW_PIN), "point", -1);
        saySealed(out, "and the nonce is gone: a good envelope under it is 6985, and costs nothing", INS_VERIFY_PIN, SW_CONDITIONS_NOT_SATIS, sk, 1, pinBlock(NEW_PIN), "", -1);
        sk = sayPinKey(out, "a nonce for the right PIN");
        saySealed(out, "VERIFY_PIN sealed, the right PIN: the tries are back", INS_VERIFY_PIN, SW_OK, sk, 1, pinBlock(NEW_PIN), "", -1);
        sk = sayPinKey(out, "a nonce for a SET_PIN with its tag spoiled");
        saySealed(out, "SET_PIN sealed, the last byte of the tag changed: 6A80 and the PIN is as it was", INS_SET_PIN, SW_WRONG_DATA, sk, 0, pinBlock(TEST_PIN), "tag", -1);
        sk = sayPinKey(out, "a nonce for a SET_PIN with its body spoiled");
        saySealed(out, "SET_PIN sealed, the first byte of the ciphertext changed", INS_SET_PIN, SW_WRONG_DATA, sk, 0, pinBlock(TEST_PIN), "body", -1);
        sk = sayPinKey(out, "a nonce for a SET_PIN sealed for VERIFY_PIN");
        saySealed(out, "SET_PIN sent, sealed for VERIFY_PIN", INS_SET_PIN, SW_WRONG_DATA, sk, 0, pinBlock(TEST_PIN), "", INS_VERIFY_PIN & 0xFF);
        sk = sayPinKey(out, "a nonce for a SET_PIN whose E is no point");
        saySealed(out, "SET_PIN sealed, E replaced by 04 and zeros: 6A80 and the PIN is as it was", INS_SET_PIN, SW_WRONG_DATA, sk, 0, pinBlock(TEST_PIN), "point", -1);
        saySealed(out, "and the nonce is gone: a good envelope under it is 6985", INS_SET_PIN, SW_CONDITIONS_NOT_SATIS, sk, 0, pinBlock(TEST_PIN), "", -1);
        say(out, "a sealed VERIFY_PIN of 81 bytes is short", "exact", SW_WRONG_LENGTH, new CommandAPDU(CLA, INS_VERIFY_PIN, 1, 0, new byte[81]));
        say(out, "VERIFY_PIN with P1 = 2", "exact", SW_INCORRECT_P1P2, new CommandAPDU(CLA, INS_VERIFY_PIN, 2, 0, TEST_PIN));
        say(out, "SET_PIN with P1 = 2", "exact", SW_INCORRECT_P1P2, new CommandAPDU(CLA, INS_SET_PIN, 2, 0, TEST_PIN));
        say(out, "CHANGE_PIN with P1 = 2", "exact", SW_INCORRECT_P1P2, new CommandAPDU(CLA, INS_CHANGE_PIN, 2, 0, new byte[90]));
        sk = sayPinKey(out, "a nonce for the PIN that the rest of this conversation uses");
        saySealed(out, "SET_PIN sealed: back to the PIN the rest uses", INS_SET_PIN, SW_OK, sk, 0, pinBlock(TEST_PIN), "", -1);
        sayReset(out, "taken away and put back: no nonce is held");
        say(out, "select", "exact", SW_OK, select);
        say(out, "a sealed VERIFY_PIN with no nonce asked for in this tap is 6985, whatever the envelope", "exact", SW_CONDITIONS_NOT_SATIS, new CommandAPDU(CLA, INS_VERIFY_PIN, 1, 0, lastEnvelope));
        say(out, "VERIFY_PIN with nothing wrong", "exact", SW_OK, verifyOk);
        say(out, "a wrong PIN", "exact", 0x63C2, new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, WRONG_PIN));
        say(out, "the info after a wrong PIN", "exact", SW_OK, info);
        say(out, "the right PIN", "exact", SW_OK, verifyOk);
        say(out, "a record whose refund key is not a point", "exact", SW_WRONG_DATA, setCardOpenCommand(record(MINT, badRefund)));
        say(out, "a record with anything where the time key was is taken: the card does not read those 65 bytes", "exact", SW_OK, setCardOpenCommand(recordWithKeyBytes(MINT, REFUND, formerKey)));
        say(out, "a record whose length is not its mint's", "exact", SW_WRONG_LENGTH, setCardOpenCommand(lyingRecord));
        say(out, "SET_CARD, with no refund key", "exact", SW_OK, setCardOpenCommand(record(MINT, NO_REFUND)));
        say(out, "SET_CARD again, with one, and zeros where the time key was", "exact", SW_OK, setCardOpenCommand(record(MINT, REFUND)));
        say(out, "the record, read back: the clock's proof is zeros (no header seen), and no limit", "exact", SW_OK, getCard);
        say(out, "a limit by PIN needs no clock: its window waits for the first block header (the first day is on trust)", "exact", SW_OK, setLimitByPinCommand(500));
        say(out, "the info: the limit, no clock, no window", "exact", SW_OK, info);
        say(out, "no limit again", "exact", SW_OK, setLimitByPinCommand(0));
        say(out, "nothing loads onto a card with no owner", "exact", SW_NO_OWNER, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 16, 1), 1));
        say(out, "an owner key of the wrong length", "exact", SW_WRONG_LENGTH, new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, new byte[64]));
        say(out, "an owner key that is not uncompressed", "exact", SW_WRONG_DATA, new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, oneKey));
        say(out, "SET_OWNER", "exact", SW_OK, setOwnerOpenCommand(OWNER));
        say(out, "the info with an owner", "exact", SW_OK, info);
        say(out, "SET_OWNER again, with no proof", "exact", SW_OWNER_PROOF, setOwnerOpenCommand(OTHER_OWNER));
        say(out, "SET_PIN on a card with an owner", "exact", SW_OWNER_PROOF, new CommandAPDU(CLA, INS_SET_PIN, 0, 0, NEW_PIN));
        say(out, "SET_CARD on a card with an owner, with no proof", "exact", SW_OWNER_PROOF, setCardOpenCommand(record(MINT, REFUND)));
        say(out, "a limit by PIN on a card with an owner", "exact", SW_OWNER_PROOF, setLimitByPinCommand(0));

        // 1.15: the first day is on trust. A card that has seen no block header loads, takes a day's limit whose window has no start, and spends up
        // to the limit and no further; the first header begins the window. The time the terminal tells moves nothing.
        say(out, "a piece loads before the card has seen a block header: nothing answers 'never told the time' any more", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 16, 1), 1));
        owner(out, "the owner's day limit of 16, set with no clock: its window has no start", SW_OK, L_LIMIT, OWNER, u32(16), p -> setLimitCommand(p, 16));
        say(out, "the info: the limit, no clock, no window, nothing spent", "exact", SW_OK, info);
        told(out, "the terminal tells its own clock: a note, and the card still has none of its own", OLD_TIME + 20);
        say(out, "the info: the clock is still nothing", "exact", SW_OK, info);
        saySpend(out, "spend the 16 on trust: the limit exactly", SW_OK, 0);
        say(out, "the info: 16 spent, and still no window", "exact", SW_OK, info);
        say(out, "a piece of 1", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 1, 2), 1));
        saySpend(out, "one sat more is past the limit with no clock: 6A8F", SW_OVER_LIMIT, 1);
        block(out, "the first block header the card sees: the older of the two, and the clock is its time", SW_OK, old);
        say(out, "the info: the clock, the window begun at the block's time, and the 16 still counted in it", "exact", SW_OK, info);
        say(out, "the record: the older block's difficulty and hash", "exact", SW_OK, getCard);
        saySpend(out, "still the day it was", SW_OVER_LIMIT, 1);
        owner(out, "the owner takes the limit off", SW_OK, L_LIMIT, OWNER, u32(0), p -> setLimitCommand(p, 0));
        saySpend(out, "and the piece goes", SW_OK, 1);
        say(out, "CLEAR_SPENT: the card is empty again", "exact", SW_OK, clear);
        block(out, "the same block again is taken for nothing", SW_OK, old);
        say(out, "the info after the block", "exact", SW_OK, info);

        byte[] n = sayNonce(out);
        say(out, "a limit by the owner with another key's proof", "exact", SW_OWNER_PROOF, setLimitCommand(ownerProof(L_LIMIT, OTHER_OWNER, n, u32(1000)), 1000));
        owner(out, "a limit with a proof for another number", SW_OWNER_PROOF, L_LIMIT, OWNER, u32(1000), p -> setLimitCommand(p, 5000));
        owner(out, "a limit with CHANGE_PIN's proof", SW_OWNER_PROOF, L_PIN, OWNER, u32(1000), p -> setLimitCommand(p, 1000));
        byte[] limitNonce = sayNonce(out);
        byte[] limitProof = ownerProof(L_LIMIT, OWNER, limitNonce, u32(1000));
        say(out, "a limit of 1000 by the owner, with no PIN needed", "exact", SW_OK, setLimitCommand(limitProof, 1000));
        say(out, "the same proof again", "exact", SW_OWNER_PROOF, setLimitCommand(limitProof, 1000));
        say(out, "the info: the limit, and a window begun at the clock", "exact", SW_OK, info);
        say(out, "the record, read back", "exact", SW_OK, getCard);

        say(out, "a piece of 600 with a date", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 600, 1, 1900000000L), 1));
        say(out, "a piece of 400 with none", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 400, 2), 1));
        say(out, "a piece of 1", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 1, 3, 1900000000L), 1));
        say(out, "a piece of 2000", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 2000, 4), 1));
        say(out, "a piece whose C is not a point", "exact", SW_WRONG_DATA, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, notPoint, 1));
        say(out, "a piece worth nothing", "exact", SW_WRONG_DATA, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 0, 6), 1));
        say(out, "a piece that is on the card already is not written twice", "exact", SW_PIECE_ON_CARD, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 600, 1, 1900000000L), 1));
        say(out, "nor a copy of it that states another amount", "exact", SW_PIECE_ON_CARD, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 1, 1, 1900000000L), 1));
        say(out, "a piece of upstream's length", "exact", SW_WRONG_LENGTH, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, new byte[77], 1));
        owner(out, "the record cannot change under unspent pieces, owner's proof or not", SW_CARD_IN_USE, L_CARD, OWNER, record("https://other.example.com", REFUND),
              p -> setCardCommand(p, record("https://other.example.com", REFUND)));
        say(out, "loading did not give the day anything back", "exact", SW_OK, info);
        say(out, "every slot's state", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256));
        say(out, "every piece and every slot's state: the first page", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 0, 0, 256));
        say(out, "and the second, from where the first stopped", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 3, 0, 256));
        say(out, "and from a slot there is not: 128", "exact", SW_SLOT_OUT_OF_RANGE, new CommandAPDU(CLA, INS_GET_PIECES, 128, 0, 256));
        say(out, "slot 0", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PROOF, 0, 0, 256));
        say(out, "slot 1", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PROOF, 1, 0, 256));
        say(out, "an empty slot", "exact", SW_SLOT_EMPTY, new CommandAPDU(CLA, INS_GET_PROOF, 9, 0, 256));
        say(out, "a slot there is not: 128", "exact", SW_SLOT_OUT_OF_RANGE, new CommandAPDU(CLA, INS_GET_PROOF, 128, 0, 256));
        say(out, "the balance", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4));
        say(out, "how many slots are in use", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PROOF_COUNT, 0, 0, 1));
        saySpend(out, "2000 is over the limit by itself", SW_OVER_LIMIT, 3);
        saySpend(out, "spend slot 0", SW_OK, 0);
        say(out, "the day after it", "exact", SW_OK, info);
        saySpend(out, "spend slot 1, to the limit exactly", SW_OK, 1);
        saySpend(out, "one sat more is over it", SW_OVER_LIMIT, 2);
        saySpend(out, "slot 0 a second time", SW_CONDITIONS_NOT_SATIS, 0);
        say(out, "a spent piece is not written again beside itself", "exact", SW_PIECE_ON_CARD, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 1, 1, 1900000000L), 1));
        saySpend(out, "an empty slot spent", SW_SLOT_EMPTY, 9);
        say(out, "the PIN again", "exact", SW_OK, verifyOk);
        saySpend(out, "it gives none of the day back", SW_OVER_LIMIT, 2);
        say(out, "a new tap", "exact", SW_OK, select);
        say(out, "the PIN in it", "exact", SW_OK, verifyOk);
        saySpend(out, "nor does a new tap", SW_OVER_LIMIT, 2);
        told(out, "the terminal tells a time a day and more on: a note, and the day is the same", OLD_TIME + 90_000);
        saySpend(out, "is the same day", SW_OVER_LIMIT, 2);
        say(out, "and the info is as it was", "exact", SW_OK, info);
        block(out, "the newer block, 92,419 seconds on: a day on", SW_OK, tip);
        saySpend(out, "the next day: slot 2, one sat", SW_OK, 2);
        say(out, "the window began at the clock, with one sat in it", "exact", SW_OK, info);
        saySpend(out, "2000 is still over the limit by itself", SW_OVER_LIMIT, 3);
        owner(out, "the owner takes the limit off", SW_OK, L_LIMIT, OWNER, u32(0), p -> setLimitCommand(p, 0));
        saySpend(out, "and 2000 goes", SW_OK, 3);
        say(out, "nothing is counted with no limit", "exact", SW_OK, info);
        owner(out, "the owner puts a limit of 50 back", SW_OK, L_LIMIT, OWNER, u32(50), p -> setLimitCommand(p, 50));
        say(out, "its window, begun at the clock", "exact", SW_OK, info);
        say(out, "spent places are listed by their tags alone", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 0, 0, 256));
        say(out, "CLEAR_SPENT", "exact", SW_OK, clear);
        say(out, "every slot's state after", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256));
        say(out, "and nothing is left to list", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 0, 0, 256));
        say(out, "the freed slot is used next", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 8, 7), 1));
        say(out, "the piece of 8 is listed in the place that was freed", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 0, 0, 256));
        say(out, "change loaded does not give the day anything back", "exact", SW_OK, info);
        say(out, "a piece whose place was freed may be loaded again", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 600, 1, 1900000000L), 1));
        say(out, "and is then on the card, and not written twice", "exact", SW_PIECE_ON_CARD, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 600, 1, 1900000000L), 1));

        // the tap that writes the change may load with no PIN; the note stands until a load uses it (8.2)
        say(out, "a new tap, after payments", "exact", SW_OK, select);
        say(out, "the info: this tap may load with no PIN", "exact", SW_OK, info);
        say(out, "a tap that only reads the card", "exact", SW_OK, select);
        say(out, "still may: a glance did not spend the note", "exact", SW_OK, info);
        say(out, "a piece of 4, with no PIN: change", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 4, 12), 1));
        say(out, "the same tap may still load the rest", "exact", SW_OK, info);
        say(out, "CLEAR_SPENT, with no PIN", "exact", SW_OK, clear);
        saySpend(out, "but not a spend", SW_PIN_NEEDED, 0);
        say(out, "nor a limit by PIN", "exact", SW_SECURITY_NOT_SATIS, setLimitByPinCommand(0));
        say(out, "a new tap: the load closed the window", "exact", SW_OK, select);
        say(out, "which says so", "exact", SW_OK, info);
        say(out, "and loads nothing with no PIN", "exact", SW_SECURITY_NOT_SATIS, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 4, 13), 1));
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        saySpend(out, "a payment: the piece of 8", SW_OK, 0);
        say(out, "the tap it was paid in gets no grant of its own", "exact", SW_OK, info);
        say(out, "a tap after it", "exact", SW_OK, select);
        say(out, "has the grant", "exact", SW_OK, info);
        say(out, "and a glance after that keeps it", "exact", SW_OK, select);
        say(out, "still has it", "exact", SW_OK, info);
        say(out, "a load with no PIN takes it", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 4, 13), 1));
        say(out, "a new tap after the load", "exact", SW_OK, select);
        say(out, "has none", "exact", SW_OK, info);
        say(out, "nor loads", "exact", SW_SECURITY_NOT_SATIS, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 2, 14), 1));
        say(out, "the PIN, for the rest", "exact", SW_OK, verifyOk);

        // 1.9: the owner changes the PIN, sealed: the proof over the label, the nonce of GET_NONCE with P1 = 1 and the PIN itself, inside the envelope
        sk = sayPinKey(out, "a nonce for the owner's sealed CHANGE_PIN");
        saySealed(out, "CHANGE_PIN sealed: the owner's proof and the PIN block, in one envelope", INS_CHANGE_PIN, SW_OK, sk, 2, changeClear(sk.nonce, NEW_PIN), "", -1);
        say(out, "the old PIN is wrong now", "exact", 0x63C2, verifyOk);
        say(out, "and the new one is right", "exact", SW_OK, new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, NEW_PIN));
        sk = sayPinKey(out, "a nonce for a CHANGE_PIN with its body spoiled");
        saySealed(out, "CHANGE_PIN sealed, the first byte of the ciphertext changed: 6A80 and nothing changed", INS_CHANGE_PIN, SW_WRONG_DATA, sk, 2, changeClear(sk.nonce, TEST_PIN), "body", -1);
        sk = sayPinKey(out, "a nonce for a CHANGE_PIN whose E is no point");
        saySealed(out, "CHANGE_PIN sealed, E replaced by 04 and zeros: 6A80 and nothing changed", INS_CHANGE_PIN, SW_WRONG_DATA, sk, 2, changeClear(sk.nonce, TEST_PIN), "point", -1);
        saySealed(out, "and the nonce is gone: a good envelope under it is 6985", INS_CHANGE_PIN, SW_CONDITIONS_NOT_SATIS, sk, 2, changeClear(sk.nonce, TEST_PIN), "", -1);
        sk = sayPinKey(out, "a nonce for a CHANGE_PIN with a proof over the block");
        byte[] overBlock = ownerProof(L_PIN, OWNER, sk.nonce, pinBlock(TEST_PIN));
        saySealed(out, "CHANGE_PIN sealed, the owner's proof over the PIN block and not the PIN: 6A91", INS_CHANGE_PIN, SW_OWNER_PROOF, sk, 2,
            concat(new byte[] { (byte) overBlock.length }, overBlock, pinBlock(TEST_PIN)), "", -1);
        sk = sayPinKey(out, "a nonce for the PIN that the rest uses");
        saySealed(out, "CHANGE_PIN sealed: back to the PIN the rest uses", INS_CHANGE_PIN, SW_OK, sk, 2, changeClear(sk.nonce, TEST_PIN), "", -1);
        say(out, "the PIN again", "exact", SW_OK, verifyOk);

        say(out, "SIGN_ARBITRARY is not a command", "exact", SW_INS_NOT_SUPPORTED, new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, new byte[32], 64));
        say(out, "AUTH", "auth", SW_OK, new CommandAPDU(CLA, INS_AUTH, 0, 0, hexToBytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"), 80));
        say(out, "AUTH with 32 bytes", "exact", SW_WRONG_LENGTH, new CommandAPDU(CLA, INS_AUTH, 0, 0, new byte[32], 80));

        // the owner adds funds, with no PIN
        say(out, "a new tap", "exact", SW_OK, select);
        say(out, "a load, with no PIN", "exact", SW_SECURITY_NOT_SATIS, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 4, 8), 1));
        say(out, "CLEAR_SPENT, with no PIN", "exact", SW_SECURITY_NOT_SATIS, clear);
        say(out, "ALLOW_LOAD with no nonce asked for", "exact", SW_OWNER_PROOF, allowLoadCommand(new byte[8]));
        owner(out, "ALLOW_LOAD with another command's proof", SW_OWNER_PROOF, L_PIN, OWNER, new byte[0], p -> allowLoadCommand(p));
        owner(out, "ALLOW_LOAD with the owner's proof", SW_OK, L_LOAD, OWNER, new byte[0], p -> allowLoadCommand(p));
        say(out, "a load, with no PIN", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 4, 8), 1));
        say(out, "CLEAR_SPENT, with no PIN", "exact", SW_OK, clear);
        saySpend(out, "but not a spend", SW_PIN_NEEDED, 4);
        say(out, "nor a limit by PIN", "exact", SW_SECURITY_NOT_SATIS, setLimitByPinCommand(0));
        say(out, "nor the PIN", "exact", SW_OWNER_PROOF, new CommandAPDU(CLA, INS_SET_PIN, 0, 0, NEW_PIN));
        say(out, "a new tap", "exact", SW_OK, select);
        say(out, "the grant is gone with the tap", "exact", SW_SECURITY_NOT_SATIS, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 4, 9), 1));

        // CHANGE_PIN, by the owner
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        say(out, "CHANGE_PIN with no nonce asked for", "exact", SW_OWNER_PROOF, changePinCommand(new byte[8], NEW_PIN));
        owner(out, "CHANGE_PIN with another key's proof", SW_OWNER_PROOF, L_PIN, OTHER_OWNER, NEW_PIN, p -> changePinCommand(p, NEW_PIN));
        say(out, "it cost no try", "exact", SW_OK, info);
        owner(out, "CHANGE_PIN with a proof for another PIN", SW_OWNER_PROOF, L_PIN, OWNER, WRONG_PIN, p -> changePinCommand(p, NEW_PIN));
        owner(out, "CHANGE_PIN with a PIN of the wrong length", SW_WRONG_LENGTH, L_PIN, OWNER, new byte[] { 1, 2, 3 }, p -> changePinCommand(p, new byte[] { 1, 2, 3 }));
        byte[] pinNonce = sayNonce(out);
        byte[] pinProof = ownerProof(L_PIN, OWNER, pinNonce, NEW_PIN);
        say(out, "CHANGE_PIN", "exact", SW_OK, changePinCommand(pinProof, NEW_PIN));
        say(out, "the same proof again", "exact", SW_OWNER_PROOF, changePinCommand(pinProof, TEST_PIN));
        saySpend(out, "which ended the session", SW_PIN_NEEDED, 4);
        say(out, "the old PIN", "exact", 0x63C2, verifyOk);
        say(out, "the new PIN", "exact", SW_OK, new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, NEW_PIN));
        say(out, "a new tap", "exact", SW_OK, select);
        owner(out, "CHANGE_PIN back, with no PIN in the tap", SW_OK, L_PIN, OWNER, TEST_PIN, p -> changePinCommand(p, TEST_PIN));

        // blocked, and the owner unblocks it
        say(out, "another new tap", "exact", SW_OK, select);
        say(out, "wrong, two left", "exact", 0x63C2, new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, WRONG_PIN));
        say(out, "wrong, one left", "exact", 0x63C1, new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, WRONG_PIN));
        say(out, "wrong, blocked", "exact", SW_PIN_BLOCKED, new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, WRONG_PIN));
        say(out, "a blocked card says so", "exact", SW_OK, info);
        say(out, "the right PIN opens nothing now", "exact", SW_PIN_BLOCKED, verifyOk);
        saySpend(out, "a blocked card does not spend", SW_PIN_NEEDED, 4);
        say(out, "nor load", "exact", SW_SECURITY_NOT_SATIS, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 16, 8), 1));
        say(out, "nor be given a PIN by whoever is at the reader", "exact", SW_OWNER_PROOF, new CommandAPDU(CLA, INS_SET_PIN, 0, 0, NEW_PIN));
        block(out, "but it takes a block header, as any card does", SW_OK, tip);
        owner(out, "the owner's CHANGE_PIN unblocks it, with no old PIN", SW_OK, L_PIN, OWNER, TEST_PIN, p -> changePinCommand(p, TEST_PIN));
        say(out, "unblocked, with the tries back", "exact", SW_OK, info);
        say(out, "the PIN", "exact", SW_OK, verifyOk);

        // a new record does not touch the clock (a different time key used to clear it, before 1.15): an empty card, the owner's proof, other bytes where the key was
        owner(out, "the owner takes the limit off, to empty the card", SW_OK, L_LIMIT, OWNER, u32(0), p -> setLimitCommand(p, 0));
        for (int i = 0; i < MAX_PROOFS; i++) {
            byte[] st = slot(i);
            if (st.length == 0 || st[0] != 1) continue;
            saySpend(out, "spend slot " + i, SW_OK, i);
        }
        say(out, "CLEAR_SPENT: the card is empty", "exact", SW_OK, clear);
        owner(out, "owner's proof, a record with a time key where an earlier phone put one: the card does not read it, and its clock stays", SW_OK, L_CARD, OWNER, recordWithKeyBytes(MINT, REFUND, formerKey),
              p -> setCardCommand(p, recordWithKeyBytes(MINT, REFUND, formerKey)));
        say(out, "the info: the clock, the window and what was spent as they were", "exact", SW_OK, info);
        say(out, "the record: the clock's proof where the time key would be, and not the bytes that were sent", "exact", SW_OK, getCard);
        block(out, "the older block, which has the work and is no later than the clock: taken for nothing", SW_OK, old);
        say(out, "the clock is where it was", "exact", SW_OK, info);

        // the limit on one payment: a second limit, which a payment over is waited for and never refused; a new tap, since the tap's first payment is the one that goes at once
        sayReset(out, "the card is taken away and put back, for the limit on one payment");
        say(out, "select", "exact", SW_OK, select);
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        CommandAPDU infoTap = new CommandAPDU(CLA, INS_GET_INFO, 1, 0, 256);
        say(out, "the info asked for the limit on one payment as well: twelve bytes more, and no limit", "exact", SW_OK, infoTap);
        owner(out, "both limits in one command, with a proof for the day's alone", SW_OWNER_PROOF, L_LIMIT, OWNER, u32(0), p -> setLimitsCommand(p, 0, 100));
        owner(out, "both limits by the owner: none on the day, 100 on one payment", SW_OK, L_LIMIT, OWNER, concat(u32(0), u32(100)), p -> setLimitsCommand(p, 0, 100));
        say(out, "the info: the limit on one payment, and eight bytes after it that are always nothing", "exact", SW_OK, infoTap);
        say(out, "and the thirty bytes say nothing of it", "exact", SW_OK, info);
        for (int i = 0; i < 9; i++) {
            say(out, "load 50, for the limit on a payment", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 50, 21 + i), 1));
        }
        sayPay(out, "spend 50: within the limit", SW_OK, 0, 0);
        sayPay(out, "100 in two pieces: the limit exactly, the tap's second payment: slowed", SW_OK, -1, 1, 2);
        sayPay(out, "150 in three pieces: over the limit, and waited for", SW_OK, WAIT_OVER_SIGNS, 3, 4, 5);
        say(out, "the info: nothing of it is remembered", "exact", SW_OK, infoTap);
        told(out, "the terminal tells a time ten seconds on: a note, and the wait is the same", TIP_TIME + 10);
        say(out, "a payment begun: three places, 150 together", "exact", SW_OK, beginCommand(6, 7, 8));
        ResponseAPDU firstWait = say(out, "its first wait: not yet", "exact", SW_OK, SIGN_ALL);
        assertNotYet(firstWait, "four waits, and the first says no more than the last");
        say(out, "a command that is not its next step", "exact", SW_OK, info);
        say(out, "gives the payment and the waiting up: no signature", "exact", 0x6985, SIGN_ALL);
        say(out, "and the pieces are on the card", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4));
        sayPay(out, "the same payment begun again waits the whole wait again", SW_OK, WAIT_OVER_SIGNS, 6, 7, 8);
        // 1.12: the change a payment makes for itself, with the limit of 100 on one payment still on; a new tap, so that the payment is the tap's first
        sayReset(out, "the card is taken away and put back, for a payment with change");
        say(out, "select", "exact", SW_OK, select);
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        say(out, "load 100, for a payment with change", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 100, 41), 1));
        say(out, "load 50, for the same", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 50, 42), 1));
        say(out, "no change with no payment begun", "exact", 0x6985, new CommandAPDU(CLA, INS_SPEND_ALL_CHANGE, 0, 0, u32(10), 33));
        say(out, "a payment begun: 150 in two pieces", "exact", SW_OK, beginCommand(9, 10));
        say(out, "the terminal's output: 90", "exact", SW_OK, new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, output(90, blinded(41))));
        int changeAt = out.length();
        ResponseAPDU changeA = say(out, "the card's own change: 40", "exact", SW_OK, new CommandAPDU(CLA, INS_SPEND_ALL_CHANGE, 0, 0, u32(40), 33));
        ResponseAPDU changeB = say(out, "and 20", "exact", SW_OK, new CommandAPDU(CLA, INS_SPEND_ALL_CHANGE, 0, 0, u32(20), 33));
        assertEquals(33, changeA.getData().length); assertEquals(33, changeB.getData().length);
        say(out, "no output of the terminal's after the card's change: the payment is given up", "exact", 0x6985, new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, output(1, blinded(42))));
        say(out, "and there is nothing to sign", "exact", 0x6985, SIGN_ALL);
        say(out, "begun again: 150 in two pieces", "exact", SW_OK, beginCommand(9, 10));
        say(out, "the terminal's output: 90, again", "exact", SW_OK, new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, output(90, blinded(41))));
        int changeAgainAt = out.length();
        changeA = say(out, "the card's own change: 40, a fresh output", "exact", SW_OK, new CommandAPDU(CLA, INS_SPEND_ALL_CHANGE, 0, 0, u32(40), 33));
        changeB = say(out, "and 20, another", "exact", SW_OK, new CommandAPDU(CLA, INS_SPEND_ALL_CHANGE, 0, 0, u32(20), 33));
        ResponseAPDU changeSigned = say(out, "90 leaves the card, within the limit: no wait for change; the signature, over the pieces, the terminal's output and the card's two", "sigall", SW_OK, SIGN_ALL);
        assertEquals(64, changeSigned.getData().length);
        say(out, "the info: the day counted nothing, having no limit; the log says 90", "exact", SW_OK, infoTap);
        ResponseAPDU opened = say(out, "the openings of the change: two, pending", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_CHANGE, 0, 0, 256));
        assertEquals(2, opened.getData()[0], "two openings");
        say(out, "the next page: none", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_CHANGE, 1, 0, 256));
        byte[] openA = Arrays.copyOfRange(opened.getData(), 1, 81), openB = Arrays.copyOfRange(opened.getData(), 81, 161);
        assertArrayEquals(changeA.getData(), blindedFor(changeSecret(openA, REFUND), Arrays.copyOfRange(openA, 48, 80)), "the first opening opens the first change output");
        assertArrayEquals(changeB.getData(), blindedFor(changeSecret(openB, REFUND), Arrays.copyOfRange(openB, 48, 80)), "and the second the second");
        // the change entries carry the nonce and the blinding factor the card drew, for a model to draw the same (the given-up payment's drafts were let go unread: theirs are not known, and are not needed)
        String withA = "\"nonce\": \"" + toHex(Arrays.copyOfRange(openA, 16, 48)) + "\", \"r\": \"" + toHex(Arrays.copyOfRange(openA, 48, 80)) + "\", \"kind\": \"exact\"";
        String withB = "\"nonce\": \"" + toHex(Arrays.copyOfRange(openB, 16, 48)) + "\", \"r\": \"" + toHex(Arrays.copyOfRange(openB, 48, 80)) + "\", \"kind\": \"exact\"";
        int a2 = out.indexOf("\"kind\": \"exact\"", changeAgainAt);
        out.replace(a2, a2 + "\"kind\": \"exact\"".length(), withA);
        int b2 = out.indexOf("\"kind\": \"exact\"", out.indexOf("and 20, another", changeAgainAt));
        out.replace(b2, b2 + "\"kind\": \"exact\"".length(), withB);
        // the first two change outputs, of the payment that was given up, are marked as such: a model draws its own and only the length is held to
        int a1 = out.indexOf("\"kind\": \"exact\"", changeAt);
        out.replace(a1, a1 + "\"kind\": \"exact\"".length(), "\"kind\": \"point\"");
        int b1 = out.indexOf("\"kind\": \"exact\"", out.indexOf("and 20\"", changeAt));
        out.replace(b1, b1 + "\"kind\": \"exact\"".length(), "\"kind\": \"point\"");
        // the change back on the card, in the tap after the payment: the first piece, with its opening's nonce
        byte[] changePiece = buildProof(KEYSET, 40, 43);
        System.arraycopy(openA, 16, changePiece, 12, 32);
        sayReset(out, "the card is taken away and comes back for its change");
        say(out, "select", "exact", SW_OK, select);
        told(out, "the terminal tells its own clock, with no PIN: the entry this tap gets will have it", TIP_TIME + 600);
        say(out, "the change goes on with no PIN, the tap after a payment", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, changePiece, 1));
        say(out, "its opening is gone; the other is left", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_CHANGE, 0, 0, 256));
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        saySpend(out, "the change spent, as any piece: 40 within the limit", SW_OK, 11);
        owner(out, "the day's limit alone, in four bytes", SW_OK, L_LIMIT, OWNER, u32(900), p -> setLimitCommand(p, 900));
        say(out, "the info: the limit on one payment is left as it was", "exact", SW_OK, infoTap);
        owner(out, "both taken off", SW_OK, L_LIMIT, OWNER, concat(u32(0), u32(0)), p -> setLimitsCommand(p, 0, 0));
        say(out, "the info: no limits", "exact", SW_OK, infoTap);
        say(out, "CLEAR_SPENT: the card is empty again", "exact", SW_OK, clear);

        // the card's own log: every spend and every refusal above is in it, as one tap, for the card has not left the field
        CommandAPDU getLog = new CommandAPDU(CLA, INS_GET_LOG, 0, 0, 256);
        say(out, "the log, to the PIN: all of the above as one time in the field", "exact", SW_OK, getLog);
        sayReset(out, "the card is taken out of the field and put back");
        say(out, "select", "exact", SW_OK, select);
        say(out, "the log is not for a reader with no PIN", "exact", SW_SECURITY_NOT_SATIS, getLog);
        owner(out, "the owner's grant", SW_OK, L_LOAD, OWNER, new byte[0], p -> allowLoadCommand(p));
        say(out, "opens it, with no PIN", "exact", SW_OK, getLog);
        owner(out, "a limit of 100 on the day, to be tried", SW_OK, L_LIMIT, OWNER, concat(u32(100), u32(0)), p -> setLimitsCommand(p, 100, 0));
        for (int i = 0; i < 3; i++) {
            say(out, "load 100, for the log", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 100, 31 + i), 1));
        }
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        saySpend(out, "spend 100: the day's limit", SW_OK, 0);
        saySpend(out, "a second is refused, and written down", SW_OVER_LIMIT, 1);
        saySpend(out, "and again", SW_OVER_LIMIT, 1);
        say(out, "the log: a new tap, one spend and two refusals in it, and no mark", "exact", SW_OK, getLog);
        saySpend(out, "a third refusal inside ten seconds of the clock", SW_OVER_LIMIT, 1);
        say(out, "the log: the tap is marked, and the run counted", "exact", SW_OK, getLog);
        sayReset(out, "taken away and put back again");
        say(out, "select", "exact", SW_OK, select);
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        told(out, "the terminal tells its own clock: the entry this tap gets will have it, beside the card's own", TIP_TIME + 3_600);
        owner(out, "the owner raises the limit by a sat: the day's window begins afresh at the clock", SW_OK, L_LIMIT, OWNER, concat(u32(101), u32(0)), p -> setLimitsCommand(p, 101, 0));
        saySpend(out, "the next tap, a new window: a spend within the limit", SW_OK, 1);
        say(out, "the log: a third tap, newest first, with nothing refused in it, and the time told in it", "exact", SW_OK, getLog);
        owner(out, "the limit taken off again", SW_OK, L_LIMIT, OWNER, concat(u32(0), u32(0)), p -> setLimitsCommand(p, 0, 0));
        saySpend(out, "spend the last", SW_OK, 2);
        say(out, "CLEAR_SPENT", "exact", SW_OK, clear);
        say(out, "leaves the log as it is", "exact", SW_OK, getLog);

        // one signature for a payment of three pieces into two outputs; the signature again; and a payment given up. A new tap first:
        // the payment is written step by step, and only a tap's first payment signs at its first SIGN
        sayReset(out, "the card is taken away and put back, for a payment written step by step");
        say(out, "select", "exact", SW_OK, select);
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        for (int i = 0; i < 4; i++) {
            say(out, "load, for one signature", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 8L << i, 41 + i), 1));
        }
        say(out, "the last signature this card gave, asked for again", "again", SW_OK, new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64));
        say(out, "a payment begun: three places, in the order the swap will name them", "exact", SW_OK, beginCommand(2, 0, 1));
        say(out, "its outputs, the amount and the blinded message of each", "exact", SW_OK,
            new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, concat(output(32, blinded(1)), output(24, blinded(2)))));
        say(out, "one signature, and the three are burned", "sigall", SW_OK, SIGN_ALL);
        say(out, "the same signature, asked for again", "again", SW_OK, new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64));
        say(out, "a second signature needs a second beginning", "exact", 0x6985, SIGN_ALL);
        say(out, "a payment begun", "exact", SW_OK, beginCommand(3));
        say(out, "and a command that is not its next step", "exact", SW_OK, info);
        say(out, "gives it up: no signature", "exact", 0x6985, SIGN_ALL);
        say(out, "outputs with no payment begun", "exact", 0x6985, new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, output(1, blinded(3))));
        say(out, "a place named twice", "exact", 0x6A80, beginCommand(3, 3));
        say(out, "SPEND_PROOF is gone", "exact", 0x6D00, new CommandAPDU(CLA, INS_SPEND_PROOF, 3, 0, 64));
        say(out, "the log: the payment is one tap's, with its three pieces", "exact", SW_OK, getLog);
        saySpend(out, "spend the fourth", SW_OK, 3);
        say(out, "CLEAR_SPENT", "exact", SW_OK, clear);

        /* version 1.6: several pieces to a LOAD_PROOF, and GET_PIECES' two short forms. The card is empty and the PIN is in
         * force here. Everything put on is paid and freed again at the end of this section, so that no answer after it is
         * different from what it was before the section was written. */
        byte[] batch0 = edgeProof(0, 0), batch1 = edgeProof(3, 1900000000L), batch2 = buildProof(KEYSET, 32, 51);
        byte[] notAPoint = buildProof(KEYSET, 4, 52); notAPoint[44] = 0x04;
        say(out, "three pieces in one LOAD_PROOF: a place for each", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, concat(batch0, batch1, batch2), 3));
        say(out, "a batch whose second piece is not a point: the first is stored, and the answer is its place alone", "exact", SW_OK,
            new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, concat(buildProof(KEYSET, 16, 53), notAPoint, buildProof(KEYSET, 2, 54)), 3));
        say(out, "the piece that was refused, sent alone, gives its own word", "exact", SW_WRONG_DATA, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, notAPoint, 1));
        say(out, "a batch whose first piece is refused is refused with that word, and stores nothing", "exact", SW_WRONG_DATA,
            new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, concat(notAPoint, buildProof(KEYSET, 2, 54)), 3));
        say(out, "a batch of 82 bytes is not pieces", "exact", SW_WRONG_LENGTH, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, new byte[82], 3));
        say(out, "the short listing: the first entry names its keyset and date, the rest are a place and a size", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 0, 3, 256));
        say(out, "the short listing from the second place: it begins with the twelve bytes again", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 1, 3, 256));
        say(out, "the short listing from a place there is not", "exact", SW_SLOT_OUT_OF_RANGE, new CommandAPDU(CLA, INS_GET_PIECES, 128, 3, 256));
        say(out, "two places, whole, in the order asked: the second and the first", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 0, 2, new byte[] { 1, 0 }, 256));
        say(out, "four places are too many", "exact", SW_WRONG_LENGTH, new CommandAPDU(CLA, INS_GET_PIECES, 0, 2, new byte[] { 0, 1, 2, 3 }, 256));
        say(out, "a place there is not", "exact", SW_SLOT_OUT_OF_RANGE, new CommandAPDU(CLA, INS_GET_PIECES, 0, 2, new byte[] { 0, (byte) 128 }, 256));
        sayPay(out, "pay the undated pieces together", SW_OK, -1, 0, 2, 3);
        saySpend(out, "and the dated one alone", SW_OK, 1);
        say(out, "CLEAR_SPENT: the card is empty again", "exact", SW_OK, clear);
        say(out, "and the short listing is one byte: 128, nothing more to ask for", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 0, 3, 256));

        /* version 1.7: a hundred and twenty-eight places, and the short listing. Sixty-six pieces are put on (three to a command), so that
         * places 64 and 65 are used; one of them is paid, which makes a spent tag above 63; the listings are read; and everything is paid and
         * freed again at the end, so that the card is empty for what follows. Piece i is worth 2^(i mod 8), except piece 20, worth 1000
         * (no power of two); piece 10 is of another keyset, and piece 30 has a date, so that the short listing names them. */
        byte[][] deep = new byte[66][];
        for (int i = 0; i < 66; i++) deep[i] = buildProof(i == 10 ? KEYSET_B : KEYSET, i == 20 ? 1000 : 1L << (i % 8), 200 + i, i == 30 ? 1900000000L : 0);
        for (int at = 0; at < 66; at += 3) {
            say(out, "three pieces put on, places " + at + " to " + (at + 2), "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, concat(deep[at], deep[at + 1], deep[at + 2]), 3));
        }
        say(out, "the info: 66 unspent, none spent, 62 empty, of 128 places", "exact", SW_OK, info);
        say(out, "the whole listing from place 63: a tag is the place's number, and 0x80 where it is spent; places 63, 64 and 65, and the end is 128", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 63, 0, 256));
        saySpend(out, "a piece above 63 is paid", SW_OK, 65);
        say(out, "the whole listing from place 63 again: 65 is a spent tag, 0xC1", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 63, 0, 256));
        say(out, "the short listing from the first place: one answer; places 10, 11, 30 and 31 name a keyset and date, place 20 gives 0xFF and its amount, 65 is spent and not listed", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 0, 3, 256));
        say(out, "the short listing from place 64: it begins with the twelve bytes", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 64, 3, 256));
        say(out, "the short listing from a place past the pieces: the single byte 128", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 66, 3, 256));
        say(out, "the short listing from place 128: there is none", "exact", SW_SLOT_OUT_OF_RANGE, new CommandAPDU(CLA, INS_GET_PIECES, 128, 3, 256));
        say(out, "the brief listing of the sixty-four-place card is gone", "exact", SW_INCORRECT_P1P2, new CommandAPDU(CLA, INS_GET_PIECES, 0, 1, 256));
        say(out, "two places by name above 63: 127, which is empty, and 64", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 0, 2, new byte[] { 127, 64 }, 256));
        say(out, "GET_PROOF for place 64", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PROOF, 64, 0, 256));
        say(out, "GET_PROOF for place 128: there is none", "exact", SW_SLOT_OUT_OF_RANGE, new CommandAPDU(CLA, INS_GET_PROOF, 128, 0, 256));
        say(out, "a payment may name 128: it is no place", "exact", SW_SLOT_OUT_OF_RANGE, beginCommand(1, 128));
        sayPay(out, "the dated piece alone", SW_OK, -1, 30);
        say(out, "129 places named are too many: a payment may name every place the card has, 128, and no more", "exact", SW_TOO_MANY, new CommandAPDU(CLA, INS_SPEND_ALL_BEGIN, 0, 0, new byte[129], 4));
        int[] sixtyFour = new int[64];
        for (int i = 0; i < 30; i++) sixtyFour[i] = i;
        for (int i = 30; i < 64; i++) sixtyFour[i] = i + 1;
        sayPayWith(out, "sixty-four places in one payment (0 to 29 and 31 to 64, both sides of 63) into two outputs", -1, sixtyFour,
            new byte[][] { output(70, blinded(81)), output(30, blinded(82)) }, 2);
        say(out, "the info: 66 spent", "exact", SW_OK, info);
        say(out, "CLEAR_SPENT: all sixty-six freed at once", "exact", SW_OK, clear);
        say(out, "and the whole listing is one byte, 128", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_PIECES, 0, 0, 256));

        /* the limit on one payment is the holder's to read, the log counts what is put on, and the card keeps a receipt of every
         * payment (version 1.6). The card is empty and the PIN is in force. What is done here is undone at its end: the limit is set
         * and taken off, the pieces are paid and freed, and the card is selected again, so that no grant goes on to what follows. */
        CommandAPDU receiptsAsked = new CommandAPDU(CLA, INS_GET_LOG, 1, 0, 256);
        owner(out, "a limit of 100 on one payment, by the owner", SW_OK, L_LIMIT, OWNER, concat(u32(0), u32(100)), p -> setLimitsCommand(p, 0, 100));
        say(out, "the info asked for the limit on one payment, under the PIN alone: zeros, as on a card with none", "exact", SW_OK, infoTap);
        say(out, "the receipts are not for the PIN", "exact", SW_SECURITY_NOT_SATIS, receiptsAsked);
        say(out, "a form of GET_LOG there is not", "exact", SW_INCORRECT_P1P2, new CommandAPDU(CLA, INS_GET_LOG, 2, 0, 256));
        say(out, "a form of GET_PIECES there is not", "exact", SW_INCORRECT_P1P2, new CommandAPDU(CLA, INS_GET_PIECES, 0, 4, 256));
        owner(out, "the owner's grant, for this tap", SW_OK, L_LOAD, OWNER, new byte[0], p -> allowLoadCommand(p));
        say(out, "the info with the grant: the limit on one payment", "exact", SW_OK, infoTap);
        say(out, "the receipts with the grant, asked for from 16 back, which is past what the ring holds: the count of every payment ever, alone", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_LOG, 1, 16, 256));
        byte[] r0 = buildProof(KEYSET, 60, 61), r1 = buildProof(KEYSET, 60, 62), r2 = buildProof(KEYSET, 30, 63);
        say(out, "three pieces put on in one command", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, concat(r0, r1, r2), 3));
        told(out, "the terminal tells its own clock before the payment: the receipt will have it, and the receipts of the payments before it will not", TIP_TIME + 300);
        sayPayWith(out, "150 over a limit of 100, with three outputs in two commands", WAIT_OVER_SIGNS, new int[] { 0, 1, 2 },
            new byte[][] { output(100, blinded(61)), output(40, blinded(62)), output(10, blinded(63)) }, 2, 1);
        say(out, "the receipts: the count, and the three newest receipts, that payment's first (each the card's clock, the time the terminal told, its worth, the digest of what was signed, and the first output given)", "receipt", SW_OK, receiptsAsked);
        say(out, "from 16 back: the count alone, one more than before", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_LOG, 1, 16, 256));
        say(out, "the log: what was put on and what was paid, in one entry, and the payment marked as waited for", "exact", SW_OK, getLog);
        say(out, "a new SELECT takes the grant away", "exact", SW_OK, select);
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        say(out, "the receipts are refused again under the PIN", "exact", SW_SECURITY_NOT_SATIS, receiptsAsked);
        say(out, "and so is the limit on one payment: zeros", "exact", SW_OK, infoTap);
        owner(out, "the owner takes the limit off", SW_OK, L_LIMIT, OWNER, concat(u32(0), u32(0)), p -> setLimitsCommand(p, 0, 0));
        say(out, "CLEAR_SPENT: the card is empty again", "exact", SW_OK, clear);

        /* The terminal's own clock is a note: told, it goes into the entry a tap gets and into the receipt of a payment made in the time in the
         * field, and it moves nothing; the last telling before the entry is made is the one it has. No clock told and no block taken is marked
         * (a clock moved on twice in a time in the field was, before 1.15), and neither begins an entry in the log. (The card is not locked
         * yet, so a piece can be put on here.) */
        sayReset(out, "taken away and put back: a new time in the field, for a time told that goes into an entry");
        say(out, "select", "exact", SW_OK, select);
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        say(out, "the log, before: the ring and the four counts", "exact", SW_OK, getLog);
        told(out, "the terminal tells its own clock", TIP_TIME + 87_000);
        told(out, "and again, two days on: the card keeps the last, and marks nothing", TIP_TIME + 87_121 + 2 * DAY);
        block(out, "the newer block again: taken for nothing", SW_OK, tip);
        say(out, "the log: the ring as it was and the fourth count the same; a time told and a block taken begin no entry", "exact", SW_OK, getLog);
        say(out, "one piece put on: the first thing this tap writes", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 5, 71), 1));
        say(out, "the log: the entry the load begins has the block's time as the clock, and the time told last beside it", "exact", SW_OK, getLog);
        saySpend(out, "pay it, so that the card is empty again", SW_OK, 0);
        say(out, "CLEAR_SPENT", "exact", SW_OK, clear);

        /* 1.16: the PIN is optional, and a card that has one has an allowance of what it signs for in a day without it. The card is empty and the
         * PIN is in force. The owner gives it twelve bytes of limits (a day's of 1000, none on one payment, an allowance of 50); three pieces of 30
         * are put on; one is paid with no PIN, the next is over the allowance and asks for the PIN, and is paid with it. Everything is paid and
         * freed again at the end, and the limits are taken off, so that nothing after this section is different from what it was. */
        byte[] al0 = buildProof(KEYSET, 30, 91), al1 = buildProof(KEYSET, 30, 92), al2 = buildProof(KEYSET, 30, 93);
        byte[] eleven = new byte[11];
        owner(out, "eleven bytes are no limit", SW_WRONG_LENGTH, L_LIMIT, OWNER, eleven, p -> new CommandAPDU(CLA, INS_SET_LIMIT_OWNER, 0, 0, ownerData(p, eleven)));
        owner(out, "twelve bytes: a day of 1000, none on one payment, and an allowance of 50 a day with no PIN", SW_OK, L_LIMIT, OWNER, concat(u32(1000), u32(0), u32(50)),
            p -> setLimits3Command(p, 1000, 0, 50));
        say(out, "the info asked for the tap, under the PIN: the allowance and what is counted against it; the limit on one payment is the grant's alone", "exact", SW_OK, infoTap);
        say(out, "three pieces of 30", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, concat(al0, al1, al2), 3));
        sayReset(out, "taken away and put back: a new time in the field, with no PIN given");
        say(out, "select", "exact", SW_OK, select);
        say(out, "the info asked for the tap, with no PIN: the allowance is said to anyone", "exact", SW_OK, infoTap);
        saySpend(out, "30 of the allowance of 50, signed with no PIN", SW_OK, 0);
        say(out, "the signature again, with no PIN, as it was given with none", "again", SW_OK, new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64));
        say(out, "the info: 30 counted against the allowance, and in the day", "exact", SW_OK, infoTap);
        sayReset(out, "taken away and put back");
        say(out, "select", "exact", SW_OK, select);
        saySpend(out, "30 more is 60 of 50: the PIN, for the whole payment (6A94, at the signature)", SW_PIN_NEEDED, 1);
        say(out, "the payment is gone, as one over a limit is", "exact", 0x6985, SIGN_ALL);
        say(out, "the info: nothing more is counted, and nothing is written in the log for it", "exact", SW_OK, infoTap);
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        saySpend(out, "with the PIN the same payment is signed", SW_OK, 1);
        say(out, "the info: the allowance's count is as it was, the day's is 60", "exact", SW_OK, infoTap);
        say(out, "the log: a payment with no PIN is marked (flag 08) in its tap's entry, and the one with the PIN is not", "exact", SW_OK, getLog);
        sayReset(out, "taken away and put back, the PIN not given");
        say(out, "select", "exact", SW_OK, select);
        say(out, "the last signature was given with the PIN: asked for again it is the PIN's", "exact", SW_SECURITY_NOT_SATIS, new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64));
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        saySpend(out, "pay the third", SW_OK, 2);
        owner(out, "the limits taken off, the allowance too", SW_OK, L_LIMIT, OWNER, concat(u32(0), u32(0), u32(0)), p -> setLimits3Command(p, 0, 0, 0));
        say(out, "the info: no limits and no allowance", "exact", SW_OK, infoTap);
        say(out, "CLEAR_SPENT: the card is empty again", "exact", SW_OK, clear);

        // 1.19: the NFC tag, which a new card has on and which the owner's proof switches off and on: no PIN, with money on the card or without.
        // Its state is said by GET_INFO with P1 = 2, the 42 bytes of P1 = 1 and one more; P1 = 1 answers the 42 bytes it always did, whatever the tag's state
        CommandAPDU infoTag = new CommandAPDU(CLA, INS_GET_INFO, 2, 0, 256);
        ResponseAPDU tapWhenOn = say(out, "the info asked for the tap (P1 = 1): 42 bytes, and the NFC tag is not in them", "exact", SW_OK, infoTap);
        ResponseAPDU tagWhenOn = say(out, "the info asked for the tag (P1 = 2, 1.19): the same 42 bytes and then 00, the NFC tag on", "exact", SW_OK, infoTag);
        assertEquals(42, tapWhenOn.getData().length);
        assertEquals(43, tagWhenOn.getData().length);
        assertArrayEquals(tapWhenOn.getData(), Arrays.copyOf(tagWhenOn.getData(), 42), "P1 = 2 begins with the 42 bytes of P1 = 1");
        assertEquals(0, tagWhenOn.getData()[42]);
        say(out, "SET_TAG with no nonce asked for", "exact", SW_OWNER_PROOF, setTagCommand(new byte[8], 1));
        owner(out, "SET_TAG with LOCK_CARD's proof", SW_OWNER_PROOF, L_LOCK, OWNER, new byte[] { 1 }, p -> setTagCommand(p, 1));
        owner(out, "SET_TAG by another owner's key", SW_OWNER_PROOF, L_TAG, OTHER_OWNER, new byte[] { 1 }, p -> setTagCommand(p, 1));
        owner(out, "SET_TAG with a proof for the other state", SW_OWNER_PROOF, L_TAG, OWNER, new byte[] { 0 }, p -> setTagCommand(p, 1));
        byte[] tagNonce = sayNonce(out);
        say(out, "SET_TAG with a P1 of 2", "exact", 0x6B00, new CommandAPDU(CLA, INS_SET_TAG, 2, 0, ownerData(ownerProof(L_TAG, OWNER, tagNonce, new byte[] { 2 }), new byte[] { 2 })));
        say(out, "SET_TAG with a P2 of 1: the nonce is left unspent", "exact", 0x6B00, new CommandAPDU(CLA, INS_SET_TAG, 1, 1, ownerData(ownerProof(L_TAG, OWNER, tagNonce, new byte[] { 1 }), new byte[] { 1 })));
        owner(out, "SET_TAG whose byte after the proof is not P1", 0x6B00, L_TAG, OWNER, new byte[] { 0 }, p -> new CommandAPDU(CLA, INS_SET_TAG, 1, 0, ownerData(p, new byte[] { 0 })));
        owner(out, "SET_TAG with no byte after the proof", SW_WRONG_LENGTH, L_TAG, OWNER, new byte[0], p -> new CommandAPDU(CLA, INS_SET_TAG, 1, 0, ownerData(p, new byte[0])));
        owner(out, "SET_TAG with two", SW_WRONG_LENGTH, L_TAG, OWNER, new byte[] { 1, 1 }, p -> new CommandAPDU(CLA, INS_SET_TAG, 1, 0, ownerData(p, new byte[] { 1, 1 })));
        say(out, "none of those changed it", "exact", SW_OK, infoTag);
        ResponseAPDU thirtyWhenOn = say(out, "the info: thirty bytes", "exact", SW_OK, info);
        owner(out, "SET_TAG off, with the PIN in the tap and none needed", SW_OK, L_TAG, OWNER, new byte[] { 1 }, p -> setTagCommand(p, 1));
        ResponseAPDU tagWhenOff = say(out, "the info asked for the tag (P1 = 2): the same 42 bytes and then 01, the NFC tag off", "exact", SW_OK, infoTag);
        ResponseAPDU tapWhenOff = say(out, "the info asked for the tap (P1 = 1): the 42 bytes it was, to the byte", "exact", SW_OK, infoTap);
        ResponseAPDU thirtyWhenOff = say(out, "and the thirty bytes are as they were", "exact", SW_OK, info);
        assertEquals(1, tagWhenOff.getData()[42]);
        assertArrayEquals(tapWhenOn.getData(), tapWhenOff.getData(), "a reader that asks P1 = 1 sees nothing of the switch");
        assertArrayEquals(tapWhenOff.getData(), Arrays.copyOf(tagWhenOff.getData(), 42));
        assertArrayEquals(thirtyWhenOn.getData(), thirtyWhenOff.getData(), "nor does a reader that asks P1 = 0");
        owner(out, "SET_TAG off again: the state it has, and nothing changes", SW_OK, L_TAG, OWNER, new byte[] { 1 }, p -> setTagCommand(p, 1));
        owner(out, "SET_TAG on", SW_OK, L_TAG, OWNER, new byte[] { 0 }, p -> setTagCommand(p, 0));
        say(out, "the info asked for the tag: on", "exact", SW_OK, infoTag);
        owner(out, "SET_TAG off, and left off for the rest", SW_OK, L_TAG, OWNER, new byte[] { 1 }, p -> setTagCommand(p, 1));
        say(out, "the info asked for the tag: off", "exact", SW_OK, infoTag);

        /* 1.20: the mint's proof kept with a piece. LOAD_PROOF with P1 = 1 takes a piece and, after its 81 bytes, e, s and r (96) and answers the
         * place and 01; GET_DLEQ gives the proof back for an unspent place (01 and the 96 bytes) and the single byte 00 for a place that is empty,
         * spent, or holds a piece that came with none. The card does not check the proof, and a payment is what it was. The card is empty and
         * the PIN is in force; everything put on is paid and freed again at the end, each payment the first of a time in the field. */
        byte[] proofA = dleqProof(1), proofB = dleqProof(2), proofC = dleqProof(3);
        byte[] mp0 = buildProof(KEYSET, 16, 111), mp1 = buildProof(KEYSET, 8, 112), mp2 = buildProof(KEYSET, 4, 113), mp3 = buildProof(KEYSET, 2, 114);
        byte[] mp4 = buildProof(KEYSET, 1, 115), mp5 = buildProof(KEYSET, 1, 116);
        byte[] none = { 0 };
        sayReset(out, "taken away and put back: a new time in the field, for the mint's proofs");
        say(out, "select", "exact", SW_OK, select);
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        assertArrayEquals(none, say(out, "GET_DLEQ for a place with nothing in it: the single byte 00", "exact", SW_OK, getDleqCommand(0, 255)).getData());
        assertArrayEquals(new byte[] { 0, 1 }, say(out, "a piece with its mint's proof: LOAD_PROOF with P1 = 1 answers its place and 01, the proof kept", "exact", SW_OK, loadWithProofCommand(mp0, proofA)).getData());
        assertArrayEquals(dleqHeld(proofA), say(out, "GET_DLEQ for it: 01 and the 96 bytes, e, s and r", "exact", SW_OK, getDleqCommand(0, 255)).getData());
        assertArrayEquals(new byte[] { 1 }, say(out, "a piece with none, put on as ever (P1 = 0)", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, mp1, 1)).getData());
        assertArrayEquals(concat(dleqHeld(proofA), none), say(out, "GET_DLEQ for two places: the first's proof, then the single byte 00 for the plain piece", "exact", SW_OK, getDleqCommand(0, 1)).getData());
        assertArrayEquals(concat(dleqHeld(proofA), dleqHeld(proofA)), say(out, "the same place twice is answered twice", "exact", SW_OK, getDleqCommand(0, 0)).getData());
        assertArrayEquals(concat(none, dleqHeld(proofA)), say(out, "an empty place and then the piece with its proof, in the order asked", "exact", SW_OK, getDleqCommand(2, 0)).getData());
        say(out, "a place there is not: 128", "exact", SW_SLOT_OUT_OF_RANGE, getDleqCommand(128, 255));
        say(out, "nor a second place there is not: 0 and 128 (FF alone is no second place)", "exact", SW_SLOT_OUT_OF_RANGE, getDleqCommand(0, 128));
        say(out, "nor 255 as the first place", "exact", SW_SLOT_OUT_OF_RANGE, getDleqCommand(255, 255));
        say(out, "P1 = 1 with the 81 bytes of a plain piece is the wrong length", "exact", SW_WRONG_LENGTH, new CommandAPDU(CLA, INS_LOAD_PROOF, 1, 0, mp2, 256));
        say(out, "and with 176 bytes", "exact", SW_WRONG_LENGTH, new CommandAPDU(CLA, INS_LOAD_PROOF, 1, 0, concat(mp2, new byte[95]), 256));
        say(out, "and with 178", "exact", SW_WRONG_LENGTH, new CommandAPDU(CLA, INS_LOAD_PROOF, 1, 0, concat(mp2, proofB, new byte[1]), 256));
        say(out, "and with the 177 bytes of a piece and a proof of zeros: not a piece", "exact", SW_WRONG_DATA, loadWithProofCommand(mp2, new byte[96]));
        say(out, "a piece that is on the card already is not written again, with a proof of its own or none", "exact", SW_PIECE_ON_CARD, loadWithProofCommand(mp0, proofB));
        assertArrayEquals(dleqHeld(proofA), say(out, "and its proof is the one it came with", "exact", SW_OK, getDleqCommand(0, 255)).getData());
        say(out, "P1 = 0 with 177 bytes is not a whole number of pieces", "exact", SW_WRONG_LENGTH, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, concat(mp2, proofB), 256));
        assertArrayEquals(new byte[] { 2 }, say(out, "a P1 that is not 1 is what it always was: P1 = 2 puts on a plain piece", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 2, 0, mp2, 1)).getData());
        assertArrayEquals(new byte[] { 3, 1 }, say(out, "a piece with a proof of its own", "exact", SW_OK, loadWithProofCommand(mp3, proofB)).getData());
        assertArrayEquals(concat(dleqHeld(proofA), dleqHeld(proofB)), say(out, "GET_DLEQ for places 0 and 3", "exact", SW_OK, getDleqCommand(0, 3)).getData());
        sayPay(out, "pay the first and the last, in one payment", SW_OK, 0, 0, 3);
        assertArrayEquals(concat(none, none), say(out, "GET_DLEQ for the two that are spent: 00 each, the proof of a spent piece is not given", "exact", SW_OK, getDleqCommand(0, 3)).getData());
        say(out, "CLEAR_SPENT", "exact", SW_OK, clear);
        assertArrayEquals(new byte[] { 0 }, say(out, "a piece put on plain into the place that was freed", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, mp4, 1)).getData());
        assertArrayEquals(none, say(out, "GET_DLEQ for it: 00, the proof the place held before is not served", "exact", SW_OK, getDleqCommand(0, 255)).getData());
        assertArrayEquals(new byte[] { 3, 1 }, say(out, "a piece with a new proof into the next free place", "exact", SW_OK, loadWithProofCommand(mp5, proofC)).getData());
        assertArrayEquals(concat(none, dleqHeld(proofC)), say(out, "GET_DLEQ for the two: 00, and the new proof, and not the old one", "exact", SW_OK, getDleqCommand(0, 3)).getData());
        sayReset(out, "taken away and put back: a new time in the field, to pay what is left");
        say(out, "select", "exact", SW_OK, select);
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        assertArrayEquals(concat(dleqHeld(proofC), none), say(out, "the proofs are kept through the power: place 3, then place 0", "exact", SW_OK, getDleqCommand(3, 0)).getData());
        sayPay(out, "pay what is on the card, the pieces with a proof and without", SW_OK, 0, 0, 1, 2, 3);
        say(out, "CLEAR_SPENT: the card is empty again", "exact", SW_OK, clear);

        // the owner replaces itself, and locks
        say(out, "SET_OWNER with no proof", "exact", SW_OWNER_PROOF, setOwnerOpenCommand(OTHER_OWNER));
        say(out, "LOCK_CARD with no proof asked for", "exact", SW_OWNER_PROOF, lockCommand(new byte[8]));
        owner(out, "LOCK_CARD with CHANGE_PIN's proof", SW_OWNER_PROOF, L_PIN, OWNER, new byte[0], p -> lockCommand(p));
        byte[] lockNonce = sayNonce(out);
        say(out, "LOCK_CARD without its byte", "exact", 0x6B00, new CommandAPDU(CLA, INS_LOCK_CARD, 0, 0, ownerData(ownerProof(L_LOCK, OWNER, lockNonce, new byte[0]), new byte[0])));
        owner(out, "LOCK_CARD with the PIN and its own proof", SW_OK, L_LOCK, OWNER, new byte[0], p -> lockCommand(p));
        say(out, "a locked card says so", "exact", SW_OK, info);
        say(out, "and takes no more writes: a load", "exact", SW_NOT_ALLOWED, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 4, 11), 1));
        say(out, "a grant", "exact", SW_NOT_ALLOWED, allowLoadCommand(new byte[8]));
        say(out, "a limit", "exact", SW_NOT_ALLOWED, setLimitCommand(new byte[8], 5));
        say(out, "a PIN", "exact", SW_NOT_ALLOWED, changePinCommand(new byte[8], NEW_PIN));
        say(out, "an owner", "exact", SW_NOT_ALLOWED, setOwnerOpenCommand(OTHER_OWNER));
        say(out, "a record", "exact", SW_NOT_ALLOWED, setCardOpenCommand(record(MINT, REFUND)));
        say(out, "a CLEAR_SPENT", "exact", SW_NOT_ALLOWED, clear);
        say(out, "a SET_TAG (1.19)", "exact", SW_NOT_ALLOWED, setTagCommand(new byte[8], 0));
        block(out, "but a block header, which is no write to what is locked", SW_OK, tip);
        say(out, "and proves it is the card", "auth", SW_OK, new CommandAPDU(CLA, INS_AUTH, 0, 0, new byte[16], 80));

        /* A locked card takes the terminal's clock and a block header, and gives its log to the PIN. Neither begins an entry in the log or is
         * marked, and a SELECT is not the card leaving the field: what was told stays told. */
        sayReset(out, "taken away and put back: a new time in the field, the card locked");
        say(out, "select", "exact", SW_OK, select);
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        told(out, "a locked card takes the terminal's clock", TIP_TIME + 90_000);
        block(out, "and the older block, which changes nothing", SW_OK, old);
        say(out, "the log: nothing marked, and no entry begun", "exact", SW_OK, getLog);
        block(out, "and the newer, which the card has already", SW_OK, tip);
        say(out, "select", "exact", SW_OK, select);
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        say(out, "the log: the count is as it was", "exact", SW_OK, getLog);

        /* RESET_CARD (1.17), last of all: the card as it was out of its packet, for another person to set up. A locked card wants the
         * owner's proof and the PIN given in this tap. It keeps its clock (the network's block it was shown) and takes a new key, which
         * a model draws for itself: the key is a `key`, another card's to differ in. */
        sayReset(out, "taken away and put back: the card locked, the PIN not given");
        say(out, "select", "exact", SW_OK, select);
        owner(out, "RESET_CARD on a locked card without the PIN", SW_SECURITY_NOT_SATIS, L_RESET, OWNER, new byte[0], p -> resetCommand(p));
        say(out, "the PIN", "exact", SW_OK, verifyOk);
        byte[] resetNonce = sayNonce(out);
        say(out, "RESET_CARD without its byte", "exact", 0x6B00, new CommandAPDU(CLA, INS_RESET_CARD, 0, 0, ownerData(ownerProof(L_RESET, OWNER, resetNonce, new byte[0]), new byte[0])));
        say(out, "RESET_CARD with P1 = 1", "exact", 0x6B00, new CommandAPDU(CLA, INS_RESET_CARD, 1, RESET_CONFIRM, ownerData(ownerProof(L_RESET, OWNER, resetNonce, new byte[0]), new byte[0])));
        say(out, "RESET_CARD with no proof asked for", "exact", SW_OWNER_PROOF, resetCommand(new byte[8]));
        owner(out, "RESET_CARD with LOCK_CARD's proof", SW_OWNER_PROOF, L_LOCK, OWNER, new byte[0], p -> resetCommand(p));
        owner(out, "RESET_CARD with a proof for a value", SW_WRONG_LENGTH, L_RESET, OWNER, new byte[] { 1 },
            p -> new CommandAPDU(CLA, INS_RESET_CARD, 0, RESET_CONFIRM, ownerData(p, new byte[] { 1 })));
        owner(out, "RESET_CARD by another owner's key", SW_OWNER_PROOF, L_RESET, OTHER_OWNER, new byte[0], p -> resetCommand(p));
        say(out, "the card is as it was: locked, with its owner", "exact", SW_OK, info);
        owner(out, "RESET_CARD with the PIN and its own proof", SW_OK, L_RESET, OWNER, new byte[0], p -> resetCommand(p));
        say(out, "a new card says what it is: no PIN, no owner, not locked, no record, the clock it had", "exact", SW_OK, info);
        say(out, "its tag is on again (1.19): the info asked for the tag", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_INFO, 2, 0, 256));
        say(out, "its key is a new one", "key", SW_OK, new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256));
        say(out, "its record is not written, and the hash of the last block header is the one it was shown", "exact", SW_OK, getCard);
        say(out, "its log is empty", "exact", SW_OK, getLog);
        say(out, "its receipts are empty", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_LOG, 1, 0, 256));
        say(out, "the PIN it had verifies nothing", "exact", SW_PIN_NOT_SET, verifyOk);
        say(out, "no nonce for the old owner's proof", "exact", SW_NO_OWNER, new CommandAPDU(CLA, INS_GET_NONCE, 0, 0, 16));
        say(out, "the old owner's proof, sent all the same", "exact", SW_NO_OWNER, resetCommand(ownerProof(L_RESET, OWNER, new byte[16], new byte[0])));
        say(out, "nothing loads onto a card with no owner", "exact", SW_NO_OWNER, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 16, 1), 1));
        say(out, "another person sets it up: a PIN", "exact", SW_OK, new CommandAPDU(CLA, INS_SET_PIN, 0, 0, NEW_PIN));
        say(out, "the PIN", "exact", SW_OK, new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, NEW_PIN));
        say(out, "a record", "exact", SW_OK, setCardOpenCommand(record(MINT, REFUND)));
        say(out, "and an owner", "exact", SW_OK, setOwnerOpenCommand(OTHER_OWNER));
        say(out, "set up: a card that is not locked, with an owner and a record", "exact", SW_OK, info);
        owner(out, "the old owner's proof is no proof", SW_OWNER_PROOF, L_LOAD, OWNER, new byte[0], p -> allowLoadCommand(p));
        owner(out, "the new owner's is", SW_OK, L_LOAD, OTHER_OWNER, new byte[0], p -> allowLoadCommand(p));
        say(out, "a piece loads", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 16, 1), 1));
        assertArrayEquals(none, say(out, "and has no mint's proof of the last owner's to be given (1.20)", "exact", SW_OK, getDleqCommand(0, 255)).getData());
        owner(out, "RESET_CARD with a piece on the card", SW_CARD_IN_USE, L_RESET, OTHER_OWNER, new byte[0], p -> resetCommand(p));

        /* 2.0 (D20, D26): the rollover budget, REFRESH and the anchored owner, on the wire. The card is emptied, its owner gives it to
         * a new owner with an anchor (SET_OWNER, 145 bytes: the key and a block header), the limits are set in thirteen bytes with a
         * rollover budget of 1, and the four-byte form then leaves that budget as it is (D26). A payment that moves no value (the
         * piece all back as the card's own change) rolls nothing (D26); a payment of value rolls the day until the budget is spent,
         * the day then stands, and REFRESH lets it roll again. The headers are the network's, a day apart (spec/vectors/headers.json).
         * GET_CARD's bytes 76 to 78 say the rolls, the budget and the arming throughout. */
        ClockWalkTest.readTheHeaders();
        byte[] h9 = ClockWalkTest.H.get(9), h10 = ClockWalkTest.H.get(10), h11 = ClockWalkTest.H.get(11);
        assertTrue(ClockWalkTest.T.get(9) > TIP_TIME, "the anchor is newer than the card's clock");
        sayReset(out, "taken away and put back: the rollover budget (2.0, D20 and D26)");
        say(out, "select", "exact", SW_OK, select);
        CommandAPDU verifyNew = new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, NEW_PIN);
        say(out, "the PIN", "exact", SW_OK, verifyNew);
        sayPay(out, "the piece paid, to empty the card for a new owner", SW_OK, -1, 0);
        say(out, "CLEAR_SPENT: the card is empty", "exact", SW_OK, clear);
        byte[] anchorGenesis = concat(OWNER.pub, genesis), anchor = concat(OWNER.pub, h9);
        owner(out, "SET_OWNER with an anchor that has not the work: refused, and the owner with it", SW_LITTLE_WORK, L_OWNER, OTHER_OWNER, anchorGenesis,
            p -> new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, ownerData(p, anchorGenesis)));
        owner(out, "SET_OWNER with an anchor (145 bytes: the new owner's key and the tip's header), by the old owner's proof", SW_OK, L_OWNER, OTHER_OWNER, anchor,
            p -> new CommandAPDU(CLA, INS_SET_OWNER, 0, 0, ownerData(p, anchor)));
        say(out, "the info: the clock is the anchor's", "exact", SW_OK, info);
        say(out, "the record: no roll, the default budget (00, read as 7), armed by the owner's proof", "exact", SW_OK, getCard);
        byte[] budget0 = concat(u32(100), u32(0), u32(50), new byte[] { 0 }), budget31 = concat(u32(100), u32(0), u32(50), new byte[] { 31 });
        owner(out, "a rollover budget of 0 is no budget", SW_WRONG_DATA, L_LIMIT, OWNER, budget0, p -> new CommandAPDU(CLA, INS_SET_LIMIT_OWNER, 0, 0, ownerData(p, budget0)));
        owner(out, "nor is 31", SW_WRONG_DATA, L_LIMIT, OWNER, budget31, p -> new CommandAPDU(CLA, INS_SET_LIMIT_OWNER, 0, 0, ownerData(p, budget31)));
        byte[] limits13 = concat(u32(100), u32(0), u32(50), new byte[] { 1 });
        owner(out, "the limits in thirteen bytes: 100 a day, none on one payment, 50 with no PIN, a rollover budget of 1", SW_OK, L_LIMIT, OWNER, limits13,
            p -> new CommandAPDU(CLA, INS_SET_LIMIT_OWNER, 0, 0, ownerData(p, limits13)));
        say(out, "the record: the budget is 1", "exact", SW_OK, getCard);
        owner(out, "the day's limit alone, in four bytes", SW_OK, L_LIMIT, OWNER, u32(100), p -> setLimitCommand(p, 100));
        say(out, "the record: a form without the budget's byte leaves the budget as it was (D26)", "exact", SW_OK, getCard);
        say(out, "load 10, to be paid with nothing leaving the card", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 10, 501), 1));
        for (int i = 0; i < 3; i++) {
            say(out, "load 60", "exact", SW_OK, new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, buildProof(KEYSET, 60, 502 + i), 1));
        }
        sayReset(out, "taken away and put back a day on, by a reader with no PIN");
        say(out, "select", "exact", SW_OK, select);
        block(out, "the next day's header: the day is over", SW_OK, h10);
        say(out, "a payment of the 10, no PIN: the places named", "exact", SW_OK, beginCommand(0));
        int nothingAt = out.length();
        ResponseAPDU nothingChange = say(out, "all of it back as the card's own change: 10, so that nothing leaves the card", "exact", SW_OK,
            new CommandAPDU(CLA, INS_SPEND_ALL_CHANGE, 0, 0, u32(10), 33));
        say(out, "the signature, with no PIN, under the allowance: nothing leaves the card", "sigall", SW_OK, SIGN_ALL);
        say(out, "the info: the window is where it was, and nothing counted", "exact", SW_OK, info);
        say(out, "the record: no roll spent by a payment that moves no value (D26)", "exact", SW_OK, getCard);
        ResponseAPDU nothingOpened = say(out, "its change's opening, pending", "exact", SW_OK, new CommandAPDU(CLA, INS_GET_CHANGE, 0, 0, 256));
        byte[] openN = null;
        for (int k = 0; k < (nothingOpened.getData()[0] & 0xFF); k++) {
            byte[] o = Arrays.copyOfRange(nothingOpened.getData(), 1 + 80 * k, 81 + 80 * k);
            if (Arrays.equals(nothingChange.getData(), blindedFor(changeSecret(o, REFUND), Arrays.copyOfRange(o, 48, 80)))) openN = o;
        }
        assertNotNull(openN, "an opening opens the change of the payment of nothing");
        String withN = "\"nonce\": \"" + toHex(Arrays.copyOfRange(openN, 16, 48)) + "\", \"r\": \"" + toHex(Arrays.copyOfRange(openN, 48, 80)) + "\", \"kind\": \"exact\"";
        int n2 = out.indexOf("\"kind\": \"exact\"", nothingAt);
        out.replace(n2, n2 + "\"kind\": \"exact\"".length(), withN);
        say(out, "the PIN", "exact", SW_OK, verifyNew);
        sayPay(out, "60 with the PIN, the tap's second payment (so it waits): the day rolls, and the budget's one roll is spent", SW_OK, -1, 1);
        say(out, "the record: one roll, the budget spent; the roll spent the arming too", "exact", SW_OK, getCard);
        sayReset(out, "taken away and put back the day after");
        say(out, "select", "exact", SW_OK, select);
        block(out, "the next day's header", SW_OK, h11);
        say(out, "the PIN", "exact", SW_OK, verifyNew);
        sayPay(out, "60 more: the budget is spent, the day stands, and 60 and 60 are over its 100", SW_OVER_LIMIT, 0, 2);
        say(out, "the record: still one roll", "exact", SW_OK, getCard);
        owner(out, "REFRESH by the old owner's key", SW_OWNER_PROOF, L_REFRESH, OTHER_OWNER, h11, p -> refreshCommand(p, h11));
        owner(out, "REFRESH: the owner's phone, online, with the tip (the header the card has: it moves nothing), answers the clock", SW_OK, L_REFRESH, OWNER, h11,
            p -> refreshCommand(p, h11));
        say(out, "the record: no roll, the budget full again", "exact", SW_OK, getCard);
        sayPay(out, "the 60 again: the day rolls", SW_OK, -1, 2);
        say(out, "the record: one roll", "exact", SW_OK, getCard);
        say(out, "the info: the new window, and 60 in it", "exact", SW_OK, info);

        String text = out.toString();
        text = text.substring(0, text.lastIndexOf(",\n")) + "\n]\n";
        java.nio.file.Path target = appletFolder();
        java.nio.file.Files.createDirectories(target.resolve("target"));
        java.nio.file.Files.write(target.resolve("target").resolve("transcript.json"), text.getBytes(StandardCharsets.UTF_8));
    }

    static String jsonString(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    // =========================================================================
    // The PIN is optional, and a card that has one has a no-PIN allowance (1.16)
    // =========================================================================
    //
    // A card may be set up with no PIN, and then it pays without one: its daily limit and its limit on one payment still hold,
    // and the owner's proofs are what protect the rest. A card with a PIN has a third limit, the allowance: what it signs for in
    // a day without the PIN. The day's window is the daily limit's, shared. Over the allowance the card refuses the signature
    // with 6A94, the PIN is asked for the whole payment, and nothing is written in the log.

    /** SET_LIMIT by the owner, with the three numbers: the day's, the limit on one payment and the no-PIN allowance (twelve bytes). */
    private static CommandAPDU setLimits3Command(byte[] proof, long day, long tap, long allowance) {
        return new CommandAPDU(CLA, INS_SET_LIMIT_OWNER, 0, 0, ownerData(proof, concat(u32(day), u32(tap), u32(allowance))));
    }
    /** The owner's phone setting all three limits: a nonce, a proof over the twelve bytes, the command. */
    private int setAllowance(long day, long tap, long allowance) {
        return sw(setLimits3Command(ownerProof(L_LIMIT, OWNER, nonceBytes(), concat(u32(day), u32(tap), u32(allowance))), day, tap, allowance));
    }
    /** The card taken out of the field and put back: a new time in the field, with no PIN given. */
    private void tap() {
        simulator.reset();
        reselect();
    }
    /** The no-PIN allowance, as a reader with no PIN reads it: GET_INFO P1 = 1, bytes 34..37. */
    private long noPinLimit() { return readUint32(infoTap(), 34); }
    /** What has been signed for with no PIN in the day's window: bytes 38..41 (as the record has it: not yet cleared by a day that has turned). */
    private long noPinSpent() { return readUint32(infoTap(), 38); }
    /** A card set up with no PIN at all: the record by an open card, the owner, a block header. Nothing on it, no limit. The PIN key is its own (for a sealed ADD PIN). */
    private void noPinCard() throws Exception {
        simulator = freshCard();
        ownPinKey();
        useTheTestFloor();
        assertEquals(SW_OK, setCardOpen(MINT, REFUND), "the record, with no PIN");
        assertEquals(SW_OK, setOwner(OWNER), "the owner, with no PIN");
        assertEquals(SW_OK, setTime(T0));
        assertEquals(0, info()[7], "and no PIN");
    }
    private static final CommandAPDU AGAIN = new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64);
    private CommandAPDU receiptsCommand() { return new CommandAPDU(CLA, INS_GET_LOG, 1, 0, 256); }

    @Test
    @DisplayName("A card is set up with no PIN, and every owner's flow works on it: the record, the owner, a load by the owner's grant, limits, a payment, the change, the log, an emptied card's new record, and a PIN added")
    void testACardIsSetUpWithNoPinAndTheOwnersFlowsWork() throws Exception {
        noPinCard();
        byte[] d = info();
        assertEquals(1, d[11], "a record");
        assertEquals(1, d[16], "an owner");
        assertEquals(T0, readUint32(d, 17), "and a clock");
        assertEquals(SW_PIN_NOT_SET, verify(TEST_PIN), "there is no PIN to give");
        assertEquals(SW_OWNER_PROOF, setPin(TEST_PIN), "no PIN is added by whoever is at the reader");
        assertEquals(SW_SECURITY_NOT_SATIS, lock(), "a card with no PIN is not locked (it has no PIN to give for it)");
        // the owner's phone: the grant, and a load
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW(), "a load, under the owner's grant");
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 2)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 3)).getSW());
        assertEquals(40, balance());
        assertEquals(SW_OK, logAnswer().getSW(), "the log, under the grant");
        assertArrayEquals(new long[] { 3, 40 }, logLoaded(0));
        assertEquals(SW_OK, transmit(receiptsCommand()).getSW(), "and the receipts");
        // limits, by the owner: the day's, and both
        assertEquals(SW_OK, setLimit(1000));
        assertEquals(SW_OK, setLimits(1000, 100));
        assertEquals(1000, limit());
        assertEquals(100, paymentLimit());
        assertEquals(0, noPinLimit(), "and no allowance: there is no PIN for it to stand in front of");
        // it pays with no PIN, one signature, as a card with a PIN does for a PIN given
        tap();
        byte[] s0 = slot(0);
        ResponseAPDU paid = spend(0);
        assertEquals(SW_OK, paid.getSW(), "a payment, with no PIN");
        assertTrue(signedFor(paid.getData(), s0, REFUND), "the card's signature, over the piece's secret");
        assertEquals(0, waitsTaken(), "16 is within the limit on one payment");
        assertEquals(16, spentToday(), "and the day counts it");
        assertEquals(0, noPinSpent(), "but it is no part of an allowance, there being none");
        // the signature again, asked for with no PIN on a card that has none
        simulator.reset(); reselect();
        assertArrayEquals(paid.getData(), transmit(AGAIN).getData(), "the signature again, a card with no PIN having none to ask");
        // the tap after a payment writes the change with no PIN and no grant, as on a card with one
        assertEquals(1, info()[29], "this tap may put the change on");
        assertEquals(SW_OK, clearSpent(), "the burned place is freed");
        assertEquals(SW_OK, load(buildProof(KEYSET, 4, 4)).getSW(), "and a piece of change goes on");
        reselect();
        assertEquals(0, info()[29], "the load closed the window");
        // the day's limit holds a payment with no PIN as it holds any other: refused, and written down
        assertEquals(SW_OK, setLimits(20, 0));
        tap();
        assertEquals(SW_OK, spend(1).getSW(), "16 of a day of 20");
        tap();
        assertEquals(SW_OVER_LIMIT, spend(2).getSW(), "8 more is 24 of 20: refused, as it is on a card with a PIN");
        assertEquals(SW_OK, allowLoad());
        assertEquals(1, logRefused(), "and written down");
        for (int k = 0; k < logHeld(); k++) assertEquals(0, logTap(k)[4] & 0x08, "a card with no PIN has no 'no PIN' payments to mark: tap " + k);
        // emptied by the owner's phone: a withdrawal is a payment, and the day's limit taken off for it
        assertEquals(SW_OK, setLimits(0, 0));
        tap();
        assertEquals(SW_OK, spendAll(new int[] { 0, 2 }, new byte[0][]).getSW(), "the rest of the card, in one payment");
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_OK, clearSpent(), "the grant frees the places");
        assertEquals(0, balance());
        // a stranger, with no PIN to give and no grant, in a tap of their own: a card with no PIN is anyone's to fill, to look at and to spend
        tap();
        assertEquals(SW_OK, load(buildProof(KEYSET, 2, 9)).getSW(), "a stranger's top-up loads with no PIN and no grant");
        assertEquals(2, balance());
        assertEquals(SW_OK, logAnswer().getSW(), "the log is anyone's who holds the card");
        assertEquals(SW_OK, transmit(receiptsCommand()).getSW(), "and so are the receipts");
        assertEquals(SW_OK, spendAll(new int[] { 0 }, new byte[0][]).getSW(), "and the piece is anyone's to spend");
        assertEquals(SW_OK, clearSpent(), "and the place anyone's to free");
        assertEquals(0, balance());
        // a new record, by the owner, on the emptied card; the owner replaced
        assertEquals(SW_OK, ownerSetCard(MINT, REFUND));
        assertEquals(SW_OK, sw(setOwnerCommand(ownerProof(L_OWNER, OWNER, nonceBytes(), OTHER_OWNER.pub), OTHER_OWNER)), "the owner may give the card to another");
        // CHANGE_PIN is the owner's way to a PIN too (the proof is by the new owner now)
        assertEquals(SW_OK, sw(changePinCommand(ownerProof(L_PIN, OTHER_OWNER, nonceBytes(), NEW_PIN), NEW_PIN)), "a PIN added by the owner's proof");
        assertEquals(1, info()[7]);
        assertEquals(0, noPinLimit(), "an allowance of nothing: every payment asks for it");
    }

    @Test
    @DisplayName("A card that has an owner and no PIN may be given one under the owner's grant (ADD PIN, SET_PIN): clear or sealed, with money on the card, and not without the grant, not twice, not the wrong length; the allowance is then nothing")
    void testAddPin() throws Exception {
        noPinCard();
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        tap();
        // no grant: refused, in either form
        assertEquals(SW_OWNER_PROOF, setPin(TEST_PIN), "the clear form, with no grant");
        PinKey k = askPinKey();
        assertEquals(SW_OWNER_PROOF, sendSealed(SET_INS, envelope(EPH[0], k.key, k.nonce, SET_INS, pinBlock(TEST_PIN))).getSW(), "the sealed form, with no grant");
        assertEquals(0, info()[7], "still no PIN");
        // the grant: the clear form, on a card that holds money
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_WRONG_LENGTH, setPin(new byte[] { 1, 2, 3 }), "a PIN of the wrong length is refused, and nothing changes");
        assertEquals(0, info()[7]);
        // no command can put an allowance on a card with no PIN; were one in the record all the same, adding the PIN would leave it at nothing
        field("cardRecord")[CashuApplet.CARD_NOPIN_LIMIT_OFFSET + 3] = 99;
        field("cardRecord")[CashuApplet.CARD_NOPIN_SPENT_OFFSET + 3] = 7;
        assertEquals(SW_OK, setPin(TEST_PIN), "ADD PIN under the owner's grant");
        assertEquals(1, info()[7], "a PIN is set");
        assertEquals(3, tries());
        assertFalse(verified(), "and not yet given");
        assertEquals(0, noPinLimit(), "the allowance is nothing: every payment asks for the PIN");
        assertEquals(0, noPinSpent());
        assertEquals(16, balance(), "the money on the card is as it was");
        // there is a PIN now: not again, even with the grant (CHANGE_PIN is the owner's way to another)
        assertEquals(SW_OWNER_PROOF, setPin(NEW_PIN), "a card with a PIN is refused, grant or none");
        assertEquals(SW_OK, verify(TEST_PIN), "and the PIN is the one that was added");
        // it asks for it
        tap();
        assertEquals(SW_PIN_NEEDED, spend(0).getSW(), "a payment asks for the PIN, at the signature");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(0).getSW());

        // the sealed form: a PIN of five bytes under a nonce asked for after the grant, which the grant itself used up
        noPinCard();
        assertEquals(SW_OK, allowLoad());
        PinKey s = askPinKey();
        assertEquals(SW_WRONG_DATA, sendSealed(SET_INS, spoiled(envelope(EPH[1], s.key, s.nonce, SET_INS, pinBlock(PIN5)), "tag")).getSW(), "an envelope that does not open is refused (6A80)");
        assertEquals(0, info()[7], "and sets nothing");
        s = askPinKey();
        assertEquals(SW_OK, sendSealed(SET_INS, envelope(EPH[2], s.key, s.nonce, SET_INS, pinBlock(PIN5))).getSW(), "ADD PIN, sealed, under the owner's grant");
        assertEquals(1, info()[7]);
        assertFalse(nonceLive(), "and the nonce is used up");
        assertEquals(0x63C2, verify(TEST_PIN), "a wrong PIN costs a try");
        assertEquals(SW_OK, verify(PIN5), "and the one sealed is the PIN");
        // a sealed ADD PIN under no grant, under a fresh nonce
        noPinCard();
        s = askPinKey();
        assertEquals(SW_OWNER_PROOF, sendSealed(SET_INS, envelope(EPH[3], s.key, s.nonce, SET_INS, pinBlock(PIN8))).getSW());
        assertEquals(0, info()[7]);
    }

    @Test
    @DisplayName("SET_LIMIT by the owner takes twelve bytes: the day's limit, the limit on one payment and the no-PIN allowance; a card with no PIN refuses an allowance (6985); a number that does not change keeps its count; GET_INFO P1 = 1 says the allowance to anyone")
    void testSetLimitTakesTheAllowance() throws Exception {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        // the shapes: 4, 8, 12 and (2.0, D20) 13, the rollover budget after the allowance; nothing between, nothing past
        for (int n : new int[] { 0, 1, 5, 9, 11, 14, 16 }) {
            byte[] v = new byte[n];
            assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_SET_LIMIT_OWNER, 0, 0, ownerData(ownerProof(L_LIMIT, OWNER, nonceBytes(), v), v))), n + " bytes");
        }
        assertEquals(SW_OK, setAllowance(1000, 100, 50));
        assertEquals(1000, limit());
        assertEquals(100, paymentLimit());
        assertEquals(50, noPinLimit());
        assertEquals(T0, windowStart(), "a new day's limit begins its window at the clock");
        // GET_INFO: thirty bytes as ever; asked for with P1 = 1, forty-two: the limit on one payment to the grant alone, the allowance to anyone
        assertEquals(30, info().length);
        tap();
        byte[] anyone = infoTap();
        assertEquals(42, anyone.length);
        assertArrayEquals(new byte[4], Arrays.copyOfRange(anyone, 30, 34), "the limit on one payment: zeros to a reader with no grant, and to the PIN");
        assertEquals(50, readUint32(anyone, 34), "the allowance, to a reader with nothing");
        assertEquals(0, readUint32(anyone, 38), "and what is counted against it");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(50, readUint32(infoTap(), 34), "to the PIN too");
        assertArrayEquals(new byte[4], Arrays.copyOfRange(infoTap(), 30, 34), "the limit on one payment still not");
        assertEquals(100, paymentLimit(), "and to the grant");
        // a payment with no PIN, counted; then numbers that do not change keep their count
        tap();
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(16, noPinSpent());
        assertEquals(16, spentToday());
        assertEquals(SW_OK, setTime(T0 + 1000));
        assertEquals(SW_OK, setAllowance(1000, 200, 50));
        assertEquals(16, noPinSpent(), "the day's and the allowance's numbers as they were: the count stays");
        assertEquals(16, spentToday());
        assertEquals(T0, windowStart(), "and so does the window");
        assertEquals(SW_OK, setAllowance(1000, 200, 80));
        assertEquals(80, noPinLimit());
        assertEquals(0, noPinSpent(), "a new number for the allowance counts from nothing");
        assertEquals(16, spentToday(), "the day's count is the day's, and stays");
        assertEquals(T0, windowStart(), "in the window as it stands");
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 2)).getSW());
        tap();
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(16, noPinSpent());
        assertEquals(SW_OK, setAllowance(2000, 200, 80));
        assertEquals(2000, limit());
        assertEquals(80, noPinLimit(), "the allowance as it was");
        assertEquals(0, noPinSpent(), "a new day's limit begins the window again, and what the allowance counted in the old one goes with it");
        assertEquals(0, spentToday());
        assertEquals(T0 + 1000, windowStart());
        // the four-byte and the eight-byte forms leave the allowance as it is
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 3)).getSW());
        tap();
        assertEquals(SW_OK, spend(2).getSW());
        assertEquals(8, noPinSpent());
        assertEquals(SW_OK, setLimit(2000));
        assertEquals(80, noPinLimit(), "the day's alone: the allowance as it was");
        assertEquals(0, noPinSpent(), "(four bytes begin the window again, as ever)");
        assertEquals(SW_OK, setLimits(2000, 100));
        assertEquals(80, noPinLimit(), "the day's and the payment's: the allowance as it was");
        assertEquals(100, paymentLimit());
        // the allowance off
        assertEquals(SW_OK, setAllowance(2000, 100, 0));
        assertEquals(0, noPinLimit());
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 4)).getSW());
        tap();
        assertEquals(SW_PIN_NEEDED, spend(3).getSW(), "an allowance of nothing: every payment asks for the PIN");

        // a card with no PIN has no allowance to set
        noPinCard();
        assertEquals(SW_CONDITIONS_NOT_SATIS, setAllowance(1000, 100, 50), "6985: there is nothing for an allowance to stand in front of");
        assertEquals(0, limit(), "and nothing of the command was done");
        assertEquals(SW_OK, allowLoad());
        assertEquals(0, readUint32(infoTap(), 34));
        assertEquals(0, paymentLimit());
        assertEquals(SW_OK, setAllowance(1000, 100, 0), "twelve bytes with a zero allowance are the eight-byte form");
        assertEquals(1000, limit());
        assertEquals(100, paymentLimit());
        assertEquals(0, noPinLimit());
        // and when a PIN is added, the allowance is nothing still
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(0, noPinLimit());
        assertEquals(SW_OK, setAllowance(1000, 100, 25), "and now the owner may give it one");
        assertEquals(25, noPinLimit());
    }

    @Test
    @DisplayName("The allowance: a payment with no PIN signs while what the day has signed for with no PIN, and this payment, come to no more than it; over it the card answers 6A94 and gives the payment up; the PIN signs the whole; a payment with the PIN counts for nothing against it; nothing is split")
    void testTheNoPinAllowance() throws Exception {
        ready();
        long[] pieces = { 40, 40, 40, 30, 20, 10, 10 };
        for (int i = 0; i < pieces.length; i++) assertEquals(SW_OK, load(buildProof(KEYSET, pieces[i], i + 1)).getSW());
        assertEquals(SW_OK, setAllowance(1000, 0, 100));
        tap();
        assertEquals(100, noPinLimit(), "said to a reader with no PIN");
        assertEquals(0, noPinSpent());
        byte[] s0 = slot(0);
        ResponseAPDU first = spend(0);
        assertEquals(SW_OK, first.getSW(), "40 of 100, with no PIN");
        assertTrue(signedFor(first.getData(), s0, REFUND));
        assertEquals(0, waitsTaken());
        assertEquals(40, noPinSpent());
        assertEquals(40, spentToday(), "the day counts it as it counts every payment");
        tap();
        assertEquals(SW_OK, spend(1).getSW(), "40 more: 80 of 100");
        assertEquals(80, noPinSpent());
        assertEquals(80, spentToday());
        // 40 more would be 120: the PIN, for the whole of it; the payment is given up, nothing is burned, nothing is counted
        tap();
        assertEquals(SW_PIN_NEEDED, spend(2).getSW());
        assertEquals(SW_CONDITIONS_NOT_SATIS, sw(SIGN_ALL), "the payment is gone, as one over a limit is");
        assertEquals(1, slot(2)[0], "nothing burned");
        assertEquals(80, noPinSpent());
        assertEquals(80, spentToday());
        for (int i = 0; i < 3; i++) assertEquals(SW_PIN_NEEDED, spend(2).getSW(), "and again, and again");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(3, logTaps(), "nothing was written down for them: three taps, the loading and the two payments");
        assertEquals(0, logRefused(), "not a refusal over a limit");
        assertEquals(0, logTampers(), "and no run of three of them");
        assertEquals(0, logTap(0)[3], "nor in the entry of the tap");
        // the PIN, in the tap that asked: the same payment signs
        ResponseAPDU withPin = spend(2);
        assertEquals(SW_OK, withPin.getSW(), "with the PIN, the whole payment");
        assertEquals(80, noPinSpent(), "a payment with the PIN is none of the allowance's");
        assertEquals(120, spentToday(), "and the day's all the same");
        assertEquals(4, logTaps());
        assertEquals(0, logTap(0)[4] & 0x08, "the payment with the PIN is not marked");
        assertEquals(0x08, logTap(1)[4] & 0x08, "the second with no PIN is");
        assertEquals(0x08, logTap(2)[4] & 0x08, "and the first");
        // the allowance has 20 left: a payment of 30 is not split, 20 with no PIN and 10 with
        tap();
        assertEquals(SW_PIN_NEEDED, spend(3).getSW(), "30 against 20 left: the PIN, for the whole of it");
        assertEquals(80, noPinSpent());
        assertEquals(SW_OK, spend(4).getSW(), "20 is exactly what is left: the allowance, to the sat");
        assertEquals(100, noPinSpent());
        tap();
        assertEquals(SW_PIN_NEEDED, spend(5).getSW(), "and now not a sat more");
        // the day turns: a block a day on, and what was counted goes to nothing in the payment that follows
        assertEquals(SW_OK, setTime(T0 + DAY));
        assertEquals(100, noPinSpent(), "(the card writes the new day with the first payment in it)");
        tap();
        assertEquals(SW_OK, spend(5).getSW(), "the next day's first payment");
        assertEquals(10, noPinSpent(), "both counts are the new day's alone");
        assertEquals(10, spentToday());
        assertEquals(T0 + DAY, windowStart());
    }

    @Test
    @DisplayName("The allowance is held to what leaves the card for good (the pieces less the change the card makes), counts nothing for a payment with the PIN, and with an allowance of nothing the PIN is asked even for a payment that takes nothing")
    void testTheAllowanceCountsWhatLeavesTheCard() throws Exception {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 100, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 60, 2)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 60, 3)).getSW());
        // an allowance of nothing: a payment that takes nothing (all change) still asks for the PIN
        tap();
        assertEquals(SW_OK, transmit(beginCommand(0)).getSW());
        assertEquals(SW_OK, change(100).getSW());
        assertEquals(SW_PIN_NEEDED, transmit(SIGN_ALL).getSW(), "nothing to be paid, and no allowance: the PIN");
        assertEquals(1, slot(0)[0]);
        assertEquals(SW_OK, setAllowance(0, 0, 50));
        // 100 in, 30 out and 70 change: 30 leaves the card
        tap();
        assertEquals(SW_OK, transmit(beginCommand(0)).getSW());
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, output(30, blinded(1)))));
        assertEquals(SW_OK, change(70).getSW());
        assertEquals(SW_OK, signAll().getSW(), "30 of 50, though 100 are burned");
        assertEquals(30, noPinSpent());
        // 60 in, 25 out and 35 back is 25: 55 of 50, refused, and with it the change the card made is let go
        tap();
        assertEquals(SW_OK, transmit(beginCommand(1)).getSW());
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, output(25, blinded(2)))));
        assertEquals(SW_OK, change(35).getSW());
        assertEquals(SW_PIN_NEEDED, transmit(SIGN_ALL).getSW());
        assertEquals(30, noPinSpent());
        assertEquals(1, slot(1)[0], "nothing burned");
        assertEquals(1, openings().size(), "and no change is owed for the payment that was never signed: only the first payment's is");
        // 20 out of the 60, 40 back: 50 exactly
        tap();
        assertEquals(SW_OK, transmit(beginCommand(1)).getSW());
        assertEquals(SW_OK, sw(new CommandAPDU(CLA, INS_SPEND_ALL_OUTPUTS, 0, 0, output(20, blinded(3)))));
        assertEquals(SW_OK, change(40).getSW());
        assertEquals(SW_OK, signAll().getSW());
        assertEquals(50, noPinSpent());
        // with the PIN, a payment the allowance is spent for: counts nothing
        tap();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(2).getSW());
        assertEquals(50, noPinSpent());
    }

    @Test
    @DisplayName("A blocked PIN has no allowance: nothing is signed with no PIN until the owner has unblocked the card, and the count stands through it")
    void testABlockedCardHasNoAllowance() throws Exception {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 20, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 20, 2)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 20, 3)).getSW());
        assertEquals(SW_OK, setAllowance(1000, 0, 100));
        tap();
        assertEquals(SW_OK, spend(0).getSW());
        tap();
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(0x63C1, verify(WRONG_PIN));
        assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN));
        assertEquals(2, info()[7]);
        assertEquals(SW_PIN_NEEDED, spend(1).getSW(), "within the allowance, and blocked: the PIN is asked for, and it cannot be given");
        tap();
        assertEquals(SW_PIN_NEEDED, spend(1).getSW(), "in a later tap too");
        assertEquals(20, noPinSpent());
        assertEquals(SW_OK, changePin(NEW_PIN), "the owner unblocks it");
        tap();
        assertEquals(SW_OK, spend(1).getSW(), "and the allowance is there again");
        assertEquals(40, noPinSpent(), "with what was counted before");
    }

    @Test
    @DisplayName("The daily limit holds every payment, PIN or not: a payment with no PIN within the allowance and over the day is refused (6A8F) and written down; one over both asks for the PIN first (6A94) and writes nothing, and a run of those marks no tamper")
    void testTheAllowanceAsksBeforeTheLimitsAreRead() throws Exception {
        ready();
        for (int i = 0; i < 4; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 100, i + 1)).getSW());
        assertEquals(SW_OK, setAllowance(250, 0, 500));
        tap();
        assertEquals(SW_OK, spend(0).getSW(), "100, the day's first, with no PIN");
        tap();
        assertEquals(SW_OK, spend(1).getSW(), "200 of a day of 250");
        tap();
        assertEquals(SW_OVER_LIMIT, spend(2).getSW(), "300 of a day of 250, within an allowance of 500: the day's limit refuses it, and writes it down");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(1, logRefused());
        assertEquals(200, noPinSpent(), "and it counted nothing");

        simulator = freshCard();
        ready();
        for (int i = 0; i < 4; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 100, i + 1)).getSW());
        assertEquals(SW_OK, setAllowance(250, 0, 250));
        tap();
        assertEquals(SW_OK, spend(0).getSW());
        tap();
        assertEquals(SW_OK, spend(1).getSW());
        tap();
        assertEquals(SW_PIN_NEEDED, spend(2).getSW(), "300 against an allowance of 250 and a day of 250: over both, and the PIN is asked for first");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(0, logRefused(), "and nothing was written down");
        assertEquals(SW_OVER_LIMIT, spend(2).getSW(), "with the PIN it is the day that refuses it");
        assertEquals(1, logRefused());
        // a run of requests for the PIN is no run of refusals: four in ten seconds mark nothing
        tap();
        for (int i = 0; i < 4; i++) assertEquals(SW_PIN_NEEDED, spend(3).getSW());
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(0, logTampers());
        assertEquals(1, logRefused());
    }

    @Test
    @DisplayName("The limit on one payment waits a payment made with no PIN as any other, counts it against the allowance, and a second payment in a tap with no PIN is slowed")
    void testTheWaitHoldsPaymentsWithNoPin() throws Exception {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 250, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 2)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 10, 3)).getSW());
        assertEquals(SW_OK, setAllowance(0, 100, 500));
        tap();
        assertEquals(SW_OK, spend(0).getSW(), "250 over a limit of 100, with no PIN, within an allowance of 500");
        assertEquals(waitsRule(100, 250, 0), waitsTaken(), "waited for as a payment with the PIN is");
        assertEquals(250, noPinSpent());
        assertEquals(SW_OK, setAllowance(0, 0, 500));
        tap();
        assertEquals(SW_OK, spend(1).getSW());
        assertEquals(0, waitsTaken(), "the tap's first payment: at full speed");
        assertEquals(SW_OK, spend(2).getSW());
        assertEquals(waitsRule(0, 10, 0, true), waitsTaken(), "the second in the same tap: slowed, with no PIN as with it");
        assertEquals(270, noPinSpent());
    }

    @Test
    @DisplayName("The window begins at the first payment when only the allowance is set, and ends a day on, resetting the allowance's count; a payment with the PIN that turns the day resets it too")
    void testTheWindowBeginsOnTheAllowanceAlone() throws Exception {
        ready();
        for (int i = 0; i < 6; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 10, i + 1)).getSW());
        assertEquals(SW_OK, setAllowance(0, 0, 25));
        assertEquals(0, limit(), "no limit on the day");
        assertEquals(0, windowStart(), "and no window: nothing has begun one");
        tap();
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(T0, windowStart(), "the first payment begins the window at the clock");
        assertEquals(10, noPinSpent());
        assertEquals(0, spentToday(), "(the day's limit counts nothing, having none)");
        assertEquals(SW_OK, setTime(T0 + DAY - 1));
        tap();
        assertEquals(SW_OK, spend(1).getSW(), "a second before the day is out: the same day");
        assertEquals(20, noPinSpent());
        tap();
        assertEquals(SW_PIN_NEEDED, spend(2).getSW(), "10 more would be 30 of 25");
        assertEquals(SW_OK, setTime(T0 + DAY));
        tap();
        assertEquals(SW_OK, spend(2).getSW(), "a day on: the count is the new day's");
        assertEquals(10, noPinSpent());
        assertEquals(T0 + DAY, windowStart());
        // a payment with the PIN that turns the day resets the count as well
        assertEquals(SW_OK, setTime(T0 + 2 * DAY));
        tap();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(3).getSW());
        assertEquals(0, noPinSpent(), "the new day, and this payment was made with the PIN: nothing is counted");
        assertEquals(T0 + 2 * DAY, windowStart());
        tap();
        assertEquals(SW_OK, spend(4).getSW());
        assertEquals(10, noPinSpent());
        // a daily limit as well: the day and the allowance turn together
        assertEquals(SW_OK, setAllowance(100, 0, 25));
        assertEquals(T0 + 2 * DAY, windowStart(), "the window begun again by the new day's limit, at the clock");
        assertEquals(0, noPinSpent(), "and what the allowance had counted in the old one goes with it");
    }

    @Test
    @DisplayName("A card that has seen no block header counts the allowance from set-up, with no window, and fails toward the PIN; the first header anchors the window and keeps the count")
    void testTheAllowanceOfACardWithNoHeader() throws Exception {
        readyWithoutAHeader(0);
        for (int i = 0; i < 4; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 30, i + 1)).getSW());
        assertEquals(SW_OK, setAllowance(0, 0, 50));
        assertEquals(0, now());
        tap();
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(30, noPinSpent());
        assertEquals(0, windowStart(), "no clock, no window");
        tap();
        assertEquals(SW_PIN_NEEDED, spend(1).getSW(), "60 of 50: the count does not end without a clock");
        assertEquals(SW_OK, setTime(T0));
        assertEquals(T0, windowStart(), "the first header anchors the window an allowance began");
        assertEquals(30, noPinSpent(), "and keeps what was counted");
        tap();
        assertEquals(SW_PIN_NEEDED, spend(1).getSW(), "still the same day");
        assertEquals(SW_OK, setTime(T0 + DAY));
        tap();
        assertEquals(SW_OK, spend(1).getSW(), "a day on");
        assertEquals(30, noPinSpent());
    }

    @Test
    @DisplayName("A sum that wraps is past any allowance: with the PIN not given it asks for the PIN and writes nothing; and the largest allowance counts up without wrapping")
    void testASumThatWrapsAsksForThePin() throws Exception {
        readyWithLimit(4294967295L);
        assertEquals(SW_OK, load(buildProof(KEYSET, 4294967294L, 1)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 5, 2)).getSW());
        assertEquals(SW_OK, load(buildProof(KEYSET, 1, 3)).getSW());
        assertEquals(SW_OK, setAllowance(4294967295L, 0, 4294967295L));
        tap();
        assertEquals(SW_PIN_NEEDED, sw(beginCommand(0, 1)), "the sum wraps, and the PIN is not given");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(0, logRefused(), "nothing written down for it");
        assertEquals(SW_OVER_LIMIT, sw(beginCommand(0, 1)), "with the PIN it is the day's limit that refuses it");
        assertEquals(1, logRefused());
        tap();
        assertEquals(SW_OK, spend(0).getSW(), "4294967294 with no PIN, of the largest allowance there is");
        assertEquals(4294967294L, noPinSpent());
        tap();
        assertEquals(SW_OK, spend(2).getSW(), "one more is exactly the largest number there is");
        assertEquals(4294967295L, noPinSpent());
        tap();
        assertEquals(SW_PIN_NEEDED, spend(1).getSW(), "and 5 more would wrap: the PIN");
    }

    @Test
    @DisplayName("The last signature, asked for again, is given with no PIN when it was given with none, and with the PIN when it was given with it; a card with no PIN gives it to anyone")
    void testTheLastSignatureAgainWithNoPin() throws Exception {
        ready();
        for (int i = 0; i < 3; i++) assertEquals(SW_OK, load(buildProof(KEYSET, 8, i + 1)).getSW());
        assertEquals(SW_OK, setAllowance(0, 0, 100));
        tap();
        assertEquals(SW_SECURITY_NOT_SATIS, sw(AGAIN), "a card with a PIN that has never signed asks the PIN before it says so");
        ResponseAPDU noPin = spend(0);
        assertEquals(SW_OK, noPin.getSW());
        tap();
        ResponseAPDU again = transmit(AGAIN);
        assertEquals(SW_OK, again.getSW(), "the signature given with no PIN is given again with none");
        assertArrayEquals(noPin.getData(), again.getData());
        assertEquals(SW_OK, verify(TEST_PIN));
        ResponseAPDU withPin = spend(1);
        assertEquals(SW_OK, withPin.getSW());
        tap();
        assertEquals(SW_SECURITY_NOT_SATIS, sw(AGAIN), "the signature given with the PIN is given again to the PIN");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertArrayEquals(withPin.getData(), transmit(AGAIN).getData());

        noPinCard();
        assertEquals(SW_SLOT_EMPTY, sw(AGAIN), "a card with no PIN that has never signed has none");
        assertEquals(SW_OK, allowLoad());
        assertEquals(SW_OK, load(buildProof(KEYSET, 8, 1)).getSW());
        tap();
        ResponseAPDU p = spend(0);
        assertEquals(SW_OK, p.getSW());
        tap();
        assertArrayEquals(p.getData(), transmit(AGAIN).getData(), "and to anyone");
    }

    @Test
    @DisplayName("Set-up with no PIN is for an open card only: with a PIN set and not given the record is the PIN's, as it was; a blocked card's record is not open")
    void testSetUpAsksThePinWhereThereIsOne() throws Exception {
        simulator = freshCard();
        assertEquals(SW_OK, setPin(TEST_PIN));
        simulator.reset(); reselect();
        assertEquals(SW_SECURITY_NOT_SATIS, setCard(MINT, REFUND), "a PIN set and not given: the record is not written");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setCard(MINT, REFUND), "given, it is");
        // no PIN, no owner: the record and the owner by anyone, and then the card is the owner's
        simulator = freshCard();
        assertEquals(SW_OK, setCard(MINT, REFUND));
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(SW_OWNER_PROOF, setCardOpen(MINT, REFUND), "an owned card's record is the owner's");
        assertEquals(SW_OWNER_PROOF, setOwner(OTHER_OWNER), "and so is the owner's key");
        // a blocked PIN is a PIN: the record is not open
        simulator = freshCard();
        assertEquals(SW_OK, setPin(TEST_PIN));
        simulator.reset(); reselect();
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(0x63C1, verify(WRONG_PIN));
        assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN));
        assertEquals(SW_SECURITY_NOT_SATIS, setCardOpen(MINT, REFUND), "a blocked card's record is not written by whoever is at the reader");
    }

    // =========================================================================
    // A locked card
    // =========================================================================

    @Test
    @DisplayName("A locked card takes no writes, still takes the time, and still pays")
    void testLocked() throws Exception {
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        byte[] n = nonceBytes();
        assertEquals(0x6B00, sw(new CommandAPDU(CLA, INS_LOCK_CARD, 0, 0, ownerData(ownerProof(L_LOCK, OWNER, n, new byte[0]), new byte[0]))),
            "without its confirming byte it is not locked, whatever the proof");
        assertEquals(SW_OK, lock());
        assertEquals(1, info()[10]);
        assertEquals(SW_NOT_ALLOWED, load(buildProof(KEYSET, 16, 2)).getSW());
        assertEquals(SW_NOT_ALLOWED, setLimit(5));
        assertEquals(SW_NOT_ALLOWED, changePin(NEW_PIN));
        assertEquals(SW_NOT_ALLOWED, allowLoad());
        assertEquals(SW_NOT_ALLOWED, setPin(NEW_PIN));
        assertEquals(SW_NOT_ALLOWED, setOwner(OTHER_OWNER));
        assertEquals(SW_NOT_ALLOWED, sw(setLimitByPinCommand(5)));
        assertEquals(SW_NOT_ALLOWED, setCard(MINT, REFUND));
        assertEquals(SW_NOT_ALLOWED, sw(new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1)));
        assertEquals(SW_CONDITIONS_NOT_SATIS, lock(), "and it is locked once");
        assertEquals(SW_OK, setTime(T0 + 10), "the time is not a write to what is locked");
        byte[] before = slot(0);
        ResponseAPDU r = spend(0);
        assertEquals(SW_OK, r.getSW());
        assertTrue(signedFor(r.getData(), before, REFUND));
    }

    @Test
    @DisplayName("LOCK_CARD is refused on a fresh card: any reader could once lock it for good")
    void testLockRefusedOnAFreshCard() {
        assertEquals(SW_SECURITY_NOT_SATIS, sw(lockCommand(new byte[8])), "no PIN, no owner");
        assertEquals(SW_SECURITY_NOT_SATIS, sw(new CommandAPDU(CLA, INS_LOCK_CARD, 0, 0xDE)), "the shape it had, with nothing");
        assertEquals(0, info()[10]);
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(SW_SECURITY_NOT_SATIS, lock(), "an owner and no PIN");
        assertEquals(0, info()[10]);
        simulator = freshCard();
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, setOwner(OWNER));
        assertEquals(SW_SECURITY_NOT_SATIS, lock(), "an owner and a PIN that has not been given");
        assertEquals(0, info()[10]);
    }

    @Test
    @DisplayName("LOCK_CARD is refused with the PIN alone, with another command's proof, with a wrong or replayed one, and with no owner")
    void testLockNeedsThePinAndItsOwnProof() {
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_NO_OWNER, sw(lockCommand(new byte[8])), "a PIN and no owner");
        assertEquals(0, info()[10]);

        simulator = freshCard();
        ready();
        assertEquals(SW_OWNER_PROOF, sw(lockCommand(new byte[8])), "the PIN alone, no nonce");
        nonceBytes();
        assertEquals(SW_OWNER_PROOF, sw(lockCommand(new byte[8])), "the PIN, a nonce, no proof");
        assertEquals(SW_OWNER_PROOF, sw(new CommandAPDU(CLA, INS_LOCK_CARD, 0, 0xDE)), "the shape it had, with nothing");
        byte[] n = nonceBytes();
        assertEquals(SW_OWNER_PROOF, sw(lockCommand(ownerProof(L_PIN, OWNER, n, new byte[0]))), "a CHANGE_PIN proof");
        n = nonceBytes();
        assertEquals(SW_OWNER_PROOF, sw(lockCommand(ownerProof(L_LIMIT, OWNER, n, new byte[0]))), "a SET_LIMIT proof");
        n = nonceBytes();
        assertEquals(SW_OWNER_PROOF, sw(lockCommand(ownerProof(L_LOAD, OWNER, n, new byte[0]))), "an ALLOW_LOAD proof");
        n = nonceBytes();
        assertEquals(SW_OWNER_PROOF, sw(lockCommand(ownerProof(L_LOCK, OTHER_OWNER, n, new byte[0]))), "another phone's key");
        byte[] n1 = nonceBytes();
        byte[] old = ownerProof(L_LOCK, OWNER, n1, new byte[0]);
        nonceBytes();
        assertEquals(SW_OWNER_PROOF, sw(lockCommand(old)), "a proof for an earlier nonce");
        assertEquals(0, info()[10], "not locked by any of them");
        assertEquals(3, info()[9], "and no try was spent");
        // after a wrong PIN there is no session, and so no lock
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(SW_SECURITY_NOT_SATIS, lock());
        assertEquals(0, info()[10]);
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, lock(), "the PIN, and its own proof");
        assertEquals(1, info()[10]);
    }

    // =========================================================================
    // RESET_CARD (1.17): the card as it was out of its packet, for another person to set up
    // =========================================================================

    /** A scalar for the card's own key (ownCardKey), as PIN_D is for the PIN key. */
    static final java.math.BigInteger CARD_D = new java.math.BigInteger("2718281828459045235360287471352662497757247093699959574966967627", 16);

    /** Gives the card's signing key a scalar of this file's choosing, so that a key made afresh by a reset is told from it (jCardSim draws the same key every time). */
    private void ownCardKey() throws Exception {
        javacard.security.ECPrivateKey priv = (javacard.security.ECPrivateKey) appletObject("cardPrivKey");
        javacard.security.ECPublicKey pub = (javacard.security.ECPublicKey) appletObject("cardPubKey");
        priv.setS(unsigned32(CARD_D), (short) 0, (short) 32);
        java.math.BigInteger[] w = ecMulTest(CARD_D, SECP_GX, SECP_GY);
        pub.setW(concat(new byte[] { 4 }, unsigned32(w[0]), unsigned32(w[1])), (short) 0, (short) 65);
    }

    /**
     * A card with a history, empty of money at the end: a record with a design, the three limits, a clock a little past the first
     * header, three pieces paid away in one payment with an output (so there are spent places, a log entry, a receipt, a kept
     * signature and a change note), and an opening of change still owed, written in by hand. The PIN is verified.
     */
    private void aCardWithAHistory() throws Exception {
        readyWithLimit(0);
        byte[] data = record(MINT, REFUND, "ABC");
        assertEquals(SW_OK, sw(setCardCommand(ownerProof(L_CARD, OWNER, nonceBytes(), data), data)));
        assertEquals(SW_OK, setAllowance(5000, 400, 300));
        assertEquals(SW_OK, setTime(T0 + 100));
        loadMany(3, i -> buildProof(KEYSET, 10 + i, i + 1));
        assertEquals(SW_OK, spendAll(new int[] { 0, 1, 2 }, new byte[][] { output(5, blinded(1)) }).getSW());
        assertEquals(0, balance());
        field("openState")[3] = 2;
        field("changeOpen")[3 * 80 + 20] = 7;
    }

    private static void assertAllZero(byte[] a, String what) {
        for (int i = 0; i < a.length; i++) if (a[i] != 0) fail(what + ": byte " + i + " is " + (a[i] & 0xFF));
    }

    @Test
    @DisplayName("RESET_CARD is instruction 0x51, with P2 = 0xAD and P1 = 0 (6B00 for any other, before the owner is looked at and with the nonce left unspent), and the constants are the applet's")
    void testResetCardShape() throws Exception {
        assertEquals(0x51, CashuApplet.INS_RESET_CARD);
        assertEquals((byte) 0xAD, CashuApplet.RESET_CONFIRM_BYTE);
        // a card with no owner: the byte is looked at first
        for (int p2 : new int[] { 0, 0xDE, 0xAC, 0xAE, 0xFF }) {
            assertEquals(0x6B00, sw(new CommandAPDU(CLA, INS_RESET_CARD, 0, p2, new byte[8])), "no owner, P2 = " + p2);
        }
        assertEquals(0x6B00, sw(new CommandAPDU(CLA, INS_RESET_CARD, 1, RESET_CONFIRM, new byte[8])), "no owner, P1 = 1");
        assertEquals(SW_NO_OWNER, sw(resetCommand(new byte[8])), "and with the byte right, 6A90");
        ready();
        byte[] n = nonceBytes();
        byte[] proof = ownerProof(L_RESET, OWNER, n, new byte[0]);
        for (int p2 : new int[] { 0, 0xDE, 0xAC, 0xAE, 0xFF }) {
            assertEquals(0x6B00, sw(new CommandAPDU(CLA, INS_RESET_CARD, 0, p2, ownerData(proof, new byte[0]))), "P2 = " + p2);
        }
        assertEquals(0x6B00, sw(new CommandAPDU(CLA, INS_RESET_CARD, 1, RESET_CONFIRM, ownerData(proof, new byte[0]))), "P1 = 1");
        assertEquals(SW_OK, sw(resetCommand(proof)), "the proof was not spent by those: it works with the right bytes");
        assertEquals(0, info()[16]);
    }

    @Test
    @DisplayName("RESET_CARD takes the owner's proof over \"CashuCard/reset\" and no value, and nothing else: a proof over a value, or data after the proof, is 6700; no data at all is 6A91; nothing changes")
    void testResetCardTakesTheProofAndNothingElse() throws Exception {
        ready();
        Object before = persistent();
        byte[] n = nonceBytes();
        byte[] proofOverOne = ownerProof(L_RESET, OWNER, n, new byte[] { 1 });
        assertEquals(SW_WRONG_LENGTH, sw(new CommandAPDU(CLA, INS_RESET_CARD, 0, RESET_CONFIRM, ownerData(proofOverOne, new byte[] { 1 }))), "a proof that is good for a value: the value is more than the command takes");
        assertEquals(SW_OWNER_PROOF, sw(new CommandAPDU(CLA, INS_RESET_CARD, 0, RESET_CONFIRM)), "no data at all");
        assertEquals(SW_OWNER_PROOF, sw(new CommandAPDU(CLA, INS_RESET_CARD, 0, RESET_CONFIRM, ownerData(ownerProof(L_RESET, OWNER, nonceBytes(), new byte[0]), new byte[3]))), "and a proof over nothing, with bytes after it, is not the proof");
        assertEquals(SW_OWNER_PROOF, sw(resetCommand(ownerProof(L_LOCK, OWNER, nonceBytes(), new byte[0]))), "another command's proof");
        assertEquals(SW_OWNER_PROOF, sw(resetCommand(ownerProof(L_RESET, OTHER_OWNER, nonceBytes(), new byte[0]))), "another key's");
        @SuppressWarnings("unchecked") java.util.Map<String, byte[]> was = (java.util.Map<String, byte[]>) before;
        assertPersistent(was, "nothing was changed by any of them");
        assertEquals(1, info()[16]);
        assertEquals(3, info()[9], "and no PIN try was spent");
    }

    @Test
    @DisplayName("RESET_CARD checks in the order: the bytes, an owner (6A90), the proof (6A91), a locked card's PIN (6982), anything unspent (6A8D); a refusal changes nothing that lasts")
    void testResetCardRefusalsAndTheirOrder() throws Exception {
        // a card with an owner, a piece on it, locked, the PIN not given: the PIN is asked before the money is
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        assertEquals(SW_OK, lock());
        simulator.reset();
        reselect();
        java.util.Map<String, byte[]> was = persistent();
        byte[] keyBefore = cardKey();
        assertEquals(SW_SECURITY_NOT_SATIS, resetCard(), "locked, the PIN not given, money on it: the PIN first");
        assertEquals(SW_OWNER_PROOF, sw(resetCommand(ownerProof(L_RESET, OTHER_OWNER, nonceBytes(), new byte[0]))), "a wrong proof comes before the PIN");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_CARD_IN_USE, resetCard(), "the PIN given and a piece unspent");
        assertPersistent(was, "neither refusal wrote anything");
        assertArrayEquals(keyBefore, cardKey(), "and the key is the key");
        assertEquals(1, info()[16]);
        assertEquals(1, info()[10], "still locked");

        // an unlocked card: money is 6A8D whatever the PIN, and the owner's proof is asked before it
        simulator = freshCard();
        ready();
        assertEquals(SW_OK, load(buildProof(KEYSET, 16, 1)).getSW());
        reselect();
        was = persistent();
        assertEquals(SW_CARD_IN_USE, resetCard(), "an unlocked card asks for no PIN, and refuses the money");
        assertEquals(SW_OWNER_PROOF, sw(resetCommand(ownerProof(L_RESET, OTHER_OWNER, nonceBytes(), new byte[0]))));
        assertPersistent(was, "nothing was written");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(0).getSW());
        assertEquals(SW_OK, resetCard(), "paid away, the piece is spent and the card resets");
        assertEquals(SW_OK, transmit(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4)).getSW());
    }

    @Test
    @DisplayName("RESET_CARD wipes the card to what it was out of its packet, and every field is read back: no PIN, three tries, no owner, not locked, no record, limits, allowance, window or spending, no log, receipts, change, kept signature, change note, place or mint's proof (1.20); it keeps the clock (the time and the header's hash, the bits go to nothing); and it is one transaction")
    void testResetCardWipes() throws Exception {
        ownPinKey();
        aCardWithAHistory();
        long nowBefore = now();
        assertEquals(T0 + 100, nowBefore);
        byte[] recordBefore = field("cardRecord").clone();
        byte[] hashBefore = headerHash();
        assertNotEquals(0, readUint32(headerBits(), 0) | 0, "the ratchet has a difficulty in it before");
        assertFalse(isAllZero(hashBefore), "and the hash of the last header");
        assertFalse(isAllZero(Arrays.copyOfRange(recordBefore, 0, 124)), "the record has things in it");
        assertFalse(isAllZero(field("cardLog")), "a log");
        assertFalse(isAllZero(field("cardReceipts")), "receipts");
        assertFalse(isAllZero(field("lastSig")), "a signature kept");
        assertEquals(1, field("changeDue")[0], "a change note");
        byte[] pinKeyBefore = askPinKey().key;
        assertEquals(1, field("pinKeySig")[0], "(the PIN key's signature is made at the first asking)");
        assertEquals(2, statusOf(0));
        assertEquals(1, info()[7]);
        byte[] keyBefore = cardKey();

        assertEquals(SW_OK, setTag(true), "the owner has switched the NFC tag off (1.19)");
        assertEquals(1, field("tagOff")[0], "and it is off before");
        Arrays.fill(field("dleq"), (byte) 0x5A);        // the mint's proofs of the last owner's pieces (1.20), whatever they were

        long commits = runtime.commits;
        assertEquals(SW_OK, resetCard());
        assertEquals(1, runtime.commits - commits, "one transaction, five bytes: the lock, the PIN, the change note, the owner and the tag's switch");

        assertAllZero(field("proofStorage"), "the places");
        for (String zero : new String[] { "cardLog", "cardReceipts", "changeOpen", "openState", "lastSig", "burnPending", "changeDue", "cardLocked", "pinState", "ownerSet", "tagOff", "dleq" }) {
            assertAllZero(field(zero), zero);
        }
        assertEquals(0, field("pinKeySig")[0], "no signature over a PIN key stands");
        byte[] want = new byte[212];
        System.arraycopy(recordBefore, 124, want, 124, 32);
        System.arraycopy(recordBefore, 185, want, 185, 4);
        assertArrayEquals(want, field("cardRecord"), "the record is zeros but for the clock's time and the header's hash");
        // what a reader sees
        byte[] d = info();
        assertEquals(30, d.length);
        byte[] fresh = new byte[30];
        fresh[0] = 2; fresh[1] = 1; fresh[2] = (byte) 128; fresh[5] = (byte) 128; fresh[6] = (byte) 0xFF; fresh[8] = 4; fresh[9] = 3;
        System.arraycopy(u32(nowBefore), 0, fresh, 17, 4);
        assertArrayEquals(fresh, d, "GET_INFO: a new card, with the clock it had");
        assertEquals(nowBefore, now());
        byte[] c = cardRecord();
        assertEquals(109, c.length);
        assertEquals(4, c[0]); assertEquals(0, c[1], "no record");
        assertAllZero(Arrays.copyOfRange(c, 2, 40), "unit, limit, refund key");
        assertAllZero(Arrays.copyOfRange(c, 40, 44), "the ratchet's bits");
        assertArrayEquals(hashBefore, headerHash(), "and the header's hash is what it was");
        assertAllZero(Arrays.copyOfRange(c, 76, 109), "nothing after: no mint, no design");
        assertAllZero(infoTap(), 30, 42, "no limit on one payment, no allowance, nothing spent with no PIN");
        assertEquals(0, infoTag()[42], "and the tag is on again (1.19)");
        assertEquals(0, balance());
        assertAllZero(transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, 256)).getData(), "the statuses");
        assertArrayEquals(new byte[16], log(), "GET_LOG: no taps, no counts (and no PIN to give: the card is open)");
        ResponseAPDU receipts = transmit(new CommandAPDU(CLA, INS_GET_LOG, 1, 0, 256));
        assertEquals(SW_OK, receipts.getSW());
        assertArrayEquals(new byte[4], receipts.getData(), "no receipts");
        assertEquals(SW_SLOT_EMPTY, transmit(new CommandAPDU(CLA, INS_GET_PROOF, 0, 0, 256)).getSW());
        // the keys are new
        assertFalse(Arrays.equals(pinKeyBefore, askPinKey().key), "a new PIN key (the card's own is told from the old one in testResetCardMakesNewKeys, where it is planted: jCardSim draws the same one every time)");
    }

    private static boolean isAllZero(byte[] a) {
        for (byte b : a) if (b != 0) return false;
        return true;
    }
    private static void assertAllZero(byte[] a, int from, int to, String what) {
        assertAllZero(Arrays.copyOfRange(a, from, to), what);
    }

    @Test
    @DisplayName("RESET_CARD gives the card a new key, and a new PIN key vouched for by it: the old key (planted here, for jCardSim draws the same one every time) is gone, the new one signs AUTH and a payment, the PIN key's signature is over the new PIN key under the new card key")
    void testResetCardMakesNewKeys() throws Exception {
        ownPinKey();
        ownCardKey();
        ready();
        java.math.BigInteger[] w = ecMulTest(CARD_D, SECP_GX, SECP_GY);
        byte[] keyBefore = cardKey();
        assertArrayEquals(compressed(w), keyBefore, "the planted key is the card's");
        PinKey oldPin = askPinKey();
        assertEquals(1, field("pinKeySig")[0]);
        assertTrue(schnorrVerify(extractPubkeyX(keyBefore), sha256(concat("CashuCard/pinkey".getBytes(StandardCharsets.US_ASCII), oldPin.key)), oldPin.sig));
        assertEquals(SW_OK, resetCard());
        assertFalse(Arrays.equals(keyBefore, cardKey()), "GET_PUBKEY is another key");
        assertEquals(33, cardKey().length);
        assertEquals(0, field("pinKeySig")[0], "the signature over the old PIN key is let go");
        PinKey newPin = askPinKey();
        assertFalse(Arrays.equals(oldPin.key, newPin.key), "the PIN key is another key");
        assertEquals(1, field("pinKeySig")[0], "and its signature is made again at the asking");
        assertTrue(schnorrVerify(extractPubkeyX(cardKey()), sha256(concat("CashuCard/pinkey".getBytes(StandardCharsets.US_ASCII), newPin.key)), newPin.sig), "the new card key vouches for the new PIN key");
        assertFalse(schnorrVerify(extractPubkeyX(cardKey()), sha256(concat("CashuCard/pinkey".getBytes(StandardCharsets.US_ASCII), oldPin.key)), oldPin.sig), "and not for the old");
        assertFalse(schnorrVerify(extractPubkeyX(keyBefore), sha256(concat("CashuCard/pinkey".getBytes(StandardCharsets.US_ASCII), newPin.key)), newPin.sig), "nor does the old key");
        // it proves it is the card: AUTH under the new key
        byte[] reader = new byte[16];
        Arrays.fill(reader, (byte) 0x5A);
        ResponseAPDU auth = transmit(new CommandAPDU(CLA, INS_AUTH, 0, 0, reader, 256));
        assertEquals(SW_OK, auth.getSW());
        byte[] cardNonce = Arrays.copyOfRange(auth.getData(), 0, 16), sig = Arrays.copyOfRange(auth.getData(), 16, 80);
        assertTrue(schnorrVerify(extractPubkeyX(cardKey()), authMessage(reader, cardNonce, cardKey()), sig), "AUTH is signed by the new key");
        assertFalse(schnorrVerify(extractPubkeyX(keyBefore), authMessage(reader, cardNonce, keyBefore), sig), "and not by the old");
        // and a payment, set up by another person
        simulator.reset();
        reselect();
        assertEquals(SW_OK, setPin(NEW_PIN));
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, setCardOpen(MINT, REFUND));
        assertEquals(SW_OK, setOwner(OTHER_OWNER));
        assertEquals(SW_OK, load(buildProof(KEYSET, 25, 9)).getSW());
        byte[] piece = slot(0);
        ResponseAPDU paid = spend(0);
        assertEquals(SW_OK, paid.getSW());
        assertTrue(signedFor(paid.getData(), piece, REFUND), "the payment is signed by the card's new key (signedFor reads GET_PUBKEY)");
    }

    @Test
    @DisplayName("RESET_CARD keeps the clock: the time, and the hash of the last header, stay; the ratchet's bits go to nothing, so the next header sets them; the window and the spending are cleared; an older header changes nothing, a newer one moves the clock on")
    void testResetCardKeepsTheClock() throws Exception {
        aCardWithAHistory();
        byte[] hash = headerHash();
        long t = now();
        assertEquals(SW_OK, resetCard());
        assertEquals(t, now());
        assertArrayEquals(hash, headerHash());
        assertArrayEquals(new byte[4], headerBits());
        assertEquals(0, windowStart());
        assertEquals(0, spentToday());
        assertEquals(SW_OK, setTime(t - 50));
        assertEquals(t, now(), "an older header changes nothing");
        assertEquals(SW_OK, setTime(t + 50));
        assertEquals(t + 50, now());
        assertFalse(isAllZero(headerBits()), "and the bits are set afresh by the header");
    }

    @Test
    @DisplayName("RESET_CARD leaves a card another person sets up as they would a new one: with a PIN or with none, an open record, a new owner; the old owner's proofs fail (6A90 before a new owner is set, 6A91 after), and the old owner cannot reset it")
    void testResetCardIsSetUpAfreshByAnotherOwner() throws Exception {
        aCardWithAHistory();
        assertEquals(SW_OK, resetCard());
        simulator.reset();
        reselect();
        // the old owner has nothing to prove against
        assertEquals(SW_NO_OWNER, nonce().getSW());
        assertEquals(SW_NO_OWNER, sw(resetCommand(ownerProof(L_RESET, OWNER, new byte[16], new byte[0]))), "a reset by the old owner");
        assertEquals(SW_NO_OWNER, sw(changePinCommand(ownerProof(L_PIN, OWNER, new byte[16], NEW_PIN), NEW_PIN)));
        assertEquals(SW_NO_OWNER, load(buildProof(KEYSET, 5, 70)).getSW(), "nothing loads onto a card with no owner");
        // set up with a PIN, as the phone does it
        assertEquals(3, info()[9]);
        assertEquals(SW_OK, setPin(NEW_PIN));
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, setCardOpen("https://other.example.com", NO_REFUND));
        assertEquals(SW_OK, setOwner(OTHER_OWNER));
        assertEquals(1, info()[16]);
        assertEquals(1, info()[11]);
        assertEquals(SW_OWNER_PROOF, setLimit(5), "the old owner's proof is no proof now");
        assertEquals(SW_OWNER_PROOF, resetCard(), "nor does it reset the card");
        assertEquals(SW_OWNER_PROOF, sw(changePinCommand(ownerProof(L_PIN, OWNER, nonceBytes(), TEST_PIN), TEST_PIN)));
        assertEquals(SW_OK, sw(setLimitCommand(ownerProof(L_LIMIT, OTHER_OWNER, nonceBytes(), u32(9)), 9)), "the new owner's is");
        assertEquals(9, limit());
        assertEquals(SW_OK, load(buildProof(KEYSET, 5, 71)).getSW(), "and loading works");
        assertEquals(1, logTaps(), "the log begins at once with this tap's load");

        // or with no PIN at all (1.16)
        simulator = freshCard();
        aCardWithAHistory();
        assertEquals(SW_OK, resetCard());
        simulator.reset();
        reselect();
        assertEquals(0, info()[7], "no PIN");
        assertEquals(SW_OK, setCardOpen(MINT, REFUND), "a record with no PIN");
        assertEquals(SW_OK, setOwner(OTHER_OWNER));
        assertEquals(SW_OK, load(buildProof(KEYSET, 5, 72)).getSW(), "loaded by whoever holds it");
        assertEquals(SW_OWNER_PROOF, setLimit(5), "the old owner is refused");
    }

    @Test
    @DisplayName("RESET_CARD on a locked card wants the owner's proof and the PIN given in this tap (6982 without it, before the money is looked at); it unlocks the card, and a locked card whose PIN is blocked cannot be reset")
    void testResetCardOnALockedCard() throws Exception {
        ready();
        assertEquals(SW_OK, lock());
        assertEquals(1, info()[10]);
        assertEquals(SW_OK, resetCard(), "the PIN was given in this tap, and the card is empty");
        assertEquals(0, info()[10], "no longer locked");
        assertEquals(0, info()[7]);
        assertEquals(SW_OK, setPin(NEW_PIN), "and takes writes: the lock is gone, not just the PIN");
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, setCardOpen(MINT, REFUND));
        assertEquals(SW_OK, setOwner(OTHER_OWNER));
        assertEquals(SW_OK, load(buildProof(KEYSET, 5, 3)).getSW());

        simulator = freshCard();
        ready();
        assertEquals(SW_OK, lock());
        simulator.reset();
        reselect();
        assertEquals(SW_SECURITY_NOT_SATIS, resetCard(), "locked, the PIN not given");
        assertEquals(1, info()[10]);
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(SW_SECURITY_NOT_SATIS, resetCard(), "a wrong PIN ends the session");
        assertEquals(0x63C1, verify(WRONG_PIN));
        assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN));
        assertEquals(2, info()[7], "blocked");
        assertEquals(SW_SECURITY_NOT_SATIS, resetCard(), "locked and blocked: the PIN can never be given, and the card stays as it is");
        assertEquals(1, info()[10]);
        assertEquals(1, info()[16]);
    }

    @Test
    @DisplayName("RESET_CARD on a card whose PIN is blocked, not locked, is no bar: the owner is resetting, not unblocking; the card has no PIN and three tries after")
    void testResetCardWithABlockedPin() throws Exception {
        ready();
        simulator.reset();
        reselect();
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(0x63C1, verify(WRONG_PIN));
        assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN));
        assertEquals(2, info()[7]);
        assertEquals(0, info()[9]);
        assertEquals(SW_OK, resetCard());
        assertEquals(0, info()[7], "no PIN");
        assertEquals(3, info()[9], "three tries");
        assertEquals(SW_PIN_NOT_SET, verify(TEST_PIN), "and the old PIN verifies nothing");
        assertEquals(SW_OK, setPin(NEW_PIN));
        assertEquals(1, info()[7]);
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(0x63C2, verify(TEST_PIN), "the old PIN is not the PIN");
    }

    @Test
    @DisplayName("RESET_CARD clears an opening of change that is owed, a kept signature and a change note, and a grant given in the tap: the tap after it is a new card's, and the log begins with its first entry; a new tap is not needed")
    void testResetCardClearsWhatTheTapHeld() throws Exception {
        aCardWithAHistory();
        assertEquals(SW_OK, allowLoad());
        assertEquals(1, field("loadGrant")[0]);
        assertEquals(SW_OK, resetCard());
        assertEquals(0, field("loadGrant")[0], "the owner's grant is gone");
        assertEquals(0, field("pinVerifiedFlag")[0], "and the PIN given");
        assertEquals(0, field("changeGrant")[0]);
        assertAllZero(field("openState"), "the owed change");
        assertEquals(SW_SLOT_EMPTY, sw(new CommandAPDU(CLA, INS_SPEND_ALL_AGAIN, 0, 0, 64)), "no signature to give again");
        assertAllZero(transmit(new CommandAPDU(CLA, INS_GET_CHANGE, 0, 0, 256)).getData(), "no change owed (the count is 0)");
        // the next entry in the log is the first
        assertEquals(SW_OK, setPin(NEW_PIN));
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, setCardOpen(MINT, REFUND));
        assertEquals(SW_OK, setOwner(OTHER_OWNER));
        assertEquals(SW_OK, load(buildProof(KEYSET, 5, 80)).getSW());
        assertEquals(1, logTaps());
        assertEquals(5, readUint32(log(), 16 + 12), "sats put on, in the first entry");
    }

    @Test
    @DisplayName("RESET_CARD torn after its one transaction commits leaves a new card, with at worst the old PIN's tries not yet back; torn before it (the owner still there) it can be sent again, with the card half wiped")
    void testResetCardTorn() throws Exception {
        ready();
        simulator.reset();
        reselect();
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(0x63C1, verify(WRONG_PIN));
        assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN));
        runtime.commitsUntilTear = 1;
        byte[] n = nonceBytes();
        ResponseAPDU lost;
        try {
            lost = transmit(resetCommand(ownerProof(L_RESET, OWNER, n, new byte[0])));
        } catch (RuntimeException e) {
            lost = null;
        } finally {
            runtime.commitsUntilTear = 0;
        }
        assertTrue(lost == null || lost.getSW() != SW_OK, "nothing was answered");
        // as it was left: who the card is was changed in the transaction
        assertEquals(0, field("ownerSet")[0]);
        assertEquals(0, field("pinState")[0]);
        assertEquals(0, field("cardLocked")[0]);
        simulator.reset();
        reselect();
        assertEquals(0, info()[7]);
        assertEquals(SW_NO_OWNER, nonce().getSW());
        assertEquals(SW_OK, setPin(NEW_PIN), "set up as a new card");
        assertEquals(3, info()[9], "and a new PIN has its three tries");
        assertEquals(SW_OK, verify(NEW_PIN));

        // torn before: the record and the log wiped by hand, the owner there, and the card resets again
        simulator = freshCard();
        aCardWithAHistory();
        Arrays.fill(field("cardLog"), (byte) 0);
        Arrays.fill(field("cardRecord"), 0, 124, (byte) 0);
        simulator.reset();
        reselect();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(1, info()[16]);
        assertEquals(SW_OK, resetCard(), "the owner is still there, and resets it");
        assertEquals(0, info()[16]);
    }

    @Test
    @DisplayName("RESET_CARD's source: the bytes, the owner, the proof, the locked card's PIN and the money are checked in that order, before anything is written; the wipe is outside any transaction but one of five bytes, which comes after the keys and holds the lock, the PIN, the change note, the owner and the tag's switch; the signature over the PIN key is let go before the keys are drawn; the PIN's bytes and tries are written after")
    void testResetCardSource() throws Exception {
        String code = appletCode();
        String r = body(code, "private void processResetCard(", "private void requireNotLocked(");
        int[] order = { r.indexOf("OFFSET_P2] != RESET_CONFIRM_BYTE"), r.indexOf("ownerSet[0] != (byte) 1"), r.indexOf("requireOwnerProof(LABEL_RESET"),
            r.indexOf("cardLocked[0] == (byte) 1 && pinVerifiedFlag[0] != (byte) 1"), r.indexOf("requireNothingUnspent()"), r.indexOf("freeSpent()"),
            r.indexOf("pinKeySig[0] = (byte) 0"), r.indexOf("cardKeyPair.genKeyPair()"), r.indexOf("pinKeyPair.genKeyPair()"), r.indexOf("beginTransaction"),
            r.indexOf("cardLocked[0] = (byte) 0"), r.indexOf("pinState[0] = (byte) 0"), r.indexOf("ownerSet[0] = (byte) 0"), r.indexOf("commitTransaction"),
            r.indexOf("pin.update(") };
        for (int i = 0; i < order.length; i++) {
            assertTrue(order[i] > 0, "step " + i + " is there");
            if (i > 0) assertTrue(order[i - 1] < order[i], "step " + i + " follows step " + (i - 1));
        }
        assertEquals(1, count(r, "beginTransaction"), "one transaction");
        assertEquals(1, count(r, "commitTransaction"));
        String tx = r.substring(r.indexOf("beginTransaction"), r.indexOf("commitTransaction"));
        assertEquals(5, count(tx, "[0] = (byte) 0;"), "five bytes in it");
        assertTrue(tx.contains("changeDue[0] = (byte) 0;"));
        assertTrue(tx.contains("tagOff[0] = (byte) 0;"), "and one of them puts the NFC tag back on (1.19)");
        assertFalse(tx.contains("arrayFill") || tx.contains("arrayCopy") || tx.contains("setW") || tx.contains("genKeyPair"), "and nothing else");
        assertTrue(r.contains("ownerKey.setW(P256_G"), "the old owner's key is written over");
        assertEquals(2, count(r, "genKeyPair"), "two keys drawn, from the key objects the card has");
        assertFalse(r.contains("new KeyPair") || r.contains("initCardKeypair") || r.contains("initPinKey"), "no new key object is allocated, which a chip has no way to free");
        assertFalse(r.contains("CARD_NOW_OFFSET, ") && r.contains("arrayFillNonAtomic(cardRecord, CARD_NOW_OFFSET"), "the clock is not written");
        assertTrue(r.contains("CARD_HEADER_OFFSET + 32") && r.contains("CARD_WINDOW_OFFSET"), "the record is cleared in three runs that step over the header's hash and the clock");
        // and it is dispatched, and answers nothing
        assertTrue(body(code, "switch (buf[ISO7816.OFFSET_INS])", "default:").contains("case INS_RESET_CARD:       processResetCard(apdu);"));
        assertFalse(r.contains("setOutgoing"), "an empty answer");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /** Where, if set, every command is preceded by this much rubbish in the applet's scratch (the room a sealed command works in is the first 99 bytes of it). */
    private java.util.Random scratchPoison;
    /** Where, if set, every answer is written down: its status, a colon, its data. */
    private java.util.List<String> answersRecorded;

    private ResponseAPDU transmit(CommandAPDU apdu) {
        if (scratchPoison != null) {
            try {
                scratchPoison.nextBytes(field("scratch"));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
        ResponseAPDU r = simulator.transmitCommand(apdu);
        answered.add(r.getSW());
        if (answersRecorded != null) answersRecorded.add(String.format("%04x:%s", r.getSW(), toHex(r.getData())));
        return r;
    }

    /**
     * Install and SELECT a brand-new card. Each one runs genKeyPair() afresh, so
     * successive calls draw independent card keys (and independent P.y parities).
     * The runtime is kept, so what no command reaches can be read and set.
     */
    private CardSimulator freshCard() {
        runtime = new ExposedRuntime();
        CardSimulator sim = new CardSimulator(runtime);
        sim.installApplet(AIDUtil.create(AID_HEX), CashuApplet.class);
        ResponseAPDU resp = sim.transmitCommand(
            new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(AID_STR)));
        assertEquals(SW_OK, resp.getSW(), "SELECT on a fresh card should succeed");
        return sim;
    }

    /** Parity of the public key's y-coordinate, from either EC point encoding. */
    static boolean pubkeyYIsOdd(byte[] pubBytes) {
        if (pubBytes.length == 65 && pubBytes[0] == 0x04) {
            return (pubBytes[64] & 1) == 1;          // uncompressed: LSB of Y
        } else if (pubBytes.length == 33) {
            return (pubBytes[0] & 1) == 1;           // compressed: 0x02 even / 0x03 odd
        }
        throw new IllegalArgumentException("Unexpected pubkey length: " + pubBytes.length);
    }

    /**
     * Build an 81-byte proof payload: keyset_id[8] + amount[4] + nonce[32] + C[33] + date[4].
     *
     * keysetIdHex is hex-decoded to 8 RAW bytes, never ASCII-encoded. The
     * 32-byte field is the P2PK nonce, not the secret string. `date` is the
     * piece's locktime, 0 for none.
     */
    static byte[] buildProof(String keysetIdHex, long amount, int seed, long date) {
        if (keysetIdHex.length() != 16) {
            throw new IllegalArgumentException(
                "keyset id must be 16 hex chars (8 raw bytes), got " + keysetIdHex.length()
                + ": " + keysetIdHex);
        }
        byte[] proof = new byte[81];
        System.arraycopy(hexToBytes(keysetIdHex), 0, proof, 0, 8);
        putUint32(proof, 8, amount);
        for (int i = 0; i < 32; i++) proof[12 + i] = (byte) (seed + i);
        proof[44] = 0x02;
        for (int i = 0; i < 32; i++) proof[45 + i] = (byte)(seed + 1);
        putUint32(proof, 77, date);
        return proof;
    }

    static byte[] buildProof(String keysetIdHex, long amount, int seed) {
        return buildProof(keysetIdHex, amount, seed, 0);
    }

    static void putUint32(byte[] buf, int off, long v) {
        buf[off]     = (byte)((v >> 24) & 0xFF);
        buf[off + 1] = (byte)((v >> 16) & 0xFF);
        buf[off + 2] = (byte)((v >> 8)  & 0xFF);
        buf[off + 3] = (byte)( v        & 0xFF);
    }

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte v : b) sb.append(String.format("%02x", v & 0xFF));
        return sb.toString();
    }

    static byte[] sha256(byte[] in) {
        try { return java.security.MessageDigest.getInstance("SHA-256").digest(in); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    /**
     * A piece's NUT-10 secret, as whoever makes the piece writes it and as the
     * card must rebuild it (CashuApplet's SECRET_* constants). Written out here
     * by hand, on purpose: this is the other side of the wire.
     */
    static String secretText(byte[] nonce, byte[] cardKey, long date, byte[] refundKey) {
        String s = "[\"P2PK\",{\"nonce\":\"" + toHex(nonce) + "\",\"data\":\"" + toHex(cardKey)
                 + "\",\"tags\":[";
        // the flag is every piece's last tag, as the wallet's library writes it: after the refund key, or alone
        if (date != 0) s += "[\"locktime\",\"" + date + "\"],[\"refund\",\"" + toHex(refundKey) + "\"],";
        return s + "[\"sigflag\",\"SIG_ALL\"]]}]";
    }

    static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
    }

    static long readUint32(byte[] buf, int offset) {
        return ((long)(buf[offset]     & 0xFF) << 24)
             | ((long)(buf[offset + 1] & 0xFF) << 16)
             | ((long)(buf[offset + 2] & 0xFF) << 8)
             |  (long)(buf[offset + 3] & 0xFF);
    }

    // =========================================================================
    // Schnorr / EC helpers (BigInteger, jCardSim/JVM only)
    // =========================================================================

    static final java.math.BigInteger SECP_P = new java.math.BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    static final java.math.BigInteger SECP_N = new java.math.BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    static final java.math.BigInteger SECP_GX = new java.math.BigInteger(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    static final java.math.BigInteger SECP_GY = new java.math.BigInteger(
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);

    /**
     * BIP-340 Schnorr verify.
     * sig = R.x (32) || s (32)
     */
    static boolean schnorrVerify(byte[] pubX, byte[] msg, byte[] sig)
            throws java.security.NoSuchAlgorithmException {
        java.math.BigInteger p = SECP_P;
        java.math.BigInteger n = SECP_N;

        java.math.BigInteger r = new java.math.BigInteger(1,
            java.util.Arrays.copyOfRange(sig, 0, 32));
        java.math.BigInteger s = new java.math.BigInteger(1,
            java.util.Arrays.copyOfRange(sig, 32, 64));

        if (r.compareTo(p) >= 0) return false;
        if (s.compareTo(n) >= 0) return false;

        // P = lift_x(pubX) — even-y point
        java.math.BigInteger[] P = liftX(new java.math.BigInteger(1, pubX));
        if (P == null) return false;

        // e = tagged_hash("BIP0340/challenge", bytes(r) || bytes(P.x) || msg) mod n
        byte[] rBytes  = toBytes32Test(r);
        byte[] PxBytes = toBytes32Test(P[0]);
        byte[] challengeInput = new byte[96];
        System.arraycopy(rBytes,  0, challengeInput,  0, 32);
        System.arraycopy(PxBytes, 0, challengeInput, 32, 32);
        System.arraycopy(msg,     0, challengeInput, 64, 32);
        java.math.BigInteger e = new java.math.BigInteger(1,
            taggedHashTest("BIP0340/challenge", challengeInput)).mod(n);

        // R = s*G - e*P  (subtract = add negated point: -P = (P.x, p - P.y))
        java.math.BigInteger[] sG  = ecMulTest(s,  SECP_GX, SECP_GY);
        java.math.BigInteger[] eP  = ecMulTest(e,  P[0],    P[1]);
        if (sG == null || eP == null) return false;

        // Negate eP: (eP.x, p - eP.y)
        java.math.BigInteger[] negEP = { eP[0], p.subtract(eP[1]) };
        java.math.BigInteger[] R = ecAddTest(sG[0], sG[1], negEP[0], negEP[1]);
        if (R == null) return false;

        // R.y must be even, R.x must equal r
        if (R[1].testBit(0)) return false;
        return R[0].equals(r);
    }

    /** lift_x: find the even-y point on secp256k1 with the given x-coordinate. */
    static java.math.BigInteger[] liftX(java.math.BigInteger x) {
        java.math.BigInteger p = SECP_P;
        if (x.compareTo(p) >= 0) return null;
        java.math.BigInteger rhs = x.modPow(java.math.BigInteger.valueOf(3), p)
            .add(java.math.BigInteger.valueOf(7)).mod(p);
        java.math.BigInteger y = rhs.modPow(p.add(java.math.BigInteger.ONE)
            .divide(java.math.BigInteger.valueOf(4)), p);
        // Verify it's actually a square root
        if (!y.modPow(java.math.BigInteger.TWO, p).equals(rhs)) return null;
        // Choose even y
        if (y.testBit(0)) y = p.subtract(y);
        return new java.math.BigInteger[]{ x, y };
    }

    /** Extract 32-byte x-coordinate from a compressed (33) or uncompressed (65) public key. */
    static byte[] extractPubkeyX(byte[] pubBytes) {
        if (pubBytes.length == 65 && pubBytes[0] == 0x04) {
            return java.util.Arrays.copyOfRange(pubBytes, 1, 33);
        } else if (pubBytes.length == 33) {
            return java.util.Arrays.copyOfRange(pubBytes, 1, 33);
        }
        throw new IllegalArgumentException("Unexpected pubkey length: " + pubBytes.length);
    }

    /** Returns true if every byte in the array is 0x00. */
    static boolean isAllZeros(byte[] b) {
        for (byte v : b) if (v != 0) return false;
        return true;
    }

    /** Scalar multiplication: k * (x,y) using double-and-add. */
    static java.math.BigInteger[] ecMulTest(java.math.BigInteger k,
                                             java.math.BigInteger x,
                                             java.math.BigInteger y) {
        java.math.BigInteger[] R = null;
        java.math.BigInteger[] P = { x, y };
        k = k.mod(SECP_N);
        while (k.signum() > 0) {
            if (k.testBit(0)) {
                R = (R == null) ? new java.math.BigInteger[]{ P[0], P[1] }
                                : ecAddTest(R[0], R[1], P[0], P[1]);
            }
            P = ecAddTest(P[0], P[1], P[0], P[1]);
            k = k.shiftRight(1);
        }
        return R;
    }

    /** EC point addition / doubling on secp256k1. Returns null for point at infinity. */
    static java.math.BigInteger[] ecAddTest(java.math.BigInteger x1,
                                             java.math.BigInteger y1,
                                             java.math.BigInteger x2,
                                             java.math.BigInteger y2) {
        java.math.BigInteger p  = SECP_P;
        java.math.BigInteger p2 = p.subtract(java.math.BigInteger.TWO);
        java.math.BigInteger lambda;
        if (x1.equals(x2)) {
            if (!y1.equals(y2)) return null; // point at infinity
            // doubling
            java.math.BigInteger num = java.math.BigInteger.valueOf(3)
                .multiply(x1.modPow(java.math.BigInteger.TWO, p)).mod(p);
            java.math.BigInteger den = java.math.BigInteger.valueOf(2).multiply(y1).mod(p);
            lambda = num.multiply(den.modPow(p2, p)).mod(p);
        } else {
            java.math.BigInteger num = y2.subtract(y1).mod(p);
            java.math.BigInteger den = x2.subtract(x1).mod(p);
            lambda = num.multiply(den.modPow(p2, p)).mod(p);
        }
        java.math.BigInteger x3 = lambda.modPow(java.math.BigInteger.TWO, p)
            .subtract(x1).subtract(x2).mod(p);
        java.math.BigInteger y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(p);
        if (x3.signum() < 0) x3 = x3.add(p);
        if (y3.signum() < 0) y3 = y3.add(p);
        return new java.math.BigInteger[]{ x3, y3 };
    }

    /** BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg) */
    static byte[] taggedHashTest(String tag, byte[] msg)
            throws java.security.NoSuchAlgorithmException {
        java.security.MessageDigest sha =
            java.security.MessageDigest.getInstance("SHA-256");
        byte[] tagHash = sha.digest(
            tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        sha.reset();
        sha.update(tagHash);
        sha.update(tagHash);
        sha.update(msg);
        return sha.digest();
    }

    /** BigInteger → big-endian 32-byte array (zero-padded / sign-stripped). */
    static byte[] toBytes32Test(java.math.BigInteger n) {
        byte[] b = n.toByteArray();
        if (b.length == 32) return b;
        byte[] out = new byte[32];
        if (b.length > 32) {
            System.arraycopy(b, b.length - 32, out, 0, 32);
        } else {
            System.arraycopy(b, 0, out, 32 - b.length, b.length);
        }
        return out;
    }

    // Expose ISO7816 constants for tests
    static class ISO7816 {
        static final int SW_COMMAND_NOT_ALLOWED = 0x6986;

}
}
