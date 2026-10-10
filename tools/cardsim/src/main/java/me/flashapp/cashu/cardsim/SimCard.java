package me.flashapp.cashu.cardsim;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import me.flashapp.cashu.CashuApplet;

import java.util.Arrays;

/**
 * One simulated card: the real {@link CashuApplet} installed into a
 * jCardSim {@link CardSimulator} exactly as the applet's own test suite does
 * it (CashuAppletTest.setup), driven with raw APDU bytes so that the bytes
 * the app sends are the bytes the applet sees.
 *
 * <p><b>Thread confinement.</b> jCardSim keeps the active runtime in a
 * {@code ThreadLocal} ({@code SimulatorSystem.currentRuntime}), set when the
 * simulator is constructed. Every call on this object — the constructor
 * included — must come from the same thread. {@link CardSim} guarantees that
 * by building it lazily inside its single-thread executor.
 *
 * <p><b>SELECT starts a session.</b> The applet's PIN-verified flag is a
 * {@code CLEAR_ON_DESELECT} transient (CashuApplet.java, pinVerifiedFlag), so
 * a re-SELECT drops a verified session, as a new NFC tap does. A fake
 * transport sends SELECT on every tap; there is no separate "tap" operation here.
 *
 * <p><b>The key is deterministic.</b> jCardSim's key generator draws from an
 * unseeded generator, so every install — every {@link #reset()} — yields the
 * same keypair. A proof minted to this key in one run is spent at the mint
 * after any run that redeemed it. Loaders mint per run, after reading
 * {@code pubkey} from {@link #state()}.
 */
final class SimCard {

    static final String AID_HEX = "D276000085010200";
    static final byte[] SELECT = Hex.parse("00A4040007D2760000850102");

    static final int SW_OK = 0x9000;

    private static final byte[] GET_INFO = Hex.parse("B001000000");
    private static final byte[] GET_PUBKEY = Hex.parse("B010000021");
    private static final byte[] GET_BALANCE = Hex.parse("B011000004");
    private static final byte[] GET_SLOT_STATUS = Hex.parse("B014000020");
    private static final byte[] ZERO_MESSAGE = new byte[32];
    private static final byte[] WRONG_PIN_DEFAULT = { '0', '0', '0', '0' };
    private static final byte[] WRONG_PIN_ALT = { '9', '9', '9', '9' };

    private CardSimulator sim;
    private VersionMask real;
    private VersionMask mask;
    private long generation;
    private FixtureException fixtureError;

    SimCard() {
        install();
        generation = 0;
    }

    private void install() {
        sim = new CardSimulator();
        sim.installApplet(AIDUtil.create(AID_HEX), CashuApplet.class);
        byte[] resp = sim.transmitCommand(SELECT);
        if (sw(resp) != SW_OK || resp.length != 4) {
            throw new IllegalStateException("SELECT after install answered " + Hex.format(resp));
        }
        real = VersionMask.real(Arrays.copyOf(resp, 2));
        mask = real;
        fixtureError = null;
    }

    /** A brand-new card: fresh simulator, install, SELECT, mask back to real. */
    void reset() {
        install();
        generation++;
    }

    long generation() {
        return generation;
    }

    VersionMask real() {
        return real;
    }

    /**
     * Send raw command bytes through the active version mask and return
     * data‖SW. Nothing here retries: a replayed LOAD_PROOF burns a slot and a
     * replayed SPEND_PROOF answers 6985.
     */
    byte[] transmit(byte[] command) {
        if (command == null || command.length < 4) {
            throw new IllegalArgumentException("an APDU is at least CLA INS P1 P2 (4 bytes)");
        }
        byte[] refused = mask.refuse(command);
        if (refused != null) return refused;
        return mask.rewrite(command, sim.transmitCommand(command));
    }

    /** Straight to the applet: never masked. For fixtures and state. */
    private byte[] raw(byte[] command) {
        return sim.transmitCommand(command);
    }

    /**
     * Apply a fixture, additively, to the current card. The order is the one
     * the applet's gates dictate:
     * <ol>
     *   <li>LOAD_PROOF per proof — ungated while no PIN exists;</li>
     *   <li>SPEND_PROOF over 32 zero bytes per spent slot — before SET_PIN,
     *       which would gate it. Spent on the card only: the mint still
     *       holds the proof live, so a flow that reconciles with the mint
     *       before CLEAR_SPENT sees a mismatch, and a reclaim test that needs
     *       mint-spent slots redeems them with a real swap instead;</li>
     *   <li>SET_PUK — unverified while pinState is 0, so before SET_PIN;</li>
     *   <li>SET_PIN;</li>
     *   <li>three wrong VERIFY_PINs when blockedPin, expecting 63C2, 63C1, 6983;</li>
     *   <li>the version mask;</li>
     *   <li>SELECT, so the app's first command finds an unverified session.</li>
     * </ol>
     * The generation moves on success and on failure. A refused step leaves
     * the card as the steps before it left it, with {@code fixtureError} set
     * until the next fixture or reset.
     */
    void applyFixture(Fixture f) throws FixtureException {
        generation++;
        fixtureError = null;
        try {
            int[] slotOf = new int[f.proofs.size()];
            for (int i = 0; i < f.proofs.size(); i++) {
                byte[] resp = expect("LOAD_PROOF", apdu(0x30, 0, 0, f.proofs.get(i).payload(), 0x01), SW_OK);
                slotOf[i] = resp[0] & 0xFF;
            }
            for (int idx : f.spentSlots) {
                expect("SPEND_PROOF", apdu(0x20, slotOf[idx], 0, ZERO_MESSAGE, 0x40), SW_OK);
            }
            if (f.puk != null) {
                expect("SET_PUK", apdu(0x44, 0, 0, lengthPrefixed(f.puk), -1), SW_OK);
            }
            if (f.pin != null) {
                expect("SET_PIN", apdu(0x41, 0, 0, f.pin, -1), SW_OK);
            }
            if (f.blockedPin) {
                byte[] wrong = Arrays.equals(f.pin, WRONG_PIN_DEFAULT) ? WRONG_PIN_ALT : WRONG_PIN_DEFAULT;
                expect("VERIFY_PIN", apdu(0x40, 0, 0, wrong, -1), 0x63C2);
                expect("VERIFY_PIN", apdu(0x40, 0, 0, wrong, -1), 0x63C1);
                expect("VERIFY_PIN", apdu(0x40, 0, 0, wrong, -1), 0x6983);
            }
            mask = f.mask != null ? f.mask : real;
            expect("SELECT", SELECT, SW_OK);
        } catch (FixtureException e) {
            fixtureError = e;
            throw e;
        }
    }

    private byte[] expect(String step, byte[] command, int expectedSw) throws FixtureException {
        byte[] resp = raw(command);
        int sw = sw(resp);
        if (sw != expectedSw) throw new FixtureException(step, sw);
        return resp;
    }

    /**
     * The card as the applet reports it, unmasked, through non-PIN-gated
     * reads only (GET_INFO, GET_PUBKEY, GET_BALANCE, GET_SLOT_STATUS, and
     * GET_PROOF for each non-empty slot). Reading never touches the session.
     */
    JsonObject state() {
        JsonObject s = new JsonObject();
        s.addProperty("generation", generation);
        s.addProperty("appletVersion", mask.version());
        s.addProperty("realVersion", real.version());
        s.addProperty("deterministicKey", true);

        byte[] info = data(raw(GET_INFO), "GET_INFO");
        byte[] pubkey = data(raw(GET_PUBKEY), "GET_PUBKEY");
        byte[] balance = data(raw(GET_BALANCE), "GET_BALANCE");
        byte[] status = data(raw(GET_SLOT_STATUS), "GET_SLOT_STATUS");

        s.addProperty("pubkey", Hex.formatLower(pubkey));
        s.addProperty("balance", readUint32(balance, 0));
        s.addProperty("pinState", info[7] & 0xFF);
        s.addProperty("pukState", info.length > 8 ? info[8] & 0xFF : 0);

        JsonArray slots = new JsonArray();
        for (int i = 0; i < status.length; i++) {
            JsonObject slot = new JsonObject();
            slot.addProperty("slot", i);
            slot.addProperty("status", statusName(status[i]));
            if (status[i] != 0) {
                byte[] p = data(raw(apdu(0x13, i, 0, null, 0x4E)), "GET_PROOF");
                slot.addProperty("keysetId", Hex.formatLower(p, 1, 8));
                slot.addProperty("amount", readUint32(p, 9));
                slot.addProperty("nonce", Hex.formatLower(p, 13, 32));
                slot.addProperty("C", Hex.formatLower(p, 45, 33));
            }
            slots.add(slot);
        }
        s.add("slots", slots);

        if (fixtureError != null) {
            JsonObject err = new JsonObject();
            err.addProperty("step", fixtureError.step);
            err.addProperty("sw", Hex.sw(fixtureError.sw));
            s.add("fixtureError", err);
        }
        return s;
    }

    static String statusName(byte b) {
        switch (b) {
            case 0: return "empty";
            case 1: return "unspent";
            case 2: return "spent";
            default: return "unknown(" + (b & 0xFF) + ")";
        }
    }

    private static byte[] data(byte[] resp, String what) {
        if (sw(resp) != SW_OK) {
            throw new IllegalStateException(what + " answered " + Hex.sw(sw(resp)));
        }
        return Arrays.copyOf(resp, resp.length - 2);
    }

    static int sw(byte[] resp) {
        if (resp == null || resp.length < 2) throw new IllegalStateException("response shorter than a status word");
        return ((resp[resp.length - 2] & 0xFF) << 8) | (resp[resp.length - 1] & 0xFF);
    }

    static long readUint32(byte[] b, int off) {
        return ((long) (b[off] & 0xFF) << 24) | ((long) (b[off + 1] & 0xFF) << 16)
             | ((long) (b[off + 2] & 0xFF) << 8) | (long) (b[off + 3] & 0xFF);
    }

    /** CLA B0 ‖ INS ‖ P1 ‖ P2 [‖ Lc ‖ data] [‖ Le]; {@code le < 0} means no Le. */
    static byte[] apdu(int ins, int p1, int p2, byte[] data, int le) {
        int len = 4 + (data != null && data.length > 0 ? 1 + data.length : 0) + (le >= 0 ? 1 : 0);
        byte[] out = new byte[len];
        out[0] = (byte) 0xB0;
        out[1] = (byte) ins;
        out[2] = (byte) p1;
        out[3] = (byte) p2;
        int i = 4;
        if (data != null && data.length > 0) {
            out[i++] = (byte) data.length;
            System.arraycopy(data, 0, out, i, data.length);
            i += data.length;
        }
        if (le >= 0) out[i] = (byte) le;
        return out;
    }

    private static byte[] lengthPrefixed(byte[] v) {
        byte[] out = new byte[v.length + 1];
        out[0] = (byte) v.length;
        System.arraycopy(v, 0, out, 1, v.length);
        return out;
    }
}
