package me.flashapp.cashu.cardsim;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A {@code POST /fixture} body, parsed and fully validated before a single
 * APDU is sent.
 *
 * <pre>
 * {
 *   "pin":           "1234",            // optional, 4–8 bytes
 *   "puk":           "12345678",        // optional, 8–12 bytes; needs a PUK-capable appletVersion
 *   "proofs":        [{ "keysetId", "amount", "nonce", "C" }, ...],   // optional, at most 32
 *   "spentSlots":    [1],               // optional, indexes into "proofs"
 *   "blockedPin":    true,              // optional, needs "pin"
 *   "appletVersion": "0.4"              // optional, one of VersionMask.known(), not above the applet's
 * }
 * </pre>
 *
 * Slot keys are CARD-FILE v1's (spec/CARD-FILE.md), minus {@code spent},
 * which {@code spentSlots} carries instead because LOAD_PROOF cannot. Unknown
 * keys are refused at both levels for the reason CARD-FILE.md gives: a field
 * silently dropped here is a card that does not hold what the test believes
 * it holds. Every refusal is an {@link IllegalArgumentException}, which the
 * HTTP layer answers 400 with the card untouched.
 *
 * The checks mirror what the applet would refuse (lengths, slot count,
 * prefixes) so that a fixture that passes here is refused by the card only
 * for what the card already holds, never for its own shape; a mid-apply
 * refusal leaves a half-written card, and validate-before-apply removes
 * every client-side cause of one.
 */
final class Fixture {

    static final int MAX_PROOFS = 32;
    static final int PIN_MIN_LEN = 4, PIN_MAX_LEN = 8;
    static final int PUK_MIN_LEN = 8, PUK_MAX_LEN = 12;
    static final long MAX_AMOUNT = 1L << 32;

    private static final Set<String> KEYS = new HashSet<>(Arrays.asList(
        "pin", "puk", "proofs", "spentSlots", "blockedPin", "appletVersion"));
    private static final Set<String> PROOF_KEYS = new HashSet<>(Arrays.asList(
        "keysetId", "amount", "nonce", "C"));

    static final class Proof {
        final byte[] keysetId;   // 8 bytes
        final long amount;       // 1 <= amount < 2^32
        final byte[] nonce;      // 32 bytes
        final byte[] c;          // 33 bytes, 02/03 prefix

        Proof(byte[] keysetId, long amount, byte[] nonce, byte[] c) {
            this.keysetId = keysetId;
            this.amount = amount;
            this.nonce = nonce;
            this.c = c;
        }

        /** The 77-byte LOAD_PROOF payload: keyset8 ‖ amount4BE ‖ nonce32 ‖ C33. */
        byte[] payload() {
            byte[] p = new byte[77];
            System.arraycopy(keysetId, 0, p, 0, 8);
            p[8] = (byte) (amount >>> 24);
            p[9] = (byte) (amount >>> 16);
            p[10] = (byte) (amount >>> 8);
            p[11] = (byte) amount;
            System.arraycopy(nonce, 0, p, 12, 32);
            System.arraycopy(c, 0, p, 44, 33);
            return p;
        }
    }

    final byte[] pin;              // null when absent
    final byte[] puk;              // null when absent
    final List<Proof> proofs;      // never null
    final int[] spentSlots;        // never null; indexes into proofs
    final boolean blockedPin;
    final VersionMask mask;        // null when appletVersion is absent

    private Fixture(byte[] pin, byte[] puk, List<Proof> proofs, int[] spentSlots,
                    boolean blockedPin, VersionMask mask) {
        this.pin = pin;
        this.puk = puk;
        this.proofs = proofs;
        this.spentSlots = spentSlots;
        this.blockedPin = blockedPin;
        this.mask = mask;
    }

    /**
     * Parse and validate. {@code real} is the applet's own mask, so that
     * {@code appletVersion} can be refused when it is newer than the applet
     * and {@code puk} when the emulated build has no SET_PUK.
     */
    static Fixture parse(String json, VersionMask real) {
        JsonElement root;
        try {
            root = JsonParser.parseString(json == null ? "" : json);
        } catch (JsonParseException e) {
            throw new IllegalArgumentException("fixture is not valid JSON: " + e.getMessage());
        }
        if (!root.isJsonObject()) throw new IllegalArgumentException("fixture must be a JSON object");
        JsonObject o = root.getAsJsonObject();
        for (String k : o.keySet()) {
            if (!KEYS.contains(k)) throw new IllegalArgumentException("unknown fixture key: " + k);
        }

        byte[] pin = optionalSecret(o, "pin", PIN_MIN_LEN, PIN_MAX_LEN);
        byte[] puk = optionalSecret(o, "puk", PUK_MIN_LEN, PUK_MAX_LEN);
        boolean blockedPin = optionalBoolean(o, "blockedPin");
        if (blockedPin && pin == null) throw new IllegalArgumentException("blockedPin requires pin");

        VersionMask mask = null;
        if (o.has("appletVersion")) {
            JsonElement v = o.get("appletVersion");
            if (!isString(v)) throw new IllegalArgumentException("appletVersion must be a string");
            mask = VersionMask.forVersion(v.getAsString(), real);
        }
        if (puk != null && mask != null && !mask.hasPuk()) {
            throw new IllegalArgumentException("puk needs a PUK-capable applet; " + mask.version()
                + " has no SET_PUK (appletVersion must be absent or 0.6 or later)");
        }

        List<Proof> proofs = new ArrayList<>();
        if (o.has("proofs")) {
            JsonElement p = o.get("proofs");
            if (!p.isJsonArray()) throw new IllegalArgumentException("proofs must be an array");
            JsonArray arr = p.getAsJsonArray();
            if (arr.size() > MAX_PROOFS) {
                throw new IllegalArgumentException("proofs has " + arr.size() + " entries; the card has "
                    + MAX_PROOFS + " slots");
            }
            for (int i = 0; i < arr.size(); i++) {
                proofs.add(parseProof(arr.get(i), "proofs[" + i + "]"));
            }
        }

        int[] spentSlots = new int[0];
        if (o.has("spentSlots")) {
            JsonElement s = o.get("spentSlots");
            if (!s.isJsonArray()) throw new IllegalArgumentException("spentSlots must be an array");
            JsonArray arr = s.getAsJsonArray();
            spentSlots = new int[arr.size()];
            Set<Integer> seen = new HashSet<>();
            for (int i = 0; i < arr.size(); i++) {
                JsonElement e = arr.get(i);
                if (!isInteger(e)) throw new IllegalArgumentException("spentSlots[" + i + "] must be an integer");
                long v = e.getAsLong();
                if (v < 0 || v >= proofs.size()) {
                    throw new IllegalArgumentException("spentSlots[" + i + "] = " + v
                        + " is not an index into proofs (" + proofs.size() + " entries)");
                }
                if (!seen.add((int) v)) throw new IllegalArgumentException("spentSlots repeats " + v);
                spentSlots[i] = (int) v;
            }
        }

        return new Fixture(pin, puk, Collections.unmodifiableList(proofs), spentSlots, blockedPin, mask);
    }

    private static Proof parseProof(JsonElement e, String where) {
        if (!e.isJsonObject()) throw new IllegalArgumentException(where + " must be an object");
        JsonObject p = e.getAsJsonObject();
        for (String k : p.keySet()) {
            if (!PROOF_KEYS.contains(k)) throw new IllegalArgumentException("unknown key in " + where + ": " + k);
        }
        for (String k : PROOF_KEYS) {
            if (!p.has(k)) throw new IllegalArgumentException(where + " is missing " + k);
        }
        byte[] keysetId = hexField(p, "keysetId", 8, where);
        byte[] nonce = hexField(p, "nonce", 32, where);
        byte[] c = hexField(p, "C", 33, where);
        if (c[0] != 0x02 && c[0] != 0x03) {
            throw new IllegalArgumentException(where + ".C must start with 02 or 03, got "
                + Hex.formatLower(c, 0, 1));
        }
        JsonElement a = p.get("amount");
        if (!isInteger(a)) throw new IllegalArgumentException(where + ".amount must be an integer");
        long amount = a.getAsLong();
        if (amount < 1 || amount >= MAX_AMOUNT) {
            throw new IllegalArgumentException(where + ".amount must satisfy 1 <= amount < 2^32, got " + amount);
        }
        return new Proof(keysetId, amount, nonce, c);
    }

    private static byte[] hexField(JsonObject p, String key, int bytes, String where) {
        JsonElement v = p.get(key);
        if (!isString(v)) throw new IllegalArgumentException(where + "." + key + " must be a hex string");
        byte[] b;
        try {
            b = Hex.parse(v.getAsString());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(where + "." + key + ": " + e.getMessage());
        }
        if (b.length != bytes) {
            throw new IllegalArgumentException(where + "." + key + " must be " + bytes + " bytes ("
                + bytes * 2 + " hex chars), got " + b.length);
        }
        return b;
    }

    private static byte[] optionalSecret(JsonObject o, String key, int min, int max) {
        if (!o.has(key)) return null;
        JsonElement v = o.get(key);
        if (!isString(v)) throw new IllegalArgumentException(key + " must be a string");
        byte[] b = v.getAsString().getBytes(StandardCharsets.UTF_8);
        if (b.length < min || b.length > max) {
            throw new IllegalArgumentException(key + " must be " + min + "-" + max + " bytes, got " + b.length);
        }
        return b;
    }

    private static boolean optionalBoolean(JsonObject o, String key) {
        if (!o.has(key)) return false;
        JsonElement v = o.get(key);
        if (!v.isJsonPrimitive() || !v.getAsJsonPrimitive().isBoolean()) {
            throw new IllegalArgumentException(key + " must be true or false");
        }
        return v.getAsBoolean();
    }

    private static boolean isString(JsonElement v) {
        return v != null && v.isJsonPrimitive() && v.getAsJsonPrimitive().isString();
    }

    private static boolean isInteger(JsonElement v) {
        if (v == null || !v.isJsonPrimitive() || !v.getAsJsonPrimitive().isNumber()) return false;
        // JSON has one number type; 8.0 is 8, 8.5 is not an amount or a slot.
        double d = v.getAsDouble();
        return d == Math.rint(d) && !Double.isInfinite(d) && Math.abs(d) < (double) Long.MAX_VALUE;
    }
}
