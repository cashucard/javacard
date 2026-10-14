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
 * A {@code POST /fixture} body for a protocol 2.0 card, parsed and fully validated before a single APDU is sent.
 *
 * <pre>
 * {
 *   "pin":        "1234",                    // optional, 4–8 bytes: SET_PIN on a card with none, then VERIFY_PIN
 *   "mint":       "http://127.0.0.1:3338",   // optional, 1–77 characters: the record (SET_CARD)
 *   "refundKey":  "02…",                     // optional, 33 bytes, with mint: the record's refund key (dated pieces need one)
 *   "owner":      true,                      // optional: SET_OWNER with the deterministic TEST owner key (OwnerKey.TEST)
 *   "ownerKey":   "…",                       // optional, 32 bytes: SET_OWNER with this P-256 private key instead
 *   "anchor":     "<80-byte header>",        // optional, needs an owner in this fixture: SET_OWNER's anchor (D20)
 *   "headers":    ["<80-byte header>", …],   // optional: SET_HEADER, in order (real mainnet headers: the floor is built in)
 *   "proofs":     [{ "keysetId", "amount", "nonce", "C", "date"?, "dleq"?: { "e", "s", "r" } }, …],   // optional, at most 128
 *   "spentSlots": [1],                       // optional, indexes into "proofs": spent on the card by a payment of that piece
 *   "limits":     { "day", "payment", "allowance", "rollBudget" },   // optional, needs an owner: SET_LIMIT, always 13 bytes
 *   "blockedPin": true                       // optional, needs "pin": three wrong VERIFY_PINs
 * }
 * </pre>
 *
 * {@code limits} always sends the owner's thirteen-byte SET_LIMIT: a key left out is 0 (no limit, no allowance), and
 * {@code rollBudget} left out is 7, the card's default (D20). The card leaves its budget as it is for a form without
 * the byte (D26); the fixture always sends it, so a fixture's card never keeps a budget from before. tools/cardsim/README.md
 * has the whole schema.
 *
 * The pieces are format-4 SIG_ALL pieces locked to the card key (spec/NUT-XX.md), minted by the caller at a mint
 * after reading {@code /state.pubkey}; with {@code dleq} they are loaded with the mint's proof (LOAD_PROOF P1 = 1).
 * The 0.x keys {@code puk} and {@code appletVersion} are refused by name: there is no PUK and no version mask on 2.0
 * (D18). Unknown keys are refused at every level, for the reason CARD-FILE.md gives: a field silently dropped here is
 * a card that does not hold what the test believes it holds. Every refusal is an {@link IllegalArgumentException},
 * which the HTTP layer answers 400 with the card untouched.
 *
 * The checks mirror what the applet would refuse, against the card as it is ({@link Context}), so that a fixture that
 * passes here is refused by the card only for what the card holds, never for its own shape.
 */
final class Fixture {

    static final int MAX_PROOFS = 128;
    static final int PIN_MIN_LEN = 4, PIN_MAX_LEN = 8;
    static final int MINT_MAX = 77;
    static final int HEADER_LEN = 80;
    static final int DLEQ_LEN = 96;
    static final long MAX_AMOUNT = 1L << 32;
    static final int ROLL_BUDGET_DEFAULT = 7, ROLL_BUDGET_MOST = 30;

    private static final Set<String> KEYS = new HashSet<>(Arrays.asList(
        "pin", "mint", "refundKey", "owner", "ownerKey", "anchor", "headers", "proofs", "spentSlots", "limits", "blockedPin"));
    private static final Set<String> PROOF_KEYS = new HashSet<>(Arrays.asList("keysetId", "amount", "nonce", "C", "date", "dleq"));
    private static final Set<String> PROOF_REQUIRED = new HashSet<>(Arrays.asList("keysetId", "amount", "nonce", "C"));
    private static final Set<String> DLEQ_KEYS = new HashSet<>(Arrays.asList("e", "s", "r"));
    private static final Set<String> LIMIT_KEYS = new HashSet<>(Arrays.asList("day", "payment", "allowance", "rollBudget"));

    /** What the card already is, read before a fixture is checked (SimCard.context()). */
    static final class Context {
        final boolean pinSet, recordSet, refundSet, owned, ownerKnown;

        Context(boolean pinSet, boolean recordSet, boolean refundSet, boolean owned, boolean ownerKnown) {
            this.pinSet = pinSet;
            this.recordSet = recordSet;
            this.refundSet = refundSet;
            this.owned = owned;
            this.ownerKnown = ownerKnown;
        }

        static final Context FRESH = new Context(false, false, false, false, false);
    }

    static final class Proof {
        final byte[] keysetId;   // 8 bytes
        final long amount;       // 1 <= amount < 2^32
        final byte[] nonce;      // 32 bytes
        final byte[] c;          // 33 bytes, 02/03 prefix
        final long date;         // 0 <= date < 2^32
        final byte[] dleq;       // null, or e || s || r, 96 bytes

        Proof(byte[] keysetId, long amount, byte[] nonce, byte[] c, long date, byte[] dleq) {
            this.keysetId = keysetId;
            this.amount = amount;
            this.nonce = nonce;
            this.c = c;
            this.date = date;
            this.dleq = dleq;
        }

        /** LOAD_PROOF's data: keyset8 ‖ amount4 ‖ nonce32 ‖ C33 ‖ date4 (81), and with P1 = 1 the 96 bytes of the mint's proof. */
        byte[] payload() {
            byte[] p = new byte[81 + (dleq != null ? DLEQ_LEN : 0)];
            System.arraycopy(keysetId, 0, p, 0, 8);
            putUint32(p, 8, amount);
            System.arraycopy(nonce, 0, p, 12, 32);
            System.arraycopy(c, 0, p, 44, 33);
            putUint32(p, 77, date);
            if (dleq != null) System.arraycopy(dleq, 0, p, 81, DLEQ_LEN);
            return p;
        }
    }

    static final class Limits {
        final long day, payment, allowance;
        final int rollBudget;

        Limits(long day, long payment, long allowance, int rollBudget) {
            this.day = day;
            this.payment = payment;
            this.allowance = allowance;
            this.rollBudget = rollBudget;
        }

        /** SET_LIMIT's thirteen bytes: day ‖ payment ‖ allowance ‖ rollover budget. */
        byte[] value() {
            byte[] v = new byte[13];
            putUint32(v, 0, day);
            putUint32(v, 4, payment);
            putUint32(v, 8, allowance);
            v[12] = (byte) rollBudget;
            return v;
        }
    }

    final byte[] pin;              // null when absent
    final byte[] mint;             // null when absent
    final byte[] refundKey;        // null when absent (33 zeros are written with a mint)
    final OwnerKey owner;          // null when absent
    final byte[] anchor;           // null when absent
    final List<byte[]> headers;    // never null
    final List<Proof> proofs;      // never null
    final int[] spentSlots;        // never null; indexes into proofs
    final Limits limits;           // null when absent
    final boolean blockedPin;

    private Fixture(byte[] pin, byte[] mint, byte[] refundKey, OwnerKey owner, byte[] anchor, List<byte[]> headers,
                    List<Proof> proofs, int[] spentSlots, Limits limits, boolean blockedPin) {
        this.pin = pin;
        this.mint = mint;
        this.refundKey = refundKey;
        this.owner = owner;
        this.anchor = anchor;
        this.headers = headers;
        this.proofs = proofs;
        this.spentSlots = spentSlots;
        this.limits = limits;
        this.blockedPin = blockedPin;
    }

    /** Parse and validate against a card as it is. */
    static Fixture parse(String json, Context card) {
        JsonElement root;
        try {
            root = JsonParser.parseString(json == null ? "" : json);
        } catch (JsonParseException e) {
            throw new IllegalArgumentException("fixture is not valid JSON: " + e.getMessage());
        }
        if (root == null || !root.isJsonObject()) throw new IllegalArgumentException("fixture must be a JSON object");
        JsonObject o = root.getAsJsonObject();
        for (String k : o.keySet()) {
            if ("puk".equals(k)) throw new IllegalArgumentException("puk: there is no PUK on a 2.0 card (D18); the owner's change-pin unblocks a PIN");
            if ("appletVersion".equals(k)) throw new IllegalArgumentException("appletVersion: the 0.x version masks are gone (D18); the bridge is the 2.0 applet");
            if (!KEYS.contains(k)) throw new IllegalArgumentException("unknown fixture key: " + k);
        }

        byte[] pin = optionalSecret(o, "pin", PIN_MIN_LEN, PIN_MAX_LEN);
        boolean blockedPin = optionalBoolean(o, "blockedPin");
        if (blockedPin && pin == null) throw new IllegalArgumentException("blockedPin requires pin");

        byte[] mint = null;
        if (o.has("mint")) {
            JsonElement m = o.get("mint");
            if (!isString(m)) throw new IllegalArgumentException("mint must be a string");
            mint = m.getAsString().getBytes(StandardCharsets.US_ASCII);
            if (mint.length < 1 || mint.length > MINT_MAX || !StandardCharsets.US_ASCII.newEncoder().canEncode(m.getAsString())) {
                throw new IllegalArgumentException("mint must be 1-" + MINT_MAX + " ASCII characters");
            }
        }
        byte[] refundKey = null;
        if (o.has("refundKey")) {
            if (mint == null) throw new IllegalArgumentException("refundKey is part of the record: give mint with it");
            refundKey = hexField(o, "refundKey", 33, "fixture");
            if (refundKey[0] != 0x02 && refundKey[0] != 0x03) throw new IllegalArgumentException("refundKey must be a compressed point (02/03)");
        }

        OwnerKey owner = null;
        if (o.has("ownerKey")) {
            JsonElement k = o.get("ownerKey");
            if (!isString(k)) throw new IllegalArgumentException("ownerKey must be a hex string");
            owner = OwnerKey.fromHex(k.getAsString());
        } else if (optionalBoolean(o, "owner")) {
            owner = OwnerKey.TEST;
        }
        if (o.has("owner") && o.has("ownerKey")) throw new IllegalArgumentException("give owner or ownerKey, not both");
        if (owner != null && card.owned && !card.ownerKnown) {
            throw new IllegalArgumentException("the card already has an owner whose key the bridge does not hold: /reset first");
        }
        byte[] anchor = null;
        if (o.has("anchor")) {
            if (owner == null) throw new IllegalArgumentException("anchor is SET_OWNER's: give owner or ownerKey with it");
            anchor = hexField(o, "anchor", HEADER_LEN, "fixture");
        }
        boolean ownedAfter = owner != null || (card.owned && card.ownerKnown);

        List<byte[]> headers = new ArrayList<>();
        if (o.has("headers")) {
            JsonElement h = o.get("headers");
            if (!h.isJsonArray()) throw new IllegalArgumentException("headers must be an array");
            JsonArray arr = h.getAsJsonArray();
            for (int i = 0; i < arr.size(); i++) {
                JsonElement e = arr.get(i);
                if (!isString(e)) throw new IllegalArgumentException("headers[" + i + "] must be a hex string");
                byte[] b = parseHex(e.getAsString(), "headers[" + i + "]");
                if (b.length != HEADER_LEN) throw new IllegalArgumentException("headers[" + i + "] must be " + HEADER_LEN + " bytes, got " + b.length);
                headers.add(b);
            }
        }

        boolean pinAfter = pin != null || card.pinSet;
        Limits limits = null;
        if (o.has("limits")) {
            if (!ownedAfter) throw new IllegalArgumentException("limits are the owner's: give owner or ownerKey (or set one in an earlier fixture)");
            JsonElement l = o.get("limits");
            if (!l.isJsonObject()) throw new IllegalArgumentException("limits must be an object");
            JsonObject lo = l.getAsJsonObject();
            for (String k : lo.keySet()) if (!LIMIT_KEYS.contains(k)) throw new IllegalArgumentException("unknown key in limits: " + k);
            long day = optionalUint32(lo, "day", "limits.day");
            long payment = optionalUint32(lo, "payment", "limits.payment");
            long allowance = optionalUint32(lo, "allowance", "limits.allowance");
            int budget = ROLL_BUDGET_DEFAULT;
            if (lo.has("rollBudget")) {
                JsonElement b = lo.get("rollBudget");
                if (!isInteger(b) || b.getAsLong() < 1 || b.getAsLong() > ROLL_BUDGET_MOST) {
                    throw new IllegalArgumentException("limits.rollBudget must be an integer, 1 to " + ROLL_BUDGET_MOST);
                }
                budget = (int) b.getAsLong();
            }
            if (allowance != 0 && !pinAfter) {
                throw new IllegalArgumentException("limits.allowance needs a PIN on the card: the applet refuses a no-PIN allowance on a card with none (6985)");
            }
            limits = new Limits(day, payment, allowance, budget);
        }

        List<Proof> proofs = new ArrayList<>();
        if (o.has("proofs")) {
            JsonElement p = o.get("proofs");
            if (!p.isJsonArray()) throw new IllegalArgumentException("proofs must be an array");
            JsonArray arr = p.getAsJsonArray();
            if (arr.size() > MAX_PROOFS) {
                throw new IllegalArgumentException("proofs has " + arr.size() + " entries; the card has " + MAX_PROOFS + " slots");
            }
            Set<String> nonces = new HashSet<>();
            for (int i = 0; i < arr.size(); i++) {
                Proof proof = parseProof(arr.get(i), "proofs[" + i + "]");
                if (!nonces.add(Hex.formatLower(proof.nonce))) {
                    throw new IllegalArgumentException("proofs[" + i + "] repeats a nonce: the card refuses a piece already on it (6A94)");
                }
                if (proof.date != 0 && refundKey == null && !card.refundSet) {
                    throw new IllegalArgumentException("proofs[" + i + "] has a date: the record needs a refundKey (6A8E)");
                }
                proofs.add(proof);
            }
            if (!proofs.isEmpty()) {
                if (mint == null && !card.recordSet) throw new IllegalArgumentException("proofs need a record: give mint (LOAD_PROOF answers 6A8C without one)");
                if (!ownedAfter) throw new IllegalArgumentException("proofs need an owner: nothing is loaded onto a card with no owner (6A90)");
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
                    throw new IllegalArgumentException("spentSlots[" + i + "] = " + v + " is not an index into proofs (" + proofs.size() + " entries)");
                }
                if (!seen.add((int) v)) throw new IllegalArgumentException("spentSlots repeats " + v);
                spentSlots[i] = (int) v;
            }
            if (spentSlots.length > 0 && card.pinSet && pin == null) {
                throw new IllegalArgumentException("spentSlots on a card with a PIN need the pin in this fixture: a payment is signed under it");
            }
        }

        return new Fixture(pin, mint, refundKey, owner, anchor, Collections.unmodifiableList(headers),
            Collections.unmodifiableList(proofs), spentSlots, limits, blockedPin);
    }

    private static Proof parseProof(JsonElement e, String where) {
        if (!e.isJsonObject()) throw new IllegalArgumentException(where + " must be an object");
        JsonObject p = e.getAsJsonObject();
        for (String k : p.keySet()) {
            if (!PROOF_KEYS.contains(k)) throw new IllegalArgumentException("unknown key in " + where + ": " + k);
        }
        for (String k : PROOF_REQUIRED) {
            if (!p.has(k)) throw new IllegalArgumentException(where + " is missing " + k);
        }
        byte[] keysetId = hexField(p, "keysetId", 8, where);
        byte[] nonce = hexField(p, "nonce", 32, where);
        byte[] c = hexField(p, "C", 33, where);
        if (c[0] != 0x02 && c[0] != 0x03) {
            throw new IllegalArgumentException(where + ".C must start with 02 or 03, got " + Hex.formatLower(c, 0, 1));
        }
        JsonElement a = p.get("amount");
        if (!isInteger(a)) throw new IllegalArgumentException(where + ".amount must be an integer");
        long amount = a.getAsLong();
        if (amount < 1 || amount >= MAX_AMOUNT) {
            throw new IllegalArgumentException(where + ".amount must satisfy 1 <= amount < 2^32, got " + amount);
        }
        long date = optionalUint32(p, "date", where + ".date");
        byte[] dleq = null;
        if (p.has("dleq")) {
            JsonElement d = p.get("dleq");
            if (!d.isJsonObject()) throw new IllegalArgumentException(where + ".dleq must be an object {e, s, r}");
            JsonObject dq = d.getAsJsonObject();
            for (String k : dq.keySet()) if (!DLEQ_KEYS.contains(k)) throw new IllegalArgumentException("unknown key in " + where + ".dleq: " + k);
            dleq = new byte[DLEQ_LEN];
            int at = 0;
            for (String k : new String[] { "e", "s", "r" }) {
                if (!dq.has(k)) throw new IllegalArgumentException(where + ".dleq is missing " + k);
                System.arraycopy(hexField(dq, k, 32, where + ".dleq"), 0, dleq, at, 32);
                at += 32;
            }
            boolean zero = true;
            for (byte b : dleq) if (b != 0) { zero = false; break; }
            if (zero) throw new IllegalArgumentException(where + ".dleq of 96 zero bytes is no proof (the card answers 6A80)");
        }
        return new Proof(keysetId, amount, nonce, c, date, dleq);
    }

    private static byte[] hexField(JsonObject p, String key, int bytes, String where) {
        JsonElement v = p.get(key);
        if (!isString(v)) throw new IllegalArgumentException(where + "." + key + " must be a hex string");
        byte[] b = parseHex(v.getAsString(), where + "." + key);
        if (b.length != bytes) {
            throw new IllegalArgumentException(where + "." + key + " must be " + bytes + " bytes (" + bytes * 2 + " hex chars), got " + b.length);
        }
        return b;
    }

    private static byte[] parseHex(String s, String where) {
        try {
            return Hex.parse(s);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(where + ": " + e.getMessage());
        }
    }

    private static long optionalUint32(JsonObject o, String key, String where) {
        if (!o.has(key)) return 0;
        JsonElement v = o.get(key);
        if (!isInteger(v) || v.getAsLong() < 0 || v.getAsLong() >= MAX_AMOUNT) {
            throw new IllegalArgumentException(where + " must be an integer, 0 <= n < 2^32");
        }
        return v.getAsLong();
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

    static void putUint32(byte[] b, int at, long v) {
        b[at] = (byte) (v >>> 24);
        b[at + 1] = (byte) (v >>> 16);
        b[at + 2] = (byte) (v >>> 8);
        b[at + 3] = (byte) v;
    }
}
