package me.flashapp.cashu;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Math-level tests for SchnorrHW's hand-rolled 256-bit modular arithmetic.
 *
 * These deliberately bypass the card/APDU layer and check the primitives
 * directly against java.math.BigInteger, so that a failing BIP-340 signature
 * can be attributed to either the modular arithmetic or the higher-level
 * signing logic rather than guessed at.
 */
class SchnorrHWMathTest {

    /** secp256k1 group order n. */
    private static final BigInteger N = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    private static byte[] to32(BigInteger v) {
        byte[] out = new byte[32];
        byte[] raw = v.toByteArray();
        int len = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - len, out, 32 - len, len);
        return out;
    }

    private static BigInteger from32(byte[] b) {
        return new BigInteger(1, b);
    }

    /** Deterministic seed so failures are reproducible. */
    private static Random rng() {
        return new Random(0xCA54D00DL);
    }

    /**
     * Scratch buffer for mulModN. On-card this is a CLEAR_ON_DESELECT transient
     * array allocated once in the SchnorrHW constructor; here a plain array is
     * fine. Deliberately sized from the constant so a future growth of the
     * arithmetic scratch shows up here rather than as an out-of-bounds read.
     */
    private static byte[] work() {
        return new byte[SchnorrHW.WORK_LEN];
    }

    @Test
    @DisplayName("addModN matches BigInteger (a + b) mod n")
    void addModNMatchesBigInteger() {
        Random r = rng();
        for (int i = 0; i < 200; i++) {
            BigInteger a = new BigInteger(256, r).mod(N);
            BigInteger b = new BigInteger(256, r).mod(N);
            byte[] out = new byte[32];
            SchnorrHW.addModN(to32(a), (short) 0, to32(b), (short) 0, out, (short) 0);
            assertEquals(a.add(b).mod(N), from32(out),
                "addModN mismatch at iteration " + i + " (a=" + a.toString(16)
                    + ", b=" + b.toString(16) + ")");
        }
    }

    @Test
    @DisplayName("mulModN matches BigInteger (a * b) mod n")
    void mulModNMatchesBigInteger() {
        Random r = rng();
        for (int i = 0; i < 200; i++) {
            BigInteger a = new BigInteger(256, r).mod(N);
            BigInteger b = new BigInteger(256, r).mod(N);
            byte[] out = new byte[32];
            SchnorrHW.mulModN(to32(a), (short) 0, to32(b), (short) 0, out, (short) 0,
                work(), (short) 0);
            assertEquals(a.multiply(b).mod(N), from32(out),
                "mulModN mismatch at iteration " + i + " (a=" + a.toString(16)
                    + ", b=" + b.toString(16) + ")");
        }
    }

    @Test
    @DisplayName("mulModN handles edge values (0, 1, n-1)")
    void mulModNEdgeCases() {
        BigInteger[] vals = { BigInteger.ZERO, BigInteger.ONE, N.subtract(BigInteger.ONE),
                              BigInteger.TWO, N.shiftRight(1) };
        for (BigInteger a : vals) {
            for (BigInteger b : vals) {
                byte[] out = new byte[32];
                SchnorrHW.mulModN(to32(a), (short) 0, to32(b), (short) 0, out, (short) 0,
                    work(), (short) 0);
                assertEquals(a.multiply(b).mod(N), from32(out),
                    "mulModN edge mismatch a=" + a.toString(16) + " b=" + b.toString(16));
            }
        }
    }

    // ── D21: the field multiply does the same work for every input ───────────

    /** An operand with each byte zeroed with probability `zeros` in 1: the inputs an early exit on a zero byte would run faster on. */
    private static byte[] sparse(Random r, int zeros) {
        byte[] b = new byte[32];
        r.nextBytes(b);
        for (int k = 0; k < 32; k++) if (r.nextInt(zeros) == 0) b[k] = 0;
        return b;
    }

    @Test
    @DisplayName("D21: mulModN matches BigInteger on operands full of zero bytes, a zero high or low half, and single-byte operands")
    void mulModNWithZeroBytesMatchesBigInteger() {
        Random r = new Random(0x0D21L);
        for (int i = 0; i < 2000; i++) {
            byte[] a = sparse(r, 1 + (i % 4)), b = sparse(r, 1 + ((i / 4) % 4));
            if (i % 50 == 0) java.util.Arrays.fill(a, 0, 16, (byte) 0);       // a zero high half
            if (i % 50 == 1) java.util.Arrays.fill(b, 16, 32, (byte) 0);      // a zero low half
            if (i % 50 == 2) { java.util.Arrays.fill(a, (byte) 0); a[r.nextInt(32)] = (byte) (1 + r.nextInt(255)); }
            BigInteger av = from32(a).mod(N), bv = from32(b).mod(N);
            byte[] out = new byte[32];
            SchnorrHW.mulModN(to32(av), (short) 0, to32(bv), (short) 0, out, (short) 0, work(), (short) 0);
            assertEquals(av.multiply(bv).mod(N), from32(out), "iteration " + i + " a=" + av.toString(16) + " b=" + bv.toString(16));
        }
    }

    @Test
    @DisplayName("D21: the raw 512-bit products, mul256x256 and mulByDelta, match BigInteger with zero bytes in the secret operand")
    void theRawProductsMatchBigInteger() throws Exception {
        java.lang.reflect.Method mul = SchnorrHW.class.getDeclaredMethod("mul256x256",
            byte[].class, short.class, byte[].class, short.class, byte[].class, short.class);
        java.lang.reflect.Method byDelta = SchnorrHW.class.getDeclaredMethod("mulByDelta",
            byte[].class, short.class, byte[].class, short.class);
        mul.setAccessible(true);
        byDelta.setAccessible(true);
        BigInteger delta = BigInteger.ONE.shiftLeft(256).subtract(N);
        Random r = new Random(0x0D21DL);
        for (int i = 0; i < 2000; i++) {
            byte[] a = sparse(r, 1 + (i % 5)), b = sparse(r, 1 + ((i / 5) % 5));
            if (i == 0) java.util.Arrays.fill(a, (byte) 0);
            if (i == 1) java.util.Arrays.fill(a, (byte) 0xFF);
            if (i == 2) { java.util.Arrays.fill(a, (byte) 0xFF); java.util.Arrays.fill(b, (byte) 0xFF); }
            byte[] out = new byte[64];
            java.util.Arrays.fill(out, (byte) 0x5A);    // whatever was there before is written over
            mul.invoke(null, a, (short) 0, b, (short) 0, out, (short) 0);
            assertEquals(from32(a).multiply(from32(b)), new BigInteger(1, out), "a×b at " + i);
            byte[] d = new byte[64];
            java.util.Arrays.fill(d, (byte) 0xA5);
            byDelta.invoke(null, a, (short) 0, d, (short) 0);
            assertEquals(from32(a).multiply(delta), new BigInteger(1, d), "a×DELTA at " + i);
        }
    }

    @Test
    @DisplayName("D21: neither multiply has a branch or a loop on a byte of its operands (no continue, no if, no while), read in the source")
    void theMultipliesHaveNoSecretDependentBranch() throws Exception {
        String src = new String(java.nio.file.Files.readAllBytes(mainSourceDir().resolve("SchnorrHW.java")),
            java.nio.charset.StandardCharsets.UTF_8);
        java.util.List<String> violations = branchyMultiplies(src);
        org.junit.jupiter.api.Assertions.assertTrue(violations.isEmpty(), String.join("\n", violations));
    }

    @Test
    @DisplayName("D21: the scan fails the old early exit, the old carry loop and an if on an operand byte")
    void theBranchScanCanSayNo() {
        String rest = " private static void mulByDelta(byte[] a, short aOff, byte[] out, short outOff) {"
            + " for (short i = 31; i >= 0; i--) { short ai = (short)(a[i] & 0xFF); short carry = 0;"
            + " for (short j = 31; j >= DELTA_FROM; j--) { carry = 0; } out[i] = (byte) carry; } }";
        String good = "class A { private static void mul256x256(byte[] a, short aOff, byte[] b, short bOff, byte[] out, short outOff) {"
            + " for (short i = 31; i >= 0; i--) { short ai = (short)(a[i] & 0xFF); short carry = 0;"
            + " for (short j = 31; j >= 0; j--) { carry = 0; } out[i] = (byte) carry; } }" + rest + " }";
        String earlyExit = good.replace("short ai = (short)(a[i] & 0xFF);", "short ai = (short)(a[i] & 0xFF); if (ai == 0) continue;");
        String carryLoop = good.replace("out[i] = (byte) carry; } }" + rest, "while (carry != 0 && pos >= outOff) { carry = 0; } } }" + rest);
        String anIf = good.replace(rest, rest.replace("short carry = 0;", "short carry = 0; if (ai > 1) carry = 1;"));
        org.junit.jupiter.api.Assertions.assertTrue(branchyMultiplies(good).isEmpty(), String.join("\n", branchyMultiplies(good)));
        org.junit.jupiter.api.Assertions.assertFalse(branchyMultiplies(earlyExit).isEmpty(), "the early exit passed");
        org.junit.jupiter.api.Assertions.assertFalse(branchyMultiplies(carryLoop).isEmpty(), "the carry loop passed");
        org.junit.jupiter.api.Assertions.assertFalse(branchyMultiplies(anIf).isEmpty(), "an if in mulByDelta passed");
    }

    /**
     * D21's reach (review of PR #34). D21 took the branches out of the two multiplies and nothing else: the reductions on
     * the same signing path still branch on values derived from the key and the nonce (e·d, k + e·d, k). An earlier
     * spec sentence claimed the card's arithmetic had no secret-dependent branches at all, which a reviewer would read as
     * "no timing analysis needed". This holds the documents to the source: every helper here that still branches is
     * named as open in SECURITY-MODEL item 5, and neither the spec nor the threat table claims more than the multiplies.
     * When a helper is made branch-free, this fails until it leaves the list and the documents.
     */
    static final String[] OPEN_BRANCHING_REDUCTIONS = { "reduce512toModN", "addModN", "reduceModN", "sub32", "cmp32", "mulSmallByDelta" };

    @Test
    @DisplayName("D21's reach: the reductions that still branch are open in SECURITY-MODEL item 5, and no document claims the whole arithmetic is branch-free")
    void theReductionsThatStillBranchAreListedAsOpen() throws Exception {
        String src = stripCommentsAndCharLiterals(new String(java.nio.file.Files.readAllBytes(mainSourceDir().resolve("SchnorrHW.java")),
            java.nio.charset.StandardCharsets.UTF_8));
        java.nio.file.Path root = mainSourceDir().toAbsolutePath().normalize();
        for (int i = 0; i < 7; i++) root = root.getParent();   // <repo>/applet/src/main/java/me/flashapp/cashu -> <repo>
        String model = flat(root.resolve("docs").resolve("SECURITY-MODEL.md"));
        String apdu = flat(root.resolve("spec").resolve("APDU.md"));
        String decisions = flat(root.resolve("docs").resolve("DECISIONS.md"));
        int from = model.indexOf("5. **Side-channel review**");
        int to = model.indexOf("6. **", from);
        org.junit.jupiter.api.Assertions.assertTrue(from >= 0 && to > from, "SECURITY-MODEL has open item 5");
        String item5 = model.substring(from, to);
        // Decision anchors are stable; editorial titles and punctuation may change.
        int d21 = decisions.indexOf("<a id=\"d21\"></a>");
        int d22 = decisions.indexOf("<a id=\"d22\"></a>", d21);
        org.junit.jupiter.api.Assertions.assertTrue(d21 >= 0 && d22 > d21, "DECISIONS retains the D21 and D22 anchors");
        String d21Text = decisions.substring(d21, d22);
        java.util.List<String> problems = new java.util.ArrayList<>();
        for (String name : OPEN_BRANCHING_REDUCTIONS) {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("static\\s+\\w+\\s+" + name + "\\(").matcher(src);
            if (!m.find()) { problems.add(name + " is not in SchnorrHW"); continue; }
            int[] body = bodyRange(src, m.group());
            String b = src.substring(body[0], body[1]);
            boolean branches = java.util.regex.Pattern.compile("\\b(if|while|continue|break)\\b").matcher(b).find() || b.contains("?");
            if (!branches) problems.add(name + " no longer branches: take it out of OPEN_BRANCHING_REDUCTIONS, SECURITY-MODEL item 5 and D21's reach");
            if (!item5.contains("`" + name + "`")) problems.add(name + " branches and is not named in SECURITY-MODEL open item 5");
            if (!d21Text.contains(name)) problems.add(name + " branches and is not named in D21's 'What this does not reach'");
        }
        if (apdu.contains("arithmetic on its key and nonces has no secret-dependent branches")) {
            problems.add("spec/APDU.md claims the card's whole arithmetic has no secret-dependent branches; D21 covers the multiplies only");
        }
        if (model.contains("Mitigated in our arithmetic")) {
            problems.add("SECURITY-MODEL #19 calls timing 'Mitigated in our arithmetic'; the reductions still branch");
        }
        org.junit.jupiter.api.Assertions.assertTrue(problems.isEmpty(), String.join("\n", problems));
    }

    /** A document's text with every run of whitespace made one space, so that a phrase wrapped across lines is found. */
    private static String flat(java.nio.file.Path p) throws java.io.IOException {
        return new String(java.nio.file.Files.readAllBytes(p), java.nio.charset.StandardCharsets.UTF_8).replaceAll("\\s+", " ");
    }

    /** `continue`, `if`, `while`, `break`, `?` or `return` in the bodies of mul256x256 and mulByDelta: each a branch whose timing could follow a byte of the operands. */
    static java.util.List<String> branchyMultiplies(String rawSrc) {
        String src = stripCommentsAndCharLiterals(rawSrc);
        java.util.List<String> out = new java.util.ArrayList<>();
        for (String name : new String[] { "mul256x256(byte[]", "mulByDelta(byte[]" }) {
            int decl = src.indexOf("static void " + name);
            if (decl < 0) { out.add("no " + name + " in the source"); continue; }
            int[] body = bodyRange(src, "static void " + name);
            String b = src.substring(body[0], body[1]);
            for (String w : new String[] { "continue", "if", "while", "break", "return" }) {
                if (java.util.regex.Pattern.compile("\\b" + w + "\\b").matcher(b).find()) out.add(name + " has `" + w + "`");
            }
            if (b.contains("?")) out.add(name + " has a conditional expression");
        }
        return out;
    }

    /**
     * The odd-y normalisation d = n - d is picked at random by the card's key
     * generation (P.y parity), so the applet-level tests only exercise it about
     * half the time on any given run. This pins the primitive deterministically.
     */
    @Test
    @DisplayName("subtractFromN matches BigInteger n - a")
    void subtractFromNMatchesBigInteger() {
        Random r = rng();
        for (int i = 0; i < 200; i++) {
            BigInteger a = new BigInteger(256, r).mod(N);
            byte[] out = new byte[32];
            SchnorrHW.subtractFromN(to32(a), (short) 0, out, (short) 0);
            assertEquals(N.subtract(a), from32(out),
                "subtractFromN mismatch at iteration " + i + " (a=" + a.toString(16) + ")");
        }
    }

    @Test
    @DisplayName("subtractFromN handles edge values (0, 1, n-1)")
    void subtractFromNEdgeCases() {
        BigInteger[] vals = { BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO,
                              N.subtract(BigInteger.ONE), N.shiftRight(1) };
        for (BigInteger a : vals) {
            byte[] out = new byte[32];
            SchnorrHW.subtractFromN(to32(a), (short) 0, out, (short) 0);
            assertEquals(N.subtract(a), from32(out),
                "subtractFromN edge mismatch a=" + a.toString(16));
        }
    }

    /**
     * Reusing one scratch buffer across calls must not leak state between them:
     * on-card the buffer is a single long-lived transient array, so a helper that
     * reads a stale byte instead of writing it first would only misbehave on the
     * second and later signatures.
     */
    @Test
    @DisplayName("mulModN is correct when the work buffer is reused and pre-dirtied")
    void mulModNReusesWorkBufferSafely() {
        Random r = rng();
        byte[] shared = work();
        java.util.Arrays.fill(shared, (byte) 0xA5);
        for (int i = 0; i < 100; i++) {
            BigInteger a = new BigInteger(256, r).mod(N);
            BigInteger b = new BigInteger(256, r).mod(N);
            byte[] out = new byte[32];
            SchnorrHW.mulModN(to32(a), (short) 0, to32(b), (short) 0, out, (short) 0,
                shared, (short) 0);
            assertEquals(a.multiply(b).mod(N), from32(out),
                "mulModN mismatch on reused work buffer at iteration " + i);
        }
    }

    /**
     * The methods that are allowed to allocate, per source file: everything that
     * runs exactly once at install time. Anything else in these files is
     * reachable from an APDU handler.
     *
     * Entry format: { file name, install-time declaration, ... }. The
     * declarations are matched literally against the comment-stripped source, so
     * they must be unique in it — {@code "private CashuApplet()"} rather than
     * {@code "CashuApplet()"}, which would also hit the {@code new CashuApplet()}
     * inside install().
     *
     * Every .java file under src/main/java/me/flashapp/cashu must appear here;
     * a new one with no entry fails the test rather than slipping through
     * unchecked.
     *
     * "Runs exactly once at install time" is itself enforced, not taken on
     * trust: {@link #assertNoAllocationOutside} requires every unqualified call
     * to a listed method to sit inside another listed method's body. A helper
     * like {@code initCardKeypair()} is only install-time for as long as nobody
     * wires it to an APDU handler, and a whole-body allocation waiver granted on
     * the strength of a comment is exactly how the leak this test guards against
     * would come back.
     */
    private static final String[][] INSTALL_TIME_METHODS = {
        { "SchnorrHW.java",
          "SchnorrHW(", "void init()" },
        { "CashuApplet.java",
          "public static void install(", "private CashuApplet()",
          "private void initCardKeypair()", "private void initPinKey()" },
        // the applet instantiated first, so that the chip takes the card's own (FOXY-CARD-HARDWARE.md): it allocates nothing at all
        { "Opener.java",
          "public static void install(", "private Opener()" },
        // the NFC tag: it allocates one transient byte, in its constructor, and nothing else (and its interface nothing at all)
        { "Tag.java",
          "public static void install(", "private Tag()" },
        { "TagSwitch.java" },
    };

    /**
     * The allocations that are not install-time and are let through all the same (1.20), each by its file, by the method it is
     * in and by the whole statement it is, so that nothing else in that method, or anywhere else, goes through with it:
     * { file, the method's declaration, the statement }. There is one, the room for the mint's proofs. The chip will not install an
     * applet whose constructor asks for that much more (+300 bytes installs, +12,288 does not: docs/FOXY-CARD-HARDWARE.md), and gives the
     * same bytes asked for after the install, so SET_CARD reserves them. What this test exists to catch, an allocation that repeats on
     * every command until the card's persistent memory is gone, cannot come of it: it is guarded so that it happens once in a card's
     * life (`if (dleq == null)`), and a request the card refuses allocates nothing and leaves the store null. The statement is found
     * ignoring white space, once, inside the method named; an allocation beside it is still refused.
     */
    private static final String[][] ONCE_ONLY_ALLOCATIONS = {
        { "CashuApplet.java", "private void processSetCard(",
          "if (dleq == null) { try { dleq = new byte[(short)(MAX_PROOFS * DLEQ_LEN)]; } catch (SystemException e) { dleq = null; } }" },
    };

    /**
     * JavaCard Classic allocates `new` in persistent EEPROM/Flash and never
     * collects it, so a single `new byte[]` on an APDU path leaks the card's
     * persistent memory a few dozen bytes per tap until every write command
     * throws. jCardSim runs on the JVM heap with a real GC and therefore cannot
     * surface this — only a source-level check can. It is CONTRIBUTING.md
     * principle 5, and this test is its enforcement.
     *
     * Both applet sources are scanned, not just the signer: {@code CashuApplet}
     * is every bit as much on the APDU path, and a stray {@code byte[] tmp = new
     * byte[64]} inside processLoadProof would leak exactly the same way.
     */
    @Test
    @DisplayName("no applet source allocates outside its install-time methods")
    void noAllocationOutsideInstallTime() throws Exception {
        java.nio.file.Path dir = mainSourceDir();
        java.util.List<java.nio.file.Path> sources;
        try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.list(dir)) {
            sources = s.filter(p -> p.getFileName().toString().endsWith(".java"))
                       .sorted()
                       .collect(java.util.stream.Collectors.toList());
        }
        org.junit.jupiter.api.Assertions.assertFalse(sources.isEmpty(),
            "no applet sources found under " + dir.toAbsolutePath());

        java.util.Set<String> scanned = new java.util.HashSet<>();
        for (java.nio.file.Path p : sources) {
            String name = p.getFileName().toString();
            String[] installTime = installTimeMethods(name);
            assertNoAllocationOutside(name,
                new String(java.nio.file.Files.readAllBytes(p),
                    java.nio.charset.StandardCharsets.UTF_8),
                installTime, onceOnlyAllocations(name));
            scanned.add(name);
        }

        for (String[] entry : INSTALL_TIME_METHODS) {
            org.junit.jupiter.api.Assertions.assertTrue(scanned.contains(entry[0]),
                "INSTALL_TIME_METHODS names " + entry[0] + ", which no longer exists under "
                + dir.toAbsolutePath() + " — the allow-list is stale");
        }
    }

    /**
     * The guard above is only worth anything if it can say no, so it is pointed
     * at sources written to fail it.
     *
     * The waived-helper leak is the one this exists for: {@code initThing()}
     * allocates and is allow-listed, which is fine while only the constructor
     * calls it. The moment an APDU handler calls it too, every tap allocates a
     * new array in EEPROM — and the allocation itself never moved, so the plain
     * allocation scan stays green. Only the call-site check catches it.
     */
    @Test
    @DisplayName("the allow-list rejects an install-time helper called from the APDU path")
    void allowListRejectsInstallTimeHelperCalledFromApduPath() {
        String[] allowList = {
            "public static void install(", "private Fake()", "private void initThing()"
        };

        String clean =
            "class Fake {\n"
            + "    private byte[] buf;\n"
            + "    public static void install(byte[] a, short b, byte c) { new Fake(); }\n"
            + "    private Fake() { initThing(); }\n"
            + "    private void initThing() { buf = new byte[64]; }\n"
            + "    private void processApdu() { buf[0] = 1; }\n"
            + "}\n";
        assertNoAllocationOutside("Fake.java", clean, allowList);

        String leaky = clean.replace(
            "private void processApdu() { buf[0] = 1; }",
            "private void processApdu() { initThing(); }");
        org.opentest4j.AssertionFailedError failed =
            org.junit.jupiter.api.Assertions.assertThrows(
                org.opentest4j.AssertionFailedError.class,
                () -> assertNoAllocationOutside("Fake.java", leaky, allowList),
                "an allow-listed allocating helper reached from the APDU path must fail");
        org.junit.jupiter.api.Assertions.assertTrue(failed.getMessage().contains("initThing"),
            "the failure must name the helper that gained an APDU-path caller, got: "
                + failed.getMessage());
    }

    /**
     * A call on another object that merely shares a name with an allow-listed
     * method is not a call to it — {@code ecdh.init(tmpPriv)} in SchnorrHW is
     * exactly that, and flagging it would make the guard unusable.
     */
    @Test
    @DisplayName("the call-site check ignores calls qualified by a receiver")
    void allowListIgnoresQualifiedSameNameCalls() {
        String src =
            "class Fake {\n"
            + "    private byte[] buf;\n"
            + "    private Other other;\n"
            + "    public static void install(byte[] a, short b, byte c) { new Fake(); }\n"
            + "    private Fake() { initThing(); }\n"
            + "    private void initThing() { buf = new byte[64]; }\n"
            + "    private void processApdu() { other.initThing(); }\n"
            + "}\n";
        assertNoAllocationOutside("Fake.java", src, new String[] {
            "public static void install(", "private Fake()", "private void initThing()"
        });
    }

    /**
     * The once-only waiver (1.20) is as narrow as it says: the statement, whole, once, in the method it was named for, and nothing beside
     * it. A guard left off (it would allocate again at every SET_CARD), a second allocation next to it, a second copy of it, the same
     * statement in another method, and a waiver for a statement that is not there are each refused.
     */
    @Test
    @DisplayName("the once-only allocation is let through whole, once, in its own method, and nothing beside it: no guard, a second allocation, a second copy, another method and a missing statement are each refused")
    void theOnceOnlyAllocationIsNarrow() {
        String statement = "if (dleq == null) { try { dleq = new byte[96]; } catch (SystemException e) { dleq = null; } }";
        String[] allowList = { "public static void install(", "private Fake()" };
        String[][] once = { { "private void setCard(", statement } };
        String clean =
            "class Fake {\n"
            + "    private byte[] dleq;\n"
            + "    public static void install(byte[] a, short b, byte c) { new Fake(); }\n"
            + "    private Fake() { }\n"
            + "    private void setCard() {\n"
            + "        " + statement + "\n"
            + "    }\n"
            + "    private void other() { }\n"
            + "}\n";
        assertNoAllocationOutside("Fake.java", clean, allowList, once);
        // laid out another way: it is the statement that is let through, and not its spacing
        assertNoAllocationOutside("Fake.java",
            clean.replace(statement, "if (dleq == null) {\n    try {\n        dleq = new byte[96];\n    } catch (SystemException e) {\n        dleq = null;\n    }\n}"),
            allowList, once);
        // an allocation in the constructor is install-time, as ever
        assertNoAllocationOutside("Fake.java", clean.replace("private Fake() { }", "private Fake() { dleq = new byte[4]; }"), allowList, once);

        String[][] refused = {
            // { what is wrong, the source, the part of the failure's message that says so }
            { "no guard", clean.replace(statement, "dleq = new byte[96];"), "is not there, whole" },
            { "guarded by the wrong test", clean.replace("dleq == null", "dleq != null"), "is not there, whole" },
            { "a second allocation beside it", clean.replace(statement, statement + " byte[] t = new byte[4];"), "allocation outside the install-time methods" },
            { "a second copy of it", clean.replace("private void other() { }", "private void other() { " + statement + " }"), "twice" },
            { "the same statement in another method", clean.replace(statement, "").replace("private void other() { }", "private void other() { " + statement + " }"), "elsewhere" },
            { "a waiver for a statement that is not there", clean.replace(statement, ""), "is not there, whole" },
        };
        for (String[] r : refused) {
            org.opentest4j.AssertionFailedError failed = org.junit.jupiter.api.Assertions.assertThrows(org.opentest4j.AssertionFailedError.class,
                () -> assertNoAllocationOutside("Fake.java", r[1], allowList, once), r[0] + " must fail");
            org.junit.jupiter.api.Assertions.assertTrue(failed.getMessage().contains(r[2]), r[0] + ": the failure must say '" + r[2] + "', got: " + failed.getMessage());
        }
        // and without the waiver the same allocation is refused outright, as every allocation on the APDU path always was
        org.junit.jupiter.api.Assertions.assertThrows(org.opentest4j.AssertionFailedError.class,
            () -> assertNoAllocationOutside("Fake.java", clean, allowList), "no waiver, no allocation");
    }

    /**
     * 1.20 reserves the store of the mint's proofs in SET_CARD, and nowhere else: the constructors name it nowhere, the one allocation
     * is the guarded one in SET_CARD, it comes before the transaction that writes the record and outside any, and nothing else assigns
     * the store. (The chip refuses an applet whose constructor asks for that much more; no simulator does, so the source is read.)
     */
    @Test
    @DisplayName("the store of the mint's proofs is reserved in SET_CARD, guarded, before and outside its transaction, and no constructor or other method assigns it")
    void theProofStoreIsReservedInSetCardAndNowhereElse() throws Exception {
        String src = stripCommentsAndCharLiterals(new String(
            java.nio.file.Files.readAllBytes(mainSourceDir().resolve("CashuApplet.java")), java.nio.charset.StandardCharsets.UTF_8));
        int[] constructor = bodyRange(src, "private CashuApplet()");
        org.junit.jupiter.api.Assertions.assertFalse(src.substring(constructor[0], constructor[1]).contains("dleq"),
            "the constructor does not name the store: asked for there, the chip refuses to install the applet");
        int[] setCard = bodyRange(src, "private void processSetCard(");
        String body = src.substring(setCard[0], setCard[1]);
        int guard = body.indexOf("if (dleq == null)");
        int allocation = body.indexOf("dleq = new byte[");
        int begin = body.indexOf("JCSystem.beginTransaction()");
        org.junit.jupiter.api.Assertions.assertTrue(guard > 0 && guard < allocation && allocation < begin,
            "reserved once, behind its guard, before the transaction that writes the record");
        org.junit.jupiter.api.Assertions.assertTrue(!body.substring(0, allocation).contains("beginTransaction"),
            "and outside any transaction");
        // every assignment to the store: the allocation, and the null the catch leaves it as
        java.util.regex.Matcher assigned = java.util.regex.Pattern.compile("(?<![\\w.])dleq\\s*=(?!=)").matcher(src);
        int assignments = 0;
        while (assigned.find()) {
            assignments++;
            org.junit.jupiter.api.Assertions.assertTrue(assigned.start() > setCard[0] && assigned.start() < setCard[1],
                "the store is assigned only in SET_CARD, near: ..." + src.substring(Math.max(0, assigned.start() - 60), Math.min(src.length(), assigned.start() + 40)).replaceAll("\\s+", " "));
        }
        org.junit.jupiter.api.Assertions.assertEquals(2, assignments, "the allocation, and the null the catch leaves it as");
    }

    /**
     * The persistent arrays the constructors make, by their sizes: 29,806 bytes in 1.19, and the same in 1.20. The chip took +300 bytes
     * more in a constructor and refused +12,288 (measured, docs/FOXY-CARD-HARDWARE.md), where the 12,288 bytes of the mint's proofs are
     * given when asked for after the install. A figure past this one has to be measured on a card first.
     */
    @Test
    @DisplayName("the constructors make 29,806 bytes of persistent arrays, 1.19's figure: the 12,288 of the mint's proofs are not among them, for the chip refuses a constructor that asks for that much more")
    void theConstructorsAskForNoMorePersistentMemoryThanTheBuildThatInstalls() throws Exception {
        String applet = stripCommentsAndCharLiterals(new String(
            java.nio.file.Files.readAllBytes(mainSourceDir().resolve("CashuApplet.java")), java.nio.charset.StandardCharsets.UTF_8));
        String signer = stripCommentsAndCharLiterals(new String(
            java.nio.file.Files.readAllBytes(mainSourceDir().resolve("SchnorrHW.java")), java.nio.charset.StandardCharsets.UTF_8));
        java.util.Map<String, String> constants = constantExpressions(applet, signer);
        int total = 0, arrays = 0;
        String[][] constructors = { { "CashuApplet", "private CashuApplet()" }, { "SchnorrHW", "SchnorrHW(" } };
        for (String[] c : constructors) {
            String src = c[0].equals("CashuApplet") ? applet : signer;
            int[] body = bodyRange(src, c[1]);
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\bnew\\s+byte\\s*\\[([^\\]]+)\\]").matcher(src.substring(body[0], body[1]));
            while (m.find()) {
                total += evaluated(m.group(1), constants);
                arrays++;
            }
        }
        org.junit.jupiter.api.Assertions.assertEquals(29_806, total,
            "the persistent arrays the constructors make are the 29,806 bytes of the build that installs (1.19's, and 1.20's: the store of the mint's proofs is made after install). "
            + "A larger figure has to be measured on a card first: +300 bytes installed, +12,288 did not.");
        org.junit.jupiter.api.Assertions.assertEquals(20, arrays, "the parse found the 17 arrays of CashuApplet's constructor and the 3 of SchnorrHW's");
        org.junit.jupiter.api.Assertions.assertTrue(total + 12_288 > 29_806 + 300, "and the store is the kind of figure the chip refuses there");
    }

    /** The once-only allocations registered for a source file: { the method's declaration, the statement } each. */
    private static String[][] onceOnlyAllocations(String fileName) {
        java.util.List<String[]> found = new java.util.ArrayList<>();
        for (String[] entry : ONCE_ONLY_ALLOCATIONS) {
            if (entry[0].equals(fileName)) found.add(new String[] { entry[1], entry[2] });
        }
        return found.toArray(new String[0][]);
    }

    /** The install-time declarations registered for a source file. */
    private static String[] installTimeMethods(String fileName) {
        for (String[] entry : INSTALL_TIME_METHODS) {
            if (entry[0].equals(fileName)) {
                return java.util.Arrays.copyOfRange(entry, 1, entry.length);
            }
        }
        throw new org.opentest4j.AssertionFailedError(
            fileName + " is on the APDU path but has no entry in INSTALL_TIME_METHODS. "
            + "Add one listing the methods that run once at install time (constructor, "
            + "install(), anything called only from them) so the rest of the file is "
            + "checked for persistent-memory allocation.");
    }

    /**
     * Fails if the source allocates anywhere inside a method body other than the
     * given install-time declarations.
     */
    private static void assertNoAllocationOutside(String fileName, String rawSrc,
                                                  String[] installTimeDeclarations) {
        assertNoAllocationOutside(fileName, rawSrc, installTimeDeclarations, new String[0][]);
    }

    /**
     * The same, and the once-only statements ({ method declaration, statement }) let through: each must be there, once, whole, inside
     * the body of the method named.
     */
    private static void assertNoAllocationOutside(String fileName, String rawSrc,
                                                  String[] installTimeDeclarations, String[][] onceOnly) {
        String src = stripCommentsAndCharLiterals(rawSrc);

        int[][] allowedRanges = new int[installTimeDeclarations.length + onceOnly.length][];
        for (int i = 0; i < installTimeDeclarations.length; i++) {
            allowedRanges[i] = bodyRange(src, installTimeDeclarations[i]);
        }
        for (int i = 0; i < onceOnly.length; i++) {
            int[] method = bodyRange(src, onceOnly[i][0]);
            int[] at = findIgnoringSpace(src, onceOnly[i][1], 0, src.length());
            org.junit.jupiter.api.Assertions.assertNotNull(at,
                "the once-only allocation of " + fileName + " is not there, whole: " + onceOnly[i][1]);
            org.junit.jupiter.api.Assertions.assertTrue(at[0] > method[0] && at[1] < method[1],
                "the once-only allocation of " + fileName + " is not in " + onceOnly[i][0] + " but elsewhere: " + onceOnly[i][1]);
            org.junit.jupiter.api.Assertions.assertNull(findIgnoringSpace(src, onceOnly[i][1], at[1], src.length()),
                "the once-only allocation of " + fileName + " is there twice: " + onceOnly[i][1]);
            allowedRanges[installTimeDeclarations.length + i] = new int[] { at[0] - 1, at[1] };
        }

        // a once-only statement is no install-time body: an install-time helper called from it would be called from the APDU path
        assertOnlyCalledAtInstallTime(fileName, src, installTimeDeclarations,
            java.util.Arrays.copyOf(allowedRanges, installTimeDeclarations.length));

        // `new byte[..]` plus the array-initializer form `byte[] x = { .. }`,
        // which allocates just the same but contains no `new` keyword.
        java.util.regex.Pattern allocation = java.util.regex.Pattern.compile(
            "\\bnew\\b"
            + "|\\b(?:byte|short|int|boolean|Object)\\s*\\[\\s*\\]\\s*\\w+\\s*=\\s*\\{");

        int[] depth = braceDepths(src);

        java.util.regex.Matcher m = allocation.matcher(src);
        while (m.find()) {
            int at = m.start();
            // Depth 1 is the class body: field initialisers run once when the
            // applet is installed, which is exactly what we want. Depth >= 2 is
            // inside a method, and only the install-time methods may allocate.
            boolean allowed = depth[at] < 2;
            for (int[] range : allowedRanges) {
                allowed |= at > range[0] && at < range[1];
            }
            if (!allowed) {
                int from = Math.max(0, at - 90);
                int to = Math.min(src.length(), at + 90);
                org.junit.jupiter.api.Assertions.fail(
                    "allocation outside the install-time methods of " + fileName
                    + " leaks persistent EEPROM on every call — allocate once at install "
                    + "time as a CLEAR_ON_DESELECT transient array and thread it through "
                    + "as (work, workOff). Found near:\n..."
                    + src.substring(from, to).replaceAll("\\s+", " ") + "...");
            }
        }
    }

    /**
     * Fails if a method whose whole body is waived as install-time is reachable
     * from anywhere that is not itself waived.
     *
     * The waiver on {@code initCardKeypair()} is only sound while the "called
     * once, from the constructor" claim in its comment holds. Add a
     * {@code 0x4x REGENERATE_KEY} handler that calls it and the leak is back —
     * a fresh {@code KeyPair} in EEPROM per APDU — with the allocation guard
     * still green, because the allocation never moved. So the claim is checked
     * rather than read: every unqualified call to a listed name must sit inside
     * a listed body.
     *
     * Unqualified on purpose. {@code ecdh.init(tmpPriv)} is a call on another
     * object that happens to share a name with {@code SchnorrHW.init()}, and a
     * receiver before the dot is the one signal available without a type
     * checker. The flip side is the known limit of this check: a cross-file
     * {@code schnorrHW.init()} from an APDU handler is invisible to it. Both
     * cross-file entry points here are install-time by construction — the JCRE
     * calls {@code install()}, which calls the constructor — and the guard
     * covers the case that actually rots, which is a local helper quietly
     * gaining a second caller.
     */
    private static void assertOnlyCalledAtInstallTime(String fileName, String src,
                                                      String[] installTimeDeclarations,
                                                      int[][] allowedRanges) {
        for (int i = 0; i < installTimeDeclarations.length; i++) {
            String declaration = installTimeDeclarations[i];
            String name = declaredName(declaration);
            int declAt = src.indexOf(declaration);
            int declEnd = declAt + declaration.length();

            java.util.regex.Matcher calls = java.util.regex.Pattern
                .compile("(?<![.\\w$])" + java.util.regex.Pattern.quote(name) + "\\s*\\(")
                .matcher(src);
            while (calls.find()) {
                int at = calls.start();
                if (at >= declAt && at < declEnd) {
                    continue;   // the declaration itself
                }
                boolean allowed = false;
                for (int[] range : allowedRanges) {
                    allowed |= at > range[0] && at < range[1];
                }
                if (!allowed) {
                    int from = Math.max(0, at - 90);
                    int to = Math.min(src.length(), at + 90);
                    org.junit.jupiter.api.Assertions.fail(
                        name + "() is on the INSTALL_TIME_METHODS allow-list of " + fileName
                        + ", so its entire body is waived from the no-allocation rule — but "
                        + "it is called from outside every install-time method, i.e. from the "
                        + "APDU path. Either drop the waiver and stop allocating in it, or "
                        + "remove the call. Found near:\n..."
                        + src.substring(from, to).replaceAll("\\s+", " ") + "...");
                }
            }
        }
    }

    /** The method (or constructor) name in a declaration like "private void foo(". */
    private static String declaredName(String declaration) {
        int paren = declaration.indexOf('(');
        if (paren < 0) {
            throw new IllegalStateException(
                "INSTALL_TIME_METHODS entries must name a method: " + declaration);
        }
        int end = paren;
        while (end > 0 && Character.isWhitespace(declaration.charAt(end - 1))) end--;
        int start = end;
        while (start > 0 && Character.isJavaIdentifierPart(declaration.charAt(start - 1))) start--;
        if (start == end) {
            throw new IllegalStateException(
                "no method name found in INSTALL_TIME_METHODS entry: " + declaration);
        }
        return declaration.substring(start, end);
    }

    /** Applet main-source directory, resolved from either module or repo root. */
    static java.nio.file.Path mainSourceDir() throws java.io.IOException {
        String[] candidates = {
            "src/main/java/me/flashapp/cashu",
            "applet/src/main/java/me/flashapp/cashu",
        };
        for (String c : candidates) {
            java.nio.file.Path p = java.nio.file.Paths.get(c);
            if (java.nio.file.Files.isDirectory(p)) {
                return p;
            }
        }
        throw new java.io.FileNotFoundException(
            "applet sources not found relative to "
            + java.nio.file.Paths.get("").toAbsolutePath());
    }

    /** Drop comments and char literals so `new` and braces are only ever real code. */
    static String stripCommentsAndCharLiterals(String s) {
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            if (s.startsWith("/*", i)) {
                int e = s.indexOf("*/", i + 2);
                i = (e < 0) ? s.length() : e + 2;
            } else if (s.startsWith("//", i)) {
                int e = s.indexOf('\n', i);
                i = (e < 0) ? s.length() : e;
            } else if (s.charAt(i) == '\'') {
                int j = i + 1;
                while (j < s.length() && s.charAt(j) != '\'') {
                    j += (s.charAt(j) == '\\') ? 2 : 1;
                }
                out.append("' '");
                i = j + 1;
            } else {
                out.append(s.charAt(i));
                i++;
            }
        }
        return out.toString();
    }

    /** Brace nesting depth at every character index. Class body = 1, method body = 2. */
    static int[] braceDepths(String src) {
        int[] depth = new int[src.length()];
        int d = 0;
        for (int i = 0; i < src.length(); i++) {
            char c = src.charAt(i);
            if (c == '{') d++;
            depth[i] = d;
            if (c == '}') d--;
        }
        return depth;
    }

    /**
     * Where, in src from `from` to `to`, a run of characters begins that is `wanted` but for its white space: [start, end), or null.
     */
    private static int[] findIgnoringSpace(String src, String wanted, int from, int to) {
        String w = wanted.replaceAll("\\s+", "");
        for (int i = from; i < to; i++) {
            if (Character.isWhitespace(src.charAt(i))) continue;
            int a = i, b = 0;
            while (a < to && b < w.length()) {
                char c = src.charAt(a);
                if (Character.isWhitespace(c)) { a++; continue; }
                if (c != w.charAt(b)) break;
                a++;
                b++;
            }
            if (b == w.length()) return new int[] { i, a };
        }
        return null;
    }

    /** [openBraceIndex, closeBraceIndex] of the body following the given declaration. */
    private static int[] bodyRange(String src, String declaration) {
        int decl = src.indexOf(declaration);
        if (decl < 0) throw new IllegalStateException("not found in source: " + declaration);
        int open = src.indexOf('{', decl);
        if (open < 0) throw new IllegalStateException("no body for: " + declaration);
        int depth = 0;
        for (int i = open; i < src.length(); i++) {
            char c = src.charAt(i);
            if (c == '{') depth++;
            else if (c == '}' && --depth == 0) return new int[] { open, i };
        }
        throw new IllegalStateException("unbalanced braces after: " + declaration);
    }

    /**
     * The PIN key (1.9) is made once, at install, and the allow-list waives its body from the no-allocation rule (it builds a KeyPair and
     * a KeyAgreement). That is sound only while nothing on the APDU path can call it: a second call would put a new key pair in EEPROM
     * for every asking. The general call-site check above lets any install-time body call any listed method; this one is exact. Each of the
     * two key makers is called once, from the constructor, and the constructor is made once, by install().
     */
    @Test
    @DisplayName("initPinKey() and initCardKeypair() are each called once, from the constructor and nowhere else, and the constructor only by install()")
    void keyMakersAreCalledOnlyFromTheConstructor() throws Exception {
        String src = stripCommentsAndCharLiterals(new String(
            java.nio.file.Files.readAllBytes(mainSourceDir().resolve("CashuApplet.java")), java.nio.charset.StandardCharsets.UTF_8));
        int[] constructor = bodyRange(src, "private CashuApplet()");
        int[] install = bodyRange(src, "public static void install(");
        for (String maker : new String[] { "initCardKeypair", "initPinKey" }) {
            int declaration = src.indexOf("private void " + maker + "(");
            org.junit.jupiter.api.Assertions.assertTrue(declaration > 0, maker + " is declared");
            java.util.regex.Matcher calls = java.util.regex.Pattern.compile("(?<![.\\w$])" + maker + "\\s*\\(").matcher(src);
            int made = 0;
            while (calls.find()) {
                if (calls.start() == declaration + "private void ".length()) continue;
                made++;
                org.junit.jupiter.api.Assertions.assertTrue(calls.start() > constructor[0] && calls.start() < constructor[1],
                    maker + "() is called from outside the constructor, near: ..." + src.substring(Math.max(0, calls.start() - 80), Math.min(src.length(), calls.start() + 40)).replaceAll("\\s+", " "));
            }
            org.junit.jupiter.api.Assertions.assertEquals(1, made, maker + "() is called once");
        }
        java.util.regex.Matcher built = java.util.regex.Pattern.compile("\\bnew\\s+CashuApplet\\s*\\(").matcher(src);
        int constructed = 0;
        while (built.find()) {
            constructed++;
            org.junit.jupiter.api.Assertions.assertTrue(built.start() > install[0] && built.start() < install[1], "the constructor is run only from install()");
        }
        org.junit.jupiter.api.Assertions.assertEquals(1, constructed, "and once");
    }

    // ── The memory the applet asks of the chip at install ─────────────────

    /**
     * The figures of the build that is known to install on the chip (1.7): the transient memory the two
     * constructors ask for, by kind, and how many arrays that is. jCardSim has no limit on any of it, and a chip
     * has: 1.9 asked for 1,030 bytes of CLEAR_ON_DESELECT (in 15 arrays) where 1.7 asked for 931 (in 14), and
     * the chip answered INSTALL with 6F00 (which the opener applet turned out to be the cure for, not the
     * memory). 1.12 asks for 941 in 16: the change and the net of a payment, four bytes each. A larger figure
     * has to be measured on a card first.
     */
    static final int RAM_ON_DESELECT_MOST = 941, RAM_ON_RESET_MOST = 8, RAM_ARRAYS_MOST = 16;

    /** Every `static final short|byte|int NAME = expr;` of the applet's two sources. */
    private static java.util.Map<String, String> constantExpressions(String... sources) {
        java.util.Map<String, String> m = new java.util.HashMap<>();
        java.util.regex.Matcher c = java.util.regex.Pattern.compile("static\\s+final\\s+(?:short|byte|int)\\s+(\\w+)\\s*=\\s*([^;]+);").matcher(String.join("\n", sources));
        while (c.find()) m.put(c.group(1), c.group(2).trim());
        return m;
    }

    /** An integer expression of numbers, constants, + - * and parentheses, casts ignored. */
    private static int evaluated(String expr, java.util.Map<String, String> constants) {
        String e = expr.replaceAll("\\(\\s*(?:short|byte|int)\\s*\\)", "").replaceAll("\\s+", "");
        int[] at = { 0 };
        int v = sum(e, at, constants);
        if (at[0] != e.length()) throw new IllegalStateException("not an integer expression: " + expr);
        return v;
    }
    private static int sum(String e, int[] at, java.util.Map<String, String> k) {
        int v = product(e, at, k);
        while (at[0] < e.length() && (e.charAt(at[0]) == '+' || e.charAt(at[0]) == '-')) {
            char op = e.charAt(at[0]++);
            int w = product(e, at, k);
            v = op == '+' ? v + w : v - w;
        }
        return v;
    }
    private static int product(String e, int[] at, java.util.Map<String, String> k) {
        int v = factor(e, at, k);
        while (at[0] < e.length() && e.charAt(at[0]) == '*') { at[0]++; v *= factor(e, at, k); }
        return v;
    }
    private static int factor(String e, int[] at, java.util.Map<String, String> k) {
        if (e.charAt(at[0]) == '(') {
            at[0]++;
            int v = sum(e, at, k);
            at[0]++;
            return v;
        }
        int from = at[0];
        while (at[0] < e.length() && (Character.isLetterOrDigit(e.charAt(at[0])) || e.charAt(at[0]) == '_')) at[0]++;
        String token = e.substring(from, at[0]);
        if (Character.isDigit(token.charAt(0))) return Integer.decode(token);
        if (!k.containsKey(token)) throw new IllegalStateException("a constant with no definition: " + token);
        return evaluated(k.get(token), k);
    }

    /** { bytes CLEAR_ON_DESELECT, bytes CLEAR_ON_RESET, arrays } asked for by every JCSystem.makeTransientByteArray in the two sources. */
    static int[] transientMemoryAskedFor() throws Exception {
        String applet = stripCommentsAndCharLiterals(new String(java.nio.file.Files.readAllBytes(mainSourceDir().resolve("CashuApplet.java")), java.nio.charset.StandardCharsets.UTF_8));
        String signer = stripCommentsAndCharLiterals(new String(java.nio.file.Files.readAllBytes(mainSourceDir().resolve("SchnorrHW.java")), java.nio.charset.StandardCharsets.UTF_8));
        java.util.Map<String, String> constants = constantExpressions(applet, signer);
        int onDeselect = 0, onReset = 0, arrays = 0;
        for (String source : new String[] { applet, signer }) {
            org.junit.jupiter.api.Assertions.assertEquals(
                java.util.regex.Pattern.compile("makeTransient").matcher(source).results().count(),
                java.util.regex.Pattern.compile("JCSystem\\.makeTransientByteArray\\(").matcher(source).results().count(),
                "the only transient memory made is byte arrays through JCSystem: a boolean, short or object array is not counted here");
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("JCSystem\\.makeTransientByteArray\\(\\s*([^,]+?)\\s*,\\s*JCSystem\\.(CLEAR_ON_DESELECT|CLEAR_ON_RESET)\\s*\\)").matcher(source);
            while (m.find()) {
                int size = evaluated(m.group(1), constants);
                if (m.group(2).equals("CLEAR_ON_DESELECT")) onDeselect += size; else onReset += size;
                arrays++;
            }
            org.junit.jupiter.api.Assertions.assertEquals(
                java.util.regex.Pattern.compile("JCSystem\\.makeTransientByteArray\\(").matcher(source).results().count(),
                java.util.regex.Pattern.compile("JCSystem\\.makeTransientByteArray\\(\\s*[^,]+?\\s*,\\s*JCSystem\\.(?:CLEAR_ON_DESELECT|CLEAR_ON_RESET)\\s*\\)").matcher(source).results().count(),
                "every makeTransientByteArray names its size and one of the two kinds the parse knows");
        }
        return new int[] { onDeselect, onReset, arrays };
    }

    @Test
    @DisplayName("RAM budget: the two constructors ask for no more than 941 bytes of CLEAR_ON_DESELECT, 8 of CLEAR_ON_RESET, in no more than 16 arrays: the figures of 1.12, which are 1.7's and a payment's change and net (1.15 asks for 6 on reset: the time the terminal told, 4, and the tap's two flags)")
    void transientMemoryIsWithinTheBuildThatInstallsOnTheChip() throws Exception {
        int[] asked = transientMemoryAskedFor();
        String why = " These are the figures of 1.12 (941 bytes that are cleared on deselect, 8 on reset, in 16 arrays: 1.7's 931 in 14, and the change and the net of a payment). "
            + "1.9 asked for 1,030 in 15 and the chip refused to install it (6F00); jCardSim has no limit and says nothing. A larger figure has to be measured on a card first.";
        org.junit.jupiter.api.Assertions.assertTrue(asked[0] <= RAM_ON_DESELECT_MOST, "CLEAR_ON_DESELECT is " + asked[0] + " bytes, over " + RAM_ON_DESELECT_MOST + "." + why);
        org.junit.jupiter.api.Assertions.assertTrue(asked[1] <= RAM_ON_RESET_MOST, "CLEAR_ON_RESET is " + asked[1] + " bytes, over " + RAM_ON_RESET_MOST + "." + why);
        org.junit.jupiter.api.Assertions.assertTrue(asked[2] <= RAM_ARRAYS_MOST, "transient arrays are " + asked[2] + ", over " + RAM_ARRAYS_MOST + "." + why);
        // a parse that found nothing would prove nothing
        org.junit.jupiter.api.Assertions.assertEquals(16, asked[2], "the parse found the 14 of CashuApplet and the 2 of SchnorrHW");
        org.junit.jupiter.api.Assertions.assertEquals(941, asked[0], "and they add up: CashuApplet 397 and SchnorrHW 544");
        org.junit.jupiter.api.Assertions.assertEquals(6, asked[1], "1.15: the time the terminal told (4) and the tap's two flags (2); 1.14 kept six bytes for a clock told twice, and eight with the flags");
    }

    @Test
    @DisplayName("The parse of the RAM budget can say no: a source with a hundred bytes more, or another array, is over it")
    void theRamBudgetCanSayNo() throws Exception {
        java.util.Map<String, String> k = constantExpressions("static final short X_LEN = (short) 196; static final short ALL = MAX; static final short MAX = (short) 128;");
        org.junit.jupiter.api.Assertions.assertEquals(196, evaluated("X_LEN", k));
        org.junit.jupiter.api.Assertions.assertEquals(128, evaluated("(short) ALL", k));
        org.junit.jupiter.api.Assertions.assertEquals(10496, evaluated("(short)(MAX * 82)", k));
        org.junit.jupiter.api.Assertions.assertEquals(129, evaluated("(short)(MAX + 1)", k));
        int[] asked = transientMemoryAskedFor();
        org.junit.jupiter.api.Assertions.assertTrue(asked[0] + 100 > RAM_ON_DESELECT_MOST, "a hundred bytes more is over");
        org.junit.jupiter.api.Assertions.assertTrue(asked[2] + 1 > RAM_ARRAYS_MOST, "and so is one array more");
    }

    /**
     * What the two constructors create that a chip counts: crypto engines, key pairs and keys, a PIN object, a random source. Another of
     * any of them is memory the chip has not been shown to give (the failed 1.9 build had a second key agreement). Counted by call site;
     * a site that runs twice says so.
     */
    @Test
    @DisplayName("Crypto objects: CashuApplet makes 1 OwnerPIN, 1 Signature, 2 MessageDigests, 1 RandomData, 2 KeyPairs and 2 key sites (newP256Key, run once since 1.15 for the owner's key alone, and the RSA keys of the change); SchnorrHW makes 1 MessageDigest, 2 KeyAgreements, 1 RandomData and 1 key; no KeyAgreement, Cipher or Checksum is made anywhere else")
    void cryptoObjectsAreThoseOfTheBuildThatInstalls() throws Exception {
        String applet = stripCommentsAndCharLiterals(new String(java.nio.file.Files.readAllBytes(mainSourceDir().resolve("CashuApplet.java")), java.nio.charset.StandardCharsets.UTF_8));
        String signer = stripCommentsAndCharLiterals(new String(java.nio.file.Files.readAllBytes(mainSourceDir().resolve("SchnorrHW.java")), java.nio.charset.StandardCharsets.UTF_8));
        String[] kinds = { "new\\s+OwnerPIN\\(", "Signature\\.getInstance\\(", "MessageDigest\\.getInstance\\(", "RandomData\\.getInstance\\(", "new\\s+KeyPair\\(",
            "KeyBuilder\\.buildKey\\(", "KeyAgreement\\.getInstance\\(", "Cipher\\.getInstance\\(", "Checksum\\.getInstance\\(", "KeyAgreement\\b" };
        // 1.12: the RSA keys of the change (one buildKey site, run three times) and their Cipher; SchnorrHW's second KeyAgreement is the chip's point addition
        int[] inApplet = { 1, 1, 2, 1, 2, 2, 0, 1, 0, 0 };
        // SchnorrHW names KeyAgreement in its fields' types and in the getInstance calls, and in its agree-less comments only
        int[] inSigner = { 0, 0, 1, 1, 0, 1, 2, 0, 0, -1 };
        for (int i = 0; i < kinds.length; i++) {
            long a = java.util.regex.Pattern.compile(kinds[i]).matcher(applet).results().count();
            org.junit.jupiter.api.Assertions.assertEquals(inApplet[i], a, "CashuApplet.java: " + kinds[i] + " is called " + a + " times where the build that installs called it " + inApplet[i] + ". A chip counts these; measure a larger figure on a card first.");
            if (inSigner[i] >= 0) {
                long h = java.util.regex.Pattern.compile(kinds[i]).matcher(signer).results().count();
                org.junit.jupiter.api.Assertions.assertEquals(inSigner[i], h, "SchnorrHW.java: " + kinds[i] + " is called " + h + " times where the build that installs called it " + inSigner[i] + ". A chip counts these; measure a larger figure on a card first.");
            }
        }
        // and the EC key objects that exist: the card's pair, the PIN key's pair, the signer's temporary key, and the owner's key (the time signer's key went in 1.15: the clock is block headers)
        org.junit.jupiter.api.Assertions.assertEquals(1, java.util.regex.Pattern.compile("\\bnewP256Key\\(\\)").matcher(applet).results().count() - 1, "newP256Key is run for the owner key, and for no more: the time key is gone");
    }

    @Test
    @DisplayName("mul256x256 (raw 512-bit product) matches BigInteger a*b")
    void mul256x256MatchesBigInteger() throws Exception {
        java.lang.reflect.Method m = SchnorrHW.class.getDeclaredMethod(
            "mul256x256", byte[].class, short.class, byte[].class, short.class,
            byte[].class, short.class);
        m.setAccessible(true);
        Random r = rng();
        for (int i = 0; i < 200; i++) {
            BigInteger a = new BigInteger(256, r).mod(N);
            BigInteger b = new BigInteger(256, r).mod(N);
            byte[] prod = new byte[64];
            m.invoke(null, to32(a), (short) 0, to32(b), (short) 0, prod, (short) 0);
            assertEquals(a.multiply(b), new BigInteger(1, prod),
                "mul256x256 mismatch at iteration " + i);
        }
    }
}
