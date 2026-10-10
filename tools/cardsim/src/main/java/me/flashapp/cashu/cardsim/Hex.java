package me.flashapp.cashu.cardsim;

/**
 * Hex in and out of the bridge.
 *
 * Parsing is lenient the way spec/CARD-FILE.md says readers are: case does not
 * matter, spaces are ignored, and a {@code 0x}/{@code 0X} prefix is tolerated.
 * Anything else — an odd number of digits, a non-hex character — is refused
 * with {@link IllegalArgumentException}, which the HTTP layer turns into a 400.
 * The bytes the app sends are the bytes the applet sees, so a lenient parser
 * must never guess: a typo is an error, not a different APDU.
 *
 * Formatting is upper case for wire-level fields ({@code /apdu} responses,
 * status words) and lower case for the card-file-shaped fields in
 * {@code /state} (pubkey, keysetId, nonce, C), which CARD-FILE.md writes in
 * lower case. No {@code java.util.HexFormat}: that is JDK 17 and this tool
 * runs on the pom's JDK 11 floor.
 */
final class Hex {

    private static final char[] UPPER = "0123456789ABCDEF".toCharArray();
    private static final char[] LOWER = "0123456789abcdef".toCharArray();

    private Hex() {}

    static byte[] parse(String text) {
        if (text == null) throw new IllegalArgumentException("hex is missing");
        String s = text.replace(" ", "");
        if (s.length() >= 2 && (s.startsWith("0x") || s.startsWith("0X"))) {
            s = s.substring(2);
        }
        if ((s.length() & 1) != 0) {
            throw new IllegalArgumentException("hex has an odd number of digits: " + text);
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = digit(s.charAt(2 * i), text);
            int lo = digit(s.charAt(2 * i + 1), text);
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static int digit(char c, String whole) {
        int d = Character.digit(c, 16);
        if (d < 0 || c > 0x7F) throw new IllegalArgumentException("not hex: " + whole);
        return d;
    }

    static String format(byte[] bytes) {
        return format(bytes, 0, bytes.length, UPPER);
    }

    static String format(byte[] bytes, int off, int len) {
        return format(bytes, off, len, UPPER);
    }

    static String formatLower(byte[] bytes) {
        return format(bytes, 0, bytes.length, LOWER);
    }

    static String formatLower(byte[] bytes, int off, int len) {
        return format(bytes, off, len, LOWER);
    }

    private static String format(byte[] bytes, int off, int len, char[] alphabet) {
        char[] out = new char[len * 2];
        for (int i = 0; i < len; i++) {
            int b = bytes[off + i] & 0xFF;
            out[2 * i] = alphabet[b >>> 4];
            out[2 * i + 1] = alphabet[b & 0x0F];
        }
        return new String(out);
    }

    /** A status word as the four upper-case digits every spec table uses. */
    static String sw(int sw) {
        return String.format("%04X", sw & 0xFFFF);
    }
}
