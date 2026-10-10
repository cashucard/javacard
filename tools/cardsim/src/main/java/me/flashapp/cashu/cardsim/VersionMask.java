package me.flashapp.cashu.cardsim;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Makes the one applet in jCardSim look like an older build on the wire.
 *
 * The apps have to handle a 0.4 card (no CLEAR_PIN, no PUK) and a 0.5 card
 * (no PUK) that are still in holders' hands, and the only way those builds
 * differ from 0.6 on the wire is: SELECT's version bytes, GET_INFO's length
 * and capability bits, and {@code 6D00} for the instructions they lack
 * (CashuApplet.java, the version comment above VERSION_MINOR; spec/APDU.md,
 * GET_INFO capability bits 3 and 4). A mask reproduces exactly that and
 * nothing else:
 *
 * <ul>
 *   <li>a refused INS is answered {@code 6D00} without reaching the applet,
 *       but only for CLA {@code B0}: any other CLA still reaches the applet's
 *       own {@code 6E00} (CashuApplet.process);</li>
 *   <li>SELECT and GET_INFO responses are rewritten only when the applet
 *       answered {@code 9000}; an error passes through untouched.</li>
 * </ul>
 *
 * The table is keyed by minor version. {@link #forVersion} refuses a version
 * the table does not know and a version above the real applet's, so a 0.7
 * bump without a table entry fails the coverage test rather than silently
 * serving 0.6 behaviour under a 0.7 label.
 */
final class VersionMask {

    private static final int CLA_SELECT = 0x00;
    private static final int INS_SELECT = 0xA4;
    private static final int CLA_APPLET = 0xB0;
    private static final int INS_GET_INFO = 0x01;
    private static final int INS_CLEAR_PIN = 0x43;
    private static final int INS_SET_PUK = 0x44;
    private static final int INS_UNBLOCK_PIN = 0x45;

    private static final byte[] SW_INS_NOT_SUPPORTED = { (byte) 0x6D, (byte) 0x00 };

    /** Known builds, oldest first. Every entry is a build a card in the field may run. */
    private static final Map<Integer, VersionMask> TABLE = new LinkedHashMap<>();
    static {
        // 0.4: D13 + D14 fixes, no CLEAR_PIN, no PUK. caps 0x07, 8-byte GET_INFO.
        put(new VersionMask(0, 4, 0x07, 8, set(INS_CLEAR_PIN, INS_SET_PUK, INS_UNBLOCK_PIN)));
        // 0.5: CLEAR_PIN (D15), no PUK. caps 0x0F, 8-byte GET_INFO.
        put(new VersionMask(0, 5, 0x0F, 8, set(INS_SET_PUK, INS_UNBLOCK_PIN)));
        // 0.6: SET_PUK + UNBLOCK_PIN (D16). caps 0x1F, 9 bytes, nothing refused.
        put(new VersionMask(0, 6, 0x1F, 9, Collections.emptySet()));
    }

    private static void put(VersionMask m) { TABLE.put(m.minor, m); }

    private static Set<Integer> set(int... ins) {
        Set<Integer> s = new TreeSet<>();
        for (int i : ins) s.add(i);
        return Collections.unmodifiableSet(s);
    }

    final int major;
    final int minor;
    final int capsMask;
    final int infoLen;
    final Set<Integer> refusedIns;

    private VersionMask(int major, int minor, int capsMask, int infoLen, Set<Integer> refusedIns) {
        this.major = major;
        this.minor = minor;
        this.capsMask = capsMask;
        this.infoLen = infoLen;
        this.refusedIns = refusedIns;
    }

    /** "0.4", "0.5", ... as the fixture's {@code appletVersion} spells it. */
    String version() {
        return major + "." + minor;
    }

    /** Whether this build answers SET_PUK / UNBLOCK_PIN (capability bit 4). */
    boolean hasPuk() {
        return (capsMask & 0x10) != 0;
    }

    /** The versions the table knows, oldest first. */
    static List<String> known() {
        java.util.ArrayList<String> out = new java.util.ArrayList<>();
        for (VersionMask m : TABLE.values()) out.add(m.version());
        return out;
    }

    /**
     * The mask for the real applet, read from its SELECT response. A real
     * version the table does not know is a bug in this file, not in the
     * applet: the table has to be extended before the bridge can run it.
     */
    static VersionMask real(byte[] selectVersion) {
        if (selectVersion == null || selectVersion.length != 2) {
            throw new IllegalStateException("SELECT did not answer two version bytes");
        }
        int major = selectVersion[0] & 0xFF;
        int minor = selectVersion[1] & 0xFF;
        VersionMask m = TABLE.get(minor);
        if (major != 0 || m == null) {
            throw new IllegalStateException("no VersionMask entry for applet " + major + "." + minor
                + ": add one to VersionMask.TABLE");
        }
        return m;
    }

    /**
     * The mask for an emulated version. Refuses an unknown version and one
     * above the real applet's, since a newer build cannot be emulated by an
     * older applet.
     */
    static VersionMask forVersion(String version, VersionMask real) {
        if (version == null) throw new IllegalArgumentException("appletVersion is missing");
        String[] parts = version.split("\\.", -1);
        int major, minor;
        try {
            if (parts.length != 2) throw new NumberFormatException();
            major = Integer.parseInt(parts[0]);
            minor = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("appletVersion must be \"<major>.<minor>\", got " + version);
        }
        VersionMask m = major == 0 ? TABLE.get(minor) : null;
        if (m == null) {
            throw new IllegalArgumentException("appletVersion " + version + " is not one of " + known());
        }
        if (major > real.major || (major == real.major && minor > real.minor)) {
            throw new IllegalArgumentException("appletVersion " + version + " is newer than the applet ("
                + real.version() + ")");
        }
        return m;
    }

    /**
     * The command-side mask: a {@code 6D00} response when this build refuses
     * the instruction, or {@code null} when the command should reach the
     * applet.
     */
    byte[] refuse(byte[] command) {
        if (command.length < 2) return null;
        int cla = command[0] & 0xFF;
        int ins = command[1] & 0xFF;
        if (cla == CLA_APPLET && refusedIns.contains(ins)) {
            return SW_INS_NOT_SUPPORTED.clone();
        }
        return null;
    }

    /**
     * The response-side mask. {@code response} is data‖SW as the simulator
     * returned it. Only SELECT and GET_INFO with SW 9000 are rewritten.
     */
    byte[] rewrite(byte[] command, byte[] response) {
        if (command.length < 2 || response.length < 2) return response;
        int sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
        if (sw != 0x9000) return response;
        int cla = command[0] & 0xFF;
        int ins = command[1] & 0xFF;
        int dataLen = response.length - 2;

        if (cla == CLA_SELECT && ins == INS_SELECT && dataLen == 2) {
            byte[] out = response.clone();
            out[0] = (byte) major;
            out[1] = (byte) minor;
            return out;
        }
        if (cla == CLA_APPLET && ins == INS_GET_INFO && dataLen >= infoLen && infoLen >= 7) {
            byte[] out = new byte[infoLen + 2];
            System.arraycopy(response, 0, out, 0, infoLen);
            out[0] = (byte) major;
            out[1] = (byte) minor;
            out[6] = (byte) (out[6] & capsMask);
            out[infoLen] = response[response.length - 2];
            out[infoLen + 1] = response[response.length - 1];
            return out;
        }
        return response;
    }
}
