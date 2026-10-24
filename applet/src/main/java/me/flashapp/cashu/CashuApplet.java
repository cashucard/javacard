package me.flashapp.cashu;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * Cashu JavaCard Applet
 *
 * Implements NUT-XX Profile B (Bearer/Offline) for offline NFC payments.
 * Stores Cashu proofs in hardware-persistent EEPROM with non-resettable
 * spend counters. Provides secp256k1 signing for NUT-11 P2PK spending
 * conditions.
 *
 * This is the shared Cashu card protocol, version 2.1: the Foxy wallet
 * project's fork at software 1.20 (docs/FOXY-CARD-SPEC.md), merged back into
 * cashu-javacard with a neutral identity and the fixes in docs/DECISIONS.md
 * D18 to D26. It is not compatible on the wire with cashu-javacard 0.x nor
 * with Foxy's 1.x, and has an AID of its own so that none of the three can be
 * mistaken for another:
 *
 * AID: F0 43 41 53 48 55 43 41 52 44   ("CASHUCARD" after a proprietary F0)
 *
 * Command set:
 *   0x01  GET_INFO         — version, format, slot stats, PIN state, tries, limit, owner, the day; with P1 = 1, the tap limit (owner only) and the no-PIN allowance as well; with P1 = 2, those and whether the NFC tag is on
 *   0x10  GET_PUBKEY       — 33-byte compressed secp256k1 card pubkey
 *   0x11  GET_BALANCE      — sum of unspent proof amounts (uint32)
 *   0x12  GET_PROOF_COUNT  — count of non-empty slots
 *   0x13  GET_PROOF        — full proof data at slot index, with its date
 *   0x14  GET_SLOT_STATUS  — bulk 1-byte status for all slots
 *   0x15  AUTH             — prove this is the card: sign the reader's nonce and its own
 *   0x16  GET_CARD         — the card record: mint, unit, refund key, limit, the clock's block header (its bits and hash)
 *   0x17  GET_PIECES       — every slot's state and every unspent piece, a page at a time (P1 = the first slot)
 *   0x18  GET_LOG          — the card's own account of its taps: what it signed for, what it refused
 *   0x19  GET_CHANGE       — the change the card made for itself and has not been handed: the openings, a page at a time
 *   0x1A  GET_DLEQ         — the mint's proof kept with an unspent piece, for one place or two (P1, P2; FF for none)
 *   0x22  SPEND_ALL_BEGIN  — the places a payment is made of, in order (one signature for all: NUT-11 SIG_ALL)
 *   0x23  SPEND_ALL_OUTPUTS — the swap's outputs, 37 bytes each, hashed into the message as they come
 *   0x26  SPEND_ALL_CHANGE — one change output the card makes for itself, locked to its own key; answers the blinded message
 *   0x24  SPEND_ALL_SIGN   — the one signature; every piece named is burned as it is given; with a PIN set, the PIN or the no-PIN allowance (6A94)
 *   0x25  SPEND_ALL_AGAIN  — the last signature given, again, for an answer lost on the air
 *   0x30  LOAD_PROOF       — store new proof (an owner, a time, and a PIN or the owner's grant); with P1 = 1, one piece and the mint's proof for it
 *   0x31  CLEAR_SPENT      — free spent slots (PIN, or the owner's grant)
 *   0x32  SET_CARD         — write the card record (open card: PIN; owned card: the owner's proof; only with nothing unspent)
 *   0x33  SET_LIMIT        — the daily limit, by PIN: an open card only (no owner, nothing unspent)
 *   0x34  SET_LIMIT        — the daily limit, by the owner's proof; with eight bytes, the limit on one payment as well; with twelve, the no-PIN allowance
 *   0x35  (was SET_TIME, a time under a key's signature: gone in 1.15, answers 6D00)
 *   0x36  SET_HEADER       — a Bitcoin block header: its proof of work moves the card's clock forward
 *   0x37  TELL_TIME        — the terminal's own clock, a note for receipts and the log, trusted for nothing
 *   0x40  VERIFY_PIN       — verify the PIN
 *   0x41  SET_PIN          — set or replace the PIN on an open card (no owner, nothing unspent); add one to a card with an owner that has none (the owner's grant)
 *   0x42  CHANGE_PIN       — the owner's proof and the new PIN: no old PIN, any state
 *   0x43  SET_OWNER        — give the card its owner key (an open card, or the old owner's proof; nothing unspent)
 *   0x44  GET_NONCE        — a fresh nonce for the owner's proof
 *   0x45  ALLOW_LOAD       — the owner's proof lets LOAD_PROOF and CLEAR_SPENT through, with no PIN, for this tap
 *   0x50  LOCK_CARD        — permanently disable write operations (PIN, and the owner's proof)
 *   0x51  RESET_CARD       — back to a card out of its packet, for another person to set up (the owner's proof; nothing unspent; the PIN too if locked)
 *   0x52  SET_TAG          — switch the card's NFC tag off or on (the owner's proof; no PIN; any funds)
 *   0x53  REFRESH          — the owner's proof over a block header: the header is taken, and the rollover budget is full again (2.0)
 *
 * What the fork changes, and why (the spec's section 4, and docs/FOXY-CARD-DAILY-LIMIT.md):
 *   - SPEND_PROOF takes no message. Upstream signed 32 bytes the reader
 *     supplied, so a reader could have slot A burned for slot B's signature,
 *     and the SPENT flag bound nothing. The card now rebuilds the slot's own
 *     NUT-10 secret and signs its hash.
 *   - SIGN_ARBITRARY is gone. It signed anything and burned nothing. AUTH is
 *     what is left of "prove you are the card", over a tagged hash that no
 *     secret can hash to.
 *   - Nothing is loaded onto a card with no PIN but by the owner's grant (or the
 *     change of a payment it has just made), and nothing onto a card with no
 *     owner. (Since 1.16 a card may have no PIN at all; it then pays without one.)
 *   - A piece is loaded once. A nonce that is in any slot, spent or not, is
 *     refused (6A94): the card signs the secret, which the nonce makes, and
 *     takes the amount on the terminal's word, so a copy with a smaller
 *     amount would have been signed for at the smaller price.
 *   - The card keeps a DAILY LIMIT in permanent memory, and a clock of its own
 *     (`now`) that only moves forward: the time written in the newest Bitcoin
 *     block header it has been shown (SET_HEADER), which it believes for the
 *     work in it and not for who brought it. A spend is counted against the
 *     day it falls in. A terminal that was handed the PIN can sign for one
 *     day's limit and no more, and can end the day only by bringing a real
 *     block dated a day on, which exists only once the world has mined it.
 *     The PIN, a new SELECT or a reset change nothing about it.
 *   - A card with an OWNER (a P-256 public key) is its owner's, empty or not:
 *     changing the PIN, the limit, the owner or the card record, adding funds
 *     without the PIN, and locking the card each need the owner's proof, an
 *     ECDSA signature over a label, a nonce the card has just given and the
 *     value being set. A card with no owner is open while it is empty, and
 *     cannot be loaded.
 *   - A slot carries a date, and the card a refund key, so a lost or blocked
 *     card's pieces can be taken back by whoever loaded them.
 *   - The card says which mint its pieces are at.
 *
 * @see <a href="https://github.com/cashucard/javacard">cashu-javacard</a>
 * @see spec/APDU.md for full command reference
 * @see spec/NUT-XX.md for protocol specification
 */
public class CashuApplet extends Applet implements TagSwitch {

    // -------------------------------------------------------------------------
    // Applet version
    //
    // Moves with every wire-visible behaviour change, and with every fix that
    // a card in the field has to be told apart by, because it is the only
    // non-destructive way to tell two builds apart. 0.3 is the ENG-615 fix:
    // on 0.2 a blocked PIN stopped gating; on 0.3 it gates for good, and a
    // failed PIN check (VERIFY_PIN or CHANGE_PIN) ends the session's
    // authentication. 0.4 is the ENG-620 fix (D14): every slot write commits
    // the status byte last. Nothing on the wire changes outside a torn write,
    // but main tracked a 0.3 CAP with the old order, and SELECT's version is
    // all an installed card reports about its build.
    // -------------------------------------------------------------------------
    //
    // 1.0 is the Foxy fork: another AID, another slot, another SPEND_PROOF.
    // 1.1 is the daily limit, the owner key and the clock (docs/FOXY-CARD-DAILY-LIMIT.md).
    // FORMAT is what a reader checks before it reads a slot: 3 for this design
    // (2 was the allowance draft and the first limit).
    // 2.0 is the shared protocol (ENG-673, DECISIONS D18): Foxy's 1.20 under the neutral AID F0 CASHUCARD and the neutral
    // labels "CashuCard/..." (D19), with the rollover budget, REFRESH, the armed allowance and the clock anchored at
    // SET_OWNER (D20), a field multiply with no secret-dependent branch (D21; the reductions still branch, SECURITY-MODEL open item 5), the PIN state as the PIN's commit byte (D22),
    // the tear review (D23) and a floor of work recomputed for its own time (D24).
    // The minor counts from 0 again: 2.0 is the first of the shared wire.
    // 2.1 is ENG-699 (D26, from Mike Greff's review): a payment that moves no value (all of it back as the card's own change)
    // neither begins a day nor spends a roll of the budget, and a SET_LIMIT without the budget's byte (4, 8 or 12 bytes, and
    // the PIN's form) leaves the budget as it is, where 2.0 set it back to 7. Nothing on the wire is added or moved; two
    // answers change (GET_CARD's bytes 76 and 77 after such a payment or such a SET_LIMIT), and v2.0.0 was released with
    // the old ones, so a reader can tell the two builds apart by the minor alone.
    static final byte VERSION_MAJOR = (byte) 0x02;
    // 1.9 takes its PIN sealed: enciphered to a key the card keeps for that and nothing else, under
    // sixteen bytes of its own that are good once (see `unseal`). Capability bit 7 says so.
    // 1.8 burns a payment's pieces outside the transaction that commits the payment (see `finishBurn`):
    // on the chip a transaction held about a dozen places and no more, and a payment of thirty-two was
    // refused. Now a payment is of as many places as the card has, and capability bit 6 says so.
    // 1.7 is the same card with twice the places (128), so that it can hold a deep drawer of small
    // pieces; a place's number is seven bits where it was six, so GET_PIECES' tags changed, and the
    // short listing is a shorter one (see `processGetPieces`). Nothing it signs or stores for a piece
    // is different.
    // 1.6 is the same card made quicker to hold (see `slotHex`, GET_PIECES' two short forms, and several
    // pieces to one LOAD_PROOF): nothing it signs, refuses or stores for a piece is different.
    // 1.3 was a limit on one tap, a window of ten seconds that refused. 1.5 makes it the limit on one
    // payment, which asks no clock and is waited for (docs/FOXY-CARD-DAILY-LIMIT.md, section 6a).
    // 1.4 is one signature for a whole payment (NUT-11 SIG_ALL): format 4, in
    // which every piece's secret carries the flag and SPEND_PROOF is gone.
    // 1.12 makes a payment's change itself (SPEND_ALL_CHANGE): outputs locked to the card's own key,
    // built by the card, so that nothing a terminal names can take them; the limits and the wait are
    // held to what leaves the card for good, the pieces less that change; and the openings of change
    // not yet handed back can be read (GET_CHANGE) by any phone that would finish the pieces.
    // 1.13 shapes the wait so that a payer can tell by feel that a payment was over the limit: nothing
    // within it (change or no change: the phone says change is coming, the card does not), about five
    // seconds over it, and two more for every further limit's worth (`waitsFor`). The work of making the
    // change counts toward it. And one payment a tap at full speed: a second one in the same time in the
    // field is slowed as one over the limit, unless the owner's grant is in the tap.
    // 1.16 makes the PIN optional. A card may have none, and then it pays without one (its limits still hold). A card
    // with a PIN has a third limit, the NO-PIN ALLOWANCE: what it signs for in a day without the PIN, counted in the day's
    // window beside the daily limit; over it the signature is refused with 6A94 and the PIN is asked for the whole payment.
    // A PIN is added to a card that has an owner by the owner's grant (SET_PIN). The wire is otherwise 1.15's.
    // 1.17 is RESET_CARD (0x51): the owner's proof wipes the card to what it was out of its packet, with a new key of its own, so that
    // another person may set it up. It keeps its clock and its software. Nothing unspent may be on it (6A8D), and a locked card
    // wants the PIN as well. The wire is otherwise 1.16's.
    // 1.18 waits four signatures of the card's own work for each limit's worth over the limit past the first, where 1.13 to
    // 1.17 waited three (the first limit's worth over is ten, as it was in 1.17). Nothing else is different: the wire is 1.17's.
    // 1.19 is the NFC tag. The card also answers as an NFC Forum Type 4 Tag carrying one web address, the same on every card (the
    // applet `Tag`, instantiated under the NFC Forum's own name), and its owner switches that off and on with SET_TAG (0x52: the
    // owner's proof under "CashuCard/tag", no PIN, any funds). The switch is one persistent byte: on for a new card, a card with no
    // owner and a card just reset. GET_INFO has a new form, P1 = 2, whose 43rd byte says it; the answers to P1 = 0 and P1 = 1
    // are the 30 and the 42 bytes they were, whatever the tag's state, because the wallets that went before take the answer to
    // P1 = 1 as the long form only when it is exactly 42 bytes. The wire is otherwise 1.18's.
    // 1.20 keeps the mint's proof with each piece. LOAD_PROOF with P1 = 1 takes one piece and, after it, the three numbers a later
    // holder needs to check that the mint made the piece (NUT-12: e, s and the blinding factor r, 96 bytes), and GET_DLEQ (0x1A)
    // gives them back for an unspent place. The card does not check the proof and never uses it, and a payment is what it was: no
    // payment command writes them. The 12,288 bytes that hold them (`dleq`) are reserved by the first SET_CARD and NOT in the
    // constructor, which the chip refuses to install with so much more in it (docs/FOXY-CARD-HARDWARE.md); the same bytes asked for
    // after the install are given. Every use of `dleq` is safe while it is null (before the first SET_CARD, or after the card has
    // refused the room). GET_INFO is 1.19's to the byte but for the version; a phone tells a 1.20 card by that.
    static final byte VERSION_MINOR = (byte) 0x01;
    static final byte FORMAT        = (byte) 0x04;

    // -------------------------------------------------------------------------
    // APDU instruction bytes
    // -------------------------------------------------------------------------
    static final byte INS_GET_INFO         = (byte) 0x01;
    static final byte INS_GET_PUBKEY       = (byte) 0x10;
    static final byte INS_GET_BALANCE      = (byte) 0x11;
    static final byte INS_GET_PROOF_COUNT  = (byte) 0x12;
    static final byte INS_GET_PROOF        = (byte) 0x13;
    static final byte INS_GET_SLOT_STATUS  = (byte) 0x14;
    static final byte INS_AUTH             = (byte) 0x15;
    static final byte INS_GET_CARD         = (byte) 0x16;
    static final byte INS_GET_PIECES       = (byte) 0x17;
    static final byte INS_GET_LOG          = (byte) 0x18;
    static final byte INS_GET_CHANGE       = (byte) 0x19;
    static final byte INS_GET_DLEQ         = (byte) 0x1A;
    // 0x20 was SPEND_PROOF: one piece, one signature over its secret alone. A
    // piece of format 4 says SIG_ALL in its secret, and a mint takes no such
    // signature for it. It answers 6D00 and stays unassigned.
    static final byte INS_SPEND_ALL_BEGIN   = (byte) 0x22;
    static final byte INS_SPEND_ALL_OUTPUTS = (byte) 0x23;
    static final byte INS_SPEND_ALL_SIGN    = (byte) 0x24;
    static final byte INS_SPEND_ALL_AGAIN   = (byte) 0x25;
    static final byte INS_SPEND_ALL_CHANGE  = (byte) 0x26;
    // 0x21 was SIGN_ARBITRARY. It answers 6D00 and must stay unassigned.
    static final byte INS_LOAD_PROOF       = (byte) 0x30;
    static final byte INS_CLEAR_SPENT      = (byte) 0x31;
    static final byte INS_SET_CARD         = (byte) 0x32;
    // 0x33 was once a limit on one PIN entry, which a terminal holding the PIN
    // walked round. It is back as the daily limit set by PIN, for an open card
    // only (no owner): the owner's form is 0x34.
    static final byte INS_SET_LIMIT        = (byte) 0x33;
    static final byte INS_SET_LIMIT_OWNER  = (byte) 0x34;
    // 0x35 was SET_TIME, a time under the signature of a key that lived in the app: gone in
    // 1.15 (the key could be copied out of any phone), it answers 6D00 and stays unassigned.
    static final byte INS_SET_HEADER       = (byte) 0x36;
    static final byte INS_TELL_TIME        = (byte) 0x37;
    static final byte INS_VERIFY_PIN       = (byte) 0x40;
    static final byte INS_SET_PIN          = (byte) 0x41;
    static final byte INS_CHANGE_PIN       = (byte) 0x42;
    static final byte INS_SET_OWNER        = (byte) 0x43;
    static final byte INS_GET_NONCE        = (byte) 0x44;
    static final byte INS_ALLOW_LOAD       = (byte) 0x45;
    static final byte INS_LOCK_CARD        = (byte) 0x50;
    static final byte INS_RESET_CARD       = (byte) 0x51;
    static final byte INS_SET_TAG          = (byte) 0x52;
    /** 2.0 (D20): the owner's proof over a block header; the header is taken as SET_HEADER takes it, and the rollover budget is full again. */
    static final byte INS_REFRESH          = (byte) 0x53;

    // -------------------------------------------------------------------------
    // Proof slot layout constants (82 bytes per slot: upstream's 78 and a date)
    // -------------------------------------------------------------------------
    static final short PROOF_SIZE          = (short) 82;
    static final short PROOF_STATUS_OFFSET = (short) 0;
    static final short PROOF_KEYSET_OFFSET = (short) 1;
    static final short PROOF_AMOUNT_OFFSET = (short) 9;
    // The 32 bytes are the P2PK *nonce*, not the secret: a NUT-10 P2PK secret
    // is a JSON string of ~150 bytes and cannot fit. The reader rebuilds the
    // secret from this nonce plus GET_PUBKEY. See spec/NUT-XX.md.
    static final short PROOF_NONCE_OFFSET  = (short) 13;
    static final short PROOF_C_OFFSET      = (short) 45;
    // The piece's NUT-11 locktime, big-endian seconds, or 0 for none. With a
    // date the piece's secret also names the card's refund key, which may
    // spend it once the date has passed (spec section 6).
    static final short PROOF_DATE_OFFSET   = (short) 78;

    static final short PROOF_DATA_LEN      = (short) 81;  // PROOF_SIZE - 1 (no status byte on input)

    static final byte STATUS_EMPTY   = (byte) 0x00;
    static final byte STATUS_UNSPENT = (byte) 0x01;
    static final byte STATUS_SPENT   = (byte) 0x02;

    // 128: a place's number is a byte and seven bits of a GET_PIECES tag, and the
    // two arrays that hold the places are 10,496 and 16,640 bytes, each under
    // what one array may be.
    static final short MAX_PROOFS = (short) 128;

    // GET_PIECES' answer is at most this many bytes: under what a short APDU
    // carries (256), and room for three unspent entries (1 + 3 * 82 = 247).
    static final short PAGE_MAX = (short) 255;
    /** A place's text for hashing, kept beside it: its nonce in hex (64) and its C in hex (66). See `slotHex`. */
    static final short HEX_LEN = (short) 130;
    /** GET_PIECES, P2 = 3: the most one entry of the short listing comes to: place, keyset (8), date (4), size, amount (4). */
    static final short SHORT_MOST = (short) 18;
    /** The most pieces one LOAD_PROOF takes, and the most places GET_PIECES gives whole when asked for by name. */
    static final short BATCH_MOST = (short) 3;

    /**
     * The mint's proof for a piece (1.20), as a later holder needs it (NUT-12): e (32), s (32) and the blinding factor r (32), kept
     * for each place in `dleq`, the place k's record at k * DLEQ_LEN. A record of zeros is "no proof". The card does not check it.
     */
    static final short DLEQ_LEN = (short) 96;
    /** LOAD_PROOF with P1 = 1: one piece (81 bytes) and, after it, its proof (96). */
    static final short LOAD_DLEQ_LEN = (short)(PROOF_DATA_LEN + DLEQ_LEN);

    // -------------------------------------------------------------------------
    // The card record (persistent): which mint, which unit, who may take the
    // pieces back, the daily limit, the clock's block header and the day.
    // -------------------------------------------------------------------------
    static final short CARD_SET_OFFSET     = (short) 0;   // 1 once SET_CARD has run
    static final short CARD_UNIT_OFFSET    = (short) 1;   // 0 = sat
    // The most the card signs for in one day, sats, big-endian. 0 is NO limit,
    // and is what a new card has. SET_CARD never writes it.
    static final short CARD_LIMIT_OFFSET   = (short) 2;
    static final short CARD_REFUND_OFFSET  = (short) 6;   // 33 bytes, zeros = none
    static final short CARD_MINTLEN_OFFSET = (short) 39;
    static final short CARD_MINT_OFFSET    = (short) 40;
    // 80, not 96: SET_CARD with the owner's proof carries a proof of up to 72
    // bytes and its length, 100 bytes of record and the mint, in one short
    // APDU of 255 data bytes.
    static final short CARD_MINT_MAX       = (short) 77;   // 80 before the design: a short APDU holds the proof, the record, the mint and it (1 + 72 + 100 + 77 + 3 = 253)
    // The clock's own proof. The hardest difficulty of any block header the card
    // has accepted, as the header carries it (4 bytes, `bits`, little-endian;
    // zeros until one has): a later header must show at least a quarter of that
    // work. Then the hash of the last header taken (32 bytes, as Bitcoin shows a
    // block hash), for the owner's screen. The 29 bytes after are zeros. These
    // 65 bytes held a time signer's key until 1.15.
    static final short CARD_BITS_OFFSET    = (short) 120;
    static final short CARD_HEADER_OFFSET  = (short) 124;
    // 2.0 (D20), three of the 29 bytes after the hash, so that GET_CARD shows them (its bytes 76, 77, 78) and RESET_CARD
    // clears them with the rest: how many times the day's window has rolled since the owner's last REFRESH (or the anchored
    // SET_OWNER); the most it may roll before the next (0 is the default, ROLL_BUDGET_DEFAULT; 1 to ROLL_BUDGET_MOST); and
    // whether the no-PIN allowance may begin again at the next roll (1 once a PIN or an owner's proof has been given since it
    // last did). The 26 bytes after them are zeros.
    static final short CARD_ROLLS_OFFSET   = (short) 156;
    static final short CARD_BUDGET_OFFSET  = (short) 157;
    static final short CARD_ARMED_OFFSET   = (short) 158;
    static final byte  ROLL_BUDGET_DEFAULT = (byte) 7;
    static final byte  ROLL_BUDGET_MOST    = (byte) 30;
    /** A block header, as SET_HEADER, REFRESH and an anchored SET_OWNER take it. */
    static final short HEADER_LEN          = (short) 80;
    // The latest block time the card has accepted, seconds, big-endian, 0 until
    // it has seen a header. SET_HEADER writes it; nothing lowers it.
    static final short CARD_NOW_OFFSET     = (short) 185;
    // When the current day began, and what has been signed for since.
    static final short CARD_WINDOW_OFFSET  = (short) 189;
    static final short CARD_SPENT_OFFSET   = (short) 193;
    // The most the card signs for in one payment without making the terminal
    // wait, sats, big-endian; 0 is NO limit. It is not counted against a clock
    // and nothing is remembered of it from one payment to the next: a payment
    // is judged by its own size, and every limit's worth past the first costs
    // signatures of the card's own work before it signs (6a, `waitsFor`).
    static final short CARD_TAP_LIMIT_OFFSET  = (short) 197;
    // The NO-PIN ALLOWANCE (1.16): what the card signs for in a day without the PIN, sats, big-endian, on a card that has
    // a PIN; 0 is none, and then every payment needs the PIN. And what it has signed for with no PIN in the day's window
    // (CARD_WINDOW_OFFSET, shared with the daily limit): it goes to 0 when the day turns. Only a payment signed with no
    // PIN while a PIN was set counts. These eight bytes held a ten-second window and its count of the limit on one payment
    // until 1.15 and were zeros since; GET_INFO P1 = 1 says them (34..37 and 38..41), to anyone.
    static final short CARD_NOPIN_LIMIT_OFFSET = (short) 201;
    static final short CARD_NOPIN_SPENT_OFFSET = (short) 205;
    /** The card's face: a code of three characters (capital letters and digits) naming its design, or zeros for none (1.10, docs/CARD-DESIGNS.md). */
    static final short CARD_DESIGN_OFFSET  = (short) 209;
    static final short CARD_DESIGN_LEN     = (short) 3;
    static final short CARD_RECORD_LEN     = (short) 212;
    // SET_CARD's data: unit (1), refund key (33), 65 bytes that held a time key until 1.15 and are not read, mint length (1), then the mint
    static final short SET_CARD_FIXED      = (short) 100;
    static final short SET_CARD_MINTLEN_AT = (short) 99;
    static final short EC_POINT_LEN        = (short) 65;

    static final short AUTH_NONCE_LEN      = (short) 16;

    // -------------------------------------------------------------------------
    // The PIN, sealed (1.9). See `unseal`.
    // -------------------------------------------------------------------------
    /** A sealed command's tag: the first sixteen bytes of block 0. */
    static final short SEAL_TAG_LEN        = (short) 16;
    /** A PIN as it is sealed: its length (1), the PIN, zeros to eight. Always nine bytes, so its length says nothing of the PIN's. */
    static final short PIN_BLOCK_LEN       = (short) 9;
    /** GET_NONCE with P1 = 1: the nonce (16), the PIN key (33, compressed), the card key's signature over it (64). */
    static final short PIN_KEY_ANSWER      = (short) 113;
    private static final byte[] SEAL_LABEL = {
        'C', 'a', 's', 'h', 'u', 'C', 'a', 'r', 'd', '/', 's', 'e', 'a', 'l'
    };
    private static final byte[] PINKEY_LABEL = {
        'C', 'a', 's', 'h', 'u', 'C', 'a', 'r', 'd', '/', 'p', 'i', 'n', 'k', 'e', 'y'
    };
    // `seal` (RAM; the first S_LEN bytes of `scratch`): the point the two keys share (65), a block of the hash (32), and the two single bytes the hash takes (a counter, the instruction)
    private static final short S_POINT = (short) 0;
    private static final short S_HASH  = (short) 65;
    private static final short S_I     = (short) 97;
    private static final short S_INS   = (short) 98;
    private static final short S_LEN   = (short) 99;

    // One signature for a payment: no more pieces than this in it, and an
    // output is its amount (4, big-endian) and its blinded message (33).
    // Every place the card has (it was thirty-two): a deep drawer holds its
    // money in small pieces, and a payment of most of a small card is many of
    // them. The transaction that commits a payment is the same size whatever
    // their number (`finishBurn`).
    static final short ALL_MOST            = MAX_PROOFS;
    static final short ALL_OUTPUT_LEN      = (short) 37;

    // The change a payment makes for itself (1.12): the card's own change outputs, kept open from the
    // moment they are made until the piece is written back. An opening is the amount (4), the keyset
    // (8), the date (4), the nonce (32) and the blinding factor (32); its state is a byte of `openState`,
    // kept apart so that a payment's SIGN flips every opening it made in one write of its transaction.
    static final short CHANGE_MOST   = (short) 8;    // openings a card keeps; a payment makes at most this many change outputs
    static final short OPEN_LEN      = (short) 80;
    static final short OPEN_AMOUNT   = (short) 0;
    static final short OPEN_KEYSET   = (short) 4;
    static final short OPEN_DATE     = (short) 12;
    static final short OPEN_NONCE    = (short) 16;
    static final short OPEN_R        = (short) 48;
    static final byte  OPEN_EMPTY    = (byte) 0;
    static final byte  OPEN_DRAFT    = (byte) 1;   // made for a payment not yet signed for: let go at the next BEGIN
    static final byte  OPEN_PENDING  = (byte) 2;   // signed for; the piece is to come back
    static final short CHANGE_PAGE   = (short) 3;  // openings to one GET_CHANGE answer (80 bytes each, after a count)

    // -------------------------------------------------------------------------
    // The log (persistent): the card's own account of what it has signed for
    // and what it has refused. A spend writes it, in the transaction that
    // burns the piece, and a spend refused for being over a limit writes it
    // before it is refused. Nothing else does: no command sets it or moves it
    // back, for the PIN or for the owner, and the one that clears it is
    // RESET_CARD (1.17), which makes the card a new one. The counts only go up,
    // and stop at the top of four bytes.
    //
    // A tap, here, is one time in a reader's field: from the card being
    // powered to its being taken away: it counts by the field, because that
    // is what a person did. A terminal that cuts the field to
    // begin again shows as more taps, and the totals count them all.
    // -------------------------------------------------------------------------
    static final short LOG_TAPS_OFFSET      = (short) 0;   // taps in which anything was signed for or refused, ever
    static final short LOG_SATS_OFFSET      = (short) 4;   // sats signed for, ever
    static final short LOG_REFUSED_OFFSET   = (short) 8;   // spends refused for being over a limit, ever
    static final short LOG_TAMPERS_OFFSET   = (short) 12;  // times a third spend was refused inside ten seconds of the clock, and times in the field in which the clock was moved twice (5.3)
    static final short LOG_RUN_AT_OFFSET    = (short) 16;  // the clock at the first refusal of the run in hand
    static final short LOG_RUN_OFFSET       = (short) 20;  // how many refusals are in that run (1 byte)
    static final short LOG_HEAD_LEN         = (short) 21;
    // the last eight taps, in a ring: the tap numbered n is at (n - 1) mod 8
    static final short LOG_ENTRIES          = (short) 8;
    static final short LOG_ENTRY_LEN        = (short) 20;
    static final short LOG_E_TIME           = (short) 0;   // the clock when the tap's first entry was made (4)
    static final short LOG_E_SATS           = (short) 4;   // sats signed for in it (4)
    static final short LOG_E_PIECES         = (short) 8;   // pieces signed (1, stops at 255)
    static final short LOG_E_REFUSED        = (short) 9;   // spends refused in it for being over a limit (1, stops at 255)
    static final short LOG_E_FLAGS          = (short) 10;  // bit 0: the third refusal of a run, or one after it, was in this tap; bit 1: a payment in it waited (6a); bit 2: unused since 1.15; bit 3: a payment in it was signed with no PIN
    static final byte  LOG_FLAG_TAMPER      = (byte) 0x01;
    static final byte  LOG_FLAG_WAITED      = (byte) 0x02; // a payment in this tap was over the limit on one payment, and was waited for
    static final byte  LOG_FLAG_CLOCK       = (byte) 0x04; // set by software before 1.15, when a signed clock was moved on twice in one tap; never set since (the clock is block headers)
    static final byte  LOG_FLAG_NOPIN       = (byte) 0x08; // 1.16: a payment in this tap was signed with no PIN, on a card that has one, under its no-PIN allowance
    static final short LOG_E_LOADS          = (short) 11;  // pieces put on in it (1, stops at 255)
    static final short LOG_E_LOADED         = (short) 12;  // sats put on in it (4)
    static final short LOG_E_TOLD           = (short) 16;  // the time the terminal told at the tap (TELL_TIME, 4; zeros if it told none): a note, trusted for nothing
    static final short LOG_LEN              = (short) 181; // LOG_HEAD_LEN + LOG_ENTRIES * LOG_ENTRY_LEN

    /* ---- receipts -----------------------------------------------------------
     * For each payment the card signs, kept after the pieces are burned: the
     * clock (4), what the pieces were worth (4), SHA-256 of the message it
     * signed (32), and the first output's blinded message as it was given
     * (33; zeros for a payment with no outputs). The last RECEIPTS of them,
     * in a ring, after a count of every payment ever (4).
     *
     * The log says what left the card and when. A receipt says where it went,
     * as far as a card can: under SIG_ALL the message names every output of
     * the one swap the mint took the signature for, and an output is made
     * from its receiver's seed. Nobody can tell whose it is by looking; but
     * anyone who is later shown a wallet's seed can make that wallet's
     * outputs again and find this one among them, and the hash then pins the
     * whole swap, piece for piece and output for output. It is what a holder
     * has to show for a payment they did not mean to make. Read with the
     * owner's grant and nothing less: a terminal that has the PIN cannot read
     * it, and nothing clears it but RESET_CARD (1.17). */
    static final short RECEIPTS             = (short) 16;
    static final short RECEIPT_LEN          = (short) 77;
    static final short RECEIPTS_HEAD        = (short) 4;
    static final short RECEIPTS_LEN         = (short) 1236; // RECEIPTS_HEAD + RECEIPTS * RECEIPT_LEN
    // GET_LOG's answer: the four counts, then the taps the ring holds, newest first
    static final short LOG_ANSWER_HEAD      = (short) 16;
    // a run of this many refusals inside one tap's ten seconds is a terminal trying the limit, and is marked
    static final short TAMPER_RUN           = (short) 3;

    // The owner: a P-256 public key the card is given, a nonce of 16 it gives
    // for each proof, and a proof that is an ECDSA signature in DER form, 72
    // bytes at the most.
    static final short OWNER_NONCE_LEN     = (short) 16;
    static final short SIG_DER_MAX         = (short) 72;

    // -------------------------------------------------------------------------
    // Status words
    // -------------------------------------------------------------------------
    static final short SW_WRONG_PIN_REMAINING_2 = (short) 0x63C2;
    static final short SW_WRONG_PIN_REMAINING_1 = (short) 0x63C1;
    static final short SW_WRONG_PIN_REMAINING_0 = (short) 0x63C0;
    static final short SW_PIN_BLOCKED           = (short) 0x6983;
    static final short SW_PIN_NOT_SET           = (short) 0x6984;
    static final short SW_ALREADY_SPENT         = (short) 0x6985;
    static final short SW_SLOT_EMPTY            = (short) 0x6A88;
    static final short SW_NO_SPACE              = (short) 0x6A84;
    static final short SW_SLOT_OUT_OF_RANGE     = (short) 0x6A83;
    static final short SW_CRYPTO_ERROR          = (short) 0x6F00;
    static final short SW_CARD_LOCKED           = (short) 0x6985;
    // The fork's own, in a part of 6Axx ISO 7816-4 leaves unassigned
    static final short SW_NO_CARD_RECORD        = (short) 0x6A8C; // LOAD_PROOF before SET_CARD
    static final short SW_CARD_IN_USE           = (short) 0x6A8D; // SET_CARD with pieces unspent
    static final short SW_NO_REFUND_KEY         = (short) 0x6A8E; // a dated piece on a card with no refund key
    static final short SW_OVER_LIMIT            = (short) 0x6A8F; // the piece would take today past the daily limit
    static final short SW_NO_OWNER              = (short) 0x6A90; // a command that needs the owner, or a load, on a card with none
    static final short SW_OWNER_PROOF           = (short) 0x6A91; // no nonce given, or the proof is not the owner's, or the form is not open to an owned card
    // 0x6A92 was "never told the time": since 1.15 a card spends its first day on trust, and nothing answers it.
    static final short SW_LITTLE_WORK           = (short) 0x6A93; // SET_HEADER whose work is not enough: not its own difficulty's, under the floor, or under a quarter of the best seen
    static final short SW_PIECE_ON_CARD         = (short) 0x6A94; // LOAD_PROOF of a piece whose nonce is already in a slot, spent or not
    static final short SW_PIN_NEEDED            = (short) 0x6A94; // SPEND_ALL_SIGN, a PIN set and not given, and the no-PIN allowance not enough: the PIN, for the whole payment (1.16; a different command from the load that answers the same word)
    // 6A95 was "over the limit on one tap", when that was refused; it is now waited for (6a) and the word is unused
    static final short SW_TOO_MANY              = (short) 0x6A96; // more pieces than one signature can burn at once

    // LOCK_CARD confirmation byte
    static final byte LOCK_CONFIRM_BYTE = (byte) 0xDE;
    // RESET_CARD confirmation byte
    static final byte RESET_CONFIRM_BYTE = (byte) 0xAD;

    // PIN constraints
    static final short PIN_MIN_LEN  = (short) 4;
    static final short PIN_MAX_LEN  = (short) 8;
    static final byte  PIN_MAX_TRIES = (byte) 3;

    // -------------------------------------------------------------------------
    // secp256k1 curve parameters (JavaCard byte arrays)
    // Used by setSecp256k1Params() — hardware-compatible code.
    // -------------------------------------------------------------------------

    /** secp256k1 field prime p */
    private static final byte[] SECP256K1_P = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
    };

    /** secp256k1 a = 0 */
    private static final byte[] SECP256K1_A = new byte[32];

    /** secp256k1 b = 7 */
    private static final byte[] SECP256K1_B = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7
    };

    /** secp256k1 uncompressed generator G = 04 || Gx || Gy (65 bytes) */
    private static final byte[] SECP256K1_G = {
        (byte)0x04,
        // Gx
        (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E,(byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
        (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95,(byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
        (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB,(byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
        (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B,(byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
        // Gy
        (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77,(byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
        (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC,(byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
        (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48,(byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
        (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F,(byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8
    };

    /** secp256k1 group order n */
    private static final byte[] SECP256K1_N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
    };

    // -------------------------------------------------------------------------
    // NIST P-256 (secp256r1) parameters, for the owner key.
    // They have nothing to do with the card's own secp256k1 key. Set on each
    // key object explicitly; no default curve is relied on.
    // -------------------------------------------------------------------------

    /** P-256 field prime p */
    /** NUT-00's domain for hashing a secret to the curve: "Secp256k1_HashToCurve_Cashu_". */
    private static final byte[] H2C_DOMAIN = {
        'S','e','c','p','2','5','6','k','1','_','H','a','s','h','T','o','C','u','r','v','e','_','C','a','s','h','u','_'
    };
    /*
     * The field's arithmetic for a change output (1.12) is the chip's RSA: a
     * private key whose modulus is p*p (512 bits, as the chip wants a
     * modulus) and whose exponent is whatever power is wanted, the answer
     * taken mod p after. The cube (x^3, for x^3 + 7), Euler's test (v^((p-1)/2):
     * 1 for a square) and the root (v^((p+1)/4), which for a square is the
     * root; the exponent used is (p+1)/4 + (p-1)/2, odd as an RSA exponent
     * should be, and v^((p-1)/2) is 1 for a square, so the same root).
     */
    private static final byte[] RSA_PP = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFD,(byte)0xFF,(byte)0xFF,(byte)0xF8,(byte)0x5E,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x07,(byte)0xA2,(byte)0x00,(byte)0x0E,(byte)0x90,(byte)0xA1
    };
    private static final byte[] RSA_D_CUBE  = { (byte) 0x03 };
    private static final byte[] RSA_D_ROOT = {
        (byte)0xBF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x3F,(byte)0xFF,(byte)0xFD,(byte)0x23
    };
    private static final byte[] RSA_D_EULER = {
        (byte)0x7F,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x7F,(byte)0xFF,(byte)0xFE,(byte)0x17
    };

    private static final byte[] P256_P = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF
    };

    /** P-256 a = p - 3 */
    private static final byte[] P256_A = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFC
    };

    /** P-256 b */
    private static final byte[] P256_B = {
        (byte)0x5A,(byte)0xC6,(byte)0x35,(byte)0xD8,(byte)0xAA,(byte)0x3A,(byte)0x93,(byte)0xE7,
        (byte)0xB3,(byte)0xEB,(byte)0xBD,(byte)0x55,(byte)0x76,(byte)0x98,(byte)0x86,(byte)0xBC,
        (byte)0x65,(byte)0x1D,(byte)0x06,(byte)0xB0,(byte)0xCC,(byte)0x53,(byte)0xB0,(byte)0xF6,
        (byte)0x3B,(byte)0xCE,(byte)0x3C,(byte)0x3E,(byte)0x27,(byte)0xD2,(byte)0x60,(byte)0x4B
    };

    /** P-256 uncompressed generator G = 04 || Gx || Gy (65 bytes) */
    private static final byte[] P256_G = {
        (byte)0x04,
        (byte)0x6B,(byte)0x17,(byte)0xD1,(byte)0xF2,(byte)0xE1,(byte)0x2C,(byte)0x42,(byte)0x47,
        (byte)0xF8,(byte)0xBC,(byte)0xE6,(byte)0xE5,(byte)0x63,(byte)0xA4,(byte)0x40,(byte)0xF2,
        (byte)0x77,(byte)0x03,(byte)0x7D,(byte)0x81,(byte)0x2D,(byte)0xEB,(byte)0x33,(byte)0xA0,
        (byte)0xF4,(byte)0xA1,(byte)0x39,(byte)0x45,(byte)0xD8,(byte)0x98,(byte)0xC2,(byte)0x96,
        (byte)0x4F,(byte)0xE3,(byte)0x42,(byte)0xE2,(byte)0xFE,(byte)0x1A,(byte)0x7F,(byte)0x9B,
        (byte)0x8E,(byte)0xE7,(byte)0xEB,(byte)0x4A,(byte)0x7C,(byte)0x0F,(byte)0x9E,(byte)0x16,
        (byte)0x2B,(byte)0xCE,(byte)0x33,(byte)0x57,(byte)0x6B,(byte)0x31,(byte)0x5E,(byte)0xCE,
        (byte)0xCB,(byte)0xB6,(byte)0x40,(byte)0x68,(byte)0x37,(byte)0xBF,(byte)0x51,(byte)0xF5
    };

    /** P-256 group order n */
    private static final byte[] P256_N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xBC,(byte)0xE6,(byte)0xFA,(byte)0xAD,(byte)0xA7,(byte)0x17,(byte)0x9E,(byte)0x84,
        (byte)0xF3,(byte)0xB9,(byte)0xCA,(byte)0xC2,(byte)0xFC,(byte)0x63,(byte)0x25,(byte)0x51
    };

    // -------------------------------------------------------------------------
    // A piece's NUT-10 secret, as text. The card signs SHA-256 of exactly this
    // (NUT-11), so it is the wire format between the card and whoever made the
    // piece: no spaces, this key order, lowercase hex, the date in decimal.
    //
    //   ["P2PK",{"nonce":"<64 hex>","data":"<66 hex card key>","tags":[]}]
    //
    // and with a date:
    //
    //   ...,"tags":[["locktime","<date>"],["refund","<66 hex>"]]}]
    //
    // It is the text cashu-ts writes for a piece locked to one key, and for
    // one with a locktime and one refund key (OutputData.createP2PKData), to
    // the character: the wallet that loads a card makes its pieces with that
    // library, so the card builds what the library builds and nothing has to
    // be made specially for it. Foxy's tests hold the two together. It is not
    // upstream's text, which carried a sigflag tag the library does not write.
    // -------------------------------------------------------------------------
    private static final byte[] SECRET_1 = {   // ["P2PK",{"nonce":"
        '[','"','P','2','P','K','"',',','{','"','n','o','n','c','e','"',':','"' };
    private static final byte[] SECRET_2 = {   // ","data":"
        '"',',','"','d','a','t','a','"',':','"' };
    private static final byte[] SECRET_3 = {   // ","tags":[
        '"',',','"','t','a','g','s','"',':','[' };
    private static final byte[] SECRET_DATE = {   // ["locktime","
        '[','"','l','o','c','k','t','i','m','e','"',',','"' };
    private static final byte[] SECRET_REFUND = { // "],["refund","
        '"',']',',','[','"','r','e','f','u','n','d','"',',','"' };
    // Every piece's last tag: ["sigflag","SIG_ALL"]. After the refund key where
    // the piece has a date, and alone where it has none.
    private static final byte[] SECRET_END_DATED = {   // "],["sigflag","SIG_ALL"]]}]
        '"',']',',','[','"','s','i','g','f','l','a','g','"',',','"','S','I','G','_','A','L','L','"',']',']','}',']' };
    private static final byte[] SECRET_END = {         // ["sigflag","SIG_ALL"]]}]
        '[','"','s','i','g','f','l','a','g','"',',','"','S','I','G','_','A','L','L','"',']',']','}',']' };
    private static final byte[] HEX = {
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
    /** AUTH's tag: the message signed is SHA-256(SHA-256(tag) || SHA-256(tag) || ...). */
    private static final byte[] AUTH_TAG = {
        'C','a','s','h','u','C','a','r','d','/','a','u','t','h' };

    // The owner's proofs: an ECDSA signature (P-256, SHA-256, DER) by the owner
    // key over label || nonce || value. One label for each command, so a proof
    // made for one is of no use to another, and the value being set is inside
    // what is signed, so a proof made for one value is of no use for another.
    private static final byte[] LABEL_CHANGE_PIN = {   // CashuCard/change-pin
        'C','a','s','h','u','C','a','r','d','/','c','h','a','n','g','e','-','p','i','n' };
    private static final byte[] LABEL_SET_LIMIT = {   // CashuCard/set-limit
        'C','a','s','h','u','C','a','r','d','/','s','e','t','-','l','i','m','i','t' };
    private static final byte[] LABEL_SET_OWNER = {   // CashuCard/set-owner
        'C','a','s','h','u','C','a','r','d','/','s','e','t','-','o','w','n','e','r' };
    private static final byte[] LABEL_SET_CARD = {   // CashuCard/set-card
        'C','a','s','h','u','C','a','r','d','/','s','e','t','-','c','a','r','d' };
    private static final byte[] LABEL_LOAD = {   // CashuCard/load
        'C','a','s','h','u','C','a','r','d','/','l','o','a','d' };
    private static final byte[] LABEL_LOCK = {   // CashuCard/lock
        'C','a','s','h','u','C','a','r','d','/','l','o','c','k' };
    private static final byte[] LABEL_RESET = {   // CashuCard/reset
        'C','a','s','h','u','C','a','r','d','/','r','e','s','e','t' };
    private static final byte[] LABEL_REFRESH = {   // CashuCard/refresh
        'C','a','s','h','u','C','a','r','d','/','r','e','f','r','e','s','h' };
    private static final byte[] LABEL_TAG = {   // CashuCard/tag
        'C','a','s','h','u','C','a','r','d','/','t','a','g' };
    /* The least work a block header must show to be taken, as a header carries
     * its difficulty (`bits`, little-endian): 0x17087BC0, four times the
     * target of the network's blocks when this version was made (0x17021EF0),
     * so a quarter of their work: a difficulty of about 3.3e13, 2^77 hashes a
     * block. Only the first header a card ever takes is held to this alone;
     * from then on it is held to a quarter of the hardest it has taken
     * (SET_HEADER), which climbs with the network, so this is the same bound
     * for a new card as the ratchet is for a used one. Set in each version to a
     * quarter of its own time's, so that a card set up years from now starts
     * from its own era; the network's difficulty has never fallen by three
     * quarters, and a fall that deep would stall every card's ratchet alike.
     * 2.0 (D24): recomputed from the newest header in spec/vectors/headers.json
     * (height 971,100, bits 0x17021EF0): four times its target is 0x17087BC0,
     * the same as 1.15's, and FloorBitsTest holds the two together. */
    private static final byte[] FLOOR_BITS = { (byte) 0xC0, (byte) 0x7B, (byte) 0x08, (byte) 0x17 };

    /** 86 400 seconds, big-endian: how long a day is. */
    private static final byte[] DAY_SECONDS = { (byte) 0x00, (byte) 0x01, (byte) 0x51, (byte) 0x80 };

    private static final byte[] ONE = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01 };
    private static final byte[] ZERO = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };

    /** What one limit's worth past the first costs a payment: this many signatures of work, about three seconds on the chip. */
    // The wait (6a), in signatures of the card's own work (about 0.6 s each on the chip, 0.7 over NFC):
    // for the first limit's worth over the limit, and for every further limit's worth. Each change output
    // made (about 0.4 s) counts as one of them done. Within the limit there is no wait.
    static final short WAIT_OVER_SIGNS   = (short) 10;
    static final short WAIT_MORE_SIGNS   = (short) 4;
    /** The most limits' worth a payment is counted as: past this it waits as 255 do (about twelve minutes). */
    static final short WAIT_UNITS_MOST = (short) 255;
    /** What 255 limits' worth waits: the most any payment does. */
    static final short WAIT_SIGNS_MOST = (short)(WAIT_OVER_SIGNS + WAIT_MORE_SIGNS * (WAIT_UNITS_MOST - 2));
    /** 10 seconds, big-endian: how close together refusals are one run of them, in the card's own log (6b). */
    private static final byte[] TAP_SECONDS = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x0A };

    // -------------------------------------------------------------------------
    // Persistent state (EEPROM)
    // -------------------------------------------------------------------------

    /** Proof storage: MAX_PROOFS * PROOF_SIZE bytes */
    private byte[] proofStorage;
    /**
     * For each place, its nonce and its C as lowercase hex text, HEX_LEN bytes:
     * the two parts of a piece's secret and of a payment's message that differ
     * from piece to piece. Written when the piece is loaded, before its status
     * byte, and read only for a place that is UNSPENT.
     *
     * It is here for time and nothing else. A payment's message is every
     * piece's secret and C as text, and the card used to make that text for
     * each piece as it was named: a hundred and thirty bytes turned to hex a
     * byte at a time, in bytecode, most of a tenth of a second a piece on the
     * chip, while the card was being held to a till. Now that is done once,
     * when the piece goes on, and a payment hashes what is already written.
     */
    private byte[] slotHex;

    /**
     * The mint's proof for each place (1.20): MAX_PROOFS records of DLEQ_LEN, e ‖ s ‖ r, the record of place k at k * DLEQ_LEN, and
     * a record of zeros for a place with no proof. The card never checks a proof and never uses one: it is kept for the phone that
     * reads the card, which checks it (GET_DLEQ).
     *
     * NOT allocated in the constructor, and null from install until the first SET_CARD, which reserves it (once, outside any
     * transaction; if the card refuses the room it stays null and the card works as a card with no room for proofs). The chip
     * refuses to install an applet whose constructor asks for this much more (+300 bytes installs, +12,288 does not:
     * docs/FOXY-CARD-HARDWARE.md), and no simulator has that limit, so a test pins it. EVERY use of it is safe while it is null.
     *
     * The rule that keeps it honest: a place that is UNSPENT holds in it its own proof or zeros, never another piece's. LOAD_PROOF
     * writes the record before the place's data and long before its status byte, the commit (`loadOne`), and nothing else writes
     * it but RESET_CARD, which zeros it. CLEAR_SPENT and the payment commands do not touch it.
     */
    private byte[] dleq;

    /** Card locked flag — once set to 1, write operations are disabled */
    private byte[] cardLocked;   // 1-byte array (persistent)

    /** PIN state: 0=unset, 1=set, 2=locked */
    private byte[] pinState;     // 1-byte array (persistent)

    /** The provisioning PIN (up to PIN_MAX_LEN bytes) */
    private OwnerPIN pin;

    /** The card record (CARD_RECORD_LEN bytes) */
    private byte[] cardRecord;

    /** SHA-256 of AUTH_TAG, worked out once at install */
    private byte[] authTagHash;

    /**
     * The owner's public key (P-256), and whether one has been given
     * (persistent). It is never read out: GET_INFO says only whether there is one.
     */
    private ECPublicKey ownerKey;
    private byte[] ownerSet;

    /**
     * Whether the owner has switched the card's NFC tag off (persistent): 0 is on, which a new card, a card with no
     * owner and a card just reset all have, and 1 is off. Written only by SET_TAG and RESET_CARD; read by GET_INFO
     * (P1 = 2) and by the tag applet, which asks at each selection (`tagIsOn`).
     */
    private byte[] tagOff;

    /**
     * That the card has signed for a payment since it was last tapped
     * (persistent, so it outlives the card leaving the field): the tap after
     * a payment is let put pieces on with no PIN, for the change. A till
     * writes change in a second tap, the card having been let go while the
     * mint was asked, and the holder should not have to type the PIN twice
     * for one payment. Set by SPEND_PROOF, taken by the next SELECT (into
     * changeGrant, for that tap only) and cleared then, whatever that tap
     * does with it. It opens one thing: putting pieces on (LOAD_PROOF, and
     * CLEAR_SPENT to make room), and only to the next reader, which is the
     * one that had the PIN a moment before. See the spec's 8.2.
     */
    private byte[] changeDue;

    /** The one ECDSA verifier (SHA-256, DER signatures), for the owner's proofs. */
    private Signature ecdsa;

    // -------------------------------------------------------------------------
    // Card keypair (persistent, generated once on install)
    // -------------------------------------------------------------------------

    private KeyPair     cardKeyPair;
    private ECPrivateKey cardPrivKey;
    private ECPublicKey  cardPubKey;

    // -------------------------------------------------------------------------
    // Schnorr engine (ENG-182)
    //
    // SchnorrHW is the only signer. It uses JavaCard-native crypto
    // (ALG_EC_SVDP_DH_PLAIN_XY + byte-array modular arithmetic) and therefore
    // requires JavaCard 3.0.5 or later — that constant does not exist in 3.0.4.
    //
    // A BigInteger-based simulation used to live here behind a HARDWARE flag.
    // It could never be converted to a .cap (the JavaCard runtime has no
    // java.math, java.security, java.util or long), so it has been removed.
    // -------------------------------------------------------------------------
    private SchnorrHW schnorrHW;

    // -------------------------------------------------------------------------
    // Transient state (RAM, cleared on deselect)
    // -------------------------------------------------------------------------

    /**
     * Set to 0x01 after a successful VERIFY_PIN. Cleared on deselect, and by
     * any failed PIN check (see failPinCheck).
     */
    private byte[] pinVerifiedFlag;

    /**
     * The nonce the card last gave (GET_NONCE), and whether it can still be
     * used. One try for each nonce, right or wrong; gone with the tap.
     */
    private byte[] ownerNonce;
    private byte[] nonceLive;

    /**
     * Whether the owner has allowed loading in this tap (ALLOW_LOAD): LOAD_PROOF
     * and CLEAR_SPENT then need no verified PIN. Gone with the tap. Nothing else
     * reads it: SPEND_PROOF never does.
     */
    private byte[] loadGrant;

    /**
     * Whether this tap is the one after a payment (changeDue, taken at
     * SELECT): LOAD_PROOF and CLEAR_SPENT then need no verified PIN, as under
     * loadGrant. Gone with the tap. SPEND_PROOF never reads it.
     */
    private byte[] changeGrant;

    // Scratch for building a secret's hash and AUTH's (D10: allocated once).
    //   0..65   hex text of the value being hashed
    //   66..97  the 32-byte message
    //   98..107 a date's decimal digits
    //   108..111 a copy of a date, divided away; the end of a window, added up
    //   112..115 what the day would have signed for, with this piece
    //   116..119 what the tap would have signed for, with this piece
    //   128..131 what the day's no-PIN allowance would have been signed for, with this payment (SPEND_ALL_SIGN)
    private static final short X_HEX   = (short) 0;
    private static final short X_MSG   = (short) 66;
    private static final short X_DEC   = (short) 98;
    private static final short X_NUM   = (short) 108;
    private static final short X_SUM   = (short) 112;
    private static final short X_TAP   = (short) 116;
    // an output's text for the hash, in one piece: its amount in decimal, right-aligned in ten bytes, then its B_ in hex (66)
    private static final short X_OUT   = (short) 120;
    // in the room SPEND_ALL_SIGN leaves free after the eight states of the openings (X_OUT .. X_OUT + 7)
    private static final short X_NOPIN = (short) 128;
    private static final short X_LEN   = (short) 196;
    private byte[] scratch;
    /** The log (LOG_*). Permanent. */
    private byte[] cardLog;
    private byte[] cardReceipts;
    /** The first output of the payment in hand, for its receipt (RAM). */
    private byte[] allOut;
    /**
     * The time the terminal told in this time in the field (TELL_TIME; RAM,
     * gone with the power): four bytes, big-endian seconds, zeros until told.
     * A note for the receipts and the log, so that the owner's screen can show
     * when a payment was made to the second; the card trusts it for nothing,
     * and its day is counted by block headers alone (SET_HEADER).
     */
    private byte[] tapTime;
    /**
     * This time in the field (gone with the power, not with a SELECT): [0]
     * whether it has an entry in the log yet; [1] whether a payment has been
     * signed in it, so that a second one is slowed (6a: one payment a tap at
     * full speed, unless the owner's grant is in this tap).
     */
    private byte[] tapOpen;
    private MessageDigest sha;
    /** The hash of the message a payment's one signature is over, kept from SPEND_ALL_BEGIN to SPEND_ALL_SIGN. */
    private MessageDigest shaAll;
    /** The places being paid with, in the order they were named. Gone with a SELECT. */
    private byte[] allSlots;
    /** [0] whether a payment is begun and not yet signed for; [1] how many places it names. Gone with a SELECT. */
    private byte[] allState;
    /** What those pieces are worth together. Gone with a SELECT. */
    private byte[] allSum;
    /** What the change the payment in hand makes for itself comes to (RAM), and what leaves the card for good: the pieces less it. */
    private byte[] allChange;
    private byte[] allNet;
    /** The openings of the change the card has made for itself (CHANGE_MOST of OPEN_LEN), and their states. Permanent. */
    private byte[] changeOpen;
    private byte[] openState;
    /** The chip's RSA, for the field's arithmetic (see RSA_PP). */
    private Cipher rsa;
    private RSAPrivateKey rsaCube, rsaRoot, rsaEuler;
    /**
     * The last signature given (64), and whether there has been one (1).
     * Permanent, and written in the transaction that burns the pieces it is
     * for: a card taken away as its answer was on the air has burned them, and
     * the terminal that asked has nothing. It asks again (SPEND_ALL_AGAIN).
     */
    private byte[] lastSig;
    /**
     * The places of the payment last committed: how many (1), then a byte
     * each. Written before the payment's transaction, and read only while
     * `burnPending` is set. See `finishBurn`.
     */
    private byte[] burnList;
    /** 1 from the moment a payment is committed until every place in `burnList` has been marked spent. */
    private byte[] burnPending;
    /** The key a PIN is sealed to: the card's own, made on the card, for that and nothing else. Never the key it signs payments with. */
    private KeyPair      pinKeyPair;
    private ECPrivateKey pinPrivKey;
    private ECPublicKey  pinPubKey;
    /** The card key's signature over the PIN key: [0] is 1 once it has been made, then its 64 bytes. Made once, at the first asking. */
    private byte[] pinKeySig;
    /** Working room for a sealed command (RAM): `scratch`, by another name. */
    private byte[] seal;
    private RandomData rng;

    // -------------------------------------------------------------------------
    // Install / init
    // -------------------------------------------------------------------------

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CashuApplet().register();
    }

    /**
     * A tap begins. The one thing that crosses from the last tap into this
     * one is that the card paid since it was last loaded: this tap may then
     * put pieces on with no PIN (changeGrant, transient, for this tap). The
     * note (changeDue, persistent) is NOT cleared here — only a load that
     * uses the grant clears it (processLoadProof). So a tap that reads the
     * card and does not write, a tap cut short, and a fresh session the phone
     * opens for the write itself all leave the note standing, and the change
     * still goes on with no PIN at the tap that writes it. The window closes
     * the moment the change lands, and a later stranger's tap gets nothing.
     */
    public boolean select() {
        changeGrant[0] = changeDue[0];
        return true;
    }

    private CashuApplet() {
        proofStorage    = new byte[(short)(MAX_PROOFS * PROOF_SIZE)];
        slotHex         = new byte[(short)(MAX_PROOFS * HEX_LEN)];
        cardLocked      = new byte[1];
        pinState        = new byte[1];
        pin             = new OwnerPIN(PIN_MAX_TRIES, (byte) PIN_MAX_LEN);
        cardRecord      = new byte[CARD_RECORD_LEN];
        authTagHash     = new byte[32];
        ownerSet        = new byte[1];
        tagOff          = new byte[1];
        changeDue       = new byte[1];
        ownerKey        = newP256Key();
        ecdsa           = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        pinVerifiedFlag = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        ownerNonce      = JCSystem.makeTransientByteArray(OWNER_NONCE_LEN, JCSystem.CLEAR_ON_DESELECT);
        nonceLive       = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        loadGrant       = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        changeGrant     = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        scratch         = JCSystem.makeTransientByteArray(X_LEN, JCSystem.CLEAR_ON_DESELECT);
        cardLog         = new byte[LOG_LEN];
        cardReceipts    = new byte[RECEIPTS_LEN];
        allOut          = JCSystem.makeTransientByteArray((short) 33, JCSystem.CLEAR_ON_DESELECT);
        tapTime         = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_RESET);
        tapOpen         = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_RESET);
        sha             = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        shaAll          = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        allSlots        = JCSystem.makeTransientByteArray(ALL_MOST, JCSystem.CLEAR_ON_DESELECT);
        // [0] a payment is begun, [1] its places, [2..3] the signatures of work still to be done before it is signed (-1: not
        // yet worked out), [4] it waited, [5] its first output is kept (`allOut`), [6] the change outputs it made for itself,
        // [7] its sum wrapped
        allState        = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
        allSum          = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
        allChange       = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
        allNet          = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
        changeOpen      = new byte[(short)(CHANGE_MOST * OPEN_LEN)];
        openState       = new byte[CHANGE_MOST];
        rsa             = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        rsaCube         = fieldKey(RSA_D_CUBE);
        rsaRoot         = fieldKey(RSA_D_ROOT);
        rsaEuler        = fieldKey(RSA_D_EULER);
        lastSig         = new byte[(short) 65];
        burnList        = new byte[(short)(MAX_PROOFS + 1)];
        burnPending     = new byte[1];
        pinKeySig       = new byte[(short) 65];
        /* A sealed command's working room is the scratch the applet already
         * has, by another name: its first S_LEN bytes, which nothing else is
         * using while a PIN command runs. Not an array of its own. With one,
         * the applet asked for 1,030 bytes of memory that is cleared when
         * another applet is chosen, where it had asked for 931, and the chip
         * refused to install it (6F00). No simulator has a limit there. */
        seal            = scratch;
        rng             = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sha.reset();
        sha.doFinal(AUTH_TAG, (short) 0, (short) AUTH_TAG.length, authTagHash, (short) 0);
        initCardKeypair();
        initPinKey();

        schnorrHW = new SchnorrHW(SECP256K1_G, SECP256K1_P,
                                  SECP256K1_A, SECP256K1_B, SECP256K1_N);
        schnorrHW.init();
    }

    /**
     * Initialises the secp256k1 card keypair.
     *
     * Sets standard secp256k1 curve parameters on the key objects before
     * generating a random key pair.
     *
     * Hardware notes:
     * - JCOP4 SmartMX3 (JavaCard 3.0.5): supports custom EC-FP curves
     * - jCardSim 3.x: supported, but its generator is seeded with
     *   SecureRandomNullProvider, so every simulator produces the SAME keypair
     * - JavaCard 3.0.4 chips are NOT supported by this applet at all — see the
     *   SchnorrHW note above
     */
    private void initCardKeypair() {
        cardKeyPair  = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        cardPrivKey  = (ECPrivateKey) cardKeyPair.getPrivate();
        cardPubKey   = (ECPublicKey)  cardKeyPair.getPublic();
        setSecp256k1Params(cardPubKey, cardPrivKey);
        cardKeyPair.genKeyPair();
    }

    /**
     * The key a PIN is sealed to: a second secp256k1 pair, made on the card
     * as the card's own key is. The key agreement that uses it is the
     * signer's own (`SchnorrHW.agree`): one on the card, and the one this
     * chip is known to have.
     */
    private void initPinKey() {
        pinKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        pinPrivKey = (ECPrivateKey) pinKeyPair.getPrivate();
        pinPubKey  = (ECPublicKey)  pinKeyPair.getPublic();
        setSecp256k1Params(pinPubKey, pinPrivKey);
        pinKeyPair.genKeyPair();
    }

    /**
     * A public key on NIST P-256, with the curve's parameters set explicitly
     * (field, a, b, generator, order, cofactor 1). For the owner key, which
     * verifies ECDSA signatures and has nothing to do with the card's own
     * secp256k1 key. Its point (W) is set when one is given.
     */
    private static ECPublicKey newP256Key() {
        ECPublicKey key = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        key.setFieldFP(P256_P, (short) 0, (short) 32);
        key.setA(P256_A, (short) 0, (short) 32);
        key.setB(P256_B, (short) 0, (short) 32);
        key.setG(P256_G, (short) 0, (short) 65);
        key.setR(P256_N, (short) 0, (short) 32);
        key.setK((short) 1);
        return key;
    }

    /**
     * Sets secp256k1 curve parameters on a JavaCard EC key pair.
     *
     * This method uses only the standard JavaCard ECKey API and is
     * hardware-compatible (JCOP4 and any JavaCard 3.0.5+ part with custom EC-FP
     * curve support; jCardSim). Feitian's JavaCard 3.0.4 parts are not in that
     * set — see the note on initCardKeypair above.
     *
     * @param pub  EC public key to configure
     * @param priv EC private key to configure
     */
    private void setSecp256k1Params(ECPublicKey pub, ECPrivateKey priv) {
        pub.setFieldFP(SECP256K1_P, (short) 0, (short) 32);
        pub.setA(SECP256K1_A, (short) 0, (short) 32);
        pub.setB(SECP256K1_B, (short) 0, (short) 32);
        pub.setG(SECP256K1_G, (short) 0, (short) 65);
        pub.setR(SECP256K1_N, (short) 0, (short) 32);
        pub.setK((short) 1);

        priv.setFieldFP(SECP256K1_P, (short) 0, (short) 32);
        priv.setA(SECP256K1_A, (short) 0, (short) 32);
        priv.setB(SECP256K1_B, (short) 0, (short) 32);
        priv.setG(SECP256K1_G, (short) 0, (short) 65);
        priv.setR(SECP256K1_N, (short) 0, (short) 32);
        priv.setK((short) 1);
    }

    // -------------------------------------------------------------------------
    // APDU dispatch
    // -------------------------------------------------------------------------

    @Override
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        /* A payment that was committed as the card left the field, with its
         * pieces not all marked spent yet: they are marked now, before
         * anything looks at a place (`finishBurn`). */
        if (burnPending[0] != (byte) 0) finishBurn();

        if (selectingApplet()) {
            buf[0] = VERSION_MAJOR;
            buf[1] = VERSION_MINOR;
            apdu.setOutgoingAndSend((short) 0, (short) 2);
            return;
        }

        if (buf[ISO7816.OFFSET_CLA] != (byte) 0xB0) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        /* A payment begun (SPEND_ALL_BEGIN) is given up by anything that is not
         * its next step: nothing may come between the pieces being named and
         * their being burned and signed for, that could change either. */
        if (buf[ISO7816.OFFSET_INS] != INS_SPEND_ALL_OUTPUTS && buf[ISO7816.OFFSET_INS] != INS_SPEND_ALL_CHANGE
            && buf[ISO7816.OFFSET_INS] != INS_SPEND_ALL_SIGN) {
            allState[0] = (byte) 0;
        }

        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_GET_INFO:         processGetInfo(apdu);        break;
            case INS_GET_PUBKEY:       processGetPubkey(apdu);      break;
            case INS_GET_BALANCE:      processGetBalance(apdu);     break;
            case INS_GET_PROOF_COUNT:  processGetProofCount(apdu);  break;
            case INS_GET_PROOF:        processGetProof(apdu);       break;
            case INS_GET_SLOT_STATUS:  processGetSlotStatus(apdu);  break;
            case INS_AUTH:             processAuth(apdu);           break;
            case INS_GET_CARD:         processGetCard(apdu);        break;
            case INS_GET_PIECES:       processGetPieces(apdu);      break;
            case INS_GET_LOG:          processGetLog(apdu);         break;
            case INS_GET_CHANGE:       processGetChange(apdu);      break;
            case INS_GET_DLEQ:         processGetDleq(apdu);        break;
            case INS_SPEND_ALL_BEGIN:   processSpendAllBegin(apdu);   break;
            case INS_SPEND_ALL_OUTPUTS: processSpendAllOutputs(apdu); break;
            case INS_SPEND_ALL_CHANGE:  processSpendAllChange(apdu);  break;
            case INS_SPEND_ALL_SIGN:    processSpendAllSign(apdu);    break;
            case INS_SPEND_ALL_AGAIN:   processSpendAllAgain(apdu);   break;
            case INS_LOAD_PROOF:       processLoadProof(apdu);      break;
            case INS_CLEAR_SPENT:      processClearSpent(apdu);     break;
            case INS_SET_CARD:         processSetCard(apdu);        break;
            case INS_SET_LIMIT:        processSetLimit(apdu);       break;
            case INS_SET_LIMIT_OWNER:  processSetLimitOwner(apdu);  break;
            case INS_SET_HEADER:       processSetHeader(apdu);      break;
            case INS_TELL_TIME:        processTellTime(apdu);       break;
            case INS_VERIFY_PIN:       processVerifyPin(apdu);      break;
            case INS_SET_PIN:          processSetPin(apdu);         break;
            case INS_CHANGE_PIN:       processChangePin(apdu);      break;
            case INS_SET_OWNER:        processSetOwner(apdu);       break;
            case INS_GET_NONCE:        processGetNonce(apdu);       break;
            case INS_ALLOW_LOAD:       processAllowLoad(apdu);      break;
            case INS_LOCK_CARD:        processLockCard(apdu);       break;
            case INS_RESET_CARD:       processResetCard(apdu);      break;
            case INS_SET_TAG:          processSetTag(apdu);         break;
            case INS_REFRESH:          processRefresh(apdu);        break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // -------------------------------------------------------------------------
    // Category 0x0x / 0x1x — Read commands
    // -------------------------------------------------------------------------

    private void processGetInfo(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        // read before the answer is written over the command
        byte p1 = buf[ISO7816.OFFSET_P1];
        short unspent = 0, spent = 0, empty = 0;
        for (short i = 0; i < MAX_PROOFS; i++) {
            byte status = proofStorage[(short)(i * PROOF_SIZE + PROOF_STATUS_OFFSET)];
            if      (status == STATUS_UNSPENT) unspent++;
            else if (status == STATUS_SPENT)   spent++;
            else                               empty++;
        }
        buf[0] = VERSION_MAJOR;
        buf[1] = VERSION_MINOR;
        buf[2] = (byte) MAX_PROOFS;
        buf[3] = (byte) unspent;
        buf[4] = (byte) spent;
        buf[5] = (byte) empty;
        // Capabilities flags:
        //   bit0 = secp256k1 native key generation (set — ENG-181 complete)
        //   bit1 = BIP-340 Schnorr signing (set — ENG-181 complete)
        //   bit2 = PIN supported (always set)
        // secp256k1 + Schnorr + PIN + the limit on one payment is waited for, not refused
        // + GET_PIECES names places whole and LOAD_PROOF takes several pieces (bit 4)
        // + more than sixty-four places: seven-bit tags, and the short listing is P2 = 3 (bit 5)
        // + a payment's pieces are burned outside its transaction, so it may be of any number (bit 6)
        // + the PIN is taken sealed (bit 7)
        buf[6] = (byte) 0xFF;
        buf[7] = pinState[0];
        // The fork's: the first eight bytes are upstream's, so a reader that
        // knows only those still reads them right.
        buf[8]  = FORMAT;
        buf[9]  = pin.getTriesRemaining();
        buf[10] = cardLocked[0];
        buf[11] = cardRecord[CARD_SET_OFFSET];
        Util.arrayCopyNonAtomic(cardRecord, CARD_LIMIT_OFFSET, buf, (short) 12, (short) 4);
        // appended: whether the card has an owner. Nothing before it moved.
        buf[16] = ownerSet[0];
        // and the day: the card's clock, when its window began, what it has signed for since
        Util.arrayCopyNonAtomic(cardRecord, CARD_NOW_OFFSET, buf, (short) 17, (short) 4);
        Util.arrayCopyNonAtomic(cardRecord, CARD_WINDOW_OFFSET, buf, (short) 21, (short) 4);
        Util.arrayCopyNonAtomic(cardRecord, CARD_SPENT_OFFSET, buf, (short) 25, (short) 4);
        // and whether this tap, being the one after a payment, may put pieces on with no PIN
        buf[29] = changeGrant[0];
        /* P1 = 1 asks for the limit on one payment and the no-PIN allowance as
         * well: the limit on one payment (30..33), the allowance (34..37) and
         * what has been signed for with no PIN in the day's window (38..41), 42
         * bytes in all.
         * Asked for, and not simply appended, so that a reader that knows the
         * thirty bytes and checks for them still gets thirty.
         *
         * P1 = 2 (1.19) is the same 42 bytes and then one more, byte 42:
         * whether the NFC tag is on (0 on, 1 off; the tag shows as much to any
         * reader). It is a form of its own and not a 43rd byte of the answer to
         * P1 = 1, because a reader that asks P1 = 1 takes the answer as the long
         * form only when it is exactly 42 bytes: P1 = 1 is the 42 bytes it always
         * was, whatever the tag's state. Any other P1 is answered as it was, with
         * the thirty bytes. */
        if (p1 == (byte) 1 || p1 == (byte) 2) {
            /* The limit on one payment is the holder's and is said to the
             * holder only: with the owner's grant given in this tap, and to
             * nobody else, not even under the PIN, which a till has. A
             * terminal that knew it would ask for just under it, again and
             * again, and never be made to wait. To anyone else these four
             * bytes are zeros, which is also what a card with no such limit
             * says: a terminal cannot tell the two apart by asking. (What it
             * can do is find out by trying, a wait at a time: see 6a.) */
            if (loadGrant[0] == (byte) 1) {
                Util.arrayCopyNonAtomic(cardRecord, CARD_TAP_LIMIT_OFFSET, buf, (short) 30, (short) 4);
            } else {
                Util.arrayFillNonAtomic(buf, (short) 30, (short) 4, (byte) 0);
            }
            /* The allowance is said to anyone: a till needs it to know whether
             * to ask for the PIN, and nothing is learned from it that trying
             * would not tell. (Not the limit on one payment above: that one
             * is waited for, and knowing it would be a way round the wait.)
             * It and what is counted against it are side by side in the record
             * (CARD_NOPIN_LIMIT_OFFSET, CARD_NOPIN_SPENT_OFFSET), as they are
             * in the answer (34..37, 38..41): one copy of eight bytes. */
            Util.arrayCopyNonAtomic(cardRecord, CARD_NOPIN_LIMIT_OFFSET, buf, (short) 34, (short) 8);
            // the byte after them is sent by P1 = 2 alone
            buf[42] = tagOff[0];
            apdu.setOutgoingAndSend((short) 0, p1 == (byte) 2 ? (short) 43 : (short) 42);
            return;
        }
        apdu.setOutgoingAndSend((short) 0, (short) 30);
    }

    private void processGetPubkey(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = toCompressed(buf, cardPubKey.getW(buf, (short) 0));
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Rewrite an EC public key to the spec's 33-byte compressed form, in place.
     *
     * ECPublicKey.getW() returns the uncompressed point (04 || X || Y, 65 bytes)
     * on real silicon but 33 bytes under jCardSim, so this branch is otherwise
     * never taken in CI — see the direct test. A part already returning 33 bytes
     * is passed through untouched. Anything else (a bare X||Y, a 65-byte blob
     * without the 0x04 marker) is refused with SW_CRYPTO_ERROR rather than
     * handed to the host: SchnorrHW.sign() takes the same stance for the same
     * getW() output, and a mint cannot parse it anyway.
     */
    static short toCompressed(byte[] buf, short len) {
        if (len == (short) 65 && buf[0] == (byte) 0x04) {
            // Prefix replaces the 0x04 marker in place; X already sits at
            // buf[1..32], so only the first byte changes. The prefix encodes the
            // parity of Y's least-significant byte.
            buf[0] = ((buf[64] & 0x01) == 0) ? (byte) 0x02 : (byte) 0x03;
            return (short) 33;
        }
        if (len == (short) 33 && (buf[0] == (byte) 0x02 || buf[0] == (byte) 0x03)) {
            return len;
        }
        ISOException.throwIt(SW_CRYPTO_ERROR);
        return (short) 0; // unreachable
    }

    private void processGetBalance(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        // Accumulate the uint32 total directly in the outgoing buffer.
        // JavaCard has no long, so the sum is done byte-wise with carry. A sum
        // past 2^32-1 wraps, and the carry out is let go: it cannot happen for
        // any realistic set of pieces, but the wrap is real behaviour, not an
        // impossibility (testGetBalanceWrapsPast2Pow32 pins it).
        buf[0] = 0; buf[1] = 0; buf[2] = 0; buf[3] = 0;
        for (short i = 0; i < MAX_PROOFS; i++) {
            short base = (short)(i * PROOF_SIZE);
            if (proofStorage[(short)(base + PROOF_STATUS_OFFSET)] == STATUS_UNSPENT) {
                addUint32Carry(buf, (short) 0, proofStorage,
                               (short)(base + PROOF_AMOUNT_OFFSET));
            }
        }
        apdu.setOutgoingAndSend((short) 0, (short) 4);
    }

    private void processGetProofCount(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short count = 0;
        for (short i = 0; i < MAX_PROOFS; i++) {
            if (proofStorage[(short)(i * PROOF_SIZE + PROOF_STATUS_OFFSET)] != STATUS_EMPTY) count++;
        }
        buf[0] = (byte) count;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private void processGetProof(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short idx = (short)(buf[ISO7816.OFFSET_P1] & 0xFF);
        if (idx >= MAX_PROOFS) ISOException.throwIt(SW_SLOT_OUT_OF_RANGE);

        short base = (short)(idx * PROOF_SIZE);
        if (proofStorage[(short)(base + PROOF_STATUS_OFFSET)] == STATUS_EMPTY) {
            ISOException.throwIt(SW_SLOT_EMPTY);
        }
        Util.arrayCopy(proofStorage, base, buf, (short) 0, PROOF_SIZE);
        apdu.setOutgoingAndSend((short) 0, PROOF_SIZE);
    }

    private void processGetSlotStatus(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        for (short i = 0; i < MAX_PROOFS; i++) {
            buf[i] = proofStorage[(short)(i * PROOF_SIZE + PROOF_STATUS_OFFSET)];
        }
        apdu.setOutgoingAndSend((short) 0, MAX_PROOFS);
    }

    /**
     * GET_PIECES: what GET_SLOT_STATUS and a GET_PROOF for each slot say, in as
     * few answers as a short APDU allows. No PIN: it says what they say.
     *
     * P1 is the first slot to report. The answer is
     *
     *   next (1)                  the first slot this answer does not cover;
     *                             128 means there is nothing more to ask for
     *   then, for each slot from P1 up to next that is not empty, in order:
     *     tag (1)                 the slot's number, and 0x80 where it is spent
     *     the piece (81)          only for an unspent slot: what GET_PROOF gives
     *                             after its status byte (keyset, amount, nonce, C, date)
     *
     * A slot in that range with no entry is empty. A spent slot is listed by its
     * tag alone: its bytes stay on the card until CLEAR_SPENT frees the place, and
     * nothing that reads the card wants them. The phone asks again with P1 = next
     * until next is 128.
     *
     * (A card of sixty-four places, 1.6 and before, has a tag of
     * (state << 6) | slot, state 1 unspent and 2 spent, and ends at 64. GET_INFO
     * says how many places a card has, and its capabilities which tags it gives.)
     *
     * An answer is at most PAGE_MAX bytes, which is under the 256 a short APDU
     * carries, so three unspent pieces (247 bytes) make a page and the card does
     * not need extended length, which is not something every reader and phone
     * will carry. At least one entry always fits, so every answer moves on.
     * The slots are sent from where they sit, with no copy of the page made, so
     * the APDU buffer's size is not something this relies on.
     */
    private void processGetPieces(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p2 = buf[ISO7816.OFFSET_P2];
        /* P2 = 2: the places named in the data, whole. A till that has chosen
         * its pieces from the short listing asks for those and no others. */
        if (p2 == (byte) 2) { processGetSome(apdu); return; }
        // P2 = 3: the short listing, for choosing
        if (p2 == (byte) 3) { processGetShort(apdu); return; }
        /* A form this card does not have is refused, and not answered with
         * another. P2 = 1 was the short listing of a card of sixty-four
         * places: its tags cannot name these, and it is not kept. */
        if (p2 != (byte) 0) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        short from = (short)(buf[ISO7816.OFFSET_P1] & 0xFF);
        if (from >= MAX_PROOFS) ISOException.throwIt(SW_SLOT_OUT_OF_RANGE);

        // what fits: slots from `from` while the next entry still leaves the answer within the page
        short length = 1;
        short next = from;
        while (next < MAX_PROOFS) {
            byte status = proofStorage[(short)(next * PROOF_SIZE + PROOF_STATUS_OFFSET)];
            short cost = (status == STATUS_UNSPENT) ? PROOF_SIZE : (status == STATUS_SPENT) ? (short) 1 : (short) 0;
            if ((short)(length + cost) > PAGE_MAX) break;
            length += cost;
            next++;
        }

        apdu.setOutgoing();
        apdu.setOutgoingLength(length);
        buf[0] = (byte) next;
        apdu.sendBytes((short) 0, (short) 1);
        for (short i = from; i < next; i++) {
            short base = (short)(i * PROOF_SIZE);
            byte status = proofStorage[(short)(base + PROOF_STATUS_OFFSET)];
            if (status != STATUS_UNSPENT && status != STATUS_SPENT) continue;
            buf[0] = (byte)(status == STATUS_SPENT ? (short)(i | (short) 0x80) : i);
            apdu.sendBytes((short) 0, (short) 1);
            if (status == STATUS_UNSPENT) {
                apdu.sendBytesLong(proofStorage, (short)(base + PROOF_KEYSET_OFFSET), PROOF_DATA_LEN);
            }
        }
    }

    /**
     * GET_PIECES with P2 = 3: the short listing. What every unspent place is
     * worth and no more, which is all that choosing pieces needs, in as few
     * bytes as say it: a card with a deep drawer holds a hundred pieces, and a
     * till reads them at every payment.
     *
     * P1 is the first place to report. The answer is
     *
     *   next (1)                  as GET_PIECES: the first place not covered, 128 at the end
     *   then, for each UNSPENT place from P1 up to next, in order:
     *     place (1)               its number, and 0x80 where its keyset and date follow
     *     keyset (8), date (4)    only with 0x80: where they are not those of the
     *                             entry before it in this answer. The first entry
     *                             of every answer has them.
     *     size (1)                the power of two the piece is worth (0 for 1, 10
     *                             for 1,024), or 0xFF where it is worth some other
     *                             amount, which then follows
     *     amount (4)              only after 0xFF
     *
     * A place with no entry is empty or spent, and this does not say which:
     * GET_INFO counts both. A card whose pieces are of one keyset and one date
     * and are powers of two, which is every card Foxy has loaded, is two bytes
     * a piece after the first: all 128 places in two answers, where the whole
     * form takes forty-three.
     */
    private void processGetShort(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short from = (short)(buf[ISO7816.OFFSET_P1] & 0xFF);
        if (from >= MAX_PROOFS) ISOException.throwIt(SW_SLOT_OUT_OF_RANGE);
        /* Gathered in the APDU buffer in one pass, and sent when it has no
         * room for another entry (an entry is at most SHORT_MOST bytes, and
         * a whole answer is at most PAGE_MAX, which the buffer holds): the
         * place the next answer starts at goes first, once it is known. A
         * send for each entry, and a pass to measure before the pass that
         * gathered, were most of what a listing took. */
        short at = (short) 1;
        short next = from;
        short prev = (short) -1;
        while (next < MAX_PROOFS) {
            short base = (short)(next * PROOF_SIZE);
            if (proofStorage[(short)(base + PROOF_STATUS_OFFSET)] == STATUS_UNSPENT) {
                boolean named = shortNamed(base, prev);
                short size = sizeOf((short)(base + PROOF_AMOUNT_OFFSET));
                short cost = (short)(2 + (named ? 12 : 0) + (size < 0 ? 4 : 0));
                if ((short)(at + cost) > PAGE_MAX) break;
                if (named) {
                    buf[at++] = (byte)(next | (short) 0x80);
                    Util.arrayCopyNonAtomic(proofStorage, (short)(base + PROOF_KEYSET_OFFSET), buf, at, (short) 8);
                    Util.arrayCopyNonAtomic(proofStorage, (short)(base + PROOF_DATE_OFFSET), buf, (short)(at + 8), (short) 4);
                    at += (short) 12;
                } else {
                    buf[at++] = (byte) next;
                }
                if (size < 0) {
                    buf[at++] = (byte) 0xFF;
                    Util.arrayCopyNonAtomic(proofStorage, (short)(base + PROOF_AMOUNT_OFFSET), buf, at, (short) 4);
                    at += (short) 4;
                } else {
                    buf[at++] = (byte) size;
                }
                prev = base;
            }
            next++;
        }
        buf[0] = (byte) next;
        apdu.setOutgoing();
        apdu.setOutgoingLength(at);
        apdu.sendBytes((short) 0, at);
    }

    /** Whether the short listing says the keyset and date of the place at `base`: it does unless they are those of `prev`, the place listed before it in the same answer (-1: none). */
    private boolean shortNamed(short base, short prev) {
        if (prev < 0) return true;
        // the chip's own compare: a keyset and a date are not secrets, and a loop in bytecode over them was most of an entry's cost
        return Util.arrayCompare(proofStorage, (short)(base + PROOF_KEYSET_OFFSET), proofStorage, (short)(prev + PROOF_KEYSET_OFFSET), (short) 8) != (byte) 0
            || Util.arrayCompare(proofStorage, (short)(base + PROOF_DATE_OFFSET), proofStorage, (short)(prev + PROOF_DATE_OFFSET), (short) 4) != (byte) 0;
    }

    /** The power of two the four bytes at `at` in the places are (0 to 31), or -1 where they are no power of two. */
    private short sizeOf(short at) {
        short found = (short) -1;
        for (short k = 0; k < 4; k++) {
            short b = (short)(proofStorage[(short)(at + k)] & 0xFF);
            if (b == 0) continue;
            if (found >= 0 || (short)(b & (short)(b - 1)) != 0) return (short) -1;
            short bit = 0;
            while (b > 1) { b = (short)(b >> 1); bit++; }
            found = (short)((short)((short)(3 - k) * 8) + bit);
        }
        return found;
    }

    /**
     * GET_PIECES with P2 = 2: one to BATCH_MOST places, a byte each, answered
     * with each one's slot as GET_PROOF gives it (status, then its 81 bytes),
     * in the order asked. An empty or spent place is answered as it is, so
     * the terminal sees for itself that it is not what the listing said.
     */
    private void processGetSome(APDU apdu) {
        short n = apdu.setIncomingAndReceive();
        if (n < 1 || n > BATCH_MOST) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte[] buf = apdu.getBuffer();
        // the places are kept aside: the answer is written over the buffer they came in
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, scratch, X_NUM, n);
        for (short i = 0; i < n; i++) {
            if ((short)(scratch[(short)(X_NUM + i)] & 0xFF) >= MAX_PROOFS) ISOException.throwIt(SW_SLOT_OUT_OF_RANGE);
        }
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)(n * PROOF_SIZE));
        for (short i = 0; i < n; i++) {
            apdu.sendBytesLong(proofStorage, (short)((short)(scratch[(short)(X_NUM + i)] & 0xFF) * PROOF_SIZE), PROOF_SIZE);
        }
    }

    // -------------------------------------------------------------------------
    // Category 0x2x — Spend commands (the PIN, or the no-PIN allowance, is asked at the signature when a PIN is set or blocked, D13 and 1.16)
    // -------------------------------------------------------------------------

    /*
     * A payment is one signature, however many pieces it is made of (NUT-11
     * SIG_ALL). The message the mint checks it against is every input's secret
     * and its C, in order, and then every output's amount and blinded message:
     *
     *   secret_0 || C_0 || ... || secret_n || C_n || amount_0 || B_0 || ... || amount_m || B_m
     *
     * as text (C and B_ in hex, an amount in decimal), hashed with SHA-256.
     *
     * The card builds the first half itself, from the places it is told to pay
     * with, and burns exactly those: a terminal that could hand it a hash to
     * sign would name one small piece to burn and get a signature good for
     * every piece on the card. The second half is the terminal's, and the card
     * cannot check it: it is where the terminal wants the money to go. It is
     * hashed as it comes, so the signature is good for those outputs and no
     * others.
     *
     * Three commands, in one tap and with nothing between them:
     *
     *   SPEND_ALL_BEGIN    the places, in the order the swap will name them
     *   SPEND_ALL_OUTPUTS  the outputs, thirty-seven bytes each; as many
     *                      commands as they need, or none
     *   SPEND_ALL_SIGN     the signature; the pieces are burned as it is given
     */

    /**
     * SPEND_ALL_BEGIN: one byte for each place to pay with, in order.
     *
     * No PIN is asked here (1.16): whether this payment may be signed for without
     * one is for SPEND_ALL_SIGN to say, when what it takes from the card is
     * known, and a payment begun is of no use to anyone until it is signed.
     * Every place named once, holding an unspent piece,
     * and all of one date (pieces with different dates have different lock
     * conditions, and a mint takes no one signature for those: `6A80`). The
     * day's limit and the wait on one payment are held to what leaves the
     * card, the pieces less the change the card makes for itself (1.12),
     * which is not known until SIGN: both are worked out there, at the first
     * SIGN, before anything is burned. Only a sum that wraps is refused here,
     * as over any day there is (`6A8F`). Answers what the pieces are worth
     * (4, big-endian).
     */
    private void processSpendAllBegin(APDU apdu) {
        // A LOCKED card still spends (lock disables writes, not the bearer's ability to pay).
        short n = apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        if (n < (short) 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (n > ALL_MOST) ISOException.throwIt(SW_TOO_MANY);
        // kept apart from the APDU buffer, which the hashing below writes over
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, allSlots, (short) 0, n);
        Util.arrayFillNonAtomic(allSum, (short) 0, (short) 4, (byte) 0);
        short first = (short)((short)(allSlots[0] & 0xFF) * PROOF_SIZE);
        short carry = 0;
        /* A place named twice is refused. Found by a bit a place: sixteen bytes
         * of working room (X_OUT, which the hashing below writes over only
         * after this loop) and one look per place, where looking back over
         * every place named before it was most of a second for a hundred. */
        Util.arrayFillNonAtomic(scratch, X_OUT, (short) 16, (byte) 0);
        for (short i = 0; i < n; i++) {
            short idx = (short)(allSlots[i] & 0xFF);
            if (idx >= MAX_PROOFS) ISOException.throwIt(SW_SLOT_OUT_OF_RANGE);
            short base = (short)(idx * PROOF_SIZE);
            byte status = proofStorage[(short)(base + PROOF_STATUS_OFFSET)];
            if (status == STATUS_EMPTY)  ISOException.throwIt(SW_SLOT_EMPTY);
            if (status == STATUS_SPENT)  ISOException.throwIt(SW_ALREADY_SPENT);
            short seen = (short)(X_OUT + (idx >> 3));
            byte bit = (byte)(1 << (idx & 7));
            if ((scratch[seen] & bit) != 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            scratch[seen] |= bit;
            if (!sameBytes(proofStorage, (short)(base + PROOF_DATE_OFFSET), proofStorage, (short)(first + PROOF_DATE_OFFSET), (short) 4)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            if (addUint32Carry(allSum, (short) 0, proofStorage, (short)(base + PROOF_AMOUNT_OFFSET)) != 0) carry = 1;
        }
        // a sum that wraps is past any limit, and past what four bytes can say: not a payment
        if (carry != 0) Util.arrayFillNonAtomic(allSum, (short) 0, (short) 4, (byte) 0xFF);
        /* And past any allowance: with a PIN set and not given it is the PIN's
         * to ask for, and no refusal is written in the log for a reader that has
         * not the PIN (the one refusal this command makes, below, is the log's). */
        if (carry != 0 && needsAllowance()) ISOException.throwIt(SW_PIN_NEEDED);
        /* The day's limit and the wait (6a) are held to what leaves the card
         * for good: the pieces less the change the card makes for itself
         * (1.12), which is not known until SIGN, where both are worked out,
         * before anything is burned. A sum that wraps is past any day there
         * is, whatever its change, and is refused here, before anything is
         * hashed. */
        if (carry != 0) requireUnderLimits(allSum, (short) 0, carry);
        Util.setShort(allState, (short) 2, (short) -1);
        allState[4] = (byte) 0;
        allState[5] = (byte) 0;
        allState[6] = (byte) 0;
        allState[7] = (byte) carry;
        Util.arrayFillNonAtomic(allChange, (short) 0, (short) 4, (byte) 0);
        // change made for a payment that was never signed for is let go
        for (short k = 0; k < CHANGE_MOST; k++) {
            if (openState[k] == OPEN_DRAFT) openState[k] = OPEN_EMPTY;
        }

        /* The message's half that is the card's to build. Every piece of a
         * payment has the same key and the same date, so everything in a
         * secret after its nonce is the same text for all of them: built once
         * here (`secretTail`, into the APDU buffer, which is free now that the
         * places are in `allSlots`), and each piece is then four spans handed
         * to the hash, two of them its own hex as it was written at loading. */
        short tail = secretTail(buf, first);
        shaAll.reset();
        for (short i = 0; i < n; i++) {
            secretInto(shaAll, (short)(allSlots[i] & 0xFF), buf, tail);
        }
        allState[1] = (byte) n;
        allState[0] = (byte) 1;
        Util.arrayCopyNonAtomic(allSum, (short) 0, buf, (short) 0, (short) 4);
        apdu.setOutgoingAndSend((short) 0, (short) 4);
    }

    /**
     * SPEND_ALL_OUTPUTS: the swap's outputs, in order, thirty-seven bytes
     * each: the amount (4, big-endian) and the blinded message (33). Hashed as
     * the mint will read them, the amount in decimal and the point in hex. As
     * many of these commands as the outputs need. `6985` with no payment begun.
     */
    private void processSpendAllOutputs(APDU apdu) {
        if (allState[0] != (byte) 1) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // the terminal's outputs come before the card's own change, as the swap will name them: none after it
        if (allState[6] != (byte) 0) dropPayment(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        short len = apdu.setIncomingAndReceive();
        if (len < ALL_OUTPUT_LEN || (short)(len % ALL_OUTPUT_LEN) != (short) 0) dropPayment(ISO7816.SW_WRONG_LENGTH);
        byte[] buf = apdu.getBuffer();
        // the first output of the payment, for its receipt
        if (allState[5] != (byte) 1) {
            Util.arrayCopyNonAtomic(buf, (short)(ISO7816.OFFSET_CDATA + 4), allOut, (short) 0, (short) 33);
            allState[5] = (byte) 1;
        }
        short end = (short)(ISO7816.OFFSET_CDATA + len);
        for (short at = ISO7816.OFFSET_CDATA; at < end; at += ALL_OUTPUT_LEN) {
            // its amount in decimal ending where its B_ in hex begins: one span to the hash
            short digits = decimalBefore(buf, at, (short)(X_OUT + 10));
            hexInto(buf, (short)(at + 4), (short) 33, (short)(X_OUT + 10));
            shaAll.update(scratch, (short)(X_OUT + 10 - digits), (short)(digits + 66));
        }
    }

    /**
     * SPEND_ALL_CHANGE: one change output the card makes for itself (1.12),
     * after the outputs the terminal names and before the signature. The
     * amount (4, big-endian). The card draws a nonce, builds the secret as
     * its inputs' are (its own key, the payment's date and refund key,
     * SIG_ALL), hashes it to the curve as the mint will (NUT-00), draws a
     * blinding factor and blinds the point (`blindChange`); the amount and
     * the blinded message go into the message as an output of the terminal's
     * would, and the opening is kept until the piece is written back.
     * Answers the blinded message, 33 bytes. A terminal names only how much:
     * nothing in the output is its to choose, so nothing it chooses can take
     * the change, and the limits are held to what leaves the card for good.
     * `6985` with no payment begun; `6A80` for nothing, or for more change
     * than the pieces come to; `6A84` with no opening free.
     */
    private void processSpendAllChange(APDU apdu) {
        if (allState[0] != (byte) 1) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        short len = apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        if (len != (short) 4) dropPayment(ISO7816.SW_WRONG_LENGTH);
        // the change, with this, may not come to more than the pieces: what leaves the card cannot be less than nothing
        Util.arrayCopyNonAtomic(allChange, (short) 0, scratch, X_TAP, (short) 4);
        if (isZero(buf, ISO7816.OFFSET_CDATA, (short) 4)
            || addUint32Carry(scratch, X_TAP, buf, ISO7816.OFFSET_CDATA) != 0
            || cmpUint32(scratch, X_TAP, allSum, (short) 0) > 0) {
            dropPayment(ISO7816.SW_WRONG_DATA);
        }
        short which = (short) -1;
        for (short k = 0; k < CHANGE_MOST; k++) {
            if (openState[k] == OPEN_EMPTY) {
                which = k;
                break;
            }
        }
        if (which < 0) dropPayment(SW_NO_SPACE);
        short open = (short)(which * OPEN_LEN);
        // the opening's amount, keyset and date: the payment's, as every piece of it has them
        short first = (short)((short)(allSlots[0] & 0xFF) * PROOF_SIZE);
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, changeOpen, (short)(open + OPEN_AMOUNT), (short) 4);
        Util.arrayCopyNonAtomic(proofStorage, (short)(first + PROOF_KEYSET_OFFSET), changeOpen, (short)(open + OPEN_KEYSET), (short) 8);
        Util.arrayCopyNonAtomic(proofStorage, (short)(first + PROOF_DATE_OFFSET), changeOpen, (short)(open + OPEN_DATE), (short) 4);
        try {
            blindChange(first, open, buf);
        } catch (CryptoException e) {
            dropPayment(SW_CRYPTO_ERROR);
        }
        // the opening is the payment's until it is signed for (SIGN) or given up (BEGIN)
        openState[which] = OPEN_DRAFT;
        Util.arrayCopyNonAtomic(scratch, X_TAP, allChange, (short) 0, (short) 4);
        allState[6] = (byte)(allState[6] + 1);
        // into the message as an output: the amount in decimal, then the blinded message in hex, as the terminal's go
        short digits = decimalBefore(changeOpen, (short)(open + OPEN_AMOUNT), (short)(X_OUT + 10));
        hexInto(buf, (short) 0, (short) 33, (short)(X_OUT + 10));
        shaAll.update(scratch, (short)(X_OUT + 10 - digits), (short)(digits + 66));
        apdu.setOutgoingAndSend((short) 0, (short) 33);
    }

    /**
     * The blinded message of a change output, made as the mint will read it.
     * The secret is `["P2PK",{"nonce":"<nonce>"` and then what every piece
     * of this payment has after its nonce (`secretTail`: the card's key, the
     * date, the refund key, SIG_ALL). It is hashed to the curve as NUT-00
     * says: x is SHA-256 of SHA-256(domain || secret) and a counter from 0,
     * little-endian; the first x under p for which x^3 + 7 has a square root
     * is the point's, with the even root for y. The cube, Euler's test and
     * the root are the chip's RSA over p*p (RSA_PP, `powModP`), each taken mod p after.
     * Then B_ = Y + r*G, by the chip, r fresh and under n. The nonce and r
     * go into the opening at `open`; B_, compressed, into buf[0..33).
     *
     * The APDU buffer is the card's for the length of it: the secret's text
     * to begin with, and after it is hashed the RSA's input (64, at 32: zeros
     * and then the value), its output (64, at 96), the point Y (65, at 160)
     * and the counter (4, at 225). Scratch holds the hashes and the working
     * room of the reduction (X_OUT).
     */
    private void blindChange(short first, short open, byte[] buf) {
        // the secret's tail, as every piece of this payment has it; the key's hex passes through X_HEX on the way
        short tail = secretTail(buf, first);
        // a fresh nonce into the opening, and its hex into X_HEX, which secretTail is done with
        rng.generateData(changeOpen, (short)(open + OPEN_NONCE), (short) 32);
        toHex(changeOpen, (short)(open + OPEN_NONCE), (short) 32);
        sha.reset();
        sha.update(H2C_DOMAIN, (short) 0, (short) H2C_DOMAIN.length);
        sha.update(SECRET_1, (short) 0, (short) SECRET_1.length);
        sha.update(scratch, X_HEX, (short) 64);
        sha.doFinal(buf, (short) 0, tail, scratch, X_MSG);
        Util.arrayFillNonAtomic(buf, (short) 32, (short) 32, (byte) 0);
        Util.arrayFillNonAtomic(buf, (short) 225, (short) 4, (byte) 0);
        while (true) {
            sha.reset();
            sha.update(scratch, X_MSG, (short) 32);
            sha.doFinal(buf, (short) 225, (short) 4, buf, (short) 64);
            // the counter moves on now, for the next round should this x not be the one
            for (short i = 225; i < 229; i++) {
                buf[i] = (byte)(buf[i] + 1);
                if (buf[i] != (byte) 0) break;
            }
            if (cmp256(buf, (short) 64, SECP256K1_P, (short) 0) >= 0) continue;
            Util.arrayCopyNonAtomic(buf, (short) 64, buf, (short) 161, (short) 32);
            // x^3 + 7 mod p, kept at 0 for the root
            powModP(rsaCube, buf);
            add7ModP(buf, (short) 128);
            Util.arrayCopyNonAtomic(buf, (short) 128, buf, (short) 0, (short) 32);
            // Euler: a square, or the next counter
            Util.arrayCopyNonAtomic(buf, (short) 128, buf, (short) 64, (short) 32);
            powModP(rsaEuler, buf);
            if (!isZero(buf, (short) 128, (short) 31) || buf[159] != (byte) 1) continue;
            // the root, the even one
            Util.arrayCopyNonAtomic(buf, (short) 0, buf, (short) 64, (short) 32);
            powModP(rsaRoot, buf);
            if ((buf[159] & 1) != 0) negateModP(buf, (short) 128);
            buf[160] = (byte) 0x04;
            Util.arrayCopyNonAtomic(buf, (short) 128, buf, (short) 193, (short) 32);
            break;
        }
        // r: fresh and under n, into the opening
        do {
            rng.generateData(scratch, X_OUT, (short) 32);
            SchnorrHW.reduceModN(scratch, X_OUT);
        } while (isZero(scratch, X_OUT, (short) 32));
        Util.arrayCopyNonAtomic(scratch, X_OUT, changeOpen, (short)(open + OPEN_R), (short) 32);
        // B_ = Y + r*G, by the chip; compressed by the parity of its y
        schnorrHW.addToG(scratch, X_OUT, buf, (short) 160, buf, (short) 0);
        buf[0] = (byte)(((buf[64] & 1) == 0) ? 0x02 : 0x03);
    }

    /**
     * The value at buf[64..96) (buf[32..64) zeros) to the key's power, mod p,
     * into buf[128..160): the chip's RSA over p*p, then the reduction. An
     * answer may come back shorter than the modulus, without its leading
     * zeros (the simulator's does; a chip's is the modulus' length): it is
     * taken by the length answered and set right-aligned in the 64 bytes.
     */
    private void powModP(RSAPrivateKey key, byte[] buf) {
        rsa.init(key, Cipher.MODE_DECRYPT);
        short n = rsa.doFinal(buf, (short) 32, (short) 64, buf, (short) 96);
        if (n < (short) 64) {
            Util.arrayCopyNonAtomic(buf, (short) 96, buf, (short)(160 - n), n);
            Util.arrayFillNonAtomic(buf, (short) 96, (short)(64 - n), (byte) 0);
        }
        reduceModP(buf, (short) 96, scratch, X_OUT);
    }

    /** The payment in hand is given up, and the command refused with `sw`. */
    private void dropPayment(short sw) {
        allState[0] = (byte) 0;
        ISOException.throwIt(sw);
    }

    /** The chip's RSA key for one power over p*p (RSA_PP). */
    private static RSAPrivateKey fieldKey(byte[] d) {
        RSAPrivateKey k = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        k.setModulus(RSA_PP, (short) 0, (short) 64);
        k.setExponent(d, (short) 0, (short) d.length);
        return k;
    }

    /**
     * v[off..off+64) mod p, left in its low 32 bytes. 2^256 is 2^32 + 977
     * mod p, so the high half times that, added to the low half, is the same
     * number mod p and 223 bits shorter; twice over it is under 2^257, and
     * then p is taken off while it is p or more. `w`: 40 bytes of working
     * room.
     */
    private static void reduceModP(byte[] v, short off, byte[] w, short wOff) {
        for (short pass = 0; pass < 2; pass++) {
            Util.arrayFillNonAtomic(w, wOff, (short) 40, (byte) 0);
            Util.arrayCopyNonAtomic(v, (short)(off + 32), w, (short)(wOff + 8), (short) 32);     // the low half
            mulAddByte(w, (short)(wOff + 36), v, off, (short) 32, (byte) 0x01);                 // + the high half * 2^32
            mulAddByte(w, (short)(wOff + 40), v, off, (short) 32, (byte) 0xD1);                 // + the high half * 977 (0x03D1)
            mulAddByte(w, (short)(wOff + 39), v, off, (short) 32, (byte) 0x03);
            Util.arrayFillNonAtomic(v, off, (short) 24, (byte) 0);
            Util.arrayCopyNonAtomic(w, wOff, v, (short)(off + 24), (short) 40);
        }
        while (!isZero(v, off, (short) 32) || cmp256(v, (short)(off + 32), SECP256K1_P, (short) 0) >= 0) {
            subP64(v, off);
        }
    }

    /** w, ending at `wEnd` (exclusive), += a (`len` bytes) times the byte m, the last byte of the product at w[wEnd - 1]; the carry runs left as far as it goes. */
    private static void mulAddByte(byte[] w, short wEnd, byte[] a, short aOff, short len, byte m) {
        short mm = (short)(m & 0xFF);
        short carry = 0;
        short pos = (short)(wEnd - 1);
        for (short i = (short)(len - 1); i >= 0; i--, pos--) {
            short prod = (short)((short)((short)(a[(short)(aOff + i)] & 0xFF) * mm) + (short)(w[pos] & 0xFF) + carry);
            w[pos] = (byte)(prod & 0xFF);
            carry = (short)((prod >> 8) & 0xFF);
        }
        while (carry != 0 && pos >= 0) {
            short sum = (short)((short)(w[pos] & 0xFF) + carry);
            w[pos] = (byte)(sum & 0xFF);
            carry = (short)((sum >> 8) & 0xFF);
            pos--;
        }
    }

    /** out = a - b over 32 bytes, big-endian (out may be a): the borrow out of the top, 1 where b was the larger. */
    private static short sub256(byte[] a, short aOff, byte[] b, short bOff, byte[] out, short outOff) {
        short borrow = 0;
        for (short i = 31; i >= 0; i--) {
            short d = (short)((short)(a[(short)(aOff + i)] & 0xFF) - (short)(b[(short)(bOff + i)] & 0xFF) - borrow);
            if (d < 0) { d += (short) 256; borrow = 1; } else { borrow = 0; }
            out[(short)(outOff + i)] = (byte) d;
        }
        return borrow;
    }

    /** v[off..off+64) -= p, as one 64-byte number: the low half less p, and the borrow taken from the high half. */
    private static void subP64(byte[] v, short off) {
        short borrow = sub256(v, (short)(off + 32), SECP256K1_P, (short) 0, v, (short)(off + 32));
        for (short i = (short)(off + 31); borrow != 0 && i >= off; i--) {
            short d = (short)((short)(v[i] & 0xFF) - borrow);
            if (d < 0) { d += (short) 256; borrow = 1; } else { borrow = 0; }
            v[i] = (byte) d;
        }
    }

    /** The 32 bytes at a against the 32 at b, as unsigned numbers: -1, 0 or 1. */
    private static short cmp256(byte[] a, short aOff, byte[] b, short bOff) {
        for (short i = 0; i < 32; i++) {
            short x = (short)(a[(short)(aOff + i)] & 0xFF), y = (short)(b[(short)(bOff + i)] & 0xFF);
            if (x != y) return x < y ? (short) -1 : (short) 1;
        }
        return (short) 0;
    }

    /** The 32 bytes at off, under p: += 7, mod p. */
    private static void add7ModP(byte[] v, short off) {
        short carry = 7;
        for (short i = 31; i >= 0 && carry != 0; i--) {
            short sum = (short)((short)(v[(short)(off + i)] & 0xFF) + carry);
            v[(short)(off + i)] = (byte)(sum & 0xFF);
            carry = (short)((sum >> 8) & 0xFF);
        }
        // under 2p before, so one taking of p at most; the sum cannot pass 2^256 (p + 7 does not)
        if (cmp256(v, off, SECP256K1_P, (short) 0) >= 0) sub256(v, off, SECP256K1_P, (short) 0, v, off);
    }

    /** The 32 bytes at off, under p and not zero: p - v. */
    private static void negateModP(byte[] v, short off) {
        sub256(SECP256K1_P, (short) 0, v, off, v, off);
    }

    /**
     * GET_CHANGE: the change the card has made for itself and not yet been
     * handed, three openings to a page (P1 = the page, from 0): a count, then
     * for each the amount (4), the keyset (8), the date (4), the nonce (32)
     * and the blinding factor (32). An opening whose piece is on the card by
     * now is let go first. No PIN: what it says lets a reader finish the
     * piece, which is locked to the card's key and nobody's to spend; the
     * phone that owes the change finishes it here, and the owner's phone
     * finishes change a till never handed over (NUT-09).
     */
    private void processGetChange(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short skip = (short)((short)(buf[ISO7816.OFFSET_P1] & 0xFF) * CHANGE_PAGE);
        short n = 0, at = 1;
        for (short k = 0; k < CHANGE_MOST && n < CHANGE_PAGE; k++) {
            short open = (short)(k * OPEN_LEN);
            if (openState[k] != OPEN_PENDING) continue;
            if (slotWithNonce(changeOpen, (short)(open + OPEN_NONCE)) >= 0) {
                openState[k] = OPEN_EMPTY;
                continue;
            }
            if (skip > 0) { skip--; continue; }
            Util.arrayCopyNonAtomic(changeOpen, open, buf, at, OPEN_LEN);
            at += OPEN_LEN;
            n++;
        }
        buf[0] = (byte) n;
        apdu.setOutgoingAndSend((short) 0, at);
    }

    /**
     * GET_DLEQ (1.20): the mint's proof kept with an unspent piece, for one place or two. No PIN, like GET_PIECES and
     * GET_CHANGE: it is what the mint made for a piece that is already on the card for any reader to read, and what a reader
     * does with it (checks that the mint made the piece) it does with the piece in hand.
     *
     * P1 is a place (0 to 127); P2 is a second place, or FF for none. No data. For each place asked, in the order asked, the
     * answer is 01 and the 96 bytes (e, s, r) where the place is UNSPENT and its record is not zero, and otherwise the single
     * byte 00: the place is empty or spent, or holds a piece that came with no proof, or the card has no room for proofs. The
     * same place twice is answered twice. `6A83` for a place there is not (P1 over 127, or P2 over 127 and not FF), before
     * anything is answered. At most 194 bytes.
     *
     * The card does not check the proof. Whoever reads it rebuilds the piece's secret, Y = hash_to_curve(secret), C' = C + r*K
     * (K the mint's key for the amount), B' = Y + r*G, and checks NUT-12's equation on e, s, B' and C'.
     */
    private void processGetDleq(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        // read before the answer is written over the command
        short place = (short)(buf[ISO7816.OFFSET_P1] & 0xFF);
        short second = (short)(buf[ISO7816.OFFSET_P2] & 0xFF);
        short asked = second == (short) 0xFF ? (short) 1 : (short) 2;
        if (place >= MAX_PROOFS || (asked == (short) 2 && second >= MAX_PROOFS)) ISOException.throwIt(SW_SLOT_OUT_OF_RANGE);
        short at = 0;
        for (short k = 0; k < asked; k++) {
            short rec = (short)(place * DLEQ_LEN);
            if (dleq != null
                && proofStorage[(short)(place * PROOF_SIZE + PROOF_STATUS_OFFSET)] == STATUS_UNSPENT
                && !isZero(dleq, rec, DLEQ_LEN)) {
                buf[at++] = (byte) 1;
                at = Util.arrayCopyNonAtomic(dleq, rec, buf, at, DLEQ_LEN);
            } else {
                buf[at++] = (byte) 0;
            }
            place = second;
        }
        apdu.setOutgoingAndSend((short) 0, at);
    }

    /** The place holding a piece with the 32-byte nonce at `off` in `a`, spent or not, or -1. */
    private short slotWithNonce(byte[] a, short off) {
        for (short i = 0; i < MAX_PROOFS; i++) {
            short at = (short)(i * PROOF_SIZE);
            if (proofStorage[(short)(at + PROOF_STATUS_OFFSET)] != STATUS_EMPTY
                && Util.arrayCompare(proofStorage, (short)(at + PROOF_NONCE_OFFSET), a, off, (short) 32) == 0) {
                return i;
            }
        }
        return (short) -1;
    }

    /** An opening whose nonce is the 32 bytes at `off` in `a` is let go: its piece is on the card. */
    private void clearOpening(byte[] a, short off) {
        for (short k = 0; k < CHANGE_MOST; k++) {
            if (openState[k] != OPEN_EMPTY
                && Util.arrayCompare(changeOpen, (short)(k * OPEN_LEN + OPEN_NONCE), a, off, (short) 32) == 0) {
                openState[k] = OPEN_EMPTY;
            }
        }
    }

    /**
     * SPEND_ALL_SIGN: the one signature, 64 bytes, and every piece named at
     * SPEND_ALL_BEGIN burned as it is given.
     *
     * Signed first, into the APDU buffer, which is RAM and leaves the card only
     * with the answer; then burned; then answered. A card taken away while it
     * signs (most of a second) has burned nothing and sent nothing, and no
     * signature leaves the card for pieces that are not burned, because the
     * answer is sent only after the commit. (Burned first, a card pulled away
     * while signing had spent the pieces and given nothing for them.)
     *
     * One transaction commits the payment: the note that its pieces are spent
     * (`burnPending`), what the day has signed for, the card's own log and the
     * signature kept for SPEND_ALL_AGAIN. A card pulled away in it has done all
     * of it or none. The pieces' own status bytes are written after it, from
     * the list written before it, and by the card's next command if it leaves
     * the field first (`finishBurn`): the transaction is the same size for one
     * piece as for all 128. Should it fail all the same, nothing is burned and
     * the answer is `6A96`.
     *
     * The PIN (1.16), where one is set, is asked here and nowhere earlier: once
     * what leaves the card is known, a payment is signed with the PIN given in
     * this tap, or with no PIN within the day's allowance, or it is refused
     * `6A94` and given up (`requireAllowanceOrPin`). A card with no PIN signs.
     * The day's window is begun by the first payment when either the daily
     * limit or the allowance is set, and when the day turns the day's count and
     * the allowance's both go to nothing, in the transaction that commits the
     * payment.
     */
    private void processSpendAllSign(APDU apdu) {
        if (allState[0] != (byte) 1) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        byte[] buf = apdu.getBuffer();

        /* The wait, where the payment is over the limit on one payment (6a).
         * The card has no clock that runs and cannot sleep, so its wait is
         * work: one signature, over bytes of its own choosing, thrown away.
         * That is the one thing here whose time is the chip's and no
         * terminal's. One to a command, so that no command is longer than a
         * signature (a phone gives up on a card that is silent for long), and
         * the answer is "not yet", two bytes, in place of the signature. Nothing is burned and nothing counted until they
         * are done: a card lifted in the wait has lost nothing, and whatever
         * else is sent drops the payment and the wait with it. */
        /* What leaves the card for good: the pieces less the change the card
         * made for itself (1.12). The day's limit and the wait are held to
         * it, and worked out at the first SIGN, when the change is known;
         * neither burns anything. */
        Util.arrayCopyNonAtomic(allSum, (short) 0, allNet, (short) 0, (short) 4);
        subUint32(allNet, (short) 0, allChange, (short) 0);
        short waits = Util.getShort(allState, (short) 2);
        if (waits < 0) {
            /* The PIN, where one is set (1.16): the PIN given in this tap, or
             * the no-PIN allowance, which has to hold the whole of what leaves
             * the card. Asked before the limits, so that a reader with no PIN
             * writes nothing in the card's log: a refusal for being over a
             * limit is the card's account of a terminal that was told better. */
            requireAllowanceOrPin();
            // refused by the day (or for want of a time), the payment is gone, as it was when BEGIN asked
            try {
                requireUnderLimits(allNet, (short) 0, (short) 0);
            } catch (ISOException e) {
                allState[0] = (byte) 0;
                throw e;
            }
            waits = waitsFor(allNet, (short) 0, (short)(allState[6] & 0xFF), allState[7] != (byte) 0,
                             tapOpen[1] == (byte) 1 && loadGrant[0] != (byte) 1);
            Util.setShort(allState, (short) 2, waits);
            allState[4] = (byte)(waits > 0 ? 1 : 0);
        }
        if (waits > 0) {
            rng.generateData(scratch, X_MSG, (short) 32);
            schnorrHW.sign(cardPrivKey, cardPubKey, scratch, X_MSG, buf, (short) 0);
            Util.arrayFillNonAtomic(buf, (short) 0, (short) 64, (byte) 0);
            waits--;
            Util.setShort(allState, (short) 2, waits);
            /* "Not yet", and not how many are still to come: the count would
             * say how many limits the payment is over, and so what the limit
             * is, to a terminal that had only to ask for a large payment and
             * give it up. Two bytes, 00 01, every time. */
            Util.setShort(buf, (short) 0, (short) 1);
            apdu.setOutgoingAndSend((short) 0, (short) 2);
            return;
        }

        // one signature for one beginning
        allState[0] = (byte) 0;
        short n = (short)(allState[1] & 0xFF);

        /* The day's limit again, as it stands now: what the day would have
         * signed for is left in scratch (X_SUM) for the commit. And the
         * allowance: what the day's no-PIN spending would be is left in
         * scratch (X_NOPIN). */
        boolean noPin = requireAllowanceOrPin();
        requireUnderLimits(allNet, (short) 0, (short) 0);
        boolean limited = !isZero(cardRecord, CARD_LIMIT_OFFSET, (short) 4);
        /* The day's window serves the daily limit and the allowance, and begins at
         * the first payment when either is set. When the day turns, what it
         * counted goes to nothing. */
        boolean windowed = limited || !isZero(cardRecord, CARD_NOPIN_LIMIT_OFFSET, (short) 4);
        /* 2.0 (D20): a day that is over begins again only while the rollover budget lasts (`windowRolls`), and the
         * allowance begins again with it only if a PIN or an owner's proof has armed it since it last did. A payment
         * that moves no value (all of it back as the card's own change) begins no day and spends no roll (D26). */
        boolean newDay = windowed && windowRolls();
        /* The first window a card begins (its start still 0: a limit or allowance set before any header, or an allowance
         * set alone) is a beginning, not a roll: it spends no budget and needs no arming. */
        boolean first = windowNotBegun();
        boolean renew = newDay && (first || cardRecord[CARD_ARMED_OFFSET] == (byte) 1);
        if (!noPin) {
            // not counted against the allowance: its count is what it was, or nothing in a new day that renews it
            if (renew) Util.arrayFillNonAtomic(scratch, X_NOPIN, (short) 4, (byte) 0);
            else Util.arrayCopyNonAtomic(cardRecord, CARD_NOPIN_SPENT_OFFSET, scratch, X_NOPIN, (short) 4);
        }

        shaAll.doFinal(buf, (short) 0, (short) 0, scratch, X_MSG);
        short sigLen = schnorrHW.sign(cardPrivKey, cardPubKey, scratch, X_MSG, buf, (short) 0);

        /* The places, written down where `finishBurn` will find them. Not
         * yet a burn: nothing reads this list until the transaction below
         * has set `burnPending`, and a card that leaves before then has
         * burned nothing. */
        burnList[0] = (byte) n;
        Util.arrayCopyNonAtomic(allSlots, (short) 0, burnList, (short) 1, n);
        // the openings' states as they will be, the payment's change signed for: one write in the transaction (X_OUT is free now)
        for (short k = 0; k < CHANGE_MOST; k++) {
            scratch[(short)(X_OUT + k)] = openState[k] == OPEN_DRAFT ? OPEN_PENDING : openState[k];
        }

        try {
            JCSystem.beginTransaction();
            if (windowed) {
                if (newDay) {
                    Util.arrayCopy(cardRecord, CARD_NOW_OFFSET, cardRecord, CARD_WINDOW_OFFSET, (short) 4);
                    // one roll of the budget spent, and the allowance's arming with it if it began again (D20)
                    if (!first) {
                        cardRecord[CARD_ROLLS_OFFSET] = (byte)(cardRecord[CARD_ROLLS_OFFSET] + 1);
                        if (renew) cardRecord[CARD_ARMED_OFFSET] = (byte) 0;
                    }
                }
                if (limited) Util.arrayCopy(scratch, X_SUM, cardRecord, CARD_SPENT_OFFSET, (short) 4);
                Util.arrayCopy(scratch, X_NOPIN, cardRecord, CARD_NOPIN_SPENT_OFFSET, (short) 4);
            }
            /* The payment itself: one byte, whatever the number of places.
             * From the moment this commits every place in the list is spent,
             * whether or not its status byte says so yet. */
            burnPending[0] = (byte) 1;
            // and the next tap may put the change on with no PIN (see select)
            changeDue[0] = (byte) 1;
            // and the card's own account of it, with the burn: no piece is burned that the log does not have
            short entry = logEntry();
            addUint32Stop(cardLog, (short)(entry + LOG_E_SATS), allNet, (short) 0);
            short pieces = (short)((short)(cardLog[(short)(entry + LOG_E_PIECES)] & 0xFF) + n);
            cardLog[(short)(entry + LOG_E_PIECES)] = (byte)(pieces > (short) 255 ? (short) 255 : pieces);
            addUint32Stop(cardLog, LOG_SATS_OFFSET, allNet, (short) 0);
            // the change the card made for itself is signed for now: its openings stay until the pieces are back
            if (allState[6] != (byte) 0) Util.arrayCopy(scratch, X_OUT, openState, (short) 0, CHANGE_MOST);
            // a payment that was over the limit on one payment says so in the card's account of the tap
            if (allState[4] == (byte) 1) cardLog[(short)(entry + LOG_E_FLAGS)] |= LOG_FLAG_WAITED;
            // and one that was signed with no PIN, on a card that has one
            if (noPin) cardLog[(short)(entry + LOG_E_FLAGS)] |= LOG_FLAG_NOPIN;
            /* and the signature itself, for the terminal whose answer is lost on the air (SPEND_ALL_AGAIN); a
             * signature given with no PIN is marked 2, and is given again with no PIN */
            Util.arrayCopy(buf, (short) 0, lastSig, (short) 1, (short) 64);
            lastSig[0] = noPin ? (byte) 2 : (byte) 1;
            JCSystem.commitTransaction();
        } catch (TransactionException e) {
            if (JCSystem.getTransactionDepth() != (byte) 0) JCSystem.abortTransaction();
            ISOException.throwIt(SW_TOO_MANY);
        }
        // committed: the status bytes follow, here or at the card's next command
        finishBurn();
        tapOpen[0] = (byte) 1;
        // a payment in this tap: another in the same tap is slowed (6a)
        tapOpen[1] = (byte) 1;

        /* The receipt, after the burn and by itself: what it says is true
         * only of a payment that was made, and it is kept out of the payment's
         * own transaction, which is kept small. A card pulled away between
         * the two has the payment in its log and no receipt. */
        short slot = (short)((cardReceipts[3] & 0x0F) * RECEIPT_LEN + RECEIPTS_HEAD);
        JCSystem.beginTransaction();
        // the card's own clock (the last block header's time), then the time the terminal told at this tap (a note), the sats, the message, the output
        Util.arrayCopy(cardRecord, CARD_NOW_OFFSET, cardReceipts, slot, (short) 4);
        Util.arrayCopy(tapTime, (short) 0, cardReceipts, (short)(slot + 4), (short) 4);
        Util.arrayCopy(allNet, (short) 0, cardReceipts, (short)(slot + 8), (short) 4);
        Util.arrayCopy(scratch, X_MSG, cardReceipts, (short)(slot + 12), (short) 32);
        if (allState[5] == (byte) 1) {
            Util.arrayCopy(allOut, (short) 0, cardReceipts, (short)(slot + 44), (short) 33);
        } else {
            Util.arrayFillNonAtomic(cardReceipts, (short)(slot + 44), (short) 33, (byte) 0);
        }
        addUint32Stop(cardReceipts, (short) 0, ONE, (short) 0);
        JCSystem.commitTransaction();

        apdu.setOutgoingAndSend((short) 0, sigLen);
    }

    /**
     * Mark every place of the payment last committed as spent, and take the
     * note of it down.
     *
     * A payment used to burn its pieces inside its transaction, a status
     * byte each. A chip's transaction holds only so much: on the card this
     * runs on, a dozen places went through and thirty-two were refused. So
     * the transaction now commits ONE byte for the burn, `burnPending`, with
     * the day, the log and the signature as before; the places themselves
     * were written to `burnList` before it began. Once it has committed the
     * pieces are spent, and marking them is only bookkeeping: done here at
     * the end of SIGN, and, should the card leave the field first, at the
     * start of its very next command (`process`), before anything can look at
     * a place. A byte written twice is the same byte, so doing it again from
     * the top after a tear is safe. A card that leaves before the transaction
     * commits has a list nobody reads, and has burned nothing.
     */
    private void finishBurn() {
        short n = (short)(burnList[0] & 0xFF);
        if (n > MAX_PROOFS) n = MAX_PROOFS;
        for (short i = 0; i < n; i++) {
            short idx = (short)(burnList[(short)(i + 1)] & 0xFF);
            if (idx >= MAX_PROOFS) continue;
            short at = (short)(idx * PROOF_SIZE + PROOF_STATUS_OFFSET);
            if (proofStorage[at] != STATUS_SPENT) proofStorage[at] = STATUS_SPENT;
        }
        /* The note is taken down in a transaction of its own, one byte: a
         * commit is the one write a chip must have made lasting before it
         * goes on, so the status bytes above are in place before the note
         * that they are owed is gone. */
        JCSystem.beginTransaction();
        burnPending[0] = (byte) 0;
        JCSystem.commitTransaction();
    }

    /**
     * SPEND_ALL_AGAIN: the last signature this card gave, 64 bytes, again.
     *
     * The pieces are burned as the signature is given, and the answer is the
     * one thing that can still be lost: a card taken away in those few
     * milliseconds has spent the payment's pieces, all of them, and the
     * terminal has no signature to spend them with. This is the way back. It
     * gives nothing away: the signature is good only for the pieces it burned
     * and the outputs it was made for, which are the asking terminal's own,
     * and a terminal that did not make that payment can do nothing with it.
     * The PIN, as a spend was: where a PIN is set, it must have been given in
     * this tap, unless the signature asked for is one that was given with no PIN
     * (under the allowance, 1.16), which is given again with none, so that a till
     * whose answer was lost need not ask for a PIN it did not need. `6A88` on a
     * card that has never signed.
     */
    private void processSpendAllAgain(APDU apdu) {
        if (lastSig[0] != (byte) 2) requirePinIfSet();
        if (lastSig[0] == (byte) 0) ISOException.throwIt(SW_SLOT_EMPTY);
        byte[] buf = apdu.getBuffer();
        Util.arrayCopyNonAtomic(lastSig, (short) 1, buf, (short) 0, (short) 64);
        apdu.setOutgoingAndSend((short) 0, (short) 64);
    }

    /**
     * The day's limit, held to `sum`: what leaves the card for good, the
     * pieces named at SPEND_ALL_BEGIN less the change the card makes for
     * itself (`allNet`, at SIGN; `carry` where the pieces' sum wrapped, at
     * BEGIN). Leaves in scratch what the day (X_SUM) would have signed for.
     *
     * A terminal that has the PIN picks the places, and nothing on the card
     * can tell its request from the holder's, so what bounds it is a number in
     * permanent memory, counted against a window that only time can end. The
     * card's own change is the one part of a payment it can check, and that
     * part gives the day back; change a terminal writes back by other means
     * it cannot, and that gives nothing back. A limit of 0 is no limit:
     * nothing is checked, and nothing counted. Over it, the spend is written
     * down and refused.
     */
    private void requireUnderLimits(byte[] sum, short sumOff, short carry) {
        boolean limited = !isZero(cardRecord, CARD_LIMIT_OFFSET, (short) 4);
        /* A card that has seen no block header yet (now = 0) spends its first
         * day on trust: its window has no start and cannot end, so what it
         * signs for counts up to the limit and then stops, until a header
         * arrives and the window is anchored at that block's time. */
        if (limited) {
            if (windowRolls()) {
                Util.arrayFillNonAtomic(scratch, X_SUM, (short) 4, (byte) 0);
            } else {
                Util.arrayCopyNonAtomic(cardRecord, CARD_SPENT_OFFSET, scratch, X_SUM, (short) 4);
            }
            short over = addUint32Carry(scratch, X_SUM, sum, sumOff);
            if (carry != 0 || over != 0 || cmpUint32(scratch, X_SUM, cardRecord, CARD_LIMIT_OFFSET) > 0) {
                refuseOverLimit(SW_OVER_LIMIT);
            }
        }
    }

    /**
     * What the payment costs in time: the signatures of work to be done at
     * SPEND_ALL_SIGN before it is signed (6a), shaped so that a payer can
     * feel that a payment was over the limit.
     *
     * With a limit on one payment of L and S leaving the card (`sum`: the
     * pieces less the card's own change): within L (or within a thirty-second
     * over it, see below), nothing, change or no change — that change is
     * coming is the phone's to say, not the card's; over L, WAIT_OVER_SIGNS
     * for the first limit's worth over (about seven seconds) and
     * WAIT_MORE_SIGNS for every further one, whole or in part (three seconds
     * each). The change outputs the card made (`made`), about 0.4 s of its
     * work each, count for what they cost: two signatures for every three.
     *
     * One payment a tap at full speed: a second payment signed in the same
     * time in the field (`second`: one was, and the owner's grant is not in
     * this tap) is slowed as one over the limit is, limit or no limit. A
     * terminal that has the PIN could otherwise take a limit's worth a second
     * for as long as the card is held; now each costs it about seven seconds,
     * or a fresh tap, which asks the PIN again. The owner's phone, which takes
     * a whole card off in more than one signature where its pieces have more
     * than one date, gives its grant first and is not slowed.
     *
     * Nothing is remembered from one payment to the next but that, and no
     * clock is asked, so there is nothing a terminal can replay or reset to
     * make it less. No limit: 0, or WAIT_OVER_SIGNS for a second payment in
     * the tap. A sum that wrapped (`carry`) waits the most.
     */
    private short waitsFor(byte[] sum, short sumOff, short made, boolean carry, boolean second) {
        short waits;
        if (isZero(cardRecord, CARD_TAP_LIMIT_OFFSET, (short) 4)) {
            if (!second) return (short) 0;
            waits = WAIT_OVER_SIGNS;
        } else {
            if (carry) return WAIT_SIGNS_MOST;
            /* Within the limit, or within a thirty-second over it: a limit set in
             * another money is so many sats at one moment and a price in that
             * money so many at another, and a payment of exactly the limit lands
             * a few sats over. That is one limit's worth, not two. The sum is
             * copied, to be taken from; the limit's thirty-second is its four
             * bytes shifted down by five, written beside it. Both by hand: a
             * call is a place in the package the chip relocates at an install,
             * and it takes only so many (docs/FOXY-CARD-HARDWARE.md). */
            short bits = 0;
            for (short i = 0; i < 4; i++) {
                scratch[(short)(X_TAP + i)] = sum[(short)(sumOff + i)];
                short v = (short)(cardRecord[(short)(CARD_TAP_LIMIT_OFFSET + i)] & 0xFF);
                scratch[(short)(X_NUM + i)] = (byte)(((bits << 3) | (v >> 5)) & 0xFF);
                bits = (short)(v & 0x1F);
            }
            short units;
            if (addUint32Carry(scratch, X_NUM, cardRecord, CARD_TAP_LIMIT_OFFSET) != 0 || cmpUint32(scratch, X_TAP, scratch, X_NUM) <= 0) {
                units = 1;
            } else {
                // how many limits' worth leave the card, a part counting as one: the whole ones are taken off while
                // more than one is there, so what is left is never nothing, and is the part
                units = 0;
                while (units < WAIT_UNITS_MOST && cmpUint32(scratch, X_TAP, cardRecord, CARD_TAP_LIMIT_OFFSET) > 0) {
                    subUint32(scratch, X_TAP, cardRecord, CARD_TAP_LIMIT_OFFSET);
                    units++;
                }
                if (units < WAIT_UNITS_MOST) units++;
            }
            // a second payment in the tap is at least one over the limit
            if (second && units <= 1) units = 2;
            if (units <= 1) return (short) 0;
            waits = (short)(WAIT_OVER_SIGNS + WAIT_MORE_SIGNS * (units - 2));
        }
        /* The change already made is work done, and counts for what it cost:
         * an output is about two thirds of a signature's work (0.4 s to 0.6 s
         * on the chip), so two waits come off for every three outputs. One
         * for each, as 1.13 had it, was more than an output costs, and a
         * terminal could buy a payment's wait down with outputs of a sat;
         * at two for three, outputs buy it nothing, and a payment over the
         * limit takes the same time with change as without, so what is felt
         * says how far over it was. */
        waits -= (short)((short)(made * 2) / 3);
        return waits > 0 ? waits : (short) 0;
    }
    /** a -= b, four bytes each, big-endian; a is not less than b. */
    private static void subUint32(byte[] a, short aOff, byte[] b, short bOff) {
        short borrow = 0;
        for (short i = 3; i >= 0; i--) {
            short d = (short)((short)(a[(short)(aOff + i)] & 0xFF) - (short)(b[(short)(bOff + i)] & 0xFF) - borrow);
            if (d < 0) { d += (short) 256; borrow = 1; } else { borrow = 0; }
            a[(short)(aOff + i)] = (byte) d;
        }
    }

    /**
     * What comes after the nonce in the NUT-10 secret of every piece of a
     * payment, as text, into `buf` from 0; answers its length (216 at most):
     *
     *   ","data":"<card key>","tags":[["sigflag","SIG_ALL"]]}]
     *   ","data":"<card key>","tags":[["locktime","<date>"],["refund","<refund key>"],["sigflag","SIG_ALL"]]}]
     *
     * `base` is one of the payment's slots: they are all of one date
     * (SPEND_ALL_BEGIN has seen to it), and the key is the card's.
     */
    private short secretTail(byte[] buf, short base) {
        // the key first, since exporting it uses the buffer: its hex waits in scratch while the text is begun
        short len = toCompressed(buf, cardPubKey.getW(buf, (short) 0));
        toHex(buf, (short) 0, len);
        short at = Util.arrayCopyNonAtomic(SECRET_2, (short) 0, buf, (short) 0, (short) SECRET_2.length);
        at = Util.arrayCopyNonAtomic(scratch, X_HEX, buf, at, (short) 66);
        at = Util.arrayCopyNonAtomic(SECRET_3, (short) 0, buf, at, (short) SECRET_3.length);
        if (isZero(proofStorage, (short)(base + PROOF_DATE_OFFSET), (short) 4)) {
            return Util.arrayCopyNonAtomic(SECRET_END, (short) 0, buf, at, (short) SECRET_END.length);
        }
        at = Util.arrayCopyNonAtomic(SECRET_DATE, (short) 0, buf, at, (short) SECRET_DATE.length);
        short digits = toDecimal(proofStorage, (short)(base + PROOF_DATE_OFFSET));
        at = Util.arrayCopyNonAtomic(scratch, (short)(X_DEC + 10 - digits), buf, at, digits);
        at = Util.arrayCopyNonAtomic(SECRET_REFUND, (short) 0, buf, at, (short) SECRET_REFUND.length);
        toHex(cardRecord, CARD_REFUND_OFFSET, (short) 33);
        at = Util.arrayCopyNonAtomic(scratch, X_HEX, buf, at, (short) 66);
        return Util.arrayCopyNonAtomic(SECRET_END_DATED, (short) 0, buf, at, (short) SECRET_END_DATED.length);
    }

    /**
     * The piece in place `idx` into `md`, as a payment's message has it: its
     * NUT-10 secret as text and then its C in hex, not finished, so that more
     * can follow. `buf` holds the `tail` bytes `secretTail` wrote.
     */
    private void secretInto(MessageDigest md, short idx, byte[] buf, short tail) {
        short hex = (short)(idx * HEX_LEN);
        md.update(SECRET_1, (short) 0, (short) SECRET_1.length);
        md.update(slotHex, hex, (short) 64);
        md.update(buf, (short) 0, tail);
        md.update(slotHex, (short)(hex + 64), (short) 66);
    }

    /**
     * AUTH: that this is the card whose key GET_PUBKEY gives.
     *
     * The reader sends 16 random bytes. The card answers 16 of its own and a
     * BIP-340 signature over
     *
     *   SHA-256( SHA-256("CashuCard/auth") || SHA-256("CashuCard/auth")
     *            || reader's 16 || card's 16 || the card's key, compressed )
     *
     * No PIN: it spends nothing and says only what GET_PUBKEY already has. It
     * is not SIGN_ARBITRARY by another name. That signed the reader's 32 bytes
     * as they came, which could be a piece's own message; here the reader's
     * bytes are hashed under a tag with the card's, and a spend's message is
     * the hash of a secret's text, which no such hash can equal.
     */
    private void processAuth(APDU apdu) {
        short len = apdu.setIncomingAndReceive();
        if (len != AUTH_NONCE_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte[] buf = apdu.getBuffer();

        sha.reset();
        sha.update(authTagHash, (short) 0, (short) 32);
        sha.update(authTagHash, (short) 0, (short) 32);
        sha.update(buf, ISO7816.OFFSET_CDATA, AUTH_NONCE_LEN);
        // the card's own, kept in scratch while the buffer is used for the key
        rng.generateData(scratch, X_HEX, AUTH_NONCE_LEN);
        sha.update(scratch, X_HEX, AUTH_NONCE_LEN);
        short keyLen = toCompressed(buf, cardPubKey.getW(buf, (short) 0));
        sha.doFinal(buf, (short) 0, keyLen, scratch, X_MSG);

        Util.arrayCopyNonAtomic(scratch, X_HEX, buf, (short) 0, AUTH_NONCE_LEN);
        short sigLen = schnorrHW.sign(cardPrivKey, cardPubKey, scratch, X_MSG, buf, AUTH_NONCE_LEN);
        apdu.setOutgoingAndSend((short) 0, (short)(AUTH_NONCE_LEN + sigLen));
    }

    /** GET_CARD: format, whether the record is set, unit, limit, refund key, the clock's block header (its bits and hash), mint. */
    private void processGetCard(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short mintLen = (short)(cardRecord[CARD_MINTLEN_OFFSET] & 0xFF);
        buf[0] = FORMAT;
        buf[1] = cardRecord[CARD_SET_OFFSET];
        buf[2] = cardRecord[CARD_UNIT_OFFSET];
        Util.arrayCopyNonAtomic(cardRecord, CARD_LIMIT_OFFSET, buf, (short) 3, (short) 4);
        Util.arrayCopyNonAtomic(cardRecord, CARD_REFUND_OFFSET, buf, (short) 7, (short) 33);
        // where the time key was: the hardest header's bits (4), the last header's hash (32), zeros (29)
        Util.arrayCopyNonAtomic(cardRecord, CARD_BITS_OFFSET, buf, (short) 40, (short) 65);
        buf[105] = (byte) mintLen;
        Util.arrayCopyNonAtomic(cardRecord, CARD_MINT_OFFSET, buf, (short) 106, mintLen);
        // and, after the mint, the card's design: three characters, or zeros for none (1.10)
        Util.arrayCopyNonAtomic(cardRecord, CARD_DESIGN_OFFSET, buf, (short)(106 + mintLen), CARD_DESIGN_LEN);
        apdu.setOutgoingAndSend((short) 0, (short)(106 + mintLen + CARD_DESIGN_LEN));
    }

    // -------------------------------------------------------------------------
    // Category 0x3x — Write commands (PIN required if set)
    // -------------------------------------------------------------------------

    private void processLoadProof(APDU apdu) {
        requireNotLocked();
        // Nothing goes onto a card with no PIN: upstream's did, and then any
        // reader in range could spend it. The PIN is typed, or the owner has
        // allowed loading in this tap (ALLOW_LOAD).
        requireLoadAuthority();
        // Nor onto a card with no owner: nobody could change its PIN or its
        // limit, and a terminal that had the PIN could never be bounded or
        // corrected.
        if (ownerSet[0] != (byte) 1) ISOException.throwIt(SW_NO_OWNER);
        if (cardRecord[CARD_SET_OFFSET] != (byte) 1) ISOException.throwIt(SW_NO_CARD_RECORD);

        // a full card says so whatever it is sent
        if (emptySlot() < 0) ISOException.throwIt(SW_NO_SPACE);

        /* One piece, or up to BATCH_MOST of them end to end: a card is loaded
         * with thirty at a time, and a command each was most of what loading
         * took. They are taken in order, each exactly as one alone would be.
         * The first that cannot be stored stops it: alone, or first, it is
         * refused with its own word, as it always was; after others, the
         * answer is the ones that did go on, and the terminal sends the rest
         * again to hear why. The answer is the place of each piece stored.
         *
         * 1.20: with P1 = 1 it is one piece and, after its 81 bytes, the mint's proof for it (96): exactly 177 bytes, and
         * nothing else is different. The answer is then two bytes, the place and a flag: 01 where the proof was kept, 00 where
         * the card has no room for proofs and the piece went on without it. Any other P1 is what it always was; the card
         * does not look at P1 beyond that. */
        byte[] buf = apdu.getBuffer();
        boolean withProof = buf[ISO7816.OFFSET_P1] == (byte) 1;
        short dataLen = apdu.setIncomingAndReceive();
        if (withProof ? dataLen != LOAD_DLEQ_LEN
            : (dataLen < PROOF_DATA_LEN || dataLen > (short)(BATCH_MOST * PROOF_DATA_LEN)
               || (short)(dataLen % PROOF_DATA_LEN) != (short) 0)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short n = withProof ? (short) 1 : (short)(dataLen / PROOF_DATA_LEN);
        short done = 0;
        for (short k = 0; k < n; k++) {
            short sw = loadOne(buf, (short)(ISO7816.OFFSET_CDATA + (short)(k * PROOF_DATA_LEN)), (short)(X_NUM + k),
                               withProof ? (short)(ISO7816.OFFSET_CDATA + PROOF_DATA_LEN) : (short) -1);
            if (sw != (short) 0) {
                if (k == (short) 0) ISOException.throwIt(sw);
                break;
            }
            done++;
        }
        /* And the card's own account of it (6b): what was put on in this tap,
         * once for the command. After the pieces, which are on the card
         * whether or not this is written. */
        if (done > 0) {
            Util.arrayFillNonAtomic(scratch, X_SUM, (short) 4, (byte) 0);
            for (short k = 0; k < done; k++) {
                addUint32Stop(scratch, X_SUM, buf, (short)(ISO7816.OFFSET_CDATA + (short)(k * PROOF_DATA_LEN) + PROOF_AMOUNT_OFFSET - 1));
            }
            JCSystem.beginTransaction();
            short entry = logEntry();
            addUint32Stop(cardLog, (short)(entry + LOG_E_LOADED), scratch, X_SUM);
            short loads = (short)((short)(cardLog[(short)(entry + LOG_E_LOADS)] & 0xFF) + done);
            cardLog[(short)(entry + LOG_E_LOADS)] = (byte)(loads > (short) 255 ? (short) 255 : loads);
            JCSystem.commitTransaction();
            tapOpen[0] = (byte) 1;
        }
        Util.arrayCopyNonAtomic(scratch, X_NUM, buf, (short) 0, done);
        if (withProof) {
            // the place (one piece went on, or the first would have been refused) and whether its proof is kept
            buf[1] = dleq != null ? (byte) 1 : (byte) 0;
            done = (short) 2;
        }
        apdu.setOutgoingAndSend((short) 0, done);
    }

    /** The first empty place, or -1. */
    private short emptySlot() {
        for (short i = 0; i < MAX_PROOFS; i++) {
            if (proofStorage[(short)(i * PROOF_SIZE + PROOF_STATUS_OFFSET)] == STATUS_EMPTY) return i;
        }
        return (short) -1;
    }

    /**
     * One piece, its 81 bytes at `in` in `buf`, into the first empty place.
     * Answers 0 and leaves the place's number in scratch[`out`], or answers
     * the status word it is refused with, having written nothing.
     *
     * `proofAt` (1.20) is where the mint's proof for the piece begins in `buf` (96 bytes), or -1 for a piece that comes with
     * none. A proof of zeros is refused as a piece with a point that is none is: zeros are what "no proof" is kept as. The
     * place's record is written, or made zero, before anything of the place and long before its status byte, so that an
     * UNSPENT place holds its own proof or zeros and never another piece's, whatever the place held before.
     */
    private short loadOne(byte[] buf, short in, short out, short proofAt) {
        short slot = emptySlot();
        if (slot < 0) return SW_NO_SPACE;
        /* A piece with a date names the card's refund key in its secret, so a
         * card with none cannot hold one: the card could not build the secret
         * the mint signed, and its signature would be worth nothing. */
        if (!isZero(buf, (short)(in + PROOF_DATE_OFFSET - 1), (short) 4)
            && cardRecord[CARD_REFUND_OFFSET] == (byte) 0) {
            return SW_NO_REFUND_KEY;
        }
        // not a point, or worth nothing, or a proof of nothing: not a piece
        byte c0 = buf[(short)(in + PROOF_C_OFFSET - 1)];
        if ((c0 != (byte) 0x02 && c0 != (byte) 0x03)
            || isZero(buf, (short)(in + PROOF_AMOUNT_OFFSET - 1), (short) 4)
            || (proofAt >= 0 && isZero(buf, proofAt, DLEQ_LEN))) {
            return ISO7816.SW_WRONG_DATA;
        }
        /* Not a piece that is here already. What the card signs is the piece's
         * secret, which is its nonce (with the card's key and the date) and
         * not its amount: the amount is only what the day is charged. So a
         * second copy of a piece, written with a smaller amount, would be
         * signed for the real piece's secret at the price of the small one,
         * and the day's limit would count for nothing. A nonce that is in any
         * slot, spent or not, is refused, before anything is written. A slot
         * that CLEAR_SPENT has freed holds nothing, so that piece may be
         * loaded again then, if its signature was lost. (One of the pieces
         * before it in the same command is in a slot by now, and is seen.) */
        if (slotWithNonce(buf, (short)(in + PROOF_NONCE_OFFSET - 1)) >= 0) return SW_PIECE_ON_CARD;
        short base = (short)(slot * PROOF_SIZE);
        short hex = (short)(slot * HEX_LEN);
        // its nonce and its C as the text a payment hashes (`slotHex`): before the data, and long before the status byte
        toHex(buf, (short)(in + PROOF_NONCE_OFFSET - 1), (short) 32);
        Util.arrayCopyNonAtomic(scratch, X_HEX, slotHex, hex, (short) 64);
        toHex(buf, (short)(in + PROOF_C_OFFSET - 1), (short) 33);
        Util.arrayCopyNonAtomic(scratch, X_HEX, slotHex, (short)(hex + 64), (short) 66);
        /* Its proof (1.20), in the place's record: the piece's own, or zeros. Before the data and long before the status
         * byte, like the text above, so that a place that goes UNSPENT holds its own record and not the one a piece before it
         * left (CLEAR_SPENT leaves a freed place's record as it was). A piece that comes with none makes the record zero, and
         * writes only if it is not already. A card with no room for proofs (`dleq` is null) writes nothing. */
        if (dleq != null) {
            short rec = (short)(slot * DLEQ_LEN);
            if (proofAt >= 0) Util.arrayCopyNonAtomic(buf, proofAt, dleq, rec, DLEQ_LEN);
            else if (!isZero(dleq, rec, DLEQ_LEN)) Util.arrayFillNonAtomic(dleq, rec, DLEQ_LEN, (byte) 0);
        }
        // The status byte is the slot's commit, written last (D14, ENG-620).
        // Util.arrayCopy into persistent memory is atomic, and so is a single
        // byte write, but the pair is not: with the status first, a card
        // pulled between them left a slot marked UNSPENT over whatever it held
        // before. Data first, a tear leaves the slot EMPTY with the new bytes
        // in it, which no read looks at and the next LOAD_PROOF overwrites.
        Util.arrayCopy(buf, in, proofStorage, (short)(base + PROOF_KEYSET_OFFSET), PROOF_DATA_LEN);
        proofStorage[(short)(base + PROOF_STATUS_OFFSET)] = STATUS_UNSPENT;
        // change the card made for itself, back on the card: its opening is let go (1.12)
        clearOpening(buf, (short)(in + PROOF_NONCE_OFFSET - 1));

        // A load that the change grant alone allowed (no verified PIN, no
        // owner grant) is the change going on: the note is spent now, not at
        // SELECT, so a glance or a cut-short tap before this never lost it.
        // The rest of the change in this same tap still has changeGrant
        // (transient) and goes on; the next fresh tap sees the note gone.
        if (pinVerifiedFlag[0] != (byte) 1 && loadGrant[0] != (byte) 1) {
            changeDue[0] = (byte) 0;
        }
        scratch[out] = (byte) slot;
        return (short) 0;
    }

    private void processClearSpent(APDU apdu) {
        requireNotLocked();
        /* the PIN, or the owner's grant for this tap, or the tap after a payment; a card with no PIN
         * (1.16) is freed by whoever holds it, as it is loaded by whoever holds it */
        boolean granted = loadGrant[0] == (byte) 1 || changeGrant[0] == (byte) 1;
        if (pinState[0] != (byte) 0 && pinVerifiedFlag[0] != (byte) 1 && !granted) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte[] buf = apdu.getBuffer();
        buf[0] = (byte) freeSpent();
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    /** Every spent place freed, as CLEAR_SPENT does it (and RESET_CARD): answers how many. */
    private short freeSpent() {
        short freed = 0;
        for (short i = 0; i < MAX_PROOFS; i++) {
            short base = (short)(i * PROOF_SIZE);
            if (proofStorage[(short)(base + PROOF_STATUS_OFFSET)] == STATUS_SPENT) {
                // Data first, status last (D14, ENG-620). The fill is not
                // atomic, so a tear mid-fill leaves a SPENT slot with some of
                // its bytes zeroed: never counted or signed for, and finished
                // by the next CLEAR_SPENT. An EMPTY slot never holds a spent
                // proof's bytes for a torn LOAD_PROOF to resurrect.
                Util.arrayFillNonAtomic(proofStorage, (short)(base + PROOF_KEYSET_OFFSET), PROOF_DATA_LEN, (byte) 0);
                proofStorage[(short)(base + PROOF_STATUS_OFFSET)] = STATUS_EMPTY;
                freed++;
            }
        }
        return freed;
    }

    /**
     * SET_CARD: unit (1), refund key (33, zeros for none), 65 bytes that held
     * a time key until 1.15 and are not read (a phone of a later software sends
     * zeros), mint length (1), mint. On a card with an owner the owner's proof
     * comes first: its length (1) and the proof (DER).
     *
     * Only with nothing unspent on the card. The refund key is part of every
     * dated piece's secret and the mint is where every piece is, so changing
     * either under pieces already loaded would leave them unspendable or
     * unfindable.
     *
     * Who may: on a card with NO owner, a verified PIN (or any reader, where
     * the card has no PIN at all: it is open while it is being set up); on a card WITH an
     * owner, the owner's proof over everything sent, whether or not the card
     * is empty (a terminal that holds the PIN can make a card empty, and must
     * not be able to set its own record then). The proof replaces the PIN: the
     * owner's phone does not know it.
     *
     * The clock (`now`), its window and the day's spending are kept through a
     * new record: the clock is block headers' (SET_HEADER), and no record can
     * be wrong about it. The limit stays. One transaction: the record is whole
     * or as it was.
     */
    private void processSetCard(APDU apdu) {
        requireNotLocked();
        boolean owned = ownerSet[0] == (byte) 1;
        // an open card: the PIN, if it has one (a card may have none, 1.16: set up with no PIN, it is written by whoever holds it)
        if (!owned) requirePinIfSet();
        short dataLen = apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short at = ISO7816.OFFSET_CDATA;
        short len = dataLen;
        if (owned) {
            at = requireOwnerProof(LABEL_SET_CARD, buf, dataLen);
            len = (short)(ISO7816.OFFSET_CDATA + dataLen - at);
        }
        requireNothingUnspent();
        if (len < (short)(SET_CARD_FIXED + 1)) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short mintLen = (short)(buf[(short)(at + SET_CARD_MINTLEN_AT)] & 0xFF);
        /* After the mint, the design (3 bytes) or nothing: a phone that knows no
         * design sends the record as it always did, and the card has none. */
        boolean designGiven = len == (short)(SET_CARD_FIXED + mintLen + CARD_DESIGN_LEN);
        if (mintLen < 1 || mintLen > CARD_MINT_MAX || (len != (short)(SET_CARD_FIXED + mintLen) && !designGiven)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short designAt = (short)(at + SET_CARD_FIXED + mintLen);
        if (designGiven && !isZero(buf, designAt, CARD_DESIGN_LEN)) {
            // a code of three characters, capital letters and digits, or three zeros
            for (short k = 0; k < CARD_DESIGN_LEN; k++) {
                byte c = buf[(short)(designAt + k)];
                if (!((c >= (byte) 'A' && c <= (byte) 'Z') || (c >= (byte) '0' && c <= (byte) '9'))) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
        // a refund key is a compressed point, or 33 zeros for none
        byte r0 = buf[(short)(at + 1)];
        if (r0 == (byte) 0) {
            if (!isZero(buf, (short)(at + 1), (short) 33)) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        } else if (r0 != (byte) 0x02 && r0 != (byte) 0x03) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        /* Bytes 34 to 98 of the record held a time signer's key until 1.15, and
         * are not read: a phone of an earlier software still sends one, a later
         * one sends zeros, and the card's clock, which is block headers' now
         * (SET_HEADER), keeps its reading through a new record. */
        /* The room for the mint's proofs (1.20) is reserved here, the first time the card is set up, and not at install: the
         * chip refuses to install an applet whose constructor asks for this much more, and gives the same bytes asked for after
         * it (docs/FOXY-CARD-HARDWARE.md). Once, and outside any transaction, so that nothing can undo it. If the
         * card refuses the room, `dleq` stays null, the record is written all the same, and the card works as one with no room for
         * proofs: every use of the store is safe while it is null. */
        if (dleq == null) {
            try {
                dleq = new byte[(short)(MAX_PROOFS * DLEQ_LEN)];
            } catch (SystemException e) {
                dleq = null;
            }
        }
        JCSystem.beginTransaction();
        cardRecord[CARD_UNIT_OFFSET] = buf[at];
        Util.arrayCopy(buf, (short)(at + 1), cardRecord, CARD_REFUND_OFFSET, (short) 33);
        cardRecord[CARD_MINTLEN_OFFSET] = (byte) mintLen;
        Util.arrayCopy(buf, (short)(at + SET_CARD_FIXED), cardRecord, CARD_MINT_OFFSET, mintLen);
        if (designGiven) Util.arrayCopy(buf, designAt, cardRecord, CARD_DESIGN_OFFSET, CARD_DESIGN_LEN);
        else Util.arrayFillNonAtomic(cardRecord, CARD_DESIGN_OFFSET, CARD_DESIGN_LEN, (byte) 0);
        /* The ratchet is let go: the hardest difficulty the card has taken is
         * set to nothing, and the next header sets it afresh. The one way out
         * for a card whose network has fallen under a quarter of its best and
         * would otherwise take no real header again; in the owner's or the
         * PIN's hands only, as the record is. The clock itself stays. */
        Util.arrayFillNonAtomic(cardRecord, CARD_BITS_OFFSET, (short) 4, (byte) 0);
        cardRecord[CARD_SET_OFFSET] = (byte) 1;
        JCSystem.commitTransaction();
    }

    /**
     * SET_LIMIT, the PIN form (0x33): the limit (4, big-endian).
     *
     * For an OPEN card only: one with no owner and nothing unspent, and a
     * verified PIN. On a card with an owner the PIN cannot set the limit, empty
     * or not (a terminal holding it would otherwise remove the day's bound
     * whenever the card was empty); the owner's form is 0x34.
     */
    private void processSetLimit(APDU apdu) {
        requireNotLocked();
        requirePinSetAndVerified();
        if (ownerSet[0] == (byte) 1) ISOException.throwIt(SW_OWNER_PROOF);
        requireNothingUnspent();
        short dataLen = apdu.setIncomingAndReceive();
        if (dataLen != (short) 4 && dataLen != (short) 8) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        writeLimit(apdu.getBuffer(), ISO7816.OFFSET_CDATA, dataLen);
    }

    /**
     * SET_LIMIT, the owner's form (0x34): the proof's length (1), the proof
     * (DER), then the limit (4, big-endian).
     *
     * No PIN, and any funds: the owner's phone does not know the PIN, and sets
     * or removes the limit on a funded card. A proof for one number is no proof
     * for another, and a proof once used is no proof.
     *
     * The limit is 4 bytes (the day's), 8 (the day's and the limit on one
     * payment) or, since 1.16, 12 (those two and the no-PIN allowance). A card
     * with no PIN has no allowance to set: a 12-byte form with a number in the
     * allowance is refused (`6985`), and one with a zero in it is the 8-byte form.
     * 2.0 (D20) adds a thirteenth byte, the rollover budget (1 to 30); a form
     * without it leaves the budget as it is (D26).
     */
    private void processSetLimitOwner(APDU apdu) {
        requireNotLocked();
        if (ownerSet[0] != (byte) 1) ISOException.throwIt(SW_NO_OWNER);
        short dataLen = apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short at = requireOwnerProof(LABEL_SET_LIMIT, buf, dataLen);
        short len = (short)(ISO7816.OFFSET_CDATA + dataLen - at);
        if (len != (short) 4 && len != (short) 8 && len != (short) 12 && len != (short) 13) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        // no allowance without a PIN: there is nothing for it to stand in front of
        if (len >= (short) 12 && pinState[0] == (byte) 0 && !isZero(buf, (short)(at + 8), (short) 4)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // 2.0 (D20): a thirteenth byte is the rollover budget, 1 to 30 days between the owner's REFRESHes
        if (len == (short) 13) {
            byte budget = buf[(short)(at + 12)];
            if (budget < (byte) 1 || budget > ROLL_BUDGET_MOST) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        writeLimit(buf, at, len);
    }

    /**
     * The limit written, and a window begun at `now` with nothing spent in it.
     * A limit set before the card has seen a block header begins its window at
     * the first header that arrives; until then the card spends on trust.
     * One transaction: the limit and its window are all new or all old.
     */
    /*
     * `len` is 4, 8, 12 or 13 (the owner's form only: the rollover budget,
     * D20; every shorter form leaves the budget as it is, D26). Four
     * bytes are the day's limit, as they always were,
     * and the limit on one payment and the allowance are left as they are.
     * Eight are the day's, then the limit on one payment; twelve add the
     * no-PIN allowance. In those forms a day's limit whose number is not
     * changed keeps its window and what was signed for in it, so that setting
     * the others does not begin the day again; a day's number that changes
     * begins its window at `now` with nothing spent (the allowance's count
     * too: the window is theirs both), as the four-byte form always does. An
     * allowance whose number is not changed keeps its count; a new number
     * counts from nothing in the window as it stands. The limit on one
     * payment has no window to begin.
     */
    private void writeLimit(byte[] src, short at, short len) {
        boolean both = len >= (short) 8;
        boolean three = len >= (short) 12;
        /* A day's limit set before the card has seen a block header begins a
         * window with no start (now = 0): the first header anchors it. Until
         * then the card spends its first day on trust (`requireUnderLimits`). */
        boolean dayChanged = !both || !sameBytes(src, at, cardRecord, CARD_LIMIT_OFFSET, (short) 4);
        boolean tapChanged = both && !sameBytes(src, (short)(at + 4), cardRecord, CARD_TAP_LIMIT_OFFSET, (short) 4);
        boolean allowanceChanged = three && !sameBytes(src, (short)(at + 8), cardRecord, CARD_NOPIN_LIMIT_OFFSET, (short) 4);
        JCSystem.beginTransaction();
        if (dayChanged) {
            Util.arrayCopy(src, at, cardRecord, CARD_LIMIT_OFFSET, (short) 4);
            Util.arrayCopy(cardRecord, CARD_NOW_OFFSET, cardRecord, CARD_WINDOW_OFFSET, (short) 4);
            Util.arrayCopy(ZERO, (short) 0, cardRecord, CARD_SPENT_OFFSET, (short) 4);
            // the window is the allowance's as well, and begins again: what it counted goes with the old one
            Util.arrayCopy(ZERO, (short) 0, cardRecord, CARD_NOPIN_SPENT_OFFSET, (short) 4);
        }
        if (tapChanged) {
            Util.arrayCopy(src, (short)(at + 4), cardRecord, CARD_TAP_LIMIT_OFFSET, (short) 4);
        }
        if (allowanceChanged) {
            // a new number for the allowance counts from nothing, in the window it is in; the window itself is the day's, and stays
            Util.arrayCopy(src, (short)(at + 8), cardRecord, CARD_NOPIN_LIMIT_OFFSET, (short) 4);
            Util.arrayCopy(ZERO, (short) 0, cardRecord, CARD_NOPIN_SPENT_OFFSET, (short) 4);
        }
        /* The rollover budget (2.0, D20): the owner's thirteenth byte. A form without it (4, 8 or 12 bytes, and the PIN's
         * form) leaves the budget as it is (D26, amending D20's "absent means 7"): a wallet that sets a limit and does not
         * know the byte neither loosens nor tightens the owner's choice. The rolls are not touched: a budget set under
         * them stops the day until the next REFRESH. */
        if (len == (short) 13) cardRecord[CARD_BUDGET_OFFSET] = src[(short)(at + 12)];
        JCSystem.commitTransaction();
    }

    /**
     * REFRESH (0x53, 2.0, D20): the owner's proof's length (1), the proof (over "CashuCard/refresh", the nonce just
     * given and the header), then a block header (80 bytes).
     *
     * The owner's phone, online, brings the tip. The header is held to everything SET_HEADER holds one to, and taken
     * as SET_HEADER takes it (an older one moves nothing); then the rollover budget is full again: the window may roll
     * its budget's days before the next REFRESH. One transaction: the header and the count. No PIN; any funds; a
     * locked card too, since a locked card still pays and its day still turns. A wrong proof or a header without the
     * work changes nothing. Answers the card's `now`, as SET_HEADER does.
     */
    private void processRefresh(APDU apdu) {
        short dataLen = apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short at = requireOwnerProof(LABEL_REFRESH, buf, dataLen);
        if ((short)(ISO7816.OFFSET_CDATA + dataLen - at) != HEADER_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short how = checkHeader(buf, at);
        JCSystem.beginTransaction();
        writeHeader(buf, at, how);
        cardRecord[CARD_ROLLS_OFFSET] = (byte) 0;
        JCSystem.commitTransaction();
        Util.arrayCopyNonAtomic(cardRecord, CARD_NOW_OFFSET, buf, (short) 0, (short) 4);
        apdu.setOutgoingAndSend((short) 0, (short) 4);
    }

    /**
     * SET_HEADER: a Bitcoin block header, the 80 bytes as the network carries
     * them (version, the previous block's hash, the merkle root, the time, the
     * difficulty as `bits`, the nonce; every number little-endian). The card's
     * clock is the time written in the newest header it has taken.
     *
     * The card believes the header for what it would cost to make, not for who
     * brings it: it hashes the 80 bytes twice and the hash, read as a number,
     * must be at or under the target the header's own `bits` name, which is
     * the proof of the network's ten minutes of work. Then the work must be
     * enough to be anybody's: the target at or under the floor built in
     * (FLOOR_BITS) and at or under four times the target of the hardest header
     * the card has taken, that is, a quarter of its work (`6A93` otherwise;
     * `6A80` for a difficulty no header could carry). No key, no PIN, no owner,
     * and no state of the card refuses a good header: a blocked or locked card
     * takes it. Nobody can bring a header dated tomorrow without tomorrow's
     * work, and an old header changes nothing and is answered `9000`, so a
     * terminal that brings the header it has is never in the wrong.
     *
     * A header later than the clock moves it forward, anchors the window of a
     * day's limit set before any header arrived (6), and is remembered: its
     * difficulty where it is the hardest yet, and its hash, as Bitcoin shows
     * one, for the owner's screen. Answers the card's `now`.
     */
    private void processSetHeader(APDU apdu) {
        short dataLen = apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short at = ISO7816.OFFSET_CDATA;
        if (dataLen != HEADER_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short how = checkHeader(buf, at);
        if (how != (short) 0) {
            JCSystem.beginTransaction();
            writeHeader(buf, at, how);
            JCSystem.commitTransaction();
        }
        Util.arrayCopyNonAtomic(cardRecord, CARD_NOW_OFFSET, buf, (short) 0, (short) 4);
        apdu.setOutgoingAndSend((short) 0, (short) 4);
    }

    /**
     * The checks a block header must pass, for SET_HEADER, REFRESH and an anchored SET_OWNER (D20): its own work, the
     * floor, and a quarter of the hardest taken (`6A93` otherwise, `6A80` for bits no header could carry). Writes
     * nothing. Leaves the header's time, big-endian, in scratch (X_NUM) and its hash, as Bitcoin shows one, in scratch
     * (X_OUT), and answers what taking it would do: 0 nothing (it is not later than the clock), 1 move the clock, 2 move
     * the clock and raise the hardest difficulty taken.
     */
    private short checkHeader(byte[] buf, short at) {
        // the work: the header hashed twice, the hash turned round into a big-endian number (Bitcoin reads it little-endian)
        sha.reset();
        sha.doFinal(buf, at, HEADER_LEN, scratch, X_MSG);
        sha.reset();
        sha.doFinal(scratch, X_MSG, (short) 32, scratch, X_MSG);
        for (short i = 0; i < 32; i++) scratch[(short)(X_OUT + i)] = scratch[(short)(X_MSG + 31 - i)];
        // at or under the target its own bits name
        targetOf(buf, (short)(at + 72), scratch, (short)(X_OUT + 32));
        if (cmp256(scratch, X_OUT, scratch, (short)(X_OUT + 32)) > 0) ISOException.throwIt(SW_LITTLE_WORK);
        // and enough of it: the floor built in, then a quarter of the hardest taken
        targetOf(FLOOR_BITS, (short) 0, scratch, X_HEX);
        if (cmp256(scratch, (short)(X_OUT + 32), scratch, X_HEX) > 0) ISOException.throwIt(SW_LITTLE_WORK);
        boolean seen = !isZero(cardRecord, CARD_BITS_OFFSET, (short) 4);
        if (seen) {
            targetOf(cardRecord, CARD_BITS_OFFSET, scratch, X_HEX);
            timesFour(scratch, X_HEX);
            if (cmp256(scratch, (short)(X_OUT + 32), scratch, X_HEX) > 0) ISOException.throwIt(SW_LITTLE_WORK);
        }
        // the block's time, big-endian
        scratch[X_NUM] = buf[(short)(at + 71)];
        scratch[(short)(X_NUM + 1)] = buf[(short)(at + 70)];
        scratch[(short)(X_NUM + 2)] = buf[(short)(at + 69)];
        scratch[(short)(X_NUM + 3)] = buf[(short)(at + 68)];
        if (cmpUint32(scratch, X_NUM, cardRecord, CARD_NOW_OFFSET) <= 0) return (short) 0;
        if (!seen) return (short) 2;
        targetOf(cardRecord, CARD_BITS_OFFSET, scratch, X_HEX);
        return cmp256(scratch, (short)(X_OUT + 32), scratch, X_HEX) < 0 ? (short) 2 : (short) 1;
    }

    /**
     * Takes a header that `checkHeader` has passed, as it answered (`how`), from what it left in scratch. Inside the
     * caller's transaction: the clock, the window of a limit set before any header arrived, the hardest difficulty, and
     * the hash, all new or all old.
     */
    private void writeHeader(byte[] buf, short at, short how) {
        if (how == (short) 0) return;
        Util.arrayCopy(scratch, X_NUM, cardRecord, CARD_NOW_OFFSET, (short) 4);
        // a day's limit, or an allowance, set before the card had seen a header: the window begins at this one
        if ((!isZero(cardRecord, CARD_LIMIT_OFFSET, (short) 4) || !isZero(cardRecord, CARD_NOPIN_LIMIT_OFFSET, (short) 4))
            && isZero(cardRecord, CARD_WINDOW_OFFSET, (short) 4)) {
            Util.arrayCopy(scratch, X_NUM, cardRecord, CARD_WINDOW_OFFSET, (short) 4);
        }
        if (how == (short) 2) Util.arrayCopy(buf, (short)(at + 72), cardRecord, CARD_BITS_OFFSET, (short) 4);
        Util.arrayCopy(scratch, X_OUT, cardRecord, CARD_HEADER_OFFSET, (short) 32);
    }

    /**
     * The target a header's `bits` name, as a 32-byte big-endian number at
     * `out[outOff]`: the three-byte mantissa placed `exponent` bytes up from
     * the bottom, as Bitcoin has it. `bits` are read little-endian from
     * `src[off]`, as a header carries them. A size no header could carry
     * (0, or past 32 bytes) or a mantissa with its top bit set (a negative
     * target) is refused with `6A80`.
     */
    private static void targetOf(byte[] src, short off, byte[] out, short outOff) {
        short exponent = (short)(src[(short)(off + 3)] & 0xFF);
        if (exponent < 1 || exponent > 32 || (src[(short)(off + 2)] & 0x80) != 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        Util.arrayFillNonAtomic(out, outOff, (short) 32, (byte) 0);
        for (short k = 0; k < 3; k++) {
            short idx = (short)(32 - exponent + k);
            if (idx < 32) out[(short)(outOff + idx)] = src[(short)(off + 2 - k)];
        }
    }

    /** Four times the 32-byte big-endian number at `a[off]`, in place; one too large to hold becomes the largest there is. */
    private static void timesFour(byte[] a, short off) {
        short carry = 0;
        for (short i = 31; i >= 0; i--) {
            short v = (short)(((a[(short)(off + i)] & 0xFF) << 2) | carry);
            a[(short)(off + i)] = (byte) v;
            carry = (short)((v >> 8) & 0x03);
        }
        if (carry != 0) Util.arrayFillNonAtomic(a, off, (short) 32, (byte) 0xFF);
    }

    /**
     * TELL_TIME: the terminal's own clock, four bytes, big-endian seconds. A
     * note for this time in the field, written into the receipts and the log
     * entries made in it, so that the owner's screen can say to the second
     * when a payment was; the card trusts it for nothing (its day is counted
     * by block headers), so no key, PIN or state refuses it, and a terminal's
     * lie here is its own entry's. Answers nothing.
     */
    private void processTellTime(APDU apdu) {
        short dataLen = apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        if (dataLen != (short) 4) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, tapTime, (short) 0, (short) 4);
    }

    // -------------------------------------------------------------------------
    // Category 0x4x — Authentication
    // -------------------------------------------------------------------------

    private void processVerifyPin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        boolean sealed = sealedForm(buf);
        if (pinState[0] == (byte) 0) ISOException.throwIt(SW_PIN_NOT_SET);
        /* Blocked by the state byte OR the counter (D22). A CHANGE_PIN or SET_PIN torn after the PIN's
         * write and before its state byte leaves state 2 over a new PIN with full tries: the state
         * byte is the commit, and until it is written the card is as it was, blocked. */
        if (pinState[0] == (byte) 2 || pin.getTriesRemaining() == 0) ISOException.throwIt(SW_PIN_BLOCKED);

        short pinLen = apdu.setIncomingAndReceive();
        if (sealed) {
            pinLen = unseal(buf, pinLen, true);
            if (pinLen < 0) {
                /* An envelope that does not open is a wrong PIN, and costs a
                 * try as one does: without that, a terminal could put any
                 * point it liked to the PIN key as often as it liked. The
                 * PIN is shown eight random bytes, which it is not. */
                rng.generateData(seal, S_HASH, (short) 8);
                pin.check(seal, S_HASH, (byte) 8);
                failPinCheck();
            }
            if (pinLen != PIN_BLOCK_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            pinLen = unblockPin(buf, pinLen);
        }
        if (pinLen < PIN_MIN_LEN || pinLen > PIN_MAX_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        boolean ok = pin.check(buf, ISO7816.OFFSET_CDATA, (byte) pinLen);
        if (!ok) failPinCheck();
        // Nothing about spending is touched here: the PIN can be presented as
        // often as its holder, or a terminal holding it, likes. It arms the
        // no-PIN allowance to begin again at the next roll (D20), and nothing more.
        pinVerifiedFlag[0] = (byte) 1;
        armAllowance();
    }

    /**
     * A PIN check failed. End this session's authentication, then report the
     * tries left as 63CX, or, when the last try just went, move the card to
     * the blocked state and report 6983.
     *
     * The session ends first because that is what OwnerPIN.check does to its
     * own validated flag: a failed check resets it before anything else. The
     * applet gates on pinVerifiedFlag rather than on pin.isValidated(), so it
     * has to do the same by hand. Without it a session that verified and then
     * failed stayed verified, which let a card report itself blocked (GET_INFO
     * byte 7 = 2, VERIFY_PIN 6983) while it still signed and spent for that
     * session. The write is to a CLEAR_ON_DESELECT transient, so it allocates
     * nothing and touches no EEPROM (D10).
     *
     * The blocked transition lives here and nowhere else so that every
     * command that checks the PIN (VERIFY_PIN, CHANGE_PIN) blocks the card
     * the same way. Before this helper CHANGE_PIN exhausted the OwnerPIN
     * without ever setting pinState, leaving GET_INFO reporting "set" on a
     * card that could no longer verify (ENG-615). With the session ending
     * here, CHANGE_PIN can no longer be the exhausting try at all: it needs a
     * verified session, and the successful VERIFY_PIN that opens one resets
     * the counter. Sharing the helper keeps the two paths from drifting apart
     * again if that ever changes.
     */
    private void failPinCheck() {
        pinVerifiedFlag[0] = (byte) 0;
        byte remaining = pin.getTriesRemaining();
        if (remaining == 0) {
            pinState[0] = (byte) 2;
            ISOException.throwIt(SW_PIN_BLOCKED);
        }
        short sw = (short)(0x63C0 | (remaining & 0x0F));
        ISOException.throwIt(sw);
    }

    /**
     * SET_PIN: the PIN (4 to 8 bytes). Sets or replaces it, and unblocks.
     *
     * For an OPEN card: one with no owner and nothing unspent. No PIN
     * and no proof is needed, because there is nothing on the card, and
     * nobody whose card it is. On a card with an owner it is refused unless
     * the card has no PIN and the owner's grant is in this tap (ALLOW_LOAD):
     * ADD PIN (1.16), for a card that was set up with none, whatever it holds.
     * A card with a PIN is refused (`6A91`) whether it is empty or not: a
     * terminal that holds the PIN can empty a card whose balance fits within
     * the day's limit, and must not then be able to set a PIN of its own. The
     * owner uses CHANGE_PIN. A PIN that is added leaves the allowance at
     * nothing: every payment asks for it until the owner sets one.
     */
    private void processSetPin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        boolean sealed = sealedForm(buf);
        requireNotLocked();
        if (ownerSet[0] == (byte) 1) {
            if (pinState[0] != (byte) 0 || loadGrant[0] != (byte) 1) ISOException.throwIt(SW_OWNER_PROOF);
        } else {
            requireNothingUnspent();
        }

        short pinLen = apdu.setIncomingAndReceive();
        if (sealed) {
            pinLen = unseal(buf, pinLen, true);
            if (pinLen < 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            if (pinLen != PIN_BLOCK_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            pinLen = unblockPin(buf, pinLen);
        }
        if (pinLen < PIN_MIN_LEN || pinLen > PIN_MAX_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // a card with no PIN has no allowance (SET_LIMIT refuses one); it is nothing here all the same
        if (pinState[0] == (byte) 0) {
            Util.arrayCopy(ZERO, (short) 0, cardRecord, CARD_NOPIN_LIMIT_OFFSET, (short) 4);
            Util.arrayCopy(ZERO, (short) 0, cardRecord, CARD_NOPIN_SPENT_OFFSET, (short) 4);
        }
        /* The PIN, then its state byte, which is the commit (D22): torn between the two, a card that was
         * blocked is still blocked (VERIFY_PIN reads the byte), and one that had no PIN still has none. In
         * a transaction as well, for a chip whose OwnerPIN takes part in one; nothing relies on that. */
        JCSystem.beginTransaction();
        pin.update(buf, ISO7816.OFFSET_CDATA, (byte) pinLen);
        pinState[0] = (byte) 1;
        JCSystem.commitTransaction();
        // a new PIN has not been typed yet: any session that had verified the old one is over
        pinVerifiedFlag[0] = (byte) 0;
    }

    /**
     * CHANGE_PIN: the owner's proof's length (1), the proof (DER), then the new
     * PIN. No old PIN, no verified session, any PIN state, any funds.
     *
     * The owner's phone does not know the PIN, and the cards that most need it
     * changed are the blocked and the forgotten, where there is no old PIN to
     * give. A terminal that is handed the PIN has the old one and a verified
     * session, so neither could keep it from changing the PIN and locking the
     * holder out; the proof, over the new PIN, can. It sets the PIN, resets the
     * tries, unblocks a blocked card and ends any verified session. A wrong
     * proof costs no tries and changes nothing.
     */
    private void processChangePin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        boolean sealed = sealedForm(buf);
        requireNotLocked();
        if (ownerSet[0] != (byte) 1) ISOException.throwIt(SW_NO_OWNER);
        short dataLen = apdu.setIncomingAndReceive();
        if (sealed) {
            /* Sealed under the same sixteen bytes the proof is over: opening
             * it leaves them for the proof, which uses them up. What is
             * inside is the proof and then the PIN block; the proof is over
             * the PIN itself, as it is in the clear form. */
            dataLen = unseal(buf, dataLen, false);
            if (dataLen < 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            dataLen = unblockPin(buf, dataLen);
        }
        short at = requireOwnerProof(LABEL_CHANGE_PIN, buf, dataLen);
        short newLen = (short)(ISO7816.OFFSET_CDATA + dataLen - at);
        if (newLen < PIN_MIN_LEN || newLen > PIN_MAX_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        /* The PIN, then pinState 1, its commit byte (D22). The PIN's write refills the tries; a card torn
         * after it and before the byte has a new PIN that works under a state that still says blocked,
         * and every PIN gate reads the byte (VERIFY_PIN, requirePinIfSet, needsAllowance): it is blocked
         * until the owner's CHANGE_PIN is sent again, which is what the owner's phone does for a card
         * that answers blocked. In a transaction as well, for a chip whose OwnerPIN takes part in one. */
        JCSystem.beginTransaction();
        pin.update(buf, at, (byte) newLen);
        pinState[0] = (byte) 1;
        JCSystem.commitTransaction();
        pinVerifiedFlag[0] = (byte) 0;
    }

    /**
     * SET_OWNER: the owner's public key (65 bytes, 04 || X || Y). On a card
     * that already has an owner, the old owner's proof's length (1) and the
     * proof come first.
     *
     * Only with nothing unspent. On a card with NO owner no proof is needed:
     * it is open, and has nothing to protect. On a card WITH one the old
     * owner's proof is needed, empty or not, because the only thing that could
     * authorise a new owner is the old one, and a card whose terminal can empty
     * it must not be taken over by emptying it. The key is kept and never read
     * out: nothing here answers with it. One transaction: the key and the flag
     * that it is there.
     *
     * 2.0 (D20): the key may be followed by a block header (80 bytes), the tip
     * the phone setting the card up has seen. It is held to SET_HEADER's
     * checks before anything is written, and taken in the same transaction as
     * the key, with the rollover budget full: a card set up so never runs at
     * `now = 0`, never spends a first day on trust, and refuses to move its
     * clock back to any header older than its owner's. Without one the card
     * is as 1.20 had it.
     */
    private void processSetOwner(APDU apdu) {
        requireNotLocked();
        boolean owned = ownerSet[0] == (byte) 1;
        short dataLen = apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short at = ISO7816.OFFSET_CDATA;
        short len = dataLen;
        if (owned) {
            at = requireOwnerProof(LABEL_SET_OWNER, buf, dataLen);
            len = (short)(ISO7816.OFFSET_CDATA + dataLen - at);
        }
        requireNothingUnspent();
        // 2.0 (D20): the key, and after it, if the phone has one, a block header that anchors the card's clock
        boolean anchored = len == (short)(EC_POINT_LEN + HEADER_LEN);
        if (len != EC_POINT_LEN && !anchored) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (buf[at] != (byte) 0x04) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        short headerAt = (short)(at + EC_POINT_LEN);
        // the header's checks before anything is written: one without the work refuses the owner too (6A93)
        short how = anchored ? checkHeader(buf, headerAt) : (short) 0;
        JCSystem.beginTransaction();
        try {
            ownerKey.setW(buf, at, EC_POINT_LEN);
        } catch (CryptoException e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        ownerSet[0] = (byte) 1;
        if (anchored) {
            // the clock at a real block, and a full rollover budget: an owned card never starts at now = 0
            writeHeader(buf, headerAt, how);
            cardRecord[CARD_ROLLS_OFFSET] = (byte) 0;
        }
        JCSystem.commitTransaction();
    }

    /**
     * GET_NONCE: 16 fresh random bytes, for one owner's proof.
     *
     * No PIN: it changes nothing but the nonce, which a proof must name, and
     * asking again replaces it. A card with no owner has no use for one and
     * says so.
     */
    private void processGetNonce(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_P1] == (byte) 1) { processGetPinKey(apdu); return; }
        if (buf[ISO7816.OFFSET_P1] != (byte) 0) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        if (ownerSet[0] != (byte) 1) ISOException.throwIt(SW_NO_OWNER);
        rng.generateData(ownerNonce, (short) 0, OWNER_NONCE_LEN);
        nonceLive[0] = (byte) 1;
        Util.arrayCopyNonAtomic(ownerNonce, (short) 0, buf, (short) 0, OWNER_NONCE_LEN);
        apdu.setOutgoingAndSend((short) 0, OWNER_NONCE_LEN);
    }

    /**
     * GET_NONCE with P1 = 1: what a terminal needs to seal a PIN. Sixteen
     * fresh bytes (as GET_NONCE gives, and the same ones: one asking serves an
     * owner's proof and the sealing of the command that carries it), the PIN
     * key (33 bytes, compressed), and the card's own key's signature over
     * SHA-256("CashuCard/pinkey" || that key) (64 bytes, BIP-340), by which a
     * terminal that knows the card's key knows the PIN key is the card's.
     *
     * No PIN and no owner: a card with no owner has a PIN to be set. The
     * signature is made once, at the first asking, and kept.
     */
    private void processGetPinKey(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short at = OWNER_NONCE_LEN;
        // the key, compressed in working room of its own (as GET_PUBKEY does the card's own in the answer), then put after the nonce's place
        short len = toCompressed(seal, pinPubKey.getW(seal, (short) 0));
        Util.arrayCopyNonAtomic(seal, (short) 0, buf, at, len);
        short sigAt = (short)(at + len);
        if (pinKeySig[0] != (byte) 1) {
            sha.reset();
            sha.update(PINKEY_LABEL, (short) 0, (short) PINKEY_LABEL.length);
            sha.doFinal(buf, at, len, scratch, X_MSG);
            schnorrHW.sign(cardPrivKey, cardPubKey, scratch, X_MSG, buf, sigAt);
            JCSystem.beginTransaction();
            Util.arrayCopy(buf, sigAt, pinKeySig, (short) 1, (short) 64);
            pinKeySig[0] = (byte) 1;
            JCSystem.commitTransaction();
        } else {
            Util.arrayCopyNonAtomic(pinKeySig, (short) 1, buf, sigAt, (short) 64);
        }
        rng.generateData(ownerNonce, (short) 0, OWNER_NONCE_LEN);
        nonceLive[0] = (byte) 1;
        Util.arrayCopyNonAtomic(ownerNonce, (short) 0, buf, (short) 0, OWNER_NONCE_LEN);
        apdu.setOutgoingAndSend((short) 0, (short)(sigAt + 64));
    }

    /**
     * Whether a command that carries a PIN is in its sealed form (P1 = 1) or
     * its clear one (P1 = 0). Anything else is refused.
     */
    private static boolean sealedForm(byte[] buf) {
        byte p1 = buf[ISO7816.OFFSET_P1];
        if (p1 != (byte) 0 && p1 != (byte) 1) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        return p1 == (byte) 1;
    }

    /**
     * A sealed command's data opened, in place.
     *
     * A PIN typed at a terminal crossed the air to the card as it was typed,
     * and whoever was listening had it. A sealed command carries instead
     *
     *   the sender's public key for this one message (65, 04 || X || Y, secp256k1)
     *   the data under a keystream
     *   a tag (16)
     *
     * The secret is the x of the point the sender's key and the card's PIN
     * key share. A block is SHA-256 of
     *
     *   "CashuCard/seal" || i (1) || the secret (32) || the sender's key (65)
     *     || the card's sixteen bytes (16) || the instruction (1) [ || more ]
     *
     * Block 0, with the sealed bytes as `more`, is the tag (its first
     * sixteen bytes), and it is checked before anything is opened. Blocks
     * 1, 2, ... are the keystream, thirty-two bytes each.
     *
     * The sixteen bytes are the card's (GET_NONCE), fresh at each asking and
     * good once: what was heard at one tap opens nothing at another, and
     * cannot be put to the card again. The instruction is in the sum, so an
     * envelope made for one command is none for another. `spend`: this
     * opening uses the sixteen bytes up; an owner's command leaves them for
     * its proof, which is over the same bytes and uses them up itself. An
     * envelope that does not open has used them up either way.
     *
     * @return the length of the data, now clear and at OFFSET_CDATA; or -1
     *         where the envelope does not open (the point is no point, or the
     *         tag is not this sum's)
     */
    private short unseal(byte[] buf, short len, boolean spend) {
        if (len < (short)(EC_POINT_LEN + 1 + SEAL_TAG_LEN)) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        boolean live = nonceLive[0] == (byte) 1;
        if (spend) nonceLive[0] = (byte) 0;
        if (!live) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        short e = ISO7816.OFFSET_CDATA;
        short n = (short)(len - EC_POINT_LEN - SEAL_TAG_LEN);
        short ct = (short)(e + EC_POINT_LEN);
        short tag = (short)(ct + n);
        seal[S_INS] = buf[ISO7816.OFFSET_INS];
        boolean good = false;
        try {
            if (buf[e] == (byte) 0x04) {
                short got = schnorrHW.agree(pinPrivKey, buf, e, EC_POINT_LEN, seal, S_POINT);
                if (got == EC_POINT_LEN && seal[S_POINT] == (byte) 0x04) {
                    sealBlock(buf, e, (byte) 0, buf, ct, n);
                    good = sameBytes(seal, S_HASH, buf, tag, SEAL_TAG_LEN);
                }
            }
        } catch (RuntimeException x) {
            /* Whatever the key agreement throws for a point that is no point
             * (a CryptoException on one platform, something else on another),
             * the envelope does not open: it is not an error of the card's. */
            good = false;
        }
        if (!good) {
            nonceLive[0] = (byte) 0;
            return (short) -1;
        }
        short i = 1;
        for (short at = 0; at < n; at += (short) 32) {
            sealBlock(buf, e, (byte) i, buf, (short) 0, (short) 0);
            for (short k = 0; k < (short) 32 && (short)(at + k) < n; k++) {
                buf[(short)(ct + at + k)] ^= seal[(short)(S_HASH + k)];
            }
            i++;
        }
        moveDown(buf, ct, e, n);
        return n;
    }

    /** `len` bytes of `buf` moved from `from` down to `to` (to < from), a byte at a time: the two ranges may overlap, and nothing is asked of how a copy treats that. */
    private static void moveDown(byte[] buf, short from, short to, short len) {
        for (short k = 0; k < len; k++) {
            buf[(short)(to + k)] = buf[(short)(from + k)];
        }
    }

    /** One block of a sealed command's sum (see `unseal`), into seal[S_HASH]. The shared point is in seal[S_POINT], the instruction in seal[S_INS]. */
    private void sealBlock(byte[] buf, short e, byte i, byte[] more, short moreAt, short moreLen) {
        seal[S_I] = i;
        sha.reset();
        sha.update(SEAL_LABEL, (short) 0, (short) SEAL_LABEL.length);
        sha.update(seal, S_I, (short) 1);
        sha.update(seal, (short)(S_POINT + 1), (short) 32);
        sha.update(buf, e, EC_POINT_LEN);
        sha.update(ownerNonce, (short) 0, OWNER_NONCE_LEN);
        sha.update(seal, S_INS, (short) 1);
        sha.doFinal(more, moreAt, moreLen, seal, S_HASH);
    }

    /**
     * The PIN block that ends a sealed command's data (its length, the PIN,
     * zeros to eight: nine bytes) taken out, and the PIN itself put in its
     * place, so that what follows reads the data as the clear form has it.
     *
     * @return the data's new length
     */
    private short unblockPin(byte[] buf, short len) {
        if (len < PIN_BLOCK_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short block = (short)(ISO7816.OFFSET_CDATA + len - PIN_BLOCK_LEN);
        short pinLen = (short)(buf[block] & 0xFF);
        if (pinLen < PIN_MIN_LEN || pinLen > PIN_MAX_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        moveDown(buf, (short)(block + 1), block, pinLen);
        return (short)(len - PIN_BLOCK_LEN + pinLen);
    }

    /**
     * ALLOW_LOAD: the owner's proof's length (1) and the proof, over
     * "CashuCard/load" and no value.
     *
     * For the rest of this tap, and only this tap (the grant is in transient
     * memory), LOAD_PROOF and CLEAR_SPENT need no verified PIN. The owner's
     * phone adds funds without knowing it. It lets nothing else through: not
     * SPEND_PROOF, and nothing the PIN opens. A till still writes change back
     * under the verified PIN.
     */
    private void processAllowLoad(APDU apdu) {
        requireNotLocked();
        if (ownerSet[0] != (byte) 1) ISOException.throwIt(SW_NO_OWNER);
        short dataLen = apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short at = requireOwnerProof(LABEL_LOAD, buf, dataLen);
        if ((short)(ISO7816.OFFSET_CDATA + dataLen) != at) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        loadGrant[0] = (byte) 1;
    }

    /**
     * Refuses unless the data is the owner's proof for this command: its
     * length (1), then an ECDSA signature (P-256, SHA-256, DER) by the owner
     * key over
     *
     *   label || the nonce just given || everything that follows the proof
     *
     * Answers where that value begins in the buffer, so a command can read
     * what the proof covered and nothing else, and check its length.
     *
     * The nonce is spent by being tried: a wrong proof does not leave it for
     * another go, and a proof made for an earlier nonce, or presented with none
     * given in this tap, fails. `6A91` for all of those and for a proof that is
     * missing or is not made of a length and that many bytes. `6A90` on a card
     * with no owner. Nothing here touches the PIN's tries: a wrong proof is not
     * a wrong PIN.
     */
    private short requireOwnerProof(byte[] label, byte[] buf, short dataLen) {
        if (ownerSet[0] != (byte) 1) ISOException.throwIt(SW_NO_OWNER);
        boolean live = nonceLive[0] == (byte) 1;
        nonceLive[0] = (byte) 0;
        if (!live || dataLen < (short) 1) ISOException.throwIt(SW_OWNER_PROOF);
        short proofLen = (short)(buf[ISO7816.OFFSET_CDATA] & 0xFF);
        if (proofLen < 1 || proofLen > SIG_DER_MAX || dataLen < (short)(1 + proofLen)) ISOException.throwIt(SW_OWNER_PROOF);
        short proofAt = (short)(ISO7816.OFFSET_CDATA + 1);
        short valueAt = (short)(proofAt + proofLen);
        short valueLen = (short)(dataLen - 1 - proofLen);
        boolean good = false;
        try {
            ecdsa.init(ownerKey, Signature.MODE_VERIFY);
            ecdsa.update(label, (short) 0, (short) label.length);
            ecdsa.update(ownerNonce, (short) 0, OWNER_NONCE_LEN);
            good = ecdsa.verify(buf, valueAt, valueLen, buf, proofAt, proofLen);
        } catch (CryptoException e) {
            good = false;
        }
        if (!good) ISOException.throwIt(SW_OWNER_PROOF);
        // the owner has seen the card: the no-PIN allowance may begin again at the next roll (D20)
        armAllowance();
        return valueAt;
    }

    // -------------------------------------------------------------------------
    // Category 0x5x — Admin
    // -------------------------------------------------------------------------

    /**
     * LOCK_CARD: the owner's proof's length (1) and the proof, P2 = the
     * confirming byte.
     *
     * For good, and so for the owner alone: the PIN must be set and verified,
     * and the owner's proof is needed as well, under a label of its own. It
     * was once the PIN alone, or nothing on a card that had none, and any
     * reader could lock a card, or a terminal that had been given the PIN.
     * A card with no PIN, or no owner, cannot be locked.
     */
    private void processLockCard(APDU apdu) {
        requirePinSetAndVerified();
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_P2] != LOCK_CONFIRM_BYTE) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        if (cardLocked[0] == (byte) 1) ISOException.throwIt(SW_CARD_LOCKED);
        short dataLen = apdu.setIncomingAndReceive();
        short at = requireOwnerProof(LABEL_LOCK, buf, dataLen);
        if ((short)(ISO7816.OFFSET_CDATA + dataLen) != at) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        cardLocked[0] = (byte) 1;
    }

    /**
     * RESET_CARD (1.17): P1 = 0, P2 = the confirming byte (0xAD), and the owner's
     * proof's length (1) and the proof, over "CashuCard/reset" and no value.
     *
     * The card as it was out of its packet, for another person to set up: no PIN
     * (three tries), no owner, no record, no limits, no allowance, no log, no
     * receipts, no change owed or signature kept, and a new key pair of its own
     * (the old key tied the last owner's payments to the next one's), and its NFC
     * tag on (1.19). It keeps its clock (the time and the header hash it was shown;
     * the ratchet's bits go to nothing, as SET_CARD does) and its software.
     *
     * Order of the refusals: `6B00` for the P1 and P2; `6A90` with no owner; the
     * proof (`6A91`; `6700` for anything after it); `6982` on a LOCKED card whose
     * PIN has not been verified in this tap (a locked card resets for the owner's
     * proof AND the PIN); `6A8D` with anything unspent on the card. A blocked PIN
     * is no bar: the owner is resetting, not unblocking.
     *
     * Not one transaction, and not a long one: a chip's commit buffer holds about
     * a dozen writes. The bulk is written outside any (the places, the log, the
     * receipts, the openings, the record, the new keys), and the three things that
     * say who the card is (locked, the PIN, the owner), the change note and the
     * tag's switch are flipped in a transaction of five bytes, last of all. A card that leaves the
     * field before that has the owner still, and the owner may reset it again; one
     * that leaves after it is a new card, with at worst the old PIN's bytes and
     * tries not yet cleared (nothing reads them with no PIN set, and SET_PIN
     * replaces them). The lock goes first, then the PIN, then the owner, so that a
     * locked card torn in the middle is not left locked with its PIN gone.
     */
    private void processResetCard(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_P1] != (byte) 0 || buf[ISO7816.OFFSET_P2] != RESET_CONFIRM_BYTE) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        if (ownerSet[0] != (byte) 1) ISOException.throwIt(SW_NO_OWNER);
        short dataLen = apdu.setIncomingAndReceive();
        short at = requireOwnerProof(LABEL_RESET, buf, dataLen);
        if ((short)(ISO7816.OFFSET_CDATA + dataLen) != at) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (cardLocked[0] == (byte) 1 && pinVerifiedFlag[0] != (byte) 1) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        requireNothingUnspent();

        // the places: the spent ones freed, as CLEAR_SPENT does it (nothing else is in one, and nothing unspent)
        freeSpent();
        // and the mint's proofs that were kept with them (1.20): none is a place's now, and none is for the next owner to read
        if (dleq != null) Util.arrayFillNonAtomic(dleq, (short) 0, (short)(MAX_PROOFS * DLEQ_LEN), (byte) 0);
        // nothing of the last owner's taps: the log, the receipts, the change openings and the last signature (the burn list is the places of a payment finished, and nothing reads it)
        Util.arrayFillNonAtomic(cardLog, (short) 0, LOG_LEN, (byte) 0);
        Util.arrayFillNonAtomic(cardReceipts, (short) 0, RECEIPTS_LEN, (byte) 0);
        Util.arrayFillNonAtomic(changeOpen, (short) 0, (short)(CHANGE_MOST * OPEN_LEN), (byte) 0);
        Util.arrayFillNonAtomic(openState, (short) 0, CHANGE_MOST, (byte) 0);
        Util.arrayFillNonAtomic(lastSig, (short) 0, (short) 65, (byte) 0);
        /* The record, but for the clock: the time and the header's hash stay (the
         * bits before the hash, the ratchet, go with the rest). */
        Util.arrayFillNonAtomic(cardRecord, (short) 0, CARD_HEADER_OFFSET, (byte) 0);
        Util.arrayFillNonAtomic(cardRecord, (short)(CARD_HEADER_OFFSET + 32), (short)(CARD_NOW_OFFSET - CARD_HEADER_OFFSET - 32), (byte) 0);
        Util.arrayFillNonAtomic(cardRecord, CARD_WINDOW_OFFSET, (short)(CARD_RECORD_LEN - CARD_WINDOW_OFFSET), (byte) 0);
        /* New keys, made as the constructor makes them (the same key objects, with
         * their curve set, drawn again). The signature that vouched for the old PIN
         * key is let go first, so that no card is left with a signature that is not
         * over the key it holds: it is made again at the first asking. */
        pinKeySig[0] = (byte) 0;
        cardKeyPair.genKeyPair();
        pinKeyPair.genKeyPair();

        // who the card is, last of all
        JCSystem.beginTransaction();
        cardLocked[0] = (byte) 0;
        pinState[0] = (byte) 0;
        changeDue[0] = (byte) 0;
        ownerSet[0] = (byte) 0;
        tagOff[0] = (byte) 0;
        JCSystem.commitTransaction();

        // the old owner's key and PIN overwritten (nothing reads them now), and the PIN's tries back
        ownerKey.setW(P256_G, (short) 0, EC_POINT_LEN);
        pin.update(ZERO, (short) 0, (byte) 4);
        // and this tap is a new card's: nothing the owner or the PIN had given in it, and a log to begin
        pinVerifiedFlag[0] = (byte) 0;
        loadGrant[0] = (byte) 0;
        changeGrant[0] = (byte) 0;
        tapOpen[0] = (byte) 0;
        tapOpen[1] = (byte) 0;
    }

    /**
     * SET_TAG (1.19): P1 = 0 the card answers as an NFC tag, P1 = 1 it does not; P2 = 0. The data is the owner's
     * proof's length (1), the proof (DER) and then one byte, the same as P1, which is what the proof is over:
     * "CashuCard/tag", the nonce the card gave and that byte.
     *
     * The owner's alone, and no PIN: a terminal that has been handed the PIN must not be able to turn the tag off
     * (or on) for a holder who keeps the card in a phone's wallet case and would otherwise be offered the app
     * every time the screen wakes. Allowed with money on the card. The tag is on for a new card, a card with no
     * owner and a card just reset; asking for the state it has answers 9000 and writes nothing.
     *
     * Order of the refusals, with the words the neighbouring commands use: `6B00` for a P1 or P2 not those;
     * `6986` on a locked card; `6A90` with no owner; the proof (`6A91`: no nonce asked for in this tap, or a
     * proof that is not the owner's for this label, this nonce and this byte; it costs no PIN try); `6700` for
     * anything but one byte after the proof; `6B00` for a byte that is not P1.
     */
    private void processSetTag(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte want = buf[ISO7816.OFFSET_P1];
        if ((want != (byte) 0 && want != (byte) 1) || buf[ISO7816.OFFSET_P2] != (byte) 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        requireNotLocked();
        if (ownerSet[0] != (byte) 1) ISOException.throwIt(SW_NO_OWNER);
        short dataLen = apdu.setIncomingAndReceive();
        short at = requireOwnerProof(LABEL_TAG, buf, dataLen);
        if ((short)(ISO7816.OFFSET_CDATA + dataLen) != (short)(at + 1)) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (buf[at] != want) ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if (tagOff[0] != want) tagOff[0] = want;
    }

    /** Whether the card is to answer as an NFC tag: asked by the tag applet at each of its selections (`TagSwitch`). */
    public boolean tagIsOn() {
        return tagOff[0] == (byte) 0;
    }

    /**
     * The tag applet's way to ask `tagIsOn`. The bit is public (GET_INFO with P1 = 2 says it to anyone, and so does the tag), so any
     * caller is answered; the one parameter is 0.
     */
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        return parameter == (byte) 0 ? this : null;
    }

    // -------------------------------------------------------------------------
    // Guard helpers
    // -------------------------------------------------------------------------

    private void requireNotLocked() {
        if (cardLocked[0] == (byte) 1) ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    /**
     * D13 gate, for what is still the PIN's alone (SPEND_ALL_AGAIN, a record
     * written to an open card). Fires whenever a PIN exists and this session has not verified
     * it — and "exists" includes the blocked state (pinState 2), from which
     * VERIFY_PIN can never succeed. The earlier form checked `pinState == 1`,
     * so three wrong guesses turned the card into a no-PIN bearer card:
     * every gated command opened up the moment the PIN was blocked (ENG-615).
     */
    private void requirePinIfSet() {
        // a blocked state refuses even a session that says verified (D22): the byte, not the flag, is the PIN's commit
        if (pinState[0] == (byte) 2 || (pinState[0] != (byte) 0 && pinVerifiedFlag[0] != (byte) 1)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /**
     * Whether a payment signed now would be signed with no PIN on a card that
     * has one (1.16): a PIN is set and has not been given in this tap. A card
     * with no PIN is not in this case; it pays without one, and has no
     * allowance. (The owner's grants sign nothing: a payment is the PIN's, or
     * the allowance's.)
     */
    private boolean needsAllowance() {
        // a blocked card's verified flag counts for nothing (D22): it goes to the allowance, which a blocked card does not have
        return pinState[0] != (byte) 0 && (pinVerifiedFlag[0] != (byte) 1 || pinState[0] == (byte) 2);
    }

    /**
     * SPEND_ALL_SIGN's gate (1.16, in place of D13's "a PIN is set and has not
     * been given: refused"). Answers whether the payment is signed with no PIN
     * on a card that has one (and so counts against the allowance), and
     * refuses with `6A94` unless it may be.
     *
     * No PIN set: signed (false). The PIN given in this tap: signed (false).
     * A PIN set and not given: signed under the allowance only, when the PIN
     * is not blocked, there is an allowance, the day's window is current (or
     * has not begun: a card with no header counts from set-up), and what has
     * been signed for with no PIN in it, and this payment (the pieces less the
     * change the card makes, `allNet`: what leaves the card for good), come to
     * no more than the allowance. Over it the PIN is asked for the WHOLE
     * payment, however little is over: a payment is never split. A blocked card
     * has no allowance: nothing is signed for with no PIN until the owner has
     * unblocked it. Refused, the payment in hand is given up, as a payment over
     * a limit is, and nothing is written in the log: not a refusal over a
     * limit, and no part of a run of them. What the day's no-PIN spending would
     * be is left in scratch (X_NOPIN) for the commit.
     */
    private boolean requireAllowanceOrPin() {
        if (!needsAllowance()) return false;
        /* blocked by its state byte or by its counter (a failed check torn before failPinCheck wrote state 2,
         * D23): no allowance */
        if (pinState[0] != (byte) 1 || pin.getTriesRemaining() == 0 || isZero(cardRecord, CARD_NOPIN_LIMIT_OFFSET, (short) 4)) {
            allState[0] = (byte) 0;
            ISOException.throwIt(SW_PIN_NEEDED);
        }
        // the allowance begins again with the day only when the day rolls and it is armed (D20)
        if (windowRolls() && (cardRecord[CARD_ARMED_OFFSET] == (byte) 1 || windowNotBegun())) {
            Util.arrayFillNonAtomic(scratch, X_NOPIN, (short) 4, (byte) 0);
        } else {
            Util.arrayCopyNonAtomic(cardRecord, CARD_NOPIN_SPENT_OFFSET, scratch, X_NOPIN, (short) 4);
        }
        if (addUint32Carry(scratch, X_NOPIN, allNet, (short) 0) != 0
            || cmpUint32(scratch, X_NOPIN, cardRecord, CARD_NOPIN_LIMIT_OFFSET) > 0) {
            allState[0] = (byte) 0;
            ISOException.throwIt(SW_PIN_NEEDED);
        }
        return true;
    }

    /**
     * For what writes value onto the card: a PIN must exist and be verified.
     * requirePinIfSet lets a card with no PIN through, which is right for a
     * spend on an empty card and wrong for loading one.
     */
    private void requirePinSetAndVerified() {
        if (pinState[0] != (byte) 1 || pinVerifiedFlag[0] != (byte) 1) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /**
     * For what puts a piece on the card: a PIN that is set, and either typed in
     * this tap, or waived by the owner for this tap (ALLOW_LOAD), or this tap
     * being the one after a payment (changeGrant: the change comes back with
     * no PIN). A blocked PIN waives nothing: the owner unblocks the card first.
     *
     * A card with no PIN (1.16) has none to type, and is put on by whoever
     * holds it: a top-up needs nobody's leave, as spending it needs nobody's.
     * What is the owner's alone stays so (the limits, ADD PIN, the mint, the
     * lock): those ask for the owner's proof, not a PIN.
     */
    private void requireLoadAuthority() {
        if (pinState[0] == (byte) 0) return;
        boolean granted = loadGrant[0] == (byte) 1 || changeGrant[0] == (byte) 1;
        if (pinState[0] != (byte) 1 || (pinVerifiedFlag[0] != (byte) 1 && !granted)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /** `6A8D` if any slot holds an unspent piece: what is set only on an empty card is not set under one. */
    private void requireNothingUnspent() {
        for (short i = 0; i < MAX_PROOFS; i++) {
            if (proofStorage[(short)(i * PROOF_SIZE + PROOF_STATUS_OFFSET)] == STATUS_UNSPENT) {
                ISOException.throwIt(SW_CARD_IN_USE);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    /** Compare two big-endian uint32s: negative, zero or positive as a is below, equal to or above b. */
    private static short cmpUint32(byte[] a, short aOff, byte[] b, short bOff) {
        for (short i = 0; i < 4; i++) {
            short x = (short)(a[(short)(aOff + i)] & 0xFF);
            short y = (short)(b[(short)(bOff + i)] & 0xFF);
            if (x != y) return (short)(x - y);
        }
        return (short) 0;
    }

    /**
     * Big-endian 32-bit add that says whether it wrapped: acc[accOff..+3] +=
     * src[srcOff..+3]; answers the carry out of the top byte, 0 or 1. A sum
     * that carries is past what four bytes hold, and so past any limit.
     */
    private static short addUint32Carry(byte[] acc, short accOff, byte[] src, short srcOff) {
        short carry = 0;
        for (short i = 3; i >= 0; i--) {
            short sum = (short) ((short)(acc[(short)(accOff + i)] & 0xFF)
                               + (short)(src[(short)(srcOff + i)] & 0xFF)
                               + carry);
            acc[(short)(accOff + i)] = (byte) (sum & 0xFF);
            carry = (short) ((sum >> 8) & 0xFF);
        }
        return carry;
    }

    // ---- the log ---------------------------------------------------------------

    /**
     * Where this tap's entry is in the log, begun if nothing in this time in
     * the field has been written down yet: the count of taps goes up by one,
     * and the place the ring gives it is cleared and given the clock. Called
     * inside a transaction; the caller marks the tap open once it has
     * committed (`tapOpen`, which is RAM and would not be undone with it).
     */
    private short logEntry() {
        if (tapOpen[0] != (byte) 1) addUint32Stop(cardLog, LOG_TAPS_OFFSET, ONE, (short) 0);
        // the tap numbered n is at (n - 1) mod 8: eight divides 256, so the last byte says it
        short at = (short)(LOG_HEAD_LEN + (short)(((short)((cardLog[(short)(LOG_TAPS_OFFSET + 3)] & 0xFF) - 1) & 0x07) * LOG_ENTRY_LEN));
        if (tapOpen[0] != (byte) 1) {
            Util.arrayFillNonAtomic(cardLog, at, LOG_ENTRY_LEN, (byte) 0);
            Util.arrayCopy(cardRecord, CARD_NOW_OFFSET, cardLog, (short)(at + LOG_E_TIME), (short) 4);
            // the time the terminal told at this tap (TELL_TIME), beside the card's own: a note, trusted for nothing
            Util.arrayCopy(tapTime, (short) 0, cardLog, (short)(at + LOG_E_TOLD), (short) 4);
        }
        return at;
    }

    /**
     * A spend that is over a limit: written down, and then refused with `sw`.
     *
     * A terminal that keeps to the limits never causes one: what the card has
     * left of its day and of its tap is in GET_INFO, to be read before
     * anything is asked for. So a refusal is a terminal that asked for more
     * than it was allowed, and a run of three inside one tap's ten seconds of
     * the card's clock is one trying the limit again and again: the tap is
     * marked, and the count of such runs goes up. (Ten seconds of the clock,
     * and not three in a row at any distance: a terminal that does not know
     * of a limit and is refused once at each of three visits is not that.)
     */
    private void refuseOverLimit(short sw) {
        JCSystem.beginTransaction();
        short entry = logEntry();
        addUint32Stop(cardLog, LOG_REFUSED_OFFSET, ONE, (short) 0);
        if (cardLog[(short)(entry + LOG_E_REFUSED)] != (byte) 0xFF) cardLog[(short)(entry + LOG_E_REFUSED)]++;
        /* A new run: the first refusal there has been, or ten seconds on from
         * the last run's first, or a clock that is behind that. And every
         * refusal on a card that has seen no block header yet (now = 0): with
         * no clock, three visits a week apart would read as one run of three,
         * and a false mark is worse than none. */
        if (cardLog[LOG_RUN_OFFSET] == (byte) 0
            || isZero(cardRecord, CARD_NOW_OFFSET, (short) 4)
            || cmpUint32(cardRecord, CARD_NOW_OFFSET, cardLog, LOG_RUN_AT_OFFSET) < 0
            || windowIsOver(cardLog, LOG_RUN_AT_OFFSET, TAP_SECONDS)) {
            Util.arrayCopy(cardRecord, CARD_NOW_OFFSET, cardLog, LOG_RUN_AT_OFFSET, (short) 4);
            cardLog[LOG_RUN_OFFSET] = (byte) 1;
        } else if (cardLog[LOG_RUN_OFFSET] != (byte) 0xFF) {
            cardLog[LOG_RUN_OFFSET]++;
        }
        short run = (short)(cardLog[LOG_RUN_OFFSET] & 0xFF);
        if (run == TAMPER_RUN) addUint32Stop(cardLog, LOG_TAMPERS_OFFSET, ONE, (short) 0);
        if (run >= TAMPER_RUN) cardLog[(short)(entry + LOG_E_FLAGS)] |= LOG_FLAG_TAMPER;
        JCSystem.commitTransaction();
        tapOpen[0] = (byte) 1;
        ISOException.throwIt(sw);
    }

    /**
     * GET_LOG: the card's own account of its taps. Sixteen bytes of counts
     * (taps, sats signed for, spends refused for being over a limit, runs of
     * three such refusals: four bytes each, big-endian), then the taps the
     * ring holds, newest first, twenty bytes each: the clock (the last block
     * header's time) when it began (4), sats signed for in it (4), pieces
     * signed (1), spends refused (1), flags (1; bit 0, a run of three refusals
     * reached or gone past in it), pieces put on (1), sats put on (4), and the
     * time the terminal told at the tap (4; TELL_TIME, a note trusted for
     * nothing).
     *
     * For whoever the card is open to: the PIN verified in this tap, or the
     * owner's grant (ALLOW_LOAD). It says when the card was used and for how
     * much, which is more than a stranger's reader should be told. A card
     * with no PIN and no owner yet has nothing in it, and answers anyone; one
     * with an owner and no PIN (1.16) has the owner's grant and no other.
     */
    private void processGetLog(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_P1] == (byte) 1) { processGetReceipts(apdu); return; }
        if (buf[ISO7816.OFFSET_P1] != (byte) 0) ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        // the PIN verified in this tap or the owner's grant; a card with no PIN (1.16) shows its log to whoever holds it
        if (pinState[0] != (byte) 0 && pinVerifiedFlag[0] != (byte) 1 && loadGrant[0] != (byte) 1) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        Util.arrayCopyNonAtomic(cardLog, (short) 0, buf, (short) 0, LOG_ANSWER_HEAD);
        short held = LOG_ENTRIES;
        if (isZero(cardLog, LOG_TAPS_OFFSET, (short) 3) && (short)(cardLog[(short)(LOG_TAPS_OFFSET + 3)] & 0xFF) < LOG_ENTRIES) {
            held = (short)(cardLog[(short)(LOG_TAPS_OFFSET + 3)] & 0xFF);
        }
        short newest = (short)(((short)((cardLog[(short)(LOG_TAPS_OFFSET + 3)] & 0xFF) - 1)) & 0x07);
        short out = LOG_ANSWER_HEAD;
        for (short k = 0; k < held; k++) {
            short at = (short)(LOG_HEAD_LEN + (short)(((short)(newest - k) & 0x07) * LOG_ENTRY_LEN));
            Util.arrayCopyNonAtomic(cardLog, at, buf, out, LOG_ENTRY_LEN);
            out += LOG_ENTRY_LEN;
        }
        apdu.setOutgoingAndSend((short) 0, out);
    }

    /**
     * GET_LOG with P1 = 1: the receipts. The count of every payment the card
     * has signed (4), then up to three receipts of RECEIPT_LEN, newest first,
     * beginning P2 back from the newest (P2 = 0 is the newest itself; one at
     * or past what the ring holds answers the count alone).
     *
     * By the owner's grant, given in this tap, and nothing else: not the PIN,
     * which a till has. (A card with no PIN and no owner yet has signed nothing.)
     */
    private void processGetReceipts(APDU apdu) {
        // the owner's grant; a card with no PIN (1.16) shows its receipts to whoever holds it
        if (pinState[0] != (byte) 0 && loadGrant[0] != (byte) 1) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        short back = (short)(buf[ISO7816.OFFSET_P2] & 0xFF);
        short held = RECEIPTS;
        if (isZero(cardReceipts, (short) 0, (short) 3) && (short)(cardReceipts[3] & 0xFF) < RECEIPTS) {
            held = (short)(cardReceipts[3] & 0xFF);
        }
        Util.arrayCopyNonAtomic(cardReceipts, (short) 0, buf, (short) 0, RECEIPTS_HEAD);
        short out = RECEIPTS_HEAD;
        // the payment numbered n is at (n - 1) mod 16: sixteen divides 256, so the last byte of the count says it
        short newest = (short)(((short)(cardReceipts[3] & 0xFF) - 1) & 0x0F);
        for (short k = back; k < held && k < (short)(back + 3); k++) {
            short at = (short)(RECEIPTS_HEAD + (short)(((short)(newest - k) & 0x0F) * RECEIPT_LEN));
            Util.arrayCopyNonAtomic(cardReceipts, at, buf, out, RECEIPT_LEN);
            out += RECEIPT_LEN;
        }
        apdu.setOutgoingAndSend((short) 0, out);
    }

    /**
     * Whether the window has run its day: `now` is at least 86 400 seconds past
     * the window's start. A window whose end is past what four bytes hold never
     * ends. Works in scratch[X_NUM], which nothing live is using here.
     */
    private boolean dayIsOver() {
        return windowIsOver(cardRecord, CARD_WINDOW_OFFSET, DAY_SECONDS);
    }

    /**
     * Whether the payment in hand now begins a new day (2.0, D20): the day is over, and the window has rolled fewer
     * times since the owner's last REFRESH (or anchored SET_OWNER) than the rollover budget allows. Past the budget
     * the window stays where it is, and what was signed for in it still counts: a terminal that holds the PIN and
     * walks the clock forward with headers gets the budget's days and no more, until the owner's phone has seen
     * the card again. A budget set under the rolls already spent stops the day at once.
     *
     * And only a payment that moves value (D26): `allNet`, what leaves the card for good, the pieces less the card's
     * own change, is not 0. A payment of nothing begins no day, first or not, and spends no roll; it is counted, as
     * nothing, in the window as it stands. Without that a reader with no PIN, walking real headers, spent the budget a
     * roll a tap at no cost, and left the owner one day's limit until the next REFRESH. (`allNet` is SIGN's: BEGIN asks
     * the day only of a sum that wraps, which is refused whatever the day.)
     */
    private boolean windowRolls() {
        if (isZero(allNet, (short) 0, (short) 4) || !dayIsOver()) return false;
        // a window not yet begun begins whatever the budget: that is no roll
        if (windowNotBegun()) return true;
        byte budget = cardRecord[CARD_BUDGET_OFFSET];
        if (budget == (byte) 0) budget = ROLL_BUDGET_DEFAULT;
        return (short)(cardRecord[CARD_ROLLS_OFFSET] & 0xFF) < budget;
    }

    /** Whether the day's window has never begun (its start is 0): its first beginning is no roll (D20). */
    private boolean windowNotBegun() {
        return isZero(cardRecord, CARD_WINDOW_OFFSET, (short) 4);
    }

    /** A PIN or an owner's proof has been given: the no-PIN allowance may begin again at the next roll (D20). One byte, written once. */
    private void armAllowance() {
        if (cardRecord[CARD_ARMED_OFFSET] != (byte) 1) cardRecord[CARD_ARMED_OFFSET] = (byte) 1;
    }

    /** Whether the window that began at `from[windowAt]` and lasts `seconds` (4, big-endian) has ended by the card's clock. */
    private boolean windowIsOver(byte[] from, short windowAt, byte[] seconds) {
        Util.arrayCopyNonAtomic(from, windowAt, scratch, X_NUM, (short) 4);
        if (addUint32Carry(scratch, X_NUM, seconds, (short) 0) != 0) return false;
        return cmpUint32(cardRecord, CARD_NOW_OFFSET, scratch, X_NUM) >= 0;
    }

    /** `acc` += `src`, four bytes each, big-endian; a sum past the top of four bytes stops there. */
    private static void addUint32Stop(byte[] acc, short accOff, byte[] src, short srcOff) {
        if (addUint32Carry(acc, accOff, src, srcOff) != 0) {
            acc[accOff] = (byte) 0xFF; acc[(short)(accOff + 1)] = (byte) 0xFF;
            acc[(short)(accOff + 2)] = (byte) 0xFF; acc[(short)(accOff + 3)] = (byte) 0xFF;
        }
    }

    /** Whether two ranges are the same, looking at every byte whatever it finds. */
    private static boolean sameBytes(byte[] a, short aOff, byte[] b, short bOff, short len) {
        byte diff = 0;
        for (short i = 0; i < len; i++) diff |= (byte)(a[(short)(aOff + i)] ^ b[(short)(bOff + i)]);
        return diff == (byte) 0;
    }

    private static boolean isZero(byte[] a, short off, short len) {
        byte any = 0;
        for (short i = 0; i < len; i++) any |= a[(short)(off + i)];
        return any == (byte) 0;
    }

    /** `len` bytes, 33 at most, as lowercase hex text into scratch[X_HEX]. */
    private void toHex(byte[] src, short off, short len) {
        hexInto(src, off, len, X_HEX);
    }

    /** `len` bytes as lowercase hex text into scratch from `at`. The arrays and the two ends are in locals: this loop is most of what the card does in bytecode. */
    private void hexInto(byte[] src, short off, short len, short at) {
        byte[] to = scratch;
        byte[] hex = HEX;
        short end = (short)(off + len);
        while (off < end) {
            short v = (short)(src[off++] & 0xFF);
            to[at++] = hex[(short)(v >> 4)];
            to[at++] = hex[(short)(v & 0x0F)];
        }
    }

    /**
     * A big-endian uint32 as decimal text in scratch, its last digit just
     * before `end`; answers how many digits. An amount under 32,768, which
     * nearly every output of a swap is, is divided as a short; a larger one
     * the long way (`toDecimal`).
     */
    private short decimalBefore(byte[] src, short off, short end) {
        if (src[off] == (byte) 0 && src[(short)(off + 1)] == (byte) 0 && src[(short)(off + 2)] >= (byte) 0) {
            short v = Util.getShort(src, (short)(off + 2));
            short at = end;
            do {
                scratch[--at] = (byte)('0' + (short)(v % 10));
                v = (short)(v / 10);
            } while (v != (short) 0);
            return (short)(end - at);
        }
        short digits = toDecimal(src, off);
        Util.arrayCopyNonAtomic(scratch, (short)(X_DEC + 10 - digits), scratch, (short)(end - digits), digits);
        return digits;
    }

    /**
     * A big-endian uint32 as decimal text, right-aligned in the ten bytes at
     * scratch[X_DEC], with no leading zeros. Answers how many digits.
     *
     * JavaCard has no long and int is optional, so it is long division by
     * ten, a byte at a time: the running value never passes 9*256+255.
     */
    private short toDecimal(byte[] src, short off) {
        Util.arrayCopyNonAtomic(src, off, scratch, X_NUM, (short) 4);
        short digits = 0;
        do {
            short rem = 0;
            for (short i = 0; i < 4; i++) {
                short cur = (short)((short)(rem << 8) | (short)(scratch[(short)(X_NUM + i)] & 0xFF));
                scratch[(short)(X_NUM + i)] = (byte)(cur / 10);
                rem = (short)(cur % 10);
            }
            digits++;
            scratch[(short)(X_DEC + 10 - digits)] = (byte)('0' + rem);
        } while (!isZero(scratch, X_NUM, (short) 4));
        return digits;
    }

    /**
     * Nothing is done here, and nothing calls it: this method is in the
     * package for its length alone. The chip the card runs on installs the
     * card's applet only when the load file's size falls in a window of each
     * 256 bytes (docs/FOXY-CARD-HARDWARE.md), the same code failing a few
     * dozen bytes to either side. Each line below is six bytes of the file;
     * `tools/refcheck.py`, run after every build, says how many to add or to
     * take away.
     */
    private static void sizeTheFile(byte[] a) {
        // no lines at present: the 1.20 build of 19,634 bytes (178 past a multiple of 256) installs, as a 1.19 build of 19,269 (69 past) did; 1.16 installs at 203 past a multiple of 256 (and 249), and not at 139, 164 or 176
    }
}
