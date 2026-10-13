"use strict"
/*
 * client.cjs — zero-dependency Node client for the cardsim bridge, protocol 2.0.
 *
 *   const { CardSim, CardError, encode, constants } = require("./client.cjs")
 *   const sim = new CardSim()                       // http://127.0.0.1:9876
 *   await sim.waitReady()
 *   await sim.reset()                               // fresh card; same key every time (see below)
 *   const { pubkey } = await sim.state()            // mint format-4 SIG_ALL pieces to this key, per run
 *   await sim.fixture({ pin: "1234", mint, owner: true, proofs: [...] })
 *   await sim.select(); await sim.verifyPin("1234"); await sim.getBalance()
 *
 * Node 18+ (global fetch, node:crypto). The helpers port tools/cardctl/cardctl.py's Card class: the same bytes on the
 * wire (asserted against test_apdu.py's vectors in client.test.cjs), CardError(sw, context) on any status word but
 * 9000, and the same argument checks before any transport. The pure encoders are exported as `encode.*` for a fake NFC
 * transport that needs the bytes without the HTTP, and the owner's proof as `ownerProof` (ECDSA P-256 with node:crypto).
 *
 * This file, the four routes and their bodies are the contract flash-pos and flash-mobile pin by CASHU_JAVACARD_REF.
 *
 * Nothing here retries an APDU. A replayed LOAD_PROOF burns a slot, and a payment's SPEND_ALL_SIGN is not asked twice
 * (SPEND_ALL_AGAIN gives the signature again): a transport error on /apdu is thrown to the caller, who knows whether
 * the command was idempotent. waitReady() is the one bounded retry loop, and it only reads /state.
 *
 * Two facts about the simulator a loader has to know (CardSim.java header):
 *   - SELECT starts a session: a re-SELECT drops a verified PIN, the owner's nonce and the owner's grant, as a new tap
 *     does. There is no /tap; call select() where the app would tap.
 *   - /reset does not change the key. Every install yields the same pubkey, so mint fresh pieces per run after
 *     reset(); a checked-in piece is spent at the mint after the first run that redeems it.
 */
const nodeCrypto = require("node:crypto")

const CLA = 0xb0

const INS = Object.freeze({
  GET_INFO: 0x01,
  GET_PUBKEY: 0x10,
  GET_BALANCE: 0x11,
  GET_PROOF_COUNT: 0x12,
  GET_PROOF: 0x13,
  GET_SLOT_STATUS: 0x14,
  AUTH: 0x15,
  GET_CARD: 0x16,
  GET_PIECES: 0x17,
  GET_LOG: 0x18,
  GET_CHANGE: 0x19,
  GET_DLEQ: 0x1a,
  SPEND_ALL_BEGIN: 0x22,
  SPEND_ALL_OUTPUTS: 0x23,
  SPEND_ALL_SIGN: 0x24,
  SPEND_ALL_AGAIN: 0x25,
  SPEND_ALL_CHANGE: 0x26,
  LOAD_PROOF: 0x30,
  CLEAR_SPENT: 0x31,
  SET_CARD: 0x32,
  SET_LIMIT_PIN: 0x33,
  SET_LIMIT: 0x34,
  SET_HEADER: 0x36,
  TELL_TIME: 0x37,
  VERIFY_PIN: 0x40,
  SET_PIN: 0x41,
  CHANGE_PIN: 0x42,
  SET_OWNER: 0x43,
  GET_NONCE: 0x44,
  ALLOW_LOAD: 0x45,
  LOCK_CARD: 0x50,
  RESET_CARD: 0x51,
  SET_TAG: 0x52,
  REFRESH: 0x53,
})

const SW = Object.freeze({
  OK: 0x9000,
  WRONG_LENGTH: 0x6700,
  SECURITY_NOT_SATISFIED: 0x6982,
  PIN_BLOCKED: 0x6983,
  PIN_NOT_SET: 0x6984,
  CONDITIONS_NOT_SATISFIED: 0x6985,
  CARD_LOCKED: 0x6986,
  WRONG_DATA: 0x6a80,
  NOT_FOUND: 0x6a82,
  SLOT_OUT_OF_RANGE: 0x6a83,
  NO_SPACE: 0x6a84,
  SLOT_EMPTY: 0x6a88,
  NO_CARD_RECORD: 0x6a8c,
  CARD_IN_USE: 0x6a8d,
  NO_REFUND_KEY: 0x6a8e,
  OVER_LIMIT: 0x6a8f,
  NO_OWNER: 0x6a90,
  OWNER_PROOF: 0x6a91,
  LITTLE_WORK: 0x6a93,
  PIECE_ON_CARD: 0x6a94,
  PIN_NEEDED: 0x6a94,
  TOO_MANY: 0x6a96,
  INS_NOT_SUPPORTED: 0x6d00,
  CLA_NOT_SUPPORTED: 0x6e00,
  CRYPTO_ERROR: 0x6f00,
})

// The card's applet's whole AID first, then the package AID, "CASHUCARD" after F0 (D19), as a fallback
// (cardctl.select, D25). On a chip the package AID alone is a partial name and reaches the opener, made first,
// which answers 9000 with no version; the bridge does the same, so a 9000 without a version falls through.
const PACKAGE_AID = Buffer.from("F0434153485543415244", "hex")
const APPLET_AID = Buffer.from("F043415348554341524401", "hex")
const SELECT_AIDS = Object.freeze([APPLET_AID, PACKAGE_AID])
// Withdrawn: a card that answers these, or does not answer the 2.0 AID, needs an update.
const OLD_AIDS = Object.freeze({ upstream0x: Buffer.from("D2760000850102", "hex"), foxy1x: Buffer.from("F0464F585943415244", "hex") })

const VERSION = Object.freeze({ major: 2, minor: 0 })
const MAX_PROOFS = 128
const PROOF_SIZE = 82
const DLEQ_LEN = 96
const HEADER_LEN = 80
const OUTPUT_LEN = 37
const LOCK_CONFIRM_BYTE = 0xde
const MAX_SLOT_AMOUNT = 2 ** 32
const PIN_MIN_LEN = 4, PIN_MAX_LEN = 8
const ROLL_BUDGET_DEFAULT = 7, ROLL_BUDGET_MOST = 30
const STATUS_NAMES = Object.freeze({ 0: "empty", 1: "unspent", 2: "spent" })
const PIN_STATE_NAMES = Object.freeze({ 0: "none", 1: "set", 2: "blocked" })

// The owner's proof labels (spec/APDU.md, "The owner's proof").
const LABEL = Object.freeze({
  CHANGE_PIN: "CashuCard/change-pin",
  SET_LIMIT: "CashuCard/set-limit",
  SET_OWNER: "CashuCard/set-owner",
  SET_CARD: "CashuCard/set-card",
  LOAD: "CashuCard/load",
  LOCK: "CashuCard/lock",
  RESET: "CashuCard/reset",
  TAG: "CashuCard/tag",
  REFRESH: "CashuCard/refresh",
})

// The deterministic TEST owner key, shared with cardctl (p256.TEST_OWNER_PRIVATE) and the bridge (OwnerKey.TEST):
// SHA-256("cashu-javacard/cardctl test owner key") mod n. Anyone with the repository holds it: simulated cards only.
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n
const TEST_OWNER_PRIVATE = (BigInt("0x" + nodeCrypto.createHash("sha256").update("cashu-javacard/cardctl test owner key").digest("hex")) % P256_N)
  .toString(16).padStart(64, "0")

const SW_MEANINGS = {
  0x9000: "success",
  0x6700: "wrong length",
  0x6982: "security condition not satisfied (the PIN, or the owner's grant, not given in this tap)",
  0x6983: "PIN blocked — the owner's change-pin unblocks it",
  0x6984: "PIN not set",
  0x6985: "conditions not satisfied (already spent / no payment begun / already locked / an allowance on a card with no PIN)",
  0x6986: "card locked by LOCK_CARD — writes disabled",
  0x6a80: "wrong data (not a point, a bad refund key, bits no header carries, a budget outside 1-30)",
  0x6a82: "not found — no 2.0 applet on this card (a 0.x or 1.x card needs an update)",
  0x6a83: "slot index out of range",
  0x6a84: "no space — all slots occupied",
  0x6a86: "incorrect P1/P2",
  0x6a88: "slot is empty",
  0x6a8c: "no card record — set the card up first",
  0x6a8d: "card in use — something unspent where only an empty card may be changed",
  0x6a8e: "a dated piece on a card with no refund key",
  0x6a8f: "over the day's limit",
  0x6a90: "no owner — set the owner first",
  0x6a91: "the owner's proof is missing or not the owner's, or not open to an owned card",
  0x6a93: "too little work in the block header",
  0x6a94: "already on the card (LOAD_PROOF) / the PIN needed for this payment (SPEND_ALL_SIGN)",
  0x6a96: "too many places for one signature",
  0x6b00: "wrong P1/P2 (a missing confirmation byte)",
  0x6d00: "instruction not supported",
  0x6e00: "class not supported",
  0x6f00: "signing failed (hardware error)",
}

function describeSw(sw) {
  if (sw in SW_MEANINGS) return SW_MEANINGS[sw]
  if ((sw & 0xfff0) === 0x63c0) return `wrong PIN — ${sw & 0x0f} retries remaining`
  return "unknown status word"
}

const hex4 = sw => sw.toString(16).toUpperCase().padStart(4, "0")

/** The card answered something other than 9000. `sw` is a number; `context` names the command. */
class CardError extends Error {
  constructor(sw, context = "") {
    const where = context ? ` during ${context}` : ""
    super(`card returned ${hex4(sw)}${where}: ${describeSw(sw)}`)
    this.name = "CardError"
    this.sw = sw
    this.context = context
  }
}

/** The bridge answered a non-2xx (400 bad request, 409 refused fixture, 404/405/500). */
class CardSimError extends Error {
  constructor(status, body, path) {
    const detail = body && body.error ? body.error : JSON.stringify(body)
    super(`cardsim ${path} answered ${status}: ${detail}`)
    this.name = "CardSimError"
    this.status = status
    this.body = body
  }
}

// ── bytes ─────────────────────────────────────────────────────────────────────

/** A Buffer from a Buffer/Uint8Array or a hex string (case-insensitive, 0x tolerated). */
function toBytes(value, what = "value") {
  if (Buffer.isBuffer(value)) return value
  if (value instanceof Uint8Array) return Buffer.from(value)
  if (typeof value === "string") {
    const s = value.replace(/\s+/g, "")
    const bare = /^0x/i.test(s) ? s.slice(2) : s
    if (bare.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(bare)) throw new TypeError(`${what} is not valid hex: ${value}`)
    return Buffer.from(bare, "hex")
  }
  throw new TypeError(`${what} must be a Buffer or a hex string`)
}

function expectLen(buf, len, what) {
  if (buf.length !== len) throw new RangeError(`${what} must be ${len} bytes, got ${buf.length}`)
  return buf
}

/** A PIN as bytes: a digit string is encoded as its ASCII bytes, as cardctl does. */
function secretBytes(value, what, min, max) {
  const b = typeof value === "string" ? Buffer.from(value, "utf8") : toBytes(value, what)
  if (b.length < min || b.length > max) throw new RangeError(`${what} must be ${min}-${max} bytes, got ${b.length}`)
  return b
}

const u32 = (v, what) => {
  if (!Number.isInteger(v) || v < 0 || v >= MAX_SLOT_AMOUNT) throw new RangeError(`${what} must be an integer, 0 <= n < 2^32, got ${v}`)
  const b = Buffer.alloc(4)
  b.writeUInt32BE(v)
  return b
}

/**
 * cardctl.validate_slot_amount: a positive power of two below 2^32. A mint keyset has no key for amount 3, so a piece
 * carrying one is refused on redemption, after the slot is burned.
 */
function validateSlotAmount(value, where = "") {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new TypeError(`${where}amount must be a positive integer, got ${typeof value} ${JSON.stringify(value)}`)
  }
  if (!(value > 0 && value < MAX_SLOT_AMOUNT)) {
    throw new RangeError(`${where}amount must be a positive integer below 2**32 (the card's amount field is a 4-byte uint), got ${value}`)
  }
  if (!isPowerOfTwo(value)) {
    throw new RangeError(`${where}amount must be a positive power of two — a mint keyset has no key for other denominations, so the proof is rejected on redemption after the slot is already burned. Got ${value}.`)
  }
  return value
}

function isPowerOfTwo(n) {
  return Number.isInteger(n) && n > 0 && Math.log2(n) % 1 === 0
}

/** CLA B0 ‖ INS ‖ P1 ‖ P2 [‖ Lc ‖ data] [‖ Le] — cardctl.Card.send's framing. */
function apdu(ins, p1 = 0, p2 = 0, data = null, le = null) {
  const parts = [Buffer.from([CLA, ins, p1, p2])]
  if (data && data.length) parts.push(Buffer.from([data.length]), data)
  if (le !== null && le !== undefined) parts.push(Buffer.from([le]))
  return Buffer.concat(parts)
}

function slotIndex(slot) {
  if (!Number.isInteger(slot) || slot < 0 || slot >= MAX_PROOFS) {
    throw new RangeError(`slot must be an integer in 0..${MAX_PROOFS - 1}, got ${slot}`)
  }
  return slot
}

/** An owner's command's data: the proof's length (1), the proof, then the value it was made over. */
function ownerData(proof, value = Buffer.alloc(0)) {
  const p = toBytes(proof, "proof")
  if (p.length < 1 || p.length > 72) throw new RangeError(`an owner's proof is a DER signature of at most 72 bytes, got ${p.length}`)
  return Buffer.concat([Buffer.from([p.length]), p, toBytes(value, "value")])
}

/**
 * The owner's proof: an ECDSA signature (P-256, SHA-256, DER) by the owner's private key (32 bytes hex, default the
 * TEST key) over label || nonce (16) || value.
 */
function ownerProof(label, nonce, value = Buffer.alloc(0), privateKeyHex = TEST_OWNER_PRIVATE) {
  const n = expectLen(toBytes(nonce, "nonce"), 16, "nonce")
  const key = ownerKey(privateKeyHex)
  return nodeCrypto.sign("sha256", Buffer.concat([Buffer.from(label, "ascii"), n, toBytes(value, "value")]), { key, dsaEncoding: "der" })
}

/** A node:crypto KeyObject for a P-256 private key given as 32 bytes of hex. */
function ownerKey(privateKeyHex = TEST_OWNER_PRIVATE) {
  const d = expectLen(toBytes(privateKeyHex, "owner key"), 32, "owner key")
  const ecdh = nodeCrypto.createECDH("prime256v1")
  ecdh.setPrivateKey(d)
  const pub = ecdh.getPublicKey()
  const b64 = b => b.toString("base64url")
  return nodeCrypto.createPrivateKey({ key: { kty: "EC", crv: "P-256", d: b64(d), x: b64(pub.subarray(1, 33)), y: b64(pub.subarray(33)) }, format: "jwk" })
}

/** The owner's public key, 65 bytes 04 || X || Y, as SET_OWNER takes it. */
function ownerPublicKey(privateKeyHex = TEST_OWNER_PRIVATE) {
  const ecdh = nodeCrypto.createECDH("prime256v1")
  ecdh.setPrivateKey(expectLen(toBytes(privateKeyHex, "owner key"), 32, "owner key"))
  return ecdh.getPublicKey()
}

/** SET_LIMIT's value: 4, 8, 12 or 13 bytes; each longer form needs every field before it (cardctl.limit_value). */
function limitValue({ day, payment, allowance, rollBudget } = {}) {
  if (rollBudget !== undefined && (payment === undefined || allowance === undefined)) throw new TypeError("rollBudget is the thirteenth byte: give payment and allowance too")
  if (allowance !== undefined && payment === undefined) throw new TypeError("allowance is bytes 8 to 11: give payment too")
  if (rollBudget !== undefined && !(Number.isInteger(rollBudget) && rollBudget >= 1 && rollBudget <= ROLL_BUDGET_MOST)) {
    throw new RangeError(`rollBudget must be 1 to ${ROLL_BUDGET_MOST}, got ${rollBudget}`)
  }
  const parts = [u32(day, "day")]
  if (payment !== undefined) parts.push(u32(payment, "payment"))
  if (allowance !== undefined) parts.push(u32(allowance, "allowance"))
  if (rollBudget !== undefined) parts.push(Buffer.from([rollBudget]))
  return Buffer.concat(parts)
}

/** Pure encoders: the bytes each command puts on the wire. Argument checks throw before any transport. */
const encode = Object.freeze({
  select: (aid = APPLET_AID) => Buffer.concat([Buffer.from([0x00, 0xa4, 0x04, 0x00, aid.length]), aid]),
  getInfo: (p1 = 2) => apdu(INS.GET_INFO, p1, 0, null, 0x00),
  getPubkey: () => apdu(INS.GET_PUBKEY, 0, 0, null, 0x21),
  getBalance: () => apdu(INS.GET_BALANCE, 0, 0, null, 0x04),
  getProofCount: () => apdu(INS.GET_PROOF_COUNT, 0, 0, null, 0x01),
  getSlotStatus: () => apdu(INS.GET_SLOT_STATUS, 0, 0, null, MAX_PROOFS),
  getProof: slot => apdu(INS.GET_PROOF, slotIndex(slot), 0, null, PROOF_SIZE),
  auth: reader => apdu(INS.AUTH, 0, 0, expectLen(toBytes(reader, "reader nonce"), 16, "AUTH's reader nonce"), 0x50),
  getCard: () => apdu(INS.GET_CARD, 0, 0, null, 0x00),
  getPieces: (first = 0, form = 0) => apdu(INS.GET_PIECES, slotIndex(first), form, null, 0x00),
  getChange: (page = 0) => apdu(INS.GET_CHANGE, page, 0, null, 0x00),
  getDleq: (first, second = null) => apdu(INS.GET_DLEQ, slotIndex(first), second === null ? 0xff : slotIndex(second), null, 0x00),
  spendAllBegin: slots => {
    if (!Array.isArray(slots) || slots.length < 1 || slots.length > MAX_PROOFS) throw new RangeError(`a payment names 1 to ${MAX_PROOFS} slots`)
    return apdu(INS.SPEND_ALL_BEGIN, 0, 0, Buffer.from(slots.map(slotIndex)), 0x04)
  },
  spendAllOutputs: outputs => {
    if (!Array.isArray(outputs) || outputs.length < 1 || outputs.length * OUTPUT_LEN > 255) throw new RangeError("1 to 6 outputs to a command")
    return apdu(INS.SPEND_ALL_OUTPUTS, 0, 0, Buffer.concat(outputs.map(o => Buffer.concat([u32(o.amount, "output amount"), expectLen(toBytes(o.B_, "B_"), 33, "B_")]))))
  },
  spendAllChange: amount => apdu(INS.SPEND_ALL_CHANGE, 0, 0, u32(validateSlotAmount(amount, "change "), "change"), 0x21),
  spendAllSign: () => apdu(INS.SPEND_ALL_SIGN, 0, 0, null, 0x40),
  spendAllAgain: () => apdu(INS.SPEND_ALL_AGAIN, 0, 0, null, 0x40),
  loadProof: (keysetId, amount, nonce, C, date = 0, dleq = null) => {
    const kid = expectLen(toBytes(keysetId, "keysetId"), 8, "keysetId")
    validateSlotAmount(amount)
    const n = expectLen(toBytes(nonce, "nonce"), 32, "nonce")
    const c = expectLen(toBytes(C, "C"), 33, "C")
    const body = [kid, u32(amount, "amount"), n, c, u32(date, "date")]
    if (dleq) body.push(expectLen(Buffer.concat(["e", "s", "r"].map(k => expectLen(toBytes(dleq[k], `dleq.${k}`), 32, `dleq.${k}`))), DLEQ_LEN, "dleq"))
    return apdu(INS.LOAD_PROOF, dleq ? 1 : 0, 0, Buffer.concat(body), dleq ? 0x02 : 0x01)
  },
  clearSpent: () => apdu(INS.CLEAR_SPENT, 0, 0, null, 0x01),
  setHeader: header => apdu(INS.SET_HEADER, 0, 0, expectLen(toBytes(header, "header"), HEADER_LEN, "a block header"), 0x04),
  verifyPin: pin => apdu(INS.VERIFY_PIN, 0, 0, secretBytes(pin, "pin", PIN_MIN_LEN, PIN_MAX_LEN)),
  setPin: pin => apdu(INS.SET_PIN, 0, 0, secretBytes(pin, "pin", PIN_MIN_LEN, PIN_MAX_LEN)),
  getNonce: () => apdu(INS.GET_NONCE, 0, 0, null, 0x10),
  changePin: (proof, newPin) => apdu(INS.CHANGE_PIN, 0, 0, ownerData(proof, secretBytes(newPin, "new pin", PIN_MIN_LEN, PIN_MAX_LEN))),
  setOwner: (ownerPub, anchor = null, proof = null) => {
    const value = Buffer.concat([expectLen(toBytes(ownerPub, "owner key"), 65, "the owner key"), anchor ? expectLen(toBytes(anchor, "anchor"), HEADER_LEN, "the anchor header") : Buffer.alloc(0)])
    return apdu(INS.SET_OWNER, 0, 0, proof ? ownerData(proof, value) : value)
  },
  allowLoad: proof => apdu(INS.ALLOW_LOAD, 0, 0, ownerData(proof)),
  setLimit: (proof, value) => apdu(INS.SET_LIMIT, 0, 0, ownerData(proof, value)),
  refresh: (proof, header) => apdu(INS.REFRESH, 0, 0, ownerData(proof, expectLen(toBytes(header, "header"), HEADER_LEN, "a block header")), 0x04),
  lockCard: proof => apdu(INS.LOCK_CARD, 0, LOCK_CONFIRM_BYTE, ownerData(proof)),
})

// ── parsers ───────────────────────────────────────────────────────────────────

/** GET_INFO's 30, 42 or 43 bytes (spec/APDU.md, GET_INFO). */
function parseInfo(b) {
  if (b.length < 30) throw new RangeError(`GET_INFO returned ${b.length} bytes, expected 30, 42 or 43: ${b.toString("hex")}`)
  const info = {
    version: `${b[0]}.${b[1]}`,
    major: b[0],
    minor: b[1],
    maxSlots: b[2],
    unspent: b[3],
    spent: b[4],
    empty: b[5],
    capsRaw: b[6],
    pinState: b[7],
    format: b[8],
    tries: b[9],
    locked: b[10] === 1,
    recordSet: b[11] === 1,
    dailyLimit: b.readUInt32BE(12),
    hasOwner: b[16] === 1,
    now: b.readUInt32BE(17),
    windowStart: b.readUInt32BE(21),
    spentToday: b.readUInt32BE(25),
    changeGrant: b[29] === 1,
  }
  if (b.length >= 42) Object.assign(info, { paymentLimit: b.readUInt32BE(30), allowance: b.readUInt32BE(34), nopinSpent: b.readUInt32BE(38) })
  if (b.length >= 43) info.tagOff = b[42] === 1
  return info
}

/** GET_PROOF's 82 bytes as a slot (lower-case hex, `status` named). */
function parseProof(slot, b) {
  if (b.length !== PROOF_SIZE) throw new RangeError(`GET_PROOF returned ${b.length} bytes, expected ${PROOF_SIZE}`)
  return {
    slot,
    status: STATUS_NAMES[b[0]] || `unknown(${b[0]})`,
    keysetId: b.subarray(1, 9).toString("hex"),
    amount: b.readUInt32BE(9),
    nonce: b.subarray(13, 45).toString("hex"),
    C: b.subarray(45, 78).toString("hex"),
    date: b.readUInt32BE(78),
  }
}

/** GET_CARD (spec/APDU.md, GET_CARD), with the rollover bytes. */
function parseCard(b) {
  if (b.length < 106) throw new RangeError(`GET_CARD returned ${b.length} bytes, expected at least 106`)
  const mintLen = b[105]
  return {
    format: b[0],
    recordSet: b[1] === 1,
    unit: b[2],
    dailyLimit: b.readUInt32BE(3),
    refundKey: b.subarray(7, 40).toString("hex"),
    hardestBits: b.subarray(40, 44).toString("hex"),
    lastHeader: b.subarray(44, 76).toString("hex"),
    rolls: b[76],
    rollBudget: b[77] || ROLL_BUDGET_DEFAULT,
    allowanceArmed: b[78] === 1,
    mint: b.subarray(106, 106 + mintLen).toString("ascii"),
    design: b.subarray(106 + mintLen, 109 + mintLen).toString("ascii"),
  }
}

/** GET_CHANGE: a count, then openings of 80 bytes: amount, keyset, date, nonce, r. */
function parseChange(b) {
  const n = b[0]
  const out = []
  for (let i = 0; i < n; i++) {
    const o = b.subarray(1 + i * 80, 81 + i * 80)
    out.push({ amount: o.readUInt32BE(0), keysetId: o.subarray(4, 12).toString("hex"), date: o.readUInt32BE(12), nonce: o.subarray(16, 48).toString("hex"), r: o.subarray(48, 80).toString("hex") })
  }
  return out
}

// ── fixture validation (mirrors Fixture.java's checks on the body) ───────────

const FIXTURE_KEYS = new Set(["pin", "mint", "refundKey", "owner", "ownerKey", "anchor", "headers", "proofs", "spentSlots", "limits", "blockedPin"])
const PROOF_KEYS = new Set(["keysetId", "amount", "nonce", "C", "date", "dleq"])
const LIMIT_KEYS = new Set(["day", "payment", "allowance", "rollBudget"])

function isHexOf(value, bytes) {
  if (typeof value !== "string") return false
  const s = /^0x/i.test(value) ? value.slice(2) : value
  return s.length === bytes * 2 && /^[0-9a-fA-F]+$/.test(s)
}

/**
 * The checks the server can run on the body alone, so a malformed fixture fails here, in the test's own stack. The
 * checks against the card as it is (a PIN or an owner set by an earlier fixture) are the server's (400 CardSimError).
 * Throws on the first problem; returns the fixture unchanged.
 */
function validateFixture(f) {
  if (!f || typeof f !== "object" || Array.isArray(f)) throw new TypeError("fixture must be an object")
  if ("puk" in f) throw new TypeError("puk: there is no PUK on a 2.0 card (D18); the owner's change-pin unblocks a PIN")
  if ("appletVersion" in f) throw new TypeError("appletVersion: the 0.x version masks are gone (D18)")
  for (const k of Object.keys(f)) if (!FIXTURE_KEYS.has(k)) throw new TypeError(`unknown fixture key: ${k}`)
  if (f.pin !== undefined) secretBytes(f.pin, "pin", PIN_MIN_LEN, PIN_MAX_LEN)
  if (f.blockedPin !== undefined && typeof f.blockedPin !== "boolean") throw new TypeError("blockedPin must be true or false")
  if (f.blockedPin && f.pin === undefined) throw new TypeError("blockedPin requires pin")
  if (f.mint !== undefined && (typeof f.mint !== "string" || f.mint.length < 1 || f.mint.length > 77 || !/^[\x00-\x7f]*$/.test(f.mint))) throw new TypeError("mint must be 1-77 ASCII characters")
  if (f.refundKey !== undefined && (f.mint === undefined || !isHexOf(f.refundKey, 33))) throw new TypeError("refundKey is 33 bytes, given with mint")
  if (f.owner !== undefined && typeof f.owner !== "boolean") throw new TypeError("owner must be true or false")
  if (f.owner !== undefined && f.ownerKey !== undefined) throw new TypeError("give owner or ownerKey, not both")
  if (f.ownerKey !== undefined && !isHexOf(f.ownerKey, 32)) throw new TypeError("ownerKey must be 32 bytes (64 hex chars)")
  if (f.anchor !== undefined && (!isHexOf(f.anchor, HEADER_LEN) || !(f.owner || f.ownerKey))) throw new TypeError("anchor is an 80-byte header, given with owner or ownerKey")
  if (f.headers !== undefined && (!Array.isArray(f.headers) || !f.headers.every(h => isHexOf(h, HEADER_LEN)))) throw new TypeError("headers must be 80-byte hex headers")
  if (f.limits !== undefined) {
    if (!f.limits || typeof f.limits !== "object" || Array.isArray(f.limits)) throw new TypeError("limits must be an object")
    for (const k of Object.keys(f.limits)) if (!LIMIT_KEYS.has(k)) throw new TypeError(`unknown key in limits: ${k}`)
    for (const k of ["day", "payment", "allowance"]) if (f.limits[k] !== undefined) u32(f.limits[k], `limits.${k}`)
    const b = f.limits.rollBudget
    if (b !== undefined && !(Number.isInteger(b) && b >= 1 && b <= ROLL_BUDGET_MOST)) throw new RangeError(`limits.rollBudget must be 1 to ${ROLL_BUDGET_MOST}`)
  }
  const proofs = f.proofs === undefined ? [] : f.proofs
  if (!Array.isArray(proofs)) throw new TypeError("proofs must be an array")
  if (proofs.length > MAX_PROOFS) throw new RangeError(`proofs has ${proofs.length} entries; the card has ${MAX_PROOFS} slots`)
  const nonces = new Set()
  proofs.forEach((p, i) => {
    const where = `proofs[${i}]`
    if (!p || typeof p !== "object" || Array.isArray(p)) throw new TypeError(`${where} must be an object`)
    for (const k of Object.keys(p)) if (!PROOF_KEYS.has(k)) throw new TypeError(`unknown key in ${where}: ${k}`)
    for (const k of ["keysetId", "amount", "nonce", "C"]) if (!(k in p)) throw new TypeError(`${where} is missing ${k}`)
    if (!isHexOf(p.keysetId, 8)) throw new TypeError(`${where}.keysetId must be 8 bytes (16 hex chars)`)
    if (!isHexOf(p.nonce, 32)) throw new TypeError(`${where}.nonce must be 32 bytes (64 hex chars)`)
    if (!isHexOf(p.C, 33) || !/^(0x)?0[23]/i.test(p.C)) throw new TypeError(`${where}.C must be 33 bytes with a 02/03 prefix`)
    if (typeof p.amount !== "number" || !Number.isInteger(p.amount) || p.amount < 1 || p.amount >= MAX_SLOT_AMOUNT) throw new RangeError(`${where}.amount must satisfy 1 <= amount < 2^32`)
    if (p.date !== undefined) u32(p.date, `${where}.date`)
    if (p.dleq !== undefined && !(p.dleq && ["e", "s", "r"].every(k => isHexOf(p.dleq[k], 32)) && Object.keys(p.dleq).length === 3)) throw new TypeError(`${where}.dleq must be {e, s, r}, 32 bytes each`)
    const n = p.nonce.toLowerCase().replace(/^0x/, "")
    if (nonces.has(n)) throw new TypeError(`${where} repeats a nonce: the card refuses a piece already on it (6A94)`)
    nonces.add(n)
  })
  if (f.spentSlots !== undefined) {
    if (!Array.isArray(f.spentSlots)) throw new TypeError("spentSlots must be an array")
    const seen = new Set()
    f.spentSlots.forEach((s, i) => {
      if (!Number.isInteger(s) || s < 0 || s >= proofs.length) throw new RangeError(`spentSlots[${i}] = ${s} is not an index into proofs (${proofs.length} entries)`)
      if (seen.has(s)) throw new RangeError(`spentSlots repeats ${s}`)
      seen.add(s)
    })
  }
  return f
}

// ── the bridge ────────────────────────────────────────────────────────────────

const sleep = ms => new Promise(r => setTimeout(r, ms))

class CardSim {
  /**
   * @param {string} url   the bridge, default http://127.0.0.1:9876
   * @param {{fetch?: Function, timeoutMs?: number}} [opts]
   *   fetch: a fetch to use instead of the global one (tests).
   *   timeoutMs: per-request deadline, default 5000, the same 5 s both apps' transports put on /apdu.
   */
  constructor(url = "http://127.0.0.1:9876", { fetch, timeoutMs = 5000 } = {}) {
    this.url = url.replace(/\/+$/, "")
    this.fetch = fetch || globalThis.fetch
    if (typeof this.fetch !== "function") throw new TypeError("no fetch: Node 18+ or pass { fetch }")
    if (!(Number.isFinite(timeoutMs) && timeoutMs > 0)) throw new RangeError(`timeoutMs must be a positive number, got ${timeoutMs}`)
    this.timeoutMs = timeoutMs
  }

  /** One HTTP round trip, no retry, bounded by `timeoutMs`. Non-2xx → CardSimError. */
  async request(method, path, body) {
    const res = await this.fetch(this.url + path, {
      method,
      headers: body === undefined ? {} : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
    })
    const text = await res.text()
    let parsed
    try { parsed = text ? JSON.parse(text) : null } catch { parsed = { error: text } }
    if (!res.ok) throw new CardSimError(res.status, parsed, path)
    return parsed
  }

  /** One APDU, never retried. Returns {data: Buffer, sw: number}; a non-9000 status word is returned, not thrown. */
  async apdu(command) {
    const bytes = toBytes(command, "apdu")
    if (bytes.length < 4) throw new RangeError("an APDU is at least CLA INS P1 P2 (4 bytes)")
    const r = await this.request("POST", "/apdu", { hex: bytes.toString("hex") })
    const resp = Buffer.from(r.hex, "hex")
    return { data: resp.subarray(0, resp.length - 2), sw: resp.readUInt16BE(resp.length - 2) }
  }

  /** A brand-new card (same key as before: mint per run). Returns the state document. */
  reset() {
    return this.request("POST", "/reset")
  }

  /** Validate locally, then apply additively. Returns the state document; a refused step is a CardSimError(409). */
  fixture(f) {
    return this.request("POST", "/fixture", validateFixture(f))
  }

  state() {
    return this.request("GET", "/state")
  }

  /** The only retrying call: poll /state until the bridge answers, at most `attempts` times. */
  async waitReady({ attempts = 50, intervalMs = 200 } = {}) {
    let last
    for (let i = 0; i < attempts; i++) {
      try {
        return await this.state()
      } catch (e) {
        last = e
        if (i + 1 < attempts) await sleep(intervalMs)
      }
    }
    throw new Error(`cardsim at ${this.url} not ready after ${attempts} attempts: ${last && last.message}`)
  }

  /** Send and require 9000; CardError(sw, context) otherwise. Returns the data. */
  async send(command, context) {
    const { data, sw } = await this.apdu(command)
    if (sw !== SW.OK) throw new CardError(sw, context)
    return data
  }

  // ── the card ──────────────────────────────────────────────────────────

  /**
   * SELECT by the applet's whole AID, then the package AID (D25). Returns {major, minor}. A 9000 with no version is
   * another applet of the package (the opener, which a partial name reaches) and counts as no answer. Throws the last
   * CardError, or an Error naming the AID that answered 9000 with no version when that was the last answer.
   */
  async select() {
    let last
    for (const aid of SELECT_AIDS) {
      let v
      try {
        v = await this.send(encode.select(aid), "SELECT")
      } catch (e) {
        if (!(e instanceof CardError)) throw e
        last = e
        continue
      }
      if (v.length >= 2) return { major: v[0], minor: v[1] }
      last = new Error(`SELECT ${aid.toString("hex").toUpperCase()} answered 9000 with no version: not the card's applet`)
    }
    throw last
  }

  async getInfo(p1 = 2) { return parseInfo(await this.send(encode.getInfo(p1), "GET_INFO")) }
  async getPubkey() { return this.send(encode.getPubkey(), "GET_PUBKEY") }
  async getBalance() { return (await this.send(encode.getBalance(), "GET_BALANCE")).readUInt32BE(0) }
  async getProofCount() { return (await this.send(encode.getProofCount(), "GET_PROOF_COUNT"))[0] }
  /** One status byte per slot, as numbers (0 empty, 1 unspent, 2 spent). */
  async getSlotStatus() { return Array.from(await this.send(encode.getSlotStatus(), "GET_SLOT_STATUS")) }
  async getProof(slot) { return parseProof(slot, await this.send(encode.getProof(slot), `GET_PROOF slot ${slot}`)) }
  async getCard() { return parseCard(await this.send(encode.getCard(), "GET_CARD")) }
  /** AUTH: { card: 16 bytes, signature: 64 bytes } over the tagged message (cashu-crypto.authMessage). */
  async auth(reader) {
    const b = await this.send(encode.auth(reader), "AUTH")
    return { card: b.subarray(0, 16), signature: b.subarray(16) }
  }
  async getChange(page = 0) { return parseChange(await this.send(encode.getChange(page), "GET_CHANGE")) }
  async getDleq(first, second = null) { return this.send(encode.getDleq(first, second), "GET_DLEQ") }
  async getNonce() { return this.send(encode.getNonce(), "GET_NONCE") }

  /** SPEND_ALL_BEGIN: the payment's places; answers what they are worth. */
  async spendAllBegin(slots) { return (await this.send(encode.spendAllBegin(slots), "SPEND_ALL_BEGIN")).readUInt32BE(0) }
  /** The till's outputs, six to a command. */
  async spendAllOutputs(outputs) {
    for (let i = 0; i < outputs.length; i += 6) await this.send(encode.spendAllOutputs(outputs.slice(i, i + 6)), "SPEND_ALL_OUTPUTS")
  }
  /** One change output the card makes for itself; answers its blinded message, 33 bytes. */
  async spendAllChange(amount) { return this.send(encode.spendAllChange(amount), "SPEND_ALL_CHANGE") }
  /** SPEND_ALL_SIGN, sent again for as long as the card answers "not yet" (00 01). Answers { signature, waits }. Not idempotent. */
  async spendAllSign({ maxWaits = 1100 } = {}) {
    for (let waits = 0; waits <= maxWaits; waits++) {
      const b = await this.send(encode.spendAllSign(), "SPEND_ALL_SIGN")
      if (b.length === 64) return { signature: b, waits }
    }
    throw new Error(`the card made the payment wait more than ${maxWaits} times`)
  }
  async spendAllAgain() { return this.send(encode.spendAllAgain(), "SPEND_ALL_AGAIN") }

  /** Returns the slot the piece landed in. Not idempotent: a replay is 6A94. */
  async loadProof(keysetId, amount, nonce, C, date = 0, dleq = null) {
    return (await this.send(encode.loadProof(keysetId, amount, nonce, C, date, dleq), "LOAD_PROOF"))[0]
  }
  async clearSpent() { return (await this.send(encode.clearSpent(), "CLEAR_SPENT"))[0] }
  async setHeader(header) { return (await this.send(encode.setHeader(header), "SET_HEADER")).readUInt32BE(0) }
  async verifyPin(pin) { await this.send(encode.verifyPin(pin), "VERIFY_PIN") }
  async setPin(pin) { await this.send(encode.setPin(pin), "SET_PIN") }

  // the owner's commands: GET_NONCE, then the command with a proof signed by `ownerKeyHex` (default the TEST key)
  async changePin(newPin, ownerKeyHex = TEST_OWNER_PRIVATE) {
    const pin = secretBytes(newPin, "new pin", PIN_MIN_LEN, PIN_MAX_LEN)
    await this.send(encode.changePin(ownerProof(LABEL.CHANGE_PIN, await this.getNonce(), pin, ownerKeyHex), pin), "CHANGE_PIN")
  }
  async allowLoad(ownerKeyHex = TEST_OWNER_PRIVATE) {
    await this.send(encode.allowLoad(ownerProof(LABEL.LOAD, await this.getNonce(), Buffer.alloc(0), ownerKeyHex)), "ALLOW_LOAD")
  }
  async setLimit(limits, ownerKeyHex = TEST_OWNER_PRIVATE) {
    const value = limitValue(limits)
    await this.send(encode.setLimit(ownerProof(LABEL.SET_LIMIT, await this.getNonce(), value, ownerKeyHex), value), "SET_LIMIT")
  }
  async refresh(header, ownerKeyHex = TEST_OWNER_PRIVATE) {
    const h = expectLen(toBytes(header, "header"), HEADER_LEN, "a block header")
    return (await this.send(encode.refresh(ownerProof(LABEL.REFRESH, await this.getNonce(), h, ownerKeyHex), h), "REFRESH")).readUInt32BE(0)
  }
}

const constants = Object.freeze({
  CLA, INS, SW, PACKAGE_AID, APPLET_AID, SELECT_AIDS, OLD_AIDS, VERSION, MAX_PROOFS, PROOF_SIZE, DLEQ_LEN, HEADER_LEN, OUTPUT_LEN,
  LOCK_CONFIRM_BYTE, MAX_SLOT_AMOUNT, PIN_MIN_LEN, PIN_MAX_LEN, ROLL_BUDGET_DEFAULT, ROLL_BUDGET_MOST, STATUS_NAMES,
  PIN_STATE_NAMES, LABEL, TEST_OWNER_PRIVATE,
})

module.exports = {
  CardSim, CardError, CardSimError, encode, constants,
  validateFixture, validateSlotAmount, parseInfo, parseProof, parseCard, parseChange, describeSw, toBytes,
  ownerProof, ownerData, ownerPublicKey, limitValue,
}
