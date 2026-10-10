"use strict"
/*
 * client.cjs — zero-dependency Node client for the cardsim bridge.
 *
 *   const { CardSim, CardError, encode, constants } = require("./client.cjs")
 *   const sim = new CardSim()                       // http://127.0.0.1:9876
 *   await sim.waitReady()
 *   await sim.reset()                               // fresh card; same key every time (see below)
 *   const { pubkey } = await sim.state()            // mint proofs to this key, per run
 *   await sim.fixture({ pin: "1234", proofs: [...] })
 *   await sim.select(); await sim.verifyPin("1234"); await sim.getBalance()
 *
 * Node 18+ (global fetch). The helpers port tools/cardctl/cardctl.py's Card
 * class one to one: the same bytes on the wire (asserted against
 * test_apdu.py's vectors in client.test.cjs), CardError(sw, context) on any
 * status word but 9000, and the same argument checks before any transport.
 * The pure encoders are exported as `encode.*` for a fake NFC transport that
 * needs the bytes without the HTTP.
 *
 * Nothing here retries an APDU. A replayed LOAD_PROOF burns a slot and a
 * replayed SPEND_PROOF answers 6985: a transport error on /apdu is thrown to
 * the caller, who knows whether the command was idempotent. waitReady() is
 * the one bounded retry loop, and it only reads /state.
 *
 * Two facts about the simulator a loader has to know (CardSim.java header):
 *   - SELECT starts a session: a re-SELECT drops a verified PIN, as a new
 *     tap does. There is no /tap; call select() where the app would tap.
 *   - /reset does not change the key. Every install yields the same pubkey,
 *     so mint fresh proofs per run after reset(); a checked-in proof is
 *     spent at the mint after the first run that redeems it.
 */

const CLA = 0xb0

const INS = Object.freeze({
  GET_INFO: 0x01,
  GET_PUBKEY: 0x10,
  GET_BALANCE: 0x11,
  GET_PROOF_COUNT: 0x12,
  GET_PROOF: 0x13,
  GET_SLOT_STATUS: 0x14,
  SPEND_PROOF: 0x20,
  SIGN_ARBITRARY: 0x21,
  LOAD_PROOF: 0x30,
  CLEAR_SPENT: 0x31,
  VERIFY_PIN: 0x40,
  SET_PIN: 0x41,
  CHANGE_PIN: 0x42,
  CLEAR_PIN: 0x43,
  SET_PUK: 0x44,
  UNBLOCK_PIN: 0x45,
  LOCK_CARD: 0x50,
})

const SW = Object.freeze({
  OK: 0x9000,
  WRONG_LENGTH: 0x6700,
  SECURITY_NOT_SATISFIED: 0x6982,
  PIN_BLOCKED: 0x6983,
  PIN_NOT_SET: 0x6984,
  CONDITIONS_NOT_SATISFIED: 0x6985,
  CARD_LOCKED: 0x6986,
  PUK_NOT_SET: 0x6a82,
  SLOT_OUT_OF_RANGE: 0x6a83,
  NO_SPACE: 0x6a84,
  SLOT_EMPTY: 0x6a88,
  PUK_ALREADY_SET: 0x6a89,
  INS_NOT_SUPPORTED: 0x6d00,
  CLA_NOT_SUPPORTED: 0x6e00,
  CRYPTO_ERROR: 0x6f00,
})

// GET_INFO byte 6 (spec/APDU.md).
const CAP = Object.freeze({
  SECP256K1_NATIVE: 0x01,
  SCHNORR: 0x02,
  PIN: 0x04,
  CLEAR_PIN: 0x08,
  UNBLOCK_PIN: 0x10,
})

// The 7-byte package AID, then the 8-byte applet AID as a fallback (cardctl.select).
const PACKAGE_AID = Buffer.from("D2760000850102", "hex")
const APPLET_AID = Buffer.from("D276000085010201", "hex")

const MAX_PROOFS = 32
const PROOF_SIZE = 78
const LOCK_CONFIRM_BYTE = 0xde
const MAX_SLOT_AMOUNT = 2 ** 32
const PIN_MIN_LEN = 4, PIN_MAX_LEN = 8
const PUK_MIN_LEN = 8, PUK_MAX_LEN = 12
const STATUS_NAMES = Object.freeze({ 0: "empty", 1: "unspent", 2: "spent" })

const SW_MEANINGS = {
  0x9000: "success",
  0x6700: "wrong length",
  0x6982: "security condition not satisfied (PIN set or blocked, and not verified in this session)",
  0x6983: "PIN blocked — retries exhausted",
  0x6984: "PIN not set",
  0x6985: "conditions not satisfied (already spent / PIN already set or blocked / card already locked)",
  0x6986: "card locked by LOCK_CARD — writes disabled",
  0x6a82: "PUK not set — nothing can unblock this card's PIN",
  0x6a83: "slot index out of range",
  0x6a84: "no space — all slots occupied",
  0x6a88: "slot is empty",
  0x6a89: "PUK already set (or exhausted) — a PUK is set once, at personalisation",
  0x6d00: "instruction not supported",
  0x6e00: "class not supported",
  0x6f00: "signing failed (hardware error)",
}

function describeSw(sw, context = "") {
  // UNBLOCK_PIN's 63CX and 6983 count the PUK, not the PIN (cardctl.describe_sw).
  if (context === "UNBLOCK_PIN") {
    if ((sw & 0xfff0) === 0x63c0) return `wrong PUK — ${sw & 0x0f} PUK tries remaining (0 = exhausted for good)`
    if (sw === 0x6983) return "PUK exhausted — ten wrong PUKs; UNBLOCK_PIN answers 6983 for good"
  }
  if (sw in SW_MEANINGS) return SW_MEANINGS[sw]
  if ((sw & 0xfff0) === 0x63c0) return `wrong PIN — ${sw & 0x0f} retries remaining`
  return "unknown status word"
}

const hex4 = sw => sw.toString(16).toUpperCase().padStart(4, "0")

/** The card answered something other than 9000. `sw` is a number; `context` names the command. */
class CardError extends Error {
  constructor(sw, context = "") {
    const where = context ? ` during ${context}` : ""
    super(`card returned ${hex4(sw)}${where}: ${describeSw(sw, context)}`)
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

/** A PIN or PUK as bytes: a digit string is encoded as its ASCII bytes, as cardctl does. */
function secretBytes(value, what, min, max) {
  const b = typeof value === "string" ? Buffer.from(value, "utf8") : toBytes(value, what)
  if (b.length < min || b.length > max) throw new RangeError(`${what} must be ${min}-${max} bytes, got ${b.length}`)
  return b
}

function lengthPrefixed(b) {
  return Buffer.concat([Buffer.from([b.length]), b])
}

/**
 * cardctl.validate_slot_amount: a positive power of two below 2^32. A mint
 * keyset has no key for amount 3, so a proof carrying one is refused on
 * redemption, after the slot is burned.
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

/** Pure encoders: the bytes each command puts on the wire. Argument checks throw before any transport. */
const encode = Object.freeze({
  select: (aid = PACKAGE_AID) => Buffer.concat([Buffer.from([0x00, 0xa4, 0x04, 0x00, aid.length]), aid]),
  getInfo: () => apdu(INS.GET_INFO, 0, 0, null, 0x00),
  getPubkey: () => apdu(INS.GET_PUBKEY, 0, 0, null, 0x21),
  getBalance: () => apdu(INS.GET_BALANCE, 0, 0, null, 0x04),
  getProofCount: () => apdu(INS.GET_PROOF_COUNT, 0, 0, null, 0x01),
  getSlotStatus: () => apdu(INS.GET_SLOT_STATUS, 0, 0, null, MAX_PROOFS),
  getProof: slot => apdu(INS.GET_PROOF, slotIndex(slot), 0, null, PROOF_SIZE),
  spendProof: (slot, message) =>
    apdu(INS.SPEND_PROOF, slotIndex(slot), 0, expectLen(toBytes(message, "message"), 32, "SPEND_PROOF message"), 0x40),
  sign: message => apdu(INS.SIGN_ARBITRARY, 0, 0, expectLen(toBytes(message, "message"), 32, "SIGN_ARBITRARY message"), 0x40),
  loadProof: (keysetId, amount, nonce, C) => {
    const kid = expectLen(toBytes(keysetId, "keysetId"), 8, "keysetId")
    validateSlotAmount(amount)
    const n = expectLen(toBytes(nonce, "nonce"), 32, "nonce")
    const c = expectLen(toBytes(C, "C"), 33, "C")
    const amt = Buffer.alloc(4)
    amt.writeUInt32BE(amount)
    return apdu(INS.LOAD_PROOF, 0, 0, Buffer.concat([kid, amt, n, c]), 0x01)
  },
  clearSpent: () => apdu(INS.CLEAR_SPENT, 0, 0, null, 0x01),
  verifyPin: pin => apdu(INS.VERIFY_PIN, 0, 0, secretBytes(pin, "pin", PIN_MIN_LEN, PIN_MAX_LEN)),
  setPin: pin => apdu(INS.SET_PIN, 0, 0, secretBytes(pin, "pin", PIN_MIN_LEN, PIN_MAX_LEN)),
  changePin: (oldPin, newPin) =>
    apdu(INS.CHANGE_PIN, 0, 0, Buffer.concat([
      lengthPrefixed(secretBytes(oldPin, "old pin", PIN_MIN_LEN, PIN_MAX_LEN)),
      secretBytes(newPin, "new pin", PIN_MIN_LEN, PIN_MAX_LEN),
    ])),
  clearPin: pin => apdu(INS.CLEAR_PIN, 0, 0, lengthPrefixed(secretBytes(pin, "pin", PIN_MIN_LEN, PIN_MAX_LEN))),
  setPuk: puk => apdu(INS.SET_PUK, 0, 0, lengthPrefixed(secretBytes(puk, "puk", PUK_MIN_LEN, PUK_MAX_LEN))),
  unblockPin: (puk, newPin) =>
    apdu(INS.UNBLOCK_PIN, 0, 0, Buffer.concat([
      lengthPrefixed(secretBytes(puk, "puk", PUK_MIN_LEN, PUK_MAX_LEN)),
      lengthPrefixed(secretBytes(newPin, "new pin", PIN_MIN_LEN, PIN_MAX_LEN)),
    ])),
  lockCard: () => Buffer.from([CLA, INS.LOCK_CARD, 0x00, LOCK_CONFIRM_BYTE]),
})

function slotIndex(slot) {
  if (!Number.isInteger(slot) || slot < 0 || slot >= MAX_PROOFS) {
    throw new RangeError(`slot must be an integer in 0..${MAX_PROOFS - 1}, got ${slot}`)
  }
  return slot
}

// ── parsers ───────────────────────────────────────────────────────────────────

/** GET_INFO's 8 or 9 bytes. `pukState` is null on 8 (a card from before the PUK existed). */
function parseInfo(b) {
  if (b.length < 8) throw new RangeError(`GET_INFO returned ${b.length} bytes, expected 8 or 9: ${b.toString("hex")}`)
  const caps = b[6]
  return {
    version: `${b[0]}.${b[1]}`,
    maxSlots: b[2],
    unspent: b[3],
    spent: b[4],
    empty: b[5],
    capsRaw: caps,
    secp256k1Native: !!(caps & CAP.SECP256K1_NATIVE),
    schnorr: !!(caps & CAP.SCHNORR),
    clearPin: !!(caps & CAP.CLEAR_PIN),
    unblockPin: !!(caps & CAP.UNBLOCK_PIN),
    pinState: b[7],
    pukState: b.length > 8 ? b[8] : null,
  }
}

/** GET_PROOF's 78 bytes as a CARD-FILE-shaped slot (lower-case hex, `status` named). */
function parseProof(slot, b) {
  if (b.length !== PROOF_SIZE) throw new RangeError(`GET_PROOF returned ${b.length} bytes, expected ${PROOF_SIZE}`)
  return {
    slot,
    status: STATUS_NAMES[b[0]] || `unknown(${b[0]})`,
    keysetId: b.subarray(1, 9).toString("hex"),
    amount: b.readUInt32BE(9),
    nonce: b.subarray(13, 45).toString("hex"),
    C: b.subarray(45, 78).toString("hex"),
  }
}

// ── fixture validation (mirrors Fixture.java) ─────────────────────────────────

const FIXTURE_KEYS = new Set(["pin", "puk", "proofs", "spentSlots", "blockedPin", "appletVersion"])
const PROOF_KEYS = new Set(["keysetId", "amount", "nonce", "C"])
const KNOWN_VERSIONS_WITHOUT_PUK = new Set(["0.4", "0.5"])

function isHexOf(value, bytes) {
  if (typeof value !== "string") return false
  const s = /^0x/i.test(value) ? value.slice(2) : value
  return s.length === bytes * 2 && /^[0-9a-fA-F]+$/.test(s)
}

/**
 * The checks the server can run on the body alone, so a malformed fixture
 * fails here, in the test's own stack. A puk under a mask kept from an
 * earlier fixture is only the server's to refuse (400 CardSimError): it
 * depends on /state.appletVersion. Throws on the first problem; returns the
 * fixture unchanged.
 */
function validateFixture(f) {
  if (!f || typeof f !== "object" || Array.isArray(f)) throw new TypeError("fixture must be an object")
  for (const k of Object.keys(f)) if (!FIXTURE_KEYS.has(k)) throw new TypeError(`unknown fixture key: ${k}`)
  if (f.pin !== undefined) secretBytes(f.pin, "pin", PIN_MIN_LEN, PIN_MAX_LEN)
  if (f.puk !== undefined) secretBytes(f.puk, "puk", PUK_MIN_LEN, PUK_MAX_LEN)
  if (f.blockedPin !== undefined && typeof f.blockedPin !== "boolean") throw new TypeError("blockedPin must be true or false")
  if (f.blockedPin && f.pin === undefined) throw new TypeError("blockedPin requires pin")
  if (f.appletVersion !== undefined) {
    if (typeof f.appletVersion !== "string" || !/^\d+\.\d+$/.test(f.appletVersion)) throw new TypeError("appletVersion must be \"<major>.<minor>\"")
    if (f.puk !== undefined && KNOWN_VERSIONS_WITHOUT_PUK.has(f.appletVersion)) {
      throw new TypeError(`puk needs a PUK-capable applet; ${f.appletVersion} has no SET_PUK`)
    }
  }
  const proofs = f.proofs === undefined ? [] : f.proofs
  if (!Array.isArray(proofs)) throw new TypeError("proofs must be an array")
  if (proofs.length > MAX_PROOFS) throw new RangeError(`proofs has ${proofs.length} entries; the card has ${MAX_PROOFS} slots`)
  proofs.forEach((p, i) => {
    const where = `proofs[${i}]`
    if (!p || typeof p !== "object" || Array.isArray(p)) throw new TypeError(`${where} must be an object`)
    for (const k of Object.keys(p)) if (!PROOF_KEYS.has(k)) throw new TypeError(`unknown key in ${where}: ${k}`)
    for (const k of PROOF_KEYS) if (!(k in p)) throw new TypeError(`${where} is missing ${k}`)
    if (!isHexOf(p.keysetId, 8)) throw new TypeError(`${where}.keysetId must be 8 bytes (16 hex chars)`)
    if (!isHexOf(p.nonce, 32)) throw new TypeError(`${where}.nonce must be 32 bytes (64 hex chars)`)
    if (!isHexOf(p.C, 33) || !/^(0x)?0[23]/i.test(p.C)) throw new TypeError(`${where}.C must be 33 bytes with a 02/03 prefix`)
    if (typeof p.amount !== "number" || !Number.isInteger(p.amount) || p.amount < 1 || p.amount >= MAX_SLOT_AMOUNT) {
      throw new RangeError(`${where}.amount must satisfy 1 <= amount < 2^32`)
    }
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
   *   timeoutMs: per-request deadline, default 5000, the same 5 s both apps'
   *   transports put on /apdu. A bridge that stops answering (a handler
   *   wedged behind a long request on the single card thread) fails the
   *   call with an AbortError instead of hanging the loader for good.
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

  /**
   * One APDU, never retried. Returns {data: Buffer, sw: number}; a non-9000
   * status word is returned, not thrown (the helpers below throw CardError).
   */
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

  // ── cardctl.Card, one to one ──────────────────────────────────────────

  /** SELECT by AID, 7-byte package AID then the 8-byte applet AID. Returns {major, minor}. */
  async select() {
    let last
    for (const aid of [PACKAGE_AID, APPLET_AID]) {
      try {
        const v = await this.send(encode.select(aid), "SELECT")
        return { major: v[0], minor: v[1] }
      } catch (e) {
        if (!(e instanceof CardError)) throw e
        last = e
      }
    }
    throw last
  }

  async getInfo() { return parseInfo(await this.send(encode.getInfo(), "GET_INFO")) }

  /** The 33-byte compressed pubkey as the card sends it (jCardSim always answers 33). */
  async getPubkey() { return this.send(encode.getPubkey(), "GET_PUBKEY") }

  async getBalance() { return (await this.send(encode.getBalance(), "GET_BALANCE")).readUInt32BE(0) }

  async getProofCount() { return (await this.send(encode.getProofCount(), "GET_PROOF_COUNT"))[0] }

  /** One status byte per slot, as numbers (0 empty, 1 unspent, 2 spent). */
  async getSlotStatus() { return Array.from(await this.send(encode.getSlotStatus(), "GET_SLOT_STATUS")) }

  async getProof(slot) { return parseProof(slot, await this.send(encode.getProof(slot), `GET_PROOF slot ${slot}`)) }

  /** Marks the slot spent and returns the 64-byte BIP-340 signature. Not idempotent. */
  async spendProof(slot, message) { return this.send(encode.spendProof(slot, message), `SPEND_PROOF slot ${slot}`) }

  async sign(message) { return this.send(encode.sign(message), "SIGN_ARBITRARY") }

  /** Returns the slot the proof landed in. Not idempotent: a replay burns a second slot. */
  async loadProof(keysetId, amount, nonce, C) { return (await this.send(encode.loadProof(keysetId, amount, nonce, C), "LOAD_PROOF"))[0] }

  async clearSpent() { return (await this.send(encode.clearSpent(), "CLEAR_SPENT"))[0] }

  async verifyPin(pin) { await this.send(encode.verifyPin(pin), "VERIFY_PIN") }

  async setPin(pin) { await this.send(encode.setPin(pin), "SET_PIN") }

  async changePin(oldPin, newPin) { await this.send(encode.changePin(oldPin, newPin), "CHANGE_PIN") }

  async clearPin(pin) { await this.send(encode.clearPin(pin), "CLEAR_PIN") }

  async setPuk(puk) { await this.send(encode.setPuk(puk), "SET_PUK") }

  async unblockPin(puk, newPin) { await this.send(encode.unblockPin(puk, newPin), "UNBLOCK_PIN") }

  async lockCard() { await this.send(encode.lockCard(), "LOCK_CARD") }
}

const constants = Object.freeze({
  CLA, INS, SW, CAP, PACKAGE_AID, APPLET_AID, MAX_PROOFS, PROOF_SIZE, LOCK_CONFIRM_BYTE,
  MAX_SLOT_AMOUNT, PIN_MIN_LEN, PIN_MAX_LEN, PUK_MIN_LEN, PUK_MAX_LEN, STATUS_NAMES,
})

module.exports = {
  CardSim, CardError, CardSimError, encode, constants,
  validateFixture, validateSlotAmount, parseInfo, parseProof, describeSw, toBytes,
}
