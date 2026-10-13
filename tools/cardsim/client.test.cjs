// node --test tools/cardsim/client.test.cjs
//
// Pure tests always run: the encoders are asserted against the vectors in tools/cardctl/test_apdu.py, so the JS
// client and the Python driver put the same bytes on the wire. The integration tests need a running bridge and run
// only with CARDSIM_URL set (CI starts the jar first):
//
//   CARDSIM_URL=http://127.0.0.1:9876 node --test tools/cardsim/client.test.cjs
//
// The swap at a real mint is e2e-swap.test.cjs (CARDSIM_URL and MINT_URL).
const test = require("node:test")
const assert = require("node:assert/strict")
const nodeCrypto = require("node:crypto")
const {
  CardSim, CardError, CardSimError, encode, constants, validateFixture, validateSlotAmount, parseInfo, parseProof, parseCard,
  parseChange, describeSw, ownerProof, ownerData, ownerPublicKey, limitValue,
} = require("./client.cjs")
const cc = require("./cashu-crypto.cjs")

const hex = s => Buffer.from(s.replace(/\s+/g, ""), "hex")
const bytes = n => Buffer.from(Array.from({ length: n }, (_, i) => i))
// The TEST owner key's public half, as tools/cardctl/p256.py makes it.
const TEST_OWNER_PUB = "0414bc3b7ffd3c105a4248d9ea59d36e4704e6beffa71f528730cd88f83434d5074445b3f6384158fd90c9f890179dbfc5c6b2a927bf5e3c8d8231b5e813e8dae9"

// ── encoders: test_apdu.py vectors ───────────────────────────────────────────

test("select uses the applet's 11-byte AID, F0 CASHUCARD 01, with the 10-byte package AID as the fallback (D25)", () => {
  assert.deepEqual(encode.select(), hex("00A404000BF043415348554341524401"))
  assert.deepEqual(encode.select(constants.APPLET_AID), hex("00A404000BF043415348554341524401"))
  assert.deepEqual(encode.select(constants.PACKAGE_AID), hex("00A404000AF0434153485543415244"))
  assert.deepEqual(constants.SELECT_AIDS, [constants.APPLET_AID, constants.PACKAGE_AID])
  assert.deepEqual(constants.PACKAGE_AID, Buffer.concat([Buffer.from([0xf0]), Buffer.from("CASHUCARD")]))
  assert.deepEqual(constants.APPLET_AID, Buffer.concat([constants.PACKAGE_AID, Buffer.from([0x01])]))
  assert.deepEqual(constants.OLD_AIDS.upstream0x, hex("D2760000850102"))
  assert.deepEqual(constants.OLD_AIDS.foxy1x, hex("F0464F585943415244"))
})

test("read command encodings match spec/APDU.md", () => {
  assert.deepEqual(encode.getInfo(), hex("B0010200 00"), "the long form, P1 = 2")
  assert.deepEqual(encode.getInfo(0), hex("B0010000 00"))
  assert.deepEqual(encode.getPubkey(), hex("B0100000 21"))
  assert.deepEqual(encode.getBalance(), hex("B0110000 04"))
  assert.deepEqual(encode.getProofCount(), hex("B0120000 01"))
  assert.deepEqual(encode.getSlotStatus(), hex("B0140000 80"))
  assert.deepEqual(encode.getProof(100), hex("B0136400 52"))
  assert.deepEqual(encode.getCard(), hex("B0160000 00"))
  assert.deepEqual(encode.getNonce(), hex("B0440000 10"))
  assert.deepEqual(encode.auth(bytes(16)), Buffer.concat([hex("B0150000 10"), bytes(16), hex("50")]))
  assert.deepEqual(encode.getChange(1), hex("B0190100 00"))
  assert.deepEqual(encode.getDleq(3), hex("B01A03FF 00"))
  assert.deepEqual(encode.getDleq(3, 4), hex("B01A0304 00"))
  assert.deepEqual(encode.getPieces(0, 3), hex("B0170003 00"))
})

test("loadProof builds an 81-byte payload with the date, and 177 bytes with the mint's proof (P1 = 1, Le 2)", () => {
  const sent = encode.loadProof("0059534ce0bfa19a", 4096, bytes(32), Buffer.concat([Buffer.from([2]), bytes(32)]), 1900000000)
  assert.deepEqual(sent.subarray(0, 4), hex("B0300000"))
  assert.equal(sent[4], 81, "Lc is 81")
  const payload = sent.subarray(5, 5 + 81)
  assert.deepEqual(payload.subarray(0, 8), hex("0059534ce0bfa19a"))
  assert.equal(payload.readUInt32BE(8), 4096)
  assert.deepEqual(payload.subarray(12, 44), bytes(32))
  assert.equal(payload[44], 2)
  assert.equal(payload.readUInt32BE(77), 1900000000)
  assert.equal(sent[sent.length - 1], 0x01, "Le")
  const withProof = encode.loadProof("0059534ce0bfa19a", 8, bytes(32), Buffer.concat([Buffer.from([2]), bytes(32)]), 0,
    { e: "01".repeat(32), s: "02".repeat(32), r: "03".repeat(32) })
  assert.deepEqual(withProof.subarray(0, 4), hex("B0300100"))
  assert.equal(withProof[4], 177)
  assert.deepEqual(withProof.subarray(5 + 81, 5 + 177), Buffer.concat([hex("01".repeat(32)), hex("02".repeat(32)), hex("03".repeat(32))]))
  assert.equal(withProof[withProof.length - 1], 0x02)
})

test("loadProof round-trips the keyset id and the date through parseProof", () => {
  const sent = encode.loadProof("008288762774ace1", 8, Buffer.alloc(32), Buffer.concat([Buffer.from([2]), Buffer.alloc(32)]), 7)
  const written = sent.subarray(5, 5 + 81)
  const p = parseProof(0, Buffer.concat([Buffer.from([1]), written]))
  assert.equal(p.keysetId, "008288762774ace1")
  assert.equal(p.date, 7)
})

test("the payment's encodings: BEGIN the places, OUTPUTS 37 bytes each, CHANGE the amount, SIGN and AGAIN ask for 64", () => {
  assert.deepEqual(encode.spendAllBegin([0, 5, 127]), hex("B0220000 03 00057F 04"))
  const out = encode.spendAllOutputs([{ amount: 16, B_: "02" + "11".repeat(32) }, { amount: 2, B_: "03" + "22".repeat(32) }])
  assert.deepEqual(out.subarray(0, 5), hex("B0230000 4A"))
  assert.equal(out.length, 5 + 74, "no Le")
  assert.equal(out.readUInt32BE(5), 16)
  assert.deepEqual(encode.spendAllChange(8), hex("B0260000 04 00000008 21"))
  assert.deepEqual(encode.spendAllSign(), hex("B0240000 40"))
  assert.deepEqual(encode.spendAllAgain(), hex("B0250000 40"))
  assert.throws(() => encode.spendAllOutputs(Array(7).fill({ amount: 1, B_: "02" + "11".repeat(32) })), /1 to 6/)
  assert.throws(() => encode.spendAllBegin([]), /1 to 128/)
  assert.throws(() => encode.spendAllChange(3), /power of two/)
})

test("clearSpent, setHeader, verifyPin, setPin encodings", () => {
  assert.deepEqual(encode.clearSpent(), hex("B0310000 01"))
  assert.deepEqual(encode.setHeader(bytes(80)), Buffer.concat([hex("B0360000 50"), bytes(80), hex("04")]))
  assert.deepEqual(encode.verifyPin("1234"), Buffer.concat([hex("B0400000"), Buffer.from([4]), Buffer.from("1234")]))
  assert.deepEqual(encode.setPin("1234"), Buffer.concat([hex("B0410000"), Buffer.from([4]), Buffer.from("1234")]))
})

// ── the owner's proof ────────────────────────────────────────────────────────

test("the TEST owner key is cardctl's, and ownerProof verifies over label || nonce || value", () => {
  assert.equal(ownerPublicKey().toString("hex"), TEST_OWNER_PUB)
  const nonce = bytes(16), value = Buffer.from("5678")
  const proof = ownerProof(constants.LABEL.CHANGE_PIN, nonce, value)
  const pub = nodeCrypto.createPublicKey({ key: { kty: "EC", crv: "P-256", x: hex(TEST_OWNER_PUB).subarray(1, 33).toString("base64url"), y: hex(TEST_OWNER_PUB).subarray(33).toString("base64url") }, format: "jwk" })
  assert.ok(nodeCrypto.verify("sha256", Buffer.concat([Buffer.from("CashuCard/change-pin"), nonce, value]), { key: pub, dsaEncoding: "der" }, proof))
  assert.ok(!nodeCrypto.verify("sha256", Buffer.concat([Buffer.from("FoxyCard/change-pin"), nonce, value]), { key: pub, dsaEncoding: "der" }, proof), "not a Foxy label")
  const data = ownerData(proof, value)
  assert.equal(data[0], proof.length)
  assert.deepEqual(data.subarray(1 + proof.length), value)
})

test("the owner's commands: CHANGE_PIN, SET_OWNER with the anchor, ALLOW_LOAD, SET_LIMIT, REFRESH, LOCK_CARD", () => {
  const proof = Buffer.alloc(70, 7)
  assert.deepEqual(encode.changePin(proof, "5678").subarray(0, 6), hex("B0420000 4B 46"))
  assert.deepEqual(encode.setOwner(TEST_OWNER_PUB), Buffer.concat([hex("B0430000 41"), hex(TEST_OWNER_PUB)]))
  assert.deepEqual(encode.setOwner(TEST_OWNER_PUB, bytes(80)), Buffer.concat([hex("B0430000 91"), hex(TEST_OWNER_PUB), bytes(80)]))
  assert.deepEqual(encode.setOwner(TEST_OWNER_PUB, null, proof).subarray(0, 6), hex("B0430000 88 46"))
  assert.deepEqual(encode.allowLoad(proof), Buffer.concat([hex("B0450000 47 46"), proof]))
  assert.deepEqual(encode.setLimit(proof, limitValue({ day: 100 })).subarray(0, 5), hex("B0340000 4B"))
  assert.deepEqual(encode.refresh(proof, bytes(80)).subarray(-1), hex("04"), "Le 4: the clock")
  assert.deepEqual(encode.refresh(proof, bytes(80)).subarray(0, 5), hex("B0530000 97"))
  assert.deepEqual(encode.lockCard(proof).subarray(0, 4), hex("B05000DE"))
})

test("limitValue is 4, 8, 12 or 13 bytes, and refuses a form that would zero what it was not given", () => {
  assert.equal(limitValue({ day: 1 }).length, 4)
  assert.equal(limitValue({ day: 1, payment: 0 }).length, 8)
  assert.equal(limitValue({ day: 1, payment: 0, allowance: 5 }).length, 12)
  assert.deepEqual(limitValue({ day: 1, payment: 2, allowance: 3, rollBudget: 7 }), hex("00000001 00000002 00000003 07"))
  assert.throws(() => limitValue({ day: 1, rollBudget: 7 }), /payment and allowance/)
  assert.throws(() => limitValue({ day: 1, allowance: 7 }), /give payment/)
  assert.throws(() => limitValue({ day: 1, payment: 0, allowance: 0, rollBudget: 0 }), /1 to 30/)
  assert.throws(() => limitValue({ day: 1, payment: 0, allowance: 0, rollBudget: 31 }), /1 to 30/)
})

// ── parsers ──────────────────────────────────────────────────────────────────

test("parseInfo reads 30, 42 and 43 bytes", () => {
  const b = Buffer.alloc(43)
  Buffer.from([2, 0, 128, 3, 1, 124, 0xff, 1, 4, 3, 0, 1]).copy(b)
  b.writeUInt32BE(5000, 12); b[16] = 1; b.writeUInt32BE(1791814824, 17); b.writeUInt32BE(1791800000, 21); b.writeUInt32BE(100, 25)
  b.writeUInt32BE(250, 34); b.writeUInt32BE(50, 38); b[42] = 1
  const i = parseInfo(b)
  assert.equal(i.version, "2.0")
  assert.equal(i.maxSlots, 128)
  assert.equal(i.unspent, 3)
  assert.equal(i.pinState, 1)
  assert.equal(i.format, 4)
  assert.equal(i.dailyLimit, 5000)
  assert.equal(i.hasOwner, true)
  assert.equal(i.now, 1791814824)
  assert.equal(i.allowance, 250)
  assert.equal(i.nopinSpent, 50)
  assert.equal(i.tagOff, true)
  assert.equal(parseInfo(b.subarray(0, 30)).allowance, undefined)
  assert.throws(() => parseInfo(b.subarray(0, 9)), /expected 30, 42 or 43/)
})

test("parseProof decodes the 82-byte slot with the full 16-char keyset id and the date", () => {
  const body = Buffer.concat([Buffer.from([1]), hex("0059534ce0bfa19a"), Buffer.from([0, 0, 4, 0xd2]), bytes(32), Buffer.from([2]), bytes(32), hex("713fb300")])
  const p = parseProof(4, body)
  assert.equal(p.slot, 4)
  assert.equal(p.status, "unspent")
  assert.equal(p.keysetId, "0059534ce0bfa19a")
  assert.equal(p.amount, 1234)
  assert.equal(p.C, "02" + bytes(32).toString("hex"))
  assert.equal(p.date, 1900000000)
  assert.throws(() => parseProof(0, body.subarray(4)), /expected 82/)
})

test("parseCard reads the rollover bytes, budget 0 as the default 7; parseChange reads the openings", () => {
  const mint = Buffer.from("http://m")
  const b = Buffer.concat([hex("040100 00001388"), Buffer.alloc(33), Buffer.alloc(4), bytes(32), Buffer.from([2, 0, 1]), Buffer.alloc(26), Buffer.from([mint.length]), mint, Buffer.alloc(3)])
  const c = parseCard(b)
  assert.equal(c.dailyLimit, 5000)
  assert.equal(c.rolls, 2)
  assert.equal(c.rollBudget, 7)
  assert.equal(c.allowanceArmed, true)
  assert.equal(c.mint, "http://m")
  const opening = Buffer.concat([hex("00000008"), hex("0059534ce0bfa19a"), hex("00000000"), bytes(32), Buffer.alloc(32, 9)])
  assert.deepEqual(parseChange(Buffer.concat([Buffer.from([1]), opening])), [{ amount: 8, keysetId: "0059534ce0bfa19a", date: 0, nonce: bytes(32).toString("hex"), r: "09".repeat(32) }])
})

test("describeSw names the 2.0 words", () => {
  assert.match(describeSw(0x63c2), /wrong PIN — 2 retries/)
  assert.match(describeSw(0x6983), /change-pin/)
  assert.match(describeSw(0x6a8f), /day's limit/)
  assert.match(describeSw(0x6a91), /owner's proof/)
  assert.match(describeSw(0x6a82), /needs an update/)
  assert.equal(describeSw(0x1234), "unknown status word")
  const e = new CardError(0x6982, "LOAD_PROOF")
  assert.equal(e.sw, 0x6982)
  assert.match(e.message, /6982 during LOAD_PROOF/)
})

// ── argument checks: before any transport ────────────────────────────────────

test("amount and length checks throw before any transport", async () => {
  const sim = new CardSim("http://127.0.0.1:1", { fetch: async () => { throw new Error("transport reached") } })
  const n = bytes(32), c = Buffer.concat([Buffer.from([2]), bytes(32)])
  assert.throws(() => encode.loadProof("0059534ce0bfa19a", 2 ** 32, n, c), /below 2\*\*32/)
  assert.throws(() => encode.loadProof("0059534ce0bfa19a", 0, n, c), /below 2\*\*32/)
  assert.throws(() => encode.loadProof("0059534ce0bfa19a", 3, n, c), /power of two/)
  assert.throws(() => encode.loadProof("0059534ce0bfa19a", "8", n, c), /positive integer/)
  assert.throws(() => encode.loadProof("0059534c", 8, n, c), /keysetId must be 8 bytes/)
  assert.throws(() => encode.loadProof("0059534ce0bfa19a", 8, bytes(31), c), /nonce must be 32 bytes/)
  assert.throws(() => encode.loadProof("0059534ce0bfa19a", 8, n, bytes(34)), /C must be 33 bytes/)
  assert.throws(() => encode.loadProof("0059534ce0bfa19a", 8, n, c, -1), /date/)
  assert.throws(() => encode.loadProof("0059534ce0bfa19a", 8, n, c, 0, { e: "01".repeat(32), s: "02".repeat(32) }), /dleq.r/)
  assert.throws(() => encode.getProof(128), /slot must be/)
  assert.throws(() => encode.auth(bytes(15)), /16 bytes/)
  assert.throws(() => encode.setHeader(bytes(79)), /80 bytes/)
  assert.throws(() => encode.verifyPin("123"), /pin must be 4-8 bytes/)
  assert.throws(() => encode.setOwner(TEST_OWNER_PUB, bytes(79)), /80 bytes/)
  assert.throws(() => ownerData(Buffer.alloc(73)), /at most 72/)
  assert.equal(validateSlotAmount(2 ** 31), 2 ** 31)
  await assert.rejects(sim.loadProof("0059534ce0bfa19a", 3, n, c), /power of two/)
  await assert.rejects(sim.apdu("B0"), /at least CLA INS P1 P2/)
})

test("validateFixture mirrors the server's checks on the body, and refuses the 0.x keys by name", () => {
  const proof = { keysetId: "0059534ce0bfa19a", amount: 8, nonce: "ab".repeat(32), C: "02" + "11".repeat(32) }
  assert.deepEqual(validateFixture({}), {})
  const full = {
    pin: "1234", mint: "http://m", refundKey: "02" + "11".repeat(32), owner: true, anchor: "00".repeat(80), headers: ["00".repeat(80)],
    proofs: [{ ...proof, date: 5, dleq: { e: "01".repeat(32), s: "02".repeat(32), r: "03".repeat(32) } }], spentSlots: [0],
    limits: { day: 1, payment: 0, allowance: 1, rollBudget: 7 }, blockedPin: true,
  }
  assert.deepEqual(validateFixture(full), full)
  assert.throws(() => validateFixture({ puk: "12345678" }), /no PUK/)
  assert.throws(() => validateFixture({ appletVersion: "0.6" }), /version masks are gone/)
  assert.throws(() => validateFixture({ bogus: 1 }), /unknown fixture key: bogus/)
  assert.throws(() => validateFixture({ blockedPin: true }), /blockedPin requires pin/)
  assert.throws(() => validateFixture({ pin: "123" }), /pin must be 4-8/)
  assert.throws(() => validateFixture({ owner: true, ownerKey: "11".repeat(32) }), /not both/)
  assert.throws(() => validateFixture({ anchor: "00".repeat(80) }), /given with owner/)
  assert.throws(() => validateFixture({ refundKey: "02" + "11".repeat(32) }), /given with mint/)
  assert.throws(() => validateFixture({ limits: { week: 1 } }), /unknown key in limits/)
  assert.throws(() => validateFixture({ limits: { rollBudget: 31 } }), /1 to 30/)
  assert.throws(() => validateFixture({ proofs: [{ ...proof, C: "05" + "11".repeat(32) }] }), /02\/03 prefix/)
  assert.throws(() => validateFixture({ proofs: [{ ...proof, amount: 2 ** 32 }] }), /amount/)
  assert.throws(() => validateFixture({ proofs: [{ ...proof, spent: false }] }), /unknown key in proofs\[0\]: spent/)
  assert.throws(() => validateFixture({ proofs: [{ ...proof, dleq: { e: "01".repeat(32) } }] }), /dleq must be/)
  assert.throws(() => validateFixture({ proofs: [proof, { ...proof, C: "03" + "11".repeat(32) }] }), /repeats a nonce/)
  assert.throws(() => validateFixture({ proofs: [proof], spentSlots: [7] }), /not an index/)
  assert.throws(() => validateFixture({ proofs: [proof], spentSlots: [0, 0] }), /repeats 0/)
  assert.throws(() => validateFixture({ proofs: Array.from({ length: 129 }, (_, i) => ({ ...proof, nonce: i.toString(16).padStart(64, "0") })) }), /129 entries/)
  assert.throws(() => validateFixture(null), /must be an object/)
})

// ── transport: never retried ─────────────────────────────────────────────────

test("apdu() calls fetch exactly once and throws on a transport failure (no retry)", async () => {
  let calls = 0
  const sim = new CardSim("http://127.0.0.1:1", { fetch: async () => { calls++; throw new Error("ECONNREFUSED") } })
  await assert.rejects(sim.apdu("B001000000"), /ECONNREFUSED/)
  assert.equal(calls, 1)
})

test("apdu() posts lower-case hex to /apdu and parses data‖SW; a refusal is returned, not thrown", async () => {
  const seen = []
  const fetch = async (url, init) => {
    seen.push({ url, init })
    return { ok: true, status: 200, text: async () => JSON.stringify({ hex: "6A88", sw: "6A88" }) }
  }
  const sim = new CardSim("http://127.0.0.1:9/", { fetch })
  const r = await sim.apdu("B0 13 00 00 52")
  assert.equal(seen[0].url, "http://127.0.0.1:9/apdu")
  assert.equal(seen[0].init.method, "POST")
  assert.deepEqual(JSON.parse(seen[0].init.body), { hex: "b013000052" })
  assert.equal(r.sw, 0x6a88)
  assert.equal(r.data.length, 0)
  await assert.rejects(sim.getProof(0), e => e instanceof CardError && e.sw === 0x6a88 && /GET_PROOF slot 0/.test(e.message))
  assert.equal(seen.length, 2)
})

test("a non-2xx from the bridge is a CardSimError carrying the body", async () => {
  const fetch = async () => ({ ok: false, status: 409, text: async () => JSON.stringify({ error: "VERIFY_PIN", sw: "6983", state: { generation: 2 } }) })
  const sim = new CardSim("http://127.0.0.1:9", { fetch })
  await assert.rejects(sim.fixture({ pin: "5678" }), e => e instanceof CardSimError && e.status === 409 && e.body.sw === "6983")
})

test("every request carries an AbortSignal and a wedged bridge fails the call at timeoutMs", async () => {
  // A real server that accepts the request and never answers: the shape of a /fixture stuck behind a long request on
  // the bridge's one card thread. A real socket keeps the event loop alive until the unref'd AbortSignal timer fires.
  const http = require("node:http")
  const hits = []
  const sockets = new Set()
  const server = http.createServer(req => { hits.push(req.url) })
  server.on("connection", s => { sockets.add(s); s.on("close", () => sockets.delete(s)) })
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve))
  try {
    const seen = []
    const fetch = (url, init) => { seen.push(init); return globalThis.fetch(url, init) }
    const sim = new CardSim(`http://127.0.0.1:${server.address().port}`, { fetch, timeoutMs: 250 })
    const started = Date.now()
    await assert.rejects(sim.fixture({ pin: "1234" }), e => e.name === "TimeoutError")
    assert.ok(Date.now() - started < 2000, "failed at the deadline, not the 360-minute CI default")
    assert.ok(seen[0].signal instanceof AbortSignal)
    assert.equal(seen.length, 1, "a timed-out request is not retried")
    assert.deepEqual(hits, ["/fixture"], "the request reached the server exactly once")
  } finally {
    for (const s of sockets) s.destroy()
    await new Promise(resolve => server.close(resolve))
  }

  const ok = async () => ({ ok: true, status: 200, text: async () => "{}" })
  const dflt = new CardSim("http://127.0.0.1:9", { fetch: ok })
  assert.equal(dflt.timeoutMs, 5000, "the default matches the apps' 5 s transport deadline")
  assert.throws(() => new CardSim("http://127.0.0.1:9", { fetch: ok, timeoutMs: 0 }), RangeError)
  assert.throws(() => new CardSim("http://127.0.0.1:9", { fetch: ok, timeoutMs: Infinity }), RangeError)
})

test("waitReady is bounded", async () => {
  let calls = 0
  const sim = new CardSim("http://127.0.0.1:1", { fetch: async () => { calls++; throw new Error("down") } })
  await assert.rejects(sim.waitReady({ attempts: 3, intervalMs: 1 }), /not ready after 3 attempts/)
  assert.equal(calls, 3)
})

test("select tries the applet's whole AID first, falls back to the package AID and rethrows the last CardError", async () => {
  const sent = []
  const fetch = async (url, init) => {
    sent.push(JSON.parse(init.body).hex)
    const answer = sent.length === 1 ? { hex: "6A82", sw: "6A82" } : { hex: "02009000", sw: "9000" }
    return { ok: true, status: 200, text: async () => JSON.stringify(answer) }
  }
  const sim = new CardSim("http://127.0.0.1:9", { fetch })
  assert.deepEqual(await sim.select(), { major: 2, minor: 0 })
  assert.deepEqual(sent, ["00a404000bf043415348554341524401", "00a404000af0434153485543415244"])

  const dead = new CardSim("http://127.0.0.1:9", { fetch: async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ hex: "6A82", sw: "6A82" }) }) })
  await assert.rejects(dead.select(), e => e instanceof CardError && e.sw === 0x6a82)
})

/** A fake bridge that answers SELECT as the chip does (ENG-681): the package AID reaches the opener, 9000 and no body. */
const chipFetch = sent => async (url, init) => {
  const h = JSON.parse(init.body).hex.toUpperCase()
  sent.push(h)
  const answer = h === "00A404000BF043415348554341524401" ? { hex: "02009000", sw: "9000" }
    : h === "00A404000AF0434153485543415244" ? { hex: "9000", sw: "9000" }
    : { hex: "6D00", sw: "6D00" }
  return { ok: true, status: 200, text: async () => JSON.stringify(answer) }
}

test("on a chip's answers, select reaches the card's applet with its first SELECT, never the opener", async () => {
  const sent = []
  const sim = new CardSim("http://127.0.0.1:9", { fetch: chipFetch(sent) })
  assert.deepEqual(await sim.select(), { major: 2, minor: 0 })
  assert.deepEqual(sent, ["00A404000BF043415348554341524401"])
})

test("a 9000 with no version falls through to the next AID, and is no answer when it is the last", async () => {
  // the whole AID is not answered and the package AID reaches the opener: no 2.0 applet
  let n = 0
  const opener = new CardSim("http://127.0.0.1:9", {
    fetch: async () => ({ ok: true, status: 200, text: async () => JSON.stringify(n++ === 0 ? { hex: "6A82", sw: "6A82" } : { hex: "9000", sw: "9000" }) }),
  })
  await assert.rejects(opener.select(), e => !(e instanceof CardError) && /F0434153485543415244 answered 9000 with no version/.test(e.message))
  // an empty 9000 to the whole AID is passed over for the package AID's version
  const sent = []
  const empty = new CardSim("http://127.0.0.1:9", {
    fetch: async (url, init) => {
      sent.push(JSON.parse(init.body).hex)
      return { ok: true, status: 200, text: async () => JSON.stringify(sent.length === 1 ? { hex: "9000", sw: "9000" } : { hex: "02009000", sw: "9000" }) }
    },
  })
  assert.deepEqual(await empty.select(), { major: 2, minor: 0 })
  assert.deepEqual(sent, ["00a404000bf043415348554341524401", "00a404000af0434153485543415244"])
})

// ── integration: only with a running bridge ──────────────────────────────────

const URL = process.env.CARDSIM_URL
const integration = { skip: URL ? false : "set CARDSIM_URL to run against a bridge" }

/** n points to stand in for mints' C and tills' B_: real points, so nothing about them is fake but who made them. */
const pointHex = k => cc.hexOf(cc.compressed(cc.mul(BigInt(k))))

test("the bridge answers both SELECTs as the chip does: the whole AID 02 00, the package AID the opener's bare 9000", integration, async () => {
  const sim = new CardSim(URL)
  await sim.waitReady()
  await sim.reset()
  const byPackage = await sim.apdu(encode.select(constants.PACKAGE_AID))
  assert.equal(byPackage.sw, constants.SW.OK)
  assert.equal(byPackage.data.length, 0, "the opener answers with no version")
  assert.equal((await sim.apdu(encode.getInfo())).sw, constants.SW.INS_NOT_SUPPORTED, "and refuses the next command")
  const whole = await sim.apdu(encode.select(constants.APPLET_AID))
  assert.equal(whole.sw, constants.SW.OK)
  assert.deepEqual(whole.data, Buffer.from([2, 0]))
  assert.equal((await sim.getInfo()).version, "2.0")
  // and select(), with the package AID last tried and the opener selected before it, still reaches the card's applet
  await sim.apdu(encode.select(constants.PACKAGE_AID))
  assert.deepEqual(await sim.select(), { major: 2, minor: 0 })
  assert.equal((await sim.getInfo()).version, "2.0")
})

test("reset → select 2.0 → fixture {pin, mint, owner, blockedPin} → pinState 2 → the owner's changePin → verifyPin", integration, async () => {
  const sim = new CardSim(URL)
  await sim.waitReady()
  const fresh = await sim.reset()
  assert.equal(fresh.pubkey.length, 66)
  assert.equal(fresh.slots.length, 128)
  assert.deepEqual(await sim.select(), { major: 2, minor: 0 })
  const state = await sim.fixture({ pin: "1234", mint: "http://m", owner: true, blockedPin: true })
  assert.equal(state.pinState, 2)
  assert.equal(state.ownerKey, TEST_OWNER_PUB)
  assert.equal((await sim.getInfo()).pinState, 2)
  await assert.rejects(sim.verifyPin("1234"), e => e instanceof CardError && e.sw === constants.SW.PIN_BLOCKED)
  await sim.changePin("5678")
  await sim.verifyPin("5678")
  assert.equal((await sim.send(Buffer.from("B018000000", "hex"), "GET_LOG")).length > 0, true, "the session is open")
  await sim.select()
  await assert.rejects(sim.send(Buffer.from("B018000000", "hex"), "GET_LOG"), e => e.sw === constants.SW.SECURITY_NOT_SATISFIED, "SELECT dropped the session")
  assert.equal((await sim.state()).pubkey, fresh.pubkey, "the key is deterministic across the run")
})

test("the old AIDs select nothing: an app reads it as a card that needs an update", integration, async () => {
  const sim = new CardSim(URL)
  await sim.reset()
  for (const aid of [constants.OLD_AIDS.upstream0x, constants.OLD_AIDS.foxy1x]) {
    const { sw } = await sim.apdu(encode.select(aid))
    assert.notEqual(sw, constants.SW.OK, aid.toString("hex"))
  }
})

test("SPEND_ALL_* yields one SIG_ALL signature over the pieces, the till's outputs and the card's own change, verifying against the card key", integration, async () => {
  const sim = new CardSim(URL)
  const { pubkey } = await sim.reset()
  const pieces = [32, 16, 8].map((amount, i) => ({ keysetId: "00ad268c4d1f5826", amount, nonce: cc.hexOf(nodeCrypto.randomBytes(32)), C: pointHex(1000 + i) }))
  await sim.fixture({ pin: "1234", mint: "http://127.0.0.1:3338", owner: true, proofs: pieces })
  await sim.select()
  await sim.verifyPin("1234")
  assert.equal(await sim.spendAllBegin([0, 1]), 48, "what the two pieces are worth")
  const outputs = [{ amount: 16, B_: pointHex(7) }, { amount: 8, B_: pointHex(8) }, { amount: 4, B_: pointHex(9) }]
  await sim.spendAllOutputs(outputs)
  const change = [{ amount: 16, B_: cc.hexOf(await sim.spendAllChange(16)) }, { amount: 4, B_: cc.hexOf(await sim.spendAllChange(4)) }]
  const { signature } = await sim.spendAllSign()
  const inputs = pieces.slice(0, 2).map(p => ({ secret: cc.cardSecret(p.nonce, pubkey), C: p.C }))
  const message = cc.sigAllMessage(inputs, [...outputs, ...change])
  assert.ok(cc.schnorrVerify(Buffer.from(pubkey, "hex"), message, signature), "one signature for the whole payment, the change last")
  assert.ok(!cc.schnorrVerify(Buffer.from(pubkey, "hex"), cc.sigAllMessage(inputs, outputs), signature), "not a signature without the change")
  assert.deepEqual(await sim.spendAllAgain(), signature, "the same signature, asked again")
  const after = await sim.state()
  assert.deepEqual(after.slots.slice(0, 3).map(s => s.status), ["spent", "spent", "unspent"])
  // the change openings: each blinded message is the card's own secret, hashed to the curve and blinded with r
  await sim.select()
  const openings = await sim.getChange(0)
  assert.equal(openings.length, 2)
  openings.forEach((o, i) => {
    const B_ = cc.blind(cc.cardSecret(o.nonce, pubkey), Buffer.from(o.r, "hex")).B_
    assert.equal(cc.hexOf(B_), change[i].B_, "the card's B_ is NUT-00's, recomputed here")
    assert.equal(o.amount, change[i].amount)
  })
})

test("a full card: 128 pieces, then LOAD_PROOF is 6A84; the tap after a payment frees and loads with no PIN", integration, async () => {
  const sim = new CardSim(URL)
  await sim.reset()
  const proofs = Array.from({ length: 128 }, (_, i) => ({
    keysetId: "0059534ce0bfa19a", amount: 2 ** (i % 20), nonce: i.toString(16).padStart(2, "0").repeat(32), C: pointHex(i + 1),
  }))
  const state = await sim.fixture({ pin: "1234", mint: "http://m", owner: true, proofs, spentSlots: [1] })
  assert.equal(state.slots.filter(s => s.status === "unspent").length, 127)
  assert.equal(state.slots[1].status, "spent")
  await sim.select()
  assert.deepEqual((await sim.getSlotStatus()).slice(0, 3), [1, 2, 1])
  assert.equal(await sim.getProofCount(), 128)
  assert.equal((await sim.getProof(1)).nonce, "01".repeat(32))
  assert.equal(await sim.clearSpent(), 1, "the change grant: the tap after the fixture's payment")
  assert.equal(await sim.loadProof("0059534ce0bfa19a", 2, "ff".repeat(32), pointHex(999)), 1, "the freed slot")
  await assert.rejects(
    sim.loadProof("0059534ce0bfa19a", 2, "fe".repeat(32), pointHex(998)),
    e => e instanceof CardError && e.sw === constants.SW.NO_SPACE,
  )
})

test("a refused fixture step is a CardSimError(409) and state keeps fixtureError", integration, async () => {
  const sim = new CardSim(URL)
  await sim.reset()
  await sim.fixture({ pin: "1234" })
  await assert.rejects(sim.fixture({ pin: "5678" }), e => e instanceof CardSimError && e.status === 409 && e.body.error === "VERIFY_PIN")
  assert.deepEqual((await sim.state()).fixtureError, { step: "VERIFY_PIN", sw: "63C2" })
})

test("the 0.x fixture keys are refused locally and by the bridge", integration, async () => {
  const sim = new CardSim(URL)
  await sim.reset()
  await assert.rejects(sim.request("POST", "/fixture", { puk: "12345678" }), e => e instanceof CardSimError && e.status === 400)
  await assert.rejects(sim.request("POST", "/fixture", { appletVersion: "0.6" }), e => e instanceof CardSimError && e.status === 400)
})
