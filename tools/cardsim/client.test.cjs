// node --test tools/cardsim/client.test.cjs
//
// Pure tests always run: the encoders are asserted against the vectors in
// tools/cardctl/test_apdu.py, so the JS client and the Python driver put the
// same bytes on the wire. The integration tests need a running bridge and
// run only with CARDSIM_URL set (CI starts the jar first):
//
//   CARDSIM_URL=http://127.0.0.1:9876 node --test tools/cardsim/client.test.cjs
const test = require("node:test")
const assert = require("node:assert/strict")
const {
  CardSim, CardError, CardSimError, encode, constants, validateFixture, validateSlotAmount, parseInfo, parseProof, describeSw,
} = require("./client.cjs")

const hex = s => Buffer.from(s.replace(/\s+/g, ""), "hex")
const bytes = n => Buffer.from(Array.from({ length: n }, (_, i) => i))

// ── encoders: test_apdu.py vectors ───────────────────────────────────────────

test("select uses the 7-byte package AID, with the 8-byte applet AID as the fallback", () => {
  assert.deepEqual(encode.select(), hex("00A4040007D2760000850102"))
  assert.deepEqual(encode.select(constants.APPLET_AID), hex("00A4040008D276000085010201"))
})

test("read command encodings match spec/APDU.md", () => {
  assert.deepEqual(encode.getInfo(), hex("B0010000 00"))
  assert.deepEqual(encode.getPubkey(), hex("B0100000 21"))
  assert.deepEqual(encode.getBalance(), hex("B0110000 04"))
  assert.deepEqual(encode.getProofCount(), hex("B0120000 01"))
  assert.deepEqual(encode.getSlotStatus(), hex("B0140000 20"))
  assert.deepEqual(encode.getProof(5), hex("B0130500 4E"))
})

test("spendProof puts the slot in P1 and asks for 64 bytes", () => {
  const expected = Buffer.concat([hex("B0200300"), Buffer.from([0x20]), bytes(32), Buffer.from([0x40])])
  assert.deepEqual(encode.spendProof(3, bytes(32)), expected)
  assert.deepEqual(encode.spendProof(3, bytes(32).toString("hex")), expected, "hex message")
})

test("sign encoding", () => {
  assert.deepEqual(encode.sign(bytes(32)), Buffer.concat([hex("B0210000"), Buffer.from([0x20]), bytes(32), Buffer.from([0x40])]))
})

test("loadProof builds a 77-byte payload", () => {
  const sent = encode.loadProof("0059534ce0bfa19a", 4096, bytes(32), Buffer.concat([Buffer.from([2]), bytes(32)]))
  assert.deepEqual(sent.subarray(0, 4), hex("B0300000"))
  assert.equal(sent[4], 0x4d, "Lc is 77")
  const payload = sent.subarray(5, 5 + 77)
  assert.deepEqual(payload.subarray(0, 8), hex("0059534ce0bfa19a"))
  assert.equal(payload.readUInt32BE(8), 4096)
  assert.deepEqual(payload.subarray(12, 44), bytes(32))
  assert.equal(payload[44], 2)
  assert.equal(sent[sent.length - 1], 0x01, "Le")
  assert.equal(sent.length, 4 + 1 + 77 + 1)
})

test("loadProof round-trips the keyset id through parseProof", () => {
  const sent = encode.loadProof("008288762774ace1", 8, Buffer.alloc(32), Buffer.concat([Buffer.from([2]), Buffer.alloc(32)]))
  const written = sent.subarray(5, 13)
  const body = Buffer.concat([Buffer.from([1]), written, Buffer.from([0, 0, 0, 8]), Buffer.alloc(32), Buffer.from([2]), Buffer.alloc(32)])
  assert.equal(parseProof(0, body).keysetId, "008288762774ace1")
})

test("clearSpent, verifyPin, setPin, changePin, clearPin encodings", () => {
  assert.deepEqual(encode.clearSpent(), hex("B0310000 01"))
  assert.deepEqual(encode.verifyPin("1234"), Buffer.concat([hex("B0400000"), Buffer.from([4]), Buffer.from("1234")]))
  assert.deepEqual(encode.setPin("1234"), Buffer.concat([hex("B0410000"), Buffer.from([4]), Buffer.from("1234")]))
  const change = encode.changePin("1234", "567890")
  assert.deepEqual(change.subarray(0, 4), hex("B0420000"))
  assert.equal(change[4], 1 + 4 + 6)
  assert.equal(change[5], 4)
  assert.deepEqual(change.subarray(6, 10), Buffer.from("1234"))
  assert.deepEqual(change.subarray(10), Buffer.from("567890"))
  const clear = encode.clearPin("1234")
  assert.deepEqual(clear, Buffer.concat([hex("B0430000"), Buffer.from([5, 4]), Buffer.from("1234")]))
})

test("setPuk prefixes the PUK length and sends nothing after it", () => {
  const sent = encode.setPuk("123456789012")
  assert.deepEqual(sent.subarray(0, 4), hex("B0440000"))
  assert.equal(sent[4], 1 + 12)
  assert.equal(sent[5], 12)
  assert.deepEqual(sent.subarray(6, 18), Buffer.from("123456789012"))
  assert.equal(sent.length, 18, "no Le, no trailing bytes")
})

test("unblockPin frames the PUK and the new PIN each with a length", () => {
  const sent = encode.unblockPin("12345678", "5678")
  assert.deepEqual(sent.subarray(0, 4), hex("B0450000"))
  assert.equal(sent[4], 2 + 8 + 4)
  assert.equal(sent[5], 8)
  assert.deepEqual(sent.subarray(6, 14), Buffer.from("12345678"))
  assert.equal(sent[14], 4)
  assert.deepEqual(sent.subarray(15, 19), Buffer.from("5678"))
  assert.equal(sent.length, 19)
})

test("lockCard sends the confirmation byte in P2", () => {
  assert.deepEqual(encode.lockCard(), hex("B05000DE"))
})

// ── parsers ──────────────────────────────────────────────────────────────────

test("parseInfo reads 8 and 9 bytes; pukState is null on 8", () => {
  const nine = parseInfo(hex("00 06 20 03 01 1c 1f 01 02"))
  assert.equal(nine.version, "0.6")
  assert.equal(nine.maxSlots, 32)
  assert.equal(nine.unspent, 3)
  assert.equal(nine.spent, 1)
  assert.equal(nine.empty, 28)
  assert.equal(nine.capsRaw, 0x1f)
  assert.equal(nine.clearPin, true)
  assert.equal(nine.unblockPin, true)
  assert.equal(nine.pinState, 1)
  assert.equal(nine.pukState, 2)

  const eight = parseInfo(hex("00 05 20 00 00 20 0f 00"))
  assert.equal(eight.version, "0.5")
  assert.equal(eight.unblockPin, false)
  assert.equal(eight.pukState, null)

  assert.throws(() => parseInfo(hex("00 04")), /expected 8 or 9/)
})

test("parseProof decodes the slot layout with the full 16-char keyset id", () => {
  const body = Buffer.concat([
    Buffer.from([1]), hex("0059534ce0bfa19a"), Buffer.from([0, 0, 4, 0xd2]), bytes(32), Buffer.from([2]), bytes(32),
  ])
  const p = parseProof(4, body)
  assert.equal(p.slot, 4)
  assert.equal(p.status, "unspent")
  assert.equal(p.keysetId, "0059534ce0bfa19a")
  assert.equal(p.amount, 1234)
  assert.equal(p.nonce, bytes(32).toString("hex"))
  assert.equal(p.C, "02" + bytes(32).toString("hex"))
  assert.throws(() => parseProof(0, body.subarray(1)), /expected 78/)
})

test("describeSw names the PUK for UNBLOCK_PIN and the PIN elsewhere", () => {
  assert.match(describeSw(0x63c2, "UNBLOCK_PIN"), /wrong PUK — 2 PUK tries/)
  assert.match(describeSw(0x63c2, "VERIFY_PIN"), /wrong PIN — 2 retries/)
  assert.match(describeSw(0x6983, "UNBLOCK_PIN"), /PUK exhausted/)
  assert.equal(describeSw(0x6a84), "no space — all slots occupied")
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
  assert.throws(() => encode.spendProof(0, bytes(31)), /32 bytes/)
  assert.throws(() => encode.spendProof(32, bytes(32)), /slot must be/)
  assert.throws(() => encode.sign("zz"), /not valid hex/)
  assert.throws(() => encode.verifyPin("123"), /pin must be 4-8 bytes/)
  assert.throws(() => encode.setPuk("1234567"), /puk must be 8-12 bytes/)
  assert.throws(() => encode.unblockPin("12345678", "123456789"), /new pin must be 4-8 bytes/)
  assert.equal(validateSlotAmount(2 ** 31), 2 ** 31)
  // The same checks through the client: rejected synchronously, fetch never called.
  await assert.rejects(sim.loadProof("0059534ce0bfa19a", 3, n, c), /power of two/)
  await assert.rejects(sim.apdu("B0"), /at least CLA INS P1 P2/)
})

test("validateFixture mirrors the server's checks", () => {
  const proof = { keysetId: "0059534ce0bfa19a", amount: 8, nonce: "ab".repeat(32), C: "02" + "11".repeat(32) }
  assert.deepEqual(validateFixture({}), {})
  assert.deepEqual(validateFixture({ pin: "1234", puk: "12345678", proofs: [proof], spentSlots: [0], blockedPin: true, appletVersion: "0.6" }).spentSlots, [0])
  assert.throws(() => validateFixture({ bogus: 1 }), /unknown fixture key: bogus/)
  assert.throws(() => validateFixture({ blockedPin: true }), /blockedPin requires pin/)
  assert.throws(() => validateFixture({ pin: "123" }), /pin must be 4-8/)
  assert.throws(() => validateFixture({ puk: "12345678", appletVersion: "0.4" }), /no SET_PUK/)
  assert.throws(() => validateFixture({ appletVersion: "six" }), /appletVersion/)
  assert.throws(() => validateFixture({ proofs: [{ ...proof, C: "05" + "11".repeat(32) }] }), /02\/03 prefix/)
  assert.throws(() => validateFixture({ proofs: [{ ...proof, amount: 2 ** 32 }] }), /amount/)
  assert.throws(() => validateFixture({ proofs: [{ ...proof, spent: false }] }), /unknown key in proofs\[0\]: spent/)
  assert.throws(() => validateFixture({ proofs: [{ keysetId: proof.keysetId, amount: 8, nonce: proof.nonce }] }), /missing C/)
  assert.throws(() => validateFixture({ proofs: [proof], spentSlots: [7] }), /not an index/)
  assert.throws(() => validateFixture({ proofs: [proof], spentSlots: [0, 0] }), /repeats 0/)
  assert.throws(() => validateFixture({ proofs: Array(33).fill(proof) }), /33 entries/)
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
  const r = await sim.apdu("B0 13 00 00 4E")
  assert.equal(seen[0].url, "http://127.0.0.1:9/apdu")
  assert.equal(seen[0].init.method, "POST")
  assert.deepEqual(JSON.parse(seen[0].init.body), { hex: "b01300004e" })
  assert.equal(r.sw, 0x6a88)
  assert.equal(r.data.length, 0)
  await assert.rejects(sim.getProof(0), e => e instanceof CardError && e.sw === 0x6a88 && /GET_PROOF slot 0/.test(e.message))
  assert.equal(seen.length, 2)
})

test("a non-2xx from the bridge is a CardSimError carrying the body", async () => {
  const fetch = async () => ({ ok: false, status: 409, text: async () => JSON.stringify({ error: "SET_PIN", sw: "6985", state: { generation: 2 } }) })
  const sim = new CardSim("http://127.0.0.1:9", { fetch })
  await assert.rejects(sim.fixture({ pin: "5678" }), e => e instanceof CardSimError && e.status === 409 && e.body.sw === "6985")
})

test("every request carries an AbortSignal and a wedged bridge fails the call at timeoutMs", async () => {
  // A real server that accepts the request and never answers: the shape of a
  // /fixture stuck behind a long request on the bridge's one card thread. It
  // has to be a real socket, not a fake fetch that only settles on abort:
  // AbortSignal.timeout()'s timer is unref'd, so with nothing else holding
  // the loop open Node 22 drains the loop before the deadline and node:test
  // cancels the pending test (and every test after it). In production the
  // socket is what keeps the loop alive, as it does here. The deadline is
  // well above the first fetch's cold start (undici loads lazily, ~15 ms on
  // a warm laptop) so the request has reached the server when it fires.
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

test("select falls back to the 8-byte AID and rethrows the last CardError", async () => {
  const sent = []
  const fetch = async (url, init) => {
    sent.push(JSON.parse(init.body).hex)
    const answer = sent.length === 1 ? { hex: "6A82", sw: "6A82" } : { hex: "00069000", sw: "9000" }
    return { ok: true, status: 200, text: async () => JSON.stringify(answer) }
  }
  const sim = new CardSim("http://127.0.0.1:9", { fetch })
  assert.deepEqual(await sim.select(), { major: 0, minor: 6 })
  assert.deepEqual(sent, ["00a4040007d2760000850102", "00a4040008d276000085010201"])

  const dead = new CardSim("http://127.0.0.1:9", { fetch: async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ hex: "6A82", sw: "6A82" }) }) })
  await assert.rejects(dead.select(), e => e instanceof CardError && e.sw === 0x6a82)
})

// ── integration: only with a running bridge ──────────────────────────────────

const URL = process.env.CARDSIM_URL
const integration = { skip: URL ? false : "set CARDSIM_URL to run against a bridge" }

test("reset → select → fixture {pin, puk, blockedPin} → pinState 2 → unblockPin → verifyPin", integration, async () => {
  const sim = new CardSim(URL)
  await sim.waitReady()
  const fresh = await sim.reset()
  assert.equal(fresh.pubkey.length, 66)
  assert.deepEqual(await sim.select(), { major: 0, minor: 6 })
  const state = await sim.fixture({ pin: "1234", puk: "12345678", blockedPin: true })
  assert.equal(state.pinState, 2)
  assert.equal(state.pukState, 1)
  assert.equal((await sim.getInfo()).pinState, 2)
  await assert.rejects(sim.verifyPin("1234"), e => e instanceof CardError && e.sw === constants.SW.PIN_BLOCKED)
  await sim.unblockPin("12345678", "5678")
  await sim.verifyPin("5678")
  assert.equal((await sim.sign(bytes(32))).length, 64, "the session is open")
  await sim.select()
  await assert.rejects(sim.sign(bytes(32)), e => e.sw === constants.SW.SECURITY_NOT_SATISFIED, "SELECT dropped the session")
  assert.equal((await sim.state()).pubkey, fresh.pubkey, "the key is deterministic across the run")
})

test("a full-card fixture makes loadProof throw CardError(6A84)", integration, async () => {
  const sim = new CardSim(URL)
  await sim.reset()
  const proofs = Array.from({ length: 32 }, (_, i) => ({
    keysetId: "0059534ce0bfa19a", amount: 2 ** (i % 20), nonce: i.toString(16).padStart(2, "0").repeat(32), C: "02" + (0x40 + i).toString(16).repeat(32),
  }))
  const state = await sim.fixture({ proofs, spentSlots: [1] })
  assert.equal(state.slots.filter(s => s.status === "unspent").length, 31)
  assert.equal(state.slots[1].status, "spent")
  await sim.select()
  assert.deepEqual((await sim.getSlotStatus()).slice(0, 3), [1, 2, 1])
  assert.equal(await sim.getProofCount(), 32)
  assert.equal((await sim.getProof(1)).nonce, "01".repeat(32))
  await assert.rejects(
    sim.loadProof("0059534ce0bfa19a", 2, "ff".repeat(32), "02" + "11".repeat(32)),
    e => e instanceof CardError && e.sw === constants.SW.NO_SPACE,
  )
  assert.equal(await sim.clearSpent(), 1)
  assert.equal(await sim.loadProof("0059534ce0bfa19a", 2, "ff".repeat(32), "02" + "11".repeat(32)), 1, "the freed slot")
})

test("a refused fixture step is a CardSimError(409) and state keeps fixtureError", integration, async () => {
  const sim = new CardSim(URL)
  await sim.reset()
  await sim.fixture({ pin: "1234" })
  await assert.rejects(sim.fixture({ pin: "5678" }), e => e instanceof CardSimError && e.status === 409 && e.body.error === "SET_PIN")
  assert.deepEqual((await sim.state()).fixtureError, { step: "SET_PIN", sw: "6985" })
})
