# cardsim: the 2.0 card over loopback HTTP

The real `CashuApplet` (protocol 2.0, AID `F0 43 41 53 48 55 43 41 52 44 01`) in
jCardSim, behind a small HTTP API. flash-pos and flash-mobile run it in their e2e
jobs, pinned by `CASHU_JAVACARD_REF`. **This file is that contract**: the four
routes, the `/fixture` schema, the `/state` fields and the Node client. A change to
any of them is a change for both apps, so it is made here and in both apps' pins
together.

```bash
mvn -B -f tools/cardsim/pom.xml package               # builds and tests, then target/cardsim.jar
java -jar tools/cardsim/target/cardsim.jar --port 9876
tools/cardsim/cardsim.sh --port 9876                  # the same, from source via Maven
```

The bridge binds `127.0.0.1` only. A port already in use is an error (exit 2), never
a reason to pick another port: a test that reached a stale bridge would be talking
to a card that holds an earlier run's state. Android reaches it through
`adb reverse tcp:9876 tcp:9876`.

`tools/cardsim/run.sh` and `ctl.sh` are Foxy's line-protocol bridge on port 47431,
for their iOS Simulator build. They are kept as they are. The HTTP bridge below is
the one the Flash apps and CI use.

## Routes

All bodies are JSON. Hex is accepted in either case. APDU fields come back in upper
case, and `/state`'s fields in lower case.

| Route | Answers | Status codes |
|---|---|---|
| `POST /apdu` `{"hex": "<command>"}` | `{"hex": "<data‖SW>", "sw": "9000"}` | **200** whenever the card answered, including a refusal (a non-`9000` `sw`). **400** for bad JSON or bad hex. |
| `POST /reset` | `/state` of a brand-new card | **200** |
| `POST /fixture` `{…}` (below) | `/state` after the fixture | **200** applied. **400** `{"error"}`: the fixture failed validation and the card is untouched. **409** `{"error": "<step>", "sw": "6985", "state": {…}}`: the applet refused a step. |
| `GET /state` | the card, read without changing it (below) | **200** |

Any other path is **404**, a wrong method is **405**, and anything the server did
not expect is **500** `{"error"}`. The card is kept as it was.

- **`/apdu` is never retried**, by the server or by `client.cjs`. A replayed
  `LOAD_PROOF` burns a slot. A replayed `SPEND_ALL_SIGN` of a payment already signed
  answers `6985`, and the signature is fetched again with `SPEND_ALL_AGAIN`.
- **`/reset`** builds a new simulator: the opener, the card's applet and the NFC tag
  are installed, `SELECT` is sent, and `generation` goes up by one. **The card key
  is deterministic.** jCardSim draws every key pair from an unseeded generator, so
  every reset (and every bridge) has the same `pubkey`
  (`02fa05ed0a3649886270bacec5ddc1a3643009a759bee996f9a6ac060c9992a82e` today). A
  piece minted to it in an earlier run may already be spent at the mint, so mint
  for each run after reading `/state.pubkey`. The card's other randomness (change
  openings, nonces) is seeded from the host and differs across resets.
- **Sessions.** `SELECT` starts one. The PIN-verified flag, the owner's nonce and
  the owner's load grant are cleared on deselect, so a re-`SELECT` drops them as a
  new NFC tap does. There is no "tap" route: a transport sends `SELECT` on each tap.
  `/state` sends no `SELECT` while the card's applet is selected (with the opener
  or the tag selected, see "SELECT the applet's whole AID" below). `/fixture` ends
  with one.
- **Old cards.** An old AID (0.x `D2 76 00 00 85 01 02`, or Foxy's 1.x
  `F0 46 4F 58 59 …`) through jCardSim answers `6E00` or `6999`, where a real card's
  runtime answers `6A82`. Treat any `SELECT` answer that is not `02xx 9000` as
  "This card needs an update".

## `/fixture`

A fixture is applied on top of the card as it is. The usual order is `/reset`, read
`/state.pubkey`, mint format-4 SIG_ALL pieces locked to that key at the mint, then
`/fixture`. Every key is optional. An unknown key, at any level, is a 400. The 0.x
keys `puk` and `appletVersion` are refused by name: 2.0 has no PUK and no version
mask.

```jsonc
{
  "pin":        "1234",                    // 4-8 characters: SET_PIN on a card with none, then VERIFY_PIN
  "mint":       "http://127.0.0.1:3338",   // 1-77 ASCII characters: the record (SET_CARD)
  "refundKey":  "02…",                     // 33 bytes, a compressed point, with "mint": the record's refund key
  "owner":      true,                      // SET_OWNER with the public TEST owner key (below)
  "ownerKey":   "<32 bytes>",              // SET_OWNER with this P-256 private key instead (not with "owner")
  "anchor":     "<80-byte header>",        // with an owner: SET_OWNER's anchor header (D20)
  "headers":    ["<80-byte header>", …],   // SET_HEADER, in order
  "proofs":     [{ "keysetId": "<8 bytes>", "amount": 64, "nonce": "<32 bytes>", "C": "<33 bytes>",
                   "date": 0, "dleq": { "e": "<32>", "s": "<32>", "r": "<32>" } }],   // at most 128; date, dleq optional
  "spentSlots": [1],                       // indexes into "proofs": spent on the card by a payment of that piece
  "limits":     { "day": 5000, "payment": 1000, "allowance": 250, "rollBudget": 7 },
  "blockedPin": true                       // with "pin": three wrong VERIFY_PINs, so the PIN is blocked
}
```

**Validation, before any APDU.** The whole fixture is checked against the card as it
is now. Anything the applet would refuse because of the fixture's own shape is a
**400**, and the card is not touched. The checks:

- `pin`: 4 to 8 characters. `blockedPin` needs `pin`.
- `mint`: 1 to 77 ASCII characters. `refundKey` needs `mint`, and must start `02` or `03`.
- `owner` or `ownerKey`, not both. On a card whose owner the bridge does not hold, `/reset` first.
- `anchor` needs an owner in the same fixture. Each header is exactly 80 bytes.
- `proofs`: at most 128, no repeated `nonce`, `C` starting `02` or `03`, `1 ≤ amount < 2^32`.
  A dated piece (`date` ≠ 0) needs a refund key. Proofs need a record (`mint` here or
  earlier) and an owner (here or earlier).
- `spentSlots`: distinct indexes into `proofs`. On a card with a PIN, `pin` must be in the same fixture.
- `limits` needs an owner. `allowance` above 0 needs a PIN on the card. `rollBudget` is 1 to 30.

**Apply order.** The steps run in this order, each one checked for `9000`:

1. `pin`: `SET_PIN` if the card has no PIN, then `VERIFY_PIN`.
2. `mint` and `refundKey`: `SET_CARD`, with the owner's proof if the card already has an owner.
3. `owner` or `ownerKey`, with `anchor`: `SET_OWNER`, with the old owner's proof on an owned card.
4. `headers`: `SET_HEADER`, in order.
5. `proofs`: the owner's `ALLOW_LOAD`, then one `LOAD_PROOF` per piece (`P1 = 1` with `dleq`, so the card keeps the mint's proof).
6. `spentSlots`: for each, `SPEND_ALL_BEGIN` on that piece and `SPEND_ALL_SIGN` (no outputs), waited out.
   The piece is spent on the card only. The mint still holds it as unspent.
7. `limits`: the owner's `SET_LIMIT` (`34`).
8. `blockedPin`: three wrong `VERIFY_PIN`s (`63C2`, `63C1`, `6983`).
9. `SELECT`, so the app's first command starts a fresh session.

A step the applet refuses stops the fixture there. The answer is **409**
`{"error": "<step>", "sw": "<SW>", "state": {…}}`, the steps before it stay applied,
and `/state.fixtureError` keeps `{step, sw}` until the next fixture or reset.

**`limits` always sends 13 bytes.** The bridge sends the owner's thirteen-byte
`SET_LIMIT`: `day`, `payment` and `allowance` (each 0 when left out: no limit, no
allowance), then `rollBudget`, which is **7 when left out**. That is the same rule
the card applies to a `SET_LIMIT` without the thirteenth byte: absent means 7 (the
architect's decision 2, [D20](../../docs/DECISIONS.md#d20)). So a fixture with
`limits` always leaves the budget at what it says, or at 7.

**`owner: true`** sets the **public** TEST owner key: the P-256 private key
`SHA-256("cashu-javacard/cardctl test owner key") mod n`. `tools/cardctl/p256.py`
(`TEST_OWNER_PRIVATE`) and `client.cjs` (`TEST_OWNER_PRIVATE`) hold the same key.
Anyone with this repository has it, so use it for simulated and bench cards only.
With it, the bridge signs the owner's proofs for `limits` and for loading, and
`client.cjs`'s owner commands default to it.

**Headers** must be real mainnet headers. The applet's floor (`FLOOR_BITS`, D24) is
built in, so a header mined for a test is refused (`6A93`).
`spec/vectors/headers.json` has twelve, a day apart.

## `/state`

Read through commands that need no PIN and change nothing (`GET_INFO P1 = 2`,
`GET_CARD`, `GET_PUBKEY`, `GET_BALANCE`, `GET_SLOT_STATUS`, then `GET_PROOF` and
`GET_DLEQ` for each slot that is not empty).

| Field | |
|---|---|
| `generation` | goes up on every reset and fixture, so a test can tell its card from one another run left |
| `deterministicKey` | always `true` |
| `version` | `"2.0"` |
| `pubkey` | the card key, 33 bytes compressed |
| `balance` | sats in unspent pieces |
| `pinState`, `tries`, `locked` | `0` no PIN, `1` set, `2` blocked; tries left; the owner's lock |
| `hasOwner`, `ownerKey`, `testOwner` | an owner is set; its public key (when the bridge set it); whether that is the TEST key |
| `recordSet`, `mint` | the record is set; its mint URL |
| `now`, `windowStart`, `spentToday` | the card's clock (the newest header's time, 0 before any); the day's window start; sats signed for in it |
| `dailyLimit`, `allowance`, `nopinSpent` | the day's limit and the no-PIN allowance (0 is none); what the allowance has counted |
| `rolls`, `rollBudget`, `allowanceArmed` | D20: rolls since the owner's last `REFRESH`; the budget (7 when the card holds 0); whether the allowance may renew at the next roll |
| `lastHeader` | the hash of the last header taken (zeros before any) |
| `counts` | `{unspent, spent, empty}`, the applet's own tally |
| `slots` | all 128: `{slot, status}`, and for a slot that is not empty `keysetId` (8 bytes), `amount`, `nonce`, `C`, `date`, and `dleq: {e, s, r}` when the card kept the mint's proof |
| `fixtureError` | `{step, sw}` of the last refused fixture step, until the next fixture or reset |

## The Node client

`tools/cardsim/client.cjs` has no dependencies. It exports `CardSim` (the routes plus
an encoder for each 2.0 command: `select`, `getInfo`, `getCard`, `auth`,
`spendAllBegin`, `spendAllOutputs`, `spendAllChange`, `spendAllSign`,
`spendAllAgain`, `getChange`, `getDleq`, `loadProof`, `setHeader`, `verifyPin`,
`setPin`, the owner commands `changePin`, `allowLoad`, `setLimit` and `refresh`,
and the rest), `encode`, `constants` (INS, status words, labels), the parsers,
`validateFixture` (the fixture's shape checked on the client, so most bad fixtures
fail before the HTTP call; the bridge's checks against the card are the final word), `ownerProof`, `ownerData` and `limitValue`. A refused command throws
`CardError` with its `sw`. A transport failure throws `CardSimError`. Requests time
out after 5 s. `client.setLimit(…)` without `rollBudget` sends no thirteenth byte,
so the card sets its budget back to 7.

`tools/cardsim/cashu-crypto.cjs` is the Cashu arithmetic the tests use (NUT-00
blinding, NUT-12 DLEQ, BIP-340, the format-4 card secret and the SIG_ALL message),
also with no dependencies.

## A worked example

```bash
java -jar tools/cardsim/target/cardsim.jar --port 9876 &
curl -s -X POST localhost:9876/reset | jq -r .pubkey
# mint pieces to that key at your mint (format-4 SIG_ALL secrets, spec/NUT-XX.md), then:
curl -s -X POST localhost:9876/fixture -d '{
  "pin": "1234", "mint": "http://127.0.0.1:3338", "owner": true,
  "anchor": "<the tip header, 80 bytes>",
  "proofs": [{"keysetId": "009a1f293253e41e", "amount": 32, "nonce": "<32 bytes>", "C": "02…",
              "dleq": {"e": "…", "s": "…", "r": "…"}}],
  "limits": {"day": 5000, "payment": 1000, "allowance": 250}
}' | jq '{balance, rollBudget, counts}'
# {"balance": 32, "rollBudget": 7, "counts": {"unspent": 1, "spent": 0, "empty": 127}}
curl -s -X POST localhost:9876/apdu -d '{"hex":"00A404000BF043415348554341524401"}'
# {"hex":"02009000","sw":"9000"}
```

**SELECT the applet's whole AID** (`F0 CASHUCARD 01`, [D25](../../docs/DECISIONS.md#d25)).
The bridge installs the opener first, then the card's applet, then the tag, as a
chip has them, and answers a SELECT by a partial name the way the J3R180 does: it
reaches the first instance made whose AID begins with the name. So the package AID
`F0 CASHUCARD` alone reaches the opener, which answers `9000` with no version and
`6D00` to every command after. jCardSim on its own gives a partial name to the
lowest matching AID in sort order (the card's applet), so the bridge resolves the
name itself before jCardSim sees it (`SimCard.resolveSelect`); a whole AID, a name
that begins no instance and a "next occurrence" SELECT pass through unchanged.
`GET /state` and `/fixture` read the card's applet wherever the app left the
selection: `/state` puts the app's selection back after its reads, and a fixture
ends with the card's applet selected, as before.

```bash
curl -s -X POST localhost:9876/apdu -d '{"hex":"00A404000AF0434153485543415244"}'
# {"hex":"9000","sw":"9000"}   the opener: no version
```

The same in Node, minting at a real mint with a SIG_ALL swap, is
`tools/cardsim/e2e-swap.test.cjs`. CI runs it against a Nutshell 0.20.3 with forge's
keyset shape (an 8-byte id, no fee) and against a fresh v2 keyset (a 33-byte id, a
fee of 100).
