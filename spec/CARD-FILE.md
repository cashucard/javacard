<a id="card-file--interchange-format-v1"></a>

# Card File: interchange format v1

> **0.x only.** A card file describes the pieces of a card on the 0.x applet
> (AID `D2 76 00 00 85 01 02`): a 78-byte slot with no date, whose secret is the
> 0.x P2PK text. A protocol 2.0 card's pieces carry a date and a format-4
> `SIG_ALL` secret ([NUT-CCP](https://github.com/cashucard/nut/blob/main/CCP.md#card-proofs)), which v1 cannot describe, so
> `cardctl dump` and `cardctl load-file` select the 0.x AID and refuse any other
> card. The format is kept for the sweep of 0.x cards (`docs/HARDWARE_DEPLOYMENT.md`)
> and for cashu-client's reader of existing files; a 2.0 card file would be a v2.

The mint protocol lives in TypeScript (`cashucard/client`) and the host-side
driver is Python (`tools/cardctl`). Proofs cross that boundary as a JSON file:
`cardctl dump` writes one off a card, `cardctl load-file` writes one onto a card,
and `serializeCardFile` / `parseCardFile` in cashu-client do the same on the
other side.

The field names and validation rules below define the shared contract. Tests in
`tools/cardctl/test_card_file.py` check the parser and writer against these tables.
The file carries the card's 32-byte `nonce` and 16-character hex `keysetId`.
A reader reconstructs the NUT-10 P2PK secret from the nonce and `cardPubkey`.
The full secret is about 150 bytes of JSON; the card's nonce field holds 32 bytes.

> **Implementation status.** [cashucard/client#5](https://github.com/cashucard/client/pull/5)
> merged on 28 August 2026. Both implementations carry `spent` and enforce
> `0 < amount < 2^32`. `serializeCardFile` rejects `spent: true` because
> `LOAD_PROOF` has no spent bit. `cardctl dump` preserves spent slots for recovery.
> The fixture in `tools/cardctl/testdata/card-file-v1.json` was regenerated with
> that change's TypeScript toolchain and accepted by its `parseCardFile`.

---

## Document

```json
{
  "version": 1,
  "mint": "https://forge.flashapp.me",
  "unit": "sat",
  "cardPubkey": "032994631ef9a4ba5b0db2f44b4d0d8a4b0eec49bed16091c23c171a8c553a03da",
  "slots": [
    {
      "keysetId": "0059534ce0bfa19a",
      "amount": 8,
      "nonce": "abababababababababababababababababababababababababababababababab",
      "C": "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      "spent": false
    }
  ]
}
```

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `version` | integer | yes | Schema version. Must be exactly `1`; a reader that does not recognise the value refuses the file rather than guessing. |
| `mint` | string | yes | Mint URL these proofs belong to. Non-empty. |
| `unit` | string | yes | Keyset unit, e.g. `sat`. Non-empty. |
| `cardPubkey` | string | yes | The card's 33-byte compressed secp256k1 public key, 66 hex chars, `02`/`03` prefix. Proofs are P2PK-locked to this key. |
| `slots` | array | yes | Zero or more slot objects, in card slot order. |
| `note` | string | no | Free-form provenance for a human. Untrusted display text; readers must not execute it or use it to authorize actions. `cardctl dump` emits one; a reader must tolerate its absence. |

**Readers reject keys outside the document and slot field lists.** Additions
require a `version` bump so both implementations can validate the same schema.
`note` is the only optional key.

## Slot

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `keysetId` | string | yes | NUT-02 **v0** keyset id: 8 raw bytes, written as exactly 16 hex chars, first byte `00`. Eight chars is half an id and a proof carrying it matches no keyset at the mint; a non-`00` version byte is not a v0 id and is refused rather than guessed at. |
| `amount` | integer | yes | Proof amount: a **positive power of two**, and `0 < amount < 2^32`. A mint keyset has no key for amount 3, so a non-power-of-two proof is rejected on redemption after the slot is burned. The upper bound is the card's field width: `LOAD_PROOF` carries the amount as a 4-byte unsigned integer. |
| `nonce` | string | yes | The 32-byte P2PK nonce, 64 hex chars. A reader rebuilds the NUT-10 secret string from this nonce plus `cardPubkey`. |
| `C` | string | yes | The mint's 33-byte compressed signature point, 66 hex chars, `02`/`03` prefix, x-coordinate **on the secp256k1 curve**. A prefix check alone accepts ~half of all random x values, and an off-curve `C` produces an invalid proof and consumes a slot if loaded. |
| `spent` | boolean | yes | Whether the card has already marked this slot spent. |

A reader MUST refuse a file carrying the same `nonce` twice or the same `C`
twice (compared byte-wise after hex normalization). A nonce identifies one
proof and `C` is the mint's signature over one proof, so a repeat is a
corrupted or hand-merged file: loading it either double-burns slots on one
proof or tells the operator a proof is safely on the card that was never
written. Both implementations enforce this; a third written from this document
must too.

Hex is case-insensitive on read and lower-case on write, and prefixes are never
written. Prefix tolerance differs between implementations:
`cardctl`'s reader strips a `0x`/`0X` prefix, but cashu-client's `requireHex`
requires bare hex (`/^[0-9a-f]+$/` after lowercasing), so a hand-authored
prefixed file is accepted by the Python half and refused by the TypeScript
half. **Never write prefixes.** The case claim and cardctl's prefix tolerance
are asserted by `test_card_file.py` (`test_normalises_hex_case`,
`test_tolerates_0x_prefixes_in_any_case`) rather than trusted.

<a id="why-spent-is-required-and-not-defaulted"></a>

### Required spent state

A spent slot is still *owed* until it settles at the mint, so a dump keeps it.
Dropping it loses money (the one exception, a spent slot whose data fails the
slot checks, is under [Writers validate too](#writers-validate-too)). But the
redeemer has to be able to tell the two kinds apart, and a card cannot:
`LOAD_PROOF` has no spent bit, so a spent proof written back onto a card comes
back as unspent and inflates the balance with money that is already gone.

Defaulting a missing `spent` to `false` reintroduces exactly that. A file
with a missing `spent` field has unknown state. Readers refuse it; the field is
required and has no default.

`cardctl load-file` skips any slot with `"spent": true`. It also refuses to call
a slot "already loaded" when the card has already burned that nonce: a stale
file reloaded against a card that spent one of its proofs reports
`already SPENT on this card` and counts it separately, rather than telling the
operator money that is gone is safely present.

## Version semantics

`version` is a single integer, bumped whenever a field is added, removed,
renamed, or has its meaning changed. There is no minor version and no
forward-compatibility window: a reader accepts the versions it knows and
refuses the rest by number.

JSON has one number type, so `"version": 1.0` reaches a JavaScript reader as
the number 1; `JSON.parse` cannot preserve the distinction. Readers therefore
treat an integral float as its integer value (cardctl collapses `1.0` to `1`
explicitly; cashu-client gets this from `JSON.parse` for free). A non-integral
version (`1.5`) is refused by both halves. Writers emit a bare integer.

Additive-looking changes still require a bump, because "field absent" and
"field present and false" are different claims about the proof state.

## Cross-implementation checks

- `tools/cardctl/test_card_file.py` parses the two tables above and asserts that
  the names `cardctl`'s parser requires, and the names its writer emits, are
  exactly the names published here. A rename on the Python side fails in CI.
- `tools/cardctl/testdata/card-file-v1.json` is a fixture generated with
  the TypeScript toolchain from cashu-client PR #5, which supports `spent`.
  It checks the Python side against a file accepted by the TypeScript parser.
  Regenerate it through that toolchain as part of a paired schema change.
- The TypeScript suite pins its parser and writer field lists locally. It does
  not read these tables, so a cross-repository schema change still requires
  coordinated review. The fixture records a file accepted by that toolchain;
  it does not establish that every future change is compatible.

<a id="writers-validate-too"></a>

## Writer validation

`cardctl dump` runs the document it assembled through the same validator
`cardctl load-file` uses before writing a byte, and cashu-client's
`serializeCardFile` round-trips through `parseCardFile`. This keeps each implementation's reader and writer on the same schema before
the file becomes an off-card recovery record.

One kind of spent slot is left out rather than refused. A card pulled
mid-`CLEAR_SPENT` leaves a slot that still reads spent with some of its fields
zeroed ([`APDU.md`](APDU.md#clear_spent-0x31)), and those bytes are not a
proof. `cardctl dump` skips a spent slot that fails the slot checks above,
names it on stderr and in `note`, and writes the rest of the card. The slot
checks catch a zeroed amount and a `C` that is no longer a point. A tear that
zeroed only keyset or nonce bytes, or part of `C` whose x still lands on the
curve, passes them, and `dump` writes that slot as spent. An unspent slot that
fails still refuses the whole dump: it may be the money.
