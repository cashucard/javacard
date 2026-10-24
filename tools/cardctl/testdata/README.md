# cardctl test fixtures

## `card-file-v1.json`

A v1 card file, regenerated through the `cashucard/client#5` toolchain and
verified **accepted by that branch's `parseCardFile`** (parseCardFile-accepts,
not serializeCardFile-wrote: `serializeCardFile` refuses `spent: true` by
design (that direction ends at LOAD_PROOF, which has no spent bit), so no
serializer on either side can emit a full dump with a spent slot. Full dumps
with spent slots are `cardctl dump`'s side of the format.

Keeping the fixture TypeScript-verified prevents it from agreeing with a wrong
Python parser. The client parser and this cardctl implementation both support
the `spent` field after client PR #5 and javacard PR #19 merged on 2026-08-28.

A fixture proves that one file parsed once. Both implementations follow the
contract in `spec/CARD-FILE.md`, which
`test_card_file.py` parses the spec and checks both the parser and writer against
it, so a rename that drifts fails. Only the Python side reads that document
today; making cashu-client assert the same tables is the other half of the job.
