# What the chip has room for

Foxy's card runs on an NXP J3R180 (JCOP 4, Java Card 3.0.5, 180 KB of
storage). The simulator the tests run in (jCardSim) has none of the limits
below, so each was found on the chip, usually the hard way. Each is given
with what was measured and what the card's software does about it.

## The first applet instantiated from a package must be small

The card goes mute, or answers `6F00`, at the INSTALL that both instantiates
its package for the first time and runs `CashuApplet`'s constructor, which
makes the card's key, sets the signer up and allocates about 45 KB of
storage. LOAD is accepted block by block and the last block (where the card
links the package) answers `9000` in the usual 730 ms; INSTALL then either
gets no answer at all (the reader gives up after five block waiting times,
about 7 s, and the card must be reset before it speaks again) or `6F00`
after about 1.3 s. Nothing is installed either way.

The same constructor installs in about a second once a small applet of the
same package has been instantiated before it (0.2 s). The order is what
matters: the same file with the big applet instantiated first fails again.

What was measured, on the way to that:

- Without an opener the failure is a sharp function of the load file's size
  and nothing else in it: 13,362 bytes installs, 13,377 does not, whatever
  the extra bytes are (code never run and data never read alike). Sending
  the file in more LOAD blocks, loading another package first, moving the
  code within the file, more arrays or larger ones, 544 bytes less working
  memory, a second of extra key making: none of these moved the line. A
  file that imports a second package and never calls it installs; one that
  calls into it at install does not.
- With an opener instantiated first, a file of 14,760 bytes installs, and
  its constructor leaves every one of its marks: it ran to the end.
- The reader is not the limit: a command of 14 s is answered through it.

The mechanism is not known for certain. What fits every measurement is a
budget the chip keeps for one INSTALL command (a journal for the atomic
install, most likely), charged with the package's own pages at its first
instantiation as well as with everything the constructor allocates; the
small applet pays the package's share in an INSTALL of its own.

What the software does: the package holds two applets, `Opener` first (AID
`F0464F5859434152444D`), which does nothing, and `CashuApplet`; from software
1.19 a third, `Tag` (class AID `F0464F58594341524454`), listed last, which is
the card's NFC tag and is created last, under the NFC Forum's own name
(`D2760000850101`) as its instance AID. The opener is instantiated with the load,
and the card's applet is created from the package after it. `tools/refcheck.py`
runs after every `ant cap` and refuses a file whose first applet is not the
opener. Deleting goes the other way: the tag, the card's applet, the opener, then
the package. The chip refuses to delete an instance that a static field of the
package refers to, so none does (the tag asks the card's applet for a shareable
interface at each selection and keeps nothing of it).

## The load file's size decides whether the applet installs, and the rule is not known

With the opener in place, whether the card's applet installs still turns on
the load file's size, and not in one direction. Five builds of one version
of the software failed at the card applet's INSTALL (`6F00`, or mute) while
the version before it installed, and the code they ran at install was the
same to the byte; what differed was the file's size.

For files of 17.3 to 17.7 KB it looked like a window of each 256 bytes,
measured in bytes past a multiple of 256: installs at 130, 144, 168, 181 and
186; not at 13, 30, 62, 71, 72 and 192. The proof that it was the size and
nothing in the code: a file of 17,344 bytes that failed (192 past) installed
at 17,552 (144 past) with nothing changed but a method, never called, added
at its end; and a file that installed at 17,538 (130 past) failed at 17,677
(13 past) with the same constructor.

The next version, 800 bytes larger, broke the window: files of 18,315,
18,337, 18,340 and 18,352 bytes (139 to 176 past, inside it) went mute at
INSTALL, some nine seconds in, while 18,123 (203 past) and 18,425 (249 past)
installed in two seconds, and the version before, with the one new constant
of the next added to it, installed at 17,582 (174 past). So the window moved
with the size of the file, or was never a window of 256 bytes at all. The
mechanism stays unknown: what fits is that the chip places what the install
makes (the applets' objects, which start where the package image ends)
against pages, and that something must not fall across an edge; where the
image ends is set by the file's size.

Software 1.19 added the tag's applet and was larger again. A build whose load
file was 19,269 bytes (69 past a multiple of 256) installed, and its tag
answered as a phone reads it.

Software 1.20, which keeps the mint's proof with each piece, installed at
19,634 bytes (178 past a multiple of 256), the first size tried, in about two
seconds. Its first `SET_CARD`, the one that reserves the 12,288 bytes of the
store, took about 130 ms on the chip, and a `RESET_CARD`, which fills the
store with zeros, about 270 ms (`tools/chip/proofstore.sh`, 27 checks, all
held on the chip).

The shared protocol's 2.0 (v2.0.0-rc.1, ENG-681) installed at 20,060 bytes by
refcheck's measure (92 past a multiple of 256; the install counted the load file
as 20,057), with the opener first, the first size tried. A SELECT by the package
AID alone then reached the opener and not the card's applet: the chip gives a
partial name to the first instance made whose AID begins with it, so readers
select the card's applet by its whole AID (DECISIONS D25). `cardctl selftest`
passed 12 of 12, and `AUTH` took 833 to 854 ms a signature on an ACR122U.
2.1 (ENG-699, DECISIONS D26) is 20,068 bytes by refcheck's measure (100 past a
multiple of 256), eight more than 2.0. It installed on a J3R180 with the opener
first on 2026-10-14, and `cardctl selftest` passed 12 of 12
(HARDWARE_TEST_REPORT_2026-10-14.j3r180-2.1.md).

What the software does: `CashuApplet.sizeTheFile` is never called and is in
the package for its length alone, about six bytes a line, so that a build
can be moved to a size that is known to install; `tools/refcheck.py`, after
every `ant cap`, keeps every size the chip has answered (`SIZES`) and says
whether this build's size is one that installed, one that failed, or one not
tried yet. A size not tried yet is tried on the chip with
`~/.foxycard/install-try.sh`, and the answer is added to the table. A
version is shipped at a size that installed.

## A constructor may ask for little more; the rest is asked for after the install

The budget that makes the first applet small (above) is charged with what the
constructor makes, and it is small. What was measured on the chip, in the
constructor of the card's applet:

| persistent memory asked for in the constructor, more than 1.19's | INSTALL |
|---|---|
| 300 bytes | installed |
| 12,288 bytes | failed |

The same 12,288 bytes, asked for by a command after the install (an array made in
`SET_CARD`), were given. So the 12,288 bytes that hold the mint's proofs
(software 1.20: [`FOXY-CARD-SPEC.md`](FOXY-CARD-SPEC.md) 5.9, [D17](DECISIONS.md#d17))
are not made in the constructor. The first `SET_CARD` that goes through makes them,
once, outside any transaction. A card that is refused them carries on without, and
every use of the store is safe while it does not exist.

No simulator has this limit, and a build that breaks it fails on the chip and
nowhere else, so tests pin it: the store is null after install and made by the
first `SET_CARD`; no constructor names it; the arrays the constructors make add up
to 29,806 bytes, the figure of the build that installs, and a larger figure has to
be measured on a card first; and the scan for allocations on the path of a command
(D10) lets through that one guarded statement and nothing beside it. The 1.20 build
itself has not been installed on the chip yet. `tools/chip` has a short case for
that (`ProofStoreCheck.java`, run by `proofstore.sh`): it sets a blank card up, loads a
piece with a proof and reads it back, loads a plain piece and reads `00`, pays, and
resets the card, which ends blank.

## One transaction holds about a dozen status bytes

A payment of 6 to 11 pieces was burned inside one transaction; 32 pieces
were refused with `6A96` (`TransactionException`, nothing burned). The
transaction's commit buffer on this chip is small, and jCardSim's is not.

What the software does: since 1.8 the burn is outside the transaction.
The places are written to `burnList` first, one transaction commits one
byte (`burnPending`) with the day, the log and the signature,
`finishBurn()` marks the places after, and `process()` finishes an
interrupted burn before anything else. Every transaction is the same size
whatever the number of pieces. A phone that meets a card without
capability bit 6 asks it for 8 pieces a signature at most.

## Working memory

The ISD reports about 2,486 bytes of free volatile memory on a clean card.
The applet asks for 941 bytes cleared on deselect and 6 cleared on reset,
and a unit test keeps it there. The tag (1.19) is a second applet with one more
byte cleared on deselect (the file chosen), which makes 942 in the card; the
chip's limit was found between 941 (installs) and 1,030 (refused), and 942 has
not yet been tried on it. The first build of 1.9 asked for 1,030
and was refused at INSTALL with `6F00`; it was also the package's first
applet (above), so the two were never separated.

## Storage

A clean card has 164,176 bytes free. Software 1.7 takes 45,096 of them for
128 places and everything else; from software 1.20 the first `SET_CARD` takes
12,288 more, for the mint's proofs. The figures come from the ISD's memory
tag, which needs no key:

    00A4040000          (choose the card manager)
    80CAFF2100          -> FF21 10 8102 nnnn 8204 <free storage> 8304 <free volatile>

## Times, through a contact reader

Measured with the card in an ACS ACR39U, one command at a time:

| command | about |
|---|---|
| key generation at install (the INSTALL step) | 1.0 s |
| SIGN (one signature, or one "not yet") | 0.7 s |
| AUTH | 0.7 s |
| LOAD_PROOF, three pieces in one command | 0.19 s |
| GET_PIECES, the whole list | 0.1 s |
| SET_HEADER (a real header accepted, the clock moved) | 0.05 s |
| TELL_TIME | 0.01 s |
| SELECT, GET_INFO, GET_BALANCE | 0.02 to 0.03 s |

So a drawer of about 100 pieces takes about 7 s to write through this
reader, and the listing reads around it cost as much again. A phone over
NFC is a different path and is measured there.

`SET_HEADER` (software 1.15) took the place of `SET_TIME` (0.07 s when it was
measured), which verified an ECDSA signature. It verifies none: the card hashes
the header's 80 bytes and then the 32-byte hash, as Bitcoin does, turns the
result round, and compares it with three numbers of 32 bytes (the header's own
target, the floor and four times the hardest target taken). SHA-256 over 100 bytes is measured further down this page
(4 ms); the byte loops around it, which the chip runs in bytecode, are not. The
figure in the table is an expectation, to be replaced by a measurement.
`TELL_TIME` copies four bytes.

## The field's arithmetic, measured on the chip

A change output (software 1.12, `SPEND_ALL_CHANGE`) needs arithmetic in
secp256k1's field: a cube and a square root for NUT-00's hash to the curve,
and a point addition for the blinding. A probe applet installed beside the
card's for the length of one run measured what the chip offers (times are a
command's whole round trip through a contact reader, so about 15 ms of each is
the wire):

| | On the chip |
|---|---|
| RSA, `ALG_RSA_NOPAD`, a private key with modulus p·p (512 bits) and any exponent | works; 70–80 ms an operation, whether the exponent is 3, p − 2, or 256 bits; even exponents (2) as well |
| the same with modulus p·q (q any odd 256-bit number) or a 1024-bit multiple of p | works, 70–105 ms |
| a 256-bit modulus padded to 64 bytes with leading zeros | works (the simulator refuses it: "not composite"); a 32-byte modulus is refused (`ILLEGAL_VALUE`) |
| the answer's length | the modulus' length, leading zeros included (the simulator's drops them) |
| `KeyAgreement.ALG_EC_PACE_GM` | [s]G + H in one operation, 85–100 ms, 65 bytes `04 ‖ x ‖ y`; with the key's G set to another point, an addition of any two points |
| `ALG_EC_SVDP_DH_PLAIN_XY` | 83 ms |
| a point off the curve, to either | refused, `ILLEGAL_VALUE`: the chip checks its input points |
| `Signature.verifyPreComputedHash` (ECDSA, P-256) | works, 41 ms; `verify` 42 ms |
| a 256 × 256-bit multiply in bytecode (`SchnorrHW.mul256x256`) | 242 ms |
| SHA-256 over 100 bytes | 4 ms |
| free memory with the card's applet installed | over 32 KB permanent; 2.5 KB clear-on-reset, 3.7 KB clear-on-deselect |

So the card's own change is made with the chip's RSA (a private key over p·p
with odd exponents, which the simulator also takes; each answer reduced mod p
by the applet, about 50 ms a reduction in bytecode) and the chip's generic
mapping for the point addition. Measured through the contact reader with the
live suite: a change output (`SPEND_ALL_CHANGE`) takes 300 ms when the first
x is on the curve and about 110 ms more for each further round of the hash to
the curve — 410 ms on average, 860 at the worst seen; `GET_CHANGE` 110 ms a
page. None of it is a bytecode multiply, which at 242 ms apiece is what rules
out doing the field's arithmetic in software.

## The reader, when the card goes mute

The ACR39U's block waiting time is about 1.4 s. A card that stops
answering shows as `SCARD_E_NOT_TRANSACTED` after about 7.2 s (five
waits), and the reader will not speak to it again until the card is
reset. GlobalPlatformPro disconnects without a reset, so after such a
failure either pull the card out and push it back, or connect and
disconnect with a reset (`Card.disconnect(true)`), which
`tools/chip/reset.sh` does. The reader itself waits as long as the card
asks: a command of 14 s was answered through it.
