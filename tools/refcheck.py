#!/usr/bin/env python3
"""What the chip asks of the built card file, checked after every build.

Two things, both found on the chip (docs/FOXY-CARD-HARDWARE.md):

1. The J3R180 the card is built on fails the INSTALL that both instantiates a
   package for the first time and runs a heavy constructor (6F00, or no answer
   at all). It takes the card's applet once a small applet has been
   instantiated from the package before it. So the file's Applet component
   must list the opener first, and the two are installed in that order
   (docs/HARDWARE_DEPLOYMENT.md). From software 1.19 the file lists a third applet,
   the NFC tag, last: it is made after the card's, under the NFC Forum's own name.

2. Even then, the card's applet installs at some sizes of the load file and
   not at others, and the same code fails a few dozen bytes to either side of
   a size that works. The rule is not known: it looked like a window of each
   256 bytes (130 to 186 past a multiple) for files of 17.3 to 17.7 KB, and
   files of 18.1 to 18.5 KB install at 203 and 249 past and fail at 139 to
   176. So this check keeps what has been measured on the chip (SIZES) and
   says which it is: a size known to install, a size known to fail, or one
   not tried yet. `CashuApplet.sizeTheFile` is in the package for its length
   alone, about six bytes a line, so that a build can be moved to a size
   known to install; a size not tried yet is tried on the chip with
   ~/.foxycard/install-try.sh, and the answer added here.

    python3 tools/refcheck.py <file.cap>
"""
import sys
import zipfile

OPENER = bytes.fromhex('F04341534855434152444D')
LOADED = ['Header', 'Directory', 'Import', 'Applet', 'Class', 'Method',
          'StaticField', 'Export', 'ConstantPool', 'RefLocation']
# what the chip has answered, by the load file's size (refcheck's measure, the stored components): True installed,
# False went 6F00 or mute at INSTALL. Measured on a J3R180 with the opener first.
SIZES = {
    17344: False, 17438: False, 17479: False, 17480: False, 17538: True, 17552: True, 17560: True, 17562: True,
    17564: True, 17575: True, 17582: True, 17589: True, 17677: False, 17694: False, 17726: False,
    18123: True, 18315: False, 18337: False, 18340: False, 18352: False, 18425: True, 18486: True,
    19267: True, 19269: True, 19280: True,
    19634: True,
    20060: True,  # v2.0.0-rc.1 (sha256 59f66673...), ENG-681: the install counted 20,057; selftest 12/12
    20068: True,  # v2.1.0 (sha256 f27d92b...), ENG-699: three steps, opener first; selftest 12/12 (docs/HARDWARE_TEST_REPORT_2026-10-14.j3r180-2.1.md)
}
NEAR = 8  # bytes: a size this close to one that failed is treated as that one
PAGE = 256
LINE = 6  # bytes one line of sizeTheFile adds


def components(path):
    out = {}
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.endswith('.cap'):
                out[n.rsplit('/', 1)[-1][:-4]] = z.read(n)
    return out


def applets(component):
    """The AIDs the Applet component lists, in order."""
    count = component[3]
    out, at = [], 4
    for _ in range(count):
        n = component[at]
        out.append(component[at + 1:at + 1 + n])
        at += 1 + n + 2
    return out


def load_file_size(parts):
    body = sum(len(parts[k]) for k in LOADED if k in parts)
    return body + (2 if body < 0x80 else 3 if body < 0x100 else 4)


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    parts = components(argv[1])
    size = load_file_size(parts)
    past = size % PAGE
    listed = applets(parts['Applet']) if 'Applet' in parts else []
    print('load file: %d bytes (%d past a multiple of %d); applets, in order: %s'
          % (size, past, PAGE, ', '.join(a.hex().upper() for a in listed)))
    if not listed or listed[0] != OPENER:
        print('REFUSED: the opener (%s) must be the first applet listed, so that it is instantiated first.' % OPENER.hex().upper())
        return 1
    good = sorted(s for s, ok in SIZES.items() if ok)
    bad = sorted(s for s, ok in SIZES.items() if not ok)
    if size in SIZES and SIZES[size]:
        print('a size known to install on the chip.')
        return 0
    close = [s for s in bad if abs(s - size) <= NEAR]
    if close:
        nearest = min(good, key=lambda s: abs(s - size))
        print('REFUSED: a file of %d bytes failed to install on the chip (this one is %d). The nearest size known to install is %d: '
              'move CashuApplet.sizeTheFile by about %d bytes (%d lines), or try this size with ~/.foxycard/install-try.sh and add the answer to SIZES.'
              % (close[0], size, nearest, nearest - size, (abs(nearest - size) + LINE - 1) // LINE))
        return 1
    nearest = min(good, key=lambda s: abs(s - size))
    print('a size not yet tried on the chip (the nearest known to install is %d bytes, %+d from this). Try it with ~/.foxycard/install-try.sh before shipping it, and add the answer to SIZES.'
          % (nearest, nearest - size))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
