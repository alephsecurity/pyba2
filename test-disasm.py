#!/usr/bin/env python

import r2pipe
import re
import os
import sys
from pprint import pprint


class SanityTester:
    def __init__(self, basefile):
        self._r2 = r2pipe.open()
        self._asmfile = open (basefile + '.asm', 'rt')

        if (os.path.exists (basefile + '.bin')):
            self._binfile = basefile + '.bin'
        else:
            self._binfile = basefile + '.elf'

    def __iter__(self):
        self._asmfile.seek (0)
        return self

    def __next__(self):
        for asmline in self._asmfile:
            try:
                # Code lines start with 3 spaces and have 2 tabs
                if not asmline.startswith('   ') or asmline.count('\t') < 2:
                    continue

                # Split the code line into address, actual bytes, and assembly text
                addr, asmbytes, text = asmline.strip().split('\t')

                addr = int(addr[:-1], 16)
                asmbytes = bytes.fromhex(asmbytes)
                text = re.sub(r"<.*?>", "", text).strip()

                # literals are not instructions
                if text.startswith('.'):
                    continue

                return [addr, asmbytes, text]
            except Exception as e:
                print (asmline, e)
                continue

        raise StopIteration

    def _asm_match(self, addr, text, r2disasm):
        # Split the assembly text into parts (mnemonic, arguments)
        actual_parts = [part for part in re.split(r"[\,\(\) ]+", r2disasm) if part != '']
        text_parts = [part for part in re.split(r"[\,\(\) ]+", text) if part != '']

        if len(actual_parts) != len(text_parts):
            print (f"{addr:x}: {r2disasm} != {text}")
            return False

        for actual, expected in zip(actual_parts, text_parts):
            if actual in self._symbols:
                actual = hex (self._symbols[actual])
            if actual == expected:
                continue # Perfect match, continue
            if actual.split('.')[-1] == expected.split('.')[-1]:
                continue # The prefix doesn't match - but the opcode itself does, continue
            if actual[2:] == expected:
                continue # The hexadecimal values match, continue
            if int (actual, 16) - int (expected, 16) in (-0x100, -0x10000, -0x100000000):
                print (f"\033[0;33m    {addr:x}: {r2disasm} != {text}")
                print (f"      => {actual} != {expected}\033[00m")
                continue # The values match, but signed/unsigned disassembly is wrong

            print (f"\033[1;31m*** {addr:x}: {r2disasm} != {text}")
            print (f"***   => {actual} != {expected}\033[00m")

            return False

        return True


    def test_disassembly(self):
        print (f"Starting disassembly sanity test ({self._binfile})...")

        self._r2.cmd (f'o "{self._binfile}"')
        self._r2.cmd ("e asm.arch=ba2")

        self._symbols = {sym["name"]: sym["offset"] for sym in self._r2.cmdj ("fj")}
        self._r2.cmd ("fs strings")
        self._symbols.update ({sym["name"]: sym["offset"] for sym in self._r2.cmdj ("fj")})

        skip_addresses = []

        for addr, asmbytes, text in self:
            if addr in skip_addresses:
                continue

            # Get assembly text from radare2
            r2disasm = self._r2.cmdj(f'pdj 1@{addr}')[0]['disasm']

            if not self._asm_match(addr, text, r2disasm):
                pass

        self._r2.cmd ("o--")

    def test_assembly(self):
        print (f"Starting assembly sanity test ({self._binfile})...")

        self._r2.cmd (f"o malloc://{os.stat(self._binfile).st_size} 0x80000")
        self._r2.cmd ("e asm.arch=ba2")
        self._symbols = {}

        skip_addresses = []

        for addr, asmbytes, text in self:
            if addr in skip_addresses:
                continue

            self._r2.cmd (f"wa {text} @{addr}")
            writteninsn = self._r2.cmdj (f"pdj 1@{addr}")[0]
            writtenbytes = bytes.fromhex(writteninsn["bytes"])
            writtentext = writteninsn["disasm"]
            if writtenbytes == asmbytes:
                continue
            else:
                print (' *** ')
                print (' *** ', hex(addr), ':', writtenbytes.hex(), asmbytes.hex(), writtentext, text)
                print (' *** ')
                if not self._asm_match (addr, text, writtentext):
                    pass

if __name__ == '__main__':
    if len (sys.argv) < 2:
        print (sys.argv)
        tester = SanityTester (sys.argv[-1])
        tester.test_disassembly ()
        tester.test_assembly ()
    elif len (sys.argv) == 2:
        for filename in os.listdir (sys.argv[-1]):
            if not filename.endswith ('.elf'):
                continue

            tester = SanityTester (os.path.join (sys.argv[-1], filename[:-4]))
            # tester.test_disassembly ()
            tester.test_assembly ()
    else:
        print ("Usage: test-disasm.py [test-dir]")
