import r2pipe
import re
import os


def asm_match(addr, text, r2disasm):
    # Split the assembly text into parts (mnemonic, arguments)
    actual_parts = [part for part in re.split(r"[\,\(\) ]+", r2disasm) if part != '']
    text_parts = [part for part in re.split(r"[\,\(\) ]+", text) if part != '']

    if len(actual_parts) != len(text_parts):
        print (f"{addr:x}: {r2disasm} != {text}")
        return False

    for actual, expected in zip(actual_parts, text_parts):
        if actual == expected:
            continue # Perfect match, continue
        if actual.split('.')[-1] == expected.split('.')[-1]:
            continue # The prefix doesn't match - but the opcode itself does, continue
        if actual[2:] == expected:
            continue # The hexadecimal values match, continue

        print (f"{addr:x}: {r2disasm} != {text}")
        print (f"  => {actual} != {expected}")

        return False

    return True

class SanityTester:
    def __init__(self, basefile="/Users/aronsky/Research/Aqara/MainsPowerOutlet_JN5169_DR1199"):
        self._r2 = r2pipe.open()
        self._asmfile = open (basefile + '.asm', 'rt')
        self._binfile = basefile + '.bin'

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

    def test_disassembly(self):
        print ("Starting disassembly sanity test...")

        self._r2.cmd (f"o {self._binfile}")
        skip_addresses = [0x8157a, 0x817e6]
        accepted = 2

        for addr, asmbytes, text in self:
            if addr in skip_addresses:
                continue

            # Get assembly text from radare2
            r2disasm = self._r2.cmdj(f'pdj 1@{addr}')[0]['disasm']

            if not asm_match(addr, text, r2disasm):
                break

        self._r2.cmd ("o--")

    def test_assembly(self):
        print ("Starting assembly sanity test...")

        self._r2.cmd (f"o malloc://{os.stat(self._binfile).st_size} 0x80000")
        self._r2.cmd ("e asm.arch=ba2")
        skip_addresses = [0x8157a]

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
                if asm_match (addr, text, writtentext):
                    continue
                break

if __name__ == '__main__':
    tester = SanityTester()
    #tester.test_disassembly()
    #tester.test_assembly()