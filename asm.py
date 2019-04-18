import re
from isa import instructions


class BA2Assembler:
    def __init__(self, a=0):
        if (a != 0):
            self._a = a
            print ("a", a)

    def assemble(self, asm, addr):
        print (asm)
        try:
            return instructions.Instruction.lower(asm, addr).encode()
        except Exception as e:
            import pdb
            pdb.set_trace()
            return []

    def disassemble(self, memview, addr):
        try:
            insn, parsed_bytes = instructions.Instruction.lift(memview, addr)
            return [parsed_bytes, str(insn)]
        except Exception as e:
            import traceback
            print (e)
            traceback.print_exc()
            return [0, "invalid"]

def ba2asm(a):
    assembler = BA2Assembler(a)

    return {
        "name": "ba2",
        "arch": "ba2",
        "bits": 32,
        "endian": 2, # R_SYS_ENDIAN_BIG
        "license": "BSD",
        "desc": "Beyond Architecture 2 (dis)assembly plugin",
        "assemble": assembler.assemble,
        "disassemble": assembler.disassemble,
    }
