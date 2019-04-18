from itertools import chain
from asm import BA2Assembler
from isa.instructions import InstructionGroupLookup

INSTRUCIONS = chain.from_iterable(InstructionGroupLookup.values())


class OpCodeTester:
    BASE_ADDRESS = 0x4000000

    def __init__(self):
        self._assembler = BA2Assembler()

    def _dump_registers(self):
        gdb.execute(f"info all-registers")

    def prepare(self):
        gdb.execute(f"set $PC = {BASE_ADDRESS}")
        self._dump_registers()
        self._dump_memory()

    def test(self, asm_code):
        addr = BASE_ADDRESS

        for b in ASSEMBLER.assemble (asm_code, addr):
            gdb.execute(f"set {{char}}{addr} = {ord(b)}")
            addr += 1

        gdb.execute('x/i $PC')
        gdb.execute('si')
