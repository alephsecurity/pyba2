from itertools import chain
from asm import BA2Assembler
from isa.instructions import InstructionGroupLookup


class TestOpCode (gdb.Command):
    BASE_ADDRESS = 0x4000000
    REGISTERS = [
        "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
        "R16", "R17", "R18", "R19", "R20", "R21", "R22", "R23",
        "R24", "R25", "R26", "R27", "R28", "R29", "R30", "R31",
        "PC", "SR", "UR", "EPCR", "ESR", "EEAR"
    ]


    def __init__(self):
        super ().__init__ ("test-opcode", gdb.COMMAND_USER)
        self._assembler = BA2Assembler()

    def _dump_registers(self):
        registers = {}
        for register in self.REGISTERS:
            registers[register] = gdb.parse_and_eval(f"${register}")
        return registers

    def prepare(self):
        gdb.execute (f"set $PC = {BASE_ADDRESS}")
        self._dump_registers ()
        self._dump_memory ()

    def test (self, asm_code):
        addr = BASE_ADDRESS

        for b in ASSEMBLER.assemble (asm_code, addr):
            gdb.execute (f"set {{char}}{addr} = {ord(b)}")
            addr += 1

        gdb.execute ('x/i $PC')
        gdb.execute ('si')

    def _generate_assembly (self, insn_class):
        pass

    def invoke (self, arg, from_tty):
        print (self._dump_registers ())
        for insn_class in chain.from_iterable (InstructionGroupLookup.values ()):
            if insn_class.MNEMONIC.split ('.', 1)[-1] == arg.split ('.', 1)[-1]:
                insn = self._generate_assembly (insn_class)

TestOpCode ()