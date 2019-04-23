from itertools import chain
from asm import BA2Assembler
from isa.instructions import InstructionGroupLookup
from isa.types import LetterCodes, OperandType
from pprint import pprint
from random import randint


SHOW_ALL = False
SHOW_CHANGED = True
SHOW_REFFED = True
SHOW_MATCHING = True


class TestOpCode (gdb.Command):
    BASE_ADDRESS = 0x4000000
    REGISTERS = [f"R{n}" for n in range(32)] + ["PC", "SR", "UR", "EPCR", "ESR", "EEAR"]

    def __init__(self):
        super ().__init__ ("test-opcode", gdb.COMMAND_USER)
        self._assembler = BA2Assembler()
        self._reg_state_before = None
        self._reg_state_after = None
        self._mem_state_before = None
        self._mem_state_after = None

    def _dump_registers (self):
        return {
            register: gdb.parse_and_eval(f"${register}") for register in self.REGISTERS
        }

    def _dump_memory (self):
        return None

    def _pre (self):
        gdb.execute (f"set $PC={self.BASE_ADDRESS}")
        self._reg_state_before = self._dump_registers ()
        self._mem_state_before = self._dump_memory ()

    def _post (self):
        self._reg_state_after = self._dump_registers ()
        self._mem_state_after = self._dump_memory ()

    def _test_insn (self, insn_class, args):
        insn = insn_class (args, self.BASE_ADDRESS)

        print (f"Testing '{insn}'...")

        gdb.selected_inferior ().write_memory (self.BASE_ADDRESS, bytes (0x100))
        gdb.selected_inferior ().write_memory (self.BASE_ADDRESS, bytes (insn.encode ()))

        self._pre ()
        gdb.execute ('si')
        self._post ()

        if self._reg_state_after['PC'] == self.BASE_ADDRESS:
            print ("Execution failed - check your arguments!")
        else:
            for reg in self.REGISTERS:
                before = self._reg_state_before[reg]
                after = self._reg_state_after[reg]

                if before == after:
                    if SHOW_ALL:
                        print (f"   {reg}: {after}")
                else:
                    print (f" * {reg}: {before} -> {after}")

    def _generate_args (self, insn_class):
        args = {}

        for arg in insn_class.ARGS:
            flags = LetterCodes[arg[-1]]['flags']
            length = LetterCodes[arg[-1]]['length']

            if flags & OperandType.SIG:
                value = randint (-2 ** (length - 1), 2 ** (length - 1) - 1)
            else:
                value = randint (0, 2 ** length - 1)

            args[arg[-1]] = value

        return args

    def invoke (self, arg, from_tty):
        for insn_class in chain.from_iterable (InstructionGroupLookup.values ()):
            if insn_class.MNEMONIC.split ('.', 1)[-1] == arg.split ()[0].split ('.', 1)[-1]:
                try:
                    self._test_insn (insn_class, self._generate_args (insn_class))
                except:
                    import traceback
                    traceback.print_exc ()

TestOpCode ()