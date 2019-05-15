from enum import Flag, Enum, auto


class OperandType(Flag):
    REG = 0x00000001        # The operand specifies a register index
    SIG = 0x00000002        # The operand must be sign extended
    DST = 0x00000004        # The operand is a destination
    REL = 0x00000008        # The operand is pc relative
    LSB = 0x00000010        # The operand is encoded LSB first
    DUNSIG = 0x00000020     # The operand will be disassembled as an unsigned value
    SYM = 0x00000040        # The letter is of pure symbolic value
    OP64BIT = 0x00000080    # This letter is used in instructions where the operation is carried out
                            # in 64-bits (mostly meaning that the width of the registers involved are
                            # 64-bits long)
    REGPRE = 0x00000100     # The letter is a prefix to a register.  The letter should also be marked
                            # as symbolic (SYM)

class InstructionType(Enum):
    UNKNOWN = auto()
    EXCEPTION = auto()
    ARITH = auto()
    SHIFT = auto()
    COMPARE = auto()
    BRANCH = auto()
    JUMP = auto()
    LOAD = auto()
    STORE = auto()
    MOVIMM = auto()
    MOVE = auto()
    EXTEND = auto()
    NOP = auto()
    MAC = auto()
    FLOAT = auto()

LetterCodes = {
    'A': {'flags': OperandType.REG, 'length': 5},
    'B': {'flags': OperandType.REG, 'length': 5},
    'R': {'flags': OperandType.REG, 'length': 5},
    'D': {'flags': OperandType.REG | OperandType.DST, 'length': 5},
    'Q': {'flags': OperandType.REG | OperandType.DST, 'length': 5},
    'r': {'flags': OperandType.SYM | OperandType.REGPRE, 'length': 0},
    'C': {'flags': OperandType.LSB, 'length': 2},
    'E': {'flags': OperandType.LSB, 'length': 3},
    'F': {'flags': OperandType.LSB, 'length': 4},
    'G': {'flags': OperandType.SIG | OperandType.LSB, 'length': 4},
    'L': {'flags': OperandType.SIG | OperandType.LSB, 'length': 4}, # This actually doesn't seem to be LSB...
    'H': {'flags': OperandType.LSB, 'length': 5},
    'I': {'flags': OperandType.SIG | OperandType.LSB, 'length': 5},
    'J': {'flags': OperandType.LSB | OperandType.DUNSIG, 'length': 5}, # Added DUNSIG to match binutils behavior
    'K': {'flags': OperandType.LSB | OperandType.DUNSIG, 'length': 6}, # Added DUNSIG to match binutils behavior
    'M': {'flags': OperandType.LSB | OperandType.DUNSIG, 'length': 7}, # Added DUNSIG to match binutils behavior
    'N': {'flags': OperandType.LSB, 'length': 8},
    'O': {'flags': OperandType.SIG | OperandType.LSB,   'length': 8},
    'P': {'flags': OperandType.SIG | OperandType.REL | OperandType.LSB, 'length': 8},
    'T': {'flags': OperandType.SIG | OperandType.REL | OperandType.LSB, 'length': 10},
    'U': {'flags': OperandType.SIG | OperandType.REL | OperandType.LSB, 'length': 12},
    'S': {'flags': OperandType.SIG | OperandType.REL | OperandType.LSB, 'length': 12},
    'V': {'flags': OperandType.SIG | OperandType.LSB | OperandType.DUNSIG, 'length': 13}, # Added DUNSIG to match binutils behavior
    'W': {'flags': OperandType.SIG | OperandType.LSB | OperandType.DUNSIG, 'length': 14}, # Added DUNSIG to match binutils behavior
    'X': {'flags': OperandType.SIG | OperandType.LSB | OperandType.DUNSIG, 'length': 15}, # Added DUNSIG to match binutils behavior
    'Y': {'flags': OperandType.SIG | OperandType.LSB, 'length': 16},
    'Z': {'flags': OperandType.SIG | OperandType.REL | OperandType.LSB, 'length': 16},
    's': {'flags': OperandType.SIG | OperandType.REL | OperandType.LSB, 'length': 18},
    'o': {'flags': OperandType.LSB, 'length': 24},
    'p': {'flags': OperandType.SIG | OperandType.LSB,   'length': 24},
    't': {'flags': OperandType.SIG | OperandType.REL | OperandType.LSB, 'length': 24},
    'u': {'flags': OperandType.SIG | OperandType.REL | OperandType.LSB, 'length': 28},
    'v': {'flags': OperandType.SIG | OperandType.LSB | OperandType.DUNSIG, 'length': 29},
    'w': {'flags': OperandType.LSB | OperandType.DUNSIG, 'length': 30}, # Removed SIG to match binutils behavior
    'i': {'flags': OperandType.SIG | OperandType.LSB | OperandType.DUNSIG, 'length': 31},
    'g': {'flags': OperandType.SIG | OperandType.LSB, 'length': 32},
    'h': {'flags': OperandType.LSB | OperandType.DUNSIG, 'length': 32}, # Removed SIG to match binutils behavior
    'z': {'flags': OperandType.SIG | OperandType.REL | OperandType.LSB, 'length': 32},
    'x': {'flags': OperandType.LSB, 'length': 10},
    'y': {'flags': OperandType.LSB, 'length': 27},
}