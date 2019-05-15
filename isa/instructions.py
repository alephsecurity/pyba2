from re import split
from itertools import chain
from bitstring import BitStream, ConstBitStream, CreationError

from .exceptions import InstructionMismatchException
from .types import OperandType, InstructionType, LetterCodes
from .decorators import instruction


class Instruction(object):
    MNEMONIC = "invalid"
    ARGS_RAW = ""
    ARGS = ""
    ENCODING = ""
    ESIL = "TODO"
    TYPE = InstructionType.UNKNOWN

    def __init__(self, operands, vma):
        self._operands = operands
        self._vma = vma

    @classmethod
    def parse(cls, bitstream, vma):
        data = {}

        for c, b in zip(cls.ENCODING, bitstream.bin):
            if c == '-':
                continue
            if c in '01':
                if b != c:
                    raise InstructionMismatchException()
                continue
            if c not in data:
                data[c] = BitStream()
            data[c].append('bin:1=' + b)

        operands = {}

        for arg in cls.ARGS:
            letter = arg[-1]
            bits = data[letter]
            flags = LetterCodes[letter]['flags']
            length = LetterCodes[letter]['length']

            if flags & OperandType.LSB:
                bits.reverse()
                if flags & OperandType.DUNSIG:
                    if bits.length % 8 != 0:
                        bits.append(8 - (bits.length % 8))

            if flags & OperandType.SIG:
                operands[letter] = bits.int
            else:
                operands[letter] = bits.uint

        return cls(operands, vma)

    @classmethod
    def assemble(cls, op_args, vma):
        op_args = split(r"[\(\),]+", op_args.lower())
        if '' in op_args:
            op_args.remove('')
        operands = {}

        if len(set(op_args)) > len(cls.ARGS):
            raise InstructionMismatchException()

        for arg, val in zip(cls.ARGS, op_args):
            letter = arg[-1]
            flags = LetterCodes[letter]['flags']
            length = LetterCodes[letter]['length']

            if arg.startswith('r'):
                # Register expected
                if val.startswith('r'):
                    # Register received
                    val = int(val[1:])

                    if letter in operands and operands[letter] != val:
                        raise InstructionMismatchException("These 2 registers should be the same!")

                    operands[letter] = val
                else:
                    # Immediate received
                    raise ValueError("Register argument expected, got " + val)
            else:
                if val.startswith('r'):
                    # Register received
                    raise ValueError("Immediate argument expected, got " + val)
                else:
                    # Immediate received
                    negative = False

                    if val.startswith('-'):
                        negative = True
                        val = val[1:]

                    if val.startswith('0x'):
                        operands[letter] = int(val[2:], base=16)
                    elif val.endswith('h'):
                        operands[letter] = int(val[:-1], base=16)
                    elif val.startswith('0b'):
                        operands[letter] = int(val[2:], base=2)
                    else:
                        operands[letter] = int(val, base=16)

                    if negative:
                        operands[letter] = -operands[letter]

                    if flags & OperandType.REL:
                        operands[letter] -= vma

                    # Validate size
                    prefix = "int" if flags & OperandType.SIG else "uint"
                    if flags & OperandType.DUNSIG:
                        BitStream(f"{prefix}:{8 * (length // 8 + 1)}={operands[letter]}")
                    else:
                        BitStream(f"{prefix}:{length}={operands[letter]}")

        return cls(operands, vma)

    @classmethod
    def lift(cls, buf, vma=0):
        stream = ConstBitStream(buf[:6].tobytes())
        #stream = ConstBitStream(buf)
        
        group = stream.peek('uint:4')

        for insn_class in InstructionGroupLookup[group]:
            try:
                return [insn_class.parse(stream, vma), insn_class.size()]
            except InstructionMismatchException as ie:
                continue

        return [Instruction({}, vma), 0]

    @classmethod
    def lower(cls, asm, vma=0):
        parts = asm.split()
        mnemonic = parts[0].lower()
        op_args = "".join(parts[1:])

        matching_instructions = [insn_class for insn_class in chain.from_iterable(InstructionGroupLookup.values()) if insn_class.MNEMONIC.split('.', 1)[-1] == mnemonic.split('.', 1)[-1]]
        matching_instructions.sort(key=lambda insn_class: len(insn_class.ENCODING))

        for insn_class in matching_instructions:
            try:
                return insn_class.assemble(op_args, vma)
            except Exception as e:
                continue

        raise NotImplementedError("Not implemented instruction: " + mnemonic)

    @classmethod
    def size(cls):
        return int((len(cls.ENCODING) + 4) / 8)

    def esil(self):
        return self.ESIL.format(**self._operands)

    def encode(self):
        stream = BitStream()
        operands = {}

        for arg in self.ARGS:
            letter = arg[-1]
            flags = LetterCodes[letter]['flags']
            length = LetterCodes[letter]['length']
            prefix = "int" if flags & OperandType.SIG else "uint"
            extended = 8 * (length // 8 + 1) if length % 8 else length
            extra = extended - length
            rored = False

            try:
                operands[letter] = BitStream(f"{prefix}:{length}={self._operands[letter]}")
            except CreationError:
                operands[letter] = BitStream(f"{prefix}:{extended}={self._operands[letter]}")

                if flags & OperandType.LSB:
                    if extra and operands[letter][-extra:].all(1) or operands[letter][-extra:].all(0):
                        operands[letter] = operands[letter][:-extra]
                        rored = True
                    else:
                        raise

            if flags & OperandType.LSB:
                if extra and flags & OperandType.DUNSIG and not rored:
                    operands[letter] = operands[letter][:-extra]
                    if operands[letter][0] and flags & OperandType.SIG:
                        operands[letter].prepend('0b1' * extra)
                    else:
                        operands[letter].prepend('0b0' * extra)
                    operands[letter].pos = 0
                operands[letter].reverse()

        try:
            for c in self.ENCODING:
                if c == '-':
                    stream.append('bin:1=0')
                elif c in '01':
                    stream.append('bin:1=' + c)
                else:
                    stream.append('bin:1=' + operands[c].read('bin:1'))
        except Exception as e:
            import traceback
            traceback.print_exc()
            import pdb
            pdb.set_trace()

        return list(stream.bytes)

    def __str__(self):
        operands = self.ARGS_RAW
        table = {}

        for arg in self.ARGS:
            letter = arg[-1]
            if arg.startswith('r'):
                table[letter] = str(self._operands[letter])
            else:
                value = self._operands[letter]

                if LetterCodes[letter]['flags'] & OperandType.REL:
                    value += self._vma

                table[letter] = hex(value)

        return f"{self.MNEMONIC:11} {operands.translate(str.maketrans(table))}"

## Helpers

class TrapInstruction(Instruction):
    TYPE = InstructionType.EXCEPTION

class ArithmeticInstruction(Instruction):
    TYPE = InstructionType.ARITH

class ShiftInstruction(Instruction):
    TYPE = InstructionType.SHIFT

class CompareInstruction(Instruction):
    TYPE = InstructionType.COMPARE

class LoadInstruction(Instruction):
    TYPE = InstructionType.LOAD

class StoreInstruction(Instruction):
    TYPE = InstructionType.STORE

class MoveInstruction(Instruction):
    TYPE = InstructionType.MOVE

class ExtendInstruction(Instruction):
    TYPE = InstructionType.EXTEND

class NopInstruction(Instruction):
    TYPE = InstructionType.NOP

class MacInstruction(Instruction):
    TYPE = InstructionType.MAC

class FloatInstruction(Instruction):
    TYPE = InstructionType.FLOAT

class BranchInstruction(Instruction):
    TYPE = InstructionType.BRANCH

    @property
    def fail_addr(self):
        return self._vma + self.size()

    @property
    def target_addr(self):
        return self._vma + self._operands[self.ARGS[-1]]

class JumpInstruction(Instruction):
    TYPE = InstructionType.JUMP

    @property
    def target_addr(self):
        return self._vma + self._operands[self.ARGS[-1]]

    @property
    def target_register(self):
        return self._operands[self.ARGS[-1][-1]]

class BitwiseInstruction(ArithmeticInstruction):
    def __init__(self, operands, vma):
        if operands[self.ARGS[-1]] < 0:
            operands[self.ARGS[-1]] &= 0xffffffff
        super(BitwiseInstruction, self).__init__(operands, vma)

## Instructions

@instruction("bt.movi", "rD,G", "0x0 00 DD DDD0 GGGG", "{G},r{D},=")
class BtMoviInstruction(ArithmeticInstruction):
    def __init__(self, operands, vma):
        if operands['D'] == 0:
            raise InstructionMismatchException("This is bt.trap!")
        super().__init__(operands, vma)

@instruction("bt.trap", "G", "0x0 0000 0000 GGGG")
class BtTrapInstruction(TrapInstruction):
    pass

@instruction("bt.addi", "rD,rD,G", "0x0 00 DD DDD1 GGGG", "{G},r{D},+,r{D},=")
class BtAddiInstruction(ArithmeticInstruction):
    def __init__(self, operands, vma):
        if operands['D'] == 0:
            raise InstructionMismatchException("This is bt.nop!")
        super().__init__(operands, vma)

@instruction("bt.nop", "G", "0x0 00 00 0001 GGGG")
class BtNopInstruction(NopInstruction):
    pass

@instruction("bt.mov", "rD,rA", "0x0 01 DD DDDA AAAA", "r{A},r{D},=")
class BtMovInstruction(ArithmeticInstruction):
    def __init__(self, operands, vma):
        if operands['D'] == 0 and operands['A'] in (0, 1, 2, 3):
            raise InstructionMismatchException("This is bt.rtrap!")
        super().__init__(operands, vma)

@instruction("bt.rfe", "", "0x0 01 00 0000 0000")
class BtRfeInstruction(TrapInstruction):
    pass

@instruction("bt.ei", "", "0x0 01 00 0000 0001")
class BtEiInstruction(TrapInstruction):
    pass

@instruction("bt.di", "", "0x0 01 00 0000 0010")
class BtDiInstruction(TrapInstruction):
    pass

@instruction("bt.sys", "", "0x0 01 00 0000 0011")
class BtSysInstruction(TrapInstruction):
    pass

@instruction("bt.add", "rD,rD,rA", "0x0 10 DD DDDA AAAA", "r{A},r{D},+,r{D},=")
class BtAddInstruction(ArithmeticInstruction):
    pass

@instruction("bt.j", "T", "0x0 11 TT TTTT TTTT", "2,{T},-,pc,+=")
class BtJInstruction(JumpInstruction):
    pass

@instruction("bn.sb", "N(rA),rB", "0x2 00 BB BBBA AAAA NNNN NNNN",  "r{B},{N},r{A},+,=[1]")
class BnSbInstruction(StoreInstruction):
    pass

#TODO: zero extend
@instruction("bn.lbz", "rD,N(rA)", "0x2 01 DD DDDA AAAA NNNN NNNN", "{N},r{A},+,[1],r{D},=")
class BnLbzInstruction(LoadInstruction):
    pass

@instruction("bn.sh", "M(rA),rB", "0x2 10 BB BBBA AAAA 0MMM MMMM", "r{B},{M},r{A},+,=[2]")
class BnShInstruction(StoreInstruction):
    pass

#TODO: zero extend
@instruction("bn.lhz", "rD,M(rA)", "0x2 10 DD DDDA AAAA 1MMM MMMM", "{M},r{A},+,[2],r{D},=")
class BnLhzInstruction(LoadInstruction):
    pass

@instruction("bn.sw", "K(rA),rB", "0x2 11 BB BBBA AAAA 00KK KKKK", "r{B},{K},r{A},+,=[4]")
class BnSwInstruction(StoreInstruction):
    pass

#TODO: zero extend
@instruction("bn.lwz", "rD,K(rA)", "0x2 11 DD DDDA AAAA 01KK KKKK", "{K},r{A},+,[4],r{D},=")
class BnLwzInstruction(LoadInstruction):
    pass

#TODO: sign extend
@instruction("bn.lws", "rD,K(rA)", "0x2 11 DD DDDA AAAA 10KK KKKK", "{K},r{A},+,[4],r{D},=")
class BnLwsInstruction(LoadInstruction):
    pass

#TODO: Is this 64-bit?
@instruction("bn.sd", "J(rA),rB", "0x2 11 BB BBBA AAAA 110J JJJJ")
class BnSdInstruction(StoreInstruction):
    pass

#TODO: Is this 64-bit?
@instruction("bn.ld", "rD,J(rA)", "0x2 11 DD DDDA AAAA 111J JJJJ")
class BnLdInstruction(LoadInstruction):
    pass

@instruction("bn.addi", "rD,rA,O", "0x3 00 DD DDDA AAAA OOOO OOOO", "{O},r{A},+,r{D},=")
class BnAddiInstruction(ArithmeticInstruction):
    pass

@instruction("bn.andi", "rD,rA,N", "0x3 01 DD DDDA AAAA NNNN NNNN", "{N},r{A},&,r{D},=")
class BnAndiInstruction(BitwiseInstruction):
    pass

@instruction("bn.ori", "rD,rA,N", "0x3 10 DD DDDA AAAA NNNN NNNN", "{N},r{A},|,r{D},=")
class BnOriInstruction(BitwiseInstruction):
    pass

@instruction("bn.sfeqi", "rA,O",  "0x3 11 00 000A AAAA OOOO OOOO", "0,fl,=,r{A},{O},==,$z,?{{,1,fl,}}")
class BnSfeqiInstruction(CompareInstruction):
    pass

@instruction("bn.sfnei", "rA,O",  "0x3 11 00 001A AAAA OOOO OOOO", "0,fl,=,r{A},{O},==,$z,!,?{{,1,fl,}}")
class BnSfneiInstruction(CompareInstruction):
    pass

@instruction("bn.sfgesi", "rA,O",  "0x3 11 00 010A AAAA OOOO OOOO", "0,fl,=,{O},r{A},>=,?{{,1,fl,}}")
class BnSfgesiInstruction(CompareInstruction):
    pass

#TODO: sign extend
@instruction("bn.sfgeui", "rA,O",  "0x3 11 00 011A AAAA OOOO OOOO", "0,fl,=,{O},r{A},>=,?{{,1,fl,}}")
class BnSfgeuiInstruction(CompareInstruction):
    pass

@instruction("bn.sfgtsi", "rA,O",  "0x3 11 00 100A AAAA OOOO OOOO", "0,fl,=,{O},r{A},>,?{{,1,fl,}}")
class BnSfgtsiInstruction(CompareInstruction):
    pass

#TODO: sign extend
@instruction("bn.sfgtui", "rA,O",  "0x3 11 00 101A AAAA OOOO OOOO", "0,fl,=,{O},r{A},>,?{{,1,fl,}}")
class BnSfgtuiInstruction(CompareInstruction):
    pass

@instruction("bn.sflesi", "rA,O",  "0x3 11 00 110A AAAA OOOO OOOO", "0,fl,=,{O},r{A},<=,?{{,1,fl,}}")
class BnSflesiInstruction(CompareInstruction):
    pass

#TODO: sign extend
@instruction("bn.sfleui", "rA,O",  "0x3 11 00 111A AAAA OOOO OOOO", "0,fl,=,{O},r{A},<=,?{{,1,fl,}}")
class BnSfleuiInstruction(CompareInstruction):
    pass

@instruction("bn.sfltsi", "rA,O",  "0x3 11 01 000A AAAA OOOO OOOO", "0,fl,=,{O},r{A},<,?{{,1,fl,}}")
class BnSfltsiInstruction(CompareInstruction):
    pass

#TODO: sign extend
@instruction("bn.sfltui", "rA,O",  "0x3 11 01 001A AAAA OOOO OOOO", "0,fl,=,{O},r{A},<,?{{,1,fl,}}")
class BnSfltuiInstruction(CompareInstruction):
    pass

@instruction("bn.sfeq", "rA,rB", "0x3 11 01 010A AAAA BBBB B---", "0,fl,=,r{B},r{A},==,$z,?{{,1,fl,}}")
class BnSfeqInstruction(CompareInstruction):
    pass

@instruction("bn.sfne", "rA,rB", "0x3 11 01 011A AAAA BBBB B---", "0,fl,=,r{B},r{A},==,$z,!,?{{,1,fl,}}")
class BnSfneInstruction(CompareInstruction):
    pass

@instruction("bn.sfges", "rA,rB", "0x3 11 01 100A AAAA BBBB B---", "0,fl,=,r{B},r{A},>=,?{{,1,fl,}}")
class BnSfgesInstruction(CompareInstruction):
    pass

#TODO: sign extend
@instruction("bn.sfgeu", "rA,rB", "0x3 11 01 101A AAAA BBBB B---", "0,fl,=,r{B},r{A},>=,?{{,1,fl,}}")
class BnSfgeuInstruction(CompareInstruction):
    pass

@instruction("bn.sfgts", "rA,rB", "0x3 11 01 110A AAAA BBBB B---", "0,fl,=,r{B},r{A},>,?{{,1,fl,}}")
class BnSfgtsInstruction(CompareInstruction):
    pass

#TODO: sign extend
@instruction("bn.sfgtu", "rA,rB", "0x3 11 01 111A AAAA BBBB B---", "0,fl,=,r{B},r{A},>,?{{,1,fl,}}")
class BnSfgtuInstruction(CompareInstruction):
    pass

@instruction("bn.extbz", "rD,rA", "0x3 11 10 -00A AAAA DDDD D000", "0xff,r{A},&,r{D},=,")
class BnExtbzInstruction(MoveInstruction):
    pass

@instruction("bn.extbs", "rD,rA", "0x3 11 10 -00A AAAA DDDD D001", "0,r{D},=,r{A},0x80,&,0x80,==,?{{,0xffffff00,r{D},=,}},0xff,r{A},&,r{D},|=,")
class BnExtbsInstruction(MoveInstruction):
    pass

@instruction("bn.exthz", "rD,rA", "0x3 11 10 -00A AAAA DDDD D010", "0xffff,r{A},&,r{D},=,")
class BnExthzInstruction(MoveInstruction):
    pass

@instruction("bn.exths", "rD,rA", "0x3 11 10 -00A AAAA DDDD D011", "0,r{D},=,r{A},0x8000,&,0x8000,==,?{{,0xffff0000,r{D},=,}},0xffff,r{A},&,r{D},|=,")
class BnExthsInstruction(MoveInstruction):
    pass

#TODO: tricky, find index of first 1 bit, starting from LSB
@instruction("bn.ff1", "rD,rA", "0x3 11 10 -00A AAAA DDDD D100")
class BnFf1Instruction(ArithmeticInstruction):
    pass

#TODO: count leading zeroes in rA, 0xffffffff if rA is 0
@instruction("bn.clz", "rD,rA", "0x3 11 10 -00A AAAA DDDD D101")
class BnClzInstruction(ArithmeticInstruction):
    pass

#TODO: reverse bits of rA, store in rD
@instruction("bn.bitrev", "rD,rA", "0x3 11 10 -00A AAAA DDDD D110")
class BnBitrevInstruction(ArithmeticInstruction):
    pass

#TODO: unknown
@instruction("bn.swab", "rD,rA", "0x3 11 10 -00A AAAA DDDD D111")
class BnSwabInstruction(ArithmeticInstruction):
    pass

#TODO: tricky, ESIL doesn't support MSRs...
@instruction("bn.mfspr", "rD,rA", "0x3 11 10 -01A AAAA DDDD D000")
class BnMfsprInstruction(MoveInstruction):
    pass

#TODO: tricky, ESIL doesn't support MSRs...
@instruction("bn.mtspr", "rA,rB", "0x3 11 10 -01A AAAA BBBB B001")
class BnMtsprInstruction(MoveInstruction):
    pass

#TODO: rD <- least significant byte(rA)
@instruction("bn.abs", "rD,rA", "0x3 11 10 -10A AAAA DDDD D000")
class BnAbsInstruction(ArithmeticInstruction):
    pass

#TODO: unknown... rD <- rA*rA?
@instruction("bn.sqr", "rD,rA", "0x3 11 10 -10A AAAA DDDD D001")
class BnSqrInstruction(ArithmeticInstruction):
    pass

#TODO: unknown
@instruction("bn.sqra", "rD,rA", "0x3 11 10 -10A AAAA DDDD D010")
class BnSqraInstruction(ArithmeticInstruction):
    pass

#TODO: unknown... some sort of jump?
@instruction("bn.casei", "rA,N",  "0x3 11 11 -00A AAAA NNNN NNNN")
class BnCaseiInstruction(JumpInstruction):
    pass

@instruction("bn.beqi", "rB,E,P", "0x4 00 00 EEEB BBBB PPPP PPPP", "{E},r{B},==,$z,?{{,3,{P},-,pc,+=,}}")
class BnBeqiInstruction(BranchInstruction):
    pass

@instruction("bn.bnei", "rB,E,P", "0x4 00 01 EEEB BBBB PPPP PPPP", "{E},r{B},==,$z,!,?{{,3,{P},-,pc,+=,}}")
class BnBneiInstruction(BranchInstruction):
    pass

@instruction("bn.bgesi", "rB,E,P", "0x4 00 10 EEEB BBBB PPPP PPPP", "{E},r{B},>=,?{{,3,{P},-,pc,+=,}}")
class BnBgesiInstruction(BranchInstruction):
    pass

@instruction("bn.bgtsi", "rB,E,P", "0x4 00 11 EEEB BBBB PPPP PPPP", "{E},r{B},>,?{{,3,{P},-,pc,+=,}}")
class BnBgtsiInstruction(BranchInstruction):
    pass

@instruction("bn.blesi", "rB,E,P", "0x4 01 00 EEEB BBBB PPPP PPPP", "{E},r{B},<=,?{{,3,{P},-,pc,+=,}}")
class BnBlesiInstruction(BranchInstruction):
    pass

@instruction("bn.bltsi", "rB,E,P", "0x4 01 01 EEEB BBBB PPPP PPPP", "{E},r{B},<,?{{,3,{P},-,pc,+=,}}")
class BnBltsiInstruction(BranchInstruction):
    pass

@instruction("bn.j", "Z",  "0x4 01 10 ZZZZ ZZZZ ZZZZ ZZZZ", "{Z},pc,=")
class BnJInstruction(JumpInstruction):
    pass

@instruction("bn.bf", "S",  "0x4 01 11 0010 SSSS SSSS SSSS", "fl,1,==,?{{,3,{S},-,pc,+=,}}")
class BnBfInstruction(BranchInstruction):
    pass

@instruction("bn.bnf", "S",  "0x4 01 11 0011 SSSS SSSS SSSS", "fl,0,==,?{{,3,{S},-,pc,+=,}}")
class BnBnfInstruction(BranchInstruction):
    pass

@instruction("bn.bo", "S",  "0x4 01 11 0100 SSSS SSSS SSSS", "$o,1,==,?{{,3,{S},-,pc,+=,}}")
class BnBoInstruction(BranchInstruction):
    pass

@instruction("bn.bno", "S",  "0x4 01 11 0101 SSSS SSSS SSSS", "$o,0,==,?{{,3,{S},-,pc,+=,}}")
class BnBnoInstruction(BranchInstruction):
    pass

@instruction("bn.bc", "S",  "0x4 01 11 0110 SSSS SSSS SSSS", "$c,1,==,?{{,3,{S},-,pc,+=,}}")
class BnBcInstruction(BranchInstruction):
    pass

@instruction("bn.bnc", "S",  "0x4 01 11 0111 SSSS SSSS SSSS", "$c,0,==,?{{,3,{S},-,pc,+=,}}")
class BnBncInstruction(BranchInstruction):
    pass

#TODO: function prologue - frame construction
# Push F GPRs (beginning with $lr/R9) onto the stack, then reduce the $sp/R1 by
# an additional N 32-bit words.
@instruction("bn.entri", "F,N",  "0x4 01 11 1010 FFFF NNNN NNNN")
class BnEntriInstruction(StoreInstruction):
    pass

#TODO: function epilogue - frame deconstruction
# Increase the $sp/R1 by N 32-bit words, then pop F GPRs (ending with $lr/R9)
@instruction("bn.reti", "F,N",  "0x4 01 11 1011 FFFF NNNN NNNN")
class BnRetiInstruction(LoadInstruction):
    pass

#TODO: unknown... function epilogue - stack ops
@instruction("bn.rtnei", "F,N",  "0x4 01 11 1100 FFFF NNNN NNNN")
class BnRtneiInstruction(LoadInstruction):
    pass

#TODO: unknown... same as 'jr lr'?
@instruction("bn.return", "",  "0x4 01 11 1101 --00 ---- ----")
class BnReturnInstruction(JumpInstruction):
    pass

@instruction("bn.jalr", "rA",  "0x4 01 11 1101 --01 AAAA A---", "pc,lr,=,r{A},pc,=")
class BnJalrInstruction(JumpInstruction):
    pass

@instruction("bn.jr", "rA",  "0x4 01 11 1101 --10 AAAA A---", "r{A},pc,=")
class BnJrInstruction(JumpInstruction):
    pass

@instruction("bn.jal", "s",  "0x4 10 ss ssss ssss ssss ssss", "pc,lr,=,3,{s},-,pc,+=")
class BnJalInstruction(JumpInstruction):
    pass

#TODO: unknown
@instruction("bn.mlwz", "rD,K(rA),C", "0x5 00 DD DDDA AAAA CCKK KKKK")
class BnMlwzInstruction(LoadInstruction):
    pass

#TODO: unknown
@instruction("bn.msw", "K(rA),rB,C", "0x5 01 BB BBBA AAAA CCKK KKKK")
class BnMswInstruction(StoreInstruction):
    pass

#TODO: unknown
@instruction("bn.mld", "rD,H(rA),C", "0x5 10 DD DDDA AAAA CC0H HHHH")
class BnMldInstruction(LoadInstruction):
    pass

#TODO: unknown
@instruction("bn.msd", "H(rA),rB,C", "0x5 10 BB BBBA AAAA CC1H HHHH")
class BnMsdInstruction(StoreInstruction):
    pass

#TODO: unknown
@instruction("bn.lwza", "rD,rA,L", "0x5 11 DD DDDA AAAA 1100 LLLL")
class BnLwzaInstruction(LoadInstruction):
    pass

#TODO: unknown
@instruction("bn.swa", "rA,rB,L", "0x5 11 BB BBBA AAAA 1101 LLLL")
class BnSwaInstruction(StoreInstruction):
    pass

@instruction("bn.and", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B000", "r{B},r{A},&,r{D},=")
class BnBitwiseInstruction(ArithmeticInstruction):
    pass

@instruction("bn.or", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B001", "r{B},r{A},|,r{D},=")
class BnOrInstruction(ArithmeticInstruction):
    pass

@instruction("bn.xor", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B010", "r{B},r{A},^,r{D},=")
class BnXorInstruction(ArithmeticInstruction):
    pass

@instruction("bn.nand", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B011", "r{B},r{A},&,!,r{D},=")
class BnNBitwiseInstruction(ArithmeticInstruction):
    pass

#TODO: set carry/overflow
@instruction("bn.add", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B100", "r{B},r{A},+,r{D},=")
class BnAddInstruction(ArithmeticInstruction):
    pass

#TODO: set carry/overflow
@instruction("bn.sub", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B101", "r{B},r{A},-,r{D},=")
class BnSubInstruction(ArithmeticInstruction):
    pass

#TODO: should be logical
@instruction("bn.sll", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B110", "r{B},r{A},<<,r{D},=")
class BnSllInstruction(ShiftInstruction):
    pass

#TODO: should be logical
@instruction("bn.srl", "rD,rA,rB", "0x6 00 DD DDDA AAAA BBBB B111", "r{B},r{A},>>,r{D},=")
class BnSrlInstruction(ShiftInstruction):
    pass

#TODO: should be arithmetic
@instruction("bn.sra", "rD,rA,rB", "0x6 01 DD DDDA AAAA BBBB B000", "r{B},r{A},>>,r{D},=")
class BnSraInstruction(ShiftInstruction):
    pass

@instruction("bn.ror", "rD,rA,rB", "0x6 01 DD DDDA AAAA BBBB B001", "r{B},r{A},>>>,r{D},=")
class BnRorInstruction(ShiftInstruction):
    pass

@instruction("bn.cmov", "rD,rA,rB", "0x6 01 DD DDDA AAAA BBBB B010", "r{B},r{D},=,fl,1,==,?{{,r{A},r{D},=,}}")
class BnCmovInstruction(ArithmeticInstruction):
    pass

#TODO: set overflow, treat as signed
@instruction("bn.mul", "rD,rA,rB", "0x6 01 DD DDDA AAAA BBBB B011", "r{B},r{A},*,r{D},=")
class BnMulInstruction(ArithmeticInstruction):
    pass

#TODO: set overflow, treat as signed
@instruction("bn.div", "rD,rA,rB", "0x6 01 DD DDDA AAAA BBBB B100", "r{B},r{A},/,r{D},=")
class BnDivInstruction(ArithmeticInstruction):
    pass

#TODO: set overflow, treat as unsigned
@instruction("bn.divu", "rD,rA,rB", "0x6 01 DD DDDA AAAA BBBB B101", "r{B},r{A},/,r{D},=")
class BnDivuInstruction(ArithmeticInstruction):
    pass

@instruction("bn.mac", "rA,rB", "0x6 01 00 000A AAAA BBBB B110", "r{B},r{A},*,mac,+=")
class BnMacInstruction(MacInstruction):
    pass

#TODO: figure out signed/unsigned
@instruction("bn.macs", "rA,rB", "0x6 01 00 001A AAAA BBBB B110", "r{B},r{A},*,mac,+=")
class BnMacsInstruction(MacInstruction):
    pass

#TODO: figure out signed/unsigned
@instruction("bn.macsu", "rA,rB", "0x6 01 00 010A AAAA BBBB B110", "r{B},r{A},*,mac,+=")
class BnMacsuInstruction(MacInstruction):
    pass

#TODO: figure out signed/unsigned
@instruction("bn.macuu", "rA,rB", "0x6 01 00 011A AAAA BBBB B110", "r{B},r{A},*,mac,+=")
class BnMacuuInstruction(MacInstruction):
    pass

#TODO: figure out signed/unsigned
@instruction("bn.smactt", "rA,rB", "0x6 01 00 100A AAAA BBBB B110", "r{B},r{A},*,mac,+=")
class BnSmacttInstruction(MacInstruction):
    pass

#TODO: figure out signed/unsigned
@instruction("bn.smacbb", "rA,rB", "0x6 01 00 101A AAAA BBBB B110", "r{B},r{A},*,mac,+=")
class BnSmacbbInstruction(MacInstruction):
    pass

#TODO: figure out signed/unsigned
@instruction("bn.smactb", "rA,rB", "0x6 01 00 110A AAAA BBBB B110", "r{B},r{A},*,mac,+=")
class BnSmactbInstruction(MacInstruction):
    pass

#TODO: figure out signed/unsigned
@instruction("bn.umactt", "rA,rB", "0x6 01 00 111A AAAA BBBB B110", "r{B},r{A},*,mac,+=")
class BnUmacttInstruction(MacInstruction):
    pass

#TODO: figure out signed/unsigned
@instruction("bn.umacbb", "rA,rB", "0x6 01 01 000A AAAA BBBB B110", "r{B},r{A},*,mac,+=")
class BnUmacbbInstruction(MacInstruction):
    pass

#TODO: figure out signed/unsigned
@instruction("bn.umactb", "rA,rB", "0x6 01 01 001A AAAA BBBB B110", "r{B},r{A},*,mac,+=")
class BnUmactbInstruction(MacInstruction):
    pass

#TODO: unknown
@instruction("bn.msu", "rA,rB", "0x6 01 01 010A AAAA BBBB B110")
class BnMsuInstruction(MacInstruction):
    pass

#TODO: unknown
@instruction("bn.msus", "rA,rB", "0x6 01 01 011A AAAA BBBB B110")
class BnMsusInstruction(MacInstruction):
    pass

#TODO: carry?
@instruction("bn.addc", "rD,rA,rB", "0x6 01 DD DDDA AAAA BBBB B111", "$c,r{B}+,r{A},+,r{D},=")
class BnAddcInstruction(ArithmeticInstruction):
    pass

#TODO: borrow?
@instruction("bn.subb", "rD,rA,rB", "0x6 10 DD DDDA AAAA BBBB B000", "$b,r{B}-,r{A},-,r{D},=")
class BnSubbInstruction(ArithmeticInstruction):
    pass

#TODO: unknown
@instruction("bn.flb", "rD,rA,rB", "0x6 10 DD DDDA AAAA BBBB B001")
class BnFlbInstruction(ArithmeticInstruction):
    pass

#TODO: unknown - multiply half-words?
@instruction("bn.mulhu", "rD,rA,rB", "0x6 10 DD DDDA AAAA BBBB B010")
class BnMulhuInstruction(ArithmeticInstruction):
    pass

#TODO: unknown - multiply half-words?
@instruction("bn.mulh", "rD,rA,rB", "0x6 10 DD DDDA AAAA BBBB B011")
class BnMulhInstruction(ArithmeticInstruction):
    pass

#TODO: unknown - mod?
@instruction("bn.mod", "rD,rA,rB", "0x6 10 DD DDDA AAAA BBBB B100")
class BnModInstruction(ArithmeticInstruction):
    pass

#TODO: unknown - mod unsigned?
@instruction("bn.modu", "rD,rA,rB", "0x6 10 DD DDDA AAAA BBBB B101")
class BnModuInstruction(ArithmeticInstruction):
    pass

#TODO: unknown - add and what?
@instruction("bn.aadd", "rD,rA,rB", "0x6 10 DD DDDA AAAA BBBB B110")
class BnAaddInstruction(ArithmeticInstruction):
    pass

#TODO: unknown - what's compared and what's exchanged?
@instruction("bn.cmpxchg", "rD,rA,rB", "0x6 10 DD DDDA AAAA BBBB B111")
class BnCmpxchgInstruction(ArithmeticInstruction):
    pass

#TODO: should be logical
@instruction("bn.slli", "rD,rA,H", "0x6 11 DD DDDA AAAA HHHH H-00", "{H},r{A},<<,r{D},=")
class BnSlliInstruction(ShiftInstruction):
    pass

#TODO: should be logical
@instruction("bn.srli", "rD,rA,H", "0x6 11 DD DDDA AAAA HHHH H-01", "{H},r{A},>>,r{D},=")
class BnSrliInstruction(ShiftInstruction):
    pass

#TODO: should be arithmetic
@instruction("bn.srai", "rD,rA,H", "0x6 11 DD DDDA AAAA HHHH H-10", "{H},r{A},>>,r{D},=")
class BnSraiInstruction(ShiftInstruction):
    pass

@instruction("bn.rori", "rD,rA,H", "0x6 11 DD DDDA AAAA HHHH H-11", "{H},r{A},>>>,r{D},=")
class BnRoriInstruction(ShiftInstruction):
    pass

#TODO: should be treated as floating point?
@instruction("fn.add.s", "rD,rA,rB", "0x7 00 DD DDDA AAAA BBBB B000", "r{B},r{A},+,r{D},=")
class FnAddSInstruction(FloatInstruction):
    pass

#TODO: should be treated as floating point?
@instruction("fn.sub.s", "rD,rA,rB", "0x7 00 DD DDDA AAAA BBBB B001", "r{B},r{A},-,r{D},=")
class FnSubSInstruction(FloatInstruction):
    pass

#TODO: should be treated as floating point?
@instruction("fn.mul.s", "rD,rA,rB", "0x7 00 DD DDDA AAAA BBBB B010", "r{B},r{A},*,r{D},=")
class FnMulSInstruction(FloatInstruction):
    pass

#TODO: should be treated as floating point?
@instruction("fn.div.s", "rD,rA,rB", "0x7 00 DD DDDA AAAA BBBB B011", "r{B},r{A},/,r{D},=")
class FnDivSInstruction(FloatInstruction):
    pass

#TODO: unknown - saturated? vectors?
@instruction("bn.adds", "rD,rA,rB", "0x7 01 DD DDDA AAAA BBBB B000")
class BnAddsInstruction(ArithmeticInstruction):
    pass

#TODO: unknown - saturated? vectors? looks like signed subtraction...
@instruction("bn.subs", "rD,rA,rB", "0x7 01 DD DDDA AAAA BBBB B001")
class BnSubsInstruction(ArithmeticInstruction):
    def __init__ (self, operands, vma):
        if operands['A'] == 0:
            raise InstructionMismatchException("This is bn.neg!")
        super().__init__(operands, vma)

@instruction("bn.neg", "rD,rB", "0x7 01 DD DDD0 0000 BBBB B001")
class BnNegInstruction(ArithmeticInstruction):
    pass

#TODO: unknown
@instruction("bn.xaadd", "rD,rA,rB", "0x7 01 DD DDDA AAAA BBBB B010")
class BnXaaddInstruction(ArithmeticInstruction):
    pass

#TODO: unknown
@instruction("bn.xcmpxchg","rD,rA,rB", "0x7 01 DD DDDA AAAA BBBB B011")
class BnXcmpxchgInstruction(ArithmeticInstruction):
    pass

#TODO: unknown - vectors?
@instruction("bn.max", "rD,rA,rB", "0x7 01 DD DDDA AAAA BBBB B100")
class BnMaxInstruction(ArithmeticInstruction):
    pass

#TODO: unknown - vectors?
@instruction("bn.min", "rD,rA,rB", "0x7 01 DD DDDA AAAA BBBB B101")
class BnMinInstruction(ArithmeticInstruction):
    pass

#TODO: unknown
@instruction("bn.lim", "rD,rA,rB", "0x7 01 DD DDDA AAAA BBBB B110")
class BnLimInstruction(ArithmeticInstruction):
    pass

#TODO: should be logical; signed?
@instruction("bn.slls", "rD,rA,rB", "0x7 10 DD DDDA AAAA BBBB B-00", "r{B},r{A},<<,r{D},=")
class BnSllsInstruction(ShiftInstruction):
    pass

#TODO: should be logical; signed?
@instruction("bn.sllis", "rD,rA,H", "0x7 10 DD DDDA AAAA HHHH H-01", "{H},r{A},<<,r{D},=")
class BnSllisInstruction(ShiftInstruction):
    pass

#TODO: How to implement floating point in ESIL?
@instruction("fn.ftoi.s", "rD,rA", "0x7 11 10 --0A AAAA DDDD D000")
class FnFtoiSInstruction(FloatInstruction):
    pass

#TODO: How to implement floating point in ESIL?
@instruction("fn.itof.s", "rD,rA", "0x7 11 10 --0A AAAA DDDD D001")
class FnItofSInstruction(FloatInstruction):
    pass

@instruction("bw.sb", "h(rA),rB", "0x8 00 BB BBBA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", "r{B},{h},r{A},+,=[1]")
class BwSbInstruction(StoreInstruction):
    pass

#TODO: zero extend
@instruction("bw.lbz", "rD,h(rA)", "0x8 01 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", "{h},r{A},+,[1],r{D},=")
class BwLbzInstruction(LoadInstruction):
    pass

@instruction("bw.sh", "i(rA),rB", "0x8 10 BB BBBA AAAA 0iii iiii iiii iiii iiii iiii iiii iiii", "r{B},{i},r{A},+,=[2]")
class BwShInstruction(StoreInstruction):
    pass

#TODO: zero extend
@instruction("bw.lhz", "rD,i(rA)", "0x8 10 DD DDDA AAAA 1iii iiii iiii iiii iiii iiii iiii iiii", "{i},r{A},+,[2],r{D},=")
class BwLhzInstruction(LoadInstruction):
    pass

@instruction("bw.sw", "w(rA),rB", "0x8 11 BB BBBA AAAA 00ww wwww wwww wwww wwww wwww wwww wwww", "r{B},{w},r{A},+,=[4]")
class BwSwInstruction(StoreInstruction):
    pass

#TODO: zero extend
@instruction("bw.lwz", "rD,w(rA)", "0x8 11 DD DDDA AAAA 01ww wwww wwww wwww wwww wwww wwww wwww", "{w},r{A},+,[4],r{D},=")
class BwLwzInstruction(LoadInstruction):
    pass

#TODO: sign extend
@instruction("bw.lws", "rD,w(rA)", "0x8 11 DD DDDA AAAA 10ww wwww wwww wwww wwww wwww wwww wwww", "{w},r{A},+,[4],r{D},=")
class BwLwsInstruction(LoadInstruction):
    pass

#TODO: isn't this 64-bit?
@instruction("bw.sd", "v(rA),rB", "0x8 11 BB BBBA AAAA 110v vvvv vvvv vvvv vvvv vvvv vvvv vvvv")
class BwSdInstruction(StoreInstruction):
    pass

#TODO: isn't this 64-bit?
@instruction("bw.ld", "rD,v(rA)", "0x8 11 DD DDDA AAAA 111v vvvv vvvv vvvv vvvv vvvv vvvv vvvv")
class BwLdInstruction(LoadInstruction):
    pass

@instruction("bw.addi", "rD,rA,g", "0x9 00 DD DDDA AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "{g},r{A},+,r{D},=")
class BwAddiInstruction(ArithmeticInstruction):
    pass

@instruction("bw.andi", "rD,rA,h", "0x9 01 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", "{h},r{A},&,r{D},=")
class BwAndiInstruction(BitwiseInstruction):
    def __init__(self, operands, vma):
        if operands['h'] == 0x7fffffff:
            raise InstructionMismatchException("This is f.abs.s!")
        super().__init__(operands, vma)

@instruction("f.abs.s", "rD,rA", "0x9 01 DD DDDA AAAA 1111 1111 1111 1111 1111 1111 1111 1110", "0x7fffffff,r{A},&,r{D},=")
class FAbsInstruction(ArithmeticInstruction):
    pass

@instruction("bw.ori", "rD,rA,h", "0x9 10 DD DDDA AAAA hhhh hhhh hhhh hhhh hhhh hhhh hhhh hhhh", "{h},r{A},|,r{D},=")
class BwOriInstruction(BitwiseInstruction):
    pass

@instruction("bw.sfeqi", "rA,g",  "0x9 11 01 10-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,r{A},{g},==,$z,?{{,1,fl,}}")
class BwSfeqiInstruction(CompareInstruction):
    pass

@instruction("bw.sfnei", "rA,g",  "0x9 11 01 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,r{A},{g},==,$z,!,?{{,1,fl,}}")
class BwSfneiInstruction(CompareInstruction):
    pass

@instruction("bw.sfgesi", "rA,g",  "0x9 11 10 00-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,{g},r{A},>=,?{{,1,fl,}}")
class BwSfgesiInstruction(CompareInstruction):
    pass

#TODO: sing extend
@instruction("bw.sfgeui", "rA,g",  "0x9 11 10 01-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,{g},r{A},>=,?{{,1,fl,}}")
class BwSfgeuiInstruction(CompareInstruction):
    pass

@instruction("bw.sfgtsi", "rA,g",  "0x9 11 10 10-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,{g},r{A},>,?{{,1,fl,}}")
class BwSfgtsiInstruction(CompareInstruction):
    pass

#TODO: sign extend
@instruction("bw.sfgtui", "rA,g",  "0x9 11 10 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,{g},r{A},>,?{{,1,fl,}}")
class BwSfgtuiInstruction(CompareInstruction):
    pass

@instruction("bw.sflesi", "rA,g",  "0x9 11 11 00-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,{g},r{A},<=,?{{,1,fl,}}")
class BwSflesiInstruction(CompareInstruction):
    pass

#TODO: sign extend
@instruction("bw.sfleui", "rA,g",  "0x9 11 11 01-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,{g},r{A},<=,?{{,1,fl,}}")
class BwSfleuiInstruction(CompareInstruction):
    pass

@instruction("bw.sfltsi", "rA,g",  "0x9 11 11 10-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,{g},r{A},<,?{{,1,fl,}}")
class BwSfltsiInstruction(CompareInstruction):
    pass

#TODO: sign extend
@instruction("bw.sfltui", "rA,g",  "0x9 11 11 11-A AAAA gggg gggg gggg gggg gggg gggg gggg gggg", "0,fl,=,{g},r{A},<,?{{,1,fl,}}")
class BwSfltuiInstruction(CompareInstruction):
    pass

@instruction("bw.beqi", "rB,I,u", "0xa 00 00 00II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "{I},r{B},==,$z,?{{,6,{u},-,pc,+=,}}")
class BwBeqiInstruction(BranchInstruction):
    pass

@instruction("bw.bnei", "rB,I,u", "0xa 00 00 01II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "{I},r{B},==,$z,!,?{{,6,{u},-,pc,+=,}}")
class BwBneiInstruction(BranchInstruction):
    pass

@instruction("bw.bgesi", "rB,I,u", "0xa 00 00 10II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "{I},r{B},>=,?{{,6,{u},-,pc,+=,}}")
class BwBgesiInstruction(BranchInstruction):
    pass

@instruction("bw.bgtsi", "rB,I,u", "0xa 00 00 11II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "{I},r{B},>,?{{,6,{u},-,pc,+=,}}")
class BwBgtsiInstruction(BranchInstruction):
    pass

@instruction("bw.blesi", "rB,I,u", "0xa 00 01 00II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "{I},r{B},<=,?{{,6,{u},-,pc,+=,}}")
class BwBlesiInstruction(BranchInstruction):
    pass

@instruction("bw.bltsi", "rB,I,u", "0xa 00 01 01II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "{I},r{B},<,?{{,6,{u},-,pc,+=,}}")
class BwBltsiInstruction(BranchInstruction):
    pass

#TODO: treat as unsigned
@instruction("bw.bgeui", "rB,I,u", "0xa 00 01 10II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "{I},r{B},>=,?{{,6,{u},-,pc,+=,}}")
class BwBgeuiInstruction(BranchInstruction):
    pass

#TODO: treat as unsigned
@instruction("bw.bgtui", "rB,I,u", "0xa 00 01 11II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "{I},r{B},>,?{{,6,{u},-,pc,+=,}}")
class BwBgtuiInstruction(BranchInstruction):
    pass

#TODO: treat as unsigned
@instruction("bw.bleui", "rB,I,u", "0xa 00 10 00II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "{I},r{B},<=,?{{,6,{u},-,pc,+=,}}")
class BwBleuiInstruction(BranchInstruction):
    pass

#TODO: treat as unsigned
@instruction("bw.bltui", "rB,I,u", "0xa 00 10 01II IIIB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "{I},r{B},<,?{{,6,{u},-,pc,+=,}}")
class BwBltuiInstruction(BranchInstruction):
    pass

@instruction("bw.beq", "rA,rB,u", "0xa 00 10 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},==,$z,?{{,6,{u},-,pc,+=,}}")
class BwBeqInstruction(BranchInstruction):
    pass

@instruction("bw.bne", "rA,rB,u", "0xa 00 10 11AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},==,$z,!,?{{,6,{u},-,pc,+=,}}")
class BwBneInstruction(BranchInstruction):
    pass

@instruction("bw.bges", "rA,rB,u", "0xa 00 11 00AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},>=,?{{,6,{u},-,pc,+=,}}")
class BwBgesInstruction(BranchInstruction):
    pass

@instruction("bw.bgts", "rA,rB,u", "0xa 00 11 01AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},>,?{{,6,{u},-,pc,+=,}}")
class BwBgtsInstruction(BranchInstruction):
    pass

#TODO: treat as unsigned
@instruction("bw.bgeu", "rA,rB,u", "0xa 00 11 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},>=,?{{,6,{u},-,pc,+=,}}")
class BwBgeuInstruction(BranchInstruction):
    pass

#TODO: treat as unsigned
@instruction("bw.bgtu", "rA,rB,u", "0xa 00 11 11AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},>,?{{,6,{u},-,pc,+=,}}")
class BwBgtuInstruction(BranchInstruction):
    pass

@instruction("bw.jal", "z",  "0xa 01 00 00-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", "pc,lr,=,6,{z},-,pc,+=")
class BwJalInstruction(JumpInstruction):
    pass

@instruction("bw.j", "z",  "0xa 01 00 01-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", "6,{z},-,pc,+=")
class BwJInstruction(JumpInstruction):
    pass

@instruction("bw.bf", "z",  "0xa 01 00 10-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", "fl,1,==,?{{,6,{z},-,pc,+=,}}")
class BwBfInstruction(BranchInstruction):
    pass

@instruction("bw.bnf", "z",  "0xa 01 00 11-- ---- zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz", "fl,0,==,?{{,6,{z},-,pc,+=,}}")
class BwBnfInstruction(BranchInstruction):
    pass

#TODO: jump absolute
@instruction("bw.ja", "g",  "0xa 01 01 00-- ---- gggg gggg gggg gggg gggg gggg gggg gggg")
class BwJaInstruction(JumpInstruction):
    pass

#TODO: unknown - jump absolute? multiply? add?
@instruction("bw.jma", "rD,z",  "0xa 01 01 01DD DDD0 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz")
class BwJmaInstruction(JumpInstruction):
    pass

#TODO: unknown - jump absolute? multiply? add? link?
@instruction("bw.jmal", "rD,z",  "0xa 01 01 01DD DDD1 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz")
class BwJmalInstruction(JumpInstruction):
    pass

#TODO: unknown - multiply? add?
@instruction("bw.lma", "rD,z",  "0xa 01 01 10DD DDD0 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz")
class BwLmaInstruction(LoadInstruction):
    pass

#TODO: unknown - multiply? add?
@instruction("bw.sma", "rB,z",  "0xa 01 01 10BB BBB1 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz")
class BwSmaInstruction(StoreInstruction):
    pass

#TODO: unknown... some sort of jump?
@instruction("bw.casewi", "rB,z",  "0xa 01 01 11BB BBB0 zzzz zzzz zzzz zzzz zzzz zzzz zzzz zzzz")
class BwCasewiInstruction(JumpInstruction):
    pass

#TODO: Treat as floating point
@instruction("fw.beq.s", "rA,rB,u", "0xa 01 10 00AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},==,$z,?{{,6,{u},-,pc,+=,}}")
class FwBeqSInstruction(BranchInstruction):
    pass

#TODO: Treat as floating point
@instruction("fw.bne.s", "rA,rB,u", "0xa 01 10 01AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},==,$z,!,?{{,6,{u},-,pc,+=,}}")
class FwBneSInstruction(BranchInstruction):
    pass

#TODO: Treat as floating point
@instruction("fw.bge.s", "rA,rB,u", "0xa 01 10 10AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},>=,?{{,6,{u},-,pc,+=,}}")
class FwBgeSInstruction(BranchInstruction):
    pass

#TODO: Treat as floating point
@instruction("fw.bgt.s", "rA,rB,u", "0xa 01 10 11AA AAAB BBBB uuuu uuuu uuuu uuuu uuuu uuuu uuuu", "r{B},r{A},>,?{{,6,{u},-,pc,+=,}}")
class FwBgtSInstruction(BranchInstruction):
    pass

@instruction("bw.mfspr", "rD,rA,o", "0xa 10 DD DDDA AAAA oooo oooo oooo oooo oooo oooo ---- -000")
class BwMfsprInstruction(MoveInstruction):
    pass

@instruction("bw.mtspr", "rA,rB,o", "0xa 10 BB BBBA AAAA oooo oooo oooo oooo oooo oooo ---- -001")
class BwMtsprInstruction(MoveInstruction):
    pass

@instruction("bw.addci", "rD,rA,p", "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -010")
class BwAddciInstruction(ArithmeticInstruction):
    pass

@instruction("bw.divi", "rD,rA,p", "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -011")
class BwDiviInstruction(ArithmeticInstruction):
    pass

@instruction("bw.divui", "rD,rA,o", "0xa 10 DD DDDA AAAA oooo oooo oooo oooo oooo oooo ---- -100")
class BwDivuiInstruction(ArithmeticInstruction):
    pass

@instruction("bw.muli", "rD,rA,p", "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -101")
class BwMuliInstruction(ArithmeticInstruction):
    pass

@instruction("bw.xori", "rD,rA,p", "0xa 10 DD DDDA AAAA pppp pppp pppp pppp pppp pppp ---- -110")
class BwXoriInstruction(ArithmeticInstruction):
    pass

@instruction("bw.mulas", "rD,rA,rB,H", "0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0000")
class BwMulasInstruction(ArithmeticInstruction):
    pass

@instruction("bw.muluas", "rD,rA,rB,H", "0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0001")
class BwMuluasInstruction(ArithmeticInstruction):
    pass

@instruction("bw.mulras", "rD,rA,rB,H", "0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0010")
class BwMulrasInstruction(ArithmeticInstruction):
    pass

@instruction("bw.muluras", "rD,rA,rB,H", "0xa 11 DD DDDA AAAA BBBB BHHH HH-- ---- ---- ---- --00 0011")
class BwMulurasInstruction(ArithmeticInstruction):
    pass

@instruction("bw.mulsu", "rD,rA,rB", "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --00 0100")
class BwMulsuInstruction(ArithmeticInstruction):
    pass

@instruction("bw.mulhsu", "rD,rA,rB", "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --00 0101")
class BwMulhsuInstruction(ArithmeticInstruction):
    pass

@instruction("bw.mulhlsu", "rD,rQ,rA,rB", "0xa 11 DD DDDA AAAA BBBB BQQQ QQ-- ---- ---- ---- --00 0110")
class BwMulhlsuInstruction(ArithmeticInstruction):
    pass

@instruction("bw.smultt", "rD,rA,rB", "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0000")
class BwSmulttInstruction(ArithmeticInstruction):
    pass

@instruction("bw.smultb", "rD,rA,rB", "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0001")
class BwSmultbInstruction(ArithmeticInstruction):
    pass

@instruction("bw.smulbb", "rD,rA,rB", "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0010")
class BwSmulbbInstruction(ArithmeticInstruction):
    pass

@instruction("bw.smulwb", "rD,rA,rB", "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0011")
class BwSmulwbInstruction(ArithmeticInstruction):
    pass

@instruction("bw.smulwt", "rD,rA,rB", "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 0100")
class BwSmulwtInstruction(ArithmeticInstruction):
    pass

@instruction("bw.umultt", "rD,rA,rB", "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1000")
class BwUmulttInstruction(ArithmeticInstruction):
    pass

@instruction("bw.umultb", "rD,rA,rB", "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1001")
class BwUmultbInstruction(ArithmeticInstruction):
    pass

@instruction("bw.umulbb", "rD,rA,rB", "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1010")
class BwUmulbbInstruction(ArithmeticInstruction):
    pass

@instruction("bw.umulwb", "rD,rA,rB", "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1011")
class BwUmulwbInstruction(ArithmeticInstruction):
    pass

@instruction("bw.umulwt", "rD,rA,rB", "0xa 11 DD DDDA AAAA BBBB B--- ---- ---- ---- ---- --10 1100")
class BwUmulwtInstruction(ArithmeticInstruction):
    pass

@instruction("bw.smadtt", "rD,rA,rB,rR", "0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0000")
class BwSmadttInstruction(ArithmeticInstruction):
    pass

@instruction("bw.smadtb", "rD,rA,rB,rR", "0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0001")
class BwSmadtbInstruction(ArithmeticInstruction):
    pass

@instruction("bw.smadbb", "rD,rA,rB,rR", "0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0010")
class BwSmadbbInstruction(ArithmeticInstruction):
    pass

@instruction("bw.smadwb", "rD,rA,rB,rR", "0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0011")
class BwSmadwbInstruction(ArithmeticInstruction):
    pass

@instruction("bw.smadwt", "rD,rA,rB,rR", "0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 0100")
class BwSmadwtInstruction(ArithmeticInstruction):
    pass

@instruction("bw.umadtt", "rD,rA,rB,rR", "0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1000")
class BwUmadttInstruction(ArithmeticInstruction):
    pass

@instruction("bw.umadtb", "rD,rA,rB,rR", "0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1001")
class BwUmadtbInstruction(ArithmeticInstruction):
    pass

@instruction("bw.umadbb", "rD,rA,rB,rR", "0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1010")
class BwUmadbbInstruction(ArithmeticInstruction):
    pass

@instruction("bw.umadwb", "rD,rA,rB,rR", "0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1011")
class BwUmadwbInstruction(ArithmeticInstruction):
    pass

@instruction("bw.umadwt", "rD,rA,rB,rR", "0xa 11 DD DDDA AAAA BBBB BRRR RR-- ---- ---- ---- --11 1100")
class BwUmadwtInstruction(ArithmeticInstruction):
    pass

@instruction("bw.copdss", "rD,rA,rB,y", "0xb 00 DD DDDA AAAA BBBB Byyy yyyy yyyy yyyy yyyy yyyy yyyy")
class BwCopdssInstruction(ArithmeticInstruction):
    pass

@instruction("bw.copd", "rD,g,H", "0xb 01 DD DDDH HHHH gggg gggg gggg gggg gggg gggg gggg gggg")
class BwCopdInstruction(ArithmeticInstruction):
    pass

@instruction("bw.cop", "g,x",  "0xb 10 xx xxxx xxxx gggg gggg gggg gggg gggg gggg gggg gggg")
class BwCopInstruction(ArithmeticInstruction):
    pass

@instruction("bg.sb", "Y(rA),rB", "0xc 00 BB BBBA AAAA YYYY YYYY YYYY YYYY",  "r{B},{Y},r{A},+,=[1]")
class BgSbInstruction(StoreInstruction):
    pass

@instruction("bg.lbz", "rD,Y(rA)", "0xc 01 DD DDDA AAAA YYYY YYYY YYYY YYYY", "{Y},r{A},+,[1],r{D},=")
class BgLbzInstruction(LoadInstruction):
    pass

@instruction("bg.sh", "X(rA),rB", "0xc 10 BB BBBA AAAA 0XXX XXXX XXXX XXXX",  "r{B},{X},r{A},+,=[2]")
class BgShInstruction(StoreInstruction):
    pass

@instruction("bg.lhz", "rD,X(rA)", "0xc 10 DD DDDA AAAA 1XXX XXXX XXXX XXXX", "{X},r{A},+,[2],r{D},=")
class BgLhzInstruction(LoadInstruction):
    pass

@instruction("bg.sw", "W(rA),rB", "0xc 11 BB BBBA AAAA 00WW WWWW WWWW WWWW", "r{B},{W},r{A},+,=[4]")
class BgSwInstruction(StoreInstruction):
    pass

#TODO: zero extend
@instruction("bg.lwz", "rD,W(rA)", "0xc 11 DD DDDA AAAA 01WW WWWW WWWW WWWW", "{W},r{A},+,[4],r{D},=")
class BgLwzInstruction(LoadInstruction):
    pass

#TODO: sign extend
@instruction("bg.lws", "rD,W(rA)", "0xc 11 DD DDDA AAAA 10WW WWWW WWWW WWWW", "{W},r{A},+,[4],r{D},=")
class BgLwsInstruction(LoadInstruction):
    pass

#TODO: isn't this 64-bit?
@instruction("bg.sd", "V(rA),rB", "0xc 11 BB BBBA AAAA 110V VVVV VVVV VVVV")
class BgSdInstruction(StoreInstruction):
    pass

#TODO: isn't this 64-bit?
@instruction("bg.ld", "rD,V(rA)", "0xc 11 DD DDDA AAAA 111V VVVV VVVV VVVV")
class BgLdInstruction(LoadInstruction):
    pass

@instruction("bg.beqi", "rB,I,U", "0xd 00 00 00II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},==,$z,?{{,4,{U},-,pc,+=,}}")
class BgBeqiInstruction(BranchInstruction):
    pass

@instruction("bg.bnei", "rB,I,U", "0xd 00 00 01II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},==,$z,!,?{{,4,{U},-,pc,+=,}}")
class BgBneiInstruction(BranchInstruction):
    pass

@instruction("bg.bgesi", "rB,I,U", "0xd 00 00 10II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},>=,?{{,4,{U},-,pc,+=,}}")
class BgBgesiInstruction(BranchInstruction):
    pass

@instruction("bg.bgtsi", "rB,I,U", "0xd 00 00 11II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},>,?{{,4,{U},-,pc,+=,}}")
class BgBgtsiInstruction(BranchInstruction):
    pass

@instruction("bg.blesi", "rB,I,U", "0xd 00 01 00II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},<=,?{{,4,{U},-,pc,+=,}}")
class BgBlesiInstruction(BranchInstruction):
    pass

@instruction("bg.bltsi", "rB,I,U", "0xd 00 01 01II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},<,?{{,4,{U},-,pc,+=,}}")
class BgBltsiInstruction(BranchInstruction):
    pass

#TODO: sign extend
@instruction("bg.bgeui", "rB,I,U", "0xd 00 01 10II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},>=,?{{,4,{U},-,pc,+=,}}")
class BgBgeuiInstruction(BranchInstruction):
    pass

#TODO: sign extend
@instruction("bg.bgtui", "rB,I,U", "0xd 00 01 11II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},>,?{{,4,{U},-,pc,+=,}}")
class BgBgtuiInstruction(BranchInstruction):
    pass

#TODO: sign extend
@instruction("bg.bleui", "rB,I,U", "0xd 00 10 00II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},<=,?{{,4,{U},-,pc,+=,}}")
class BgBleuiInstruction(BranchInstruction):
    pass

#TODO: sign extend
@instruction("bg.bltui", "rB,I,U", "0xd 00 10 01II IIIB BBBB UUUU UUUU UUUU", "{I},r{B},<,?{{,4,{U},-,pc,+=,}}")
class BgBltuiInstruction(BranchInstruction):
    pass

@instruction("bg.beq", "rA,rB,U", "0xd 00 10 10AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},==,$z,?{{,4,{U},-,pc,+=,}}")
class BgBeqInstruction(BranchInstruction):
    pass

@instruction("bg.bne", "rA,rB,U", "0xd 00 10 11AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},==,$z,!,?{{,4,{U},-,pc,+=,}}")
class BgBneInstruction(BranchInstruction):
    pass

@instruction("bg.bges", "rA,rB,U", "0xd 00 11 00AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},>=,?{{,4,{U},-,pc,+=,}}")
class BgBgesInstruction(BranchInstruction):
    pass

@instruction("bg.bgts", "rA,rB,U", "0xd 00 11 01AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},>,?{{,4,{U},-,pc,+=,}}")
class BgBgtsInstruction(BranchInstruction):
    pass

#TODO: sign extend
@instruction("bg.bgeu", "rA,rB,U", "0xd 00 11 10AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},>=,?{{,4,{U},-,pc,+=,}}")
class BgBgeuInstruction(BranchInstruction):
    pass

#TODO: sign extend
@instruction("bg.bgtu", "rA,rB,U", "0xd 00 11 11AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},>,?{{,4,{U},-,pc,+=,}}")
class BgBgtuInstruction(BranchInstruction):
    pass

@instruction("bg.jal", "t",  "0xd 01 00 tttt tttt tttt tttt tttt tttt", "pc,lr,=,4,{t},-,pc,+=")
class BgJalInstruction(JumpInstruction):
    pass

@instruction("bg.j", "t",  "0xd 01 01 tttt tttt tttt tttt tttt tttt", "4,{t},-,pc,+=")
class BgJInstruction(JumpInstruction):
    pass

@instruction("bg.bf", "t",  "0xd 01 10 tttt tttt tttt tttt tttt tttt", "fl,1,==,?{{,4,{t},-,pc,+=,}}")
class BgBfInstruction(BranchInstruction):
    pass

@instruction("bg.bnf", "t",  "0xd 01 11 tttt tttt tttt tttt tttt tttt", "fl,0,==,?{{,4,{t},-,pc,+=,}}")
class BgBnfInstruction(BranchInstruction):
    pass

@instruction("bg.addi", "rD,rA,Y", "0xd 10 DD DDDA AAAA YYYY YYYY YYYY YYYY", "{Y},r{A},+,r{D},=")
class BgAddiInstruction(ArithmeticInstruction):
    pass

#TODO: Treat as floating point
@instruction("fg.beq.s", "rA,rB,U", "0xd 11 00 00AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},==,$z,?{{,4,{U},-,pc,+=,}}")
class FgBeqSInstruction(BranchInstruction):
    pass

#TODO: Treat as floating point
@instruction("fg.bne.s", "rA,rB,U", "0xd 11 00 01AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},==,$z,!,?{{,4,{U},-,pc,+=,}}")
class FgBneSInstruction(BranchInstruction):
    pass

#TODO: Treat as floating point
@instruction("fg.bge.s", "rA,rB,U", "0xd 11 00 10AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},>=,?{{,4,{U},-,pc,+=,}}")
class FgBgeSInstruction(BranchInstruction):
    pass

#TODO: Treat as floating point
@instruction("fg.bgt.s", "rA,rB,U", "0xd 11 00 11AA AAAB BBBB UUUU UUUU UUUU", "r{B},r{A},>,?{{,4,{U},-,pc,+=,}}")
class FgBgtSInstruction(BranchInstruction):
    pass

InstructionGroupLookup = {
    0: [BtMoviInstruction,
        BtTrapInstruction,
        BtAddiInstruction,
        BtNopInstruction,
        BtMovInstruction,
        BtRfeInstruction,
        BtEiInstruction,
        BtDiInstruction,
        BtSysInstruction,
        BtAddInstruction,
        BtJInstruction],
    2: [BnSbInstruction,
        BnLbzInstruction,
        BnShInstruction,
        BnLhzInstruction,
        BnSwInstruction,
        BnLwzInstruction,
        BnLwsInstruction,
        BnSdInstruction,
        BnLdInstruction],
    3: [BnAddiInstruction,
        BnAndiInstruction,
        BnOriInstruction,
        BnSfeqiInstruction,
        BnSfneiInstruction,
        BnSfgesiInstruction,
        BnSfgeuiInstruction,
        BnSfgtsiInstruction,
        BnSfgtuiInstruction,
        BnSflesiInstruction,
        BnSfleuiInstruction,
        BnSfltsiInstruction,
        BnSfltuiInstruction,
        BnSfeqInstruction,
        BnSfneInstruction,
        BnSfgesInstruction,
        BnSfgeuInstruction,
        BnSfgtsInstruction,
        BnSfgtuInstruction,
        BnExtbzInstruction,
        BnExtbsInstruction,
        BnExthzInstruction,
        BnExthsInstruction,
        BnFf1Instruction,
        BnClzInstruction,
        BnBitrevInstruction,
        BnSwabInstruction,
        BnMfsprInstruction,
        BnMtsprInstruction,
        BnAbsInstruction,
        BnSqrInstruction,
        BnSqraInstruction,
        BnCaseiInstruction],
    4: [BnBeqiInstruction,
        BnBneiInstruction,
        BnBgesiInstruction,
        BnBgtsiInstruction,
        BnBlesiInstruction,
        BnBltsiInstruction,
        BnJInstruction,
        BnBfInstruction,
        BnBnfInstruction,
        BnBoInstruction,
        BnBnoInstruction,
        BnBcInstruction,
        BnBncInstruction,
        BnEntriInstruction,
        BnRetiInstruction,
        BnRtneiInstruction,
        BnReturnInstruction,
        BnJalrInstruction,
        BnJrInstruction,
        BnJalInstruction],
    5: [BnMlwzInstruction,
        BnMswInstruction,
        BnMldInstruction,
        BnMsdInstruction,
        BnLwzaInstruction,
        BnSwaInstruction],
    6: [BnBitwiseInstruction,
        BnOrInstruction,
        BnXorInstruction,
        BnNBitwiseInstruction,
        BnAddInstruction,
        BnSubInstruction,
        BnSllInstruction,
        BnSrlInstruction,
        BnSraInstruction,
        BnRorInstruction,
        BnCmovInstruction,
        BnMulInstruction,
        BnDivInstruction,
        BnDivuInstruction,
        BnMacInstruction,
        BnMacsInstruction,
        BnMacsuInstruction,
        BnMacuuInstruction,
        BnSmacttInstruction,
        BnSmacbbInstruction,
        BnSmactbInstruction,
        BnUmacttInstruction,
        BnUmacbbInstruction,
        BnUmactbInstruction,
        BnMsuInstruction,
        BnMsusInstruction,
        BnAddcInstruction,
        BnSubbInstruction,
        BnFlbInstruction,
        BnMulhuInstruction,
        BnMulhInstruction,
        BnModInstruction,
        BnModuInstruction,
        BnAaddInstruction,
        BnCmpxchgInstruction,
        BnSlliInstruction,
        BnSrliInstruction,
        BnSraiInstruction,
        BnRoriInstruction],
    7: [FnAddSInstruction,
        FnSubSInstruction,
        FnMulSInstruction,
        FnDivSInstruction,
        BnAddsInstruction,
        BnSubsInstruction,
        BnNegInstruction,
        BnXaaddInstruction,
        BnXcmpxchgInstruction,
        BnMaxInstruction,
        BnMinInstruction,
        BnLimInstruction,
        BnSllsInstruction,
        BnSllisInstruction,
        FnFtoiSInstruction,
        FnItofSInstruction],
    8: [BwSbInstruction,
        BwLbzInstruction,
        BwShInstruction,
        BwLhzInstruction,
        BwSwInstruction,
        BwLwzInstruction,
        BwLwsInstruction,
        BwSdInstruction,
        BwLdInstruction],
    9: [BwAddiInstruction,
        BwAndiInstruction,
        FAbsInstruction,
        BwOriInstruction,
        BwSfeqiInstruction,
        BwSfneiInstruction,
        BwSfgesiInstruction,
        BwSfgeuiInstruction,
        BwSfgtsiInstruction,
        BwSfgtuiInstruction,
        BwSflesiInstruction,
        BwSfleuiInstruction,
        BwSfltsiInstruction,
        BwSfltuiInstruction],
    10: [BwBeqiInstruction,
        BwBneiInstruction,
        BwBgesiInstruction,
        BwBgtsiInstruction,
        BwBlesiInstruction,
        BwBltsiInstruction,
        BwBgeuiInstruction,
        BwBgtuiInstruction,
        BwBleuiInstruction,
        BwBltuiInstruction,
        BwBeqInstruction,
        BwBneInstruction,
        BwBgesInstruction,
        BwBgtsInstruction,
        BwBgeuInstruction,
        BwBgtuInstruction,
        BwJalInstruction,
        BwJInstruction,
        BwBfInstruction,
        BwBnfInstruction,
        BwJaInstruction,
        BwJmaInstruction,
        BwJmalInstruction,
        BwLmaInstruction,
        BwSmaInstruction,
        BwCasewiInstruction,
        FwBeqSInstruction,
        FwBneSInstruction,
        FwBgeSInstruction,
        FwBgtSInstruction,
        BwMfsprInstruction,
        BwMtsprInstruction,
        BwAddciInstruction,
        BwDiviInstruction,
        BwDivuiInstruction,
        BwMuliInstruction,
        BwXoriInstruction,
        BwMulasInstruction,
        BwMuluasInstruction,
        BwMulrasInstruction,
        BwMulurasInstruction,
        BwMulsuInstruction,
        BwMulhsuInstruction,
        BwMulhlsuInstruction,
        BwSmulttInstruction,
        BwSmultbInstruction,
        BwSmulbbInstruction,
        BwSmulwbInstruction,
        BwSmulwtInstruction,
        BwUmulttInstruction,
        BwUmultbInstruction,
        BwUmulbbInstruction,
        BwUmulwbInstruction,
        BwUmulwtInstruction,
        BwSmadttInstruction,
        BwSmadtbInstruction,
        BwSmadbbInstruction,
        BwSmadwbInstruction,
        BwSmadwtInstruction,
        BwUmadttInstruction,
        BwUmadtbInstruction,
        BwUmadbbInstruction,
        BwUmadwbInstruction,
        BwUmadwtInstruction],
    11: [BwCopdssInstruction,
         BwCopdInstruction,
         BwCopInstruction],
    12: [BgSbInstruction,
        BgLbzInstruction,
        BgShInstruction,
        BgLhzInstruction,
        BgSwInstruction,
        BgLwzInstruction,
        BgLwsInstruction,
        BgSdInstruction,
        BgLdInstruction],
    13: [BgBeqiInstruction,
        BgBneiInstruction,
        BgBgesiInstruction,
        BgBgtsiInstruction,
        BgBlesiInstruction,
        BgBltsiInstruction,
        BgBgeuiInstruction,
        BgBgtuiInstruction,
        BgBleuiInstruction,
        BgBltuiInstruction,
        BgBeqInstruction,
        BgBneInstruction,
        BgBgesInstruction,
        BgBgtsInstruction,
        BgBgeuInstruction,
        BgBgtuInstruction,
        BgJalInstruction,
        BgJInstruction,
        BgBfInstruction,
        BgBnfInstruction,
        BgAddiInstruction,
        FgBeqSInstruction,
        FgBneSInstruction,
        FgBgeSInstruction,
        FgBgtSInstruction]
}
