from r2lang import R
from isa import instructions


class BA2Analyzer:
    MIN_OP_SIZE = 2
    MAX_OP_SIZE = 6

    def __init__(self, a):
        if (a != 0):
            self._a = a
            print ("a", a)

    def archinfo(self, query):
        if query == 2: # R_ANAL_ARCHINFO_ALIGN
            return 0
        elif query == 1: # R_ANAL_ARCHINFO_MAX_OP_SIZE
            return self.MAX_OP_SIZE
        elif query == 0: # R_ANAL_ARCHINFO_MIN_OP_SIZE
            return self.MIN_OP_SIZE
        return 0

    def set_reg_profile(self):
        return """
            =PC pc
            =SP r1
            =BP r2
            =A0 r0
            =A1 r1
            =A2 r2
            =A3 r3
            =A4 r4
            =A5 r5
            =A6 r6
            =A7 r7
            =A8 r8
            gpr r0  .32     0   0
            gpr r1  .32     4   0
            gpr r2  .32     8   0
            gpr r3  .32     12  0
            gpr r4  .32     16  0
            gpr r5  .32     20  0
            gpr r6  .32     24  0
            gpr r7  .32     28  0
            gpr r8  .32     32  0
            gpr r9  .32     36  0
            gpr r10 .32     40  0
            gpr r11 .32     44  0
            gpr r12 .32     48  0
            gpr r13 .32     52  0
            gpr r14 .32     56  0
            gpr r15 .32     60  0
            gpr r16 .32     64  0
            gpr r17 .32     68  0
            gpr r18 .32     72  0
            gpr r19 .32     76  0
            gpr r20 .32     80  0
            gpr r21 .32     84  0
            gpr r22 .32     88  0
            gpr r23 .32     92  0
            gpr r24 .32     96  0
            gpr r25 .32     100 0
            gpr r26 .32     104 0
            gpr r27 .32     108 0
            gpr r28 .32     112 0
            gpr r29 .32     116 0
            gpr r30 .32     120 0
            gpr r31 .32     124 0
            gpr sp  .32     4   0
            gpr fp  .32     8   0
            gpr lr  .32     36  0
            gpr pc  .32     128 0
            gpr fl  .1      132 0
            gpr mac .64     136 0"""

    def op(self, memview, addr):
        op = {
            "type" : R.R_ANAL_OP_TYPE_NULL,
            "cycles" : 0,
            "stackop" : 0,
            "stackptr" : 0,
            "ptr" : -1,
            "jump" : -1,
            "addr" : addr,
            "eob" : False,
            "esil" : "",
        }

        try:
            insn, parsed_bytes = instructions.Instruction.lift(memview, addr)

            op['esil'] = insn.esil()

            if isinstance(insn, instructions.TrapInstruction):
                op['type'] = R.R_ANAL_OP_TYPE_TRAP

            elif isinstance(insn, instructions.ArithmeticInstruction):
                op['type'] = R.R_ANAL_OP_TYPE_ADD

            elif isinstance(insn, instructions.ShiftInstruction):
                op['type'] = R.R_ANAL_OP_TYPE_SHR

            elif isinstance(insn, instructions.CompareInstruction):
                op['type'] = R.R_ANAL_OP_TYPE_CMP

            elif isinstance(insn, instructions.BranchInstruction):
                op['type'] = R.R_ANAL_OP_TYPE_CJMP
                op['jump'] = insn.target_addr
                op['fail'] = insn.fail_addr

            elif isinstance(insn, instructions.JumpInstruction):
                if isinstance(insn, (instructions.BtJInstruction,
                                     instructions.BnJInstruction,
                                     instructions.BwJInstruction,
                                     instructions.BgJInstruction)):
                    op['type'] = R.R_ANAL_OP_TYPE_JMP
                    op['jump'] = insn.target_addr
                elif isinstance(insn, (instructions.BnJalInstruction,
                                       instructions.BwJalInstruction,
                                       instructions.BgJalInstruction)):
                    op['type'] = R.R_ANAL_OP_TYPE_CALL
                    op['jump'] = insn.target_addr
                elif isinstance(insn, instructions.BnJrInstruction):
                    op['type'] = R.R_ANAL_OP_TYPE_IJMP
                elif isinstance(insn, instructions.BnJalrInstruction):
                    op['type'] = R.R_ANAL_OP_TYPE_ICALL
                    if insn.target_register == 9: # lr, Link Register
                        op['type'] = R.R_ANAL_OP_TYPE_RET

            elif isinstance(insn, instructions.LoadInstruction):
                op['type'] = R.R_ANAL_OP_TYPE_LOAD
                if isinstance(insn, instructions.BnEntriInstruction):
                    op['type'] = R.R_ANAL_OP_TYPE_RET
                    op['stackop'] = R.R_ANAL_STACK_INC

            elif isinstance(insn, instructions.StoreInstruction):
                op['type'] = R.R_ANAL_OP_TYPE_STORE
                if isinstance(insn, instructions.BnEntriInstruction):
                    op['type'] = R.R_ANAL_OP_TYPE_SUB
                    op['stackop'] = R.R_ANAL_STACK_INC

            elif isinstance(insn, instructions.MoveInstruction):
                op['type'] = R.R_ANAL_OP_TYPE_MOV

            elif isinstance(insn, instructions.NopInstruction):
                op['type'] = R.R_ANAL_OP_TYPE_NOP

            elif isinstance(insn, instructions.MacInstruction):
                op['type'] = R.R_ANAL_OP_TYPE_UNK

            elif isinstance(insn, instructions.FloatInstruction):
                op['type'] = R.R_ANAL_OP_TYPE_AND

            return [parsed_bytes, op]
        except KeyError as ke:
            # It's usually just a matter of unaligned block...
            pass
        except Exception as e:
            import traceback
            traceback.print_exc()

        return [0, op]

def ba2anal(a):
    analyzer = BA2Analyzer(a)

    return {
        "name": "ba2",
        "arch": "ba2",
        "bits": 32,
        "esil": 1,
        "license": "BSD",
        "desc": "Beyond Architecture 2 analysis plugin",
        "set_reg_profile": analyzer.set_reg_profile,
        "op": analyzer.op,
        "archinfo": analyzer.archinfo,
        "esil": False,
    }
