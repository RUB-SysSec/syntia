from miasm2.expression.expression import ExprId, ExprAff, ExprOp, ExprInt, ExprMem

from miasm2.arch.x86.ira import ir_a_x86_64, ir_a_x86_32
from miasm2.ir.ir import AssignBlock


class SubIRA64(ir_a_x86_64):
    def __init__(self, symbol_pool):
        super(SubIRA64, self).__init__(symbol_pool)

    def call_effects(self, ad, instr):
        new_sp = ExprOp("+", self.sp, ExprOp("-", ExprInt(0x8, 64)))
        next_addr = instr.offset + len(instr.b)
        next_label = self.symbol_pool.getby_offset(next_addr)

        block1 = AssignBlock([
            ExprAff(self.sp, new_sp),
            ExprAff(ExprMem(new_sp, 64), ExprId(next_label, 64))
        ])
        block2 = AssignBlock([ExprAff(self.IRDst, ad)])
        return [block1, block2]


class SubIRA32(ir_a_x86_32):
    def __init__(self, symbol_pool):
        super(SubIRA32, self).__init__(symbol_pool)

    def call_effects(self, ad, instr):
        new_sp = ExprOp("+", self.sp, ExprOp("-", ExprInt(0x4, 32)))
        next_addr = instr.offset + len(instr.b)
        next_label = self.symbol_pool.getby_offset(next_addr)

        block1 = AssignBlock([
            ExprAff(self.sp, new_sp),
            ExprAff(ExprMem(new_sp, 32), ExprId(next_label, 32))
        ])
        block2 = AssignBlock([ExprAff(self.IRDst, ad)])
        return [block1, block2]
