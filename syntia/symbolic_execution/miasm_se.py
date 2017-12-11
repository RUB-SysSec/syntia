from syntia.symbolic_execution.miasm_utils import SubIRA64

from miasm2.ir.symbexec import SymbolicExecutionEngine
from miasm2.analysis.machine import Machine

class MiasmSEOracle:

    def __init__(self, code, architecture):
        self.code = code
        self.machine = Machine(architecture)
        self.mdis = self.machine.dis_engine(code)
        self.ira = SubIRA64(self.mdis.symbol_pool)
        self.se_engine = SymbolicExecutionEngine(self.ira, self.machine.mn.regs.regs_init)

    def execute(self):
        addr = 0
        while addr < len(self.code):
            basic_block = self.mdis.dis_block(addr)
            self.ira.add_block(basic_block)
            ira_block = self.ira.get_block(addr)
            self.se_engine.emulbloc(ira_block)
            addr = basic_block.get_range()[1]

