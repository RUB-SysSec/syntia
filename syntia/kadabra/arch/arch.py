from syntia.kadabra.arch.x86.x86_64 import X86_64
from syntia.kadabra.arch.x86.x86_32 import X86_32
from syntia.kadabra.arch.arch_const import *


class Architecture:
    def __init__(self, arch_id):

        if arch_id == ARCH_X86_64:
            arch = X86_64()
        elif arch_id == ARCH_X86_32:
            arch = X86_32()
        else:
            raise NotImplementedError()

        self.IP = arch.IP
        self.SP = arch.SP
        self.SB = arch.SB
        self.FLAGS = arch.FLAGS
        self.segment_registers = arch.segment_registers

        self.conditional_jumps = arch.conditional_jumps
        self.jumps = arch.jumps
        self.returns = arch.returns
        self.calls = arch.calls

        self.uc_mode = arch.uc_mode
        self.uc_arch = arch.uc_arch

        self.registers = arch.registers
        self.size = arch.size
