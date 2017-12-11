from collections import OrderedDict
from unicorn import UC_ARCH_X86, UC_MODE_64

from unicorn.x86_const import *


class X86_64:
    def __init__(self):
        self.SB = "RBP"
        self.SP = "RSP"
        self.IP = "RIP"
        self.FLAGS = "RFLAGS"
        self.segment_registers = set(["ES", "FS", "GS"])

        self.uc_arch = UC_ARCH_X86
        self.uc_mode = UC_MODE_64

        self.size = 64

        self.registers = OrderedDict([("RAX", (UC_X86_REG_RAX, 64)),
                                      ("RBX", (UC_X86_REG_RBX, 64)),
                                      ("RCX", (UC_X86_REG_RCX, 64)),
                                      ("RDX", (UC_X86_REG_RDX, 64)),
                                      ("RSI", (UC_X86_REG_RSI, 64)),
                                      ("RDI", (UC_X86_REG_RDI, 64)),
                                      ("RBP", (UC_X86_REG_RBP, 64)),
                                      ("RSP", (UC_X86_REG_RSP, 64)),
                                      ("RIP", (UC_X86_REG_RIP, 64)),
                                      ("R8", (UC_X86_REG_R8, 64)),
                                      ("R9", (UC_X86_REG_R9, 64)),
                                      ("R10", (UC_X86_REG_R10, 64)),
                                      ("R11", (UC_X86_REG_R11, 64)),
                                      ("R12", (UC_X86_REG_R12, 64)),
                                      ("R13", (UC_X86_REG_R13, 64)),
                                      ("R14", (UC_X86_REG_R14, 64)),
                                      ("R15", (UC_X86_REG_R15, 64)),

                                      ("EAX", (UC_X86_REG_EAX, 32)),
                                      ("EBX", (UC_X86_REG_EBX, 32)),
                                      ("ECX", (UC_X86_REG_ECX, 32)),
                                      ("EDX", (UC_X86_REG_EDX, 32)),
                                      ("ESI", (UC_X86_REG_ESI, 32)),
                                      ("EDI", (UC_X86_REG_EDI, 32)),
                                      ("EBP", (UC_X86_REG_EBP, 32)),
                                      ("ESP", (UC_X86_REG_ESP, 32)),
                                      ("EIP", (UC_X86_REG_EIP, 32)),
                                      ("R8D", (UC_X86_REG_R8D, 32)),
                                      ("R9D", (UC_X86_REG_R9D, 32)),
                                      ("R10D", (UC_X86_REG_R10D, 32)),
                                      ("R11D", (UC_X86_REG_R11D, 32)),
                                      ("R12D", (UC_X86_REG_R12D, 32)),
                                      ("R13D", (UC_X86_REG_R13D, 32)),
                                      ("R14D", (UC_X86_REG_R14D, 32)),
                                      ("R15D", (UC_X86_REG_R15D, 32)),

                                      ("AX", (UC_X86_REG_AX, 16)),
                                      ("BX", (UC_X86_REG_BX, 16)),
                                      ("CX", (UC_X86_REG_CX, 16)),
                                      ("DX", (UC_X86_REG_DX, 16)),
                                      ("SI", (UC_X86_REG_SI, 16)),
                                      ("DI", (UC_X86_REG_DI, 16)),
                                      ("BP", (UC_X86_REG_BP, 16)),
                                      ("SP", (UC_X86_REG_SP, 16)),
                                      ("IP", (UC_X86_REG_IP, 16)),
                                      ("R8W", (UC_X86_REG_R8W, 16)),
                                      ("R9W", (UC_X86_REG_R9W, 16)),
                                      ("R10W", (UC_X86_REG_R10W, 16)),
                                      ("R11W", (UC_X86_REG_R11W, 16)),
                                      ("R12W", (UC_X86_REG_R12W, 16)),
                                      ("R13W", (UC_X86_REG_R13W, 16)),
                                      ("R14W", (UC_X86_REG_R14W, 16)),
                                      ("R15W", (UC_X86_REG_R15W, 16)),

                                      ("AL", (UC_X86_REG_AL, 8)),
                                      ("BL", (UC_X86_REG_BL, 8)),
                                      ("CL", (UC_X86_REG_CL, 8)),
                                      ("DL", (UC_X86_REG_DL, 8)),
                                      ("SIL", (UC_X86_REG_SIL, 8)),
                                      ("DIL", (UC_X86_REG_DIL, 8)),
                                      ("BPL", (UC_X86_REG_BPL, 8)),
                                      ("SPL", (UC_X86_REG_SPL, 8)),
                                      ("R8B", (UC_X86_REG_R8B, 8)),
                                      ("R9B", (UC_X86_REG_R9B, 8)),
                                      ("R10B", (UC_X86_REG_R10B, 8)),
                                      ("R11B", (UC_X86_REG_R11B, 8)),
                                      ("R12B", (UC_X86_REG_R12B, 8)),
                                      ("R13B", (UC_X86_REG_R13B, 8)),
                                      ("R14B", (UC_X86_REG_R14B, 8)),
                                      ("R15B", (UC_X86_REG_R15B, 8)),
                                      ("AH", (UC_X86_REG_AH, 8)),
                                      ("BH", (UC_X86_REG_BH, 8)),
                                      ("CH", (UC_X86_REG_CH, 8)),
                                      ("DH", (UC_X86_REG_DH, 8)),

                                      ("RFLAGS", (UC_X86_REG_EFLAGS, 64)),
                                      ])

        self.conditional_jumps = set(["70",
                                      "71",
                                      "72",
                                      "73",
                                      "74",
                                      "75",
                                      "76",
                                      "77",
                                      "78",
                                      "79",
                                      "7a",
                                      "7b",
                                      "7c",
                                      "7d",
                                      "7e",
                                      "7f",
                                      "e3",
                                      "0f80",
                                      "0f81",
                                      "0f82",
                                      "0f83",
                                      "0f84",
                                      "0f85",
                                      "0f86",
                                      "0f87",
                                      "0f88",
                                      "0f89",
                                      "0f8a",
                                      "0f8b",
                                      "0f8c",
                                      "0f8d",
                                      "0f8e",
                                      "0f8f",
                                      ])
        self.jumps = set(["ea",
                          "eb",
                          "e9",
                          "ff",
                          ])

        self.returns = set(["c3",
                            "cb",
                            "c2",
                            "ca"])

        self.calls = set(["e8",
                          "9a",
                          "ff"])
