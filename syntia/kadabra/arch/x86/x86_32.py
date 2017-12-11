from collections import OrderedDict
from unicorn import UC_ARCH_X86, UC_MODE_32

from unicorn.x86_const import *


class X86_32:
    def __init__(self):
        self.SB = "EBP"
        self.SP = "ESP"
        self.IP = "EIP"
        self.FLAGS = "EFLAGS"
        self.segment_registers = set(["ES", "FS", "GS"])
        self.uc_arch = UC_ARCH_X86
        self.uc_mode = UC_MODE_32

        self.size = 32

        self.registers = OrderedDict([("EAX", (UC_X86_REG_EAX, 32)),
                                      ("EBX", (UC_X86_REG_EBX, 32)),
                                      ("ECX", (UC_X86_REG_ECX, 32)),
                                      ("EDX", (UC_X86_REG_EDX, 32)),
                                      ("ESI", (UC_X86_REG_ESI, 32)),
                                      ("EDI", (UC_X86_REG_EDI, 32)),
                                      ("EBP", (UC_X86_REG_EBP, 32)),
                                      ("ESP", (UC_X86_REG_ESP, 32)),
                                      ("EIP", (UC_X86_REG_EIP, 32)),

                                      ("AX", (UC_X86_REG_AX, 16)),
                                      ("BX", (UC_X86_REG_BX, 16)),
                                      ("CX", (UC_X86_REG_CX, 16)),
                                      ("DX", (UC_X86_REG_DX, 16)),
                                      ("SI", (UC_X86_REG_SI, 16)),
                                      ("DI", (UC_X86_REG_DI, 16)),
                                      ("BP", (UC_X86_REG_BP, 16)),
                                      ("SP", (UC_X86_REG_SP, 16)),
                                      ("IP", (UC_X86_REG_IP, 16)),

                                      ("ES", (UC_X86_REG_ES, 16)),
                                      ("FS", (UC_X86_REG_FS, 16)),
                                      ("GS", (UC_X86_REG_GS, 16)),

                                      ("AL", (UC_X86_REG_AL, 8)),
                                      ("BL", (UC_X86_REG_BL, 8)),
                                      ("CL", (UC_X86_REG_CL, 8)),
                                      ("DL", (UC_X86_REG_DL, 8)),
                                      ("SIL", (UC_X86_REG_SIL, 8)),
                                      ("DIL", (UC_X86_REG_DIL, 8)),
                                      ("BPL", (UC_X86_REG_BPL, 8)),
                                      ("SPL", (UC_X86_REG_SPL, 8)),
                                      ("AH", (UC_X86_REG_AH, 8)),
                                      ("BH", (UC_X86_REG_BH, 8)),
                                      ("CH", (UC_X86_REG_CH, 8)),
                                      ("DH", (UC_X86_REG_DH, 8)),

                                      ("AH", (UC_X86_REG_AH, 8)),
                                      ("BH", (UC_X86_REG_BH, 8)),
                                      ("CH", (UC_X86_REG_CH, 8)),
                                      ("DH", (UC_X86_REG_DH, 8)),

                                      ("EFLAGS", (UC_X86_REG_EFLAGS, 32)),
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
