from random import getrandbits
from collections import OrderedDict, deque
from syntia.kadabra.arch.arch import Architecture
from syntia.kadabra.emulator.memory import PAGESIZE, Memory
from syntia.kadabra.emulator.tracer import MemoryTracer, CodeTracer

from syntia.kadabra.emulator.hooks import *


class Emulator:
    def __init__(self, arch_id):

        arch = Architecture(arch_id)
        self.arch = arch
        self.registers = arch.registers
        self.mu = Uc(arch.uc_arch, arch.uc_mode)
        self.arch = arch
        self.memory = Memory()
        self.basic_block_breakpoints = dict()
        self.instruction_breakpoints = dict()
        self.basic_block_breakpoints_enabled = False
        self.instruction_breakpoints_enabled = False
        self.memory_trace = False
        self.basic_block_trace = False
        self.instruction_trace = False
        self.memory_tracer = MemoryTracer()
        self.code_tracer = CodeTracer()
        self.verbosity_level = 0
        self.hooks = dict()

        self.start_addr = 0
        self.end_addr = 0
        self.cont_addr = 0
        self.enforced_path = deque()
        self.force_path = False

        self.final_instruction = False
        self.stop_next_instruction = False
        self.no_zero_mem = False
        self.skip_return = False

        self.mem_read_index_map = OrderedDict()
        self.mem_read_index_counter = 0

        self._initialise_hooks()

    def reg_size(self, reg):
        return self.registers[reg][1]

    def reg_read(self, reg):
        reg = self.registers[reg][0]
        return self.mu.reg_read(reg)

    def reg_write(self, reg, val):
        reg = self.registers[reg][0]
        self.mu.reg_write(reg, val)

    def mem_read(self, addr, size):
        return self.mu.mem_read(addr, size)

    def mem_write(self, addr, val):
        self.mu.mem_write(addr, val)
        self.add_to_emulator_mem(addr, val)

    def add_to_emulator_mem(self, addr, val):
        for offset, byte in enumerate(val):
            current_addr = addr + offset
            self.memory[current_addr] = byte

    def start_execution(self, start, end, count=0):
        self.start_addr = start
        self.end_addr = end
        try:
            self.mu.emu_start(start, end, count=count)
        except UcError as e:
            if e.errno == UC_ERR_FETCH_UNMAPPED:
                return

    def stop_execution(self):
        self.cont_addr = self.reg_read(self.arch.IP)
        self.mu.emu_stop()

    def continue_execution(self, count=0):
        self.start_execution(self.cont_addr, self.end_addr, count=count)

    def mem_map(self, addr, size):
        alignment = addr % PAGESIZE
        base_addr = addr - alignment

        page_size = (int(size / PAGESIZE) * PAGESIZE) + PAGESIZE

        self.mu.mem_map(base_addr, page_size)
        # self.memory.map(base_addr, page_size)

    def mem_unmap(self, addr, size):
        self.mu.mem_unmap(addr, size)
        self.memory.unmap(addr, size)

    def _initialise_hooks(self):
        self.hooks[HOOK_MEM_RW] = 0
        self.hooks[HOOK_MEM_UNMAPPED] = 0
        self.hooks[HOOK_BASIC_BLOCK] = 0
        self.hooks[HOOK_INSTRUCTION] = 0

    def set_hooks(self, mem_rw=False, mem_unmapped=False, basic_block=False, instruction=False):

        if mem_unmapped and not self.hooks[HOOK_MEM_UNMAPPED]:
            h = self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, self)
            self.hooks[HOOK_MEM_UNMAPPED] = h

        if mem_rw and not self.hooks[HOOK_MEM_RW]:
            h = self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access, self)
            self.hooks[HOOK_MEM_RW] = h

        if basic_block and not self.hooks[HOOK_BASIC_BLOCK]:
            h = self.mu.hook_add(UC_HOOK_BLOCK, hook_block, self)
            self.hooks[HOOK_BASIC_BLOCK] = h

        if instruction and not self.hooks[HOOK_INSTRUCTION]:
            h = self.mu.hook_add(UC_HOOK_CODE, hook_code, self)
            self.hooks[HOOK_INSTRUCTION] = h

    def unset_hooks(self, mem_rw=False, mem_unmapped=False, basic_block=False, instruction=False):

        if mem_unmapped and self.hook[HOOK_MEM_UNMAPPED]:
            h = self.mu.hook_del(self.hook[HOOK_MEM_UNMAPPED])
            self.hooks[HOOK_MEM_UNMAPPED] = 0

        if mem_rw and self.hooks[HOOK_MEM_RW]:
            h = self.mu.hook_del(self.hook[HOOK_MEM_RW])
            self.hooks[HOOK_MEM_RW] = 0

        if basic_block and self.hooks[HOOK_BASIC_BLOCK]:
            h = self.mu.hook_del(self.hooks[HOOK_BASIC_BLOCK])
            self.hooks[HOOK_BASIC_BLOCK] = 0

        if instruction and self.hooks[HOOK_INSTRUCTION]:
            self.mu.hook_del(self.hooks[HOOK_INSTRUCTION])
            self.hooks[HOOK_INSTRUCTION] = 0

    def initialise_regs_random(self, value=None):
        for reg in self.registers:
            if reg == self.arch.IP or reg == self.arch.FLAGS or reg in self.arch.segment_registers:
                continue
            if self.reg_size(reg) != self.arch.size:
                continue
            if not value:
                value = getrandbits(self.reg_size(reg))
            self.reg_write(reg, value)

    def dump_registers(self):
        dump = OrderedDict()
        for reg in self.registers:
            value = self.reg_read(reg)
            dump.update({reg: value})

        return dump

    def dump_mem(self):
        mem = OrderedDict()
        for addr in sorted(self.memory):
            mem[addr] = self.memory[addr]

        return mem

    def dump_state(self):
        registers = self.dump_registers()
        mem = self.dump_mem()

        return registers, mem

    def add_basic_block_breakpoint(self, addr, cb, *args):
        self.basic_block_breakpoints[addr] = [cb, args]

    def add_instruction_breakpoint(self, addr, cb, *args):
        self.instruction_breakpoints[addr] = [cb, args]

    def remove_breakpoint(self, addr, basic_block=False, instruction=False):
        if basic_block:
            if addr in self.basic_block_breakpoints:
                del [self.basic_block_breakpoints[addr]]

        if instruction:
            if addr in self.instruction_breakpoints:
                del [self.instruction_breakpoints[addr]]

    def set_traces(self, memory=False, basic_block=False, instruction=False):
        if memory:
            self.set_hooks(mem_rw=True)
            self.memory_trace = True
        if basic_block:
            self.set_hooks(basic_block=True)
            self.basic_block_trace = True
        if instruction:
            self.set_hooks(instruction=True)
            self.instruction_trace = True

    def unset_traces(self, memory=False, basic_block=False, instruction=False):
        if memory:
            self.memory_trace = False
        if basic_block:
            self.basic_block_trace = False
        if instruction:
            self.instruction_trace = False

    def reset_traces(self, memory=False, basic_block=False, instruction=False):
        if memory:
            self.memory_tracer = MemoryTracer()
        if basic_block:
            self.code_tracer.reset_basic_block_trace()
        if instruction:
            self.code_tracer.reset_instruction_trace()

    def enable_breakpoints(self, basic_block=False, instruction=False):
        if basic_block:
            self.set_hooks(basic_block=True)
            self.basic_block_breakpoints_enabled = True

        if instruction:
            self.set_hooks(instruction=True)
            self.instruction_breakpoints_enabled = True

    def disable_breakpoints(self, basic_block=False, instruction=False):
        if basic_block:
            self.basic_block_breakpoints_enabled = False

        if instruction:
            self.instruction_breakpoints_enabled = False

    def enforce_path(self, path):
        self.set_hooks(instruction=True)
        self.enforced_path = deque(path)
        self.force_path = True
        while len(self.enforced_path) > 1:
            start_addr = self.enforced_path[0][0]
            end_addr = self.enforced_path[1][0]
            self.start_execution(start_addr, end_addr)

        start_addr = self.enforced_path[0][0]
        instr_size = self.enforced_path[0][1]
        end_addr = start_addr + instr_size
        self.start_execution(start_addr, end_addr, count=1)
        self.enforced_path = deque()
        self.force_path = False

    def set_mem_read_index(self, index, val):
        self.mem_read_index_map[index] = val

    def unset_mem_read_index(self):
        self.mem_read_index_map = OrderedDict()
