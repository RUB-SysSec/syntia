import json
from collections import OrderedDict

from capstone import *
from capstone.x86 import *
from unicorn import UC_MEM_READ, UC_MEM_WRITE

from syntia.kadabra.emulator.emulator import Emulator
from syntia.kadabra.utils.utils import int_to_hex, to_unsinged


def get_modified_writes(mem_trace):
    differences = OrderedDict()

    for state in mem_trace:
        if state.access != UC_MEM_WRITE:
            continue
        if state.mem_addr not in differences:
            differences[state.mem_addr] = [state.prev_value, state.value, state.size]
        else:
            differences[state.mem_addr][1] = state.value

    return differences


class AssemblyOracle(object):
    def __init__(self, arch):
        self.visited_handlers = 0
        self.emu = Emulator(arch)
        self.emu.set_hooks(mem_unmapped=True, mem_rw=True)
        self.emu.enable_breakpoints(instruction=True)

        self.md = Cs(CS_ARCH_X86, self.emu.arch.uc_mode)
        self.md.detail = True

        self.current_state = []
        self.registers_before = OrderedDict()

        self.use_constants = False
        self.known_paths = set()

        self.instruction_hit_map = dict()

        self.constants = set()
        self.current_path = []
        self.current_code = ""

        self.current_inputs = []
        self.current_outputs = []

        self.oracle_outputs = []

        self.memory_differences = OrderedDict()

        self.register_inputs = False
        self.memory_inputs = False
        self.register_outputs = False
        self.memory_outputs = False

    def init_registers(self, reg_json):
        for reg in reg_json:
            v = int(reg_json[reg], 16)
            self.emu.reg_write(reg, v)

    def set_extract_breakpoints(self, json_file, cb_extract_start, cb_extract_end):
        data = json.load(open(json_file))["unique_window_paths"]

        for key in data:
            start_addr = int(data[key]["start"]["address"], 16)
            end_addr = int(data[key]["end"]["address"], 16)

            self.emu.add_instruction_breakpoint(start_addr, cb_extract_start)
            self.emu.add_instruction_breakpoint(end_addr, cb_extract_end)

    def init_memory(self, mem_json):
        for addr in mem_json:
            addr_int = int(addr, 16)

            size = int(mem_json[addr]["size"], 16)
            hex_bytes = mem_json[addr]["data"].decode("hex")

            self.emu.mem_map(addr_int, size - 1)
            self.emu.mem_write(addr_int, hex_bytes)

    def load_initial_state(self, json_file):
        data = json.load(open(json_file))

        self.init_registers(data["registers"])
        self.init_memory(data["memory"])

    def derive_code_path(self):
        path = []
        for instr in self.emu.code_tracer.instruction_trace:
            path.append((instr.address, instr.size))

        return path

    def derive_static_path(self, start_address, code):
        static_path = []
        for instr in self.md.disasm(code, start_address):
            static_path.append((instr.address, instr.size))
        return static_path

    def derive_memory_inputs(self):
        memory_reads = []
        written_before_read = set()
        already_read = set()

        # initialise read index
        mem_read_index = -1
        # iterate memory accesses
        for state in self.emu.memory_tracer:
            # memread
            if state.access == UC_MEM_READ:
                # increase read index
                mem_read_index += 1
                # already read or written before read
                if state.mem_addr in already_read or any(
                        ((state.mem_addr + offset) in written_before_read for offset in range(state.size))):
                    continue
                # add to already read
                for offset in range(state.size):
                    addr = state.mem_addr + offset
                    already_read.add(addr)
                # add to valid memory reads
                # memory_reads.append((state.mem_addr, state.size, state.value))
                # memory read index instead of memory address
                memory_reads.append((mem_read_index, state.size, state.value))
            else:
                # add memory writes
                for offset in range(state.size):
                    addr = state.mem_addr + offset
                    written_before_read.add(addr)

        return memory_reads

    def derive_register_input_locations(self):
        # initialise
        register_reads = []
        written_before_read = set()
        already_read = set()

        # walk over instructions
        for instr in self.md.disasm(self.current_code, 0x1000):
            # instructions' reg reads and writes
            instr_reads, instr_writes = instr.regs_access()

            # check reads
            for reg_id in instr_reads:
                # already read or written before read
                if reg_id in already_read or reg_id in written_before_read:
                    continue
                # add to done
                already_read.add(reg_id)

                # get reg name
                reg_name = str(instr.reg_name(reg_id)).upper()

                # store reg
                register_reads.append(reg_name)
            # store writes
            for reg_id in instr_writes:
                written_before_read.add(reg_id)

        return register_reads

    def derive_register_inputs(self):
        # initialise
        register_inputs = []
        # register input locations
        register_input_locations = self.derive_register_input_locations()

        for reg in register_input_locations:
            # size
            reg_size = self.emu.reg_size(reg) / 8
            if reg_size != self.emu.arch.size / 8 or reg == self.emu.arch.FLAGS or reg == self.emu.arch.IP:
                continue

            # value
            value = self.registers_before[reg]

            # add to inputs
            register_inputs.append((reg, reg_size, value))

        return register_inputs

    def derive_inputs(self):
        inputs = []
        if self.register_inputs:
            register_inputs = self.derive_register_inputs()
            inputs += register_inputs

        if self.memory_inputs:
            memory_reads = self.derive_memory_inputs()
            inputs += memory_reads

        return inputs

    def derive_register_output_locations(self):
        # initialise
        register_writes = []
        already_written = set()

        # walk over instructions
        for instr in self.md.disasm(self.current_code, 0x1000):
            # instructions' reg reads and writes
            instr_reads, instr_writes = instr.regs_access()

            # check reads
            for reg_id in instr_writes:
                # already read or written before read
                if reg_id in already_written:
                    continue
                # add to done
                already_written.add(reg_id)

                # get reg name
                reg_name = str(instr.reg_name(reg_id)).upper()

                if reg_name == self.emu.arch.FLAGS or reg_name == self.emu.arch.IP:
                    continue

                # store reg
                register_writes.append(reg_name)

        return register_writes

    def derive_register_outputs(self):
        # initialise
        register_outputs = []
        # dump values
        registers = self.derive_register_output_locations()

        # iterate registers
        for reg in registers:
            # register size
            reg_size = self.emu.reg_size(reg) / 8
            # register value
            value = self.emu.reg_read(reg)

            # build output
            output = (reg, reg_size, value)

            # if reg_size != self.emu.arch.size / 8:
            #     continue

            # add to outputs
            register_outputs.append(output)

        return register_outputs

    def derive_memory_outputs(self, memory_differences):
        # collect outputs
        memory_outputs = []
        for address in memory_differences:
            # parse outputs
            value = memory_differences[address][1]
            size = memory_differences[address][2]
            # add to outputs
            output = (address, size, value)
            memory_outputs.append(output)

        return memory_outputs

    def derive_outputs(self, memory_differences=OrderedDict()):
        outputs = []
        if self.register_outputs:
            register_outputs = self.derive_register_outputs()
            outputs += register_outputs

        if self.memory_outputs:
            # check if memory traces are defined
            if not memory_differences:
                memory_differences = get_modified_writes(self.emu.memory_tracer)
            memory_outputs = self.derive_memory_outputs(memory_differences)
            outputs += memory_outputs

        return outputs

    def derive_code(self):
        code = ""
        for instr in self.emu.code_tracer.instruction_trace:
            code = "{}{}".format(code, instr.opcode)
        return code

    def derive_constants(self):
        constants = set()

        for instr in self.md.disasm(self.current_code, 0x1000):
            print(instr.mnemonic, instr.op_str)
            # if jump, continue
            if [group for group in instr.groups if group == X86_GRP_JUMP]:
                continue

            # collect constants
            for op in instr.operands:
                if op.type == X86_OP_IMM:
                    v = to_unsinged(op.imm, op.size)

                    constants.add(v)

        return constants

    @staticmethod
    def path_key(code_path):
        return ";".join([str(x) for x in code_path])

    def path_is_known(self, path_key):
        return path_key in self.known_paths

    def extract_start(self):
        # set memory tracing
        self.emu.set_traces(memory=True)
        # set instruction tracing
        self.emu.set_traces(instruction=True)

        # enable instruction breakpoints
        self.emu.enable_breakpoints(instruction=True)

        self.current_path = []

        # save register dump
        self.registers_before = self.emu.dump_registers()

        if self.use_constants:
            self.constants = set()

    def extract_end(self):
        # current assembly code
        self.current_code = self.derive_code()
        # assembly code path
        self.current_path = self.derive_code_path()
        # memory differences
        self.memory_differences = get_modified_writes(self.emu.memory_tracer)
        # assembly inputs
        self.current_inputs = self.derive_inputs()
        # assembly outputs
        self.current_outputs = self.derive_outputs(self.memory_differences)

        # derive constants
        if self.use_constants:
            self.constants = self.derive_constants()

        # path already handled?
        path_key = self.path_key(self.current_path)
        if self.path_is_known(path_key):
            return False

        # add to known paths
        self.known_paths.add(path_key)

        # reset traces
        self.emu.reset_traces(memory=True, instruction=True)

        # unset traces
        self.emu.unset_traces(memory=True, instruction=True)

    def restore_register_state(self):
        # restore previous registers
        for reg in self.registers_before:
            reg_size = self.emu.reg_size(reg)
            if reg_size != self.emu.arch.size / 8:
                continue
            self.emu.reg_write(reg, self.registers_before[reg])

    def restore_memory_state(self):
        # restore original memory
        for addr in self.memory_differences:
            # value
            v = self.memory_differences[addr][0]
            # size
            size = self.memory_differences[addr][2]
            # write to memory
            self.emu.mem_write(addr, int_to_hex(v, size))

    def restore_state(self):
        self.restore_register_state()
        self.restore_memory_state()

    def set_oracle_inputs(self, args):
        # set register/memory reads as inputs
        index = 0
        for input_type, size, value in self.current_inputs:
            # convert to correct size
            value = args[index] % (2 ** (size * 8))

            # check if register or memory address
            if input_type in self.emu.registers:
                # register
                reg = input_type
                # write register
                self.emu.reg_write(reg, value)
            # memory
            else:
                # memory address
                addr = input_type
                # write memory
                # self.emu.mem_write(addr, int_to_hex(value, size))
                # set memory read index
                self.emu.set_mem_read_index(addr, int_to_hex(value, size))
            # increase index
            index += 1

    def execute_current_path(self):

        if self.memory_outputs:
            # reset traces
            self.emu.reset_traces(memory=True)
            # enable memory instruction traces
            self.emu.set_traces(memory=True)

        # copy path
        path_copy = list(self.current_path)

        # execute path
        self.emu.enforce_path(self.current_path)

        # restore path
        self.current_path = path_copy

        return self.oracle_outputs

    def oracle(self, args):
        self.emu.disable_breakpoints(instruction=True)
        # memory traces
        if self.memory_outputs:
            # set memory tracing
            self.emu.set_traces(memory=True)

        # set oracle inputs
        self.set_oracle_inputs(args)

        # execute path
        self.execute_current_path()

        # derive oracle outputs
        self.oracle_outputs = self.derive_outputs()

        return self.oracle_outputs
