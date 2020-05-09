from syntia.assembly_oracle.assembly_oracle import AssemblyOracle

from random import getrandbits
from collections import OrderedDict

import multiprocessing


def fork(worker, worker_args):
    """
    Forks the current state and executes a worker function
    :param worker: worker function
    :param worker_args: arguments for worker function
    :return: ret value of worker
    """
    # feedback mechanism
    manager = multiprocessing.Manager()
    q = manager.Queue()
    # add to worker arguments
    worker_args.append(q)
    # create process
    p = multiprocessing.Process(target=worker, args=worker_args)
    # start process
    p.start()
    # wait until process finishes
    p.join()
    return q.get()


def worker_extract_arguments(a_oracle, code_path, queue):
    """
    Extracts the inputs and outputs of a trace slice
    :param a_oracle: assembly oracle
    :param queue: feedback mechanism
    :return: assembly oracle state
    """
    try:
        a_oracle.emu.enable_breakpoints(instruction=True)
        a_oracle.extract_start()
        a_oracle.emu.enforce_path(code_path)
        a_oracle.extract_end()

        # define state
        state = [a_oracle.current_inputs, a_oracle.current_outputs]

        # add to feedback mechanism
        queue.put(state)
    except:
        queue.put([None] * 2)


def worker_oracle(a_oracle, args, queue):
    """
    Worker for querying the assembly oracle' oracle
    :param a_oracle: assembly oracle
    :param args: random inputs
    :param queue: feedback mechanism
    :return: oracle outputs
    """
    # catch unicorn fails
    try:
        queue.put(a_oracle.oracle(args))
    except:
        queue.put(None)


def store_input_data(args, input_values=[]):
    """
    Prepatres
    """
    ret = OrderedDict()

    for index in range(len(args)):
        ret[index] = OrderedDict()

        # input/output location, size and value
        location = args[index][0] if isinstance(args[index][0], basestring) else "mem_0x{:x}".format(args[index][0])
        size = "0x{:x}".format(args[index][1])
        value = "0x{:x}".format(input_values[index] if input_values else args[index][2])

        # store
        ret[index]["location"] = location
        ret[index]["size"] = size
        ret[index]["value"] = value

    return ret


def sample(code, max_sampling, architecture, reg_inputs=True, reg_outputs=True, mem_inputs=True, mem_outputs=True):
    global assembly_oracle

    results = OrderedDict()

    """
    1. configure assembly oracle
    """

    # assembly oracle instance
    assembly_oracle = AssemblyOracle(architecture)
    # start/end address
    start_address = 0x1000000
    # code path to enforce
    code_path = assembly_oracle.derive_static_path(start_address, code)
    # map and init memory
    assembly_oracle.emu.mem_map(start_address, 2000 * 1024 * 1024)
    assembly_oracle.emu.mem_write(start_address, code)
    # use memory inputs/outputs
    assembly_oracle.memory_inputs = mem_inputs
    assembly_oracle.memory_outputs = mem_outputs
    # use register inputs/outputs
    assembly_oracle.register_inputs = reg_inputs
    assembly_oracle.register_outputs = reg_outputs
    # disable verbosity
    assembly_oracle.emu.verbosity_level = 0
    # init registers
    assembly_oracle.emu.initialise_regs_random()

    """
    2. initial run to determine input and output locations
    """

    # error handling: if something crashes, do it again
    fail_counter = 0

    while fail_counter < 20:
        # fork to obtain inputs and output locations
        initial_inputs, initial_outputs = fork(worker_extract_arguments, [assembly_oracle, code_path])

        # no inputs => check again
        if not initial_inputs:
            fail_counter += 1
        else:
            fail_counter = 20
    # code does not have inputs or outputs => no sampling
    if not initial_inputs or not initial_outputs:
        exit()

    # assign to assembly oracle instance
    assembly_oracle.current_inputs = initial_inputs
    assembly_oracle.current_outputs = initial_outputs
    assembly_oracle.current_path = code_path
    assembly_oracle.current_code = code

    # store
    results["initial"] = OrderedDict()
    results["initial"]["inputs"] = store_input_data(initial_inputs)
    results["initial"]["outputs"] = store_input_data(initial_outputs)

    """
    3. start random sampling
    """

    # init sampling results
    sampling_results = OrderedDict()
    # init sampling counter
    sampling_index = 0
    # failure counters for error handling
    assembly_oracle_crashed = 0
    output_len_different = 0

    while sampling_index < max_sampling:

        """
        3.1 generate random inputs
        """

        oracle_inputs = []

        # store fixed inputs
        for index in range(len(assembly_oracle.current_inputs)):
            # get random input
            random_input = getrandbits(64) % 2 ** (8 * assembly_oracle.current_inputs[index][1])
            # add to list
            oracle_inputs.append(random_input)

        """
        3.2 query assembly oracle with inputs and obtain outputs
        """

        # calculate outputs in a fork
        outputs = fork(worker_oracle, [assembly_oracle, oracle_inputs])

        # error handling: if assembly oracle crashes, start again
        if not outputs and assembly_oracle_crashed < 1000:
            assembly_oracle_crashed += 1
            continue
        # if still no outputs, cancel
        if not outputs:
            exit()

        # error handling: number of outputs changed => sample again
        if len(outputs) != len(initial_outputs) and output_len_different < 100:
            output_len_different += 1
            continue

        """
        3.3 store results
        """
        sampling_results[sampling_index] = OrderedDict()
        sampling_results[sampling_index]["inputs"] = store_input_data(initial_inputs, oracle_inputs)
        sampling_results[sampling_index]["outputs"] = store_input_data(outputs)

        sampling_index += 1

    results["sampling"] = sampling_results

    return results
