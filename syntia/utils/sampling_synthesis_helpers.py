import json

from syntia.mcts.grammar import Grammar
from syntia.utils.paralleliser import Paralleliser
from syntia.mcts.mcts import *
from syntia.mcts.game import Game, Variable
from syntia.mcts.grammar import Grammar
from syntia.utils.paralleliser import Paralleliser
from syntia.mcts.utils import to_sha1
from z3 import simplify
from orderedset import OrderedSet


def parse_sampling_data(file_path):
    # load json file
    json_dump = json.load(open(file_path), object_pairs_hook=OrderedDict)

    # initialise
    data = OrderedDict()
    sampling_data = json_dump["sampling"]
    inputs = []
    outputs = []

    #
    initial_inputs = name_value_and_size(json_dump["initial"]["inputs"])
    initial_outputs = name_value_and_size(json_dump["initial"]["outputs"])

    # single iteration
    for iteration in sampling_data:
        # get inputs and outputs
        current_inputs = value_and_size(sampling_data[iteration]["inputs"])
        current_outputs = value_and_size(sampling_data[iteration]["outputs"])

        # verify if inputs/outputs are usable
        if not (verify(current_inputs, initial_inputs) and verify(current_outputs, initial_outputs)):
            continue

        # add to list
        inputs.append(current_inputs)
        outputs.append(current_outputs)

    # set inputs/outputs
    data["initial_inputs"] = initial_inputs
    data["initial_outputs"] = initial_outputs
    data["sampling_inputs"] = inputs
    data["sampling_outputs"] = outputs

    return data


def gen_variables(inputs):
    """
    Generates variables from inputs
    :param inputs: list
    :return: list
    """
    # initialise
    variables = []
    # iterate inputs
    for index in range(len(inputs)):
        # parse
        size = inputs[index][1]
        v_name = inputs[index][2]
        # create variable
        v = Variable(v_name, size=size * 8)
        # add to list
        variables.append(v)

    return variables


def value_and_size(data):
    """
    Parses tuples of (value, size)
    :param data: json dict
    :return: list of tuples
    """
    ret = []
    for index in data:
        value = int(data[index]["value"], 16)
        size = int(data[index]["size"], 16)
        current_result = (value, size)
        ret.append(current_result)
    return ret


def name_value_and_size(data):
    """
    Parses tuples of (value, size, name)
    :param data: json dict
    :return: list of tuples
    """
    ret = []
    for index in data:
        name = data[index]["location"]
        try:
            name = int(name, 16)
            name = "M.{}".format(name)
        except:
            name = str(name)
        value = int(data[index]["value"], 16)
        size = int(data[index]["size"], 16)
        current_result = (value, size, name)
        ret.append(current_result)
    return ret


def verify(current, original):
    """
    Verifies that current values are usable
    :param current: current {in,out}puts
    :param original: original {in,out}puts
    :return: True/False
    """
    # check length
    if len(current) != len(original):
        return False
    if not current:
        return False

    # check size of elements
    for index in range(len(current)):
        if current[index][1] != original[index][1]:
            return False

    return True


def inputs_without_size(arguments):
    """
    Strips the size from inputs
    :param arguments: list of inputs
    :return: list of inputs without size
    """
    # initialise
    ret = []
    # walk over inputs
    for args in arguments:
        # strip size
        args = [x[0] for x in args]
        # add to list
        ret.append(args)
    return ret


class AssemblyOracleSynthesizer:
    def __init__(self, json_file, constants):
        self.sampling_data = parse_sampling_data(json_file)

        self.inital_inputs = self.sampling_data["initial_inputs"]
        self.inital_outputs = self.sampling_data["initial_outputs"]
        self.number_of_outputs = len(self.inital_outputs)

        self.sampling_inputs = inputs_without_size(self.sampling_data["sampling_inputs"])
        self.sampling_outputs = self.sampling_data["sampling_outputs"]

        self.variables = gen_variables(self.inital_inputs)
        self.variables_grammar = OrderedSet([v.name for v in self.variables])

        # constants
        self.constants = constants

    def prepare_output_synthesis(self, output_index, uct_scalar=1.2, max_mcts_rounds=20000,
                                 playout_depth=0):
        """
        Prepares the MTS configuration for an given output number. MCTS configuration is pre-defined per default.
        :param output_index: output number
        :param uct_scalar: uct scalar for MCTS
        :param max_mcts_rounds: number of mcts rounds
        :param playout_depth: playout depth
        :return:
        """
        # output details
        output_name = self.inital_outputs[output_index][2]
        output_bitsize = self.inital_outputs[output_index][1]

        # task group
        task_group = "TG.{}".format(output_index)

        # get sampling outputs
        current_outputs = [out[output_index][0] for out in self.sampling_outputs]

        # define grammar
        grammar = Grammar(self.variables, constants=self.constants, bitsize=output_bitsize * 8)
        # synthesis command
        configuration = [self.variables, grammar, uct_scalar, max_mcts_rounds, playout_depth, output_name, output_index,
                         output_bitsize, self.sampling_inputs, current_outputs]

        return configuration, task_group

    @staticmethod
    def synthesize_parallel(worker_parameters, workers, task_groups):
        number_of_tasks = len(worker_parameters)
        paralleliser = Paralleliser(worker_parameters, workers, number_of_tasks, task_groups)

        # filter None instances
        return [r for r in paralleliser.execute() if r]


def oracle(args):
    """
    Synthesis oracle
    :param args: list of inputs
    :return: output
    """
    # initialise
    global in_out_map

    # calc hash
    args_sha1 = to_sha1(str(args).replace("L", ""))

    # return output
    return in_out_map[args_sha1]


def worker_synthesize_from_assembly_oracle(commands, result, worker_index):
    # initialise
    global in_out_map

    # parse synthesis parameters
    variables = commands[0]
    grammar = commands[1]
    utc_scalar = commands[2]
    max_mcts_rounds = commands[3]
    playout_depth = commands[4]
    output_name = commands[5]
    output_index = commands[6]
    output_bitsize = commands[7]
    synthesis_inputs = commands[8]
    synthesis_outputs = commands[9]

    # fill in/out map
    in_out_map = dict()
    for index in range(len(synthesis_inputs)):
        current_inputs_sha1 = to_sha1(str(synthesis_inputs[index]).replace("L", ""))
        in_out_map[current_inputs_sha1] = synthesis_outputs[index]

    # init mcts
    game = Game(grammar, variables, bitsize=output_bitsize * 8)
    s = State(game, output_bitsize * 8)

    mc = MCTS(game, oracle, synthesis_inputs, uct_scalar=utc_scalar)
    mc.playout_nesting = playout_depth
    mc.verbosity_level = 0

    # start synthesis
    mc.search(s, max_mcts_rounds)

    # prepare output json
    ret = OrderedDict()

    ret["output"] = OrderedDict()
    ret["output"]["name"] = output_name
    ret["output"]["number"] = output_index
    ret["output"]["size"] = output_bitsize * 8

    # top non-terminal
    ret["top_non_terminal"] = OrderedDict()
    ret["top_non_terminal"]["expression"] = OrderedDict()
    ret["top_non_terminal"]["expression"]["infix"] = rpn_to_infix(mc.top_non_terminal_node.state.expr)
    ret["top_non_terminal"]["reward"] = mc.top_non_terminal_reward

    # top terminal
    ret["top_terminal"] = OrderedDict()
    ret["top_terminal"]["expression"] = OrderedDict()
    expr = mc.top_terminal_node.state.expr if not mc.final_expression else mc.final_expression
    reward = mc.top_terminal_reward if not mc.final_expression else 1.0
    ret["top_terminal"]["expression"]["infix"] = rpn_to_infix(expr)
    ret["top_terminal"]["reward"] = reward

    # synthesis results
    ret["successful"] = "yes" if mc.final_expression else "no"
    if mc.final_expression:
        ret["result"] = OrderedDict()
        ret["result"]["final_expression"] = OrderedDict()
        ret["result"]["final_expression"]["infix"] = rpn_to_infix(mc.final_expression)
        try:
            ret["result"]["final_expression"]["simplified"] = str(simplify(game.to_z3(mc.final_expression)))
        except:
            ret["result"]["final_expression"]["simplified"] = rpn_to_infix(mc.final_expression)

    # store return value
    result[worker_index] = ret
