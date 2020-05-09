import sys

from z3 import simplify

from syntia.mcts.game import Game, Variable
from syntia.mcts.grammar import Grammar
from syntia.mcts.mcts import *
from syntia.utils.paralleliser import Paralleliser

BITSIZE = 32
MAX_UNSIGNED = 2 ** BITSIZE
NUM_OF_VARIABLES = 3

if len(sys.argv) < 2:
    max_iter = 50000
else:
    max_iter = int(sys.argv[1])

if len(sys.argv) < 3:
    uct_scalar = 1.2
else:
    uct_scalar = float(sys.argv[2])

# example I/O map
in_out_map = {
    (1, 1, 1): 2,
    (1, 2, 3): 3,
}


# todo: generate your own I/O map


def oracle(args):
    return in_out_map[tuple(args)]


def synthesise(command, result, index):
    ret = ""

    max_iter = command[0]
    uct_scalar = command[1]
    game = command[2]
    oracle = command[3]
    synthesis_inputs = command[4]

    mc = MCTS(game, oracle, synthesis_inputs, uct_scalar=uct_scalar)
    mc.verbosity_level = 2
    s = State(game, BITSIZE)

    mc.search(s, max_iter)

    if mc.final_expression:
        ret = rpn_to_infix(mc.final_expression)
        print("{} ({} iterations)".format(rpn_to_infix(mc.final_expression), mc.current_iter))
        try:
            print("{} (simplified)".format(simplify(game.to_z3(mc.final_expression))))
        except:
            pass

    result[index] = ret


variables = []
for var_index in range(3):
    v = Variable("V.{}".format(var_index), BITSIZE)
    variables.append(v)

grammar = Grammar(variables)

game = Game(grammar, variables, bitsize=BITSIZE)

task_groups = []
workers = []
commands = []

for index in range(4):
    task_group = "TG"
    task_groups.append(task_group)

    synthesis_inputs = [list(k) for k in in_out_map]
    command = [max_iter, uct_scalar, game, oracle, synthesis_inputs]

    workers.append(synthesise)
    commands.append(command)

number_of_tasks = len(commands)

print("Starting main synthesis")
print(number_of_tasks)

paralleliser = Paralleliser(commands, workers, number_of_tasks, task_groups)

start_time = time()
paralleliser.execute()

end_time = time()

print("Synthesis finished in {} seconds".format(end_time - start_time))
