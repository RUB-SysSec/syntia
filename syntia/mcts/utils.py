import re

from collections import OrderedDict
from itertools import product, chain
from random import getrandbits, sample, choice
from hashlib import sha1

from syntia.mcts.graph import DiGraph
from syntia.mcts.grammar import OP1, OP2, OP3, NON_TERMINALS


def rpn_to_infix(expr):
    """
    Converts an expression in reverse
    polish notation into infix notation
    :param expr: str, expression in rpn
    :return: str, expression in infix notation
    """
    stack = []
    # parse expression
    for e in expr.split(" "):
        # ternary operator
        if e in OP3:
            op1 = stack.pop()
            op2 = stack.pop()
            op3 = stack.pop()
            op_type = stack.pop()

            # build expression
            if e == "bvextract":
                result = "extract({}, {}, {})".format(op1, op2, op3)
            elif e == "sign_extend":
                result = "sext({}, {}, {})".format(op3, op2, op1)

            stack.append(result)

        # binary operator
        elif e in OP2:
            # operands
            op1 = stack.pop()
            op2 = stack.pop()
            op_size = stack.pop()

            # build expression
            if e == "bvadd":
                result = "({} + {})".format(op2, op1)
            elif e == "bvsub":
                result = "({} - {})".format(op2, op1)
            elif e == "bvmul":
                result = "({} * {})".format(op2, op1)
            if e == "bvudiv":
                result = "({} / {})".format(op2, op1)
            if e == "bvsdiv":
                result = "({} /s {})".format(op2, op1)
            if e == "bvurem":
                result = "({} % {})".format(op2, op1)
            if e == "bvsrem":
                result = "({} %s {})".format(op2, op1)
            elif e == "bvshl":
                result = "({} << {})".format(op2, op1)
            elif e == "bvlshr":
                result = "({} >> {})".format(op2, op1)
            if e == "bvashr":
                result = "({} a>> {})".format(op2, op1)
            elif e == "bvand":
                result = "({} & {})".format(op2, op1)
            elif e == "bvor":
                result = "({} | {})".format(op2, op1)
            elif e == "bvxor":
                result = "({} ^ {})".format(op2, op1)
            elif e == "zero_extend":
                result = "zext({}, {})".format(op2, op1)
            elif e == "bvconcat":
                result = "({} ++ {})".format(op2, op1)

            stack.append(result)
        # unary operator
        elif e in OP1:
            # operand
            op = stack.pop()
            op_size = stack.pop()

            # operator
            if e == "bvnot":
                result = "(~ {})".format(op)
            elif e == "bvneg":
                result = "(- {})".format(op)

            stack.append(result)
        else:
            stack.append(e)

    return stack.pop()


def top_most_right_most(expr):
    """
    Calculates the index of the
    top-most-right-most non-terminal
    :param expr: str, expression in rpn
    :return: int, index of the top-most right-most non-terminal
    """
    # initilaise
    expr = expr.split(" ")
    index = len(expr)
    tprm = 0

    stack = [1]
    best = float("inf")

    # parse expression
    for e in reversed(expr):
        # decrease index
        index -= 1

        # decrease number of operators
        stack[-1] -= 1

        # ternary operator
        if e in OP3:
            # append operator length
            stack.append(3 + 1)

        # binary operator
        if e in OP2:
            # append operator length
            stack.append(2 + 1)

        # unary operator
        elif e in OP1:
            # append operator length
            stack.append(1 + 1)
        # non-terminal
        elif e in NON_TERMINALS:
            # top-most level
            if len(stack) < best:
                tprm = index
                best = len(stack)
        # remove zero-remaining variables
        while stack and stack[-1] == 0:
            stack.pop()

    return tprm


def replace_nth_occurrence(s1, s2, index):
    """
    Replaces the n-th occurrence in a string
    :param s1: str, string to modify
    :param s2: string to replace
    :param index: index of the string to modify
    :return:
    """
    # parse list
    x = s1.split(" ")
    # replace
    x[index] = s2

    return " ".join(x)


def replace_last_occurrence(s1, s2, s3):
    """
    Replaces the last occurrence of s2 in s1
    with s3
    :param s1: str, string to modify
    :param s2: str, substring to replace
    :param s3: str, replacement for substring
    :return: str, replaced string
    """
    return s1[::-1].replace(s2[::-1], s3[::-1], 1)[::-1]


def tree_graph(root, max_depth=0, add_non_terminal=True):
    """
    Builds a digraph of a tree
    :param root: root node
    :param max_depth: depth to build the tree
    :param add_non_terminal: ignores non_terminal childs
    :return: graph instance
    """
    # init
    g = DiGraph()

    todo = [root]
    done = set()

    # dfs
    while todo:
        node = todo.pop(-1)

        if node in done:
            continue

        done.add(node)

        for c in node.children:
            # limit depth
            if max_depth:
                if c.depth > max_depth:
                    continue
            # ignore terminal childs
            if not add_non_terminal:
                if c.state.is_terminal():
                    continue
            # build nodes
            a = "{} -- {} -- {:.2f} -- {}".format(node.state.expr, node.visits, node.average_reward, node.depth)
            b = "{} -- {} -- {:.2f} -- {}".format(c.state.expr, c.visits, c.average_reward, c.depth)

            # add to graph
            g.add_edge(a, b)

            todo.append(c)
    return g


def slice_graph(start_node):
    """
    Builds the slice graph from a node up to the root.
    Every siblings on the way to the top will also be added.
    :param start_node: MCTS node
    :return: graph
    """
    # init
    g = DiGraph()
    node = start_node

    # walk up
    while node:

        # add childs
        for c in node.children:
            # do not print children of start_node
            if node == start_node:
                break

            # build nodes
            a = "{} -- {} -- {:.2f}".format(rpn_to_infix(node.state.expr), node.visits, node.average_reward)
            b = "{} -- {} -- {:.2f}".format(rpn_to_infix(c.state.expr), c.visits, c.average_reward)

            # add tp graph
            g.add_edge(a, b)

        # next node
        node = node.parent

    return g


def write_graph(path, graph):
    """
    Dumps a graph into a dot file
    :param path: file path
    :param graph: DiGraph
    """
    open(path, "wb").write(graph.dot())


def replace_variables(s, variables=[], values=[], replacements=OrderedDict()):
    """
    Replaces multiple variables with values
    in a string within a single pass
    :param s: string
    :param variables: list of str variables
    :param values: list of ints
    :param replacements: dict of replacements
    :return: replaced string
    """
    if not replacements:
        # build replacement rules
        replacements = OrderedDict()
        for index, v in enumerate(variables):
            # var -> str(int)
            replacements[v] = str(values[index])

    # escape keys and sort, longest first
    substrings = sorted((re.escape(x) for x in replacements.keys()), key=len, reverse=True)

    # OR regex that matches each substring
    pattern = re.compile("|".join(substrings))

    # replace subexpression for each match
    repl = pattern.sub(lambda match: replacements[match.group(0)], s)

    return repl


def get_random_inputs(number_of_registers, number_of_inputs):
    """
    Generate random oracle/synthesis inputs
    :param number_of_registers: int
    :param number_of_inputs: int
    :return: list of lists
    """
    # input set for oracle and synthesis comparisons
    l = 10
    edge_cases = [[getrandbits(1) for x in xrange(l)],
                  [getrandbits(2) for x in xrange(l)],
                  [getrandbits(4) for x in xrange(l)],
                  [getrandbits(8) for x in xrange(l)],
                  [getrandbits(16) for x in xrange(l)],
                  [getrandbits(32) for x in xrange(l)],
                  [getrandbits(64) for x in xrange(l)]]
    # join to large list
    edge_cases = list(chain.from_iterable(edge_cases))

    # cartesian product of length 4
    cartesian = list(product(edge_cases, edge_cases, edge_cases, edge_cases))

    # choose large random samples from cartesian product
    selection = sample(cartesian, 2000)

    # initialise list of lists
    inputs = []
    # number of random samples
    for i in xrange(number_of_inputs):
        # current list
        current = []

        # number of registers
        while len(current) != number_of_registers:
            # get random sublist
            random_sublist = choice(selection)

            # random sublist > missing elements
            if number_of_registers - len(current) - len(random_sublist) > 0:
                current.extend(random_sublist)
            else:
                current.extend(random_sublist[:number_of_registers - len(current)])
        # add to inputs
        inputs.append(current)

    return inputs


def to_sha1(s):
    """
    Transforms a string into sha1
    :param s: string
    :return:  str, sha1 of s
    """
    return sha1(s).hexdigest()
