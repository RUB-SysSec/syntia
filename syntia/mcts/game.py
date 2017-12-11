from __future__ import division
from random import choice
from collections import OrderedDict
from orderedset import OrderedSet
import z3

from syntia.mcts.utils import top_most_right_most, replace_nth_occurrence


class Variable(object):
    def __init__(self, name, size):
        self.name = name
        self.size = size


class Game(object):
    def __init__(self, grammar, variables, bitsize=64):
        # grammmar
        self.grammar = grammar
        # set of moves
        self.moves = OrderedDict()
        for key in grammar.non_terminals:
            self.moves[key] = grammar.rules[key].copy()
        # set of terminals
        self.terminal = self.grammar.terminals.copy()

        # variables, OrderedDict
        self.variables, self.size_to_variable = self._init_variables(variables)

        self.transformation_rules = self._init_transformation_rules()

        # bit size
        self.bitsize = bitsize
        # mac unsigned
        self.max_unsigned = 2 ** bitsize
        # z3 variables dict
        self._z3_var = dict()

        # initial move
        self.initial_move = "u{}".format(bitsize)

    def _init_variables(self, variables_):
        """
        Maps variable names to variables
        :param variables_: list of variables
        :return: OrderedDict
        """
        # initialise
        variables = OrderedDict()
        size_to_variables = OrderedDict()
        # fill dict
        for v in variables_:
            variables[v.name] = v
            if v.size not in size_to_variables:
                size_to_variables[v.size] = OrderedSet()
            size_to_variables[v.size].add(v.name)

        return variables, size_to_variables

    def _init_transformation_rules(self):
        rules = OrderedDict()
        for non_terminal in self.grammar.rules:
            if non_terminal not in rules:
                rules[non_terminal] = OrderedSet()
            for rule in self.grammar.rules[non_terminal]:
                if "extract" in rule or "extend" in rule:
                    rules[non_terminal].add(rule)
        return rules

    def is_terminal(self, expr):
        """
        Check if expr contains a non-terminal
        symbol
        :param expr: str
        :return: bool
        """
        return all(t not in expr for t in self.grammar.non_terminals)

    def derive_random_terminal(self, expr, max_nesting=1):
        """

        :param expr: str, expression
        :param max_nesting: max nesting steps
        :return: str, terminal expr
        """

        counter = 0

        while not self.is_terminal(expr):
            # get tprm
            tprm = top_most_right_most(expr)
            non_terminal = expr.split(" ")[tprm]
            # derive arbitrary rule
            if counter < max_nesting:
                r_move = self.random_rule(non_terminal)
            # derive terminal
            else:
                r_move = self.random_terminal(non_terminal)
                if not r_move:
                    r_move = self.random_transformation_rule(non_terminal)
            # replace subexpression
            expr = replace_nth_occurrence(expr, r_move, tprm)

            counter += 1

        return expr

    def random_rule(self, non_terminal):
        """
        Returns a random rule
        :param e: str, expression type
        :return: str
        """
        # key = "u{}".format(expr_size)
        return choice(self.moves[non_terminal])

    def random_transformation_rule(self, non_terminal):
        """
        Returns a random rule
        :param e: str, expression type
        :return: str
        """
        # key = "u{}".format(expr_size)
        return choice(self.transformation_rules[non_terminal])

    def random_terminal(self, non_terminal):
        """
        Returns a random terminal
        :return: str
        """
        expr_size = int(non_terminal.strip("u"))
        if not expr_size in self.size_to_variable:
            return False

        return choice(self.size_to_variable[expr_size])

    def to_signed(self, v, max_unsigned=None):
        """
        Transforms a value to signed
        :param v: int
        :return: int
        """
        if not max_unsigned:
            max_unsigned = self.max_unsigned
        if v & (max_unsigned // 2):
            v -= max_unsigned
        return v

    def trunc_div(self, a, b):
        """
        Truncating divions towards 0
        :param a: int
        :param b: int
        :return: int
        """
        if a < 0:
            a = -a
            b = -b
        if b < 0:
            return (a + b + 1) // b
        return a // b

    def evaluate_expr(self, expr):
        """
        Evaluates an expression in RPN
        :param expr: str
        :return: int, evaluated expression
        """
        stack = []
        # walk over expression
        for e in expr.split(" "):
            # ternary operator
            if e in self.grammar.op3:
                op1 = stack.pop()
                op2 = stack.pop()
                op3 = stack.pop()
                op_size = stack.pop()

                if e == "bvextract":
                    end = op1
                    start = op2

                    shift = end - start + 1
                    mask = (1 << shift) - 1
                    result = (mask & (op3 >> start))
                elif e == "sign_extend":
                    op1 = op1 % (2 ** op_size)
                    d_size = op3
                    v_size = op2

                    v_signed = self.to_signed(op1, 2 ** v_size)

                    result = v_signed % (2 ** d_size)

                stack.append(result)

            # binary operator
            elif e in self.grammar.op2:
                # operand
                op1 = stack.pop()
                op2 = stack.pop()
                op_size = stack.pop()

                # operator
                if e == "bvadd":
                    result = (op2 + op1) % (2 ** op_size)
                elif e == "bvsub":
                    result = (op2 - op1) % (2 ** op_size)
                elif e == "bvmul":
                    result = (op2 * op1) % (2 ** op_size)
                elif e == "bvudiv":
                    # op2 = op2 % (2 ** op_size)
                    # op1 = op1 % (2 ** op_size)
                    try:
                        result = (op2 // op1) % (2 ** op_size)
                    except ZeroDivisionError:
                        result = (-1) % (2 ** op_size)
                elif e == "bvsdiv":
                    # op2 = op2 % (2 ** op_size)
                    # op1 = op1 % (2 ** op_size)
                    op2 = self.to_signed(op2, max_unsigned=2 ** op_size if op2 < 2 ** op_size else 2 ** (op_size * 2))
                    op1 = self.to_signed(op1, max_unsigned=2 ** op_size)
                    try:
                        result = self.trunc_div(op2, op1) % (2 ** op_size)
                    except ZeroDivisionError:
                        result = (-1) % (2 ** op_size) if 0 <= op2 else 1
                elif e == "bvurem":
                    # op2 = op2 % (2 ** op_size)
                    # op1 = op1 % (2 ** op_size)
                    try:
                        result = (op2 - op1 * (op2 // op1)) % (2 ** op_size)
                    except ZeroDivisionError:
                        if op2 == op1:
                            result = 0
                        else:
                            result = op2
                elif e == "bvsrem":
                    # op2 = op2 % (2 ** op_size)
                    # op1 = op1 % (2 ** op_size)
                    try:
                        op2 = self.to_signed(op2,
                                             max_unsigned=2 ** op_size if op2 < 2 ** op_size else 2 ** (op_size * 2))
                        op1 = self.to_signed(op1, max_unsigned=2 ** op_size)
                        result = (op2 - op1 * self.trunc_div(op2, op1)) % (2 ** op_size)
                    except ZeroDivisionError:
                        result = op2
                elif e == "bvshl":
                    op2 = op2 % (2 ** op_size)
                    op1 = op1 % (2 ** op_size)
                    if self.bitsize == 64:
                        op1 &= 63
                    else:
                        op1 &= 31
                    result = (op2 * pow(2, op1, 2 ** op_size)) % (2 ** op_size)
                elif e == "bvlshr":
                    op2 = op2 % (2 ** op_size)
                    op1 = op1 % (2 ** op_size)
                    try:
                        if self.bitsize == 64:
                            op1 &= 63
                        else:
                            op1 &= 31
                        result = ((op2 % (2 ** op_size)) >> op1) % (2 ** op_size)
                    except OverflowError:
                        result = 0
                elif e == "bvashr":
                    op2 = op2 % (2 ** op_size)
                    op1 = op1 % (2 ** op_size)
                    op2 = self.to_signed(op2, max_unsigned=2 ** op_size)
                    try:
                        if self.bitsize == 64:
                            op1 &= 63
                        else:
                            op1 &= 31
                        result = (op2 >> (op1 % (2 ** op_size))) % (2 ** op_size)
                    except OverflowError:
                        if (op2 == 0 or (op2 < op1 and self.to_signed(op1, max_unsigned=2 ** op_size) > 0) or (
                                        op2 > self.to_signed(op1, max_unsigned=2 ** op_size) and op2 > 0)):
                            result = 0
                        else:
                            result = (-1) % (2 ** op_size)

                elif e == "bvand":
                    result = (op2 & op1) % (2 ** op_size)
                elif e == "bvor":
                    result = (op2 | op1) % (2 ** op_size)
                elif e == "bvxor":
                    result = (op2 ^ op1) % (2 ** op_size)
                elif e == "zero_extend":
                    result = op1 % (2 ** op_size)
                elif e == "bvconcat":
                    op2 = op2 % (2 ** op_size)
                    op1 = op1 % (2 ** op_size)
                    result = (op2 << op_size) | op1

                stack.append(result)
            # unary operator
            elif e in self.grammar.op1:
                # operand
                op = stack.pop()
                op_size = stack.pop()

                # operator
                if e == "bvnot":
                    result = ~ op % (2 ** op_size)
                elif e == "bvneg":
                    result = - op % (2 ** op_size)

                stack.append(result)
            else:
                stack.append(int(e))

        return stack.pop() % self.max_unsigned

    def to_z3(self, expr):
        """
        Transform an expression into an z3 expression
        :param expr: str
        :return: z3 expression
        """
        stack = []
        # walk over expression
        for e in expr.split(" "):
            # ternary operator
            if e in self.grammar.op3:
                op1 = stack.pop()
                op2 = stack.pop()
                op3 = stack.pop()
                op_type = stack.pop()

                if e == "sign_extend":
                    op1 = self.to_z3_variable(op1)
                    result = z3.SignExt(int(op3) - op1.size(), op1)
                elif e == "bvextract":
                    op3 = self.to_z3_variable(op3)
                    result = z3.Extract(int(op1), int(op2), op3)
                stack.append(result)
            # binary operator
            elif e in self.grammar.op2:
                # operands
                op1 = self.to_z3_variable(stack.pop())
                op2 = self.to_z3_variable(stack.pop())
                op_type = stack.pop()

                # operator
                if e == "bvadd":
                    result = (op2 + op1)
                elif e == "bvsub":
                    result = (op2 - op1)
                elif e == "bvmul":
                    result = (op2 * op1)
                elif e == "bvudiv":
                    result = z3.UDiv(op2, op1)
                elif e == "bvsdiv":
                    result = (op2 / op1)
                elif e == "bvurem":
                    result = z3.URem(op2, op1)
                elif e == "bvsrem":
                    result = z3.SRem(op2, op1)
                elif e == "bvshl":
                    if self.bitsize == 64:
                        op1 &= 63
                    else:
                        op1 &= 31
                    result = (op2 << op1)
                elif e == "bvlshr":
                    if self.bitsize == 64:
                        op1 &= 63
                    else:
                        op1 &= 31
                    result = z3.LShR(op2, op1)
                elif e == "bvashr":
                    if self.bitsize == 64:
                        op1 &= 63
                    else:
                        op1 &= 31
                    result = (op2 >> op1)
                elif e == "bvand":
                    result = (op2 & op1)
                elif e == "bvor":
                    result = (op2 | op1)
                elif e == "bvxor":
                    result = (op2 ^ op1)
                elif e == "zero_extend":
                    result = z3.ZeroExt(int(op2) - op1.size(), op1)
                elif e == "bvconcat":
                    result = z3.Concat(op2, op1)

                stack.append(result)
            # unary operator
            elif e in self.grammar.op1:
                # operand
                op = self.to_z3_variable(stack.pop())
                op_type = stack.pop()

                # operator
                if e == "bvnot":
                    result = ~ op
                elif e == "bvneg":
                    result = - op

                stack.append(result)
            else:
                stack.append(e)

        return stack.pop()

    def to_z3_variable(self, v):
        """
        Transforms a variable into a z3 variable
        :param v: variable
        :return: z3 variable
        """
        # no variable
        if v not in self.variables:
            return v

        # get variable
        v = self.variables[v]
        # initialise dict
        if v.name not in self._z3_var:
            v_z3 = z3.BitVec(v.name, v.size)
            self._z3_var[v.name] = v_z3

        # get z3 variable
        v_z3 = self._z3_var[v.name]

        return v_z3

    def evaluate_expr_z3(self, expr, constraints, output_size):
        """
        Tramsforms an expression to z3
        :param expr: str
        :param constraints: list of constraints
        :return: int
        """
        # to z3 expression
        expr = self.to_z3(expr)
        # initialise solver
        solver = z3.Solver()
        # output variable
        output = z3.BitVec("o", output_size)

        solver.add(expr == output)

        # add constraints
        for c in constraints:
            solver.add(c)

        # check sat
        assert (solver.check() == z3.sat)
        # parse output
        ret = solver.model()[output].as_long()

        return ret
