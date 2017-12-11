from __future__ import division

from collections import OrderedDict, deque
from math import sqrt, log
from random import choice
from time import time

from orderedset import OrderedSet

from syntia.mcts.metrics import distance_metric
from syntia.mcts.utils import rpn_to_infix, replace_variables, to_sha1, top_most_right_most, \
    replace_nth_occurrence


class Node(object):
    def __init__(self, parent=None, state=None, depth=0):
        """
        Initialises a MCTS node
        :param parent: parent node
        :param state: node state
        :param depth: level in tree
        """
        # predecessor
        self.parent = parent
        # game state
        self.state = state
        # tree level
        self.depth = depth
        # number of visits
        self.visits = 1
        # successors in tree
        self.children = []
        # average score
        self.average_reward = 0
        # total score
        self.total_reward = 0
        # node is dead or alive
        self.dead = False

    def is_fully_expanded(self):
        return self.state.remaining_moves == OrderedSet()

    def is_terminal(self):
        return self.state.is_terminal()

    def is_non_terminal(self):
        return self.state.is_non_terminal()

    def is_expandable(self):
        """
        A node is expandable iff

        1. The it's state is not terminal
        2. The it's state has moves remaining
        :return: True or False
        """
        return self.state.is_non_terminal() or self.is_fully_expanded()

    def add_child(self, node):
        """
        Adds a child to the node
        :param node: child node
        """
        self.children.append(node)

    def expand(self):
        """
        Expands the current nide
        """
        # new state
        state = self.state.next_state()
        if not state:
            return
        # increase depth
        depth = self.depth + 1
        # new node
        node = Node(parent=self, state=state, depth=depth)
        # add child node
        self.add_child(node)

        return node


class State(object):
    def __init__(self, game, size, move=None, expr=""):
        """
        Initialises a game state
        :param game:
        :param move:
        :param expr:
        """
        # game to play
        self.game = game
        # state size
        self.size = size

        # current expression
        if not expr:
            expr = self.game.initial_move
        self.expr = expr

        # all moves
        self.moves = game.moves
        # moves that can be taken
        if size:
            self.remaining_moves = game.moves["u{}".format(size)].copy()
        else:
            self.remaining_moves = OrderedSet()

        # top-most-right-most index
        self.tprm_index = -1

        # current move
        self.current_move = move

    def is_terminal(self):
        if self.game.is_terminal(self.expr):
            return True

    def is_non_terminal(self):
        return not self.is_terminal()

    def next_state(self, random=True):
        """
        Randomly determines the next state
        :param random: bool, flag how to choose next state
        :return: State
        """
        # init top-most-right-most index
        if not self.tprm_index >= 0:
            self.tprm = top_most_right_most(self.expr)

        non_terminal = self.expr.split(" ")[self.tprm]

        # chose next move randomly
        if random:
            move = choice(list(self.remaining_moves))
        else:
            move = list(self.remaining_moves[non_terminal]).pop(0)
        # remove move from list
        self.remaining_moves.remove(move)

        # replace non-terminal
        expr = replace_nth_occurrence(self.expr, move, self.tprm)

        # new state size
        tprm = top_most_right_most(expr)
        non_terminal = expr.split(" ")[tprm]

        if not self.game.is_terminal(expr):
            size = int(non_terminal.strip("u"))
        else:
            size = 0
        # new state
        state = State(self.game, size, move=move, expr=expr)

        return state

    def __eq__(self, other):
        return self.expr == other.expr

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return str(self.expr)

    def __repr__(self):
        return self.__str__()

    def __hash__(self):
        return hash(self.expr)


class MCTS(object):
    def __init__(self, game, oracle, inputs, uct_scalar=1, nesting_level=0,
                 op_to_rules=OrderedDict()):
        """
        Initialises MCTS tree search
        :param game: game to play
        :param oracle: function, in/out oracle
        :param uct_scalar: float
        :param op_to_rules: dict of pruning rules
        """
        # input/output oracle
        self.oracle = oracle
        # set of nodes
        self.nodes = set()
        # synthesis inputs
        self.inputs = inputs
        # root node
        self.root = Node()
        self.nodes.add(self.root)
        # game to play
        self.game = game

        # number of maximal iterations
        self.max_iter = 0
        # current iteration
        self.current_iter = 0

        # init top node and reward
        self.top_terminal_node = self.root
        self.top_terminal_reward = 0
        self.top_non_terminal_node = self.root
        self.top_non_terminal_reward = 0

        # scalars for best child selection
        self.uct_scalar = uct_scalar

        # synthesis result found
        self.finished = False
        # synthesis result
        self.final_expression = ""

        # dict of oracle results
        self.oracle_queries = dict()

        # max nesting playout
        self.playout_nesting = 2

        # nesting level
        self.nesting_level = nesting_level

        # nested monte carlo tree search flag
        self.nmcts = False

        # pruning rules
        self.op_to_rules = op_to_rules

        # set of variables that evaluate to zero
        self.zero_out = OrderedSet()

        # tracks best results
        self.best_terminal_results = set()
        self.best_non_terminal_results = set()

        # verbosity level
        self.verbosity_level = 0

    def search(self, state, max_iter, max_time=0):
        """
        Performs the MCTS search
        :param state: initial state
        :param max_iter: int, number of itererations
        """
        # init root state
        self.root.state = state

        # store globally
        self.max_iter = max_iter

        # init time
        start_time = time()
        required_time = 0

        current_iter = 0
        while current_iter < max_iter and not self.finished:
            # break if timeout
            if max_time and required_time > max_time:
                break

            # store globally
            self.current_iter = current_iter
            # select next node
            node = self.selection(self.root)
            # calculate the node's reward
            reward = self.simulation(node)
            # back propagate the reward
            self.back_propagation(node, reward)
            current_iter += 1

            # update time
            current_time = time()
            required_time = current_time - start_time

    def selection(self, node):
        """
        Selects the node most-promising node
        that has to be explored
        :param node: root node
        :return: node to explore
        """
        while node.state.is_non_terminal():
            if not node.is_fully_expanded():
                new_node = node.expand()

                if not new_node:
                    node = node.parent if node.parent else self.root
                    continue

                node = new_node

                self.nodes.add(node)

                return node
            # prune node with only dead children
            elif self.prune_node(node):
                node = node.parent
            else:
                node = self.best_child(node)

        return node

    def best_child(self, node):
        """
        Selects the best child node

        Currently, it uses the standard UCT
        formula with the SA-UCT scalar as
        UCT constant. In future,
        :param node: parent node
        :return: best child node
        """
        # set scalars
        uct_scalar = self.uct_scalar

        # initialise
        best_score = 0.0
        best_children = OrderedSet()

        # iterate children
        for child in node.children:
            # ignore dead children
            if child.dead:
                continue

            # SA-UCT scalar
            sa_uct_scalar = uct_scalar * (self.max_iter - self.current_iter) / self.max_iter

            # UCT score
            exploit = child.average_reward
            explore = sqrt(log(node.visits) / child.visits)
            uct_score = exploit + sa_uct_scalar * explore

            # final score
            score = uct_score

            # remember best child
            if score > best_score:
                best_children = OrderedSet([child])
                best_score = score
            elif score == best_score:
                best_children.add(child)

        return choice(best_children)

    def simulation(self, node):
        """
        Simulates game plays until game ends, with normal playouts
        or nested playouts
        :param node: tree node
        :return: reward/score for node
        """
        # calculate reward
        if self.nesting_level and not node.is_terminal():
            reward = self._simulate_nested(node)
        else:
            reward = self._simulate_node(node)

        # disable terminal nodes
        if node.is_terminal():
            node.dead = True

        return reward

    def _simulate_nested(self, node):
        """
        Wrapper for simulated nesting
        :param node: current node
        :return: best reward
        """
        # nested monte carlo tree search
        if self.nmcts:
            reward = self._nmcts_playouts(node)
        # nested full-layer playouts
        else:
            reward = self._nested_full_layer_playouts(node)

        return reward

    def _nmcts_playouts(self, node):
        """
        Nested Monte Carlo Tree Search implementation
        for playouts
        :param node: current node
        :return: float, best reward
        """
        # initialise new MCTS instance
        mc = MCTS(self.game, self.oracle, self.inputs, nesting_level=self.nesting_level - 1, uct_scalar=self.uct_scalar)

        # new state
        state = State(self.game, expr=node.state.expr)

        # enable NMCTS flag
        mc.nmcts = True

        # MCTS search
        mc.search(state, max_iter=200)

        # best reward
        reward = mc.root.average_reward

        # if synthesis finishes, save result
        if mc.final_expression:
            # print to stdout
            self.print_reward(mc.final_expression, reward, playout=True)
            # finish synthesis
            self.finish_synthesis(mc.final_expression)

        return reward

    def _nested_full_layer_playouts(self, node):
        """
        Performs nested full-layer playouts and
        remembers the best reward

        :param node: current node
        :return: float, best node's reward
        """
        # initialise
        best_reward = 0.0
        # define new state
        state = State(self.game, expr=node.state.expr)
        # copy node
        node_copy = Node(state=state)

        # worklist
        current_layer_states = deque([node_copy])

        # if nesting level > 1
        for current_layer in xrange(self.nesting_level - 1):
            # states of the next layer
            next_layer_states = deque()
            # iterate current layer
            while current_layer_states:
                # current node
                layer_node = current_layer_states.pop()

                # expand to next layer
                while not layer_node.is_fully_expanded():
                    next_layer_states.append(layer_node.expand())

            # current layer <- next layer
            current_layer_states = deque(next_layer_states)

        # final nesting level
        while current_layer_states and not self.finished:
            # get current layer node
            layer_node = current_layer_states.pop()
            # playout current layer
            while not layer_node.is_fully_expanded() and not self.finished:
                # expand
                current_node = layer_node.expand()

                # node reward
                current_reward = self._simulate_node(current_node)

                # store best layer reward
                if current_reward > best_reward:
                    best_reward = current_reward

        return best_reward

    def _simulate_node(self, node):
        """
        Simulates game plays until game ends
        :param node:
        :return: reward of current node
        """
        # random terminal expression
        expr = self.game.derive_random_terminal(node.state.expr, max_nesting=self.playout_nesting)

        # node reward
        reward = self.score(expr)

        # reward == 1 => synthesis finished
        if reward == 1.0:
            # print to stdout
            if self.verbosity_level > 0:
                self.print_reward(expr, reward, playout=True)

            # add to best results
            self.best_terminal_results.add(expr)

            # finish synthesis
            self.finish_synthesis(expr)

        return reward

    def score(self, expr):
        """
        Evaluates an expression and returns
        its score
        :param expr: expression to evaluate
        :return: score
        """
        # init reward
        reward = 0

        # iterate over input pairs
        for args in self.inputs:
            # build replacement data structures
            repl_dict, repl_list = self._build_variable_replacements(self.game.grammar.variables, list(args))

            # oracle query
            # q_oracle = self.query_oracle(repl_list)
            q_oracle = self.query_oracle(args)

            # replace terminals with concrete values
            expr_rep = replace_variables(expr, replacements=repl_dict)

            # synthesis query
            q_syn = self.game.evaluate_expr(expr_rep)

            # apply distance metrics
            d = distance_metric(q_oracle, q_syn, self.game.bitsize)

            # increase score
            reward += d

        return reward / len(self.inputs)

    def _build_variable_replacements(self, variables, values):
        """
        Builds data structures for variable replacements
        :param variables: list of variables
        :param values: list of integers
        :return: tuple of dict and list
        """
        # initialise
        repl_dict = OrderedDict()
        repl_list = []

        # iterate variables
        for index, v in enumerate(variables):
            # variable should be set to 0
            if v in self.zero_out:
                x = 0
            else:
                # get variable size
                size = self.game.variables[v].size
                # set value
                # x = values[index] % (2 ** (size * 8))
                x = values[index] % (2 ** (size))

            # fill data structures
            repl_dict[v] = str(x)
            repl_list.append(x)

        return repl_dict, repl_list

    def query_oracle(self, args):
        """
        Queries the blackbox oracle
        :param args: list of integers
        :return: oracle results
        """
        # calculate key
        key = to_sha1(str(args))
        # check if key ins known
        if key not in self.oracle_queries:
            # query oracle
            self.oracle_queries[key] = self.oracle(args)
        # oracle query
        result = self.oracle_queries[key]

        return result

    def back_propagation(self, node, reward):
        """

        :param node: evaluated node
        :param reward: last reward
        """
        # walk up to root
        while node:
            # update total reward
            node.total_reward += reward

            # remember best node
            self.update_top_results(node, reward)

            # prune node if possible
            self.prune_node(node)

            # update average reward
            node.average_reward = node.total_reward / node.visits

            # update visit count
            node.visits += 1

            # next node
            node = node.parent

    def update_top_results(self, node, reward):
        """
        Updates the best node and reward that
        have been seen.
        :param node: evaluated node
        :param reward: node's last reward
        """
        # terminal/non-terminal node
        if node.is_terminal():
            # update top node and reward
            if reward > self.top_terminal_reward:
                # print to stdout
                if self.verbosity_level > 0:
                    self.print_reward(node.state.expr, reward)

                # update top results
                self.top_terminal_node = node
                self.top_terminal_reward = reward

                # add tp best results
                self.best_terminal_results.add(node.state.expr)
        else:
            # update top non-terminal node and reward
            if reward > self.top_non_terminal_reward and node.state.expr != "u64":
                # print to stdout
                if self.verbosity_level == 2:
                    self.print_reward(node.state.expr, reward)

                # update top results
                self.top_non_terminal_node = node
                self.top_non_terminal_reward = reward

                # add to best results
                self.best_non_terminal_results.add(node.state.expr)

    def print_reward(self, expr, reward, playout=False):
        """
        Prints the current expression and reward
        :param expr: current expression
        :param reward: expression's reward
        :param playout: flag
        """
        if playout:
            output = "{} ({} iterations) (reward: {} by random playout)".format(rpn_to_infix(expr), self.current_iter,
                                                                                reward)
        else:
            output = "{} ({} iterations) (reward: {})".format(rpn_to_infix(expr), self.current_iter, reward)

        print output

    def finish_synthesis(self, expr):
        """
        Set synthesis to finished
        :param expr: final expression
        """
        self.final_expression = expr
        self.finished = True

    @staticmethod
    def prune_node(node):
        """
        Sets a node to dead if

        1. it is fully expanded and
        2. has only dead children
        :param node: node to prune
        """
        if node.is_fully_expanded():
            if all([child.dead for child in node.children]):
                node.dead = True
                return True
