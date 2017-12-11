from collections import OrderedDict
from orderedset import OrderedSet

OP1 = OrderedSet(["bvnot",
                  "bvneg",
                  ])
OP2 = OrderedSet(["bvadd",
                  "bvsub",
                  "bvmul",
                  "bvudiv",
                  "bvsdiv",
                  "bvurem",
                  "bvsrem",
                  "bvshl",
                  "bvlshr",
                  "bvashr",
                  "bvand",
                  "bvor",
                  "bvxor",
                  "zero_extend",
                  "bvconcat",
                  ])

OP3 = OrderedSet(["bvextract",
                  "sign_extend"
                  ])

COMMUTATIVE_OPS = OrderedSet(["bvadd",
                              "bvmul",
                              "bvand",
                              "bvor",
                              "bvxor"])

NON_TERMINALS = OrderedSet(["u8",
                            "u16",
                            "u32",
                            "u64",
                            ])


class Grammar(object):
    def __init__(self, variables, constants=OrderedSet(), bitsize=64):
        self.variables = OrderedDict([(v.name, v.size) for v in variables])
        self.constants = constants
        self.bit_sizes = self.gen_sizes(bitsize)

        self.terminals = OrderedSet([v.name for v in variables] + list(constants))
        self.non_terminals = OrderedSet(["u{}".format(size) for size in self.bit_sizes])

        self.op1 = OP1.copy()
        self.op2 = OP2.copy()
        self.op3 = OP3.copy()
        self.commutative_ops = COMMUTATIVE_OPS.copy()

        self.rules = self.gen_rules()

    def gen_sizes(self, bit_size):
        sizes = set([bit_size])
        for v in self.variables:
            size = self.variables[v]
            sizes.add(size)
        return list(sizes)

    def gen_rules(self):
        rules = OrderedDict()
        for index in xrange(len(self.bit_sizes)):
            size = self.bit_sizes[index]
            non_terminal = self.non_terminals[index]
            rules[non_terminal] = self.gen_size_rules(size)

        return rules

    def gen_size_rules(self, size):
        rules = OrderedSet()

        rules.add("{} u{} u{} bvadd".format(size, size, size))
        rules.add("{} u{} u{} bvsub".format(size, size, size))
        rules.add("{} u{} u{} bvmul".format(size, size, size))
        rules.add("{} {} u{} u{} bvconcat u{} bvudiv".format(size, size, size, size, size))
        rules.add("{} {} u{} u{} bvconcat u{} bvsdiv".format(size, size, size, size, size))
        rules.add("{} {} u{} u{} bvconcat u{} bvurem".format(size, size, size, size, size))
        rules.add("{} {} u{} u{} bvconcat u{} bvsrem".format(size, size, size, size, size))
        # rules.add("{} u{} u{} bvudiv".format(size, size, size))
        # rules.add("{} u{} u{} bvsdiv".format(size, size, size))
        # rules.add("{} u{} u{} bvurem".format(size, size, size))
        # rules.add("{} u{} u{} bvsrem".format(size, size, size))
        rules.add("{} u{} u{} bvshl".format(size, size, size))
        rules.add("{} u{} u{} bvlshr".format(size, size, size))
        rules.add("{} u{} u{} bvashr".format(size, size, size))
        rules.add("{} u{} u{} bvand".format(size, size, size))
        rules.add("{} u{} u{} bvor".format(size, size, size))
        rules.add("{} u{} u{} bvxor".format(size, size, size))
        rules.add("{} u{} bvnot".format(size, size))
        rules.add("{} u{} bvneg".format(size, size))

        if size == 64:
            # movzx
            if 32 in self.bit_sizes:
                rules.add("32 64 u32 zero_extend")
            if 16 in self.bit_sizes:
                rules.add("16 64 u16 zero_extend")
            if 8 in self.bit_sizes:
                rules.add("8 64 u8 zero_extend")
            # movsx
            if 32 in self.bit_sizes:
                rules.add("32 64 32 u32 sign_extend")
            if 16 in self.bit_sizes:
                rules.add("16 64 16 u16 sign_extend")
            if 8 in self.bit_sizes:
                rules.add("8 64 8 u8 sign_extend")
            # concat
            if 32 in self.bit_sizes:
                rules.add("32 u32 u32 bvconcat")
        if size == 32:
            # movzx
            if 16 in self.bit_sizes:
                rules.add("16 32 u16 zero_extend".format(size))
            if 8 in self.bit_sizes:
                rules.add("8 32 u8 zero_extend".format(size))
            # movsx
            if 16 in self.bit_sizes:
                rules.add("16 32 16 u16 sign_extend")
            if 8 in self.bit_sizes:
                rules.add("8 32 8 u8 sign_extend")
            # extract
            if 64 in self.bit_sizes:
                rules.add("64 u64 0 31 bvextract")
            # concat
            if 16 in self.bit_sizes:
                rules.add("16 u16 u16 bvconcat")
        if size == 16:
            # movzx
            if 8 in self.bit_sizes:
                rules.add("8 16 u8 zero_extend".format(size))
            # movsx
            if 8 in self.bit_sizes:
                rules.add("8 16 8 u8 sign_extend")
            # extract
            if 64 in self.bit_sizes:
                rules.add("64 u64 0 15 bvextract")
            if 32 in self.bit_sizes:
                rules.add("32 u32 0 15 bvextract")
            # concat
            if 8 in self.bit_sizes:
                rules.add("8 u8 u8 bvconcat")
        if size == 8:
            # extract
            if 64 in self.bit_sizes:
                rules.add("64 u64 0 7 bvextract")
                rules.add("64 u64 8 15 bvextract")
            if 32 in self.bit_sizes:
                rules.add("32 u32 0 7 bvextract")
                rules.add("32 u32 8 15 bvextract")
            if 16 in self.bit_sizes:
                rules.add("16 u16 0 7 bvextract")
                rules.add("16 u16 8 15 bvextract")

        for v in self.variables:
            if self.variables[v] == size:
                rules.add(v)

        for c in self.constants:
            rules.add(c)

        return rules

    def dump(self):
        """
        Dumps state to a nested dict
        :return: dict
        """
        ret = OrderedDict()
        ret["variables"] = list(self.variables)
        ret["constants"] = list(self.constants)
        ret["terminals"] = list(self.terminals)
        ret["non_terminals"] = list(self.non_terminals)
        ret["op1"] = list(self.op1)
        ret["op2"] = list(self.op2)
        ret["commutative_ops"] = list(self.commutative_ops)
        ret["u64_rules"] = list(self.u64_rules)

        return ret
