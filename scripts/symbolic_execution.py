import sys
from syntia.symbolic_execution.miasm_se import MiasmSEOracle

if len(sys.argv) != 3:
    print("[*] Syntax: <code file> <architecture>")
    exit()

code = open(sys.argv[1]).read()

architecture = sys.argv[2]

oracle = MiasmSEOracle(code, architecture)

oracle.execute()

# modified symbolic registers
oracle.se_engine.dump_id()

# modified symbolic memory
oracle.se_engine.dump_mem()
