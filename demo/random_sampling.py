import sys

from syntia.assembly_oracle.sampling import sample
from syntia.kadabra.arch.arch_const import ARCH_X86_32, ARCH_X86_64
from syntia.utils.utils import dump_to_json


def check_architecture(architecture):
    if architecture == "x86_32":
        return ARCH_X86_32
    elif architecture == "x86_64":
        return ARCH_X86_64
    else:
        print ("Invalid architecture: {}".format(architecture))
        exit()


if len(sys.argv) != 5:
    print "[*] Syntax: <code file> <architecture> <number of sampling iterations> <output file>"
    exit()

code_file = open(sys.argv[1]).read()
architecture = check_architecture(sys.argv[2])
max_sampling = int(sys.argv[3])
output_file = sys.argv[4]

results = sample(code_file, max_sampling, architecture, mem_inputs=True, mem_outputs=False, reg_inputs=False,
                 reg_outputs=True)

dump_to_json(output_file, results)
