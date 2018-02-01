import sys
from orderedset import OrderedSet
from collections import OrderedDict

from syntia.utils.sampling_synthesis_helpers import AssemblyOracleSynthesizer, worker_synthesize_from_assembly_oracle
from syntia.utils.utils import dump_to_json

# check stdin
if len(sys.argv) < 3:
    print "[*] Syntax: <sampling file> <output file>"
    sys.exit(0)

# parse stdin
sampling_file_path = sys.argv[1]
output_file = sys.argv[2]

# constants for program synthesizer
constants = OrderedSet(["1", "0"])

assembly_synthesizer = AssemblyOracleSynthesizer(sampling_file_path, constants)

# init lists for parallel synthesis
worker_parameters = []
workers = []
task_groups = []

# walk over outputs
for output_number in xrange(assembly_synthesizer.number_of_outputs):
    # prepare output configuration
    #parameters, task_group = assembly_synthesizer.prepare_output_synthesis(output_number)
    parameters, task_group = assembly_synthesizer.prepare_output_synthesis(0)
    worker_parameters.append(parameters)
    workers.append(worker_synthesize_from_assembly_oracle)
    task_groups.append(task_group)

# start parallel synthesis
synthesis_results = assembly_synthesizer.synthesize_parallel(worker_parameters, workers, task_groups)

# prepare output
results = OrderedDict()
for index in xrange(len(synthesis_results)):
    results[index] = synthesis_results[index]

# write to json file
dump_to_json(output_file, results)

