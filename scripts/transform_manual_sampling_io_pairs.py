import sys
import json
from collections import OrderedDict
from syntia.utils.utils import to_json


def build_arguments(data):
	ret = OrderedDict()
	for number in data:
		ret[number] = build_argument(data[number]["location"], data[number]["size"], "0x0")
	return ret

def build_argument(location, size, value):
	ret = OrderedDict()
	ret["location"] = location
	ret["size"] = size
	ret["value"] = value
	return ret

def build_sampling_args(values, args):
	assert(len(values) == len(args))
	ret = OrderedDict()
	for index in args:
		ret[index] = args[index].copy()
		ret[index]["value"] = values[int(index)]

	return ret

def build_sampling(data, inputs, outputs):
	ret = OrderedDict()
	for index in xrange(len(data)):
		ret[str(index)] = OrderedDict()
		ret[str(index)]["inputs"] = build_sampling_args(data[index][:len(inputs)], inputs)
		ret[str(index)]["outputs"] = build_sampling_args(data[index][len(outputs)+1:], outputs)
		
	return ret

def transform_sampling_data(data):
	ret = OrderedDict()
	ret["initial"] = OrderedDict()
	ret["initial"]["inputs"] = build_arguments(data["inputs"])
	ret["initial"]["outputs"] = build_arguments(data["outputs"])
	ret["sampling"] = build_sampling(data["samples"], ret["initial"]["inputs"], ret["initial"]["outputs"])

	return ret

if len(sys.argv) != 3:
    print "[*] Syntax: <input file> <output file>"
    exit()

input_file_path = sys.argv[1]
output_file_path = sys.argv[2]

data = json.load(open(input_file_path), object_pairs_hook=OrderedDict)

open(output_file_path, "wb").write(to_json(transform_sampling_data(data)))

