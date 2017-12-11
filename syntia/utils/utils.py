import json


def to_json(data):
    """
    Dumps data to JSON
    :param data: nested dict
    :return: json dump
    """
    return json.dumps(data, sort_keys=False, indent=4)


def dump_to_json(file_path, data):
    """
    Dumps data into a JSON file
    :param file_path: file path
    :param data: nested dict
    """
    open(file_path, "wb").write(to_json(data))
