""" Program root """
from cfg.ControlFlowGraph import ControlFlowGraph
import sys
import json


def file_get_contents(filename):
    with open(filename) as f:
        return f.read()


def main(argv):
    # TODO: Place the validations aand exception handlers on file reading
    # First parameter which is the code snippet in json format
    # Second parameter which are the vulnerability rules in json format
    parsed_snippet = file_get_contents(argv[0])
    parsed_rules = file_get_contents(argv[1])

    snippet = json.loads(parsed_snippet)
    rules = json.loads(parsed_rules)

    cfg = ControlFlowGraph(snippet['body'])

    # print(rules)


if __name__ == "__main__":
    main(sys.argv[1:])
