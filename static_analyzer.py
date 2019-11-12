""" Program root """
import sys
import json


def file_get_contents(filename):
    with open(filename) as f:
        return f.read()

def main(argv):
    # TODO: Place the validations and exception handlers on file reading
    # First parameter which is the code snippet in json format
    # Second parameter which are the vulnerability rules in json format

    parsed_snippet = json.loads(file_get_contents(argv[0]))
    parsed_rules = json.loads(file_get_contents(argv[1]))

    instructions = analyze(parsed_snippet['body'])
    cfg = ControlFlowGraph(instructions)

    # print(rules)

if __name__ == "__main__":
    main(sys.argv[1:])
