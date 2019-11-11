""" Program root """
import sys
import json

from testing import MyNode


def file_get_contents(filename):
    with open(filename) as f:
        return f.read()

def main(argv):
    parsed_snippet = file_get_contents(argv[0])
    parsed_rules = file_get_contents(argv[1])

    snippet = json.loads(parsed_snippet)
    rules = json.loads(parsed_rules)

    instructions = MyNode.MyNode.parse_instructions(snippet['body'])
    print(instructions)


if __name__ == "__main__":
    main(sys.argv[1:])
