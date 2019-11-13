""" Program root """
from searcher.Vulnerability import Vulnerability
from searcher.Searcher import Searcher
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

    vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
    instructions = Searcher(parsed_snippet['body'], vulnerabilities)

    for i in vulnerabilities:
        print(i.variables)


if __name__ == "__main__":
    main(sys.argv[1:])
