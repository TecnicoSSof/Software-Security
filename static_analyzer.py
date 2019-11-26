""" Program root """
import os

from searcher.Vulnerability import Vulnerability
from searcher.Searcher import Searcher
import sys
import json


def file_get_contents(filename):
    with open(filename) as f:
        return f.read()


def main(argv):
    parsed_snippet = json.loads(file_get_contents(argv[0]))
    parsed_rules = json.loads(file_get_contents(argv[1]))

    vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
    s = Searcher(parsed_snippet['body'], vulnerabilities)
    print(s.get_vulnerabilities_str())


if __name__ == "__main__":
    myCmd = 'astexport -i currentExample.py > specification.json'
    os.system(myCmd)
    main(sys.argv[1:])
