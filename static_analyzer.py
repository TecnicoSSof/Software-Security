""" Program root """
import os

from searcher.Vulnerability import Vulnerability
from searcher.Searcher import Searcher
import sys
import json


def file_get_contents(filename):
    with open(filename) as f:
        return f.read()

def getStr(list):
    toret = ""
    for x in list:
        toret += x + "\n"
    return toret

def main(argv):
    # TODO: Place the validations and exception handlers on file reading
    # First parameter which is the code snippet in json format
    # Second parameter which are the vulnerability rules in json format

    parsed_snippet = json.loads(file_get_contents(argv[0]))
    parsed_rules = json.loads(file_get_contents(argv[1]))

    vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
    s = Searcher(parsed_snippet['body'], vulnerabilities)
    print(getStr(s.output))


if __name__ == "__main__":
    myCmd = 'astexport -i currentExample.py > specification.json'
    os.system(myCmd)
    main(sys.argv[1:])
