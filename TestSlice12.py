import os
import unittest
from searcher.Vulnerability import Vulnerability
from searcher.Searcher import Searcher
import json

from static_analyzer import file_get_contents


class TestSlice12(unittest.TestCase):

    def test_noTuple_rules(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/slice12/slice12_noTuple.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/slice12/rules.json"))
        output = open(os.getcwd() + "/tests/slice12/slice12_noTuple_rules.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(s.get_vulnerabilities_str(), output.read(), "Should be equal")
        output.close()

    def test_rules(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/slice12/slice12.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/slice12/rules.json"))
        output = open(os.getcwd() + "/tests/slice12/slice12_rules.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(s.get_vulnerabilities_str(), output.read(), "Should be equal")
        output.close()


if __name__ == '__main__':
    unittest.main()
