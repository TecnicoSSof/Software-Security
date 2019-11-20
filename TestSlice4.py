import os
import unittest
from searcher.Vulnerability import Vulnerability
from searcher.Searcher import Searcher, getStr
import json

from static_analyzer import file_get_contents


class TestSlice4(unittest.TestCase):

    def test_rules(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/slice4/slice4.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/slice4/rules.json"))
        output = open(os.getcwd() + "/tests/slice4/slice4_rules.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_rules2(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/slice4/slice4.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/slice4/rules2.json"))
        output = open(os.getcwd() + "/tests/slice4/slice4_rules2.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_rulesNoVuln(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/slice4/slice4.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/slice4/rulesNoVuln.json"))
        output = open(os.getcwd() + "/tests/slice4/slice4_rulesNoVuln.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

if __name__ == '__main__':
    unittest.main()
