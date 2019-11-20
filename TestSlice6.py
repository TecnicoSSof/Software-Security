import os
import unittest
from searcher.Vulnerability import Vulnerability
from searcher.Searcher import Searcher, getStr
import json

from static_analyzer import file_get_contents


class TestSlice6(unittest.TestCase):

    def test_rules(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/slice6/slice6.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/slice6/rules.json"))
        output = open(os.getcwd() + "/tests/slice6/slice6_rules.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_rules2(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/slice6/slice6.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/slice6/rules2.json"))
        output = open(os.getcwd() + "/tests/slice6/slice6_rules2.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_rules3(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/slice6/slice6.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/slice6/rules3.json"))
        output = open(os.getcwd() + "/tests/slice6/slice6_rules3.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_rulesNoVuln(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/slice6/slice6.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/slice6/rulesNoVuln.json"))
        output = open(os.getcwd() + "/tests/slice6/slice6_rulesNoVuln.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_rulesSanit(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/slice6/slice6.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/slice6/rulesSanit.json"))
        output = open(os.getcwd() + "/tests/slice6/slice6_rulesSanit.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

if __name__ == '__main__':
    unittest.main()
