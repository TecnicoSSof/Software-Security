import os
import unittest
from searcher.Vulnerability import Vulnerability
from searcher.Searcher import Searcher, getStr
import json

from static_analyzer import file_get_contents


class TestSlice11(unittest.TestCase):

    def test_rules(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/slice11/slice11.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/slice11/rules.json"))
        output = open(os.getcwd() + "/tests/slice11/slice11_rules.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_rules2(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/slice11/slice11.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/slice11/rules2.json"))
        output = open(os.getcwd() + "/tests/slice11/slice11_rules2.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()


if __name__ == '__main__':
    unittest.main()
