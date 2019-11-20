import os
import unittest
from searcher.Vulnerability import Vulnerability
from searcher.Searcher import Searcher, getStr
import json

from static_analyzer import file_get_contents


class TestClass(unittest.TestCase):

    def test_1(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/test1.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/rules.json"))
        output = open(os.getcwd() + "/tests/ourTests/test1.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_2(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/test2.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/rules.json"))
        output = open(os.getcwd() + "/tests/ourTests/test2.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_3(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/test3.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/rules.json"))
        output = open(os.getcwd() + "/tests/ourTests/test3.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_4(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/test4.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/rules.json"))
        output = open(os.getcwd() + "/tests/ourTests/test4.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_5(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/test5.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/rules.json"))
        output = open(os.getcwd() + "/tests/ourTests/test5.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_6(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/test6.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/rules.json"))
        output = open(os.getcwd() + "/tests/ourTests/test6.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_7(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/test7.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/rules.json"))
        output = open(os.getcwd() + "/tests/ourTests/test7.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_8(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/test8.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/rules.json"))
        output = open(os.getcwd() + "/tests/ourTests/test8.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_9(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/test9.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/rules.json"))
        output = open(os.getcwd() + "/tests/ourTests/test9.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_10(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/test10.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/ourTests/rules.json"))
        output = open(os.getcwd() + "/tests/ourTests/test10.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(getStr(s.output), output.read(), "Should be equal")
        output.close()

if __name__ == '__main__':
    unittest.main()
