import os
import unittest
from searcher.Vulnerability import Vulnerability
from searcher.Searcher import Searcher
import json

from static_analyzer import file_get_contents


class TestClass(unittest.TestCase):

    def getStr(self, list):
        toret = ""
        for x in list:
            toret += x + "\n"
        return toret

    def test_1(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/test1.json"))
        parsed_rules = json.loads(file_get_contents("rules.json"))
        output = open(os.getcwd() + "/tests/test1.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(self.getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_2(self):
        parsed_snippet = json.loads(file_get_contents("tests\\test2.json"))
        parsed_rules = json.loads(file_get_contents("rules.json"))
        output = open("tests\\test2.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(self.getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_3(self):
        parsed_snippet = json.loads(file_get_contents("tests\\test3.json"))
        parsed_rules = json.loads(file_get_contents("rules.json"))
        output = open("tests\\test3.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(self.getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_4(self):
        parsed_snippet = json.loads(file_get_contents("tests\\test4.json"))
        parsed_rules = json.loads(file_get_contents("rules.json"))
        output = open("tests\\test4.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(self.getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_5(self):
        parsed_snippet = json.loads(file_get_contents("tests\\test5.json"))
        parsed_rules = json.loads(file_get_contents("rules.json"))
        output = open("tests\\test5.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(self.getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_6(self):
        parsed_snippet = json.loads(file_get_contents("tests\\test6.json"))
        parsed_rules = json.loads(file_get_contents("rules.json"))
        output = open("tests\\test6.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(self.getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_7(self):
        parsed_snippet = json.loads(file_get_contents("tests\\test7.json"))
        parsed_rules = json.loads(file_get_contents("rules.json"))
        output = open("tests\\test7.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(self.getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_8(self):
        parsed_snippet = json.loads(file_get_contents("tests\\test8.json"))
        parsed_rules = json.loads(file_get_contents("rules.json"))
        output = open("tests\\test8.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(self.getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_9(self):
        parsed_snippet = json.loads(file_get_contents("tests\\test9.json"))
        parsed_rules = json.loads(file_get_contents("rules.json"))
        output = open("tests\\test9.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(self.getStr(s.output), output.read(), "Should be equal")
        output.close()

    def test_10(self):
        parsed_snippet = json.loads(file_get_contents("tests\\test10.json"))
        parsed_rules = json.loads(file_get_contents("rules.json"))
        output = open("tests\\test10.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(self.getStr(s.output), output.read(), "Should be equal")
        output.close()

if __name__ == '__main__':
    unittest.main()
