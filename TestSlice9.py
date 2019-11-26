import os
import unittest
from searcher.Vulnerability import Vulnerability
from searcher.Searcher import Searcher
import json

from static_analyzer import file_get_contents


class TestSlice9(unittest.TestCase):

    def test_rules(self):
        parsed_snippet = json.loads(file_get_contents(os.getcwd() + "/tests/slice9/slice9.json"))
        parsed_rules = json.loads(file_get_contents(os.getcwd() + "/tests/slice9/rules.json"))
        output = open(os.getcwd() + "/tests/slice9/slice9_rules.out", "r")
        vulnerabilities = Vulnerability.build_vulnerabilities(parsed_rules)
        s = Searcher(parsed_snippet['body'], vulnerabilities)
        self.assertEqual(s.get_vulnerabilities_str(), output.read(), "Should be equal")
        output.close()


if __name__ == '__main__':
    unittest.main()
