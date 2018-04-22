import unittest
from paramiko.client import RejectPolicy, WarningPolicy
from webssh.policy import AutoAddPolicy, get_policy_dictionary


class TestPolicy(unittest.TestCase):

    def test_get_policy_dictionary(self):
        classes = [AutoAddPolicy, RejectPolicy, WarningPolicy]
        dic = get_policy_dictionary()
        for cls in classes:
            val = dic[cls.__name__.lower()]
            self.assertIs(cls, val)
