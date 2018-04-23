import os
import unittest
import paramiko

from paramiko.client import RejectPolicy, WarningPolicy
from policy import (AutoAddPolicy, get_policy_dictionary, load_host_keys,
                    get_policy_class, check_policy_setting)


class TestPolicy(unittest.TestCase):

    def test_get_policy_dictionary(self):
        classes = [AutoAddPolicy, RejectPolicy, WarningPolicy]
        dic = get_policy_dictionary()
        for cls in classes:
            val = dic[cls.__name__.lower()]
            self.assertIs(cls, val)

    def test_load_host_keys(self):
        path = '/path-not-exists'
        host_keys = load_host_keys(path)
        self.assertFalse(host_keys)

        path = '/tmp'
        host_keys = load_host_keys(path)
        self.assertFalse(host_keys)

        path = 'tests/known_hosts_example'
        host_keys = load_host_keys(path)
        self.assertEqual(host_keys, paramiko.hostkeys.HostKeys(path))

    def test_get_policy_class(self):
        keys = ['autoadd', 'reject', 'warning']
        vals = [AutoAddPolicy, RejectPolicy, WarningPolicy]
        for key, val in zip(keys, vals):
            cls = get_policy_class(key)
            self.assertIs(cls, val)

        key = 'non-exists'
        with self.assertRaises(ValueError):
            get_policy_class(key)

    def test_check_policy_setting(self):
        host_keys_filename = './tests/host_keys_test.db'
        host_keys_settings = dict(
            host_keys=paramiko.hostkeys.HostKeys(),
            system_host_keys=paramiko.hostkeys.HostKeys(),
            host_keys_filename=host_keys_filename
        )

        with self.assertRaises(ValueError):
            check_policy_setting(RejectPolicy, host_keys_settings)

        try:
            os.unlink(host_keys_filename)
        except OSError:
            pass
        check_policy_setting(AutoAddPolicy, host_keys_settings)
        self.assertEqual(os.path.exists(host_keys_filename), True)
