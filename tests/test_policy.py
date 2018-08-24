import os
import unittest
import paramiko

from shutil import copyfile
from paramiko.client import RejectPolicy, WarningPolicy
from tests.utils import make_tests_data_path
from webssh.policy import (
    AutoAddPolicy, get_policy_dictionary, load_host_keys,
    get_policy_class, check_policy_setting
)


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

        path = make_tests_data_path('known_hosts_example')
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
        host_keys_filename = make_tests_data_path('host_keys_test.db')
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

    def test_is_missing_host_key(self):
        client = paramiko.SSHClient()
        file1 = make_tests_data_path('known_hosts_example')
        file2 = make_tests_data_path('known_hosts_example2')
        client.load_host_keys(file1)
        client.load_system_host_keys(file2)

        autoadd = AutoAddPolicy()
        for f in [file1, file2]:
            entry = paramiko.hostkeys.HostKeys(f)._entries[0]
            hostname = entry.hostnames[0]
            key = entry.key
            self.assertIsNone(
                autoadd.is_missing_host_key(client, hostname, key)
            )

        for f in [file1, file2]:
            entry = paramiko.hostkeys.HostKeys(f)._entries[0]
            hostname = entry.hostnames[0][1:]
            key = entry.key
            self.assertTrue(
                autoadd.is_missing_host_key(client, hostname, key)
            )

        file3 = make_tests_data_path('known_hosts_example3')
        entry = paramiko.hostkeys.HostKeys(file3)._entries[0]
        hostname = entry.hostnames[0]
        key = entry.key
        with self.assertRaises(paramiko.BadHostKeyException):
            autoadd.is_missing_host_key(client, hostname, key)

    def test_missing_host_key(self):
        client = paramiko.SSHClient()
        file1 = make_tests_data_path('known_hosts_example')
        file2 = make_tests_data_path('known_hosts_example2')
        filename = make_tests_data_path('known_hosts')
        copyfile(file1, filename)
        client.load_host_keys(filename)
        n1 = len(client._host_keys)

        autoadd = AutoAddPolicy()
        entry = paramiko.hostkeys.HostKeys(file2)._entries[0]
        hostname = entry.hostnames[0]
        key = entry.key
        autoadd.missing_host_key(client, hostname, key)
        self.assertEqual(len(client._host_keys),  n1 + 1)
        self.assertEqual(paramiko.hostkeys.HostKeys(filename),
                         client._host_keys)
        os.unlink(filename)
