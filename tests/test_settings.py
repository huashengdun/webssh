import io
import sys
import os.path
import unittest
import paramiko
import tornado.options as options

from tests.utils import make_tests_data_path
from webssh.policy import load_host_keys
from webssh.settings import (
    get_host_keys_settings, get_policy_setting, base_dir, print_version
)
from webssh.utils import UnicodeType
from webssh._version import __version__


class TestSettings(unittest.TestCase):

    def test_print_version(self):
        sys_stdout = sys.stdout
        sys.stdout = io.StringIO() if UnicodeType == str else io.BytesIO()

        self.assertEqual(print_version(False), None)
        self.assertEqual(sys.stdout.getvalue(), '')

        with self.assertRaises(SystemExit):
            self.assertEqual(print_version(True), None)
        self.assertEqual(sys.stdout.getvalue(), __version__ + '\n')

        sys.stdout = sys_stdout

    def test_get_host_keys_settings(self):
        options.hostFile = ''
        options.sysHostFile = ''
        dic = get_host_keys_settings(options)

        filename = os.path.join(base_dir, 'known_hosts')
        self.assertEqual(dic['host_keys'], load_host_keys(filename))
        self.assertEqual(dic['host_keys_filename'], filename)
        self.assertEqual(
            dic['system_host_keys'],
            load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
        )

        options.hostFile = make_tests_data_path('known_hosts_example')
        options.sysHostFile = make_tests_data_path('known_hosts_example2')
        dic2 = get_host_keys_settings(options)
        self.assertEqual(dic2['host_keys'], load_host_keys(options.hostFile))
        self.assertEqual(dic2['host_keys_filename'], options.hostFile)
        self.assertEqual(dic2['system_host_keys'],
                         load_host_keys(options.sysHostFile))

    def test_get_policy_setting(self):
        options.policy = 'warning'
        options.hostFile = ''
        options.sysHostFile = ''
        settings = get_host_keys_settings(options)
        instance = get_policy_setting(options, settings)
        self.assertIsInstance(instance, paramiko.client.WarningPolicy)

        options.policy = 'autoadd'
        options.hostFile = ''
        options.sysHostFile = ''
        settings = get_host_keys_settings(options)
        instance = get_policy_setting(options, settings)
        self.assertIsInstance(instance, paramiko.client.AutoAddPolicy)
        os.unlink(settings['host_keys_filename'])

        options.policy = 'reject'
        options.hostFile = ''
        options.sysHostFile = ''
        settings = get_host_keys_settings(options)
        try:
            instance = get_policy_setting(options, settings)
        except ValueError:
            self.assertFalse(
                settings['host_keys'] and settings['system_host_keys']
            )
        else:
            self.assertIsInstance(instance, paramiko.client.RejectPolicy)
