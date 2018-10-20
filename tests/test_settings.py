import io
import ssl
import sys
import os.path
import unittest
import paramiko
import tornado.options as options

from tests.utils import make_tests_data_path
from webssh.policy import load_host_keys
from webssh.settings import (
    get_host_keys_settings, get_policy_setting, base_dir, print_version,
    get_ssl_context, get_trusted_downstream
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
        options.hostfile = ''
        options.syshostfile = ''
        dic = get_host_keys_settings(options)

        filename = os.path.join(base_dir, 'known_hosts')
        self.assertEqual(dic['host_keys'], load_host_keys(filename))
        self.assertEqual(dic['host_keys_filename'], filename)
        self.assertEqual(
            dic['system_host_keys'],
            load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
        )

        options.hostfile = make_tests_data_path('known_hosts_example')
        options.syshostfile = make_tests_data_path('known_hosts_example2')
        dic2 = get_host_keys_settings(options)
        self.assertEqual(dic2['host_keys'], load_host_keys(options.hostfile))
        self.assertEqual(dic2['host_keys_filename'], options.hostfile)
        self.assertEqual(dic2['system_host_keys'],
                         load_host_keys(options.syshostfile))

    def test_get_policy_setting(self):
        options.policy = 'warning'
        options.hostfile = ''
        options.syshostfile = ''
        settings = get_host_keys_settings(options)
        instance = get_policy_setting(options, settings)
        self.assertIsInstance(instance, paramiko.client.WarningPolicy)

        options.policy = 'autoadd'
        options.hostfile = ''
        options.syshostfile = ''
        settings = get_host_keys_settings(options)
        instance = get_policy_setting(options, settings)
        self.assertIsInstance(instance, paramiko.client.AutoAddPolicy)
        os.unlink(settings['host_keys_filename'])

        options.policy = 'reject'
        options.hostfile = ''
        options.syshostfile = ''
        settings = get_host_keys_settings(options)
        try:
            instance = get_policy_setting(options, settings)
        except ValueError:
            self.assertFalse(
                settings['host_keys'] and settings['system_host_keys']
            )
        else:
            self.assertIsInstance(instance, paramiko.client.RejectPolicy)

    def test_get_ssl_context(self):
        options.certfile = ''
        options.keyfile = ''
        ssl_ctx = get_ssl_context(options)
        self.assertIsNone(ssl_ctx)

        options.certfile = 'provided'
        options.keyfile = ''
        with self.assertRaises(ValueError) as ctx:
            ssl_ctx = get_ssl_context(options)
        self.assertEqual('keyfile is not provided', str(ctx.exception))

        options.certfile = ''
        options.keyfile = 'provided'
        with self.assertRaises(ValueError) as ctx:
            ssl_ctx = get_ssl_context(options)
        self.assertEqual('certfile is not provided', str(ctx.exception))

        options.certfile = 'FileDoesNotExist'
        options.keyfile = make_tests_data_path('cert.key')
        with self.assertRaises(ValueError) as ctx:
            ssl_ctx = get_ssl_context(options)
        self.assertIn('does not exist', str(ctx.exception))

        options.certfile = make_tests_data_path('cert.key')
        options.keyfile = 'FileDoesNotExist'
        with self.assertRaises(ValueError) as ctx:
            ssl_ctx = get_ssl_context(options)
        self.assertIn('does not exist', str(ctx.exception))

        options.certfile = make_tests_data_path('cert.key')
        options.keyfile = make_tests_data_path('cert.key')
        with self.assertRaises(ssl.SSLError) as ctx:
            ssl_ctx = get_ssl_context(options)

        options.certfile = make_tests_data_path('cert.crt')
        options.keyfile = make_tests_data_path('cert.key')
        ssl_ctx = get_ssl_context(options)
        self.assertIsNotNone(ssl_ctx)

    def test_get_trusted_downstream(self):
        tdstream = ''
        result = set()
        self.assertEqual(get_trusted_downstream(tdstream), result)

        tdstream = '1.1.1.1, 2.2.2.2'
        result = set(['1.1.1.1', '2.2.2.2'])
        self.assertEqual(get_trusted_downstream(tdstream), result)

        tdstream = '1.1.1.1, 2.2.2.2, 2.2.2.2'
        result = set(['1.1.1.1', '2.2.2.2'])
        self.assertEqual(get_trusted_downstream(tdstream), result)

        tdstream = '1.1.1.1, 2.2.2.'
        with self.assertRaises(ValueError):
            get_trusted_downstream(tdstream)
