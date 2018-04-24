import os.path
import unittest
import paramiko
import tornado.options as options

from settings import get_host_keys_settings, get_policy_setting, base_dir
from policy import load_host_keys


class TestSettings(unittest.TestCase):

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

        options.hostFile = 'tests/known_hosts_example'
        options.sysHostFile = 'tests/known_hosts_example2'
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
