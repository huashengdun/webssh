import unittest

from webssh.utils import (
    is_valid_ip_address, is_valid_port, is_valid_hostname, to_str, to_bytes,
    to_int, on_public_network_interface, get_ips_by_name, is_ip_hostname,
    is_name_open_to_public
)


class TestUitls(unittest.TestCase):

    def test_to_str(self):
        b = b'hello'
        u = u'hello'
        self.assertEqual(to_str(b), u)
        self.assertEqual(to_str(u), u)

    def test_to_bytes(self):
        b = b'hello'
        u = u'hello'
        self.assertEqual(to_bytes(b), b)
        self.assertEqual(to_bytes(u), b)

    def test_to_int(self):
        self.assertEqual(to_int(''), None)
        self.assertEqual(to_int(None), None)
        self.assertEqual(to_int('22'), 22)
        self.assertEqual(to_int(' 22 '), 22)

    def test_is_valid_ip_address(self):
        self.assertFalse(is_valid_ip_address('127.0.0'))
        self.assertFalse(is_valid_ip_address(b'127.0.0'))
        self.assertTrue(is_valid_ip_address('127.0.0.1'))
        self.assertTrue(is_valid_ip_address(b'127.0.0.1'))
        self.assertFalse(is_valid_ip_address('abc'))
        self.assertFalse(is_valid_ip_address(b'abc'))
        self.assertTrue(is_valid_ip_address('::1'))
        self.assertTrue(is_valid_ip_address(b'::1'))

    def test_is_valid_port(self):
        self.assertTrue(is_valid_port(80))
        self.assertFalse(is_valid_port(0))
        self.assertFalse(is_valid_port(65536))

    def test_is_valid_hostname(self):
        self.assertTrue(is_valid_hostname('google.com'))
        self.assertTrue(is_valid_hostname('google.com.'))
        self.assertTrue(is_valid_hostname('www.google.com'))
        self.assertTrue(is_valid_hostname('www.google.com.'))
        self.assertFalse(is_valid_hostname('.www.google.com'))
        self.assertFalse(is_valid_hostname('http://www.google.com'))
        self.assertFalse(is_valid_hostname('https://www.google.com'))
        self.assertFalse(is_valid_hostname('127.0.0.1'))
        self.assertFalse(is_valid_hostname('::1'))

    def test_get_ips_by_name(self):
        self.assertTrue(get_ips_by_name(''), {'0.0.0.0', '::'})
        self.assertTrue(get_ips_by_name('localhost'), {'127.0.0.1'})
        self.assertTrue(get_ips_by_name('192.68.1.1'), {'192.168.1.1'})
        self.assertTrue(get_ips_by_name('2.2.2.2'), {'2.2.2.2'})

    def test_on_public_network_interface(self):
        self.assertTrue(on_public_network_interface('0.0.0.0'))
        self.assertTrue(on_public_network_interface('::'))
        self.assertTrue(on_public_network_interface('0:0:0:0:0:0:0:0'))
        self.assertTrue(on_public_network_interface('2.2.2.2'))
        self.assertTrue(on_public_network_interface('2:2:2:2:2:2:2:2'))
        self.assertIsNone(on_public_network_interface('127.0.0.1'))

    def test_is_name_open_to_public(self):
        self.assertTrue(is_name_open_to_public('0.0.0.0'))
        self.assertTrue(is_name_open_to_public('::'))
        self.assertIsNone(is_name_open_to_public('192.168.1.1'))
        self.assertIsNone(is_name_open_to_public('127.0.0.1'))
        self.assertIsNone(is_name_open_to_public('localhost'))

    def test_is_ip_hostname(self):
        self.assertTrue(is_ip_hostname('[::1]'))
        self.assertTrue(is_ip_hostname('127.0.0.1'))
        self.assertFalse(is_ip_hostname('localhost'))
        self.assertFalse(is_ip_hostname('www.google.com'))
