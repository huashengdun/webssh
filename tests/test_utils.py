import unittest

from webssh.utils import (is_valid_ipv4_address, is_valid_ipv6_address,
                          is_valid_port, to_str)


class TestUitls(unittest.TestCase):

    def test_to_str(self):
        b = b'hello'
        u = u'hello'
        self.assertEqual(to_str(b), u)
        self.assertEqual(to_str(u), u)

    def test_is_valid_ipv4_address(self):
        self.assertFalse(is_valid_ipv4_address('127.0.0'))
        self.assertFalse(is_valid_ipv4_address(b'127.0.0'))
        self.assertTrue(is_valid_ipv4_address('127.0.0.1'))
        self.assertTrue(is_valid_ipv4_address(b'127.0.0.1'))

    def test_is_valid_ipv6_address(self):
        self.assertFalse(is_valid_ipv6_address('abc'))
        self.assertFalse(is_valid_ipv6_address(b'abc'))
        self.assertTrue(is_valid_ipv6_address('::1'))
        self.assertTrue(is_valid_ipv6_address(b'::1'))

    def test_is_valid_port(self):
        self.assertTrue(is_valid_port(80))
        self.assertFalse(is_valid_port(0))
        self.assertFalse(is_valid_port(65536))
