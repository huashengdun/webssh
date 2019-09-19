import unittest

from webssh.utils import (
    is_valid_ip_address, is_valid_port, is_valid_hostname, to_str, to_bytes,
    to_int, is_ip_hostname, is_same_primary_domain, parse_origin_from_url
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
        self.assertTrue(is_valid_ip_address('fe80::1111:2222:3333:4444'))
        self.assertTrue(is_valid_ip_address(b'fe80::1111:2222:3333:4444'))
        self.assertTrue(is_valid_ip_address('fe80::1111:2222:3333:4444%eth0'))
        self.assertTrue(is_valid_ip_address(b'fe80::1111:2222:3333:4444%eth0'))

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

    def test_is_ip_hostname(self):
        self.assertTrue(is_ip_hostname('[::1]'))
        self.assertTrue(is_ip_hostname('127.0.0.1'))
        self.assertFalse(is_ip_hostname('localhost'))
        self.assertFalse(is_ip_hostname('www.google.com'))

    def test_is_same_primary_domain(self):
        domain1 = 'localhost'
        domain2 = 'localhost'
        self.assertTrue(is_same_primary_domain(domain1, domain2))

        domain1 = 'localhost'
        domain2 = 'test'
        self.assertFalse(is_same_primary_domain(domain1, domain2))

        domain1 = 'com'
        domain2 = 'example.com'
        self.assertFalse(is_same_primary_domain(domain1, domain2))

        domain1 = 'example.com'
        domain2 = 'example.com'
        self.assertTrue(is_same_primary_domain(domain1, domain2))

        domain1 = 'www.example.com'
        domain2 = 'example.com'
        self.assertTrue(is_same_primary_domain(domain1, domain2))

        domain1 = 'wwwexample.com'
        domain2 = 'example.com'
        self.assertFalse(is_same_primary_domain(domain1, domain2))

        domain1 = 'www.example.com'
        domain2 = 'www2.example.com'
        self.assertTrue(is_same_primary_domain(domain1, domain2))

        domain1 = 'xxx.www.example.com'
        domain2 = 'xxx.www2.example.com'
        self.assertTrue(is_same_primary_domain(domain1, domain2))

    def test_parse_origin_from_url(self):
        url = ''
        self.assertIsNone(parse_origin_from_url(url))

        url = 'www.example.com'
        self.assertEqual(parse_origin_from_url(url), 'http://www.example.com')

        url = 'http://www.example.com'
        self.assertEqual(parse_origin_from_url(url), 'http://www.example.com')

        url = 'www.example.com:80'
        self.assertEqual(parse_origin_from_url(url), 'http://www.example.com')

        url = 'http://www.example.com:80'
        self.assertEqual(parse_origin_from_url(url), 'http://www.example.com')

        url = 'www.example.com:443'
        self.assertEqual(parse_origin_from_url(url), 'https://www.example.com')

        url = 'https://www.example.com'
        self.assertEqual(parse_origin_from_url(url), 'https://www.example.com')

        url = 'https://www.example.com:443'
        self.assertEqual(parse_origin_from_url(url), 'https://www.example.com')

        url = 'https://www.example.com:80'
        self.assertEqual(parse_origin_from_url(url), url)

        url = 'http://www.example.com:443'
        self.assertEqual(parse_origin_from_url(url), url)
