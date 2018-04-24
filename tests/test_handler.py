import unittest
import sys

from handler import MixinHandler


class RequestMock(object):

    def __init__(self):
        self.headers = {}

    def set_ip(self, ip):
        self.headers['X-Real-Ip'] = ip

    def set_port(self, port):
        self.headers['X-Real-Port'] = port


class TestMixinHandler(unittest.TestCase):

    def test_get_real_client_addr_without_nginx_config(self):
        handler = MixinHandler()
        handler.request = RequestMock()
        self.assertIsNone(handler.get_real_client_addr())

    def test_get_real_client_addr_with_correct_nginx_config(self):
        handler = MixinHandler()
        handler.request = RequestMock()

        ip = '127.0.0.1'
        handler.request.set_ip(ip)
        handler.request.set_port('12345')
        self.assertEqual(handler.get_real_client_addr(), (ip, 12345))

    @unittest.skipIf(sys.version_info < (3,),
                     reason='assertLogs not supported in Python 2')
    def test_get_real_client_addr_with_bad_nginx_config(self):
        handler = MixinHandler()
        handler.request = RequestMock()

        ip = '127.0.0.1'
        handler.request.set_ip(ip)
        with self.assertLogs() as cm:
            handler.get_real_client_addr()
        self.assertEqual(cm.output, ['WARNING:root:Bad nginx configuration.'])

        handler.request.set_port('12345x')
        with self.assertLogs() as cm:
            handler.get_real_client_addr()
        self.assertEqual(cm.output, ['WARNING:root:Bad nginx configuration.'])
