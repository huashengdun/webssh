import unittest
import sys

from tornado.httputil import HTTPServerRequest
from handler import MixinHandler


class TestMixinHandler(unittest.TestCase):

    def test_get_real_client_addr_without_nginx_config(self):
        handler = MixinHandler()
        handler.request = HTTPServerRequest(uri='/')
        self.assertIsNone(handler.get_real_client_addr())

    def test_get_real_client_addr_with_correct_nginx_config(self):
        handler = MixinHandler()
        handler.request = HTTPServerRequest(uri='/')

        ip = '127.0.0.1'
        handler.request.headers.add('X-Real-Ip', ip)
        handler.request.headers.add('X-Real-Port', '12345')
        self.assertEqual(handler.get_real_client_addr(), (ip, 12345))

    @unittest.skipIf(sys.version_info < (3,),
                     reason='assertLogs not supported in Python 2')
    def test_get_real_client_addr_with_bad_nginx_config(self):
        handler = MixinHandler()
        handler.request = HTTPServerRequest(uri='/')

        ip = '127.0.0.1'
        handler.request.headers.add('X-Real-Ip', ip)
        with self.assertLogs() as cm:
            handler.get_real_client_addr()
        self.assertEqual(cm.output, ['WARNING:root:Bad nginx configuration.'])

        handler.request.headers.add('X-Real-Port', '12345x')
        with self.assertLogs() as cm:
            handler.get_real_client_addr()
        self.assertEqual(cm.output, ['WARNING:root:Bad nginx configuration.'])
