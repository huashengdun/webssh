import unittest

from tornado.httputil import HTTPServerRequest
from handler import MixinHandler


class TestMixinHandler(unittest.TestCase):

    def test_get_real_client_addr(self):
        handler = MixinHandler()
        handler.request = HTTPServerRequest(uri='/')
        self.assertIsNone(handler.get_real_client_addr())

        ip = '127.0.0.1'
        handler.request.headers.add('X-Real-Ip', ip)
        self.assertEqual(handler.get_real_client_addr(), False)

        handler.request.headers.add('X-Real-Port', '12345x')
        self.assertEqual(handler.get_real_client_addr(), False)

        handler.request.headers.update({'X-Real-Port': '12345'})
        self.assertEqual(handler.get_real_client_addr(), (ip, 12345))

        handler.request.headers.update({'X-Real-ip': None})
        self.assertEqual(handler.get_real_client_addr(), False)

        handler.request.headers.update({'X-Real-Port': '12345x'})
        self.assertEqual(handler.get_real_client_addr(), False)
