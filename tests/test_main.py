import unittest

from tornado.web import Application
from webssh.handler import open_to_public
from webssh.main import app_listen


class TestMain(unittest.TestCase):

    def test_app_listen(self):
        app = Application()
        app.listen = lambda x, y, **kwargs: 1
        open_to_public['https'] = None
        open_to_public['http'] = None

        server_settings = dict(ssl_options=False)
        app_listen(app, 80, '127.0.0.1', server_settings)
        self.assertEqual(open_to_public['http'], False)
        self.assertIsNone(open_to_public['https'])
        open_to_public['http'] = None

        server_settings = dict(ssl_options=False)
        app_listen(app, 80, '0.0.0.0', server_settings)
        self.assertEqual(open_to_public['http'], True)
        self.assertIsNone(open_to_public['https'])
        open_to_public['http'] = None

        server_settings = dict(ssl_options=True)
        app_listen(app, 443, '127.0.0.1', server_settings)
        self.assertEqual(open_to_public['https'], False)
        self.assertIsNone(open_to_public['http'])
        open_to_public['https'] = None

        server_settings = dict(ssl_options=True)
        app_listen(app, 443, '0.0.0.0', server_settings)
        self.assertEqual(open_to_public['https'], True)
        self.assertIsNone(open_to_public['http'])
        open_to_public['https'] = None

        server_settings = dict(ssl_options=False)
        app_listen(app, 80, '0.0.0.0', server_settings)
        server_settings = dict(ssl_options=True)
        app_listen(app, 443, '0.0.0.0', server_settings)
        self.assertEqual(open_to_public['https'], True)
        self.assertEqual(open_to_public['http'], True)
