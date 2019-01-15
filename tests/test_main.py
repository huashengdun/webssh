import unittest

from tornado.web import Application
from webssh import handler
from webssh.main import app_listen


class TestMain(unittest.TestCase):

    def test_app_listen(self):
        app = Application()
        app.listen = lambda x, y, **kwargs: 1

        handler.https_server_enabled = False
        server_settings = dict()
        app_listen(app, 80, '127.0.0.1', server_settings)
        self.assertFalse(handler.https_server_enabled)

        handler.https_server_enabled = False
        server_settings = dict(ssl_options='enabled')
        app_listen(app, 80, '127.0.0.1', server_settings)
        self.assertTrue(handler.https_server_enabled)
