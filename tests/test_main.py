import unittest

from tornado.web import Application
from webssh import handler
from webssh.main import app_listen


class TestMain(unittest.TestCase):

    def test_app_listen(self):
        app = Application()
        app.listen = lambda x, y, **kwargs: 1

        handler.redirecting = None
        server_settings = dict()
        app_listen(app, 80, '127.0.0.1', server_settings)
        self.assertFalse(handler.redirecting)

        handler.redirecting = None
        server_settings = dict(ssl_options='enabled')
        app_listen(app, 80, '127.0.0.1', server_settings)
        self.assertTrue(handler.redirecting)
