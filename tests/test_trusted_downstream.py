import unittest

from tornado.options import options

from webssh.main import http_server_arguments


class TestStartWebServer(unittest.TestCase):
    def test_parsing_of_trusted_downstream(self):
        options.trusted_downstream = "172.17.0.1,127.0.0.1"

        http_server_kwargs = http_server_arguments()
        self.assertEqual(http_server_kwargs["trusted_downstream"],
                         ['172.17.0.1', '127.0.0.1'])

    def test_parsing_of_empty_trusted_downstream(self):
        options.trusted_downstream = ""
        http_server_kwargs = http_server_arguments()
        self.assertNotIn("trusted_downstream", http_server_kwargs.keys())

    def test_parsing_of_none_trusted_downstream(self):
        options.trusted_downstream = None
        http_server_kwargs = http_server_arguments()
        self.assertNotIn("trusted_downstream", http_server_kwargs.keys())
