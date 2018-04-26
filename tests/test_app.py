import json
import webssh.handler as handler
import random
import threading
import tornado.websocket
import tornado.gen

from tornado.testing import AsyncHTTPTestCase
from tornado.options import options
from webssh.main import make_app, make_handlers
from webssh.settings import get_app_settings
from tests.sshserver import run_ssh_server


handler.DELAY = 0.1


class TestApp(AsyncHTTPTestCase):

    _tear_down = False

    def get_app(self):
        loop = self.io_loop
        self._tear_down = False
        options.debug = True
        options.policy = random.choice(['warning', 'autoadd'])
        options.hostFile = ''
        options.sysHostFile = ''
        app = make_app(make_handlers(loop, options), get_app_settings(options))
        return app

    @classmethod
    def tearDownClass(cls):
        cls._tear_down = True

    def test_app_with_invalid_form(self):
        response = self.fetch('/')
        self.assertEqual(response.code, 200)
        body = u'hostname=&port=&username=&password'
        response = self.fetch('/', method="POST", body=body)
        self.assertIn(b'"status": "Empty hostname"', response.body)

        body = u'hostname=127.0.0.1&port=&username=&password'
        response = self.fetch('/', method="POST", body=body)
        self.assertIn(b'"status": "Empty port"', response.body)

        body = u'hostname=127.0.0.1&port=port&username=&password'
        response = self.fetch('/', method="POST", body=body)
        self.assertIn(b'"status": "Invalid port', response.body)

        body = u'hostname=127.0.0.1&port=70000&username=&password'
        response = self.fetch('/', method="POST", body=body)
        self.assertIn(b'"status": "Invalid port', response.body)

        body = u'hostname=127.0.0.1&port=7000&username=&password'
        response = self.fetch('/', method="POST", body=body)
        self.assertIn(b'"status": "Empty username"', response.body)

    def test_app_with_wrong_credentials(self):
        response = self.fetch('/')
        self.assertEqual(response.code, 200)
        body = u'hostname=127.0.0.1&port=2200&username=robey&password=foos'
        response = self.fetch('/', method="POST", body=body)
        self.assertIn(b'Authentication failed.', response.body)

    def test_app_with_correct_credentials(self):
        response = self.fetch('/')
        self.assertEqual(response.code, 200)
        body = u'hostname=127.0.0.1&port=2200&username=robey&password=foo'
        response = self.fetch('/', method="POST", body=body)
        worker_id = json.loads(response.body.decode('utf-8'))['id']
        self.assertIsNotNone(worker_id)

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_timeout(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        body = u'hostname=127.0.0.1&port=2200&username=robey&password=foo'
        response = yield client.fetch(url, method="POST", body=body)
        worker_id = json.loads(response.body.decode('utf-8'))['id']
        self.assertIsNotNone(worker_id)

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + worker_id
        yield tornado.gen.sleep(handler.DELAY + 0.1)
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIsNone(msg)
        ws.close()

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_welcome(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        body = u'hostname=127.0.0.1&port=2200&username=robey&password=foo'
        response = yield client.fetch(url, method="POST", body=body)
        worker_id = json.loads(response.body.decode('utf-8'))['id']
        self.assertIsNotNone(worker_id)

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + worker_id
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIn('Welcome!', msg)
        ws.close()


t = threading.Thread(target=run_ssh_server, args=(TestApp,))
t.setDaemon(True)
t.start()
