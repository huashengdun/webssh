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
from tests.sshserver import run_ssh_server, banner


handler.DELAY = 0.1


class TestApp(AsyncHTTPTestCase):

    _is_running = False
    sshserver_port = 2200
    body = u'hostname=127.0.0.1&port={}&username=robey&password=foo'.format(sshserver_port) # noqa

    def get_app(self):
        loop = self.io_loop
        options.debug = True
        options.policy = random.choice(['warning', 'autoadd'])
        options.hostFile = ''
        options.sysHostFile = ''
        app = make_app(make_handlers(loop, options), get_app_settings(options))
        return app

    @classmethod
    def setUpClass(cls):
        t = threading.Thread(
            target=run_ssh_server, args=(cls.sshserver_port, cls)
        )
        t.setDaemon(True)
        t.start()

    @classmethod
    def tearDownClass(cls):
        cls._is_running = True

    @classmethod
    def __bool__(cls):
        return cls._is_running

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
        response = self.fetch('/', method="POST", body=self.body + u's')
        self.assertIn(b'Authentication failed.', response.body)

    def test_app_with_correct_credentials(self):
        response = self.fetch('/')
        self.assertEqual(response.code, 200)
        response = self.fetch('/', method="POST", body=self.body)
        data = json.loads(response.body.decode('utf-8'))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])
        self.assertIsNotNone(data['encoding'])

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_timeout(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        response = yield client.fetch(url, method="POST", body=self.body)
        data = json.loads(response.body.decode('utf-8'))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])
        self.assertIsNotNone(data['encoding'])

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        yield tornado.gen.sleep(handler.DELAY + 0.1)
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIsNone(msg)
        ws.close()

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_user_robey(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        response = yield client.fetch(url, method="POST", body=self.body)
        data = json.loads(response.body.decode('utf-8'))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])
        self.assertIsNotNone(data['encoding'])

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertEqual(msg.decode(data['encoding']), banner)
        ws.close()

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_user_bar(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        body = self.body.replace('robey', 'bar')
        response = yield client.fetch(url, method="POST", body=body)
        data = json.loads(response.body.decode('utf-8'))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])
        self.assertIsNotNone(data['encoding'])

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertEqual(msg.decode(data['encoding']), banner)

        # messages below will be ignored silently
        yield ws.write_message('hello')
        yield ws.write_message('"hello"')
        yield ws.write_message('[hello]')
        yield ws.write_message(json.dumps({'resize': []}))
        yield ws.write_message(json.dumps({'resize': {}}))
        yield ws.write_message(json.dumps({'resize': 'ab'}))
        yield ws.write_message(json.dumps({'resize': ['a', 'b']}))
        yield ws.write_message(json.dumps({'resize': {'a': 1, 'b': 2}}))
        yield ws.write_message(json.dumps({'resize': [100]}))
        yield ws.write_message(json.dumps({'resize': [100]*10}))
        yield ws.write_message(json.dumps({'resize': [-1, -1]}))
        yield ws.write_message(json.dumps({'data': [1]}))
        yield ws.write_message(json.dumps({'data': (1,)}))
        yield ws.write_message(json.dumps({'data': {'a': 2}}))
        yield ws.write_message(json.dumps({'data': 1}))
        yield ws.write_message(json.dumps({'data': 2.1}))
        yield ws.write_message(json.dumps({'key-non-existed': 'hello'}))
        # end - those just for testing webssh websocket stablity

        yield ws.write_message(json.dumps({'resize': [79, 23]}))
        msg = yield ws.read_message()
        self.assertEqual(b'resized', msg)

        yield ws.write_message(json.dumps({'data': 'bye'}))
        msg = yield ws.read_message()
        self.assertEqual(b'bye', msg)
        ws.close()
