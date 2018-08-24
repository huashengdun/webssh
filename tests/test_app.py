import json
import os.path
import random
import threading
import tornado.websocket
import tornado.gen
import webssh.handler as handler

from tornado.testing import AsyncHTTPTestCase
from tornado.httpclient import HTTPError
from tornado.options import options
from tests.sshserver import run_ssh_server, banner
from tests.utils import encode_multipart_formdata, read_file
from webssh.main import make_app, make_handlers
from webssh.settings import get_app_settings, max_body_size, base_dir
from webssh.utils import to_str


handler.DELAY = 0.1


class TestApp(AsyncHTTPTestCase):

    running = [True]
    sshserver_port = 2200
    body = 'hostname=127.0.0.1&port={}&username=robey&password=foo'.format(sshserver_port) # noqa
    body_dict = {
        'hostname': '127.0.0.1',
        'port': str(sshserver_port),
        'username': 'robey',
        'password': ''
    }

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
        print('='*20)
        t = threading.Thread(
            target=run_ssh_server, args=(cls.sshserver_port, cls.running)
        )
        t.setDaemon(True)
        t.start()

    @classmethod
    def tearDownClass(cls):
        cls.running.pop()
        print('='*20)

    def get_httpserver_options(self):
        options = super(TestApp, self).get_httpserver_options()
        options.update(max_body_size=max_body_size)
        return options

    def test_app_with_invalid_form(self):
        response = self.fetch('/')
        self.assertEqual(response.code, 200)
        body = 'hostname=&port=&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertIn(b'The hostname field is required', response.body)

        body = 'hostname=127.0.0.1&port=&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertIn(b'The port field is required', response.body)

        body = 'hostname=127.0.0&port=22&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertIn(b'Invalid hostname', response.body)

        body = 'hostname=http://www.googe.com&port=22&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertIn(b'Invalid hostname', response.body)

        body = 'hostname=127.0.0.1&port=port&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertIn(b'Invalid port', response.body)

        body = 'hostname=127.0.0.1&port=70000&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertIn(b'Invalid port', response.body)

        body = 'hostname=127.0.0.1&port=7000&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertIn(b'The username field is required', response.body) # noqa

    def test_app_with_wrong_credentials(self):
        response = self.fetch('/')
        self.assertEqual(response.code, 200)
        response = self.fetch('/', method='POST', body=self.body + 's')
        self.assertIn(b'Authentication failed.', response.body)

    def test_app_with_correct_credentials(self):
        response = self.fetch('/')
        self.assertEqual(response.code, 200)
        response = self.fetch('/', method='POST', body=self.body)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])
        self.assertIsNotNone(data['encoding'])

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_timeout(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        response = yield client.fetch(url, method='POST', body=self.body)
        data = json.loads(to_str(response.body))
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
    def test_app_auth_with_valid_pubkey_for_user_robey(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        privatekey = read_file(os.path.join(base_dir, 'tests', 'user_rsa_key'))
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }
        response = yield client.fetch(url, method='POST', headers=headers,
                                      body=body)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])
        self.assertIsNotNone(data['encoding'])

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertEqual(to_str(msg, data['encoding']), banner)
        ws.close()

    @tornado.testing.gen_test
    def test_app_auth_with_invalid_pubkey_for_user_robey(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        privatekey = 'h' * 1024
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }
        response = yield client.fetch(url, method='POST', headers=headers,
                                      body=body)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['id'])
        self.assertIsNone(data['encoding'])
        self.assertTrue(data['status'].startswith('Invalid private key'))

    @tornado.testing.gen_test
    def test_app_auth_with_pubkey_exceeds_key_max_size(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        privatekey = 'h' * (handler.KEY_MAX_SIZE * 2)
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }
        response = yield client.fetch(url, method='POST', headers=headers,
                                      body=body)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['id'])
        self.assertIsNone(data['encoding'])
        self.assertTrue(data['status'].startswith('Invalid private key'))

    @tornado.testing.gen_test
    def test_app_auth_with_pubkey_cannot_be_decoded(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        privatekey = 'h' * 1024
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        body = body.encode('utf-8')
        # added some gbk bytes to the privatekey, make it cannot be decoded
        body = body[:-100] + b'\xb4\xed\xce\xf3' + body[-100:]
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }

        response = yield client.fetch(url, method='POST', headers=headers,
                                      body=body)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['id'])
        self.assertIsNone(data['encoding'])
        self.assertIn('Bad Request (Invalid unicode', data['status'])

    @tornado.testing.gen_test
    def test_app_post_form_with_large_body_size(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        privatekey = 'h' * (2 * max_body_size)
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }

        with self.assertRaises(HTTPError):
            yield client.fetch(url, method='POST', headers=headers, body=body)

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_user_robey(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        response = yield client.fetch(url, method='POST', body=self.body)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])
        self.assertIsNotNone(data['encoding'])

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertEqual(to_str(msg, data['encoding']), banner)
        ws.close()

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_user_bar(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        body = self.body.replace('robey', 'bar')
        response = yield client.fetch(url, method='POST', body=body)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])
        self.assertIsNotNone(data['encoding'])

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertEqual(to_str(msg, data['encoding']), banner)

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
