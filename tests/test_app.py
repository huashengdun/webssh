import json
import random
import threading
import tornado.websocket
import tornado.gen
import webssh.handler as handler

from tornado.testing import AsyncHTTPTestCase
from tornado.httpclient import HTTPError
from tornado.options import options
from tests.sshserver import run_ssh_server, banner
from tests.utils import encode_multipart_formdata, read_file, make_tests_data_path  # noqa
from webssh.main import make_app, make_handlers
from webssh.settings import get_app_settings, max_body_size
from webssh.utils import to_str

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode


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
        options.debug = False
        options.policy = random.choice(['warning', 'autoadd'])
        options.hostFile = ''
        options.sysHostFile = ''
        settings = get_app_settings(options)
        settings.update(xsrf_cookies=False)
        app = make_app(make_handlers(loop, options), settings)
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

    def test_app_with_invalid_form_for_missing_argument(self):
        response = self.fetch('/')
        self.assertEqual(response.code, 200)

        body = 'port=7000&username=admin&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertEqual(response.code, 400)
        self.assertIn(b'Missing argument hostname', response.body)

        body = 'hostname=127.0.0.1&username=admin&password'
        self.assertEqual(response.code, 400)
        response = self.fetch('/', method='POST', body=body)
        self.assertIn(b'Missing argument port', response.body)

        body = 'hostname=127.0.0.1&port=7000&password'
        self.assertEqual(response.code, 400)
        response = self.fetch('/', method='POST', body=body)
        self.assertIn(b'Missing argument username', response.body)

        body = 'hostname=&port=&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertEqual(response.code, 400)
        self.assertIn(b'Missing argument hostname', response.body)

        body = 'hostname=127.0.0.1&port=&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertEqual(response.code, 400)
        self.assertIn(b'Missing argument port', response.body)

        body = 'hostname=127.0.0.1&port=7000&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertEqual(response.code, 400)
        self.assertIn(b'Missing argument username', response.body)

    def test_app_with_invalid_form_for_invalid_value(self):
        body = 'hostname=127.0.0&port=22&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertIn(b'Invalid hostname', response.body)

        body = 'hostname=http://www.googe.com&port=22&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertEqual(response.code, 400)
        self.assertIn(b'Invalid hostname', response.body)

        body = 'hostname=127.0.0.1&port=port&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertEqual(response.code, 400)
        self.assertIn(b'Invalid port', response.body)

        body = 'hostname=127.0.0.1&port=70000&username=&password'
        response = self.fetch('/', method='POST', body=body)
        self.assertEqual(response.code, 400)
        self.assertIn(b'Invalid port', response.body)

    def test_app_with_wrong_hostname_ip(self):
        body = 'hostname=127.0.0.1&port=7000&username=admin'
        response = self.fetch('/', method='POST', body=body)
        self.assertEqual(response.code, 200)
        self.assertIn(b'Unable to connect to', response.body)

    def test_app_with_wrong_hostname_domain(self):
        body = 'hostname=xxxxxxxxxxxx&port=7000&username=admin'
        response = self.fetch('/', method='POST', body=body)
        self.assertEqual(response.code, 200)
        self.assertIn(b'Unable to connect to', response.body)

    def test_app_with_wrong_port(self):
        body = 'hostname=127.0.0.1&port=7000&username=admin'
        response = self.fetch('/', method='POST', body=body)
        self.assertEqual(response.code, 200)
        self.assertIn(b'Unable to connect to', response.body)

    def test_app_with_wrong_credentials(self):
        response = self.fetch('/')
        self.assertEqual(response.code, 200)
        response = self.fetch('/', method='POST', body=self.body + 's')
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['encoding'])
        self.assertIsNone(data['id'])
        self.assertIn('Authentication failed.', data['status'])

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
        self.assertEqual(ws.close_reason, 'Websocket authentication failed.')

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
    def test_app_with_correct_credentials_but_without_id_argument(self):
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
        ws_url = url + 'ws'
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIsNone(msg)
        self.assertIn('Missing argument id', ws.close_reason)

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_but_empty_id(self):
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
        ws_url = url + 'ws?id='
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIsNone(msg)
        self.assertIn('Missing argument id', ws.close_reason)

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_but_wrong_id(self):
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
        ws_url = url + 'ws?id=1' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIsNone(msg)
        self.assertIn('Websocket authentication failed', ws.close_reason)

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

    @tornado.testing.gen_test
    def test_app_auth_with_valid_pubkey_by_urlencoded_form(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        self.body_dict.update(privatekey=privatekey)
        body = urlencode(self.body_dict)
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
        ws.close()

    @tornado.testing.gen_test
    def test_app_auth_with_valid_pubkey_by_multipart_form(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        privatekey = read_file(make_tests_data_path('user_rsa_key'))
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
        with self.assertRaises(HTTPError) as ctx:
            yield client.fetch(url, method='POST', headers=headers, body=body)
        self.assertEqual(ctx.exception.code, 400)
        self.assertIn('Invalid private key', ctx.exception.message)

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
        with self.assertRaises(HTTPError) as ctx:
            yield client.fetch(url, method='POST', headers=headers, body=body)
        self.assertEqual(ctx.exception.code, 400)
        self.assertIn('Invalid private key', ctx.exception.message)

    @tornado.testing.gen_test
    def test_app_auth_with_pubkey_cannot_be_decoded_by_multipart_form(self):
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
        with self.assertRaises(HTTPError) as ctx:
            yield client.fetch(url, method='POST', headers=headers, body=body)
        self.assertEqual(ctx.exception.code, 400)
        self.assertIn('Invalid unicode', ctx.exception.message)

    @tornado.testing.gen_test
    def test_app_post_form_with_large_body_size_by_multipart_form(self):
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

        with self.assertRaises(HTTPError) as ctx:
            yield client.fetch(url, method='POST', headers=headers, body=body)
        self.assertEqual(ctx.exception.code, 400)
        self.assertIn('Bad Request', ctx.exception.message)

    @tornado.testing.gen_test
    def test_app_post_form_with_large_body_size_by_urlencoded_form(self):
        url = self.get_url('/')
        client = self.get_http_client()
        response = yield client.fetch(url)
        self.assertEqual(response.code, 200)

        privatekey = 'h' * (2 * max_body_size)
        body = self.body + '&privatekey=' + privatekey
        with self.assertRaises(HTTPError) as ctx:
            yield client.fetch(url, method='POST', body=body)
        self.assertEqual(ctx.exception.code, 400)
        self.assertIn('Bad Request', ctx.exception.message)
