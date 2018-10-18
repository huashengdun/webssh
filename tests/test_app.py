import json
import random
import threading
import tornado.websocket
import tornado.gen

from tornado.testing import AsyncHTTPTestCase
from tornado.httpclient import HTTPError
from tornado.options import options
from tests.sshserver import run_ssh_server, banner
from tests.utils import encode_multipart_formdata, read_file, make_tests_data_path  # noqa
from webssh import handler
from webssh.main import make_app, make_handlers
from webssh.settings import (
    get_app_settings, get_server_settings, max_body_size
)
from webssh.utils import to_str

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode


handler.DELAY = 0.1
swallow_http_errors = handler.swallow_http_errors


class TestAppBasic(AsyncHTTPTestCase):

    running = [True]
    sshserver_port = 2200
    body = 'hostname=127.0.0.1&port={}&_xsrf=yummy&username=robey&password=foo'.format(sshserver_port) # noqa
    headers = {'Cookie': '_xsrf=yummy'}

    def get_app(self):
        self.body_dict = {
            'hostname': '127.0.0.1',
            'port': str(self.sshserver_port),
            'username': 'robey',
            'password': '',
            '_xsrf': 'yummy'
        }
        loop = self.io_loop
        options.debug = False
        options.policy = random.choice(['warning', 'autoadd'])
        options.hostfile = ''
        options.syshostfile = ''
        options.tdstream = ''
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
        return get_server_settings(options)

    def assert_response(self, bstr, response):
        if swallow_http_errors:
            self.assertEqual(response.code, 200)
            self.assertIn(bstr, response.body)
        else:
            self.assertEqual(response.code, 400)
            self.assertIn(b'Bad Request', response.body)

    def sync_post(self, body, headers={}, url='/', method='POST'):
        headers.update(self.headers)
        return self.fetch(url, method=method, body=body, headers=headers)

    def async_post(self, url, body, headers={}, method='POST'):
        client = self.get_http_client()
        headers.update(self.headers)
        return client.fetch(url, method=method, body=body, headers=headers)

    def test_app_with_invalid_form_for_missing_argument(self):
        response = self.fetch('/')
        self.assertEqual(response.code, 200)

        body = 'port=7000&username=admin&password&_xsrf=yummy'
        response = self.sync_post(body)
        self.assert_response(b'Missing argument hostname', response)

        body = 'hostname=127.0.0.1&port=7000&password&_xsrf=yummy'
        response = self.sync_post(body)
        self.assert_response(b'Missing argument username', response)

        body = 'hostname=&port=&username=&password&_xsrf=yummy'
        response = self.sync_post(body)
        self.assert_response(b'Missing value hostname', response)

        body = 'hostname=127.0.0.1&port=7000&username=&password&_xsrf=yummy'
        response = self.sync_post(body)
        self.assert_response(b'Missing value username', response)

    def test_app_with_invalid_form_for_invalid_value(self):
        body = 'hostname=127.0.0&port=22&username=&password&_xsrf=yummy'
        response = self.sync_post(body)
        self.assert_response(b'Invalid hostname', response)

        body = 'hostname=http://www.googe.com&port=22&username=&password&_xsrf=yummy'  # noqa
        response = self.sync_post(body)
        self.assert_response(b'Invalid hostname', response)

        body = 'hostname=127.0.0.1&port=port&username=&password&_xsrf=yummy'
        response = self.sync_post(body)
        self.assert_response(b'Invalid port', response)

        body = 'hostname=127.0.0.1&port=70000&username=&password&_xsrf=yummy'
        response = self.sync_post(body)
        self.assert_response(b'Invalid port', response)

    def test_app_with_wrong_hostname_ip(self):
        body = 'hostname=127.0.0.1&port=7000&username=admin&_xsrf=yummy'
        response = self.sync_post(body)
        self.assertEqual(response.code, 200)
        self.assertIn(b'Unable to connect to', response.body)

    def test_app_with_wrong_hostname_domain(self):
        body = 'hostname=xxxxxxxxxxxx&port=7000&username=admin&_xsrf=yummy'
        response = self.sync_post(body)
        self.assertEqual(response.code, 200)
        self.assertIn(b'Unable to connect to', response.body)

    def test_app_with_wrong_port(self):
        body = 'hostname=127.0.0.1&port=7000&username=admin&_xsrf=yummy'
        response = self.sync_post(body)
        self.assertEqual(response.code, 200)
        self.assertIn(b'Unable to connect to', response.body)

    def test_app_with_wrong_credentials(self):
        response = self.sync_post(self.body + 's')
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['encoding'])
        self.assertIsNone(data['id'])
        self.assertIn('Authentication failed.', data['status'])

    def test_app_with_correct_credentials(self):
        response = self.sync_post(self.body)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])
        self.assertIsNotNone(data['encoding'])

    def test_app_with_correct_credentials_but_with_no_port(self):
        default_port = handler.DEFAULT_PORT
        handler.DEFAULT_PORT = self.sshserver_port

        # with no port value
        body = self.body.replace(str(self.sshserver_port), '')
        response = self.sync_post(body)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])
        self.assertIsNotNone(data['encoding'])

        # with no port argument
        body = body.replace('port=&', '')
        response = self.sync_post(body)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])
        self.assertIsNotNone(data['encoding'])

        handler.DEFAULT_PORT = default_port

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_timeout(self):
        url = self.get_url('/')
        response = yield self.async_post(url, self.body)
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
        response = yield self.async_post(url, self.body)
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
        response = yield self.async_post(url, self.body)
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
        response = yield self.async_post(url, self.body)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])
        self.assertIsNotNone(data['encoding'])

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id='
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIsNone(msg)
        self.assertIn('Missing value id', ws.close_reason)

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_but_wrong_id(self):
        url = self.get_url('/')
        response = yield self.async_post(url, self.body)
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
        body = self.body.replace('robey', 'bar')
        url = self.get_url('/')
        response = yield self.async_post(url, body)
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
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        self.body_dict.update(privatekey=privatekey)
        body = urlencode(self.body_dict)
        response = yield self.async_post(url, body)
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
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }
        response = yield self.async_post(url, body, headers=headers)
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
        privatekey = 'h' * 1024
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }

        if swallow_http_errors:
            response = yield self.async_post(url, body, headers=headers)
            self.assertIn(b'Invalid private key', response.body)
        else:
            with self.assertRaises(HTTPError) as ctx:
                yield self.async_post(url, body, headers=headers)
            self.assertIn('Bad Request', ctx.exception.message)

    @tornado.testing.gen_test
    def test_app_auth_with_pubkey_exceeds_key_max_size(self):
        url = self.get_url('/')
        privatekey = 'h' * (handler.KEY_MAX_SIZE * 2)
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }
        if swallow_http_errors:
            response = yield self.async_post(url, body, headers=headers)
            self.assertIn(b'Invalid private key', response.body)
        else:
            with self.assertRaises(HTTPError) as ctx:
                yield self.async_post(url, body, headers=headers)
            self.assertIn('Bad Request', ctx.exception.message)

    @tornado.testing.gen_test
    def test_app_auth_with_pubkey_cannot_be_decoded_by_multipart_form(self):
        url = self.get_url('/')
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
        if swallow_http_errors:
            response = yield self.async_post(url, body, headers=headers)
            self.assertIn(b'Invalid unicode', response.body)
        else:
            with self.assertRaises(HTTPError) as ctx:
                yield self.async_post(url, body, headers=headers)
            self.assertIn('Bad Request', ctx.exception.message)

    @tornado.testing.gen_test
    def test_app_post_form_with_large_body_size_by_multipart_form(self):
        url = self.get_url('/')
        privatekey = 'h' * (2 * max_body_size)
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }

        with self.assertRaises(HTTPError) as ctx:
            yield self.async_post(url, body, headers=headers)
        self.assertIn('Bad Request', ctx.exception.message)

    @tornado.testing.gen_test
    def test_app_post_form_with_large_body_size_by_urlencoded_form(self):
        url = self.get_url('/')
        privatekey = 'h' * (2 * max_body_size)
        body = self.body + '&privatekey=' + privatekey
        with self.assertRaises(HTTPError) as ctx:
            yield self.async_post(url, body)
        self.assertIn('Bad Request', ctx.exception.message)

    @tornado.testing.gen_test
    def test_app_with_user_keyonly_for_bad_authentication_type(self):
        url = self.get_url('/')
        self.body_dict.update(username='keyonly', password='foo')
        body = urlencode(self.body_dict)
        response = yield self.async_post(url, body)
        self.assertEqual(response.code, 200)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['id'])
        self.assertIsNone(data['encoding'])
        self.assertIn('Bad authentication type', data['status'])


class OtherTestBase(AsyncHTTPTestCase):
    sshserver_port = 3300
    headers = {'Cookie': '_xsrf=yummy'}
    debug = False
    policy = None
    hostfile = ''
    syshostfile = ''
    tdstream = ''
    body = {
        'hostname': '127.0.0.1',
        'port': '',
        'username': 'robey',
        'password': 'foo',
        '_xsrf': 'yummy'
    }

    def get_app(self):
        self.body.update(port=str(self.sshserver_port))
        loop = self.io_loop
        options.debug = self.debug
        options.policy = self.policy if self.policy else random.choice(['warning', 'autoadd'])  # noqa
        options.hostfile = self.hostfile
        options.syshostfile = self.syshostfile
        options.tdstream = self.tdstream
        app = make_app(make_handlers(loop, options), get_app_settings(options))
        return app

    def get_httpserver_options(self):
        return get_server_settings(options)

    def setUp(self):
        print('='*20)
        self.running = True
        OtherTestBase.sshserver_port += 1

        t = threading.Thread(
            target=run_ssh_server, args=(self.sshserver_port, self.running)
        )
        t.setDaemon(True)
        t.start()
        super(OtherTestBase, self).setUp()

    def tearDown(self):
        self.running = False
        print('='*20)
        super(OtherTestBase, self).tearDown()


class TestAppInDebug(OtherTestBase):

    debug = True

    def assert_response(self, bstr, response):
        if swallow_http_errors:
            self.assertEqual(response.code, 200)
            self.assertIn(bstr, response.body)
        else:
            self.assertEqual(response.code, 500)
            self.assertIn(b'Uncaught exception', response.body)

    def test_server_error_for_post_method(self):
        response = self.fetch(
            '/',
            method='POST',
            body=urlencode(dict(self.body, error='raise')),
            headers=self.headers
        )
        self.assert_response(b'"status": "Internal Server Error"', response)

    def test_html(self):
        response = self.fetch('/', method='GET')
        self.assertIn(b'novalidate>', response.body)


class TestAppMiscell(OtherTestBase):

    @tornado.testing.gen_test
    def test_app_for_sending_message_with_large_size(self):
        url = self.get_url('/')
        client = self.get_http_client()
        body = urlencode(dict(self.body, username='foo'))
        response = yield client.fetch(url, method='POST', body=body,
                                      headers=self.headers)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])
        self.assertIsNotNone(data['encoding'])

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertEqual(to_str(msg, data['encoding']), banner)

        send = 'h' * (64 * 1024) + '\r\n\r\n'
        yield ws.write_message(json.dumps({'data': send}))
        lst = []
        while True:
            msg = yield ws.read_message()
            lst.append(msg)
            if msg.endswith(b'\r\n\r\n'):
                break
        recv = b''.join(lst).decode(data['encoding'])
        self.assertEqual(send, recv)
        ws.close()


class TestAppWithRejectPolicy(OtherTestBase):

    policy = 'reject'
    hostfile = make_tests_data_path('known_hosts_example')

    @tornado.testing.gen_test
    def test_app_with_hostname_not_in_hostkeys(self):
        url = self.get_url('/')
        client = self.get_http_client()
        body = urlencode(dict(self.body, username='foo'))
        response = yield client.fetch(url, method='POST', body=body,
                                      headers=self.headers)
        data = json.loads(to_str(response.body))
        self.assertIsNone(data['id'])
        self.assertIsNone(data['encoding'])
        message = 'Connection to {}:{} is not allowed.'.format(self.body['hostname'], self.sshserver_port) # noqa
        self.assertEqual(message, data['status'])


class TestAppWithTrustedStream(OtherTestBase):
    tdstream = '127.0.0.2'

    def test_with_forbidden_get_request(self):
        response = self.fetch('/', method='GET')
        self.assertEqual(response.code, 403)
        self.assertIn('Forbidden', response.error.message)

    def test_with_forbidden_post_request(self):
        response = self.fetch('/', method='POST', body=urlencode(self.body),
                              headers=self.headers)
        self.assertEqual(response.code, 403)
        self.assertIn('Forbidden', response.error.message)

    def test_with_forbidden_put_request(self):
        response = self.fetch('/', method='PUT', body=urlencode(self.body),
                              headers=self.headers)
        self.assertEqual(response.code, 403)
        self.assertIn('Forbidden', response.error.message)


class TestAppNotFoundHandler(OtherTestBase):

    custom_headers = handler.MixinHandler.custom_headers

    def test_with_not_found_get_request(self):
        response = self.fetch('/pathnotfound', method='GET')
        self.assertEqual(response.code, 404)
        self.assertEqual(
            response.headers['Server'], self.custom_headers['Server']
        )
        self.assertIn(b'404: Not Found', response.body)

    def test_with_not_found_post_request(self):
        response = self.fetch('/pathnotfound', method='POST',
                              body=urlencode(self.body), headers=self.headers)
        self.assertEqual(response.code, 404)
        self.assertEqual(
            response.headers['Server'], self.custom_headers['Server']
        )
        self.assertIn(b'404: Not Found', response.body)

    def test_with_not_found_put_request(self):
        response = self.fetch('/pathnotfound', method='PUT',
                              body=urlencode(self.body), headers=self.headers)
        self.assertEqual(response.code, 404)
        self.assertEqual(
            response.headers['Server'], self.custom_headers['Server']
        )
        self.assertIn(b'404: Not Found', response.body)


class TestAppHeadRequest(OtherTestBase):

    def test_with_index_path(self):
        response = self.fetch('/', method='HEAD')
        self.assertEqual(response.code, 200)

    def test_with_ws_path(self):
        response = self.fetch('/ws', method='HEAD')
        self.assertEqual(response.code, 405)

    def test_with_not_found_path(self):
        response = self.fetch('/notfound', method='HEAD')
        self.assertEqual(response.code, 404)
