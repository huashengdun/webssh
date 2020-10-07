import json
import random
import threading
import tornado.websocket
import tornado.gen

from tornado.testing import AsyncHTTPTestCase
from tornado.httpclient import HTTPError
from tornado.options import options
from tests.sshserver import run_ssh_server, banner, Server
from tests.utils import encode_multipart_formdata, read_file, make_tests_data_path  # noqa
from webssh import handler
from webssh.main import make_app, make_handlers
from webssh.settings import (
    get_app_settings, get_server_settings, max_body_size
)
from webssh.utils import to_str
from webssh.worker import clients

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode


swallow_http_errors = handler.swallow_http_errors
server_encodings = {e.strip() for e in Server.encodings}


class TestAppBase(AsyncHTTPTestCase):

    def get_httpserver_options(self):
        return get_server_settings(options)

    def assert_response(self, bstr, response):
        if swallow_http_errors:
            self.assertEqual(response.code, 200)
            self.assertIn(bstr, response.body)
        else:
            self.assertEqual(response.code, 400)
            self.assertIn(b'Bad Request', response.body)

    def assert_status_in(self, status, data):
        self.assertIsNone(data['encoding'])
        self.assertIsNone(data['id'])
        self.assertIn(status, data['status'])

    def assert_status_equal(self, status, data):
        self.assertIsNone(data['encoding'])
        self.assertIsNone(data['id'])
        self.assertEqual(status, data['status'])

    def assert_status_none(self, data):
        self.assertIsNotNone(data['encoding'])
        self.assertIsNotNone(data['id'])
        self.assertIsNone(data['status'])

    def fetch_request(self, url, method='GET', body='', headers={}, sync=True):
        if not sync and url.startswith('/'):
            url = self.get_url(url)

        if isinstance(body, dict):
            body = urlencode(body)

        if not headers:
            headers = self.headers
        else:
            headers.update(self.headers)

        client = self if sync else self.get_http_client()
        return client.fetch(url, method=method, body=body, headers=headers)

    def sync_post(self, url, body, headers={}):
        return self.fetch_request(url, 'POST', body, headers)

    def async_post(self, url, body, headers={}):
        return self.fetch_request(url, 'POST', body, headers, sync=False)


class TestAppBasic(TestAppBase):

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
        options.delay = 0.1
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

    def test_app_with_invalid_form_for_missing_argument(self):
        response = self.fetch('/')
        self.assertEqual(response.code, 200)

        body = 'port=7000&username=admin&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Missing argument hostname', response)

        body = 'hostname=127.0.0.1&port=7000&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Missing argument username', response)

        body = 'hostname=&port=&username=&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Missing value hostname', response)

        body = 'hostname=127.0.0.1&port=7000&username=&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Missing value username', response)

    def test_app_with_invalid_form_for_invalid_value(self):
        body = 'hostname=127.0.0&port=22&username=&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Invalid hostname', response)

        body = 'hostname=http://www.googe.com&port=22&username=&password&_xsrf=yummy'  # noqa
        response = self.sync_post('/', body)
        self.assert_response(b'Invalid hostname', response)

        body = 'hostname=127.0.0.1&port=port&username=&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Invalid port', response)

        body = 'hostname=127.0.0.1&port=70000&username=&password&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assert_response(b'Invalid port', response)

    def test_app_with_wrong_hostname_ip(self):
        body = 'hostname=127.0.0.2&port=2200&username=admin&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assertEqual(response.code, 200)
        self.assertIn(b'Unable to connect to', response.body)

    def test_app_with_wrong_hostname_domain(self):
        body = 'hostname=xxxxxxxxxxxx&port=2200&username=admin&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assertEqual(response.code, 200)
        self.assertIn(b'Unable to connect to', response.body)

    def test_app_with_wrong_port(self):
        body = 'hostname=127.0.0.1&port=7000&username=admin&_xsrf=yummy'
        response = self.sync_post('/', body)
        self.assertEqual(response.code, 200)
        self.assertIn(b'Unable to connect to', response.body)

    def test_app_with_wrong_credentials(self):
        response = self.sync_post('/', self.body + 's')
        self.assert_status_in('Authentication failed.', json.loads(to_str(response.body))) # noqa

    def test_app_with_correct_credentials(self):
        response = self.sync_post('/', self.body)
        self.assert_status_none(json.loads(to_str(response.body)))

    def test_app_with_correct_credentials_but_with_no_port(self):
        default_port = handler.DEFAULT_PORT
        handler.DEFAULT_PORT = self.sshserver_port

        # with no port value
        body = self.body.replace(str(self.sshserver_port), '')
        response = self.sync_post('/', body)
        self.assert_status_none(json.loads(to_str(response.body)))

        # with no port argument
        body = body.replace('port=&', '')
        response = self.sync_post('/', body)
        self.assert_status_none(json.loads(to_str(response.body)))

        handler.DEFAULT_PORT = default_port

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_timeout(self):
        url = self.get_url('/')
        response = yield self.async_post(url, self.body)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        yield tornado.gen.sleep(options.delay + 0.1)
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIsNone(msg)
        self.assertEqual(ws.close_reason, 'Websocket authentication failed.')

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_but_ip_not_matched(self):
        url = self.get_url('/')
        response = yield self.async_post(url, self.body)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

        clients = handler.clients
        handler.clients = {}
        url = url.replace('http', 'ws')
        ws_url = url + 'ws?id=' + data['id']
        ws = yield tornado.websocket.websocket_connect(ws_url)
        msg = yield ws.read_message()
        self.assertIsNone(msg)
        self.assertEqual(ws.close_reason, 'Websocket authentication failed.')
        handler.clients = clients

    @tornado.testing.gen_test
    def test_app_with_correct_credentials_user_robey(self):
        url = self.get_url('/')
        response = yield self.async_post(url, self.body)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

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
        self.assert_status_none(data)

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
        self.assert_status_none(data)

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
        self.assert_status_none(data)

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
        self.assert_status_none(data)

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
        response = yield self.async_post(url, self.body_dict)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

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
        self.assert_status_none(data)

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
            self.assertIn(b'Invalid key', response.body)
        else:
            with self.assertRaises(HTTPError) as ctx:
                yield self.async_post(url, body, headers=headers)
            self.assertIn('Bad Request', ctx.exception.message)

    @tornado.testing.gen_test
    def test_app_auth_with_pubkey_exceeds_key_max_size(self):
        url = self.get_url('/')
        privatekey = 'h' * (handler.PrivateKey.max_length + 1)
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }
        if swallow_http_errors:
            response = yield self.async_post(url, body, headers=headers)
            self.assertIn(b'Invalid key', response.body)
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

    def test_app_post_form_with_large_body_size_by_multipart_form(self):
        privatekey = 'h' * (2 * max_body_size)
        files = [('privatekey', 'user_rsa_key', privatekey)]
        content_type, body = encode_multipart_formdata(self.body_dict.items(),
                                                       files)
        headers = {
            'Content-Type': content_type, 'content-length': str(len(body))
        }
        response = self.sync_post('/', body, headers=headers)
        self.assertIn(response.code, [400, 599])

    def test_app_post_form_with_large_body_size_by_urlencoded_form(self):
        privatekey = 'h' * (2 * max_body_size)
        body = self.body + '&privatekey=' + privatekey
        response = self.sync_post('/', body)
        self.assertIn(response.code, [400, 599])

    @tornado.testing.gen_test
    def test_app_with_user_keyonly_for_bad_authentication_type(self):
        self.body_dict.update(username='keyonly', password='foo')
        response = yield self.async_post('/', self.body_dict)
        self.assertEqual(response.code, 200)
        self.assert_status_in('Bad authentication type', json.loads(to_str(response.body))) # noqa

    @tornado.testing.gen_test
    def test_app_with_user_pass2fa_with_correct_passwords(self):
        self.body_dict.update(username='pass2fa', password='password',
                              totp='passcode')
        response = yield self.async_post('/', self.body_dict)
        self.assertEqual(response.code, 200)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

    @tornado.testing.gen_test
    def test_app_with_user_pass2fa_with_wrong_pkey_correct_passwords(self):
        url = self.get_url('/')
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        self.body_dict.update(username='pass2fa', password='password',
                              privatekey=privatekey, totp='passcode')
        response = yield self.async_post(url, self.body_dict)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

    @tornado.testing.gen_test
    def test_app_with_user_pkey2fa_with_correct_passwords(self):
        url = self.get_url('/')
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        self.body_dict.update(username='pkey2fa', password='password',
                              privatekey=privatekey, totp='passcode')
        response = yield self.async_post(url, self.body_dict)
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

    @tornado.testing.gen_test
    def test_app_with_user_pkey2fa_with_wrong_password(self):
        url = self.get_url('/')
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        self.body_dict.update(username='pkey2fa', password='wrongpassword',
                              privatekey=privatekey, totp='passcode')
        response = yield self.async_post(url, self.body_dict)
        data = json.loads(to_str(response.body))
        self.assert_status_in('Authentication failed', data)

    @tornado.testing.gen_test
    def test_app_with_user_pkey2fa_with_wrong_passcode(self):
        url = self.get_url('/')
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        self.body_dict.update(username='pkey2fa', password='password',
                              privatekey=privatekey, totp='wrongpasscode')
        response = yield self.async_post(url, self.body_dict)
        data = json.loads(to_str(response.body))
        self.assert_status_in('Authentication failed', data)

    @tornado.testing.gen_test
    def test_app_with_user_pkey2fa_with_empty_passcode(self):
        url = self.get_url('/')
        privatekey = read_file(make_tests_data_path('user_rsa_key'))
        self.body_dict.update(username='pkey2fa', password='password',
                              privatekey=privatekey, totp='')
        response = yield self.async_post(url, self.body_dict)
        data = json.loads(to_str(response.body))
        self.assert_status_in('Need a verification code', data)


class OtherTestBase(TestAppBase):
    sshserver_port = 3300
    headers = {'Cookie': '_xsrf=yummy'}
    debug = False
    policy = None
    xsrf = True
    hostfile = ''
    syshostfile = ''
    tdstream = ''
    maxconn = 20
    origin = 'same'
    encodings = []
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
        options.xsrf = self.xsrf
        options.policy = self.policy if self.policy else random.choice(['warning', 'autoadd'])  # noqa
        options.hostfile = self.hostfile
        options.syshostfile = self.syshostfile
        options.tdstream = self.tdstream
        options.maxconn = self.maxconn
        options.origin = self.origin
        app = make_app(make_handlers(loop, options), get_app_settings(options))
        return app

    def setUp(self):
        print('='*20)
        self.running = True
        OtherTestBase.sshserver_port += 1

        t = threading.Thread(
            target=run_ssh_server,
            args=(self.sshserver_port, self.running, self.encodings)
        )
        t.setDaemon(True)
        t.start()
        super(OtherTestBase, self).setUp()

    def tearDown(self):
        self.running = False
        print('='*20)
        super(OtherTestBase, self).tearDown()


class TestAppInDebugMode(OtherTestBase):

    debug = True

    def assert_response(self, bstr, response):
        if swallow_http_errors:
            self.assertEqual(response.code, 200)
            self.assertIn(bstr, response.body)
        else:
            self.assertEqual(response.code, 500)
            self.assertIn(b'Uncaught exception', response.body)

    def test_server_error_for_post_method(self):
        body = dict(self.body, error='raise')
        response = self.sync_post('/', body)
        self.assert_response(b'"status": "Internal Server Error"', response)

    def test_html(self):
        response = self.fetch('/', method='GET')
        self.assertIn(b'novalidate>', response.body)


class TestAppWithLargeBuffer(OtherTestBase):

    @tornado.testing.gen_test
    def test_app_for_sending_message_with_large_size(self):
        url = self.get_url('/')
        response = yield self.async_post(url, dict(self.body, username='foo'))
        data = json.loads(to_str(response.body))
        self.assert_status_none(data)

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
        response = yield self.async_post('/', self.body)
        data = json.loads(to_str(response.body))
        message = 'Connection to {}:{} is not allowed.'.format(self.body['hostname'], self.sshserver_port) # noqa
        self.assertEqual(message, data['status'])


class TestAppWithBadHostKey(OtherTestBase):

    policy = random.choice(['warning', 'autoadd', 'reject'])
    hostfile = make_tests_data_path('test_known_hosts')

    def setUp(self):
        self.sshserver_port = 2222
        super(TestAppWithBadHostKey, self).setUp()

    @tornado.testing.gen_test
    def test_app_with_bad_host_key(self):
        response = yield self.async_post('/', self.body)
        data = json.loads(to_str(response.body))
        self.assertEqual('Bad host key.', data['status'])


class TestAppWithTrustedStream(OtherTestBase):
    tdstream = '127.0.0.2'

    def test_with_forbidden_get_request(self):
        response = self.fetch('/', method='GET')
        self.assertEqual(response.code, 403)
        self.assertIn('Forbidden', response.error.message)

    def test_with_forbidden_post_request(self):
        response = self.sync_post('/', self.body)
        self.assertEqual(response.code, 403)
        self.assertIn('Forbidden', response.error.message)

    def test_with_forbidden_put_request(self):
        response = self.fetch_request('/', method='PUT', body=self.body)
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
        response = self.sync_post('/pathnotfound', self.body)
        self.assertEqual(response.code, 404)
        self.assertEqual(
            response.headers['Server'], self.custom_headers['Server']
        )
        self.assertIn(b'404: Not Found', response.body)

    def test_with_not_found_put_request(self):
        response = self.fetch_request('/pathnotfound', method='PUT',
                                      body=self.body)
        self.assertEqual(response.code, 404)
        self.assertEqual(
            response.headers['Server'], self.custom_headers['Server']
        )
        self.assertIn(b'404: Not Found', response.body)


class TestAppWithHeadRequest(OtherTestBase):

    def test_with_index_path(self):
        response = self.fetch('/', method='HEAD')
        self.assertEqual(response.code, 200)

    def test_with_ws_path(self):
        response = self.fetch('/ws', method='HEAD')
        self.assertEqual(response.code, 405)

    def test_with_not_found_path(self):
        response = self.fetch('/notfound', method='HEAD')
        self.assertEqual(response.code, 404)


class TestAppWithPutRequest(OtherTestBase):

    xsrf = False

    @tornado.testing.gen_test
    def test_app_with_method_not_supported(self):
        with self.assertRaises(HTTPError) as ctx:
            yield self.fetch_request('/', 'PUT', self.body, sync=False)
        self.assertIn('Method Not Allowed', ctx.exception.message)


class TestAppWithTooManyConnections(OtherTestBase):

    maxconn = 1

    def setUp(self):
        clients.clear()
        super(TestAppWithTooManyConnections, self).setUp()

    @tornado.testing.gen_test
    def test_app_with_too_many_connections(self):
        clients['127.0.0.1'] = {'fake_worker_id': None}

        url = self.get_url('/')
        response = yield self.async_post(url, self.body)
        data = json.loads(to_str(response.body))
        self.assertEqual('Too many live connections.', data['status'])

        clients['127.0.0.1'].clear()
        response = yield self.async_post(url, self.body)
        self.assert_status_none(json.loads(to_str(response.body)))


class TestAppWithCrossOriginOperation(OtherTestBase):

    origin = 'http://www.example.com'

    @tornado.testing.gen_test
    def test_app_with_wrong_event_origin(self):
        body = dict(self.body, _origin='localhost')
        response = yield self.async_post('/', body)
        self.assert_status_equal('Cross origin operation is not allowed.', json.loads(to_str(response.body))) # noqa

    @tornado.testing.gen_test
    def test_app_with_wrong_header_origin(self):
        headers = dict(Origin='localhost')
        response = yield self.async_post('/', self.body, headers=headers)
        self.assert_status_equal('Cross origin operation is not allowed.', json.loads(to_str(response.body)), ) # noqa

    @tornado.testing.gen_test
    def test_app_with_correct_event_origin(self):
        body = dict(self.body, _origin=self.origin)
        response = yield self.async_post('/', body)
        self.assert_status_none(json.loads(to_str(response.body)))
        self.assertIsNone(response.headers.get('Access-Control-Allow-Origin'))

    @tornado.testing.gen_test
    def test_app_with_correct_header_origin(self):
        headers = dict(Origin=self.origin)
        response = yield self.async_post('/', self.body, headers=headers)
        self.assert_status_none(json.loads(to_str(response.body)))
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'), self.origin
        )


class TestAppWithBadEncoding(OtherTestBase):

    encodings = [u'\u7f16\u7801']

    @tornado.testing.gen_test
    def test_app_with_a_bad_encoding(self):
        response = yield self.async_post('/', self.body)
        dic = json.loads(to_str(response.body))
        self.assert_status_none(dic)
        self.assertIn(dic['encoding'], server_encodings)


class TestAppWithUnknownEncoding(OtherTestBase):

    encodings = [u'\u7f16\u7801', u'UnknownEncoding']

    @tornado.testing.gen_test
    def test_app_with_a_unknown_encoding(self):
        response = yield self.async_post('/', self.body)
        self.assert_status_none(json.loads(to_str(response.body)))
        dic = json.loads(to_str(response.body))
        self.assert_status_none(dic)
        self.assertEqual(dic['encoding'], 'utf-8')
