import io
import unittest
import paramiko

from tornado.httputil import HTTPServerRequest
from tornado.options import options
from tests.utils import read_file, make_tests_data_path
from webssh import handler
from webssh import worker
from webssh.handler import (
    IndexHandler, MixinHandler, WsockHandler, PrivateKey, InvalidValueError, SSHClient
)

try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock


class TestMixinHandler(unittest.TestCase):

    def test_is_forbidden(self):
        mhandler = MixinHandler()
        handler.redirecting = True
        options.fbidhttp = True

        context = Mock(
            address=('8.8.8.8', 8888),
            trusted_downstream=['127.0.0.1'],
            _orig_protocol='http'
        )
        hostname = '4.4.4.4'
        self.assertTrue(mhandler.is_forbidden(context, hostname))

        context = Mock(
            address=('8.8.8.8', 8888),
            trusted_downstream=[],
            _orig_protocol='http'
        )
        hostname = 'www.google.com'
        self.assertEqual(mhandler.is_forbidden(context, hostname), False)

        context = Mock(
            address=('8.8.8.8', 8888),
            trusted_downstream=[],
            _orig_protocol='http'
        )
        hostname = '4.4.4.4'
        self.assertTrue(mhandler.is_forbidden(context, hostname))

        context = Mock(
            address=('192.168.1.1', 8888),
            trusted_downstream=[],
            _orig_protocol='http'
        )
        hostname = 'www.google.com'
        self.assertIsNone(mhandler.is_forbidden(context, hostname))

        options.fbidhttp = False
        self.assertIsNone(mhandler.is_forbidden(context, hostname))

        hostname = '4.4.4.4'
        self.assertIsNone(mhandler.is_forbidden(context, hostname))

        handler.redirecting = False
        self.assertIsNone(mhandler.is_forbidden(context, hostname))

        context._orig_protocol = 'https'
        self.assertIsNone(mhandler.is_forbidden(context, hostname))

    def test_get_redirect_url(self):
        mhandler = MixinHandler()
        hostname = 'www.example.com'
        uri = '/'
        port = 443

        self.assertEqual(
            mhandler.get_redirect_url(hostname, port, uri=uri),
            'https://www.example.com/'
        )

        port = 4433
        self.assertEqual(
            mhandler.get_redirect_url(hostname, port, uri),
            'https://www.example.com:4433/'
        )

    def test_get_client_addr(self):
        mhandler = MixinHandler()
        client_addr = ('8.8.8.8', 8888)
        context_addr = ('127.0.0.1', 1234)
        options.xheaders = True

        mhandler.context = Mock(address=context_addr)
        mhandler.get_real_client_addr = lambda: None
        self.assertEqual(mhandler.get_client_addr(), context_addr)

        mhandler.context = Mock(address=context_addr)
        mhandler.get_real_client_addr = lambda: client_addr
        self.assertEqual(mhandler.get_client_addr(), client_addr)

        options.xheaders = False
        mhandler.context = Mock(address=context_addr)
        mhandler.get_real_client_addr = lambda: client_addr
        self.assertEqual(mhandler.get_client_addr(), context_addr)

    def test_get_real_client_addr(self):
        x_forwarded_for = '1.1.1.1'
        x_forwarded_port = 1111
        x_real_ip = '2.2.2.2'
        x_real_port = 2222
        fake_port = 65535

        mhandler = MixinHandler()
        mhandler.request = HTTPServerRequest(uri='/')
        mhandler.request.remote_ip = x_forwarded_for

        self.assertIsNone(mhandler.get_real_client_addr())

        mhandler.request.headers.add('X-Forwarded-For', x_forwarded_for)
        self.assertEqual(mhandler.get_real_client_addr(),
                         (x_forwarded_for, fake_port))

        mhandler.request.headers.add('X-Forwarded-Port', fake_port + 1)
        self.assertEqual(mhandler.get_real_client_addr(),
                         (x_forwarded_for, fake_port))

        mhandler.request.headers['X-Forwarded-Port'] = x_forwarded_port
        self.assertEqual(mhandler.get_real_client_addr(),
                         (x_forwarded_for, x_forwarded_port))

        mhandler.request.remote_ip = x_real_ip

        mhandler.request.headers.add('X-Real-Ip', x_real_ip)
        self.assertEqual(mhandler.get_real_client_addr(),
                         (x_real_ip, fake_port))

        mhandler.request.headers.add('X-Real-Port', fake_port + 1)
        self.assertEqual(mhandler.get_real_client_addr(),
                         (x_real_ip, fake_port))

        mhandler.request.headers['X-Real-Port'] = x_real_port
        self.assertEqual(mhandler.get_real_client_addr(),
                         (x_real_ip, x_real_port))


class TestPrivateKey(unittest.TestCase):

    def get_pk_obj(self, fname, password=None):
        key = read_file(make_tests_data_path(fname))
        return PrivateKey(key, password=password, filename=fname)

    def _test_with_encrypted_key(self, fname, password, klass):
        pk = self.get_pk_obj(fname, password='')
        with self.assertRaises(InvalidValueError) as ctx:
            pk.get_pkey_obj()
        self.assertIn('Need a passphrase', str(ctx.exception))

        pk = self.get_pk_obj(fname, password='wrongpass')
        with self.assertRaises(InvalidValueError) as ctx:
            pk.get_pkey_obj()
        self.assertIn('wrong passphrase', str(ctx.exception))

        pk = self.get_pk_obj(fname, password=password)
        self.assertIsInstance(pk.get_pkey_obj(), klass)

    def test_class_with_invalid_key_length(self):
        key = u'a' * (PrivateKey.max_length + 1)

        with self.assertRaises(InvalidValueError) as ctx:
            PrivateKey(key)
        self.assertIn('Invalid key length', str(ctx.exception))

    def test_get_pkey_obj_with_invalid_key(self):
        key = u'a b c'
        fname = 'abc'

        pk = PrivateKey(key, filename=fname)
        with self.assertRaises(InvalidValueError) as ctx:
            pk.get_pkey_obj()
        self.assertIn('Invalid key {}'.format(fname), str(ctx.exception))

    def test_get_pkey_obj_with_plain_rsa_key(self):
        pk = self.get_pk_obj('test_rsa.key')
        self.assertIsInstance(pk.get_pkey_obj(), paramiko.RSAKey)

    def test_get_pkey_obj_with_plain_ed25519_key(self):
        pk = self.get_pk_obj('test_ed25519.key')
        self.assertIsInstance(pk.get_pkey_obj(), paramiko.Ed25519Key)

    def test_get_pkey_obj_with_encrypted_rsa_key(self):
        fname = 'test_rsa_password.key'
        password = 'television'
        self._test_with_encrypted_key(fname, password, paramiko.RSAKey)

    def test_get_pkey_obj_with_encrypted_ed25519_key(self):
        fname = 'test_ed25519_password.key'
        password = 'abc123'
        self._test_with_encrypted_key(fname, password, paramiko.Ed25519Key)

    def test_get_pkey_obj_with_encrypted_new_rsa_key(self):
        fname = 'test_new_rsa_password.key'
        password = '123456'
        self._test_with_encrypted_key(fname, password, paramiko.RSAKey)

    def test_get_pkey_obj_with_plain_new_dsa_key(self):
        pk = self.get_pk_obj('test_new_dsa.key')
        self.assertIsInstance(pk.get_pkey_obj(), paramiko.DSSKey)

    def test_parse_name(self):
        key = u'-----BEGIN PRIVATE KEY-----'
        pk = PrivateKey(key)
        name, _ = pk.parse_name(pk.iostr, pk.tag_to_name)
        self.assertIsNone(name)

        key = u'-----BEGIN xxx PRIVATE KEY-----'
        pk = PrivateKey(key)
        name, _ = pk.parse_name(pk.iostr, pk.tag_to_name)
        self.assertIsNone(name)

        key = u'-----BEGIN  RSA PRIVATE KEY-----'
        pk = PrivateKey(key)
        name, _ = pk.parse_name(pk.iostr, pk.tag_to_name)
        self.assertIsNone(name)

        key = u'-----BEGIN RSA  PRIVATE KEY-----'
        pk = PrivateKey(key)
        name, _ = pk.parse_name(pk.iostr, pk.tag_to_name)
        self.assertIsNone(name)

        key = u'-----BEGIN RSA PRIVATE  KEY-----'
        pk = PrivateKey(key)
        name, _ = pk.parse_name(pk.iostr, pk.tag_to_name)
        self.assertIsNone(name)

        for tag, to_name in PrivateKey.tag_to_name.items():
            key = u'-----BEGIN {} PRIVATE KEY----- \r\n'.format(tag)
            pk = PrivateKey(key)
            name, length = pk.parse_name(pk.iostr, pk.tag_to_name)
            self.assertEqual(name, to_name)
            self.assertEqual(length, len(key))


class TestWsockHandler(unittest.TestCase):

    def test_check_origin(self):
        request = HTTPServerRequest(uri='/')
        obj = Mock(spec=WsockHandler, request=request)

        obj.origin_policy = 'same'
        request.headers['Host'] = 'www.example.com:4433'
        origin = 'https://www.example.com:4433'
        self.assertTrue(WsockHandler.check_origin(obj, origin))

        origin = 'https://www.example.com'
        self.assertFalse(WsockHandler.check_origin(obj, origin))

        obj.origin_policy = 'primary'
        self.assertTrue(WsockHandler.check_origin(obj, origin))

        origin = 'https://blog.example.com'
        self.assertTrue(WsockHandler.check_origin(obj, origin))

        origin = 'https://blog.example.org'
        self.assertFalse(WsockHandler.check_origin(obj, origin))

        origin = 'https://blog.example.org'
        obj.origin_policy = {'https://blog.example.org'}
        self.assertTrue(WsockHandler.check_origin(obj, origin))

        origin = 'http://blog.example.org'
        obj.origin_policy = {'http://blog.example.org'}
        self.assertTrue(WsockHandler.check_origin(obj, origin))

        origin = 'http://blog.example.org'
        obj.origin_policy = {'https://blog.example.org'}
        self.assertFalse(WsockHandler.check_origin(obj, origin))

        obj.origin_policy = '*'
        origin = 'https://blog.example.org'
        self.assertTrue(WsockHandler.check_origin(obj, origin))

    def test_failed_weak_ref(self):
        request = HTTPServerRequest(uri='/')
        obj = Mock(spec=WsockHandler, request=request)
        obj.src_addr = ("127.0.0.1", 8888)

        class FakeWeakRef:
            def __init__(self):
                self.count = 0

            def __call__(self):
                self.count += 1
                return None

        ref = FakeWeakRef()
        obj.worker_ref = ref
        WsockHandler.on_message(obj, b'{"data": "somestuff"}')
        self.assertGreaterEqual(ref.count, 1)
        obj.close.assert_called_with(reason='No worker found')

    def test_worker_closed(self):
        request = HTTPServerRequest(uri='/')
        obj = Mock(spec=WsockHandler, request=request)
        obj.src_addr = ("127.0.0.1", 8888)

        class Worker:
            def __init__(self):
                self.closed = True

        class FakeWeakRef:
            def __call__(self):
                return Worker()

        ref = FakeWeakRef()
        obj.worker_ref = ref
        WsockHandler.on_message(obj, b'{"data": "somestuff"}')
        obj.close.assert_called_with(reason='Worker closed')

class TestIndexHandler(unittest.TestCase):
    def test_null_in_encoding(self):
        handler = Mock(spec=IndexHandler)

        # This is a little nasty, but the index handler has a lot of
        # dependencies to mock. Mocking out everything but the bits
        # we want to test lets us test this case without needing to
        # refactor the relevant code out of IndexHandler
        def parse_encoding(data):
            return IndexHandler.parse_encoding(handler, data)
        handler.parse_encoding = parse_encoding

        ssh = Mock(spec=SSHClient)
        stdin = io.BytesIO()
        stdout = io.BytesIO(initial_bytes=b"UTF-8\0")
        stderr = io.BytesIO()
        ssh.exec_command.return_value = (stdin, stdout, stderr)

        encoding = IndexHandler.get_default_encoding(handler, ssh)
        self.assertEquals("utf-8", encoding)

