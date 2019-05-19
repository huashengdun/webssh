import unittest
import paramiko

from tornado.httputil import HTTPServerRequest
from tornado.options import options
from tests.utils import read_file, make_tests_data_path
from webssh import handler
from webssh.handler import (
    MixinHandler, IndexHandler, WsockHandler, InvalidValueError
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


class TestIndexHandler(unittest.TestCase):

    def test_get_specific_pkey_with_plain_key(self):
        fname = 'test_rsa.key'
        cls = paramiko.RSAKey
        key = read_file(make_tests_data_path(fname))

        pkey = IndexHandler.get_specific_pkey(cls, key, None)
        self.assertIsInstance(pkey, cls)

        pkey = IndexHandler.get_specific_pkey(cls, key, 'iginored')
        self.assertIsInstance(pkey, cls)

        pkey = IndexHandler.get_specific_pkey(cls, 'x'+key, None)
        self.assertIsNone(pkey)

    def test_get_specific_pkey_with_encrypted_key(self):
        fname = 'test_rsa_password.key'
        cls = paramiko.RSAKey
        password = 'television'

        key = read_file(make_tests_data_path(fname))
        pkey = IndexHandler.get_specific_pkey(cls, key, password)
        self.assertIsInstance(pkey, cls)

        pkey = IndexHandler.get_specific_pkey(cls, 'x'+key, None)
        self.assertIsNone(pkey)

        with self.assertRaises(InvalidValueError) as ctx:
            pkey = IndexHandler.get_specific_pkey(cls, key, None)
        self.assertIn('Need a password', str(ctx.exception))

    def test_get_pkey_obj_with_plain_key(self):
        fname = 'test_ed25519.key'
        cls = paramiko.Ed25519Key
        key = read_file(make_tests_data_path(fname))

        pkey = IndexHandler.get_pkey_obj(key, None, fname)
        self.assertIsInstance(pkey, cls)

        pkey = IndexHandler.get_pkey_obj(key, 'iginored', fname)
        self.assertIsInstance(pkey, cls)

        with self.assertRaises(InvalidValueError) as ctx:
            pkey = IndexHandler.get_pkey_obj('x'+key, None, fname)
        self.assertIn('Invalid private key', str(ctx.exception))

    def test_get_pkey_obj_with_encrypted_key(self):
        fname = 'test_ed25519_password.key'
        password = 'abc123'
        cls = paramiko.Ed25519Key
        key = read_file(make_tests_data_path(fname))

        pkey = IndexHandler.get_pkey_obj(key, password, fname)
        self.assertIsInstance(pkey, cls)

        with self.assertRaises(InvalidValueError) as ctx:
            pkey = IndexHandler.get_pkey_obj(key, 'wrongpass', fname)
        self.assertIn('Wrong password', str(ctx.exception))

        with self.assertRaises(InvalidValueError) as ctx:
            pkey = IndexHandler.get_pkey_obj('x'+key, '', fname)
        self.assertIn('Invalid private key', str(ctx.exception))

        with self.assertRaises(InvalidValueError) as ctx:
            pkey = IndexHandler.get_specific_pkey(cls, key, None)
        self.assertIn('Need a password', str(ctx.exception))


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
