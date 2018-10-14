import unittest
import paramiko

from tornado.httputil import HTTPServerRequest
from tests.utils import read_file, make_tests_data_path
from webssh.handler import MixinHandler, IndexHandler, InvalidValueError


class TestMixinHandler(unittest.TestCase):

    def test_get_real_client_addr(self):
        x_forwarded_for = '1.1.1.1'
        x_forwarded_port = 1111
        x_real_ip = '2.2.2.2'
        x_real_port = 2222
        fake_port = 65535

        handler = MixinHandler()
        handler.request = HTTPServerRequest(uri='/')
        handler.request.remote_ip = x_forwarded_for

        self.assertIsNone(handler.get_real_client_addr())

        handler.request.headers.add('X-Forwarded-For', x_forwarded_for)
        self.assertEqual(handler.get_real_client_addr(),
                         (x_forwarded_for, fake_port))

        handler.request.headers.add('X-Forwarded-Port', fake_port + 1)
        self.assertEqual(handler.get_real_client_addr(),
                         (x_forwarded_for, fake_port))

        handler.request.headers['X-Forwarded-Port'] = x_forwarded_port
        self.assertEqual(handler.get_real_client_addr(),
                         (x_forwarded_for, x_forwarded_port))

        handler.request.remote_ip = x_real_ip

        handler.request.headers.add('X-Real-Ip', x_real_ip)
        self.assertEqual(handler.get_real_client_addr(),
                         (x_real_ip, fake_port))

        handler.request.headers.add('X-Real-Port', fake_port + 1)
        self.assertEqual(handler.get_real_client_addr(),
                         (x_real_ip, fake_port))

        handler.request.headers['X-Real-Port'] = x_real_port
        self.assertEqual(handler.get_real_client_addr(),
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

        with self.assertRaises(paramiko.PasswordRequiredException):
            pkey = IndexHandler.get_specific_pkey(cls, key, None)

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

        with self.assertRaises(paramiko.PasswordRequiredException):
            pkey = IndexHandler.get_pkey_obj(key, '', fname)
