import io
import json
import logging
import socket
import struct
import threading
import traceback
import weakref
import paramiko
import tornado.web

from tornado.ioloop import IOLoop
from webssh.worker import Worker, recycle_worker, workers
from webssh.utils import (
    is_valid_ipv4_address, is_valid_ipv6_address, is_valid_port,
    is_valid_hostname, to_bytes, to_str, UnicodeType
)

try:
    from concurrent.futures import Future
except ImportError:
    from tornado.concurrent import Future

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError


DELAY = 3
KEY_MAX_SIZE = 16384


def parse_encoding(data):
    for line in data.split('\n'):
        s = line.split('=')[-1]
        if s:
            return s.strip('"').split('.')[-1]


class InvalidException(Exception):
    pass


class MixinHandler(object):

    formater = 'Missing value {}'

    def write_error(self, status_code, **kwargs):
        exc_info = kwargs.get('exc_info')
        if exc_info and len(exc_info) > 1:
            info = str(exc_info[1])
            if info:
                self._reason = info.split(':', 1)[-1].strip()
        super(MixinHandler, self).write_error(status_code, **kwargs)

    def get_value(self, name):
        value = self.get_argument(name)
        if not value:
            raise InvalidException(self.formater.format(name))
        return value

    def get_real_client_addr(self):
        ip = self.request.headers.get('X-Real-Ip')
        port = self.request.headers.get('X-Real-Port')

        if ip is None and port is None:  # suppose the server doesn't use nginx
            return

        if is_valid_ipv4_address(ip) or is_valid_ipv6_address(ip):
            try:
                port = int(port)
            except (TypeError, ValueError):
                pass
            else:
                if is_valid_port(port):
                    return (ip, port)

        logging.warning('Bad nginx configuration.')
        return False


class IndexHandler(MixinHandler, tornado.web.RequestHandler):

    def initialize(self, loop, policy, host_keys_settings):
        self.loop = loop
        self.policy = policy
        self.host_keys_settings = host_keys_settings
        self.filename = None

    def get_privatekey(self):
        lst = self.request.files.get('privatekey')  # multipart form
        if not lst:
            return self.get_argument('privatekey', u'')  # urlencoded form
        else:
            self.filename = lst[0]['filename']
            data = lst[0]['body']
            if len(data) > KEY_MAX_SIZE:
                raise InvalidException(
                    'Invalid private key: {}'.format(self.filename)
                )
            return self.decode_argument(data, name=self.filename)

    @classmethod
    def get_specific_pkey(cls, pkeycls, privatekey, password):
        logging.info('Trying {}'.format(pkeycls.__name__))
        try:
            pkey = pkeycls.from_private_key(io.StringIO(privatekey),
                                            password=password)
        except paramiko.PasswordRequiredException:
            raise
        except paramiko.SSHException:
            pass
        else:
            return pkey

    @classmethod
    def get_pkey_obj(cls, privatekey, password, filename):
        bpass = to_bytes(password)

        pkey = cls.get_specific_pkey(paramiko.RSAKey, privatekey, bpass)\
            or cls.get_specific_pkey(paramiko.DSSKey, privatekey, bpass)\
            or cls.get_specific_pkey(paramiko.ECDSAKey, privatekey, bpass)\
            or cls.get_specific_pkey(paramiko.Ed25519Key, privatekey, bpass)

        if not pkey:
            if not password:
                error = 'Invalid private key: {}'.format(filename)
            else:
                error = (
                    'Wrong password {!r} for decrypting the private key.'
                ) .format(password)
            raise InvalidException(error)

        return pkey

    def get_hostname(self):
        value = self.get_value('hostname')
        if not (is_valid_hostname(value) | is_valid_ipv4_address(value) |
                is_valid_ipv6_address(value)):
            raise InvalidException('Invalid hostname: {}'.format(value))
        return value

    def get_port(self):
        value = self.get_value('port')
        try:
            port = int(value)
        except ValueError:
            pass
        else:
            if is_valid_port(port):
                return port

        raise InvalidException('Invalid port: {}'.format(value))

    def get_args(self):
        hostname = self.get_hostname()
        port = self.get_port()
        username = self.get_value('username')
        password = self.get_argument('password', u'')
        privatekey = self.get_privatekey()
        pkey = self.get_pkey_obj(privatekey, password, self.filename) \
            if privatekey else None
        args = (hostname, port, username, password, pkey)
        logging.debug(args)
        return args

    def get_client_addr(self):
        return self.get_real_client_addr() or self.request.connection.stream.\
            socket.getpeername()

    def get_default_encoding(self, ssh):
        try:
            _, stdout, _ = ssh.exec_command('locale')
        except paramiko.SSHException:
            result = None
        else:
            data = stdout.read()
            result = parse_encoding(to_str(data))

        return result if result else 'utf-8'

    def ssh_connect(self):
        ssh = paramiko.SSHClient()
        ssh._system_host_keys = self.host_keys_settings['system_host_keys']
        ssh._host_keys = self.host_keys_settings['host_keys']
        ssh._host_keys_filename = self.host_keys_settings['host_keys_filename']
        ssh.set_missing_host_key_policy(self.policy)

        try:
            args = self.get_args()
        except InvalidException as exc:
            raise tornado.web.HTTPError(400, str(exc))

        dst_addr = (args[0], args[1])
        logging.info('Connecting to {}:{}'.format(*dst_addr))

        try:
            ssh.connect(*args, timeout=6)
        except socket.error:
            raise ValueError('Unable to connect to {}:{}'.format(*dst_addr))
        except paramiko.BadAuthenticationType:
            raise ValueError('Bad authentication type.')
        except paramiko.AuthenticationException:
            raise ValueError('Authentication failed.')
        except paramiko.BadHostKeyException:
            raise ValueError('Bad host key.')

        chan = ssh.invoke_shell(term='xterm')
        chan.setblocking(0)
        worker = Worker(self.loop, ssh, chan, dst_addr)
        worker.src_addr = self.get_client_addr()
        worker.encoding = self.get_default_encoding(ssh)
        return worker

    def ssh_connect_wrapped(self, future):
        try:
            worker = self.ssh_connect()
        except Exception as exc:
            logging.error(traceback.format_exc())
            future.set_exception(exc)
        else:
            future.set_result(worker)

    def get(self):
        self.render('index.html')

    @tornado.gen.coroutine
    def post(self):
        worker_id = None
        status = None
        encoding = None

        future = Future()
        t = threading.Thread(target=self.ssh_connect_wrapped, args=(future,))
        t.setDaemon(True)
        t.start()

        try:
            worker = yield future
        except (ValueError, paramiko.SSHException) as exc:
            status = str(exc)
        else:
            worker_id = worker.id
            workers[worker_id] = worker
            self.loop.call_later(DELAY, recycle_worker, worker)
            encoding = worker.encoding

        self.write(dict(id=worker_id, status=status, encoding=encoding))


class WsockHandler(MixinHandler, tornado.websocket.WebSocketHandler):

    formater = 'Bad Request (Missing value {})'

    def initialize(self, loop):
        self.loop = loop
        self.worker_ref = None

    def get_client_addr(self):
        return self.get_real_client_addr() or self.stream.socket.getpeername()

    def open(self):
        self.src_addr = self.get_client_addr()
        logging.info('Connected from {}:{}'.format(*self.src_addr))
        try:
            worker_id = self.get_value('id')
        except (tornado.web.MissingArgumentError, InvalidException) as exc:
            self.close(reason=str(exc).split(':', 1)[-1].strip())
        else:
            worker = workers.get(worker_id)
            if worker and worker.src_addr[0] == self.src_addr[0]:
                workers.pop(worker.id)
                self.set_nodelay(True)
                worker.set_handler(self)
                self.worker_ref = weakref.ref(worker)
                self.loop.add_handler(worker.fd, worker, IOLoop.READ)
            else:
                self.close(reason='Websocket authentication failed.')

    def on_message(self, message):
        logging.debug('{!r} from {}:{}'.format(message, *self.src_addr))
        worker = self.worker_ref()
        try:
            msg = json.loads(message)
        except JSONDecodeError:
            return

        if not isinstance(msg, dict):
            return

        resize = msg.get('resize')
        if resize and len(resize) == 2:
            try:
                worker.chan.resize_pty(*resize)
            except (TypeError, struct.error, paramiko.SSHException):
                pass

        data = msg.get('data')
        if data and isinstance(data, UnicodeType):
            worker.data_to_dst.append(data)
            worker.on_write()

    def on_close(self):
        if self.close_reason:
            logging.info(
                'Disconnecting to {}:{} with reason: {reason}'.format(
                    *self.src_addr, reason=self.close_reason
                )
            )
        else:
            self.close_reason = 'client disconnected'
            logging.info('Disconnected from {}:{}'.format(*self.src_addr))

        worker = self.worker_ref() if self.worker_ref else None
        if worker:
            worker.close(reason=self.close_reason)
