import io
import json
import logging
import socket
import threading
import traceback
import weakref
import paramiko
import tornado.web

from tornado.ioloop import IOLoop
from webssh.worker import Worker, recycle_worker, workers

try:
    from concurrent.futures import Future
except ImportError:
    from tornado.concurrent import Future


DELAY = 3


class MixinHandler(object):

    def get_real_client_addr(self):
        ip = self.request.headers.get('X-Real-Ip')
        port = self.request.headers.get('X-Real-Port')

        if ip is None and port is None:
            return

        try:
            port = int(port)
        except (TypeError, ValueError):
            pass
        else:
            if ip:  # does not validate ip and port here
                return (ip, port)

        logging.warning('Bad nginx configuration.')
        return False


class IndexHandler(MixinHandler, tornado.web.RequestHandler):

    def initialize(self, loop, policy, host_keys_settings):
        self.loop = loop
        self.policy = policy
        self.host_keys_settings = host_keys_settings

    def get_privatekey(self):
        try:
            data = self.request.files.get('privatekey')[0]['body']
        except TypeError:
            return
        return data.decode('utf-8')

    @classmethod
    def get_specific_pkey(cls, pkeycls, privatekey, password):
        logging.info('Trying {}'.format(pkeycls.__name__))
        try:
            pkey = pkeycls.from_private_key(io.StringIO(privatekey),
                                            password=password)
        except paramiko.PasswordRequiredException:
            raise ValueError('Need password to decrypt the private key.')
        except paramiko.SSHException:
            pass
        else:
            return pkey

    @classmethod
    def get_pkey_obj(cls, privatekey, password):
        password = password.encode('utf-8') if password else None

        pkey = cls.get_specific_pkey(paramiko.RSAKey, privatekey, password)\
            or cls.get_specific_pkey(paramiko.DSSKey, privatekey, password)\
            or cls.get_specific_pkey(paramiko.ECDSAKey, privatekey, password)\
            or cls.get_specific_pkey(paramiko.Ed25519Key, privatekey,
                                     password)
        if not pkey:
            raise ValueError('Not a valid private key file or '
                             'wrong password for decrypting the private key.')
        return pkey

    def get_port(self):
        value = self.get_value('port')
        try:
            port = int(value)
        except ValueError:
            port = 0

        if 0 < port < 65536:
            return port

        raise ValueError('Invalid port {}'.format(value))

    def get_value(self, name):
        value = self.get_argument(name)
        if not value:
            raise ValueError('Empty {}'.format(name))
        return value

    def get_args(self):
        hostname = self.get_value('hostname')
        port = self.get_port()
        username = self.get_value('username')
        password = self.get_argument('password')
        privatekey = self.get_privatekey()
        pkey = self.get_pkey_obj(privatekey, password) if privatekey else None
        args = (hostname, port, username, password, pkey)
        logging.debug(args)
        return args

    def get_client_addr(self):
        return self.get_real_client_addr() or self.request.connection.stream.\
            socket.getpeername()

    def ssh_connect(self):
        ssh = paramiko.SSHClient()
        ssh._system_host_keys = self.host_keys_settings['system_host_keys']
        ssh._host_keys = self.host_keys_settings['host_keys']
        ssh._host_keys_filename = self.host_keys_settings['host_keys_filename']
        ssh.set_missing_host_key_policy(self.policy)

        args = self.get_args()
        dst_addr = (args[0], args[1])
        logging.info('Connecting to {}:{}'.format(*dst_addr))

        try:
            ssh.connect(*args, timeout=6)
        except socket.error:
            raise ValueError('Unable to connect to {}:{}'.format(*dst_addr))
        except paramiko.BadAuthenticationType:
            raise ValueError('SSH authentication failed.')
        except paramiko.BadHostKeyException:
            raise ValueError('Bad host key.')

        chan = ssh.invoke_shell(term='xterm')
        chan.setblocking(0)
        worker = Worker(self.loop, ssh, chan, dst_addr)
        worker.src_addr = self.get_client_addr()
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

        future = Future()
        t = threading.Thread(target=self.ssh_connect_wrapped, args=(future,))
        t.setDaemon(True)
        t.start()

        try:
            worker = yield future
        except Exception as exc:
            status = str(exc)
        else:
            worker_id = worker.id
            workers[worker_id] = worker
            self.loop.call_later(DELAY, recycle_worker, worker)

        self.write(dict(id=worker_id, status=status))


class WsockHandler(MixinHandler, tornado.websocket.WebSocketHandler):

    def initialize(self, loop):
        self.loop = loop
        self.worker_ref = None

    def get_client_addr(self):
        return self.get_real_client_addr() or self.stream.socket.getpeername()

    def open(self):
        self.src_addr = self.get_client_addr()
        logging.info('Connected from {}:{}'.format(*self.src_addr))
        worker = workers.get(self.get_argument('id'))
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
        msg = json.loads(message)
        resize = msg.get('resize')
        if resize:
            try:
                worker.chan.resize_pty(*resize)
            except paramiko.SSHException:
                pass
        data = msg.get('data')
        if data:
            worker.data_to_dst.append(data)
            worker.on_write()

    def on_close(self):
        logging.info('Disconnected from {}:{}'.format(*self.src_addr))
        worker = self.worker_ref() if self.worker_ref else None
        if worker:
            if self.close_reason is None:
                self.close_reason = 'client disconnected'
            worker.close(reason=self.close_reason)
