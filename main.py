import io
import logging
import os.path
import socket
import traceback
import uuid
import weakref
import paramiko
import tornado.ioloop
import tornado.web
import tornado.websocket
from tornado.ioloop import IOLoop
from tornado.iostream import _ERRNO_CONNRESET
from tornado.options import define, options, parse_command_line
from tornado.util import errno_from_exception


define('address', default='127.0.0.1', help='listen address')
define('port', default=8888, help='listen port', type=int)
define('debug', default=False, help='debug mode', type=bool)
define('policy', default='reject',
       help='missing host key policy, reject|autoadd|warning')
define('period', default=10, help='seconds for PeriodicCallback', type=int)


BUF_SIZE = 1024
DELAY = 3
workers = {}


class Worker(object):
    def __init__(self, ssh, chan, dst_addr):
        self.loop = IOLoop.current()
        self.ssh = ssh
        self.chan = chan
        self.dst_addr = dst_addr
        self.fd = chan.fileno()
        self.id = str(id(self))
        self.data_to_dst = []
        self.handler = None
        self.mode = IOLoop.READ

    def __call__(self, fd, events):
        if events & IOLoop.READ:
            self.on_read()
        if events & IOLoop.WRITE:
            self.on_write()
        if events & IOLoop.ERROR:
            self.close()

    def set_handler(self, handler):
        if not self.handler:
            self.handler = handler

    def update_handler(self, mode):
        if self.mode != mode:
            self.loop.update_handler(self.fd, mode)
            self.mode = mode

    def on_read(self):
        logging.debug('worker {} on read'.format(self.id))
        try:
            data = self.chan.recv(BUF_SIZE)
        except (OSError, IOError) as e:
            logging.error(e)
            if errno_from_exception(e) in _ERRNO_CONNRESET:
                self.close()
        else:
            logging.debug('"{}" from {}:{}'.format(data, *self.dst_addr))
            if not data:
                self.close()
                return

            logging.debug('"{}" to {}:{}'.format(data, *self.handler.src_addr))
            try:
                self.handler.write_message(data)
            except tornado.websocket.WebSocketClosedError:
                self.close()

    def on_write(self):
        logging.debug('worker {} on write'.format(self.id))
        if not self.data_to_dst:
            return

        data = ''.join(self.data_to_dst)
        logging.debug('"{}" to {}:{}'.format(data, *self.dst_addr))

        try:
            sent = self.chan.send(data)
        except (OSError, IOError) as e:
            logging.error(e)
            if errno_from_exception(e) in _ERRNO_CONNRESET:
                self.close()
            else:
                self.update_handler(IOLoop.WRITE)
        else:
            self.data_to_dst = []
            data = data[sent:]
            if data:
                self.data_to_dst.append(data)
                self.update_handler(IOLoop.WRITE)
            else:
                self.update_handler(IOLoop.READ)

    def close(self):
        logging.debug('Closing worker {}'.format(self.id))
        if self.handler:
            self.loop.remove_handler(self.fd)
            self.handler.close()
        self.chan.close()
        self.ssh.close()
        logging.info('Connection to {}:{} lost'.format(*self.dst_addr))


class MixinHandler(object):

    def __init__(self, *args, **kwargs):
        super(MixinHandler, self).__init__(*args, **kwargs)

    def get_client_addr(self):
        ip = self.request.headers.get('X-Real-Ip')
        port = self.request.headers.get('X-Real-Port')
        addr = None

        if ip and port:
            addr = (ip, int(port))
        elif ip or port:
            logging.warn('Wrong nginx configuration.')

        return addr


class IndexHandler(MixinHandler, tornado.web.RequestHandler):

    def get_privatekey(self):
        try:
            data = self.request.files.get('privatekey')[0]['body']
        except TypeError:
            return
        return data.decode('utf-8')

    def get_specific_pkey(self, pkeycls, privatekey, password):
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

    def get_pkey(self, privatekey, password):
        password = password.encode('utf-8') if password else None

        pkey = self.get_specific_pkey(paramiko.RSAKey, privatekey, password)\
            or self.get_specific_pkey(paramiko.DSSKey, privatekey, password)\
            or self.get_specific_pkey(paramiko.ECDSAKey, privatekey, password)\
            or self.get_specific_pkey(paramiko.Ed25519Key, privatekey,
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
        pkey = self.get_pkey(privatekey, password) if privatekey else None
        args = (hostname, port, username, password, pkey)
        logging.debug(args)
        return args

    def get_client_addr(self):
        return super(IndexHandler, self).get_client_addr() or self.request.\
                connection.stream.socket.getpeername()

    def ssh_connect(self):
        ssh = paramiko.SSHClient()
        ssh._system_host_keys = self.settings['system_host_keys']
        ssh._host_keys = self.settings['host_keys']
        ssh.set_missing_host_key_policy(self.settings['policy'])
        args = self.get_args()
        dst_addr = (args[0], args[1])
        logging.info('Connecting to {}:{}'.format(*dst_addr))
        try:
            ssh.connect(*args, timeout=6)
        except socket.error:
            raise ValueError('Unable to connect to {}:{}'.format(*dst_addr))
        except paramiko.BadAuthenticationType:
            raise ValueError('Authentication failed.')
        except paramiko.BadHostKeyException:
            raise ValueError('Bad host key.')
        chan = ssh.invoke_shell(term='xterm')
        chan.setblocking(0)
        worker = Worker(ssh, chan, dst_addr)
        IOLoop.current().call_later(DELAY, recycle, worker)
        return worker

    def get(self):
        self.render('index.html')

    def post(self):
        worker_id = None
        status = None

        try:
            worker = self.ssh_connect()
        except Exception as e:
            logging.error(traceback.format_exc())
            status = str(e)
        else:
            worker.src_addr = self.get_client_addr()
            worker_id = worker.id
            workers[worker_id] = worker

        self.write(dict(id=worker_id, status=status))


class WsockHandler(MixinHandler, tornado.websocket.WebSocketHandler):

    def __init__(self, *args, **kwargs):
        self.loop = IOLoop.current()
        self.worker_ref = None
        super(WsockHandler, self).__init__(*args, **kwargs)

    def get_client_addr(self):
        return super(WsockHandler, self).get_client_addr() or self.stream.\
                socket.getpeername()

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
            self.close()

    def on_message(self, message):
        logging.debug('"{}" from {}:{}'.format(message, *self.src_addr))
        worker = self.worker_ref()
        worker.data_to_dst.append(message)
        worker.on_write()

    def on_close(self):
        logging.info('Disconnected from {}:{}'.format(*self.src_addr))
        worker = self.worker_ref() if self.worker_ref else None
        if worker:
            worker.close()


def recycle(worker):
    if worker.handler:
        return
    logging.debug('Recycling worker {}'.format(worker.id))
    workers.pop(worker.id, None)
    worker.close()


def get_host_keys(path):
    if os.path.exists(path) and os.path.isfile(path):
        return paramiko.hostkeys.HostKeys(filename=path)
    return paramiko.hostkeys.HostKeys()


def save_host_keys(host_keys, filename):
    length = len(host_keys)
    if length != host_keys._last_len:
        logging.info('Updating {}'.format(filename))
        host_keys.save(filename)
        host_keys._last_len = length


def get_policy_class(policy):
    origin_policy = policy
    policy = policy.lower()
    if not policy.endswith('policy'):
        policy += 'policy'

    dic = {k.lower(): v for k, v in vars(paramiko.client).items() if type(v)
           is type and issubclass(v, paramiko.client.MissingHostKeyPolicy)}
    try:
        cls = dic[policy]
    except KeyError:
        raise ValueError('Unknown policy {!r}'.format(origin_policy))
    return cls


def main():
    parse_command_line()
    base_dir = os.path.dirname(__file__)
    filename = os.path.join(base_dir, 'known_hosts')
    host_keys = get_host_keys(filename)
    system_host_keys = get_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
    policy_class = get_policy_class(options.policy)

    if policy_class is paramiko.client.AutoAddPolicy:
        host_keys.save(filename)  # for permssion test
        host_keys._last_len = len(host_keys)
        tornado.ioloop.PeriodicCallback(
            lambda: save_host_keys(host_keys, filename),
            options.period * 1000  # milliseconds
        ).start()
    elif policy_class is paramiko.client.RejectPolicy:
        if not host_keys and not system_host_keys:
            raise ValueError('Empty known_hosts with reject policy?')

    settings = {
        'template_path': os.path.join(base_dir, 'templates'),
        'static_path': os.path.join(base_dir, 'static'),
        'cookie_secret': uuid.uuid1().hex,
        'xsrf_cookies': True
    }

    handlers = [
        (r'/',   IndexHandler),
        (r'/ws', WsockHandler)
    ]

    settings.update(
        debug=options.debug,
        host_keys=host_keys,
        system_host_keys=system_host_keys,
        policy=policy_class()
    )

    app = tornado.web.Application(handlers, **settings)
    app.listen(options.port, options.address)
    logging.info('Listening on {}:{}'.format(options.address, options.port))
    IOLoop.current().start()


if __name__ == '__main__':
    main()
