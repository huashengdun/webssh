import io
import logging
import os.path
import socket
import traceback
import uuid
import weakref
import paramiko
import tornado.web
import tornado.websocket
from tornado.ioloop import IOLoop
from tornado.options import define, options, parse_command_line


define('address', default='127.0.0.1', help='listen address')
define('port', default=8888, help='listen port', type=int)


BUF_SIZE = 1024
DELAY = 3
base_dir = os.path.dirname(__file__)
workers = {}


def recycle(worker):
    if worker.handler:
        return
    logging.debug('Recycling worker {}'.format(worker.id))
    workers.pop(worker.id, None)
    worker.close()


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

    def __call__(self, fd, events):
        if events & IOLoop.READ:
            self.on_read()
        if events & IOLoop.WRITE:
            self.on_write()
        if events & IOLoop.ERROR:
            self.close()

    def set_handler(self, handler):
        if self.handler:
            return
        self.handler = handler

    def on_read(self):
        logging.debug('worker {} on read'.format(self.id))
        data = self.chan.recv(BUF_SIZE)
        logging.debug('"{}" from {}'.format(data, self.dst_addr))
        if not data:
            self.close()
            return

        logging.debug('"{}" to {}'.format(data, self.handler.src_addr))
        try:
            self.handler.write_message(data)
        except tornado.websocket.WebSocketClosedError:
            self.close()

    def on_write(self):
        logging.debug('worker {} on write'.format(self.id))
        if not self.data_to_dst:
            return
        data = ''.join(self.data_to_dst)
        self.data_to_dst = []
        logging.debug('"{}" to {}'.format(data, self.dst_addr))
        try:
            sent = self.chan.send(data)
        except socket.error as e:
            logging.error(e)
            self.close()
        else:
            data = data[sent:]
            if data:
                self.data_to_dst.append(data)
                self.loop.update_handler(self.fd, IOLoop.WRITE)
            else:
                self.loop.update_handler(self.fd, IOLoop.READ)

    def close(self):
        logging.debug('Closing worker {}'.format(self.id))
        if self.handler:
            self.loop.remove_handler(self.fd)
            self.handler.close()
        self.chan.close()
        self.ssh.close()
        logging.info('Connection to {} lost'.format(self.dst_addr))


class IndexHandler(tornado.web.RequestHandler):
    def get_privatekey(self):
        try:
            return self.request.files.get('privatekey')[0]['body']
        except TypeError:
            pass

    def get_pkey(self, privatekey, password):
        if not password:
            password = None

        spkey = io.StringIO(privatekey.decode('utf-8'))

        try:
            pkey = paramiko.RSAKey.from_private_key(spkey, password=password)
        except paramiko.SSHException:
            pkey = paramiko.DSSKey.from_private_key(spkey, password=password)
        return pkey

    def get_port(self):
        value = self.get_value('port')
        try:
            port = int(value)
        except ValueError:
            port = 0

        if 0 < port < 65536:
            return port

        raise ValueError("Invalid port {}".format(value))

    def get_value(self, name):
        value = self.get_argument(name)
        if not value:
            raise ValueError("Empty {}".format(name))
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

    def ssh_connect(self):
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        args = self.get_args()
        dst_addr = '{}:{}'.format(*args[:2])
        logging.info('Connecting to {}'.format(dst_addr))
        ssh.connect(*args)
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
            worker_id = worker.id
            workers[worker_id] = worker

        self.write(dict(id=worker_id, status=status))


class WsockHandler(tornado.websocket.WebSocketHandler):

    def __init__(self, *args, **kwargs):
        self.loop = IOLoop.current()
        self.worker_ref = None
        super(self.__class__, self).__init__(*args, **kwargs)

    def check_origin(self, origin):
        return True

    def open(self):
        self.src_addr = '{}:{}'.format(*self.stream.socket.getpeername())
        logging.info('Connected from {}'.format(self.src_addr))
        worker = workers.pop(self.get_argument('id'), None)
        if not worker:
            self.close(reason='Invalid worker id')
            return
        self.set_nodelay(True)
        worker.set_handler(self)
        self.worker_ref = weakref.ref(worker)
        self.loop.add_handler(worker.fd, worker, IOLoop.READ)

    def on_message(self, message):
        logging.debug('"{}" from {}'.format(message, self.src_addr))
        worker = self.worker_ref()
        worker.data_to_dst.append(message)
        worker.on_write()

    def on_close(self):
        logging.info('Disconnected from {}'.format(self.src_addr))
        worker = self.worker_ref() if self.worker_ref else None
        if worker:
            worker.close()


def main():
    settings = {
        'template_path': os.path.join(base_dir, 'templates'),
        'static_path': os.path.join(base_dir, 'static'),
        'cookie_secret': uuid.uuid1().hex,
        'xsrf_cookies': True,
        'debug': True
    }

    handlers = [
        (r'/',   IndexHandler),
        (r'/ws', WsockHandler)
    ]

    parse_command_line()
    app = tornado.web.Application(handlers, **settings)
    app.listen(options.port, options.address)
    logging.info('Listening on {}:{}'.format(options.address, options.port))
    IOLoop.current().start()


if __name__ == '__main__':
    main()
