#!/usr/bin/env python

# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

import random
import socket
# import sys
import threading
# import traceback
import paramiko

from binascii import hexlify
from paramiko.py3compat import u, decodebytes
from tests.utils import make_tests_data_path


# setup logging
paramiko.util.log_to_file(make_tests_data_path('sshserver.log'))

host_key = paramiko.RSAKey(filename=make_tests_data_path('test_rsa.key'))
# host_key = paramiko.DSSKey(filename='test_dss.key')

print('Read key: ' + u(hexlify(host_key.get_fingerprint())))

banner = u'\r\n\u6b22\u8fce\r\n'
event_timeout = 5


class Server(paramiko.ServerInterface):
    # 'data' is the output of base64.b64encode(key)
    # (using the "user_rsa_key" files)
    data = (b'AAAAB3NzaC1yc2EAAAABIwAAAIEAyO4it3fHlmGZWJaGrfeHOVY7RWO3P9M7hp'
            b'fAu7jJ2d7eothvfeuoRFtJwhUmZDluRdFyhFY/hFAh76PJKGAusIqIQKlkJxMC'
            b'KDqIexkgHAfID/6mqvmnSJf0b5W8v5h2pI/stOSwTQ+pxVhwJ9ctYDhRSlF0iT'
            b'UWT10hcuO4Ks8=')
    good_pub_key = paramiko.RSAKey(data=decodebytes(data))

    encodings = ['UTF-8', 'GBK', 'UTF-8\r\n', 'GBK\r\n']

    def __init__(self):
        self.shell_event = threading.Event()
        self.exec_event = threading.Event()
        self.encoding = random.choice(self.encodings)

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        print('Auth attempt with username: {!r} & password: {!r}'.format(username, password)) # noqa
        if (username in ['robey', 'bar', 'foo']) and (password == 'foo'):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        print('Auth attempt with username: {!r} & key: {!r}'.format(username, u(hexlify(key.get_fingerprint())))) # noqa
        if (username in ['robey', 'keyonly']) and (key == self.good_pub_key):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        if username == 'keyonly':
            return 'publickey'
        return 'password,publickey'

    def check_channel_exec_request(self, channel, command):
        if command != b'locale charmap':
            ret = False
        else:
            ret = True
            channel.send(self.encoding)
            channel.shutdown(1)
        self.exec_event.set()
        return ret

    def check_channel_shell_request(self, channel):
        self.shell_event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        return True

    def check_channel_window_change_request(self, channel, width, height,
                                            pixelwidth, pixelheight):
        channel.send('resized')
        return True


def run_ssh_server(port=2200, running=True):
    # now connect
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(100)

    while running:
        client, addr = sock.accept()
        print('Got a connection!')

        t = paramiko.Transport(client)
        t.load_server_moduli()
        t.add_server_key(host_key)
        server = Server()
        try:
            t.start_server(server=server)
        except Exception as e:
            print(e)
            continue

        # wait for auth
        chan = t.accept(2)
        if chan is None:
            print('*** No channel.')
            continue

        username = t.get_username()
        print('{} Authenticated!'.format(username))

        server.shell_event.wait(timeout=event_timeout)
        if not server.shell_event.is_set():
            print('*** Client never asked for a shell.')
            continue

        server.exec_event.wait(timeout=event_timeout)
        if not server.exec_event.is_set():
            print('*** Client never asked for a command.')
            continue

        # chan.send('\r\n\r\nWelcome!\r\n\r\n')
        print(server.encoding)
        chan.send(banner.encode(server.encoding.strip()))
        if username == 'bar':
            msg = chan.recv(1024)
            chan.send(msg)
        elif username == 'foo':
            lst = []
            while True:
                msg = chan.recv(32 * 1024)
                lst.append(msg)
                if msg.endswith(b'\r\n\r\n'):
                    break
            data = b''.join(lst)
            while data:
                s = chan.send(data)
                data = data[s:]
        else:
            chan.close()
            t.close()
            client.close()

    try:
        sock.close()
    except Exception:
        pass


if __name__ == '__main__':
    run_ssh_server()
