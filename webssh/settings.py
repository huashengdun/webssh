import logging
import os.path
import ssl
import sys

from tornado.options import define
from webssh.policy import (
    load_host_keys, get_policy_class, check_policy_setting
)
from webssh.utils import to_ip_address
from webssh._version import __version__


def print_version(flag):
    if flag:
        print(__version__)
        sys.exit(0)


define('address', default='127.0.0.1', help='Listen address')
define('port', type=int, default=8888,  help='Listen port')
define('sslAddress', default='0.0.0.0', help='SSL listen address')
define('sslPort', type=int, default=4433,  help='SSL listen port')
define('certfile', default='', help='SSL certificate file')
define('keyfile', default='', help='SSL private key file')
define('debug', type=bool, default=False, help='Debug mode')
define('policy', default='warning',
       help='Missing host key policy, reject|autoadd|warning')
define('hostFile', default='', help='User defined host keys file')
define('sysHostFile', default='', help='System wide host keys file')
define('proxies', default='', help='trusted downstream, separated by comma')
define('wpIntvl', type=int, default=0, help='Websocket ping interval')
define('version', type=bool, help='Show version information',
       callback=print_version)


base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
max_body_size = 1 * 1024 * 1024
swallow_http_errors = True
xheaders = True


def get_app_settings(options):
    settings = dict(
        template_path=os.path.join(base_dir, 'webssh', 'templates'),
        static_path=os.path.join(base_dir, 'webssh', 'static'),
        websocket_ping_interval=options.wpIntvl,
        debug=options.debug,
        xsrf_cookies=True
    )
    return settings


def get_host_keys_settings(options):
    if not options.hostFile:
        host_keys_filename = os.path.join(base_dir, 'known_hosts')
    else:
        host_keys_filename = options.hostFile
    host_keys = load_host_keys(host_keys_filename)

    if not options.sysHostFile:
        filename = os.path.expanduser('~/.ssh/known_hosts')
    else:
        filename = options.sysHostFile
    system_host_keys = load_host_keys(filename)

    settings = dict(
        host_keys=host_keys,
        system_host_keys=system_host_keys,
        host_keys_filename=host_keys_filename
    )
    return settings


def get_policy_setting(options, host_keys_settings):
    policy_class = get_policy_class(options.policy)
    logging.info(policy_class.__name__)
    check_policy_setting(policy_class, host_keys_settings)
    return policy_class()


def get_ssl_context(options):
    if not options.certfile and not options.keyfile:
        return None
    elif not options.certfile:
        raise ValueError('certfile is not provided')
    elif not options.keyfile:
        raise ValueError('keyfile is not provided')
    elif not os.path.isfile(options.certfile):
        raise ValueError('File {!r} does not exist'.format(options.certfile))
    elif not os.path.isfile(options.keyfile):
        raise ValueError('File {!r} does not exist'.format(options.keyfile))
    else:
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(options.certfile, options.keyfile)
        return ssl_ctx


def get_trusted_downstream(options):
    proxies = set()
    for ip in options.proxies.split(','):
        ip = ip.strip()
        if ip:
            to_ip_address(ip)
            proxies.add(ip)
    return proxies
