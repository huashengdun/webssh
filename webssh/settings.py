import logging
import os.path
import ssl
import sys

from tornado.options import define
from webssh.policy import (
    load_host_keys, get_policy_class, check_policy_setting
)
from webssh.utils import (
    to_ip_address, parse_origin_from_url, is_valid_encoding
)
from webssh._version import __version__


def print_version(flag):
    if flag:
        print(__version__)
        sys.exit(0)


define('address', default='', help='Listen address')
define('port', type=int, default=8888,  help='Listen port')
define('ssladdress', default='', help='SSL listen address')
define('sslport', type=int, default=4433,  help='SSL listen port')
define('certfile', default='', help='SSL certificate file')
define('keyfile', default='', help='SSL private key file')
define('debug', type=bool, default=False, help='Debug mode')
define('policy', default='warning',
       help='Missing host key policy, reject|autoadd|warning')
define('hostfile', default='', help='User defined host keys file')
define('syshostfile', default='', help='System wide host keys file')
define('tdstream', default='', help='Trusted downstream, separated by comma')
define('redirect', type=bool, default=True, help='Redirecting http to https')
define('fbidhttp', type=bool, default=True,
       help='Forbid public plain http incoming requests')
define('xheaders', type=bool, default=True, help='Support xheaders')
define('xsrf', type=bool, default=True, help='CSRF protection')
define('origin', default='same', help='''Origin policy,
'same': same origin policy, matches host name and port number;
'primary': primary domain policy, matches primary domain only;
'<domains>': custom domains policy, matches any domain in the <domains> list
separated by comma;
'*': wildcard policy, matches any domain, allowed in debug mode only.''')
define('wpintvl', type=float, default=0, help='Websocket ping interval')
define('timeout', type=float, default=3, help='SSH connection timeout')
define('delay', type=float, default=3, help='The delay to call recycle_worker')
define('maxconn', type=int, default=20,
       help='Maximum live connections (ssh sessions) per client')
define('font', default='', help='custom font filename')
define('encoding', default='',
       help='''The default character encoding of ssh servers.
Example: --encoding='utf-8' to solve the problem with some switches&routers''')
define('version', type=bool, help='Show version information',
       callback=print_version)


base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
font_dirs = ['webssh', 'static', 'css', 'fonts']
max_body_size = 1 * 1024 * 1024


class Font(object):

    def __init__(self, filename, dirs):
        self.family = self.get_family(filename)
        self.url = self.get_url(filename, dirs)

    def get_family(self, filename):
        return filename.split('.')[0]

    def get_url(self, filename, dirs):
        return '/'.join(dirs + [filename])


def get_app_settings(options):
    settings = dict(
        template_path=os.path.join(base_dir, 'webssh', 'templates'),
        static_path=os.path.join(base_dir, 'webssh', 'static'),
        websocket_ping_interval=options.wpintvl,
        debug=options.debug,
        xsrf_cookies=options.xsrf,
        font=Font(
            get_font_filename(options.font,
                              os.path.join(base_dir, *font_dirs)),
            font_dirs[1:]
        ),
        origin_policy=get_origin_setting(options)
    )
    return settings


def get_server_settings(options):
    settings = dict(
        xheaders=options.xheaders,
        max_body_size=max_body_size,
        trusted_downstream=get_trusted_downstream(options.tdstream)
    )
    return settings


def get_host_keys_settings(options):
    if not options.hostfile:
        host_keys_filename = os.path.join(base_dir, 'known_hosts')
    else:
        host_keys_filename = options.hostfile
    host_keys = load_host_keys(host_keys_filename)

    if not options.syshostfile:
        filename = os.path.expanduser('~/.ssh/known_hosts')
    else:
        filename = options.syshostfile
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


def get_trusted_downstream(tdstream):
    result = set()
    for ip in tdstream.split(','):
        ip = ip.strip()
        if ip:
            to_ip_address(ip)
            result.add(ip)
    return result


def get_origin_setting(options):
    if options.origin == '*':
        if not options.debug:
            raise ValueError(
                'Wildcard origin policy is only allowed in debug mode.'
            )
        else:
            return '*'

    origin = options.origin.lower()
    if origin in ['same', 'primary']:
        return origin

    origins = set()
    for url in origin.split(','):
        orig = parse_origin_from_url(url)
        if orig:
            origins.add(orig)

    if not origins:
        raise ValueError('Empty origin list')

    return origins


def get_font_filename(font, font_dir):
    filenames = {f for f in os.listdir(font_dir) if not f.startswith('.')
                 and os.path.isfile(os.path.join(font_dir, f))}
    if font:
        if font not in filenames:
            raise ValueError(
                'Font file {!r} not found'.format(os.path.join(font_dir, font))
            )
    elif filenames:
        font = filenames.pop()

    return font


def check_encoding_setting(encoding):
    if encoding and not is_valid_encoding(encoding):
        raise ValueError('Unknown character encoding {!r}.'.format(encoding))
