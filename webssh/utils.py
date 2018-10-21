import ipaddress
import re
import socket

try:
    from types import UnicodeType
except ImportError:
    UnicodeType = str


numeric = re.compile(r'[0-9]+$')
allowed = re.compile(r'(?!-)[a-z0-9-]{1,63}(?<!-)$', re.IGNORECASE)

default_public_ipv4addr = ipaddress.ip_address(u'0.0.0.0')
default_public_ipv6addr = ipaddress.ip_address(u'::')


def to_str(bstr, encoding='utf-8'):
    if isinstance(bstr, bytes):
        return bstr.decode(encoding)
    return bstr


def to_bytes(ustr, encoding='utf-8'):
    if isinstance(ustr, UnicodeType):
        return ustr.encode(encoding)
    return ustr


def to_int(string):
    try:
        return int(string)
    except (TypeError, ValueError):
        pass


def to_ip_address(ipstr):
    return ipaddress.ip_address(to_str(ipstr))


def is_valid_ip_address(ipstr):
    try:
        to_ip_address(ipstr)
    except ValueError:
        return False
    return True


def is_valid_port(port):
    return 0 < port < 65536


def is_ip_hostname(hostname):
    it = iter(hostname)
    if next(it) == '[':
        return True
    for ch in it:
        if ch != '.' and not ch.isdigit():
            return False
    return True


def is_valid_hostname(hostname):
    if hostname[-1] == '.':
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False

    labels = hostname.split('.')

    # the TLD must be not all-numeric
    if numeric.match(labels[-1]):
        return False

    return all(allowed.match(label) for label in labels)


def get_ips_by_name(name):
    if name == '':
        return {'0.0.0.0', '::'}
    ret = socket.getaddrinfo(name, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
    return {t[4][0] for t in ret}


def on_public_network_interface(ip):
    ipaddr = to_ip_address(ip)
    if ipaddr == default_public_ipv4addr or ipaddr == default_public_ipv6addr:
        return True

    if not ipaddr.is_private:
        return True


def is_name_open_to_public(name):
    for ip in get_ips_by_name(name):
        if on_public_network_interface(ip):
            return True
