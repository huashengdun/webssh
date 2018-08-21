import ipaddress
import re

try:
    from types import UnicodeType
except ImportError:
    UnicodeType = str


numeric = re.compile(r'[0-9]+$')
allowed = re.compile(r'(?!-)[a-z0-9-]{1,63}(?<!-)$', re.IGNORECASE)


def to_str(bstr, encoding='utf-8'):
    if isinstance(bstr, bytes):
        return bstr.decode(encoding)
    return bstr


def to_bytes(ustr, encoding='utf-8'):
    if isinstance(ustr, UnicodeType):
        return ustr.encode(encoding)
    return ustr


def is_valid_ipv4_address(ipstr):
    ipstr = to_str(ipstr)
    try:
        ipaddress.IPv4Address(ipstr)
    except ipaddress.AddressValueError:
        return False
    return True


def is_valid_ipv6_address(ipstr):
    ipstr = to_str(ipstr)
    try:
        ipaddress.IPv6Address(ipstr)
    except ipaddress.AddressValueError:
        return False
    return True


def is_valid_port(port):
    return 0 < port < 65536


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
