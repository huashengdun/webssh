import ipaddress

try:
    from types import UnicodeType
except ImportError:
    UnicodeType = str


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
