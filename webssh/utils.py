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


def is_same_primary_domain(domain1, domain2):
    i = -1
    dots = 0
    l1 = len(domain1)
    l2 = len(domain2)
    m = min(l1, l2)

    while i >= -m:
        c1 = domain1[i]
        c2 = domain2[i]

        if c1 == c2:
            if c1 == '.':
                dots += 1
                if dots == 2:
                    return True
        else:
            return False

        i -= 1

    if l1 == l2:
        return True

    if dots == 0:
        return False

    c = domain1[i] if l1 > m else domain2[i]
    return c == '.'
