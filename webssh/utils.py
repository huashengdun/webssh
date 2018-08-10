import ipaddress


def to_str(s):
    if isinstance(s, bytes):
        return s.decode('utf-8')
    return s


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
