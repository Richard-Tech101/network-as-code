"""Read and classify the DNS resolver configuration of a Linux host."""

import re
from dataclasses import dataclass, field

IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

OK = 'OK'
COMPROMISED = 'COMPROMISED'      # uses at least one untrusted DNS server
MISCONFIGURED = 'MISCONFIGURED'  # no usable DNS server at all


@dataclass
class DnsSnapshot:
    resolv_conf: str = ''
    resolv_conf_target: str = ''
    resolvectl: str = ''
    upstream_conf: str = ''


@dataclass
class DnsVerdict:
    status: str
    message: str
    resolv_conf_servers: list = field(default_factory=list)
    uses_stub: bool = False
    upstream_servers: list = field(default_factory=list)
    servers_in_use: list = field(default_factory=list)
    untrusted: list = field(default_factory=list)


def parse_nameservers(text):
    """`nameserver` entries from a resolv.conf style file, in order, without duplicates."""
    found = []
    for line in text.splitlines():
        parts = line.split('#', 1)[0].split()
        if len(parts) >= 2 and parts[0] == 'nameserver' and parts[1] not in found:
            found.append(parts[1])
    return found


def parse_resolvectl(text):
    """IPv4 servers from `resolvectl dns` (lines like "Link 2 (eth0): 10.0.0.53")."""
    found = []
    for line in text.splitlines():
        _, sep, rest = line.partition(':')
        if sep:
            for ip in IPV4.findall(rest):
                if ip not in found:
                    found.append(ip)
    return found


def collect(session):
    """Gather everything needed to judge a host's DNS setup."""
    return DnsSnapshot(
        resolv_conf=session.output('cat /etc/resolv.conf'),
        resolv_conf_target=session.output('readlink -f /etc/resolv.conf'),
        resolvectl=session.output('SYSTEMD_PAGER=cat resolvectl dns 2>&1'),
        upstream_conf=session.output('cat /run/systemd/resolve/resolv.conf 2>/dev/null'),
    )


def classify(snapshot, trusted, stub_resolvers=('127.0.0.53',), is_dns_server=False):
    """Decide which DNS servers a host really uses and whether they are trusted.

    A stub resolver such as 127.0.0.53 says nothing on its own, so when one is
    configured we look at what systemd-resolved forwards to instead.
    """
    entries = parse_nameservers(snapshot.resolv_conf)
    uses_stub = any(ns in stub_resolvers for ns in entries)
    direct = [ns for ns in entries if not ns.startswith('127.')]

    upstream = []
    if uses_stub or not entries:
        for ns in parse_resolvectl(snapshot.resolvectl) + parse_nameservers(snapshot.upstream_conf):
            if not ns.startswith('127.') and ns not in upstream:
                upstream.append(ns)

    in_use = list(dict.fromkeys(direct + upstream))
    untrusted = [ns for ns in in_use if ns not in trusted]

    if untrusted:
        status, message = COMPROMISED, 'untrusted DNS server ' + ', '.join(untrusted)
    elif not in_use and is_dns_server and '127.0.0.1' in entries:
        status, message = OK, 'DNS server resolving through its own local service'
    elif not in_use:
        status, message = MISCONFIGURED, 'no trusted DNS server configured'
    else:
        status, message = OK, 'trusted DNS servers only'

    return DnsVerdict(status, message, entries, uses_stub, upstream, in_use, untrusted)
