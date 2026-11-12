"""Find the current IP of DHCP clients by reading the router's lease table."""

import re

IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def parse_vyos_leases(text):
    """Parse `show dhcp server leases` output from VyOS.

    Returns {hostname_lowercase: ip} for active leases. Column positions are
    taken from the header line, so extra or reordered columns are fine.
    """
    lines = [line for line in text.splitlines() if line.strip()]
    header = next((line for line in lines if 'IP Address' in line or 'IP address' in line), None)
    columns = re.split(r'\s{2,}', header.strip()) if header else []
    col = {name.lower(): i for i, name in enumerate(columns)}

    leases = {}
    for line in lines:
        if line is header or set(line.strip()) <= {'-', ' '}:
            continue
        fields = re.split(r'\s{2,}', line.strip())
        ip = fields[0] if fields and IPV4.fullmatch(fields[0]) else None
        if not ip:
            continue
        state = fields[col['state']].lower() if 'state' in col and col['state'] < len(fields) else 'active'
        host = fields[col['hostname']] if 'hostname' in col and col['hostname'] < len(fields) else ''
        if state != 'active' or not host:
            continue
        leases[host.lower().split('.')[0]] = ip
    return leases


def get_vyos_leases(router, timeout=15):
    """Log in to a VyOS router with netmiko and return its active leases."""
    from netmiko import ConnectHandler  # imported here so the rest works without netmiko

    conn = ConnectHandler(device_type='vyos', host=router.address, username=router.username,
                          password=router.password, timeout=timeout)
    try:
        return parse_vyos_leases(conn.send_command('show dhcp server leases'))
    finally:
        conn.disconnect()


def resolve_address(device, leases):
    """Return (ip, source) for a device: static from inventory, or its current DHCP lease."""
    if not device.is_dhcp:
        return device.address, 'static'
    ip = leases.get(device.name.lower())
    return (ip, 'dhcp-lease') if ip else (None, 'dhcp-unresolved')
