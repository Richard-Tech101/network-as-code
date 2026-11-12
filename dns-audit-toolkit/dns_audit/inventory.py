"""Device inventory loaded from a CSV file."""

import csv
import os
from dataclasses import dataclass

AUDIT_ROLES = ('host', 'dns')


@dataclass
class Device:
    name: str
    address: str          # static IPv4 address, or "dhcp"
    role: str             # host | dns | router | skip
    os: str               # linux | vyos | ...
    username: str = ''
    password_env: str = ''  # name of the environment variable holding the password

    @property
    def is_dhcp(self):
        return self.address.lower() == 'dhcp'

    @property
    def auditable(self):
        return self.role in AUDIT_ROLES

    @property
    def password(self):
        """Password from the environment. None means "use SSH keys / agent"."""
        return os.environ.get(self.password_env) if self.password_env else None


def load_inventory(path):
    devices = []
    with open(path, newline='') as f:
        for row in csv.DictReader(f):
            row = {k.strip().lower(): (v or '').strip() for k, v in row.items()}
            if not row.get('name'):
                continue
            devices.append(Device(
                name=row['name'],
                address=row.get('address', ''),
                role=row.get('role', 'host').lower() or 'host',
                os=row.get('os', 'linux').lower() or 'linux',
                username=row.get('username', ''),
                password_env=row.get('password_env', ''),
            ))
    return devices


def find(devices, name):
    for d in devices:
        if d.name.lower() == name.lower():
            return d
    raise KeyError(f'{name} is not in the inventory')
