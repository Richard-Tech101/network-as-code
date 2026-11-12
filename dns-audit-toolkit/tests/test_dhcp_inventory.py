import tempfile
import unittest
from pathlib import Path

from dns_audit.dhcp import parse_vyos_leases, resolve_address
from dns_audit.inventory import load_inventory

VYOS_LEASES = """\
IP Address    MAC address        State    Lease start                Lease expiration           Remaining    Pool    Hostname    Origin
------------  -----------------  -------  -------------------------  -------------------------  -----------  ------  ----------  --------
10.0.10.100   02:00:00:00:00:01  active   2026-01-01 10:00:00+00:00  2026-01-02 10:00:00+00:00  23:00:00     LAN10   ws1         local
10.0.10.101   02:00:00:00:00:02  expired  2026-01-01 08:00:00+00:00  2026-01-01 09:00:00+00:00  0:00:00      LAN10   ws2         local
10.0.10.102   02:00:00:00:00:02  active   2026-01-01 10:05:00+00:00  2026-01-02 10:05:00+00:00  23:05:00     LAN10   WS2.example.internal  local
"""


class LeaseTests(unittest.TestCase):
    def test_active_leases_only_and_hostnames_normalised(self):
        self.assertEqual(parse_vyos_leases(VYOS_LEASES), {'ws1': '10.0.10.100', 'ws2': '10.0.10.102'})

    def test_empty_output(self):
        self.assertEqual(parse_vyos_leases(''), {})


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = Path(self.tmp.name) / 'inv.csv'
        path.write_text('name,address,role,os,username,password_env\n'
                        'app1,10.0.2.10,host,linux,netops,X\n'
                        'ws1,DHCP,host,linux,netops,X\n'
                        'switch1,,skip,ovs,,\n')
        self.devices = load_inventory(path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_roles_and_dhcp_flag(self):
        self.assertEqual([d.name for d in self.devices if d.auditable], ['app1', 'ws1'])
        self.assertTrue(self.devices[1].is_dhcp)

    def test_resolve_address(self):
        leases = {'ws1': '10.0.10.100'}
        self.assertEqual(resolve_address(self.devices[0], leases), ('10.0.2.10', 'static'))
        self.assertEqual(resolve_address(self.devices[1], leases), ('10.0.10.100', 'dhcp-lease'))
        self.assertEqual(resolve_address(self.devices[1], {}), (None, 'dhcp-unresolved'))


if __name__ == '__main__':
    unittest.main()
