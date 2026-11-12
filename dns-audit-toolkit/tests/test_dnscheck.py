import unittest

from dns_audit.dnscheck import (COMPROMISED, MISCONFIGURED, OK, DnsSnapshot, classify,
                                parse_nameservers, parse_resolvectl)

TRUSTED = ['10.0.0.53', '10.0.1.53']


class ParseTests(unittest.TestCase):
    def test_nameservers_ignore_comments_and_duplicates(self):
        text = '# generated\nnameserver 10.0.0.53  # primary\nnameserver 10.0.0.53\nsearch example.internal\n'
        self.assertEqual(parse_nameservers(text), ['10.0.0.53'])

    def test_resolvectl_global_and_links(self):
        text = 'Global: 10.0.0.53\nLink 2 (eth0): 10.0.1.53 198.51.100.7\nLink 3 (eth1):'
        self.assertEqual(parse_resolvectl(text), ['10.0.0.53', '10.0.1.53', '198.51.100.7'])


class ClassifyTests(unittest.TestCase):
    def test_static_rogue_server(self):
        v = classify(DnsSnapshot(resolv_conf='nameserver 198.51.100.7\n'), TRUSTED)
        self.assertEqual(v.status, COMPROMISED)
        self.assertEqual(v.untrusted, ['198.51.100.7'])

    def test_stub_resolver_is_followed_to_upstream(self):
        snap = DnsSnapshot(resolv_conf='nameserver 127.0.0.53\n',
                           resolvectl='Global:\nLink 2 (eth0): 10.0.0.53 10.0.1.53')
        v = classify(snap, TRUSTED)
        self.assertEqual(v.status, OK)
        self.assertTrue(v.uses_stub)
        self.assertEqual(v.servers_in_use, TRUSTED)

    def test_stub_resolver_hiding_a_rogue_upstream(self):
        snap = DnsSnapshot(resolv_conf='nameserver 127.0.0.53\n', resolvectl='Link 2 (eth0): 198.51.100.7')
        self.assertEqual(classify(snap, TRUSTED).status, COMPROMISED)

    def test_one_good_one_bad_is_still_compromised(self):
        snap = DnsSnapshot(resolv_conf='nameserver 10.0.0.53\nnameserver 8.8.8.8\n')
        self.assertEqual(classify(snap, TRUSTED).untrusted, ['8.8.8.8'])

    def test_stub_with_no_upstream_is_misconfigured(self):
        snap = DnsSnapshot(resolv_conf='nameserver 127.0.0.53\n', resolvectl='Global:\nLink 2 (eth0):')
        self.assertEqual(classify(snap, TRUSTED).status, MISCONFIGURED)

    def test_falls_back_to_upstream_file_when_resolved_is_down(self):
        snap = DnsSnapshot(resolv_conf='nameserver 127.0.0.53\n',
                           resolvectl='Failed to get global data: Unit not found.',
                           upstream_conf='nameserver 198.51.100.7\n')
        self.assertEqual(classify(snap, TRUSTED).untrusted, ['198.51.100.7'])

    def test_dns_server_using_itself(self):
        snap = DnsSnapshot(resolv_conf='nameserver 127.0.0.1\n')
        self.assertEqual(classify(snap, TRUSTED, is_dns_server=True).status, OK)
        self.assertEqual(classify(snap, TRUSTED, is_dns_server=False).status, MISCONFIGURED)


if __name__ == '__main__':
    unittest.main()
