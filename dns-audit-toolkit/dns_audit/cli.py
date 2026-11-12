"""Command line entry point: python -m dns_audit <command>."""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib

from . import dhcp, dnscheck, inventory, notify, remediate, service
from .ping import ping
from .sshclient import connect


def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def load_config(path):
    with open(path, 'rb') as f:
        return tomllib.load(f)


def results_path(cfg, name):
    folder = Path(cfg.get('output', {}).get('dir', 'results'))
    folder.mkdir(parents=True, exist_ok=True)
    return folder / name


def save(cfg, name, data):
    path = results_path(cfg, name)
    path.write_text(json.dumps(data, indent=2), encoding='utf-8')
    print(f'\nSaved {path}')


def load(cfg, name, hint):
    path = results_path(cfg, name)
    if not path.exists():
        sys.exit(f'{path} not found - run "{hint}" first')
    return json.loads(path.read_text(encoding='utf-8'))


def banner(title):
    print('=' * 90)
    print(f'{title}    {now()}')
    print('=' * 90)


# ---------------------------------------------------------------- audit

def cmd_audit(cfg, devices, args):
    banner('DNS audit')
    trusted = cfg['dns']['trusted_servers']
    stubs = cfg['dns'].get('stub_resolvers', ['127.0.0.53'])
    dns_hosts = {n.lower() for n in cfg.get('dns_service', {}).get('hosts', [])}
    targets = [d for d in devices if d.auditable]
    print(f"Trusted DNS: {', '.join(trusted)}   Targets: {len(targets)}   "
          f"Skipped: {', '.join(d.name for d in devices if not d.auditable) or '-'}")

    leases = {}
    dhcp_cfg = cfg.get('dhcp', {})
    if any(d.is_dhcp for d in targets) and dhcp_cfg.get('provider') == 'vyos':
        router = inventory.find(devices, dhcp_cfg['router'])
        try:
            leases = dhcp.get_vyos_leases(router)
            print(f'DHCP leases from {router.name}: {len(leases)} active')
        except Exception as e:
            print(f'[WARN] could not read DHCP leases from {router.name}: {e}')

    results = []
    for d in targets:
        ip, source = dhcp.resolve_address(d, leases)
        entry = {'name': d.name, 'ip': ip, 'ip_source': source, 'checked_at': now(),
                 'reachable': ping(ip)}
        try:
            with connect(d, ip, cfg.get('ssh', {}).get('timeout', 10)) as s:
                verdict = dnscheck.classify(dnscheck.collect(s), trusted, stubs, d.name.lower() in dns_hosts)
            entry.update(status=verdict.status, message=verdict.message,
                         resolv_conf=verdict.resolv_conf_servers, uses_stub=verdict.uses_stub,
                         servers_in_use=verdict.servers_in_use, untrusted=verdict.untrusted)
        except Exception as e:
            entry.update(status='ERROR', message=str(e).splitlines()[0][:80] if str(e) else type(e).__name__,
                         servers_in_use=[], untrusted=[])
        results.append(entry)
        print(f"  {d.name:<10} {ip or 'unresolved':<16} {source:<15} "
              f"{'UP' if entry['reachable'] else 'DOWN':<5} "
              f"{', '.join(entry['servers_in_use']) or '-':<30} {entry['status']}")

    affected = [r for r in results if r['status'] in (dnscheck.COMPROMISED, dnscheck.MISCONFIGURED)]
    print(f'\nAffected: {len(affected)} of {len(results)}')
    for r in affected:
        print(f"  [ALERT] {r['name']} ({r['ip']}): {r['message']}")
    save(cfg, 'audit.json', {'scan_time': now(), 'trusted': trusted, 'devices': results,
                             'affected': [r['name'] for r in affected]})
    return 1 if affected else 0


def affected_devices(audit):
    return [d for d in audit['devices'] if d['name'] in audit['affected']]


# ---------------------------------------------------------------- alert / resolved emails

def cmd_alert(cfg, devices, args):
    banner('Alert email')
    targets = affected_devices(load(cfg, 'audit.json', 'audit'))
    if not targets:
        print('Nothing to report.')
        return 0
    subject, body = notify.render('alert.txt', count=len(targets),
                                  device_list=notify.alert_device_list(targets))
    return deliver(cfg, subject, body, args.dry_run)


def cmd_resolved(cfg, devices, args):
    banner('Resolution email')
    fixed = [d for d in load(cfg, 'remediation.json', 'remediate --apply')['devices'] if d.get('fixed')]
    if not fixed:
        print('No remediated devices to report.')
        return 0
    subject, body = notify.render('resolution.txt', count=len(fixed),
                                  device_list=notify.resolution_device_list(fixed))
    return deliver(cfg, subject, body, args.dry_run)


def deliver(cfg, subject, body, dry_run):
    print(f'Subject: {subject}\n{"-" * 90}\n{body}{"-" * 90}')
    if dry_run:
        print('[DRY RUN] email not sent')
        return 0
    message_id, refused = notify.send(cfg['smtp'], subject, body)
    print(f"[OK] accepted by {cfg['smtp']['host']} ({message_id})" if not refused else f'[WARN] refused: {refused}')
    return 0


# ---------------------------------------------------------------- tickets

def cmd_tickets(cfg, devices, args):
    from .tickets import TicketClient, ticket_for

    banner('Helpdesk tickets')
    audit = load(cfg, 'audit.json', 'audit')
    targets = affected_devices(audit)
    payloads = [ticket_for(d, audit['trusted'], cfg['tickets']) for d in targets]
    if args.dry_run:
        for p in payloads:
            print(json.dumps(p, indent=2))
        print(f'[DRY RUN] {len(payloads)} ticket(s) not created')
        return 0

    client = TicketClient(cfg['tickets']['url'], cfg['tickets']['token_env'])
    print(f'GET {client.url} -> HTTP {client.check()} (token accepted)')
    for p in payloads:
        code, body = client.create(p)
        print(f"POST {p['title']} -> HTTP {code}\n{json.dumps(body, indent=2)}")
    return 0


# ---------------------------------------------------------------- DNS service

def cmd_service(cfg, devices, args):
    banner('DNS service check' + (' and restart' if args.restart else ''))
    svc_cfg = cfg['dns_service']
    rc = 0
    for name in svc_cfg['hosts']:
        d = inventory.find(devices, name)
        with connect(d, d.address) as s:
            svc = service.find_service(s, svc_cfg.get('service_candidates', ['named', 'bind9', 'unbound']))
            if not svc:
                print(f'  {d.name}: no DNS service found')
                rc = 1
                continue
            st = service.status(s, svc)
            print(f"  {d.name:<8} {svc:<8} active={st['active']:<10} enabled={st['enabled']}")
            if st['active'] != 'active' and args.restart:
                print(f'  [ACTION] restarting {svc} on {d.name}')
                for step in service.restart(s, svc):
                    print(f"    sudo {step['command']} -> exit {step['exit_code']}")
                st = service.status(s, svc)
                print(f"  {d.name:<8} {svc:<8} active={st['active']:<10} enabled={st['enabled']}  (after)")
            if st['active'] != 'active':
                rc = 1
    return rc


# ---------------------------------------------------------------- remediation

def cmd_remediate(cfg, devices, args):
    banner('Remediation' + ('' if args.apply else '  [DRY RUN - add --apply to change hosts]'))
    audit = load(cfg, 'audit.json', 'audit')
    trusted, stubs = audit['trusted'], cfg['dns'].get('stub_resolvers', ['127.0.0.53'])
    targets = affected_devices(audit)
    if args.device:
        wanted = {n.lower() for n in args.device}
        targets = [t for t in targets if t['name'].lower() in wanted]

    done = []
    for t in targets:
        d = inventory.find(devices, t['name'])
        with connect(d, t['ip']) as s:
            before = dnscheck.classify(dnscheck.collect(s), trusted, stubs)
            result = remediate.restore_resolv_conf(s, trusted, dry_run=not args.apply)
            after = dnscheck.classify(dnscheck.collect(s), trusted, stubs) if args.apply else before
        print(f"  {t['name']:<10} {t['ip']:<16} before: {', '.join(before.servers_in_use) or '-'} ({before.status})")
        if args.apply:
            print(f"  {'':<27} after:  {', '.join(after.servers_in_use) or '-'} ({after.status})"
                  f"  backup {result['backup']}")
        else:
            print(f"  {'':<27} would write:\n" + ''.join(f'      | {line}\n' for line in result['content'].splitlines()))
        done.append({'name': t['name'], 'ip': t['ip'], 'fixed': args.apply and after.status == dnscheck.OK,
                     'before': before.servers_in_use, 'after': after.servers_in_use, 'at': now()})

    if args.apply:
        save(cfg, 'remediation.json', {'updated': now(), 'devices': done})
    return 0


# ---------------------------------------------------------------- main

def main(argv=None):
    parser = argparse.ArgumentParser(prog='dns_audit', description=__doc__)
    parser.add_argument('-c', '--config', default='config.toml')
    parser.add_argument('-i', '--inventory', default='inventory.csv')
    sub = parser.add_subparsers(dest='command', required=True)

    sub.add_parser('audit', help='ping every host and verify the DNS servers it uses')
    p = sub.add_parser('alert', help='email the affected hosts from the last audit')
    p.add_argument('--dry-run', action='store_true')
    p = sub.add_parser('tickets', help='open one helpdesk ticket per affected host')
    p.add_argument('--dry-run', action='store_true')
    p = sub.add_parser('service', help='check (and optionally restart) the DNS service on the DNS servers')
    p.add_argument('--restart', action='store_true')
    p = sub.add_parser('remediate', help='point affected hosts back at the trusted DNS servers')
    p.add_argument('--apply', action='store_true', help='make the change (default is a dry run)')
    p.add_argument('device', nargs='*', help='limit to these hosts')
    p = sub.add_parser('resolved', help='email the list of remediated hosts')
    p.add_argument('--dry-run', action='store_true')

    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    devices = inventory.load_inventory(args.inventory)
    commands = {'audit': cmd_audit, 'alert': cmd_alert, 'tickets': cmd_tickets,
                'service': cmd_service, 'remediate': cmd_remediate, 'resolved': cmd_resolved}
    return commands[args.command](cfg, devices, args)
