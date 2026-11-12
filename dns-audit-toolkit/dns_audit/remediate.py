"""Point a host back at the trusted DNS servers."""

import shlex
from datetime import datetime


def build_resolv_conf(trusted):
    stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lines = [f'# Managed by dns-audit-toolkit ({stamp}) - trusted DNS servers only']
    lines += [f'nameserver {ns}' for ns in trusted]
    return '\n'.join(lines) + '\n'


def restore_resolv_conf(session, trusted, dry_run=True):
    """Back up /etc/resolv.conf and replace it with the trusted servers.

    The old file is kept as evidence. A symlink is replaced by a real file so
    the fix is not undone by whatever the link pointed to.
    """
    backup = '/etc/resolv.conf.dns-audit-' + datetime.now().strftime('%Y%m%d-%H%M%S')
    content = build_resolv_conf(trusted)
    plan = [
        f'cp -P /etc/resolv.conf {backup}',
        'chattr -i /etc/resolv.conf 2>/dev/null || true',
        'rm -f /etc/resolv.conf',
        f'printf %s {shlex.quote(content)} > /etc/resolv.conf',
        'chmod 644 /etc/resolv.conf',
    ]
    if dry_run:
        return {'dry_run': True, 'backup': backup, 'commands': plan, 'content': content}

    results = [dict(zip(('exit_code', 'output'), session.sudo(cmd)), command=cmd) for cmd in plan]
    ok = all(r['exit_code'] == 0 for r in results)
    return {'dry_run': False, 'backup': backup, 'ok': ok, 'steps': results, 'content': content}
