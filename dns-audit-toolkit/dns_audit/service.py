"""Check and restart the DNS service on DNS servers (systemd)."""

import time


def find_service(session, candidates):
    for name in candidates:
        code, _ = session.run(f'systemctl cat {name}.service >/dev/null 2>&1')
        if code == 0:
            return name
    return None


def status(session, name):
    return {
        'service': name,
        'active': session.output(f'systemctl is-active {name}'),
        'enabled': session.output(f'systemctl is-enabled {name}'),
        'summary': session.output(f'systemctl status {name} --no-pager 2>&1 | head -4').splitlines(),
    }


def restart(session, name, wait_s=10):
    """Enable and restart a service, then wait for it to report active."""
    steps = []
    for cmd in (f'systemctl enable {name}', f'systemctl restart {name}'):
        code, out = session.sudo(cmd)
        steps.append({'command': cmd, 'exit_code': code, 'output': out})
    for _ in range(wait_s):
        if session.output(f'systemctl is-active {name}') == 'active':
            break
        time.sleep(1)
    return steps
