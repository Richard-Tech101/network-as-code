"""ICMP reachability check using the system ping command."""

import platform
import subprocess


def ping(ip, count=2, timeout_s=1):
    if not ip:
        return False
    if platform.system().lower() == 'windows':
        cmd = ['ping', '-n', str(count), '-w', str(timeout_s * 1000), ip]
    else:
        cmd = ['ping', '-c', str(count), '-W', str(timeout_s), ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=count * timeout_s + 5)
    except (OSError, subprocess.TimeoutExpired):
        return False
    # Windows can return 0 for "destination unreachable", so also look for a real reply
    return result.returncode == 0 and 'ttl=' in result.stdout.lower()
