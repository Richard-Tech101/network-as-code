"""Small SSH wrapper around paramiko for running commands on Linux hosts."""

import shlex

import paramiko


class SSHSession:
    def __init__(self, host, username, password=None, timeout=10):
        self.host = host
        self.password = password
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            host, username=username, password=password, timeout=timeout,
            banner_timeout=timeout, auth_timeout=timeout,
            look_for_keys=password is None, allow_agent=password is None,
        )

    def run(self, command, timeout=20):
        """Run a command. Returns (exit_code, combined stdout + stderr)."""
        _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        code = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors='replace') + stderr.read().decode(errors='replace')
        return code, out.strip()

    def output(self, command):
        return self.run(command)[1]

    def sudo(self, command, timeout=30):
        """Run a command with sudo, feeding the password on stdin when we have one."""
        stdin, stdout, stderr = self.client.exec_command(
            f"sudo -S -p '' sh -c {shlex.quote(command)}", timeout=timeout)
        if self.password:
            stdin.write(self.password + '\n')
            stdin.flush()
        code = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors='replace') + stderr.read().decode(errors='replace')
        return code, out.strip()

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def connect(device, address, timeout=10):
    return SSHSession(address, device.username, device.password, timeout)
