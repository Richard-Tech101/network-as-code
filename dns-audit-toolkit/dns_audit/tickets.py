"""Open helpdesk tickets through a bearer-token REST API."""

import os

import requests


class TicketClient:
    def __init__(self, url, token_env, timeout=10):
        token = os.environ.get(token_env)
        if not token:
            raise RuntimeError(f'Set the {token_env} environment variable to your API token')
        self.url = url
        self.timeout = timeout
        self.headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    def check(self):
        """Prove the endpoint is reachable and the token is accepted before creating anything."""
        response = requests.get(self.url, headers=self.headers, timeout=self.timeout)
        response.raise_for_status()
        return response.status_code

    def create(self, payload):
        response = requests.post(self.url, headers=self.headers, json=payload, timeout=self.timeout)
        try:
            body = response.json()
        except ValueError:
            body = response.text
        return response.status_code, body


def ticket_for(device, trusted, cfg):
    untrusted = ', '.join(device['untrusted']) or 'none'
    description = (
        f"Issue type: DNS configuration compromise\n"
        f"Target device: {device['name']}\n"
        f"IP address: {device['ip']}\n"
        f"Last checked: {device['checked_at']}\n\n"
        f"Trusted DNS servers: {', '.join(trusted)}\n"
        f"DNS servers in use: {', '.join(device['servers_in_use']) or 'none'}\n"
        f"Untrusted DNS servers: {untrusted}\n"
    )
    payload = {
        'title': f"DNS compromise on {device['name']} ({device['ip']})",
        'description': description,
        'priority': cfg.get('priority', 'high'),
        'status': 'open',
    }
    if cfg.get('assigned_to'):
        payload['assigned_to'] = cfg['assigned_to']
    return payload
