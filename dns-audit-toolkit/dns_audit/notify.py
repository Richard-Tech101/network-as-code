"""Email notifications built from plain-text templates."""

import os
import smtplib
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from string import Template

TEMPLATE_DIR = Path(__file__).parent / 'templates'


def render(template_name, **values):
    text = (TEMPLATE_DIR / template_name).read_text(encoding='utf-8')
    subject, _, body = text.partition('\n\n')
    return Template(subject.removeprefix('Subject: ')).substitute(values), Template(body).substitute(values)


def alert_device_list(devices):
    return '\n\n'.join(
        f"Device Name: {d['name']}\nIP Address: {d['ip']}\nLast Checked: {d['checked_at']}\n"
        f"Service Affected: DNS - {d['message']}"
        for d in devices)


def resolution_device_list(devices):
    return '\n'.join(f"- Hostname: {d['name']:<10} IP Address: {d['ip']}" for d in devices)


def send(smtp_cfg, subject, body):
    msg = EmailMessage()
    msg['From'] = smtp_cfg['sender']
    msg['To'] = ', '.join(smtp_cfg['recipients'])
    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid()
    msg.set_content(body)

    with smtplib.SMTP(smtp_cfg['host'], smtp_cfg.get('port', 25), timeout=15) as server:
        if smtp_cfg.get('starttls'):
            server.starttls()
        if smtp_cfg.get('username'):
            server.login(smtp_cfg['username'], os.environ.get(smtp_cfg.get('password_env', ''), ''))
        refused = server.send_message(msg)
    return msg['Message-ID'], refused
