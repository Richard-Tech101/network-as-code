# Network as Code: Learning Lab

### Richard Gan | Network Engineer moving into Network Automation

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-Richard--Tech101-black)](https://github.com/Richard-Tech101)

This repository is my working journal for treating the network as code: first rebuilding how network devices
behave in Python, then automating real operational work across many devices.
It is updated as I learn. Projects start small and get refined over time.

| # | Project | Theme | Status |
|---|---|---|---|
| 1 | [Protocol emulators](#1-protocol-emulators) | How hubs, switches, ARP and routers make decisions, written from first principles | Learning scripts |
| 2 | [dns-audit-toolkit](dns-audit-toolkit/) | Automated incident response: find, report and fix hosts using a rogue DNS server | Working tool + unit tests |

---

## 1. Protocol emulators

Small, single-file Python programs that mimic the forwarding logic of real devices and print
output styled after Cisco / Arista CLI commands. The goal is to understand *how* a device decides,
not just *what* a `show` command displays.

| File | Layer | What it does | CLI it imitates |
|---|---|---|---|
| `ethernet_hub.py` | L1 | Interactive hub: a signal on one port is repeated out of every other port | - |
| `arp_cache.py` | L2/L3 | Looks up an IP in an ARP cache; a miss is added as `Incomplete` | `show ip arp` |
| `ethernet_switch.py` | L2 | MAC learning, known-unicast forwarding, unknown-unicast and broadcast flooding | `show mac address-table` |
| `ethernet_switch_w_Interface_data.py` | L2 | The switch plus per-port in/out frame and byte counters | `show interfaces` |
| `router.py` | L3 | `Router` class: routes are added to a RIB, and the FIB is built as `ipaddress` objects | `show ip route` |

```bash
python ethernet_hub.py        # interactive: enter a port number
python arp_cache.py           # interactive: enter an IP to look up
python ethernet_switch.py
python ethernet_switch_w_Interface_data.py
python router.py
```

Concepts practiced: flooding vs forwarding, MAC table learning, ARP cache hits and misses,
interface telemetry counters, RIB vs FIB, and Python's `ipaddress` module.

---

## 2. dns-audit-toolkit

A config-driven command line tool that runs a full DNS incident response across a fleet of Linux hosts:

- **audit:** resolve each host's current IP (DHCP clients from the router's live lease table), ping it, SSH in and
  work out the DNS servers it really uses (following the `127.0.0.53` stub resolver to its upstream servers)
- **alert / tickets:** email the affected hosts and open one helpdesk ticket per host over a REST API
- **service:** check and restart BIND / unbound on the DNS servers
- **remediate:** back up the rogue config and restore the trusted servers (dry run by default), then re-verify
- **resolved:** send the "all clear" email listing every fixed host

Built with Paramiko, Netmiko, Requests, smtplib and systemd tooling, and covered by unit tests.
Full details: **[dns-audit-toolkit/README.md](dns-audit-toolkit/README.md)**

---

## Skills on display

| Area | Where |
|---|---|
| Networking fundamentals (L1-L3) | Protocol emulators |
| Python (OOP, CLI tools, packaging, unit tests) | Both projects |
| SSH automation (Paramiko, Netmiko, VyOS) | dns-audit-toolkit |
| Linux operations (systemd, resolv.conf, systemd-resolved, BIND) | dns-audit-toolkit |
| APIs and integrations (REST + bearer tokens, SMTP) | dns-audit-toolkit |
| Safe automation practice (dry runs, backups, verify after change, secrets in env vars) | dns-audit-toolkit |

---

## Learning path and roadmap

```
Protocol emulators (L1-L3 logic in code)          <- done
        |
Device automation (Netmiko / Paramiko)            <- dns-audit-toolkit
        |
Config management (Ansible, templated configs)    <- next
        |
Containers and CI/CD (Docker, GitHub Actions)
        |
AI agent tooling for network operations
```

- [x] Hub, ARP cache, switch with MAC learning, interface counters
- [x] Router RIB / FIB with `ipaddress`
- [x] Multi-device DNS audit and remediation over SSH
- [ ] Longest-prefix-match packet forwarding in `router.py`
- [ ] Router forwarding benchmark (packets per second)
- [ ] Turn the emulators into importable modules with tests
- [ ] Templated multi-device config provisioning (Arista)
- [ ] GitHub Actions running the unit tests on every push
- [ ] Docker image for the toolkit

---

## References

- Python `ipaddress` module: https://docs.python.org/3/library/ipaddress.html
- RFC 826, ARP: https://www.rfc-editor.org/rfc/rfc826
- RFC 791, IPv4: https://www.rfc-editor.org/rfc/rfc791
- `resolv.conf(5)` and `systemd-resolved(8)` man pages
- Paramiko: https://www.paramiko.org and Netmiko: https://github.com/ktbyers/netmiko

All code in this repository was written by me as part of my own learning.

---

## About

**Richard Gan**: network operations on enterprise Arista / Cisco production networks, now building automation.

- CCNA | Linux LPI | CompTIA A+
- In progress: CCNP Enterprise, Cisco DevNet Professional, AWS Cloud Practitioner
- GitHub: [github.com/Richard-Tech101](https://github.com/Richard-Tech101)

## License

MIT, see [LICENSE](LICENSE).
