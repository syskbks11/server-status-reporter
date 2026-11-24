#!/usr/bin/env python3
"""Summarize host and Docker security events and email concise reports."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import fcntl
import glob
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import smtplib
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from email.message import EmailMessage

from monitor_config import DEFAULTS, RULE_LABELS, validate, secure_read

CONFIG_DEFAULT = "/etc/server-security-report/config.json"
STATE_DIR = Path("/var/lib/server-security-report")
LOG_DIR = Path("/var/log/server-security-report")
LOCK_PATH = Path("/run/lock/server-security-report.lock")
UTC = dt.timezone.utc

HTTP_RE = re.compile(
    r'"(?P<method>GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS|PROPFIND|TRACE) '
    r'(?P<path>\S+) HTTP/[\d.]+"\s+(?P<status>\d{3})',
    re.IGNORECASE,
)
APACHE_DATE_RE = re.compile(r"\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d\d:\d\d:\d\d [+-]\d{4})\]")
SSH_FAIL_RE = re.compile(
    r"(?:Failed (?:password|publickey|keyboard-interactive)|Invalid user|"
    r"authentication failure|PAM: Authentication failure|maximum authentication attempts exceeded)",
    re.IGNORECASE,
)
SSH_SUCCESS_RE = re.compile(r"Accepted (publickey|password|keyboard-interactive/pam) for (\S+) from (\S+)")
IP_FROM_RE = re.compile(r"\bfrom\s+(\S+)", re.IGNORECASE)
SYSLOG_DATE_RE = re.compile(r"^([A-Za-z]{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+")


def clean(value: object, limit: int = 140) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).strip()
    return text[:limit] + ("..." if len(text) > limit else "")


def safe_ip(value: str) -> str:
    value = value.strip("[],: ")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return "unknown"


def abbreviated_url_path(path: str) -> str:
    """Avoid placing entire potentially sensitive query values in email."""
    if "?" not in path:
        return clean(path, 110)
    base, query = path.split("?", 1)
    first_field = query.split("&", 1)[0].split("=", 1)[0].split(":", 1)[0]
    return clean(f"{base}?{first_field}=REDACTED", 110)


def top(counter: collections.Counter, n: int = 5) -> str:
    return ", ".join(f"{clean(k, 70)} ({v})" for k, v in counter.most_common(n)) or "none"


@dataclass
class CommandResult:
    output: str = ""
    ok: bool = False
    truncated: bool = False
    error: str = ""


def command(args: list[str], *, timeout: float = 20, max_bytes: int = 1_000_000) -> CommandResult:
    """Read bounded output without allowing a noisy process to exhaust memory."""
    result = CommandResult()
    try:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as exc:
        result.error = clean(exc)
        return result
    data = bytearray()
    sel = selectors.DefaultSelector()
    sel.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    timed_out = False
    try:
        while sel.get_map():
            if time.monotonic() > deadline:
                timed_out = True
                break
            for key, _ in sel.select(timeout=0.3):
                part = os.read(key.fileobj.fileno(), min(65536, max_bytes - len(data) + 1))
                if not part:
                    sel.unregister(key.fileobj)
                    continue
                if len(data) + len(part) > max_bytes:
                    data.extend(part[:max_bytes - len(data)])
                    result.truncated = True
                    break
                data.extend(part)
            if result.truncated:
                break
        if result.truncated or timed_out:
            process.kill()
        try:
            code = process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            code = process.wait(timeout=3)
        result.ok = code == 0 and not timed_out and not result.truncated
        if timed_out:
            result.error = "Command timed out"
        elif result.truncated:
            result.error = "Command output was truncated"
        elif code != 0:
            result.error = f"Command returned {code}"
    finally:
        sel.close()
        if process.stdout:
            process.stdout.close()
    result.output = data.decode("utf-8", errors="replace")
    return result


REMEDIATION_GUIDANCE = (
    ("ssh:root:", "Verify the source and authorization of the root login; disable direct root SSH access if it is not required."),
    ("ssh:password:", "Verify the login; prefer SSH keys and review password-authentication policy."),
    ("ssh:login:", "Confirm that this login is expected and its source is authorized."),
    ("ssh:failures", "Review the SSH failure sources and rate limits; confirm SSHGuard or Fail2ban is working."),
    ("ssh:spike", "Investigate the sudden rise in SSH authentication failures and verify the connection guard is active."),
    ("host-web:probe2xx", "Inspect the matching reverse-proxy access logs and application response; HTTP 2xx is not proof of compromise."),
    ("docker-web:probe2xx", "Inspect the container and reverse-proxy logs for the paths; HTTP 2xx alone is not proof of compromise."),
    ("host-web:probes", "Check whether the same sources repeatedly probe sensitive paths; review access restrictions."),
    ("docker-web:probes", "Compare container requests with the reverse-proxy logs to identify the original source IP."),
    ("host-web:http5xx", "Inspect Apache/nginx error logs and service health around the reported period."),
    ("docker-web:http5xx", "Inspect affected container logs and upstream health for repeated HTTP 5xx errors."),
    ("docker:unhealthy:", "Review docker inspect health output and docker logs; check the application dependencies."),
    ("docker:stopped:", "Inspect exit status, recent docker logs, and the configured restart policy."),
    ("docker:required-stopped:", "Check the container exit reason and restore the required service when safe."),
    ("docker:required-missing:", "Confirm the deployment and container naming; restore the required service if unexpectedly removed."),
    ("docker:missing:", "Verify whether deployment/recreation was planned; inspect Docker events and deployment logs."),
    ("docker:restart:", "Inspect container exit codes and logs for crashes or repeated restarts."),
    ("docker:new-exposure:", "Review published port bindings and firewall rules; restrict unintended external exposure."),
    ("docker:public-port:", "Check published port bindings; restrict any unapproved non-loopback exposure."),
    ("docker:privileged:", "Confirm privileged mode is necessary; remove unnecessary container privileges."),
    ("docker:socket:", "Verify the Docker socket mount is necessary; it can grant control over the host Docker daemon."),
    ("docker:app-errors", "Review the affected application logs and correlate errors with user requests or deployments."),
    ("docker:cli-missing", "Verify the Docker installation and the required containers on this host."),
    ("docker:unavailable", "Check Docker daemon status, system resources, and journalctl -u docker."),
    ("docker:inspect", "Check Docker daemon availability and retry a bounded docker inspect command."),
    ("docker:inspect-invalid", "Check Docker daemon responses and available disk space."),
    ("service:", "Inspect systemctl status and journalctl for the affected service before restarting it."),
    ("disk:", "Identify large files and log growth; free space or extend capacity before the filesystem fills."),
    ("coverage:", "Fix the monitoring collection problem; absence of recorded events may not mean absence of attacks."),
)


def remediation_for(key: str) -> str:
    for prefix, action in REMEDIATION_GUIDANCE:
        if key.startswith(prefix):
            return action
    return "Review the relevant service logs, confirm the event, and take action if it is unexpected."


@dataclass
class Finding:
    level: str
    key: str
    message: str
    persistent: bool = False
    action: str = ""
    ongoing_since: str = ""


@dataclass
class Report:
    host: str
    start: dt.datetime
    end: dt.datetime
    mode: str
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, str] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    previous_counts: dict[str, int] = field(default_factory=dict)
    comparison_note: str = ""
    sections: list[tuple[str, list[str]]] = field(default_factory=list)
    coverage: list[str] = field(default_factory=list)
    ip_activity: dict[str, collections.Counter] = field(default_factory=dict)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    alert_policy: dict = field(default_factory=dict)
    observations: dict = field(default_factory=dict)
    recoveries: list[str] = field(default_factory=list)

    def add(self, level: str, key: str, message: str, persistent: bool = False) -> None:
        for rule_id, (_, prefix) in RULE_LABELS.items():
            if (key.startswith(prefix) if not prefix.startswith(':') else prefix in key):
                level = self.severity_overrides.get(rule_id, level)
                break
        if level == 'OFF':
            return
        if not any(item.key == key for item in self.findings):
            self.findings.append(Finding(level, key, clean(message, 400), persistent, remediation_for(key)))

    def set_metric(self, name: str, value: object) -> None:
        self.metrics[name] = str(value)
        if isinstance(value, int):
            self.counts[name] = value

    def record_ip(self, address: str, category: str, amount: int = 1) -> None:
        if amount <= 0:
            return
        address = safe_ip(address)
        if address == "unknown":
            return
        self.ip_activity.setdefault(address, collections.Counter())[category] += amount

    def section(self, name: str, lines: list[str]) -> None:
        if lines:
            self.sections.append((name, [clean(s, 320) for s in lines]))

    @property
    def level(self) -> str:
        if any(f.level == "HIGH" for f in self.findings):
            return "HIGH"
        if any(f.level == "WARN" for f in self.findings):
            return "WARN"
        return "OK"

    @property
    def status(self) -> str:
        return {"HIGH": "URGENT", "WARN": "REVIEW", "OK": "OK"}[self.level]

    @property
    def status_message(self) -> str:
        return {
            "URGENT": "Immediate verification recommended",
            "REVIEW": "Review the highlighted events",
            "OK": "No actionable findings detected",
        }[self.status]

    def subject(self) -> str:
        prefix = "SECURITY RECOVERY" if self.mode == "alert" and self.recoveries and not self.findings else ("SECURITY ALERT" if self.mode == "alert" else "Daily Security")
        return f"[{prefix}][{self.status}] {self.host} - {self.end:%Y-%m-%d %H:%M}"

    def summary_keys(self) -> list[str]:
        main = [
            "SSH authentication failures (log entries)",
            "SSH successful authentications",
            "SSHGuard/Fail2ban block events",
            "Host suspicious HTTP paths",
            "Docker containers (running/stopped/unhealthy)",
            "Docker application error indicators",
        ]
        conditional = [
            "Host suspicious paths returning 2xx",
            "Host HTTP 5xx responses",
            "Docker suspicious HTTP paths",
            "Docker suspicious paths returning 2xx",
            "Docker HTTP 5xx responses",
            "Docker non-loopback published port bindings",
        ]
        wanted = [k for k in main if k in self.metrics]
        wanted.extend(k for k in conditional if k in self.metrics and self.counts.get(k, 0) > 0)
        wanted.extend(k for k in self.metrics if k.startswith("Local filesystems at or above "))
        if "Docker" in self.metrics:
            wanted.append("Docker")
        return wanted

    def metric_change(self, name: str) -> tuple[str, str]:
        if self.mode != "daily" or name not in self.counts or name not in self.previous_counts:
            return "-", "-"
        old = self.previous_counts[name]
        diff = self.counts[name] - old
        sign = "+" if diff > 0 else ""
        return str(old), f"{sign}{diff}"

    def ip_rows(self, limit: int = 8) -> list[tuple[str, str]]:
        def score(item: tuple[str, collections.Counter]) -> tuple[int, int, str]:
            address, counts = item
            suspicious = (
                counts["ssh_failed"] * 3 + counts["host_probes"] * 2
                + counts["docker_probes"] * 2 + counts["guard_bans"] * 5
            )
            regular = counts["host_requests"] + counts["docker_requests"]
            return suspicious, regular, address

        ordered = sorted(self.ip_activity.items(), key=score, reverse=True)
        rows = []
        for address, counts in ordered[:limit]:
            pieces = []
            for key, label in (
                ("ssh_failed", "SSH failed"),
                ("ssh_success", "SSH accepted"),
                ("guard_bans", "guard blocks"),
                ("host_requests", "host HTTP"),
                ("host_probes", "host probes"),
                ("docker_requests", "Docker HTTP"),
                ("docker_probes", "Docker probes"),
            ):
                if counts[key]:
                    pieces.append(f"{label}: {counts[key]}")
            rows.append((address, "; ".join(pieces)))
        return rows

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (0 if f.level == "HIGH" else 1, f.key))

    def plaintext(self) -> str:
        lines = [
            f"SECURITY REPORT - {self.host}",
            f"Status: {self.status} - {self.status_message}",
            f"Mode: {self.mode.upper()}",
            f"Period: {self.start:%Y-%m-%d %H:%M %z} - {self.end:%Y-%m-%d %H:%M %z}",
            "", "AT A GLANCE",
        ]
        for name in self.summary_keys():
            previous, delta = self.metric_change(name)
            trend = f" | previous: {previous}, change: {delta}" if previous != "-" else ""
            lines.append(f"  {name}: {self.metrics[name]}{trend}")
        if self.mode == "daily" and self.comparison_note:
            lines.extend(["", f"Comparison: {self.comparison_note}"])
        lines.extend(["", "FINDINGS AND NEXT STEPS"])
        if self.findings:
            for finding in self.sorted_findings():
                suffix = f" (ongoing since {finding.ongoing_since})" if finding.ongoing_since else ""
                lines.append(f"  [{finding.level}] {finding.message}{suffix}")
                lines.append(f"    Next step: {finding.action}")
        else:
            lines.append("  No actionable findings")
        if self.recoveries:
            lines.extend(["", "RECOVERED INCIDENTS"])
            lines.extend(f"  {item}" for item in self.recoveries)
        lines.extend(["", "IP ACTIVITY - TOP SOURCES"])
        rows = self.ip_rows()
        lines.extend(f"  {address}: {detail}" for address, detail in rows)
        if not rows:
            lines.append("  No source IP activity recorded")
        for title, items in self.sections:
            lines.extend(["", title.upper()])
            lines.extend(f"  {item}" for item in items)
        if self.coverage:
            lines.extend(["", "MONITORING COVERAGE WARNINGS"])
            lines.extend(f"  {item}" for item in self.coverage)
        else:
            lines.extend(["", "Monitoring coverage: no warnings"])
        lines.extend([
            "", "Notes: HTTP 2xx on a suspicious path does not prove compromise.",
            "Host and Docker HTTP logs can represent the same request; do not add their counts.",
            "Container-log IPs can be a proxy address; verify client IPs in the host reverse-proxy log.",
        ])
        return "\n".join(lines) + "\n"

    def htmltext(self) -> str:
        esc = html.escape
        status_color = {"OK": "#17603a", "REVIEW": "#926000", "URGENT": "#a11"}[self.status]
        comparison = (
            f'<p style="color:#555;font-size:12px">Comparison: {esc(self.comparison_note)}</p>'
            if self.mode == "daily" and self.comparison_note else ""
        )
        metric_rows = []
        for name in self.summary_keys():
            previous, delta = self.metric_change(name)
            cells = (
                f'<td style="padding:7px;border-bottom:1px solid #ddd">{esc(name)}</td>'
                f'<td style="padding:7px;border-bottom:1px solid #ddd;text-align:right">{esc(self.metrics[name])}</td>'
            )
            if self.mode == "daily":
                cells += (
                    f'<td style="padding:7px;border-bottom:1px solid #ddd;text-align:right">{esc(previous)}</td>'
                    f'<td style="padding:7px;border-bottom:1px solid #ddd;text-align:right">{esc(delta)}</td>'
                )
            metric_rows.append('<tr>' + cells + '</tr>')
        findings = ''.join(
            '<li style="margin:9px 0">'
            f'<strong style="color:{"#a11" if f.level == "HIGH" else "#926000"}">[{esc(f.level)}]</strong> '
            f'{esc(f.message)}'
            f'{" <span style=\"color:#666\">(ongoing since " + esc(f.ongoing_since) + ")</span>" if f.ongoing_since else ""}'
            f'<div style="color:#444;font-size:13px">Next step: {esc(f.action)}</div></li>'
            for f in self.sorted_findings()
        ) or '<li>No actionable findings</li>'
        sources = ''.join(
            '<tr>'
            f'<td style="padding:5px 8px;border-bottom:1px solid #eee;font-family:monospace">{esc(address)}</td>'
            f'<td style="padding:5px 8px;border-bottom:1px solid #eee">{esc(detail)}</td>'
            '</tr>' for address, detail in self.ip_rows()
        ) or '<tr><td colspan="2">No source IP activity recorded</td></tr>'
        sections = ''.join(
            f'<h3 style="margin:20px 0 6px">{esc(title)}</h3>'
            f'<ul style="padding-left:20px;margin:5px 0">'
            + ''.join(f'<li style="margin:5px 0">{esc(item)}</li>' for item in items)
            + '</ul>'
            for title, items in self.sections
        )
        coverage = (
            '<h3>Monitoring coverage warnings</h3><ul>'
            + ''.join(f'<li>{esc(item)}</li>' for item in self.coverage) + '</ul>'
            if self.coverage else '<p style="font-size:12px;color:#555">Monitoring coverage: no warnings</p>'
        )
        return (
            '<!doctype html><html><body style="font:14px/1.5 Arial,sans-serif;color:#222;max-width:800px;margin:auto">'
            f'<h2>Security report: {esc(self.host)}</h2>'
            f'<p><strong style="color:{status_color};font-size:18px">{esc(self.status)}</strong> '
            f'&mdash; {esc(self.status_message)}<br>'
            f'{esc(self.start.isoformat(timespec="minutes"))} to {esc(self.end.isoformat(timespec="minutes"))}</p>'
            '<h3>At a glance</h3>'
            '<table style="border-collapse:collapse;width:100%">'
            '<thead><tr><th align="left">Metric</th><th align="right">Current</th>'
            + ('<th align="right">Previous</th><th align="right">Change</th>' if self.mode == "daily" else '')
            + '</tr></thead><tbody>'
            + ''.join(metric_rows) + '</tbody></table>'
            + comparison
            + '<h3>Findings and next steps</h3><ul style="padding-left:20px">' + findings + '</ul>'
            + ('<h3>Recovered incidents</h3><ul>' + ''.join('<li>' + esc(v) + '</li>' for v in self.recoveries) + '</ul>' if self.recoveries else '')
            + '<h3>IP activity - top sources</h3><table style="border-collapse:collapse;width:100%">'
            + sources + '</table>'
            + sections + coverage
            + '<p style="font-size:12px;color:#666">HTTP 2xx on a suspicious path does not prove compromise. '
            'Host and Docker HTTP logs may contain the same request. '
            'Container-log source IPs may reflect the reverse proxy.</p>'
            '</body></html>'
        )


@dataclass
class WebStats:
    requests: int = 0
    errors_4xx: int = 0
    errors_5xx: int = 0
    probes: int = 0
    probe_2xx: int = 0
    ips: collections.Counter = field(default_factory=collections.Counter)
    paths: collections.Counter = field(default_factory=collections.Counter)
    probe_ips: collections.Counter = field(default_factory=collections.Counter)
    patterns: list[str] = field(default_factory=lambda: list(DEFAULTS['http_probe_patterns']))
    ignored_paths: list[str] = field(default_factory=list)
    _probe_regex: object = field(init=False, repr=False)
    _ignore_regex: object = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._probe_regex = re.compile('|'.join('(?:' + p + ')' for p in self.patterns), re.I) if self.patterns else None
        self._ignore_regex = re.compile('|'.join('(?:' + p + ')' for p in self.ignored_paths), re.I) if self.ignored_paths else None

    def ingest(self, line: str) -> None:
        match = HTTP_RE.search(line)
        if not match:
            return
        self.requests += 1
        status = int(match.group("status"))
        path = match.group("path")
        before = line[:match.start()].split()
        address = "unknown"
        for item in before:
            checked = safe_ip(item)
            if checked != "unknown":
                address = checked
                break
        if status >= 500:
            self.errors_5xx += 1
        elif status >= 400:
            self.errors_4xx += 1
        if self._ignore_regex and self._ignore_regex.search(path):
            self.ips[address] += 1
            return
        if self._probe_regex and self._probe_regex.search(path):
            self.probes += 1
            self.probe_2xx += 200 <= status < 300
            self.paths[abbreviated_url_path(path)] += 1
            self.probe_ips[address] += 1
        self.ips[address] += 1


def host_access_stats(start: dt.datetime, end: dt.datetime, patterns: list[str], report: Report,
                      cfg: dict | None = None) -> WebStats:
    cfg = cfg or {}
    stats = WebStats(patterns=cfg.get('http_probe_patterns', DEFAULTS['http_probe_patterns']),
                     ignored_paths=cfg.get('ignored_http_path_patterns', []))
    if not patterns:
        report.coverage.append('Host HTTP scanning enabled, but no access-log paths are configured')
        report.add('WARN', 'coverage:host-http-paths', 'Host HTTP scanning has no configured log paths', persistent=True)
    names = sorted({p for pattern in patterns for p in glob.glob(pattern) if os.path.isfile(p)})
    if not names and patterns:
        report.coverage.append("No host HTTP access log found; configure host_access_log_globs if this server runs an HTTP service")
    for name in names:
        count = 0
        try:
            with open(name, "r", encoding="utf-8", errors="replace") as inp:
                for line in inp:
                    count += 1
                    if count > 2_000_000:
                        report.coverage.append(f"Host access log scan capped at 2M lines: {clean(name)}")
                        report.add("WARN", f"coverage:host-log:{name}", f"Host HTTP log scan limit exceeded: {clean(name)}", persistent=True)
                        break
                    m = APACHE_DATE_RE.search(line)
                    if not m:
                        continue
                    try:
                        when = dt.datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z")
                    except ValueError:
                        continue
                    if start <= when < end:
                        stats.ingest(line)
        except OSError as exc:
            report.coverage.append(f"Cannot read {clean(name)}: {clean(exc)}")
    return stats


def journal_logs(units: list[str], start: dt.datetime, end: dt.datetime, report: Report, label: str) -> str:
    if not shutil.which("journalctl"):
        report.coverage.append("journalctl is unavailable")
        return ""
    args = ["journalctl", "--no-pager", "-q", "-o", "cat", "--since", start.strftime("%Y-%m-%d %H:%M:%S"),
            "--until", end.strftime("%Y-%m-%d %H:%M:%S")]
    for unit in units:
        args.extend(["-u", unit])
    res = command(args, timeout=20, max_bytes=5_000_000)
    if not res.ok:
        report.coverage.append(f"{label} journal query incomplete: {res.error}")
        if res.truncated:
            report.add("WARN", f"coverage:journal:{label}", f"Monitoring coverage incomplete: {label} journal output exceeded limit", persistent=True)
    return res.output


def fallback_auth_log(start: dt.datetime, end: dt.datetime, report: Report) -> str:
    lines = []
    for name in ["/var/log/auth.log", "/var/log/auth.log.1", "/var/log/secure", "/var/log/secure.1"]:
        if not os.path.isfile(name):
            continue
        try:
            with open(name, encoding="utf-8", errors="replace") as inp:
                for line in inp:
                    if "sshd" not in line:
                        continue
                    m = SYSLOG_DATE_RE.search(line)
                    if not m:
                        continue
                    for year in {start.year, end.year}:
                        try:
                            stamp = dt.datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S")
                            stamp = stamp.replace(tzinfo=end.tzinfo)
                        except ValueError:
                            continue
                        if start <= stamp < end:
                            lines.append(line)
                            break
        except OSError as exc:
            report.coverage.append(f"Cannot read {name}: {clean(exc)}")
    return "".join(lines)


def is_trusted_ssh_source(address: str, cfg: dict) -> bool:
    try:
        ip = ipaddress.ip_address(address)
        return any(ip in ipaddress.ip_network(cidr, strict=False)
                   for cidr in cfg.get('trusted_ssh_cidrs', []))
    except ValueError:
        return False


def analyze_ssh(start: dt.datetime, end: dt.datetime, report: Report, cfg: dict) -> None:
    data = journal_logs(["ssh.service", "sshd.service"], start, end, report, "SSH")
    if not data.strip():
        data = fallback_auth_log(start, end, report)
    failures = collections.Counter()
    successes = []
    for line in data.splitlines():
        match = SSH_SUCCESS_RE.search(line)
        if match:
            method, user, address = match.groups()
            successes.append((user, method, safe_ip(address)))
        elif SSH_FAIL_RE.search(line):
            ip = IP_FROM_RE.search(line)
            failures[safe_ip(ip.group(1)) if ip else "unknown"] += 1
    report.set_metric("SSH authentication failures (log entries)", sum(failures.values()))
    report.set_metric("SSH successful authentications", len(successes))
    for address, count in failures.items():
        report.record_ip(address, "ssh_failed", count)
    for _, _, address in successes:
        report.record_ip(address, "ssh_success")
    if failures or successes:
        report.section("SSH", [
            f"Failure sources: {top(failures, 7)}" if failures else "No SSH failures recorded",
            f"Successful sessions: {', '.join(f'{u} via {m} from {ip}' for u, m, ip in successes[:15]) or 'none'}",
        ])
    threshold = int(cfg.get("ssh_failure_threshold", 30))
    if sum(failures.values()) >= threshold:
        report.add("WARN", "ssh:failures", f"SSH failures: {sum(failures.values())} log entries; top sources: {top(failures, 3)}")
    for user, method, address in successes:
        if user == "root":
            trusted = is_trusted_ssh_source(address, cfg)
            report.add("WARN" if trusted else "HIGH", f"ssh:root:{address}:{method}",
                       f"Direct root SSH login from {address} ({method})" + (" [trusted source]" if trusted else " [untrusted source]"))
        elif is_trusted_ssh_source(address, cfg):
            continue
        elif method != "publickey" and cfg.get("alert_on_ssh_password_success", True):
            report.add("WARN", f"ssh:password:{user}:{address}", f"SSH password login: {user} from {address}")
        elif cfg.get("alert_on_all_ssh_success", False):
            report.add("WARN", f"ssh:login:{user}:{address}", f"SSH login: {user} from {address} ({method})")
    # An empty event window can be normal on a quiet server.



def analyze_guards(start: dt.datetime, end: dt.datetime, report: Report) -> None:
    data = journal_logs(["sshguard.service", "fail2ban.service"], start, end, report, "Guard")
    attacks = collections.Counter()
    bans = collections.Counter()
    for line in data.splitlines():
        if "Attack from" in line:
            m = re.search(r'Attack from ["\']?([^"\'\s]+)', line)
            if m:
                attacks[safe_ip(m.group(1))] += 1
        if re.search(r"\b(?:Blocking|Ban)\b", line):
            m = re.search(r"\b(?:Blocking|Ban)\s+[\"']?([0-9a-fA-F:.]+)", line)
            if m:
                bans[safe_ip(m.group(1))] += 1
    report.set_metric("SSHGuard/Fail2ban block events", sum(bans.values()))
    for address, count in bans.items():
        report.record_ip(address, "guard_bans", count)
    if bans or attacks:
        report.section("SSHGuard / Fail2ban", [f"Blocked IPs: {top(bans)}", f"Detected attack IPs: {top(attacks)}"])


def analyze_web(stats: WebStats, name: str, report: Report, cfg: dict, prefix: str) -> None:
    report.set_metric(f"{name} HTTP requests", stats.requests)
    report.set_metric(f"{name} suspicious HTTP paths", stats.probes)
    report.set_metric(f"{name} suspicious paths returning 2xx", stats.probe_2xx)
    report.set_metric(f"{name} HTTP 5xx responses", stats.errors_5xx)
    channel = "host" if prefix == "host-web" else "docker"
    for address, count in stats.ips.items():
        report.record_ip(address, f"{channel}_requests", count)
    for address, count in stats.probe_ips.items():
        report.record_ip(address, f"{channel}_probes", count)
    if stats.requests:
        lines = [f"Total requests: {stats.requests}; HTTP 4xx: {stats.errors_4xx}; HTTP 5xx: {stats.errors_5xx}"]
        if stats.probes:
            lines.append(f"Suspicious paths: {stats.probes}; HTTP 2xx matches: {stats.probe_2xx}")
            lines.append(f"Top suspicious paths: {top(stats.paths, 5)}")
        report.section(name + " HTTP", lines)
    if stats.probe_2xx:
        report.add("WARN", f"{prefix}:probe2xx", f"{name}: {stats.probe_2xx} suspicious path requests returned HTTP 2xx; investigate target paths", persistent=True)
    if stats.probes >= int(cfg.get("web_probe_threshold", 20)):
        report.add("WARN", f"{prefix}:probes", f"{name}: {stats.probes} requests matched common exploit/scanner URL patterns", persistent=True)
    if stats.errors_5xx >= int(cfg.get("web_5xx_threshold", 50)):
        report.add("WARN", f"{prefix}:http5xx", f"{name}: {stats.errors_5xx} HTTP 5xx responses")


def parse_docker(config: dict, report: Report, previous: dict, start: dt.datetime, end: dt.datetime) -> dict:
    if not shutil.which("docker"):
        report.set_metric("Docker", "not installed")
        if config.get("required_containers"):
            report.coverage.append("Docker CLI not installed, but required containers are configured")
            report.add("HIGH", "docker:cli-missing", "Docker CLI unavailable, but required_containers is configured", persistent=True)
        return {}
    ids_result = command(["docker", "ps", "-aq"], timeout=15, max_bytes=100_000)
    if not ids_result.ok:
        report.add("HIGH", "docker:unavailable", "Docker daemon could not be queried", persistent=True)
        report.coverage.append(f"Docker CLI failure: {ids_result.error}; {clean(ids_result.output, 200)}")
        report.set_metric("Docker", "unavailable")
        return {}
    ids = ids_result.output.split()
    if not ids:
        report.observations["docker_query_ok"] = True
        report.set_metric("Docker containers (running/stopped/unhealthy)", "0/0/0")
        for required in config.get("required_containers", []):
            report.add("HIGH", f"docker:required-missing:{required}",
                       f"Required Docker container is missing: {required}", persistent=True)
        return {}
    inspect = command(["docker", "inspect", *ids], timeout=30, max_bytes=8_000_000)
    if not inspect.ok:
        report.add("HIGH", "docker:inspect", "Docker container inspection failed", persistent=True)
        report.coverage.append(f"Docker inspect incomplete: {inspect.error}")
        return {}
    try:
        containers = json.loads(inspect.output)
    except json.JSONDecodeError:
        report.add("HIGH", "docker:inspect-invalid", "Docker inspect returned invalid or incomplete JSON", persistent=True)
        return {}
    report.observations["docker_query_ok"] = True
    ignore = set(config.get("ignore_containers", []))
    states = {}
    running = stopped = unhealthy = 0
    attention = []
    restarted = []
    exposed = []
    privileged = []
    stats = WebStats(patterns=config.get('http_probe_patterns', DEFAULTS['http_probe_patterns']),
                     ignored_paths=config.get('ignored_http_path_patterns', []))
    app_errors = collections.Counter()
    custom_patterns = [
        (rule['name'], re.compile(rule['pattern'], re.I), rule['severity'])
        for rule in config.get('application_log_rules', [])
    ]
    custom_hits = collections.Counter()
    max_log_bytes = int(config.get("max_docker_log_bytes_per_container", 800_000))
    previous_containers = previous.get("containers", {}) if isinstance(previous, dict) else {}
    for container in containers:
        name = container.get("Name", "").lstrip("/")
        if name in ignore:
            continue
        c_id = container.get("Id", "")
        state = container.get("State") or {}
        status = state.get("Status", "unknown")
        health = (state.get("Health") or {}).get("Status", "not configured")
        restart_count = int(container.get("RestartCount", 0))
        log_driver = ((container.get("HostConfig") or {}).get("LogConfig") or {}).get("Type", "default")
        running += status == "running"
        stopped += status != "running"
        unhealthy += health == "unhealthy"
        previous_item = previous_containers.get(name, {})
        states[name] = {"id": c_id, "status": status, "health": health, "restarts": restart_count}
        if status != "running" or health == "unhealthy":
            attention.append(f"{name}: status={status}, health={health}, restarts={restart_count}")
        if status == "running" and health == "unhealthy":
            report.add("HIGH", f"docker:unhealthy:{name}", f"Unhealthy Docker container: {name}", persistent=True)
        if (previous_item.get("status") == "running" and status != "running"
                and name not in config.get("required_containers", [])):
            report.add("HIGH", f"docker:stopped:{name}", f"Docker container stopped: {name} ({status})", persistent=True)
        if previous_item.get("id") == c_id and restart_count > int(previous_item.get("restarts", 0)):
            delta = restart_count - int(previous_item.get("restarts", 0))
            report.add("WARN", f"docker:restart:{name}", f"Docker container {name} restarted {delta} time(s)")
            restarted.append(f"{name}: {delta} restart(s)")
        ports = (container.get("NetworkSettings") or {}).get("Ports") or {}
        binds = []
        for internal, port_bindings in ports.items():
            for bind in port_bindings or []:
                host_ip = bind.get("HostIp") or "0.0.0.0"
                host_port = bind.get("HostPort") or "?"
                entry = f"{name}: {host_ip}:{host_port} -> {internal}"
                binds.append(entry)
                if host_ip not in ("127.0.0.1", "::1", "[::1]"):
                    exposed.append(entry)
        current_exposed = {b for b in binds if b in exposed}
        states[name]["exposed"] = sorted(current_exposed)
        unapproved_ports = {
            item for item in current_exposed
            if item.split(' -> ', 1)[0].rsplit(':', 1)[-1].isdigit()
            if int(item.split(' -> ', 1)[0].rsplit(':', 1)[-1]) not in config.get('allowed_public_ports', [])
        }
        if unapproved_ports:
            report.add("HIGH", f"docker:public-port:{name}",
                       f"Unapproved non-loopback Docker port: {top(collections.Counter({v: 1 for v in unapproved_ports}), 2)}",
                       persistent=True)
        host_cfg = container.get("HostConfig") or {}
        if host_cfg.get("Privileged"):
            privileged.append(f"{name}: privileged=true")
            if config.get("warn_on_privileged_docker", True):
                report.add("WARN", f"docker:privileged:{name}", f"Privileged Docker container: {name}", persistent=True)
        for bind in host_cfg.get("Binds") or []:
            if "/var/run/docker.sock" in bind:
                privileged.append(f"{name}: Docker socket mounted")
                if config.get("warn_on_docker_socket_mount", True):
                    report.add("WARN", f"docker:socket:{name}", f"Docker socket mounted inside container: {name}", persistent=True)
        if not config.get("enable_docker_logs", True):
            continue
        if log_driver == "none":
            report.coverage.append(f"{name}: log driver 'none' disables docker logs")
            continue
        logs = command(
            ["docker", "logs", "--since", start.astimezone(UTC).isoformat(),
             "--until", end.astimezone(UTC).isoformat(), "--timestamps", c_id],
            timeout=20, max_bytes=max_log_bytes,
        )
        if not logs.ok:
            report.coverage.append(f"{name}: docker logs incomplete ({logs.error})")
            report.add("WARN", f"coverage:docker-log:{name}", f"Docker log collection incomplete: {name} ({logs.error})", persistent=True)
        for line in logs.output.splitlines():
            stats.ingest(line)
            if any(re.search(pattern, line, re.I) for pattern in config.get('app_error_patterns', DEFAULTS['app_error_patterns'])):
                app_errors[name] += 1
            for rule_name, pattern, severity in custom_patterns:
                if pattern.search(line):
                    custom_hits[(rule_name, severity, name)] += 1
    for required in config.get("required_containers", []):
        if required not in states:
            report.add("HIGH", f"docker:required-missing:{required}", f"Required Docker container is missing: {required}", persistent=True)
        elif states[required]["status"] != "running":
            report.add("HIGH", f"docker:required-stopped:{required}", f"Required Docker container is not running: {required}", persistent=True)
    for old_name, old_item in previous_containers.items():
        if (old_name not in states and old_item.get("status") == "running"
                and old_name not in ignore and old_name not in config.get("required_containers", [])):
            report.add("HIGH", f"docker:missing:{old_name}", f"Previously running Docker container is missing: {old_name}", persistent=True)
    report.set_metric("Docker containers (running/stopped/unhealthy)", f"{running}/{stopped}/{unhealthy}")
    report.set_metric("Docker non-loopback published port bindings", len(exposed))
    report.set_metric("Docker application error indicators", sum(app_errors.values()))
    docker_lines = [f"Running: {running}; stopped/other: {stopped}; unhealthy: {unhealthy}; healthy or unmonitored running containers are omitted"]
    docker_lines.extend(attention[:12])
    if len(attention) > 12:
        docker_lines.append(f"... and {len(attention) - 12} more non-normal containers")
    docker_lines.extend(restarted[:10])
    report.section("Docker containers", docker_lines)
    if exposed or privileged:
        report.section("Docker exposure and privileges", [
            "Non-loopback published ports: " + ("; ".join(exposed[:15]) or "none"),
            "Elevated privileges: " + ("; ".join(privileged[:10]) or "none"),
        ])
    if app_errors:
        report.section("Docker application logs", [f"Error indicators by container: {top(app_errors)}"])
    analyze_web(stats, "Docker", report, config, "docker-web")
    for (rule_name, severity, name), count in custom_hits.items():
        report.add(severity, f'docker:custom:{rule_name}:{name}',
                   f'Custom Docker log rule {rule_name} matched {count} line(s) in {name}', persistent=True)
    if sum(app_errors.values()) >= int(config.get("app_error_threshold", 30)):
        report.add("WARN", "docker:app-errors", f"Docker application error indicators: {sum(app_errors.values())}; containers: {top(app_errors, 3)}")
    return states


def analyze_services(report: Report, cfg: dict) -> None:
    requested = cfg.get("required_systemd_services", [])
    if not requested:
        return
    lines = []
    for service in requested:
        result = command(["systemctl", "is-active", service], timeout=10, max_bytes=4096)
        status = clean(result.output.strip(), 50) or "unknown"
        lines.append(f"{service}: {status}")
        if status != "active":
            report.add("HIGH", f"service:{service}", f"Required systemd service is not active: {service} ({status})", persistent=True)
    report.section("Required systemd services", lines)


def analyze_disks(report: Report, threshold: int) -> None:
    result = command(["df", "-PTl"], timeout=15, max_bytes=200_000)
    if not result.ok:
        report.coverage.append("Disk usage query failed")
        return
    lines = []
    report.observations["disk_percentages"] = {}
    for line in result.output.splitlines()[1:]:
        columns = line.split(maxsplit=6)
        if len(columns) < 7:
            continue
        device, filesystem, _, _, _, use_text, mount = columns
        if filesystem in ("tmpfs", "devtmpfs", "overlay", "squashfs", "ramfs"):
            continue
        try:
            percent = int(use_text.rstrip("%"))
        except ValueError:
            continue
        lines.append((percent, mount, device))
        report.observations["disk_percentages"][mount] = percent
        critical = report.alert_policy.get("disk_critical_percent", 95)
        if percent >= threshold or percent >= critical:
            report.add("HIGH" if percent >= critical else "WARN", f"disk:{mount}",
                       f"Disk usage {percent}% on {mount} ({device})", persistent=True)
    lines.sort(reverse=True)
    report.set_metric(f"Local filesystems at or above {threshold}%", sum(p >= threshold for p, _, _ in lines))
    report.section("Local disk usage", [f"{p}% {mount} ({device})" for p, mount, device in lines[:5]])



@dataclass
class AlertDecision:
    new_findings: list[Finding]
    recoveries: list[str]
    active_incidents: dict[str, dict]


def incident_identity(finding: Finding, cfg: dict) -> str:
    """Map alternative symptoms of one incident onto a stable identity."""
    key = finding.key
    required = set(cfg.get("required_containers", []))
    for prefix in ("docker:required-stopped:", "docker:required-missing:"):
        if key.startswith(prefix):
            return "docker:required:" + key[len(prefix):]
    if key.startswith("docker:unhealthy:"):
        name = key[len("docker:unhealthy:"):]
        if name in required:
            return "docker:required:" + name
    if key in ("docker:cli-missing", "docker:unavailable", "docker:inspect", "docker:inspect-invalid"):
        return "docker:daemon"
    return key


def selected_alert_incidents(report: Report, cfg: dict) -> dict[str, Finding]:
    """Only explicitly enabled actionable findings are eligible for an email."""
    policy = cfg.get("alert_policy", DEFAULTS["alert_policy"])
    selected = {}
    for finding in report.sorted_findings():
        key = finding.key
        if finding.level != "HIGH" and not (policy["minimum_level"] == "WARN" and finding.level == "WARN"):
            continue
        enabled = False
        if key.startswith("ssh:root:"):
            enabled = policy["root_login_untrusted"] and "[untrusted source]" in finding.message
        elif key == "ssh:spike":
            enabled = policy["ssh_spike"]
        elif key.startswith(("docker:required-stopped:", "docker:required-missing:")):
            enabled = policy["required_container_down"]
        elif key.startswith("docker:unhealthy:"):
            name = key[len("docker:unhealthy:"):]
            enabled = (policy["required_container_unhealthy"] if name in cfg.get("required_containers", [])
                       else policy["other_container_unhealthy"])
        elif key.startswith("service:"):
            enabled = policy["required_service_inactive"]
        elif key.startswith(("docker:unavailable", "docker:cli-missing", "docker:inspect")):
            enabled = policy["docker_daemon_unavailable"]
        elif key.startswith("disk:"):
            mount = key[len("disk:"):]
            value = report.observations.get("disk_percentages", {}).get(mount, -1)
            enabled = policy["disk_critical"] and value >= policy["disk_critical_percent"]
        elif key.startswith("docker:public-port:"):
            enabled = policy["new_public_port"]
        elif key.startswith("docker:custom:"):
            enabled = policy["custom_log_rule"]
        elif key.endswith(":probe2xx"):
            enabled = policy["http_probe_2xx"]
        elif key.endswith(":probes"):
            enabled = policy["http_probe_volume"]
        if enabled:
            identity = incident_identity(finding, cfg)
            if identity not in selected:
                selected[identity] = finding
    return selected


def incident_policy_enabled(identity: str, cfg: dict) -> bool:
    """Disable notifications for categories that a host no longer monitors."""
    policy = cfg.get("alert_policy", DEFAULTS["alert_policy"])
    if identity == "ssh:spike":
        return cfg.get("enable_ssh", True) and policy["ssh_spike"] and cfg.get("severity_overrides", {}).get("ssh_spike") != "OFF"
    if identity.startswith("docker:required:"):
        return (cfg.get("enable_docker", True)
                and identity[len("docker:required:"):] in cfg.get("required_containers", [])
                and (policy["required_container_down"] or policy["required_container_unhealthy"]))
    if identity.startswith("docker:unhealthy:"):
        return cfg.get("enable_docker", True) and policy["other_container_unhealthy"]
    if identity == "docker:daemon":
        return cfg.get("enable_docker", True) and policy["docker_daemon_unavailable"]
    if identity.startswith("docker:public-port:"):
        return cfg.get("enable_docker", True) and policy["new_public_port"]
    if identity.startswith("docker:custom:"):
        return cfg.get("enable_docker_logs", True) and policy["custom_log_rule"]
    if identity.startswith("service:"):
        return (policy["required_service_inactive"]
                and identity[len("service:"):] in cfg.get("required_systemd_services", []))
    if identity.startswith("disk:"):
        return cfg.get("enable_disks", True) and policy["disk_critical"] and cfg.get("severity_overrides", {}).get("disk_usage") != "OFF"
    if identity.endswith(":probe2xx"):
        return policy["http_probe_2xx"]
    if identity.endswith(":probes"):
        return policy["http_probe_volume"]
    return True


def keep_unverified_incident(identity: str, report: Report, cfg: dict) -> bool:
    """Do not silently clear an incident when its health cannot be verified."""
    policy = cfg.get("alert_policy", DEFAULTS["alert_policy"])
    if identity == "ssh:spike":
        if not cfg.get("enable_ssh", True) or any("SSH journal query incomplete" in x for x in report.coverage):
            return True
        failures = report.observations.get("ssh_failure_count_15m")
        return failures is None or failures > policy["ssh_spike_recovery_count"]
    if identity.startswith("disk:"):
        if not cfg.get("enable_disks", True):
            return True
        mount = identity[len("disk:"):]
        percent = report.observations.get("disk_percentages", {}).get(mount)
        return percent is None or percent > policy["disk_recovery_percent"]
    if identity.startswith("docker:") and identity != "docker:daemon":
        return not report.observations.get("docker_query_ok", False)
    if identity.startswith("service:") and not cfg.get("required_systemd_services"):
        return True
    if identity.startswith("host-web:"):
        return not cfg.get("enable_host_http", True) or bool(report.coverage)
    return False


def evaluate_alert(report: Report, previous: dict, cfg: dict) -> AlertDecision:
    """Send once per new incident; do not resend a persistent unchanged issue."""
    policy = cfg.get("alert_policy", DEFAULTS["alert_policy"])
    old_active = previous.get("active_incidents", {})
    if not isinstance(old_active, dict):
        old_active = {}
    chosen = selected_alert_incidents(report, cfg)
    updated = {}
    new_findings = []
    for identity, finding in chosen.items():
        if not finding.persistent:
            # A fresh event in a new, non-overlapping time window is new.
            new_findings.append(finding)
            continue
        prior = old_active.get(identity, {})
        if not prior:
            new_findings.append(finding)
        updated[identity] = {
            "finding_key": finding.key,
            "level": finding.level,
            "message": finding.message,
            "action": finding.action,
            "first_seen": prior.get("first_seen", report.end.isoformat()),
            "last_seen": report.end.isoformat(),
        }
    recoveries = []
    for identity, prior in old_active.items():
        if identity in updated:
            continue
        if not incident_policy_enabled(identity, cfg):
            continue
        if keep_unverified_incident(identity, report, cfg):
            updated[identity] = prior
            continue
        if policy["notify_on_recovery"]:
            recoveries.append(clean(prior.get("message", identity), 250))
    return AlertDecision(new_findings, recoveries, updated)


def merge_ongoing_into_daily(report: Report, state: dict, cfg: dict) -> None:
    """Show every still-active incident daily, without repeating an existing finding."""
    active = state.get("alert", {}).get("active_incidents", {})
    if not isinstance(active, dict):
        return
    for identity, item in sorted(active.items()):
        if not incident_policy_enabled(identity, cfg):
            continue
        first_seen = clean(item.get("first_seen", ""), 50)
        match = None
        for finding in report.findings:
            equivalent = incident_identity(finding, cfg) == identity
            if identity == "ssh:spike" and finding.key == "ssh:failures":
                equivalent = True
            if equivalent:
                match = finding
                break
        if match:
            if item.get("level") == "HIGH":
                match.level = "HIGH"
            match.ongoing_since = first_seen
        else:
            report.findings.append(Finding(
                item.get("level", "WARN"), item.get("finding_key", identity),
                clean(item.get("message", identity), 400), True,
                clean(item.get("action", remediation_for(identity)), 400), first_seen,
            ))


def send_email(report: Report, cfg: dict) -> None:
    recipients = cfg.get("mail_to") or []
    if not recipients:
        raise ValueError("mail_to must contain at least one recipient")
    user = cfg["smtp_user"]
    password = secure_read(Path(cfg["smtp_password_file"])).replace(" ", "")
    if not password:
        raise ValueError("SMTP password file is empty")
    msg = EmailMessage()
    msg["From"] = user
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = report.subject()
    msg.set_content(report.plaintext())
    msg.add_alternative(report.htmltext(), subtype="html")
    context = ssl.create_default_context()
    with smtplib.SMTP(cfg.get("smtp_host", "smtp.gmail.com"), int(cfg.get("smtp_port", 587)), timeout=30) as smtp:
        smtp.ehlo()
        smtp.starttls(context=context)
        smtp.ehlo()
        smtp.login(user, password)
        smtp.send_message(msg)


def load_state() -> dict:
    location = STATE_DIR / "state.json"
    if not location.exists():
        return {}
    return json.loads(location.read_text(encoding="utf-8"))


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="state.", suffix=".tmp", dir=STATE_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o600)
        os.replace(name, STATE_DIR / "state.json")
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save_local_report(report: Report, retention_days: int) -> None:
    LOG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    filename = LOG_DIR / f"{report.mode}-{report.end.astimezone(UTC):%Y%m%dT%H%M%SZ}.txt"
    with open(filename, "x", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(report.plaintext())
    cutoff = time.time() - retention_days * 86400
    for item in LOG_DIR.glob("*.txt"):
        if item.stat().st_mtime < cutoff:
            item.unlink()


def build_report(cfg: dict, state: dict, mode: str, end: dt.datetime) -> tuple[Report, dict]:
    current_mode = state.get(mode, {})
    default_hours = 24 if mode == "daily" else 0.25
    last_sent = current_mode.get("last_checked")
    if last_sent:
        start = dt.datetime.fromisoformat(last_sent)
        if start >= end:
            start = end - dt.timedelta(minutes=15 if mode == "alert" else 1440)
    else:
        start = end - dt.timedelta(hours=default_hours)
    report = Report(host=clean(cfg.get('report_label') or socket.gethostname(), 70),
                    start=start, end=end, mode=mode,
                    severity_overrides=cfg.get('severity_overrides', {}),
                    alert_policy=cfg.get('alert_policy', DEFAULTS['alert_policy']))
    if cfg.get('enable_ssh', True):
        analyze_ssh(start, end, report, cfg)
    if mode == "alert" and cfg.get("enable_ssh", True):
        policy = cfg.get("alert_policy", DEFAULTS["alert_policy"])
        current_failures = report.counts.get("SSH authentication failures (log entries)", 0)
        window_minutes = max((end - start).total_seconds() / 60, 1)
        rate_15m = current_failures * 15 / window_minutes
        report.observations["ssh_failure_count_15m"] = rate_15m
        previous_rate = current_mode.get("last_ssh_rate_15m")
        already_active = "ssh:spike" in current_mode.get("active_incidents", {})
        increased = (previous_rate is None or
                     rate_15m >= max(1, previous_rate) * policy["ssh_spike_increase_factor"])
        if (policy["ssh_spike"] and rate_15m >= policy["ssh_spike_trigger_count"]
                and (increased or already_active)):
            report.add("HIGH", "ssh:spike",
                       f"Sudden SSH authentication failure surge: {current_failures} log entries "
                       f"over {window_minutes:.0f} minutes ({rate_15m:.1f} per 15 minutes)",
                       persistent=True)
    if cfg.get('enable_guards', True):
        analyze_guards(start, end, report)
    if cfg.get('enable_host_http', True):
        host_stats = host_access_stats(start, end, cfg.get('host_access_log_globs', []), report, cfg)
        analyze_web(host_stats, "Host", report, cfg, "host-web")
    current_containers = parse_docker(cfg, report, current_mode, start, end) if cfg.get('enable_docker', True) else {}
    analyze_services(report, cfg)
    if cfg.get('enable_disks', True):
        analyze_disks(report, int(cfg.get("disk_warning_percent", 90)))
    if mode == "daily":
        previous_counts = current_mode.get("last_counts") or {}
        previous_hours = float(current_mode.get("last_window_hours", 0))
        current_hours = (end - start).total_seconds() / 3600
        if (
            previous_counts and 20 <= previous_hours <= 28
            and 20 <= current_hours <= 28
        ):
            report.previous_counts = {
                name: count for name, count in previous_counts.items()
                if isinstance(name, str) and isinstance(count, int)
            }
            report.comparison_note = "Compared with the previous comparable daily report (approximately 24 hours each)."
        elif previous_counts:
            report.comparison_note = "Comparison omitted: the reporting intervals are not comparable."
        else:
            report.comparison_note = "Baseline unavailable; daily comparison starts after the next report."
    if mode == "daily":
        merge_ongoing_into_daily(report, state, cfg)
    return report, current_containers


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize security logs on Ubuntu/Debian hosts with Docker support")
    parser.add_argument("--config", default=CONFIG_DEFAULT)
    parser.add_argument("--mode", choices=["daily", "alert"], default="daily")
    parser.add_argument("--dry-run", action="store_true", help="Print report; do not email or advance checkpoints")
    parser.add_argument("--test-email", action="store_true", help="Send a test email without changing checkpoints")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("This tool must run as root", file=sys.stderr)
        return 2
    try:
        cfg = validate(json.loads(secure_read(Path(args.config))))
        LOCK_PATH.parent.mkdir(mode=0o755, exist_ok=True, parents=True)
        with open(LOCK_PATH, "a+", encoding="ascii") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print("Another monitor instance is running")
                return 0
            end = dt.datetime.now().astimezone()
            if args.test_email:
                report = Report(clean(cfg.get("report_label") or socket.gethostname(), 70), end - dt.timedelta(minutes=1), end, "test")
                report.metrics = {"SMTP test": "successful if this email arrived"}
                send_email(report, cfg)
                print("Test email accepted by SMTP server")
                return 0
            state = load_state()
            report, containers = build_report(cfg, state, args.mode, end)
            mode_state = state.get(args.mode, {})
            if args.mode == "alert":
                decision = evaluate_alert(report, mode_state, cfg)
                report.findings = decision.new_findings
                report.recoveries = decision.recoveries
                should_email = bool(report.findings or report.recoveries)
                if args.dry_run:
                    print(report.plaintext())
                    print("Alert preview; email would be sent: " + str(should_email))
                    return 0
                if should_email:
                    send_email(report, cfg)
                mode_state["active_incidents"] = decision.active_incidents
                mode_state["last_ssh_rate_15m"] = report.observations.get("ssh_failure_count_15m", 0)
                mode_state.pop("persistent_alerts", None)
            else:
                if args.dry_run:
                    print(report.plaintext())
                    return 0
                send_email(report, cfg)
                should_email = True
            mode_state["last_checked"] = end.isoformat()
            mode_state["containers"] = containers
            if args.mode == "daily":
                mode_state["last_counts"] = report.counts
                mode_state["last_window_hours"] = (report.end - report.start).total_seconds() / 3600
            state[args.mode] = mode_state
            save_state(state)
            if args.mode == "daily" or should_email:
                save_local_report(report, int(cfg.get("retention_days", 90)))
            print(f"{args.mode} check complete; email_sent={should_email}; status={report.status}")
            return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, smtplib.SMTPException) as exc:
        print(f"Monitoring failed: {clean(exc, 400)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
