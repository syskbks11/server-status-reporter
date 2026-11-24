#!/usr/bin/env python3
"""Conservative publication check for emails, routable IPs, and key blocks."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b')
IP = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
ALLOWED_DOMAINS = {'example.com', 'example.org', 'example.net', 'example.invalid'}
KEY_MARKERS = ('-----BEGIN PRIVATE KEY-----', '-----BEGIN OPENSSH PRIVATE KEY-----')
SKIP_DIRS = {'__pycache__', '.git', '.venv'}
SENSITIVE_FILENAMES = {'config.json', 'smtp-password', 'gmail-app-password', 'state.json'}


def check_text(content: str, filename: str) -> list[str]:
    problems = []
    for match in MAIL.finditer(content):
        if match.group(1).lower() not in ALLOWED_DOMAINS:
            problems.append(filename + ': non-placeholder email address')
    for match in IP.finditer(content):
        try:
            addr = ipaddress.ip_address(match.group())
        except ValueError:
            continue
        if not any(addr in ipaddress.ip_network(prefix) for prefix in
                   ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24',
                    '127.0.0.0/8', '0.0.0.0/8')):
            problems.append(filename + ': non-documentation IPv4 address')
    if any(marker in content for marker in KEY_MARKERS):
        problems.append(filename + ': private key marker')
    return sorted(set(problems))


def main() -> int:
    failures = []
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.name in SENSITIVE_FILENAMES:
            failures.append(str(path.relative_to(ROOT)) + ': potentially private runtime file')
            continue
        if path.suffix not in {'.md', '.py', '.txt', '.json', '.sh', '.html', '.service', '.timer', ''}:
            continue
        if path.name in ('privacy_check.py',):
            continue
        try:
            content = path.read_text(encoding='utf-8')
        except (UnicodeError, OSError):
            continue
        failures.extend(check_text(content, str(path.relative_to(ROOT))))
    if failures:
        for failure in failures:
            print('WARNING:', failure)
        return 1
    print('No non-placeholder emails, non-documentation IPv4 addresses, or private key blocks detected.')
    print('Manual review of filenames, commit metadata, paths, and log excerpts is still required.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
