#!/usr/bin/env python3
"""Shared defaults, validation, and secure configuration I/O."""

from __future__ import annotations

import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile

CONFIG_DIR = Path('/etc/server-security-report')
CONFIG_PATH = CONFIG_DIR / 'config.json'
SECRET_PATH = CONFIG_DIR / 'smtp-password'

DEFAULTS = {
    'smtp_host': 'smtp.gmail.com',
    'smtp_port': 587,
    'smtp_user': '',
    'smtp_password_file': str(SECRET_PATH),
    'mail_to': [],
    'report_label': '',
    'enable_ssh': True,
    'enable_guards': True,
    'enable_host_http': True,
    'enable_docker': True,
    'enable_docker_logs': True,
    'enable_disks': True,
    'ssh_failure_threshold': 30,
    'alert_on_ssh_password_success': True,
    'alert_on_all_ssh_success': False,
    'trusted_ssh_cidrs': [],
    'web_probe_threshold': 20,
    'web_5xx_threshold': 50,
    'app_error_threshold': 30,
    'disk_warning_percent': 90,
    'max_docker_log_bytes_per_container': 800000,
    'retention_days': 90,
    'ignore_containers': [],
    'required_containers': [],
    'required_systemd_services': [],
    'allowed_public_ports': [],
    'host_access_log_globs': [],
    'http_probe_patterns': [
        r'/\.env(?:[/?#]|$)',
        r'/\.git(?:[/?#]|$)',
        r'(?:\.\./|%2e%2e%2f|%252e%252e%252f)',
        r'(?:\$\{jndi:|%24%7bjndi)',
        r'\?unix:',
    ],
    'ignored_http_path_patterns': [],
    'app_error_patterns': [
        r'Fatal error', r'Uncaught (?:Exception|Error)',
        r'\b(?:FATAL|CRITICAL)\b', r'authentication failed',
        r'login failed',
    ],
    'application_log_rules': [],
    'severity_overrides': {},
    'warn_on_privileged_docker': True,
    'warn_on_docker_socket_mount': True,
}

RULE_LABELS = {
    'ssh_root': ('Direct root SSH login', 'ssh:root:'),
    'ssh_password': ('SSH password authentication', 'ssh:password:'),
    'ssh_login': ('SSH successful authentication', 'ssh:login:'),
    'ssh_failures': ('SSH failure threshold', 'ssh:failures'),
    'http_probe_success': ('HTTP probe returning 2xx', ':probe2xx'),
    'http_probes': ('HTTP probe threshold', ':probes'),
    'http_5xx': ('HTTP 5xx threshold', ':http5xx'),
    'docker_unhealthy': ('Docker healthcheck failure', 'docker:unhealthy:'),
    'docker_required_missing': ('Required Docker container missing', 'docker:required-missing:'),
    'docker_required_stopped': ('Required Docker container stopped', 'docker:required-stopped:'),
    'docker_stopped': ('Previously running Docker container stopped', 'docker:stopped:'),
    'docker_missing': ('Previously running Docker container missing', 'docker:missing:'),
    'docker_restart': ('Docker restart count increase', 'docker:restart:'),
    'docker_new_port': ('New external Docker port', 'docker:new-exposure:'),
    'docker_privileged': ('Privileged Docker container', 'docker:privileged:'),
    'docker_socket': ('Docker socket mount', 'docker:socket:'),
    'docker_app_errors': ('Docker application error threshold', 'docker:app-errors'),
    'service_inactive': ('Required systemd service inactive', 'service:'),
    'disk_usage': ('Disk usage threshold', 'disk:'),
    'coverage': ('Monitoring coverage incomplete', 'coverage:'),
}


def defaults():
    return copy.deepcopy(DEFAULTS)


def secure_read(path: Path) -> str:
    """Reject symlinks and files not owned by root or accessible to others."""
    path = Path(path)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077:
        raise ValueError('Refusing insecure file type, owner, or permissions: ' + str(path))
    return path.read_text(encoding='utf-8').strip()


def secure_write(path: Path, contents: str) -> None:
    """Replace a root-only file atomically without putting data in the shell history."""
    if os.geteuid() != 0:
        raise PermissionError('Configuration writes require root')
    path = Path(path)
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or parent.stat().st_uid != 0 or stat.S_IMODE(parent.stat().st_mode) & 0o077:
        raise ValueError('Refusing insecure configuration directory: ' + str(parent))
    if path.is_symlink():
        raise ValueError('Refusing to overwrite a symbolic link: ' + str(path))
    if path.exists():
        secure_read(path)
    fd, tmp = tempfile.mkstemp(prefix='.tmp-', dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        directory_fd = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def validate(config: dict, require_email: bool = True) -> dict:
    if not isinstance(config, dict):
        raise ValueError('Configuration must be a JSON object')
    unknown = set(config) - set(DEFAULTS)
    if unknown:
        raise ValueError('Unknown configuration keys: ' + ', '.join(sorted(unknown)))
    cfg = defaults()
    cfg.update(config)
    if require_email:
        if not cfg['smtp_user'] or not cfg['mail_to']:
            raise ValueError('SMTP account and at least one recipient must be configured')
    for key in ('smtp_user', 'smtp_host', 'smtp_password_file', 'report_label'):
        if not isinstance(cfg[key], str) or '\n' in cfg[key] or '\r' in cfg[key]:
            raise ValueError('Invalid string setting: ' + key)
    if require_email and ('@' not in cfg['smtp_user'] or not cfg['smtp_host']):
        raise ValueError('SMTP account must be an email address and host must be nonempty')
    for key in ('mail_to', 'trusted_ssh_cidrs', 'ignore_containers', 'required_containers',
                'required_systemd_services', 'host_access_log_globs', 'http_probe_patterns',
                'ignored_http_path_patterns', 'app_error_patterns'):
        value = cfg[key]
        if not isinstance(value, list) or any(not isinstance(v, str) or not v or len(v) > 400 for v in value):
            raise ValueError('Setting must be a list of nonempty strings: ' + key)
    if any('@' not in address or '\n' in address or '\r' in address for address in cfg['mail_to']):
        raise ValueError('Invalid SMTP recipient')
    for key in ('smtp_port', 'ssh_failure_threshold', 'web_probe_threshold',
                'web_5xx_threshold', 'app_error_threshold', 'disk_warning_percent',
                'max_docker_log_bytes_per_container', 'retention_days'):
        value = cfg[key]
        if type(value) is not int or not 1 <= value <= (10_000_000 if key == 'max_docker_log_bytes_per_container' else 65535):
            raise ValueError('Invalid positive integer: ' + key)
    if cfg['disk_warning_percent'] > 100:
        raise ValueError('Disk warning percentage cannot exceed 100')
    for key in ('enable_ssh', 'enable_guards', 'enable_host_http', 'enable_docker',
                'enable_docker_logs', 'enable_disks', 'alert_on_ssh_password_success',
                'alert_on_all_ssh_success', 'warn_on_privileged_docker', 'warn_on_docker_socket_mount'):
        if type(cfg[key]) is not bool:
            raise ValueError('Expected boolean: ' + key)
    for cidr in cfg['trusted_ssh_cidrs']:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError('Invalid trusted SSH network: ' + cidr) from exc
    for key in ('http_probe_patterns', 'ignored_http_path_patterns', 'app_error_patterns'):
        for pattern in cfg[key]:
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise ValueError('Invalid regex in ' + key + ': ' + str(exc)) from exc
    if not isinstance(cfg['allowed_public_ports'], list) or any(
        type(port) is not int or not (1 <= port <= 65535) for port in cfg['allowed_public_ports']
    ):
        raise ValueError('Allowed public ports must be integer port numbers')
    if not isinstance(cfg['severity_overrides'], dict) or any(
        name not in RULE_LABELS or value not in ('DEFAULT', 'WARN', 'HIGH', 'OFF')
        for name, value in cfg['severity_overrides'].items()
    ):
        raise ValueError('Invalid severity override')
    if not isinstance(cfg['application_log_rules'], list):
        raise ValueError('Application rules must be a list')
    names = set()
    for rule in cfg['application_log_rules']:
        if not isinstance(rule, dict) or set(rule) != {'name', 'pattern', 'severity'}:
            raise ValueError('Application rule must have name, pattern, and severity')
        name, pattern, severity = rule['name'], rule['pattern'], rule['severity']
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', name) or name in names:
            raise ValueError('Application rule name must be unique and use ASCII letters, digits, dash or underscore')
        names.add(name)
        if not isinstance(pattern, str) or len(pattern) > 400 or severity not in ('WARN', 'HIGH'):
            raise ValueError('Invalid application rule pattern or severity')
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError('Invalid application rule regex: ' + str(exc)) from exc
    path = Path(cfg['smtp_password_file'])
    if not path.is_absolute() or os.path.commonpath((str(CONFIG_DIR), str(path.resolve(strict=False)))) != str(CONFIG_DIR):
        raise ValueError('SMTP secret must be kept under the private configuration directory')
    return cfg


def load(path: Path = CONFIG_PATH) -> dict:
    return validate(json.loads(secure_read(path)))


def secret_status(config: dict) -> str:
    try:
        secret = secure_read(Path(config['smtp_password_file']))
        return 'configured' if secret else 'empty'
    except FileNotFoundError:
        return 'missing'
    except (OSError, ValueError):
        return 'unsafe or unreadable'


def redacted_config(config: dict) -> dict:
    data = copy.deepcopy(config)
    data['smtp_host'] = '[configured]' if data['smtp_host'] else '[not configured]'
    data['smtp_user'] = 'configured' if data['smtp_user'] else 'not configured'
    data['mail_to'] = ['[recipient hidden]'] * len(data['mail_to'])
    data['smtp_password_file'] = '[private configuration path]'
    data['report_label'] = '[configured]' if data['report_label'] else '[local hostname]'
    for key in ('required_containers', 'ignore_containers', 'required_systemd_services',
                'host_access_log_globs', 'trusted_ssh_cidrs', 'application_log_rules',
                'http_probe_patterns', 'ignored_http_path_patterns', 'app_error_patterns'):
        count = len(data[key])
        data[key] = '[%d configured]' % count
    data['allowed_public_ports'] = '[%d configured]' % len(data['allowed_public_ports'])
    return data
