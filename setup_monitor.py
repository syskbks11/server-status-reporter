#!/usr/bin/env python3
"""Minimal initial setup and item-by-item interactive configuration."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import sys

from monitor_config import (
    CONFIG_PATH, RULE_LABELS, defaults, load, redacted_config,
    secret_status, secure_write, validate,
)


MONITOR_FIELDS = [
    ('enable_ssh', 'Read SSH authentication events', 'bool'),
    ('enable_guards', 'Read connection guard events', 'bool'),
    ('enable_host_http', 'Read host reverse-proxy access logs', 'bool'),
    ('enable_docker', 'Monitor Docker container state', 'bool'),
    ('enable_docker_logs', 'Scan Docker application logs', 'bool'),
    ('enable_disks', 'Check disk utilization', 'bool'),
    ('required_containers', 'Required container names', 'list'),
    ('ignore_containers', 'Container names to ignore', 'list'),
    ('required_systemd_services', 'Required systemd service units', 'list'),
    ('host_access_log_globs', 'Host HTTP log path patterns', 'list'),
    ('allowed_public_ports', 'Approved public Docker ports', 'ports'),
]

THRESHOLD_FIELDS = [
    ('ssh_failure_threshold', 'SSH failure count', 'int'),
    ('web_probe_threshold', 'Suspicious HTTP request count', 'int'),
    ('web_5xx_threshold', 'HTTP 5xx response count', 'int'),
    ('app_error_threshold', 'Application error count', 'int'),
    ('disk_warning_percent', 'Disk warning percentage', 'percent'),
    ('max_docker_log_bytes_per_container', 'Maximum Docker log bytes per scan', 'bytes'),
    ('retention_days', 'Report retention in days', 'int'),
    ('alert_on_ssh_password_success', 'Warn on SSH password logins', 'bool'),
    ('alert_on_all_ssh_success', 'Warn on all SSH logins', 'bool'),
    ('warn_on_privileged_docker', 'Warn on privileged containers', 'bool'),
    ('warn_on_docker_socket_mount', 'Warn on Docker socket mounts', 'bool'),
]

ALERT_FIELDS = [
    ('root_login_untrusted', 'Notify on untrusted root SSH login', 'bool'),
    ('ssh_spike', 'Notify on SSH failure surge', 'bool'),
    ('required_container_down', 'Notify on required container stopped or missing', 'bool'),
    ('required_container_unhealthy', 'Notify on required container unhealthy', 'bool'),
    ('other_container_unhealthy', 'Notify on other unhealthy containers', 'bool'),
    ('required_service_inactive', 'Notify on inactive required systemd service', 'bool'),
    ('docker_daemon_unavailable', 'Notify when Docker monitoring is unavailable', 'bool'),
    ('disk_critical', 'Notify on critical disk usage', 'bool'),
    ('new_public_port', 'Notify on newly exposed unapproved Docker port', 'bool'),
    ('custom_log_rule', 'Notify on custom application log rule', 'bool'),
    ('http_probe_2xx', 'Notify on suspicious HTTP request returning 2xx', 'bool'),
    ('http_probe_volume', 'Notify on unusually many suspicious HTTP requests', 'bool'),
    ('notify_on_recovery', 'Send separate recovery notifications', 'bool'),
    ('minimum_level', 'Minimum emergency severity', 'level'),
    ('ssh_spike_trigger_count', 'SSH surge trigger threshold', 'int'),
    ('ssh_spike_recovery_count', 'SSH surge recovery threshold', 'nonnegative'),
    ('ssh_spike_increase_factor', 'SSH surge increase factor', 'float'),
    ('disk_critical_percent', 'Critical disk percentage', 'percent'),
    ('disk_recovery_percent', 'Disk recovery percentage', 'percent'),
]

PATTERN_FIELDS = [
    ('trusted_ssh_cidrs', 'Trusted SSH source CIDRs', 'list'),
    ('http_probe_patterns', 'Suspicious HTTP request path regexes', 'regex'),
    ('ignored_http_path_patterns', 'Excluded HTTP request path regexes', 'regex'),
    ('app_error_patterns', 'Docker application error regexes', 'regex'),
    ('application_log_rules', 'Custom Docker application log rules', 'rules'),
]

DELIVERY_FIELDS = [
    ('smtp_user', 'SMTP login email address', 'string'),
    ('mail_to', 'Email recipients', 'list'),
    ('smtp_password', 'SMTP app password', 'secret'),
    ('smtp_host', 'SMTP hostname', 'string'),
    ('smtp_port', 'SMTP port', 'int'),
    ('report_label', 'Optional generic report label', 'string'),
]


def ask(prompt: str, current: str = '') -> str:
    suffix = (' [' + current + ']') if current else ''
    return input(prompt + suffix + ': ').strip()


def ask_string(name: str, current: str) -> str:
    value = ask(name, current)
    return value if value else current


def ask_bool(name: str, current: bool) -> bool:
    while True:
        value = ask(name + ' (y/n)', 'y' if current else 'n').lower()
        if not value:
            return current
        if value in ('y', 'yes'):
            return True
        if value in ('n', 'no'):
            return False
        print('Enter y or n.')


def ask_int(name: str, current: int, low: int = 1, high: int = 65535) -> int:
    while True:
        value = ask(name, str(current))
        if not value:
            return current
        try:
            result = int(value)
            if low <= result <= high:
                return result
        except ValueError:
            pass
        print('Enter an integer between %d and %d.' % (low, high))


def ask_float(name: str, current: float, low: float = 1.0, high: float = 1000.0) -> float:
    while True:
        value = ask(name, str(current))
        if not value:
            return current
        try:
            result = float(value)
            if low <= result <= high:
                return result
        except ValueError:
            pass
        print('Enter a number between %s and %s.' % (low, high))


def ask_choice(name: str, current: str, choices: tuple[str, ...]) -> str:
    while True:
        value = ask(name, current).upper() or current
        if value in choices:
            return value
        print('Enter one of: ' + ', '.join(choices))


def ask_list(name: str, current: list[str]) -> list[str]:
    print(name + ' (' + str(len(current)) + ' configured)')
    print('  Enter comma-separated values; Enter keeps current values; CLEAR removes all.')
    value = input('  New list: ').strip()
    if not value:
        return list(current)
    if value.upper() == 'CLEAR':
        return []
    return [item.strip() for item in value.split(',') if item.strip()]


def ask_regex_list(name: str, current: list[str]) -> list[str]:
    print('\n' + name)
    for index, value in enumerate(current, 1):
        print('  %d. %s' % (index, value))
    choice = ask_choice('Keep, clear, or replace (KEEP/CLEAR/EDIT)', 'KEEP',
                        ('KEEP', 'CLEAR', 'EDIT'))
    if choice == 'KEEP':
        return list(current)
    if choice == 'CLEAR':
        return []
    print('Enter one regex per line; an empty line finishes editing.')
    patterns = []
    while True:
        pattern = input('Pattern: ').strip()
        if not pattern:
            break
        patterns.append(pattern)
    return patterns


def ask_password(staged_secret: list[str | None], *, required: bool) -> None:
    """Keep the password in memory until validated and explicitly saved."""
    while True:
        first = getpass.getpass('SMTP app password (hidden): ').strip()
        if not first and not required:
            print('Password unchanged.')
            return
        if not first:
            print('An SMTP app password is required.')
            continue
        second = getpass.getpass('Repeat SMTP app password: ').strip()
        if first != second:
            print('Passwords do not match; please try again.')
            continue
        staged_secret[0] = first
        print('Password staged (not saved yet).')
        return


def initial_smtp(cfg: dict, staged_secret: list[str | None]) -> None:
    """Ask only for the mandatory SMTP details; keep all monitoring defaults."""
    print('\nQuick setup: SMTP sender, recipients, and app password only.')
    print('SMTP server and port use saved settings or the STARTTLS defaults.')
    while True:
        cfg['smtp_user'] = ask_string('SMTP login email address', cfg['smtp_user'])
        if '@' in cfg['smtp_user']:
            break
        print('Enter a valid SMTP login email address.')
    while True:
        cfg['mail_to'] = ask_list('Report recipients', cfg['mail_to'])
        if cfg['mail_to'] and all('@' in item for item in cfg['mail_to']):
            break
        print('At least one valid recipient is required.')
    if secret_status(cfg) != 'configured':
        ask_password(staged_secret, required=True)
    else:
        print('An SMTP app password is already configured.')
    print('All monitoring sources and alert thresholds use built-in defaults.')
    print('Use --configure to change individual settings later.')


def ask_custom_rules(current: list[dict]) -> list[dict]:
    print('Current rules: ' + ', '.join(rule['name'] for rule in current))
    choice = ask_choice('Keep, clear, or replace rules (KEEP/CLEAR/EDIT)', 'KEEP',
                        ('KEEP', 'CLEAR', 'EDIT'))
    if choice == 'KEEP':
        return list(current)
    if choice == 'CLEAR':
        return []
    print('Enter a blank rule ID to finish.')
    rules = []
    while True:
        name = input('Rule ID (ASCII identifier): ').strip()
        if not name:
            break
        pattern = input('Matching regex: ').strip()
        severity = ask_choice('Finding severity (WARN/HIGH)', 'WARN', ('WARN', 'HIGH'))
        rules.append({'name': name, 'pattern': pattern, 'severity': severity})
    return rules


def value_summary(cfg: dict, staged_secret: list[str | None], key: str, kind: str) -> str:
    """Display only non-sensitive values in option menus."""
    if kind == 'secret':
        return 'staged' if staged_secret[0] is not None else secret_status(cfg)
    if key.startswith('alert_policy.'):
        value = cfg['alert_policy'][key.split('.', 1)[1]]
    elif key.startswith('severity_overrides.'):
        value = cfg['severity_overrides'].get(key.split('.', 1)[1], 'DEFAULT')
    else:
        value = cfg[key]
    if key in ('smtp_user', 'smtp_host', 'report_label'):
        return 'configured' if value else 'not configured'
    if kind in ('list', 'regex', 'ports', 'rules'):
        return '%d configured' % len(value)
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    return str(value)


def edit_one(cfg: dict, staged_secret: list[str | None], key: str, label: str, kind: str) -> None:
    """Edit exactly one setting selected by the operator."""
    if kind == 'secret':
        ask_password(staged_secret, required=False)
        return
    parent = cfg
    name = key
    if '.' in key:
        parent_name, name = key.split('.', 1)
        parent = cfg[parent_name]
    current = parent.get(name, 'DEFAULT')
    if kind == 'bool':
        value = ask_bool(label, current)
    elif kind in ('int', 'nonnegative', 'percent', 'bytes'):
        low = 0 if kind == 'nonnegative' else 1
        high = 100 if kind == 'percent' else (10000000 if kind == 'bytes' else 65535)
        value = ask_int(label, current, low, high)
    elif kind == 'float':
        value = ask_float(label, current)
    elif kind == 'string':
        value = ask_string(label, current)
    elif kind == 'list':
        value = ask_list(label, current)
    elif kind == 'regex':
        value = ask_regex_list(label, current)
    elif kind == 'ports':
        while True:
            entries = ask_list(label, [str(port) for port in current])
            if all(entry.isdigit() and 1 <= int(entry) <= 65535 for entry in entries):
                value = [int(entry) for entry in entries]
                break
            print('All ports must be integers between 1 and 65535.')
    elif kind == 'rules':
        value = ask_custom_rules(current)
    elif kind == 'level':
        value = ask_choice(label + ' (HIGH/WARN)', current, ('HIGH', 'WARN'))
    elif kind == 'severity':
        value = ask_choice(label + ' (DEFAULT/WARN/HIGH/OFF)', current,
                           ('DEFAULT', 'WARN', 'HIGH', 'OFF'))
        if value == 'DEFAULT':
            parent.pop(name, None)
            return
    else:
        raise ValueError('Unknown interactive setting type: ' + kind)
    parent[name] = value
    print('Updated in memory. Save changes from the main menu.')


def section_menu(cfg: dict, staged_secret: list[str | None], title: str,
                 fields: list[tuple[str, str, str]]) -> None:
    while True:
        print('\n' + title)
        for index, (key, label, kind) in enumerate(fields, 1):
            print('%2d) %s [%s]' % (index, label, value_summary(cfg, staged_secret, key, kind)))
        print(' 0) Back')
        choice = input('Select a setting: ').strip()
        if choice == '0' or not choice:
            return
        if not choice.isdecimal() or not (1 <= int(choice) <= len(fields)):
            print('Select an available number.')
            continue
        edit_one(cfg, staged_secret, *fields[int(choice) - 1])


def save_config(config_path: Path, cfg: dict, staged_secret: list[str | None]) -> bool:
    """Validate before writing, retaining the edit session after a failed save."""
    try:
        cfg = validate(cfg)
    except (ValueError, TypeError) as exc:
        print('Configuration not saved: ' + str(exc), file=sys.stderr)
        return False
    if staged_secret[0] is None and secret_status(cfg) != 'configured':
        print('Configuration not saved: SMTP app password is required.', file=sys.stderr)
        return False
    if not ask_bool('Save this configuration', True):
        print('Returning to settings without saving.')
        return False
    if staged_secret[0] is not None:
        secure_write(Path(cfg['smtp_password_file']), staged_secret[0] + '\n')
    secure_write(config_path, json.dumps(cfg, indent=2, sort_keys=True) + '\n')
    print('Configuration saved: ' + str(config_path))
    print('Test email: server-security-report --test-email')
    return True


def show(cfg: dict) -> None:
    print(json.dumps(redacted_config(cfg), indent=2, sort_keys=True))
    print('SMTP secret status: ' + secret_status(cfg))


def interactive(config_path: Path, initial: bool) -> int:
    cfg = load(config_path) if config_path.exists() else defaults()
    staged_secret: list[str | None] = [None]
    print('Server Security Monitor - interactive setup')
    print('Settings and secrets are stored outside the Git checkout.')
    if initial:
        initial_smtp(cfg, staged_secret)
        return 0 if save_config(config_path, cfg, staged_secret) else 1
    severity_fields = [
        ('severity_overrides.' + key, label, 'severity')
        for key, (label, _) in RULE_LABELS.items()
    ]
    sections = [
        ('SMTP delivery and recipients', DELIVERY_FIELDS),
        ('Monitoring sources and targets', MONITOR_FIELDS),
        ('Daily report thresholds', THRESHOLD_FIELDS),
        ('Emergency notification policy', [
            ('alert_policy.' + key, label, kind) for key, label, kind in ALERT_FIELDS
        ]),
        ('Matching rules and exclusions', PATTERN_FIELDS),
        ('Finding severity overrides', severity_fields),
    ]
    while True:
        print('\nConfiguration menu')
        for index, (label, _) in enumerate(sections, 1):
            print('%d) %s' % (index, label))
        print('7) Preview redacted settings')
        print('8) Save and exit')
        print('0) Exit without saving')
        choice = input('Select: ').strip()
        if choice == '0':
            print('No changes saved.')
            return 0
        if choice == '7':
            show(cfg)
        elif choice == '8':
            if save_config(config_path, cfg, staged_secret):
                return 0
        elif choice.isdecimal() and 1 <= int(choice) <= len(sections):
            title, fields = sections[int(choice) - 1]
            section_menu(cfg, staged_secret, title, fields)
        else:
            print('Select an available number.')


def main() -> int:
    parser = argparse.ArgumentParser(description='Configure server security monitoring interactively')
    parser.add_argument('--config', type=Path, default=CONFIG_PATH)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--init', action='store_true', help='Configure SMTP and use default monitoring rules')
    group.add_argument('--configure', action='store_true', help='Edit individual settings using menus')
    group.add_argument('--show', action='store_true', help='Show redacted settings')
    group.add_argument('--validate', action='store_true', help='Validate settings and secret permissions')
    args = parser.parse_args()
    if os.geteuid() != 0:
        print('Run as root.', file=sys.stderr)
        return 2
    try:
        if args.show or args.validate:
            cfg = load(args.config)
            status = secret_status(cfg)
            if args.show:
                show(cfg)
            if args.validate:
                if status != 'configured':
                    raise ValueError('SMTP app password is ' + status)
                print('Configuration and SMTP secret permissions are valid.')
            return 0
        if not sys.stdin.isatty():
            print('Interactive setup requires a terminal.', file=sys.stderr)
            return 2
        return interactive(args.config, args.init or not args.config.exists())
    except (OSError, ValueError, json.JSONDecodeError, EOFError, KeyboardInterrupt) as exc:
        print('Setup stopped: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
