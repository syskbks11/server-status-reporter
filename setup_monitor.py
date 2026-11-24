#!/usr/bin/env python3
"""Interactive terminal configuration for Server Security Monitor."""

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


def ask_list(name: str, current: list[str], *, sep: str = ',') -> list[str]:
    print(name + ' (' + str(len(current)) + ' configured)')
    print('  Press Enter to keep, type CLEAR to remove all, or enter a new comma-separated list.')
    value = input('  New list: ').strip()
    if not value:
        return list(current)
    if value.upper() == 'CLEAR':
        return []
    return [item.strip() for item in value.split(sep) if item.strip()]


def ask_regex_list(name: str, current: list[str]) -> list[str]:
    print('\n' + name)
    print('Current regular expressions:')
    for idx, value in enumerate(current, 1):
        print('  %d. %s' % (idx, value))
    print('Press Enter to keep the list, CLEAR to remove all, or EDIT to replace it.')
    choice = input('Choice: ').strip().upper()
    if not choice:
        return list(current)
    if choice == 'CLEAR':
        return []
    if choice != 'EDIT':
        print('Unrecognized choice; keeping the existing list.')
        return list(current)
    print('Enter one Python regular expression per line. Enter a blank line to finish.')
    patterns = []
    while True:
        pattern = input('Pattern: ').strip()
        if not pattern:
            break
        patterns.append(pattern)
    return patterns


def email_section(cfg: dict, secret: list[str | None]) -> None:
    print('\nSMTP delivery (STARTTLS is required; secret input is hidden)')
    cfg['smtp_host'] = ask_string('SMTP hostname', cfg['smtp_host'])
    cfg['smtp_port'] = ask_int('SMTP port', cfg['smtp_port'])
    cfg['smtp_user'] = ask_string('SMTP login email address', cfg['smtp_user'])
    cfg['mail_to'] = ask_list('Email recipients', cfg['mail_to'])
    print('SMTP secret status: ' + secret_status(cfg))
    if ask_bool('Enter or replace the SMTP app password now', secret[0] is None and secret_status(cfg) != 'configured'):
        first = getpass.getpass('App password (not echoed): ').strip()
        if first:
            second = getpass.getpass('Repeat app password: ').strip()
            if first != second:
                print('Passwords do not match; secret was not changed.')
            else:
                secret[0] = first
                print('Secret staged; it will be saved only after configuration validation.')
        else:
            print('Blank password; keeping the previous secret.')
    cfg['report_label'] = ask_string('Optional generic report label', cfg['report_label'])


def monitor_section(cfg: dict) -> None:
    print('\nMonitoring categories')
    for key, label in (
        ('enable_ssh', 'Read SSH authentication events'),
        ('enable_guards', 'Read connection guard events'),
        ('enable_host_http', 'Read host reverse-proxy access logs'),
        ('enable_docker', 'Monitor Docker container state'),
        ('enable_docker_logs', 'Scan Docker application logs'),
        ('enable_disks', 'Check disk utilization'),
    ):
        cfg[key] = ask_bool(label, cfg[key])
    cfg['required_containers'] = ask_list('Required container names', cfg['required_containers'])
    cfg['ignore_containers'] = ask_list('Container names to ignore', cfg['ignore_containers'])
    cfg['required_systemd_services'] = ask_list('Required systemd service unit names', cfg['required_systemd_services'])
    cfg['host_access_log_globs'] = ask_list('Host HTTP log globs', cfg['host_access_log_globs'])
    while True:
        ports = ask_list('Approved public TCP/UDP port numbers', [str(p) for p in cfg['allowed_public_ports']])
        if all(p.isdigit() and 1 <= int(p) <= 65535 for p in ports):
            cfg['allowed_public_ports'] = [int(p) for p in ports]
            break
        print('Port entries must be integers between 1 and 65535.')


def threshold_section(cfg: dict) -> None:
    print('\nEvent thresholds')
    for key, label, high in (
        ('ssh_failure_threshold', 'SSH failure event threshold', 65535),
        ('web_probe_threshold', 'Suspicious HTTP request threshold', 65535),
        ('web_5xx_threshold', 'HTTP 5xx response threshold', 65535),
        ('app_error_threshold', 'Application error indicator threshold', 65535),
        ('disk_warning_percent', 'Disk warning percentage', 100),
        ('max_docker_log_bytes_per_container', 'Maximum Docker log bytes per scan', 10000000),
        ('retention_days', 'Report retention (days)', 65535),
    ):
        cfg[key] = ask_int(label, cfg[key], high=high)
    for key, label in (
        ('alert_on_ssh_password_success', 'Warn on successful SSH password logins'),
        ('alert_on_all_ssh_success', 'Warn on all successful SSH logins'),
        ('warn_on_privileged_docker', 'Warn on privileged containers'),
        ('warn_on_docker_socket_mount', 'Warn on Docker socket mount'),
    ):
        cfg[key] = ask_bool(label, cfg[key])


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


def alert_policy_section(cfg: dict) -> None:
    print('\nEmergency notification policy (all values are stored in config.json)')
    policy = cfg['alert_policy']
    for key, label in (
        ('root_login_untrusted', 'Notify on root login from an untrusted source'),
        ('ssh_spike', 'Notify on sudden SSH failure surge'),
        ('required_container_down', 'Notify when a required container is stopped or missing'),
        ('required_container_unhealthy', 'Notify when a required container is unhealthy'),
        ('other_container_unhealthy', 'Notify when any other container is unhealthy'),
        ('required_service_inactive', 'Notify when a required systemd service is inactive'),
        ('docker_daemon_unavailable', 'Notify when Docker monitoring is unavailable'),
        ('disk_critical', 'Notify when disk usage reaches the critical threshold'),
        ('new_public_port', 'Notify when a new unapproved public Docker port appears'),
        ('custom_log_rule', 'Notify for matching custom Docker log rules'),
        ('http_probe_2xx', 'Notify about suspicious HTTP paths returning 2xx'),
        ('http_probe_volume', 'Notify about unusually many suspicious HTTP requests'),
        ('notify_on_recovery', 'Send a separate email when an ongoing incident recovers'),
    ):
        policy[key] = ask_bool(label, policy[key])
    policy['minimum_level'] = ask('Minimum emergency level (HIGH/WARN)', policy['minimum_level']).upper()
    policy['ssh_spike_trigger_count'] = ask_int('SSH failures per alert window to consider a surge', policy['ssh_spike_trigger_count'])
    policy['ssh_spike_recovery_count'] = ask_int('SSH failures at or below which a surge is resolved', policy['ssh_spike_recovery_count'], low=0)
    policy['ssh_spike_increase_factor'] = ask_float('Minimum increase relative to previous alert window', policy['ssh_spike_increase_factor'])
    policy['disk_critical_percent'] = ask_int('Critical disk percentage (notification)', policy['disk_critical_percent'], high=100)
    policy['disk_recovery_percent'] = ask_int('Disk percentage at or below which the incident resolves', policy['disk_recovery_percent'], high=100)


def pattern_section(cfg: dict) -> None:
    print('\nEnvironment-specific matching and exclusions')
    cfg['trusted_ssh_cidrs'] = ask_list('Trusted SSH source CIDRs (suppress non-root login notices only)', cfg['trusted_ssh_cidrs'])
    cfg['http_probe_patterns'] = ask_regex_list('Suspicious HTTP request path regexes', cfg['http_probe_patterns'])
    cfg['ignored_http_path_patterns'] = ask_regex_list('Excluded HTTP path regexes', cfg['ignored_http_path_patterns'])
    cfg['app_error_patterns'] = ask_regex_list('Docker application error regexes', cfg['app_error_patterns'])
    print('\nOptional custom Docker log rules')
    print('Current rules: ' + ', '.join(rule['name'] for rule in cfg['application_log_rules']))
    choice = ask('Change custom rules? (keep/clear/edit)', 'keep').lower()
    if choice == 'clear':
        cfg['application_log_rules'] = []
    elif choice == 'edit':
        rules = []
        print('Type a blank name to finish.')
        while True:
            name = input('Rule ID (ASCII identifier): ').strip()
            if not name:
                break
            pattern = input('Matching regex: ').strip()
            severity = ask('Finding level (WARN/HIGH)', 'WARN').upper()
            rules.append({'name': name, 'pattern': pattern, 'severity': severity})
        cfg['application_log_rules'] = rules


def policy_section(cfg: dict) -> None:
    print('\nFinding severity policy')
    print('DEFAULT uses the built-in priority; WARN and HIGH change it; OFF hides the finding.')
    overrides = dict(cfg['severity_overrides'])
    for key, (label, _) in RULE_LABELS.items():
        while True:
            previous = overrides.get(key, 'DEFAULT')
            value = ask(label + ' (DEFAULT/WARN/HIGH/OFF)', previous).upper() or previous
            if value in ('DEFAULT', 'WARN', 'HIGH', 'OFF'):
                if value == 'DEFAULT':
                    overrides.pop(key, None)
                else:
                    overrides[key] = value
                break
            print('Enter DEFAULT, WARN, HIGH, or OFF.')
    cfg['severity_overrides'] = overrides


def show(cfg: dict) -> None:
    print(json.dumps(redacted_config(cfg), indent=2, sort_keys=True))
    print('SMTP secret status: ' + secret_status(cfg))


def interactive(config_path: Path, initial: bool) -> int:
    if config_path.exists():
        cfg = load(config_path)
    else:
        cfg = defaults()
    staged_secret = [None]
    print('Server Security Monitor - interactive setup')
    print('Settings and secrets are stored outside the Git checkout.')
    if initial:
        print('Initial setup: enter SMTP settings and select monitoring rules.')
        email_section(cfg, staged_secret)
        monitor_section(cfg)
        threshold_section(cfg)
        alert_policy_section(cfg)
        pattern_section(cfg)
        policy_section(cfg)
    else:
        while True:
            print('\n1) SMTP and recipients   2) Monitoring sources   3) Thresholds')
            print('4) Regex rules/exclusions   5) Severity policy   6) Preview (redacted)')
            print('7) Emergency notification policy   8) Save and exit   0) Exit without saving')
            choice = input('Select: ').strip()
            if choice == '1':
                email_section(cfg, staged_secret)
            elif choice == '2':
                monitor_section(cfg)
            elif choice == '3':
                threshold_section(cfg)
            elif choice == '4':
                pattern_section(cfg)
            elif choice == '5':
                policy_section(cfg)
            elif choice == '6':
                show(cfg)
            elif choice == '7':
                alert_policy_section(cfg)
            elif choice == '8':
                break
            elif choice == '0':
                return 0
            else:
                print('Unknown menu selection.')
    try:
        cfg = validate(cfg)
    except (ValueError, TypeError) as exc:
        print('Configuration not saved: ' + str(exc), file=sys.stderr)
        return 1
    if staged_secret[0] is None and secret_status(cfg) != 'configured':
        print('Configuration not saved: an SMTP app password is required.', file=sys.stderr)
        return 1
    print('\nConfiguration validated. Summary (sensitive values hidden):')
    show(cfg)
    if not ask_bool('Save this configuration', True):
        print('No files changed.')
        return 0
    if staged_secret[0] is not None:
        secure_write(Path(cfg['smtp_password_file']), staged_secret[0] + '\n')
    secure_write(config_path, json.dumps(cfg, indent=2, sort_keys=True) + '\n')
    print('Saved. Settings file: ' + str(config_path))
    print('To send a test message, run: server-security-report --test-email')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description='Configure server security monitoring interactively')
    parser.add_argument('--config', type=Path, default=CONFIG_PATH)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--init', action='store_true', help='Walk through all settings')
    group.add_argument('--configure', action='store_true', help='Edit settings with a CUI menu')
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
