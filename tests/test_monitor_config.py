#!/usr/bin/env python3
"""Configuration and policy tests that do not require root or network access."""

from __future__ import annotations

import datetime as dt
import json
import os
import stat
import tempfile
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import monitor_config as cfgmod
import server_security_report as monitor
import setup_monitor as setup


class ConfigTests(unittest.TestCase):
    def valid(self) -> dict:
        cfg = cfgmod.defaults()
        cfg['smtp_user'] = 'sender@example.invalid'
        cfg['mail_to'] = ['recipient@example.invalid']
        return cfg

    def test_defaults_and_schema(self):
        cfg = cfgmod.validate(self.valid())
        self.assertEqual(cfg['smtp_port'], 587)
        self.assertTrue(cfg['enable_docker'])
        self.assertEqual(cfg['http_probe_patterns'], cfgmod.DEFAULTS['http_probe_patterns'])

    def test_invalid_regex_fails(self):
        cfg = self.valid()
        cfg['http_probe_patterns'] = ['(']
        with self.assertRaises(ValueError):
            cfgmod.validate(cfg)

    def test_invalid_cidr_fails(self):
        cfg = self.valid()
        cfg['trusted_ssh_cidrs'] = ['not-a-network']
        with self.assertRaises(ValueError):
            cfgmod.validate(cfg)

    def test_invalid_severity_and_custom_rules_fail(self):
        cfg = self.valid()
        cfg['severity_overrides'] = {'ssh_root': 'LOW'}
        with self.assertRaises(ValueError):
            cfgmod.validate(cfg)
        cfg = self.valid()
        cfg['application_log_rules'] = [{'name':'bad space','pattern':'error','severity':'HIGH'}]
        with self.assertRaises(ValueError):
            cfgmod.validate(cfg)

    def test_secret_path_is_confined(self):
        cfg = self.valid()
        cfg['smtp_password_file'] = '/tmp/smtp-password'
        with self.assertRaises(ValueError):
            cfgmod.validate(cfg)
        cfg['smtp_password_file'] = '/etc/server-security-report/../unrelated-file'
        with self.assertRaises(ValueError):
            cfgmod.validate(cfg)

    def test_redacted_view_does_not_print_private_values(self):
        cfg = self.valid()
        cfg['report_label'] = 'production-host-name'
        cfg['host_access_log_globs'] = ['/var/log/private.log']
        cfg['required_containers'] = ['secret-container-name']
        cfg['trusted_ssh_cidrs'] = ['198.51.100.0/24']
        output = json.dumps(cfgmod.redacted_config(cfg))
        for secret in ('sender@example.invalid', 'recipient@example.invalid',
                       'production-host-name', 'secret-container-name', '/var/log/private.log', '198.51.100.0/24'):
            self.assertNotIn(secret, output)

    def test_ssh_trust_does_not_suppress_root_warnings(self):
        now = dt.datetime.now(dt.timezone.utc)
        report = monitor.Report('host-a', now - dt.timedelta(minutes=15), now, 'alert')
        logs = '\n'.join([
            'Accepted publickey for root from 192.0.2.8 port 20',
            'Accepted publickey for user from 192.0.2.8 port 21',
        ])
        config = {'trusted_ssh_cidrs': ['192.0.2.0/24'], 'alert_on_all_ssh_success': True}
        with patch.object(monitor, 'journal_logs', return_value=logs):
            monitor.analyze_ssh(report.start, report.end, report, config)
        self.assertEqual([item.key for item in report.findings], ['ssh:root:192.0.2.8:publickey'])

    def test_http_regex_override_and_ignore(self):
        stats = monitor.WebStats(patterns=['/sensitive'], ignored_paths=['/sensitive/health'])
        stats.ingest('192.0.2.1 - - [20/Nov/2026:12:00:00 +0000] "GET /sensitive HTTP/1.1" 404 0')
        stats.ingest('192.0.2.1 - - [20/Nov/2026:12:00:00 +0000] "GET /sensitive/health HTTP/1.1" 200 0')
        self.assertEqual(stats.requests, 2)
        self.assertEqual(stats.probes, 1)

    def test_severity_policy_can_override_and_suppress(self):
        now = dt.datetime.now(dt.timezone.utc)
        report = monitor.Report('host-a', now - dt.timedelta(minutes=15), now, 'alert',
                                severity_overrides={'ssh_root': 'WARN', 'disk_usage': 'OFF'})
        report.add('HIGH', 'ssh:root:192.0.2.1', 'Root login')
        report.add('WARN', 'disk:/', 'Disk full')
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].level, 'WARN')

    def test_custom_log_rule_and_docker_log_toggle(self):
        now = dt.datetime.now(dt.timezone.utc)
        report = monitor.Report('host-a', now - dt.timedelta(minutes=15), now, 'alert')
        inspect = [{
            'Name': '/app-a', 'Id': 'unit-test-id', 'RestartCount': 0,
            'State': {'Status': 'running'},
            'HostConfig': {'LogConfig': {'Type': 'json-file'}, 'Binds': [], 'Privileged': False},
            'NetworkSettings': {'Ports': {}},
        }]
        commands = []
        def fake_command(args, **kwargs):
            commands.append(args)
            if args[:3] == ['docker', 'ps', '-aq']:
                return monitor.CommandResult('unit-test-id', True)
            if args[:2] == ['docker', 'inspect']:
                return monitor.CommandResult(json.dumps(inspect), True)
            if args[:2] == ['docker', 'logs']:
                return monitor.CommandResult('ALARM TRIGGERED', True)
            raise AssertionError(args)
        config = {'application_log_rules': [{'name':'alert_log', 'pattern':r'ALARM', 'severity':'HIGH'}],
                  'enable_docker_logs': True}
        with patch.object(monitor.shutil, 'which', return_value='/usr/bin/docker'), \
             patch.object(monitor, 'command', side_effect=fake_command):
            monitor.parse_docker(config, report, {}, report.start, report.end)
            self.assertTrue(any(f.key == 'docker:custom:alert_log:app-a' for f in report.findings))
            commands.clear()
            config['enable_docker_logs'] = False
            monitor.parse_docker(config, report, {}, report.start, report.end)
            self.assertFalse(any(call[:2] == ['docker', 'logs'] for call in commands))

    def test_initial_setup_asks_only_for_required_smtp_fields(self):
        cfg = cfgmod.defaults()
        staged = [None]
        answers = iter(['sender@example.invalid', 'one@example.invalid, two@example.invalid'])
        with patch('builtins.input', side_effect=lambda prompt='': next(answers)), \
             patch.object(setup, 'secret_status', return_value='missing'), \
             patch.object(setup, 'ask_password') as password:
            setup.initial_smtp(cfg, staged)
        self.assertEqual(cfg['smtp_host'], 'smtp.gmail.com')
        self.assertEqual(cfg['smtp_port'], 587)
        self.assertEqual(cfg['mail_to'], ['one@example.invalid', 'two@example.invalid'])
        self.assertEqual(cfg['alert_policy']['minimum_level'], 'HIGH')
        self.assertTrue(cfg['enable_docker'])
        password.assert_called_once_with(staged, required=True)
        cfg = cfgmod.validate(cfg)
        self.assertEqual(cfg['ssh_failure_threshold'], 30)

    def test_blank_choice_preserves_current_emergency_level(self):
        with patch('builtins.input', return_value=''):
            self.assertEqual(setup.ask_choice('Emergency level', 'HIGH', ('HIGH', 'WARN')), 'HIGH')

    def test_item_menu_only_updates_selected_threshold(self):
        cfg = self.valid()
        staged = [None]
        old = cfg['ssh_failure_threshold']
        answers = iter(['2', '42', '0'])
        with patch('builtins.input', side_effect=lambda prompt='': next(answers)):
            setup.section_menu(cfg, staged, 'Thresholds', setup.THRESHOLD_FIELDS)
        self.assertEqual(cfg['web_probe_threshold'], 42)
        self.assertEqual(cfg['ssh_failure_threshold'], old)

    def test_emergency_level_can_be_kept_or_changed_individually(self):
        cfg = self.valid()
        staged = [None]
        fields = [('alert_policy.minimum_level', 'Minimum emergency level', 'level')]
        answers = iter(['1', '', '1', 'WARN', '0'])
        with patch('builtins.input', side_effect=lambda prompt='': next(answers)):
            setup.section_menu(cfg, staged, 'Emergency policy', fields)
        self.assertEqual(cfg['alert_policy']['minimum_level'], 'WARN')

    def test_edit_mode_does_not_force_visiting_all_fields(self):
        cfg = self.valid()
        answers = iter(['4', '14', '', '0', '8'])
        with patch('builtins.input', side_effect=lambda prompt='': next(answers)), \
             patch.object(setup, 'load', return_value=cfg), \
             patch.object(setup, 'save_config', return_value=True) as save:
            result = setup.interactive(Path('/tmp/config.json'), initial=False)
        self.assertEqual(result, 0)
        self.assertEqual(cfg['alert_policy']['minimum_level'], 'HIGH')
        self.assertEqual(save.call_count, 1)

    def test_failed_save_returns_to_menu(self):
        cfg = self.valid()
        answers = iter(['8', '0'])
        with patch('builtins.input', side_effect=lambda prompt='': next(answers)), \
             patch.object(setup, 'load', return_value=cfg), \
             patch.object(setup, 'save_config', return_value=False):
            result = setup.interactive(Path('/tmp/config.json'), initial=False)
        self.assertEqual(result, 0)

    @unittest.skipUnless(os.geteuid() == 0, 'Root is required for secure-write round-trip')
    def test_secure_configuration_round_trip(self):
        with tempfile.TemporaryDirectory() as location:
            directory = Path(location) / 'private'
            directory.mkdir(mode=0o700)
            settings = directory / 'config.json'
            secret = directory / 'smtp-password'
            config = self.valid()
            config['smtp_password_file'] = str(secret)
            with patch.object(cfgmod, 'CONFIG_DIR', directory):
                cfgmod.secure_write(secret, 'not-a-real-app-password\n')
                cfgmod.secure_write(settings, json.dumps(config))
                loaded = cfgmod.load(settings)
                self.assertEqual(loaded['smtp_user'], 'sender@example.invalid')
                self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(settings.stat().st_mode), 0o600)
                self.assertEqual(cfgmod.secret_status(loaded), 'configured')

    def test_docker_new_port_with_unresolved_host_port(self):
        now = dt.datetime.now(dt.timezone.utc)
        report = monitor.Report('host-a', now - dt.timedelta(minutes=15), now, 'alert')
        inspect = [{
            'Name': '/app-a', 'Id': 'unit-test-id', 'RestartCount': 0,
            'State': {'Status': 'running'},
            'HostConfig': {'LogConfig': {'Type': 'none'}, 'Binds': [], 'Privileged': False},
            'NetworkSettings': {'Ports': {'80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '?'}]}},
        }]
        prior = {'containers': {'app-a': {'id':'unit-test-id','status':'running','restarts':0,'exposed':[]}}}
        def fake_command(args, **kwargs):
            if args[:3] == ['docker', 'ps', '-aq']:
                return monitor.CommandResult('unit-test-id', True)
            if args[:2] == ['docker', 'inspect']:
                return monitor.CommandResult(json.dumps(inspect), True)
            raise AssertionError(args)
        with patch.object(monitor.shutil, 'which', return_value='/usr/bin/docker'), \
             patch.object(monitor, 'command', side_effect=fake_command):
            updated = monitor.parse_docker({}, report, prior, report.start, report.end)
        self.assertIn('app-a', updated)


if __name__ == '__main__':
    unittest.main()
