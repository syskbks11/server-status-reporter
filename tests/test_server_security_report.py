#!/usr/bin/env python3
"""Offline unit tests for the security report parser."""

import datetime as dt
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / "server_security_report.py"
sys_path = str(MODULE.parent)
if sys_path not in __import__("sys").path:
    __import__("sys").path.insert(0, sys_path)
spec = importlib.util.spec_from_file_location("server_security_report", MODULE)
monitor = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = monitor
spec.loader.exec_module(monitor)


class SecurityReportTests(unittest.TestCase):
    def test_http_probe_and_redaction(self):
        stats = monitor.WebStats()
        stats.ingest('203.0.113.11 - - [19/Nov/2026:12:00:00 +0900] "GET /?unix:AAAASECRET HTTP/1.1" 200 123')
        stats.ingest('203.0.113.12 - - [19/Nov/2026:12:00:00 +0900] "GET /index.html HTTP/1.1" 200 123')
        self.assertEqual(stats.requests, 2)
        self.assertEqual(stats.probes, 1)
        self.assertEqual(stats.probe_2xx, 1)
        self.assertNotIn('AAAASECRET', str(stats.paths))

    def test_ssh_authentication(self):
        now = dt.datetime(2026, 11, 19, 12, tzinfo=dt.timezone.utc)
        report = monitor.Report('test', now - dt.timedelta(hours=1), now, 'alert')
        output = '\n'.join([
            'sshd[1]: Invalid user guest from 203.0.113.4 port 5000',
            'sshd[1]: Failed password for invalid user guest from 203.0.113.4 port 5000',
            'sshd[1]: Accepted publickey for root from 192.0.2.4 port 5000',
        ])
        with patch.object(monitor, 'journal_logs', return_value=output):
            monitor.analyze_ssh(report.start, report.end, report, {'ssh_failure_threshold': 2})
        self.assertEqual(report.metrics['SSH authentication failures (log entries)'], '2')
        self.assertEqual(report.level, 'HIGH')
        self.assertEqual(report.metrics['SSH successful authentications'], '1')

    def test_html_escaping(self):
        now = dt.datetime(2026, 11, 19, tzinfo=dt.timezone.utc)
        report = monitor.Report('test', now - dt.timedelta(hours=1), now, 'daily')
        report.section('Web', ['<script>alert(1)</script>'])
        self.assertNotIn('<script>', report.htmltext())
        self.assertIn('&lt;script&gt;', report.htmltext())

    def test_command_output_is_bounded(self):
        result = monitor.command(['python3', '-c', 'print("a" * 1000000)'], timeout=10, max_bytes=2000)
        self.assertEqual(len(result.output), 2000)
        self.assertTrue(result.truncated)

    def test_docker_stopped_container_logs_and_missing_container(self):
        now = dt.datetime(2026, 11, 19, tzinfo=dt.timezone.utc)
        report = monitor.Report('test', now - dt.timedelta(minutes=15), now, 'alert')
        inspect = [{
            'Name': '/wiki', 'Id': 'abcdef', 'RestartCount': 2,
            'State': {'Status': 'exited'},
            'HostConfig': {'LogConfig': {'Type': 'json-file'}, 'Binds': [], 'Privileged': False},
            'NetworkSettings': {'Ports': {}}
        }]
        prior = {'containers': {
            'wiki': {'id': 'abcdef', 'status': 'running', 'restarts': 1, 'exposed': []},
            'retired': {'id': 'old', 'status': 'running', 'restarts': 0, 'exposed': []}
        }}

        def fake_command(args, **kwargs):
            if args[:3] == ['docker', 'ps', '-aq']:
                return monitor.CommandResult('abcdef\n', True, False, '')
            if args[:2] == ['docker', 'inspect']:
                import json
                return monitor.CommandResult(json.dumps(inspect), True, False, '')
            if args[:2] == ['docker', 'logs']:
                return monitor.CommandResult('203.0.113.77 - - [19/Nov/2026:12:00:00 +0900] "GET /.env HTTP/1.1" 200 1', True, False, '')
            raise AssertionError(args)

        with patch.object(monitor.shutil, 'which', return_value='/usr/bin/docker'):
            with patch.object(monitor, 'command', side_effect=fake_command):
                updated = monitor.parse_docker({'web_probe_threshold': 20}, report, prior, report.start, report.end)
        self.assertIn('wiki', updated)
        self.assertIn('docker:missing:retired', [f.key for f in report.findings])
        self.assertIn('docker:stopped:wiki', [f.key for f in report.findings])
        self.assertEqual(report.metrics['Docker suspicious paths returning 2xx'], '1')

    def test_probe_reduction_does_not_imply_compromise(self):
        now = dt.datetime(2026, 11, 19, tzinfo=dt.timezone.utc)
        report = monitor.Report('test', now - dt.timedelta(hours=1), now, 'daily')
        stats = monitor.WebStats()
        stats.ingest('198.51.100.10 - - [19/Nov/2026:12:00:00 +0900] "GET /.env HTTP/1.1" 404 123')
        monitor.analyze_web(stats, 'Host', report, {'web_probe_threshold': 20}, 'host-web')
        self.assertEqual(report.level, 'OK')
        self.assertEqual(stats.probe_2xx, 0)


    def test_three_state_label_and_next_steps(self):
        now = dt.datetime(2026, 11, 19, tzinfo=dt.timezone.utc)
        report = monitor.Report('host-a', now - dt.timedelta(hours=24), now, 'daily')
        self.assertEqual(report.status, 'OK')
        report.add('WARN', 'ssh:failures', 'Repeated SSH failures')
        self.assertEqual(report.status, 'REVIEW')
        self.assertIn('SSHGuard or Fail2ban', report.plaintext())
        report.add('HIGH', 'docker:unhealthy:wiki', 'Unhealthy Docker container: wiki')
        self.assertEqual(report.status, 'URGENT')
        self.assertIn('[Daily Security][URGENT]', report.subject())

    def test_daily_comparison_and_change_signs(self):
        now = dt.datetime(2026, 11, 19, tzinfo=dt.timezone.utc)
        report = monitor.Report('host-a', now - dt.timedelta(hours=24), now, 'daily')
        report.set_metric('SSH authentication failures (log entries)', 71)
        report.set_metric('SSH successful authentications', 3)
        report.set_metric('SSHGuard/Fail2ban block events', 0)
        report.previous_counts = {
            'SSH authentication failures (log entries)': 32,
            'SSH successful authentications': 5,
            'SSHGuard/Fail2ban block events': 0,
        }
        self.assertEqual(report.metric_change('SSH authentication failures (log entries)'), ('32', '+39'))
        self.assertEqual(report.metric_change('SSH successful authentications'), ('5', '-2'))
        self.assertEqual(report.metric_change('SSHGuard/Fail2ban block events'), ('0', '0'))
        self.assertIn('previous: 32, change: +39', report.plaintext())
        self.assertIn('<th align="right">Change</th>', report.htmltext())

    def test_ip_activity_combines_channels_without_summing_duplicates(self):
        now = dt.datetime(2026, 11, 19, tzinfo=dt.timezone.utc)
        report = monitor.Report('host-a', now - dt.timedelta(hours=24), now, 'daily')
        report.record_ip('203.0.113.1', 'ssh_failed', 5)
        host = monitor.WebStats()
        host.ingest('203.0.113.1 - - [19/Nov/2026:12:00:00 +0900] "GET /.env HTTP/1.1" 404 0')
        monitor.analyze_web(host, 'Host', report, {}, 'host-web')
        docker = monitor.WebStats()
        docker.ingest('203.0.113.1 - - [19/Nov/2026:12:00:00 +0900] "GET /.env HTTP/1.1" 404 0')
        monitor.analyze_web(docker, 'Docker', report, {}, 'docker-web')
        address, detail = report.ip_rows()[0]
        self.assertEqual(address, '203.0.113.1')
        self.assertIn('SSH failed: 5', detail)
        self.assertIn('host HTTP: 1', detail)
        self.assertIn('Docker HTTP: 1', detail)
        self.assertNotIn('total requests: 2', detail)
        self.assertIn('do not add their counts', report.plaintext())

    def test_ip_activity_orders_suspicious_sources_first(self):
        now = dt.datetime(2026, 11, 19, tzinfo=dt.timezone.utc)
        report = monitor.Report('host-a', now - dt.timedelta(hours=24), now, 'daily')
        report.record_ip('192.0.2.1', 'host_requests', 1000)
        report.record_ip('203.0.113.5', 'ssh_failed', 10)
        self.assertEqual(report.ip_rows()[0][0], '203.0.113.5')

    def test_daily_comparison_requires_comparable_windows(self):
        now = dt.datetime(2026, 11, 19, 7, tzinfo=dt.timezone.utc)
        prior = {
            'daily': {
                'last_checked': (now - dt.timedelta(days=1)).isoformat(),
                'last_window_hours': 24.0,
                'last_counts': {'SSH authentication failures (log entries)': 20},
                'containers': {},
            }
        }

        def fake_ssh(start, end, report, cfg):
            report.set_metric('SSH authentication failures (log entries)', 30)

        with patch.object(monitor, 'analyze_ssh', side_effect=fake_ssh), \
             patch.object(monitor, 'analyze_guards'), \
             patch.object(monitor, 'host_access_stats', return_value=monitor.WebStats()), \
             patch.object(monitor, 'analyze_web'), \
             patch.object(monitor, 'parse_docker', return_value={}), \
             patch.object(monitor, 'analyze_services'), \
             patch.object(monitor, 'analyze_disks'):
            report, _ = monitor.build_report({}, prior, 'daily', now)
            self.assertEqual(report.metric_change('SSH authentication failures (log entries)'), ('20', '+10'))
            late, _ = monitor.build_report({}, prior, 'daily', now + dt.timedelta(days=3))
            self.assertEqual(late.metric_change('SSH authentication failures (log entries)'), ('-', '-'))
            self.assertIn('omitted', late.comparison_note)

    def test_docker_running_names_are_not_listed(self):
        now = dt.datetime(2026, 11, 19, tzinfo=dt.timezone.utc)
        report = monitor.Report('host-a', now - dt.timedelta(hours=1), now, 'daily')
        base = {
            'Id': 'dummy', 'RestartCount': 0,
            'HostConfig': {'LogConfig': {'Type': 'none'}, 'Binds': [], 'Privileged': False},
            'NetworkSettings': {'Ports': {}}
        }
        normal = dict(base, Name='/web', State={'Status': 'running'})
        abnormal = dict(base, Name='/database', State={'Status': 'exited'})
        calls = [monitor.CommandResult('id1\nid2', True), monitor.CommandResult(__import__('json').dumps([normal, abnormal]), True)]
        with patch.object(monitor.shutil, 'which', return_value='/usr/bin/docker'), \
             patch.object(monitor, 'command', side_effect=calls):
            monitor.parse_docker({}, report, {}, report.start, report.end)
        parts = dict(report.sections)
        self.assertIn('Docker containers', parts)
        self.assertNotIn('web:', str(parts['Docker containers']))
        self.assertIn('database:', str(parts['Docker containers']))

    def test_action_text_html_is_escaped(self):
        now = dt.datetime(2026, 11, 19, tzinfo=dt.timezone.utc)
        report = monitor.Report('test', now - dt.timedelta(hours=1), now, 'daily')
        report.add('WARN', 'ssh:login:evil', '<img src=x onerror=alert(1)>')
        rendered = report.htmltext()
        self.assertIn('&lt;img src=x', rendered)
        self.assertNotIn('<img src=x', rendered)


if __name__ == '__main__':
    unittest.main()
