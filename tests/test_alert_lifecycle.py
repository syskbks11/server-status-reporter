#!/usr/bin/env python3
"""Exercise incident transitions, daily continuation, and policy boundaries."""

import datetime as dt
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitor_config
import server_security_report as monitor
import setup_monitor

UTC = dt.timezone.utc


class AlertLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.cfg = monitor_config.defaults()
        self.t0 = dt.datetime(2026, 1, 1, 1, 0, tzinfo=UTC)

    def report(self, minutes=15, start=None, mode='alert'):
        end = start or self.t0
        return monitor.Report('server-a', end-dt.timedelta(minutes=minutes), end, mode,
                              severity_overrides=self.cfg['severity_overrides'],
                              alert_policy=self.cfg['alert_policy'])

    def test_normal_ssh_failures_are_daily_only(self):
        report = self.report()
        report.add('WARN', 'ssh:failures', 'SSH authentication failures: 500')
        report.set_metric('SSH authentication failures (log entries)', 500)
        decision = monitor.evaluate_alert(report, {}, self.cfg)
        self.assertEqual(decision.new_findings, [])
        self.assertEqual(decision.active_incidents, {})

    def test_suspicious_http_requests_are_daily_only_by_default(self):
        report = self.report()
        report.add('HIGH', 'host-web:probe2xx', 'Suspicious HTTP path returned 200')
        report.add('HIGH', 'host-web:probes', 'Large volume of suspicious HTTP probes')
        self.assertFalse(monitor.evaluate_alert(report, {}, self.cfg).new_findings)
        self.cfg['alert_policy']['http_probe_2xx'] = True
        self.assertEqual(len(monitor.evaluate_alert(report, {}, self.cfg).new_findings), 1)

    def test_untrusted_root_login_event_and_trusted_root_not_alerted(self):
        report = self.report()
        self.cfg['trusted_ssh_cidrs'] = ['192.0.2.0/24']
        logs = '\n'.join([
            'Accepted publickey for root from 192.0.2.15 port 5000',
            'Accepted publickey for root from 203.0.113.3 port 5000',
        ])
        with patch.object(monitor, 'journal_logs', return_value=logs):
            monitor.analyze_ssh(report.start, report.end, report, self.cfg)
        self.assertEqual(len(report.findings), 2)
        self.assertEqual(report.findings[0].level, 'WARN')
        decision = monitor.evaluate_alert(report, {}, self.cfg)
        self.assertEqual(len(decision.new_findings), 1)
        self.assertIn('203.0.113.3', decision.new_findings[0].key)
        self.assertEqual(decision.active_incidents, {})

    def test_critical_required_docker_stop_alerts_once_and_continues_daily(self):
        self.cfg['required_containers'] = ['core-service']
        first = self.report()
        first.add('HIGH', 'docker:required-stopped:core-service', 'Required container stopped', True)
        first.observations['docker_query_ok'] = True
        decision1 = monitor.evaluate_alert(first, {}, self.cfg)
        self.assertEqual(len(decision1.new_findings), 1)
        key = 'docker:required:core-service'
        self.assertIn(key, decision1.active_incidents)

        second = self.report(start=self.t0+dt.timedelta(minutes=15))
        second.add('HIGH', 'docker:required-stopped:core-service', 'Required container still stopped', True)
        second.observations['docker_query_ok'] = True
        decision2 = monitor.evaluate_alert(second, {'active_incidents': decision1.active_incidents}, self.cfg)
        self.assertEqual(decision2.new_findings, [])
        self.assertEqual(len(decision2.active_incidents), 1)

        next_day = self.report(minutes=1440, start=self.t0+dt.timedelta(days=1), mode='daily')
        next_day.add('HIGH', 'docker:required-stopped:core-service', 'Required container still stopped', True)
        monitor.merge_ongoing_into_daily(next_day, {'alert': {'active_incidents': decision2.active_incidents}}, self.cfg)
        self.assertEqual(len(next_day.findings), 1)
        self.assertTrue(next_day.findings[0].ongoing_since)
        self.assertIn('ongoing since', next_day.plaintext())
        self.assertIn('ongoing since', next_day.htmltext())

        next_day2 = self.report(minutes=1440, start=self.t0+dt.timedelta(days=2), mode='daily')
        monitor.merge_ongoing_into_daily(next_day2, {'alert': {'active_incidents': decision2.active_incidents}}, self.cfg)
        self.assertEqual(len(next_day2.findings), 1)
        self.assertIn('Required container still stopped', next_day2.findings[0].message)

    def test_docker_stopped_to_missing_does_not_generate_second_alert(self):
        self.cfg['required_containers'] = ['core-service']
        first = self.report()
        first.add('HIGH', 'docker:required-stopped:core-service', 'Container stopped', True)
        incident = monitor.evaluate_alert(first, {}, self.cfg).active_incidents
        second = self.report(start=self.t0+dt.timedelta(minutes=15))
        second.add('HIGH', 'docker:required-missing:core-service', 'Container missing', True)
        decision = monitor.evaluate_alert(second, {'active_incidents': incident}, self.cfg)
        self.assertFalse(decision.new_findings)
        self.assertEqual(len(decision.active_incidents), 1)
        self.assertEqual(next(iter(decision.active_incidents.values()))['message'], 'Container missing')

    def test_resolution_is_silent_by_default_and_new_event_can_alert_again(self):
        self.cfg['required_containers'] = ['core-service']
        report = self.report()
        report.add('HIGH', 'docker:required-missing:core-service', 'Container missing', True)
        active = monitor.evaluate_alert(report, {}, self.cfg).active_incidents
        healthy = self.report(start=self.t0+dt.timedelta(minutes=15))
        healthy.observations['docker_query_ok'] = True
        result = monitor.evaluate_alert(healthy, {'active_incidents': active}, self.cfg)
        self.assertEqual(result.recoveries, [])
        self.assertEqual(result.active_incidents, {})
        third = monitor.evaluate_alert(report, {'active_incidents': result.active_incidents}, self.cfg)
        self.assertEqual(len(third.new_findings), 1)

    def test_recovery_notification_is_opt_in(self):
        self.cfg['required_containers'] = ['core-service']
        self.cfg['alert_policy']['notify_on_recovery'] = True
        report = self.report()
        report.add('HIGH', 'docker:required-stopped:core-service', 'Container stopped', True)
        active = monitor.evaluate_alert(report, {}, self.cfg).active_incidents
        healthy = self.report(start=self.t0+dt.timedelta(minutes=15))
        healthy.observations['docker_query_ok'] = True
        decision = monitor.evaluate_alert(healthy, {'active_incidents': active}, self.cfg)
        healthy.recoveries = decision.recoveries
        self.assertEqual(decision.recoveries, ['Container stopped'])
        self.assertEqual(decision.active_incidents, {})
        self.assertTrue(healthy.subject().startswith('[SECURITY RECOVERY][OK]'))
        self.assertIn('RECOVERED INCIDENTS', healthy.plaintext())

    def test_docker_read_failure_does_not_fake_recovery(self):
        self.cfg['required_containers'] = ['core-service']
        report = self.report()
        report.add('HIGH', 'docker:required-missing:core-service', 'Container missing', True)
        active = monitor.evaluate_alert(report, {}, self.cfg).active_incidents
        inconclusive = self.report(start=self.t0+dt.timedelta(minutes=15))
        decision = monitor.evaluate_alert(inconclusive, {'active_incidents': active}, self.cfg)
        self.assertEqual(decision.active_incidents, active)
        daily = self.report(mode='daily', minutes=1440)
        monitor.merge_ongoing_into_daily(daily, {'alert': {'active_incidents': decision.active_incidents}}, self.cfg)
        self.assertEqual(len(daily.findings), 1)

    def test_disk_hysteresis_and_daily_deduplication(self):
        alert = self.report()
        alert.add('HIGH', 'disk:/data', 'Disk usage 96%', True)
        alert.observations['disk_percentages'] = {'/data': 96}
        active = monitor.evaluate_alert(alert, {}, self.cfg).active_incidents
        self.assertIn('disk:/data', active)
        between = self.report(start=self.t0+dt.timedelta(minutes=15))
        between.add('WARN', 'disk:/data', 'Disk usage 93%', True)
        between.observations['disk_percentages'] = {'/data': 93}
        decision = monitor.evaluate_alert(between, {'active_incidents': active}, self.cfg)
        self.assertFalse(decision.new_findings)
        self.assertIn('disk:/data', decision.active_incidents)
        daily = self.report(mode='daily', minutes=1440)
        daily.add('WARN', 'disk:/data', 'Disk usage 93%', True)
        monitor.merge_ongoing_into_daily(daily, {'alert': {'active_incidents': decision.active_incidents}}, self.cfg)
        self.assertEqual(len(daily.findings), 1)
        self.assertEqual(daily.findings[0].level, 'HIGH')
        resolved = self.report(start=self.t0+dt.timedelta(minutes=30))
        resolved.observations['disk_percentages'] = {'/data': 89}
        self.assertEqual(monitor.evaluate_alert(resolved, {'active_incidents': active}, self.cfg).active_incidents, {})

    def test_ssh_surge_needs_threshold_and_growth_and_recovers(self):
        self.cfg['alert_policy']['ssh_spike_trigger_count'] = 100
        self.cfg['alert_policy']['ssh_spike_recovery_count'] = 30
        self.cfg['alert_policy']['ssh_spike_increase_factor'] = 3.0
        self.cfg['enable_guards'] = False
        self.cfg['enable_host_http'] = False
        self.cfg['enable_docker'] = False
        self.cfg['enable_disks'] = False
        with patch.object(monitor, 'analyze_ssh') as fake:
            fake.side_effect = lambda start, end, report, cfg: report.set_metric('SSH authentication failures (log entries)', 120)
            state = {'alert': {'last_checked': (self.t0-dt.timedelta(minutes=15)).isoformat(),
                               'last_ssh_rate_15m': 50, 'active_incidents': {}}}
            report, _ = monitor.build_report(self.cfg, state, 'alert', self.t0)
        self.assertNotIn('ssh:spike', [f.key for f in report.findings])
        state['alert']['last_ssh_rate_15m'] = 20
        with patch.object(monitor, 'analyze_ssh') as fake:
            fake.side_effect = lambda start, end, report, cfg: report.set_metric('SSH authentication failures (log entries)', 120)
            report, _ = monitor.build_report(self.cfg, state, 'alert', self.t0)
        self.assertIn('ssh:spike', [f.key for f in report.findings])
        active = monitor.evaluate_alert(report, state['alert'], self.cfg).active_incidents
        self.assertIn('ssh:spike', active)
        current = self.report()
        current.observations['ssh_failure_count_15m'] = 45
        self.assertIn('ssh:spike', monitor.evaluate_alert(current, {'active_incidents': active}, self.cfg).active_incidents)
        current.observations['ssh_failure_count_15m'] = 20
        self.assertNotIn('ssh:spike', monitor.evaluate_alert(current, {'active_incidents': active}, self.cfg).active_incidents)

    def test_ssh_spike_daily_does_not_add_second_ssh_finding(self):
        daily = self.report(mode='daily', minutes=1440)
        daily.add('WARN', 'ssh:failures', 'SSH failures above normal volume')
        active = {'ssh:spike': {'level':'HIGH', 'finding_key':'ssh:spike', 'message':'SSH failure surge',
                                'action':'Review', 'first_seen':'2026-01-01T01:00:00+00:00'}}
        monitor.merge_ongoing_into_daily(daily, {'alert': {'active_incidents': active}}, self.cfg)
        self.assertEqual(len(daily.findings), 1)
        self.assertEqual(daily.findings[0].level, 'HIGH')

    def test_disabling_rule_drops_incident_without_recovery_email(self):
        self.cfg['required_containers'] = ['core-service']
        self.cfg['alert_policy']['notify_on_recovery'] = True
        active = {'docker:required:core-service': {
            'level': 'HIGH', 'message':'Container stopped',
            'finding_key':'docker:required-stopped:core-service',
            'action':'Check', 'first_seen':'2026-01-01T00:00:00+00:00'}}
        self.cfg['required_containers'] = []
        report = self.report()
        decision = monitor.evaluate_alert(report, {'active_incidents': active}, self.cfg)
        self.assertEqual(decision.active_incidents, {})
        self.assertEqual(decision.recoveries, [])
        daily = self.report(mode='daily', minutes=1440)
        monitor.merge_ongoing_into_daily(daily, {'alert': {'active_incidents': active}}, self.cfg)
        self.assertEqual(daily.findings, [])

    def test_required_container_missing_when_no_docker_ids(self):
        self.cfg['required_containers'] = ['core-service']
        report = self.report()
        with patch.object(monitor.shutil, 'which', return_value='/usr/bin/docker'), \
             patch.object(monitor, 'command', return_value=monitor.CommandResult('', True)):
            current = monitor.parse_docker(self.cfg, report, {}, report.start, report.end)
        self.assertEqual(current, {})
        self.assertEqual(report.observations['docker_query_ok'], True)
        self.assertIn('docker:required-missing:core-service', [f.key for f in report.findings])

    def test_unapproved_public_port_is_persistent_and_only_one_finding(self):
        self.cfg['enable_docker_logs'] = False
        report = self.report()
        inspect = [{'Name':'/app-a', 'Id':'test-id', 'RestartCount':0,
                    'State':{'Status':'running'},
                    'HostConfig':{'LogConfig':{'Type':'none'},'Binds':[],'Privileged':False},
                    'NetworkSettings':{'Ports':{'80/tcp':[{'HostIp':'0.0.0.0','HostPort':'8080'}]}}}]
        import json
        def fake_command(args, **kwargs):
            if args[:3] == ['docker', 'ps', '-aq']:
                return monitor.CommandResult('test-id', True)
            return monitor.CommandResult(json.dumps(inspect), True)
        with patch.object(monitor.shutil, 'which', return_value='/usr/bin/docker'), \
             patch.object(monitor, 'command', side_effect=fake_command):
            monitor.parse_docker(self.cfg, report, {}, report.start, report.end)
        incidents = [f for f in report.findings if 'public-port' in f.key]
        self.assertEqual(len(incidents), 1)
        self.assertTrue(incidents[0].persistent)
        first = monitor.evaluate_alert(report, {}, self.cfg)
        second = monitor.evaluate_alert(report, {'active_incidents':first.active_incidents}, self.cfg)
        self.assertEqual(len(first.new_findings), 1)
        self.assertFalse(second.new_findings)

    def test_stale_ssh_interval_is_normalized_to_rate(self):
        self.cfg.update({'enable_guards':False, 'enable_host_http':False,
                         'enable_docker':False, 'enable_disks':False})
        state = {'alert': {'last_checked':(self.t0-dt.timedelta(hours=4)).isoformat()}}
        with patch.object(monitor, 'analyze_ssh') as fake:
            fake.side_effect = lambda start, end, report, cfg: report.set_metric('SSH authentication failures (log entries)', 110)
            report, _ = monitor.build_report(self.cfg, state, 'alert', self.t0)
        self.assertAlmostEqual(report.observations['ssh_failure_count_15m'], 6.875)
        self.assertNotIn('ssh:spike', [f.key for f in report.findings])

    def test_policy_validation_and_old_config_migration(self):
        settings = monitor_config.defaults()
        settings['smtp_user'] = 'sender@example.invalid'
        settings['mail_to'] = ['recipient@example.invalid']
        old = dict(settings)
        old.pop('alert_policy')
        self.assertEqual(monitor_config.validate(old)['alert_policy']['disk_critical_percent'], 95)
        settings['alert_policy']['disk_recovery_percent'] = 98
        with self.assertRaises(ValueError):
            monitor_config.validate(settings)
        settings['alert_policy']['disk_recovery_percent'] = 90
        settings['alert_policy']['minimum_level'] = 'OFF'
        with self.assertRaises(ValueError):
            monitor_config.validate(settings)

    def test_daily_merge_html_escapes_stored_incident(self):
        self.cfg['required_systemd_services'] = ['other']
        daily = self.report(mode='daily', minutes=1440)
        active = {'service:other': {'level':'HIGH', 'finding_key':'service:other',
                                    'message':'<img src=x onerror=alert(1)>', 'action':'Check',
                                    'first_seen':'2026-01-01T00:00:00+00:00'}}
        monitor.merge_ongoing_into_daily(daily, {'alert': {'active_incidents': active}}, self.cfg)
        self.assertNotIn('<img src=x', daily.htmltext())
        self.assertIn('&lt;img src=x', daily.htmltext())


if __name__ == '__main__':
    unittest.main()
