#!/usr/bin/env python3
"""Generate entirely synthetic HTML and text email samples."""

import datetime as dt
from pathlib import Path
from server_security_report import Report

ROOT = Path(__file__).resolve().parent
end = dt.datetime(2026, 1, 2, 7, tzinfo=dt.timezone.utc)
report = Report('host-a', end - dt.timedelta(days=1), end, 'daily')
report.set_metric('SSH authentication failures (log entries)', 46)
report.set_metric('SSH successful authentications', 2)
report.set_metric('SSHGuard/Fail2ban block events', 3)
report.set_metric('Host suspicious HTTP paths', 12)
report.set_metric('Docker containers (running/stopped/unhealthy)', '3/1/1')
report.set_metric('Docker application error indicators', 4)
report.set_metric('Local filesystems at or above 90%', 0)
report.previous_counts = {
    'SSH authentication failures (log entries)': 15,
    'SSH successful authentications': 2,
    'SSHGuard/Fail2ban block events': 1,
    'Host suspicious HTTP paths': 8,
    'Docker application error indicators': 1,
    'Local filesystems at or above 90%': 0,
}
report.add('HIGH', 'docker:unhealthy:app-a', 'Unhealthy Docker container: app-a')
report.add('WARN', 'ssh:failures', 'SSH failures: 46 log entries; top source: 203.0.113.20 (31)')
report.record_ip('203.0.113.20', 'ssh_failed', 31)
report.record_ip('192.0.2.10', 'ssh_success', 2)
report.section('Docker containers', [
    'Running: 3; stopped: 1; unhealthy: 1',
    'app-a: status=running, health=unhealthy',
])
(ROOT / 'sample-email.html').write_text(report.htmltext(), encoding='utf-8')
(ROOT / 'sample-email.txt').write_text('Subject: ' + report.subject() + '\n\n' + report.plaintext(), encoding='utf-8')
