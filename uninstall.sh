#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo 'Run uninstaller as root.' >&2
  exit 2
fi

systemctl disable --now security-report-daily.timer security-report-alert.timer 2>/dev/null || true
rm -f /etc/systemd/system/security-report-{daily,alert}.{service,timer}
rm -f /usr/local/sbin/server-security-report /usr/local/sbin/server-security-setup
rm -rf -- /usr/local/lib/server-security-monitor
systemctl daemon-reload
printf '%s\n' \
  'Programs and systemd units removed.' \
  'Private configuration, secrets, monitoring state, and local reports are intentionally retained:' \
  '  /etc/server-security-report' \
  '  /var/lib/server-security-report' \
  '  /var/log/server-security-report'
