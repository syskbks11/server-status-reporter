#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo 'Run installer as root.' >&2
  exit 2
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR='/usr/local/lib/server-security-monitor'
BIN_DIR='/usr/local/sbin'
UNIT_DIR='/etc/systemd/system'

install -d -o root -g root -m 755 "$LIB_DIR"
install -o root -g root -m 755 \
  "$SCRIPT_DIR/server_security_report.py" \
  "$SCRIPT_DIR/setup_monitor.py" \
  "$LIB_DIR/"
install -o root -g root -m 644 "$SCRIPT_DIR/monitor_config.py" "$LIB_DIR/monitor_config.py"
install -o root -g root -m 755 "$SCRIPT_DIR/bin/server-security-report" "$BIN_DIR/server-security-report"
install -o root -g root -m 755 "$SCRIPT_DIR/bin/server-security-setup" "$BIN_DIR/server-security-setup"
install -o root -g root -m 644 "$SCRIPT_DIR"/systemd/security-report-{daily,alert}.{service,timer} "$UNIT_DIR/"
systemctl daemon-reload
printf '%s\n' 'Installed. Configure with:' \
  '  sudo server-security-setup --init' \
  '  sudo server-security-setup --validate' \
  '  sudo server-security-report --test-email' \
  '  sudo systemctl enable --now security-report-daily.timer security-report-alert.timer'
