# Server Security Monitor

Host and Docker security summaries by email, with an interactive terminal setup and incident-based notifications. Intended for privately managed Linux servers, run as `root` via systemd. Python 3.8+ and no third-party Python modules are required.

All deployment identifiers and credentials are configured **after installation**, outside the repository. Do not put real addresses, log excerpts, system names, access tokens, or application-specific settings into Git history.

## Features

- SSH authentication failures and successes, guard bans, trusted source networks.
- Host HTTP access statistics, custom suspicious-path regexes, optional exclusions, threshold alerts.
- Docker container state, health, restarts, missing required containers, new public bindings, permissions, and optionally container log patterns.
- Custom per-application Docker log rules, configurable severity, service and disk checks.
- Concise HTML and plain-text reports, daily deltas, top source IP activity, recommended follow-up steps, and incident start dates.
- Daily reports with continuing incidents and incident-transition notifications from 15-minute checks via systemd timers.
- Gmail SMTP with STARTTLS, interactive hidden password entry, private root-owned configuration.

This is a log summarizer, **not** an intrusion prevention or forensic investigation system. HTTP 2xx responses on suspicious paths do not establish compromise. Reverse-proxy and container HTTP logs may contain the same request; counts are not added together. Some applications log only to files inside the container, which `docker logs` cannot read.

## Install

From a newly downloaded, trusted copy of this repository, inspect the scripts before running them as root.

```bash
sudo bash install.sh
sudo server-security-setup --init
sudo server-security-setup --validate
sudo server-security-report --test-email
sudo server-security-report --dry-run
sudo systemctl enable --now security-report-daily.timer security-report-alert.timer
```

The setup prompts for SMTP hostname, sender, recipients, app password (hidden input), a generic report label, host log paths, Docker container names, exclusions, detection rules, notification thresholds and severity policy. Press Enter to retain a default, `CLEAR` to clear list fields, and `EDIT` to replace regex lists. For Gmail, the default SMTP service is `smtp.gmail.com:587`, and a Google app password may be used if supported by the account. A standard sign-in password should not be used.

**Do not edit Python source code to store credentials or host-specific configuration.** The script reads the private JSON settings at runtime. On separate servers, run the setup separately.

## Reconfigure

```bash
sudo server-security-setup --configure
sudo server-security-setup --show
sudo server-security-setup --validate
sudo server-security-report --test-email
sudo server-security-report --mode alert --dry-run
```

Select **7) Emergency notification policy** to change urgent notification conditions, SSH surge trigger/recovery thresholds, critical disk trigger/recovery percentages, and recovery email behavior. Select **3) Thresholds** for regular daily-report warning thresholds. All thresholds, exceptions and emergency flags live together in the private **`/etc/server-security-report/config.json`** file. No Python edit is needed.

`--show` redacts account addresses, log paths, service names, networks and match expressions, and never prints the SMTP password. `--validate` checks configuration fields and secure secret permissions. The monitoring script accepts `--config /absolute/path/config.json` for advanced deployments; the default is `/etc/server-security-report/config.json`.

Changes made in the CUI are applied on the next monitor run. The setup does not automatically restart services, modify firewall rules, or repair failed applications.

## Private files

| Path | Purpose | Permissions |
| --- | --- | --- |
| `/etc/server-security-report/config.json` | Local settings | root, `0600` |
| `/etc/server-security-report/smtp-password` | App password | root, `0600` |
| `/var/lib/server-security-report/state.json` | Checkpoint and last measurements | root-only |
| `/var/log/server-security-report/` | Local reports | root-only |

The password is never passed as a shell argument. `install.sh` does not copy any private file into the checkout. Keep secrets out of repository clones, issue reports, support chats, and CI output. Use a separate app password for each host where possible, and revoke it if leaked.

## Reporting

Daily checks run at 07:00 local time and alert checks every 15 minutes by default. The systemd timer schedules are in `systemd/`; use local systemd drop-ins if a host needs a different schedule. Daily messages show `OK`, `REVIEW` or `URGENT` and approximate 24-hour previous-period comparisons when available.

**Emergency notifications are incident-based rather than every-check messages.** Normal SSH authentication failures and suspicious HTTP scans appear in the daily report, but do not trigger emergency mail by default. The default emergency policy includes untrusted-source root SSH logins, a sharp SSH failure surge, required container stopped/missing/unhealthy, required systemd services inactive, Docker daemon failure, unapproved public Docker ports and critical disk usage. High-severity custom Docker log rules are opt-in through the rule definition. HTTP alerts are separately opt-in. All notification categories can be changed in the interactive setup.

An actionable *persistent* incident sends one new-incident alert, then remains active in `/var/lib/server-security-report/state.json`. A continuing incident appears in **each daily report** with its first detection timestamp; if the daily report already includes the same condition, it appears **only once**. Resolved incidents are cleared without an email by default; enable `notify_on_recovery` to receive a recovery message. A fresh incident after a verified resolution may notify again. Individual new root SSH login events may legitimately trigger separate notifications. If Docker monitoring becomes unavailable, existing Docker incidents are retained until verification is possible; they must not be mistaken for confirmed recoveries.

### Single-file notification policy

The host-specific policy is a section of the private `config.json`, not a second policy file. Example values (use interactive setup to modify them):

```json
{
  "alert_policy": {
    "minimum_level": "HIGH",
    "notify_on_recovery": false,
    "root_login_untrusted": true,
    "ssh_spike": true,
    "ssh_spike_trigger_count": 100,
    "ssh_spike_recovery_count": 30,
    "ssh_spike_increase_factor": 3.0,
    "required_container_down": true,
    "required_container_unhealthy": true,
    "other_container_unhealthy": false,
    "required_service_inactive": true,
    "docker_daemon_unavailable": true,
    "disk_critical": true,
    "disk_critical_percent": 95,
    "disk_recovery_percent": 90,
    "new_public_port": true,
    "custom_log_rule": true,
    "http_probe_2xx": false,
    "http_probe_volume": false
  }
}
```

This is an **excerpt**, not a complete configuration file. The actual setup also stores monitoring rules, the SMTP account, recipient list and secret file path in the same `config.json`, and the password is kept separately. All real configuration belongs outside Git.

For SSH surge detection, the program calculates a failure rate normalized to a 15-minute interval and requires both the configured trigger rate and a rise relative to the previous alert window. The incident remains open until the 15-minute rate falls to or below the recovery threshold. For disk usage, a high-severity incident is opened at the critical threshold and stays open until the recovery percentage is reached. These hysteresis thresholds prevent repeated notifications around a boundary. **Tune the defaults to each host's normal traffic**; they are not universal security baselines.

`--mode alert --dry-run` previews only newly eligible alerts and opt-in recovery notices without changing the checkpoint. Use it to calibrate rules before enabling timers.

A test or dry-run does not advance checkpoints. If SMTP delivery fails, checkpoints are not advanced. Mail itself is not a reliable heartbeat: use independent availability monitoring if a missing email must trigger a page.

## Test

```bash
python3 -m unittest discover -s tests -v
python3 privacy_check.py
```

## Uninstall

```bash
sudo bash uninstall.sh
```

Uninstall preserves configuration, secrets, state and reports to avoid accidental loss. Delete these private directories explicitly after confirming they are no longer needed.

## Publishing safely

1. Use a **fresh** Git repository. Do not import history from a private project that may contain configuration, user names or system identifiers.
2. Run the unit tests and `python3 privacy_check.py` and inspect its limitations; manually inspect all tracked files and samples.
3. Run `git status --short` and `git diff --cached --check`; confirm only intended source files are staged.
4. Review GitHub account details, repository owner, README text, screenshots, and **Git commit author name/email**. A public repository can identify its owner even when source is anonymous.
5. Use GitHub's account-provided `noreply` email if you want to reduce exposure of the underlying account email. Check existing local/global Git author settings.
6. Check that **no real production configuration** or local report has ever been committed; `.gitignore` does not remove sensitive content from existing history.

Example initialization:

```bash
git init
git add .
git status --short
git diff --cached --check
git commit -m "Initial public release"
```

A public repository cannot guarantee anonymity; Git metadata, account associations, and external references may identify maintainers.

## Notes and limitations

- `journalctl` must be available for journal-based events, and Docker must be installed for Docker checks.
- Host HTTP detection reads only the log glob patterns supplied through setup. Configure them on each machine.
- Docker logging drivers and application log destinations determine whether `docker logs` includes useful events.
- Custom regexes are evaluated against untrusted logs; use simple, bounded expressions and test carefully.
- A known/trusted SSH source suppresses emergency root-login notifications by default, but its root logins still appear as warnings in the daily report. Configure trusted SSH networks carefully.
- Severity `OFF` suppresses an alert but does not delete or rewrite its underlying event logs.
- Configure required containers, required services, trusted SSH networks, and allowed public ports per host before enabling timers; otherwise baseline conditions may trigger first-run alerts.
- Upgrading from an older release preserves the local configuration. The new `alert_policy` is filled with defaults; review it via `sudo server-security-setup --configure` (menu 7). The incident state starts a new baseline because older state files lack `active_incidents`, so existing outages may produce a one-time notification after upgrade.
- Check for false positives and adjust per-host rules through the setup wizard before enabling timers.
