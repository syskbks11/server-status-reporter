# Server Security Monitor

Host and Docker security summaries by email, with an interactive terminal setup. Intended for privately managed Linux servers, run as `root` via systemd. Python 3.8+ and no third-party Python modules are required.

All deployment identifiers and credentials are configured **after installation**, outside the repository. Do not put real addresses, log excerpts, system names, access tokens, or application-specific settings into Git history.

## Features

- SSH authentication failures and successes, guard bans, trusted source networks.
- Host HTTP access statistics, custom suspicious-path regexes, optional exclusions, threshold alerts.
- Docker container state, health, restarts, missing required containers, new public bindings, permissions, and optionally container log patterns.
- Custom per-application Docker log rules, configurable severity, service and disk checks.
- Concise HTML and plain-text reports, daily deltas, top source IP activity, recommended follow-up steps.
- Daily reports and deduplicated 15-minute checks via systemd timers.
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

The setup prompts for SMTP hostname, sender, recipients, app password (hidden input), a generic report label, host log paths, Docker container names, exclusions, detection rules and severity policy. Press Enter to retain a default, `CLEAR` to clear list fields, and `EDIT` to replace regex lists. For Gmail, the default SMTP service is `smtp.gmail.com:587`, and a Google app password may be used if supported by the account. A standard sign-in password should not be used.

**Do not edit Python source code to store credentials or host-specific configuration.** The script reads the private JSON settings at runtime. On separate servers, run the setup separately.

## Reconfigure

```bash
sudo server-security-setup --configure
sudo server-security-setup --show
sudo server-security-setup --validate
sudo server-security-report --test-email
sudo server-security-report --mode alert --dry-run
```

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

Daily checks run at 07:00 local time and alert checks every 15 minutes by default. The systemd timer schedules are in `systemd/`; use local systemd drop-ins if a host needs a different schedule. Daily messages show `OK`, `REVIEW` or `URGENT` and approximate 24-hour previous-period comparisons when available. Alert messages are sent for new findings, with persistent findings deduplicated by key.

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
- A known/trusted SSH source suppresses ordinary successful-login warnings, **not root-login alerts**.
- Severity `OFF` suppresses an alert but does not delete or rewrite its underlying event logs.
- Check for false positives and adjust per-host rules through the setup wizard before enabling timers.
