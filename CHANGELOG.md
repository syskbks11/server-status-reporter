# Changelog

## v4.1 — Quick setup and selective editing

- Reduce initial setup to SMTP sender, recipients, and hidden app password; use defaults for all monitoring categories and thresholds.
- Introduce item-level configuration menus so operators can change only the settings they choose.
- Preserve the configured minimum emergency severity when the input is blank.
- Keep the editing session open if validation fails instead of discarding staged changes.
- Avoid unapproved-port emergency alerts before an explicit Docker port allowlist is configured; published ports remain visible in daily reports.
- Expand regression tests for quick setup, menu selection, unchanged settings, and default port policy.

## v4 — Incident-based emergency notifications

- Prevent routine SSH failures and HTTP scans from triggering emergency mail by default.
- Add a single private `config.json` section, `alert_policy`, for emergency rules, trigger thresholds, recovery thresholds and optional recovery mail.
- Track persistent incident identities across checks and notify only on a new incident.
- Repeat active incidents in every daily report without duplicating existing findings.
- Normalize SSH failure surges to a 15-minute rate; use hysteresis for SSH and disk thresholds.
- Preserve active Docker incidents when container inspection cannot confirm recovery.
- Include root SSH logins from untrusted sources; known sources are still described in daily reports.
- Add regression tests for incident lifecycle, rule changes, missing Docker containers and the public-port policy.

## v3 — Interactive setup and GitHub-ready distribution

- Add a terminal-based setup for SMTP settings, local monitoring sources and detection rules.
- Keep local configuration and credentials outside Git.
- Provide systemd timers, sample email output, tests and a conservative privacy check.
