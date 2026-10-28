# SOC-20261027-011 Incident Summary

Triage summary of the AI-Agentic SOC report for the /etc/passwd and /etc/shadow integrity alert on the Kali host.

**Status:** DRAFT, needs analyst review. Severity is **High** with **Medium** confidence. It is not rated Critical because nothing malicious was corroborated.

## What happened

At 04:07:34 UTC on 2026-10-27, Wazuh's scheduled file integrity scan (rule 100032, level 10) flagged changes to `/etc/passwd` and `/etc/shadow` on the Kali host (agent 002, 192.168.64.3). The inode of `/etc/passwd` changed from 264756 to 264757, which means the file was replaced rather than edited in place. Five more generic "integrity checksum changed" events (rule 550) fired in the same 0.1-second scan. There were no logins, failed authentications, privilege changes or session activity in the correlation window. The report cannot tell whether this is legitimate account administration, a package update, or malicious tampering.

## Threats (possible, none confirmed)

| Threat | MITRE | Evidence |
| --- | --- | --- |
| Tampering with authentication data | T1565.001 | Both files modified, and `/etc/passwd` was replaced. This is the best-supported item. |
| Persistence through account manipulation | T1098.004 | Only inherited from the rule's tags. There is no evidence of SSH key changes. |
| Evidence destruction | T1070.004 | Only inherited from the rule's tags. There is no deletion event, and replacement could overwrite old content. |

## Vulnerabilities and gaps

- There is no content diff or hash of what changed inside either file.
- There is no auditd, shell history or process data for the modification period, so the actor is unknown.
- Detection was late. Changes happened roughly 1 to 2 days before the scan flagged them, so the scan interval is a blind window.
- The EDR lookup failed (connection refused), so there is no endpoint context.
- Five rule 550 events do not name their files. The report never says which other files changed.

## Reliability problems in the report

- **Dates look off.** The mtime `1793031852` converts to about 2026-10-26 16:24 UTC, not 10-25, and the old mtime to about 10-20, not 10-19. Check with `date -d @1793031852`.
- **The "50m 25s" figure is mislabeled.** It is the Wazuh-to-agent processing delay. It is not the gap between modification and detection, which is days.
- **The 108h end-to-end latency conflicts** with the report's own timestamps, which are about 51 minutes apart.
- **The `brute_force` rule group is misleading.** No brute-force activity occurred.
- **"Attack duration 0.1s"** is just the length of the scan cycle, not an attack.

## Actions and escalation

### Do first (High)

1. Diff `/etc/passwd` and `/etc/shadow` against a backup or known-good baseline. Look for new UID 0 accounts, new accounts with login shells, and changed password hashes.
2. Check auditd, `last`, `lastb`, `~/.bash_history` and `/var/log/auth.log` for `useradd`, `usermod`, `passwd`, `chpasswd`, `vipw` or `sudo` around Oct 25 to 26. Also check `~/.ssh/authorized_keys` for every user, given the T1098.004 tag.
3. Find out which files the five rule 550 events covered.

### Then (Medium)

4. Check package manager logs (`/var/log/apt/history.log`, `dpkg.log`) and any config management for a legitimate cause.
5. Check whether a pentest, CTF or lab exercise ran that day.

### Escalate to incident response if any of these turn up

- Unknown accounts, duplicate UID 0 entries, or altered hashes.
- No benign explanation (package update, admin change, scheduled work).
- New SSH keys, new sudoers entries, or suspicious processes or logins around the change.
- Evidence the host reached sensitive segments, or the same changes appear on other hosts.

### Containment, if confirmed

Lock or remove the rogue accounts, rotate credentials, isolate the host, and preserve `/etc/passwd*`, `/etc/shadow*` and logs before changing anything.

## Likely outcome

If the diff and package logs show an ordinary `passwd`, `useradd` or `apt` run, close it as benign. The adjacent inode (264756 to 264757) is typical of the atomic-replace behavior those tools use.
