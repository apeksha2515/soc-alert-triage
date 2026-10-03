# SOC-003 — Suspicious PowerShell Execution Attempting Credential Access

## Summary
A hidden PowerShell session, executed under a normally non-interactive
service account (`svc_backup`), downloaded a remote script and attempted
to invoke a credential-dumping tool against LSASS memory. EDR blocked the
LSASS access attempt before credentials could be dumped.

## Alert Triage
- **Trigger:** Wazuh rule 92501 (hidden-window PowerShell, no-profile flag)
- **Severity:** High — combination of (a) an out-of-pattern account using
  interactive-style PowerShell, (b) a known credential-dumping tool name
  in the command line, and (c) a subsequent LSASS access attempt makes
  this a high-confidence true positive.
- **Initial classification:** True Positive — Credential Access attempt.

## Evidence Reviewed
- Sysmon process chain: `cmd.exe → powershell.exe` under `svc_backup`
- Command line referencing `Invoke-Mimikatz -DumpCreds`, a well-known
  credential-dumping module
- Outbound HTTP connection retrieving a remote script (`inv.ps1`)
- Sysmon Event ID 10 showing a process-access request to `lsass.exe`
  with an access mask matching credential-dumping behaviour
- EDR log confirming the LSASS read was blocked
- Prior 24h logon history for `svc_backup` showing only scheduled-task
  logons (Type 4), with this session recorded as Type 3 (network) —
  strongly suggesting the account's credentials were used by an attacker
  remotely rather than a legitimate process on the account's own behalf

## MITRE ATT&CK Mapping
| Stage | Technique |
|---|---|
| Execution | T1059.001 – Command and Scripting Interpreter: PowerShell |
| Credential Access | T1003.001 – OS Credential Dumping: LSASS Memory |
| Defense Evasion | T1027 – Obfuscated Files or Information (hidden window, no-profile) |
| Command and Control | T1105 – Ingress Tool Transfer |

## Investigation Steps Taken
1. Compared this session's logon type and timing against `svc_backup`'s
   established baseline (scheduled task only, 02:00 daily) — confirmed
   anomaly.
2. Reviewed the full PowerShell command line for indicators of a known
   offensive tool (Mimikatz) rather than a legitimate admin script.
3. Cross-referenced Sysmon Event ID 10 (process access) to confirm the
   LSASS access attempt and its outcome (blocked).
4. Checked the source of the interactive-style session (network logon
   from IT-ADMIN-02) to scope which host and credentials may be
   compromised.
5. Searched for the same source IP (198.51.100.23) and script name
   across other hosts — no further matches found at time of writing.

## Verdict
**True Positive — Attempted Credential Dumping.** Blocked by EDR before
credentials were exfiltrated; account and host contained.

## SOC Response Recommendations
- Disable and rotate credentials for `svc_backup` immediately (actioned).
- Isolate host `IT-ADMIN-02` pending full forensic review.
- Block outbound access to `198.51.100.23` at the firewall/proxy.
- Review all systems where `svc_backup` has access, since its credentials
  may already be compromised beyond this host.
- Threat-hunt for `Invoke-Mimikatz` and similar LSASS-access patterns
  across the environment for the preceding 7 days.
- Recommend restricting service accounts to explicit allow-listed
  execution contexts to prevent this class of misuse going forward.

## False Positive Considerations
- Some legitimate admin tooling uses `-nop -w hidden` for scheduled
  automation; however, the explicit `Invoke-Mimikatz -DumpCreds` string
  and the subsequent LSASS access attempt rule out a benign explanation
  here.
