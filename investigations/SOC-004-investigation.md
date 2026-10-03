# SOC-004 — Lateral Movement via SMB and Remote Service Creation

## Summary
The service account `svc_backup` — previously implicated in the SOC-003
credential-access attempt — was used to authenticate to the domain
controller `DC-01`, access the `ADMIN$` share, and install a PsExec-style
remote service. A reconnaissance command (`whoami /all`) was then executed
on the domain controller.

## Alert Triage
- **Trigger:** Wazuh rule 92710 (remote service creation via ADMIN$ share
  following a network logon)
- **Severity:** Critical — this is lateral movement onto a domain
  controller by a previously compromised identity; potential for full
  domain compromise.
- **Initial classification:** True Positive — Lateral Movement.

## Evidence Reviewed
- Windows Security 4624: network logon on `DC-01` from `svc_backup`,
  sourced from `IT-ADMIN-02` (the host from SOC-003)
- Windows Security 5140: access to the `ADMIN$` share, a hallmark of
  remote administration / PsExec-style tooling
- Windows Security 7045: installation of service `PSEXESVC` with binary
  path `C:\Windows\PSEXESVC.exe` — the default artifact left by
  Sysinternals PsExec
- Sysmon: `cmd.exe /c whoami /all` executed via the new service,
  output redirected to a file rather than printed to console — consistent
  with automated/scripted reconnaissance rather than manual interactive use

## MITRE ATT&CK Mapping
| Stage | Technique |
|---|---|
| Lateral Movement | T1021.002 – Remote Services: SMB/Windows Admin Shares |
| Execution | T1569.002 – System Services: Service Execution (PsExec-style) |
| Discovery | T1033 – System Owner/User Discovery (`whoami /all`) |
| Persistence (potential) | T1543.003 – Create or Modify System Process: Windows Service |

## Investigation Steps Taken
1. Correlated this alert's source account (`svc_backup`) and source host
   (`IT-ADMIN-02`) against the SOC-003 case — confirmed same identity,
   same host, ~4.5 hours later.
2. Confirmed the service name/binary path (`PSEXESVC.exe`) against known
   PsExec artifacts rather than a legitimate scheduled/managed service.
3. Reviewed the reconnaissance command executed post-service-creation to
   assess attacker intent (privilege enumeration, not yet destructive).
4. Checked for additional service installs or lateral hops from `DC-01`
   to other hosts — none observed before containment.
5. Flagged a process gap: `svc_backup` was disabled after SOC-003 but
   re-enabled/reused before this event, indicating containment in
   SOC-003 was incomplete or the account was re-enabled prematurely.

## Verdict
**True Positive — Lateral Movement to Domain Controller.** Contained
before further service creation, file transfer, or persistence
mechanisms could be established.

## SOC Response Recommendations
- Immediately and permanently disable `svc_backup`; issue a new service
  account with a rotated, vaulted credential if backup functionality is
  still required.
- Isolate `DC-01` and perform full forensic imaging before returning it
  to production.
- Force a domain-wide password reset for privileged and service accounts
  as a precaution, given DC-level access was achieved.
- Review Group Policy / firewall rules to restrict `ADMIN$` share access
  and remote service creation to a small allow-list of jump hosts only.
- Conduct a full incident retrospective covering SOC-003 → SOC-004 to
  identify why the account wasn't fully contained after the first
  detection (process/tooling gap, not a detection gap).
- Hunt for `PSEXESVC` service installs and matching `whoami` command
  patterns across the rest of the estate.

## False Positive Considerations
- PsExec is sometimes used legitimately by IT admins for remote
  administration. However, the direct link to the already-compromised
  `svc_backup` account from SOC-003, combined with a DC as the target
  and no associated change ticket, rules out a benign administrative
  explanation.
