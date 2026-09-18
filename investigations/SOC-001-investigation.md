# SOC-001 — Multiple Failed Login Attempts

## 1. Alert Summary

- Alert ID: SOC-001
- Alert Name: Multiple Failed Login Attempts
- Timestamp: 2026-09-18 09:42:15 UTC
- Source IP: 185.203.117.42
- Username: administrator
- Failed Attempts: 8
- Event ID: 4625
- Host: WIN-SOC-01
- Severity: Medium
- Status: New

## 2. Initial Triage

The alert indicates eight failed authentication attempts against the
administrator account on the Windows host WIN-SOC-01.

The activity requires investigation because repeated failed authentication
attempts can be associated with password guessing or brute-force activity.

However, the alert alone does not confirm malicious activity. Other possible
explanations include a legitimate user entering an incorrect password multiple
times or a service/application using an outdated password.

## 3. Initial Questions

1. Did the failed attempts come from the same source IP?
2. Did the attempts occur within a short period of time?
3. Has the source IP contacted other hosts?
4. Was the administrator account successfully logged into afterwards?
5. Are there other Event ID 4625 events from the same IP?
6. Is the source IP known or trusted?
## 4. MITRE ATT&CK Mapping

### T1110 — Brute Force

The repeated failed authentication attempts may be consistent with
credential-guessing activity.

The activity is mapped to T1110 for investigation purposes. This mapping does
not by itself confirm that a brute-force attack occurred.

### Evidence

- 8 failed authentication attempts
- Target account: administrator
- Windows Event ID: 4625
- Source IP: 185.203.117.42

### Evidence Still Required

- Authentication attempt timestamps
- Successful login events following the failures
- Additional activity from the source IP
- Whether the source IP is known or trusted
- Whether other accounts or hosts were targeted
## 5. Investigation Findings

### Finding 1 — Authentication Pattern

Eight consecutive failed authentication attempts were observed against the
administrator account from source IP 185.203.117.42.

A successful authentication occurred approximately 13 seconds after the
failed attempts.

### Finding 2 — Source IP

The source IP 185.203.117.42 generated all observed failed authentication
attempts and the subsequent successful authentication.

The IP should be investigated to determine whether it is an expected source
for the administrator account.

### Finding 3 — Potential False Positive

The activity could represent legitimate user behaviour if an authorised user
repeatedly entered an incorrect password and subsequently authenticated
successfully.

### Finding 4 — Additional Investigation Required

The following should be checked:

- Whether the administrator account is authorised and expected to be used.
- Whether the source IP is known or trusted.
- Whether the successful login was legitimate.
- What activity occurred after the successful authentication.
- Whether similar authentication events occurred previously.

## 6. Verdict

**Classification: Suspicious**

The alert is classified as suspicious because multiple failed authentication
attempts were followed by a successful login from the same source IP.

Malicious activity has not been confirmed. However, the available evidence is
insufficient to classify the activity as benign.

Further investigation is required to determine whether the successful
authentication was legitimate.

## 7. Recommended SOC Response

1. Validate the successful login with the account owner or appropriate system
   administrator.
2. Investigate the reputation and ownership of the source IP.
3. Review authentication activity from the same IP across other accounts and
   hosts.
4. Review activity performed after the successful authentication.
5. Escalate the alert if additional evidence of credential abuse or
   unauthorised access is identified.
