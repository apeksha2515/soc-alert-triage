# SOC Alert Triage & Investigation Toolkit

## Overview

This project is a hands-on Security Operations Centre (SOC) alert triage and
investigation toolkit developed to practise the workflow used by entry-level
SOC analysts.

The project simulates security alerts and documents the process of:

- Alert triage
- Evidence analysis
- IOC extraction
- MITRE ATT&CK mapping
- Investigation
- Alert classification
- SOC response recommendations

## Investigation Workflow

Alert
  ↓
Initial Triage
  ↓
Evidence Collection
  ↓
IOC Extraction
  ↓
MITRE ATT&CK Mapping
  ↓
Investigation
  ↓
Verdict
  ↓
SOC Response

## Current Cases

### SOC-001 — Multiple Failed Login Attempts

A simulated Windows authentication alert involving repeated failed login
attempts against an administrator account.

Key investigation points:

- 8 failed authentication attempts
- Windows Event ID 4625
- Source IP: 185.203.117.42
- Administrator account targeted
- Successful authentication following the failed attempts
- MITRE ATT&CK T1110 considered during investigation
- Final classification: Suspicious

## Repository Structure

soc-alert-triage/
├── alerts/
│   └── multiple_failed_logins.json
├── investigations/
│   ├── SOC-001-evidence.txt
│   └── SOC-001-investigation.md
├── iocs/
│   └── SOC-001-iocs.txt
└── README.md

## Skills Demonstrated

- SOC alert triage
- Authentication log analysis
- IOC identification
- Incident investigation
- MITRE ATT&CK mapping
- False-positive analysis
- Security alert classification
- SOC response recommendations
- Linux/macOS command-line usage
- Git/GitLab project management

## Disclaimer

All alerts, IP addresses, usernames, hosts and investigation evidence in this
project are simulated for cybersecurity training and portfolio purposes.
