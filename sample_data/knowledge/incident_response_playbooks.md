# Incident Response Playbooks (project-authored general guidance)

Written for ARYAN CYBERSHIELD AI by Aryan's project team as general operational guidance. Adapt to your organisation's policy.

## Playbook: Brute-Force / Repeated Failed Logins
Indicators: many failed authentications from one source IP, many usernames tried from one IP (password spraying), or many failures followed by a success.
Triage: confirm whether a success followed the failures; check whether the targeted account is privileged; check source IP reputation.
Containment: rate-limit or temporarily block the source IP at the perimeter after approval; force password reset and revoke active sessions for any account that had a success after failures.
Investigation: review authentication logs for the same source across other services; look for lateral movement from the affected account (ATT&CK T1110 Brute Force, T1078 Valid Accounts).
Recovery: enable multi-factor authentication, enforce lockout thresholds, monitor the account for 30 days.

## Playbook: Phishing Email
Indicators: sender domain mismatch or lookalike domain, urgency or threat language, credential-harvesting links, mismatched link text and destination, unexpected attachments.
Triage: do not click links; extract sender, headers and URLs; check URL and domain reputation.
Containment: quarantine the message across mailboxes; block the sender domain and URLs after approval; identify users who clicked.
Investigation: for users who clicked or entered credentials, treat the account as compromised (ATT&CK T1566 Phishing).
Recovery: reset affected credentials, revoke sessions, report the campaign, run user awareness follow-up.

## Playbook: Compromised Account
Indicators: logins from unusual locations or times, impossible travel, new mailbox rules, access to unusual resources.
Containment: reset the password, revoke all active sessions and tokens, require MFA re-enrolment.
Investigation: build a timeline of the account's activity; identify data accessed; check for persistence such as new API keys or forwarding rules (T1078 Valid Accounts).
Recovery: confirm the legitimate owner regained control; monitor for repeat activity.

## Playbook: Malicious Indicator (IP, Domain, File Hash)
Indicators: an indicator flagged malicious by multiple independent threat intelligence engines.
Triage: confirm detections are from reputable engines and recent; check for false positives such as shared hosting or CDN addresses.
Containment: block the indicator at proxy, DNS or firewall after approval; search historical logs for any contact with it.
Investigation: identify every internal host that communicated with the indicator and scope the exposure.
Recovery: remove malicious files, rebuild affected hosts if needed, retain blocks while the indicator stays active.

## Playbook: Endpoint Isolation
Use when an endpoint shows signs of active compromise such as command-and-control traffic or ransomware behaviour.
Prerequisite: explicit approval from an authorised analyst. Isolation must preserve forensic evidence and keep the management channel available.
Steps: record the pre-isolation state, isolate the host from the network, capture volatile evidence per procedure, verify isolation succeeded, and document a rollback plan to restore connectivity once the host is cleaned.

## General Principles
Document every action with who, what and when. Distinguish confirmed facts from hypotheses. Prefer the least disruptive action that contains the threat. Consequential actions require human approval. Preserve evidence before remediation.
