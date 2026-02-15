# Project 01: Mini SOC Lab (Wazuh + Sysmon)
Windows telemetry → Wazuh SIEM → detections → investigations → tickets

**Status:** 🟡 in progress  
**Project repo:** https://github.com/Samaale11/soc-project-01-wazuh-sysmon-siem

## Goal
Build a SOC-style pipeline where a Windows endpoint produces high-value telemetry (Sysmon + Windows Event Logs), Wazuh ingests and parses it, detections trigger alerts, and each alert is investigated and documented as a SOC ticket.

## Lab scope (high level)
- **Endpoint:** Windows VM with Sysmon + Wazuh agent
- **SIEM:** Wazuh stack on Ubuntu VM (Docker single-node)
- **Network:** VirtualBox NAT (internet) + Host-only (private lab network)

## What this proves (Tier 1/2 skills)
- [ ] Alert triage decision (close vs escalate) with evidence
- [ ] Investigation timeline (who, what, when, where)
- [ ] Detection logic (rule) + test case
- [ ] Noise control (false positives and tuning notes)

## Data sources and tools (Project 01)
- **Logs:** Sysmon, Windows Security, Windows System, Windows Application
- **Tools:** Wazuh (manager/indexer/dashboard/agent), VirtualBox, Windows Event Viewer

## Detections and hunts (placeholders for now)
- Detection 1: Suspicious PowerShell usage (MITRE: T1059.001 placeholder)
- Detection 2: Local user account created (MITRE: T1136.001 placeholder)
- Hunt query: Find suspicious parent-child process chains (placeholder)

## Evidence checklist (links added when done)
- [ ] Architecture diagram
- [ ] Setup proof screenshots (Wazuh running + agent connected)
- [ ] Sysmon proof (Event ID 1 visible on the endpoint and inside Wazuh)
- [ ] Alert proof screenshots (2 detections)
- [ ] 2 tickets in `tickets/` with timeline + evidence + decision
- [ ] Custom rules in `rules/` (and tuning notes)

## How to verify my work (once filled)
Open the project repo and check:
1) `screenshots/` for agent connection, Sysmon events, and alerts  
2) `rules/` for the custom rules used to trigger the alerts  
3) `tickets/` for investigation notes, evidence, and final decision  
