# Project 01: Mini SOC Lab (Wazuh + Sysmon)

**Status:** 🟡 in progress  
**Project repo:** https://github.com/Samaale11/soc-project-01-wazuh-sysmon-siem

## Name
Mini SOC Lab on a laptop: **Windows telemetry → Wazuh SIEM → detections → investigations → tickets → GitHub proof**

## Goal
Build a small SOC-style pipeline where a Windows endpoint produces high-value telemetry (Sysmon + Windows logs), Wazuh ingests and parses it, detections trigger alerts, and each alert is investigated and documented as a SOC ticket.

## What I can explain in an interview
- How logs move from an endpoint to a SIEM, what gets parsed, and what becomes an alert
- Why Sysmon adds value beyond standard Windows Security logs (process creation, network connections, richer context)
- Wazuh components and roles (manager, indexer, dashboard, agent) and what each one does
- How a custom Wazuh rule works (field matching, rule level, and safe placement so updates do not overwrite work)

## Lab scope (high level)
- **Endpoint:** Windows VM with Sysmon + Wazuh agent
- **SIEM:** Wazuh stack on Ubuntu VM (Docker single-node)
- **Network:** VirtualBox NAT (internet) + Host-only (private lab network)

## Evidence that will be added later (proof)
- [ ] Architecture diagram (image in `diagrams/`)
- [ ] Data sources list and why they matter (in `docs/02_data_sources.md`)
- [ ] Sysmon config used (in `configs/sysmon/`)
- [ ] Wazuh agent config snippet (in `configs/wazuh-agent/`)
- [ ] Custom Wazuh rules (in `rules/local_rules.xml`)
- [ ] Screenshots that prove ingestion and alerts (in `screenshots/`)
- [ ] 2 investigation tickets with timelines and decisions (in `tickets/`)

## Planned detections and tickets (placeholders for now)
- [ ] INC-001: Suspicious PowerShell with `-EncodedCommand`
- [ ] INC-002: Local user account created

## How to verify my work (once filled)
Open the project repo and check:
1) `screenshots/` for agent connection, Sysmon events, and alerts  
2) `rules/` for custom rules used to trigger the alerts  
3) `tickets/` for investigation notes, evidence, and final decision  
