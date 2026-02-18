---
<h1 align="center"> SOC Analyst Portfolio tier 1 and 2 </h1>

<p align="center">I am <strong>Mohamed Farah, a Cybersecurity professional with a Bachelor’s degree in Cybersecurity from IU International University of Applied Sciences</strong>, the Google Cybersecurity Professional Certificate, and IT Fundamentals certification.</p>

<p align="center">This repository serves as the centralized hub for my <strong>SOC Analyst Tier 1 and 2 portfolio</strong>. It features <strong>evidence-based projects</strong> including log pipelines, alert triage, detection rules, threat hunting, incident tickets, and detailed lab writeups. These practical projects provide technical proof of my ability to collect telemetry, triage alerts, build detections, and write clear incident tickets using industry-standard tools such as Wazuh, Sysmon, Zeek, Suricata, and Velociraptor.</p>


## Target role: SOC Analyst Tier 1 or 2



### Credentials


- **Bachelor’s degree:** Cybersecurity, 2026 | IU International University of Applied Sciences  
- **Certification:** Technical Support Fundamentals, 2022 | Google, Coursera  
- **Certification:** Google Cybersecurity Professional Certificate, 2022 | Google, Coursera  

Additionally, I document each project with repeatable steps, screenshots, and tickets so the work can be verified quickly.

**Location:** Nairobi, Kenya | **LinkedIn:** www.linkedin.com/in/mohamed-farah-bb7b8622a 

**Resume:** in-progress | **Email:** Mohamedalas929@gmail.com


---
### What this portfolio proves


- I can move logs from endpoints and network sensors into a SIEM and confirm coverage.
- I can investigate alerts with a repeatable method: validate, scope, timeline, decision, next actions.
- I can build detections and tune noise, then map detections to attacker behavior.
- I can document work so another analyst can reproduce and verify it.



## Skill coverage (what you can hire me for)


### Core SOC Tier 1


- Alert triage: severity, false positive checks, evidence collection, escalation notes
- Windows telemetry: Event Logs, Sysmon, process and network activity review
- SIEM daily work: onboarding, parsing/fields, searching, dashboards, basic tuning
- Ticket writing: clear summary, impact, evidence, actions taken, recommendations


### Core SOC Tier 2


- Detection engineering: custom rules, thresholds, tuning, test cases
- Threat hunting: hypothesis-driven hunts, pivots, timelines, suspicious chains
- Incident response basics: containment ideas, scoping, communication notes, final report
- Threat intelligence basics: IOC checks, enrichment, confidence notes, limitations
---



### Fundamentals (broad cybersecurity base)


- Networking: TCP/IP, DNS, HTTP/S, common ports, NAT, basic packet and flow logic
- Operating systems: Windows process model, persistence concepts, service and task basics
- Security basics: authentication vs authorization, least privilege, logging strategy, risk thinking



### Standards and methods used


- MITRE ATT&CK mapping for detections and investigations (TTP-focused notes)
- NIST incident response flow (prepare, detect, analyze, contain, recover, lessons learned)
- CIS-style thinking for controls and hardening recommendations
---


## How to verify my work


If you only have 2 minutes: open Project 01 and read one ticket in `tickets/` plus the proof screenshots.

Each project repo follows a consistent structure so you can check evidence fast:

- `docs/` architecture, setup notes, and what “good” looks like
- `screenshots/` proof of configuration and alerts
- `rules/` custom detection rules and tuning notes
- `hunts/` hunt queries and findings
- `tickets/` SOC-style incident tickets (timeline + evidence + decision)
- `references/` official docs used.
---

**Ticket format is consistent:**


1) Summary and severity  
2) What triggered the alert  
3) Evidence (host, user, process tree, network, hashes, timestamps)  
4) Scope and impact (what is affected, what is not known yet)  
5) Decision (benign, suspicious, confirmed)  
6) Actions taken + next steps  
---


# Projects (10 practical SOC projects)


Legend: ✅ done | 🟡 in progress | ⬜ planned

1) ⬜ **Project 01: Mini SOC Lab (Wazuh + Sysmon on Windows)**
   
   -
   
   -
   
   - Build: SIEM pipeline for telemetry collection and alert detection via Wazuh and Sysmon.
   - Output: Lab writeups, custom detection rules, and professional incident tickets.
   - [Overview: Wazuh & Sysmon SIEM Implementation](./projects/project-01-wazuh-sysmon-siem/README.md)
   - Repo: https://github.com/<your-username>/soc-project-01-wazuh-sysmon-siem
     
3) ⬜ **Project 02: Alert Triage Playbook Pack (Tier 1 workflow)**
   - Build: step-by-step playbooks for common alerts (brute force, suspicious PowerShell, new admin user)
   - Output: triage checklists + sample tickets + close/escalate criteria
   - Overview: [projects/project-02.md](projects/project-02.md)
   - Repo: https://github.com/<your-username>/soc-project-02-triage-playbooks

4) ⬜ **Project 03: Network Visibility Lab (Suricata + Zeek)**
   - Build: IDS + network metadata, then send alerts/logs into your SIEM
   - Output: detections for scan behavior, suspicious DNS, and unusual outbound patterns
   - Overview: [projects/project-03.md](projects/project-03.md)
   - Repo: https://github.com/<your-username>/soc-project-03-suricata-zeek

5) ⬜ **Project 04: Phishing Investigation Lab**
   - Analyze: headers, URLs, attachments, payload indicators
   - Output: phishing decision notes + user guidance + containment steps
   - Overview: [projects/project-04.md](projects/project-04.md)
   - Repo: https://github.com/<your-username>/soc-project-04-phishing-triage

6) ⬜ **Project 05: Threat Hunting on Endpoints (Velociraptor)**
   - Hunt: persistence checks, unusual parent-child process chains, unsigned binaries
   - Output: hunt queries + findings + follow-up detections
   - Overview: [projects/project-05.md](projects/project-05.md)
   - Repo: https://github.com/<your-username>/soc-project-05-velociraptor-hunting

7) ⬜ **Project 06: Detection Engineering Pack (ATT&CK mapped)**
   - Write: a set of detections with test cases and tuning notes
   - Output: “why this is suspicious”, expected false positives, and validation steps
   - Overview: [projects/project-06.md](projects/project-06.md)
   - Repo: https://github.com/<your-username>/soc-project-06-detection-pack

8) ⬜ **Project 07: Cloud Log Triage (AWS CloudTrail)**
   - Build: a small cloud logging setup and investigate common IAM risks
   - Output: triage notes for risky API calls and access patterns
   - Overview: [projects/project-07.md](projects/project-07.md)
   - Repo: https://github.com/<your-username>/soc-project-07-cloudtrail-triage

9) ⬜ **Project 08: Vulnerability Management to SOC Workflow**
   - Scan: a lab environment, prioritize findings, and open remediation tickets
   - Output: risk notes, fixes, and verification screenshots
   - Overview: [projects/project-08.md](projects/project-08.md)
   - Repo: https://github.com/<your-username>/soc-project-08-vuln-to-tickets

10) ⬜ **Project 09: Incident Timeline Case (Ransomware-style simulation)**
   - Build: timeline from telemetry, confirm what happened, propose containment
   - Output: incident report + executive summary + lessons learned
   - Overview: [projects/project-09.md](projects/project-09.md)
   - Repo: https://github.com/<your-username>/soc-project-09-incident-timeline

11) ⬜ **Project 10: SOC Automation Lite (Enrichment + Ticketing)**
   - Automate: IOC enrichment, reputation checks, and a basic triage workflow
   - Output: faster triage notes, consistent evidence collection
   - Overview: [projects/project-10.md](projects/project-10.md)
   - Repo: https://github.com/<your-username>/soc-project-10-automation-lite
---


### Repo structure


- `projects/` contains one-page summaries for quick scanning
- Each project repo contains the full evidence trail and reproducible steps
  

I treat every project as a real SOC case. You can review my tickets, validate the evidence in screenshots, and follow my steps to reproduce the results.


