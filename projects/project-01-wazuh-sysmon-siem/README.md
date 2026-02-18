# Project 01: Mini SOC Lab on a Laptop (Wazuh + Sysmon)

**Goal:** build a SOC-style pipeline where Windows telemetry is collected, analyzed in Wazuh, turned into alerts, investigated, and documented as tickets.

**Status:** documentation, repo layout, and templates are complete. Implementation evidence and final results are **to be written later**.

---

## What this project proves

- Collect Windows Event Logs and Sysmon telemetry from a Windows endpoint and send them to Wazuh for analysis. [2][6]
- Explain how events are ingested, decoded, stored, and evaluated against rules to produce alerts. [1][5]
- Create custom Wazuh rules that match specific event fields and raise alerts with clear descriptions. [5][7]
- Perform basic alert triage and document findings using SOC-style tickets with evidence links. [1]
- Maintain a clean repo layout that supports fast review and verification.

Log collection matters because investigations depend on reliable, searchable historical records after the event, not only what is visible in real time. [1]

---

## Lab architecture

![Hybrid Lab Architecture](./diagrams/Hybrid%20Lab%20architecture%20Diagram.png)

- **Windows host (endpoint):** this is the monitored endpoint running Sysmon and the Wazuh agent. [2][6]
- **Ubuntu VM (SIEM server):** runs the Wazuh stack (manager, indexer, dashboard) using Docker. [4]
- **Wazuh agent (Windows):** collects Windows event channels and forwards data to the Wazuh manager. [6]
- **Wazuh manager (Ubuntu):** analyzes incoming events using the ruleset and generates alerts when rule conditions match. [5]
- **Wazuh indexer and dashboard (Ubuntu):** stores and exposes events and alerts for searching and investigation. [4]

**Networking note:** the Ubuntu VM uses a VirtualBox Host-only Adapter so the Windows host can communicate with the VM over an isolated lab network. Host-only networking creates a software interface on the host and allows host and VM communication without exposing that traffic to the external network. [8][9]

---

## Data sources collected

- Windows **Security**
- Windows **System**
- Windows **Application**
- **Microsoft-Windows-Sysmon/Operational** [2]

Sysmon provides richer process context than Security-only telemetry, including full command line details and a stable process identifier (ProcessGUID) that helps correlate activity. This context supports faster and more accurate triage. [2]

---

## Detections built

1) **Suspicious PowerShell EncodedCommand**  
Matches PowerShell process creation where the command line contains `-enc` or `-encodedcommand`. This pattern is commonly used to hide intent, so it is a useful investigation starting point. [2][10]

2) **Local user created (Security 4720)**  
Triggers on Windows Security Event ID **4720** (a user account was created). New account creation can be legitimate, but it can also indicate persistence activity, so the alert requires context checks. [11]

---

## How to reproduce

### Server setup (Ubuntu VM)
1. Prepare the Ubuntu VM and configure its network adapters.
2. Deploy Wazuh using the Docker deployment guide (includes required `vm.max_map_count` setting for the indexer). [4]
3. Confirm the Wazuh dashboard is reachable.

**To be written later (template):**
- Ubuntu VM specs used (CPU, RAM, disk):
  - CPU: ___
  - RAM: ___
  - Disk: ___
- Docker and Docker Compose install steps used:
  - ___
- Wazuh Docker version/tag used:
  - ___
- Commands executed and outputs captured:
  - ___

### Endpoint setup (Windows host)
1. Install Sysmon and confirm Sysmon process creation events are visible in Event Viewer. [2]
2. Install the Wazuh agent and enroll it with the Wazuh server. [6]
3. Configure the agent to collect the Sysmon Operational event channel. [6]
4. Confirm network connectivity and required ports from Windows to the Wazuh manager (1514/TCP for agent communication, 1515/TCP for enrollment if using agent-request). [3]
5. Add the two custom detection rules and reload rules. [5][7]
6. Generate safe test events and confirm alerts.
7. Complete two incident tickets with timelines and evidence links.

**To be written later (template):**
- Sysmon installation method and config used:
  - ___
- Wazuh agent enrollment method used:
  - ___
- Windows firewall checks performed:
  - ___
- Safe test steps performed:
  - Test 1:
    - ___
  - Test 2:
    - ___

---

## Evidence (to be written later)

- `screenshots/01_wazuh_running/`  
  To be written later: proof that Wazuh is running and the dashboard is reachable. [4]
- `screenshots/02_agent_connected/`  
  To be written later: proof that the Windows agent is enrolled and connected. [6]
- `screenshots/03_sysmon_events/`  
  To be written later: proof that Sysmon Operational logs include Event ID 1 process creation. [2]
- `screenshots/04_alerts/`  
  To be written later: proof that both detections fire in Wazuh with matching event fields visible.
- `screenshots/05_tickets/`  
  To be written later: proof that tickets are completed with evidence links and conclusions.

**To be written later (template for evidence index):**
- Screenshot filenames and what each proves:
  - 01: ___
  - 02: ___
  - 03: ___
  - 04: ___

---

## Tickets / investigations

- Ticket format: [tickets/_template.md](tickets/_template.md)
- INC-001: [tickets/INC-001-suspicious-powershell.md](tickets/INC-001-suspicious-powershell.md)
- INC-002: [tickets/INC-002-local-user-created.md](tickets/INC-002-local-user-created.md)

---

## What I learned

- Why log management is required for investigation, retention, and later analysis. [1]
- What Sysmon Event ID 1 provides and why command line and ProcessGUID improve triage. [2]
- What Windows Security Event 4720 represents and why attribution fields matter (who created the account and where). [11]
- How Wazuh rules evaluate decoded fields and generate alerts when all conditions match. [5]
- How Wazuh rule severity levels support prioritization. [12]
- How to structure triage: confirm alert details, extract key fields, build a short timeline, decide benign versus suspicious.
- How to document investigations with consistent ticket structure and evidence links.

---

## References

[1] NIST SP 800-92, Guide to Computer Security Log Management  
https://csrc.nist.gov/pubs/sp/800/92/final

[2] Microsoft Sysmon (Sysinternals) documentation  
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

[3] Wazuh agent enrollment requirements (ports 1514/TCP and 1515/TCP)  
https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/requirements.html

[4] Wazuh deployment on Docker (includes `vm.max_map_count` requirement)  
https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html

[5] Wazuh Rules syntax (ruleset evaluates events and generates alerts when conditions match)  
https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html

[6] Deploying Wazuh agents on Windows endpoints  
https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html

[7] Wazuh custom rules  
https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html

[8] Oracle VirtualBox Host-only Networking  
https://docs.oracle.com/en/virtualization/virtualbox/6.0/user/network_hostonly.html

[9] VirtualBox manual, Chapter 6: Virtual Networking  
https://www.virtualbox.org/manual/ch06.html

[10] MITRE ATT&CK T1059.001: PowerShell  
https://attack.mitre.org/techniques/T1059/001/

[11] Microsoft Security Event 4720: A user account was created  
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720

[12] Wazuh rules classification levels (0 to 16)  
https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html
