# Threat-Hunting-Scenario-The-Broker

## RDP Compromise Incident

**Report ID:** INC-2026-2102

**Analyst:** Nadezna Morris

**Date:** 21-Feburary-2026

**Incident Date:** 15-January-2026

---

## **1. Findings**

### **Key Indicators of Compromise (IOCs):**

- **Attack Source IP:** `104.21.30.237`
- **Compromised Account:** `as-pc1`
- **Malicious File:** `notepad.exe`
- **Persistence Mechanism:** 
- **C2 Server:** 
- **Exfiltration Destination:**

### **KQL Queries Used:**

***SECTION 1: INITIAL ACCESS***

**Objective:** Identify the file that started the infection chain.

**Flag:** `daniel_richardson_cv.pdf.exe`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-14) .. datetime(2026-01-31))
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by TimeGenerated asc
``` 
<img width="1300" height="142" alt="image" src="https://github.com/user-attachments/assets/da2bb4c4-8db1-4ba6-a037-2c5470f2aa09" /> <br>

**Objective:** Identify the SHA256 hash of the initial payload.

**Flag:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

```
DeviceFileEvents
| where DeviceName startswith "as-"
| where TimeGenerated between (datetime(2026-01-14) .. datetime(2026-01-31))
| where FileName has_any ("daniel")
| project TimeGenerated, DeviceName, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, SHA256, InitiatingProcessParentFileName
| order by TimeGenerated asc
```
<img width="1162" height="120" alt="image" src="https://github.com/user-attachments/assets/f290b64d-c5de-4caa-b7d7-0e2ca6c6a39b" /> <br>

**Objective:** Determine how the payload was initially launched.

**Flag:** `explorer.exe`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-14) .. datetime(2026-01-31))
| where InitiatingProcessFileName has_any ("daniel")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by TimeGenerated asc
```
<img width="1172" height="147" alt="Flag 3" src="https://github.com/user-attachments/assets/da31e3eb-b0af-4dfa-9111-8c7447729152" /> <br>

**Objective:** The payload created a child process for further activity.

**Flag:** `notepad.exe`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-14) .. datetime(2026-01-31))
| where InitiatingProcessFileName has_any ("daniel")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="850" height="112" alt="image" src="https://github.com/user-attachments/assets/0dea15c0-5c45-46c8-9c9d-a2ebbc16d727" /> <br>

**Objective:** The spawned process executed with unusual arguments.

**Flag:** `notepad.exe ""`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-14) .. datetime(2026-01-31))
| where InitiatingProcessFileName has_any ("daniel")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="850" height="112" alt="image" src="https://github.com/user-attachments/assets/0dea15c0-5c45-46c8-9c9d-a2ebbc16d727" />

---

***SECTION 2: COMMAND & CONTROL***

**Objective:** The payload established outbound connections.

**Flag:** `cdn.cloud-endpoint.net`

```
DeviceNetworkEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where isnotempty(RemoteUrl)
| where InitiatingProcessCommandLine has_any ("daniel")
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl
| order by TimeGenerated asc
```
<img width="1186" height="150" alt="image" src="https://github.com/user-attachments/assets/2f1a06e2-4b83-4fa3-9007-317ee5df8476" /> <br>

**Objective:** Identify the process responsible for C2 traffic.

**Flag:** `"Daniel_Richardson_CV.pdf.exe"`

```
DeviceNetworkEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where isnotempty(RemoteUrl)
| where InitiatingProcessCommandLine has_any ("daniel")
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="850" height="141" alt="image" src="https://github.com/user-attachments/assets/94ade4c3-d413-462a-997e-bc484ef712cb" /> <br>

**Objective:** Additional payloads were hosted externally.

**Flag:** `sync.cloud-endpoint.net`

```
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where isnotempty(RemoteUrl)
| where InitiatingProcessCommandLine has_any ("daniel")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteUrl, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```
<img width="980" height="82" alt="image" src="https://github.com/user-attachments/assets/35617b8b-8fd4-40b4-b488-b717af50b980" />

---

***SECTION 3: CREDENTIAL ACCESS***

**Objective:** The attacker targeted local credential stores.

**Flag:** `SAM, SYSTEM`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ProcessCommandLine has_any ("reg.exe")
| where ProcessCommandLine has_any ("save")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="1172" height="127" alt="image" src="https://github.com/user-attachments/assets/3a782800-9079-43b2-ad89-96b431169bc8" /> <br>

**Objective:** Extracted data was saved locally before exfiltration.

**Flag:** `C:\Users\Public\`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ProcessCommandLine has_any ("reg.exe")
| where ProcessCommandLine has_any ("save")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="1172" height="127" alt="image" src="https://github.com/user-attachments/assets/3a782800-9079-43b2-ad89-96b431169bc8" /> <br>

**Objective:** Credential extraction was performed under a specific user context.

**Flag:** `sophie.turner`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ProcessCommandLine has_any ("reg.exe")
| where ProcessCommandLine has_any ("save")
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="880" height="113" alt="image" src="https://github.com/user-attachments/assets/4307167f-8b33-4244-9e33-c205b6693eda" />

---

***SECTION 4: DISCOVERY***

**Objective:** The attacker confirmed their identity after initial access.

**Flag:** `whoami.exe`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ProcessCommandLine has_any ("whoami", "localgroup", "view")
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="950" height="82" alt="Flag 12" src="https://github.com/user-attachments/assets/9d0a2154-32ed-4286-8915-f39ac5f1b974" /> <br>

**Objective:** The attacker enumerated network resources.

**Flag:** `net.exe view`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ProcessCommandLine has_any ("whoami", "localgroup", "view")
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="950" height="80" alt="image" src="https://github.com/user-attachments/assets/357166b1-1bb7-4ccd-be51-02b0f8adff3e" /> <br>

**Objective:** The attacker enumerated privileged local group membership.

**Flag:** `administrators`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ProcessCommandLine has_any ("whoami", "localgroup", "view")
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="950" height="81" alt="image" src="https://github.com/user-attachments/assets/e8eca8d8-1857-49b7-8078-6a968a92fb39" />

---

***SECTION 5: PERSISTENCE - REMOTE TOOL***

**Objective:** A legitimate remote administration tool was deployed for ongoing access.

**Flag:** `AnyDesk.exe`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName has_any (
    "teamviewer", "anydesk", "screenconnect", "connectwise",
    "splashtop", "aeroadmin", "logmein", "ngrok",
    "rustdesk", "dwagent", "ultravnc", "tightvnc",
    "ammyy", "zohoassist")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="830" height="150" alt="image" src="https://github.com/user-attachments/assets/69f20eeb-bfe9-4b81-beb1-df20b101b039" /> <br>

**Objective:** Identify the SHA256 hash of the remote access tool.

**Flag:** `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ProcessCommandLine has_any ("AnyDesk")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, SHA256
| sort by TimeGenerated asc
```
<img width="1277" height="146" alt="image" src="https://github.com/user-attachments/assets/aea67e7d-499a-4e7c-8655-2ff3b321b515" /> <br>

**Objective:** The tool was downloaded using a native Windows binary.

**Flag:** `certutil.exe`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ProcessCommandLine has_any ("AnyDesk")
| where ProcessCommandLine has_any ("download")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="1218" height="115" alt="image" src="https://github.com/user-attachments/assets/04ba1bda-c900-4edb-a9ed-3462aa2c9228" /> <br>

**Objective:** After installation, a configuration file was accessed.

**Flag:** `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf"`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ProcessCommandLine has_any ("AnyDesk")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="1150" height="95" alt="image" src="https://github.com/user-attachments/assets/74dc45a3-aa7d-448b-aa5e-1bb992cb182c" /> <br>

**Objective:** Unattended access was configured for the remote tool.

**Flag:** `intrud3r!`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where InitiatingProcessCommandLine has_any ("daniel")
| project TimeGenerated, DeviceName, ActionType, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1161" height="90" alt="image" src="https://github.com/user-attachments/assets/4796a5bb-20ce-48fc-a286-feb25a70d461" /> <br>

**Objective:** The remote tool was installed across the environment.

**Flag:** `as-pc1, as-srv, as-pc2`

```
DeviceProcessEvents
| where DeviceName startswith "as-"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName =~ "AnyDesk.exe"
| distinct DeviceName
```
<img width="155" height="150" alt="image" src="https://github.com/user-attachments/assets/2d30dc8a-1c59-4fff-ba2d-1387ac9e2728" />

---

***SECTION 6: LATERAL MOVEMENT***

**Objective:** The attacker attempted remote execution methods that failed.

**Flag:** `WMIC.exe, PsExec.exe`

```
DeviceProcessEvents
| where DeviceName startswith "as-"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName in~ ("psexec.exe","wmic.exe","winrs.exe","schtasks.exe","sc.exe")
| project TimeGenerated, DeviceName, FileName, ActionType, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="960" height="170" alt="image" src="https://github.com/user-attachments/assets/7531e4a6-e82c-4aaa-b2d5-052af21dfdde" /> <br>

**Objective:** Remote execution was attempted against a specific system.

**Flag:** `AS-PC2`

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName in~ ("wmic.exe","psexec.exe")
| where ProcessCommandLine has_any ("/node:","\\\\")
| project TimeGenerated, FileName, ProcessCommandLine
```
<img width="800" height="78" alt="image" src="https://github.com/user-attachments/assets/bfbf02ce-b054-47bf-b442-5138db2bb053" /> <br>

**Objective:** After failed attempts, a different method achieved lateral movement.

**Flag:** `mstsc.exe`

```
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName !in~ ("wmic.exe","psexec.exe")
| where InitiatingProcessAccountName has_any ("david")
| project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated asc
```
<img width="875" height="115" alt="image" src="https://github.com/user-attachments/assets/7d4b9309-c5bf-457e-8083-7dc7160e2c73" /> <br>

**Objective:** The attacker moved through the environment in a specific sequence.

**Flag:** `as-pc1 > as-pc2 > as-srv`

```
DeviceProcessEvents
| where DeviceName startswith "as-"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName == "AnyDesk.exe"
| summarize FirstExec=min(TimeGenerated) by DeviceName
| sort by FirstExec asc
| project DeviceName, FirstExec
```
<img width="366" height="146" alt="image" src="https://github.com/user-attachments/assets/5423e92c-3d4d-41ab-927a-a485e0d8cb8f" /> <br>

**Objective:** A valid account was used for successful lateral movement.

**Flag:** `david.mitchell`

```
DeviceLogonEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, RemoteIP, LogonType
| sort by TimeGenerated asc
```
<img width="677" height="145" alt="image" src="https://github.com/user-attachments/assets/cf176290-4622-48ad-bf21-a2e15163b6fb" /> <br>

**Objective:** A disabled account was enabled for further access.

**Flag:** `/active:yes`

```
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName == "net.exe"
| where ProcessCommandLine has_any ("user", "active")
| project TimeGenerated,DeviceName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="675" height="81" alt="image" src="https://github.com/user-attachments/assets/72c10297-c08e-4351-8fbf-8304ddef47fd" /> <br>

**Objective:** The account activation was performed by a specific user.

**Flag:** `david.mitchell`

```
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName == "net.exe"
| where ProcessCommandLine has_any ("user", "active")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="790" height="115" alt="image" src="https://github.com/user-attachments/assets/d69e1c05-5f8d-4d34-b649-6ac1b1665ca8" />

---

***SECTION 7: PERSISTENCE - SCHEDULED TASK***

**Objective:** A scheduled task was created for persistence.

**Flag:** `MicrosoftEdgeUpdateCheck`

```
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName == "schtasks.exe"
| where ProcessCommandLine has_any ("/Create")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="1112" height="82" alt="image" src="https://github.com/user-attachments/assets/195e0ee6-758d-4588-9606-27996782f1c4" /> <br>

**Objective:** The persistence payload was renamed to avoid detection.

**Flag:** `RuntimeBroker.exe`

```
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
  and ProcessCommandLine has_all ("schtasks.exe", "/create")
| extend
    TaskName = extract(@"/tn\s+([^\s]+)", 1, ProcessCommandLine),
    TaskRun  = extract(@"/tr\s+([^\s]+)", 1, ProcessCommandLine)
| project TimeGenerated, DeviceName, TaskName, TaskRun
```
<img width="760" height="86" alt="image" src="https://github.com/user-attachments/assets/7d41aef0-5dd3-4821-9aa1-83222bb06b4e" /> <br>

**Objective:** The persistence payload shares a hash with another file in the investigation.

**Flag:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

```
DeviceFileEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName =~ "RuntimeBroker.exe"
| where isnotempty(SHA256)
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated asc
```
<img width="1127" height="82" alt="image" src="https://github.com/user-attachments/assets/1d7b66a1-0f4d-4c9d-a7c4-4649803923b6" /> <br>

**Objective:** A new local account was created for future access.

**Flag:** `svc_backup`

```
DeviceProcessEvents
| where DeviceName startswith "as-"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName =~ "net.exe"
| where ProcessCommandLine has_any ("user")
| where ProcessCommandLine has_any ("/add")
| project TimeGenerated, DeviceName, FolderPath, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="820" height="83" alt="Flag 31" src="https://github.com/user-attachments/assets/857e8909-9709-4ee3-8ecf-632a74791d35" />

---

***SECTION 8: DATA ACCESS***

**Objective:** A sensitive document was accessed on the file server.

**Flag:** `BACS_Payments_Dec2025.ods`

```
DeviceFileEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FolderPath has "\\\\"
| project TimeGenerated, DeviceName, FileName, FolderPath
| sort by TimeGenerated asc
```
<img width="850" height="86" alt="image" src="https://github.com/user-attachments/assets/0adf0638-7f2f-473c-a7b4-ae6912969503" /> <br>

**Objective:** The document was opened for editing, not just viewing.

**Flag:** `.~lock.BACS_Payments_Dec2025.ods#`

```
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName has "BACS_Payments"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath
| sort by TimeGenerated asc
```
<img width="1167" height="117" alt="Flag 33" src="https://github.com/user-attachments/assets/72d42bbb-aeb2-4491-9419-9c73732e3088" /> <br>

**Objective:** The document was accessed from a specific workstation.

**Flag:** `as-pc2`

```
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName has "BACS_Payments"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountName
| sort by TimeGenerated asc
```
<img width="1360" height="117" alt="image" src="https://github.com/user-attachments/assets/b7bd8479-707e-4d77-a7cb-671bf80725b6" /> <br>

**Objective:** Data was archived before potential exfiltration.

**Flag:** `Shares.7z`

```
DeviceFileEvents
| where DeviceName startswith "as-"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ActionType == "FileCreated"
| where FileName has_any (".zip" ".rar", ".7z")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| sort by TimeGenerated asc
```
<img width="750" height="82" alt="image" src="https://github.com/user-attachments/assets/a88164f4-dad8-49b6-9ffd-36323883fc0c" /> <br>

**Objective:** Identify the SHA256 hash of the staged archive.

**Flag:** `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048`

```
DeviceFileEvents
| where DeviceName startswith "as-"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ActionType == "FileCreated"
| where FileName has_any (".zip" ".rar", ".7z")
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| sort by TimeGenerated asc
```
<img width="1052" height="85" alt="image" src="https://github.com/user-attachments/assets/a4cb1cb7-c717-4901-a56b-0944569997ac" />

---

***SECTION 9: ANTI-FORENSICS & MEMORY***

**Objective:** The attacker cleared logs to cover their tracks.

**Flag:** `Security, System`

```
DeviceProcessEvents
| where DeviceName startswith "as-"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ProcessCommandLine has_any ("cl ")
| where FileName has_any ("wevtutil")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="780" height="112" alt="image" src="https://github.com/user-attachments/assets/a32a63d2-b846-488f-bff1-bf92514434f5" /> <br>

**Objective:** Evidence of reflective code loading was captured.

**Flag:** `ClrUnbackedModuleLoaded`

```
DeviceEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where InitiatingProcessFileName endswith ".exe"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName
| sort by TimeGenerated asc
```
<img width="720" height="83" alt="image" src="https://github.com/user-attachments/assets/7fdc6ce4-deee-4ee2-97e9-4a08a0df38e7" /> <br>

**Objective:** A credential theft tool was loaded directly into memory.

**Flag:** `SharpChrome`

```
DeviceEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ActionType == "ClrUnbackedModuleLoaded"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessCommandLine, AdditionalFields
| sort by TimeGenerated asc
```
<img width="1093" height="108" alt="image" src="https://github.com/user-attachments/assets/09298972-b321-4e11-99e7-450b82c3a6ad" /> <br>

**Objective:** The credential theft tool was injected into a legitimate process.

**Flag:** `notepad.exe`

```
DeviceEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ActionType == "ClrUnbackedModuleLoaded"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```
<img width="910" height="120" alt="image" src="https://github.com/user-attachments/assets/9926ca53-a56c-434a-8f55-a281c8bded1b" />

---

## 2. Investigation Summary — Ashford Sterling Recruitment

A targeted intrusion against Ashford Sterling Recruitment's internal environment was initiated via a socially engineered malicious file disguised as a CV. A file named `daniel_richardson_cv.pdf.exe` was delivered to workstation `as-pc1` and executed manually by the user through `explorer.exe`. The payload (SHA256: `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`) spawned `notepad.exe` with empty arguments (`notepad.exe ""`) as a hollowed host process, established C2 communications to `cdn.cloud-endpoint.net`, and downloaded secondary payloads from `sync.cloud-endpoint.net`.

The attacker operating under the compromised context of `sophie.turner` dumped credential material from the `SAM` and `SYSTEM` registry hives to `C:\Users\Public\`, then conducted post-exploitation enumeration using `whoami.exe`, `net.exe view`, and `net.exe localgroup administrators`. A remote access tool, `AnyDesk.exe`, was downloaded via `certutil.exe` (LOLBin), configured with the password `intrud3r!` for unattended access, and deployed across three systems: `as-pc1`, `as-srv`, and `as-pc2`. Credential theft was performed in-memory via `SharpChrome`, injected into `notepad.exe` using reflective CLR loading (`ClrUnbackedModuleLoaded`).

Lateral movement from `as-pc1` to `as-pc2` was achieved via RDP (`mstsc.exe`) using the stolen credentials of `david.mitchell`, after failed attempts with `WMIC.exe` and `PsExec.exe`. The attacker then progressed to `as-srv`, completing the movement chain `as-pc1 → as-pc2 → as-srv`. On `as-pc2`, persistence was established via a scheduled task named `MicrosoftEdgeUpdateCheck`, pointing to `RuntimeBroker.exe` — a renamed copy of the original payload (matching SHA256: `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`). A backdoor local account `svc_backup` was created, and the built-in Administrator account was re-enabled via `net user /active:yes` under `david.mitchell`'s context.

The attacker accessed the financial document `BACS_Payments_Dec2025.ods` from a network share via `as-pc2`, opening it for editing (evidenced by the LibreOffice lock file `.~lock.BACS_Payments_Dec2025.ods#`). Network share content was archived into `Shares.7z` (SHA256: `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048`) in preparation for exfiltration. Finally, the attacker cleared `Security` and `System` event logs via `wevtutil.exe` to hinder forensic investigation.

----
