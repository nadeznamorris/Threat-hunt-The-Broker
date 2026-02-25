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
<br>
<img width="1184" height="176" alt="image" src="https://github.com/user-attachments/assets/9b22cfa1-4c8f-4abd-bcab-d47afe1abb88" /> <br><br>

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
<br>
<img width="1292" height="120" alt="image" src="https://github.com/user-attachments/assets/10dc83bc-dba6-4952-a2d3-0b18204258af" /> <br><br>

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
<br>
<img width="1282" height="207" alt="image" src="https://github.com/user-attachments/assets/c2a6e593-c5cd-4788-9ad9-d733b3cdce55" /> <br><br>

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
<br>
<img width="1206" height="81" alt="image" src="https://github.com/user-attachments/assets/1b2c87a4-efd4-46d0-91e3-5de63added8c" /> <br><br>

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
<br>
<img width="1206" height="81" alt="image" src="https://github.com/user-attachments/assets/1b2c87a4-efd4-46d0-91e3-5de63added8c" />

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
<br>
<img width="1308" height="600" alt="image" src="https://github.com/user-attachments/assets/6a385efb-2ede-4a9d-ba8e-14002a4ae932" /> <br><br>

**Objective:** Identify the process responsible for C2 traffic.

**Flag:** `"Daniel_Richardson_CV.pdf.exe"`

```
DeviceNetworkEvents
| where DeviceName == "as-pc1"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where isnotempty(RemoteUrl)
| where InitiatingProcessCommandLine has_any ("daniel")
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl
| order by TimeGenerated asc
```
<br>
<img width="1021" height="151" alt="Flag " src="https://github.com/user-attachments/assets/1a4bce11-56c3-4b79-a3ec-4129bb790482" /> <br><br>

**Objective:** Additional payloads were hosted externally.

**Flag:** `sync.cloud-endpoint.net`

```
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-14) .. datetime(2026-01-31))
| where isnotempty(RemoteUrl)
| where InitiatingProcessCommandLine has_any ("daniel")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteUrl, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```
<br>
<img width="882" height="85" alt="image" src="https://github.com/user-attachments/assets/29574243-f496-43ee-a964-e94db2343dd7" />

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
<br>
<img width="1172" height="127" alt="image" src="https://github.com/user-attachments/assets/3a782800-9079-43b2-ad89-96b431169bc8" /> <br><br>

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
<br>
<img width="1172" height="127" alt="image" src="https://github.com/user-attachments/assets/3a782800-9079-43b2-ad89-96b431169bc8" /> <br><br>

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
<br>
<img width="1287" height="122" alt="image" src="https://github.com/user-attachments/assets/7929af2c-c26b-4e35-8e92-b412a688d11a" />

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
<br>
<img width="1085" height="97" alt="image" src="https://github.com/user-attachments/assets/0161b507-d2f0-4277-8faa-ce30958ffe61" /> <br><br>

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
<br>
<img width="1017" height="80" alt="image" src="https://github.com/user-attachments/assets/357166b1-1bb7-4ccd-be51-02b0f8adff3e" /> <br><br>

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
<br>
<img width="1125" height="82" alt="image" src="https://github.com/user-attachments/assets/2a892075-0acc-4662-808e-26156ce87593" />

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
    "ammyy", "zohoassist"
)
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated asc
```
<br>
<img width="1258" height="115" alt="image" src="https://github.com/user-attachments/assets/d94d010e-27dc-4f13-831e-772cac7ab629" /> <br><br>

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
<br>
<img width="1266" height="112" alt="image" src="https://github.com/user-attachments/assets/30c09a4c-f019-40dd-a512-bff1f8af1f07" /> <br><br>

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
<br>
<img width="1236" height="85" alt="image" src="https://github.com/user-attachments/assets/db7478eb-fcc0-4a4d-b049-f8b5a2355184" /> <br><br>

**Objective:** After installation, a configuration file was accessed.

**Flag:** `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf"`

```
DeviceProcessEvents
| where DeviceName startswith "as-"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where ProcessCommandLine has_any ("AnyDesk")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| sort by TimeGenerated asc
```
<br>
<img width="1316" height="63" alt="image" src="https://github.com/user-attachments/assets/1a86580d-215c-4834-a51a-9766309f1542" /> <br><br>

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
<br>
<img width="1210" height="95" alt="image" src="https://github.com/user-attachments/assets/74b49bdc-5233-48fc-9dbc-38e9e782bbf9" /> <br><br>

**Objective:** The remote tool was installed across the environment.

**Flag:** `as-pc1, as-srv, as-pc2`

```
DeviceProcessEvents
| where DeviceName startswith "as-"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName =~ "AnyDesk.exe"
| distinct DeviceName
```
<br>
<img width="262" height="147" alt="image" src="https://github.com/user-attachments/assets/55286957-c48a-4786-9a3a-3e97bc340f59" />

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
<br>
<img width="1182" height="133" alt="image" src="https://github.com/user-attachments/assets/756a736e-2a8b-43b6-91ac-171dba3f0d77" /> <br><br>

**Objective:** Remote execution was attempted against a specific system.

**Flag:** `AS-PC2`

```
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName in~ ("wmic.exe","psexec.exe")
| where ProcessCommandLine has_any ("/node:","\\\\")
| project TimeGenerated, FileName, ProcessCommandLine
```
<br>
<img width="852" height="77" alt="image" src="https://github.com/user-attachments/assets/4e467a25-8767-472e-9930-88efc0b19f14" /> <br><br>

**Objective:** After failed attempts, a different method achieved lateral movement.

**Flag:** `mstsc.exe`

```
DeviceProcessEvents
| where DeviceName =~ "as-pc2"
| where TimeGenerated between (datetime(2026-01-01) .. datetime(2026-01-31))
| where FileName !in~ ("wmic.exe","psexec.exe")
| where InitiatingProcessAccountName has_any ("david")
| project TimeGenerated, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated asc
```
<br>
<img width="1093" height="123" alt="image" src="https://github.com/user-attachments/assets/569fd6e9-d386-4bc1-a382-5eac3a96ada6" /> <br><br>

**Objective:** The attacker moved through the environment in a specific sequence.

**Flag:** `as-pc1 > as-pc2 > as-srv`

```
DeviceProcessEvents
| where DeviceName startswith "as-"
| where TimeGenerated between (datetime(2026-01-15) .. datetime(2026-01-31))
| where FileName =~ "AnyDesk.exe"
| summarize FirstExec=min(TimeGenerated) by DeviceName
| sort by FirstExec asc
| project DeviceName, FirstExec
```
<br>
<img width="392" height="147" alt="image" src="https://github.com/user-attachments/assets/32d9b35a-0891-4291-bc50-f213bfc3bfd6" /> <br><br>

**Objective:** A valid account was used for successful lateral movement.

**Flag:** david.mitchell

```


