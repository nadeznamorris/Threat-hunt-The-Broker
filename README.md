# Threat-Hunting-Scenario-The-Broker

## RDP Compromise Incident

**Report ID:** INC-2026-2102

**Analyst:** Nadezna Morris

**Date:** 21-Feburary-2026

**Incident Date:** 15-January-2026

---

## **1. Findings**

### **Key Indicators of Compromise (IOCs):**

- **Attack Source IP:** 
- **Compromised Account:** `as-pc1`
- **Malicious File:** `notepad.exe`
- **Persistence Mechanism:** 
- **C2 Server:** 
- **Exfiltration Destination:**

### **KQL Queries Used:**

***SECTION 1:***  ***INITIAL ACCESS***

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
<img width="1510" height="450" alt="image" src="https://github.com/user-attachments/assets/57de01b3-7fae-495c-a643-c015177900da" /> <br><br>

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
<img width="1452" height="250" alt="image" src="https://github.com/user-attachments/assets/3fff5c9f-702b-4e43-b4fc-96986236c538" /> <br><br>

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

***SECTION 2:***  ***COMMAND & CONTROL***

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
<img width="1121" height="151" alt="Flag " src="https://github.com/user-attachments/assets/1a4bce11-56c3-4b79-a3ec-4129bb790482" /> <br><br>

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
<img width="2500" height="2000" alt="image" src="https://github.com/user-attachments/assets/66760694-8956-4473-a4f1-552cd973f3c5" />

---

***SECTION 3:*** ***CREDENTIAL ACCESS***





