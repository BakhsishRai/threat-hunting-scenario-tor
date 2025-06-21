# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/BakhsishRai/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at 2025-06-18T01:33:39.971327Z. These events began at: 2025-06-17T23:23:29.486429Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "bucklabs"
| where InitiatingProcessAccountName == "bucklabs"
| where Timestamp >= datetime(2025-06-17T23:23:29.486429Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountDomain

```
![Screenshot_261](https://github.com/user-attachments/assets/0b7997ee-7c99-46e2-999b-2fac2de84f6d)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.5.3.exe”. Based on the logs returned, at 2025-06-17T23:26:18.2837205Z, an employee on the “bucklabs” device ran the file tor‑browser‑windows‑x86_64‑portable‑14.5.3.exe from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "bucklabs"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project Timestamp, DeviceId, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
![Screenshot_262](https://github.com/user-attachments/assets/94fa686a-b95f-4b2b-aaa2-6d3bbeba277e)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user actually opened the TOR browser. There was evidence that they did open it at 2025-06-17T23:26:35.5786633Z. There was another instance of firefox.exe (TOR) afterwards.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "bucklabs"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, RequestAccountName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine  
| order by Timestamp desc

```
![Screenshot_263](https://github.com/user-attachments/assets/90714edc-8649-4efb-83f1-abe34475c0e3)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports.On 2025-06-21T01:18:53.7970479Z, a computer successfully made a connection using tor.exe, a file located in the Tor Browser folder on the desktop. The connection went to the remote IP address 166.88.239.170 over port 443.The connection was initiated by the process tor.exe, located in the folder. There were a couple of other connections to sites over port 443.


**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "bucklabs"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc

```
![Screenshot_265](https://github.com/user-attachments/assets/0adefe58-ee51-4f34-960f-f2a30bc4e13e)



---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** 2025-06-17T23:26:18.2837205Z
- **Event:** The user downloaded a file named tor‑browser‑windows‑x86_64‑portable‑14.5.3.exe to the Downloads folder.
- **Action:** File download detected.
- **File Path:** C:\Users\bucklabs\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** 2025-06-17T23:26:18.2837205Z
- **Event:** The user executed the file tor‑browser‑windows‑x86_64‑portable‑14.5.3.exe in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** tor‑browser‑windows‑x86_64‑portable‑14.5.3.exe /S
- **File Path:** C:\Users\bucklabs\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** 2025-06-17T23:26:35.5786633Z
- **Event:** User opened the TOR browser. Subsequent processes associated with TOR browser, such as firefox.exe and tor.exe, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** C:\Users\bucklabs\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

### 4. Network Connection - TOR Network

- **Timestamp:** 2025-06-21T01:18:53.7970479Z
- **Event:** A network connection to IP 166.88.239.170 on port 443 by the user was established using tor.exe, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** tor.exe
- **File Path:** c:\users\bucklabs\desktop\tor browser\browser\torbrowser\tor\tor.exe

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - 2025-06-21T01:18:22.5054779Z - Connected to 176.65.149.97 on port 443.
  - 2025-06-21T01:18:19.1736913Z - Local connection to 198.50.223.16 on port 443.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by the user through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** 2025-06-18T01:33:39.971327Z
- **Event:** The user created a file named tor-shopping-list.txt on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** C:\Users\bucklabs\Desktop\tor-shopping-list.txt

---

## Summary

The user on the buckslab device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named tor-shopping-list.txt. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the shopping list file.

---

## Response Taken

TOR usage was confirmed on the endpoint buckslab by the user. The device was isolated, and the user's direct manager was notified.

---
