### System Coverage Summary

This summary outlines the critical Windows system areas explored during the project, explaining their cybersecurity relevance and highlighting key areas for potential future investigation.

---

#### **Core Areas Explored**

- **System32 Folder**  
  - **Status:** Explored  
  - **Why it matters:** Core system binaries live here, including tools like `cmd.exe` and `powershell.exe`, which are frequently abused by attackers for execution, lateral movement, or obfuscation.

- **Command-Line Interfaces (`cmd.exe`, `powershell.exe`)**  
  - **Status:** Explored  
  - **Why it matters:** Script-based attacks and fileless malware frequently use these tools to execute commands silently or escalate privileges.

  ### Clarification: Relationship Between `System32` and Command-Line Interfaces

During this project, we explored both the **System32 folder** and the **command-line tools** `cmd.exe` and `powershell.exe`. While these were discussed in two different sections, they are directly related:

- **`cmd.exe` and `powershell.exe` are stored in the System32 folder.**
  - The System32 directory contains essential Windows binaries, including the executables for both Command Prompt and PowerShell.
  **Essential Windows binaries** are low-level executable files (.exe, .dll, etc.) that provide core functionality for the operating system — such as system management, configuration, input/output operations, and user interface support. These are typically written in binary machine code and interpreted directly by the Windows OS kernel.
  - When we inspected their file properties earlier, we were viewing them as static files that reside in this core system directory.

- **In the "Command-Line Interfaces" section, we focused on their usage rather than their location.**
  - This part emphasized how attackers utilize these tools for:
    - Executing malicious scripts (fileless attacks)
    - Bypassing traditional antivirus
    - Escalating privileges or moving laterally across the network
  - This shows that while these tools are legitimate Windows components, their misuse is a well-known tactic in post-exploitation stages.

**In summary**, our analysis of `cmd.exe` and `powershell.exe` in both sections was complementary:
- First, identifying them as core binaries in System32.
- Then, understanding how they function as powerful interfaces that can be leveraged — or abused — within a live system.

This layered approach reinforces not only the structure of Windows but also the tactics attackers use to operate within it.




- **Registry Editor – `Run` Keys**  
  - **Status:** Explored  
  - **Why it matters:** A classic persistence mechanism; malware and legitimate software can configure automatic startup behavior via this location.
 
Run keys in the Windows Registry are a classic mechanism used to **configure programs to automatically start when a user logs in**. This is useful for legitimate software (like antivirus tools or update checkers), but it's also **frequently abused by attackers** to maintain persistence on a compromised system.

These keys are located at:
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`

**Why attackers use it:**  
- **Stealthy Persistence:** Allows malware to auto-launch at startup without user interaction.
- **Low-friction Access:** No special privileges are needed to add entries to the current user’s Run key.
- **Blends with Legitimate Behavior:** Since many legitimate apps also use this mechanism, malicious entries may go unnoticed.

**Security Relevance:**  
- Defenders routinely inspect Run keys during incident response and threat hunting.
- SIEM tools and EDR platforms often flag new or unexpected entries in these keys.
- Some malware variants even overwrite or remove existing Run key entries to disable security tools.
> Understanding this Registry location is crucial for spotting unauthorized startup behaviors and validating system integrity.


- **Task Scheduler**  
  - **Status:** Explored  
  - **Why it matters:** Scheduled tasks are often created to maintain persistence or launch payloads at specific times or on system events.
  
Task Scheduler is a built-in Windows utility that allows the operating system and applications to **schedule tasks**—such as launching programs, running scripts, or performing maintenance—based on triggers like time, login, idle state, or system startup.

**Used legitimately for:**  
- System maintenance (e.g., Windows Updates, disk cleanup)
- Software updates
- Automated security scans

**Why attackers use it:**  
- **Persistence:** Malicious tasks can be scheduled to run at boot or user login to re-establish presence after reboots.
- **Stealth:** Tasks can be configured to run silently in the background using legitimate Windows utilities like `powershell.exe` or `cmd.exe`.
- **Flexibility:** Attackers can use custom triggers (e.g., idle time, time-based scheduling) to avoid detection during normal usage hours.

**Common Techniques:**  
- Creating a task that launches malware under the guise of a legitimate filename.
- Modifying an existing task to point to a malicious binary.
- Hiding tasks under obscure or system-sounding names to avoid user suspicion.

**Security Relevance:**  
- **Threat hunters and incident responders** inspect the Task Scheduler for unusual task names, unfamiliar paths, or suspicious triggers.
- SIEMs and EDR platforms often alert on new scheduled tasks or modified ones—especially when they execute known living-off-the-land binaries (LOLBins) like `powershell.exe`.
- Windows logs task events under **Event ID 4698** (task created) and **Event ID 4702** (task updated), which are monitored by defenders.

> Understanding Task Scheduler is crucial for spotting persistence mechanisms, investigating silent task executions, and verifying that scheduled tasks align with legitimate administrative functions.


- **Windows Services (`services.msc`)**  
  - **Status:** Explored  
  - **Why it matters:** Attackers may disable defensive services (like antivirus), install malicious services, or exploit weak permissions.
  
Windows Services are long-running background processes that are crucial for the operating system's core functionality. These include networking, security, user login, system updates, and more. Services typically run with **elevated privileges**, making them powerful targets for attackers.

**Used legitimately for:**  
- Antivirus and firewall protection (e.g., Windows Defender services)  
- System event logging (e.g., Windows Event Log service)  
- Networking and remote access (e.g., Remote Desktop Services, DHCP Client)  
- Scheduled maintenance, updates, and telemetry reporting  

**Why attackers use or target services:**  
- **Persistence:** A malicious service can be created to auto-start on boot, keeping the attacker’s payload running indefinitely.  
- **Defense Evasion:** Attackers may **disable or modify legitimate services**, especially those related to antivirus, firewall, or telemetry, to avoid detection.  
- **Privilege Escalation:** Poorly secured services (e.g., misconfigured permissions or weak paths) can be hijacked or replaced to execute code with SYSTEM-level privileges.  
- **Masquerading:** Malicious services may use legitimate-looking names to blend in with real system processes.

**Common Techniques:**  
- Creating a new service using `sc.exe` or PowerShell that points to a malicious executable.  
- Modifying the **binary path** of an existing service to point to attacker-controlled code.  
- Exploiting **unquoted service paths** where spaces allow injection of rogue executables.  
- Disabling security services like **Windows Defender (SENSE, MPSSVC)** or **Event Log (eventlog)**.

**Security Relevance:**  
- Defenders review service configurations using tools like **Services.msc**, **PowerShell**, or **Autoruns**.  
- Investigators look for services that were **recently added**, **set to start automatically**, or have **binaries in suspicious locations**.  
- Windows logs service creation and changes under **Event ID 7045** (new service) and **Event ID 7036** (service state changes).

> Understanding Windows Services is critical for identifying malicious persistence, detecting disabled security controls, and validating system integrity in any post-compromise analysis.


- **Windows Event Viewer (System Logs)**  
  - **Status:** Explored  
  - **Why it matters:** Event logs are essential for forensics. They show evidence of login activity, service behavior, system errors, and potential attacker footprints.
 
**Windows Event Logs serve as the authoritative audit trail for system activity. They are the **primary source of forensic evidence** when investigating security incidents. Everything from service changes, driver issues, login attempts, to scheduled task execution is recorded here. Security professionals rely on these logs to understand what happened, when, and by whom.

### Expanded Definitions of Logged Activities in Windows Event Viewer

- **Service changes**:  
  Events that track when a Windows service is installed, started, stopped, or modified. These entries can help detect when an attacker disables defenses (e.g., antivirus) or installs a malicious service to maintain persistence.

- **Driver issues**:  
  Logs related to the loading or failure of system drivers—low-level software that communicates between the operating system and hardware. Driver errors can indicate system instability or potentially malicious kernel-level activity.

- **Login attempts**:  
  Recorded events that track successful and failed user logins. Failed logins (e.g., Event ID 4625) are especially important for identifying brute-force attempts, unauthorized access, or lateral movement.

- **Scheduled task execution**:  
  Events showing when a task in the Task Scheduler was triggered, whether by time, login, or system event. These entries are critical for detecting persistence mechanisms or timed malware payloads.


**Used legitimately for:**  
- Auditing **login activity**, both successful and failed  
- Tracking **service lifecycle events** (starts, stops, crashes)  
- Capturing **hardware and driver issues**  
- Recording **scheduled task executions**, application errors, and updates  
- Alerting for **system integrity violations** or unusual behavior

**Why attackers care about logs:**  
- **Log tampering or clearing** (Event ID 1102) may be used to hide evidence  
- **System log silence** or missing expected entries may itself be suspicious  
- Sophisticated attackers may manipulate or **inject false entries** to confuse defenders  
- Post-exploitation tools like **Mimikatz**, privilege escalation scripts, or malware often generate detectable log artifacts

**Important Log Sources:**  
- **System Log:** Kernel-level events, driver failures, power state transitions  
- **Security Log:** Authentication attempts, account lockouts, privilege use  
- **Application Log:** Crashes, errors from installed apps  
- **Windows Defender / Microsoft-Windows-Security-Auditing:** AV and threat-related events

**Common Security-Relevant Events:**  
- **4624:** Successful login  
- **4625:** Failed login attempt  
- **7045:** New service installed  
- **1102:** Event log cleared  
- **4697:** New scheduled task created  
- **4688:** New process creation (if auditing is enabled)

**Security Relevance:**  
- Logs are used during both **real-time detection** (e.g., SIEM correlation) and **post-incident investigation**  
- Analysts frequently pivot between events to trace activity timelines, identify attacker IPs, and correlate with other system changes  
- Many detection rules in tools like **Splunk**, **Elastic**, or **Microsoft Defender** are triggered by patterns in these logs

> Mastering the structure and content of Windows Event Logs is essential for incident detection, investigation, and response. Logs are one of the few immutable records defenders can rely on—unless attackers erase or manipulate them.


---

#### **Optional Areas for Future Exploration (Not Covered in This Project)**

- **AppData & User Profile Directories**  
  - Malware frequently drops payloads here due to user-level write permissions.

  ### AppData and User Profile Directories  
**Why It Matters:**  
The `AppData` folder and broader user profile directories (e.g., `C:\Users\<Username>\`) are high-value areas for attackers because they provide a writable space that is often overlooked by security tools and users alike. These locations are routinely used by legitimate applications to store configurations, cached files, session tokens, and runtime data — but this same flexibility makes them ideal for attacker operations.

- **Persistence without elevated privileges**:  
  Attackers can drop payloads, scripts, or even entire backdoors in user-specific folders without requiring administrative rights. These files can be set to run at startup using user-level registry run keys or scheduled tasks.

- **Evasion from system-wide defenses**:  
  Because antivirus and Endpoint Detection and Response (EDR) tools often focus more aggressively on system directories, malware hiding in `AppData` may evade detection, especially if it mimics the structure or naming of legitimate software.

- **User-specific targeting**:  
  Attackers may use these directories to store tools that activate only for certain users, enabling stealthy, role-specific surveillance or data collection — for example, targeting only accounts with access to sensitive files or VPN credentials.

- **Key locations**:  
  - `AppData\Roaming`: Commonly abused for persistence, especially because its contents sync with domain profiles in enterprise environments.  
  - `AppData\Local`: Often used for dropped binaries or temporary storage.  
  - `AppData\LocalLow`: A more restricted version used by some applications (like web browsers or Flash-based apps).

- **Investigation insight**:  
  Security analysts should routinely inspect these directories during incident response to locate hidden executables, suspicious folders, or scripts mimicking legitimate applications.


- **Security Audit Policy (`secpol.msc`)**  
  - Governs what is logged by the system. Understanding this is critical when configuring a forensic-ready system or evaluating log coverage.

  ### Security Audit Policy  
**Status:** Not explored  
**Why it matters:**  
Security audit policies govern what types of events are recorded in the Windows event logs, particularly within the Security log. These settings determine whether the system logs successful and failed logon attempts, object access (e.g., file or folder interactions), privilege use, system changes, and more.

Proper configuration of audit policies is foundational for forensic readiness. If logging is not enabled for specific event types, critical evidence may be lost during an investigation. For example, without auditing object access or privilege use, an attacker could read sensitive files or escalate privileges without leaving a trace.

Security teams rely on these policies to ensure visibility into suspicious or unauthorized activity, and to maintain compliance with regulatory frameworks (e.g., HIPAA, PCI-DSS). Misconfigured or overly permissive audit settings can hinder incident detection and delay response.

**Key Concepts:**
- **Audit Success**: Records successful actions (e.g., a user successfully logged in).
- **Audit Failure**: Records failed attempts (e.g., failed logins or privilege use).
- **Granular Control**: Admins can define which activities are audited under categories like logon events, object access, policy changes, and process tracking.

**Use Case:**  
Security Audit Policy settings should be reviewed and tailored to organizational needs. Overly broad settings may generate noise, while under-auditing risks losing evidence of attacker behavior.


- **Windows Defender Logs / Security Center Interface**  
  - Viewing how Defender logs alerts or actions can aid in threat detection or false positive evaluation.

  ### Windows Defender Logs (Security Center Interface)  
**Status:** Not explored  
**Why it matters:**  
**Windows Defender** is Microsoft’s built-in antivirus and antimalware solution included in modern versions of Windows. It provides real-time protection against threats such as viruses, spyware, ransomware, and other forms of malware. It integrates with the Windows Security Center to centralize visibility of threat detections, protection status, and alerts across various security features (e.g., firewall, device health, and SmartScreen).

Reviewing **Windows Defender logs** through the Security Center or associated event logs (e.g., `Microsoft-Windows-Windows Defender/Operational`) is crucial for understanding system-level threat responses. These logs reveal:
- What threats were detected
- When and where the threats occurred
- Whether remediation actions were successful
- If any real-time protection features were disabled or bypassed

This visibility is essential for:
- **Threat Detection:** Identifying real-world malware encounters, including file paths and affected users.
- **Incident Response:** Verifying whether a threat was mitigated or requires escalation.
- **False Positive Investigation:** Determining whether benign files or scripts were misclassified and blocked.
- **Auditing & Compliance:** Showing protection activity and system health over time.

**Use Case:**  
In security operations or incident response, analysts rely on Defender logs to validate endpoint activity and assess whether malware was neutralized or persisted. These logs also support the tuning of exclusions and real-time protection features to balance security and usability.


- **Temp Folders (`%TEMP%`)**  
  - Another common drop zone for temporary payloads or scripts used in staged attacks.

  ### Temp Folders  
**Status:** Not explored  
**Why it matters:**  
Temporary folders (such as `C:\Windows\Temp` and `%USERPROFILE%\AppData\Local\Temp`) are system-designated storage areas used to hold short-lived files generated by applications, installers, or system processes. These files may include setup data, extracted archives, cached installers, crash dumps, or application logs.

Because these folders are **writable by user-level processes** and typically excluded from strict access controls, they are frequently exploited by attackers during staged or fileless attacks. Common attacker uses include:
- **Dropping malicious payloads** that are executed later (e.g., malware stagers, initial scripts).
- **Extracting archive contents** (e.g., from phishing-delivered ZIP files or embedded executables).
- **Living off the land** by executing malicious scripts from temporary locations to evade detection.
- **Bypassing application controls** that ignore or allow execution from these directories.

Security teams monitor temp folder activity to catch:
- Suspicious script execution (`.vbs`, `.js`, `.ps1`, `.bat`) from temp paths.
- Unexpected binaries dropped by unusual parent processes.
- Indicators of tools like LOLBins (Living Off the Land Binaries) being launched from temporary storage.

**Use Case:**  
In threat hunting or incident response, correlating temp folder usage with known attack timelines helps determine staging behavior, privilege escalation attempts, or lateral movement. Behavioral detection rules often flag execution from temp folders as high-risk, particularly for script-based attacks.


---
