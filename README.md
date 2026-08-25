Endpoint-Detection-Response-EDR-Lab-Threat-Detection-with-LimaCharlie
Hands-on EDR engineering lab using LimaCharlie and a Windows 11 VM. Features agent deployment, telemetry analysis of process creation events (NEW_PROCESS), and custom YAML D&amp;R rules mapped to MITRE ATT&amp;CK for Reconnaissance and Registry Persistence.

Technical Stack & Architecture
EDR Platform: LimaCharlie

Target Endpoint: Windows 11 Enterprise Virtual Machine (xdr)

Execution Environment: Windows PowerShell & Command Prompt (Admin)

Framework Mapping: MITRE ATT&CK (T1033 - Discovery: System Owner/User Discovery, T1547.001 - Persistence: Registry Run Keys)

Lab Implementation & Workflow
1. Sensor Deployment & Installation
Generated unique Installation Keys within the LimaCharlie platform interface.

Deployed the LimaCharlie Agent onto the Windows 11 host via PowerShell using administrative privileges.

Confirmed successful agent communication and real-time telemetry streaming to the cloud interface.

2. Telemetry Analysis & Event Inspection
Filtered endpoint event streams within the LimaCharlie Timeline tab to inspect process creation events (NEW_PROCESS).

Extracted and parsed JSON payloads for target process executions, evaluating keys such as FILE_PATH, COMMAND_LINE, HASH, and parent process details.

3. Detection & Response (D&R) Rule Construction
Rule 1: Reconnaissance Detection (win-recon-whoami)
Objective: Detect execution of system user discovery tools (MITRE ATT&CK T1033).

Target Event: NEW_PROCESS

Rule Logic:

YAML
# Detect Block
event: NEW_PROCESS
op: ends with
path: event/FILE_PATH
value: whoami.exe

# Response Block
- action: report
  name: Reconnaissance - whoami Executed
Rule 2: Command-Line Registry Persistence Detection (win-persistence-registry-run)
Objective: Detect command-line attempts to establish startup persistence via reg.exe (MITRE ATT&CK T1547.001).

Target Event: NEW_PROCESS

Rule Logic:

YAML
# Detect Block
event: NEW_PROCESS
op: and
rules:
  - op: ends with
    path: event/FILE_PATH
    value: reg.exe
    case sensitive: false
  - op: contains
    path: event/COMMAND_LINE
    value: \CurrentVersion\Run
    case sensitive: false

# Response Block
- action: report
  name: Persistence - Windows Registry Run Key Modified
Execution Verification & Results
Adversary Emulation: Executed discovery commands (whoami /all) and registry modifications (reg add HKCU\...\Run ...) on the Windows 11 VM.

Alert Verification: Confirmed immediate generation of real-time alert notifications within the LimaCharlie Detections tab.

Telemetry Validation: Verified accurate mapping between telemetry events (NEW_PROCESS) and D&R engine response triggers.

Key SOC Analyst Learnings
Process vs. Kernel Telemetry: Understood the trade-offs between raw kernel-level logging (REGISTRY_WRITE, process handle access) and high-fidelity command-line analysis (NEW_PROCESS inspection).

Rule Optimization: Mastered multi-condition logic (and operators, path definitions, case sensitivity handling) in YAML schemas to eliminate false positives and catch attack signatures cleanly.
