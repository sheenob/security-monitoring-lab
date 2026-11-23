# Investigation – Account Discovery via `net user`

## 1. Overview

This investigation validates the detection of Windows account discovery activity using Wazuh, Sysmon, and MITRE ATT&CK.

The activity was intentionally generated on a Windows 11 endpoint to validate the SIEM detection pipeline.

## 2. Detection

| Field | Value |
|---|---|
| SIEM | Wazuh |
| Rule ID | 92031 |
| Rule | Discovery activity executed |
| MITRE ATT&CK | T1087 – Account Discovery |
| Sysmon Event ID | 1 – Process Create |
| Command | `net user` |
| Process | `net1.exe` |
| Parent Process | `net.exe` |
| Source | Windows Sysmon Operational log |

## 3. Investigation

The command `net user` was executed on the Windows endpoint.

Sysmon generated a Process Create event containing:

- `Image`: `C:\Windows\System32\net1.exe`
- `CommandLine`: `C:\WINDOWS\system32\net1.exe user`
- `ParentImage`: `C:\Windows\System32\net.exe`
- `IntegrityLevel`: `High`

The event was successfully collected by the Wazuh agent and forwarded to the Wazuh manager.

## 4. MITRE ATT&CK Mapping

**Tactic:** Discovery

**Technique:** T1087 – Account Discovery

The `net user` command can be used to enumerate local user accounts on a Windows system.

## 5. Assessment

The activity was intentionally generated for detection validation and is therefore considered **benign** in this investigation.

However, the same behavior could be relevant during a real security incident because attackers may use account discovery to identify valid users and privileged accounts.

## 6. Conclusion

The detection pipeline successfully identified the execution of `net user`.

The following components were validated:

Windows endpoint → Sysmon → Wazuh Agent → Wazuh Manager → Detection Rule → MITRE ATT&CK mapping.

This demonstrates the ability to collect Windows process telemetry, identify suspicious discovery behavior, and investigate the resulting SIEM alert.

## 7. Detection Validation

**Status:** Validated

**Result:** Detection triggered successfully

**False positive:** No – activity was intentionally generated for testing.

**Recommended next step:** Investigate additional Windows discovery techniques and evaluate detection tuning to distinguish legitimate administrative activity from potentially malicious behavior.
