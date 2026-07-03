# ATT&CK Technique Mapping

| Lab scenario | Evidence | ATT&CK mapping | Why I mapped it there |
|---|---|---|---|
| 3.1 encoded PowerShell | Sysmon EID 1, Wazuh rule 92057 | T1059.001 PowerShell | Encoded command execution through `powershell.exe` is PowerShell execution, regardless of whether the command is toy-lab simple or production-grade ugly. |
| 3.2 local admin creation | Security 4732 | T1098 Account Manipulation / T1136.001 Local Account | 4732 proves local group membership changed; if the local account was created as part of the action, local account creation also applies. |
| 3.3 RDP enable on legacy | Legacy endpoint exposure | T1021.001 Remote Desktop Protocol | Enabling RDP on a constrained Windows host creates a lateral-movement path, which is the point that matters operationally. |
| 3.5 7-Zip 21.07 | CVE-2022-29072 on `win-user-01` and `win-dev-01` | T1068 Exploitation for Privilege Escalation, plus T1203 Exploitation for Client Execution | The primary behavior is local privilege escalation; the crafted archive interaction also fits client-side exploitation. |

These mappings are mine as the analyst, cross-checked against Arcane's read-only ATT&CK surface.
