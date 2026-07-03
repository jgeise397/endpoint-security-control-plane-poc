# Drift Scenarios

These five scenarios are an arc, not a list: telemetry depth, posture drift, constrained remediation, cross-platform validation, and finally risk prioritization by endpoint persona and threat context.

## 1. Suspicious PowerShell Execution

Target: `win-user-01`

Purpose: Demonstrate that Sysmon and Wazuh preserve useful process telemetry when native PowerShell logging is comparatively thin.

Procedure:

```powershell
powershell.exe -NoProfile -EncodedCommand RwBlAHQALQBEAGEAdABlACAAfAAgAE8AdQB0AC0ARgBpAGwAZQAgAC0ARgBpAGwAZQBQAGEAdABoACAAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAbABhAGIALQBkAHIAaQBmAHQALQBwAG8AdwBlAHIAcwBoAGUAbABsAC4AdAB4AHQAIAAtAEUAbgBjAG8AZABpAG4AZwAgAEEAUwBDAEkASQA=
```

Decoded intent: `Get-Date` writes `C:\ProgramData\lab-drift-powershell.txt`.

Expected telemetry:

- Sysmon EID 1 records the process creation event with the full `powershell.exe -NoProfile -EncodedCommand` command line.
- Wazuh raises an alert from the Sysmon eventchannel.
- Default PowerShell logs are expected to be comparatively thin for this demo.

Remediation and re-validation: n/a. This is a detection-depth demo, not a policy drift remediation.

Cleanup:

```powershell
Remove-Item -Path 'C:\ProgramData\lab-drift-powershell.txt' -Force -ErrorAction SilentlyContinue
```

Evidence IDs: `E3.1a` Sysmon event, `E3.1b` Wazuh alert.

## 2. Local Admin Creation

Target: `win-dev-01`

Purpose: Show that durable local privilege drift is detected by Fleet policy and corroborated by Windows security telemetry.

Procedure:

Run from an elevated Command Prompt:

```cmd
set /p LABDRIFT_TEMP_PASSWORD=Temporary labdrift password:
net user labdrift "%LABDRIFT_TEMP_PASSWORD%" /add
net localgroup Administrators labdrift /add
set "LABDRIFT_TEMP_PASSWORD="
```

Expected telemetry:

- Fleet policy `Local Administrators group matches baseline` flips to fail on the next policy run.
- The first failing policy timestamp is the time-to-detect marker.
- Windows Security event 4732 corroborates that `labdrift` was added to Administrators.

Remediation and re-validation:

```cmd
net localgroup Administrators labdrift /delete
net user labdrift /delete
```

Re-run or wait for the next Fleet policy check. `Local Administrators group matches baseline` should return to pass.

Cleanup: Confirm `labdrift` no longer exists and no stale profile or home directory remains.

Evidence IDs: `E3.2`.

## 3. RDP Enabled on the Legacy Box

Target: `win-legacy-01`

Purpose: Exercise the legacy compensating-control story: RDP is useful, risky, and allowed only with an explicit exception record.

Procedure:

Run from an elevated Command Prompt:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes
```

Expected telemetry:

- Fleet policy `Remote Desktop is disabled` fails on `win-legacy-01`.
- The failure should be tied back to the legacy endpoint exception workflow, not treated as a generic Windows finding.

Remediation and re-validation:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
netsh advfirewall firewall set rule group="Remote Desktop" new enable=No
```

Re-run or wait for the next Fleet policy check. `Remote Desktop is disabled` should return to pass. The exception record remains the compensating-control reference: RDP is disabled by default, inbound access is constrained, and drift gets reviewed rather than waved through.

Cleanup: Confirm Remote Desktop is disabled in system settings and the firewall group is disabled.

Evidence IDs: `E3.3a` Fleet policy failure, `E3.3b` Arcane enrichment at Gate 3.

## 4. Weak SSH Configuration

Target: `ubuntu-dev-01`

Purpose: Prove Linux app-configuration drift is detected and can be reversed cleanly.

Procedure:

The two SSH policies parse the main `/etc/ssh/sshd_config`; the drop-in directory is outside this lab check's scope. Write the drift as active directives in the main file:

```bash
sudo cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.lab-backup
sudo sed -i '/^[[:space:]]*PermitRootLogin[[:space:]]/d; /^[[:space:]]*PasswordAuthentication[[:space:]]/d' /etc/ssh/sshd_config
printf '%s\n' 'PermitRootLogin yes' 'PasswordAuthentication yes' | sudo tee -a /etc/ssh/sshd_config
sudo sshd -t
sudo systemctl restart ssh
```

Expected telemetry:

- Fleet control `sshd_permit_root_login_no` fails through the policy `sshd PermitRootLogin is not enabled`.
- Fleet control `sshd_password_authentication_no` fails through the policy `sshd PasswordAuthentication is not enabled`.

Remediation and re-validation:

```bash
sudo sed -i '/^[[:space:]]*PermitRootLogin[[:space:]]/d; /^[[:space:]]*PasswordAuthentication[[:space:]]/d' /etc/ssh/sshd_config
printf '%s\n' 'PermitRootLogin no' 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config
sudo sshd -t
sudo systemctl restart ssh
```

Re-run or wait for the next Fleet policy check. Both SSH policies should return to pass.

Cleanup: Confirm `/etc/ssh/sshd_config` contains the restored `no` values, remove `/etc/ssh/sshd_config.lab-backup`, and confirm sshd accepted the restored configuration.

Evidence IDs: `E3.4` fail-to-pass pair.

## 5. Outdated Vulnerable Application

Targets: `win-dev-01` and `win-user-01`

Purpose: Install the same outdated application on two different personas so Gate 3 can show why identical software findings do not always carry identical priority.

Application: 7-Zip 21.07 x64, staged as `7z2107-x64.exe` from the lab software cache.

Procedure:

Run on both `win-dev-01` and `win-user-01` from an elevated PowerShell prompt:

```powershell
$Installer = 'C:\LabInstallers\7z2107-x64.exe'
Start-Process -FilePath $Installer -ArgumentList '/S' -Wait
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
  Where-Object { $_.DisplayName -like '7-Zip*' } |
  Select-Object DisplayName, DisplayVersion, InstallLocation
```

Expected telemetry:

- Software inventory shows 7-Zip 21.07 on both endpoints.
- The finding pair feeds `risk_model.py` at Gate 3.
- Persona differentiation does the work: `win-dev-01` has developer access and elevated exposure; `win-user-01` is a standard user endpoint with medium criticality and normal exposure.

Remediation and re-validation:

```powershell
Start-Process -FilePath "$env:ProgramFiles\7-Zip\Uninstall.exe" -ArgumentList '/S' -Wait
```

Re-run or wait for software inventory. The outdated 7-Zip finding should disappear on both endpoints, or be replaced by the approved current version if the remediation path is upgrade instead of uninstall.

Cleanup:

```powershell
Remove-Item -Path 'C:\LabInstallers\7z2107-x64.exe' -Force -ErrorAction SilentlyContinue
```

Evidence IDs: `E3.5a` and `E3.5b` at Gate 3.

## Results

Results get appended from real runs; do not fabricate outcome data in this procedure file.
