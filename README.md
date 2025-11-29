# Windows Forensic Scanner – Portable EXE

## 1. Overview
The portable Windows Forensic Scanner is a self-contained Python 3.11+ toolkit that inspects 20 high-signal artifact families in under five minutes. It highlights persistence, tampering, and anti-forensic moves, then delivers neon-themed HTML plus machine-readable CSV/JSON/TXT reports. The latest build introduces a correlation matrix that chains findings occurring within the same minute, a category-vs-time heatmap, and per-category severity tallies that surface in the CLI, GUI, and every export format.

Key traits:
- **20 artifact families** spanning event telemetry, registry-based persistence, filesystem residue, process/network memory, encrypted containers, and user-writable stash locations.
- **Correlation summary** that clusters findings per minute, exposes category heatmaps, and keeps the GUI/CLI timeline synchronized with exports.
- **PyInstaller-ready** one-file packaging for a USB-deployable `.exe` that carries its own neon GUI.
- **Graceful degradation** when administrative rights or PowerShell modules are missing (the scanner logs which analyzers fell back to reduced visibility).

## 2. Quick start (< 5 minute field triage)
1. **Install Python 3.11+** (the standard library is sufficient).
2. **Clone or copy** this repository to the target Windows host.
3. **Launch elevated** from an Administrator PowerShell:
   ```powershell
   python -m portable_scanner --nogui --lookback 2 --deep --export-dir C:\Evidence
   ```
   - `--nogui` avoids Tk startup, `--lookback 2` keeps the data window tight for faster scans, and `--deep` ensures the Special Locations analyzer sweeps the user profile once.
4. **Review CLI output** – findings stream first, followed by the correlation timeline and per-category severity tallies.
5. **Open the HTML report** in `C:\Evidence\forensic_report.html` for a color-coded dashboard with the heatmap and matrix embedded.

> **Tip:** For the fastest path, deselect heavy analyzers (ADS + Special Locations) in the GUI sidebar or omit them with `--categories` in CLI runs. Everything else generally concludes inside 5 minutes on commodity hardware.

## 3. Running the scanner
### GUI mode
```powershell
python -m portable_scanner
```
- The sidebar lists all artifact families; toggle sets to scope the run.
- The right-hand panel now includes a live **correlation stream** that updates in real time as the shared timeline detects chained artifacts.
- Use **COPY FINDINGS** to push a severity-sorted text summary to the clipboard, or **EXPORT REPORT** to write HTML/CSV/JSON/TXT bundles.

### CLI mode
```powershell
python -m portable_scanner --nogui --lookback 6 --deep --categories EVENT_LOGS PREFETCH USN
```
- CLI output lists each finding, then prints the correlation timeline and category severity tallies.
- Pair with `--export-dir <path>` to automatically persist all report formats.

### Administrative & graceful-degradation notes
- The scanner auto-checks elevation and relaunches itself with `runAs` when possible. Without admin, registry hive loading, shadow copy enumeration, ADS recursion, and some event log queries will downgrade and log the limitation.
- PowerShell must be accessible on `PATH`. If specific cmdlets are missing, the engine logs "limited" status per analyzer but continues with remaining categories.
- Deep filesystem recursion honors the `--lookback` window unless `--deep` is toggled, helping you trade fidelity for speed on the fly.

## 4. Building the unified portable `.exe`
1. From an elevated PowerShell prompt:
   ```powershell
   python -m pip install --upgrade pip
   pip install pyinstaller
   ```
2. Package the GUI/CLI hybrid into a single executable:
   ```powershell
   pyinstaller --noconfirm --onefile --windowed \
     --name forensic_scanner portable_scanner/__main__.py
   ```
3. The binary appears under `dist/forensic_scanner.exe`. Copy it to removable media.
4. (Optional) Sign the executable and add `--uac-admin` if you want PyInstaller to request elevation automatically when end users double-click the tool.

## 5. Reporting, correlation matrix & exports
- **HTML** reports now contain severity cards, the chronological timeline, the new correlation timeline, a category-vs-time heatmap, and per-category severity tallies.
- **CSV** append three extra sections (timeline clusters, heatmap matrix, severity tallies) beneath the raw findings.
- **JSON** includes a `correlation` object with serialised timeline buckets, heatmap counts, and severity distributions.
- **TXT / CLI output** prints an ASCII bar chart per severity plus the correlation timeline summary.
- The **GUI correlation pane** shares the same data structure, so analysts watching a live scan see the same chains that end up in exports.

Use the matrix to:
1. Spot **burst activity** (multiple categories firing within the same minute).
2. Confirm **coverage** (which categories contributed evidence during the lookback window).
3. Prioritise **severity triage** by comparing category tallies to your escalation matrix.

## 6. Severity grading guidance
| Severity | Meaning | Typical cues |
|----------|---------|--------------|
| **CRITICAL** | Active tampering or clear cheat deployment. | Security/Application log clears, USN 142 deletions, locked BitLocker volumes with no disclosure, Prefetch disabled, Command lines with encoded payloads. |
| **HIGH** | Strong persistence/cleanup signal that needs immediate escalation. | Autoruns from `%TEMP%`, scheduled cleanup tasks, missing-on-disk binaries referenced by Prefetch/Amcache, ADS payloads >10 KB, multiple remote sockets from high-risk processes. |
| **MEDIUM** | Supporting context that frames intent and timeline. | Recent links into suspicious downloads, ActivitiesCache rows referencing cheat keywords, alternate data streams with benign names, tasks modified inside lookback. |
| **LOW** | Baseline telemetry proving coverage. | Successful logons, presence/absence of shadow copies, clean process snapshots. |

Pair the severity label with the correlation timeline: CRITICAL+HIGH events within the same minute usually justify immediate containment.

## 7. Artifact coverage (20 categories)
| # | Artifact family | What we interrogate | Severity cues | Counter-bypass notes |
|---|-----------------|---------------------|---------------|----------------------|
| 1 | **Security Event Log** | IDs 1102/4624/4625/4720-4738 via `Get-WinEvent`. | CRITICAL when 1102 or EventLog service stopped; HIGH for bulk 4625 failures/time tampering. | Watch for EventLog service disabled or channels cleared — the scanner alerts when the service is down. |
| 2 | **System Event Log** | IDs 104/7034/7040/7045 + service mutations. | HIGH for new/modified services, CRITICAL for log clears. | Attackers sometimes disable the Windows Event Log service after tampering; use the CLI notice to validate. |
| 3 | **Application & Setup Logs** | Installer/USN-related events plus crash telemetry. | CRITICAL for USN delete (3079); MEDIUM for repeated crashes tied to cheat loaders. | If Application logging is quiet, align with Prefetch/Amcache — absence plus Prefetch empty indicates cleanup. |
| 4 | **Task Scheduler Operational Log** | IDs 106/129/140 on `Microsoft-Windows-TaskScheduler/Operational`. | HIGH for rapid task registration or encoded commands. | Clearing the operational log still leaves XML artifacts; cross-check row 12 below. |
| 5 | **PowerShell Operational Log** | IDs 4103-4106 with full script blocks. | HIGH when encoded/obfuscated commands trigger; MEDIUM for benign admin tooling. | If attackers disable the log, Prefetch/Amcache still record `powershell.exe` launches; correlation exposes the gap. |
| 6 | **Autorun Keys** | `HKLM/HKCU Run*`, `RunOnce`, and Command Processor `Autorun`. | HIGH when pointing to `%TEMP%` or missing binaries; CRITICAL for high-entropy names plus keyword hits. | Attackers try to strip file paths after execution; Amcache references help prove prior presence. |
| 7 | **Explorer Policies & Prefetch Parameters** | Policies hiding drives/UIs, `EnablePrefetcher` toggles. | CRITICAL when Prefetch disabled; HIGH when policies hide shell features. | Even if the registry value is deleted post-scan, USN/Prefetch gaps expose the tamper. |
| 8 | **Execution Activity (UserAssist & BAM)** | UserAssist ROT13 paths + BAM SID-scoped executions. | HIGH when keywords hit in decoded entries; MEDIUM for suspicious but known admin tools. | Clearing BAM requires SYSTEM; if both BAM and UserAssist are empty, look for Event Log clears in the same minute. |
| 9 | **Prefetch Cache** | `%SystemRoot%\Prefetch\*.pf` presence and recent hits. | CRITICAL when directory is empty/missing; MEDIUM when high-risk binaries show recent access. | Attackers delete Prefetch, but the scanner flags both emptiness and folder removal instantly. |
| 10 | **Amcache Hive** | Temporary HKLM mount to parse `Root\File` entries. | HIGH when Amcache references files missing on disk; MEDIUM for keyword hits on surviving binaries. | Hive load failures are logged; rerun as admin or copy the hive offline if EDR blocks access. |
| 11 | **USN Journal** | `Microsoft-Windows-Ntfs/Operational` IDs 142/98/2003/2045. | CRITICAL for journal deletion, HIGH for truncation or `fsutil deletejournal`. | Attackers may stop the NTFS log — correlate with Recycle Bin entries to show intent. |
| 12 | **Scheduled Task Definitions** | XML under `C:\Windows\System32\Tasks`. | HIGH when tasks reference encoded commands/user-writable binaries; MEDIUM for recent modifications. | Even if the Task Scheduler log is missing, the XML timestamps remain — compare with the correlation matrix. |
| 13 | **Activities Timeline** | `%LOCALAPPDATA%\ConnectedDevicesPlatform\*\ActivitiesCache.db`. | MEDIUM/HIGH when activity text references cheat archives/executables. | If the database is locked, the scanner copies it; anti-forensic truncation still leaves USN gaps. |
| 14 | **Recent & Jump Lists** | `%APPDATA%\Microsoft\Windows\Recent\*.lnk` resolved via COM. | MEDIUM for shortcuts into `%TEMP%`/Downloads; HIGH if pointing to deleted executables. | Clearing Recent Items requires extra manual steps — combine with Recycle Bin metadata to prove intent. |
| 15 | **Recycle Bin Metadata** | `$Recycle.Bin\<SID>\$I*` headers. | HIGH for executables/scripts deleted minutes before collection; MEDIUM for benign file types. | Attackers often forget to wipe both `$I` and `$R` pairs — the scanner parses metadata even if payloads gone. |
| 16 | **Volume Shadow Copies** | `vssadmin list shadows` parsing. | HIGH when copies created/removed within lookback; LOW if none exist. | If `vssadmin` is blocked, run the scanner from an elevated PowerShell — failures are logged in the report. |
| 17 | **Alternate Data Streams** | Recursive `Get-ChildItem -Stream` across user/temp folders. | HIGH for ADS larger than 10 KB or keyword hits. | ADS enumeration requires admin; without it, rely on Special Locations + Prefetch overlap to expose hidden payloads. |
| 18 | **Special Artifact Locations** | `%TEMP%`, `%LOCALAPPDATA%`, `%USERPROFILE%\Downloads/Desktop`. | HIGH when suspicious binaries exist within lookback; LOW when clean. | Deep mode widens recursion; if the folder was wiped, USN + Recent link correlations still highlight the removal. |
| 19 | **Process & Network Snapshot** | `Get-CimInstance Win32_Process` + `Get-NetTCPConnection` + module lists. | CRITICAL for encoded/obfuscated commands, HIGH for missing-on-disk executables, MEDIUM for high-risk binary fan-out. | If `Get-NetTCPConnection` is blocked, only the process heuristics run; exports call out the limitation. |
| 20 | **Encrypted Volume Indicators** | `manage-bde -status`, `Get-BitLockerVolume`, and VeraCrypt/TrueCrypt process sweeps. | CRITICAL when locked BitLocker volumes or container tools are running; MEDIUM when protection merely enabled. | Attackers may stop BitLocker services; correlate with process list + Event Logs to prove tampering. |

## 8. Counter-bypass & mitigation playbook
- **Correlation-first triage:** Use the new per-minute clusters to show juries exactly when a cheat archive was downloaded, executed, and deleted. Export CSV/JSON to feed SIEM cases or share with other responders.
- **Evidence continuity:** Even when Event Logs are cleared, Prefetch + Amcache + UserAssist often remain. The severity tallies show which categories still produced data, guiding re-collection (e.g., mount Volume Shadow Copies when live residue is gone).
- **Admin gaps:** If an analyzer reports "limited" access, rerun elevated or execute from a trusted live response account. Every limitation is written to the log view and the HTML report footer for defensibility.

## 9. Troubleshooting & tips
| Issue | Resolution |
|-------|------------|
| **UAC prompt loops** | Launch from an elevated PowerShell (`Start-Process python -Verb runAs`). |
| **PowerShell missing** | Ensure `%SystemRoot%\System32\WindowsPowerShell\v1.0` is on `PATH`; Windows 10/11 ship it by default. |
| **Registry/Event Log access denied** | Confirm admin rights; some EDRs block hive loading — copy the hive to `%TEMP%` and rerun that analyzer if needed. |
| **Slow scans** | Reduce `--lookback`, uncheck ADS/Special Locations, or run CLI mode for fewer GUI updates. |
| **PyInstaller antivirus alerts** | Rebuild on a clean host, sign the binary, and consider toggling `--clean` plus `--uac-admin`. |

---
**Reminder:** Always export findings (HTML/CSV/JSON/TXT) for chain-of-custody. Use the correlation matrix and severity tallies to brief stakeholders quickly, then dig into raw evidence with your preferred triage toolkit.
