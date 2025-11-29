# Windows Forensic Scanner – Portable EXE

## 1. What This Does
The Windows Forensic Scanner is a self-contained Python 3.11+ tool that triages critical Windows artifacts in minutes, highlights persistence and anti-forensic behavior, and outputs neon-themed visual and machine-readable reports. It operates without external dependencies, is built for PyInstaller one-file packaging, and was designed for rapid onsite verification of cheating indicators, tampering, and stealth persistence on Windows 10/11 hosts.

## 2. Quick Start
1. **Install Python 3.11+** (standard library only is required).
2. **Clone / copy this repository** onto the target Windows system.
3. **Run elevated** (UAC prompt will appear if not already admin):
   ```powershell
   python -m portable_scanner
   ```
4. **Build standalone EXE (optional)**:
   ```powershell
   pyinstaller --noconfirm --onefile --windowed -n forensic_scanner portable_scanner/__main__.py
   ```
   The resulting `dist/forensic_scanner.exe` can be copied to USB media and executed without dependencies.

CLI-only mode (headless / scripted triage):
```powershell
python -m portable_scanner --nogui --lookback 6 --deep --export-dir C:\Evidence
```

Use the **COPY FINDINGS** button to push a severity-sorted summary into the clipboard for quick paste into case notes.

## 3. Artifact Categories
Each category below is selectable in the GUI sidebar and covered by an independent analyzer thread.

### 3.1 Event Logs
- **What**: Security, System, Application, Setup, PowerShell, and TaskScheduler logs queried via `Get-WinEvent`.
- **Why**: Detect clearing events (IDs 1102, 104), account manipulation (4720-4738), time tampering (4616), task registration (106), PowerShell abuse (4103/4104).
- **Interpretation**: CRITICAL when logs are cleared or EventLog service is stopped; HIGH for time changes or firewall manipulation; MEDIUM for suspicious PowerShell commands.

### 3.2 Registry (Persistence)
- **What**: Autoruns (Run/RunOnce HKLM/HKCU), Command Processor autoruns, Explorer policies, UserAssist, BAM, Prefetch parameters.
- **Why**: Registry-based persistence, hiding of UI elements, and traces of execution survive application deletion.
- **Interpretation**: HIGH when autoruns point to Temp/AppData paths or missing binaries; CRITICAL when Prefetch is disabled or policies block access to evidence locations.

### 3.3 Prefetch & Amcache
- **What**: Prefetch folder enumeration and Amcache hive parsing (mounted via temporary HKLM key).
- **Why**: Demonstrates actual execution history and binaries removed from disk.
- **Interpretation**: CRITICAL if Prefetch cache empty; HIGH when Amcache references executables missing on disk or located in user-writable folders.

### 3.4 USN Journal
- **What**: NTFS Operational events (IDs 142/98/2003/2045) to catch journal deletion, truncation, and mass deletes.
- **Why**: Journal clearing is a top-tier anti-forensic action and often paired with cheat cleanup.
- **Interpretation**: CRITICAL for Event 142 (journal deleted); HIGH for fsutil delete commands or truncations.

### 3.5 Task Scheduler
- **What**: XML definitions under `C:\Windows\System32\Tasks` inspected for encoded PowerShell, cleanup commands, or recent modifications.
- **Why**: Scheduled tasks are a common persistence & cleanup vector.
- **Interpretation**: HIGH when commands reference PowerShell `-EncodedCommand`, `clean`, `del`, or run from Temp; MEDIUM if the XML file changed inside the lookback window.

### 3.6 ActivitiesCache Timeline
- **What**: `%LOCALAPPDATA%\ConnectedDevicesPlatform\*\ActivitiesCache.db` (copied & queried via SQLite) for timeline reconstruction.
- **Why**: Ties together downloads, archives, and executables for narrative context.
- **Interpretation**: MEDIUM/HIGH when activity rows reference suspicious app IDs or cheat keywords during the session window.

### 3.7 Recent / Jump Lists
- **What**: `%APPDATA%\Microsoft\Windows\Recent\*.lnk` resolved via COM; metadata for Automatic Destinations.
- **Why**: Identifies recently accessed files, even when originals are deleted.
- **Interpretation**: MEDIUM when shortcuts point to Temp downloads or deleted executables; LOW when benign.

### 3.8 Recycle Bin
- **What**: `$Recycle.Bin\<SID>\$I*` metadata parsed to original path, deletion time, and size.
- **Why**: Captures last-minute cleanup attempts; correlates with USN deletions.
- **Interpretation**: HIGH for executable/script deletions minutes before review; MEDIUM otherwise.

### 3.9 Volume Shadow Copies (VSS)
- **What**: `vssadmin list shadows` parsing, detection of recent shadow copy manipulation.
- **Why**: Shadow copies retain sanitized evidence; recent creation or removal is notable.
- **Interpretation**: HIGH when a shadow copy is created/removed during lookback; LOW if none exist.

### 3.10 Alternate Data Streams (ADS)
- **What**: PowerShell `Get-ChildItem -Stream` across user & temp directories for ADS > 10 KB.
- **Why**: ADS hides payloads inside benign files.
- **Interpretation**: HIGH when ADS > 10 KB or matches cheat keywords; MEDIUM for smaller streams.

### 3.11 Process & Memory Snapshot
- **What**: `Get-CimInstance Win32_Process`, `Get-NetTCPConnection`, and module lists for suspicious processes.
- **Why**: Detects processes running from Temp/AppData, missing binaries, encoded PowerShell, unusual network fan-out, or injected modules.
- **Interpretation**: CRITICAL for obfuscated commands/injection, HIGH for missing-on-disk executables or remote Temp processes, MEDIUM for high-risk binaries with benign paths.

### 3.12 Encrypted Volumes
- **What**: `manage-bde -status` + `Get-BitLockerVolume` + process scan for VeraCrypt/TrueCrypt.
- **Why**: Encrypted containers obstruct evidence; detection informs escalation.
- **Interpretation**: CRITICAL if BitLocker volumes are locked or container processes run without disclosure; MEDIUM if protection is merely enabled.

### 3.13 Special Artifact Locations
- **What**: `%TEMP%`, `%LOCALAPPDATA%\Temp`, `%USERPROFILE%\Downloads`, `%USERPROFILE%\Desktop` recursion for recent executables, DLLs, scripts, archives.
- **Why**: Cheats and cleaners often reside in temp or user downloads.
- **Interpretation**: HIGH when suspicious filenames exist within lookback; LOW when clean.

### 3.14 Browser Activity
- **What**: Chrome `%LOCALAPPDATA%\Google\Chrome\User Data\*\History` and Firefox `%APPDATA%\Mozilla\Firefox\Profiles\*\places.sqlite`/`downloads.sqlite` copied for read-only SQLite queries.
- **Why**: Identifies suspicious browsing and downloads that coincide with the review window, even when artifacts are locked in-use.
- **Interpretation**: HIGH when URLs or filenames match cheat indicators inside the session; otherwise suppressed.

### 3.15 Windows Error Reporting
- **What**: `C:\Users\*\AppData\Local\Microsoft\Windows\WER\{ReportArchive,ReportQueue}` parsed for `Report.wer` crash metadata.
- **Why**: Cheat loaders and unsigned modules frequently crash under scrutiny, leaving canonical traces in WER buckets.
- **Interpretation**: HIGH when AppPath/module references cheat loaders or user-writable paths; MEDIUM when unsigned modules are involved.

### 3.16 DNS & Network Cache
- **What**: `ipconfig /displaydns` output plus `arp -a` neighbor cache parsed into structured entries.
- **Why**: Recent DNS lookups and peers reveal command-and-control staging hosts or evidence of cache flushing.
- **Interpretation**: HIGH for domains/IPs on the cheat/C2 list, MEDIUM for unexplained remote ARP peers, LOW when caches appear forcibly cleared.

## 4. Severity Guide

| Severity  | Meaning | Examples |
|-----------|---------|----------|
| **CRITICAL** | Immediate evidence of tampering or active cheat | Log clearing (1102/104), USN delete (142), locked BitLocker volume, Prefetch disabled |
| **HIGH** | Strong indicator of persistence or cleanup | Autorun from Temp, scheduled cleanup tasks, executable missing but Amcache entry present |
| **MEDIUM** | Supporting evidence needing correlation | Suspicious Recent link, PowerShell command history, unusual ADS |
| **LOW** | Contextual or baseline information | Normal logon event, absence of shadow copies |

## 5. Interpreting Findings

1. **Correlate timestamps** – the timeline view ties Event Logs, Prefetch, ActivitiesCache, and USN entries to reconstruct intent.
2. **Look for gaps** – Prefetch entries without UserAssist/BAM or vice versa suggest deliberate cleanup.
3. **Cross-reference artifacts** – e.g., Recycle Bin + USN + Recent link showing the same executable equals strong attribution.
4. **Beware false positives** – enterprise agents may run from `%ProgramData%` or `%LOCALAPPDATA%`; use the severity filter to focus on CRITICAL/HIGH first.

## 6. Command-Line Options
| Option | Description |
|--------|-------------|
| `--nogui` | Run full scan in headless mode (stdout + optional exports). |
| `--lookback <hours>` | Window for “recent” modifications (default 4). |
| `--deep` | Enables exhaustive recursion in temp/download folders. |
| `--categories <names>` | Subset of categories (use enum names, e.g., `EVENT_LOGS PREFETCH`). |
| `--export-dir <path>` | Folder for HTML/CSV/JSON/TXT outputs (CLI). |
| `--auto` | In GUI mode, immediately start scanning after launch. |

## 7. Known Limitations
- Requires Windows 10/11 with PowerShell and administrative rights for full coverage.
- ActivitiesCache.db may be locked when Timeline is active; the scanner copies the file but extremely busy systems may still block access.
- Alternate Data Stream enumeration is constrained to user/temp paths for performance; enable `--deep` for broader coverage.
- Live memory string carving is out-of-scope for a dependency-free tool; module path inspection is used instead.
- Headless mode still depends on PowerShell for event, ADS, and registry hive parsing.

## 8. Troubleshooting
| Issue | Resolution |
|-------|------------|
| **UAC prompt loops** | Launch from elevated PowerShell (`Start-Process python -Verb runAs`). |
| **“PowerShell not found”** | Ensure `%SystemRoot%\System32\WindowsPowerShell\v1.0` is on PATH. |
| **Access denied on registry or event logs** | Confirm the tool is running as administrator; some EDR tools block hive loading. |
| **Slow scans** | Disable deep scan, reduce lookback, or deselect heavy categories (ADS, Special Locations). |
| **PyInstaller antivirus flag** | Rebuild with `--uac-admin --clean` and sign the EXE when distributing. |

## 9. Forensic Notes for Analysts
- **Primary hot spots**: `C:\Windows\Prefetch`, `C:\Windows\AppCompat\Programs\Amcache.hve`, `$Extend\$UsnJrnl`, `%APPDATA%\Microsoft\Windows\Recent`, `$Recycle.Bin`, `%LOCALAPPDATA%\ConnectedDevicesPlatform`.
- **Registry triage map**:
  - Autoruns: `HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run*`
  - Command Processor: `HKLM/HKCU\Software\Microsoft\Command Processor\Autorun`
  - UserAssist: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
  - BAM: `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`
  - Prefetcher switch: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`
- **Common evasion patterns**:
  - Prefetch/Event/USN clearing before screenshares.
  - Executables renamed to innocuous extensions (watch for Prefetch entries referencing non-existent files).
  - ADS payloads (`file.png:hidden.exe`) surfaced via the ADS analyzer.
  - Cleanup scheduled tasks firing at logon/AnyDesk start.
  - Memory-only loaders indicated by processes running from `%TEMP%` with missing on-disk images.
- **Suggested live triage order**: EventLog service status → Prefetch/Amcache sanity → USN journal health → Autoruns/TaskCache → Temp/Downloads quick scan → Process snapshot/network ports → VSS presence.

## 10. Severity Interpretation Examples
- **CRITICAL**: Security log cleared (ID 1102) + USN journal deletion (ID 142) minutes before review; Prefetch folder empty; locked BitLocker volume with user refusal.
- **HIGH**: Autorun pointing to `%LOCALAPPDATA%\Temp\cheat.exe`; scheduled task with `PowerShell -EncodedCommand`; Recycle Bin entry for `injector.dll` deleted moments before scan.
- **MEDIUM**: Recent shortcut to `%USERPROFILE%\Downloads\mod.jar`; ADS of 12 KB attached to a PNG; Activity timeline showing archive→exe double-click flow.
- **LOW**: Normal logon events, lack of VSS snapshots, or benign downloads without execution evidence.

## 11. “Schnellüberblick” Cheat Sheet
- **Top files**: Prefetch (`C:\Windows\Prefetch`), Amcache, USN Journal, Event Logs, Registry hives, Task Scheduler XML, ActivitiesCache.db, Recent links, Recycle Bin, VSS, ADS.
- **Registry watch list**: `Run`, `RunOnce`, `TaskCache`, `UserAssist`, `BAM`, `ComDlg32`, `PrefetchParameters`, `Command Processor`, `UAC bypass keys` (`HKCU\Software\Classes\mscfile\shell\open\command`).
- **Common anti-forensic moves**: Spoofed extensions, ADS payloads, log/Prefetch clearing, randomized filenames, scheduled cleanup tasks, encrypted containers, ACL tampering.
- **Memory/process cues**: Paths to deleted files, encoded command lines, modules from Temp, multiple remote sockets, suspicious strings like `.jar`, `.dll`, `http://` in process info.

---
**Reminder:** Always capture findings (HTML/CSV/JSON/TXT) for chain-of-custody, and rerun with a read-only shadow copy if live artifacts appear wiped.
