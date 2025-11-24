# Windows Forensic Scanner

A comprehensive C# (.NET 6+) Windows forensic scanner application with CLI and GUI interfaces for detecting cheating/evasion artifacts on Windows 10/11 (64-bit only). **Must run as Administrator.**

## Features

### Scan Depth Levels

- **Light**: Prefetch + Event Logs (clears only) + Run keys + quick memory scan
- **Medium**: Light + Amcache + USN Journal + Task Scheduler + BAM + UserAssist
- **Deep**: Medium + VSS inspection + ADS enumeration + full memory scan of game/system processes

### Severity Categories

Each finding is categorized into one of four severity levels:

- **Normal**: Expected system behavior
- **Slightly Sus**: Minor anomalies or single indicators
- **Very Sus**: Multiple correlated indicators or suspicious patterns
- **CHEAT**: Strong evidence of cheating/evasion

### Core Modules

1. **Admin Check & Elevation**: Check admin privileges; graceful error if not admin
2. **Registry Hive Parser**: Read System, Software, SAM, per-user hives with LastWrite time tracking
3. **Event Log Analyzer**: Check for Event IDs: 1102, 104, 4616, 3079, service stops
4. **Prefetch Parser**: Extract .pf files from C:\Windows\Prefetch\, parse execution metadata
5. **Amcache Parser**: Read C:\Windows\AppCompat\Programs\Amcache.hve for file execution history
6. **USN Journal Reader**: Read filesystem journal for DELETE events and suspicious activity spikes
7. **Task Scheduler Parser**: Parse C:\Windows\System32\Tasks\ XML files
8. **BAM & UserAssist Analyzer**: Check registry values, detect deletions or anomalies
9. **ADS Detector**: Enumerate Alternate Data Streams using dir /r equivalent
10. **VSS Enumerator**: List Volume Shadow Copies using vssadmin
11. **Process Memory Scanner**: Scan javaw.exe, explorer.exe, csrss.exe for injected code
12. **Run/RunOnce Analyzer**: Check HKCU/HKLM Run keys with LastWrite times
13. **Custom Artifact Detection**: Allow users to specify additional registry keys or file paths
14. **Report Generator**: Output to CLI (console) + optionally save timestamped report to file
15. **GUI Wrapper**: WinForms interface for interactive depth selection, progress display, color-coded results

## Requirements

- Windows 10 or Windows 11 (64-bit)
- .NET 6.0 Runtime
- Administrator privileges

## Building the Project

### Prerequisites

- .NET 6.0 SDK or later
- Visual Studio 2022 or later (recommended) or JetBrains Rider

### Build Steps

1. Open `ForensicScanner.sln` in Visual Studio or Rider
2. Select the Release configuration
3. Build the solution (Ctrl+Shift+B in Visual Studio)

Alternatively, from the command line:

```bash
dotnet build ForensicScanner.sln -c Release /p:Platform=x64
```

## Usage

### CLI (Command-Line Interface)

1. Run `ForensicScanner.Cli.exe` as Administrator
2. Select scan depth (1-3)
3. Optionally provide custom registry keys and file paths
4. Review scan results in console
5. Optionally save report to file

### GUI (Graphical User Interface)

#### Option 1: Launch GUI directly
```bash
ForensicScanner.Gui.exe
```

#### Option 2: Launch GUI from CLI
```bash
ForensicScanner.Cli.exe --gui
```

The GUI provides:
- Radio buttons for depth selection (Light/Medium/Deep)
- Text areas for custom registry keys and file paths
- Start/Cancel scan buttons
- Progress bar with status messages
- Color-coded results display (Gray/Orange/Magenta/Red)
- Save report to file functionality

## Output Format

Each finding includes:
- **Severity**: Normal, Slightly Sus, Very Sus, or CHEAT
- **Title**: Brief description of the finding
- **Explanation**: 1-2 sentence explanation of why it's suspicious
- **Artifact Path**: Direct link to registry key, file path, event ID, or process name
- **Category**: Module that generated the finding (e.g., "Prefetch", "Event Logs", "Memory")

## Example Report

```
===============================================================
Forensic Scanner Report
Generated at: 2024-01-15 14:30:22
Scan Depth: Deep
Duration: 00:02:15
Findings Summary: Normal: 45 | Slightly Sus: 12 | Very Sus: 3 | CHEAT: 1
===============================================================

[CHEAT] Findings (1)
------------------------------------------------------------
[CHEAT] USN Journal Disabled
  USN Journal is disabled. This is highly suspicious as it prevents tracking file operations.
  Artifact: C: USN Journal

[Very Sus] Findings (3)
------------------------------------------------------------
[Very Sus] Event ID 1102 detected in Security
  Security audit log was cleared. This may indicate tampering or evasion attempts.
  Artifact: Event Viewer > Security > Event ID 1102 at 2024-01-15 12:00:00

...
```

## Error Handling

The scanner gracefully handles:
- Missing registry hives
- Permission denied errors
- Inaccessible artifacts
- Missing files or directories

Errors are logged but do not stop the scan. Each module continues independently.

## Project Structure

```
ForensicScanner/
├── src/
│   ├── ForensicScanner.Core/           # Core library
│   │   ├── Admin/                      # Admin privilege checking
│   │   ├── Analyzers/                  # Forensic analysis modules
│   │   ├── Models/                     # Data models
│   │   ├── Scanning/                   # Scan orchestration
│   │   ├── Services/                   # Report generation
│   │   └── Utilities/                  # Helper functions
│   ├── ForensicScanner.Cli/            # Console application
│   └── ForensicScanner.Gui/            # WinForms GUI application
└── ForensicScanner.sln                 # Solution file
```

## Technical Details

### Windows API Usage

- **Registry**: Uses managed `Microsoft.Win32.Registry` APIs with P/Invoke for LastWriteTime
- **Event Logs**: Uses `System.Diagnostics.Eventing.Reader` namespace
- **Process Memory**: P/Invoke to `kernel32.dll` for OpenProcess, ReadProcessMemory
- **Command Execution**: Uses `System.Diagnostics.Process` for fsutil, vssadmin, dir /r

### Correlation Logic

The scanner correlates findings across multiple artifacts:
- Missing Prefetch + Event log clear + Time change = Very Sus
- USN Journal disabled + Shadow copies deleted = CHEAT
- Process module from Temp folder + suspicious memory strings = Very Sus

## Limitations

- Does not parse binary Prefetch files (checks metadata only)
- USN Journal reading uses fsutil (limited details)
- Memory scanning is basic pattern matching
- ADS detection uses dir /r (not native WinAPI)
- Amcache parsing checks file existence only (not full parsing)

## License

This is a forensic tool for educational and investigative purposes. Use responsibly and only on systems you own or have authorization to analyze.

## Support

For issues, questions, or contributions, please refer to the project documentation or contact the development team.
