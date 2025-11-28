# macOS Forensic Scanner

A Swift-based command-line forensic analysis framework for macOS that inspects preferences, logs, persistence mechanisms, browser artifacts, shell history, applications, credentials, and more. The scanner is tuned for anti-cheat investigations and highlights signs of tampering, evasion, and suspicious activity.

## Features
- Multi-threaded analyzer pipeline (preferences, logs, trash, processes, persistence, browser/network, user activity, applications, keychains, security posture, and custom paths)
- LaunchAgents/Daemons parsing with RunAtLoad/KeepAlive heuristics
- Unified log tailing with clearing/tampering detection
- Shell history parsing for destructive or evasive commands
- Browser history & quarantine analysis with SQLite parsing
- Process inspection with dylib listing and network connection analysis
- Cron/kext/system extension enumeration for persistence pathways
- Keychain & SSH artifact auditing
- Recent items, quarantine events, and temporary directories review
- Baseline comparison and delta reporting
- Rich text report with severity breakdown, recommendations, and optional timeline view
- Monitoring mode for repeated scans and real-time triage

## Building
```
swift build
```

## Usage
```
macos-forensic-scanner [options]
```

Common flags:

| Option | Description |
| --- | --- |
| `--all` | Run every analyzer (default) |
| `--preferences`, `--logs`, `--processes`, `--launch`, `--browser`, `--history`, `--persistence`, `--user-activity`, `--applications`, `--keychain`, `--security` | Enable target categories when building a custom scan set |
| `--user <name>` / `--all-users` | Focus the scan on a specific user or enumerate `/Users` |
| `--path <path>` | Add a custom directory/file to analyze (enables filesystem analyzer) |
| `--critical-only`, `--high-and-above`, `--severity <level>` | Filter findings by minimum severity |
| `--timeline` | Include a chronological timeline in the report |
| `--output <file>` | Write the report to disk |
| `--compare <baseline>` | Compare results against a prior baseline report |
| `--save-baseline <file>` | Persist the current run as a JSON baseline |
| `--monitor` | Continuous monitoring loop (combine with `--monitor-interval` / `--monitor-iterations`) |
| `--verbose` | Enable verbose logging |

Run `macos-forensic-scanner --help` for the complete flag reference.

## Baselines
To capture a baseline from a known-good system:
```
macos-forensic-scanner --output baseline.json --save-baseline baseline.json
```
Later runs can highlight deltas with:
```
macos-forensic-scanner --compare baseline.json
```

## Monitoring
Enable continuous monitoring with a custom interval and iteration cap:
```
macos-forensic-scanner --monitor --monitor-interval 120 --monitor-iterations 5
```
Press `Ctrl+C` to stop an indefinite monitoring loop.

## Tests
```
swift test
```
