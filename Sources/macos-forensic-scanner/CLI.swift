import Foundation
import ForensicScannerCore

final class CommandLineInterface {
    func run() {
        var arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.contains("--help") || arguments.contains("-h") {
            printHelp()
            return
        }
        if arguments.contains("--version") {
            print("macOS Forensic Scanner 1.0.0")
            return
        }
        var options = ScanOptions()
        var customFeatureSelection = false
        var filesystemRequested = false

        func enableFeature(_ feature: ScanFeature) {
            if !customFeatureSelection {
                options.features = []
                customFeatureSelection = true
            }
            options.features.insert(feature)
            if feature == .filesystem {
                filesystemRequested = true
            }
        }

        func requireValue(_ flag: String) -> String? {
            guard let value = arguments.popValue() else {
                fputs("Missing value for \(flag)\n", stderr)
                return nil
            }
            return value
        }

        while !arguments.isEmpty {
            let arg = arguments.removeFirst()
            switch arg {
            case "--all":
                options.enableAllFeatures()
                customFeatureSelection = false
            case "--preferences": enableFeature(.preferences)
            case "--logs": enableFeature(.logs)
            case "--trash": enableFeature(.trash)
            case "--processes": enableFeature(.processes)
            case "--launch": enableFeature(.launch)
            case "--browser": enableFeature(.browser)
            case "--history": enableFeature(.history)
            case "--persistence": enableFeature(.persistence)
            case "--user-activity": enableFeature(.user)
            case "--user":
                guard let value = requireValue("--user") else { return }
                options.targetUser = value
            case "--applications": enableFeature(.applications)
            case "--keychain": enableFeature(.keychain)
            case "--security": enableFeature(.security)
            case "--filesystem": enableFeature(.filesystem)
            case "--logs-only":
                options.features = [.logs]
                customFeatureSelection = true
            case "--critical-only":
                options.severityThreshold = .critical
            case "--high-and-above":
                options.severityThreshold = .high
            case "--severity":
                guard let level = requireValue("--severity") else { return }
                if let severity = Severity(rawValue: level.lowercased()) {
                    options.severityThreshold = severity
                } else {
                    fputs("Unknown severity level: \(level)\n", stderr)
                    return
                }
            case "--timeline":
                options.timeline = true
            case "--verbose":
                options.verbose = true
            case "--output":
                guard let output = requireValue("--output") else { return }
                options.outputPath = output
            case "--compare":
                guard let baseline = requireValue("--compare") else { return }
                options.compareBaselinePath = baseline
            case "--save-baseline":
                guard let destination = requireValue("--save-baseline") else { return }
                options.saveBaselinePath = destination
            case "--monitor":
                options.monitor = true
                options.realTime = true
                if options.monitorIterations == 1 {
                    options.monitorIterations = Int.max
                }
            case "--monitor-interval":
                guard let value = requireValue("--monitor-interval") else { return }
                guard let seconds = Double(value) else {
                    fputs("Invalid monitor interval: \(value)\n", stderr)
                    return
                }
                options.monitorInterval = seconds
            case "--monitor-iterations":
                guard let value = requireValue("--monitor-iterations") else { return }
                guard let count = Int(value) else {
                    fputs("Invalid monitor iteration count: \(value)\n", stderr)
                    return
                }
                options.monitorIterations = max(1, count)
            case "--path":
                guard let path = requireValue("--path") else { return }
                options.customPaths.append(path)
                options.features.insert(.filesystem)
                filesystemRequested = true
            case "--all-users":
                options.scanAllUsers = true
            default:
                if arg.hasPrefix("--") {
                    fputs("Unknown option: \(arg)\n", stderr)
                    return
                } else {
                    options.customPaths.append(arg)
                }
            }
        }

        if options.customPaths.isEmpty && options.features.contains(.filesystem) {
            if filesystemRequested {
                fputs("Custom path scan requires --path <value>. Skipping filesystem analyzer.\n", stderr)
            }
            options.features.remove(.filesystem)
        }

        if options.severityThreshold == nil && options.realTime {
            options.severityThreshold = .medium
        }

        runScan(with: options)
    }

    private func runScan(with options: ScanOptions) {
        let coordinator = ScanCoordinator()
        let reportBuilder = ReportBuilder()
        var iteration = 0
        repeat {
            iteration += 1
            let report = coordinator.performScan(options: options)
            let text = reportBuilder.makeTextReport(report: report, includeTimeline: options.timeline)
            print(text)
            if let output = options.outputPath {
                do {
                    try text.write(toFile: (output as NSString).expandingTildeInPath, atomically: true, encoding: .utf8)
                    print("Report written to \(output)")
                } catch {
                    fputs("Failed to write report: \(error)\n", stderr)
                }
            }
            if options.monitor {
                print("Monitoring iteration \(iteration). Next scan in \(Int(options.monitorInterval)) seconds. Press Ctrl+C to stop.")
                if iteration >= options.monitorIterations { break }
                Thread.sleep(forTimeInterval: options.monitorInterval)
            }
        } while options.monitor
    }

    private func printHelp() {
        let text = """
        macOS Forensic Scanner
        Usage: macos-forensic-scanner [options]

        General Options:
          --all                    Run all analyzers (default)
          --preferences            Scan user & system preferences
          --logs                   Analyze macOS logs
          --trash                  Inspect trash and deletions
          --processes              Inspect running processes
          --launch                 Parse LaunchAgents/Daemons
          --browser                Analyze browser/network artifacts
          --history                Review shell history and configs
          --persistence            Evaluate cron/kext/system persistence
          --user-activity          Analyze user recent items/quarantine
          --applications           Review installed applications
          --keychain               Inspect keychains and SSH configs
          --security               Review Gatekeeper/SIP/XProtect
          --filesystem             Scan custom paths (requires --path)
          --path <path>            Add custom path to scan (repeatable)
          --all-users              Scan artifacts for all users in /Users
          --user <name>            Focus on a specific username

        Reporting & Filtering:
          --critical-only          Show only critical findings
          --high-and-above         Show high+ severity findings
          --severity <level>       Set severity threshold (critical|high|medium|low|info)
          --timeline               Include chronological timeline
          --output <file>          Write report to file
          --compare <baseline>     Compare findings against a baseline report
          --save-baseline <file>   Save current run as a baseline JSON

        Monitoring:
          --monitor                Continuous monitoring loop
          --monitor-interval <s>   Interval between scans (default 60s)
          --monitor-iterations <n> Stop after N loops (default infinite)

        Misc:
          --verbose                Enable verbose logging
          --help                   Show this help message
          --version                Show version information
        """
        print(text)
    }
}

private extension Array where Element == String {
    mutating func popValue() -> String? {
        guard !isEmpty else { return nil }
        return removeFirst()
    }
}
