import Foundation

public struct LaunchItemAnalyzer: ArtifactAnalyzer {
    public let name = "Launch Agent & Daemon Analyzer"
    public let category: ArtifactCategory = .launchItems
    public let feature: ScanFeature = .launch

    private let directories: [String] = [
        "~/Library/LaunchAgents",
        "~/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/System/Library/LaunchDaemons"
    ]

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        var findings: [Finding] = []
        for path in directories {
            let expanded = FileSystem.url(path)
            guard FileSystem.directoryExists(expanded, fileManager: context.fileManager) else { continue }
            let files = FileSystem.enumerateFiles(at: expanded, fileManager: context.fileManager, depthLimit: 1)
            for plist in files where plist.pathExtension == "plist" {
                guard let dictionary = PlistReader.dictionary(at: plist) else { continue }
                if let finding = evaluate(dictionary: dictionary, path: plist.path, context: context) {
                    findings.append(finding)
                }
            }
        }
        return findings
    }

    private func evaluate(dictionary: [String: Any], path: String, context: ScanContext) -> Finding? {
        var program: String?
        if let value = dictionary["Program"] as? String {
            program = value
        } else if let args = dictionary["ProgramArguments"] as? [String], let first = args.first {
            program = first
        }
        guard let resolvedProgram = program else { return nil }
        let runAtLoad = dictionary["RunAtLoad"] as? Bool ?? false
        let keepAlive = dictionary["KeepAlive"] as? Bool ?? false
        let startInterval = dictionary["StartInterval"] as? Int
        let calendar = dictionary["StartCalendarInterval"] as? [String: Any]
        let sockets = dictionary["Sockets"]
        let watchPaths = dictionary["WatchPaths"] as? [String]
        let queueDirectories = dictionary["QueueDirectories"] as? [String]
        let severity = calculateSeverity(program: resolvedProgram, runAtLoad: runAtLoad, keepAlive: keepAlive, startInterval: startInterval, sockets: sockets)
        guard let determinedSeverity = severity else {
            if (watchPaths?.contains { SuspicionRules.detectSeverity(in: $0) != nil } ?? false) || (queueDirectories?.contains { SuspicionRules.detectSeverity(in: $0) != nil } ?? false) {
                return Finding(
                    category: category,
                    severity: .medium,
                    description: "Launch item monitoring sensitive paths",
                    location: path,
                    context: ["Program": resolvedProgram]
                )
            }
            return nil
        }
        var contextInfo: [String: String] = ["Program": resolvedProgram]
        if runAtLoad { contextInfo["RunAtLoad"] = "true" }
        if keepAlive { contextInfo["KeepAlive"] = "true" }
        if let startInterval { contextInfo["StartInterval"] = "\(startInterval)" }
        if let calendar {
            contextInfo["Schedule"] = calendar.description
        }
        if sockets != nil {
            contextInfo["Sockets"] = "configured"
        }
        if let watchPaths, !watchPaths.isEmpty {
            contextInfo["WatchPaths"] = watchPaths.joined(separator: ", ")
        }
        return Finding(
            category: category,
            severity: determinedSeverity,
            description: "Suspicious launch item persistence",
            location: path,
            context: contextInfo
        )
    }

    private func calculateSeverity(program: String, runAtLoad: Bool, keepAlive: Bool, startInterval: Int?, sockets: Any?) -> Severity? {
        let lowerProgram = program.lowercased()
        if lowerProgram.contains("/tmp/") || lowerProgram.contains("/Users/Shared/") || lowerProgram.contains(".sh") {
            return .high
        }
        if SuspicionRules.detectSeverity(in: program) != nil {
            return .high
        }
        if runAtLoad && keepAlive {
            return .medium
        }
        if sockets != nil || startInterval != nil {
            return .medium
        }
        return nil
    }
}
