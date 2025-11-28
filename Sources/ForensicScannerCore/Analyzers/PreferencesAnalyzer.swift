import Foundation

public struct PreferencesAnalyzer: ArtifactAnalyzer {
    public let name = "Preferences Analyzer"
    public let category: ArtifactCategory = .preferences
    public let feature: ScanFeature = .preferences

    private let recentThreshold: TimeInterval = 60 * 60 * 24 * 2 // 48 hours

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        var findings: [Finding] = []
        var directories: [URL] = []
        directories.append(contentsOf: context.userHomes().map { $0.appendingPathComponent("Library/Preferences", isDirectory: true) })
        directories.append(URL(fileURLWithPath: "/Library/Preferences", isDirectory: true))
        directories.append(URL(fileURLWithPath: "/private/etc", isDirectory: true))

        for directory in directories where FileSystem.directoryExists(directory, fileManager: context.fileManager) {
            let files = FileSystem.enumerateFiles(at: directory, fileManager: context.fileManager, depthLimit: 1)
            for file in files where file.pathExtension == "plist" {
                guard let metadata = context.cache.metadata(for: file, fileManager: context.fileManager) else { continue }
                let isRecent = metadata.modificationDate.map { context.now.timeIntervalSince($0) < recentThreshold } ?? false
                let plistTextSummary = summarize(plistAt: file)
                var severity: Severity?
                if let summary = plistTextSummary {
                    severity = SuspicionRules.detectSeverity(in: summary, recencyBoost: isRecent)
                }
                if severity == nil, isRecent {
                    severity = file.lastPathComponent.contains("com.apple") ? .medium : .low
                }
                if let severity = severity {
                    var contextInfo: [String: String] = [
                        "size": ByteCountFormatter.string(fromByteCount: Int64(metadata.size), countStyle: .file),
                        "modified": format(date: metadata.modificationDate)
                    ]
                    if let summary = plistTextSummary {
                        contextInfo["keys"] = summary.prefix(240).description
                    }
                    let finding = Finding(
                        category: category,
                        severity: severity,
                        description: "Suspicious preference change detected in \(file.lastPathComponent)",
                        location: file.path,
                        context: contextInfo
                    )
                    findings.append(finding)
                } else if isRecent && file.lastPathComponent.contains("com.apple.LaunchServices") {
                    let finding = Finding(
                        category: category,
                        severity: .medium,
                        description: "Recent modification to LaunchServices preferences",
                        location: file.path,
                        context: ["modified": format(date: metadata.modificationDate)]
                    )
                    findings.append(finding)
                }
            }
        }
        return findings
    }

    private func summarize(plistAt url: URL) -> String? {
        guard let plist = PlistReader.propertyList(at: url) else { return nil }
        if let dict = plist as? [String: Any] {
            let keys = dict.keys.joined(separator: ", ")
            return keys
        }
        if let array = plist as? [Any] {
            return "Items: \(array.count)"
        }
        return String(describing: plist)
    }

    private func format(date: Date?) -> String {
        guard let date else { return "unknown" }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }
}
