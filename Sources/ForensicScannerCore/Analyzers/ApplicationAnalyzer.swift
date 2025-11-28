import Foundation

public struct ApplicationAnalyzer: ArtifactAnalyzer {
    public let name = "Application & Installation Analyzer"
    public let category: ArtifactCategory = .applications
    public let feature: ScanFeature = .applications

    private let applicationDirectories = [
        "/Applications",
        "/Applications/Utilities",
        "~/Applications",
        "/Library/Application Support"
    ]

    private let recentThreshold: TimeInterval = 60 * 60 * 24 * 3

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        var findings: [Finding] = []
        for path in applicationDirectories {
            let url = FileSystem.url(path)
            guard FileSystem.directoryExists(url, fileManager: context.fileManager) else { continue }
            let apps = FileSystem.enumerateFiles(at: url, fileManager: context.fileManager, depthLimit: 1)
            for app in apps where app.pathExtension == "app" {
                guard let metadata = context.cache.metadata(for: app, fileManager: context.fileManager) else { continue }
                let name = app.deletingPathExtension().lastPathComponent
                let recent = metadata.modificationDate.map { Date().timeIntervalSince($0) < recentThreshold } ?? false
                if let severity = SuspicionRules.detectSeverity(in: name) {
                    findings.append(Finding(
                        category: category,
                        severity: severity,
                        description: "Suspicious application installed: \(name)",
                        location: app.path,
                        context: ["modified": format(date: metadata.modificationDate)]
                    ))
                } else if recent {
                    findings.append(Finding(
                        category: category,
                        severity: .low,
                        description: "Recently installed/modified application: \(name)",
                        location: app.path,
                        context: ["modified": format(date: metadata.modificationDate)]
                    ))
                }
            }
        }
        findings.append(contentsOf: inspectReceipts())
        return findings
    }

    private func inspectReceipts() -> [Finding] {
        let receiptDirs = ["/Library/Receipts", "~/Library/Receipts"]
        var findings: [Finding] = []
        for dir in receiptDirs {
            let url = FileSystem.url(dir)
            guard FileSystem.directoryExists(url) else { continue }
            let files = FileSystem.enumerateFiles(at: url, depthLimit: 1)
            for file in files where file.pathExtension == "pkg" || file.pathExtension == "plist" {
                if let severity = SuspicionRules.detectSeverity(in: file.lastPathComponent) {
                    findings.append(Finding(
                        category: category,
                        severity: severity,
                        description: "Suspicious installer receipt",
                        location: file.path,
                        context: [:]
                    ))
                }
            }
        }
        return findings
    }

    private func format(date: Date?) -> String {
        guard let date else { return "unknown" }
        return ISO8601DateFormatter().string(from: date)
    }
}
