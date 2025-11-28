import Foundation

public struct TrashAnalyzer: ArtifactAnalyzer {
    public let name = "Trash & File Removal Analyzer"
    public let category: ArtifactCategory = .trash
    public let feature: ScanFeature = .trash

    private let recencyThreshold: TimeInterval = 60 * 60 * 12 // 12 hours

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        var findings: [Finding] = []
        var trashDirectories: [URL] = []
        trashDirectories.append(contentsOf: context.userHomes().map { $0.appendingPathComponent(".Trash", isDirectory: true) })
        trashDirectories.append(URL(fileURLWithPath: "/.Trashes", isDirectory: true))
        for directory in trashDirectories where FileSystem.directoryExists(directory, fileManager: context.fileManager) {
            let items = FileSystem.enumerateFiles(at: directory, fileManager: context.fileManager, depthLimit: 1)
            for item in items where item.lastPathComponent != ".DS_Store" {
                guard let metadata = context.cache.metadata(for: item, fileManager: context.fileManager) else { continue }
                let recent = metadata.modificationDate.map { Date().timeIntervalSince($0) < recencyThreshold } ?? false
                let severity = SuspicionRules.detectSeverity(in: item.lastPathComponent, recencyBoost: recent) ?? (recent ? .medium : nil)
                if let severity = severity {
                    let finding = Finding(
                        category: category,
                        severity: severity,
                        description: "Suspicious deleted item \(item.lastPathComponent)",
                        location: item.path,
                        context: [
                            "size": ByteCountFormatter.string(fromByteCount: Int64(metadata.size), countStyle: .file),
                            "modified": format(date: metadata.modificationDate)
                        ]
                    )
                    findings.append(finding)
                }
            }
            // Detect secure empty trash by metadata churn
            if let metadata = context.cache.metadata(for: directory, fileManager: context.fileManager), metadata.size == 0,
               metadata.modificationDate.map({ Date().timeIntervalSince($0) < recencyThreshold }) ?? false {
                let finding = Finding(
                    category: category,
                    severity: .medium,
                    description: "Trash appears to have been emptied recently",
                    location: directory.path,
                    context: ["modified": format(date: metadata.modificationDate)]
                )
                findings.append(finding)
            }
        }

        // Inspect DS_Store artifacts
        for home in context.userHomes() {
            let library = home.appendingPathComponent("Library", isDirectory: true)
            findings.append(contentsOf: inspectDSStore(in: library, context: context))
        }
        return findings
    }

    private func inspectDSStore(in directory: URL, context: ScanContext) -> [Finding] {
        guard FileSystem.directoryExists(directory, fileManager: context.fileManager) else { return [] }
        let files = FileSystem.enumerateFiles(at: directory, fileManager: context.fileManager, depthLimit: 2)
        var findings: [Finding] = []
        for file in files where file.lastPathComponent == ".DS_Store" {
            guard let metadata = context.cache.metadata(for: file, fileManager: context.fileManager) else { continue }
            if let date = metadata.modificationDate, Date().timeIntervalSince(date) < recencyThreshold {
                let finding = Finding(
                    category: category,
                    severity: .low,
                    description: "Recently modified .DS_Store may indicate access activity",
                    location: file.path,
                    context: ["modified": format(date: metadata.modificationDate)]
                )
                findings.append(finding)
            }
        }
        return findings
    }

    private func format(date: Date?) -> String {
        guard let date else { return "unknown" }
        return ISO8601DateFormatter().string(from: date)
    }
}
