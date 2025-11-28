import Foundation

public struct LogsAnalyzer: ArtifactAnalyzer {
    public let name = "Logs Analyzer"
    public let category: ArtifactCategory = .logs
    public let feature: ScanFeature = .logs

    private let logPaths: [String] = [
        "/var/log/system.log",
        "/var/log/secure.log",
        "/var/log/kernel.log",
        "/var/log/install.log",
        "/var/log/asl/log.tracer",
        "~/Library/Logs",
        "/Library/Logs",
        "/var/log/DiagnosticMessages",
        "/var/log/audit",
        "/var/audit",
        "/var/db/diagnostics"
    ]

    private let suspiciousLogIndicators = [
        "code signing",
        "denied",
        "sandbox",
        "entitlement",
        "injection",
        "segmentation fault",
        "tamper",
        "VPN",
        "proxy",
        "spawn",
        "Failed to load",
        "quarantine",
        "csrutil",
        "spctl",
        "authorization"
    ]

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        var findings: [Finding] = []
        for path in logPaths {
            let url = FileSystem.url(path)
            if FileSystem.directoryExists(url, fileManager: context.fileManager) {
                let files = FileSystem.recentFiles(at: url, fileManager: context.fileManager)
                for file in files where file.pathExtension == "log" || file.lastPathComponent.contains("log") {
                    findings.append(contentsOf: inspectLog(file: file, context: context))
                }
            } else if FileSystem.fileExists(url, fileManager: context.fileManager) {
                findings.append(contentsOf: inspectLog(file: url, context: context))
            }
        }
        return findings
    }

    private func inspectLog(file: URL, context: ScanContext) -> [Finding] {
        guard let metadata = context.cache.metadata(for: file, fileManager: context.fileManager) else { return [] }
        var results: [Finding] = []
        let tail = tailContent(file: file, bytes: 16384)
        for indicator in suspiciousLogIndicators {
            if tail.range(of: indicator, options: .caseInsensitive) != nil {
                let finding = Finding(
                    category: category,
                    severity: .medium,
                    description: "Suspicious log entry containing \(indicator)",
                    location: file.path,
                    context: [
                        "indicator": indicator,
                        "excerpt": snippet(from: tail, matching: indicator)
                    ]
                )
                results.append(finding)
            }
        }
        if metadata.size < 1024 && (metadata.modificationDate.map { Date().timeIntervalSince($0) < 3600 } ?? false) {
            let finding = Finding(
                category: category,
                severity: .high,
                description: "Potential log clearing detected",
                location: file.path,
                context: [
                    "modified": format(date: metadata.modificationDate),
                    "size": "\(metadata.size)"
                ]
            )
            results.append(finding)
        }
        return results
    }

    private func tailContent(file: URL, bytes: Int) -> String {
        guard let handle = try? FileHandle(forReadingFrom: file) else { return "" }
        defer { try? handle.close() }
        let fileSize = (try? handle.seekToEnd()) ?? 0
        let offset = max(0, fileSize - UInt64(bytes))
        try? handle.seek(toOffset: offset)
        let data = handle.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func snippet(from text: String, matching indicator: String) -> String {
        guard let range = text.range(of: indicator, options: .caseInsensitive) else { return "" }
        let start = text.index(range.lowerBound, offsetBy: -min(40, text.distance(from: text.startIndex, to: range.lowerBound)), limitedBy: text.startIndex) ?? text.startIndex
        let end = text.index(range.upperBound, offsetBy: min(40, text.distance(from: range.upperBound, to: text.endIndex)), limitedBy: text.endIndex) ?? text.endIndex
        return String(text[start..<end])
    }

    private func format(date: Date?) -> String {
        guard let date else { return "unknown" }
        return ISO8601DateFormatter().string(from: date)
    }
}
