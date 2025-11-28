import Foundation

public struct CustomPathAnalyzer: ArtifactAnalyzer {
    public let name = "Custom Path Analyzer"
    public let category: ArtifactCategory = .filesystem
    public let feature: ScanFeature = .filesystem

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        guard !context.options.customPaths.isEmpty else { return [] }
        var findings: [Finding] = []
        for path in context.options.customPaths {
            let expanded = FileSystem.url(path)
            if FileSystem.directoryExists(expanded, fileManager: context.fileManager) {
                let files = FileSystem.enumerateFiles(at: expanded, fileManager: context.fileManager, depthLimit: 3)
                for file in files {
                    findings.append(contentsOf: inspectFile(url: file))
                }
            } else if FileSystem.fileExists(expanded, fileManager: context.fileManager) {
                findings.append(contentsOf: inspectFile(url: expanded))
            }
        }
        return findings
    }

    private func inspectFile(url: URL) -> [Finding] {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }
        let data = handle.readData(ofLength: 65_536)
        var findings: [Finding] = []
        if let text = String(data: data, encoding: .utf8), let severity = SuspicionRules.detectSeverity(in: text) {
            findings.append(Finding(
                category: category,
                severity: severity,
                description: "Suspicious content in custom path",
                location: url.path,
                context: [:]
            ))
        } else if url.pathExtension == "plist", let dictionary = PlistReader.dictionary(at: url), let severity = SuspicionRules.detectSeverity(in: dictionary.description) {
            findings.append(Finding(
                category: category,
                severity: severity,
                description: "Suspicious plist in custom path",
                location: url.path,
                context: [:]
            ))
        }
        return findings
    }
}
