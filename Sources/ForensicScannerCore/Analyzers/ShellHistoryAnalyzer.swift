import Foundation

public struct ShellHistoryAnalyzer: ArtifactAnalyzer {
    public let name = "Shell History Analyzer"
    public let category: ArtifactCategory = .shellHistory
    public let feature: ScanFeature = .history

    private let historyRelativePaths = [
        ".bash_history",
        ".zsh_history",
        ".zhistory",
        ".bash_sessions",
        ".config/fish/fish_history",
        ".local/share/fish/fish_history"
    ]

    private let configFiles = [
        ".bashrc",
        ".bash_profile",
        ".zshrc",
        ".zprofile",
        ".profile"
    ]

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        var findings: [Finding] = []
        for home in context.userHomes() {
            for relative in historyRelativePaths {
                let url = home.appendingPathComponent(relative)
                guard FileSystem.fileExists(url, fileManager: context.fileManager) else { continue }
                let content = tail(url: url, limitBytes: 32_768)
                let commands = parseHistory(content: content)
                for command in commands where SuspicionRules.isSuspiciousCommand(command) {
                    let finding = Finding(
                        category: category,
                        severity: .medium,
                        description: "Suspicious shell command",
                        location: url.path,
                        context: ["command": command]
                    )
                    findings.append(finding)
                }
            }

            for relative in configFiles {
                let url = home.appendingPathComponent(relative)
                guard FileSystem.fileExists(url, fileManager: context.fileManager) else { continue }
                let content = tail(url: url, limitBytes: 32_768)
                if let severity = SuspicionRules.detectSeverity(in: content) {
                    let finding = Finding(
                        category: category,
                        severity: severity,
                        description: "Potential persistence in shell config \(relative)",
                        location: url.path,
                        context: ["excerpt": content.prefix(200).description]
                    )
                    findings.append(finding)
                }
            }
        }
        return findings
    }

    private func tail(url: URL, limitBytes: Int) -> String {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return "" }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        let offset = max(0, size - UInt64(limitBytes))
        try? handle.seek(toOffset: offset)
        let data = handle.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func parseHistory(content: String) -> [String] {
        return content
            .split(separator: "\n")
            .map { line -> String in
                if line.starts(with: ": ") {
                    if let range = line.firstIndex(of: ";") {
                        return String(line[line.index(after: range)..<line.endIndex])
                    }
                }
                return String(line)
            }
            .filter { !$0.isEmpty }
    }
}
