import Foundation

public struct KeychainAnalyzer: ArtifactAnalyzer {
    public let name = "Keychain & Credential Analyzer"
    public let category: ArtifactCategory = .keychain
    public let feature: ScanFeature = .keychain

    private let sshFiles = ["authorized_keys", "config", "known_hosts", "id_rsa", "id_ed25519"]

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        var findings: [Finding] = []
        for home in context.userHomes() {
            let keychainDir = home.appendingPathComponent("Library/Keychains", isDirectory: true)
            findings.append(contentsOf: inspectKeychains(in: keychainDir, context: context))
            findings.append(contentsOf: inspectSSH(home: home))
        }
        let systemKeychains = URL(fileURLWithPath: "/Library/Keychains", isDirectory: true)
        findings.append(contentsOf: inspectKeychains(in: systemKeychains, context: context))
        return findings
    }

    private func inspectKeychains(in directory: URL, context: ScanContext) -> [Finding] {
        guard FileSystem.directoryExists(directory, fileManager: context.fileManager) else { return [] }
        let files = FileSystem.enumerateFiles(at: directory, fileManager: context.fileManager, depthLimit: 1)
        var findings: [Finding] = []
        for file in files where file.pathExtension == "keychain" || file.pathExtension == "db" {
            guard let metadata = context.cache.metadata(for: file, fileManager: context.fileManager) else { continue }
            if let date = metadata.modificationDate, Date().timeIntervalSince(date) < 60 * 60 * 24 {
                findings.append(Finding(
                    category: category,
                    severity: .medium,
                    description: "Keychain modified recently: \(file.lastPathComponent)",
                    location: file.path,
                    context: ["modified": ISO8601DateFormatter().string(from: date)]
                ))
            }
            if let severity = SuspicionRules.detectSeverity(in: file.lastPathComponent) {
                findings.append(Finding(
                    category: category,
                    severity: severity,
                    description: "Suspicious keychain filename",
                    location: file.path,
                    context: [:]
                ))
            }
        }
        return findings
    }

    private func inspectSSH(home: URL) -> [Finding] {
        let sshDir = home.appendingPathComponent(".ssh", isDirectory: true)
        guard FileSystem.directoryExists(sshDir) else { return [] }
        var findings: [Finding] = []
        for name in sshFiles {
            let file = sshDir.appendingPathComponent(name)
            guard FileSystem.fileExists(file) else { continue }
            if let content = try? String(contentsOf: file), let severity = SuspicionRules.detectSeverity(in: content) {
                findings.append(Finding(
                    category: category,
                    severity: severity,
                    description: "Suspicious SSH artifact (\(name))",
                    location: file.path,
                    context: ["excerpt": content.prefix(200).description]
                ))
            }
        }
        return findings
    }
}
