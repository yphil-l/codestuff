import Foundation

public struct SystemPersistenceAnalyzer: ArtifactAnalyzer {
    public let name = "System Persistence Analyzer"
    public let category: ArtifactCategory = .persistence
    public let feature: ScanFeature = .persistence

    private let cronPaths = [
        "/var/spool/cron/tabs",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly"
    ]

    private let kextPaths = [
        "/Library/Extensions",
        "/System/Library/Extensions"
    ]

    private let systemExtensionDir = URL(fileURLWithPath: "/Library/SystemExtensions", isDirectory: true)

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        var findings: [Finding] = []
        findings.append(contentsOf: inspectCron(context: context))
        findings.append(contentsOf: inspectKexts(context: context))
        findings.append(contentsOf: inspectSystemExtensions(context: context))
        findings.append(contentsOf: inspectLoginHooks())
        return findings
    }

    private func inspectCron(context: ScanContext) -> [Finding] {
        var findings: [Finding] = []
        for path in cronPaths {
            let url = URL(fileURLWithPath: path, isDirectory: true)
            guard FileSystem.directoryExists(url, fileManager: context.fileManager) else { continue }
            let files = FileSystem.enumerateFiles(at: url, fileManager: context.fileManager, depthLimit: 1)
            for file in files {
                guard let content = try? String(contentsOf: file) else { continue }
                if let severity = SuspicionRules.detectSeverity(in: content) {
                    findings.append(Finding(
                        category: category,
                        severity: severity,
                        description: "Suspicious cron entry",
                        location: file.path,
                        context: ["entry": content.split(separator: "\n").first.map(String.init) ?? ""]
                    ))
                }
            }
        }
        if let crontabPath = CommandRunner.which("crontab") {
            let result = CommandRunner.run(crontabPath, arguments: ["-l"])
            if result.exitCode == 0 {
                for line in result.output.split(separator: "\n") {
                    let command = String(line)
                    if let severity = SuspicionRules.detectSeverity(in: command) {
                        findings.append(Finding(
                            category: category,
                            severity: severity,
                            description: "Suspicious user crontab entry",
                            location: "crontab",
                            context: ["entry": command]
                        ))
                    }
                }
            }
        }
        return findings
    }

    private func inspectKexts(context: ScanContext) -> [Finding] {
        var findings: [Finding] = []
        for path in kextPaths {
            let url = URL(fileURLWithPath: path, isDirectory: true)
            guard FileSystem.directoryExists(url, fileManager: context.fileManager) else { continue }
            let directories = FileSystem.enumerateFiles(at: url, fileManager: context.fileManager, depthLimit: 1)
            for dir in directories where dir.pathExtension == "kext" {
                let name = dir.lastPathComponent
                if !name.lowercased().contains("apple") {
                    findings.append(Finding(
                        category: category,
                        severity: .high,
                        description: "Third-party kernel extension detected",
                        location: dir.path,
                        context: [:]
                    ))
                }
            }
        }
        return findings
    }

    private func inspectSystemExtensions(context: ScanContext) -> [Finding] {
        guard FileSystem.directoryExists(systemExtensionDir, fileManager: context.fileManager) else { return [] }
        let contents = FileSystem.enumerateFiles(at: systemExtensionDir, fileManager: context.fileManager, depthLimit: 2)
        var findings: [Finding] = []
        for item in contents where item.pathExtension == "systemextension" || item.pathExtension == "appex" {
            let name = item.deletingPathExtension().lastPathComponent
            if SuspicionRules.detectSeverity(in: name) != nil {
                findings.append(Finding(
                    category: category,
                    severity: .medium,
                    description: "Suspicious system extension \(name)",
                    location: item.path,
                    context: [:]
                ))
            }
        }
        return findings
    }

    private func inspectLoginHooks() -> [Finding] {
        let loginWindowPlist = URL(fileURLWithPath: "/Library/Preferences/com.apple.loginwindow.plist")
        guard let dictionary = PlistReader.dictionary(at: loginWindowPlist) else { return [] }
        var findings: [Finding] = []
        for key in ["LoginHook", "LogoutHook"] {
            if let value = dictionary[key] as? String, !value.isEmpty {
                let severity: Severity = SuspicionRules.detectSeverity(in: value) ?? .medium
                findings.append(Finding(
                    category: category,
                    severity: severity,
                    description: "Login hook configured (\(key))",
                    location: loginWindowPlist.path,
                    context: ["script": value]
                ))
            }
        }
        return findings
    }
}
