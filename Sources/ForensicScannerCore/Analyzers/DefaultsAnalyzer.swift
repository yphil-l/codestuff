import Foundation

public struct DefaultsAnalyzer: ArtifactAnalyzer {
    public let name = "Defaults Analyzer"
    public let category: ArtifactCategory = .defaults
    public let feature: ScanFeature = .preferences

    private let monitoredDomains = [
        "com.apple.LaunchServices",
        "com.apple.loginwindow",
        "com.apple.WindowServer",
        "com.apple.security",
        "com.apple.systempreferences",
        "com.apple.quarantine"
    ]

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        guard let defaultsPath = CommandRunner.which("defaults") else {
            context.logger.debug("defaults command not found")
            return []
        }
        var findings: [Finding] = []
        for domain in monitoredDomains {
            let result = CommandRunner.run(defaultsPath, arguments: ["read", domain])
            guard result.exitCode == 0 else { continue }
            let output = result.output
            if let severity = SuspicionRules.detectSeverity(in: output) ?? detectSecurityDeviations(text: output) {
                let finding = Finding(
                    category: category,
                    severity: severity,
                    description: "Suspicious defaults value in \(domain)",
                    location: "defaults read \(domain)",
                    context: ["value": output.trimmingCharacters(in: .whitespacesAndNewlines)]
                )
                findings.append(finding)
            }
        }
        return findings
    }

    private func detectSecurityDeviations(text: String) -> Severity? {
        let lowered = text.lowercased()
        if lowered.contains("disable") && lowered.contains("security") {
            return .high
        }
        if lowered.contains("allowunsigned") || lowered.contains("disablesystemintegrity") {
            return .critical
        }
        if lowered.contains("autologinuser") {
            return .medium
        }
        return nil
    }
}
