import Foundation

public struct SecurityPostureAnalyzer: ArtifactAnalyzer {
    public let name = "Security Posture Analyzer"
    public let category: ArtifactCategory = .security
    public let feature: ScanFeature = .security

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        #if os(macOS)
        var findings: [Finding] = []
        findings.append(contentsOf: inspectGatekeeper())
        findings.append(contentsOf: inspectSIP())
        findings.append(contentsOf: inspectXProtect())
        return findings
        #else
        return []
        #endif
    }

    private func inspectGatekeeper() -> [Finding] {
        guard let spctlPath = CommandRunner.which("spctl") else { return [] }
        let result = CommandRunner.run(spctlPath, arguments: ["--status"])
        guard result.exitCode == 0 else { return [] }
        let output = result.output.lowercased()
        if output.contains("disabled") {
            return [Finding(
                category: category,
                severity: .high,
                description: "Gatekeeper is disabled",
                location: "spctl --status",
                context: ["status": result.output.trimmingCharacters(in: .whitespacesAndNewlines)]
            )]
        }
        return []
    }

    private func inspectSIP() -> [Finding] {
        guard let csrutilPath = CommandRunner.which("csrutil") else { return [] }
        let result = CommandRunner.run(csrutilPath, arguments: ["status"])
        guard result.exitCode == 0 else { return [] }
        if result.output.lowercased().contains("disabled") {
            return [Finding(
                category: category,
                severity: .critical,
                description: "System Integrity Protection disabled",
                location: "csrutil status",
                context: ["status": result.output.trimmingCharacters(in: .whitespacesAndNewlines)]
            )]
        }
        return []
    }

    private func inspectXProtect() -> [Finding] {
        let xprotect = URL(fileURLWithPath: "/System/Library/CoreServices/XProtect.bundle")
        guard FileSystem.directoryExists(xprotect) else {
            return [Finding(
                category: category,
                severity: .high,
                description: "XProtect bundle missing",
                location: xprotect.path,
                context: [:]
            )]
        }
        guard let metadata = try? FileManager.default.attributesOfItem(atPath: xprotect.path), let date = metadata[.modificationDate] as? Date else { return [] }
        if Date().timeIntervalSince(date) > 60 * 60 * 24 * 30 {
            return [Finding(
                category: category,
                severity: .medium,
                description: "XProtect signatures appear outdated",
                location: xprotect.path,
                context: ["modified": ISO8601DateFormatter().string(from: date)]
            )]
        }
        return []
    }
}
