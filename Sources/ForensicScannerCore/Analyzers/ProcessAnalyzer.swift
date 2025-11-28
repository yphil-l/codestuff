import Foundation

public struct ProcessAnalyzer: ArtifactAnalyzer {
    public let name = "Process & Memory Analyzer"
    public let category: ArtifactCategory = .processes
    public let feature: ScanFeature = .processes

    private let suspiciousNames = ["frida", "cheat", "inject", "spoof", "aimbot", "wallhack", "macro", "agent", "loader"]

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        var findings: [Finding] = []
        let processes = ProcessInspector.runningProcesses()
        for process in processes {
            if let severity = evaluate(process: process) {
                var info: [String: String] = [
                    "user": process.user,
                    "elapsed": process.elapsed
                ]
                let dylibs = ProcessInspector.loadedDylibs(for: process.pid)
                if !dylibs.isEmpty {
                    info["dylibs"] = dylibs.prefix(5).joined(separator: ", ")
                }
                if let binaryPath = binaryPath(from: process.command) {
                    info["binary"] = binaryPath
                    if let binarySeverity = inspectBinary(path: binaryPath) {
                        info["binaryIndicator"] = binarySeverity.1
                        findings.append(Finding(
                            category: category,
                            severity: max(severity, binarySeverity.0),
                            description: "Process \(process.command) flagged",
                            location: binaryPath,
                            context: info
                        ))
                        continue
                    }
                }
                findings.append(Finding(
                    category: category,
                    severity: severity,
                    description: "Suspicious process \(process.command)",
                    location: "/proc/\(process.pid)",
                    context: info
                ))
            }
        }

        let connections = ProcessInspector.networkConnections()
        for connection in connections where isSuspicious(connection: connection) {
            let finding = Finding(
                category: .network,
                severity: .medium,
                description: "Suspicious network connection by \(connection.process)",
                location: connection.localAddress,
                context: [
                    "remote": connection.remoteAddress,
                    "protocol": connection.protocolName,
                    "state": connection.state
                ]
            )
            findings.append(finding)
        }
        return findings
    }

    private func evaluate(process: ProcessSnapshot) -> Severity? {
        let lower = process.command.lowercased()
        if lower.contains("dyld_insert_libraries") || lower.contains("inject") {
            return .critical
        }
        if suspiciousNames.contains(where: { lower.contains($0) }) {
            return .high
        }
        if lower.contains("/tmp/") || lower.contains("/private/tmp") {
            return .high
        }
        if lower.contains("python") || lower.contains("ruby") {
            if lower.contains(" -c ") || lower.contains(" -e ") {
                return .medium
            }
        }
        if lower.contains("curl") || lower.contains("wget") {
            return .medium
        }
        if lower.contains("ssh") && lower.contains("-D") {
            return .medium
        }
        return nil
    }

    private func binaryPath(from command: String) -> String? {
        if command.hasPrefix("/") {
            let components = command.split(separator: " ")
            if let first = components.first {
                return String(first)
            }
        }
        return nil
    }

    private func inspectBinary(path: String) -> (Severity, String)? {
        let url = URL(fileURLWithPath: path)
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        let data = handle.readData(ofLength: 8192)
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        if let severity = SuspicionRules.detectSeverity(in: text) {
            return (severity, text.prefix(80).description)
        }
        return nil
    }

    private func isSuspicious(connection: NetworkConnection) -> Bool {
        let remote = connection.remoteAddress.lowercased()
        if remote.contains("localhost") || remote.contains("127.0.0.1") || remote.isEmpty {
            return false
        }
        if remote.contains(":80") || remote.contains(":443") {
            return false
        }
        if remote.contains(":1337") || remote.contains(":31337") {
            return true
        }
        return SuspicionRules.detectSeverity(in: connection.remoteAddress) != nil
    }
}
