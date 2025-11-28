import Foundation

public struct CommandResult {
    public let output: String
    public let error: String
    public let exitCode: Int32
}

public enum CommandRunner {
    private static let fileManager = FileManager.default

    @discardableResult
    public static func run(_ launchPath: String, arguments: [String] = []) -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        do {
            try process.run()
        } catch {
            return CommandResult(output: "", error: error.localizedDescription, exitCode: -1)
        }
        process.waitUntilExit()
        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        let errorData = stderr.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        let err = String(data: errorData, encoding: .utf8) ?? ""
        return CommandResult(output: output, error: err, exitCode: process.terminationStatus)
    }

    public static func runShell(_ command: String) -> CommandResult {
        let shell = "/bin/bash"
        guard fileManager.isExecutableFile(atPath: shell) else {
            return CommandResult(output: "", error: "Shell not available", exitCode: -1)
        }
        return run(shell, arguments: ["-c", command])
    }

    public static func runIfAvailable(_ launchPath: String, arguments: [String] = []) -> CommandResult? {
        guard fileManager.isExecutableFile(atPath: launchPath) else {
            return nil
        }
        return run(launchPath, arguments: arguments)
    }

    public static func which(_ executable: String) -> String? {
        let candidates = ["/usr/bin/which", "/bin/which", "/usr/bin/env"]
        for candidate in candidates {
            if candidate.hasSuffix("env") {
                if fileManager.isExecutableFile(atPath: candidate) {
                    let result = run(candidate, arguments: ["which", executable])
                    if result.exitCode == 0 {
                        let trimmed = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
                        if !trimmed.isEmpty { return trimmed }
                    }
                }
                continue
            }
            guard fileManager.isExecutableFile(atPath: candidate) else { continue }
            let result = run(candidate, arguments: [executable])
            if result.exitCode == 0 {
                let trimmed = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty { return trimmed }
            }
        }
        return nil
    }
}
