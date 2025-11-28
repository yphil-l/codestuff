import Foundation

public struct ProcessSnapshot {
    public let pid: Int32
    public let parentPid: Int32
    public let user: String
    public let elapsed: String
    public let command: String

    public init(pid: Int32, parentPid: Int32, user: String, elapsed: String, command: String) {
        self.pid = pid
        self.parentPid = parentPid
        self.user = user
        self.elapsed = elapsed
        self.command = command
    }
}

public struct NetworkConnection {
    public let process: String
    public let pid: Int32
    public let protocolName: String
    public let localAddress: String
    public let remoteAddress: String
    public let state: String
}

public enum ProcessInspector {
    public static func runningProcesses() -> [ProcessSnapshot] {
        guard let psPath = discoverCommand(["/bin/ps", "/usr/bin/ps"]) else { return [] }
        let result = CommandRunner.run(psPath, arguments: ["-axo", "pid=,ppid=,user=,etime=,command="])
        guard result.exitCode == 0 else { return [] }
        let lines = result.output.split(separator: "\n")
        return lines.compactMap { line -> ProcessSnapshot? in
            let components = line.split(maxSplits: 4, omittingEmptySubsequences: true) { $0 == " " || $0 == "\t" }
            guard components.count >= 5 else { return nil }
            guard let pid = Int32(String(components[0])),
                  let ppid = Int32(String(components[1])) else { return nil }
            let user = String(components[2])
            let elapsed = String(components[3])
            let command = String(components[4])
            return ProcessSnapshot(pid: pid, parentPid: ppid, user: user, elapsed: elapsed, command: command)
        }
    }

    public static func networkConnections() -> [NetworkConnection] {
        if let lsofPath = discoverCommand(["/usr/sbin/lsof", "/usr/bin/lsof", "/bin/lsof"]) {
            let result = CommandRunner.run(lsofPath, arguments: ["-nP", "-i"])
            guard result.exitCode == 0 else { return [] }
            let lines = result.output.split(separator: "\n")
            guard lines.count > 1 else { return [] }
            return lines.dropFirst().compactMap { line in
                let columns = line.split(maxSplits: 8, omittingEmptySubsequences: true) { $0 == " " || $0 == "\t" }
                guard columns.count >= 9 else { return nil }
                let process = String(columns[0])
                let pid = Int32(String(columns[1])) ?? -1
                let proto = String(columns[7])
                let addresses = String(columns[8])
                let parts = addresses.components(separatedBy: "->")
                let local = parts.first ?? ""
                let remote = parts.count > 1 ? parts[1] : ""
                let state = columns.count > 9 ? String(columns[9]) : ""
                return NetworkConnection(process: process, pid: pid, protocolName: proto, localAddress: local, remoteAddress: remote, state: state)
            }
        }
        if let netstatPath = discoverCommand(["/usr/sbin/netstat", "/usr/bin/netstat"]) {
            let result = CommandRunner.run(netstatPath, arguments: ["-anv"])
            guard result.exitCode == 0 else { return [] }
            return result.output.split(separator: "\n").compactMap { line -> NetworkConnection? in
                if !line.contains(".") || !line.contains(":") { return nil }
                let components = line.split(maxSplits: 5, omittingEmptySubsequences: true) { $0 == " " || $0 == "\t" }
                guard components.count >= 5 else { return nil }
                let proto = String(components[0])
                let local = String(components[3])
                let remote = String(components[4])
                return NetworkConnection(process: "netstat", pid: -1, protocolName: proto, localAddress: local, remoteAddress: remote, state: components.last.map(String.init) ?? "")
            }
        }
        return []
    }

    public static func loadedDylibs(for pid: Int32) -> [String] {
        guard let lsofPath = discoverCommand(["/usr/sbin/lsof", "/usr/bin/lsof", "/bin/lsof"]) else { return [] }
        let result = CommandRunner.run(lsofPath, arguments: ["-p", String(pid)])
        guard result.exitCode == 0 else { return [] }
        var dylibs: Set<String> = []
        for line in result.output.split(separator: "\n") {
            if line.contains(".dylib") {
                let parts = line.split(separator: " ", omittingEmptySubsequences: true)
                if let path = parts.last {
                    dylibs.insert(String(path))
                }
            }
        }
        return Array(dylibs)
    }

    private static func discoverCommand(_ candidates: [String]) -> String? {
        for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
            return path
        }
        return nil
    }
}
