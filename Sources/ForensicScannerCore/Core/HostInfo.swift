import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

public struct HostInfo: Codable {
    public let hostname: String
    public let user: String
    public let osVersion: String
    public let hardware: String
    public let locale: String
    public let timezone: String

    public init(hostname: String, user: String, osVersion: String, hardware: String, locale: String, timezone: String) {
        self.hostname = hostname
        self.user = user
        self.osVersion = osVersion
        self.hardware = hardware
        self.locale = locale
        self.timezone = timezone
    }

    public static func collect(fileManager: FileManager = .default) -> HostInfo {
        let processInfo = ProcessInfo.processInfo
        let user = HostInfo.resolveUserName(environment: processInfo.environment)
        let hostname = processInfo.hostName
        let osVersion = processInfo.operatingSystemVersionString
        let locale = Locale.current.identifier
        let timezone = TimeZone.current.identifier
        let hardware = HardwareInfoFetcher.detectHardware()
        return HostInfo(hostname: hostname, user: user, osVersion: osVersion, hardware: hardware, locale: locale, timezone: timezone)
    }

    private static func resolveUserName(environment: [String: String]) -> String {
        if let envUser = environment["USER"], !envUser.isEmpty {
            return envUser
        }
        #if canImport(Darwin)
        return NSUserName()
        #else
        guard let pwd = getpwuid(geteuid()), let cString = pwd.pointee.pw_name else {
            return "unknown"
        }
        return String(cString: cString)
        #endif
    }
}

private enum HardwareInfoFetcher {
    static func detectHardware() -> String {
        #if os(macOS)
        if let result = CommandRunner.runIfAvailable("/usr/sbin/sysctl", arguments: ["-n", "hw.model"]), result.exitCode == 0 {
            let trimmed = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                return trimmed
            }
        }
        #endif
        return "Unknown"
    }
}
