import Foundation

public struct ScanContext {
    public let options: ScanOptions
    public let fileManager: FileManager
    public let cache: ArtifactCache
    public let now: Date
    public let hostInfo: HostInfo
    public let logger: Logger
    public let baseline: Baseline?

    public init(
        options: ScanOptions,
        fileManager: FileManager = .default,
        cache: ArtifactCache = ArtifactCache(),
        now: Date = Date(),
        hostInfo: HostInfo = .collect(),
        logger: Logger = Logger(),
        baseline: Baseline? = nil
    ) {
        self.options = options
        self.fileManager = fileManager
        self.cache = cache
        self.now = now
        self.hostInfo = hostInfo
        self.logger = logger
        self.baseline = baseline
    }

    public func userHomes() -> [URL] {
        if options.scanAllUsers {
            let usersRoot = URL(fileURLWithPath: "/Users", isDirectory: true)
            guard let contents = try? fileManager.contentsOfDirectory(at: usersRoot, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else {
                return [primaryUserHome()]
            }
            return contents.filter { $0.hasDirectoryPath }
        }

        return [primaryUserHome()]
    }

    public func primaryUserHome() -> URL {
        if let targetUser = options.targetUser {
            return URL(fileURLWithPath: "/Users/\(targetUser)", isDirectory: true)
        }

        if let custom = ProcessInfo.processInfo.environment["HOME"] {
            return URL(fileURLWithPath: custom, isDirectory: true)
        }

        return URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
    }
}
