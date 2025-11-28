import Foundation
import Dispatch

public final class Logger {
    public enum Level: String {
        case info = "INFO"
        case warning = "WARN"
        case error = "ERROR"
        case debug = "DEBUG"
    }

    private let queue = DispatchQueue(label: "logger.queue", qos: .utility)
    public var isVerbose: Bool

    public init(verbose: Bool = false) {
        self.isVerbose = verbose
    }

    public func log(_ level: Level, _ message: String) {
        queue.async {
            #if DEBUG
            let shouldPrint = true
            #else
            let shouldPrint = level != .debug || self.isVerbose
            #endif
            guard shouldPrint else { return }
            print("[\(level.rawValue)] \(message)")
        }
    }

    public func info(_ message: String) { log(.info, message) }
    public func warn(_ message: String) { log(.warning, message) }
    public func error(_ message: String) { log(.error, message) }
    public func debug(_ message: String) {
        guard isVerbose else { return }
        log(.debug, message)
    }
}
