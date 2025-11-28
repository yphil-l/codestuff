import Foundation
import Dispatch

public struct FileMetadata {
    public let path: String
    public let size: UInt64
    public let modificationDate: Date?
    public let creationDate: Date?

    public init(path: String, size: UInt64, modificationDate: Date?, creationDate: Date?) {
        self.path = path
        self.size = size
        self.modificationDate = modificationDate
        self.creationDate = creationDate
    }
}

public final class ArtifactCache {
    private var attributesCache: [String: FileMetadata] = [:]
    private let queue = DispatchQueue(label: "artifact.cache", attributes: .concurrent)

    public init() {}

    public func metadata(for url: URL, fileManager: FileManager = .default) -> FileMetadata? {
        let path = url.path
        if let cached = queue.sync(execute: { attributesCache[path] }) {
            return cached
        }
        guard let attributes = try? fileManager.attributesOfItem(atPath: path) else {
            return nil
        }
        let size = attributes[.size] as? UInt64 ?? 0
        let modificationDate = attributes[.modificationDate] as? Date
        let creationDate = attributes[.creationDate] as? Date
        let metadata = FileMetadata(path: path, size: size, modificationDate: modificationDate, creationDate: creationDate)
        queue.async(flags: .barrier) {
            self.attributesCache[path] = metadata
        }
        return metadata
    }
}
