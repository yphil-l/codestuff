import Foundation

public enum FileSystem {
    public static func expandPath(_ path: String) -> String {
        (path as NSString).expandingTildeInPath
    }

    public static func url(_ path: String) -> URL {
        URL(fileURLWithPath: expandPath(path))
    }

    public static func directoryExists(_ url: URL, fileManager: FileManager = .default) -> Bool {
        var isDirectory: ObjCBool = false
        return fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory) && isDirectory.boolValue
    }

    public static func fileExists(_ url: URL, fileManager: FileManager = .default) -> Bool {
        fileManager.fileExists(atPath: url.path)
    }

    public static func enumerateFiles(
        at directory: URL,
        fileManager: FileManager = .default,
        includingProperties: [URLResourceKey]? = [.isRegularFileKey],
        depthLimit: Int = 3
    ) -> [URL] {
        guard directoryExists(directory, fileManager: fileManager) else { return [] }
        guard let enumerator = fileManager.enumerator(
            at: directory,
            includingPropertiesForKeys: includingProperties,
            options: [.skipsHiddenFiles],
            errorHandler: nil
        ) else { return [] }
        var results: [URL] = []
        for case let url as URL in enumerator {
            let level = (url.pathComponents.count - directory.pathComponents.count)
            if level > depthLimit {
                enumerator.skipDescendents()
                continue
            }
            results.append(url)
        }
        return results
    }

    public static func recentFiles(at directory: URL, limit: Int = 50, fileManager: FileManager = .default) -> [URL] {
        let files = enumerateFiles(at: directory, fileManager: fileManager, depthLimit: 1)
        return files.sorted { lhs, rhs in
            let lhsDate = (try? lhs.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            let rhsDate = (try? rhs.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            return lhsDate > rhsDate
        }.prefix(limit).map { $0 }
    }
}
