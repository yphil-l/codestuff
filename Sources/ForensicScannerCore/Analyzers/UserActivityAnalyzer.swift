import Foundation

public struct UserActivityAnalyzer: ArtifactAnalyzer {
    public let name = "User Activity Analyzer"
    public let category: ArtifactCategory = .userActivity
    public let feature: ScanFeature = .user

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        var findings: [Finding] = []
        for home in context.userHomes() {
            findings.append(contentsOf: inspectRecentItems(home: home))
            findings.append(contentsOf: inspectQuarantineDatabase(home: home))
        }
        findings.append(contentsOf: inspectTemporaryDirectories())
        return findings
    }

    private func inspectRecentItems(home: URL) -> [Finding] {
        let plist = home.appendingPathComponent("Library/Preferences/com.apple.recentitems.plist")
        guard let dictionary = PlistReader.dictionary(at: plist) else { return [] }
        var findings: [Finding] = []
        for (key, value) in dictionary {
            let entries: [[String: Any]]?
            if let array = value as? [[String: Any]] {
                entries = array
            } else if let dict = value as? [String: Any] {
                entries = (dict["RecentDocuments"] as? [[String: Any]]) ?? (dict["CustomListItems"] as? [[String: Any]])
            } else {
                entries = nil
            }
            guard let array = entries else { continue }
            for entry in array {
                if let url = entry["URL"] as? String, let severity = SuspicionRules.detectSeverity(in: url) {
                    findings.append(Finding(
                        category: category,
                        severity: severity,
                        description: "Suspicious recent item in \(key)",
                        location: plist.path,
                        context: ["url": url]
                    ))
                }
            }
        }
        return findings
    }

    private func inspectQuarantineDatabase(home: URL) -> [Finding] {
        let quarantineDB = home.appendingPathComponent("Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
        guard FileSystem.fileExists(quarantineDB) else { return [] }
        var findings: [Finding] = []
        if SQLiteInspector.isSupported {
            let rows = SQLiteInspector.fetchRows(databasePath: quarantineDB.path, query: "SELECT LSQuarantineDataURLString AS url, LSQuarantineOriginTitle AS source FROM LSQuarantineEvent")
            for row in rows {
                if let url = row.columns["url"], let severity = SuspicionRules.detectSeverity(in: url) {
                    findings.append(Finding(
                        category: category,
                        severity: severity,
                        description: "Suspicious quarantined download",
                        location: quarantineDB.path,
                        context: ["url": url, "source": row.columns["source"] ?? "unknown"]
                    ))
                }
            }
        } else if let data = try? Data(contentsOf: quarantineDB), let text = String(data: data, encoding: .utf8) {
            if let severity = SuspicionRules.detectSeverity(in: text) {
                findings.append(Finding(
                    category: category,
                    severity: severity,
                    description: "Potential suspicious quarantine entry",
                    location: quarantineDB.path,
                    context: [:]
                ))
            }
        }
        return findings
    }

    private func inspectTemporaryDirectories() -> [Finding] {
        let tmpDirs = ["/tmp", "/var/tmp", "/var/folders"]
        var findings: [Finding] = []
        for dir in tmpDirs {
            let url = URL(fileURLWithPath: dir, isDirectory: true)
            guard FileSystem.directoryExists(url) else { continue }
            let files = FileSystem.recentFiles(at: url, limit: 20)
            for file in files {
                let name = file.lastPathComponent
                if let severity = SuspicionRules.detectSeverity(in: name) {
                    findings.append(Finding(
                        category: .filesystem,
                        severity: severity,
                        description: "Suspicious temporary file",
                        location: file.path,
                        context: [:]
                    ))
                }
            }
        }
        return findings
    }
}
