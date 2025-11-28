import Foundation

public struct BrowserAnalyzer: ArtifactAnalyzer {
    public let name = "Browser & Network Analyzer"
    public let category: ArtifactCategory = .browser
    public let feature: ScanFeature = .browser

    private let suspiciousKeywords = ["cheat", "aimbot", "spoof", "macro", "bypass", "inject", "crack", "loader", "hack", "keygen", "vpn"]

    public init() {}

    public func analyze(context: ScanContext) -> [Finding] {
        var findings: [Finding] = []
        for home in context.userHomes() {
            findings.append(contentsOf: inspectSafari(home: home))
            findings.append(contentsOf: inspectChrome(home: home))
            findings.append(contentsOf: inspectFirefox(home: home))
        }
        findings.append(contentsOf: inspectNetworkPreferences())
        return findings
    }

    private func inspectSafari(home: URL) -> [Finding] {
        var findings: [Finding] = []
        let historyPath = home.appendingPathComponent("Library/Safari/History.db")
        findings.append(contentsOf: analyzeSQLiteHistory(path: historyPath, label: "Safari History"))
        let downloadsPlist = home.appendingPathComponent("Library/Safari/Downloads.plist")
        if let dictionary = PlistReader.dictionary(at: downloadsPlist) {
            let flattened = dictionary.description
            if let severity = SuspicionRules.detectSeverity(in: flattened) {
                findings.append(Finding(
                    category: category,
                    severity: severity,
                    description: "Suspicious Safari download entry",
                    location: downloadsPlist.path,
                    context: ["details": flattened.prefix(180).description]
                ))
            }
        }
        return findings
    }

    private func inspectChrome(home: URL) -> [Finding] {
        var findings: [Finding] = []
        let chromeSupport = home.appendingPathComponent("Library/Application Support/Google/Chrome")
        let altChrome = home.appendingPathComponent(".config/google-chrome")
        for dir in [chromeSupport, altChrome] where FileSystem.directoryExists(dir) {
            let historyFiles = FileSystem.enumerateFiles(at: dir, depthLimit: 2).filter { $0.lastPathComponent == "History" }
            for history in historyFiles {
                findings.append(contentsOf: analyzeSQLiteHistory(path: history, label: "Chrome History"))
            }
            let preferenceFiles = FileSystem.enumerateFiles(at: dir, depthLimit: 2).filter { $0.lastPathComponent == "Preferences" }
            for pref in preferenceFiles {
                if let data = try? Data(contentsOf: pref), let text = String(data: data, encoding: .utf8), let severity = SuspicionRules.detectSeverity(in: text) {
                    findings.append(Finding(
                        category: category,
                        severity: severity,
                        description: "Suspicious Chrome preference entry",
                        location: pref.path,
                        context: ["excerpt": text.prefix(200).description]
                    ))
                }
            }
        }
        return findings
    }

    private func inspectFirefox(home: URL) -> [Finding] {
        var findings: [Finding] = []
        let profilesDir = home.appendingPathComponent("Library/Application Support/Firefox/Profiles", isDirectory: true)
        guard FileSystem.directoryExists(profilesDir) else { return findings }
        let sqliteFiles = FileSystem.enumerateFiles(at: profilesDir, depthLimit: 2).filter { $0.pathExtension == "sqlite" }
        for file in sqliteFiles {
            if file.lastPathComponent == "places.sqlite" || file.lastPathComponent == "downloads.sqlite" {
                findings.append(contentsOf: analyzeSQLiteHistory(path: file, label: "Firefox History"))
            }
        }
        return findings
    }

    private func analyzeSQLiteHistory(path: URL, label: String) -> [Finding] {
        guard FileSystem.fileExists(path) else { return [] }
        var findings: [Finding] = []
        if SQLiteInspector.isSupported {
            let queries = [
                "SELECT url AS item FROM urls ORDER BY last_visit_time DESC",
                "SELECT url AS item FROM history_items ORDER BY visit_time DESC",
                "SELECT url AS item FROM moz_places ORDER BY last_visit_date DESC"
            ]
            for query in queries {
                let rows = SQLiteInspector.fetchRows(databasePath: path.path, query: query, limit: 50)
                for row in rows {
                    if let url = row.columns["item"], isSuspicious(url: url) {
                        findings.append(Finding(
                            category: category,
                            severity: .medium,
                            description: "Suspicious \(label) URL",
                            location: path.path,
                            context: ["url": url]
                        ))
                    }
                }
                if !findings.isEmpty { break }
            }
        } else if let data = try? Data(contentsOf: path), let text = String(data: data, encoding: .utf8) {
            for keyword in suspiciousKeywords where text.range(of: keyword, options: .caseInsensitive) != nil {
                findings.append(Finding(
                    category: category,
                    severity: .low,
                    description: "Potential suspicious \(label) content",
                    location: path.path,
                    context: ["indicator": keyword]
                ))
            }
        }
        return findings
    }

    private func inspectNetworkPreferences() -> [Finding] {
        let networkPlist = URL(fileURLWithPath: "/Library/Preferences/SystemConfiguration/preferences.plist")
        guard FileSystem.fileExists(networkPlist) else { return [] }
        guard let dictionary = PlistReader.dictionary(at: networkPlist) else { return [] }
        var findings: [Finding] = []
        if let services = dictionary["NetworkServices"] as? [String: Any] {
            for (key, value) in services {
                if let dict = value as? [String: Any], let proxies = dict["Proxies"] as? [String: Any], proxies.values.contains(where: { isProxyEnabled(value: $0) }) {
                    findings.append(Finding(
                        category: .network,
                        severity: .medium,
                        description: "Proxy/VPN configuration detected",
                        location: "NetworkService: \(key)",
                        context: ["details": proxies.description]
                    ))
                }
            }
        }
        return findings
    }

    private func isProxyEnabled(value: Any) -> Bool {
        if let boolValue = value as? Bool {
            return boolValue
        }
        if let number = value as? NSNumber {
            return number.boolValue
        }
        return false
    }

    private func isSuspicious(url: String) -> Bool {
        let lower = url.lowercased()
        for keyword in suspiciousKeywords where lower.contains(keyword) {
            return true
        }
        return false
    }
}
