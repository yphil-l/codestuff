import Foundation

public enum SecuritySoftwareDetector {
    private static let knownExecutables: [String] = [
        "CrowdStrike",
        "SentinelOne",
        "CarbonBlack",
        "Falcon",
        "Defender",
        "Bitdefender",
        "ESET",
        "Malwarebytes",
        "FortiClient",
        "Sophos"
    ]

    public static func detect(fileManager: FileManager = .default) -> [String] {
        let applicationDirs = ["/Applications", "/Library/Application Support", "/Library/LaunchDaemons", "/Library/LaunchAgents"]
        var detected: Set<String> = []
        for dir in applicationDirs {
            let url = URL(fileURLWithPath: dir, isDirectory: true)
            guard FileSystem.directoryExists(url, fileManager: fileManager) else { continue }
            if let contents = try? fileManager.contentsOfDirectory(atPath: dir) {
                for item in contents {
                    for keyword in knownExecutables where item.localizedCaseInsensitiveContains(keyword) {
                        detected.insert(keyword)
                    }
                }
            }
        }
        return Array(detected).sorted()
    }
}
