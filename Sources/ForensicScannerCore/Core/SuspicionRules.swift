import Foundation

public enum SuspicionRules {
    private static let suspiciousTerms: [String] = [
        "cheat",
        "hack",
        "spoof",
        "aimbot",
        "wallhack",
        "inject",
        "bypass",
        "disable sip",
        "codesign --force",
        "unsigned dylib",
        "dlopen",
        "payload",
        "shellcode",
        "frida",
        "xattr -d",
        "chmod 777",
        "launchctl load",
        "launchctl unload",
        "csrutil",
        "spctl --master-disable",
        "sudo rm -rf",
        "killall -9",
        "DYLD_INSERT_LIBRARIES",
        "LD_PRELOAD",
        "proxychains",
        "vpn",
        "tunnel",
        "obfuscate",
        "keylogger",
        "rootkit",
        "evasion",
        "tamper"
    ]

    private static let destructiveCommands: [String] = [
        "rm -rf",
        "dd if=",
        "mktemp -t",
        "curl http",
        "wget http",
        "python -c",
        "ruby -e",
        "osascript",
        "scutil --set",
        "defaults write com.apple",
        "launchctl",
        "chmod +x",
        "codesign",
        "spctl",
        "security delete",
        "sqlite3",
        "killall"
    ]

    private static let suspiciousPaths: [String] = [
        "/tmp/",
        "/private/tmp/",
        "/var/tmp/",
        "~/Desktop/",
        "~/Library/Application Support/",
        "/Users/Shared/",
        "/Library/LaunchAgents/",
        "/Library/LaunchDaemons/",
        "~/Library/LaunchAgents/",
        "~/Library/LaunchDaemons/",
        "~/Library/Scripts/",
        "/Applications/Utilities/",
        "/System/Library/Extensions/",
        "/Library/SystemExtensions/"
    ]

    public static func score(for text: String) -> Int {
        let lower = text.lowercased()
        var score = 0
        for term in suspiciousTerms where lower.contains(term.lowercased()) {
            score += 2
        }
        for term in destructiveCommands where lower.contains(term.lowercased()) {
            score += 1
        }
        for path in suspiciousPaths where lower.contains(path.lowercased()) {
            score += 1
        }
        return score
    }

    public static func severity(forScore score: Int, recencyBoost: Bool = false) -> Severity? {
        let adjusted = recencyBoost ? score + 1 : score
        switch adjusted {
        case 4...: return .critical
        case 3: return .high
        case 2: return .medium
        case 1: return .low
        default: return nil
        }
    }

    public static func detectSeverity(in text: String, recencyBoost: Bool = false) -> Severity? {
        let score = score(for: text)
        return severity(forScore: score, recencyBoost: recencyBoost)
    }

    public static func isSuspiciousCommand(_ command: String) -> Bool {
        detectSeverity(in: command) != nil
    }
}
