import Foundation

public enum ArtifactCategory: String, Codable, CaseIterable {
    case preferences
    case defaults
    case launchItems
    case logs
    case trash
    case browser
    case shellHistory
    case processes
    case persistence
    case userActivity
    case applications
    case keychain
    case network
    case security
    case filesystem
    case timeline

    public var displayName: String {
        switch self {
        case .preferences: return "Preferences"
        case .defaults: return "Defaults Database"
        case .launchItems: return "LaunchAgents/Daemons"
        case .logs: return "Logs"
        case .trash: return "Trash & File Removal"
        case .browser: return "Browser & Network"
        case .shellHistory: return "Shell History"
        case .processes: return "Processes & Memory"
        case .persistence: return "Persistence Mechanisms"
        case .userActivity: return "User Activity"
        case .applications: return "Applications & Installations"
        case .keychain: return "Keychain & Credentials"
        case .network: return "Network Connections"
        case .security: return "Security Posture"
        case .filesystem: return "Filesystem"
        case .timeline: return "Timeline"
        }
    }
}
