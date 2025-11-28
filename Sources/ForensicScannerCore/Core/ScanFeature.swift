import Foundation

public enum ScanFeature: String, CaseIterable, Codable {
    case preferences
    case logs
    case trash
    case processes
    case launch
    case browser
    case history
    case persistence
    case user
    case applications
    case keychain
    case security
    case filesystem

    public var defaultCategory: ArtifactCategory {
        switch self {
        case .preferences: return .preferences
        case .logs: return .logs
        case .trash: return .trash
        case .processes: return .processes
        case .launch: return .launchItems
        case .browser: return .browser
        case .history: return .shellHistory
        case .persistence: return .persistence
        case .user: return .userActivity
        case .applications: return .applications
        case .keychain: return .keychain
        case .security: return .security
        case .filesystem: return .filesystem
        }
    }
}
