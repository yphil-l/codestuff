import Foundation

public enum Severity: String, Codable, CaseIterable, Comparable {
    case critical
    case high
    case medium
    case low
    case info

    private var rank: Int {
        switch self {
        case .critical: return 4
        case .high: return 3
        case .medium: return 2
        case .low: return 1
        case .info: return 0
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        return lhs.rank < rhs.rank
    }

    public func meets(threshold: Severity?) -> Bool {
        guard let threshold = threshold else { return true }
        return self.rank >= threshold.rank
    }

    public var displayName: String {
        rawValue.uppercased()
    }
}
