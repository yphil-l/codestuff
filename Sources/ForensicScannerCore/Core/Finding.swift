import Foundation

public struct Finding: Codable, Hashable {
    public let id: UUID
    public let category: ArtifactCategory
    public let severity: Severity
    public let description: String
    public let location: String
    public let timestamp: Date
    public let context: [String: String]

    public init(
        id: UUID = UUID(),
        category: ArtifactCategory,
        severity: Severity,
        description: String,
        location: String,
        timestamp: Date = Date(),
        context: [String: String] = [:]
    ) {
        self.id = id
        self.category = category
        self.severity = severity
        self.description = description
        self.location = location
        self.timestamp = timestamp
        self.context = context
    }

    public var summaryLine: String {
        "[\(severity.displayName)] \(description) (\(location))"
    }

    public var hashKey: String {
        let values = [category.rawValue, severity.rawValue, description, location]
        return values.joined(separator: "|")
    }
}
