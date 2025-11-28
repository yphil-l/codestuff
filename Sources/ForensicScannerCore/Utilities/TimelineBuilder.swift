import Foundation

public enum TimelineBuilder {
    public static func build(from findings: [Finding], limit: Int = 200) -> [TimelineEntry] {
        let sorted = findings.sorted { $0.timestamp < $1.timestamp }
        return sorted.prefix(limit).map {
            TimelineEntry(timestamp: $0.timestamp, severity: $0.severity, category: $0.category, summary: $0.description)
        }
    }
}
