import Foundation

public struct ScanReport: Codable {
    public let generatedAt: Date
    public let host: HostInfo
    public let options: ScanOptions
    public let findings: [Finding]
    public let statistics: SeverityBreakdown
    public let recommendations: [String]
    public let timeline: [TimelineEntry]
    public let baselineDelta: BaselineDelta?
    public let securitySoftware: [String]

    public init(
        generatedAt: Date = Date(),
        host: HostInfo,
        options: ScanOptions,
        findings: [Finding],
        statistics: SeverityBreakdown,
        recommendations: [String],
        timeline: [TimelineEntry],
        baselineDelta: BaselineDelta?,
        securitySoftware: [String]
    ) {
        self.generatedAt = generatedAt
        self.host = host
        self.options = options
        self.findings = findings
        self.statistics = statistics
        self.recommendations = recommendations
        self.timeline = timeline
        self.baselineDelta = baselineDelta
        self.securitySoftware = securitySoftware
    }
}

public struct SeverityBreakdown: Codable {
    public let critical: Int
    public let high: Int
    public let medium: Int
    public let low: Int
    public let info: Int

    public var total: Int {
        critical + high + medium + low + info
    }

    public static func from(findings: [Finding]) -> SeverityBreakdown {
        func count(_ severity: Severity) -> Int {
            findings.filter { $0.severity == severity }.count
        }
        return SeverityBreakdown(
            critical: count(.critical),
            high: count(.high),
            medium: count(.medium),
            low: count(.low),
            info: count(.info)
        )
    }
}

public struct TimelineEntry: Codable {
    public let timestamp: Date
    public let severity: Severity
    public let category: ArtifactCategory
    public let summary: String
}
