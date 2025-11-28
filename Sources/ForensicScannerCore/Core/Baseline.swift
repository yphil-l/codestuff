import Foundation

public struct Baseline: Codable {
    public let createdAt: Date
    public let host: HostInfo
    public let findingHashes: Set<String>

    public init(createdAt: Date = Date(), host: HostInfo, findingHashes: Set<String>) {
        self.createdAt = createdAt
        self.host = host
        self.findingHashes = findingHashes
    }
}

public struct BaselineDelta: Codable {
    public let newFindings: [Finding]
    public let resolvedFindings: [String]
}

public enum BaselineLoader {
    public static func load(from path: String) -> Baseline? {
        let expanded = (path as NSString).expandingTildeInPath
        let url = URL(fileURLWithPath: expanded)
        guard let data = try? Data(contentsOf: url) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        if let baseline = try? decoder.decode(Baseline.self, from: data) {
            return baseline
        }
        if let report = try? decoder.decode(ScanReport.self, from: data) {
            return Baseline(createdAt: report.generatedAt, host: report.host, findingHashes: Set(report.findings.map { $0.hashKey }))
        }
        return nil
    }

    public static func save(baseline: Baseline, to path: String) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(baseline)
        let expanded = (path as NSString).expandingTildeInPath
        try data.write(to: URL(fileURLWithPath: expanded))
    }
}

public enum BaselineComparator {
    public static func compare(report: ScanReport, baseline: Baseline) -> BaselineDelta {
        let current = Set(report.findings.map { $0.hashKey })
        let newKeys = current.subtracting(baseline.findingHashes)
        let resolved = baseline.findingHashes.subtracting(current)
        let newFindings = report.findings.filter { newKeys.contains($0.hashKey) }
        return BaselineDelta(newFindings: newFindings, resolvedFindings: Array(resolved))
    }
}

public extension ScanReport {
    func toBaseline() -> Baseline {
        Baseline(createdAt: generatedAt, host: host, findingHashes: Set(findings.map { $0.hashKey }))
    }
}
