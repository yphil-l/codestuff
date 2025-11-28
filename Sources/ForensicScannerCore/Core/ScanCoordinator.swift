import Foundation
import Dispatch

public final class ScanCoordinator {
    private let analyzers: [ArtifactAnalyzer]

    public init(analyzers: [ArtifactAnalyzer] = AnalyzerFactory.defaultAnalyzers()) {
        self.analyzers = analyzers
    }

    public func performScan(options: ScanOptions) -> ScanReport {
        let logger = Logger(verbose: options.verbose)
        let baseline = options.compareBaselinePath.flatMap { BaselineLoader.load(from: $0) }
        let context = ScanContext(options: options, logger: logger, baseline: baseline)
        var collected: [Finding] = []
        let lock = NSLock()
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "forensic.scanner", attributes: .concurrent)

        for analyzer in analyzers where options.isFeatureEnabled(analyzer.feature) {
            group.enter()
            queue.async {
                analyzer.logStart(context)
                let findings = analyzer.analyze(context: context)
                analyzer.logEnd(context, count: findings.count)
                lock.lock()
                collected.append(contentsOf: findings)
                lock.unlock()
                group.leave()
            }
        }
        group.wait()

        let filtered = collected.filter { $0.severity.meets(threshold: options.severityThreshold) }
        let statistics = SeverityBreakdown.from(findings: filtered)
        let timeline = options.timeline ? TimelineBuilder.build(from: filtered) : []
        let recommendations = RecommendationEngine.buildRecommendations(from: filtered)
        let securitySoftware = SecuritySoftwareDetector.detect(fileManager: context.fileManager)
        let baseReport = ScanReport(
            generatedAt: Date(),
            host: context.hostInfo,
            options: options,
            findings: filtered,
            statistics: statistics,
            recommendations: recommendations,
            timeline: timeline,
            baselineDelta: nil,
            securitySoftware: securitySoftware
        )
        let baselineDelta = baseline.map { BaselineComparator.compare(report: baseReport, baseline: $0) }
        let finalReport = ScanReport(
            generatedAt: baseReport.generatedAt,
            host: baseReport.host,
            options: baseReport.options,
            findings: baseReport.findings,
            statistics: baseReport.statistics,
            recommendations: baseReport.recommendations,
            timeline: baseReport.timeline,
            baselineDelta: baselineDelta,
            securitySoftware: baseReport.securitySoftware
        )
        if let destination = options.saveBaselinePath {
            let baselineModel = finalReport.toBaseline()
            try? BaselineLoader.save(baseline: baselineModel, to: destination)
        }
        return finalReport
    }
}
