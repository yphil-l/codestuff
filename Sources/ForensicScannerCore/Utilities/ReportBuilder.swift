import Foundation

public struct ReportBuilder {
    private let dateFormatter: DateFormatter

    public init() {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        formatter.locale = Locale(identifier: "en_US_POSIX")
        self.dateFormatter = formatter
    }

    public func makeTextReport(report: ScanReport, includeTimeline: Bool) -> String {
        var lines: [String] = []
        lines.append("macOS Forensic Scanner Report")
        lines.append(String(repeating: "=", count: 32))
        lines.append("Generated: \(dateFormatter.string(from: report.generatedAt))")
        lines.append("Host: \(report.host.hostname) | User: \(report.host.user)")
        lines.append("OS: \(report.host.osVersion) | Hardware: \(report.host.hardware)")
        lines.append("Locale: \(report.host.locale) | Timezone: \(report.host.timezone)")
        lines.append("Security Software: \(report.securitySoftware.isEmpty ? "Not detected" : report.securitySoftware.joined(separator: ", "))")
        lines.append("")
        lines.append("Severity Summary (threshold: \(report.options.severityFilterDescription))")
        lines.append("  Critical: \(report.statistics.critical)")
        lines.append("  High:     \(report.statistics.high)")
        lines.append("  Medium:   \(report.statistics.medium)")
        lines.append("  Low:      \(report.statistics.low)")
        lines.append("  Info:     \(report.statistics.info)")
        lines.append("  Total:    \(report.statistics.total)")
        lines.append("")

        if let delta = report.baselineDelta {
            lines.append("Baseline Comparison")
            lines.append(String(repeating: "-", count: 24))
            lines.append("New Findings: \(delta.newFindings.count)")
            for finding in delta.newFindings {
                lines.append("  + \(finding.summaryLine)")
            }
            lines.append("Resolved (not present now): \(delta.resolvedFindings.count)")
            for key in delta.resolvedFindings {
                lines.append("  - \(key)")
            }
            lines.append("")
        }

        let grouped = Dictionary(grouping: report.findings) { $0.category.displayName }
        let sortedGroups = grouped.keys.sorted()
        for key in sortedGroups {
            lines.append("\(key)")
            lines.append(String(repeating: "-", count: key.count))
            for finding in grouped[key]!.sorted(by: { $0.severity > $1.severity }) {
                let timestamp = dateFormatter.string(from: finding.timestamp)
                lines.append("[\(finding.severity.displayName)] \(finding.description)")
                lines.append("  Path: \(finding.location)")
                lines.append("  Time: \(timestamp)")
                if !finding.context.isEmpty {
                    for (key, value) in finding.context.sorted(by: { $0.key < $1.key }) {
                        lines.append("  \(key): \(value)")
                    }
                }
            }
            lines.append("")
        }

        if !report.recommendations.isEmpty {
            lines.append("Recommendations")
            lines.append(String(repeating: "-", count: 15))
            for recommendation in report.recommendations {
                lines.append("- \(recommendation)")
            }
            lines.append("")
        }

        if includeTimeline && !report.timeline.isEmpty {
            lines.append("Timeline")
            lines.append(String(repeating: "-", count: 8))
            for entry in report.timeline.sorted(by: { $0.timestamp < $1.timestamp }) {
                lines.append("\(dateFormatter.string(from: entry.timestamp)) | \(entry.severity.displayName) | \(entry.category.displayName) | \(entry.summary)")
            }
            lines.append("")
        }

        return lines.joined(separator: "\n")
    }
}
