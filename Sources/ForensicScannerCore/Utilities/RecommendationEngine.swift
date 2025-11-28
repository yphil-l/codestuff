import Foundation

public enum RecommendationEngine {
    public static func buildRecommendations(from findings: [Finding]) -> [String] {
        var set: Set<String> = []
        if findings.contains(where: { $0.severity == .critical }) {
            set.insert("Isolate the host from networks and perform immediate incident response triage.")
        }
        if findings.contains(where: { $0.category == .launchItems }) {
            set.insert("Audit LaunchAgents/Daemons for unauthorized persistence and remove malicious plists.")
        }
        if findings.contains(where: { $0.category == .logs }) {
            set.insert("Preserve system logs and review for tampering or clearing attempts.")
        }
        if findings.contains(where: { $0.category == .shellHistory }) {
            set.insert("Review shell history for malicious commands and rotate credentials that may be exposed.")
        }
        if findings.contains(where: { $0.category == .browser }) {
            set.insert("Correlate browser downloads with known malicious indicators and quarantine suspect files.")
        }
        if findings.contains(where: { $0.category == .keychain }) {
            set.insert("Force rotate credentials stored in impacted keychains.")
        }
        if findings.contains(where: { $0.severity == .high }) {
            set.insert("Escalate high severity findings to the security team for deeper investigation.")
        }
        if findings.isEmpty {
            set.insert("Establish a baseline report for future comparisons using --output and --compare options.")
        }
        return Array(set).sorted()
    }
}
