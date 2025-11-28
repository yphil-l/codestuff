import Foundation

public struct ScanOptions: Codable {
    public var features: Set<ScanFeature>
    public var severityThreshold: Severity?
    public var verbose: Bool
    public var timeline: Bool
    public var monitor: Bool
    public var monitorInterval: TimeInterval
    public var monitorIterations: Int
    public var outputPath: String?
    public var compareBaselinePath: String?
    public var saveBaselinePath: String?
    public var targetUser: String?
    public var scanAllUsers: Bool
    public var customPaths: [String]
    public var realTime: Bool

    public init(
        features: Set<ScanFeature> = Set(ScanFeature.allCases),
        severityThreshold: Severity? = nil,
        verbose: Bool = false,
        timeline: Bool = false,
        monitor: Bool = false,
        monitorInterval: TimeInterval = 60,
        monitorIterations: Int = 1,
        outputPath: String? = nil,
        compareBaselinePath: String? = nil,
        saveBaselinePath: String? = nil,
        targetUser: String? = nil,
        scanAllUsers: Bool = false,
        customPaths: [String] = [],
        realTime: Bool = false
    ) {
        self.features = features
        self.severityThreshold = severityThreshold
        self.verbose = verbose
        self.timeline = timeline
        self.monitor = monitor
        self.monitorInterval = monitorInterval
        self.monitorIterations = monitorIterations
        self.outputPath = outputPath
        self.compareBaselinePath = compareBaselinePath
        self.saveBaselinePath = saveBaselinePath
        self.targetUser = targetUser
        self.scanAllUsers = scanAllUsers
        self.customPaths = customPaths
        self.realTime = realTime
    }

    public mutating func enableAllFeatures() {
        features = Set(ScanFeature.allCases)
    }

    public func isFeatureEnabled(_ feature: ScanFeature) -> Bool {
        features.contains(feature)
    }

    public var severityFilterDescription: String {
        guard let severityThreshold else { return "ALL" }
        return "\(severityThreshold.displayName)+"
    }
}
