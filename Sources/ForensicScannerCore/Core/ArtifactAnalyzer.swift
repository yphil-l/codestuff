import Foundation

public protocol ArtifactAnalyzer {
    var name: String { get }
    var category: ArtifactCategory { get }
    var feature: ScanFeature { get }
    func analyze(context: ScanContext) -> [Finding]
}

public extension ArtifactAnalyzer {
    func logStart(_ context: ScanContext) {
        context.logger.debug("Starting \(name)")
    }

    func logEnd(_ context: ScanContext, count: Int) {
        context.logger.debug("Finished \(name) with \(count) findings")
    }
}
