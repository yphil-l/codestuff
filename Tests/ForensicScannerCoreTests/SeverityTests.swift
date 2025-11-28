import XCTest
@testable import ForensicScannerCore

final class SeverityTests: XCTestCase {
    func testSeverityOrdering() {
        XCTAssertTrue(Severity.critical > Severity.high)
        XCTAssertTrue(Severity.high > Severity.medium)
        XCTAssertTrue(Severity.medium > Severity.low)
        XCTAssertTrue(Severity.low > Severity.info)
    }

    func testSuspicionRulesDetection() {
        let sample = "Launching dyld_insert_libraries cheat payload"
        let severity = SuspicionRules.detectSeverity(in: sample)
        XCTAssertEqual(severity, .critical)
    }
}
