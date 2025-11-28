// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "macos-forensic-scanner",
    platforms: [
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "ForensicScannerCore",
            targets: ["ForensicScannerCore"]
        ),
        .executable(
            name: "macos-forensic-scanner",
            targets: ["macos-forensic-scanner"]
        )
    ],
    dependencies: [],
    targets: [
        .target(
            name: "ForensicScannerCore",
            dependencies: []
        ),
        .executableTarget(
            name: "macos-forensic-scanner",
            dependencies: ["ForensicScannerCore"]
        ),
        .testTarget(
            name: "ForensicScannerCoreTests",
            dependencies: ["ForensicScannerCore"]
        )
    ]
)
