// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "NavigoCore",
    platforms: [.macOS(.v10_15), .iOS(.v17)],
    products: [
        .library(name: "NavigoCore", targets: ["NavigoCore"])
    ],
    targets: [
        .target(name: "NavigoCore", dependencies: []),
        .testTarget(name: "NavigoCoreTests", dependencies: ["NavigoCore"])
    ]
)
