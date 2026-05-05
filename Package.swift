// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MobileSecurityKit",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "MobileSecurityKit",
            type: .dynamic,
            targets: ["MobileSecurityKit"]
        )
    ],
    targets: [
        .target(
            name: "MobileSecurityKit",
            path: "Sources/MobileSecurityKit"
        ),
        .testTarget(
            name: "MobileSecurityKitTests",
            dependencies: ["MobileSecurityKit"],
            path: "Tests/MobileSecurityKitTests"
        )
    ]
)
