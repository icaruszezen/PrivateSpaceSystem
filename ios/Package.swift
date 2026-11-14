// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "PrivateSpaceKit",
    defaultLocalization: "zh-Hans",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(
            name: "PrivateSpaceKit",
            targets: ["PrivateSpaceKit"]
        ),
    ],
    targets: [
        .target(
            name: "PrivateSpaceKit",
            path: "Sources/PrivateSpaceKit"
        ),
        .testTarget(
            name: "PrivateSpaceKitTests",
            dependencies: ["PrivateSpaceKit"],
            path: "Tests/PrivateSpaceKitTests"
        ),
    ]
)
