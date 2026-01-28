// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "tauri-plugin-ble",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "tauri-plugin-ble",
            targets: ["tauri-plugin-ble"]
        )
    ],
    dependencies: [
        .package(name: "Tauri", path: "../.tauri/tauri-api")
    ],
    targets: [
        .target(
            name: "tauri-plugin-ble",
            dependencies: [
                .product(name: "Tauri", package: "Tauri")
            ],
            path: "Sources"
        )
    ]
)
