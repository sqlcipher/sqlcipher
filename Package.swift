// swift-tools-version: 5.6
import PackageDescription

let package = Package(
    name: "SQLCipher",
    products: [
        .library(
            name: "sqlcipher",
            targets: ["sqlcipher"]),
    ],
    dependencies: [],
    targets: [
        .executableTarget(
            name: "Amalgamation",
            path: "SwiftPM/Amalgamation"
        ),
        .plugin(
            name: "AmalgamationPlugin",
            capability: .buildTool(),
            dependencies: ["Amalgamation"],
            path: "SwiftPM/AmalgamationPlugin"
        ),
        .target(
            name: "sqlcipher",
            path: "SwiftPM/sqlcipher",
            cSettings: [
                .define("NDEBUG", to: nil),
                .define("SQLITE_HAS_CODEC", to: nil),
                .define("SQLITE_TEMP_STORE", to: "2"),
                .define("SQLITE_SOUNDEX", to: nil),
                .define("SQLITE_THREADSAFE", to: nil),
                .define("SQLITE_ENABLE_RTREE", to: nil),
                .define("SQLITE_ENABLE_STAT3", to: nil),
                .define("SQLITE_ENABLE_STAT4", to: nil),
                .define("SQLITE_ENABLE_COLUMN_METADATA", to: nil),
                .define("SQLITE_ENABLE_MEMORY_MANAGEMENT", to: nil),
                .define("SQLITE_ENABLE_LOAD_EXTENSION", to: nil),
                .define("SQLITE_ENABLE_FTS4", to: nil),
                .define("SQLITE_ENABLE_FTS4_UNICODE61", to: nil),
                .define("SQLITE_ENABLE_FTS3_PARENTHESIS", to: nil),
                .define("SQLITE_ENABLE_UNLOCK_NOTIFY", to: nil),
                .define("SQLITE_ENABLE_JSON1", to: nil),
                .define("SQLITE_ENABLE_FTS5", to: nil),
                .define("SQLCIPHER_CRYPTO_CC", to: nil),
                .define("HAVE_USLEEP", to: "1")
            ],
            swiftSettings: [
                .define("SQLITE_HAS_CODEC")
            ]
            ,linkerSettings: [
                .linkedFramework("Foundation"),
                .linkedFramework("Security")
            ],
            plugins: [
                .plugin(
                    name: "AmalgamationPlugin"
                )
            ]
        )
    ]
)
