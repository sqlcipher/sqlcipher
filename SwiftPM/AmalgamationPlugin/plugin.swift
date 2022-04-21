// swift-tools-version: 5.6
import Foundation
import PackagePlugin

@main struct AmalgamationPlugin: BuildToolPlugin {
    func createBuildCommands(context: PluginContext, target: Target) throws -> [Command] {
        let outputDir = context.pluginWorkDirectory.appending("gen")
        let toolPath = try context.tool(named: "Amalgamation").path
        print("outputFilesDirectory: \(outputDir) pluginWorkDir: \(context.pluginWorkDirectory) toolPath: \(toolPath)")
        return [.buildCommand(
              displayName: "Running Amalgamation",
              executable: toolPath,
              arguments: [context.pluginWorkDirectory.string, outputDir.string],
              outputFiles: [
                outputDir.appending("sqlite3.c"),
                outputDir.appending("sqlite3.h"),
              ]
        )]
    }
}
