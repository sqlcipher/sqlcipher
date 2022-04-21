import Foundation

func exec(_ command: String) throws -> String {
    let proc = Process()
    let pipe = Pipe()
    
    proc.standardOutput = pipe
    proc.standardError = pipe
    proc.arguments = ["-c", command]
    proc.launchPath = "/bin/zsh"
    proc.launch()
    proc.waitUntilExit()
    
    let output = pipe.fileHandleForReading.readDataToEndOfFile()
    return String(data: output, encoding: .utf8)!
}

let pluginWorkDir = CommandLine.arguments[1]
let outputDir = CommandLine.arguments[2]

// clean out the working directory and copy the package source files there
var prep = [
    "rm -rf '\(pluginWorkDir)'",
    "cp -R . '\(pluginWorkDir)'"
]

try prep.forEach { cmd in
    let out = try exec(cmd)
    print ("\(cmd) returned \(out)")
}

// change to working directory
FileManager.default.changeCurrentDirectoryPath(pluginWorkDir)
print(FileManager.default.currentDirectoryPath)

// build the amalgamation and copy it to the output folder
var build = [
    "./configure --with-crypto-lib=none",
    "make clean",
    "make sqlite3.c",
    "mkdir -p gen/include",
    "cp sqlite3.c \(outputDir)",
    "cp sqlite3.h \(outputDir)"
]

try build.forEach { cmd in
    let out = try exec(cmd)
    print ("\(cmd) returned \(out)")
}
