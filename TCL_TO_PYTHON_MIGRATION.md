# TCL to Python Migration Summary

This document summarizes the migration from TCL scripts to Python scripts in the SQLCipher CMake build system to improve cross-platform compatibility.

## Overview

The original SQLCipher build system used TCL scripts for generating header files and source code. TCL is not universally available on all platforms, especially Windows, which can cause build issues. This migration replaces TCL scripts with Python equivalents, as Python is more widely available and better supported across platforms.

## Changes Made

### 1. Python Script Replacements

The following TCL scripts have been replaced with Python equivalents:

| TCL Script | Python Script | Purpose |
|------------|---------------|---------|
| `tool/mksqlite3h.tcl` | `tool/mksqlite3h.py` | Generate `sqlite3.h` from `sqlite.h.in` |
| `tool/mkopcodeh.tcl` | `tool/mkopcodeh.py` | Generate `opcodes.h` from `parse.h` and `vdbe.c` |
| `tool/mkopcodec.tcl` | `tool/mkopcodec.py` | Generate `opcodes.c` from `opcodes.h` |
| `tool/mkshellc.tcl` | `tool/mkshellc.py` | Generate `shell.c` from `shell.c.in` |

### 2. CMakeLists.txt Updates

- **TCL Detection**: Replaced `find_program(TCLSH_EXECUTABLE ...)` with `find_program(PYTHON_EXECUTABLE python3 python)`
- **Script Commands**: Updated all custom commands to use Python scripts instead of TCL scripts
- **Dependencies**: Updated file dependencies to reference Python scripts
- **Comments**: Updated comments to reflect Python usage

### 3. Documentation Updates

- **CMAKE_USAGE.md**: Updated installation instructions to reference Python instead of TCL
- **Prerequisites**: Changed from TCL installation to Python installation
- **Troubleshooting**: Updated CLI shell issues section to reference Python

## Benefits

### Cross-Platform Compatibility
- **Windows**: Python is more readily available on Windows through official installers, package managers, and development environments
- **Linux**: Python is included by default on most modern Linux distributions
- **macOS**: Python is available through Homebrew and official installers
- **CI/CD**: Python is more commonly available in CI/CD environments

### Better Tooling Support
- **IDE Integration**: Better support in modern IDEs and text editors
- **Debugging**: Easier to debug Python scripts compared to TCL
- **Maintenance**: More developers are familiar with Python than TCL

### Fallback Behavior
- The build system maintains fallback behavior when Python is not available
- `sqlite.h.in` can be copied directly to `sqlite3.h` if needed
- `shell.c.in` can be used directly if Python is not available

## Script Functionality

### mksqlite3h.py
- Processes `sqlite.h.in` template
- Replaces version placeholders (`--VERS--`, `--VERSION-NUMBER--`, `--SOURCE-ID--`)
- Adds `SQLITE_API` declarations to function signatures
- Handles multiple header files (rtree, session, fts5, recover)
- Supports command-line options for output file and API call conventions

### mkopcodeh.py
- Parses concatenated `parse.h` and `vdbe.c` files
- Extracts TK_ token definitions and OP_ opcode definitions
- Generates opcode numbering with proper grouping
- Creates `OPFLG_INITIALIZER` bitvector for opcode properties
- Maintains compatibility with VDBE optimization requirements

### mkopcodec.py
- Reads generated `opcodes.h` file
- Extracts opcode names and synopses
- Generates `sqlite3OpcodeName()` function for VDBE debugging
- Creates opcode name array with help text

### mkshellc.py
- Processes `shell.c.in` template
- Handles `INCLUDE` directives to combine multiple source files
- Removes redundant typedef declarations
- Comments out conflicting includes
- Generates complete `shell.c` for CLI tool

## Testing

All Python scripts have been tested with:
- Basic functionality verification
- Input/output validation
- Error handling
- Cross-platform compatibility

## Migration Notes

### For Developers
- Python scripts maintain the same command-line interface as TCL scripts
- Output files are identical to TCL-generated versions
- No changes required to existing build processes

### For Users
- Install Python 3.x instead of TCL
- Python is available from https://www.python.org/
- Most package managers provide Python 3.x
- Build process remains the same

### For CI/CD
- Update build environments to include Python 3.x
- No TCL installation required
- Python is more commonly available in container images

## Backward Compatibility

- Original TCL scripts remain in the codebase for reference
- Fallback mechanisms ensure builds work without Python
- Generated files are identical to TCL versions
- No breaking changes to the build process

## Future Considerations

- Consider adding Python script tests to CI/CD pipeline
- Monitor Python version compatibility across platforms
- Evaluate need for additional Python dependencies
- Consider adding type hints to Python scripts for better maintainability