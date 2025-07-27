# SQLCipher CMake Build System

This CMakeLists.txt provides a cross-platform build system for SQLCipher using CMake, replacing the autotools/Makefile system.

## Features

- **Cross-platform support**: Linux, macOS, Windows
- **Customizable library names**: Set custom base names for output libraries
- **Multiple crypto backends**: OpenSSL, NSS, LibTomCrypt, CommonCrypto (macOS)
- **Flexible build options**: Static/shared libraries, CLI tool, optional features

## Basic Usage

```bash
# Create build directory
mkdir build && cd build

# Configure with default settings (OpenSSL backend)
cmake ..

# Build
cmake --build .

# Install
cmake --install .
```

## Customizing Library Output Names

You can customize the base names of the output libraries and executable:

```bash
cmake .. \
  -DSQLCIPHER_LIB_NAME="mycustom_sqlcipher" \
  -DSQLCIPHER_CLI_NAME="mycustom_sqlcipher_cli"
```

This will produce:
- Shared library: `libmycustom_sqlcipher.so` (Linux), `libmycustom_sqlcipher.dylib` (macOS), `mycustom_sqlcipher.dll` (Windows)
- Static library: `libmycustom_sqlcipher.a` (Unix), `mycustom_sqlcipher.lib` (Windows)
- CLI executable: `mycustom_sqlcipher_cli`

**Note**: The default CLI name is `sqlcipher-cli` to avoid target name conflicts with the shared library.

## Configuration Options

### Crypto Backend Selection

```bash
# Use OpenSSL (default)
cmake .. -DSQLCIPHER_CRYPTO_BACKEND=openssl

# Use NSS
cmake .. -DSQLCIPHER_CRYPTO_BACKEND=nss

# Use LibTomCrypt
cmake .. -DSQLCIPHER_CRYPTO_BACKEND=libtomcrypt

# Use CommonCrypto (macOS only)
cmake .. -DSQLCIPHER_CRYPTO_BACKEND=commoncrypto
```

### Build Type Options

```bash
# Enable/disable components
cmake .. \
  -DSQLCIPHER_ENABLE_SHARED=ON \
  -DSQLCIPHER_ENABLE_STATIC=ON \
  -DSQLCIPHER_ENABLE_CLI=ON

### Complete Example with Custom Names

```bash
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DSQLCIPHER_CRYPTO_BACKEND=openssl \
  -DSQLCIPHER_LIB_NAME="myapp_sqlcipher" \
  -DSQLCIPHER_CLI_NAME="myapp_sqlcipher_cli" \
  -DCMAKE_INSTALL_PREFIX=/usr/local
```

### Complete Example with OpenSSL 3 root dir on Windows

```
cmake -G "Ninja" .. -DCMAKE_BUILD_TYPE=Release -DSQLCIPHER_CRYPTO_BACKEND=openssl -DCMAKE_INSTALL_PREFIX=..\install -DOPENSSL_ROOT_DIR=C:\Qt\Tools\OpenSSLv3\Win_x64
```

## Prerequisites

### Required Dependencies

**For OpenSSL backend:**
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# CentOS/RHEL/Fedora
sudo yum install openssl-devel

# macOS
brew install openssl
```

**For CLI shell (optional but recommended):**
```bash
# Ubuntu/Debian
sudo apt-get install python3

# CentOS/RHEL/Fedora
sudo yum install python3

# macOS
brew install python3

# Windows
# Download from https://www.python.org/ or use package manager
```

**Note**: Python is used to generate the full-featured CLI shell and other header files. Without Python, fallback methods are used that work but may have fewer features.

**For NSS backend:**
```bash
# Ubuntu/Debian
sudo apt-get install libnss3-dev

# CentOS/RHEL/Fedora
sudo yum install nss-devel
```

**For LibTomCrypt backend:**
```bash
# Ubuntu/Debian
sudo apt-get install libtomcrypt-dev

# Build from source if not available in package manager
```

## Cross-Platform Notes

### Windows with MSVC
```bash
# Use Visual Studio generator
cmake .. -G "Visual Studio 16 2019" -A x64
cmake --build . --config Release
```

### Windows with MinGW
```bash
cmake .. -G "MinGW Makefiles"
cmake --build .
```

### macOS with Xcode
```bash
cmake .. -G Xcode
cmake --build . --config Release
```

## Installation

The build system supports standard CMake installation:

```bash
# Install to system directories
sudo cmake --install .

# Install to custom prefix
cmake --install . --prefix /opt/sqlcipher

# Install specific components
cmake --install . --component Runtime    # CLI only
cmake --install . --component Development # Headers and libraries
```

## pkg-config Support

The build system generates a `sqlcipher.pc` file for pkg-config integration:

```bash
# After installation
pkg-config --cflags sqlcipher
pkg-config --libs sqlcipher
```

## Troubleshooting

### Crypto Library Not Found
Ensure the crypto library is installed and in the system path. For custom installations, set CMAKE_PREFIX_PATH:

```bash
cmake .. -DCMAKE_PREFIX_PATH=/path/to/openssl
```

### Library Naming Conflicts
If you have naming conflicts with system SQLite, use custom library names:

```bash
cmake .. -DSQLCIPHER_LIB_NAME="sqlcipher_custom"
```

### Target Name Conflicts
CMake doesn't allow multiple targets with the same name. Ensure your library and executable names are different:

```bash
# Good - different names
cmake .. \
  -DSQLCIPHER_LIB_NAME="myapp_db" \
  -DSQLCIPHER_CLI_NAME="myapp_db_cli"

# Bad - same names will cause CMake errors
cmake .. \
  -DSQLCIPHER_LIB_NAME="myapp" \
  -DSQLCIPHER_CLI_NAME="myapp"  # ERROR: target name conflict
```

### CLI Shell Issues
If you get warnings about Python not being found:

```bash
# The build will work but use a fallback method
# To get the full-featured shell, install Python:

# Linux
sudo apt-get install python3

# macOS
brew install python3

# Windows - download from https://www.python.org/
```

The fallback method copies `shell.c.in` directly and works on all platforms, but the Python-generated version has additional features and optimizations.

### Missing Generated Files
When building from individual source files, SQLite requires several generated header files:

- `parse.h` - Generated from `src/parse.y` using lemon parser
- `opcodes.h` - Generated using Python scripts (requires Python)
- `keywordhash.h` - Generated using mkkeywordhash tool

The CMake build automatically generates these files, but:

### SQLCipher Compilation Requirements
SQLCipher has specific compilation requirements that are automatically handled by this CMake build:

- `SQLITE_HAS_CODEC=1` - Enable codec support
- `SQLITE_EXTRA_INIT=sqlcipher_extra_init` - SQLCipher initialization
- `SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown` - SQLCipher cleanup
- `SQLITE_TEMP_STORE=2` - Use memory for temporary storage
- C99 standard compliance with automatic `stdint.h` inclusion
- Cross-platform `uint64_t` type support (GCC/Clang/MSVC)

These are automatically set by the CMake configuration and don't require manual setup.