cmake_minimum_required(VERSION 3.16)

# Extract version from VERSION file
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION")
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" SQLCIPHER_VERSION)
    string(STRIP "${SQLCIPHER_VERSION}" SQLCIPHER_VERSION)
else()
    set(SQLCIPHER_VERSION "3.49.2")
endif()

project(SQLCipher
    VERSION ${SQLCIPHER_VERSION}
    LANGUAGES C
    DESCRIPTION "SQLCipher is an SQLite extension that provides 256 bit AES encryption of database files"
)

# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build." FORCE)
endif()

# Build options
option(SQLCIPHER_ENABLE_SHARED "Build shared library" ON)
option(SQLCIPHER_ENABLE_STATIC "Build static library" OFF)
option(SQLCIPHER_ENABLE_CLI "Build command line interface" ON)
option(SQLCIPHER_ENABLE_TESTS "Build test programs" OFF)

# Library base name options (customizable output names)
set(SQLCIPHER_LIB_NAME "sqlcipher" CACHE STRING "Base name for library")
set(SQLCIPHER_CLI_NAME "sqlcipher" CACHE STRING "Name for CLI executable")

# Crypto backend selection (only one should be enabled)
set(SQLCIPHER_CRYPTO_BACKEND "openssl" CACHE STRING
    "Crypto backend: openssl, nss, libtomcrypt, commoncrypto")
set_property(CACHE SQLCIPHER_CRYPTO_BACKEND PROPERTY STRINGS
    "openssl" "nss" "libtomcrypt" "commoncrypto")

# Log configuration information
message(STATUS "SQLCipher crypto backend: ${SQLCIPHER_CRYPTO_BACKEND}")
message(STATUS "CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")
message(STATUS "CMAKE_FIND_ROOT_PATH: ${CMAKE_FIND_ROOT_PATH}")

# Standard setup
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Ensure C99 features are available
add_definitions(-D_GNU_SOURCE)
if(NOT WIN32)
    add_definitions(-D_POSIX_C_SOURCE=200809L)
endif()

# Platform-specific settings
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

if(WIN32)
    add_definitions(-DSQLITE_OS_WIN=1)
    if(MSVC)
        add_compile_options(/W3)
        add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_SECURE_NO_DEPRECATE)
        # Force include stdint.h for MSVC (Visual Studio 2010+)
        add_compile_options(/FI stdint.h)
        message(STATUS "Using MSVC compiler with stdint.h forced include")
    endif()
else()
    add_definitions(-DSQLITE_OS_UNIX=1)
    if(APPLE)
        # Enable BSD-style types (u_int, u_char, u_short, etc.) on macOS
        add_definitions(-D_DARWIN_C_SOURCE)
        message(STATUS "Added macOS-specific definitions for BSD types")
    endif()
    if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
        add_compile_options(-Wall -Wextra)
        # Ensure stdint.h and other C99 headers are available
        add_compile_options(-std=c99)
        # Force include stdint.h to ensure uint64_t types are available
        add_compile_options(-include stdint.h)
        message(STATUS "Using GCC/Clang compiler with C99 and stdint.h")
    endif()
endif()

# Find dependencies based on crypto backend
if(SQLCIPHER_CRYPTO_BACKEND STREQUAL "openssl")
    find_package(OpenSSL REQUIRED)
    message(STATUS "OpenSSL found: ${OpenSSL_VERSION}")
    message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL library dir: ${OPENSSL_LIBRARY_DIR}")
    message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
    message(STATUS "OpenSSL crypto library: ${OPENSSL_CRYPTO_LIBRARY}")
    message(STATUS "OpenSSL ssl library: ${OPENSSL_SSL_LIBRARY}")
    set(CRYPTO_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
    add_definitions(-DSQLCIPHER_CRYPTO_OPENSSL=1)
elseif(SQLCIPHER_CRYPTO_BACKEND STREQUAL "nss")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(NSS REQUIRED nss)
    set(CRYPTO_LIBRARIES ${NSS_LIBRARIES})
    include_directories(${NSS_INCLUDE_DIRS})
    add_definitions(-DSQLCIPHER_CRYPTO_NSS=1)
    link_directories(${NSS_LIBRARY_DIRS})
elseif(SQLCIPHER_CRYPTO_BACKEND STREQUAL "libtomcrypt")
    find_library(TOMCRYPT_LIBRARY tomcrypt)
    if(NOT TOMCRYPT_LIBRARY)
        message(FATAL_ERROR "LibTomCrypt library not found")
    endif()
    set(CRYPTO_LIBRARIES ${TOMCRYPT_LIBRARY})
    add_definitions(-DSQLCIPHER_CRYPTO_LIBTOMCRYPT=1)
elseif(SQLCIPHER_CRYPTO_BACKEND STREQUAL "commoncrypto")
    if(NOT APPLE)
        message(FATAL_ERROR "CommonCrypto is only available on Apple platforms")
    endif()
    find_library(COMMONCRYPTO_LIBRARY CommonCrypto)
    if(NOT COMMONCRYPTO_LIBRARY)
        message(FATAL_ERROR "CommonCrypto framework not found")
    endif()
    set(CRYPTO_LIBRARIES ${COMMONCRYPTO_LIBRARY})
    add_definitions(-DSQLCIPHER_CRYPTO_CC=1)
else()
    message(FATAL_ERROR "Invalid crypto backend: ${SQLCIPHER_CRYPTO_BACKEND}")
endif()

# Core SQLite/SQLCipher compiler definitions
add_definitions(
    -DSQLITE_HAS_CODEC=1
    -DSQLITE_EXTRA_INIT=sqlcipher_extra_init
    -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown
    -DSQLITE_TEMP_STORE=2
    -DSQLITE_THREADSAFE=1
    -DSQLITE_ENABLE_COLUMN_METADATA=1
)

# System libraries
set(SYSTEM_LIBRARIES)
if(NOT WIN32)
    list(APPEND SYSTEM_LIBRARIES m pthread dl)
    if(NOT APPLE)
        list(APPEND SYSTEM_LIBRARIES rt)
    endif()
endif()

# Source files
set(SQLCIPHER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/alter.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/analyze.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/attach.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/auth.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/backup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bitvec.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/btmutex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/btree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/build.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/callback.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/complete.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ctime.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/date.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dbpage.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dbstat.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/delete.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/expr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/fault.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/fkey.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/func.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/global.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/insert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/json.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/legacy.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/loadext.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/malloc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mem0.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mem1.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mem2.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mem3.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mem5.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/memdb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/memjournal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mutex.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mutex_noop.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mutex_unix.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mutex_w32.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/notify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/os.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/os_kv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/os_unix.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/os_win.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pager.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pcache.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pcache1.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pragma.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/prepare.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/printf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/random.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/resolve.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/rowset.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/status.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/table.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/threads.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tokenize.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/treeview.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/trigger.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/update.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/upsert.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/util.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vacuum.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vdbe.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vdbeapi.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vdbeaux.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vdbeblob.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vdbemem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vdbesort.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vdbetrace.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vdbevtab.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/vtab.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/wal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/walker.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/where.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/wherecode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/whereexpr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/window.c
    # SQLCipher sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sqlcipher.c
)

# Add appropriate crypto backend source
if(SQLCIPHER_CRYPTO_BACKEND STREQUAL "openssl")
    list(APPEND SQLCIPHER_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_openssl.c)
elseif(SQLCIPHER_CRYPTO_BACKEND STREQUAL "nss")
    list(APPEND SQLCIPHER_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_nss.c)
elseif(SQLCIPHER_CRYPTO_BACKEND STREQUAL "libtomcrypt")
    list(APPEND SQLCIPHER_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_libtomcrypt.c)
elseif(SQLCIPHER_CRYPTO_BACKEND STREQUAL "commoncrypto")
    list(APPEND SQLCIPHER_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto_cc.c)
endif()

# Add include directories for extensions
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
)

# Generate required header files
# Find Python for header generation (cross-platform alternative to TCL)
find_program(PYTHON_EXECUTABLE python3 python HINTS ENV PATH)
message(STATUS "Python executable: ${PYTHON_EXECUTABLE}")

# Build mksourceid tool for sqlite3.h generation
add_executable(mksourceid ${CMAKE_CURRENT_SOURCE_DIR}/tool/mksourceid.c)
set_target_properties(mksourceid PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Generate sqlite3.h from sqlite.h.in (contains SQLCipher function declarations)
if(PYTHON_EXECUTABLE)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sqlite3.h
        COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tool/mksqlite3h.py ${CMAKE_CURRENT_SOURCE_DIR} -o ${CMAKE_CURRENT_BINARY_DIR}/sqlite3.h
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/src/sqlite.h.in
            ${CMAKE_CURRENT_SOURCE_DIR}/VERSION
            ${CMAKE_CURRENT_SOURCE_DIR}/manifest
            mksourceid
            ${CMAKE_CURRENT_SOURCE_DIR}/tool/mksqlite3h.py
        COMMENT "Generating sqlite3.h from sqlite.h.in using Python"
    )
else()
    # Fallback: copy sqlite.h.in to sqlite3.h
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sqlite3.h
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/sqlite.h.in ${CMAKE_CURRENT_BINARY_DIR}/sqlite3.h
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/sqlite.h.in
        COMMENT "Copying sqlite.h.in to sqlite3.h (fallback)"
    )
endif()

# Build lemon parser generator
add_executable(lemon ${CMAKE_CURRENT_SOURCE_DIR}/tool/lemon.c)
set_target_properties(lemon PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Build mkkeywordhash tool
add_executable(mkkeywordhash ${CMAKE_CURRENT_SOURCE_DIR}/tool/mkkeywordhash.c)
set_target_properties(mkkeywordhash PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Generate parse.c and parse.h from parse.y
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/parse.c ${CMAKE_CURRENT_BINARY_DIR}/parse.h
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/parse.y ${CMAKE_CURRENT_BINARY_DIR}/parse.y
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/tool/lempar.c ${CMAKE_CURRENT_BINARY_DIR}/lempar.c
    COMMAND $<TARGET_FILE:lemon> ${CMAKE_CURRENT_BINARY_DIR}/parse.y
    DEPENDS lemon ${CMAKE_CURRENT_SOURCE_DIR}/src/parse.y ${CMAKE_CURRENT_SOURCE_DIR}/tool/lempar.c
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating parse.c and parse.h from parse.y"
)

# Generate keywordhash.h
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/keywordhash.h
    COMMAND $<TARGET_FILE:mkkeywordhash> > ${CMAKE_CURRENT_BINARY_DIR}/keywordhash.h
    DEPENDS mkkeywordhash
    COMMENT "Generating keywordhash.h"
        )

    # Generate opcodes.h (requires Python)
if(PYTHON_EXECUTABLE)
    # Create CMake script to generate opcodes.h
    set(OPCODES_CMAKE_SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/generate_opcodes.cmake)
    file(WRITE ${OPCODES_CMAKE_SCRIPT}
        "# Generate opcodes.h\n"
        "execute_process(\n"
        "    COMMAND \"${CMAKE_COMMAND}\" -E cat \"${CMAKE_CURRENT_BINARY_DIR}/parse.h\" \"${CMAKE_CURRENT_SOURCE_DIR}/src/vdbe.c\"\n"
        "    COMMAND \"${PYTHON_EXECUTABLE}\" \"${CMAKE_CURRENT_SOURCE_DIR}/tool/mkopcodeh.py\"\n"
        "    OUTPUT_FILE \"${CMAKE_CURRENT_BINARY_DIR}/opcodes.h\"\n"
        "    RESULT_VARIABLE opcodes_result\n"
        ")\n"
        "if(NOT opcodes_result EQUAL 0)\n"
        "    message(FATAL_ERROR \"Failed to generate opcodes.h\")\n"
        "endif()\n"
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/opcodes.h
        COMMAND ${CMAKE_COMMAND} -P ${OPCODES_CMAKE_SCRIPT}
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/parse.h ${CMAKE_CURRENT_SOURCE_DIR}/src/vdbe.c ${CMAKE_CURRENT_SOURCE_DIR}/tool/mkopcodeh.py
        COMMENT "Generating opcodes.h using Python"
    )

    # Create CMake script to generate opcodes.c
    set(OPCODES_C_CMAKE_SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/generate_opcodes_c.cmake)
    file(WRITE ${OPCODES_C_CMAKE_SCRIPT}
        "# Generate opcodes.c\n"
        "execute_process(\n"
        "    COMMAND \"${PYTHON_EXECUTABLE}\" \"${CMAKE_CURRENT_SOURCE_DIR}/tool/mkopcodec.py\" \"${CMAKE_CURRENT_BINARY_DIR}/opcodes.h\"\n"
        "    OUTPUT_FILE \"${CMAKE_CURRENT_BINARY_DIR}/opcodes.c\"\n"
        "    RESULT_VARIABLE opcodes_c_result\n"
        ")\n"
        "if(NOT opcodes_c_result EQUAL 0)\n"
        "    message(FATAL_ERROR \"Failed to generate opcodes.c\")\n"
        "endif()\n"
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/opcodes.c
        COMMAND ${CMAKE_COMMAND} -P ${OPCODES_C_CMAKE_SCRIPT}
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/opcodes.h ${CMAKE_CURRENT_SOURCE_DIR}/tool/mkopcodec.py
        COMMENT "Generating opcodes.c using Python"
    )
    set(GENERATED_OPCODES_SOURCES ${CMAKE_CURRENT_BINARY_DIR}/opcodes.c)
else()
    message(WARNING "Python not found - opcodes.h and opcodes.c will not be generated. Some functionality may be missing.")
    set(GENERATED_OPCODES_SOURCES "")
endif()

# Add generated sources to the source list
list(APPEND SQLCIPHER_SOURCES
    ${CMAKE_CURRENT_BINARY_DIR}/parse.c
    ${GENERATED_OPCODES_SOURCES}
)

# Create custom target for generated files
add_custom_target(generate_headers
    DEPENDS
    ${CMAKE_CURRENT_BINARY_DIR}/sqlite3.h
    ${CMAKE_CURRENT_BINARY_DIR}/parse.h
    ${CMAKE_CURRENT_BINARY_DIR}/keywordhash.h
    ${CMAKE_CURRENT_BINARY_DIR}/opcodes.h
)

# Check if sources exist
foreach(src_file ${SQLCIPHER_SOURCES})
    if(NOT EXISTS "${src_file}")
        message(WARNING "Source file ${src_file} not found")
    endif()
endforeach()

# Shared library
if(SQLCIPHER_ENABLE_SHARED)
    add_library(${SQLCIPHER_LIB_NAME} SHARED ${SQLCIPHER_SOURCES})

    # Ensure generated headers are built first
    add_dependencies(${SQLCIPHER_LIB_NAME} generate_headers)

    target_link_libraries(${SQLCIPHER_LIB_NAME}
        ${CRYPTO_LIBRARIES}
        ${SYSTEM_LIBRARIES}
    )

    set_target_properties(${SQLCIPHER_LIB_NAME} PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        OUTPUT_NAME ${SQLCIPHER_LIB_NAME}
        POSITION_INDEPENDENT_CODE ON
    )

    if(WIN32)
        set_target_properties(${SQLCIPHER_LIB_NAME} PROPERTIES
            WINDOWS_EXPORT_ALL_SYMBOLS ON
        )
    endif()

    # Set rpath for Unix-like systems
    if(NOT WIN32)
        set_target_properties(${SQLCIPHER_LIB_NAME} PROPERTIES
            INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib"
            INSTALL_RPATH_USE_LINK_PATH TRUE
        )
    endif()
endif()

# Static library
if(SQLCIPHER_ENABLE_STATIC)
    add_library(${SQLCIPHER_LIB_NAME}_static STATIC ${SQLCIPHER_SOURCES})

    add_dependencies(${SQLCIPHER_LIB_NAME}_static generate_headers)

    target_link_libraries(${SQLCIPHER_LIB_NAME}_static
        ${CRYPTO_LIBRARIES}
        ${SYSTEM_LIBRARIES}
    )

    set_target_properties(${SQLCIPHER_LIB_NAME}_static PROPERTIES
        OUTPUT_NAME ${SQLCIPHER_LIB_NAME}
        POSITION_INDEPENDENT_CODE ON
    )
endif()

# Command line interface
if(SQLCIPHER_ENABLE_CLI)
    # Generate shell.c from shell.c.in or use it directly
    set(SHELL_C_IN "${CMAKE_CURRENT_SOURCE_DIR}/src/shell.c.in")
    set(SHELL_C "${CMAKE_CURRENT_BINARY_DIR}/shell.c")

    if(EXISTS "${SHELL_C_IN}")
        if(PYTHON_EXECUTABLE AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tool/mkshellc.py")
            # Generate shell.c using the Python script (preferred method)
            add_custom_command(
                OUTPUT ${SHELL_C}
                COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tool/mkshellc.py ${SHELL_C}
                DEPENDS ${SHELL_C_IN} ${CMAKE_CURRENT_SOURCE_DIR}/tool/mkshellc.py
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                COMMENT "Generating shell.c using Python script (full-featured)"
            )
            set(CLI_SOURCES ${SHELL_C})
            message(STATUS "Using Python to generate shell.c (recommended)")
        else()
            # Cross-platform fallback: copy shell.c.in to shell.c
            # Note: shell.c.in is valid C code and will work on all platforms
            add_custom_command(
                OUTPUT ${SHELL_C}
                COMMAND ${CMAKE_COMMAND} -E copy ${SHELL_C_IN} ${SHELL_C}
                DEPENDS ${SHELL_C_IN}
                COMMENT "Using shell.c.in directly (cross-platform fallback)"
            )
            set(CLI_SOURCES ${SHELL_C})
            if(NOT PYTHON_EXECUTABLE)
                message(STATUS "Python not found - using fallback method for shell.c")
                message(STATUS "  To get full shell features, install Python: https://www.python.org/")
            endif()
        endif()
    else()
        message(WARNING "CLI source ${SHELL_C_IN} not found, skipping CLI build")
        set(SQLCIPHER_ENABLE_CLI OFF)
    endif()
endif()

if(SQLCIPHER_ENABLE_CLI)
    add_executable(${SQLCIPHER_CLI_NAME}_bin ${CLI_SOURCES})

    # Link with shared library if available, otherwise static
    if(SQLCIPHER_ENABLE_SHARED)
        target_link_libraries(${SQLCIPHER_CLI_NAME}_bin ${SQLCIPHER_LIB_NAME})
    elseif(SQLCIPHER_ENABLE_STATIC)
        target_link_libraries(${SQLCIPHER_CLI_NAME}_bin ${SQLCIPHER_LIB_NAME}_static)
        target_link_libraries(${SQLCIPHER_CLI_NAME}_bin ${CRYPTO_LIBRARIES} ${SYSTEM_LIBRARIES})
    endif()

    # Add shell-specific definitions
    target_compile_definitions(${SQLCIPHER_CLI_NAME}_bin PRIVATE
        -DSQLITE_ENABLE_EXPLAIN_COMMENTS=1
        -DSQLITE_ENABLE_UNKNOWN_SQL_FUNCTION=1
        -DSQLITE_ENABLE_STMTVTAB=1
        -DSQLITE_ENABLE_DBPAGE_VTAB=1
        -DSQLITE_ENABLE_DBSTAT_VTAB=1
        -DSQLITE_ENABLE_BYTECODE_VTAB=1
        -DSQLITE_ENABLE_OFFSET_SQL_FUNC=1
        -DSQLITE_DQS=0
    )

    # Add readline support if available
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(READLINE readline)
        if(READLINE_FOUND)
            target_compile_definitions(${SQLCIPHER_CLI_NAME}_bin PRIVATE -DHAVE_READLINE=1)
            target_link_libraries(${SQLCIPHER_CLI_NAME}_bin ${READLINE_LIBRARIES})
            target_include_directories(${SQLCIPHER_CLI_NAME}_bin PRIVATE ${READLINE_INCLUDE_DIRS})
        endif()
    endif()

    set_target_properties(${SQLCIPHER_CLI_NAME}_bin PROPERTIES
        OUTPUT_NAME ${SQLCIPHER_CLI_NAME}
        POSITION_INDEPENDENT_CODE ON
    )
endif()

# Installation
include(GNUInstallDirs)

if(SQLCIPHER_ENABLE_SHARED)
    install(TARGETS ${SQLCIPHER_LIB_NAME}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

if(SQLCIPHER_ENABLE_STATIC)
    install(TARGETS ${SQLCIPHER_LIB_NAME}_static
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

if(SQLCIPHER_ENABLE_CLI)
    install(TARGETS ${SQLCIPHER_CLI_NAME}_bin
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

# Install headers
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/sqlite3.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    RENAME ${SQLCIPHER_LIB_NAME}.h
)

# Create pkg-config file
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/sqlite3.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/sqlcipher.pc"
    @ONLY
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/sqlcipher.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)

# Tests (if enabled)
if(SQLCIPHER_ENABLE_TESTS)
    enable_testing()
    # Add test targets here if needed
endif()

# Summary
message(STATUS "")
message(STATUS "SQLCipher ${PROJECT_VERSION} Configuration Summary:")
message(STATUS "  Crypto Backend: ${SQLCIPHER_CRYPTO_BACKEND}")
message(STATUS "  Build shared library: ${SQLCIPHER_ENABLE_SHARED}")
message(STATUS "  Build static library: ${SQLCIPHER_ENABLE_STATIC}")
message(STATUS "  Build CLI: ${SQLCIPHER_ENABLE_CLI}")
message(STATUS "  Library name: ${SQLCIPHER_LIB_NAME}")
message(STATUS "  Header name: ${SQLCIPHER_LIB_NAME}.h")
message(STATUS "  CLI name: ${SQLCIPHER_CLI_NAME}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")