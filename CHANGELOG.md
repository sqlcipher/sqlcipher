# SQLCipher Change Log
Notable changes to this project are documented in this file.

## [unreleased] - (? 2025 - [unreleased changes])

## [4.8.0] - (? 2025 - [4.8.0 changes])
- Fixes regression in `PRAGMA cipher_migrate` where an error would be thrown when migrating a current-version database
- Adds selective locking in critical sections of the library for shared cache connections (Note: use of shared cache is still strongly discouraged)

## [4.7.0] - (March 2025 - [4.7.0 changes])
- Updates baseline to upstream SQLite 3.49.1, including complete upstream SQLite refactoring of build system to use autosetup
- Significantly refactors and optimizes library initialization and cleanup
- Allocates majority of requisite memory at startup to improve memory locking on constrained platforms (i.e. Android and Windows) and reduce fragmentation
- Expands `sqlcipher_provider` interface to include `init` and `shutdown` functions
- Adds support for `.recover` shell command on corrupt databases with a full plaintext first page
- Performs fast random overwrite of freed memory segments for improved security
- Adds basic obfuscation of context key material for improved security
- Generates keyspecs dynamically on demand instead of storing them
- Expands keyspec/raw key format to accept key, HMAC key, and salt
- Improves error handling in `sqlcipher_export()` and `PRAGMA cipher_migrate`
- Allows setting custom compile-time default cryptographic provider via the `SQLCIPHER_CRYPTO_CUSTOM` macro
- Removes support for end-of-life OpenSSL versions older than 3.0
__BREAKING CHANGE__: `SELECT` statements (now also including schema independent queries like `SELECT 1`) cannot be executed on encrypt ed databases prior to setting the database key (behavior inherited from upstream SQLite)
- __BREAKING CHANGE__: Renames `configure` flag `--enable-tempstore=yes` to `--with-tempstore=yes` for alignment with SQLite (change required for upstream SQLite autosetup)
- __BREAKING CHANGE__: Renames default executable and library build outputs from `sqlcipher` and `libsqlcipher` to `sqlite3` and `libsqlite3` (for alignment with SQLite)
- __BREAKING CHANGE__: Removes `configure` flag `--with-crypto-lib` (replace with appropriate `-DSQLCIPHER_CRYPTO_*` CFLAG)
- __BREAKING CHANGE__: Requires defining `SQLITE_EXTRA_INIT=sqlcipher_extra_init` and `SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown` at compile time for optimized library initialization and cleanup
- __BREAKING CHANGE__: Enforces thread safe mode (i.e. `SQLITE_THREADSAFE` of 1 or 2) and temporary storage (i.e. `SQLITE_TEMP_STORE` of 2 or 3) settings at compile time

## [4.6.1] - (August 2024 - [4.6.1 changes])
- Updates baseline to upstream SQLite 3.46.1
- Significant refactor to merge `crypto.h`, `crypto.c`, and `crypto_impl.c` into a single `sqlcipher.c` source file for simplicity.
- Updates minimum working set size on windows to increase lockable pages
- Adds new `PRAGMA cipher_log_source` for filtering log output on higher verbosity levels
- Improves log output by including the log level and source prior to message
- Improves error logging in `PRAGMA cipher_migrate`
- Fixes issue where log level and target would be overwritten if set prior to initialization
- Corrects Podspec license element to use specific BSD 3 Clause
- Fixes default log output to console for macOS

## [4.6.0] - (May 2024 - [4.6.0 changes])
- Sets default log level to WARN
- Sends default log output to: logcat for Android; Console for iOS and macOS; and stderr for all other platforms
- General improvements to log level assignments, output, and sanitization
- Fixes Apple Privacy Manifest by removing empty NSPrivacyCollectedDataType from PrivacyInfo.xcprivacy
- Moves Swift support defines for podspec user_target_xcconfig so they only apply to the consuming project

## [4.5.7] - (April 2024 - [4.5.7 changes])
- Updates baseline to upstream SQLite 3.45.3
- Adds "device" logging and profile target using os_log for Apple (and logcat on Android)
- Fixes issues compiling with SQLITE_OMIT_LOG
- fixes malformed man page caused by old merge conflict
- Updates podspec for current Xcode versions, improved Swift support, and Privacy Manifest

## [4.5.6] - (January 2024 - [4.5.6 changes])
- Updates baseline to upstream SQLite 3.44.2
- Improve PRAGMA cipher_integrity check to report expected page size if invalid
- Implement PRAGMA page_size compatibility with PRAGMA cipher_page_size so both will operate properly on encrypted databases
- Updates LICENSE.md with SQLCipher license to avoid ambiguity and remove redundance

## [4.5.5] - (August 2023 - [4.5.5 changes])
- Updates baseline to upstream SQLite 3.42.0
- Do not allow key to be changed on a connection after it has been successfully used for an encryption or decryption operation to prevent accidental database corruption
- Raise an error if a rekey operation is attempted on an unencrypted database
- Raise an error when a key or rekey operation is passed an empty key
- Minor improvements to constant time functions
- Miscellaneous code and comment cleanup

## [4.5.4] - (April 2023 - [4.5.4 changes])
- Updates baseline to upstream SQLite 3.41.2
- Updates minimum Apple SDK versions in podspec for new Xcode compatibility
- Return runtime OpenSSL version from PRAGMA cipher_provider_version (instead of hardcoded value)
- Adds guard against zero block size and crash if cryptographic provider initialization fails
- When an ATTACH occurs creating a new encrypted database as the first operation after keying the main database, the new database will have the same salt value.

## [4.5.3] - (December 2022 - [4.5.3 changes])
- Updates baseline to upstream SQLite 3.39.4

## [4.5.2] - (August 2022 - [4.5.2 changes])
- Updates source code baseline to upstream SQLite 3.39.2
- Simplifies OpenSSL version conditional code
- Fixes issue where PRAGMA cipher_memory_security could report OFF when it was actually ON
- Fixes fix unfreed OpenSSL allocation when compiled against version 3
- Fixes support for building against recent versions of BoringSSL

## [4.5.1] - (March 2022 - [4.5.1 changes])
- Updates source code baseline to upstream SQLite 3.37.2
- Adds PRAGMA cipher_log and cipher_log_level features to allow logging of TRACE, DEBUG, INFO, WARN, and ERROR messages to stdout, stderr, file, or logcat
- Modifies PRAGMA cipher_profile to use sqlite3_trace_v2 and adds logcat target for Android
- Updates OpenSSL provider to use EVP_MAC API with version 3+
- Adds new PRAGMA cipher_test_on, cipher_test_off, and cipher_test_rand (available when compiled with -DSQLCIPHER_TEST) to facilitate simulation of error conditions
- Fixes PRAGMA cipher_integrity_check to work properly with databases larger that 2GB
- Fixes missing munlock before free for context internal buffer (thanks to Fedor Indutny)

## [4.5.0] - (October 2021 - [4.5.0 changes])
- Updates baseline to upstream SQLite 3.36.0
- Changes the enhanced memory security feature to be DISABLED by default; once enabled by PRAGMA cipher_memory_security = ON, it can't be turned off for the lifetime of the process
- Changes PRAGMA cipher_migrate to permanently enter an error state if a migration fails
- Fixes memory locking/unlocking issue with realloc implementation on hardened runtimes when memory security is enabled
- Fixes cipher_migrate to cleanup the temporary database if a migration fails
- Removes logging of non-string pointers when compiling with trace level logging

## [4.4.3] - (February 2021 - [4.4.3 changes])
- Updates baseline to ustream SQLite 3.34.1
- Fixes sqlcipher_export handling of NULL parameters
- Removes randomization of rekey-delete tests to avoid false test failures
- Changes internal usage of sqlite_master to sqlite_schema
- Omits unusued profiling function under certain defines to avoid compiler warnings

## [4.4.2] - (November 2020 - [4.4.2 changes])
- Improve error handling to resolve potential corruption if an encryption operation failed while operating in WAL mode
- Changes to OpenSSL library cryptographic provider to reduce initialization complexity
- Adjust cipher_integrity_check to skip locking page to avoid a spurious error report for very large databases
- Miscellaneous code and comment cleanup

## [4.4.1] - (October 2020 - [4.4.1 changes])
- Updates baseline to upstream SQLite 3.33.0
- Fixes double-free bug in cipher_default_plaintext_header_size
- Changes SQLCipher tests to use suite runner
- Improvement to cipher_integrity_check tests to minimize false negatives
- Deprecates PRAGMA cipher_store_pass

## [4.4.0] - (May 2020 - [4.4.0 changes])
- Updates baseline to upstream SQLite 3.31.0
- Adjusts shell to report SQLCipher version alongside SQLite version
- Fixes various build warnings under several compilers
- Removes unused id and status functions from provider interface

## [4.3.0] - (November 2019 - [4.3.0 changes])
- Updates baseline to upstream SQLite 3.30.1
- PRAGMA key now returns text result value "ok" after execution
- Adjusts backup API so that encrypted to encrypted backups are permitted
- Adds NSS crypto provider implementation
- Fixes OpenSSL provider compatibility with BoringSSL
- Separates memory related traces to reduce verbosity of logging
- Fixes output of PRAGMA cipher_integrity_check on big endian platforms
- Cryptograpic provider interface cleanup
- Rework of mutex allocation and management
- Resolves miscellaneous build warnings
- Force error state at database pager level if SQLCipher initialization fails

## [4.2.0] - (May 2019 - [4.2.0 changes])
- Adds PRAGMA cipher_integrity_check to perform independent verification of page HMACs
- Updates baseline to upstream SQLite 3.28.0
- Improves PRAGMA cipher_migrate to handle keys containing non-terminating zero bytes

## [4.1.0] - (March 2019 - [4.1.0 changes])
- Defer reading salt from header until key derivation is triggered
- Clarify usage of sqlite3_rekey for plaintext databases in header
- Normalize attach behavior when key is not yet derived
- Adds PRAGMA cipher_settings to query current database codec settings
- Adds PRAGMA cipher_default_settings to query current default SQLCipher options
- PRAGMA cipher_hmac_pgno is now deprecated
- PRAGMA cipher_hmac_salt_mask is now deprecated
- PRAGMA fast_kdf_iter is now deprecated
- Improve sqlcipher_export routine and restore all database flags
- Clear codec data buffers if a crypographic provider operation fails
- Disable backup API for encrypted databases (this was previously documented as not-working and non-supported, but will now explicitly error out on initialization)
- Updates baseline to upstream SQLite 3.27.2

## [4.0.1] - (December 2018 - [4.0.1 changes])
- Based on upstream SQLite 3.26.0 (addresses SQLite “Magellan” issue)
- Adds PRAGMA cipher_compatibility and cipher_default_compatibility which take automatcially configure appropriate compatibility settings for the specified SQLCipher major version number
- Filters attach statements with KEY parameters from readline history
- Fixes crash in command line shell with empty input (i.e. ^D)
- Fixes warnings when compiled with strict-prototypes

## [4.0.0] - (November 2018 - [4.0.0 changes])
### Changed
- Default page size for databases increased to 4096 bytes (up from 1024) *
- Default PBKDF2 iterations increased to 256,000 (up from 64,000) *
- Default KDF algorithm is now PBKDF2-HMAC-SHA512 (from PBKDF2-HMAC-SHA1) *
- Default HMAC algorithm is now HMAC-SHA512 (from HMAC-SHA1) *
- PRAGMA cipher is now disabled and no longer supported (after multi-year deprecation) *
- PRAGMA rekey_cipher is now disabled and no longer supported *
- PRAGMA rekey_kdf_iter is now disabled and no longer supported *
- By default all memory allocated internally by SQLite before the memory is wiped before it is freed 
- PRAGMA cipher_memory_security: allows full memory wiping to be disabled for performance when the feature is not required
- PRAGMA cipher_kdf_algorithm, cipher_default_kdf_algorithm to control KDF algorithm selection between PBKDF2-HMAC-SHA1, PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA512
- PRAGMA cipher_hmac_algorithm, cipher_default_hmac_algorithm to control HMAC algorithm selection between HMAC-SHA1, HMAC-SHA256 and PBKDF2-HMAC-SHA512
- Based on upstream SQLite 3.25.2
- When compiled with readline support, PRAGMA key and rekey lines will no longer be
  saved to history
- Adds second optional parameter to sqlcipher_export to specify source database to
  support bidirectional exports
- Fixes compatibility with LibreSSL 2.7.0+
- Fixes compatibility with OpenSSL 1.1.x
- Simplified and improved performance for PRAGMA cipher_migrate when migrating older database versions
- Refactoring of SQLCipher tests into separate files by test type
- PRAGMA cipher_plaintext_header_size and cipher_default_plaintext_header_size: allocates a portion of the database header which will not be encrypted to allow identification as a SQLite database
- PRAGMA cipher_salt: retrieve or set the salt value for the database
- Adds Podspec for using tagged versions of SQLCipher
- Define SQLCIPHER_PROFILE_USE_FOPEN for WinXP support
- Improved error handling for cryptographic providers
- Improved memory handling for PRAGMA commands that return values
- Improved version reporting to assist with identification of distribution
- Major rewrite and simplification of internal codec and pager extension
- Fixes compilation with --disable-amalgamation
- Removes sqlcipher.xcodeproj build support

## [3.4.2] - (December 2017 - [3.4.2 changes])
### Added
- Added support for building with LibreSSL

### Changed
- Merge upstream SQLite 3.20.1
- Text strings for `SQLITE_ERROR` and `SQLITE_NOTADB` changed to match upstream SQLite
- Remove static modifier for codec password functions
- Page alignment for `mlock`
- Fix segfault in `sqlcipher_cipher_ctx_cmp` during rekey operation
- Fix `sqlcipher_export` and `cipher_migrate` when tracing API in use
- Validate codec page size when setting
- Guard OpenSSL initialization and cleanup routines
- Allow additional linker options to be passed via command line for Windows platforms

## [3.4.1] - (December 2016 - [3.4.1 changes])
### Added
- Added support for OpenSSL 1.1.0

### Changed
- Merged upstream SQLite 3.15.2

## [3.4.0] - (April 2016 - [3.4.0 changes])
### Added
- Added `PRAGMA cipher_provider_version`

### Changed
- Merged upstream SQLite 3.11.0

### Deprecated
- Deprecated `PRAGMA cipher` command

## [3.3.1] - (July 2015 - [3.3.1 changes])
### Changed
- Merge upstream SQLite 3.8.10.2
- Fixed segfault when provided an invalid cipher name
- Check for codec context when performing `PRAGMA cipher_store_pass`
- Remove extraneous null check in `PRAGMA cipher_migrate`

## [3.3.0] - (March 2015 - [3.3.0 changes])
### Added
- Added FIPS API calls within the OpenSSL crypto provider
- `PRAGMA cipher_default_page_size` - support for attaching non-default page sizes

### Changed
- Merged upstream SQLite 3.8.8.3

## [3.2.0] - (September 2014 - [3.2.0 changes])
### Added
- Added `PRAGMA cipher_store_pass`

### Changed
- Merged upstream SQLite 3.8.6
- Renmed README to README.md

## [3.1.0] - (April 2014 - [3.1.0 changes])
### Added
- Added `PRAGMA cipher_profile`

### Changed
- Merged upstream SQLite 3.8.4.3

## [3.0.1] - (December 2013 - [3.0.1 changes])
### Added
- Added `PRAGMA cipher_add_random` to source external entropy

### Changed
- Fix `PRAGMA cipher_migrate` to handle passphrases longer than 64 characters & raw keys
- Improvements to the libtomcrypt provider

## [3.0.0] - (November 2013 - [3.0.0 changes])
### Added
- Added `PRAGMA cipher_migrate` to migrate older database file formats

### Changed
- Merged upstream SQLite 3.8.0.2
- Remove usage of VirtualLock/Unlock on WinRT and Windows Phone
- Ignore HMAC read during Btree file copy
- Fix lib naming for pkg-config
- Use _v2 version of `sqlite3_key` and `sqlite3_rekey`
- Update xcodeproj file

### Security
- Change KDF iteration length from 4,000 to 64,000

[unreleased]: https://github.com/sqlcipher/sqlcipher/tree/prerelease
[unreleased changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.7.2...prerelease
[4.7.2]: https://github.com/sqlcipher/sqlcipher/tree/v4.7.2
[4.7.2 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.7.0...v4.7.2
[4.7.0]: https://github.com/sqlcipher/sqlcipher/tree/v4.7.0
[4.7.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.6.1...v4.7.0
[4.6.1]: https://github.com/sqlcipher/sqlcipher/tree/v4.6.1
[4.6.1 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.6.0...v4.6.1
[4.6.0]: https://github.com/sqlcipher/sqlcipher/tree/v4.6.0
[4.6.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.5.7...v4.6.0
[4.5.7]: https://github.com/sqlcipher/sqlcipher/tree/v4.5.7
[4.5.7 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.5.6...v4.5.7
[4.5.6]: https://github.com/sqlcipher/sqlcipher/tree/v4.5.6
[4.5.6 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.5.5...v4.5.6
[4.5.5]: https://github.com/sqlcipher/sqlcipher/tree/v4.5.5
[4.5.5 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.5.4...v4.5.5
[4.5.4]: https://github.com/sqlcipher/sqlcipher/tree/v4.5.4
[4.5.4 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.5.3...v4.5.4
[4.5.3]: https://github.com/sqlcipher/sqlcipher/tree/v4.5.3
[4.5.3 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.5.2...v4.5.3
[4.5.2]: https://github.com/sqlcipher/sqlcipher/tree/v4.5.2
[4.5.2 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.5.1...v4.5.2
[4.5.1]: https://github.com/sqlcipher/sqlcipher/tree/v4.5.1
[4.5.1 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.5.0...v4.5.1
[4.5.0]: https://github.com/sqlcipher/sqlcipher/tree/v4.5.0
[4.5.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.4.3...v4.5.0
[4.4.3]: https://github.com/sqlcipher/sqlcipher/tree/v4.4.3
[4.4.3 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.4.2...v4.4.3
[4.4.2]: https://github.com/sqlcipher/sqlcipher/tree/v4.4.2
[4.4.2 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.4.1...v4.4.2
[4.4.1]: https://github.com/sqlcipher/sqlcipher/tree/v4.4.1
[4.4.1 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.4.0...v4.4.1
[4.4.0]: https://github.com/sqlcipher/sqlcipher/tree/v4.4.0
[4.4.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.3.0...v4.4.0
[4.3.0]: https://github.com/sqlcipher/sqlcipher/tree/v4.3.0
[4.3.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.2.0...v4.3.0
[4.2.0]: https://github.com/sqlcipher/sqlcipher/tree/v4.2.0
[4.2.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.1.0...v4.2.0
[4.1.0]: https://github.com/sqlcipher/sqlcipher/tree/v4.1.0
[4.1.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.0.1...v4.1.0
[4.0.1]: https://github.com/sqlcipher/sqlcipher/tree/v4.0.1
[4.0.1 changes]: https://github.com/sqlcipher/sqlcipher/compare/v4.0.0...v4.0.1
[4.0.0]: https://github.com/sqlcipher/sqlcipher/tree/v4.0.0
[4.0.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v3.4.2...v4.0.0
[3.4.2]: https://github.com/sqlcipher/sqlcipher/tree/v3.4.2
[3.4.2 changes]: https://github.com/sqlcipher/sqlcipher/compare/v3.4.1...v3.4.2
[3.4.1]: https://github.com/sqlcipher/sqlcipher/tree/v3.4.1
[3.4.1 changes]: https://github.com/sqlcipher/sqlcipher/compare/v3.4.0...v3.4.1
[3.4.0]: https://github.com/sqlcipher/sqlcipher/tree/v3.4.0
[3.4.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v3.3.1...v3.4.0
[3.3.1]: https://github.com/sqlcipher/sqlcipher/tree/v3.3.1
[3.3.1 changes]: https://github.com/sqlcipher/sqlcipher/compare/v3.3.0...v3.3.1
[3.3.0]: https://github.com/sqlcipher/sqlcipher/tree/v3.3.0
[3.3.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v3.2.0...v3.3.0
[3.2.0]: https://github.com/sqlcipher/sqlcipher/tree/v3.2.0
[3.2.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/sqlcipher/sqlcipher/tree/v3.1.0
[3.1.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v3.0.1...v3.1.0
[3.0.1]: https://github.com/sqlcipher/sqlcipher/tree/v3.0.1
[3.0.1 changes]: https://github.com/sqlcipher/sqlcipher/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/sqlcipher/sqlcipher/tree/v3.0.0
[3.0.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v2.2.0...v3.0.0
[2.2.0]: https://github.com/sqlcipher/sqlcipher/tree/v2.2.0
[2.2.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/sqlcipher/sqlcipher/tree/v2.1.1
[2.1.1 changes]: https://github.com/sqlcipher/sqlcipher/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/sqlcipher/sqlcipher/tree/v2.1.0
[2.1.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v2.0.6...v2.1.0
[2.0.6]: https://github.com/sqlcipher/sqlcipher/tree/v2.0.6
[2.0.6 changes]: https://github.com/sqlcipher/sqlcipher/compare/v2.0.5...v2.0.6
[2.0.5]: https://github.com/sqlcipher/sqlcipher/tree/v2.0.5
[2.0.5 changes]: https://github.com/sqlcipher/sqlcipher/compare/v2.0.3...v2.0.5
[2.0.3]: https://github.com/sqlcipher/sqlcipher/tree/v2.0.3
[2.0.3 changes]: https://github.com/sqlcipher/sqlcipher/compare/v2.0.0...v2.0.3
[2.0.0]: https://github.com/sqlcipher/sqlcipher/tree/v2.0.0
[2.0.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/v1.1.10...v2.0.0
[1.1.10]: https://github.com/sqlcipher/sqlcipher/tree/v1.1.10
[1.1.10 changes]: https://github.com/sqlcipher/sqlcipher/compare/v1.1.9...v1.1.10
[1.1.9]: https://github.com/sqlcipher/sqlcipher/tree/v1.1.9
[1.1.9 changes]: https://github.com/sqlcipher/sqlcipher/compare/v1.1.8...v1.1.9
[1.1.8]: https://github.com/sqlcipher/sqlcipher/tree/v1.1.8
[1.1.8 changes]: https://github.com/sqlcipher/sqlcipher/compare/v1.1.7...v1.1.8
[1.1.7]: https://github.com/sqlcipher/sqlcipher/tree/v1.1.7
[1.1.7 changes]: https://github.com/sqlcipher/sqlcipher/compare/v1.1.6...v1.1.7
[1.1.6]: https://github.com/sqlcipher/sqlcipher/tree/v1.1.6
[1.1.6 changes]: https://github.com/sqlcipher/sqlcipher/compare/v1.1.5...v1.1.6
[1.1.5]: https://github.com/sqlcipher/sqlcipher/tree/v1.1.5
[1.1.5 changes]: https://github.com/sqlcipher/sqlcipher/compare/v1.1.4...v1.1.5
[1.1.4]: https://github.com/sqlcipher/sqlcipher/tree/v1.1.4
[1.1.4 changes]: https://github.com/sqlcipher/sqlcipher/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/sqlcipher/sqlcipher/tree/v1.1.3
[1.1.3 changes]: https://github.com/sqlcipher/sqlcipher/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/sqlcipher/sqlcipher/tree/v1.1.2
[1.1.2 changes]: https://github.com/sqlcipher/sqlcipher/compare/v1.1.1...v1.1.1
[1.1.1]: https://github.com/sqlcipher/sqlcipher/tree/v1.1.1
[1.1.1 changes]: https://github.com/sqlcipher/sqlcipher/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/sqlcipher/sqlcipher/tree/v1.1.0
[1.1.0 changes]: https://github.com/sqlcipher/sqlcipher/compare/617ed01...v1.1.0
