## SQLCipher

SQLCipher is an SQLite extension that provides transparent 256-bit AES encryption of 
database files. Pages are encrypted before being written to disk and are decrypted 
when read back. Due to the small footprint and great performance it’s ideal for 
protecting embedded application databases and is well suited for mobile development.

The official SQLCipher software site is http://sqlcipher.net

SQLCipher was initially developed by Stephen Lombardo at Zetetic LLC 
(sjlombardo@zetetic.net) as the encrypted database layer for Strip, 
an iPhone data vault and password manager (http://getstrip.com).   

## Features

- Fast performance with as little as 5-15% overhead for encryption on many operations
- 100% of data in the database file is encrypted
- Good security practices (CBC mode, key derivation)
- Zero-configuration and application level cryptography
- Algorithms provided by the peer reviewed OpenSSL crypto library.
- Configurable crypto providers

## Compiling

Building SQLCipher is almost the same as compiling a regular version of 
SQLite with two small exceptions: 

 1. You must define SQLITE_HAS_CODEC and SQLITE_TEMP_STORE=2 when building sqlcipher
 2. You need to link against a OpenSSL's libcrypto 
 
Example Static linking (replace /opt/local/lib with the path to libcrypto.a)

	$ ./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC" \
		LDFLAGS="/opt/local/lib/libcrypto.a"
	$ make

Example Dynamic linking

	$ ./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC" \
		LDFLAGS="-lcrypto"
	$ make

## Encrypting a database

To specify an encryption passphrase for the database via the SQL interface you 
use a pragma. The passphrase you enter is passed through PBKDF2 key derivation to
obtain the encryption key for the database 

	PRAGMA key = 'passphrase';

Alternately, you can specify an exact byte sequence using a blob literal. If you
use this method it is your responsibility to ensure that the data you provide a
64 character hex string, which will be converted directly to 32 bytes (256 bits) of 
key data without key derivation.

	PRAGMA key = "x'2DD29CA851E7B56E4697B0E1F08507293D761A05CE4D1B628663F411A8086D99'";

To encrypt a database programatically you can use the sqlite3_key function. 
The data provided in pKey is converted to an encryption key according to the 
same rules as PRAGMA key. 

	int sqlite3_key(sqlite3 *db, const void *pKey, int nKey);

PRAGMA key or sqlite3_key should be called as the first operation when a database is open.

## Changing a database key

To change the encryption passphrase for an existing database you may use the rekey pragma
after you've supplied the correct database password;

	PRAGMA key = 'passphrase'; -- start with the existing database passphrase
	PRAGMA rekey = 'new-passphrase'; -- rekey will reencrypt with the new passphrase

The hexrekey pragma may be used to rekey to a specific binary value

	PRAGMA rekey = "x'2DD29CA851E7B56E4697B0E1F08507293D761A05CE4D1B628663F411A8086D99'";

This can be accomplished programtically by using sqlite3_rekey;
  
	sqlite3_rekey(sqlite3 *db, const void *pKey, int nKey)

## Support

The primary avenue for support and discussions is the SQLCipher users mailing list:

http://groups.google.com/group/sqlcipher

Issues or support questions on using SQLCipher should be entered into the 
GitHub Issue tracker:

http://github.com/sjlombardo/sqlcipher/issues

Please DO NOT post issues, support questions, or other problems to blog 
posts about SQLCipher as we do not monitor them frequently.

If you are using SQLCipher in your own software please let us know at 
support@zetetic.net!

## License

Copyright (c) 2008, ZETETIC LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the ZETETIC LLC nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## End SQLCipher

This directory contains source code to 

  SQLite: An Embeddable SQL Database Engine

To compile the project, first create a directory in which to place
the build products.  It is recommended, but not required, that the
build directory be separate from the source directory.  Cd into the
build directory and then from the build directory run the configure
script found at the root of the source tree.  Then run "make".

For example:

	tar xzf sqlite.tar.gz    ;#  Unpack the source tree into "sqlite"
    mkdir bld                ;#  Build will occur in a sibling directory
    cd bld                   ;#  Change to the build directory
    ../sqlite/configure      ;#  Run the configure script
    make                     ;#  Run the makefile.
    make install             ;#  (Optional) Install the build products

The configure script uses autoconf 2.61 and libtool.  If the configure
script does not work out for you, there is a generic makefile named
"Makefile.linux-gcc" in the top directory of the source tree that you
can copy and edit to suit your needs.  Comments on the generic makefile
show what changes are needed.

The linux binaries on the website are created using the generic makefile,
not the configure script.  The windows binaries on the website are created
using MinGW32 configured as a cross-compiler running under Linux.  For 
details, see the ./publish.sh script at the top-level of the source tree.
The developers do not use teh configure script.

SQLite does not require TCL to run, but a TCL installation is required
by the makefiles.  SQLite contains a lot of generated code and TCL is
used to do much of that code generation.  The makefile also requires
AWK.

Contacts:

  http://www.sqlite.org/
