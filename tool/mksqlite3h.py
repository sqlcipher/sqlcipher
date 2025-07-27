#!/usr/bin/env python3
"""
Python replacement for mksqlite3h.tcl

This script constructs the "sqlite3.h" header file from the following sources:

1) The src/sqlite.h.in source file.  This is the template for sqlite3.h.
2) The VERSION file containing the current SQLite version number.
3) The manifest file from the fossil SCM.  This gives us the date.
4) The manifest.uuid file from the fossil SCM.  This gives the SHA1 hash.

This script performs processing on src/sqlite.h.in. It:

1) Adds SQLITE_EXTERN in front of the declaration of global variables,
2) Adds SQLITE_API in front of the declaration of API functions,
3) Replaces the string --VERS-- with the current library version,
   formatted as a string (e.g. "3.6.17"), and
4) Replaces the string --VERSION-NUMBER-- with current library version,
   formatted as an integer (e.g. "3006017").
5) Replaces the string --SOURCE-ID-- with the date and time and sha1
   hash of the fossil-scm manifest for the source tree.
6) Adds the SQLITE_CALLBACK calling convention macro in front of all
   callback declarations.

Example usage:
  python3 mksqlite3h.py ../sqlite [OPTIONS]
                    ^^^^^^^^^
                    Root of source tree

Where options are:
  --enable-recover          Include the sqlite3recover extension
  -o FILENAME               Write results to FILENAME instead of stdout
  --useapicall              SQLITE_APICALL instead of SQLITE_CDECL
"""

import os
import sys
import re
import subprocess
import argparse
from pathlib import Path


def get_version_number(version_str):
    """Convert version string like '3.6.17' to integer like 3006017"""
    parts = version_str.split('.')
    if len(parts) >= 3:
        return int(parts[0]) * 1000000 + int(parts[1]) * 1000 + int(parts[2])
    elif len(parts) == 2:
        return int(parts[0]) * 1000000 + int(parts[1]) * 1000
    else:
        return int(parts[0]) * 1000000


def get_source_id(top_dir, mksourceid_path):
    """Get source ID using mksourceid tool"""
    try:
        # Change to top directory for mksourceid
        old_cwd = os.getcwd()
        os.chdir(top_dir)

        # Run mksourceid
        result = subprocess.run([mksourceid_path, 'manifest'],
                              capture_output=True, text=True, check=True)
        source_id = result.stdout.strip()

        os.chdir(old_cwd)
        return source_id
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback: return a placeholder
        return "unknown-source-id"


def process_file(filepath, version_str, version_num, source_id, useapicall, out_file):
    """Process a single header file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Skip sqlite3.h includes when processing extension headers
    if 'sqlite3rtree.h' in str(filepath) or 'sqlite3session.h' in str(filepath) or 'fts5.h' in str(filepath):
        content = re.sub(r'#include\s+[<"]sqlite3\.h[>"]', '/* #include <sqlite3.h> */', content)

    # Replace version placeholders
    content = content.replace('--VERS--', version_str)
    content = content.replace('--VERSION-NUMBER--', str(version_num))
    content = content.replace('--SOURCE-ID--', source_id)

    # Process API declarations
    lines = content.split('\n')
    processed_lines = []

    # Patterns for API declarations
    var_pattern = re.compile(r'^[a-zA-Z][a-zA-Z_0-9 *]+sqlite3_[_a-zA-Z0-9]+(\[|;| =)')
    decl_patterns = [
        re.compile(r'^ *([a-zA-Z][a-zA-Z_0-9 ]+ \**)(sqlite3_[_a-zA-Z0-9]+)(\(.*)$'),
        re.compile(r'^ *([a-zA-Z][a-zA-Z_0-9 ]+ \**)(sqlite3session_[_a-zA-Z0-9]+)(\(.*)$'),
        re.compile(r'^ *([a-zA-Z][a-zA-Z_0-9 ]+ \**)(sqlite3changeset_[_a-zA-Z0-9]+)(\(.*)$'),
        re.compile(r'^ *([a-zA-Z][a-zA-Z_0-9 ]+ \**)(sqlite3changegroup_[_a-zA-Z0-9]+)(\(.*)$'),
        re.compile(r'^ *([a-zA-Z][a-zA-Z_0-9 ]+ \**)(sqlite3rebaser_[_a-zA-Z0-9]+)(\(.*)$'),
    ]

    # Functions that need cdecl calling convention
    cdecl_list = {
        'sqlite3_config', 'sqlite3_db_config', 'sqlite3_log', 'sqlite3_mprintf',
        'sqlite3_snprintf', 'sqlite3_test_control', 'sqlite3_vtab_config'
    }

    for line in lines:
        # Handle variable declarations
        if var_pattern.match(line) and not line.strip().startswith('typedef'):
            line = f"SQLITE_API {line}"
        else:
            # Handle function declarations
            for pattern in decl_patterns:
                match = pattern.match(line)
                if match:
                    rettype, funcname, rest = match.groups()
                    line = f"SQLITE_API {rettype.strip()}"
                    if not rettype.strip().endswith('*'):
                        line += " "

                    if useapicall:
                        if funcname in cdecl_list:
                            line += "SQLITE_CDECL "
                        else:
                            line += "SQLITE_APICALL "

                    line += f"{funcname}{rest}"
                    break

        # Handle callback declarations
        if useapicall:
            line = line.replace('(*sqlite3_syscall_ptr)', '(SQLITE_SYSAPI *sqlite3_syscall_ptr)')
            line = re.sub(r'\(\*', '(SQLITE_CALLBACK *', line)

        processed_lines.append(line)

    return '\n'.join(processed_lines)


def main():
    parser = argparse.ArgumentParser(description='Generate sqlite3.h from sqlite.h.in')
    parser.add_argument('top_dir', help='Root directory of source tree')
    parser.add_argument('--enable-recover', action='store_true',
                       help='Include the sqlite3recover extension')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('--useapicall', action='store_true',
                       help='Use SQLITE_APICALL instead of SQLITE_CDECL')

    args = parser.parse_args()

    top_dir = Path(args.top_dir)

    # Determine output
    if args.output:
        out_file = open(args.output, 'w', encoding='utf-8')
    else:
        out_file = sys.stdout

    # Read version
    version_file = top_dir / 'VERSION'
    with open(version_file, 'r', encoding='utf-8') as f:
        version_str = f.read().strip()

    version_num = get_version_number(version_str)

    # Get source ID
    mksourceid_path = Path(__file__).parent / 'mksourceid'
    if not mksourceid_path.exists() and os.name == 'nt':
        mksourceid_path = Path(__file__).parent / 'mksourceid.exe'

    source_id = get_source_id(top_dir, str(mksourceid_path))

    # List of files to process
    filelist = [
        top_dir / 'src' / 'sqlite.h.in',
        top_dir / 'ext' / 'rtree' / 'sqlite3rtree.h',
        top_dir / 'ext' / 'session' / 'sqlite3session.h',
        top_dir / 'ext' / 'fts5' / 'fts5.h',
    ]

    if args.enable_recover:
        filelist.append(top_dir / 'ext' / 'recover' / 'sqlite3recover.h')

    # Process each file
    for filepath in filelist:
        if not filepath.exists():
            print(f"Warning: {filepath} not found", file=sys.stderr)
            continue

        if 'sqlite.h.in' not in str(filepath):
            print(f"/******** Begin file {filepath.name} *********/", file=out_file)

        content = process_file(filepath, version_str, version_num, source_id,
                             args.useapicall, out_file)
        print(content, file=out_file)

        if 'sqlite.h.in' not in str(filepath):
            print(f"/******** End of {filepath.name} *********/", file=out_file)

    print("#endif /* SQLITE3_H */", file=out_file)

    if args.output:
        out_file.close()


if __name__ == '__main__':
    main()