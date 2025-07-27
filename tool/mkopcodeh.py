#!/usr/bin/env python3
"""
Python replacement for mkopcodeh.tcl

Generate the file opcodes.h.

This Python script scans a concatenation of the parse.h output file from the
parser and the vdbe.c source file in order to generate the opcodes numbers
for all opcodes.

The lines of the vdbe.c that we are interested in are of the form:

      case OP_aaaa:      /* same as TK_bbbbb */

The TK_ comment is optional.  If it is present, then the value assigned to
the OP_ is the same as the TK_ value.  If missing, the OP_ value is assigned
a small integer that is different from every other OP_ value.

We go to the trouble of making some OP_ values the same as TK_ values
as an optimization.  During parsing, things like expression operators
are coded with TK_ values such as TK_ADD, TK_DIVIDE, and so forth.  Later
during code generation, we need to generate corresponding opcodes like
OP_Add and OP_Divide.  By making TK_ADD==OP_Add and TK_DIVIDE==OP_Divide,
code to translate from one to the other is avoided.  This makes the
code generator smaller and faster.

This script also scans for lines of the form:

      case OP_aaaa:       /* jump, in1, in2, in3, out2, out3 */

When such comments are found on an opcode, it means that certain
properties apply to that opcode.  Set corresponding flags using the
OPFLG_INITIALIZER macro.
"""

import sys
import re
from collections import defaultdict


def parse_input():
    """Parse input from stdin (concatenated parse.h and vdbe.c)"""
    tk_values = {}
    opcodes = {}
    used = {}
    def_val = {}
    same_as = {}
    current_op = None
    prev_name = None
    n_op = 0
    n_group = 0
    groups = defaultdict(list)

    # Properties for each opcode
    jump = {}
    jump0 = {}
    in1 = {}
    in2 = {}
    in3 = {}
    out2 = {}
    out3 = {}
    ncycle = {}
    param_used = {}
    synopsis = {}
    order = []

    for line in sys.stdin:
        line = line.rstrip()

        # Remember the TK_ values from the parse.h file
        tk_match = re.match(r'^#define TK_(\w+)\s+(\d+)', line)
        if tk_match:
            tk_name = f"TK_{tk_match.group(1)}"
            tk_value = int(tk_match.group(2))
            tk_values[tk_name] = tk_value
            continue

        # Find "/* Opcode: " lines in the vdbe.c file
        opcode_match = re.match(r'^.. Opcode:\s+(\w+)', line)
        if opcode_match:
            current_op = f"OP_{opcode_match.group(1)}"
            # Parse parameters (P1, P2, P3, P4, P5)
            m = 0
            if 'P1' in line:
                m |= 1
            if 'P2' in line:
                m |= 2
            if 'P3' in line:
                m |= 4
            if 'P4' in line:
                m |= 8
            if 'P5' in line:
                m |= 16
            param_used[current_op] = m
            continue

        # Find "** Synopsis: " lines
        synopsis_match = re.match(r'^.. Synopsis:\s+(.*)', line)
        if synopsis_match and current_op:
            synopsis[current_op] = synopsis_match.group(1).strip()
            continue

        # Scan for "case OP_aaaa:" lines in the vdbe.c file
        case_match = re.match(r'^case\s+(OP_\w+):', line)
        if case_match:
            name = case_match.group(1)
            if name == "OP_Abortable":
                continue  # put OP_Abortable last

            opcodes[name] = -1
            groups[name] = 0
            jump[name] = 0
            jump0[name] = 0
            in1[name] = 0
            in2[name] = 0
            in3[name] = 0
            out2[name] = 0
            out3[name] = 0
            ncycle[name] = 0

            # Parse properties from the comment part of the case line
            comment_match = re.search(r'/\*\s*(.*?)\s*\*/', line)
            if comment_match:
                comment = comment_match.group(1)
                # Parse "same as TK_xxx" part
                same_match = re.search(r'same\s+as\s+(TK_\w+)', comment)
                if same_match:
                    sym = same_match.group(1)
                    if sym in tk_values:
                        val = tk_values[sym]
                        opcodes[name] = val
                        used[val] = 1
                        same_as[val] = sym
                        def_val[val] = name

                # Parse properties
                if 'group' in comment:
                    groups[name] = 1
                if 'jump' in comment:
                    jump[name] = 1
                if 'in1' in comment:
                    in1[name] = 1
                if 'in2' in comment:
                    in2[name] = 1
                if 'in3' in comment:
                    in3[name] = 1
                if 'out2' in comment:
                    out2[name] = 1
                if 'out3' in comment:
                    out3[name] = 1
                if 'ncycle' in comment:
                    ncycle[name] = 1
                if 'jump0' in comment:
                    jump[name] = 1
                    jump0[name] = 1

            # Handle grouping
            if groups[name]:
                new_group = 0
                if n_group not in groups or (prev_name and not groups.get(prev_name, 0)):
                    new_group = 1
                groups[n_group].append(name)
                if new_group:
                    n_group += 1
            else:
                if prev_name and groups.get(prev_name, 0):
                    n_group += 1

            order.append(name)
            prev_name = name
            n_op += 1

    return {
        'tk_values': tk_values,
        'opcodes': opcodes,
        'used': used,
        'def_val': def_val,
        'same_as': same_as,
        'groups': groups,
        'jump': jump,
        'jump0': jump0,
        'in1': in1,
        'in2': in2,
        'in3': in3,
        'out2': out2,
        'out3': out3,
        'ncycle': ncycle,
        'param_used': param_used,
        'synopsis': synopsis,
        'order': order,
        'n_op': n_op,
        'n_group': n_group
    }


def generate_opcodes(data):
    """Generate the opcodes.h file content"""
    tk_values = data['tk_values']
    opcodes = data['opcodes']
    used = data['used']
    def_val = data['def_val']
    same_as = data['same_as']
    groups = data['groups']
    jump = data['jump']
    jump0 = data['jump0']
    in1 = data['in1']
    in2 = data['in2']
    in3 = data['in3']
    out2 = data['out2']
    out3 = data['out3']
    ncycle = data['ncycle']
    synopsis = data['synopsis']
    order = data['order']
    n_op = data['n_op']
    n_group = data['n_group']

    # Add special opcodes
    for name in ['OP_Noop', 'OP_Explain', 'OP_Abortable']:
        jump[name] = 0
        jump0[name] = 0
        in1[name] = 0
        in2[name] = 0
        in3[name] = 0
        out2[name] = 0
        out3[name] = 0
        ncycle[name] = 0
        opcodes[name] = -1
        order.append(name)
        n_op += 1

    # The following are the opcodes that receive special processing in the
    # resolveP2Values() routine
    rp2v_ops = {
        'OP_Transaction', 'OP_AutoCommit', 'OP_Savepoint', 'OP_Checkpoint',
        'OP_Vacuum', 'OP_JournalMode', 'OP_VUpdate', 'OP_VFilter', 'OP_Init'
    }

    # Assign numbers to opcodes
    cnt = -1

    # Assign the smallest values to opcodes that are processed by resolveP2Values()
    for i in range(n_op):
        name = order[i]
        if name in rp2v_ops:
            cnt += 1
            while cnt in used:
                cnt += 1
            opcodes[name] = cnt
            used[cnt] = 1
            def_val[cnt] = name

    mx_case1 = cnt

    # Assign the next group of values to JUMP opcodes
    for i in range(n_op):
        name = order[i]
        if opcodes[name] >= 0:
            continue
        if not jump.get(name, 0):
            continue
        cnt += 1
        while cnt in used:
            cnt += 1
        opcodes[name] = cnt
        used[cnt] = 1
        def_val[cnt] = name

    # Find the numeric value for the largest JUMP opcode
    mx_jump = -1
    for i in range(n_op):
        name = order[i]
        if jump.get(name, 0) and opcodes[name] > mx_jump:
            mx_jump = opcodes[name]

    # Generate the numeric values for all remaining opcodes, while
    # preserving any groupings of opcodes
    for g in range(n_group):
        g_len = len(groups[g])
        ok = 0
        start = -1
        seek = cnt
        while not ok:
            seek += 1
            while seek in used:
                seek += 1
            ok = 1
            start = seek
            for j in range(g_len):
                seek += 1
                if seek in used:
                    ok = 0
                    break
        if ok:
            next_val = start
            for j in range(g_len):
                name = groups[g][j]
                if opcodes[name] >= 0:
                    continue
                opcodes[name] = next_val
                used[next_val] = 1
                def_val[next_val] = name
                next_val += 1
        else:
            print(f"Error: cannot find opcodes for group: {groups[g]}", file=sys.stderr)
            sys.exit(1)

    # Assign remaining opcodes
    for i in range(n_op):
        name = order[i]
        if opcodes[name] < 0:
            cnt += 1
            while cnt in used:
                cnt += 1
            opcodes[name] = cnt
            used[cnt] = 1
            def_val[cnt] = name

    # Find maximum opcode value
    max_val = max(used.keys()) if used else 0

    # Fill in unused opcodes
    for i in range(max_val + 1):
        if i not in used:
            def_val[i] = f"OP_NotUsed_{i}"

    # Generate output
    print("/* Automatically generated.  Do not edit */")
    print("/* See the tool/mkopcodeh.py script for details */")

    for i in range(max_val + 1):
        name = def_val[i]
        print(f"#define {name:<16} {i:3d}", end="")

        comments = []
        if jump0.get(name, 0):
            comments.append("jump0")
        elif jump.get(name, 0):
            comments.append("jump")

        if name in same_as:
            comments.append(f"same as {same_as[name]}")

        if name in synopsis:
            comments.append(f"synopsis: {synopsis[name]}")

        if comments:
            comment_str = ", ".join(comments)
            print(f" /* {comment_str:<42} */", end="")
        print()

    if max_val > 255:
        print("Error: More than 255 opcodes - VdbeOp.opcode is of type u8!", file=sys.stderr)
        sys.exit(1)

    # Generate the bitvectors
    print()
    print("/* Properties such as \"out2\" or \"jump\" that are specified in")
    print("** comments following the \"case\" for each opcode in the vdbe.c")
    print("** are encoded into bitvectors as follows:")
    print("*/")
    print("#define OPFLG_JUMP        0x01  /* jump:  P2 holds jmp target */")
    print("#define OPFLG_IN1         0x02  /* in1:   P1 is an input */")
    print("#define OPFLG_IN2         0x04  /* in2:   P2 is an input */")
    print("#define OPFLG_IN3         0x08  /* in3:   P3 is an input */")
    print("#define OPFLG_OUT2        0x10  /* out2:  P2 is an output */")
    print("#define OPFLG_OUT3        0x20  /* out3:  P3 is an output */")
    print("#define OPFLG_NCYCLE      0x40  /* ncycle:Cycles count against P1 */")
    print("#define OPFLG_JUMP0       0x80  /* jump0:  P2 might be zero */")
    print("#define OPFLG_INITIALIZER {\\")

    for i in range(max_val + 1):
        if i % 8 == 0:
            print(f"/* {i:3d} */", end="")

        x = 0
        name = def_val[i]
        if not name.startswith("OP_NotUsed"):
            if jump.get(name, 0):
                x |= 1
            if in1.get(name, 0):
                x |= 2
            if in2.get(name, 0):
                x |= 4
            if in3.get(name, 0):
                x |= 8
            if out2.get(name, 0):
                x |= 16
            if out3.get(name, 0):
                x |= 32
            if ncycle.get(name, 0):
                x |= 64
            if jump0.get(name, 0):
                x |= 128

        print(f" 0x{x:02x},", end="")
        if i % 8 == 7:
            print("\\")

    print("}")
    print()
    print("/* The resolve3P2Values() routine is able to run faster if it knows")
    print("** the value of the largest JUMP opcode.  The smaller the maximum")
    print("** JUMP opcode the better, so the mkopcodeh.py script that")
    print("** generated this include file strives to group all JUMP opcodes")
    print("** together near the beginning of the list.")
    print("*/")
    print(f"#define SQLITE_MX_JUMP_OPCODE  {mx_jump}  /* Maximum JUMP opcode */")


def main():
    if len(sys.argv) > 1:
        print("Usage: python3 mkopcodeh.py < parse.h+vdbe.c > opcodes.h", file=sys.stderr)
        sys.exit(1)

    data = parse_input()
    generate_opcodes(data)


if __name__ == '__main__':
    main()