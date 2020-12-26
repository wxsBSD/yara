#!/usr/bin/env python3

# Copyright (c) 2020. Wesley Shields. All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import struct
import sys

from bf2y_lexer import bf2y_lexer
from bf2y_utils import yr_opcodes, bf2y_exception


def compile(infile):
    lexer = bf2y_lexer()
    with open(infile, "r") as f:
        lexer.lex(f.read())

    # A stack of offsets for LB.
    offsets = []

    # We dedicate mem[0] as the pointer, the rest is for the user.
    #
    # Caveat emptor. YARA only has 8 (by default) memory cells, if you point
    # outside of that your program will crash.
    yr_bytecode = bytearray()
    yr_bytecode += struct.pack("=cQ", yr_opcodes["OP_INCR_M"], 0)
    for t in lexer.get_tokens():
        if t.type == "GT":
            yr_bytecode += struct.pack("=cQ", yr_opcodes["OP_INCR_M"], 0)
        elif t.type == "LT":
            yr_bytecode += struct.pack("=cq", yr_opcodes["OP_PUSH"], -1)
            yr_bytecode += struct.pack("=cQ", yr_opcodes["OP_ADD_M"], 0)
        elif t.type == "PLUS":
            yr_bytecode += struct.pack("=c", yr_opcodes["OP_BF_PUSH_P"])
            yr_bytecode += struct.pack("=cQ", yr_opcodes["OP_PUSH"], 1)
            yr_bytecode += struct.pack("=c", yr_opcodes["OP_ADD"])
            yr_bytecode += struct.pack("=c", yr_opcodes["OP_BF_POP_P"])
        elif t.type == "MINUS":
            yr_bytecode += struct.pack("=c", yr_opcodes["OP_BF_PUSH_P"])
            yr_bytecode += struct.pack("=cq", yr_opcodes["OP_PUSH"], -1)
            yr_bytecode += struct.pack("=c", yr_opcodes["OP_ADD"])
            yr_bytecode += struct.pack("=c", yr_opcodes["OP_BF_POP_P"])
        elif t.type == "PERIOD":
            yr_bytecode += struct.pack("=c", yr_opcodes["OP_BF_OUTPUT"])
        elif t.type == "COMMA":
            yr_bytecode += struct.pack("=c", yr_opcodes["OP_BF_INPUT"])
        elif t.type == "LB":
            # Don't insert a jump target here, we calculate the correct one
            # when a matching a matching RB is found and splice it in.
            yr_bytecode += struct.pack("=c", yr_opcodes["OP_BF_PUSH_P"])
            offsets.append(len(yr_bytecode))
        elif t.type == "RB":
            if len(offsets) == 0:
                raise bf2y_exception("RB before LB")

            yr_bytecode += struct.pack("=c", yr_opcodes["OP_BF_PUSH_P"])

            # Get the offset of the matching LB and calculate the relative
            # offset to it from our current position. This is the jump target
            # for the current RB.
            lb = offsets.pop()
            # This should always be a negative value.
            lb_rel = lb - len(yr_bytecode)
            if lb_rel > 0:
                raise bf2y_exception("Positive LB relative value")

            yr_bytecode += struct.pack("=ci", yr_opcodes["OP_JTRUE_P"], lb_rel)

            # Now do the jump target for the matching LB. We calculate it
            # relative ot the matching LB and then splice in the target.
            target_rel = len(yr_bytecode) - lb
            inst = struct.pack("=ci", yr_opcodes["OP_JFALSE_P"], target_rel)
            left = yr_bytecode[:lb]
            right = yr_bytecode[lb:]
            yr_bytecode = left + inst + right

    yr_bytecode += struct.pack("=c", yr_opcodes["OP_HALT"])
    if len(offsets) != 0:
        raise bf2y_exception("Unbalanced LB/RB")

    return yr_bytecode


def __main__():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <bf.src> <a.out>")
        return

    try:
        yr_bytecode = compile(sys.argv[1])
    except bf2y_exception as e:
        print(e)
        return

    with open(sys.argv[2], "wb") as f:
        f.write(yr_bytecode)


if __name__ == "__main__":
    __main__()
