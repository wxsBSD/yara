# Copyright (c) 2020. Wesley Shields. All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import ply.lex as lex


class bf2y_lexer(object):
    tokens = ["GT", "LT", "PLUS", "MINUS", "PERIOD", "COMMA", "LB", "RB"]

    t_GT = r">"
    t_LT = r"<"
    t_PLUS = r"\+"
    t_MINUS = r"-"
    t_PERIOD = r"\."
    t_COMMA = r","
    t_LB = r"\["
    t_RB = r"\]"

    def __init__(self, **kwargs):
        self.lexer = lex.lex(module=self, **kwargs)

    def lex(self, data):
        self.lexer.input(data)

    # We ignore all other tokens.
    def t_error(self, t):
        t.lexer.skip(1)

    def get_tokens(self):
        while True:
            token = self.lexer.token()
            if not token:
                break
            yield token
