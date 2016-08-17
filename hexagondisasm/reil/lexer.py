from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from builtins import (ascii, bytes, chr, dict, filter, hex, input,
                      int, map, next, oct, open, pow, range, round,
                      str, super, zip)

import sys
import logging

import ply.lex as lex

from hexagondisasm import common
from hexagondisasm.common import UnknownBehaviorException

class HexagonBehaviorLexer(object):
    """Lexer for the Hexagon instructions behavior.

    It takes encapsulates the real PLY lexer (`self.lexer`). Taken from a PLY example.

    Attributes:
        lexer (ply.lex): PLY lexer.

     TODOs:

        * The `build` function (necessary every time the class is used) could
            be included in the constructor.

   """

    # List of token names.   This is always required
    tokens = (
        'NUMBER',
        'PLUS',
        'MINUS',
        'TIMES',
        'DIVIDE',
        'LPAREN',
        'RPAREN',
    )

    # Regular expression rules for simple tokens
    t_PLUS = r'\+'
    t_MINUS = r'-'
    t_TIMES = r'\*'
    t_DIVIDE = r'/'
    t_LPAREN = r'\('
    t_RPAREN = r'\)'

    # A regular expression rule with some action code
    # Note addition of self parameter since we're in a class
    def t_NUMBER(self, t):
        r'\d+'
        t.value = int(t.value)
        return t

    # Define a rule so we can track line numbers
    def t_newline(self, t):
        r'\n+'
        t.lexer.lineno += len(t.value)

    # A string containing ignored characters (spaces and tabs)
    t_ignore = ' \t'

    # Error handling rule
    def t_error(self, t):
        raise UnknownBehaviorException("Illegal character {:s}".format(t.value))

    # Build the lexer
    def build(self, **kwargs):
        self.lexer = lex.lex(module=self, **kwargs)

    # Test it output
    def test(self, data):
        self.lexer.input(data)
        while True:
            tok = self.lexer.token()
            if not tok:
                break
            print(tok)


if __name__ == "__main__":

    logging.basicConfig(
        level = logging.INFO,
        stream = sys.stdout,
        format = "%(filename)10s:%(lineno)4d: %(message)s"
    )
    log = logging.getLogger()
    # TODO: Add the logger to the HexagonBehaviorLexer class?

    # Build the lexer and try it out
    m = HexagonBehaviorLexer()
    m.build(debug=True)  # Build the lexer

    inst_defs = common.pickle_load(common.INST_DEF_PATH)

    for inst in inst_defs:
        behavior = inst.behavior

        if inst.behavior == '':
            # No behavior available (probably it wasn't correctly parsed
            # from the Hexagon Reference Manual).
            continue

        try:
            m.test(behavior)
        except UnknownBehaviorException as e:
            log.info("Unknown behavior instruction: {:s}".format(behavior))
            pass
