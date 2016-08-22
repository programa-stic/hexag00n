from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from builtins import (ascii, bytes, chr, dict, filter, hex, input,
                      int, map, next, oct, open, pow, range, round,
                      str, super, zip)

import os
import sys
import logging
import ply.lex as lex
import ply.yacc as yacc

from hexagondisasm import common
from hexagondisasm.common import UnknownBehaviorException


class Parser(object):
    """Base class for a lexer/parser that has the rules defined as methods.

    Adapted from a `PLY example`_.

    .. _PLY example: https://github.com/dabeaz/ply/blob/master/example/newclasscalc/calc.py

    """
    tokens = ()
    precedence = ()

    def __init__(self, **kw):
        self.debug = kw.get('debug', 0)
        self.names = {}
        try:
            modname = os.path.split(os.path.splitext(__file__)[0])[1] + "_" + self.__class__.__name__
        except:
            modname = "parser" + "_" + self.__class__.__name__
        self.debugfile = modname + ".dbg"
        self.tabmodule = modname + "_" + "parsetab"

        # Build the lexer and parser
        lex.lex(module=self, debug=self.debug)
        yacc.yacc(module=self,
                  debug=self.debug,
                  debugfile=self.debugfile,
                  tabmodule=self.tabmodule)

    def parse(self, input):
        """Parse input text with rules defined in the child class
        (`HexagonBehaviorParser`).

        Args:
            input (str): Input text to parse.

        Returns:
            Unkonwn: Parse result.

        Raises:
            UnknownBehaviorException: If the rules define can't process the input text.

        TODOs:
            * Define return type.

            * Decouple base and child classes, or document it appropriately.

        """
        return yacc.parse(input, debug=self.debug)


class HexagonBehaviorParser(Parser):
    """Parser for the Hexagon instructions behavior.

    It contains the rules for both the lexer and parser.

   """
    def __init__(self, **kw):
        super(HexagonBehaviorParser, self).__init__(**kw)


    tokens = [
         'REG', 'IMM', 'NAME', 'IMM_OP', 'MEM_ACCESS', 'REG_EA',
     ]

    def t_newline(self, t):
        r'\n+'
        t.lexer.lineno += t.value.count("\n")

    def t_error(self, t):
        raise UnknownBehaviorException("Illegal character {:s}".format(t.value[0]))


    def p_statement_expr(self, p):
        'statement : expression'
        p[0] = p[1]

    def p_expression_register(self, p):
        "expression : register"
        p[0] = p[1]

    def p_register_reg(self, p):
        "register : REG"
        p[0] = p[1]
        debug_parse("Create reil reg: {:s}".format(p[1]))

    def p_error(self, p):
        if p:
            error_msg = "Syntax error at {:s}".format(p.value)
        else:
            error_msg = "Syntax error at EOF"
        raise UnknownBehaviorException(error_msg)


def debug_parse(s):
    print(s)
    return


logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(filename)10s:%(lineno)4d: %(message)s"
)
log = logging.getLogger()
# TODO: Add the logger to the HexagonBehaviorParser class?


if __name__ == "__main__":

    parser = HexagonBehaviorParser(debug = True)

    inst_defs = common.pickle_load(common.INST_DEF_PATH)

    for inst in inst_defs:
        behavior = inst.behavior

        if inst.behavior == '':
            # No behavior available (probably it wasn't correctly parsed
            # from the Hexagon Reference Manual).
            continue

        try:
            parser.parse(behavior)
        except UnknownBehaviorException as e:
            log.info("Unknown behavior instruction: {:s}".format(behavior))
            pass
