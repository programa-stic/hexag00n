from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

# TODO: Removed int import because the newint type is not compatible with
# what BARF uses for REIL immediate operands.
from builtins import (ascii, bytes, chr, dict, filter, hex, input,
                      map, next, oct, open, pow, range, round,
                      str, super, zip)

from hexagondisasm.common import UnexpectedException


'''
Based on: https://github.com/eliben/pycparser/blob/master/pycparser/c_ast.py
'''

class Node(object):
    """ Abstract base class for AST nodes.

    TODOs:
        * Add a print method?
    """
    __slots__ = []

    def __repr__(self):
        raise UnexpectedException("Trying to print base (abstract) class Node")



class Assignment(Node):
    __slots__ = ['src', 'dst', 'type']
    def __init__(self, dst, type, src):
        self.dst = dst
        self.src = src
        self.type = type

    def __repr__(self):
        return "(Assignment: {:s} {:s} {:s})".format(self.dst, self.type, self.src)


class BinOp(Node):
    __slots__ = ['src_1', 'src_2', 'op']
    # TODO: only one src as an array?
    def __init__(self, src_1, op, src_2):
        self.src_1 = src_1
        self.src_2 = src_2
        self.op = op

    def __repr__(self):
        return "(BinOp: {:s} {:s} {:s})".format(self.src_1, self.op, self.src_2)


class MemLoad(Node):
    __slots__ = ['src', 'size']
    def __init__(self, src, size):
        self.src = src
        self.size = size

    def __repr__(self):
        return "(MemLoad: {:s} ({:s}))".format(self.src, self.size)


class MemSave(Node):
    __slots__ = ['dst', 'size']
    def __init__(self, dst, size):
        self.dst = dst
        self.size = size

    def __repr__(self):
        return "(MemSave: {:s} ({:s}))".format(self.src, self.size)

class Statement(Node):
    # TODO: This is actually a (possibly) list of statements, not a single
    # one, should this distinction be made?
    # TODO: Should this list actually be structured in a tree, with multiple
    # Statement objects?
    __slots__ = ['sl'] # statement list
    def __init__(self, sl):
        self.sl = sl

    def __repr__(self):
        ret_str = "(Statement:"
        for s in self.sl:
            ret_str += "\n\t{:s}".format(s)
        ret_str += "\n)"
        # TODO: list comprehension

        return ret_str


class IfConditional(Node):
    __slots__ = ['if_block', 'condition', 'else_block']
    def __init__(self, condition, if_block, else_block = ""):
        # TODO: Empty string, or create an empty node class?
        self.if_block = if_block
        self.condition = condition
        self.else_block = else_block

    def __repr__(self):
        return "(IF {:s} THEN {:s} ELSE {:s}".format(self.condition, self.if_block, self.else_block)


class RegAccesor(Node):
    __slots__ = ['reg', 'index', 'else_block']
    def __init__(self, condition, if_block, else_block = ""):
        # TODO: Empty string, or create an empty node class?
        self.if_block = if_block
        self.condition = condition
        self.else_block = else_block

    def __repr__(self):
        return "(IF {:s} THEN {:s} ELSE {:s}".format(self.condition, self.if_block, self.else_block)
