"""Hexagon to IR Translator.

Defined from BARF's ``Translator`` API which requires that the ``translate``
method be implemented.

Todo:
    *

"""
from barf.arch.translator import Translator
from hexagondisasm.reil.behavior_parser import HexagonBehaviorParser
from hexagondisasm.common import UnknownBehaviorException


class HexagonTranslator(Translator):

    def __init__(self):
        pass

    def translate(self, instruction):
        """Return IR representation of an instruction.
        """

        parser = HexagonBehaviorParser(debug=True)

        if instruction.template is None:
            # TODO: In which cases the template is None?
            return []

        behavior = instruction.template.behavior

        if behavior == '':
            # No behavior available (probably it wasn't correctly parsed
            # from the Hexagon Reference Manual).
            return []

        try:
            print("Parsing: {:s}".format(behavior.strip()))
            parsed = parser.parse_and_translate(behavior)
            for ri in parsed._instructions:
                print(ri)
            print("DONE!")
            return parsed._instructions
        except UnknownBehaviorException as e:
            print("Unknown behavior instruction: {:s}".format(behavior))
            print(e)
            pass


        return []

    def reset(self):
        """Restart IR register name generator.
        """
        pass
