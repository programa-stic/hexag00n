import os
import sys
import traceback

from barf.arch.x86.x86base import X86ArchitectureInformation
from barf.arch.x86.x86disassembler import X86Disassembler
from barf.arch.x86.x86translator import X86Translator
from barf.arch.arch import ARCH_X86_MODE_32
from barf.barf import BARF

from hexagontranslator import HexagonTranslator
from hexagondisasm.disassembler import HexagonDisassembler
from arch import HexagonArchitectureInformation

"""
Original example modified to use the Hexagon Translator
but still with the X86Disassembler, this is done just to
test the Hexagon Translator API, which is returning
empty REIL instructions for now.
"""

if __name__ == "__main__":
    #
    # Open file
    #
    try:

        # filename = sys.argv[1]
        # filename = r"/sbin/gdisk" # x86 ELF
        filename = r"../data/factorial_example.elf"

        arch_mode = ARCH_X86_MODE_32
        # arch_info = X86ArchitectureInformation(arch_mode)
        arch_info = HexagonArchitectureInformation()

        # disassembler = X86Disassembler(architecture_mode=arch_mode)
        disassembler = HexagonDisassembler()

        # translator = X86Translator(architecture_mode=arch_mode)
        translator = HexagonTranslator()

        barf = BARF(filename)

        barf.load_architecture("x86", arch_info, disassembler, translator)

    except Exception as err:
        print "[-] Error opening file : %s" % filename

        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_exception(exc_type, exc_value, exc_traceback, file=sys.stdout)

        sys.exit(1)

    #
    # Translate to REIL
    #
    print("[+] Translating x86 to REIL...")

    for addr, asm_instr, reil_instrs in barf.translate():
        print("0x{0:08x} : {1}".format(addr, asm_instr.text))

        for reil_instr in reil_instrs:
            print("{0:14}{1}".format("", reil_instr))
