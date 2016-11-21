import os
import sys
import traceback

from barf.arch.arch import ARCH_X86_MODE_32
from barf.barf import BARF

from hexagontranslator import HexagonTranslator
from hexagondisasm.disassembler import HexagonDisassembler
from arch import HexagonArchitectureInformation

if __name__ == "__main__":
    #
    # Open file
    #
    try:

        # filename = sys.argv[1]
        filename = r"../data/factorial_example.elf"

        arch_mode = ARCH_X86_MODE_32
        arch_info = HexagonArchitectureInformation()

        disassembler = HexagonDisassembler()

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
    print("[+] Translating Hexagon to REIL...")

    # Main function addresses of the factorial_example.elf
    ea_start = 0x00005120
    ea_end = 0x000051D8

    for addr, asm_instr, reil_instrs in barf.translate(ea_start, ea_end):
        print("0x{0:08x} : {1}".format(addr, asm_instr.text))

        for reil_instr in reil_instrs:
            print("{0:14}{1}".format("", reil_instr))

    print(barf.binary.architecture_mode)

    # Recover CFG.
    cfg = barf.recover_cfg(ea_start, ea_end)

    # Save CFG to a .dot file.
    cfg.save("main_cfg")
