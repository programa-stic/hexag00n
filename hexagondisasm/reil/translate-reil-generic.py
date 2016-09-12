import os
import sys

from barf.arch.x86.x86base import X86ArchitectureInformation
from barf.arch.x86.x86disassembler import X86Disassembler
from barf.arch.x86.x86translator import X86Translator
from barf.arch.arch import ARCH_X86_MODE_32
from barf.barf import BARF

if __name__ == "__main__":
    #
    # Open file
    #
    try:
        filename = sys.argv[1]

        arch_mode = ARCH_X86_MODE_32
        arch_info = X86ArchitectureInformation(arch_mode)
        disassembler = X86Disassembler(architecture_mode=arch_mode)
        translator = X86Translator(architecture_mode=arch_mode)

        barf = BARF(filename)

        barf.load_architecture("x86", arch_info, disassembler, translator)

    except Exception as err:
        print err

        print "[-] Error opening file : %s" % filename

        sys.exit(1)

    #
    # Translate to REIL
    #
    print("[+] Translating x86 to REIL...")

    for addr, asm_instr, reil_instrs in barf.translate():
        print("0x{0:08x} : {1}".format(addr, asm_instr))

        for reil_instr in reil_instrs:
            print("{0:14}{1}".format("", reil_instr))
