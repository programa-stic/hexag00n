import os
import sys
import traceback

from barf.analysis.basicblock.callgraph import CallGraph
from barf.arch.arch import ARCH_X86_MODE_32
from barf.barf import BARF

from hexagontranslator import HexagonTranslator
from hexagondisasm.reil.barf_disassembler import BARFHexagonDisassembler
from arch import HexagonArchitectureInformation

if __name__ == "__main__":
    #
    # Open file
    #
    try:

        # filename = sys.argv[1]
        filename = r"../data/factorial_example.elf"

        arch_info = HexagonArchitectureInformation()

        disassembler = BARFHexagonDisassembler()

        translator = HexagonTranslator()

        barf = BARF(filename)

        barf.load_architecture("hexagon", arch_info, disassembler, translator)

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
    cfg = barf.recover_cfg(ea_start=ea_start, ea_end=ea_end)

    # Save CFG to a .dot file.
    cfg.save("main_cfg")

    # Recover CFGs.
    print("[+] Recovering CFGs...")

    entries = [ea_start]
    symbols_by_addr ={
        0x00005120: ("main", 0x000051D8-0x00005120, True)
    }

    cfgs = barf.recover_cfg_all(entries, symbols=symbols_by_addr)

    # Recover CG.
    print("[+] Recovering program CG...")

    cfgs_filtered = []
    for cfg in cfgs:
        if len(cfg.basic_blocks) == 0:
            print("[*] Ignoring empty CFG: {}".format(cfg.name))
            continue

        cfgs_filtered.append(cfg)

    cg = CallGraph(cfgs_filtered)

    cg.save("main_cg")

    pass




    # reil_emulator = barf.ir_emulator
    # c_analyzer = barf.code_analyzer
    #
    # # Setting parameters.
    # # ==================================================================== #
    # print("[+] Setting parameters...")
    #
    # esp = 0x00001500
    #
    # in_array_addr = 0x4093a8
    # out_array_addr = esp - 0x25
    # array_size = 32
    #
    # # Push parameters into the stack.
    # reil_emulator.write_memory(esp + 0x00, 4, 0x41414141) # return address
    # reil_emulator.write_memory(esp + 0x04, 4, 0x12345678) # x
    # reil_emulator.write_memory(esp + 0x08, 4, 0x87654321) # y
    #
    # # # Print stack.
    # # ==================================================================== #
    # # print("[+] Printing stack content... ")
    #
    # # __print_stack(esp)
    #
    # # Taint parameters.
    # # ==================================================================== #
    # print("[+] Tainting parameters...")
    #
    # # Taint in array and parameters.
    # reil_emulator.set_memory_taint(in_array_addr, array_size, True)
    # reil_emulator.set_memory_taint(esp + 0x04, 4, True) # x
    # reil_emulator.set_memory_taint(esp + 0x08, 4, True) # y
    #
    # # Generate trace.
    # # ==================================================================== #
    # print("[+] Generating trace...")
    #
    # # Hook instructions in order to record execution trace.
    # trace = []
    #
    # reil_emulator.set_instruction_post_handler(__instr_post, trace)
    #
    # # Set registers.
    # ctx_init = {
    #     'registers' : {
    #         # Set eflags and stack pointer.
    #         'eflags' : 0x202,
    #         'esp'    : esp,
    #     }
    # }
    #
    # # Emulate code.
    # _ = barf.emulate_full(ctx_init, 0x004010ec, 0x0040111d)
    #
    # # Save trace to a file.
    # # ==================================================================== #
    # print("[+] Saving trace...")
    #
    # __save_trace(trace, "trace.log")
    #
