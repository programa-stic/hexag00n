from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from builtins import (ascii, bytes, chr, dict, filter, hex, input,
                      int, map, next, oct, open, pow, range, round,
                      str, super, zip)

import cProfile
import pstats
import struct
import time

from hexagondisasm import common
from hexagondisasm.disassembler import HexagonDisassembler
from hexagondisasm.objdump_wrapper import ObjdumpWrapper
from hexagondisasm.common import INST_SIZE

from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS

def test_disasm_against_objdump(objdump_path, binary_path):
    # TODO: code repetition from test_disasm_standalone, encapsulate inner functionality.

    start_time = time.time()
    total_inst = 0
    match_inst = 0

    print(('Processing file:', binary_path))
    elf_file = ELFFile(open(binary_path, 'rb'))

    if elf_file.num_segments() == 0:
        print('There are no program headers in this file.')
        return

    objdump = ObjdumpWrapper(objdump_path)
    disasm = HexagonDisassembler(objdump_compatible=True)

    for segment in elf_file.iter_segments():
        if segment['p_flags'] & P_FLAGS.PF_X:

            print("Offset: {:x}".format(segment['p_offset']))
            print("VirtAddr: {:x}".format(segment['p_vaddr']))
            print("FileSiz: {:x}".format(segment['p_filesz']))

            segment_data = segment.data()
            data_pos = 0

            while data_pos + INST_SIZE <= len(segment_data):

                addr = segment['p_vaddr'] + data_pos

                inst_as_int = struct.unpack('<I', segment_data[data_pos: data_pos + 4])[0]

                disasm_output = disasm.disasm_one_inst(inst_as_int, addr).text.strip()

                objdump_output = objdump.disasm_packet_raw(
                    segment_data[data_pos: min(data_pos + 4 * 4, segment_data)],
                    addr).strip()

                if (objdump_output != disasm_output):
                    print("[{:08x}] {:s}".format(addr, objdump_output))
                    print("[{:08x}] {:s}".format(addr, disasm_output))
                    print()
                else:
                    match_inst += 1

                data_pos += 4
                total_inst += 1

    elapsed_time = time.time() - start_time

    print("Elapsed time: {0:.2f}".format(elapsed_time))
    print('Match: {0:.2f}%'.format(match_inst / total_inst * 100))


def test_disasm_standalone(binary_path, timeout = None):

    profile = cProfile.Profile()
    profile.enable()

    start_time = time.time()

    print(('Processing file:', binary_path))
    elf_file = ELFFile(open(binary_path, 'rb'))

    if elf_file.num_segments() == 0:
        print('There are no program headers in this file.')
        return

    disasm = HexagonDisassembler()

    total_inst = 0

    for segment in elf_file.iter_segments():
        if segment['p_flags'] & P_FLAGS.PF_X:
            print("Offset: {:x}".format(segment['p_offset']))
            print("VirtAddr: {:x}".format(segment['p_vaddr']))
            print("FileSiz: {:x}".format(segment['p_filesz']))

            segment_data = segment.data()
            data_pos = 0

            while data_pos + INST_SIZE <= len(segment_data):

                addr = segment['p_vaddr'] + data_pos

                inst_as_int = struct.unpack('<I', segment_data[data_pos: data_pos + 4])[0]

                dis = disasm.disasm_one_inst(inst_as_int, addr)
                print("[{:08x}] {:s}".format(addr, dis.text))

                data_pos += 4
                total_inst += 1

                if timeout and (time.time() - start_time) > timeout:
                    break

    profile.disable()
    prof_stats = pstats.Stats(profile)
    prof_stats.strip_dirs().sort_stats('cumulative').print_stats(20)

    print("Total instructions: " + str(total_inst))
    elapsed_time = time.time() - start_time
    print("Elapsed time: " + str(elapsed_time))


if __name__ == "__main__":

    binary_path = common.FACTORIAL_EXAMPLE_ELF

    test_disasm_standalone(binary_path)

    # objdump_path = "hexagon-objdump.exe"
    #
    # test_disasm_against_objdump(objdump_path, binary_path)
