from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from builtins import (ascii, bytes, chr, dict, filter, hex, input,
                      int, map, next, oct, open, pow, range, round,
                      str, super, zip)

import subprocess
import re
import struct
import os

from hexagondisasm.common import hex_digit

class ObjdumpWrapper(object):
    """Wrapper class to use the objdump provided by the Hexagon SDK.

    The objdump relies on the ELF section headers for a correct disassembly, normally an
    Hexagon modem firmware was stripped of such headers, to bypass this the objdump
    is used in raw binary mode, where objdump just disassembles bytes of instructions
    from a file without any kind of format. The drawback is that for each instruction
    being disassembled a temporary binary with such instruction has to be written to
    disk to be processed by objdump, as it wasn't found a way to pass a binary stream
    to objdump stdin.

    To be able to use this class the objdump binary (e.g., ``hexagon-objdump.exe``)
    has to be downloaded from the Hexagon SDK and its path passed to the constructor.

    Attributes:
        objdump_path (str): Path to the objdump program.
        dump_binary_path (str): Path to the temporary raw instruction file created that will
            be the input of objdump. The directory is set to the same as `objdump_path`.
        inst_cache (Dict[int, str]): Cache for already disassembled instructions. Used
            to improve performance when disassembling an entire packet for just one instruction.

    """
    __slots__ = ['objdump_path', 'dump_binary_path', 'inst_cache']

    def __init__(self, objdump_path):
        self.inst_cache = dict()
        self.objdump_path = objdump_path
        self.dump_binary_path = os.path.join(os.path.dirname(os.path.abspath(self.objdump_path)), 'instructions.bin')

    def disasm_packet_raw(self, packet_bytes, addr):
        """Disassemble an Hexagon packet.

        As each call to objdump is made in isolation, there's no point in disassembling
        each instruction of a packet separately, because information such as constant extension
        would be lost, therefore entire packets are handled.

        Packets can have 1-4 instructions, therefore the length of `packet_bytes` should
        be between 4-16 bytes (multiple of 4).

        Args:
            packet_bytes (str): bytes of the instruction packet.
            addr (int): address of the start of the packet.

        Returns:
            str: text representation of the disassembled instruction.

        """
        if (addr not in self.inst_cache):
            
            if len(packet_bytes) < 4:
                raise Exception("Received less tha 4 bytes: {:d}".format(len(packet_bytes)))

            # For some reason objdump in binary mode is not correctly processing an
            # all zeros instruction, so this special case is handled here as an
            # unknown instruction (which is the behavior of objdump in non-binary mode).

            if struct.unpack('<I', packet_bytes[0:4])[0] == 0:
                return "{ <unknown> }"

            # Write temporary file with the packet instructions bytes.

            with open(self.dump_binary_path, 'wb') as f:
                f.write(packet_bytes)
                f.close()

            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            detached_process_flag = 0x00000008

            stdoutdata = subprocess.Popen([
                    self.objdump_path,
                    "--disassemble-all",                # Display assembler contents of all sections
                    "-b", "binary",                     # Specify the target object format as BFDNAME
                    "-mhexagon",                        # Specify the target architecture
                    "--adjust-vma=0x{:x}".format(addr), # Add OFFSET to all displayed section addresses
                    "--no-show-raw-insn",               # Don't display hex alongside symbolic disassembly
                    self.dump_binary_path,
                ],
                stderr = subprocess.STDOUT,
                stdout = subprocess.PIPE,
                startupinfo = si,
                creationflags = detached_process_flag
            ).communicate()[0]

            self.populate_inst_cache(stdoutdata)
            
        return self.inst_cache[addr]

    def populate_inst_cache(self, objdump_data):
        """Populate the instruction cache with the stdout data returned from objdump.

        Args:
            objdump_data (str): Text returned from objdump.

        Returns:
            None: the information is stored in `inst_cache`.

        """
        for line in objdump_data.splitlines():
            m = re.match("^\s*(" + hex_digit + '{1,8}):\s+(' + hex_digit + '{1,8})', line)
            # TODO: Improve regex readability.

            if m:
                addr = int(m.group(1),16)
                
                line = line[m.end(2): ].strip()
                
                self.inst_cache[addr] = line
                # TODO: How much can the cache size grow?
                
                if '}' in line:
                    # Don't go past the end of a packet
                    break
