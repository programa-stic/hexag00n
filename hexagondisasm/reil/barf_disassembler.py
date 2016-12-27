import struct

from hexagondisasm.disassembler import HexagonDisassembler
from hexagondisasm.reil.arch import ARCH_HEXAGON_MODE

from barf.core.disassembler import DisassemblerError


class BARFHexagonDisassembler(HexagonDisassembler):
    """Hexagon disassembler implementing the BARF API.

    Attributes:

    TODOs:

        * Revist class name, the Hexagon term may be ommited, in this project everything (e.g., a disassembler)
            concerns the Hexagon architecture..
    """

    def disassemble(self, data, address, architecture_mode=ARCH_HEXAGON_MODE):
        """BARF: Disassemble raw bytes into an instruction.

        This function is added to comply with BARF's API that calls
        the `disassemble` function from its loaded disassembler (which will be
        `HexagonDisassembler` in this case).

        Args:
            data (str): Raw bytes (extracted from a binary file) that represent
                one or possibly more instructions.
            address (int): Starting address of the data (raw bytes), which will
                be the address of the disassembled instruction.
            architecture_mode (int): Used in BARF to indicate variations of the
                same architecture, it's not used here.

        Returns:
            HexagonInstruction: disassembled instruction.

        """

        # BARF will pass at most 16 bytes of data, and it is assumed that at least
        # 4 bytes (the length of an Hexagon instruction) will be passed.
        if len(data) < 4:
            raise DisassemblerError("BARF called the disassemble function with less than 4 bytes.")
            # TODO: Is this the correct way to stop the disassembly process in BARF's _disassemble_bb().

        # The 4 bytes are reconstructed in an int representing the instruction bits,
        # which is what disasm_one_inst is expecting. The current function aims to
        # modify the existing code as little as possible.
        inst_as_int = struct.unpack('<I', data[0:4])[0]

        return self.disasm_one_inst(inst_as_int, address)
