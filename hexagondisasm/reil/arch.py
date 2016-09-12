"""Hexagon architecture definition.

This module was copied from BARF (``barf/arch/arch.py``). It will be used to integrate
the Hexagon to REIL translator with the BARF framework implementing the methods
defined in ``ArchitectureInformation`` (without those, an ``NotImplementedError``
exception is raised).

Todo:
    * Should constants like `ARCH_HEXAGON` be added to BARF's `arch.py`? Hexagon
        won't be fully integrated with BARF, it will use is as a library.

    * Normally, in this same module the instruction object is defined (e.g.,
        ``ArmInstruction`` for ARM). The `HexagonInstruction` is already
        defined (in the `common.py` module). How can that be signaled here?

"""
from barf.arch import ArchitectureInformation


ARCH_HEXAGON = 2
# TODO: This number follows from ARM's arch. number 1 (defined in BARF). But this
#   number isn't registered in BARF, so it can be used by other
#   architectures, is this an issue?

ARCH_HEXAGON_MODE = 0
# TODO: Hexagon doesn't have multiple arch. modes, register this (only)
#   mode anyways?


ARCH_HEXAGON_SIZE = 32
ARCH_HEXAGON_OPERAND_SIZE = ARCH_HEXAGON_SIZE
ARCH_HEXAGON_ADDRESS_SIZE = ARCH_HEXAGON_SIZE


class HexagonArchitectureInformation(ArchitectureInformation):

    reg_names = [
        "r0", "r1", "r2", "r3",
        "r4", "r5", "r6", "r7",
        "r8", "r9", "r10", "r11",
        "r12", "r13", "r14", "r15",
    ]
    # TODO: How to add (these) registers to the arch. info?

    def __init__(self):
        pass

    @property
    def architecture_mode(self):
        return ARCH_HEXAGON_MODE

    @property
    def architecture_size(self):
        raise ARCH_HEXAGON_SIZE

    @property
    def operand_size(self):
        raise ARCH_HEXAGON_OPERAND_SIZE

    @property
    def address_size(self):
        raise ARCH_HEXAGON_ADDRESS_SIZE

    @property
    def registers(self):
        return []
        # TODO: In ARM this returns an emṕty list and x86 doesn't seem to define it.
