"""Hexagon architecture definition.

This module was copied from BARF (``barf/arch/arch.py``). It will be used to integrate
the Hexagon to REIL translator with the BARF framework implementing the methods
defined in ``ArchitectureInformation`` (without those, an ``NotImplementedError``
exception is raised).

Todo:
    * Should this module be named ``hexagonbase.py`` (like ``armbase.py`` in ARM)
        instead of ``arch.py`` (which is used only for the base arch. info
        class)?

    * Should constants like `ARCH_HEXAGON` be added to BARF's `arch.py`? Hexagon
        won't be fully integrated with BARF, it will use is as a library.

    * Normally, in this same module the instruction object is defined (e.g.,
        ``ArmInstruction`` for ARM). The `HexagonInstruction` is already
        defined (in the `common.py` module). How can that be signaled here?

"""
from barf.arch import ArchitectureInformation
from hexagondisasm.common import TemplateBranch


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
        self.registers_gp_all = []
        self.registers_gp_base = []
        self.registers_size = []
        # TODO: What registers should be defined?
        pass

    @property
    def architecture_mode(self):
        return ARCH_HEXAGON_MODE

    @property
    def architecture_size(self):
        return ARCH_HEXAGON_SIZE

    @property
    def operand_size(self):
        return ARCH_HEXAGON_OPERAND_SIZE

    @property
    def address_size(self):
        return ARCH_HEXAGON_ADDRESS_SIZE

    @property
    def registers(self):
        return []
        # TODO: In ARM this returns an empty list and x86 doesn't seem to define it.

    def instr_is_ret(self, instruction):
        if instruction.template and instruction.template.branch:
            branch = instruction.template.branch

            if branch.type in [TemplateBranch.dealloc_ret_syntax]:
                return True
                # TODO: This is not the only ret type (only the most common), jumps to the link
                # register should be included as well, but those are not specialized instructions,
                # they are ``jumpr Rs`` (and the conditional variant). It should be checked for a
                # `jump_reg_syntax` and a ``Rs`` operand set to a value or 31 (R31: LR).

        return False

    def instr_is_call(self, instruction):
        if instruction.template and instruction.template.branch:
            branch = instruction.template.branch

            if branch.type in [TemplateBranch.call_reg_syntax, TemplateBranch.call_imm_syntax]:
                return True

        return False

    def instr_is_halt(self, instruction):
        return False

    def instr_is_branch(self, instruction):
        # NOTE: In the Hexagon terminology, there are only jump and calls, branch is just
        # a generic term used to refer to both of those types. In BARF a branch is what
        # Hexagon would refer as a jump (and only that, not including a call).
        if instruction.template and instruction.template.branch:
            branch = instruction.template.branch

            if branch.type in [TemplateBranch.jump_reg_syntax, TemplateBranch.jump_imm_syntax]:
                return True

        return False

    @property
    def max_instruction_size(self):
        """Return the maximum instruction size in bytes.
        """
        return 4
        # TODO: How is this function used? Should this better return the size of a packet? (16 bytes)


    def instr_is_branch_cond(self, instruction):
        if instruction.template and instruction.template.branch:
            branch = instruction.template.branch

            return branch.is_conditional

        return False
