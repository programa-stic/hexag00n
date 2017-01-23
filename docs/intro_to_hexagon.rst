Introduction to Hexagon
=======================

This is a short introduction to the `Qualcomm Hexagon`_  (QDSP6) architecture. It is not a self-contained guide, it is just a complement to the main reference, the "Hexagon V5/V55 Programmer’s Reference Manual" (80-N2040-8 Rev. A, August 29, 2013), that can be obtained from the `Hexagon SDK`_. The main objective of this document is to highlight the key ideas and terminology used throughout this repository.

.. _Qualcomm Hexagon: https://en.wikipedia.org/wiki/Qualcomm_Hexagon

.. _Hexagon SDK: https://developer.qualcomm.com/software/hexagon-dsp-sdk/tools


Main characteristics
====================

The manual defines Hexagon as a *general-purpose digital signal processor*, intended originally for specific digital signal processing jobs, it is now a full featured general purpose architecture, which is the aspect this project focuses on: analysis of general purpose control code (vector and floating point instructions are beyond the scope of the project). Hexagon is a 32-bit architecture, all its instructions have a size of 32 bits, it has 32-bit general purpose registers and a 32-bit address space. Instructions can be grouped together into *packets* (discussed later) for parallel execution, with each packet containing from one to four instructions. The Hexagon processor has two sets of registers: general registers and control registers. The general registers include thirty-two 32-bit registers (named R0 through R31).

Most instructions have a straight forward syntax, ``dest = instr_name(source1,source2,...)``, that contrast with the mnemonic-oriented typical syntax ``MNEM dest, source1, source2``. In many occasions the ``instr_name`` (as named in the manual, but it doesn't really constitutes an instruction name) is not enough to univocally define the instruction, e.g., a load operation ``R2 = memw(R1)`` has the same components of the store operation ``memw(R1) = R2``, and more important, the same name (``memw``), the only difference being their position in the instruction (left or right hand side). As a consequence, the mnemonic or instruction name (both terms that don't fully apply here) are not good indicators of the instruction, but rather its syntax can univocally define it.

This apparent confusion in the instruction nomenclature is actually very helpful when reading Hexagon assembly code, as the instruction behavior is shown explicitly in the syntax, without the need to rely on a rather short instruction mnemonic that have to be looked up in a table to fully understand its behavior. The disadvantage of this arrangement is a higher instruction verbosity.

Branches are performed on conditions stored in special predicate registers (P0 - P3), there is no status register that saves conditions like overflow or zero, rather, explicit compare instructions are executed that save the result (normally a true or false result) in these predicate registers, e.g., ``P1 = cmp.eq(R2, R3)`` and later another instruction performs a conditional jump based on the value of the predicate register, e.g., ``if (P1) jump #target``.

Memory access is performed mainly through the use of the ``mem()`` instruction. As described earlier, loads have the memory access on the RHS and stores on the LHS. There are many memory addressing modes but the most common ones are 32-bit absolute, e.g., ``R2 = memw(##myvariable)``, and indirect with register offset, e.g., ``R2 = memw(R3 + #100)``. The ``mem()`` instruction has a suffix that indicates the size of the memory access, e.g., ``memw`` shown earlier indicates that the instruction is performing a word (32-bit) access.


Instructions
============

Hexagon instructions are hierarchically organized into classes and (optionally) subclasses. As described in the *Instruction Set* chapter of the manual, an instruction can have many variations, e.g., the class *ALU32* has a subclass *ALU32/ALU* that has an *Add* instruction with 3 different variations. To simplify the terminology used, any of these instruction variations will just be called an instruction, disregarding the hierarchy they belong, e.g., this document won't talk about an *Add* instruction that has 3 variations, but 3 logically different instructions, all of them which perform an addition, disregarding the fact that in the *Instruction Set* they will be listed together under the *Add* title. The only circumstance where an instruction class is relevant (and only its class, not its subclass or instruction name) is resource constraints of packets (discussed later) which restrict what kind of instructions can be executed together.

An Hexagon instruction is composed of syntax, encoding, and behavior. The instruction encoding indicates how the instruction information is formatted inside the 32-bits and univocally defines the instruction, the syntax shows how the instruction is written, and the behavior explains what the instruction does.

It has to be distinguished between an **instruction definition**, as just mentioned, and an **actual instruction**, one that is generated by the assembler, stored in memory as 32-bit little endian value, and executed by the processor. An instruction definition has a **syntax**, that shows how to write it, independently of its operand values, e.g., ``Rd = add(Rs, #s16)``, whereas an actual instruction has a **text**, that describes that particular instruction, with its particular operands, e.g., ``R4 = add(R2, 38)``. An instruction definition has an **encoding**, whereas an actual instruction has a concrete **value** (that conforms to that encoding). In sum, an instruction definition is the (unique) pattern of the (many) actual instructions that where generated from that definition. Normally the ambiguous term instruction will be used, without any qualifier, except when the situation warrants it.

An instruction has two types of operands, register and immediate (sometimes referred as numeric operands in the manual).

Hexagon instructions are fixed to 32 bits, so many immediate values can't be encoded (similar to ARM). To circumvent this issue, a special kind of instruction named **constant extender** exists, which is placed before the instruction whose immediate value wants to be extended, being able to reach any 32 bit immediate value. The constant extender instruction has an special encoding, is not listed in the *Instruction Set*, it syntax is ``immext (##constant)`` and is commonly seen in any program disassembly.


Duplex and compound instructions
--------------------------------

For some special cases, the Hexagon architecture permits coding two instructions into a single one. This can add some conflicts in the terminology, so some definitions are added (and others avoided).

Duplex instructions have two instructions in one **32-bit instruction**, that is, if we term the instructions discussed so far as **normal instructions**, a different kind of instruction, termed a **duplex instruction**, allows (through a separate coding scheme) to code two normal instructions inside 32 bits. The syntax is the same as the original normal instructions, separated by a semicolon, e.g., ``Rd16 = add (Ru16 , #-1) ; memb (Rs16 + #u4:0) = Rt16``.

**Compound instructions**, as defined by the manual, *merge certain common operation sequences (add-accumulate, shift-add, etc.) into a single instruction*, e.g., two instructions that perform an addition are merged into ``Rd = add(Rs, add(Ru, #s6))``, which normally doesn't deserve any more attention than a normal instruction, it has its own syntax, encoding, and behavior. There are, however, some special cases of compound instructions that may look like a duplex instruction, that have a semicolon, e.g., a compare and jump: ``p0 = cmp.eq(Rs, #-1) ; if (p0.new) jump:nt #r9:2``.

From an static analysis standpoint, it's useful to abstract from the normal/duplex/compound categories, and split instructions to the smallest unit that can be analyzed by itself, we term this an **atomic instruction**. Atomic not in the sense of atomic execution, but to referring to its syntax and understanding. Normally any instruction that has a semicolon can be separated into two atomic instructions. A compound instruction like ``Rd = add(Rs, add(Ru, #s6))`` doesn't have two atomic instructions, even though it has two distinct addition operations, they can't be split in two atomic instructions logically equivalent to the original (if one tries to express it as two ``Rd = add(Rs, Rt/#s16)`` instructions, the inner addition result would have to be stored in a different, temporal, register).

In the manual terminology, the two inner atomic instructions are normally called sub-instructions, that term won't be used, as it can't be applied to the inner atomic instructions of a compound instruction. Other terms mentioned in the manual and not used here include: parallel instructions, single instruction, single 32-bit word.

The given definition of normal instruction may clash with the one of atomic instruction, the difference is that the first one in used in the context of duplex and compound instructions (to distinguish it from them), and the second one is used in the context of static analysis.


Vocabulary
----------

Summing up the various terms defined are:

* Instruction definition.
	* Syntax.
	* Encoding.
	* Behavior.

* Actual instruction.
	* Text.
	* Value.

* 32-bit instruction.

* Constant extender instruction.

* Instruction:
	* Normal.
	* Duplex.
	* Compound.

* Atomic instruction.


Instruction encoding
====================

Each Hexagon instruction has an encoding, defined in the *Instruction Set*. Encodings are grouped in **encoding tables** (according to the type of instruction), which show multiple instruction encodings, one row per instruction and one column per instruction bit (32 in total). **Encoding bits** can either be fixed to 0/1 or belong to an instruction encoding field. **Fixed bits** identify univocally the instruction. An **encoding field** is a bit field that composes a specific value in an actual instruction. **Field values** store information about that instruction, generally about its operands, e.g., it can store a register number (for a register operand) or an immediate value (for an immediate operand). Each field is characterized by a name (shown after the encoding table) and a char. The **field char** is used to indicate, in the encoding table, that a particular bit (column) for a particular instruction (row) belongs to (or represents) that field. For example, register operand ``Rd`` in ``Rd = add(Rs, #s16)``, has a 5-bit instruction field named field ``d5``, that spans from bits 4:0 (inclusive), all marked, in the instruction encoding table, with the char ``d``.

A field carries information for a particular attribute of the instruction, it is not always obvious for which attribute this is, the field char is the best indicator of that, and usually follows the rules described next, that depend on the char itself:

* ``P``: Parse bits, to indicate a packet end, and optionally, also the end of a hardware loop.

* ``i``,``I``: Immediate operands, when there are two of them, the lowercase ``i`` matches the immediate operand with a lowercase letter and the uppercase ``I`` matches the immediate operand with a uppercase letter.

* ``s``,``t``,``d``: Register operands. The field char matches the letter following the register type, e.g., a general purpose register ``Rd`` matches to the char ``d``.

* ``-``: Not strictly a field, indicates that the value of the bit is irrelevant to fully qualify the instruction.


Vocabulary
----------

Summing up the various terms defined are:

* Encoding table.
* Instruction Encoding.
* Fixed bits.
* Encoding Field.
	* Field char.
	* Field name.
	* Field value.

Packets
=======

Delimited by brace characters (``{}``). All instructions in a packet are executed in parallel, register sources used reference the values they had before the packet execution, i.e., no instruction can affect the result of another in the same packet (except the registers that have a new-value suffix, e.g., ``R2.new`` or ``P0.new``, that indicate they take the register value created by another instruction in the packet). Jumps take place after all other instructions in the packet executes, without regard to the order of the jump instruction inside the packet.

Packet have an atomic execution, it is not allowed (in theory) to jump to the middle of a packet. The end of the packet is coded inside its last instruction (in the parse bits), but there is no bit in the instruction that signals the start of a packet, this is deduced from the context, i.e., if the previous instruction seen by the processor (or disassembler) is the last instruction of the previous packet, then the next instruction has to be the start of a new one. This means the restriction to jump to the middle of a packet is theoretical, because the processor has no way to ensure that the target instruction is not the first one of the packet, it just assumes so, it is the responsibility of the assembler to ensure that.


TODO
====

* Add the rest of the possible (at least seen by the compiler) field chars that correspond to the register operand.
  
* Field mask. Is it a useful term to define here?. Similar for "Instruction defining bits" (fixed bits).

* Describe instruction behavior. (Useful later for REIL translations.)
  
* Add a "Gotchas" section: Clarifications on themes that may not be correctly understood from reading the manual (e.g., how registers are accessed with suffixes like ``.h[]``).

* As of now, every instruction belongs to a packet, even one-instruction packets, can an instruction be outside a packet?
  
* Add a vocabulary section that would reunite all the definitions of the document? The current definition summaries at the end of every section seem enough for now. Maybe just add an abbreviations section.
