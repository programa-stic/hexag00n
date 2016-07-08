*****************************
Qualcomm Hexagon Disassembler
*****************************

A standalone disassembler for the `Qualcomm Hexagon`_  architecture (v5) written in Python. It is used by the `IDA processor module`_ also included in this repository. The idea came from an `xda thread`_ by E\:V\:A. 

Although this dissassembler can be used standalone, the recommended disassembler is Qualcomm's own port of the objdump (and also llvm) for Hexagon included in the `Hexagon SDK`_.

.. _Qualcomm Hexagon: https://en.wikipedia.org/wiki/Qualcomm_Hexagon

.. _Hexagon SDK: https://developer.qualcomm.com/software/hexagon-dsp-sdk/tools

.. _IDA processor module: ../ida

.. _xda thread: http://forum.xda-developers.com/showthread.php?t=2598969

The disassembler obtains the instruction definitions from the "Hexagon V5/V55 Programmer’s Reference Manual" (also available in the `Hexagon SDK`_). It tries to support as many instructions from the manual as possible but the main focus is on control flow instructions, floating point and vector instructions are outside the scope of this project.

The disassembler was tested on Windows (8.1) and Linux (Ubuntu 14.04). It tries to be platform independent (like Python) as much as possible, but the main target for the use and testing was, as in the case for the IDA processor module, Windows.


How to use it
=============

Install:

.. code-block:: bash

	python -m pip install setuptools
	python setup.py install

Example: see the `test module`_.

.. _test module: ./tests.py


How it works
============

::

	Programmer’s
	Reference Manual

	        v
	        v     1. Parsing stage: ManualParser (importer.py).
	        v

	InstructionDefinition

	        v
	        v     2. Decoding stage: HexagonInstructionDecoder (decoder.py).
	        v

	InstructionTemplate

	        v
	        v     3. Disassembly stage: HexagonDisassembler (disassembler.py).
	        v

	HexagonInstruction


The *Hexagon V5/V55 Programmer’s Reference Manual* is converted (from pdf) to plain text, and parsed by ``ManualParser``, creating a list of ``InstructionDefinition`` objects, that have the basic definition of an instruction: syntax, encoding, and behavior. Each object of the list (``InstructionDefinition``) has a correspondence with one line of the encoding table for a particular instruction type, e.g., the syntax ``Rd=add(Rs,#s16)`` (and corresponding encoding and behavior) is stored in one ``InstructionDefinition``, for the instruction type *Add* (from the ALU32 class, ALU subclass).

The ``InstructionDefinition`` has all the information required to identify, and hence disassemble, an Hexagon instruction. The information in ``InstructionDefinition`` is decoded (by the ``HexagonInstructionDecoder``) into an ``InstructionTemplate`` (one-to-one correspondence), that doesn't add new information, but expands the original definition (e.g., identifying the instruction operands), as a way of preprocessing this information for the ``HexagonDisassembler``, which will use it to disassemble instruction bytes into an ``HexagonInstruction``.

The ``InstructionTemplate`` represents a kind of instruction definition from the manual, but the ``HexagonInstruction`` represents an actual instruction, instantiated from a stream of bytes (32 bits exactly). The information from the ``InstructionTemplate`` shouldn't be modified, the information that changes (e.g., register number or immediate value) is stored in the ``HexagonInstruction``.

The normal use of the disassembler involves only the last stage, from template to instruction, therefore the original manual is not needed. The disassembler takes 32 bits, and compares it with the encoding from the ``InstructionTemplate``, when (and if) a match is found, an ``HexagonInstruction`` is returned, which has the information from the ``InstructionTemplate`` filled with the data from the 32 bits.
The list of the ``InstructionTemplate`` objects is stored in a (pickle) file, and normally it doesn't need to be modified, unless new instructions want to be added (or old ones corrected), which would involve the first two stages.


Code architecture
=================

In this section the inner workings of the disassembler are explained in more detail. It's not necessary to read this section in order to use the disassembler or the IDA processor module, it is useful only for people wanting to modify (expand, correct, etc.) the disassembler behavior.


Disassembly stage
-----------------

When the ``HexagonDisassembler`` is instantiated (``__init__``) it loads the list of instruction templates (``inst_template_list``). Each ``InstructionTemplate`` has, apart from the instruction definition (syntax and encoding), several attributes that are of interest to generate the text output of a disassembled instruction and to perform code analysis. Some of these attributes are:

* ``reg_ops``: list of the register templates (analogous to a instruction template, this is a kind of register found in the instruction definitions, e.g., a general registers like ``Rx`` or a predicate register like ``Px``).
* ``imm_ops``: list of the immediate operand templates.
* ``is_duplex``: indicates if it is duplex instruction.
* ``branch``: indicates if the instruction performs either a jump or a call.

When ``HexagonDisassembler`` is used to disassembly an instruction (``disasm_one_inst``), it iterates the list of templates to find a match (``find_template``), if it does, it creates an ``HexagonInstruction`` from that template (``HexagonInstruction`` has a reference to the ``InstructionTemplate`` from which it was created) inserting the missing information, e.g., in ``Rd=add(Rs,#s16)``, ``Rd`` and ``Rs`` are set to a register number (R0-R31), and ``#s16`` is set to a 16 bit signed number. As the templates are not modified, since multiple ``HexagonInstruction`` may be pointing to the same ``InstructionTemplate`` (composition is used instead of inheritance although **inheritance should be used**), this "new" information (e.g., the number of ``Rd``) provided by the instruction bytes, is stored in the attributes of ``HexagonInstruction``. The most relevant are:

* ``reg_ops``: analogous to the template attribute with the same name, it contains the list of the register operands, although this are actual operands (similar to the contrast between ``HexagonInstruction`` and ``InstructionTemplate``), e.g., ``R4`` and ``R18`` could be the register operands from the add instruction.
* ``addr``: address of the instruction. Note that this is an attribute that cannot exist in ``InstructionTemplate`` because it describes a kind of instruction, but is not an actual instruction in a binary being disassembled, where an address could be assigned to it.
* ``text``: representation of a disassembled instruction in plain text (this is the output, for example, of typical programs like objdump).
* ``is_start_packet``/``is_end_packet``: indicates if it is the first/last instruction in the packet (can be both). This is another attribute, like ``addr``, that cannot exist in ``InstructionTemplate``, as it is a property that depends in the arrangement of the instruction with respect to the rest of them.

The exception to this model is the constant extender instruction, that doesn't have an ``InstructionTemplate``, instead the ``immext`` attribute of ``HexagonInstruction`` indicates that it is a constant extender, and the instruction is explicitly detected analyzing the parse bits (15:14).


Parsing stage
-------------

Most of the instruction information is taken from the manual, by the class ``ManualParser``. To simplify the parsing stage the manual was previously converted to plain text, using the site http://www.zamzar.com/ (which renders the most reliable plain text for the particular characteristics of the manual's pdf), and which should be used if the parsing stage is performed, as the parser was coded explicitly to deal with the particular output of this site.

The other source of instructions was the file ``hexagon_iset_v5.h`` from Qualcomm's objdump source code, parsed by the ``HeaderParser``. The only instructions imported are the duplex instructions, whose encoding the manual didn't specify clearly enough.

Both the manual and the header file are not provided with this tool but can be obtained from the `Hexagon SDK`_.

.. _Hexagon SDK: https://developer.qualcomm.com/software/hexagon-dsp-sdk/tools


Decoding stage
--------------

The ``HexagonInstructionDecoder`` creates the list of ``InstructionTemplate`` objects and saves it as a pickle file (in ``INST_TEMPL_PATH``). Most of the decoding logic is in the ``InstructionTemplate`` itself, ``HexagonInstructionDecoder`` has some functions to extract additional (not indispensable) information.


File structure
--------------

* ``disassembler.py``: ``HexagonDisassembler``.
* ``common.py``: Contains most of the information objects (e.g., ``HexagonInstruction``, ``InstructionTemplate``) and functions common to many classes.
* ``importer.py``: ``ManualParser`` and ``HeaderParser``.
* ``decoder.py``: ``HexagonInstructionDecoder``.
* ``objdump_wrapper.py``: ``ObjdumpWrapper`` used to interface with Qualcomm's objdump.


Testing
=======

The testing (``tests.py``) is done against the Qualcomm's objdump output, comparing the instruction texts provided but both the disassembler and objdump for discrepancies. To streamline the process ``HexagonDisassembler`` has an ``objdump_compatible`` argument to indicate to output text as close as possible to the observed objdump output (that many times do not match the syntax seen in the manual).

Like the manual, the objdump executable is not provided with this tool but can be obtained from the `Hexagon SDK`_. Once installed its path has to be provided to the ``ObjdumpWrapper`` for its use.


Package data
============

The list of instruction templates (``instruction_templates.pkl``) is included in the python package under the ``data`` directory, and marked as ``package_data`` in the framework setup script (``setup.py``).


Common abbreviations
====================

List of most common abbreviations used in the disassembler source code.

* ``const``: constant (usually referring to constant extenders).
* ``curr``: current.
* ``disasm``: disassembler (or disassembly, depending on the context).  
* ``extract``: used as a prefix to a function that extracts information from the instruction value (sometimes also ``get`` is used).
* ``fill_in``: used as a prefix to a function (like ``fill_in_reg_info``) to indicate that information from a template is being completed with information from the actual instruction, e.g., the number from a register in the instruction template is filled with the value extracted from the actual instruction.
* ``hex``: hexadecimal, usually Hexagon is not abbreviated like this to avoid confusion.
* ``hi``: Hexagon instruction, generally an object of the class ``HexagonInstruction``.
* ``immext``: constant extender, this is the syntax used by the constant extender instruction.
* ``imm``: immediate.
* ``inst``: instruction, generally referring to integer value of the instruction in memory, not the object (abbreviated as ``hi``), this is a more generic term.
* ``op``: operand.
* ``reg``: register.
* ``process``: used as a prefix to a function (like ``process_constant_extender``) to imply that the action is not mandatory, and maybe a check (inside the function) will be performed prior to it to clear as much as possible the logic from the caller, e.g., in ``process_constant_extender`` the check to see if the instruction is a constant extender is done inside the same function (if it is not, nothing more is done and it returns).


.. _fill_in: http://forum.wordreference.com/threads/fill-in-fill-out-and-fill-up.1453182/#post-7347463



TODOs
=====

General
-------

* Refactor in more files, split the ``common.py``.
  
* Add unit testing for specific functions, don't just test the disassembler output.

* Add instruction definitions (``instruction_definitions.pkl``) also in the package?

* Instruction text type: ``str`` vs ``unicode``. The ``future`` package is using ``unicode`` but that causes issued in the IDA proc. module where ``future`` package doesn't work and ``unicode`` breaks the output (so it is converted to ``str``). Standardize. For now I'm documenting all types as ``str``.

* Change ``RawInstruction`` to ``InstructionDefinition``, and maybe include it later inside the InstructionTemplate, instead of just copying (the same) syntax and encoding attributes.
  
* Create an ``InstructionField`` class, to cluster the different component of an inst. field (value, char, mask) in one object (and pass around easily).

* Rename all module files to reflect their contained classes (at least the disassembler and decoder).

* Objdump compatible mode: remove packet start/end ``{ }`` from unknown instructions, it is causing unnecessary discrepancies.

* REIL translation.

* Constant extenders: The extension is not getting the (negative) sign right. This is low priority, as branch targets (even with constant extenders) are always positive and are correctly processed.

* Register alias. Some are undocumented, e.g., ``htid := s8``.
 
* Hardware loops: detect ``endloop1``. Low priority.

* ``N`` operand. Used to identify an optional shift in the syntax (usually for each optional feature of an instruction there are many instruction variations with its own syntax, not a single syntax overloaded with optional features).

* Add a function that disassembles an entire packet, taking a stream of bytes as argument and returning an HexagonPacket.


Documentation
-------------

* Add vocabulary section (besides the "Common abbreviations") if useful.

* How to handle packets. Use the disassembler with a consecutive stream of bytes, and not jumping from one address to another, where packet information is lost.

* Decide between get and extract (preferred) prefixes form functions and standardize.

* Vocabulary: "Instruction database". List of imported instruction definitions from the manual or the headers, and maybe also the instruction templates. Search for alternative names.

* Vocabulary: "bit span" or "bit range", e.g., 5:8. Use definition in the code. Decide if the end bit is inclusive or exclusive and standardize.

* Use of "The" before class names, e.g. "The HexagonInstruction". Where is it convenient and where it generates unnecessary clutter?

* Parsing stage should be more generically defined as importing stage, the two definitions are mixed now. New instructions could be added manually, for example, and that would still belong to the importing stage.

* Document the use and motivation of Python 3 compatibility package: ``future``.

* Add a testing stage (for objdump tests). It would be the 4th step. HexagonInstructionDecoder >>> Match rate.


Discrepancies with objdump
--------------------------

* ``vcmpw.eq`` vs ``dfclass``. Both manual and header file favor the second but objdump print the first. These are low priority instructions, could be specifically ignored in the testing stage.


Multiprocessing
---------------

The disassembler is limited to a single core but simple jobs like ``extract_bits`` and ``find_template`` could be parallelized. There is a `multiprocessing example`_ that could be used as a starting point.

.. _multiprocessing example: https://pymotw.com/2/multiprocessing/communication.html
