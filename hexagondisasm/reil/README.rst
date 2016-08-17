***************
REIL Translator
***************

Hexagon to REIL translator.

Intended primarily to be used with `BARF`_, which implements a modified version of the original `REIL specification`_. 

.. _REIL specification: https://www.zynamics.com/binnavi/manual/html/reil_language.htm

.. _BARF: https://github.com/programa-stic/barf-project

The **Hexagon instructions behavior** (defined in the Reference Manual) is used to perform the translation. This behavior is actually a pseudo-code that implements Hexagon instructions in more simple (low level) and atomic ones, that are closer to the REIL language. This pseudo-code is not formally defined (AFAIK), there is no specification for it in the Reference Manual, but it is very regular, so an unofficial specification can be derived from it, as the behavior instructions are included to the translator.

The translation is perform on the behavior pseudo-code instructions themselves, so the translator relies in the correct definition of the Hexagon instruction behaviors.

The behavior code is parsed using `PLY`_, the translation is performed during the parsing process (as opposed to constructing an AST and processing that later).

.. _PLY: https://github.com/dabeaz/ply


TODOs
=====

* Define a small subset of Hexagon instructions to translate for the initial version of the translator (whose objective is not the translation itself but to define the underlying mechanism of the translation process). These subset should be the easiest of the most used instructions (as observed in the binary examples like ``factorial.elf``).

* Define a basic API to use the translator. This API should be as close as BARF's as possible (even though their underlying mechanisms of translation differ), to facilitate its future integration.

* Explain difference between BARF translation and this one.

* Define an informal specification for the behavior pseudo-code instructions (maybe a summary, compilation, or classification are more adequate terms). At the very least, every pseudo-code instruction added to the translator should be included in a list.

* Add an example in this documentation of a simple translation of an Hexagon instruction with 3 or 4 behavior pseudo-code instructions.

* Define vocabulary. There is an Hexagon instruction (e.g., ``Rd = add(Rs, #s16)``) and its corresponding behavior pseudo-code instructions that represent it (e.g., ``Rd = Rs + #s``). Only when the context is clear enough the simple "instruction" term (without additional qualifications) should be used.

* Introduce PLY translation source code progressively, clearly documenting and explaining what it does, do not add it all at once.

* Review PLY documentation, the current implementation of the translator generates the REIL code in a single pass (during the parsing process), review the name of that parsing mode. Is this mode enough to cover all of the logic of the behavior pseudo-code like ``if/else`` branches and loops?

* Add unit testing (similar to BARF).

* Currently this translator is a sub-package (``reil``) of the disassembler python package (``hexagondisasm``). Should this be in a separate package?

* Review the behavior instructions of the repository database (``hexagondisasm/data/instruction_definitions.pkl``) to check how many Hexagon behaviors have been correctly parsed from the Manual, and if that's enough for the first version of the translator.

* Add PLY to the dependencies in ``setup.py``.
