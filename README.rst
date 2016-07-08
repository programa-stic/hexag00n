********
Hexag00n
********

Hexagon is Qualcomm's Digital Signal Processor included in the Snapdragon series System-on-a-Chip found in billions of cellphones and other consumer electronic devices worldwide. 

The Hexagon processor is a hardware multi-threaded, variable instruction length, VLIW processor architecture developed for efficient control and signal processing code execution at low power levels. It runs a proprietary Real Time Operating System and it is commonly used for modem and media processing applications. According to the manufacturer: `"As of 2012, multiple Hexagon cores form the processing engine behind virtually every commercially shipping 4G LTE modem by Qualcomm Technologies"`__ .

__ https://developer.qualcomm.com/software/hexagon-dsp-sdk/dsp-processor

This repository includes a collection of tools for security research and reverse engineering of the  `Qualcomm Hexagon (QDSP6)`_  .

* `Brief introduction to Hexagon`_.

* `Disassembler`_: Standalone disassembler written in Python, based on the ISA specification in the Hexagon Programmer’s Reference Manual.

* `IDA processor module`_: To load and analyze ELF binaries for the Hexagon architecture with IDA.


.. _Qualcomm Hexagon (QDSP6): https://en.wikipedia.org/wiki/Qualcomm_Hexagon

.. _Brief introduction to Hexagon: ./docs/intro_to_hexagon.rst

.. _Disassembler: ./hexagondisasm

.. _IDA processor module: ./ida


License
=======

The BSD 2-Clause License. For more information, see `LICENSE`_.

.. _LICENSE: ./LICENSE


Collaborators
=============

* Lucas Molas

* Iván Arce

* Juan Heguiabehere

* Christian Heitman

* D.C.


Contact Us
==========

The preferred way of participation is through the `GitHub’s issue tracker <https://github.com/programa-stic/hexag00n/issues>`_, but for a private channel of communication send an email to stic at fundacionsadosky dot org dot ar.
