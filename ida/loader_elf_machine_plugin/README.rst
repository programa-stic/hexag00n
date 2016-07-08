*********************************************************************
IDA plugin to fix the "Undefined or unknown machine type 164" warning
*********************************************************************

This plugin intercepts the ``loader_elf_machine`` notification (that corresponds to the event: "ELF loader machine type checkpoint") and sets the Hexagon IDA processor module to disassemble the binary. This procedure eliminates the warning "Undefined or unknown machine type 164" (164 being the Hexagon machine type for the ELF format).

This not only eases IDA's interactive disassembly, but more importantly, it allow to run IDA in batch mode (``-B`` and ``-A`` switches in when `running IDA in command line`_) to disassemble binaries (and also run other IDA processing scripts on them) automatically, without human interaction. Without this fix batch mode silently fails for unknown machine types.

.. _running IDA in command line: https://www.hex-rays.com/products/ida/support/idadoc/417.shtml


How to use it
=============

The plugin ``loader_elf_machine_plugin.cpp`` has to be built with IDA's SDK and the resulting binary has to be copied to the ``plugins`` directory of IDA (e.g., ``C:\Program Files (x86)\IDA 6.9\plugins``).

A built version of the plugin is available (``loader_elf_machie_plugin.plw``), built with IDA SDK v6.9 for Windows (as a 32-bit DLL).

Once installed, no matter the processor type selected, if the ELF file is marked as an Hexagon binary (``e_machine`` attribute of the ELF header set to 164), the Hexagon processor module will be used to disassemble it, and the "Undefined or unknown machine type 164" won't be displayed.


How to build the plugin
=======================

The best guide to build an IDA plugin is in chapter 17, "The IDA plug-in architecture", of the "The IDA Pro Book".

Particularly for Windows, the *Microsoft Visual C++ Express 2008* was used, noting, as the book says, that until a ``.cpp`` file is added to the project some (C++) options that the book mentions won't be available. Apart from that there was no other complication.
