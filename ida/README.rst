****************************
IDA Hexagon Processor Module
****************************

IDA processor module for the Hexagon `Qualcomm Hexagon`_  architecture (v5) written in Python. It depends on the `Qualcomm Hexagon Disassembler <../hexagondisasm>`_ .

The `most reliable Hexagon processor module`_ so far is from Willem Hengeveld (itsme@gsmk.de), written in C++ as a wrapper for Qualcomm's own objdump port for Hexagon. Another recently available processor module, also in C++, is `nogaxeh`_.

As this module is written in Python, it aims at platform independence, but as we only have a Windows license for IDA, this is the only platform where the module was tested.

NOTE: There is a bug for Python 2.7.11 in IDA for Windows (when opening IDA: ``IDAPython: imporing "site" failed``), Hex-Rays posted a `fix`_ in their blog.


.. _Qualcomm Hexagon: https://en.wikipedia.org/wiki/Qualcomm_Hexagon

.. _most reliable Hexagon processor module: https://github.com/gsmk/hexagon

.. _nogaxeh: https://github.com/ANSSI-FR/nogaxeh

.. _fix: http://www.hexblog.com/?p=949

.. _Qualcomm Hexagon Disassembler: ../hexagondisasm


How to use it
=============

Install the `Qualcomm Hexagon Disassembler <../hexagondisasm/README.rst#how-to-use-it>`_.

Copy ``hexagon.py`` to IDA's processor module directory, e.g., ``C:\Program Files (x86)\IDA 6.9\procs\`` (administrator access required).

In IDA's "Load a new file" window, under "Processor type", select ``Qualcomm Hexagon DSP v5[QDSP6V5]``. When loading a binary for the first time IDA will complain with "Undefined or unknown machine type 164" (this can be avoided with the `loader_elf_machine plugin`_), select "Yes", and ignore IDA's warning about unknown flag bits.

The module (quite verbose) logging is turned off by default but setting the environment variable ``IDP_LOGGING`` will turn it on.

By default the module outputs text highlighting the instruction operands, this can be disabled setting the environment variable ``IDP_OUT_SIMPLE_SYNTAX``. Disabling text highlighting is recommended for programmatic processing of the module's output.

Environment variables can be set through the OS or using IDA python console:

.. code-block:: python

	import os; os.environ["IDP_LOGGING"] = "True"


.. _loader_elf_machine plugin: ./loader_elf_machine_plugin


Notes on developing the module
==============================

There are not many IDA processor modules written in Python, ``proctemplate.py`` was used as a base, and ``msp430.py`` served as an additional reference.

The `The IDA Pro Book`_ was the main reference along with the `IDA SDK online doc`_.

.. _IDA SDK online doc: https://www.hex-rays.com/products/ida/support/sdkdoc/

.. _The IDA Pro Book: http://www.hexblog.com/?p=363


For an easy modification of the IDA processor module file, a link can be created to the repo file, to avoid continually copying it, e.g., in Windows:

.. code-block:: bash

	mklink "C:\Program Files (x86)\IDA 6.9\procs\hexagon.py" "C:\Users\test\hexag00n\ida\hexagon.py"

To make IDA take notice of the modifications in the module file the only way found was to restart IDA, so, as a convenience, IDA was started (and restarted) from the command line:

.. code-block:: bash

	C:\Program Files (x86)\IDA 6.9\idaq.exe -c example.elf

With ``-c`` used to "disassemble a new file (delete the old database)".

It is not clear which information populated by the processor module is used outside it. The ``cmd`` structure is handled apparently only in the cycle ``ana/emu/out``. There is also not a clear warning for not doing everything in one of the three functions.

The distinction between near and far doesn't apply in the Hexagon architecture, thus, according to the IDA documentation, everything should be referenced as near (e.g., jumps and calls).

Profiler
--------

Profiling is done in the main functions ``ana/emu/out`` and saved in the ``hexagondisasm`` module, to make it accessible from IDA's Python console (there should be a better way to do this):

.. code-block:: python

	import hexagondisasm
	import pstats
	prof_stats = pstats.Stats(hexagondisasm.profiler)
	prof_stats.strip_dirs().sort_stats('cumulative').print_stats(20)

Various notes
=============

In the IDA SDK terminology, a word is 2 bytes, whereas in Hexagon terminology it is 4 bytes, thus ``ua_next_long`` is used in the module (not ``ua_next_word``).

Nice and short explanation about IDA's algorithm to walk a binary: https://www.reddit.com/r/ReverseEngineering/comments/rtzb0/disassembling_in_ida/c48tiuy.

Useful Python regex tester: https://regex101.com/.

TODOs
=====

* Identify fatal functions that do not return and mark them accordingly as instructions of type ``CF_STOP``.

* Identify indirect call functions: ``immext`` + ``jump`` instruction.
