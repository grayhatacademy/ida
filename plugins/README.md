IDA Plugins
===

Collection of IDA plugins that I've written to help with embedded RE work.
Unless otherwise specified, just drop the .py files into IDA's `plugins` directory.

alleycat
----------

  * Finds paths between two or more functions
  * Generates interactive call graphs
  * Fully scriptable

codatify
--------

  * Defines ASCII strings that IDA's auto analysis missed
  * Defines functions/code that IDA's auto analysis missed
  * Converts all undefined bytes in the data segment into DWORDs (thus allowing IDA to resolve function and jump table pointers)

fluorescence
------------

  * Highlights all call instructions in an IDB.

leafblower
----------

  * Assists in identifying standard POSIX functions in MIPS/ARM code.

localxrefs
----------

  * Finds references from within the current function to any highlighted text

mipslocalvars
-------------

  * Names stack variables used by the compiler for storing registers on the stack, simplifying stack data analysis (MIPS only)

mipsrop
-------

  * Allows you to search for suitable ROP gadgets in MIPS executable code (MIPS only)

rizzo
-----

  * Performs function signature generation and matching to identify common functions between different IDBs

