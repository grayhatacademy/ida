IDA Plugins
===

Collection of IDA plugins that I've written to help ease RE work. Unless otherwise specified, just drop the .py files into IDA's *plugins* directory.

codatify
--------

  * Defines ASCII strings that IDA's auto analysis missed
  * Defines functions/code that IDA's auto analysis missed
  * Converts all undefined bytes in the data segment into DWORDs (thus allowing IDA to resolve function and jump table pointers)

localxrefs
----------

  * Finds references from within the current function to any highlighted text

mipslocalvars
-------------

  * Names stack variables used by the compiler for storing registers on the stack, simplifying stack data analysis (MIPS only)

mipsrop
-------

  * Allows you to search for suitable ROP gadgets in MIPS executable code (MIPS only)

pathfinder
----------

  * Finds paths between two or more functions
  * Generates interactive call graphs
  * Fully scriptable
