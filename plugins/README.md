IDA Plugins
===

Collection of IDA plugins that I've written to help ease RE work. Just drop them into IDA's *plugins* directory.

codatify.py
-----------

What it does: 

  * Defines ASCII strings that IDA's auto analysis missed
  * Defines functions/code that IDA's auto analysis missed
  * Converts all undefined bytes in the data segment into DWORDs (thus allowing IDA to resolve function and jump table pointers)

Blob of data before running codatify:

![Before codatify.py](images/undefined_data.png)

Running codatify:

![Running codatify.py](images/how_to_use_codatify.png)

Blob of data after running codatify:

![After codatify.py](images/defined_data.png)

localxrefs.py
-------------

What it does:

  * Finds references from within the current function to any highlighted text

Here's some MIPS code. Where does that $s2 register get set?

![Before localxrefs.py](images/where_does_s2_get_set.png)

Running localxrefs:

![Running localxrefs.py](images/how_to_run_localxrefs.png)

All references to $s2 in the current function are clearly listed:

![After localxrefs.py](images/localxrefs_output.png)

mipslocalvars.py
----------------

What it does:

  * Names stack variables used by the compiler for storing registers on the stack, simplifying stack data analysis (MIPS only)

A function's stack layout before running mipslocalvars:

![Before mipslocalvars.py](images/before_mipslocalvars.png)

Running mipslocalvars:

![Running mipslocalvars.py](images/how_to_run_mipslocalvars.png)

The function's stack layout after running mipslocalvars:

![After mipslocalvars.py](images/after_mipslocalvars.png)

