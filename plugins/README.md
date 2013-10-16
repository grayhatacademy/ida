IDA Plugins
===

Collection of IDA plugins.

codatify.py
===

What it does: 

	o Defines ASCII strings that IDA's auto analysis missed
	o Converts all undefined bytes in the data segment into DWORDs
	o Defines functions/code that IDA's auto analysis missed

![Running codatify.py](devttys0.github.com/ida/plugins/images/how_to_run_codatify.png)

localxrefs.py
===

What it does:

	o Finds references from within the current function to any highlighted text

mipslocalvars.py
===

What it does:

	o Appropriately names stack variables used by the compiler for storing registers on the stack
