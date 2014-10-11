localxrefs.py
=============

Features
--------

  * Finds references to any selected text from within the current function

Usage
-----

Here's some MIPS code. Where does that $s2 register get set?

![Before localxrefs.py](../../images/where_does_s2_get_set.png)

Running localxrefs:

![Running localxrefs.py](../../images/how_to_run_localxrefs.png)

All references to $s2 in the current function are clearly listed:

![After localxrefs.py](../../images/localxrefs_output.png)

And, these references can be highlighted in the disassembly view by running *localxrefs.highlight()* in IDA's Python terminal:

![Highlight localxrefs.py](../../images/localxrefs_highlight.png)

(To un-highlight, run *localxrefs.unhighlight()*)

Installation
------------

Just copy localxrefs.py into your IDA *plugins* directory.
