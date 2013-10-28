localxrefs.py
-------------

What it does:

  * Finds references from within the current function to any highlighted text

Here's some MIPS code. Where does that $s2 register get set?

![Before localxrefs.py](../images/where_does_s2_get_set.png)

Running localxrefs:

![Running localxrefs.py](../images/how_to_run_localxrefs.png)

All references to $s2 in the current function are clearly listed:

![After localxrefs.py](../images/localxrefs_output.png)

