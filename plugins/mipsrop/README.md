mipsrop.py
==========

Features
----------

  * Allows you to search for suitable ROP gadgets in MIPS executable code
  * Built-in methods to search for common ROP gadgets

Running mipsrop:

![Running mipsrop.py](../../images/how_to_run_mipsrop.png)

Searching for ROP gadgets that put a stack address into the $a0 register:

![Using mipsrop.py](../../images/mipsrop_find.png)

Listing a summary of marked ROP gadgets in the current IDB:

![Listing mipsrop.py](../../images/mipsrop_summary.png)

Use *mipsrop.help()* to see all available options!

Installation
------------

Just copy mipsrop.py into your IDA *plugins* directory.
