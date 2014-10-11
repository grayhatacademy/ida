mipslocalvars.py
================

Features
--------

  * Names stack variables used by the compiler for storing registers on the stack, simplifying stack data analysis (MIPS only)

Usage
-----

A function's stack layout before running mipslocalvars:

![Before mipslocalvars.py](../../images/before_mipslocalvars.png)

Running mipslocalvars:

![Running mipslocalvars.py](../../images/how_to_run_mipslocalvars.png)

The function's stack layout after running mipslocalvars:

![After mipslocalvars.py](../../images/after_mipslocalvars.png)

Installation
------------

Just copy mipslocalvars.py into your IDA *plugins* directory.
