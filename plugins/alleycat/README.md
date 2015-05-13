alleycat.py
================

Features
--------

  * Finds paths to a given code block inside a function
  * Finds paths between two or more functions
  * Generates interactive call graphs
  * Fully scriptable

Usage
-----

In IDA's UI, navigate to `View->Graphs->Find paths from the current function to...`; this will search for call paths from the function your cursor is currently in to one or more destination functions.

Select a function from the function chooser dialog and click `OK`.

You will be prompted again to choose another function; you may continue this process to select as many destination functions as you'd like. Once you are finished, click `Cancel` or press the `Esc` button.

The call graph is interactive; double-clicking on a graph node will jump to that location in IDA's disassembly window. You may also dynamically change which nodes are displayed at any time using the following hotkeys:

  * To only show paths that traverse a particular node: right-click the graph, select `Include node`, and then click on the node.
  * To exclude all paths that traverse a particular node: right-click the graph, select `Exclude node` and then click on the node.
  * To undo any of the above actions: right-click the graph, and select `Undo`.
  * To redo an undo: right-click the graph, and select `Redo`.
  * To reset the graph: right-click the graph, and select `Reset graph`.

For practical purposes, there is a maximum depth limit imposed on path searches. You can increase or decrease this limit in the IDAPython terminal:

```
Python> print ALLEYCAT_LIMIT
10000
Python> ALLEYCAT_LIMIT = 2500
```

Scripting
---------

To generate a list of unique paths between two functions, use the `AlleyCatFunctionPaths` class:

```
Python> print AlleyCatFunctionPaths(ScreenEA(), idc.LocByName('strcpy')).paths
```

To generate a list of unique paths from the between two code blocks inside a function, use the `AlleyCatCodePaths` class:

```
Python> print AlleyCatCodePaths(idaapi.get_func(idc.ScreenEA()).startEA, idc.ScreenEA())
```

To create an interactive graph, use the `AlleyCatGraph` class:

```
Python> paths = AlleyCatFunctionPaths(ScreenEA(), idc.LocByName('strcpy')).paths
Python> AlleyCatGraph(paths)
```

Installation
------------

Just copy alleycat.py into your IDA `plugins` directory.

