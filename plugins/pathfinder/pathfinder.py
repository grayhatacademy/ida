import idc
import idaapi
import idautils
import time

class History(object):
    '''
    Manages include/exclude graph history.
    '''

    INCLUDE_ACTION = 0
    EXCLUDE_ACTION = 1

    def __init__(self):
        self.reset()

    def reset(self):
        self.history = []
        self.includes = []
        self.excludes = []
        self.history_index = 0
        self.include_index = 0
        self.exclude_index = 0

    def update_history(self, action):
        if self.excludes and len(self.history)-1 != self.history_index:
            self.history = self.history[0:self.history_index+1]
        self.history.append(action)
        self.history_index = len(self.history)-1

    def add_include(self, obj):
        if self.includes and len(self.includes)-1 != self.include_index:
            self.includes = self.includes[0:self.include_index+1]
        self.includes.append(obj)
        self.include_index = len(self.includes)-1
        self.update_history(self.INCLUDE_ACTION)

    def add_exclude(self, obj):
        if len(self.excludes)-1 != self.exclude_index:
            self.excludes = self.excludes[0:self.exclude_index+1]
        self.excludes.append(obj)
        self.exclude_index  = len(self.excludes)-1
        self.update_history(self.EXCLUDE_ACTION)

    def get_includes(self):
        return set(self.includes[0:self.include_index+1])

    def get_excludes(self):
        return set(self.excludes[0:self.exclude_index+1])

    def undo(self):
        if self.history:
            if self.history[self.history_index] == self.INCLUDE_ACTION:
                if self.include_index >= 0:
                    self.include_index -= 1
            elif self.history[self.history_index] == self.EXCLUDE_ACTION:
                if self.exclude_index >= 0:
                    self.exclude_index -= 1

            self.history_index -= 1
            if self.history_index < 0:
                self.history_index = 0

    def redo(self):
        self.history_index += 1
        if self.history_index >= len(self.history):
            self.history_index = len(self.history)-1

        if self.history[self.history_index] == self.INCLUDE_ACTION:
            if self.include_index < len(self.includes)-1:
                self.include_index += 1
        elif self.history[self.history_index] == self.EXCLUDE_ACTION:
            if self.exclude_index < len(self.excludes)-1:
                self.exclude_index += 1

class PathFinderGraph(idaapi.GraphViewer):
    '''
    Displays the graph and manages graph actions.
    '''

    def __init__(self, results, title="PathFinder Graph"):
        idaapi.GraphViewer.__init__(self, title)
        self.results = results

        self.nodes_ea2id = {}
        self.nodes_id2ea = {}
        self.edges = {}
        self.end_nodes = []
        self.edge_nodes = []
        self.start_nodes = []

        self.history = History()
        self.include_on_click = False
        self.exclude_on_click = False

    def Show(self):
        '''
        Display the graph.

        Returns True on success, False on failure.
        '''
        if not idaapi.GraphViewer.Show(self):
            return False
        else:
            self.cmd_undo = self.AddCommand("Undo", "U")
            self.cmd_redo = self.AddCommand("Redo", "R")
            self.cmd_reset = self.AddCommand("Reset graph", "G")
            self.cmd_exclude = self.AddCommand("Exclude node", "X")
            self.cmd_include = self.AddCommand("Include node", "I")
            return True

    def OnRefresh(self):
        # Clear the graph before refreshing
        self.Clear()
        self.nodes_ea2id = {}
        self.nodes_id2ea = {}
        self.edges = {}
        self.end_nodes = []
        self.edge_nodes = []
        self.start_nodes = []

        includes = self.history.get_includes()
        excludes = self.history.get_excludes()

        for path in self.results:
            parent_node = None

            # Check to see if this path contains all nodes marked for explicit inclusion
            if (set(path) & includes) != includes:
                continue

            # Check to see if this path contains any nodes marked for explicit exclusion
            if (set(path) & excludes) != set():
                continue

            for ea in path:
                # If this node already exists, use its existing node ID
                if self.nodes_ea2id.has_key(ea):
                    this_node = self.nodes_ea2id[ea]
                # Else, add this node to the graph
                else:
                    this_node = self.AddNode(self.get_name_by_ea(ea))
                    self.nodes_ea2id[ea] = this_node
                    self.nodes_id2ea[this_node] = ea

                # If there is a parent node, add an edge between the parent node and this one
                if parent_node is not None:
                    self.AddEdge(parent_node, this_node)
                    if this_node not in self.edges[parent_node]:
                        self.edges[parent_node].append(this_node)

                # Update the parent node for the next loop
                parent_node = this_node
                if not self.edges.has_key(parent_node):
                    self.edges[parent_node] = []

            try:
                # Track the first, last, and next to last nodes in each path for
                # proper colorization in self.OnGetText.
                self.start_nodes.append(self.nodes_ea2id[path[0]])
                self.end_nodes.append(self.nodes_ea2id[path[-1]])
                self.edge_nodes.append(self.nodes_ea2id[path[-2]])
            except:
                pass

        return True

    def OnGetText(self, node_id):
        color = idc.DEFCOLOR

        if node_id in self.edge_nodes:
            color = 0x00ffff
        elif node_id in self.start_nodes:
            color = 0x00ff00
        elif node_id in self.end_nodes:
            color = 0x0000ff

        return (self[node_id], color)

    def OnHint(self, node_id):
        hint = ""

        try:
            for edge_node in self.edges[node_id]:
                hint += "%s\n" % self[edge_node]
        except Exception as e:
            pass

        return hint

    def OnCommand(self, cmd_id):
        if self.cmd_undo == cmd_id:
            if self.include_on_click or self.exclude_on_click:
                self.include_on_click = False
                self.exclude_on_click = False
            else:
                self.history.undo()
            self.Refresh()
        elif self.cmd_redo == cmd_id:
            self.history.redo()
            self.Refresh()
        elif self.cmd_include == cmd_id:
            self.include_on_click = True
        elif self.cmd_exclude == cmd_id:
            self.exclude_on_click = True
        elif self.cmd_reset == cmd_id:
            self.include_on_click = False
            self.exclude_on_click = False
            self.history.reset()
            self.Refresh()

    def OnClick(self, node_id):
        if self.include_on_click:
            self.history.add_include(self.nodes_id2ea[node_id])
            self.include_on_click = False
        elif self.exclude_on_click:
            self.history.add_exclude(self.nodes_id2ea[node_id])
            self.exclude_on_click = False
        self.Refresh()

    def OnDblClick(self, node_id):
        xref_locations = []
        node_ea = self.get_ea_by_name(self[node_id])

        if self.edges.has_key(node_id):
            for edge_node_id in self.edges[node_id]:

                edge_node_name = self[edge_node_id]
                edge_node_ea = self.get_ea_by_name(edge_node_name)

                if edge_node_ea != idc.BADADDR:
                    for xref in idautils.XrefsTo(edge_node_ea):
                        # Is the specified node_id the source of this xref?
                        if self.match_xref_source(xref, node_ea):
                            xref_locations.append((xref.frm, edge_node_ea))

        if xref_locations:
            xref_locations.sort()

            print ""
            print "Path Xrefs from %s:" % self[node_id]
            print "-" * 100
            for (xref_ea, dst_ea) in xref_locations:
                print "%-50s  =>  %s" % (self.get_name_by_ea(xref_ea), self.get_name_by_ea(dst_ea))
            print "-" * 100
            print ""

            idc.Jump(xref_locations[0][0])
        else:
            idc.Jump(node_ea)

    def match_xref_source(self, xref, source):
        # TODO: This must be modified if support for graphing function blocks is added.
        return ((xref.type != idc.fl_F) and (idc.GetFunctionAttr(xref.frm, idc.FUNCATTR_START) == source))

    def get_ea_by_name(self, name):
        '''
        Get the address of a location by name.

        @name - Location name

        Returns the address of the named location, or idc.BADADDR on failure.
        '''
        # This allows support of the function offset style names (e.g., main+0C)
        # TODO: Is there something in the IDA API that does this already??
        if '+' in name:
            (func_name, offset) = name.split('+')
            base_ea = idc.LocByName(func_name)
            if base_ea != idc.BADADDR:
                try:
                    ea = base_ea + int(offset, 16)
                except:
                    ea = idc.BADADDR
        else:
            ea = idc.LocByName(name)
            if ea == idc.BADADDR:
                try:
                    ea = int(name, 0)
                except:
                    ea = idc.BADADDR

        return ea

    def get_name_by_ea(self, ea):
        '''
        Get the name of the specified address.

        @ea - Address.

        Returns a name for the address, one of idc.Name, idc.GetFuncOffset or 0xXXXXXXXX.
        '''
        name = idc.Name(ea)
        if not name:
            name = idc.GetFuncOffset(ea)
            if not name:
                name = "0x%X" % ea
        return name

class PathFinder(object):
    '''
    Base class for finding the path between two addresses.
    '''
    # Subclass should override this with an appropriate method
    # to perform colorization of nodes in the main IDA view.
    COLORIZE = None

    # Limit the max recursion depth
    MAX_DEPTH = 500

    def __init__(self, destination):
        '''
        Class constructor.

        @destination - The end node ea.

        Returns None.
        '''
        self.tree = {}
        self.nodes = {}
        self.depth = 0
        self.last_depth = 0
        self.full_paths = []
        self.current_path = []
        self.destination = self._name2ea(destination)
        self.build_call_tree(self.destination)

    def __enter__(self):
        return self

    def __exit__(self, t, v, traceback):
        return

    def _name2ea(self, nea):
        if isinstance(nea, type('')):
            return idc.LocByName(nea)
        return nea

    def paths_from(self, source, exclude=[], include=[], xrefs=[], noxrefs=[]):
        '''
        Find paths from a source node to a destination node.

        @source  - The source node ea to start the search from.
        @exclude - A list of ea's to exclude from paths.
        @include - A list of ea's to include in paths.
        @xrefs   - A list of ea's that must be referenced from at least one of the path nodes.
        @noxrefs - A list of ea's that must not be referenced from any of the path nodes.

        Returns a list of path lists.
        '''
        paths = []
        good_xrefs = []
        bad_xrefs = []

        source = self._name2ea(source)

        # If all the paths from the destination node have not already
        # been calculated, find them first before doing anything else.
        if not self.full_paths:
            s = time.time()
            self.find_paths(self.destination, source)
            e = time.time()

        for xref in xrefs:
            xref = self._name2ea(xref)

            for x in idautils.XrefsTo(xref):
                f = idaapi.get_func(x.frm)
                if f:
                    good_xrefs.append(f.startEA)

        for xref in noxrefs:
            bad_xrefs.append(self._name2ea(xref))
            xref = self._name2ea(xref)

            for x in idautils.XrefsTo(xref):
                f = idaapi.get_func(x.frm)
                if f:
                    bad_xrefs.append(f.startEA)

        for p in self.full_paths:
            try:
                index = p.index(source)

                if exclude:
                    for ex in excludes:
                        if ex in p:
                            index = -1
                            break

                if include:
                    orig_index = index
                    index = -1

                    for inc in include:
                        if inc in p:
                            index = orig_index
                            break

                if good_xrefs:
                    orig_index = index
                    index = -1

                    for xref in good_xrefs:
                        if xref in p:
                            index = orig_index

                    if index == -1:
                        print "Sorry, couldn't find", good_xrefs, "in", p

                if bad_xrefs:
                    for xref in bad_xrefs:
                        if xref in p:
                            index = -1
                            break

                # Be sure to include the destination and source nodes in the final path
                p = [self.destination] + p[:index+1]
                # The path is in reverse order (destination -> source), so flip it
                p = p[::-1]
                # Ignore any potential duplicate paths
                if p not in paths:
                    paths.append(p)
            except:
                pass

        return paths

    def find_paths(self, ea, source=None, i=0):
        '''
        Performs a depth-first (aka, recursive) search to determine all possible call paths originating from the specified location.
        Called internally by self.paths_from.

        @ea - The start node to find a path from.
        @i  - Used to specify the recursion depth; for internal use only.

        Returns None.
        '''
        # Increment recursion depth counter by 1
        i += 1
        # Get the current call graph depth
        this_depth = self.depth

        # If this is the first level of recursion and the call
        # tree has not been built, then build it.
        if i == 1 and not self.tree:
            self.build_call_tree(ea)

        # Don't recurse past MAX_DEPTH
        if i >= self.MAX_DEPTH:
            return

        # Loop through all the nodes in the call tree, starting at the specified location
        for (reference, children) in self.nodes[ea].iteritems():
            # Does this node have a reference that isn't already listed in our current call path?
            if reference and reference not in self.current_path:
                    # Increase the call depth by 1
                    self.depth += 1
                    # Add the reference to the current path
                    self.current_path.append(reference)
                    # Find all paths from this new reference
                    self.find_paths(reference, source, i)

        # If we didn't find any additional references to append to the current call path (i.e., this_depth == call depth)
        # then we have reached the limit of this call path.
        if self.depth == this_depth:
            # If the current call depth is not the same as the last recursive call, and if our list of paths
            # does not already contain the current path, then append a copy of the current path to the list of paths
            if self.last_depth != self.depth and self.current_path and self.current_path not in self.full_paths:
                self.full_paths.append(list(self.current_path))
            # Decrement the call path depth by 1 and pop the latest node out of the current call path
            self.depth -= 1
            if self.current_path:
                self.current_path.pop(-1)

        # Track the last call depth
        self.last_depth = self.depth

    def build_call_tree(self, ea):
        '''
        Performs a breadth first (aka, iterative) search to build a call tree to the specified address.

        @ea - The node to generate a tree for.

        Returns None.
        '''
        self.tree[ea] = {}
        self.nodes[ea] = self.tree[ea]
        nodes = [ea]

        while nodes:
            new_nodes = []

            for node in nodes:
                if node and node != idc.BADADDR:
                    node_ptr = self.nodes[node]

                    for reference in self.node_xrefs(node):
                        if reference not in self.nodes:
                            node_ptr[reference] = {}
                            self.nodes[reference] = node_ptr[reference]
                            new_nodes.append(reference)
                        elif not node_ptr.has_key(reference):
                            node_ptr[reference] = self.nodes[reference]

            nodes = new_nodes

    def node_xrefs(self, node):
        '''
        This must be overidden by a subclass to provide a list of xrefs.

        @node - The EA of the node that we need xrefs for.

        Returns a list of xrefs to the specified node.
        '''
        return []

class FunctionPathFinder(PathFinder):
    '''
    Subclass to generate paths between functions.
    '''

    def __init__(self, destination):
        # IDA 6.4 needs the extra import here, else idaapi is type None
        import idaapi
        func = idaapi.get_func(self._name2ea(destination))
        super(FunctionPathFinder, self).__init__(func.startEA)

    def node_xrefs(self, node):
        '''
        Return a list of function EA's that reference the given node.
        '''
        xrefs = []

        for x in idautils.XrefsTo(node):
            if x.type != idaapi.fl_F:
                f = idaapi.get_func(x.frm)
                if f and f.startEA not in xrefs:
                    xrefs.append(f.startEA)
        return xrefs

class BlockPathFinder(PathFinder):
    '''
    Subclass to generate paths between code blocks inside a function.
    '''

    def __init__(self, destination):
        func = idaapi.get_func(destination)
        self.blocks = idaapi.FlowChart(f=func)
        self.block_table = {}

        for block in self.blocks:
            self.block_table[block.startEA] = block
            self.block_table[block.endEA] = block

        self.source_ea = func.startEA
        dst_block = self.LookupBlock(destination)

        if dst_block:
            self.COLORIZE = self._colorize_block
            super(BlockPathFinder, self).__init__(dst_block.startEA)

    def _colorize_block(self, block_ea, color=idc.DEFCOLOR):
        if self.block_table.has_key(block_ea):
            ea = self.block_table[block_ea].startEA
            while ea < self.block_table[block_ea].endEA:
                idc.SetColor(ea, idc.CIC_ITEM, color)
                ea = idc.NextAddr(ea)

    def LookupBlock(self, ea):
        try:
            return self.block_table[ea]
        except:
            for block in self.blocks:
                if ea >= block.startEA and ea < block.endEA:
                    return block
        return None

    def node_xrefs(self, node):
        '''
        Return a list of blocks that reference the provided block.
        '''
        xrefs = []

        block = self.LookupBlock(node)
        if block:
            for xref in idautils.XrefsTo(block.startEA):
                xref_block = self.LookupBlock(xref.frm)
                if xref_block and xref_block.startEA not in xrefs:
                    xrefs.append(xref_block.startEA)

        return xrefs

class Find(object):

    def __init__(self, start=[], end=[], include=[], exclude=[], xrefs=[], noxrefs=[]):
        self.start = self._obj2list(start)
        self.end = self._obj2list(end)
        self.include = self._obj2list(include)
        self.exclude = self._obj2list(exclude)
        self.xrefs = self._obj2list(xrefs)
        self.noxrefs = self._obj2list(noxrefs)

        if len(self.start) > 0:
            first_ea = self._obj2ea(self.start[0])
            func = idaapi.get_func(self.start[0])
            if func:
                results = []

                end_func = idaapi.get_func(self.end[0])
                if end_func and end_func.startEA == self.end[0]:
                    pfclass = FunctionPathFinder
                else:
                    pfclass = BlockPathFinder
                print pfclass

                for destination in self.end:
                    pf = pfclass(destination)
                    for source in self.start:
                        results += pf.paths_from(source, exclude=self.exclude, include=self.include, xrefs=self.xrefs, noxrefs=self.noxrefs)
                    del pf

                print "RESULTS:", results
                if results:
                    pg = PathFinderGraph(results)
                    pg.Show()
                    del pg

    def _obj2list(self, obj):
        '''
        Converts the supplied object to a list, if it is not already a list.

        @obj - The object.

        Returns a list.
        '''
        l = []

        if not isinstance(obj, type([])):
            l.append(self._obj2ea(obj))
        else:
            for o in obj:
                l.append(self._obj2ea(o))
        return l

    def _obj2ea(self, ea):
        if isinstance(ea, type('')):
            return idc.LocByName(ea)
        return ea

#if __name__ == "__main__":
    #Find(['main'], ['strcpy'])
    #Find('execute_other_requests', 'loc_408E80')

