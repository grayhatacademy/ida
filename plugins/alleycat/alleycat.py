import idc
import idaapi
import idautils
import time

# This limits the depth of any individual path, as well as the maximum
# number of paths that will be searched; this is needed for practical
# reasons, as IDBs with tens of thousands of functions take a long time
# to exhaust all possible paths without some practical limitation.
#
# This is global so it's easy to change from the IDAPython prompt.
ALLEYCAT_LIMIT = 10000

class AlleyCatException(Exception):
    pass

class AlleyCat(object):
    '''
    Class which resolves function paths. This is where most of the work is done.
    '''

    def __init__(self, start_ea, end_ea):
        '''
        Class constructor.

        @start_ea - An address in the head function.
        @end_ea   - An address in the tail funciton.

        Returns None.
        '''
        global ALLEYCAT_LIMIT
        self.limit = ALLEYCAT_LIMIT

        self.paths = []

        # We work backwards via xrefs, so we start at the end and end at the start
        try:
            start = idaapi.get_func(end_ea).startEA
        except:
            raise AlleyCatException("Address 0x%X is not part of a function!" % end)
        try:
            end = idaapi.get_func(start_ea).startEA
        except:
            end = idc.BADADDR

        print "Generating call paths from %s to %s..." % (idc.Name(end), idc.Name(start))
        self._build_paths(start, end)

    def _build_paths(self, start, end=idc.BADADDR):
        partial_paths = [[start]]

        # Loop while there are still unresolve paths and while all path sizes have not exceeded ALLEYCAT_LIMIT
        while partial_paths and len(self.paths) < self.limit and len(partial_paths) < self.limit:
            # Initialize a unique set of callers for this iteration
            callers = set()

            # Callee is the last entry of the first path in partial paths.
            # The first path list will change as paths are completed and popped from the list.
            callee = partial_paths[0][-1]

            # Find all unique functions that reference the callee, assuming this path has not
            # exceeded ALLEYCAT_LIMIT.
            if len(partial_paths[0]) < self.limit:
                for xref in idautils.XrefsTo(callee):
                    caller = idaapi.get_func(xref.frm)
                    if caller and caller.startEA not in callers:
                        callers.add(caller.startEA)

            # If there are callers to the callee, remove the callee's current path
            # and insert new ones with the new callers appended.
            if callers:
                base_path = partial_paths.pop(0)
                for caller in callers:
                    # If we've reached the desired end node, don't go any further down this path
                    if caller == end:
                        self.paths.append((base_path + [caller])[::-1])
                    else:
                        partial_paths.append(base_path + [caller])
            # Else, our end node is not in this path, so don't include it in the finished path list.
            elif end not in partial_paths[0]:
                partial_paths.pop(0)
            # If there were no callers then this path has been exhaused and should be
            # popped from the partial path list into the finished path list.
            elif end in partial_paths[0]:
                # Paths start with the end function and end with the start function; reverse it.
                self.paths.append(partial_paths.pop(0)[::-1])


### Everything below here is just IDA UI/Plugin stuff ###


class AlleyCatGraphHistory(object):
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

class AlleyCatGraph(idaapi.GraphViewer):
    '''
    Displays the graph and manages graph actions.
    '''

    def __init__(self, results, title="AlleyCat Graph"):
        idaapi.GraphViewer.__init__(self, title)
        self.results = results

        self.nodes_ea2id = {}
        self.nodes_id2ea = {}
        self.edges = {}
        self.end_nodes = []
        self.edge_nodes = []
        self.start_nodes = []

        self.history = AlleyCatGraphHistory()
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

class idapathfinder_t(idaapi.plugin_t):

    flags = 0
    comment = ''
    help = ''
    wanted_name = 'AlleyCat'
    wanted_hotkey = ''

    def init(self):
        ui_path = "View/Graphs/"
        self.menu_contexts = []
        self.graph = None

        self.menu_contexts.append(idaapi.add_menu_item(ui_path,
                                "Find paths to the current function from...",
                                "Alt-6",
                                0,
                                self.FindPathsFromMany,
                                (None,)))
        self.menu_contexts.append(idaapi.add_menu_item(ui_path,
                                "Find paths from the current function to...",
                                "Alt-5",
                                0,
                                self.FindPathsToMany,
                                (None,)))

        return idaapi.PLUGIN_KEEP

    def term(self):
        for context in self.menu_contexts:
            idaapi.del_menu_item(context)
        return None

    def run(self, arg):
        pass

    def _current_function(self):
        return idaapi.get_func(ScreenEA()).startEA

    def _find_and_plot_paths(self, sources, targets):
        results = []

        for target in targets:
            for source in sources:
                s = time.time()
                r = AlleyCat(source, target).paths
                e = time.time()
                print "Found %d paths in %f seconds." % (len(r), (e-s))

                if r:
                    results += r
                else:
                    name = idc.Name(target)
                    if not name:
                        name = "0x%X" % target
                    print "No paths found to", name

        if results:
            # Be sure to close any previous graph before creating a new one.
            # Failure to do so may crash IDA.
            try:
                self.graph.Close()
            except:
                pass

            self.graph = AlleyCatGraph(results, 'Path Graph')
            self.graph.Show()

    def _get_user_selected_functions(self, many=False):
        functions = []
        ea = idc.ScreenEA()
        try:
            current_function = idc.GetFunctionAttr(ea, idc.FUNCATTR_START)
        except:
            current_function = None

        while True:
            function = idc.ChooseFunction("Select a function and click 'OK' until all functions have been selected. When finished, click 'Cancel' to display the graph.")
            # ChooseFunction automatically jumps to the selected function
            # if the enter key is pressed instead of clicking 'OK'. Annoying.
            if idc.ScreenEA() != ea:
                idc.Jump(ea)

            if not function or function == idc.BADADDR or function == current_function:
                break
            elif function not in functions:
                functions.append(function)

            if not many:
                break

        return functions

    def FindPathsToMany(self, arg):
        source = self._current_function()

        if source:
            targets = self._get_user_selected_functions(many=True)
            if targets:
                self._find_and_plot_paths([source], targets)

    def FindPathsFromMany(self, arg):
        target = self._current_function()

        if target:
            sources = self._get_user_selected_functions(many=True)
            if sources:
                self._find_and_plot_paths(sources, [target])

def PLUGIN_ENTRY():
    return idapathfinder_t()

