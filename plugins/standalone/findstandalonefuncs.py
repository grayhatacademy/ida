import idc
import idautils

class Function(object):

    def __init__(self, **kwargs):
        for (k,v) in kwargs.iteritems():
            setattr(self, k, v)

        self.name = idc.Name(self.start)

class StandaloneFunctionFinder(object):

    MIN_XREFS = 25

    def __init__(self):
        self.standalones = []
        self._find_standalones()

    def _find_standalones(self):
        for func_ea in idautils.Functions():
            nxrefs = len([x for x in idautils.XrefsTo(func_ea)])
            if nxrefs >= self.MIN_XREFS:
                func = idaapi.get_func(func_ea)
                if func:
                    standalone_function = True
                    ea = func.startEA

                    while ea <= func.endEA:
                        if idaapi.is_call_insn(ea):
                            standalone_function = False
                            break

                        idaapi.decode_insn(ea)
                        ea += idaapi.cmd.size

                    if standalone_function:
                        self.standalones.append(Function(start=func.startEA, end=func.endEA, xrefs=nxrefs, loop=self.has_loop(func)))

        self.standalones.sort(key=lambda f: f.xrefs, reverse=True)

    def has_loop(self, func):
        blocks = [func.startEA] + [block.endEA for block in idaapi.FlowChart(func)]
        for block in blocks:
            for xref in idautils.XrefsTo(block):
                xref_func = idaapi.get_func(xref.frm)
                if xref_func and xref_func.startEA == func.startEA:
                    if xref.frm <= block:
                        return True
        return False

    def show(self):
        delim = '-'
        col1_title = "Function"
        col2_title = "Xrefs"
        col3_title = "Has Loop(s)"
        max_str_len = len(col1_title)

        for func in self.standalones:
            if len(func.name) > max_str_len:
                max_str_len = len(func.name)

        fmt = "| %%-%ds | %%-10s | %%-11s |" % max_str_len
        header = fmt % (col1_title, col2_title, col3_title)
        delim_len = len(header)

        print ""
        print delim * delim_len
        print header
        print delim * delim_len
        for func in self.standalones:
            print fmt % (func.name, str(func.xrefs), str(func.loop))
        print delim * delim_len
        print "Found %d standalone functions with at least %d xrefs each" % (len(self.standalones), self.MIN_XREFS)
        print ""

def StandaloneFunctions(quiet=True):
    obj = StandaloneFunctionFinder()
    if not quiet:
        obj.show()
    return [x.start for x in obj.standalones]

class standalone_function_finder_t(idaapi.plugin_t):

    flags = 0
    comment = "Finds functions that don't call any other functions"
    help = ''
    wanted_name = 'StandaloneFunctions'
    wanted_hotkey = ''

    def init(self):
        self.context_menu = idaapi.add_menu_item("Search/", "standalone functions", "Alt-S", 0, self.RunFromMenu, (None,))
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.del_menu_item(self.context_menu)
        return None

    def run(self):
        StandaloneFunctions(quiet=False)

    def RunFromMenu(self, arg):
        StandaloneFunctions(quiet=False)

def PLUGIN_ENTRY():
    return standalone_function_finder_t()

