import re
import idc
import idaapi
import idautils
from operator import attrgetter

IDA_FUNCTION_PROFILES = None

class IDAProfilerXref(object):

    def __init__(self, **kwargs):
        for (k, v) in kwargs.iteritems():
            setattr(self, k, v)

class IDAFunctionProfiler(object):

    def __init__(self):
        self.functions = {}
        self._build_string_xrefs()
        self._build_function_xrefs()
        self._sort_functions()

    def _build_string_xrefs(self):
        #print "Building string profiles..."
        #orig_functions_len = len(self.functions)

        for string in idautils.Strings():
            keystr = str(string)

            for xref in idautils.XrefsTo(string.ea):
                func = idaapi.get_func(xref.frm)
                if func:
                    if not self.functions.has_key(func.startEA):
                        self.functions[func.startEA] = list()

                    self.functions[func.startEA].append(IDAProfilerXref(ea=string.ea, string=keystr, xref=xref.frm, type=str))

        #print "Built xref profiles for %d strings" % (len(self.functions) - orig_functions_len)

    def _build_function_xrefs(self):
        #print "Building function profiles..."
        #orig_functions_len = len(self.functions)

        for function in idautils.Functions():
            for xref in idautils.XrefsTo(function):
                func = idaapi.get_func(xref.frm)
                if func:
                    if not self.functions.has_key(func.startEA):
                        self.functions[func.startEA] = list()

                    self.functions[func.startEA].append(IDAProfilerXref(ea=function, string=idc.Name(function), xref=xref.frm, type=callable))

        #print "Built xref profiles for %d functions" % (len(self.functions) - orig_functions_len)

    def _sort_functions(self):
        # Sort by the xref source so that when per-function xrefs are displayed, they are
        # displayed in the order in which they appear in the linear disassembly.
        for function in self.functions.keys():
            self.functions[function] = sorted(self.functions[function], key=attrgetter('xref'))

class IDAFunctionProfilerChooser(idaapi.Choose2):

    DELIM_COL_1 = '-' * 125
    DELIM_COL_2 = '-' * 175

    def __init__(self):
        global IDA_FUNCTION_PROFILES

        idaapi.Choose2.__init__(self,
                                "Strings Profile",
                                [
                                    ["Function", 50 | idaapi.Choose2.CHCOL_PLAIN],
                                    ["Xrefs", 75 | idaapi.Choose2.CHCOL_PLAIN],
                                ])

        self.icon = 41

        if not IDA_FUNCTION_PROFILES:
            IDA_FUNCTION_PROFILES = IDAFunctionProfiler()

        self.string_filters = set()
        self.function_filters = set()

        self.profile = IDA_FUNCTION_PROFILES
        self.populate_items()

    def OnSelectLine(self, n):
        idc.Jump(self.items[n][2])

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnClose(self):
        pass

    def OnCommand(self, n, cmd):
        if cmd == self.rename_function_cmd and self.items[n][0] != self.DELIM_COL_1:
            self.rename_function(n)
        elif cmd == self.rename_regex_cmd:
            self.rename_regex(n)
        elif cmd == self.rename_regex_test_cmd:
            self.rename_regex(n, dryrun=True)
        elif cmd == self.rename_regex_fuzzy_cmd:
            self.rename_fuzzy(n)

        self.populate_items()
        return 0

    def set_internal_filter(self, functions=set(), strings=set()):
        self.string_filters = strings
        self.function_filters = functions
        self.populate_items()

    def populate_items(self):
        self.items = []

        for (func_ea, xrefs) in self.profile.functions.iteritems():
            if not self.function_filters or func_ea in self.function_filters:
                orig_items_len = len(self.items)

                for xref in xrefs:
                    if not self.string_filters or xref.string in self.string_filters:
                        if xref.type == callable:
                            display_string = xref.string + "()"
                        elif xref.type == str:
                            display_string = '"%s"' % xref.string
                        else:
                            display_string = xref.string

                        self.items.append([idc.Name(func_ea), display_string, xref.xref, func_ea])

                if len(self.items) != orig_items_len:
                    self.items.append([self.DELIM_COL_1, self.DELIM_COL_2, idc.BADADDR, idc.BADADDR])

        # Remove the last delimiter column
        if self.items and self.items[-1][-1] == idc.BADADDR:
            self.items.pop(-1)

    def show(self):
        if self.Show(modal=False) < 0:
            return False

        self.rename_function_cmd = self.AddCommand("Rename this function")
        self.rename_regex_test_cmd = self.AddCommand("Test a regex renaming rule")
        self.rename_regex_cmd = self.AddCommand("Apply a regex renaming rule")
        self.rename_regex_fuzzy_cmd = self.AddCommand("Apply generic fuzzy naming rules")

        return True

    def rename_function(self, n):
        new_name = idc.AskIdent(self.items[n][0], "New function name")
        if new_name:
            idc.MakeName(self.items[n][3], new_name)

    def rename_fuzzy(self, n):
        if idc.AskYN(0, "Really rename functions based on fuzzy string matching? (Save your database first!)") == 1:
            self.rename_regex(n, regex_str="\[(.*?)\]")
            self.rename_regex(n, regex_str="(\w*)\(\)")
            self.rename_regex(n, regex_str="^In.(\w*)(?i)")
            self.rename_regex(n, regex_str="(^\w*):")
            self.rename_regex(n, regex_str="(\w*)\.c(?i)")
            self.rename_regex(n, regex_str="(\w*):")
            self.rename_regex(n, regex_str="(^\w*)")

    def rename_regex(self, n, regex_str="", dryrun=False):
        count = 0
        if not regex_str:
            regex_str = idc.AskStr("", "Regex rename rule")

        if regex_str:
            if dryrun:
                print "Testing regex rename rule: '%s'" % regex_str

            regex = re.compile(regex_str)

            # Look at all the profiled functions
            for (function, xrefs) in self.profile.functions.iteritems():
                new_function_name = ""

                # Don't rename functions that have already been renamed
                if not idc.Name(function).startswith("sub_"):
                    continue

                # Look through all the strings referenced by this function
                for string in [x.string for x in xrefs if x.type == str]:

                    # Does the string match the given regex?
                    m = regex.search(string)
                    if m:
                        # Take the last group from the regex match
                        potential_function_name = m.groups()[-1].split(" ")[0]

                        # Replace common bad chars with underscores
                        for c in ['-', '>']:
                            potential_function_name = potential_function_name.replace(c, '_')

                        # Make sure this is a valid name; should not include format strings
                        if idaapi.isident(potential_function_name) and '%' not in potential_function_name:
                            # Use the longest of the matching strings
                            if len(potential_function_name) > len(new_function_name):
                                new_function_name = potential_function_name

                if new_function_name:
                    # Append _n to the function name, if it already exists
                    n = 1
                    orig_new_function_name = new_function_name
                    while idc.LocByName(new_function_name) != idc.BADADDR:
                        new_function_name = "%s_%d" % (orig_new_function_name, n)
                        n += 1

                    if dryrun:
                        print "%s => %s" % (idc.Name(function), new_function_name)
                        count += 1
                    else:
                        if idc.MakeName(function, new_function_name):
                            count += 1

            print "Renamed %d functions" % count

class IDAFunctionProfilerPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Function xref profiler"
    help = ""
    wanted_name = "Function Profiler"
    wanted_hotkey = ""

    def init(self):
        self.menu_context_2 = idaapi.add_menu_item("View/Open subviews/", "Xrefs from the current function", "", 0, self.run, (True,))
        self.menu_context_1 = idaapi.add_menu_item("View/Open subviews/", "All function xrefs", "", 0, self.run, (False,))
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.del_menu_item(self.menu_context_1)
        idaapi.del_menu_item(self.menu_context_2)
        return None

    def run(self, just_this_function=False):
        try:
            chooser = IDAFunctionProfilerChooser()
            if just_this_function:
                cur_loc = idc.ScreenEA()
                func = idaapi.get_func(cur_loc)
                if func:
                    chooser.set_internal_filter(functions=set([func.startEA]))
                else:
                    raise Exception("Can't limit profile to just this function, because 0x%X is not inside a function!" % cur_loc)
            chooser.show()
        except Exception as e:
            print "IDAFunctionProfiler ERROR: %s" % str(e)

def IDAFunctionProfilerRefresh():
    global IDA_FUNCTION_PROFILES
    IDA_FUNCTION_PROFILES = IDAFunctionProfiler()

def PLUGIN_ENTRY():
    return IDAFunctionProfilerPlugin()

