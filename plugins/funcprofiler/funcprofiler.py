import re
import idc
import idaapi
import idautils
from shims import ida_shims
from operator import attrgetter

# Legacy IDA fix-up for the Choose class.
try:
    import ida_kernwin
    choose = ida_kernwin.Choose
except ImportError:
    choose = idaapi.Choose2

IDA_FUNCTION_PROFILES = None


class IDAProfilerXref(object):
    def __init__(self, **kwargs):
        for (k, v) in kwargs.items():
            setattr(self, k, v)


class IDAFunctionProfiler(object):
    def __init__(self):
        self.functions = {}
        self._build_string_xrefs()
        self._build_function_xrefs()
        self._sort_functions()

    def _build_string_xrefs(self):
        for string in idautils.Strings():
            key_string = str(string)

            for xref in idautils.XrefsTo(string.ea):
                func = idaapi.get_func(xref.frm)
                if func:
                    start_ea = ida_shims.start_ea(func)
                    if start_ea not in self.functions:
                        self.functions[start_ea] = list()

                    xref = IDAProfilerXref(ea=string.ea, string=key_string,
                                           xref=xref.frm, type=str)
                    self.functions[start_ea].append(xref)

    def _build_function_xrefs(self):
        for function in idautils.Functions():
            for xref in idautils.XrefsTo(function):
                func = idaapi.get_func(xref.frm)
                if func:
                    start_ea = ida_shims.start_ea(func)
                    if start_ea not in self.functions:
                        self.functions[start_ea] = list()

                    self.functions[start_ea].append(IDAProfilerXref(
                        ea=function, string=ida_shims.get_name(function),
                        xref=xref.frm, type=callable))

    def _sort_functions(self):
        for function in list(self.functions.keys()):
            self.functions[function] = sorted(self.functions[function],
                                              key=attrgetter('xref'))


class IDAFunctionProfilerChooser(choose):
    DELIM_COL_1 = '-' * 125
    DELIM_COL_2 = '-' * 175

    def __init__(self):
        global IDA_FUNCTION_PROFILES
        choose.__init__(self,
                        "Strings Profile",
                        [["Function", 50 | choose.CHCOL_PLAIN],
                         ["Xrefs", 75 | choose.CHCOL_PLAIN], ])

        self.icon = 41

        if not IDA_FUNCTION_PROFILES:
            IDA_FUNCTION_PROFILES = IDAFunctionProfiler()

        self.items = []
        self.rename_function_cmd = None
        self.rename_regex_test_cmd = None
        self.rename_regex_cmd = None
        self.rename_regex_fuzzy_cmd = None

        self.string_filters = set()
        self.function_filters = set()

        self.profile = IDA_FUNCTION_PROFILES
        self.populate_items()

    def OnSelectLine(self, n):
        ida_shims.jumpto(self.items[n][2])

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnClose(self):
        pass

    def OnCommand(self, n, cmd):
        if cmd == self.rename_function_cmd and \
                self.items[n][0] != self.DELIM_COL_1:
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

        for (func_ea, xrefs) in self.profile.functions.items():
            if not self.function_filters or func_ea in self.function_filters:
                orig_items_len = len(self.items)

                for xref in xrefs:
                    if not self.string_filters or \
                            xref.string in self.string_filters:
                        if xref.type == callable:
                            display_string = xref.string + "()"
                        elif xref.type == str:
                            display_string = '"%s"' % xref.string
                        else:
                            display_string = xref.string

                        self.items.append([ida_shims.get_name(func_ea),
                                           display_string,
                                           xref.xref, func_ea])

                if len(self.items) != orig_items_len:
                    self.items.append([self.DELIM_COL_1, self.DELIM_COL_2,
                                       idc.BADADDR, idc.BADADDR])

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
        new_name = ida_shims.ask_ident(self.items[n][0], "New function name")
        if new_name:
            ida_shims.set_name(self.items[n][3], new_name)

    def rename_fuzzy(self, n):
        if idc.AskYN(0, "Really rename functions based on fuzzy string "
                        "matching? (Save your database first!)") == 1:
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
                print("Testing regex rename rule: '%s'" % regex_str)

            regex = re.compile(regex_str)

            # Look at all the profiled functions
            for (function, xrefs) in self.profile.functions.items():
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
                            potential_function_name = \
                                potential_function_name.replace(c, '_')

                        if idaapi.isident(potential_function_name) and \
                                '%' not in potential_function_name:
                            if len(potential_function_name) > len(new_function_name):
                                new_function_name = potential_function_name

                if new_function_name:
                    # Append _n to the function name, if it already exists
                    n = 1
                    orig_new_function_name = new_function_name
                    while idc.LocByName(new_function_name) != idc.BADADDR:
                        new_function_name = "%s_%d" % (orig_new_function_name,
                                                       n)
                        n += 1

                    if dryrun:
                        print("%s => %s" % (idc.Name(function),
                                            new_function_name))
                        count += 1
                    else:
                        if ida_shims.set_name(function, new_function_name):
                            count += 1

            print("Renamed %d functions" % count)


def from_function_profiler(arg=None):
    try:
        chooser = IDAFunctionProfilerChooser()
        cur_loc = ida_shims.get_screen_ea()
        func = idaapi.get_func(cur_loc)
        if func:
            start_ea = ida_shims.start_ea(func)
            chooser.set_internal_filter(functions=set([start_ea]))
        else:
            raise Exception("Can't limit profile to just this function, "
                            "because 0x%X is not inside a function!" % cur_loc)
        chooser.show()
    except Exception as e:
        print("IDAFunctionProfiler ERROR: %s" % str(e))


def all_functions_profiler(arg=None):
     try:
        chooser = IDAFunctionProfilerChooser()
        chooser.show()
     except Exception as e:
        print("IDAFunctionProfiler ERROR: %s" % str(e))


try:
    class FunctionProfilerFromFunctionActionHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            from_function_profiler()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS


    class FunctionProfilerAllFunctionsActionHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            all_functions_profiler()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
except AttributeError:
    pass


class IDAFunctionProfilerPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Function xref profiler"
    help = ""
    wanted_name = "Function Profiler"
    wanted_hotkey = ""
    xref_current_func_action_name = 'xrefcurrentfunction:action'
    all_xref_action_name = 'allxrefs:action'
    xref_current_func_menu_name = 'Xrefs from the current function'
    all_xref_menu_name = 'All function xrefs'
    menu_tab = 'View/Open subviews/'
    menu_context = []

    def init(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            xref_current_func_desc = idaapi.action_desc_t(
                self.xref_current_func_action_name,
                self.xref_current_func_menu_name,
                FunctionProfilerFromFunctionActionHandler(),
                self.wanted_hotkey, 'Xrefs from the current function.', 199)

            all_xref_desc = idaapi.action_desc_t(
                self.all_xref_action_name, self.all_xref_menu_name,
                FunctionProfilerAllFunctionsActionHandler(), self.wanted_hotkey,
                'All functions xref.', 199)

            idaapi.register_action(xref_current_func_desc)
            idaapi.register_action(all_xref_desc)

            idaapi.attach_action_to_menu(
                self.menu_tab, self.xref_current_func_action_name,
                idaapi.SETMENU_APP)

            idaapi.attach_action_to_menu(
                self.menu_tab, self.all_xref_action_name, idaapi.SETMENU_APP)
        else:
            self.menu_context.append(
                idaapi.add_menu_item(self.menu_tab,
                                     self.xref_current_func_menu_name,
                                     "",
                                     0,
                                     from_function_profiler,
                                     (True,)))

            self.menu_context.append(
                idaapi.add_menu_item(self.menu_tab,
                                     self.all_xref_menu_name,
                                     "",
                                     0,
                                     all_functions_profiler,
                                     (False,)))
        return idaapi.PLUGIN_KEEP

    def term(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            idaapi.detach_action_from_menu(self.menu_tab,
                                           self.xref_current_func_action_name)
            idaapi.detach_action_from_menu(self.menu_tab,
                                           self.all_xref_action_name)
        else:
            for context in self.menu_context:
                idaapi.del_menu_item(context)
        return None

    def run(self, arg):
        pass


def IDAFunctionProfilerRefresh():
    global IDA_FUNCTION_PROFILES
    IDA_FUNCTION_PROFILES = IDAFunctionProfiler()


def PLUGIN_ENTRY():
    return IDAFunctionProfilerPlugin()

