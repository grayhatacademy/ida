################################################################################
#
# A plugin to help identify common POSIX functions such as printf, sprintf,
# memcmp, strcpy, etc.
#
# This plugin will really only work with RISC architectures, as it assumes a
# fixed instruction size, and that function arguments are passed via registers.
#
################################################################################
import idc
import idaapi
import idautils

from shims import ida_shims

# Legacy IDA fix-up for the Choose class.
try:
    import ida_kernwin
    choose = ida_kernwin.Choose
except ImportError:
    choose = idaapi.Choose2


class LeafBlowerFunctionChooser(choose):
    MIN_XREFS = 25
    MUST_HAVE_LOOP = True

    def __init__(self, lbobj):
        self.lb = lbobj
        self.min_xrefs = self.MIN_XREFS
        self.must_have_loop = self.MUST_HAVE_LOOP
        self.items = []

        choose.__init__(self, self.lb.TITLE, self.lb.COLUMNS)
        self.icon = 41

        self.populate_items()
        self.show_all_toggle_cmd = None
        self.rename_cmd = None

    def OnSelectLine(self, n):
        ida_shims.jumpto(ida_shims.get_name_ea_simple(self.items[n][0]))

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnRefresh(self, n):
        self.populate_items()
        return len(self.items)

    def OnClose(self):
        pass

    def AddCommand(self, caption):
        pass

    def OnCommand(self, n, cmd):
        if cmd == self.show_all_toggle_cmd:

            if self.min_xrefs == self.MIN_XREFS:
                self.min_xrefs = 0
            if self.min_xrefs != self.MIN_XREFS:
                self.min_xrefs = self.MIN_XREFS

            if self.must_have_loop == self.MUST_HAVE_LOOP:
                self.must_have_loop = False
            else:
                self.must_have_loop = self.MUST_HAVE_LOOP

        elif cmd == self.rename_cmd:
            response = ida_shims.ask_yn(
                0, "Are you sure you want to rename all 'sub_XXXXXX' functions "
                   "to 'leaf_XXXXXX'?")
            if response:
                for item in self.items:
                    # Is this a leaf function?
                    if item[-1] is True:
                        current_name = item[0]
                        if current_name.startswith('sub_'):
                            new_name = current_name.replace('sub_', 'leaf_')
                            ida_shims.set_name(
                                ida_shims.get_name_ea_simple(current_name),
                                new_name)
        self.populate_items()
        return 0

    def populate_items(self):
        self.items = []

        for function in self.lb.functions:
            candidates = []

            if function.leaf:
                if function.xrefs < self.min_xrefs:
                    continue
                if function.loop is False and self.must_have_loop is True:
                    continue

            for candidate in function.candidates:
                candidates.append(candidate)

            if function.xrefs:
                xrefs = str(function.xrefs)
            else:
                xrefs = "*"

            if function.argc is not None:
                argc = str(function.argc)
            else:
                argc = "*"

            if function.leaf:
                loops = str(function.loop)
            else:
                loops = "*"

            name = ida_shims.get_name(function.start)

            self.items.append([name, xrefs, argc, loops, ', '.join(candidates),
                               function.leaf])

    def show(self):
        if self.Show(modal=False) < 0:
            return False
        self.show_all_toggle_cmd = self.AddCommand("Toggle 'show all leaf functions'")
        self.rename_cmd = self.AddCommand("Rename all sub_XXXXXX leaf functions to 'leaf_XXXXXX'")


class ArchitectureSettings(object):
    def __init__(self, **kwargs):
        for (k, v) in kwargs.items():
            setattr(self, k, v)


class ArchitectureSpecific(object):
    '''
    Architecture specific configuration / code.
    '''
    ARCHES = [
        ArchitectureSettings(name="MIPS",
                             argv=['$a0', '$a1', '$a2', '$a3'],
                             delay=1, size=4),
        ArchitectureSettings(name="ARM",
                             argv=['R0', 'R1', 'R2', 'R3'],
                             delay=0, size=4)
    ]

    def __init__(self):
        self.registers = idaapi.ph_get_regnames()

        # Find the list of function argument registers that fit the current
        # processor module
        # TODO: Probably better to look this up based on the processor module
        # name, as it can't distinguish between ARM and Thumb.
        self.argv = None
        for arch in self.ARCHES:
            if not (set(arch.argv) - set(self.registers)):
                self.argv = list(arch.argv)
                self.delay_slot = arch.delay
                self.insn_size = arch.size
                break

        if self.argv is None:
            self.argv = []
            self.registers = []
            self.delay_slot = False
            self.insn_size = 0
            self.unknown = True
        else:
            self.unknown = False


class Prototype(object):
    def __init__(self, name, argc, argv=[], loop=True, fmtarg=None):
        self.name = name
        self.argc = argc
        self.loop = loop
        self.argv = argv
        self.fmtarg = fmtarg


class Function(object):
    '''
    A wrapper class for storing function related info.
    '''

    PROTOTYPES = [
                    Prototype(name="atoi", argc=1),
                    Prototype(name="atol", argc=1),
                    Prototype(name="strlen", argc=1),
                    Prototype(name="strcpy", argc=2),
                    Prototype(name="strcat", argc=2),
                    Prototype(name="strcmp", argc=2),
                    Prototype(name="strstr", argc=2),
                    Prototype(name="strchr", argc=2),
                    Prototype(name="strrchr", argc=2),
                    Prototype(name="bzero", argc=2),
                    Prototype(name="strtol", argc=3),
                    Prototype(name="strncpy", argc=3),
                    Prototype(name="strncat", argc=3),
                    Prototype(name="strncmp", argc=3),
                    Prototype(name="memcpy", argc=3),
                    Prototype(name="memmove", argc=3),
                    Prototype(name="bcopy", argc=3),
                    Prototype(name="memcmp", argc=3),
                    Prototype(name="memset", argc=3),

                    Prototype(name="printf", argc=1, fmtarg=0),
                    Prototype(name="sprintf", argc=2, fmtarg=1),
                    Prototype(name="snprintf", argc=3, fmtarg=2),
                    Prototype(name="fprintf", argc=2, fmtarg=1),
                    Prototype(name="fscanf", argc=2, fmtarg=1),
                    Prototype(name="sscanf", argc=2, fmtarg=1),
                 ]

    def __init__(self, **kwargs):
        self.argc = None
        self.loop = False
        self.leaf = False
        self.xrefs = None
        self.fmtarg = None
        self.start = idc.BADADDR
        self.end = idc.BADADDR
        self.candidates = {}
        self.argp = ArgParser()

        for (k,v) in kwargs.items():
            setattr(self, k, v)

        self.name = ida_shims.get_name(self.start)

        if self.xrefs is None:
            self.xrefs = len([x for x in idautils.XrefsTo(self.start)])

        if not self.candidates:
            for prototype in self.PROTOTYPES:
                if self.leaf and prototype.fmtarg is None and \
                        prototype.argc == self.argc and prototype.loop == self.loop:
                    if prototype.name in self.candidates:
                        self.candidates[prototype.name] += 1
                    else:
                        self.candidates[prototype.name] = 1
                elif not self.leaf and \
                        self.fmtarg is not None and \
                        prototype.fmtarg is not None and \
                        self.fmtarg == prototype.fmtarg:
                    if prototype.name in self.candidates:
                        self.candidates[prototype.name] += 1
                    else:
                        self.candidates[prototype.name] = 1


class ArgParser(object):
    '''
    Attempts to identify the number of arguments a function takes as well as
    what type of arguments a function takes.
    '''

    # An iterable list of canonical flags indicating an operand has been changed
    CHANGE_OPND = [
                    idaapi.CF_CHG1,
                    idaapi.CF_CHG2,
                    idaapi.CF_CHG3,
                    idaapi.CF_CHG4,
                    idaapi.CF_CHG5,
                    idaapi.CF_CHG6,
                  ]

    # An iterable list of canonical flags indicating an operand has been used
    USE_OPND = [
                    idaapi.CF_USE1,
                    idaapi.CF_USE2,
                    idaapi.CF_USE3,
                    idaapi.CF_USE4,
                    idaapi.CF_USE5,
                    idaapi.CF_USE6,
               ]

    def __init__(self):
        self.arch = ArchitectureSpecific()

    def argc(self, function):
        '''
        Counts the number of arguments used by the specified function.
        '''
        argv = set()
        notargv = set()
        ea = ida_shims.start_ea(function)
        end_ea = ida_shims.end_ea(function)

        if self.arch.unknown:
            return 0

        while ea < end_ea:
            insn = ida_shims.decode_insn(ea)
            features = ida_shims.get_canon_feature(insn)

            for n in range(0, len(self.USE_OPND)):
                ops = ida_shims.get_operands(insn)
                if ops[n].type in [idaapi.o_reg, idaapi.o_displ,
                                   idaapi.o_phrase]:
                    try:
                        regname = self.arch.registers[ops[n].reg]
                        index = self.arch.argv.index(regname)
                    except ValueError:
                        continue

                    if features & self.USE_OPND[n] and regname not in notargv:
                        argv.update(self.arch.argv[:index+1])

            for n in range(0, len(self.CHANGE_OPND)):
                ops = ida_shims.get_operands(insn)
                if ops[n].type in [idaapi.o_reg, idaapi.o_displ,
                                   idaapi.o_phrase]:
                    try:
                        regname = self.arch.registers[ops[n].reg]
                        index = self.arch.argv.index(regname)
                    except ValueError:
                        continue

                    if regname not in argv:
                        notargv.update(self.arch.argv[index:])

            if argv.union(notargv) == set(self.arch.argv):
                break

            # TODO: Use idc.NextHead(ea) instead...
            ea += self.arch.insn_size

        return len(argv)

    def trace(self, ea):
        '''
        Given an EA where an argument register is set, attempt to trace what
        function call that argument is passed to.

        @ea - The address of an instruction that modifies a function argument
        register.

        Returns a tuple of (function EA, argv index, argument register name) on
        success.
        Returns None on failure.
        '''
        insn = ida_shims.decode_insn(ea)
        features = ida_shims.get_canon_feature(insn)

        if self.arch.unknown:
            return (None, None, None)

        for n in range(0, len(self.CHANGE_OPND)):
            ops = ida_shims.get_operands(insn)
            if ops[n].type in [idaapi.o_reg, idaapi.o_displ, idaapi.o_phrase]:
                try:
                    regname = self.arch.registers[ops[n].reg]
                    index = self.arch.argv.index(regname)
                except ValueError:
                    continue

                if features & self.CHANGE_OPND[n]:
                    ea = ea - (self.arch.delay_slot * self.arch.insn_size)

                    while True:
                        insn = ida_shims.decode_insn(ea)

                        if idaapi.is_call_insn(ea):
                            for xref in idautils.XrefsFrom(ea):
                                if xref.type in [idaapi.fl_CF, idaapi.fl_CN]:
                                    return (xref.to, index, regname)
                            # If we couldn't figure out where the function call
                            # was going to, just quit
                            break

                        try:
                            is_block_end = idaapi.is_basic_block_end(ea)
                        except TypeError:
                            is_block_end = idaapi.is_basic_block_end(ea, True)

                        if is_block_end:
                            break

                        # TODO: Use idc.NextHead(ea) instead...
                        ea += self.arch.insn_size

        return (None, None, None)

    def argv(self, func):
        '''
        Attempts to identify what types of arguments are passed to a given
        function. Currently unused.
        '''
        args = [None for x in self.arch.argv]

        if not self.arch.unknown:
            start_ea = ida_shims.start_ea(func)
            for xref in idautils.XrefsTo(start_ea):
                if idaapi.is_call_insn(xref.frm):
                    insn = ida_shims.decode_insn(xref.frm)

                    ea = xref.frm + (self.arch.delay_slot * self.arch.insn_size)
                    end_ea = (xref.frm - (self.arch.insn_size * 10))

                    while ea >= end_ea:
                        if idaapi.is_basic_block_end(ea) or \
                                (ea != xref.frm and idaapi.is_call_insn(ea)):
                            break

                        insn = ida_shims.decode_insn(ea)
                        features = ida_shims.get_canon_feature(insn)

                        for n in range(0, len(self.CHANGE_OPND)):
                            ops = ida_shims.get_operands(insn)
                            if ops[n].type in [idaapi.o_reg, idaapi.o_displ,
                                               idaapi.o_phrase]:
                                try:
                                    regname = self.arch.registers[ops[n].reg]
                                    index = self.arch.argv.index(regname)
                                except ValueError:
                                    continue

                                if features & self.CHANGE_OPND[n]:
                                    for xref in idautils.XrefsFrom(ea):
                                        # TODO: Where is this xref type defined?
                                        if xref.type == 1:
                                            string = \
                                                ida_shims.get_strlit_contents(
                                                    xref.to)
                                            if string and len(string) > 4:
                                                args[index] = str
                                            break

                        ea -= self.arch.insn_size

                yield args


class LeafFunctionFinder(object):
    '''
    Class that searches for functions that do not call any other functions.
    '''

    TITLE = "Leaf functions"

    COLUMNS = [
                ["Function", 25 | choose.CHCOL_PLAIN],
                ["Xrefs", 8 | choose.CHCOL_PLAIN],
                ["argc", 8 | choose.CHCOL_PLAIN],
                ["Has Loop(s)", 8 | choose.CHCOL_PLAIN],
                ["Possible candidate(s)", 50 | choose.CHCOL_PLAIN],
              ]

    def __init__(self):
        self.functions = []
        self.arch = ArchitectureSpecific()
        self.argp = ArgParser()
        self._find_leafs()

    def _find_leafs(self):
        # Loop through every function
        for func_ea in idautils.Functions():
            # Count the number of xrefs to this function
            func = idaapi.get_func(func_ea)
            if func:
                leaf_function = True
                ea = ida_shims.start_ea(func)
                end_ea = ida_shims.end_ea(func)

                # Loop through all instructions in this function looking
                # for call instructions; if found, then this is not a leaf.
                while ea <= end_ea:
                    insn = ida_shims.decode_insn(ea)
                    if idaapi.is_call_insn(ea):
                        leaf_function = False
                        break

                    ea = ida_shims.next_head(ea)

                if leaf_function:
                    self.functions.append(
                        Function(start=ida_shims.start_ea(func),
                                 end=ida_shims.end_ea(func), leaf=True,
                                 loop=self.has_loop(func),
                                 argc=self.argp.argc(func)))

        # Sort leafs by xref count, largest first
        self.functions.sort(key=lambda f: f.xrefs, reverse=True)

    def has_loop(self, func):
        '''
        A naive method for checking to see if a function contains a loop.
        Works pretty well for simple functions though.
        '''
        func_start_ea = ida_shims.start_ea(func)

        blocks = [func_start_ea]
        for block in idaapi.FlowChart(func):
            end_ea = ida_shims.end_ea(block)
            blocks.append(end_ea)

        for block in blocks:
            for xref in idautils.XrefsTo(block):
                xref_func = idaapi.get_func(xref.frm)
                xref_start_ea = ida_shims.start_ea(xref_func)

                if xref_func and xref_start_ea == func_start_ea:
                    if xref.frm >= block:
                        return True
        return False


class FormatStringFunctionFinder(object):

    TITLE = "Format string functions"

    COLUMNS = [
                ["Function", 25 | choose.CHCOL_PLAIN],
                ["Xrefs", 8 | choose.CHCOL_PLAIN],
                ["Format string argv index", 15 | choose.CHCOL_PLAIN],
                ["Has Loop(s)", 8 | choose.CHCOL_PLAIN],
                ["Possible candidate(s)", 50 | choose.CHCOL_PLAIN],
              ]

    def __init__(self):
        self.functions = []
        self.argp = ArgParser()
        self._find_format_string_functions()

    def _find_format_string_functions(self):
        processed_func_eas = set()

        for string in idautils.Strings():
            if '%' in str(string):
                for xref in idautils.XrefsTo(string.ea):
                    (func_ea, argn, regname) = self.argp.trace(xref.frm)
                    if func_ea is not None and \
                            func_ea not in processed_func_eas:
                        self.functions.append(Function(start=func_ea,
                                                       argc=argn,
                                                       fmtarg=argn))
                        processed_func_eas.add(func_ea)

        # Sort format string functions by xref count, largest first
        self.functions.sort(key=lambda f: f.xrefs, reverse=True)


def leaf_from_menu(arg=None):
    LeafBlowerFunctionChooser(LeafFunctionFinder()).show()


def format_from_menu(arg=None):
    LeafBlowerFunctionChooser(FormatStringFunctionFinder()).show()


try:
    class LeafFunctionAction(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            leaf_from_menu()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS


    class FormatStringFunctionAction(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            format_from_menu()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
except AttributeError:
    pass


class leaf_blower_t(idaapi.plugin_t):
    flags = 0
    comment = "Assists in identifying common POSIX functions in RISC " \
              "architectures"
    help = ''
    wanted_name = 'leafblower'
    wanted_hotkey = ''
    leaf_function_action_name = 'leaffunction:action'
    format_string_action_name = 'formatstring:action'
    leaf_function_name = 'leaf functions'
    format_string_name = 'format string functions'
    leaf_function_tooltip = 'Find leaf functions'
    format_string_tooltip = 'Find format string functions'
    menu_tab = 'Search/'
    menu_context = []

    def init(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            leaf_desc = idaapi.action_desc_t(
                self.leaf_function_action_name, self.leaf_function_name,
                LeafFunctionAction(), self.wanted_hotkey,
                self.leaf_function_tooltip, 199)

            format_string_desc = idaapi.action_desc_t(
                self.format_string_action_name, self.format_string_name,
                FormatStringFunctionAction(), self.wanted_hotkey,
                self.format_string_tooltip, 199)

            idaapi.register_action(leaf_desc)
            idaapi.register_action(format_string_desc)

            idaapi.attach_action_to_menu(
                self.menu_tab, self.leaf_function_action_name,
                idaapi.SETMENU_APP)

            idaapi.attach_action_to_menu(
                self.menu_tab, self.format_string_action_name,
                idaapi.SETMENU_APP)
        else:
            self.menu_context.append(
                idaapi.add_menu_item(
                    self.menu_tab, self.leaf_function_name, "", 0,
                    leaf_from_menu, (None,)))

            self.menu_context.append(
                idaapi.add_menu_item(
                    self.menu_tab, self.format_string_name, "", 0,
                    format_from_menu, (None,)))

        return idaapi.PLUGIN_KEEP

    def term(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            idaapi.detach_action_from_menu(
                self.menu_tab, self.leaf_function_action_name)
            idaapi.detach_action_from_menu(
                self.menu_tab, self.format_string_action_name)
        else:
            for context in self.menu_context:
                idaapi.del_menu_item(context)
        return None

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return leaf_blower_t()

