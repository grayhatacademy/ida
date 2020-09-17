# IDA Plugin to search for cross references only within the current defined
# function. Useful, for example, to find instructions that use a particular
# register, or that reference a literal value.
#
# Invoke by highlighting the desired text in IDA, then going to
# Jump->List local xrefs. Highlighting is also supported; once xrefs are found,
# Type the following in the Python command window:
#
#    Python> localxrefs.highlight()       <-- Highlight all xrefs
#    Python> localxrefs.highlight(False)  <-- Un-highlight all xrefs
#
# Craig Heffner
# Tactical Network Solutions

import sys
import idc
import idaapi
import idautils

from shims import ida_shims

localxrefs = None


def add_to_namespace(namespace, name, variable):
    '''
    Add a variable to a different namespace, likely __main__.
    '''
    import importlib
    importer_module = sys.modules[namespace]
    if name in sys.modules.keys():
        importlib.reload(sys.modules[name])
    else:
        m = importlib.import_module(name, None)
        sys.modules[name] = m

    setattr(importer_module, name, variable)


class LocalXrefs(object):
    UP = 'Up  '
    DOWN = 'Down'
    THIS = '-   '

    READ = 'r'
    WRITE = 'w'

    OPND_WRITE_FLAGS = {
            0: idaapi.CF_CHG1,
            1: idaapi.CF_CHG2,
            2: idaapi.CF_CHG3,
            3: idaapi.CF_CHG4,
            4: idaapi.CF_CHG5,
            5: idaapi.CF_CHG6}

    def __init__(self):
        self.xrefs = {}
        self.function = ''
        self._profile_function()

    def _profile_function(self):
        current_ea = ida_shims.get_screen_ea()
        current_function = ida_shims.get_func_name(current_ea)
        current_function_ea = ida_shims.get_name_ea_simple(current_function)

        if current_function:
            self.function = current_function

        ea = ida_shims.get_func_attr(current_function_ea,  idc.FUNCATTR_START)
        end_ea = ida_shims.get_func_attr(current_function_ea, idc.FUNCATTR_END)

        self.highlighted = ida_shims.get_highlighted_identifier()

        while ea < end_ea and ea != idc.BADADDR and self.highlighted:
            i = 0
            match = False
            optype = self.READ

            insn = ida_shims.decode_insn(ea)

            mnem = ida_shims.print_insn_mnem(ea)

            if self.highlighted in mnem:
                match = True
            elif idaapi.is_call_insn(ea):
                for xref in idautils.XrefsFrom(ea):
                    if xref.type != 21:
                        name = ida_shims.get_name(xref.to)
                        if name and self.highlighted in name:
                            match = True
                            break
            else:
                while True:
                    opnd = ida_shims.print_operand(ea, i)
                    if opnd:
                        if self.highlighted in opnd:
                            canon_feature = ida_shims.get_canon_feature(insn)
                            match = True
                            if canon_feature & self.OPND_WRITE_FLAGS[i]:
                                optype = self.WRITE
                        i += 1
                    else:
                        break

            if not match:
                comment = idc.GetCommentEx(ea, 0)
                if comment and self.highlighted in comment:
                    match = True
                else:
                    comment = idc.GetCommentEx(ea, 1)
                    if comment and self.highlighted in comment:
                        match = True

            if match:
                if ea > current_ea:
                    direction = self.DOWN
                elif ea < current_ea:
                    direction = self.UP
                else:
                    direction = self.THIS

                self.xrefs[ea] = {
                    'offset': ida_shims.get_func_off_str(ea),
                    'mnem': mnem,
                    'type': optype,
                    'direction': direction,
                    'text': idc.GetDisasm(ea),
                }

            ea = ida_shims.next_head(ea)

    def highlight(self, highlight=True, mnem=None, optype=None, direction=None,
                  text=None):
        for (ea, info) in self.xrefs.items():
            if mnem and info['mnem'] != mnem:
                highlight = False
            elif optype and info['optype'] != optype:
                highlight = False
            elif direction and info['direction'] != direction:
                highlight = False
            elif text and info['text'] != text:
                highlight = False

            if highlight:
                color = 0x00ff00
            else:
                color = idc.DEFCOLOR

            ida_shims.set_color(ea, idc.CIC_ITEM, color)

    def unhighlight(self):
        self.highlight(False)


def show_local_xrefs(arg=None):
    delim = '-' * 86 + '\n'
    header = '\nXrefs to %s from %s:\n'

    global localxrefs
    fmt = ''

    r = LocalXrefs()
    localxrefs = r

#    offsets = r.xrefs.keys()
#    offsets.sort()

    offsets = sorted(r.xrefs)

    if r.highlighted:
        ida_shims.msg(header % (r.highlighted, r.function))
        ida_shims.msg(delim)

        for ea in offsets:
            info = r.xrefs[ea]

            if not fmt:
                fmt = "%%s   %%s   %%-%ds   %%s\n" % (len(info['offset']) + 15)

            ida_shims.msg(fmt % (info['direction'], info['type'],
                                 info['offset'], info['text']))

        ida_shims.msg(delim)


try:
    class LocalXrefHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            global localxrefs
            show_local_xrefs()
            add_to_namespace('__main__', 'localxrefs', localxrefs)
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
except AttributeError:
    pass


class localizedxrefs_t(idaapi.plugin_t):
    flags = 0
    comment = "IDA Localized Xrefs"
    help = ""
    wanted_name = "Localized Xrefs"
    wanted_hotkey = ""
    menu_context = None
    menu_name = 'List local xrefs'
    action_name = 'localxrefs:action'
    menu_tab = 'Jump/'

    def init(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            action_desc = idaapi.action_desc_t(self.action_name,
                                               self.menu_name,
                                               LocalXrefHandler(),
                                               self.wanted_hotkey,
                                               'Localized Xrefs.',
                                               199)
            idaapi.register_action(action_desc)
            idaapi.attach_action_to_menu(
                self.menu_tab, self.action_name, idaapi.SETMENU_APP)
        else:
            self.menu_context = idaapi.add_menu_item(
                self.menu_tab, self.menu_name, "", 0, show_local_xrefs, (None,))
        return idaapi.PLUGIN_KEEP

    def term(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            idaapi.detach_action_from_menu(self.menu_tab, self.action_name)
        else:
            if self.menu_context is not None:
                idaapi.del_menu_item(self.menu_context)
        return None

    def run(self):
        pass


def PLUGIN_ENTRY():
    return localizedxrefs_t()
