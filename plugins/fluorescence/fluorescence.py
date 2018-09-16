# Plugin to highlight and un-highlight call instructions.
import idc
import idaapi
import idautils

class CallHighlighter(object):

    COLOR = 0xFF99FF #BBGGRR

    def highlight(self):
        for ea in idautils.Heads():
            if idaapi.isCode(idaapi.getFlags(ea)) and idaapi.is_call_insn(ea):
                current_color = idaapi.get_item_color(ea)
                if current_color == self.COLOR:
                    idaapi.set_item_color(ea, idc.DEFCOLOR)
                elif current_color == idc.DEFCOLOR:
                    idaapi.set_item_color(ea, self.COLOR)


try:
    class FluorescenceActionHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            CallHighlighter().highlight()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
except AttributeError:
    pass


class fluorescence_blower_t(idaapi.plugin_t):
    flags = 0
    comment = "Highlights function calls"
    help = ''
    wanted_name = 'fluorescence'
    wanted_hotkey = ''
    fluorescence_action_name = 'fluorescence:action'
    menu_tab = 'Options/'
    menu_name = 'Un/highlight call instructions'
    context_menu = None

    def init(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            fluorescence_desc = idaapi.action_desc_t(self.fluorescence_action_name,
                                                     self.menu_name,
                                                     FluorescenceActionHandler(),
                                                     self.wanted_hotkey,
                                                     'Highlights function calls.',
                                                     199)

            idaapi.register_action(fluorescence_desc)
            idaapi.attach_action_to_menu(self.menu_tab, self.fluorescence_action_name, idaapi.SETMENU_APP)
        else:
            self.context_menu = idaapi.add_menu_item(self.menu_tab, self.menu_name, "", 0, self.highlight, (None,))
        return idaapi.PLUGIN_KEEP

    def term(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            idaapi.detach_action_from_menu(self.menu_tab, self.fluorescence_action_name)
        else:
            if self.context_menu is not None:
                idaapi.del_menu_item(self.context_menu)
        return None

    def run(self, arg):
        pass

    def highlight(self, arg):
        CallHighlighter().highlight()


def PLUGIN_ENTRY():
    return fluorescence_blower_t()

