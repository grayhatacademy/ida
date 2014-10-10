# Plugin to highlight and un-highlight call instructions.
import idc
import idaapi
import idautils

class CallHighlighter(object):

    COLOR = 0xFF99FF #BBGGRR

    def highlight(self, color=COLOR):
        for ea in idautils.Heads():
            if idaapi.isCode(idaapi.getFlags(ea)) and idaapi.is_call_insn(ea):
                current_color = idaapi.get_item_color(ea)
                if current_color == self.COLOR:
                    idaapi.set_item_color(ea, idc.DEFCOLOR)
                elif current_color == idc.DEFCOLOR:
                    idaapi.set_item_color(ea, self.COLOR)

class fluorescence_blower_t(idaapi.plugin_t):

    flags = 0
    comment = "Highlights function calls"
    help = ''
    wanted_name = 'fluorescence'
    wanted_hotkey = ''

    def init(self):
        self.highlighted = False
        self.context_menu = idaapi.add_menu_item("Options/", "Un/highlight call instructions", "", 0, self.run, (None,))
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.del_menu_item(self.context_menu)
        return None

    def run(self, arg):
        CallHighlighter().highlight()

def PLUGIN_ENTRY():
    return fluorescence_blower_t()

