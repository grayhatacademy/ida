# Plugin to highlight and un-highlight call instructions.
import idc
import idaapi
import idautils

VERSION = "0.1"

try:
    class Kp_Menu_Context(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        # This action is always available.
        @classmethod
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class Fluorescence(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.run()
            return 1

except:
    pass


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


#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------

p_initialized = False

class Fluorescence_Plugin_t(idaapi.plugin_t):
    comment = "Highlights function calls"
    help = ""
    wanted_name = "Fluorescence"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global p_initialized
        
        # register popup menu handlers
        try:
            Fluorescence.register(self, "Un/highlight call instructions")
        except:
            pass
        
        self.highlighted = False
        
        if p_initialized is False:
            p_initialized = True
            idaapi.register_action(idaapi.action_desc_t(
                "Fluorescence",
                "Highlights function calls",
                self.run,
                None,
                None,
                0))
            idaapi.attach_action_to_menu("Options/General...", "Fluorescence", idaapi.SETMENU_APP)
            print("=" * 80)
            print("Fluorescence v{0} by devttys0, 2017".format(VERSION))
            print("=" * 80)

        return idaapi.PLUGIN_KEEP

    def run(self):
        CallHighlighter().highlight()
        return 1

    def term(self):
        pass

# register IDA plugin
def PLUGIN_ENTRY():
    return Fluorescence_Plugin_t()
