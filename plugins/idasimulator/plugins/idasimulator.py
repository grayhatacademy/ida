import os
import pickle
import inspect
import idaapi
import idautils
import idc
import idasim

IDASIM = None

class IDASimConfiguration:
    '''
    Responsible for loading, saving and cleaning the idasimulator configuration file.
    Configuration data is a dictionary stored in pickle format:

        cfg = {
            '/path/to/database.idb' : {
                        'handlers'   : [enabled handlers],
                        'startup'    : 'startup script',
                        'startname'  : named location to set breakpoint for setting startup values,
                        'membase'    : membase value
            }
        }
    '''
    CONFIG_FILE = 'idasimulator.cfg'

    def __init__(self, sim):
        '''
        Class constructor.

        @sim - idasimulator_t class instance.

        Returns None.
        '''
        self.cfg = None
        self.sim = sim
        self.idb = idc.GetIdbPath()
        self.confile = os.path.join(idaapi.get_user_idadir(), self.CONFIG_FILE)

    def _load_config_file(self):
        '''
        Loads the entire configuration file, cleaning out stale config entries in the process.

        Returns the entire configuration dictionary.
        '''
        cfg = {}
        stale = []

        try:
            cfg = pickle.load(open(self.confile, "rb"))

            # The IDB path is used as the configuration key. If a IDB no longer exists, its config data is useless.
            # Mark any IDB's that no longer exist.
            for (idb, config) in cfg.iteritems():
                if not os.path.exists(idb):
                    stale.append(idb)

            # Delete any stale config entries and save the data back to the config file.
            if len(stale) > 0:
                for idb in stale:
                    del cfg[idb]
                self._save_config_file(cfg)
        except Exception, e:
            pass

        return cfg

    def _save_config_file(self, fdata):
        '''
        Saves data to the config file, in pickle format.
        
        @fdata - Configuration file dictionary.

        Returns None.
        '''
        try:
            pickle.dump(fdata, open(self.confile, "wb"))
        except Exception, e:
            print "Failed to save %s: %s" % (self.confile, str(e))

    def _load_config_data(self, idb_path):
        '''
        Loads configuration data for this IDB from the config file.

        Returns this IDB's configuration data.
        '''
        data = {}

        if os.path.exists(self.confile):
            cfgdata = self._load_config_file()
            if cfgdata.has_key(idb_path):
                data = cfgdata[idb_path]
        return data

    def _populate_config_data(self, data):
        '''
        Populates the current running configuration from data.
        
        @data - Configuration dictionary.

        Returns None.
        '''
        for name in data['handlers']:
            self.sim.EnableHandler(name)

        self.sim.SetInitValues(data['startname'], data['startup'])
        self.sim.idasim.mmu.base(data['membase'])

    def _save_config_data(self, idb_path, fdata):
        '''
        Saves the current running configuration to disk.

        @idb_path - Path to the IDB file.
        @fdata    - Configuration file dictionary.

        Returns None.
        '''
        fdata[idb_path] = {}
        fdata[idb_path]['handlers'] = self.sim.EnabledHandlers()
        fdata[idb_path]['membase'] = self.sim.idasim.mmu.base()

        (start_name, start_script) = self.sim.GetInitValues()
        fdata[idb_path]['startname'] = start_name
        fdata[idb_path]['startup'] = start_script

        self._save_config_file(fdata)

    def Load(self):
        '''
        Loads the saved configuration data into the running configuration.

        Returns None.
        '''
        data = self._load_config_data(self.idb)
        if data:
            self._populate_config_data(data)

    def Save(self):
        '''
        Saves the running configuration to disk.
    
        Returns None.
        '''
        fdata = self._load_config_file()
        self._save_config_data(self.idb, fdata)


class IDASimFunctionChooser(idaapi.Choose2):
    '''
    Primary IDASimulator UI.
    '''

    def __init__(self, sim):
        idaapi.Choose2.__init__(self, "IDA Simulator", [     
                                    ["Handler", 20 | Choose2.CHCOL_PLAIN], 
                                    ["Name", 15 | Choose2.CHCOL_PLAIN], 
                                    ["Description", 30 | Choose2.CHCOL_PLAIN], 
                                    ["Status", 10 | Choose2.CHCOL_PLAIN], 
                                ])
        self.icon = 41
        self.sim = sim
        self.save_cmd = None
        self.quit_cmd = None
        self.goto_cmd = None
        self.reset_cmd = None
        self.mbase_cmd = None
        self.toggle_cmd = None
        self.config_cmd = None
        self.enable_all_cmd = None
        self.disable_all_cmd = None

        self.PopulateItems()

    def PopulateItems(self):
        '''
        Populates the chooser window with named locations that have registered handlers.
        '''
        self.items = []

        for (name, info) in self.sim.functions.iteritems():
            addr = idc.LocByName(info['function'])

            if addr != idc.BADADDR:
                if self.sim.IsSimulated(name):
                    status = "Enabled"
                else:
                    status = "Disabled"
                
                self.items.append([name, info['function'], self.sim.GetHandlerDesc(name), status, addr])

    def OnSelectLine(self, n):
        '''
        Invoked when the user double-clicks on a selection in the chooser.
        '''
        self.sim.ToggleHandler(self.items[n][0])
        # Not sure why, but the displayed items aren't refreshed if PopulateItems isn't called here.
        # Interestingly, this is NOT required when OnSelectLine is invoked via the OnCommand method.
        self.PopulateItems()
        self.Refresh()

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnDeleteLine(self, n):
        '''
        Invoked when a user deletes a selection from the chooser.
        '''
        return n

    def OnRefresh(self, n):
        '''
        Refreshes the display.
        '''
        self.sim.Refresh()
        self.PopulateItems()
        return n

    def OnCommand(self, n, cmd_id):
        '''
        Handles custom right-click commands.
        '''
        if self.sim.idasim is not None:
            if cmd_id == self.reset_cmd:
                self.reset()
            elif cmd_id == self.goto_cmd:
                idc.Jump(self.items[n][-1])
            elif cmd_id == self.toggle_cmd:
                self.OnSelectLine(n)
            elif cmd_id == self.enable_all_cmd:
                self.enable_all()
            elif cmd_id == self.disable_all_cmd:
                self.disable_all()
            elif cmd_id == self.mbase_cmd:
                self.set_mbase()
            elif cmd_id == self.config_cmd:
                self.configure_form()
            elif cmd_id == self.save_cmd:
                self.sim.config.Save()
            elif cmd_id == self.quit_cmd:
                self.quit_idasim()
        return 1

    def OnClose(self):
        '''
        Save the current settings when the chooser window is closed.
        '''
        if self.sim.idasim is not None:
            self.sim.config.Save()
        return None

    def quit_idasim(self):
        '''
        Quits IDASimulator, disabling everything.
        '''
        self.sim.config.Save()
        self.sim.Cleanup(closegui=False)

    def set_mbase(self):
        '''
        Sets the memory base address for the IDASimMMU instance.
        '''
        mbase = AskAddr(self.sim.idasim.mmu.base(), "Configure base memory allocation address")
        if mbase != idc.BADADDR:
            if mbase == 0:
                mbase = idc.BADADDR
            self.sim.idasim.mmu.base(mbase)

    def configure_form(self):
        '''
        Displays the configuration form for setting up startup register values.
        '''
        script_file = AskFile(0, '*.py', 'Select a script to run on process init/attach.')
        if script_file:
            self.sim.SetInitValues(None, open(script_file, 'rb').read())

    def enable_all(self):
        '''
        Enables all handlers.
        '''
        for i in range(0, len(self.items)):
            self.sim.EnableHandler(self.items[i][0])
        self.Refresh()

    def disable_all(self):
        '''
        Disable all handlers.
        '''
        for i in range(0, len(self.items)):
            self.sim.DisableHandler(self.items[i][0])
        self.Refresh()

    def reset(self):
        '''
        Resets all settings to the defaults.
        '''
        if idc.AskYN(0, "Are you sure you want to undo all changes and reset?") == 1:
            self.sim.Reset()
            self.Refresh()

    def show(self):
        '''
        Displays the chooser, initializes the custom right-click options.
        '''
        if self.Show(modal=False) < 0:
            return False
    
        self.toggle_cmd = self.AddCommand("Enable / disable selected handler")
        self.enable_all_cmd = self.AddCommand("Enable all handlers")
        self.disable_all_cmd = self.AddCommand("Disable all handlers")
        self.config_cmd = self.AddCommand("Load startup script")
        self.mbase_cmd = self.AddCommand("Set MMU base address")
        self.reset_cmd = self.AddCommand("Reset to defaults")
        self.goto_cmd = self.AddCommand("Jump to selected name")
        self.save_cmd = self.AddCommand("Save settings")
        self.quit_cmd = self.AddCommand("Quit")
        return True


class idasimulator_t(idaapi.plugin_t):
    '''
    Primary IDASimulator plugin class.
    '''

    flags = 0
    comment = "IDA Simulator Plugin"
    help = "Simulate excutable logic in Python"
    wanted_name = "IDA Simulator"
    wanted_hotkey = ""

    def init(self):
        '''
        Initialize some default values for class variables.
        '''
        self.gui = None
        self.idasim = None
        self.config = None
        self.functions = {}
        self.startup_script = ''
        self.startup_name = None
        self.stubs = True
        self.menu_context = idaapi.add_menu_item("Options/", "Simulate functions and code blocks...", "Alt-0", 0, self.run, (None,))
        return idaapi.PLUGIN_KEEP

    def term(self):
        '''
        Cleanup IDASimulator and breakpoints when terminated.
        '''
        self.Cleanup()
        idaapi.del_menu_item(self.menu_context)
        return None

    def run(self, arg):
        '''
        Initialize IDASimulator and chooser GUI, if not already initialized.
        '''
        global IDASIM

        if IDASIM is None:
            IDASIM = idasim.IDASim()
            print "%s enabled." % self.wanted_name
        
        self.idasim = IDASIM
        
        self.__parse_libraries()
    
        self.config = IDASimConfiguration(self)
        self.config.Load()
            
        self.gui = IDASimFunctionChooser(self)
        self.gui.show()

    def GetInitValues(self):
        '''
        Returns the named initialization location and the array of startup Python statements.
        '''
        return (self.startup_name, self.startup_script)

    def SetInitValues(self, name=None, script=''):
        '''
        Sets the named initialization location and the array of startup Python statements.

        @name  - Named location.
        @lines - Array of tuples (register name, Python statement).

        Returns the named initialization location and the array of startup Python statements.
        '''
        self.idasim.ExecuteOnStart(None, None, disable=True)

        if not name:
            disable = True
        else:
            disable = False
        
        self.startup_name = name
        self.startup_script = script
        self.idasim.ExecuteOnStart(self.startup_script, self.startup_name, disable=disable)
        
        return (self.startup_name, self.startup_script)

    def IsSimulated(self, name):
        '''
        Checks if a named location has an active IDASimulator handler.

        @name - Named location.

        Returns True if a handler is active, False if not.
        '''
        if self.functions.has_key(name):
            return self.functions[name]['enabled']
        else:
            return False

    def GetHandlerDesc(self, name):
        '''
        Get a handler description for a given named location.

        @name - Handler name.

        Returns the handler description, if it exists. Else, returns None.
        '''
        if name == self.startup_name:
            return 'Initialization handler.'
        else:
            return self.functions[name]['description']

    def ToggleHandler(self, name):
        '''
        Enables/disables the handler for the named location.

        @name - Named location.

        Returns None.
        '''
        if self.IsSimulated(name):
            self.DisableHandler(name)
        else:
            self.EnableHandler(name)

    def EnableHandler(self, name):
        '''
        Enables the handler for the named location.

        @name - Named location.

        Returns None.
        '''
        existing_handler = self.idasim.FunctionHandler.GetHandler(self.functions[name]['function'])
        if existing_handler:
            self.DisableHandler(self.__get_handler_name(existing_handler.im_class.__name__, existing_handler.__name__))

        self.idasim.FunctionHandler.RegisterHandler(self.functions[name]['function'], self.functions[name]['handler'], self.stubs)
        self.functions[name]['enabled'] = True
    
    def EnabledHandlers(self):
        '''
        Returns a list of all named locations that have an active handler.
        '''
        return [name for (name, info) in self.functions.iteritems() if info['enabled']]

    def DisableHandler(self, name):
        '''
        Disables the handler for the named location.

        @name - Named location.
        
        Returns None.
        '''
        self.idasim.FunctionHandler.UnregisterHandler(self.functions[name]['function'], self.stubs)
        self.functions[name]['enabled'] = False

    def Refresh(self):
        '''
        Refreshes the internal list of supported handlers.
        '''
        if self.idasim is not None:
            self.__parse_libraries()
        
            for name in self.EnabledHandlers():
                if name != self.startup_name:
                    self.idasim.FunctionHandler.RegisterHandler(self.functions[name]['function'], self.functions[name]['handler'], self.stubs)    
                    
    def Reset(self):
        '''
        Resets all IDASimulator settings to the defaults.
        '''
        self.SetInitValues(None, None)
        self.idasim.Cleanup()
        self.idasim.mmu.base(idc.BADADDR)
        self.__parse_libraries()

    def Cleanup(self, closegui=True):
        '''
        Cleans up all IDASimulator changes and disables the plugin.
        '''
        global IDASIM

        try:
            if closegui and self.gui is not None:
                self.gui.Close()
        except:
            pass

        try:
            if self.idasim is not None:
                self.idasim.Cleanup()
        except:
            pass

        IDASIM = None
        self.gui = None
        self.idasim = None
        self.functions = {}
        print "%s disabled." % self.wanted_name

    def __get_handler_name(self, class_name, method_name):
        '''
        Builds a handler key name from the class and method names.
        '''
        return class_name + '.' + method_name

    def __generate_handler_entry(self, instance, method, name=None):
        '''
        Creates a single handler dictionary entry for the provided class instance and method.
        '''
        if not name:
            name = method

        handler = getattr(instance, method)
        class_name = instance.__class__.__name__
        handler_name = self.__get_handler_name(class_name, method)

        entry = {}
        entry[handler_name] = {}

        entry[handler_name]['class'] = class_name
        entry[handler_name]['handler'] = handler
        entry[handler_name]['function'] = name
        entry[handler_name]['enabled'] = False

        existing_handler = self.idasim.FunctionHandler.GetHandler(name)
        if existing_handler:
            if self.__get_handler_name(existing_handler.im_class.__name__, existing_handler.__name__) == handler_name:
                entry[handler_name]['enabled'] = True
        try:
            entry[handler_name]['description'] = handler.__doc__.strip().split('\n')[0].strip()
        except:
            entry[handler_name]['description'] = 'Simulates the ' + name + ' function.'

        return entry

    def __parse_library(self, lib):
        '''
        Parses a loaded library for all handlers.

        @lib - Class instance.
        
        Returns a dictionary of handlers.
        '''
        ignore = ['__init__', '__del__', '__enter__', '__exit__']
        handlers = {}
        instance = lib(IDASIM)

        for (name, obj) in inspect.getmembers(lib, inspect.ismethod):
            if name not in ignore:
                handlers.update(self.__generate_handler_entry(instance, name))
        
        self.functions.update(handlers)
        return handlers

    def __parse_libraries(self):
        '''
        Loads/reloads and parses all IDASimulator handlers.
        '''
        import idasimlib
        reload(idasimlib)
        self.functions = {}

        for module_name in dir(idasimlib):
            # Don't process modules whose file names begin with a double underscore
            if not module_name.startswith('__'):
                try:
                    module = getattr(idasimlib, module_name)
                    reload(module)
                    for (class_name, class_obj) in inspect.getmembers(module, inspect.isclass):
                        # Don't process classes whose names begin with an underscore
                        if not class_name.startswith('_'):
                            self.__parse_library(getattr(module, class_name))
                except Exception, e:
                    print "WARNING: Failed to load %s: %s" % (module_name, str(e))
                    continue

def PLUGIN_ENTRY():
    return idasimulator_t()

