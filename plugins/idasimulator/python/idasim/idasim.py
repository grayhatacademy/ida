__all__ = ['IDASim']

import idc
import idaapi
import idautils
from mmu import *
from handler import *
from exceptions import *
from application import *
from architecture import *

class IDASimDbgHook(idaapi.DBG_Hooks):
    '''
    Resets the IDASimMMU base address (MP) whenever the debugger is started/stopped.
    Executes startup code when the debugger is started, if specified.
    Only used internally by the IDASim class.
    '''
    def dbg_init(self, idasim):
        self.debugging = False
        self.sim = idasim
        self.hook()

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        self.sim.mmu.reset()
        if not self.debugging:
            self.debugging = True
            self.sim.InitHandler(init=True)

    def dbg_process_exit(self, pid, tid, ea, code):
        self.debugging = False
        self.sim.mmu.reset()

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        self.sim.mmu.reset()
        if not self.debugging:
            self.debugging = True
            self.sim.InitHandler(init=True)

    def dbg_process_detatch(self, pid, tid, ea):
        self.debugging = False
        self.sim.mmu.reset()

class IDASim(object):
    '''
    Class for easily simulating library function calls and initializing memory/registers when debugging emulated code in IDA. 
    '''

    def __init__(self, handlers={}, debug=False, attach=False, membase=None):
        '''
        Class constructor.

        @handlers  - A dictionary of function names/addresses to simulate and their corresponding handlers.
        @debug     - Set to True to automatically start debugging.
        @attach    - Set to True to attach to a process, rather than directly running the debugger.
        @membase   - Specify the base address to start at when allocating memory.

        Returns None.
        '''
        self.user_handlers = handlers
        self.script = None
        self.script_name = None

        self.cpu = Architecture()
        self.mmu = IDASimMMU()
        self.app = Application()
        self.FunctionHandler = IDASimFunctionHandler(self.mmu)
        self.dbg_hook = IDASimDbgHook()
        self.dbg_hook.dbg_init(self)

        self.__register_handlers()
        
        if attach:
            self.AttachDebugger()
        elif debug:
            self.StartDebugger()

        if membase is not None:
            self.mmu.base(membase)

        def __register_handlers(self):
        '''
        Registers function names and handlers with the IDB function handler.
        For internal use only.
        '''
        for (name, handler) in self.user_handlers.iteritems():
            self.FunctionHandler.RegisterHandler(name, handler)

    def __get_instance_methods(self, instance):
        methods = {}

        for name in dir(instance):
            if not name.startswith('_'):
                obj = getattr(instance, name)
                if 'method' in type(obj).__name__:
                    methods[name] = obj

        return methods

    def InitHandler(self, init=False):
        if self.script is not None:
            if (self.script_name is not None and not init) or (self.script_name is None and init):
                script_globals = {
                        'IDASIM'     : self,
                        'idc'        : idc,
                        'idaapi'    : idaapi,
                        'idautils'    : idautils,
                }

                script_globals.update(self.__get_instance_methods(self))
                script_globals.update(self.__get_instance_methods(self.cpu))

                try:
                    exec(self.script, script_globals)
                except Exception, e:
                    print "Failed to exec startup script:", str(e)
                    print "################"
                    print self.script
                    print "################"
        return None

    def ExecuteOnStart(self, script=None, name=None, disable=False):
        '''
        Specify a Python string to be evaluated when the debugger is started/attahced.

        @script - Python string to be evaluated. If None, this feature will be disabled.

        Returns None.
        '''
        self.script = script

        if disable:
            self.FunctionHandler.UnregisterHandler(self.script_name)
            self.script_name = None
        elif name is not None and script is not None:
            self.FunctionHandler.RegisterHandler(name, self.InitHandler)
            
        self.script_name = name
        
    def vsprintf(self, fmt, index):
        '''
        Builds a string from a format string and format arguments.
                
        @fmt   - The format string.
        @index - The function argument number at which the format string arguments start (0-indexed).

        Returns a formatted string.
        '''
        n = 0
        for i in range(0, len(fmt)-1):
            if fmt[i] == '%' and fmt[i+1] != '%':
                n += 1

        return fmt % tuple(self.cpu.GetArguments(index, n))

    def WaitForDebugger(self):
        '''
        Waits for the debugger event (WFNE_CONT | WFNE_SUSP).
        Called internally by StartDebugger and AttachDebugger.

        Returns None.
        '''
        idc.GetDebuggerEvent(idc.WFNE_CONT | idc.WFNE_SUSP, -1)

    def StartDebugger(self):
        '''
        Starts the debugger (equivalent of pressing F9).

        Returns None.
        '''
        idc.StartDebugger('', '', '')
        self.WaitForDebugger()

    def AttachDebugger(self, pid=-1):
        '''
        Attaches the debugger to a running process.

        @pid - The PID of the process to attach to (user will be prompted if not specified).

        Returns None.
        '''
        idc.AttachProcess(pid, -1)
        self.WaitForDebugger()

    def Malloc(self, data=None, size=0):
        '''
        Allocates space in the debugger's memory.

        @data - Fill the allocated space with this data.
        @size - If data is None, allocate and zero out size bytes of memory.

        Returns the address of the allocated memory.
        '''
        return self.mmu.malloc(data, size)

    def String(self, string, raw=False):
        '''
        Creates a NULL-terminated string in the debugger's memory.

        @string - The string, or list of strings, to place into memory.
        @raw    - If set to True, the string will not be NULL terminated.

        Returns the address, or list of addresses, of the string(s) in memory.
        '''
        addrs = []

        if type(string) == type(""):
            array = [string]
        else:
            array = string

        for s in array:
            if not raw:
                s = s + "\x00"
            addrs.append(self.Malloc(s))

        if type(string) == type(""):
            addrs = addrs[0]

        return addrs

    def Int(self, value, size):
        '''
        Creates an integer value of size bytes in the debugger's memory.

        @value - The integer value, or list of values, to place into memory.
        @size  - The size of the interger value(s), in bytes.

        Returns the address, or a list of addresses, of the integer(s) in memory.
        '''
        data = []

        if type(value) != type([]):
            value = [value]

        for d in value:
            data.append(self.cpu.ToString(d, size))

        return self.String(data, raw=True)

    def DoubleWord(self, dword):
        '''
        Places a double word integer into the debugger's memory.
        
        @dword - The value, or list of values, to place into memory.

        Returns the address, or a list of addresses, of the dword(s) in memory.
        '''
        return self.Int(dword, self.cpu.bsize*2)

    def Word(self, word):
        '''
        Places a word-sized integer into the debugger's memory.

        @word - The four byte integer value, or list of values, to place into memory.

        Returns the address, or a list of addresses, of the word(s) in memory.
        '''
        return self.Int(word, self.cpu.bsize)

    def HalfWord(self, hword):
        '''
        Places a half-word sized integer into the debugger's memory.

        @hword - The two byte value, or list of values, to place into memory.

        Returns the address, or a list of addresses, of the half word(s) in memory.
        '''
        return self.Int(hword, self.cpu.bsize/2)

    def Byte(self, byte):
        '''
        Places one byte of data into the debugger's memory.
        
        @byte - The byte value, or list of values, to place into memory.
        
        Returns the address, or a list of addresses, of the byte(s) in memory.
        '''
        return self.Int(byte, 1)

    def ARGV(self, argv):
        '''
        Allocates space for an argv data structure.

        @argv - A list of argv strings.

        Returns the address of the argv array of pointers.
        '''
        return self.Word(self.String(argv))[0]

    def Cleanup(self):
        '''
        Removes all registered function simulation hooks.

        Returns None.
        '''
        self.FunctionHandler.UnregisterHandlers()

