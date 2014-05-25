__all__ = ['IDASimFunctionHandler']

import idc
import idaapi
import inspect
import traceback
from exceptions import *
from architecture import Architecture

class IDASimFunctionHandler(object):
    '''
    Registers and manages function simulators.
    '''
    FUNCTION_HANDLERS = {}
    DEFAULT_HANDLER = None
    BPT_CND = '%s.Handler()'
    STUB_NAMING_CONVENTION = '.%s'

    def __init__(self, idbm, name=None, verbose=False):
        '''
        Class constructor.

        @idbm    - Instance of IDASimMMU.
        @name    - Name that will be assigned to the class instance.
        @verbose - Enable verbose mode.

        Returns None.
        '''
        self.idbm = idbm
        self.name = name
        self.verbose = verbose
        self.cpu = Architecture()

        if self.name == None:
            self.name = self.__get_my_name()

        self.bpt_cnd = self.BPT_CND % self.name

        self.UnregisterHandlers()

        # Eval this IDC expression to ensure that Python is set as the
        # preferred external scripting language. This is necessary for the
        # Python function handler to operate correctly.
        idc.Eval('RunPlugin("python", 3)')

    def cleanup(self):
        idc.Eval('RunPlugin("python", 4)')

    def __del__(self):
        self.cleanup()

    def __get_my_name(self):
        '''
        This is a hack to get the name of the class instance variable. For internal use only.
        '''
        i = -3
        (filename, line_number, function_name, text) = traceback.extract_stack()[i]
        name = text[:text.find('=')].strip()
        while 'self' in name:
            i -= 1
            (filename, line_number, function_name, text) = traceback.extract_stack()[i]
            name = name.replace('self', text[:text.find('=')].strip())
        return name

    def SetHandlerBreakpoint(self, address):
        '''
        Sets a handler breakpoint on the specified address.

        @address - Address to set the breakpoint at.

        Returns True on success, False on failure.
        '''
        # Some remote debugger stubs have special needs for different architectures (e.g., gdb).
        # Thus, setting breakpoints should be done through the architecture abstraction class, 
        # rather than directly through AddBpt/AddBptEx.
        self.cpu.SetBreakpoint(address)

        # A bug in versions of IDAPython shipped with IDA prior to 6.4sp1 improperly interpreted 
        # the is_lowcnd value set via SetBptCnd/SetBptCndEx. Do this directly through idaapi
        # ourselves in order to support older versions.
        bpt = idaapi.bpt_t()
        idaapi.get_bpt(address, bpt)
        bpt.condition = self.bpt_cnd
        bpt.flags &= ~idc.BPT_LOWCND
        return idaapi.update_bpt(bpt)

    def __register_internal_handler(self, name, handler):
        '''
        Internal handler registration function. For internal use only.
        '''
        if type(name) == type(""):
            address = idc.LocByName(name)
        else:
            address = name

        if address != idc.BADADDR:
            bpt_result = self.SetHandlerBreakpoint(address)

            if bpt_result:
                self.FUNCTION_HANDLERS[name] = {}
                self.FUNCTION_HANDLERS[name]["handler"] = handler
                self.FUNCTION_HANDLERS[name]["address"] = address

            return bpt_result
        else:
            return False

    def Handler(self):
        '''
        Breakpoint condition handler, called by IDA to evaluate conditional brekpoints. It in turn calls the 
        appropriate function handler, populates the return value and puts execution back at the return address. 
    
        This is a (slight) abuse of IDA's conditional breakpoints; this function always returns 0, indicating that
        the breakpoint condition has not been met. However, it does ensure that every call to a given function
        can be intercepted and simulated, regardless of whether the process is running freely, or the function has 
        been stepped over, stepped into, etc.
        '''
        retval = 0
        retaddr = None

        if self.verbose:
            print self.FUNCTION_HANDLERS

        for (name, properties) in self.FUNCTION_HANDLERS.iteritems():
            if self.cpu.ProgramCounter() == properties["address"]:
                handler = properties["handler"]
                break

        # If no explicit handler was found, use the default handler
        if not handler and self.DEFAULT_HANDLER:
            handler = self.DEFAULT_HANDLER

        if handler:
            if self.verbose:
                print "Using function handler:", handler.__name__

            parameters = {}
        
            # Enumerate the arguments and default values for the handler    
            args, varargs, keywords, defaults = inspect.getargspec(handler)
            try:
                defaults = dict(zip(reversed(args), reversed(defaults)))
            except:
                defaults = {}

            # Build the handler parameters
            try:
                i = 0
                for arg in args:
                    if arg != 'self':
                        parameters[arg] = self.cpu.Argument(i)
                        
                        if defaults.has_key(arg):
                            # If default value is of type string, get the string automatically
                            if type(defaults[arg]) == type(''):
                                parameters[arg] = idc.GetString(parameters[arg])
                            # If default value is of type list, get an array of bytes
                            elif type(defaults[arg]) == type([]) and len(defaults[arg]) == 1:
                                parameters[arg] = [c for c in idc.DbgRead(parameters[arg], defaults[arg][0])]
                        i += 1
            except Exception, e:
                print "WARNING: Failed to parse handler parameters:", str(e)
                parameters = {}

            try:
                retval = handler(**parameters)
            except JumpTo, offset:
                retaddr = self.cpu.ReturnAddress() + offset.message
            except GoTo, addr:
                retaddr = addr.message
            except Exception, e:
                print "WARNING: Failed to simulate function '%s': %s" % (handler.__name__, str(e))
                retval = 0

            if retval is not None:
                if retaddr is None:
                    retaddr = self.cpu.ReturnAddress()

                # If a string type was returned by the handler, place the string in memory and return a pointer
                if type(retval) == type(""):
                    retval = self.idbm.malloc(retval)
                # Map python's True and False to 1 and 0 repsectively
                elif retval == True:
                    retval = 1
                elif retval == False:
                    retval = 0

                self.cpu.ReturnValue(retval)
                self.cpu.ProgramCounter(retaddr)
                self.cpu.StackCleanup()
    
                # Since the PC register is manually manipulated, a breakpoint set on the return
                # address won't be triggered. In this case, make sure we pause the process manually.
                if idc.CheckBpt(self.cpu.ProgramCounter()) > 0:
                    idc.PauseProcess()
            
        return 0

    def RegisterDefaultHandler(self, handler):
        '''
        Register a default "catch-all" handler.

        @handler - Method/function handler.

        Returns None.
        '''
        self.DEFAULT_HANDLER = handler

    def UnregisterDefaultHandler(self):
        '''
        Unregister a default "catch-all" handler.
        
        Returns None.
        '''
        self.DEFAULT_HANDLER = None

    def RegisterHandler(self, name, handler, stubs=True):
        '''
        Registers a given function handler for a given function name.
    
        @name    - Name of the function.
        @handler - The function handler to call.
        @stubs   - If True, handle calls to both extern and stub addresses.

        Returns True on success, False on failure.
        '''

        retval = self.__register_internal_handler(name, handler)

        if retval and stubs and type(name) == type(""):
            stub_name = self.STUB_NAMING_CONVENTION % name
            retval = self.__register_internal_handler(stub_name, handler)
            
        return retval

    def RegisterHandlers(self, handlers, stubs=True):
        '''
        Registers a set of function handlers.

        @handlers - A dictionary consisting of 'name':handler pairs.
        @stubs    - If True, handle calls to both extern and stub addresses.
        
        Returns the number of handlers successfully registered.
        '''
        count = 0

        for (name, handler) in handlers.iteritems():
            if self.RegisterHandler(name, handler, stubs):
                count += 1

        return count

    def UnregisterHandler(self, name, stubs=True):
        '''
        Removes a function handler by name.

        @name  - The name of the function handler to be removed.
        @stubs - If True, corresponding function stub handlers that were automatically created by RegisterHandler will also be removed.

        Returns None.
        '''
        addr = None
        stub_name = None
        stub_addr = None

        if name is not None:
            try:
                stub_name = self.STUB_NAMING_CONVENTION % name
            except:
                pass

            if self.FUNCTION_HANDLERS.has_key(name):
                addr = self.FUNCTION_HANDLERS[name]['address']

            if self.FUNCTION_HANDLERS.has_key(stub_name):
                stub_addr = self.FUNCTION_HANDLERS[stub_name]['address']

        if addr is not None and name is not None:
            idc.DelBpt(addr)
            del self.FUNCTION_HANDLERS[name]

        if stubs and stub_addr is not None and stub_name is not None:
            idc.DelBpt(stub_addr)
            del self.FUNCTION_HANDLERS[stub_name]

    def UnregisterHandlers(self, purge=False):
        '''
        Deletes breakpoints for all registered handlers.

        @purge - Removes all handlers for all instances of IDBFunctionHandler.

        Returns None.
        '''
        self.UnregisterDefaultHandler()
    
        if not purge:
            # Only remove this instance's handlers
            for (name, info) in self.FUNCTION_HANDLERS.iteritems():
                condition = idc.GetBptAttr(info['address'], idc.BPTATTR_COND)

                if condition == self.bpt_cnd:
                    idc.DelBpt(info['address'])
        else:
            # Try to remove ALL instance's handlers (this could remove other conditional breakpoints...)
            for i in range(0, idc.GetBptQty()):
                ea = idc.GetBptEA(i)
                condition = idc.GetBptAttr(ea, idc.BPTATTR_COND)
                if condition.endswith(self.BPT_CND % ''):
                    idc.DelBpt(ea)
        
        self.FUNCTION_HANDLERS = {}

    def GetHandler(self, name):
        '''
        Returns the current handler for the named location.

        @name - Function/location name.

        Returns the handler instance.
        '''
        if self.FUNCTION_HANDLERS.has_key(name):
            return self.FUNCTION_HANDLERS[name]["handler"]
        else:
            return None

