__all__ = ['Application']

import idc
from architecture import Architecture

class Application(object):
    '''
    Class for invoking functions in the target process.
    '''

    def __init__(self):
        '''
        Class constructor.
        '''
        self.cpu = Architecture()

    def Call(self, function, arguments=[], retaddr=0, block_until_return=True):
        '''
        Call a given function. Arguments must already be configured.
        This should not be used to call functions hooked with IDASimulator or it likely won't work.

        @function           - The name or address of the function to call.
        @arguments          - A list of function arguments.
        @retaddr            - The address to return to.
        @block_until_return - If set to True, this method will not return until the function does.
                              If set to False, this method will return immediately after calling the function.

        Returns the return value of the function on success.
        Returns None on failure, or if block_until_return is False.
        '''
        retval = None

        # Process should already be paused, but just in case...
        idc.PauseProcess()

        # If a function name was specified, get its address
        if isinstance(function, type('')):
            function = idc.LocByName('.' + function)

            if function == idc.BADADDR:
                function = idc.LocByName(function)

        if function != idc.BADADDR:
            if not retaddr:
                retaddr = self.cpu.ProgramCounter()

            # Set the specified function arguments
            self.cpu.SetArguments(arguments)

            # Do any arch-specific initialization before the function call
            self.cpu.PreFunctionCall(function)
    
            # Set up the return address and point the program counter to the start of the target function    
            self.cpu.ReturnAddress(value=retaddr)
            self.cpu.ProgramCounter(value=function)
            idc.Jump(function)

            if block_until_return:
                # Resume process and wait for the target function to return
                idc.StepUntilRet()
                idc.GetDebuggerEvent(idc.WFNE_CONT|idc.WFNE_SUSP, -1)
                idc.Jump(retaddr)
                retval = self.cpu.ReturnValue()
            else:
                idc.ResumeProcess()

        return retval
