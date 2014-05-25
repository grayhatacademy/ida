__all__ = ['Architecture']

import idc

class Architecture(object):
    '''
    Abstraction class for accessing CPU-specific registers and data.
    '''

    BIG = 'big'
    LITTLE = 'little'

    ARCH = {
        'mips'    : {
                'spoffset'  : 0x10,
                'argreg'    : ['a0', 'a1', 'a2', 'a3'],
                'retval'    : ['v0', 'v1'],
                'sp'        : 'sp',
                'ra'        : 'ra',
                'pc'        : 'pc',
                # Common calling convention for MIPS GCC is to place the address of the function
                # into $t9 and then jalr $t9. The callee then expects $t9 to point to the beginning
                # of itself, so $t9 is used to calculate the relative offset to the global pointer.
                # If $t9 is not set appropriately, any data/code xrefs that rely on $gp will fail.
                'callreg'   : 't9'
        },
        'arm'    : {
                'spoffset'  : 0x10,
                'argreg'    : ['R0', 'R1', 'R2', 'R3'],
                'retval'    : ['R0', 'R1'],
                'sp'        : 'SP',    
                'ra'        : 'LR',
                'pc'        : 'PC',
        },
        'ppc'    : {
                'spoffset'  : 8,
                'argreg'    : ['R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R10'],
                'retval'    : ['R3'],
                'sp'        : 'R1',
                'ra'        : 'LR',
                'pc'        : 'PC',
                # GDB stubs for PPC are special...
                'bpt_size'  : 1,
                'bpt_type'  : idc.BPT_EXEC
        },
        'ia32'    : {
                'spoffset'  : 4,
                'argreg'    : [],
                'retval'    : ['EAX'],
                'sp'        : 'ESP',
                'ra'        : '*ESP',
                'pc'        : 'EIP',
        },
        'ia64'    : {
                'spoffset'  : 8,
                'argreg'    : ['RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9'],
                'retval'    : ['RAX'],
                'sp'        : 'RSP',
                'ra'        : '*RSP',
                'pc'        : 'RIP',
        },
        'win64'    : {
                'spoffset'  : 8,
                'argreg'    : ['RDX', 'RCX', 'R8', 'R9'],
                'retval'    : ['RAX'],
                'sp'        : 'RSP',
                'ra'        : '*RSP',
                'pc'        : 'RIP',
        }
    }
    
    PROCESSORS = {
        'mipsl'    : [{
                'architecture'  : 'mips',
                'endianess'     : LITTLE,
                'bits'          : 32,
        }],
        'mipsb'    : [{
                'architecture'    : 'mips',
                'endianess'    : BIG,
                'bits'        : 32,
        }],
        'arm'    : [{
                'architecture'    : 'arm',
                'endianess'    : LITTLE,
                'bits'        : 32,
        }],
        'armb'    : [{
                'architecture'    : 'arm',
                'endianess'    : BIG,
                'bits'        : 32,
        }],
        'ppc'    : [{
                'architecture'    : 'ppc',
                'endianess'    : BIG,
                'bits'        : 32,
        }],
        'metapc': [{
                'architecture'    : 'ia32',
                'endianess'    : LITTLE,
                'bits'        : 32,
               },
               {
                'architecture'    : 'win64',
                'endianess'    : LITTLE,
                'bits'        : 64,
                # Windows passes args differently in x86_64
                'file_types'    : [idc.FT_PE, idc.FT_EXE]
               },
               {
                'architecture'    : 'ia64',
                'endianess'    : LITTLE,
                'bits'        : 64,
               }
        ],
                
    }

    def __init__(self):
        '''
        Class constructor.
        
        Returns None.
        '''
        self.cpu = None
        self.cpu_name = None
        self.architecture = None
        self.bits64 = False
        self.bits = 0
        self.bsize = 0    

        self.__cpu_id()

        if self.cpu == None:
            if self.bits64:
                bits = '64'
            else:
                # This is an assumption, but it's only for the error message.
                # TODO: How to determine if a target is 16/32 bit from IDA's API?
                bits = '32'

            raise Exception("Unsupported cpu type: %s.%s" % (self.cpu_name, bits))

    def __stack_dword(self, n, value=None):
        addr = self.StackPointer() + self.cpu['spoffset'] + (n * self.bsize)

        if value is not None:
            sval = self.ToString(value, size=self.bsize)
            idc.DbgWrite(addr, sval)

        return idc.DbgDword(addr)

    def __reg_value(self, reg, value=None):
        if value is not None:
            if reg.startswith('*'):
                idc.DbgWrite(idc.GetRegValue(reg[1:]), self.ToString(value))
            else:
                idc.SetRegValue(value, reg)
        
        if reg.startswith('*'):
            return idc.DbgDword(idc.GetRegValue(reg[1:]))
        else:
            return idc.GetRegValue(reg)

    def __cpu_id(self):
        self.cpu_name = idc.GetShortPrm(idc.INF_PROCNAME).lower()
        
        if (idc.GetShortPrm(idc.INF_LFLAGS) & idc.LFLG_64BIT) == idc.LFLG_64BIT:
            self.bits64 = True
        else:
            self.bits64 = False

        for (processor, architectures) in self.PROCESSORS.iteritems():
            if self.cpu_name == processor:
                for arch in architectures:
                    # Only use 64-bit processor modules for a 64 bit binary
                    if (self.bits64 and arch['bits'] != 64) or (not self.bits64 and arch['bits'] == 64):
                        continue

                    # If specific file types were specified for this processor module, make sure the target file is in that list
                    if arch.has_key('file_types') and idc.GetShortPrm(idc.INF_FILETYPE) not in arch['file_types']:
                        continue

                    self.cpu = self.ARCH[arch['architecture']]
                    self.architecture = arch['architecture']
                    self.endianess = arch['endianess']
                    self.bits = arch['bits']
                    self.bsize = self.bits / 8
                    break

                if self.cpu:
                    break
        return None

    def ToString(self, value, size=None):
        '''
        Converts an integer value of size bytes into a raw string of bytes.

        @value - Integer value to be represented as a raw string.
        @size  - Size of the integer value, in bytes.

        Returns a raw string containing the integer value in string form, and in the appropriate endianess.
        '''
        data = ""

        if size is None:
            size = self.bsize

        for i in range(0, size):
            data += chr((value >> (8*i)) & 0xFF)

        if self.endianess != self.LITTLE:
            data = data[::-1]

        return data

    def FromString(self, data, size=None):
        '''
        Converts raw string data into an integer value, with appropriate endianess.

        @data - Raw string data.
        @size - Number of bytes to convert.

        Returns an integer value.
        '''
        i = 0
        value = 0

        if size is None:
            size = len(data)

        if self.endianess != self.LITTLE:
            data = data[::-1]

        for c in data[:size]:
            value += (ord(c) << (8*i))
            i += 1

        return value

    def GetArguments(self, index, n):
        '''
        Get a list of function arguments. Any valid string pointers will be converted to strings.

        @index - First argument index, 0-indexed.
        @n     - The number of arguments to retrieve.

        Returns a list of n arguments.
        '''
        args = []

        for j in range(index, n+index):
            arg = self.Argument(j)
            try:
                sval = idc.GetString(arg)
            except:
                sval = None

            if sval is not None:
                args.append(sval)
            else:
                args.append(arg)

        return args

    def SetArguments(self, arguments):
        '''
        Sets a list of function arguments.

        @arguments - List of function arguments.

        Returns None.
        '''
        for i in range(0, len(arguments)):
            self.Argument(i, value=arguments[i])

    def Argument(self, n, value=None):
        '''
        Read/write function arguments.

        @n     - Argument index number, 0-indexed.
        @value - If specified, the argument will be set to this value.

        Returns the current argument value.
        '''
        regn = len(self.cpu['argreg'])

        if value is not None:
            if n < regn:
                self.__reg_value(self.cpu['argreg'][n], value)
            else:
                self.__stack_dword(n-regn, value)
            
        if n < regn:
            return self.__reg_value(self.cpu['argreg'][n])
        else:
            return self.__stack_dword(n-regn)

    def StackPointer(self, value=None):
        '''
        Read/write the stack pointer register.

        @value - If specified, the stack pointer register will be set to this value.

        Returns the current stack pointer register value.
        '''
        return self.__reg_value(self.cpu['sp'], value)

    def ReturnValue(self, value=None, n=0):
        '''
        Read/write the function return register value.

        @value - If specified, the return register will be set to this value.
        @n     - Return register index number, for those architectures with multiple return registers.

        Returns the current return register value.
        '''
        return self.__reg_value(self.cpu['retval'][n], value)

    def ProgramCounter(self, value=None):
        '''
        Read/write the program counter register.

        @value - If specified, the program counter register will be set to this value.

        Returns the current value of the program counter register.
        '''
        return self.__reg_value(self.cpu['pc'], value)

    def ReturnAddress(self, value=None):
        '''
        Read/write the return address.

        @value - If specified, the return address will be set to this value.

        Returns the current return address value.
        '''
        return self.__reg_value(self.cpu['ra'], value)

    def StackCleanup(self):
        '''
        Cleans up values automatically pushed onto the stack by some architectures (return address in x86 for example).
        '''
        if self.cpu['ra'].startswith('*') and self.cpu['ra'][1:] == self.cpu['sp']:
            self.StackPointer(self.StackPointer() + self.bsize)

    def SetBreakpoint(self, address):
        '''
        Some GDB stubs for various architectures require different breakpoint settings.
        This method sets the appropriate breakpoint for the selected architecture.

        @address - The breakpoint address.

        Returns True on success, False on failure.
        '''
        bpt_size = 0
        bpt_type = idc.BPT_SOFT

        if self.cpu.has_key('bpt_size'):
            bpt_size = self.cpu['bpt_size']
        if self.cpu.has_key('bpt_type'):
            bpt_type = self.cpu['bpt_type']

        return idc.AddBptEx(address, bpt_size, bpt_type)

    def PreFunctionCall(self, function):
        '''
        Configure architecture-specific pre-requisites before calling a function.
        Called internally by Application.Call.

        @function - The address of the function to call.

        Returns None.
        '''
        if self.cpu.has_key('callreg'):
            idc.SetRegValue(function, self.cpu['callreg'])
