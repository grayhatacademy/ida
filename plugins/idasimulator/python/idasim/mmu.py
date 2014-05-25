__all__  = ['IDASimMMU']

import idc
import idaapi
from application import Application
from architecture import Architecture

class IDASimMMU(object):
    '''
    Manages the allocation of memory while running in the debugger.
    The term 'manage' is used very loosely here; it really only allocates memory.
    '''
    ALIGN = 4
    DEFAULT_MP = 0x100000
    SEGNAME = 'MMU'
    LAST_SEGNAME = ['MEMORY', 'RAM']

    def __init__(self, base=None):
        '''
        Class constructor.
        '''
        # Disable this for now, it doesn't work.
        self.use_native_malloc = False
        self.allocated_addresses = {}

        self.app = Application()
        self.cpu = Architecture()

        if base is not None:
            self.MP = self.BASE_MP = base
        else:
            self.MP = self.BASE_MP = idc.BADADDR

    def _detect_membase(self):
        '''
        Attempts to locate a section of memory for IDBMMU's internal memory allocation.
        For internal use only.
        '''
        if self.BASE_MP == idc.BADADDR:

            # Look for the MMU segment
            ea = idc.SegByName(self.SEGNAME)

            # No MMU segment?
            if ea == idc.BADADDR:
                ea = 0

                # Find the very last defined segment
                while True:
                    segea = idc.NextSeg(ea)
                    
                    if segea == idc.BADADDR:
                        break
                    else:
                        ea = segea

                # Is it not a memory segment?
                if idc.SegName(ea) not in self.LAST_SEGNAME:
                    try:
                        # Find the start of the stack
                        ea = idc.SegStart(self.cpu.StackPointer())

                        # Still nothing? Use the default.
                        if ea == idc.BADADDR:
                            ea = self.DEFAULT_MP
                    except:
                        if not self.use_native_malloc:
                            raise Exception("No available segments for memory allocation! Try defining segment %s." % self.SEGNAME)
            self.BASE_MP = ea

        if self.MP == idc.BADADDR:
            self.MP = self.BASE_MP

        return self.BASE_MP

    def reset(self):
        '''
        Resets the current allocation address.
        '''
        self.MP = idc.BADADDR
        self.allocated_addresses = {}

    def base(self, base=None):
        '''
        Set the base address at which to start allocating memory. Default: 0x100000.

        @base - The base address. If specified BASE_MP will be set to this value.

        Returns the current BASE_MP value.
        '''
        if base is not None:
            self.MP = self.BASE_MP = base
        return self.BASE_MP

    def malloc(self, data=None, size=0):
        '''
        Allocates space for data in the debugger's memory and populates it.
    
        @data - Data to place into memory. If None, NULL bytes will be used.
        @size - Size of memory to allocate. If 0, len(data) bytes will be allocated.
    
        Returns the address of the allocated memory.
        '''
        if size == 0 and data is not None:
            size = len(data)
    
        if data is None:
            data = "\x00" * size

        if self.use_native_malloc:
            addr = self.app.Call('malloc', arguments=[size], retaddr=self.cpu.ReturnAddress())
        else:
            self._detect_membase()
    
            addr = self.MP
            self.MP += size
            # This ensures memory addresses are 4-byte aligned. This is important for some architectures.
            if (self.MP % self.ALIGN) > 0:
                self.MP += (self.ALIGN - (self.MP % self.ALIGN))

            # Keep a dictionary of allocated addresses and their sizes
            self.allocated_addresses[addr] = size
    
        idc.DbgWrite(addr, data)
    
        return addr

