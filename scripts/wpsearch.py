import idc
import idaapi

class WPSearch(object):
    '''
    Searches for immediate values commonly founds in MIPS WPS checksum implementations.
    May be applicable to other architectures as well.
    '''

    IMMEDIATES = {
                        0x6B5FCA6B : set(),
                        0x431BDE83 : set(),
                        0x0A7C5AC5 : set(),
                        0x10624DD3 : set(),
                        0x51EB851F : set(),
                        0xCCCCCCCD : set(),
                        0xD1B71759 : set(),
                 }

    def __init__(self):
        for immediate in self.IMMEDIATES.keys():
            ea = 0
            while ea != idc.BADADDR:
                (ea, n) = idc.FindImmediate(ea, idc.SEARCH_DOWN, self._twos_compliment(immediate))
                if ea != idc.BADADDR:
                    func = idaapi.get_func(ea)
                    if func:
                        self.IMMEDIATES[immediate].add(func.startEA)

    def _twos_compliment(self, val):
        '''
        Python converts values larger than 0x7FFFFFFF into longs, which
        aren't converted properly in the swig translation. Use 2's compliment
        for large values instead.
        '''
        bits = 32

        if (val & (1 << (bits - 1))) != 0:
            val = val - (1 << bits)

        return val

    def checksum(self):
        s = self.IMMEDIATES.values()[0]
        for i in range(1, len(self.IMMEDIATES.values())):
            s = s & self.IMMEDIATES.values()[i]
        return s



cksum = WPSearch().checksum()

if cksum:
    print "\nPossible WPS checksum functions:"
    for func_ea in cksum:
        print "\t0x%.8X  [%s]" % (func_ea, idc.Name(func_ea))
else:
    print "\nNo WPS checksum functions found!"

