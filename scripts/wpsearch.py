import idc
import idaapi
import idautils

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
        self.cksums = set()

    def checksums(self):
        '''
        Search for WPS checksum functions.

        Returns a set of function EAs.
        '''
        self._search_for_immediates()

        self.cksums = self.IMMEDIATES.values()[0]
        for i in range(1, len(self.IMMEDIATES.values())):
            self.cksums = self.cksums & self.IMMEDIATES.values()[i]

        return self.cksums

    def xrefs(self):
        '''
        Identify functions that reference the WPS checksum functions and resolve their string xrefs.

        Returns a dictionary of function EAs and a list of their string xrefs.
        '''
        self._generate_checksum_xrefs_table()

        for string in idautils.Strings():
            for xref in idautils.XrefsTo(string.ea):
                func = idaapi.get_func(xref.frm)
                if func and self.funcs.has_key(func.startEA):
                    self.funcs[func.startEA].add(str(string))

        return self.funcs

    def _search_for_immediates(self):
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

    def _generate_checksum_xrefs_table(self):
        self.funcs = {}

        if not self.cksums:
            self.checksums()

        for cksum in self.cksums:
            func = idaapi.get_func(cksum)
            if func:
                self.funcs[func.startEA] = set()

            for xref in idautils.XrefsTo(cksum):
                func = idaapi.get_func(xref.frm)
                if func and not self.funcs.has_key(func.startEA):
                    self.funcs[func.startEA] = set()

class WPSearchFunctionChooser(idaapi.Choose2):

    DELIM_COL_1 = '-' * 50
    DELIM_COL_2 = '-' * 20
    DELIM_COL_3 = '-' * 125

    def __init__(self):
        idaapi.Choose2.__init__(self,
                                "WPS Function Profiles",
                                [
                                    ["Function", 15 | idaapi.Choose2.CHCOL_PLAIN],
                                    ["Contains checksum algorithm", 15 | idaapi.Choose2.CHCOL_PLAIN],
                                    ["String(s)", 75 | idaapi.Choose2.CHCOL_PLAIN],
                                ])

        self.icon = 41
        self.wps = WPSearch()

        self.run_scans()
        self.populate_items()

    def OnSelectLine(self, n):
        idc.Jump(self.items[n][-1])

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnClose(self):
        pass

    def run_scans(self):
        self.checksum_functions = self.wps.checksums()
        self.checksum_string_xrefs = self.wps.xrefs()

    def populate_items(self):
        self.items = []

        for (func_ea, strings) in self.checksum_string_xrefs.iteritems():

            is_checksum_function = str(func_ea in self.checksum_functions)

            if not strings:
                self.items.append([idc.Name(func_ea), is_checksum_function, "", func_ea])
            else:
                for string in strings:
                    self.items.append([idc.Name(func_ea), is_checksum_function, string, func_ea])

            self.items.append([self.DELIM_COL_1, self.DELIM_COL_2, self.DELIM_COL_3, idc.BADADDR])

        # Remove the last delimiter column
        if self.items and self.items[-1][-1] == idc.BADADDR:
            self.items.pop(-1)

    def show(self):
        if self.Show(modal=False) < 0:
            return False
        return True



if __name__ == '__main__':
    WPSearchFunctionChooser().show()

