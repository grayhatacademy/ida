# IDA plugin that converts all data in data segments to defined data types, and
# all data in code segments to code.
#
# Use by going to Options->Define data and code.
#
# Craig Heffner
# Tactical Network Solutions

from __future__ import print_function
import idc
import string
import idaapi
import idautils

from shims import ida_shims


class StructEntry(object):
    def __init__(self, ea):
        self.ea = ea
        self.dword = ida_shims.get_wide_dword(self.ea)
        self.type = None
        self.value = None

        string = ida_shims.get_strlit_contents(self.dword)
        name = ida_shims.get_func_name(self.dword)
        if ida_shims.get_name_ea_simple(name) != self.dword:
            name = ''

        if name:
            self.type = int
            self.value = name
        elif string:
            self.type = str
            self.value = string


class StructCast(object):
    def __init__(self, ea, n=16):
        self.entries = []

        for i in range(0, n):
            self.entries.append(StructEntry(ea+(4*i)))


class StructPatternDetector(object):
    def __init__(self, ea, n=16):
        self.address = ea
        self.stop = None
        self.start = None
        self.element_size = 4
        self.num_entries = 0
        self.num_elements = 0
        self.function_element = -1
        self.name_element = -1
        entry_element_count = None

        structure = StructCast(ea, n)

        if structure.entries[0].type is not None:
            (p1, p2) = self.get_entry_pair(structure)

            pattern_to_match = [x.type for x in structure.entries[p1:p2+1]]

            for i in range(0, n):
                address = ea + ((p2+i)*self.element_size)
                struct2 = StructCast(address, n)
                this_pattern = [x.type for x in struct2.entries[p1:p2+1]]
                if this_pattern == pattern_to_match:
                    entry_element_count = int((address - ea) / self.element_size)
                    break

            if entry_element_count is not None and entry_element_count > 0:
                num_entries = self.get_entry_count(ea,
                                                   entry_element_count,
                                                   [x.type for x in structure.entries[p1:entry_element_count]])

                self.start = self.address
                self.num_elements = entry_element_count
                self.num_entries = num_entries
                self.stop = self.address + (self.num_elements *
                                            self.element_size *
                                            self.num_entries)

                if structure.entries[p1].type == str:
                    self.name_element = p1
                    self.function_element = p2
                else:
                    self.name_element = p2
                    self.function_element = p1

    def get_entry_count(self, start, entry_element_count, expected_pattern):
        entry_count = 1

        while True:
            address = start + (entry_element_count * self.element_size * entry_count)
            struct = StructCast(address, entry_element_count)
            this_pattern = [x.type for x in struct.entries[0:entry_element_count]]
            if this_pattern != expected_pattern:
                break
            else:
                entry_count += 1

        return entry_count

    def get_entry_pair(self, structure):
        end = 0
        start = 0
        count = 0

        for entry in structure.entries:
            if entry.type is not None and \
                    entry.type != structure.entries[0].type:
                end = count
                break
            count += 1

        return start, end


class Struct(object):

    def __init__(self, **kwargs):
        for (k, v) in kwargs.items():
            setattr(self, k, v)


class StructFinder(object):
    def __init__(self):
        (self.start, self.stop) = self.get_data_section()

    def get_data_section(self):
        ea = idc.BADADDR
        seg = ida_shims.get_first_seg()
        stop = idc.BADADDR

        while seg != idc.BADADDR:
            if ea == idc.BADADDR and \
                    ida_shims.get_segm_attr(seg, idc.SEGATTR_TYPE) == 2:
                ea = seg

            stop = ida_shims.get_segm_end(seg)
            seg = ida_shims.get_next_seg(seg)

        return ea, stop

    def valid_function_name(self, name):
        allowed_characters = set(string.digits + string.ascii_letters + '_')
        allowed_first_character = set(string.ascii_letters + '_')

        if not name:
            return False
        elif name[0] not in allowed_first_character:
            return False
        elif len([x for x in name if x not in allowed_characters]) > 0:
            return False

        return True

    def search(self):
        patterns = []

        print("Searching for data structure arrays from %s to %s" % \
              (hex(self.start), hex(self.stop)))

        ea = self.start
        while ea < self.stop:
            pattern = StructPatternDetector(ea)
            if pattern.num_entries > 0:
                patterns.append(pattern)
                ea = pattern.stop
            else:
                ea += pattern.element_size

        i = 0
        while i < len(patterns):
            # Consolidate obvious duplicate consecutive structure arrays
            j = i + 1
            while j < len(patterns):
                if (patterns[i].stop == patterns[j].start and
                        patterns[i].num_elements == patterns[j].num_elements and
                        patterns[i].function_element == patterns[j].function_element and
                        patterns[i].name_element == patterns[i].name_element):
                    patterns[i].stop = patterns[j].stop
                    patterns[i].num_entries += patterns[j].num_entries
                    del patterns[j]
                else:
                    j += 1

            print("Found an array of %d structures at 0x%X - 0x%X. Each " \
                  "entry has %d elements of %d bytes each." % \
                  (patterns[i].num_entries, patterns[i].start, patterns[i].stop,
                   patterns[i].num_elements, patterns[i].element_size))

            print("Array element #%d is the address pointer, and element #%d " \
                  "is the address pointer name.\n" % \
                  (patterns[i].function_element, patterns[i].name_element))

            i += 1

        return patterns

    def parse_function_tables(self):
        count = 0

        for pattern in self.search():
            name2func = {}

            ea = pattern.start
            while ea < pattern.stop:
                string_address = ida_shims.get_wide_dword(
                    ea + (pattern.name_element * pattern.element_size))
                function_address = ida_shims.get_wide_dword(
                    ea + (pattern.function_element * pattern.element_size))

                new_function_name = ida_shims.get_strlit_contents(
                    string_address).decode("utf8")
                current_function_name = ida_shims.get_name(function_address)

                if not self.valid_function_name(new_function_name):
                    print("ERROR: '%s' is not a valid function name. This is " \
                          "likely not a function table, or I have parsed it " \
                          "incorrectly!" % new_function_name)
                    print("       Ignoring all entries in the structures " \
                          "between 0x%X and 0x%X.\n" % (pattern.start,
                                                        pattern.stop))
                    name2func = {}
                    break
                elif current_function_name.startswith("sub_"):
                    name2func[new_function_name] = function_address

                ea += (pattern.num_elements * pattern.element_size)

            for (name, address) in name2func.items():
                print("0x%.8X => %s" % (address, name))
                ida_shims.set_name(address, name)
                count += 1

        print("Renamed %d functions!" % count)


class FunctionNameology(object):
    def __init__(self):
        pass

    def rename_functions(self, debug=True, dry_run=False):
        '''
        Renames functions starting with "sub_" based on unique string xrefs.

        @debug   - Set to False to suppress debug output.
        @dry_run - Set to True to perform a dry run (functions will not actually
                   be renamed).

        Returns the number of renamed functions.
        '''
        count = 0

        for (function_address, function_name) in self.func2str_mappings().items():
            if ida_shims.get_name(function_address).startswith("sub_"):
                if dry_run or ida_shims.set_name(function_address, function_name):
                    if debug:
                        print("0x%.8X  =>  %s" % (function_address,
                                                  function_name))
                    count += 1

        if debug:
            print("Renamed %d functions based on unique string xrefs!" % count)

        return count

    def func2str_mappings(self):
        '''
        Resolve unique mappings between functions and strings that those
        functions reference.

        Returns a dictionary of {int(function_address) : str(function_name)}.
        '''
        function_map = {}

        for string in idautils.Strings():
            if self.is_valid_function_name(str(string)):
                function_address = self.str2func(string.ea)
                if function_address is not None:
                    if function_address not in function_map:
                        function_map[function_address] = []
                    function_map[function_address].append(str(string))

        # Each function must have only one candidate string
        for function_address in list(function_map.keys()):
            if len(function_map[function_address]) == 1:
                function_map[function_address] = function_map[function_address][0]
            else:
                del function_map[function_address]

        return function_map

    def is_valid_function_name(self, string):
        '''
        Determines if a string is a valid function name.

        @string - The string to check

        Returns True or False.
        '''
        valid_first_characters = ['_'] + [chr(x) for x in range(65, 91)] + [chr(x) for x in range(97, 123)]
        valid_characters = valid_first_characters + [chr(x) for x in range(48, 58)]

        return (len(string) in range(1, 256) and
                string[0] in valid_first_characters and
                set(string) <= set(valid_characters))

    def str2func(self, ea):
        '''
        Identifies a unique function associated with a given string.

        @ea - The effective address of the string

        Returns the address of the associated function, or None.
        '''
        functions = []

        for xref in idautils.XrefsTo(ea):
            func = idaapi.get_func(xref.frm)
            if func and func.startEA not in functions:
                functions.append(func.startEA)

        # Each string must be referenced by only one function
        if len(functions) == 1:
            return functions[0]
        else:
            return None


class Codatify(object):
    CODE = 2
    DATA = 3
    SEARCH_DEPTH = 25

    def __init__(self):
        if self.get_start_ea(self.DATA) == idc.BADADDR:
            if ida_shims.ask_yn(0, "There are no data segments defined! This "
                                   "probably won't end well. Continue?") != 1:
                raise Exception("Action cancelled by user.")

    # Get the start of the specified segment type (2 == code, 3 == data)
    def get_start_ea(self, attr):
        ea = idc.BADADDR
        seg = ida_shims.get_first_seg()

        while seg != idc.BADADDR:
            if ida_shims.get_segm_attr(seg, idc.SEGATTR_TYPE) == attr:
                ea = seg
                break
            else:
                seg = ida_shims.get_next_seg(seg)

        return ea

    # Creates ASCII strings
    def stringify(self):
        n = 0
        ea = self.get_start_ea(self.DATA)

        if ea == idc.BADADDR:
            ea = ida_shims.get_first_seg()

        print("Looking for possible strings starting at: 0x%X..." % ea, end=' ')

        for s in idautils.Strings():
            if s.ea >= ea:
                if not ida_shims.is_strlit(ida_shims.get_full_flags(s.ea)) \
                        and ida_shims.create_strlit(s.ea, 0):
                    n += 1

        print("created %d new ASCII strings" % n)

    # Converts remaining data into DWORDS.
    def datify(self):
        ea = self.get_start_ea(self.DATA)
        if ea == idc.BADADDR:
            ea = ida_shims.get_first_seg()

        print("Converting remaining data to DWORDs...", end=' ')

        while ea != idc.BADADDR:
            flags = ida_shims.get_full_flags(ea)

            if (ida_shims.is_unknown(flags) or ida_shims.is_byte(flags)) and \
                    ((ea % 4) == 0):
                ida_shims.create_dword(ea)
                ida_shims.op_plain_offset(ea, 0, 0)

            ea = ida_shims.next_addr(ea)

        print("done.")

        self._fix_data_offsets()

    def pointify(self):
        counter = 0

        print("Renaming pointers...", end=' ')

        for (name_ea, name) in idautils.Names():
            for xref in idautils.XrefsTo(name_ea):
                xref_name = ida_shims.get_name(xref.frm)
                if xref_name and xref_name.startswith("off_"):
                    i = 0
                    new_name = name + "_ptr"
                    while ida_shims.get_name_ea_simple(new_name) != idc.BADADDR:
                        new_name = name + "_ptr%d" % i
                        i += 1

                    if ida_shims.set_name(xref.frm, new_name):
                        counter += 1
                    #else:
                    #    print "Failed to create name '%s'!" % new_name

        print("renamed %d pointers" % counter)

    def _fix_data_offsets(self):
        ea = 0
        count = 0

        print("Fixing unresolved offset xrefs...", end=' ')

        while ea != idaapi.BADADDR:
            (ea, n) = idaapi.find_notype(ea, idaapi.SEARCH_DOWN)
            if ida_shims.can_decode(ea):
                insn = ida_shims.decode_insn(ea)
                ops = ida_shims.get_operands(insn)
                for i in range(0, len(ops)):
                    op = ops[i]
                    if op.type == idaapi.o_imm and idaapi.getseg(op.value):
                        idaapi.add_dref(ea, op.value,
                                        (idaapi.dr_O | idaapi.XREF_USER))
                        count += 1

        print("created %d new data xrefs" % count)

    # Creates functions and code blocks
    def codeify(self, ea=idc.BADADDR):
        func_count = 0
        code_count = 0

        if ea == idc.BADADDR:
            ea = self.get_start_ea(self.CODE)
            if ea == idc.BADADDR:
                ea = ida_shims.get_first_seg()

        print("\nLooking for undefined code starting at: %s:0x%X" % \
              (ida_shims.get_segm_name(ea), ea))

        while ea != idc.BADADDR:
            try:
                if ida_shims.get_segm_attr(ea, idc.SEGATTR_TYPE) == self.CODE:
                    if ida_shims.get_func_name(ea) != '':
                        ea = ida_shims.find_func_end(ea)
                        continue
                    else:
                        if ida_shims.add_func(ea):
                            func_count += 1
                        elif ida_shims.create_insn(ea):
                            code_count += 1
            except:
                pass

            ea = ida_shims.next_addr(ea)

        print("Created %d new functions and %d new code blocks\n" % \
              (func_count, code_count))


try:
    class CodatifyFixupCode(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            cd = Codatify()
            cd.codeify()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS


    class CodatifyFixupData(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            cd = Codatify()
            cd.stringify()
            cd.datify()
            cd.pointify()
            StructFinder().parse_function_tables()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
except AttributeError:
    pass


def fix_code(arg=None):
    cd = Codatify()
    cd.codeify()


def fix_data(arg=None):
    cd = Codatify()
    cd.stringify()
    cd.datify()
    cd.pointify()
    StructFinder().parse_function_tables()
    FunctionNameology().rename_functions()


class codatify_t(idaapi.plugin_t):
    flags = 0
    comment = ""
    help = ""
    wanted_name = "Fixup Code and Data"
    wanted_hotkey = ""
    code_action_name = 'fixupcode:action'
    data_action_name = 'fixupdata:action'
    menu_tab = 'Options/'
    menu_context = []

    def init(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            code_desc = idaapi.action_desc_t(self.code_action_name,
                                             'Fixup Code',
                                             CodatifyFixupCode(),
                                             self.wanted_hotkey,
                                             'Fixup Code',
                                             199)

            data_desc = idaapi.action_desc_t(self.data_action_name,
                                             'Fixup Data',
                                             CodatifyFixupData(),
                                             self.wanted_hotkey,
                                             'Fixup Data',
                                             199)

            idaapi.register_action(code_desc)
            idaapi.register_action(data_desc)

            idaapi.attach_action_to_menu(
                self.menu_tab, self.code_action_name, idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                self.menu_tab, self.data_action_name, idaapi.SETMENU_APP)
        else:
            self.menu_context.append(
                idaapi.add_menu_item(
                    "Options/", "Fixup code", "", 0, fix_code, (None,)))
            self.menu_context.append(
                idaapi.add_menu_item(
                    "Options/", "Fixup data", "", 0, fix_data, (None,)))

        return idaapi.PLUGIN_KEEP

    def term(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            idaapi.detach_action_from_menu(self.menu_tab, self.code_action_name)
            idaapi.detach_action_from_menu(self.menu_tab, self.data_action_name)
        else:
            for context in self.menu_context:
                idaapi.del_menu_item(context)
        return None

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return codatify_t()
