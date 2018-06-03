# IDA plugin that converts all data in data segments to defined data types, and all data in code segments to code.
#
# Use by going to Options->Define data and code.
#
# Craig Heffner
# Tactical Network Solutions

import idc
import idaapi
import idautils
import string

class StructEntry(object):

    def __init__(self, ea):
        self.ea = ea
        self.dword = idc.Dword(self.ea)
        self.type = None
        self.value = None

        string = idc.GetString(self.dword)
        name = idc.GetFunctionName(self.dword)
        if idc.LocByName(name) != self.dword:
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

        struct = StructCast(ea, n)

        if struct.entries[0].type is not None:
            (p1, p2) = self.get_entry_pair(struct)

            pattern_to_match = [x.type for x in struct.entries[p1:p2+1]]

            for i in range(0, n):
                address = ea + ((p2+i)*self.element_size)
                struct2 = StructCast(address, n)
                this_pattern = [x.type for x in struct2.entries[p1:p2+1]]
                if this_pattern == pattern_to_match:
                    entry_element_count = (address - ea) / self.element_size
                    break

            if entry_element_count is not None and entry_element_count > 0:
                num_entries = self.get_entry_count(ea,
                                                   entry_element_count,
                                                   [x.type for x in struct.entries[p1:entry_element_count]])

                self.start = self.address
                self.num_elements = entry_element_count
                self.num_entries = num_entries
                self.stop = self.address + (self.num_elements * self.element_size * self.num_entries)

                if struct.entries[p1].type == str:
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


    def get_entry_pair(self, struct):
        end = 0
        start = 0
        count = 0

        for entry in struct.entries:
            if entry.type is not None and entry.type != struct.entries[0].type:
                end = count
                break
            count += 1

        return (start, end)


class Struct(object):

    def __init__(self, **kwargs):
        for (k, v) in kwargs.iteritems():
            setattr(self, k, v)

class StructFinder(object):

    def __init__(self):
        (self.start, self.stop) = self.get_data_section()

    def get_data_section(self):
        ea = idc.BADADDR
        seg = idc.FirstSeg()

        while seg != idc.BADADDR:
            if ea == idc.BADADDR and idc.GetSegmentAttr(seg, idc.SEGATTR_TYPE) == 2:
                ea = seg

            stop = idc.SegEnd(seg)
            seg = idc.NextSeg(seg)

        return (ea, stop)

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

        print "Searching for data structure arrays from", hex(self.start), "to", hex(self.stop)

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

            print "Found an array of %d structures at 0x%X - 0x%X. Each entry has %d elements of %d bytes each." % (patterns[i].num_entries,
                                                                                                                    patterns[i].start,
                                                                                                                    patterns[i].stop,
                                                                                                                    patterns[i].num_elements,
                                                                                                                    patterns[i].element_size)
            print "Array element #%d is the address pointer, and element #%d is the address pointer name.\n" % (patterns[i].function_element, patterns[i].name_element)

            i += 1

        return patterns

    def parse_function_tables(self):
        count = 0

        for pattern in self.search():
            name2func = {}

            ea = pattern.start
            while ea < pattern.stop:
                string_address = idc.Dword(ea + (pattern.name_element * pattern.element_size))
                function_address = idc.Dword(ea + (pattern.function_element * pattern.element_size))

                new_function_name = idc.GetString(string_address)
                current_function_name = idc.Name(function_address)

                if not self.valid_function_name(new_function_name):
                    print "ERROR: '%s' is not a valid function name. This is likely not a function table, or I have parsed it incorrectly!" % new_function_name
                    print "       Ignoring all entries in the structures between 0x%X and 0x%X.\n" % (pattern.start, pattern.stop)
                    name2func = {}
                    break
                elif current_function_name.startswith("sub_"):
                    name2func[new_function_name] = function_address

                ea += (pattern.num_elements * pattern.element_size)

            for (name, address) in name2func.iteritems():
                print "0x%.8X => %s" % (address, name)
                idc.MakeName(address, name)
                count += 1

        print "Renamed %d functions!" % count

class Codatify(object):

    CODE = 2
    DATA = 3
    SEARCH_DEPTH = 25

    def __init__(self):
        if self.get_start_ea(self.DATA) == idc.BADADDR:
            if idc.AskYN(0, "There are no data segments defined! This probably won't end well. Continue?") != 1:
                raise Exception("Action cancelled by user.")

    # Get the start of the specified segment type (2 == code, 3 == data)
    def get_start_ea(self, attr):
        ea = idc.BADADDR
        seg = idc.FirstSeg()

        while seg != idc.BADADDR:
            if idc.GetSegmentAttr(seg, idc.SEGATTR_TYPE) == attr:
                ea = seg
                break
            else:
                seg = idc.NextSeg(seg)

        return ea

    # Creates ASCII strings
    def stringify(self):
        n = 0
        ea = self.get_start_ea(self.DATA)

        if ea == idc.BADADDR:
            ea = idc.FirstSeg()

        print ("Looking for possible strings starting at: %s:0x%X..." % (idc.SegName(ea), ea)),

        for s in idautils.Strings():
            if s.ea > ea:
                if not idc.isASCII(idc.GetFlags(s.ea)) and idc.create_strlit(s.ea, idc.BADADDR):
                    n += 1

        print "created %d new ASCII strings" % n

    # Converts remaining data into DWORDS.
    def datify(self):
        ea = self.get_start_ea(self.DATA)
        if ea == idc.BADADDR:
            ea = idc.FirstSeg()

        print "Converting remaining data to DWORDs...",

        while ea != idc.BADADDR:
            flags = idc.GetFlags(ea)

            if (idc.isUnknown(flags) or idc.isByte(flags)) and ((ea % 4) == 0):
                idc.MakeDword(ea)
                idc.OpOff(ea, 0, 0)

            ea = idc.NextAddr(ea)

        print "done."

        self._fix_data_offsets()

    def pointify(self):
        counter = 0

        print "Renaming pointers...",

        for (name_ea, name) in idautils.Names():
            for xref in idautils.XrefsTo(name_ea):
                xref_name = idc.Name(xref.frm)
                if xref_name and xref_name.startswith("off_"):
                    i = 0
                    new_name = name + "_ptr"
                    while idc.LocByName(new_name) != idc.BADADDR:
                        new_name = name + "_ptr%d" % i
                        i += 1

                    if idc.MakeName(xref.frm, new_name):
                        counter += 1
                    #else:
                    #    print "Failed to create name '%s'!" % new_name

        print "renamed %d pointers" % counter

    def _fix_data_offsets(self):
        ea = 0
        count = 0

        print "Fixing unresolved offset xrefs...",

        while ea != idaapi.BADADDR:
            (ea, n) = idaapi.find_notype(ea, idaapi.SEARCH_DOWN)
            if idaapi.decode_insn(ea):
                for i in range(0, len(idaapi.cmd.Operands)):
                    op = idaapi.cmd.Operands[i]
                    if op.type == idaapi.o_imm and idaapi.getseg(op.value):
                        idaapi.add_dref(ea, op.value, (idaapi.dr_O | idaapi.XREF_USER))
                        count += 1

        print "created %d new data xrefs" % count

    # Creates functions and code blocks
    def codeify(self, ea=idc.BADADDR):
        func_count = 0
        code_count = 0

        if ea == idc.BADADDR:
            ea = self.get_start_ea(self.CODE)
            if ea == idc.BADADDR:
                ea = idc.FirstSeg()

        print "\nLooking for undefined code starting at: %s:0x%X" % (idc.SegName(ea), ea)

        while ea != idc.BADADDR:
            try:
                if idc.GetSegmentAttr(ea, idc.SEGATTR_TYPE) == self.CODE:
                    if idc.GetFunctionName(ea) != '':
                        ea = idc.FindFuncEnd(ea)
                        continue
                    else:
                        if idc.MakeFunction(ea):
                            func_count += 1
                        elif idc.MakeCode(ea):
                            code_count += 1
            except:
                pass

            ea = idc.NextAddr(ea)

        print "Created %d new functions and %d new code blocks\n" % (func_count, code_count)


try:
    class FixCodeHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            codatify_t.fix_code()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
except AttributeError:
    pass


try:
    class FixDataHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        def activate(self, ctx):
            codatify_t.fix_data()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
except AttributeError:
    pass


class codatify_t(idaapi.plugin_t):
    flags = 0
    comment = ""
    help = ""
    wanted_name = "Define all data and code"
    wanted_hotkey = ""
    menu_context_fixup_code = None
    menu_context_fixup_data = None
    fixup_code_action_desc = None
    fixup_data_action_desc = None

    def init(self):
        if idaapi.IDA_SDK_VERSION <= 695:
            self.menu_context_fixup_code = idaapi.add_menu_item("Options/", "Fixup code", "", 0, self._fix_code, (None,))
            self.menu_context_fixup_data = idaapi.add_menu_item("Options/", "Fixup data", "", 0, self._fix_data, (None,))
        elif idaapi.IDA_SDK_VERSION >= 700:
            # Describe the 'Fixup code' action
            self.fixup_code_action_desc = idaapi.action_desc_t(
                'codatify:fixupcodeaction',  # The action name. This acts like an ID and must be unique
                'Fixup code',  # The action text.
                FixCodeHandler(),  # The action handler.
                '',  # Optional: the action shortcut
                'Fixes the code',  # Optional: the action tooltip (available in menus/toolbar)
            )  # Optional: the action icon (shows when in menus/toolbars)

            # Register the 'Fixup code' action
            idaapi.register_action(self.fixup_code_action_desc)

            # Attach the 'Fixup code' action to the menu
            idaapi.attach_action_to_menu(
                'Options/',  # The relative path of where to add the action
                'codatify:fixupcodeaction',  # The action ID (see above)
                idaapi.SETMENU_APP)  # We want to append the action after the 'Manual instruction...'

            # Describe the 'Fixup data' action
            self.fixup_data_action_desc = idaapi.action_desc_t(
                'codatify:fixupdataaction',
                'Fixup data',
                FixDataHandler(),
                '',
                'Fixes the data',
            )

            # Register the 'Fixup data' action
            idaapi.register_action(self.fixup_data_action_desc)

            # Attach the 'Fixup data' action to the menu
            idaapi.attach_action_to_menu(
                'Options/',
                'codatify:fixupdataaction',
                idaapi.SETMENU_APP
            )

        else:
            pass
        return idaapi.PLUGIN_KEEP

    def term(self):
        if idaapi.IDA_SDK_VERSION <= 695:
            idaapi.del_menu_item(self.menu_context_fixup_code)
            idaapi.del_menu_item(self.menu_context_fixup_data)
        elif idaapi.IDA_SDK_VERSION >= 700:
            idaapi.detach_action_from_menu('Options/', 'codatify:fixupcodection')
            idaapi.detach_action_from_menu('Options/', 'codatify:fixupdataaction')
            idaapi.unregister_action('codatify:fixupcodection')
            idaapi.unregister_action('codatify:fixupdataaction')
        else:
            pass
        return None

    def run(self, arg):
        pass

    def _fix_code(self, arg):
        self.fix_code()

    def _fix_data(self, arg):
        self.fix_data()

    @staticmethod
    def fix_code():
        cd = Codatify()
        cd.codeify()

    @staticmethod
    def fix_data():
        cd = Codatify()
        cd.stringify()
        cd.datify()
        cd.pointify()
        StructFinder().parse_function_tables()


def PLUGIN_ENTRY():
    return codatify_t()

