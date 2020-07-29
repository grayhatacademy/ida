# Shim file to support IDA 6.x-7.3 and 7.5+
# Documentation provided by Hex-Rays:
# https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.html

import idc
import idaapi

try:
    import ida_bytes
except ImportError:
    ida_bytes = None

try:
    import ida_name
except ImportError:
    ida_name = None

try:
    import ida_kernwin
except ImportError:
    ida_kernwin = None

try:
    import ida_nalt
except ImportError:
    ida_nalt = None

try:
    import ida_ua
except ImportError:
    ida_ua = None

try:
    import ida_funcs
except ImportError:
    ida_funcs = None


def _get_fn_by_version(lib, curr_fn, archive_fn, archive_lib=None):
    '''
    Determine which function should be called based on the version of IDA.

    :param curr_fn: 7.X version of the function.

    :param archive_fn: 6.X version of the function.

    :param archive_lib: If the archive lib is different than the current lib,
                        set it here.

    :return: Function based on the version of IDA.
    '''
    if idaapi.IDA_SDK_VERSION >= 700:
        try:
            return getattr(lib, curr_fn)
        except AttributeError:
            raise Exception('%s is not a valid function in %s' % (curr_fn,
                                                                  lib))
    use_lib = lib if archive_lib is None else archive_lib
    try:
        return getattr(use_lib, archive_fn)
    except AttributeError:
        raise Exception('%s is not a valid function in %s' % (archive_fn,
                                                              use_lib))


def print_insn_mnem(ea):
    '''
    Get instruction mnemonics.

    :param ea: Linear address of the instruction.
    :type ea: int

    :return: Instruction mnemonic. "" if not instruction is found.

    :note: *Heavy breath* This function may not return exactly the same
    mnemonics as you see on the screen.
    '''
    fn = _get_fn_by_version(idc, 'print_insn_mnem', 'GetMnem')
    return fn(ea)


def print_operand(ea, n):
    '''
    Get operand of an instruction or data.

    :param ea: Linear address of the item.
    :type ea: int

    :param n: Number of operand: 0 - the first operand 1 - the second operand.
    :type n: int

    :return: The current text representation of operand or "".
    '''
    fn = _get_fn_by_version(idc, 'print_operand', 'GetOpnd')
    return fn(ea, n)


def define_local_var(start, end, location, name):
    '''
    Create a local variable.

    :param start: Start address range for the local variable.
    :type start: int

    :param end: End of address range for the local variable.
    :type end: int

    :param location: The variable location in the "[bp+xx]" form where xx is
                     a number. The location can also be specified as a
                     register name.
    :type location: str

    :param name: Name of the local variable.
    :type name: str

    :return: 1-ok, 0-failure
    '''
    fn = _get_fn_by_version(idc, 'define_local_var', 'MakeLocal')
    return fn(start, end, location, name)


def find_func_end(ea):
    '''
    Determine a new function boundaries.

    :param ea: Start address of the new function.
    :type ea: int

    :return: If a function already exists, then return its end address. If a
    function end cannot be determine, the return BADADDR otherwise return the
    end address of the new function.
    '''
    fn = _get_fn_by_version(idc, 'find_func_end', 'FindFuncEnd')
    return fn(ea)


def is_code(flag):
    '''
    Does flag denote start of an instruction.
    :param flag: Flag for an instruction.
    :type flag: int

    :return: True if flags indicate code, False otherwise.
    '''
    fn = _get_fn_by_version(ida_bytes, 'is_code', 'isCode', idaapi)
    return fn(flag)


def get_full_flags(ea):
    '''
    Get flags value for address 'ea'

    :param ea: Linear address.
    :type ea: int

    :return: 0 if flags not present in the program
    '''
    fn = _get_fn_by_version(ida_bytes, 'get_full_flags', 'getFlags', idaapi)
    return fn(ea)


def get_name(ea):
    '''
    Get name at the specified address.

    :param ea: Linear address
    :type ea: int

    :return: "" - byte has no name.
    '''
    fn = _get_fn_by_version(idc, 'get_name', 'Name')

    if idaapi.IDA_SDK_VERSION > 700:
        return fn(ea, ida_name.GN_VISIBLE)
    return fn(ea)


def get_func_off_str(ea):
    '''
    Convert address to 'funcname+offset' string.

    :param ea: Address to convert.
    :type ea: int

    :return: If the address belongs to a function then return a string formed as
    'name+offset' where 'name' is a function name, 'offset' is offset within
    the function else return null string.
    '''
    fn = _get_fn_by_version(idc, 'get_func_off_str', 'GetFuncOffset')
    return fn(ea)


def jumpto(ea, opnum=-1, uijmp_flags=0x0001):
    '''
    Jump to the specified address.

    :param ea: Destination
    :type ea: int

    :param opnum: -1: don't change the x coord.
    :type opnum: int

    :param uijmp_flags: Jump flags.
    :type uijmp_flags: int

    :return: success
    '''
    fn = _get_fn_by_version(ida_kernwin, 'jumpto', 'Jump', idc)
    if idaapi.IDA_SDK_VERSION >= 700:
        return fn(ea, opnum, uijmp_flags)
    return fn(ea)


def ask_yn(default, format_str):
    '''
    Display a dialog box and get choice from "Yes", "No", "Cancel".

    :param default: Default choice: one of Button IDs
    :type default: int

    :param format_str: The question in printf() style format.
    :type format_str: str

    :return: The selected button (one of Button IDs).
    '''
    fn = _get_fn_by_version(ida_kernwin, 'ask_yn', 'AskYN', idc)
    return fn(default, format_str)


def ask_file(for_saving, default, dialog):
    '''
    Get file from user.

    :param for_saving: File is for saving.
    :type for_saving: int

    :param default: File extension.
    :type default: str

    :param dialog: Dialog box to display to the user.
    :type dialog: str

    :return: file path.
    '''
    fn = _get_fn_by_version(ida_kernwin, 'ask_file', 'AskFile', idc)
    return fn(for_saving, default, dialog)


def get_func_attr(ea, attr):
    '''
    Get a function attribute.

    :param ea: Any address belonging to the function.
    :type ea: int

    :param attr: One of FUNCATTR_... constants

    :return: BADADDR - error otherwise returns the attribute value.
    '''
    fn = _get_fn_by_version(idc, 'get_func_attr', 'GetFunctionAttr')
    return fn(ea, attr)


def get_name_ea_simple(name):
    '''
    Get linear address of a name.

    :param name: Name of program byte.
    :type name: str

    :return: Address of the name or BADADDR - No such name.
    '''
    fn = _get_fn_by_version(idc, 'get_name_ea_simple', 'LocByName')
    return fn(name)


def next_head(ea, maxea=4294967295):
    '''
    Get next defined item (instruction or data) in the program.

    :param ea: Linear address to start search from.
    :type ea: int

    :param maxea: The search will stop at the address maxea. maxea is not
                  included in the search range
    :type maxea: int

    :return: BADADDR - no (more) defined items
    '''
    fn = _get_fn_by_version(idc, 'next_head', 'NextHead')
    return fn(ea, maxea)


def get_screen_ea():
    '''
    Return the linear address of the current screen location.

    :return: Address of screen focus.
    '''
    fn = _get_fn_by_version(idc, 'get_screen_ea', 'ScreenEA')
    return fn()


def choose_func(title):
    '''
    Ask the user to select a function.

    :param title: Title of the dialog box.
    :type title: str

    :return: -1 user refused to select a function, otherwise function start addr
    '''
    fn = _get_fn_by_version(idc, 'choose_func', 'ChooseFunction')
    return fn(title)


def ask_ident(default, prompt):
    '''
    Ask for a long text.
    :param default: The default value.
    :type default: str

    :param prompt: The prompt value.
    :type prompt: str

    :return: None or the entered string.
    '''
    fn = _get_fn_by_version(ida_kernwin, 'ask_str', 'AskIdent', idc)
    if idaapi.IDA_SDK_VERSION >= 700:
        return fn(default, ida_kernwin.HIST_IDENT, prompt)
    return fn(default, prompt)


def set_name(ea, name):
    '''
    Rename an address.

    :param ea: Linear address.
    :type ea: int

    :param name: New name of address. If name == "" then delete old name.
    :type name: str

    :return: 1-ok, 0-failure
    '''
    fn = _get_fn_by_version(idc, 'set_name', 'MakeName')
    if idaapi.IDA_SDK_VERSION >= 700:
        return fn(ea, name, ida_name.SN_CHECK)
    return fn(ea, name)


def get_wide_dword(ea):
    '''
    Get one wide word of the program at 'ea'
    :param ea: linear address.
    :type ea: int

    :return: uint64
    '''
    fn = _get_fn_by_version(idc, 'get_wide_dword', 'Dword')
    return fn(ea)


def get_strlit_contents(ea):
    '''
    Get string contents.

    :param ea: Linear address.
    :type ea: int

    :return: String contents or empty string.
    '''
    fn = _get_fn_by_version(idc, 'get_strlit_contents', 'GetString')
    return fn(ea)


def get_func_name(ea):
    '''
    Retrieve function name.

    :param ea: Any address belonging to the function.
    :type ea: int

    :return: Null string if not found, otherwise the functions name.
    '''
    fn = _get_fn_by_version(idc, 'get_func_name', 'GetFunctionName')
    return fn(ea)


def get_first_seg():
    '''
    Get first segment.

    :return: Address of the start of the first segment or BADADDR if no
    segments found.
    '''
    fn = _get_fn_by_version(idc, 'get_first_seg', 'FirstSeg')
    return fn()


def get_segm_attr(segea, attr):
    '''
    Get segment attribute.

    :param segea: Any address within the segment.
    :type segea: int

    :param attr: One of SEGATTR_... constants.
    :type attr: int

    :return: Segment attributes.
    '''
    fn = _get_fn_by_version(idc, 'get_segm_attr', 'GetSegmentAttr')
    return fn(segea, attr)


def get_next_seg(ea):
    '''
    Get next segment.

    :param ea: Linear address.
    :type ea: int

    :return: Start of the next segment or BADADDR
    '''
    fn = _get_fn_by_version(idc, 'get_next_seg', 'NextSeg')
    return fn(ea)


def is_strlit(flags):
    '''
    Do flags indicate a string.

    :param flags: Flags for address.
    :type flags: int

    :return: bool
    '''
    fn = _get_fn_by_version(ida_bytes, 'is_strlit', 'isASCII', idc)
    return fn(flags)


def create_strlit(start, lenth):
    '''
    Convert to string literal and give a meaningful name.

    :param start: Start ea.
    :type start: int

    :param lenth: Length of string, or 0 to determine dynamically.
    :type lenth: int

    :return: bool
    '''
    fn = _get_fn_by_version(ida_bytes, 'create_strlit', 'MakeStr', idc)
    if idaapi.IDA_SDK_VERSION >= 700:
        return fn(start, lenth, ida_nalt.STRTYPE_C)
    return fn(start, idc.BADADDR)


def is_unknown(flags):
    '''
    Do flags indicate an unknown type.

    :param flags: Flags for address.
    :type flags: int

    :return: bool
    '''
    fn = _get_fn_by_version(ida_bytes, 'is_unknown', 'isUnknown', idc)
    return fn(flags)


def is_byte(flags):
    '''
    Do flags indicate a byte type.

    :param flags: Flags for address.
    :type flags: int

    :return: bool
    '''
    fn = _get_fn_by_version(ida_bytes, 'is_byte', 'isByte', idc)
    return fn(flags)


def create_dword(ea):
    '''
    Convert to data.

    :param ea: Linear address .
    :type ea: int

    :return: bool
    '''
    fn = _get_fn_by_version(ida_bytes, 'create_data', 'MakeDword', idc)
    if idaapi.IDA_SDK_VERSION >= 700:
        return fn(ea, ida_bytes.FF_DWORD, 4, idaapi.BADADDR)
    return fn(ea)


def op_plain_offset(ea, n, base):
    '''
    Convert operand to an offset.

    :param ea: Linear address.
    :type ea: int

    :param n: Number of operands.
    :type n: int

    :param base: Base of the offset.
    :type base: int

    :return:
    '''
    fn = _get_fn_by_version(idc, 'op_plain_offset', 'OpOff')
    return fn(ea, n, base)


def next_addr(ea):
    '''
    Get next address in the program.

    :param ea: Linear address.
    :type ea: int

    :return: Next address or BADADDR
    '''
    fn = _get_fn_by_version(ida_bytes, 'next_addr', 'NextAddr', idc)
    return fn(ea)


def can_decode(ea):
    '''
    Can the bytes at ea be decoded as an instruction?

    :param ea: Linear address
    :type ea: int

    :return: bool
    '''
    fn = _get_fn_by_version(ida_ua, 'can_decode', 'decode_insn', idaapi)
    return fn(ea)


def get_operands(insn):
    '''
    Get operands for the current address.

    :return:
    '''
    if idaapi.IDA_SDK_VERSION >= 700:
        return insn.ops
    return idaapi.cmd.Operands


def get_canon_feature(insn):
    '''
    Get operands for the provided instruction.

    :return:
    '''
    if idaapi.IDA_SDK_VERSION >= 700:
        return insn.get_canon_feature()
    return idaapi.cmd.get_canon_feature()


def get_segm_name(ea):
    '''
    Get name of a segment.

    :param ea: Any address within the segment.
    :type ea: int

    :return: Segement name.
    '''
    fn = _get_fn_by_version(idc, 'get_segm_name', 'SegName')
    return fn(ea)


def add_func(ea):
    '''
    Add a new function.

    :param ea: Start address.
    :type ea: int

    :return: bool
    '''
    fn = _get_fn_by_version(ida_funcs, 'add_func', 'MakeFunction', idc)
    return fn(ea)


def create_insn(ea):
    '''
    Create instruction.

    :param ea: Linear address
    :type ea: int

    :return: bool
    '''
    fn = _get_fn_by_version(idc, 'create_insn', 'MakeCode')
    return fn(ea)


def get_segm_end(ea):
    '''
    Get end address of a segment.

    :param ea: Linear address
    :type ea: int

    :return: Address
    '''
    fn = _get_fn_by_version(idc, 'get_segm_end', 'SegEnd')
    return fn(ea)


def get_segm_start(ea):
    '''
    Get start address of a segment.

    :param ea: Linear address
    :type ea: int

    :return: Address
    '''
    fn = _get_fn_by_version(idc, 'get_segm_start', 'SegStart')
    return fn(ea)


def decode_insn(ea):
    """
    Decode instruction.
    :param ea: Linear address.
    :type ea: int

    :return: Instruction at ea.
    """
    fn = _get_fn_by_version(ida_ua, 'decode_insn', 'decode_insn', idaapi)
    if idaapi.IDA_SDK_VERSION >= 700:
        insn = ida_ua.insn_t()
        fn(insn, ea)
        return insn
    fn(ea)
    return idaapi.cmd


def get_bookmark(index):
    """
    Get bookmark

    :param index: Index of bookmark
    :type index: int

    :return: Address of bookmark
    """
    fn = _get_fn_by_version(idc, 'get_bookmark', 'GetMarkedPos')
    return fn(index)


def get_bookmark_desc(index):
    """
    Get bookmark description.

    :param index: Index of bookmark
    :type index: int

    :return:
    """
    fn = _get_fn_by_version(idc, 'get_bookmark_desc', 'GetMarkComment')
    return fn(index)


def set_color(ea, what, color):
    """
    Set item color.

    :param ea: Linear address.
    :type ea: int

    :param what: Type of the item, one of CIC_... contstants
    :type what: int

    :param color: New color code in RGB.
    :type color: int

    :return: bool
    """
    fn = _get_fn_by_version(idc, 'set_color', 'SetColor')
    return fn(ea, what, color)


def msg(message):
    """
    Display a UTF-8 string in the message window.

    :param message: Message to print.
    :type message: str

    :return: PyObject * (what?)
    """
    fn = _get_fn_by_version(ida_kernwin, 'msg', 'Message', idc)
    return fn(message)


def get_highlighted_identifier():
    """
    Get currently highlighted text.

    :return: Highlighted text or ""
    """
    fn = _get_fn_by_version(ida_kernwin, 'get_highlight',
                            'get_highlighted_identifier', idaapi)

    if idaapi.IDA_SDK_VERSION >= 700:
        viewer = ida_kernwin.get_current_viewer()
        highlight = fn(viewer)
        if highlight and highlight[1]:
            return highlight[0]
    return fn()


def start_ea(obj):
    """
    Return start ea for supplied object.

    :param obj: Object to retrieve start ea.

    :return: start ea.
    """
    if not obj:
        return None

    try:
        return obj.startEA
    except AttributeError:
        return obj.start_ea


def end_ea(obj):
    """
    Return end ea for supplied object.

    :param obj: Object to retrieve end ea.

    :return: end ea.
    """
    if not obj:
        return None

    try:
        return obj.endEA
    except AttributeError:
        return obj.end_ea


def set_func_flags(ea, flags):
    """
    Change function flags.

    :param ea: Any address belonging to the function.
    :type ea: int

    :param flags: Flags to set.
    :type flags: int

    :return: 0 - ok
    """
    fn = _get_fn_by_version(idc, 'set_func_attr', 'SetFunctionFlags')
    if idaapi.IDA_SDK_VERSION >= 700:
        return fn(ea, idc.FUNCATTR_FLAGS, flags)
    return fn(ea, flags)


def get_func_flags(ea):
    """
    Get function flags.

    :param ea: Any address belonging to the function.
    :type ea: int

    :return: Flags
    """
    fn = _get_fn_by_version(idc, 'get_func_attr', 'GetFunctionFlags')
    if idaapi.IDA_SDK_VERSION >= 700:
        return fn(ea, idc.FUNCATTR_FLAGS)
    return fn(ea)
