##########################################################################
# An IDAPython plugin that generates "fuzzy" function signatures that can
# be shared and applied amongst different IDBs.
#
# There are multiple sets of signatures that are generated:
#
#   o "Formal" signatures, where functions must match exactly
#   o "Fuzzy" signatures, where functions must only resemble each other
#     in terms of data/call references.
#   o String-based signatures, where functions are identified based on
#     unique string references.
#   o Immediate-based signatures, where functions are identified based
#     on immediate value references.
#
# These signatures are applied based on accuracy, that is, formal
# signatures are applied first, then string and immediate based
# signatures, and finally fuzzy signatures.
#
# Further, functions are identified based on call references. Consider,
# for example, two functions, one named 'foo', the other named 'bar'.
# The 'foo' function is fairly unique and a reliable signature is easily
# generated for it, but the 'bar' function is more difficult to reliably
# identify. However, 'foo' calls 'bar', and thus once 'foo' is identified,
# 'bar' can also be identified by association.
#
# Craig Heffner
# @devttys0
##########################################################################
import idc
import idaapi
import idautils

import os
import sys
import time
import pickle       # http://natashenka.ca/pickle/
import tempfile
import collections

class RizzoSignatures(object):
    '''
    Simple wrapper class for storing signature info.
    '''

    SHOW = []

    def __init__(self):
        self.fuzzy = {}
        self.formal = {}
        self.strings = {}
        self.functions = {}
        self.immediates = {}

        self.fuzzydups = set()
        self.formaldups = set()
        self.stringdups = set()
        self.immediatedups = set()

    def show(self):
        if not self.SHOW:
            return

        print "\n\nGENERATED FORMAL SIGNATURES FOR:"
        for (key, ea) in self.formal.iteritems():
            func = RizzoFunctionDescriptor(self.formal, self.functions, key)
            if func.name in self.SHOW:
                print func.name

        print "\n\nGENERATRED FUZZY SIGNATURES FOR:"
        for (key, ea) in self.fuzzy.iteritems():
            func = RizzoFunctionDescriptor(self.fuzzy, self.functions, key)
            if func.name in self.SHOW:
                print func.name

class RizzoStringDescriptor(object):
    '''
    Wrapper class for easily accessing necessary string information.
    '''

    def __init__(self, string):
        self.ea = string.ea
        self.value = str(string)
        self.xrefs = [x.frm for x in idautils.XrefsTo(self.ea)]

class RizzoBlockDescriptor(object):
    '''
    Code block info is stored in tuples, which minimize pickle storage space.
    This class provides more Pythonic (and sane) access to values of interest for a given block.
    '''

    def __init__(self, block):
        self.formal = block[0]
        self.fuzzy = block[1]
        self.immediates = block[2]
        self.functions = block[3]

    def match(self, nblock, fuzzy=False):
        # TODO: Fuzzy matching at the block level gets close, but produces a higher number of
        #       false positives; for example, it confuses hmac_md5 with hmac_sha1.
        #return ((self.formal == nblock.formal or (fuzzy and self.fuzzy == nblock.fuzzy)) and
        return (self.formal == nblock.formal and
                len(self.immediates) == len(nblock.immediates) and
                len(self.functions) == len(nblock.functions))

class RizzoFunctionDescriptor(object):
    '''
    Function signature info is stored in dicts and tuples, which minimize pickle storage space.
    This class provides more Pythonic (and sane) access to values of interest for a given function.
    '''

    def __init__(self, signatures, functions, key):
        self.ea = signatures[key]
        self.name = functions[self.ea][0]
        self.blocks = functions[self.ea][1]

class Rizzo(object):
    '''
    Workhorse class which performs the primary logic and functionality.
    '''

    DEFAULT_SIGNATURE_FILE = "rizzo.sig"

    def __init__(self, sigfile=None):
        if sigfile:
            self.sigfile = sigfile
        else:
            self.sigfile = os.path.join(tempfile.gettempdir(), self.DEFAULT_SIGNATURE_FILE)

        # Useful for quickly identifying string xrefs from individual instructions
        self.strings = {}
        for string in idautils.Strings():
            self.strings[string.ea] = RizzoStringDescriptor(string)

        start = time.time()
        self.signatures = self.generate()
        end = time.time()

        print "Generated %d formal signatures and %d fuzzy signatures for %d functions in %.2f seconds." % (len(self.signatures.formal), len(self.signatures.fuzzy), len(self.signatures.functions), (end-start))

    def save(self):
        print ("Saving signatures to %s..." % self.sigfile),
        fp = open(self.sigfile, "wb")
        pickle.dump(self.signatures, fp)
        fp.close()
        print "done."

    def load(self):
        print ("Loading signatures from %s..." % self.sigfile),
        fp = open(self.sigfile, "rb")
        sigs = pickle.load(fp)
        fp.close()
        print "done."
        return sigs

    def sighash(self, value):
        return hash(str(value)) & 0xFFFFFFFF

    def block(self, block):
        '''
        Returns a tuple: ([formal, block, signatures], [fuzzy, block, signatures], set([unique, immediate, values]), [called, function, names])
        '''
        formal = []
        fuzzy = []
        functions = []
        immediates = []

        ea = block.startEA
        while ea < block.endEA:
            idaapi.decode_insn(ea)

            # Get a list of all data/code references from the current instruction
            drefs = [x for x in idautils.DataRefsFrom(ea)]
            crefs = [x for x in idautils.CodeRefsFrom(ea, False)]

            # Add all instruction mnemonics to the formal block hash
            formal.append(idc.GetMnem(ea))

            # If this is a call instruction, be sure to note the name of the function
            # being called. This is used to apply call-based signatures to functions.
            #
            # For fuzzy signatures, we can't use the actual name or EA of the function,
            # but rather just want to note that a function call was made.
            #
            # Formal signatures already have the call instruction mnemonic, which is more
            # specific than just saying that a call was made.
            if idaapi.is_call_insn(ea):
                for cref in crefs:
                    func_name = idc.Name(cref)
                    if func_name:
                        functions.append(func_name)
                        fuzzy.append("funcref")
            # If there are data references from the instruction, check to see if any of them
            # are strings. These are looked up in the pre-generated strings dictionary.
            #
            # String values are easily identifiable, and are used as part of both the fuzzy
            # and the formal signatures.
            #
            # It is more difficult to determine if non-string values are constants or not;
            # for both fuzzy and formal signatures, just use "data" to indicate that some data
            # was referenced.
            elif drefs:
                for dref in drefs:
                    if self.strings.has_key(dref):
                        formal.append(self.strings[dref].value)
                        fuzzy.append(self.strings[dref].value)
                    else:
                        formal.append("dataref")
                        fuzzy.append("dataref")
            # If there are no data or code references from the instruction, use every operand as
            # part of the formal signature.
            #
            # Fuzzy signatures are only concerned with interesting immediate values, that is, values
            # that are greater than 65,535, are not memory addresses, and are not displayed as
            # negative values.
            elif not drefs and not crefs:
                for n in range(0, len(idaapi.cmd.Operands)):
                    opnd_text = idc.GetOpnd(ea, n)
                    formal.append(opnd_text)
                    if idaapi.cmd.Operands[n].type == idaapi.o_imm and not opnd_text.startswith('-'):
                        if idaapi.cmd.Operands[n].value >= 0xFFFF:
                            if idaapi.getFlags(idaapi.cmd.Operands[n].value) == 0:
                                fuzzy.append(str(idaapi.cmd.Operands[n].value))
                                immediates.append(idaapi.cmd.Operands[n].value)

            ea = idc.NextHead(ea)

        return (self.sighash(''.join(formal)), self.sighash(''.join(fuzzy)), immediates, functions)

    def function(self, func):
        '''
        Returns a list of blocks.
        '''
        blocks = []

        for block in idaapi.FlowChart(func):
            blocks.append(self.block(block))

        return blocks

    def generate(self):
        signatures = RizzoSignatures()

        # Generate unique string-based function signatures
        for (ea, string) in self.strings.iteritems():
            # Only generate signatures on reasonably long strings with one xref
            if len(string.value) >= 8 and len(string.xrefs) == 1:
                func = idaapi.get_func(string.xrefs[0])
                if func:
                    strhash = self.sighash(string.value)

                    # Check for and remove string duplicate signatures (the same
                    # string can appear more than once in an IDB).
                    # If no duplicates, add this to the string signature dict.
                    if signatures.strings.has_key(strhash):
                        del signatures.strings[strhash]
                        signatures.stringdups.add(strhash)
                    elif strhash not in signatures.stringdups:
                        signatures.strings[strhash] = func.startEA

        # Generate formal, fuzzy, and immediate-based function signatures
        for ea in idautils.Functions():
            func = idaapi.get_func(ea)
            if func:
                # Generate a signature for each block in this function
                blocks = self.function(func)

                # Build function-wide formal and fuzzy signatures by simply
                # concatenating the individual function block signatures.
                formal = self.sighash(''.join([str(e) for (e, f, i, c) in blocks]))
                fuzzy = self.sighash(''.join([str(f) for (e, f, i, c) in blocks]))

                # Add this signature to the function dictionary.
                signatures.functions[func.startEA] = (idc.Name(func.startEA), blocks)

                # Check for and remove formal duplicate signatures.
                # If no duplicates, add this to the formal signature dict.
                if signatures.formal.has_key(formal):
                    del signatures.formal[formal]
                    signatures.formaldups.add(formal)
                elif formal not in signatures.formaldups:
                    signatures.formal[formal] = func.startEA

                # Check for and remove fuzzy duplicate signatures.
                # If no duplicates, add this to the fuzzy signature dict.
                if signatures.fuzzy.has_key(fuzzy):
                    del signatures.fuzzy[fuzzy]
                    signatures.fuzzydups.add(fuzzy)
                elif fuzzy not in signatures.fuzzydups:
                    signatures.fuzzy[fuzzy] = func.startEA

                # Check for and remove immediate duplicate signatures.
                # If no duplicates, add this to the immediate signature dict.
                for (e, f, immediates, c) in blocks:
                    for immediate in immediates:
                        if signatures.immediates.has_key(immediate):
                            del signatures.immediates[immediate]
                            signatures.immediatedups.add(immediate)
                        elif immediate not in signatures.immediatedups:
                            signatures.immediates[immediate] = func.startEA

        # These need not be maintained across function calls,
        # and only add to the size of the saved signature file.
        signatures.fuzzydups = set()
        signatures.formaldups = set()
        signatures.stringdups = set()
        signatures.immediatedups = set()

        # DEBUG
        signatures.show()

        return signatures

    def match(self, extsigs):
        fuzzy = {}
        formal = {}
        strings = {}
        immediates = {}

        # Match formal function signatures
        start = time.time()
        for (extsig, ext_func_ea) in extsigs.formal.iteritems():
            if self.signatures.formal.has_key(extsig):
                newfunc = RizzoFunctionDescriptor(extsigs.formal, extsigs.functions, extsig)
                curfunc = RizzoFunctionDescriptor(self.signatures.formal, self.signatures.functions, extsig)
                formal[curfunc] = newfunc
        end = time.time()
        print "Found %d formal matches in %.2f seconds." % (len(formal), (end-start))

        # Match fuzzy function signatures
        start = time.time()
        for (extsig, ext_func_ea) in extsigs.fuzzy.iteritems():
            if self.signatures.fuzzy.has_key(extsig):
                curfunc = RizzoFunctionDescriptor(self.signatures.fuzzy, self.signatures.functions, extsig)
                newfunc = RizzoFunctionDescriptor(extsigs.fuzzy, extsigs.functions, extsig)
                # Only accept this as a valid match if the functions have the same number of basic code blocks
                if len(curfunc.blocks) == len(newfunc.blocks):
                    fuzzy[curfunc] = newfunc
        end = time.time()
        print "Found %d fuzzy matches in %.2f seconds." % (len(fuzzy), (end-start))

        # Match string based function signatures
        start = time.time()
        for (extsig, ext_func_ea) in extsigs.strings.iteritems():
            if self.signatures.strings.has_key(extsig):
                curfunc = RizzoFunctionDescriptor(self.signatures.strings, self.signatures.functions, extsig)
                newfunc = RizzoFunctionDescriptor(extsigs.strings, extsigs.functions, extsig)
                strings[curfunc] = newfunc
        end = time.time()
        print "Found %d string matches in %.2f seconds." % (len(strings), (end-start))

        # Match immediate baesd function signatures
        start = time.time()
        for (extsig, ext_func_ea) in extsigs.immediates.iteritems():
            if self.signatures.immediates.has_key(extsig):
                curfunc = RizzoFunctionDescriptor(self.signatures.immediates, self.signatures.functions, extsig)
                newfunc = RizzoFunctionDescriptor(extsigs.immediates, extsigs.functions, extsig)
                immediates[curfunc] = newfunc
        end = time.time()
        print "Found %d immediate matches in %.2f seconds." % (len(immediates), (end-start))

        # Return signature matches in the order we want them applied
        # The second tuple of each match is set to True if it is a fuzzy match, e.g.:
        #
        #   ((match, fuzzy), (match, fuzzy), ...)
        return ((formal, False), (strings, False), (immediates, False), (fuzzy, True))

    def rename(self, ea, name):
        # Don't rely on the name in curfunc, as it could have already been renamed
        curname = idc.Name(ea)
        # Don't rename if the name is a special identifier, or if the ea has already been named
        # TODO: What's a better way to check for reserved name prefixes?
        if curname.startswith('sub_') and name.split('_')[0] not in set(['sub', 'loc', 'unk', 'dword', 'word', 'byte']):
            # Don't rename if the name already exists in the IDB
            if idc.LocByName(name) == idc.BADADDR:
                if idc.MakeName(ea, name):
                    idc.SetFunctionFlags(ea, (idc.GetFunctionFlags(ea) | idc.FUNC_LIB))
                    #print "%s  =>  %s" % (curname, name)
                    return 1
            #else:
            #    print "WARNING: Attempted to rename '%s' => '%s', but '%s' already exists!" % (curname, name, name)
        return 0

    def apply(self, extsigs):
        count = 0

        start = time.time()

        # This applies formal matches first, then fuzzy matches
        for (match, fuzzy) in self.match(extsigs):
            # Keeps track of all function names that we've identified candidate functions for
            rename = {}

            for (curfunc, newfunc) in match.iteritems():
                if not rename.has_key(newfunc.name):
                    rename[newfunc.name] = []

                # Attempt to rename this function
                rename[newfunc.name].append(curfunc.ea)

                bm = {}
                duplicates = set()

                # Search for unique matching code blocks inside this function
                for nblock in newfunc.blocks:
                    nblock = RizzoBlockDescriptor(nblock)
                    for cblock in curfunc.blocks:
                        cblock = RizzoBlockDescriptor(cblock)

                        if cblock.match(nblock, fuzzy):
                            if bm.has_key(cblock):
                                del bm[cblock]
                                duplicates.add(cblock)
                            elif cblock not in duplicates:
                                bm[cblock] = nblock

                # Rename known function calls from each unique identified code block
                for (cblock, nblock) in bm.iteritems():
                    for n in range(0, len(cblock.functions)):
                        ea = idc.LocByName(cblock.functions[n])
                        if ea != idc.BADADDR:
                            if rename.has_key(nblock.functions[n]):
                                rename[nblock.functions[n]].append(ea)
                            else:
                                rename[nblock.functions[n]] = [ea]

                # Rename the identified functions
                for (name, candidates) in rename.iteritems():
                    if candidates:
                        winner = collections.Counter(candidates).most_common(1)[0][0]
                        count += self.rename(winner, name)

        end = time.time()
        print "Renamed %d functions in %.2f seconds." % (count, (end-start))

def RizzoBuild(sigfile=None):
    print "Building Rizzo signatures, this may take a few minutes..."
    start = time.time()
    r = Rizzo(sigfile)
    r.save()
    end = time.time()
    print "Built signatures in %.2f seconds" % (end-start)

def RizzoApply(sigfile=None):
    print "Applying Rizzo signatures, this may take a few minutes..."
    start = time.time()
    r = Rizzo(sigfile)
    s = r.load()
    r.apply(s)
    end = time.time()
    print "Signatures applied in %.2f seconds" % (end-start)




class RizzoPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Function signature"
    help = ""
    wanted_name = "Rizzo"
    wanted_hotkey = ""

    NAME = "rizzo.py"

    def init(self):
        self.menu_context_load = idaapi.add_menu_item("File/Load file/", "Rizzo signature file...", "", 0, self.rizzo_load, (None,))
        self.menu_context_produce = idaapi.add_menu_item("File/Produce file/", "Rizzo signature file...", "", 0, self.rizzo_produce, (True,))
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.del_menu_item(self.menu_context_load)
        idaapi.del_menu_item(self.menu_context_produce)
        return None

    def run(self, arg):
        return None

    def rizzo_script(self):
        idaapi.IDAPython_ExecScript(self.script, globals())

    def rizzo_produce(self, arg):
        fname = idc.AskFile(1, "*.riz", "Save signature file as")
        if fname:
            if '.' not in fname:
                fname += ".riz"
            RizzoBuild(fname)
        return None

    def rizzo_load(self, arg):
        fname = idc.AskFile(0, "*.riz", "Load signature file")
        if fname:
            RizzoApply(fname)
        return None

def PLUGIN_ENTRY():
    return RizzoPlugin()
