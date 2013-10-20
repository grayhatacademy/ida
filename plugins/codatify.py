# IDA plugin that converts all data in data segments to defined data types, and all data in code segments to code.
#
# Use by going to Options->Define data and code, or use the Alt+3 hotkey.
#
# Craig Heffner
# Tactical Network Solutions

import idc
import idaapi
import idautils

class Codatify(object):

	CODE = 2
	DATA = 3
	SEARCH_DEPTH = 25

	def __init__(self):
		pass

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

	# Creates ASCII strings and converts remaining data into DWORDS.
	def datify(self):
		n = 0
		ea = self.get_start_ea(self.DATA)

		print "\nLooking for possible strings starting at: %s:0x%X" % (idc.SegName(ea), ea)

		for s in idautils.Strings():
			if s.ea > ea:
				if not idc.isASCII(idc.GetFlags(s.ea)) and idc.MakeStr(s.ea, idc.BADADDR):
					n += 1

		print "Created %d new ASCII strings" % n
	
		print "Converting remaining data to DWORDs...",
	
		while ea != idc.BADADDR:
			flags = idc.GetFlags(ea)
		            
			if idc.isUnknown(flags) or idc.isByte(flags):
				idc.MakeDword(ea)
				idc.OpOff(ea, 0, 0)

			ea = idc.NextAddr(ea)

		print "done.\n"

	def codeify(self, ea=idc.BADADDR, force=False):
		func_count = 0
		code_count = 0

		if ea == idc.BADADDR:
			ea = self.get_start_ea(self.CODE)

		if not force and self.get_start_ea(self.DATA) == idc.BADADDR:
			print "WARNING: No data segments defined! I don't know where the code segment ends and the data segment begins."
	
		print "\nLooking for undefined code starting at: 0x%X...\n" % ea

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
    
		print "\nCreated %d new functions and %d new code blocks\n" % (func_count, code_count)



class codatify_t(idaapi.plugin_t):
	flags = 0
	comment = ""
	help = ""
	wanted_name = "Define all data and code"
	wanted_hotkey = ""

	def init(self):
		self.menu_context = idaapi.add_menu_item("Options/", "Fixup code/data", "Alt-3", 0, self.fix_code_data, (None,))
		return idaapi.PLUGIN_KEEP

	def term(self):
		idaapi.del_menu_item(self.menu_context)
		return None

	def run(self, arg):
		pass

	def fix_code_data(self, arg):
		cd = Codatify()
		cd.datify()
		cd.codeify()

def PLUGIN_ENTRY():
	return codatify_t()

