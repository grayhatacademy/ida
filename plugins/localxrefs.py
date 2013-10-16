# IDA Plugin to search for cross references only within the current defined function.
#
# Useful, for example, to find instructions that use a particular register, or that reference a literal value.
#
# Invoke by highlighting the desired text in IDA, then going to Jump->List local xrefs, or by pressing Alt+8.
#
# Craig Heffner
# Tactical Network Solutions

import idc
import idaapi

class LocalXrefs(object):

	UP   = 'Up  '
	DOWN = 'Down'
	THIS = '-   '

	READ    = 'r'
	WRITE   = 'w'

	OPND_WRITE_FLAGS = {
			0	: idaapi.CF_CHG1,
			1	: idaapi.CF_CHG2,
			2	: idaapi.CF_CHG3,
			3	: idaapi.CF_CHG4,
			4	: idaapi.CF_CHG5,
			5	: idaapi.CF_CHG6,
	}

	def __init__(self):
		self.xrefs = {}
		self.function = ''
		self._profile_function()

	def _profile_function(self):
		current_ea = ScreenEA()
		current_function = idc.GetFunctionName(current_ea)
		current_function_ea = idc.LocByName(current_function)

		if current_function:
			self.function = current_function

		ea = start_ea = idc.GetFunctionAttr(current_function_ea,  idc.FUNCATTR_START)
		end_ea = idc.GetFunctionAttr(current_function_ea, idc.FUNCATTR_END)

		self.highlighted = idaapi.get_highlighted_identifier()

		while ea < end_ea and ea != idc.BADADDR and self.highlighted:

			i = 0
			match = False
			optype = self.READ
			comment = None

			idaapi.decode_insn(ea)
			
			mnem = idc.GetMnem(ea)

			if self.highlighted in mnem:
				match = True
			elif idaapi.is_call_insn(ea):
				for xref in idautils.XrefsFrom(ea):
					if xref.type != 21:
						name = idc.Name(xref.to)
						if name and self.highlighted in name:
							match = True
							break
			else:	
				while True:
					opnd = idc.GetOpnd(ea, i)
					if opnd:
						if self.highlighted in opnd:
							match = True
							if (idaapi.insn_t_get_canon_feature(idaapi.cmd.itype) & self.OPND_WRITE_FLAGS[i]):
								optype = self.WRITE
						i += 1
					else:
						break

			if not match:
				comment = idc.GetCommentEx(ea, 0)
				if comment and self.highlighted in comment:
					match = True
				else:
					comment = idc.GetCommentEx(ea, 1)
					if comment and self.highlighted in comment:
						match = True
					else:
						comment = None

			if match:
				if ea > current_ea:
					direction = self.DOWN
				elif ea < current_ea:
					direction = self.UP
				else:
					direction = self.THIS

				self.xrefs[ea] = {
					'offset' 	: idc.GetFuncOffset(ea),
					'mnem'	 	: mnem,
					'type'		: optype,
					'direction'	: direction,
					'text'		: idc.GetDisasm(ea),
				}

			ea += idaapi.cmd.size
	
class localizedxrefs_t(idaapi.plugin_t):
	flags = 0
	comment = "IDA Localized Xrefs"
	help = ""
	wanted_name = "Localized Xrefs"
	wanted_hotkey = ""

	DELIM = '-' * 86
	HEADER = '\nXrefs to %s from %s:'

	def init(self):
		self.menu_context = idaapi.add_menu_item("Jump/", "List local xrefs", "Alt-8", 0, self.run, (None,))
		return idaapi.PLUGIN_KEEP

	def term(self):
		idaapi.del_menu_item(self.menu_context)
		return None

	def run(self, arg):
		fmt = ''

		r = LocalXrefs()
		offsets = r.xrefs.keys()
		offsets.sort()

		if r.highlighted:
			print self.HEADER % (r.highlighted, r.function)
			print self.DELIM
			
			for ea in offsets:
				info = r.xrefs[ea]
	
				if not fmt:
					fmt = "%%s   %%s   %%-%ds   %%s" % (len(info['offset']) + 15)

				print fmt % (info['direction'], info['type'], info['offset'], info['text'])
	
			print self.DELIM

def PLUGIN_ENTRY():
	return localizedxrefs_t()

