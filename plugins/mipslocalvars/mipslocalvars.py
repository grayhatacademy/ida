# IDA plugin to name stack variables that are simply used to store register values until a function returns ($ra, $s0-$s7, $fp, $gp).
#
# Invoke by going to Options->Name saved registers.
#
# Craig Heffner
# Tactical Network Solutions

import idc
import idaapi
import idautils

class NameMIPSSavedRegisters(object):

	INSIZE = 4
	SEARCH_DEPTH = 25

	ARCH = {
			'arguments'	: ['$a0', '$a1', '$a2', '$a3'],
			'savedregs'	: ['$s0', '$s1', '$s2', '$s3', '$s4', '$s5', '$s6', '$s7', '$fp', '$gp', '$ra'],
	}

	def __init__(self):
		print "Naming saved register locations...",

		for ea in idautils.Functions():
			mea = ea
			named_regs = []
			last_iteration = False

			while mea < (ea + (self.INSIZE * self.SEARCH_DEPTH)):
				mnem = idc.GetMnem(mea)

				if mnem in ['sw', 'sd']:
					reg = idc.GetOpnd(mea, 0)
					dst = idc.GetOpnd(mea, 1)

					if reg in self.ARCH['savedregs'] and reg not in named_regs and dst.endswith('($sp)') and 'var_' in dst:
						offset = int(dst.split('var_')[1].split('(')[0], 16)
						idc.MakeLocal(ea, idc.FindFuncEnd(ea), "[sp-%d]" % offset, "saved_%s" % reg[1:])
						named_regs.append(reg)

				if last_iteration:
					break
				elif mnem.startswith('j') or mnem.startswith('b'):
					last_iteration = True

				mea += self.INSIZE

		print "done."


class mips_saved_registers_t(idaapi.plugin_t):
	flags = 0
	comment = ""
	help = ""
	wanted_name = "Names MIPS registers saved on the stack"
	wanted_hotkey = ""

	def init(self):
		self.menu_context = idaapi.add_menu_item("Options/", "Name saved registers", "", 0, self.name_saved_registers, (None,))
		return idaapi.PLUGIN_KEEP

	def term(self):
		idaapi.del_menu_item(self.menu_context)
		return None

	def run(self, arg):
		pass

	def name_saved_registers(self, arg):
		NameMIPSSavedRegisters()

def PLUGIN_ENTRY():
	return mips_saved_registers_t()

