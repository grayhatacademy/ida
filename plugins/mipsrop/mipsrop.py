# IDA plugin for identifying ROP gadgets in Linux MIPS binaries.
#
# Return Oriented Programming in Linux MIPS is more like Jump Oriented Programming; the idea is to
# control enough of the stack/registers in order to control various jumps. Since all instructions
# in MIPS must be 4-byte aligned, you cannot "create" new instructions by returning into the middle
# of existing instructions, as is possible with some other architectures.
#
# In any given MIPS function, various registers are saved onto the stack by necessity:
#
#	o $s0 - $s7
#	o $fp
#	o $ra
#
# These values are restored from the stack before the function returns, thus, during a stack overflow
# one can control some or all of these register values. The subroutine registers ($s*) are of particular
# interest, as they are commonly used by the compiler to store function pointers. By convention, gcc will
# move function pointers into the $t9 register, then call the function using jalr:
#
# 	move $t9, $s0  <-- If we control $s0, we control where the jump is taken
#	jalr $t9
#
# While there are other jumps that are of use, and which this plugin searches for, the premise is the same:
# control the stack/registers, and you control various jumps allowing you to chain various blocks of code
# together.
#
# With a list of controllable jumps such as these, we then just need to search the surrounding instructions
# to see if they perform some operation which may be useful. For example, let's say we need to load the
# value 1 into the $a0 register; in this case, we would want to look for a controllable jump such as this:
#
#	move $t9, $s1
#	jalr $t9
#	li $a0, 1    <-- Remember MIPS has jump delay slots, so this instruction is executed with the jump
#
# If we return to this piece of code (and if we control $s1), we can pre-load $s1 with the address of the
# next ROP gadget; thus, $a0 will be loaded with the value 1 and we can chain this block of code with other
# gadgets in order to perform more complex operations.
#
# This plugin finds all potentially controllable jumps, and then allows you to search for desired instructions
# surrounding these controllable jumps. Example:
#
#	Python> mipsrop.find("li $a0, 1")
#	----------------------------------------------------------------------------------------------------
#	|  Address     |  Action                                              |  Control Jump              |
#	----------------------------------------------------------------------------------------------------
#	|  0x0002F0F8  |  li $a0,1                                            |  jalr  $s4                 |
#	|  0x00057E50  |  li $a0,1                                            |  jalr  $s1                 |
#	----------------------------------------------------------------------------------------------------
#
# The output shows the offset of each ROP gadget, the instruction within the gadget that your search matched,
# and the effective register that is jumped to after that instruction is executed.
#
# The specified instruction can be a full instruction, such as the example above, or a partial instruction.
# Regex is supported for any of the instruction mnemonics or operands; for convenience, the dollar signs in 
# front of register names are automatically escaped.
#
# If .set_base(int) is called with a non-zero value then the output will include base, offset and address.
# Example
# -------------------------------------------------------------------------------------------------------------------------------------------
# |  Base       + Offset     =  Address     |  Action                                              |  Control Jump                          |
# -------------------------------------------------------------------------------------------------------------------------------------------
#
# Craig Heffner
# Tactical Network Solutions

import re
import idc
import idaapi
import idautils

# Global instance of MIPSROPFinder
mipsrop = None

class MIPSInstruction(object):
	'''
	Class for storing info about a specific instruction.
	'''

	def __init__(self, mnem, opnd0=None, opnd1=None, opnd2=None, ea=idc.BADADDR):
		self.mnem = mnem
		self.operands = [opnd0, opnd1, opnd2]
		self.opnd0 = opnd0
		self.opnd1 = opnd1
		self.opnd2 = opnd2
		self.ea = ea

	def __str__(self):
		string = self.mnem + " "

		for op in self.operands:
			if op:
				string += "%s," % op
			else:
				break

		return string[:-1]

class ROPGadget(object):
	'''
	Class for storing information about a specific ROP gadget.
	'''
	
	def __init__(self, control, jump, operation=None, description="ROP gaget", base=0):
		self.control = control
		self.exit = jump
		self.operation = operation
		self.description = description
		self.base = base
		self.h = '-' * 112
		if self.base != 0:
			self.h += '-' * 27

		if self.control.opnd1:
			self.control.register = self.control.opnd1
		else:
			self.control.register = self.control.opnd0

		if self.exit.opnd1:
			self.exit.register = self.exit.opnd1
		else:
			self.exit.register = self.exit.opnd0
		
		if self.operation:
			if self.operation.ea < self.control.ea:
				self.entry = self.operation
			else:
				self.entry = self.control
		else:
			self.operation = self.control
			self.entry = self.control


	def header(self):
		if self.base != 0:
			return self.h + "\n|  Base       + Offset     =  Address       |  Action                                              |  Control Jump                          |\n" + self.h
		else:
			return self.h + "\n|  Address     |  Action                                              |  Control Jump                          |\n" + self.h

	def footer(self):
		return self.h

	def __str__(self):
		if self.base != 0:
			return "|  0x%.8X + 0x%.8X = 0x%.8X     |  %-50s  |  %-5s %-30s  |" % (self.base, self.entry.ea, self.entry.ea + self.base, str(self.operation), self.exit.mnem, self.control.register)
		else:
			return "|  0x%.8X  |  %-50s  |  %-5s %-30s  |" % (self.entry.ea, str(self.operation), self.exit.mnem, self.control.register)

class BowcasterBuilder(object):
	'''
	Class to generate bowcaster code from a list of selected ROP gadgets. WIP.
	'''

	INSIZE = 4
	SEARCH_DEPTH = 25

	def __init__(self, gadgets):
		self.code = []
		self.gadgets = gadgets

	def build_code(self):
		keys = self.gadgets.keys()
		keys.sort()
	
		for key in keys[::-1]:
			last_instruction = False
			ea = self.gadgets[key]
			end_ea = ea + self.SEARCH_DEPTH

			while ea <= end_ea:
				mnem = idc.GetMnem(ea)
				if mnem in ['jr', 'jalr']:
					last_instruction = True
				ea += self.INSIZE

	def print_code(self):
		for line in self.code:
			print line

class MIPSROPFinder(object):
	'''
	Primary ROP finder class.
	'''

	CODE = 2
        DATA = 3
	INSIZE = 4
        SEARCH_DEPTH = 25
	
	def __init__(self):
		self.base = 0

		self._initial_find()

		if self.controllable_jumps or self.system_calls:
			print "MIPS ROP Finder activated, found %d controllable jumps between 0x%.8X and 0x%.8X" % (len(self.controllable_jumps), self.start, self.end)

	def _initial_find(self):
		self.start = idc.BADADDR
		self.end = idc.BADADDR
		self.system_calls = []
		self.double_jumps = []
		self.controllable_jumps = []
		start = 0
		end = 0

		for (start, end) in self._get_segments(self.CODE):
			self.controllable_jumps += self._find_controllable_jumps(start, end)
			self.system_calls += self._find_system_calls(start, end)
			self.double_jumps += self._find_double_jumps(start, end)
			if self.start == idc.BADADDR:
				self.start = start
		self.end = end
	
	def _get_segments(self, attr):
		segments = []
		start = idc.BADADDR
		end = idc.BADADDR
		seg = idc.FirstSeg()

		while seg != idc.BADADDR:
			if idc.GetSegmentAttr(seg, idc.SEGATTR_TYPE) == attr:
				start = idc.SegStart(seg)
				end = idc.SegEnd(seg)
				segments.append((start, end))
			seg = idc.NextSeg(seg)

		return segments

	def _get_instruction(self, ea):
		return MIPSInstruction(idc.GetMnem(ea), idc.GetOpnd(ea, 0), idc.GetOpnd(ea, 1), idc.GetOpnd(ea, 2), ea)

	def _does_instruction_match(self, ea, instruction, regex=False):
		i = 0
		op_cnt = 0
		op_ok_cnt = 0
		match = False
		ins_size = idaapi.decode_insn(ea)
		mnem = GetMnem(ea)

		if (not instruction.mnem) or (instruction.mnem == mnem) or (regex and re.match(instruction.mnem, mnem)):
			for operand in instruction.operands:
				if operand:
					op_cnt += 1
					op = idc.GetOpnd(ea, i)

					if regex:
						if re.match(operand, op):
							op_ok_cnt += 1
					elif operand == op:
						op_ok_cnt += 1
				i += 1

			if op_cnt == op_ok_cnt:
				match = True

		return match

	def _is_bad_instruction(self, ea, bad_instructions=['j', 'b'], no_clobber=[]):
		bad = False
		mnem = GetMnem(ea)

		if mnem and mnem[0] in bad_instructions:
			bad = True
		else:
			for register in no_clobber:
				if (idaapi.insn_t_get_canon_feature(idaapi.cmd.itype) & idaapi.CF_CHG1) == idaapi.CF_CHG1:
					if idc.GetOpnd(ea, 0) == register:
						bad = True

		return bad

	def _contains_bad_instruction(self, start_ea, end_ea, bad_instructions=['j', 'b'], no_clobber=[]):
		ea = start_ea

		while ea <= end_ea:
			if self._is_bad_instruction(ea, bad_instructions, no_clobber):
				return True
			else:
				ea += self.INSIZE

		return False
		
	def _find_prev_instruction_ea(self, start_ea, instruction, end_ea=0, no_baddies=True, regex=False, dont_overwrite=[]):
		instruction_ea = idc.BADADDR
		ea = start_ea
		baddies = ['j', 'b']

		while ea >= end_ea:
			if self._does_instruction_match(ea, instruction, regex):
				instruction_ea = ea
				break
			elif no_baddies and self._is_bad_instruction(ea, no_clobber=dont_overwrite):
				break

			ea -= self.INSIZE

		return instruction_ea

	def _find_next_instruction_ea(self, start_ea, instruction, end_ea=idc.BADADDR, no_baddies=False, regex=False, dont_overwrite=[]):
		instruction_ea = idc.BADADDR
		ea = start_ea

		while ea <= end_ea:
			if self._does_instruction_match(ea, instruction, regex):
				instruction_ea = ea
				break
			elif no_baddies and self._is_bad_instruction(ea, no_clobber=dont_overwrite):
				break

			ea += self.INSIZE

		return instruction_ea

	def _find_controllable_jumps(self, start_ea, end_ea):
		controllable_jumps = []
		t9_controls = [
			MIPSInstruction("move", "\$t9"),
			MIPSInstruction("addiu", "\$t9", "^\$"),
		]
		t9_jumps = [
			MIPSInstruction("jalr", "\$t9"),
			MIPSInstruction("jr", "\$t9"),
		]
		ra_controls = [
			MIPSInstruction("lw", "\$ra"),
		]
		ra_jumps = [
			# TODO: Search for jumps to registers other than $ra.
			MIPSInstruction("jr", "\$ra"),
		]
		t9_musnt_clobber = ["$t9"]
		ra_musnt_clobber = ["$ra"]

		for possible_control_instruction in t9_controls+ra_controls:
			ea = start_ea
			found = 0

			if possible_control_instruction in t9_controls:
				jumps = t9_jumps
				musnt_clobber = t9_musnt_clobber
			else:
				jumps = ra_jumps
				musnt_clobber = ra_musnt_clobber

			while ea <= end_ea:

				ea = self._find_next_instruction_ea(ea, possible_control_instruction, end_ea, regex=True)
				if ea != idc.BADADDR:
					ins_size = idaapi.decode_insn(ea)

					control_instruction = self._get_instruction(ea)
					control_register = control_instruction.operands[1]
					
					if control_register:
						for jump in jumps:
							jump_ea = self._find_next_instruction_ea(ea+ins_size, jump, end_ea, no_baddies=True, regex=True, dont_overwrite=musnt_clobber)
							if jump_ea != idc.BADADDR:
								jump_instruction = self._get_instruction(jump_ea)
								controllable_jumps.append(ROPGadget(control_instruction, jump_instruction, description="Controllable Jump", base=self.base))
								ea = jump_ea
					
					ea += ins_size

		return controllable_jumps

	def _find_system_calls(self, start_ea, end_ea):
		system_calls = []
		system_load = MIPSInstruction("la", "$t9", "system")
		stack_arg_zero = MIPSInstruction("addiu", "$a0", "$sp")

		for xref in idautils.XrefsTo(idc.LocByName('system')):
			ea = xref.frm
			if ea >= start_ea and ea <= end_ea and idc.GetMnem(ea)[0] in ['j', 'b']:
				a0_ea = self._find_next_instruction_ea(ea+self.INSIZE, stack_arg_zero, ea+self.INSIZE)
				if a0_ea == idc.BADADDR:
					a0_ea = self._find_prev_instruction_ea(ea, stack_arg_zero, ea-(self.SEARCH_DEPTH*self.INSIZE))
				
				if a0_ea != idc.BADADDR:
					control_ea = self._find_prev_instruction_ea(ea-self.INSIZE, system_load, ea-(self.SEARCH_DEPTH*self.INSIZE))
					if control_ea != idc.BADADDR:
						system_calls.append(ROPGadget(self._get_instruction(control_ea), self._get_instruction(ea), self._get_instruction(a0_ea), description="System call", base=self.base))

				ea += self.INSIZE
			else:
				break

		return system_calls

	def _find_double_jumps(self, start_ea, end_ea):
		double_jumps = []
		
		for i in range(0, len(self.controllable_jumps)):
			g1 = self.controllable_jumps[i]
			if g1.exit.mnem != 'jalr':
				continue

			for j in range(i+1, len(self.controllable_jumps)):
				g2 = self.controllable_jumps[j]
				distance = (g2.entry.ea - g1.exit.ea)

				if distance > 0 and distance <= (self.SEARCH_DEPTH * self.INSIZE):
					if g1.control.register != g2.control.register:
						if not self._contains_bad_instruction(g1.exit.ea+self.INSIZE, g2.control.ea-self.INSIZE, no_clobber=[g2.control.register]):
							double_jumps.append(g1)
							break

		return double_jumps

	def _find_rop_gadgets(self, gadget):
		gadget_list = []

		for controllable_jump in self.controllable_jumps:
			gadget_ea = idc.BADADDR

			ea = self._find_next_instruction_ea(controllable_jump.entry.ea, gadget, controllable_jump.exit.ea+self.INSIZE, regex=True)
			if ea != idc.BADADDR:
				gadget_ea = ea
			else:
				ea = self._find_prev_instruction_ea(controllable_jump.entry.ea, gadget, controllable_jump.entry.ea-(self.SEARCH_DEPTH*self.INSIZE), no_baddies=True, regex=True, dont_overwrite=[controllable_jump.entry.opnd1])
				if ea != idc.BADADDR:
					gadget_ea = ea
		
			if gadget_ea != idc.BADADDR:
				gadget_list.append(ROPGadget(controllable_jump.entry, controllable_jump.exit, self._get_instruction(gadget_ea), base=self.base))

		return gadget_list

	def _print_gadgets(self, gadgets):
		if gadgets:
			print gadgets[0].header()

		for gadget in gadgets:
			print str(gadget)

		if gadgets:
			print gadgets[0].footer()
		
		print "Found %d matching gadgets" % (len(gadgets))

	def _get_marked_gadgets(self):
		rop_gadgets = {}

		for i in range(1, 1024):
			marked_pos = idc.GetMarkedPos(i)
			if marked_pos != idc.BADADDR:
				marked_comment = idc.GetMarkComment(i)
				if marked_comment and marked_comment.lower().startswith("rop"):
					rop_gadgets[marked_comment] = marked_pos
			else:
				break

		return rop_gadgets

	def double(self):
		self.doubles()

	def doubles(self):
		'''
		Prints a list of all "double jump" gadgets (useful for function calls).
		'''
		self._print_gadgets(self.double_jumps)

	def stackfinder(self):
		self.stackfinders()

	def stackfinders(self):
		'''
		Prints a list of all gadgets that put a stack address into a register.
		'''
		self.find("addiu .*, $sp")

	def lia0(self):
		'''
		Prints a list of all gadgets that load an immediate value number into $a0 (useful for setting up the argument to sleep).
		'''
		self.find("li $a0")

	def tail(self):
		return self.tails()

	def tails(self):
		'''
		Prints a lits of all tail call gadgets (useful for function calls).
		'''
		return self.iret()

	def iret(self):
		'''
		Prints a lits of all tail gadgets (useful for function calls).
		'''
		tail_gadgets = []

		for gadget in self._find_rop_gadgets(MIPSInstruction("move", "\$t9")):
			if gadget.exit.mnem == 'jr' and gadget.exit.register == '$t9':
				tail_gadgets.append(gadget)

		self._print_gadgets(tail_gadgets)

	def system(self):
		'''
		Prints a list of gadgets that may be used to call system().
		'''
		sys_gadgets = self.system_calls + self._find_rop_gadgets(MIPSInstruction("addiu", "\$a0", "\$sp"))
		self._print_gadgets(sys_gadgets)

	def find(self, instruction_string=""):
		'''
		Locates all potential ROP gadgets that contain the specified instruction.

		@instruction_string - The instruction you need executed. This can be either a:

					o Full instruction    - "li $a0, 1"
					o Partial instruction - "li $a0"
					o Regex instruction   - "li $a0, .*"
		'''
		registers = ['$v', '$s', '$a', '$t', '$k', '$pc', '$fp', '$ra', '$gp', '$at', '$zero']

		comma_split = instruction_string.split(',')
		instruction_parts = comma_split[0].split()
		if len(comma_split) > 1:
			instruction_parts += comma_split[1:]

		for i in range(0, 4):
			if i > len(instruction_parts) - 1:
				instruction_parts.append(None)
			else:
				instruction_parts[i] = instruction_parts[i].strip().strip(',').strip()
				for reg in registers:
					instruction_parts[i] = instruction_parts[i].replace(reg, "\\%s" % reg)

		instruction = MIPSInstruction(instruction_parts[0], instruction_parts[1], instruction_parts[2], instruction_parts[3])
		gadgets = self._find_rop_gadgets(instruction)
		if gadgets:
			self._print_gadgets(gadgets)
		else:
			print "No ROP gadgets found!"

	def summary(self):
		'''
		Prints a summary of your currently marked ROP gadgets, in alphabetical order by the marked name.
		To mark a location as a ROP gadget, simply mark the position in IDA (Alt+M) with any name that starts with "ROP".
		'''
		rop_gadgets = self._get_marked_gadgets()
		summaries = []
		delim_char = "-"
		headings = {
			'name' 		: "Gadget Name",
			'offset'	: "Gadget Offset",
			'summary'	: "Gadget Summary"
		}
		if self.base != 0:
			headings['offset'] = "Gadget Base + Offset = Address       "
		lengths = {
			'name'		: len(headings['name']),
			'offset'	: len(headings['offset']),
			'summary'	: len(headings['summary']),
		}
		total_length = (3 * len(headings)) + 1

		if rop_gadgets:
			gadget_keys = rop_gadgets.keys()
			gadget_keys.sort()

			for marked_comment in gadget_keys:
				if len(marked_comment) > lengths['name']:
					lengths['name'] = len(marked_comment)

				summary = []
				ea = rop_gadgets[marked_comment]
				end_ea = ea + (self.SEARCH_DEPTH * self.INSIZE)

				while ea <= end_ea:
					summary.append(idc.GetDisasm(ea))
					mnem = idc.GetMnem(ea)
					if len(mnem) > 0 and mnem[0].lower() in ['j', 'b']:
						summary.append(idc.GetDisasm(ea+self.INSIZE))
						break

					ea += self.INSIZE

				if len(summary) == 0:
					summary.append('')

				for line in summary:
					if len(line) > lengths['summary']:
						lengths['summary'] = len(line)

				summaries.append(summary)

			for (heading, size) in lengths.iteritems():
				total_length += size

			delim = delim_char * total_length
			line_fmt = "| %%-%ds | %%-%ds | %%-%ds |" % (lengths['name'], lengths['offset'], lengths['summary'])

			print delim
			print line_fmt % (headings['name'], headings['offset'], headings['summary'])
			print delim
			
			for i in range(0, len(gadget_keys)):
				line_count = 0
				marked_comment = gadget_keys[i]
				if self.base != 0:
					offset = "0x%.8X + 0x%.8X = 0x%.8X" % (self.base, rop_gadgets[marked_comment], self.base + rop_gadgets[marked_comment])
				else:
					offset = "0x%.8X" % rop_gadgets[marked_comment]
				summary = summaries[i]
				
				for line in summary:
					if line_count == 0:
						print line_fmt % (marked_comment, offset, line)
					else:
						print line_fmt % ('', '', line)

					line_count += 1

				print delim

	def build(self):
		'''
		WIP.
		'''
		gadgets = self._get_marked_gadgets()
		bc = BowcasterBuilder(gadgets)
		bc.build_code()

	def set_base(self, base=0):
		'''
		Set base address used for display
		'''
		self.base = base
		self._initial_find()

	def help(self):
		'''
		Show help info.
		'''
		delim = "---------------------------------------------------------------------" * 2
		
		print ""
		print "mipsrop.find(instruction_string)"
		print delim
		print self.find.__doc__

		print ""
		print "mipsrop.system()"
		print delim
		print self.system.__doc__

		print ""
		print "mipsrop.doubles()"
		print delim
		print self.doubles.__doc__

		print ""
		print "mipsrop.stackfinders()"
		print delim
		print self.stackfinders.__doc__

		print ""
		print "mipsrop.tails()"
		print delim
		print self.tails.__doc__

		print ""
		print "mipsrop.set_base()"
		print delim
		print self.set_base.__doc__

		print ""
		print "mipsrop.summary()"
		print delim
		print self.summary.__doc__


class mipsropfinder_t(idaapi.plugin_t):
	flags = 0
	comment = "MIPS ROP Finder"
	help = ""
	wanted_name = "MIPS ROP Finder"
	wanted_hotkey = ""

	def init(self):
		self.menu_context = idaapi.add_menu_item("Search/", "mips rop gadgets", "Alt-1", 0, self.run, (None,))
		return idaapi.PLUGIN_KEEP

	def term(self):
		idaapi.del_menu_item(self.menu_context)
		return None

	def run(self, arg):
		global mipsrop
		mipsrop = MIPSROPFinder()
                
def PLUGIN_ENTRY():
        return mipsropfinder_t()

# DEBUG
#if __name__ == '__main__':
#	mipsrop = MIPSROPFinder()

