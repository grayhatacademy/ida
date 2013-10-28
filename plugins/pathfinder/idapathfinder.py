import idc
import idaapi
import idautils
import pathfinder
import time

class idapathfinder_t(idaapi.plugin_t):

	flags = 0
	comment = ''
	help = ''
	wanted_name = 'PathFinder'
	wanted_hotkey = ''

	def init(self):
		ui_path = "View/Graphs/"
		self.menu_contexts = []
		self.graph = None

		#self.menu_contexts.append(idaapi.add_menu_item(ui_path,
		#						"Find code paths to the current function block",
		#						"Alt-7",
		#						0,
		#						self.FindBlockPaths,
		#						(None,)))
		self.menu_contexts.append(idaapi.add_menu_item(ui_path,
								"Find function path(s) to here",
								"Alt-6",
								0,
								self.FindPathsFromMany,
								(None,)))
		#self.menu_contexts.append(idaapi.add_menu_item(ui_path,
		#						"Find paths to here from a single function",
		#						"Alt-7",
		#						0,
		#						self.FindPathsFromSingle,
		#						(None,)))
		self.menu_contexts.append(idaapi.add_menu_item(ui_path, 
								"Find function path(s) from here", 
								"Alt-5", 
								0, 
								self.FindPathsToMany, 
								(None,)))
		#self.menu_contexts.append(idaapi.add_menu_item(ui_path, 
		#						"Find paths from here to a single function", 
		#						"Alt-5", 
		#						0, 
		#						self.FindPathsToSingle, 
		#						(None,)))
		return idaapi.PLUGIN_KEEP

	def term(self):
		for context in self.menu_contexts:
			idaapi.del_menu_item(context)
		return None
	
	def run(self, arg):
		self.FindPathsToSingle()

	def _current_function(self):
		return idaapi.get_func(ScreenEA()).startEA

	def _find_and_plot_paths(self, sources, targets, pfc=pathfinder.FunctionPathFinder):
		results = []

		for target in targets:
			pf = pfc(target)
			for source in sources:
				s = time.time()
				r = pf.paths_from(source)
				e = time.time()
				#print "paths_from took %f seconds." % (e-s)

				if r:
					results += r
				else:
					name = idc.Name(target)
					if not name:
						name = "0x%X" % target
					print "No paths found to", name

		if results:
			# Be sure to close any previous graph before creating a new one.
			# Failure to do so may crash IDA.
			try:
				self.graph.Close()
			except:
				pass

			self.graph = pathfinder.PathFinderGraph(results, 'Path Graph', pf.colorize)
			self.graph.Show()

	def _get_user_selected_functions(self, many=False):
		functions = []
		ea = idc.ScreenEA()
		try:
			current_function = idc.GetFunctionAttr(ea, idc.FUNCATTR_START)
		except:
			current_function = None

		while True:
			function = idc.ChooseFunction("Select a function and click 'OK' until all functions have been selected. When finished, click 'Cancel' to display the graph.")
			# ChooseFunction automatically jumps to the selected function
			# if the enter key is pressed instead of clicking 'OK'. Annoying.
			if idc.ScreenEA() != ea:
				idc.Jump(ea)

			if not function or function == idc.BADADDR or function == current_function:
				break
			elif function not in functions:
				functions.append(function)

			if not many:
				break

		return functions
			
	def FindPathsToSingle(self, arg):
		source = self._current_function()

		if source:
			targets = self._get_user_selected_functions()
			if targets:
				print source, targets
				self._find_and_plot_paths([source], targets)

	def FindPathsToMany(self, arg):
		source = self._current_function()

		if source:
			targets = self._get_user_selected_functions(many=True)
			if targets:
				self._find_and_plot_paths([source], targets)

	def FindPathsFromSingle(self, arg):
		target = self._current_function()

		if target:
			sources = self._get_user_selected_functions()
			if sources:
				self._find_and_plot_paths(sources, [target])

	def FindPathsFromMany(self, arg):
		target = self._current_function()

		if target:
			sources = self._get_user_selected_functions(many=True)
			if sources:
				self._find_and_plot_paths(sources, [target])

	def FindBlockPaths(self, arg):
		target = idc.ScreenEA()
		source = idaapi.get_func(idc.ScreenEA())

		if source:
			self._find_and_plot_paths([source.startEA], [target], pfc=pathfinder.BlockPathFinder)
		else:
			print "Block graph error: The location must be part of a function!"

def PLUGIN_ENTRY():
	return idapathfinder_t()
