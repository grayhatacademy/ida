import idc
import idaapi
import idautils
import time

class PathFinderGraph(idaapi.GraphViewer):
	'''
	Class for generating an idaapi.GraphViewer graph.
	'''

	def __init__(self, results, title="PathFinder Graph", colorize=None):
		'''
		Class constructor.

		@results - A list of lists, each representing a call graph.
		@title   - The title of the graph window.

		Returns None.
		'''
		idaapi.GraphViewer.__init__(self, title)
		self.ids = {}
		self.nodes = {}
		self.history = []
		self.includes = []
		self.excludes = []
		self.end_nodes = []
		self.edge_nodes = []
		self.start_nodes = []
		self.delete_on_click = False
		self.include_on_click = False
		self.results = results
		self.colorize = colorize
		self.activate_count = 0

	def Show(self):
		'''
		Display the graph.

		Returns True on success, False on failure.
		'''
		if not idaapi.GraphViewer.Show(self):
			return False
		else:
			self.cmd_undo = self.AddCommand("Undo", "U")
			self.cmd_reset = self.AddCommand("Reset graph", "R")
			self.cmd_delete = self.AddCommand("Exclude node", "X")
			self.cmd_include = self.AddCommand("Include node", "I")
			self.activate_count = 0
			return True

	def OnRefresh(self):
		self.Clear()
		self.ids = {}
		self.nodes = {}
		self.nodes_xrefs = {}
		self.end_nodes = []
		self.edge_nodes = []
		self.start_nodes = []

		for path in self.results:
			nogo = False

			for include in self.includes:
				if include not in path:
					nogo = True

			for exclude in self.excludes:
				if exclude in path:
					nogo = True
					break
	
			if not nogo:
				prev_node = None
				prev_nod_name = None

				for node in path:
					name = self.get_node_name(node)

					if not self.ids.has_key(name):
						self.ids[name] = self.AddNode(name)
						self.nodes[self.ids[name]] = node
					if prev_node is not None:
						self.AddEdge(prev_node_name, self.ids[name])
						if node not in self.nodes_xrefs[prev_node]:
							self.nodes_xrefs[prev_node].append(node)
					prev_node = node
					prev_node_name = self.ids[name]
					try:
						self.nodes_xrefs[prev_node]
					except:
						self.nodes_xrefs[prev_node] = []

				try:
					self.start_nodes.append(path[0])
					self.end_nodes.append(path[-1])
					self.edge_nodes.append(path[-2])
				except:
					pass
			else:
				# Be sure to uncolorize the nodes in the path here, else 
				# user-excluded nodes will still remain colorized in the disassembly.
				for node in path:
					self._uncolorize(node)

		return True

	def OnActivate(self):
		# Can't call refresh on the first callback to OnActivate (results in crash).
		if self.activate_count > 0:
			self.Refresh()
		self.activate_count += 1

	def OnHint(self, node_id):
		return str(self[node_id])

	def OnGetText(self, node_id):
		name = str(self[node_id])
		color = idc.DEFCOLOR

		if self.nodes[node_id] in self.edge_nodes:
			color = 0x00ffff
		elif self.nodes[node_id] in self.start_nodes:
			color = 0x00ff00
		elif self.nodes[node_id] in self.end_nodes:
			color = 0x0000ff

		self.colorize(self.nodes[node_id], color)
		return (name, color)

	def OnCommand(self, cmd_id):
		if self.cmd_undo == cmd_id:
			self._undo()
		elif self.cmd_include == cmd_id:
			self.include_on_click = True
		elif self.cmd_delete == cmd_id:
			self.delete_on_click = True
		elif self.cmd_reset == cmd_id:
			self._reset()

	def OnDblClick(self, node_id):
		edges = []
		jump_ea = None
		delim = "-"
		header1 = "Edge Source"
		header2 = "Edge Destination"
		to_max_len = len(header2)
		frm_max_len = len(header1)
		this_func_ea = idc.LocByName(str(self[node_id]))

		for named_xref_ea in self.nodes_xrefs[self.nodes[node_id]]:
			named_xref = idc.Name(named_xref_ea)
			print "Looking for %s => %s (0x%.8X)" % (str(self[node_id]), named_xref, named_xref_ea)

			for xref in idautils.XrefsTo(named_xref_ea):
				if xref.type in [idc.fl_CN, idc.fl_CF] and idc.GetFunctionAttr(xref.frm, idc.FUNCATTR_START) == this_func_ea:
					xref_ea = xref.frm

					if jump_ea is None:
						jump_ea = xref_ea

					frm = self.get_node_name(xref_ea)
					to = self.get_node_name(named_xref_ea)

					if len(frm) > frm_max_len:
						frm_max_len = len(frm)
					if len(to) > to_max_len:
						to_max_len = len(to)

					edges.append((frm, to))

		if edges:
			fmt = "| %%-%ds | %%-%ds |" % (frm_max_len, to_max_len)
			total_len = frm_max_len + to_max_len + 7
			
			print delim * total_len
			print fmt % (header1, header2)
			print delim * total_len

			for (frm, to) in edges:
				print fmt % (frm, to)
			
			print delim * total_len

		if jump_ea is None:
			jump_ea = self.nodes[node_id]
		
		idc.Jump(jump_ea)

	def OnClick(self, node_id):
		if self.delete_on_click:
			self.delete_on_click = False
			self.excludes.append(self.nodes[node_id])
			self.history.append('exclude')
		elif self.include_on_click:
			self.include_on_click = False
			self.includes.append(self.nodes[node_id])
			self.history.append('include')
		self.Refresh()

	def OnClose(self):
		# Clean up node colorization
		for (name, node) in self.nodes.iteritems():
			self._uncolorize(node)

	def get_node_name(self, ea):
		name = idc.Name(ea)
		if not name:
			name = idc.GetFuncOffset(ea)
			if not name:
				name = "0x%X" % ea
		return name

	def _get_first_xref(self, frm, to):
		frm_func_ea = frm

		for xref in idautils.XrefsTo(to):
			if xref.frm != idc.BADADDR and idc.GetFunctionAttr(xref.frm. idc.FUNCATTR_START) == frm_func_ea:
				return xref.frm

		return frm

	def _undo(self):
		self.delete_on_click = False
		self.include_on_click = False
		
		if self.history:
			last_action = self.history.pop(-1)
		else:
			last_action = None

		if last_action == 'include' and self.includes:
			self.includes.pop(-1)
		elif last_action == 'exclude' and self.excludes:
			self.excludes.pop(-1)
			
		self.Refresh()

	def _reset(self):
		self.history = []
		self.includes = []
		self.excludes = []
		self.delete_on_click = False
		self.include_on_click = False
		self.Refresh()

	def _uncolorize(self, node):
		self.colorize(node, idc.DEFCOLOR)

class PathFinder(object):
	'''
	Base class for finding the path between two addresses.
	'''

	# Limit the max recursion depth
	MAX_DEPTH = 500

	def __init__(self, destination):
		'''
		Class constructor.

		@destination - The end node ea.

		Returns None.
		'''
		self.tree = {}
		self.nodes = {}
		self.depth = 0
		self.last_depth = 0
		self.full_paths = []
		self.current_path = []
		self.destination = destination
		self.build_call_tree(self.destination)

	def __enter__(self):
		return self
		
	def __exit__(self, t, v, traceback):
		return

	def _name2ea(self, nea):
		if isinstance(nea, type('')):
			return idc.LocByName(nea)
		return nea

	def paths_from(self, source, exclude=[], include=[], xrefs=[], noxrefs=[]):
		'''
		Find paths from a source node to a destination node.

		@source  - The source node ea to start the search from.
		@exclude - A list of ea's to exclude from paths.
		@include - A list of ea's to include in paths.
		@xrefs   - A list of ea's that must be referenced from at least one of the path nodes.
		@noxrefs - A list of ea's that must not be referenced from any of the path nodes.

		Returns a list of path lists.
		'''
		paths = []
		good_xrefs = []
		bad_xrefs = []

		source = self._name2ea(source)

		# If all the paths from the destination node have not already
		# been calculated, find them first before doing anything else.
		if not self.full_paths:
			s = time.time()
			self.find_paths(self.destination, source)
			e = time.time()

		for xref in xrefs:
			xref = self._name2ea(xref)

			for x in idautils.XrefsTo(xref):
				f = idaapi.get_func(x.frm)
				if f:
					good_xrefs.append(f.startEA)

		for xref in noxrefs:
			bad_xrefs.append(self._name2ea(xref))
			xref = self._name2ea(xref)

			for x in idautils.XrefsTo(xref):
				f = idaapi.get_func(x.frm)
				if f:
					bad_xrefs.append(f.startEA)

		for p in self.full_paths:
			try:
				index = p.index(source)

				if exclude:
					for ex in excludes:
						if ex in p:
							index = -1
							break
				
				if include:
					orig_index = index
					index = -1

					for inc in include:
						if inc in p:
							index = orig_index
							break

				if good_xrefs:
					orig_index = index
					index = -1
					
					for xref in good_xrefs:
						if xref in p:
							index = orig_index

					if index == -1:
						print "Sorry, couldn't find", good_xrefs, "in", p

				if bad_xrefs:
					for xref in bad_xrefs:
						if xref in p:
							index = -1
							break

				# Be sure to include the destinatin and source nodes in the final path
				p = [self.destination] + p[:index+1]
				# The path is in reverse order (destination -> source), so flip it
				p = p[::-1]
				# Ignore any potential duplicate paths
				if p not in paths:
					paths.append(p)
			except:
				pass

		return paths

	def find_paths(self, ea, source=None, i=0):
		'''
		Performs a depth-first (aka, recursive) search to determine all possible call paths originating from the specified location.
		Called internally by self.paths_from.

		@ea - The start node to find a path from.
		@i  - Used to specify the recursion depth; for internal use only.

		Returns None.
		'''
		# Increment recursion depth counter by 1
		i += 1
		# Get the current call graph depth
		this_depth = self.depth

		# If this is the first level of recursion and the call
		# tree has not been built, then build it.
		if i == 1 and not self.tree:
			self.build_call_tree(ea)

		# Don't recurse past MAX_DEPTH	
		if i >= self.MAX_DEPTH:
			return

		# Loop through all the nodes in the call tree, starting at the specified location
		for (reference, children) in self.nodes[ea].iteritems():
			# Does this node have a reference that isn't already listed in our current call path?
			if reference and reference not in self.current_path:
					# Increase the call depth by 1
					self.depth += 1
					# Add the reference to the current path
					self.current_path.append(reference)
					# Find all paths from this new reference
					self.find_paths(reference, source, i)

		# If we didn't find any additional references to append to the current call path (i.e., this_depth == call depth)
		# then we have reached the limit of this call path.
		if self.depth == this_depth:
			# If the current call depth is not the same as the last recursive call, and if our list of paths
			# does not already contain the current path, then append a copy of the current path to the list of paths
			if self.last_depth != self.depth and self.current_path and self.current_path not in self.full_paths:
				self.full_paths.append(list(self.current_path))
			# Decrement the call path depth by 1 and pop the latest node out of the current call path
			self.depth -= 1
			if self.current_path:
				self.current_path.pop(-1)

		# Track the last call depth
		self.last_depth = self.depth	

	def build_call_tree(self, ea):
		'''
		Performs a breadth first (aka, iterative) search to build a call tree to the specified address.

		@ea - The node to generate a tree for.

		Returns None.
		'''
		self.tree[ea] = {}
		self.nodes[ea] = self.tree[ea]
		nodes = [ea]

		while nodes:
			new_nodes = []

			for node in nodes:
				if node and node != idc.BADADDR:
					node_ptr = self.nodes[node]

					for reference in self.node_xrefs(node):
						if reference not in self.nodes:
							node_ptr[reference] = {}
							self.nodes[reference] = node_ptr[reference]
							new_nodes.append(reference)
						elif not node_ptr.has_key(reference):
							node_ptr[reference] = self.nodes[reference]
			
			nodes = new_nodes

	def node_xrefs(self, node):
		'''
		This must be overidden by a subclass to provide a list of xrefs.

		@node - The EA of the node that we need xrefs for.

		Returns a list of xrefs to the specified node.
		'''
		return []

	def colorize(self, node, color):
		'''
		This should be overidden by a subclass to properly colorize the specified node.

		@node  - The Node object to be colorized.
		@color - The HTML color code.
		
		Returns None.
		'''
		#idc.SetColor(node, idc.CIC_ITEM, color)

class FunctionPathFinder(PathFinder):
	'''
	Subclass to generate paths between functions.
	'''

	def __init__(self, destination):
		func = idaapi.get_func(self._name2ea(destination))
		super(FunctionPathFinder, self).__init__(func.startEA)

	def node_xrefs(self, node):
		'''
		Return a list of function EA's that reference the given node.
		'''
		xrefs = []

		for x in idautils.XrefsTo(node):
			if x.type != idaapi.fl_F:
				f = idaapi.get_func(x.frm)
				if f and f.startEA not in xrefs:
					xrefs.append(f.startEA)
		return xrefs
	
	#def colorize(self, node, color):
	#	'''
	#	Colorize the entire function.
	#	'''
	#	if idc.GetColor(node, idc.CIC_FUNC) != color:
	#		idc.SetColor(node, idc.CIC_FUNC, color)

class BlockPathFinder(PathFinder):
	'''
	Subclass to generate paths between code blocks inside a function.
	'''

	def __init__(self, destination):
		func = idaapi.get_func(destination)
		self.blocks = idaapi.FlowChart(f=func)
		self.block_table = {}

		for block in self.blocks:
			self.block_table[block.startEA] = block
			self.block_table[block.endEA] = block

		self.source_ea = func.startEA
		dst_block = self.LookupBlock(destination)

		if dst_block:
			super(BlockPathFinder, self).__init__(dst_block.startEA)

	def LookupBlock(self, ea):
		try:
			return self.block_table[ea]
		except:
			for block in self.blocks:
				if ea >= block.startEA and ea < block.endEA:
					return block
		return None
		
	def node_xrefs(self, node):
		'''
		Return a list of blocks that reference the provided block.
		'''
		xrefs = []

		block = self.LookupBlock(node)
		if block:
			for xref in idautils.XrefsTo(block.startEA):
				xref_block = self.LookupBlock(xref.frm)
				if xref_block and xref_block.startEA not in xrefs:
					xrefs.append(xref_block.startEA)

		return xrefs

	def colorize(self, node, color):
		'''
		Colorize the entire code block.
		'''
		block = self.LookupBlock(node)
		if block and idc.GetColor(block.startEA, idc.CIC_ITEM) != color:
			ea = block.startEA
			while ea < block.endEA:
				idc.SetColor(ea, idc.CIC_ITEM, color)
				ea += idaapi.decode_insn(ea)
		

class Find(object):

	def __init__(self, start=[], end=[], include=[], exclude=[], xrefs=[], noxrefs=[]):
		self.start = self._obj2list(start)
		self.end = self._obj2list(end)
		self.include = self._obj2list(include)
		self.exclude = self._obj2list(exclude)
		self.xrefs = self._obj2list(xrefs)
		self.noxrefs = self._obj2list(noxrefs)

		if len(self.start) > 0:
			first_ea = self._obj2ea(self.start[0])
			func = idaapi.get_func(self.start[0])
			if func:
				results = []

				if func.startEA == first_ea:
					pfclass = FunctionPathFinder
				else:
					pfclass = BlockPathFinder

				
				for destination in self.end:
					pf = pfclass(destination)
					for source in self.start:
						results += pf.paths_from(source, exclude=self.exclude, include=self.include, xrefs=self.xrefs, noxrefs=self.noxrefs)
					del pf

				if results:
					pg = PathFinderGraph(results)
					pg.Show()
					del pg

	def _obj2list(self, obj):
		'''
		Converts the supplied object to a list, if it is not already a list.

		@obj - The object.
	
		Returns a list.
		'''
		l = []

		if not isinstance(obj, type([])):
			l.append(self._obj2ea(obj))
		else:
			for o in obj:
				l.append(self._obj2ea(o))
		return l

	def _obj2ea(self, ea):
		if isinstance(ea, type('')):
			return idc.LocByName(ea)
		return ea

