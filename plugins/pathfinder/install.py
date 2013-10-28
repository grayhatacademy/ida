#!/usr/bin/env python
# Simple installer script to drop the files where they need to be.

import sys
import shutil
import os.path

try:
	ida_dir = sys.argv[1]
except:
	print "Usage: %s <path to IDA install directory>" % sys.argv[0]
	sys.exit(1)

if os.path.exists(ida_dir):
	shutil.copyfile('pathfinder.py', os.path.join(ida_dir, 'python', 'pathfinder.py'))
	shutil.copyfile('idapathfinder.py', os.path.join(ida_dir, 'plugins', 'idapathfinder.py'))
	print "PathFinder installed to '%s'." % ida_dir
else:
	print "Install failed, '%s' does not exist!" % ida_dir
	sys.exit(1)
