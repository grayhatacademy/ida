#!/usr/bin/env python

import os
import sys
import shutil

try:
    py_module_path = os.path.realpath(os.path.join(sys.argv[1], 'python'))
    try:
        install = sys.argv[2] != '--remove'
    except IndexError as e:
        install = True
except IndexError as e:
    print ("Usage: %s <IDA install path> [--install | --remove]" % sys.argv[0])
    sys.exit(1)

source_path = os.path.dirname(os.path.realpath(__file__))

if install:
    print ("Installing python modules from %s to %s..." % (source_path, py_module_path))
else:
    print ("Removing python modules from %s..." % py_module_path)

for py_module in next(os.walk('.'))[1]:
    src = os.path.join(source_path, py_module, py_module + '.py')
    dst = os.path.join(py_module_path, py_module + '.py')

    if install:
        print ("Installing %s..." % py_module)
        shutil.copyfile(src, dst)
    else:
        print ("Removing %s..." % py_module)
        os.remove(dst)

print ("Done.")
