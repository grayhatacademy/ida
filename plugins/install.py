#!/usr/bin/env python

import os
import sys
import shutil

try:
    plugin_path = os.path.realpath(os.path.join(sys.argv[1], 'plugins'))
    try:
        install = sys.argv[2] != '--remove'
    except IndexError as e:
        install = True
except IndexError as e:
    print ("Usage: %s <IDA install path> [--install | --remove]" % sys.argv[0])
    sys.exit(1)

source_path = os.path.dirname(os.path.realpath(__file__))

if install:
    print ("Installing plugins from %s to %s..." % (source_path, plugin_path))
else:
    print ("Removing plugins from %s..." % plugin_path)

for plugin in next(os.walk('.'))[1]:

    if 'shims' in plugin:
        shims_dir = os.path.join(plugin_path, 'shims')
        try:
            os.mkdir(shims_dir)
        except OSError:
            pass
        src = os.path.join(source_path, plugin, 'ida_' + plugin + '.py')
        dst = os.path.join(shims_dir, 'ida_' + plugin + '.py')
        open(os.path.join(shims_dir, '__init__.py'), 'a').close()
    else:
        src = os.path.join(source_path, plugin, plugin + '.py')
        dst = os.path.join(plugin_path, plugin + '.py')


    if install:
        print ("Installing %s..." % plugin)
        shutil.copyfile(src, dst)
    else:
        print ("Removing %s..." % plugin),
        try:
            if 'shims' in dst:
                shutil.rmtree(os.path.dirname(dst))
            else:
                os.remove(dst)
            print ("removed.")
        except OSError:
            print ("not found.")
            continue

print ("Done.")
