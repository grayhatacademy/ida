#!/usr/bin/env python
from __future__ import print_function

import os
import shutil
import argparse


def get_plugin_directories(source_path):
    """
    Find IDA plugins in the provided source directory.

    :param source_path: Path to look for directories.
    :type source_path: str

    :returns: List of directories in the source path. Only returns the
              directory name and not the full path.
    :rtype: list(str)
    """
    plugins = []
    for plugin in os.listdir(source_path):
        if not os.path.isdir(os.path.join(source_path, plugin)):
            continue
        plugins.append(plugin)
    return plugins


def install_plugins(ida_install_path):
    """
    Install the plugins.

    :param ida_install_path: Full IDA installation path.
    :type ida_install_path: str
    """
    install_path = os.path.realpath(os.path.join(ida_install_path, 'plugins'))
    source_path = os.path.dirname(os.path.realpath(__file__))
    print("Installing plugins from %s to %s..." % (source_path, install_path))

    plugins = get_plugin_directories(source_path)
    for plugin in plugins:
        print("Installing %s..." % plugin, end=''),
        if 'shims' in plugin:
            shims_dir = os.path.join(install_path, 'shims')
            try:
                os.mkdir(shims_dir)
            except OSError:
                pass
            src = os.path.join(source_path, plugin, 'ida_' + plugin + '.py')
            dst = os.path.join(shims_dir, 'ida_' + plugin + '.py')
            open(os.path.join(shims_dir, '__init__.py'), 'a').close()
        else:
            src = os.path.join(source_path, plugin, plugin + '.py')
            dst = os.path.join(install_path, plugin + '.py')

        shutil.copyfile(src, dst)
        print('Done')


def remove_plugins(ida_install_path):
    """
    Remove plugins from the IDA installation directory.

    :param ida_install_path: Full IDA installation path.
    :type ida_install_path: str
    """
    install_path = os.path.realpath(os.path.join(ida_install_path, 'plugins'))
    source_path = os.path.dirname(os.path.realpath(__file__))
    print("Removing plugins from %s..." % install_path)

    plugins = get_plugin_directories(source_path)
    for plugin in plugins:
        print("Removing %s..." % plugin, end='')
        try:
            if 'shims' in plugin:
                dst = os.path.join(install_path, 'shims', 'ida_' +
                                   plugin + '.py')
                shutil.rmtree(os.path.dirname(dst))
            else:
                dst = os.path.join(install_path, plugin + '.py')
                os.remove(dst)
        except OSError:
            print('%s was not installed' % plugin)

        print('Done')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Install IDA plugins.')

    objective = parser.add_mutually_exclusive_group()
    objective.add_argument('-i', '--install', action='store_true', 
                           help='Install plugins.')
    objective.add_argument('-r', '--remove', action='store_true', 
                           help='Remove plugins.')
    
    parser.add_argument('-d', '--directory', help='IDA installation directory.')

    args = parser.parse_args()

    if not os.path.exists(args.directory):
        raise Exception('IDA installation, %s, does not exist.' %
                        args.directory)

    if args.install:
        install_plugins(args.directory)
    elif args.remove:
        remove_plugins(args.directory)

    print('Done.')
