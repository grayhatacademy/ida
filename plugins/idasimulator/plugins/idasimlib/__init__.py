import os as _os

# Load all modules
for _module in _os.listdir(_os.path.dirname(__file__)):
    if _module != '__init__.py' and _module[-3:] == '.py':
        __import__(_module[:-3], locals(), globals())

del _os
del _module
