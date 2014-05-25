import idc

class LibNVRAM(object):

    _CONFIG_FILE = "/tmp/nvram.cfg"

    __IDASIM_DEFAULT_HANDLER_CLASS__ = True

    def __init__(self, idasim):
        self.idasim = idasim

        self.config = {}

        try:
            for line in open(self._CONFIG_FILE).readlines():
                if '=' in line:
                    kv = line.strip().split('=')
                    if not self.config.has_key(kv[0]):
                        self.config[kv[0]] = kv[1]
        except:
            pass

    def nvram_init(self):
        return 0

    def nvram_get(self, zero, key=''):
        return self.nvram_bufget(zero, key)

    def nvram_bufget(self, zero, key=''):
        try:
            value = self.config[key]
        except:
            value = ''

        print "nvram_get: {'%s' : '%s'}" % (key, value)
        return value + "\x00"

    def nvram_bufset(self, zero, key='', value=''):
        self.config[key] = value
        print "nvram_set: {'%s' : '%s'}" % (key, value)
        return 0

    def nvram_get_ex(self, key='', dst=0, size=0):
        idc.DbgWrite(dst, self.nvram_bufget(0, key)[:size])
        return 0

    def nvram_match(self, key='', match=''):
        if self.nvram_bufget(0, key)[:-1] == match:
            return 1
        return 0

    def nvram_invmatch(self, key='', match=''):
        if self.nvram_match(key, match):
            return 0
        return 1

