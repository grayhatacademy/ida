import idc

class LibCSMAN(object):

    _CONFIG = "/tmp/nvram.cfg"

    __IDASIM_DEFAULT_HANDLER_CLASS__ = True

    def __init__(self, idasim):
        self.idasim = idasim

        self.config = {}

        try:
            for line in open(self._CONFIG_FILE).readlines():
                if '=' in line:
                    kv = line.strip().split('=')
                    name = kv[0]
                    key = int(kv[1], 16)
                    if len(kv) == 3:
                        value = kv[2].decode('string_escape')
                    else:
                        value = "\x00"

                    if not self.config.has_key(key):
                        self.config[key] = {
                                'name'    : name,
                                'value'    : value
                        }
        except:
            pass

    def open_csman(self):
        return 128

    def close_csman(self):
        return 0

    def write_csman(self, fd, key, buf, size, default):
        return 0

    def read_csman(self, fd, key, value, size, default):
        if self.config.has_key(key):
            print "read_csman(%s)" % self.config[key]['name']
            idc.DbgWrite(value, self.config[key]['value'])
        else:
            print "UNKNOWN CSID: 0x%.8X called from 0x%.8X" % (key, self.idasim.cpu.ReturnAddress())

        return 0

