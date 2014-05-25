import idc

class _FuzzHelper(object):
    
    def __init__(self, idasim):
        self.idasim = idasim

    def sanitize(self, data):
        try:
            return data.replace('"', '\\"')
        except:
            return data

    def display(self, message):
        print "%-25s %s" % (idc.GetFuncOffset(self.idasim.cpu.ReturnAddress()), message)
    
class Fuzz(object):

    def __init__(self, idasim):
        self.helper = _FuzzHelper(idasim)
        self.idasim = idasim

    def strcpy(self, dst, src=''):
        self.helper.display('strcpy(0x%X, "%s")' % (dst, self.helper.sanitize(src)))
        return None

    def strcat(self, dst='', src=''):
        self.helper.display('strcat("%s", "%s")' % (self.helper.sanitize(dst), self.helper.sanitize(src)))
        return None

    def sprintf(self, dst, fmt=''):
        string = self.idasim.vsprintf(fmt, 2)
        self.helper.display('sprintf(0x%X, "%s")' % (dst, self.helper.sanitize(string)))
        return None

    def system(self, cmd=''):
        self.helper.display('system("%s")' % self.helper.sanitize(cmd))
        return None

    def popen(self, cmd='', attrib=''):
        self.helper.display('popen("%s", "%s")' % (self.helper.sanitize(cmd), self.helper.sanitize(attrib)))
        return None

    def strncpy(self, dst, src='', n=0):
        if len(src) >= n:
            self.helper.display('strncpy(0x%X, "%s", %d)' % (dst, self.helper.sanitize(src), n))
        return None

    def strncat(self, dst='', src='', n=0):
        self.helper.display('strncat("%s", "%s", %d)' % (self.helper.sanitize(dst), self.helper.sanitize(src), n))

    def snprintf(self, dst, size, fmt=''):
        string = self.idasim.vsprintf(fmt, 3)
        if len(string) >= size:
            self.helper.display('snprintf(0x%X, %d, "%s")' % (dst, size, self.helper.sanitize(string)))
        return None

    def printf(self, fmt=''):
        if '%' not in fmt:
            self.helper.display('printf("%s")' % self.helper.sanitize(fmt))
        return None

    def fprintf(self, fd, fmt=''):
        if '%' not in fmt:
            self.helper.display('fprintf(%d, "%s")' % (fd, self.helper.sanitize(fmt)))
        return None

