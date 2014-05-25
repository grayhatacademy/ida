import os
import time
import idc
import idaapi
import idautils

class LibC(object):
    '''
    Class containing simulators for various common libc functions.
    '''

    __IDASIM_DEFAULT_HANDLER_CLASS__ = True

    def __init__(self, idasim=None):
        '''
        Class constructor.
        '''
        self.idasim = idasim

    def sleep(self, t):
        time.sleep(t)
        return 0

    def atoi(self, string=''):
        return int(string)

    def atol(self, string=''):
        return self.atoi(string)

    def atoll(self, string=''):
        return self.atoi(string)

    def atoq(self, string=''):
        return self.atoi(string)

    def strlen(self, string=''):
        return len(string)

    def getenv(self, envar=''):
        return os.getenv(envar) + "\x00"

    def malloc(self, n):
        return "\x00" * n

    def memset(self, buf, c, n):
        idc.DbgWrite(buf, (chr(c) * n))
        return buf

    def memcpy(self, dst, src, n):
        idc.DbgWrite(dst, idc.GetManyBytes(src, n, use_dbg=False))
        return dst

    def strcpy(self, dst, src=''):
        '''
        Monitors, reports and simulates the strcpy function.
        '''
        print 'strcpy(0x%X, "%s")' % (dst, src)
        idc.DbgWrite(dst, src + "\x00")
        return dst

    def strcat(self, dst, src=''):
        '''
        Monitors, reports and simulates the strcat function.
        '''
        print 'strcat(0x%X, "%s")' % (dst, src)
        addr = dst + len(idc.GetString(dst))
        idc.DbgWrite(addr, src + "\x00")
        return dst

    def strncpy(self, dst, src='', n=0):
        idc.DbgWrite(dst, src + "\x00", length=n)
        return dst

    def strncat(self, dst, src='', n=0):
        addr = dst + len(idc.GetString(dst))
        idc.DbgWrite(addr, src + "\x00", length=n)
        return dst

    def strdup(self, string=''):
        return string + "\x00"

    def strcmp(self, s1='', s2=''):
        if s1 == s2:
            return 0
        else:
            return 1

    def strncmp(self, s1='', s2='', n=0):
        if s1[:n] == s2[:n]:
            return 0
        else:
            return 1

    def memcmp(self, dp1, dp2, n):
        d1 = idc.DbgRead(dp1, n)
        d2 = idc.DbgRead(dp2, n)
    
        if d1 == d2:
            return 0
        else:
            return 1

    def memchr(self, dp, c, n):
        c = chr(c)
        data = idc.DbgRead(dp, n)
        
        offset = data.find(c)

        if offset == -1:
            return 0
        else:
            return dp + offset

    def system(self, command=''):
        '''
        Displays the system() command, does not execute.
        '''
        print '0x%X : system("%s");' % (self.idasim.cpu.ReturnAddress(), command)
        return 0

    def strstr(self, hayptr, needle=''):
        haystack = idc.GetString(hayptr)
        offset = haystack.find(needle)
        
        if offset == -1:
            return 0
        else:
            return hayptr + offset

    def strchr(self, hayptr, needle):
        haystack = idc.GetString(hayptr)
        needle = chr(needle)
        offset = haystack.find(needle)
        
        if offset == -1:
            return 0
        else:
            return hayptr + offset

    def daemon(self):
        '''
        Fakes a daemon(), returns 0.
        '''
        return 0

    def fork(self):
        '''
        Fakes a fork(), always returns 0.
        '''
        return 0
    
    def free(self, address):
        '''
        Frees heap data not allocated by IDASimulator.
        '''
        if self.idasim.mmu.allocated_addresses.has_key(address):
            return 0
        else:
            return None

    def strtol(self, string='', base=0):
        return int(string, base)

    def strtoul(self, string='', base=0):
        return self.strtol(string, base)
    
    def strtod(self, string='', base=0):
        return self.strtod(string, base)

    def strcasecmp(self, s1='', s2=''):
        if s1.lower() == s2.lower():
            return 0
        else:
            return 1

    def strncasecmp(self, s1='', s2='', n=0):
        if s1[:n].lower() == s2[:n].lower():
            return 0
        else:
            return 1
    
    def exit(self, code):
        '''
        Prints exit code and stops debugger.
        '''
        print "Exit code:", code
        idc.StopDebugger()

    def setgroups(self):
        '''
        Fakes setgroups(), returns 0.
        '''
        return 0

