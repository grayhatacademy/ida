import os
import sys
import idc

class Stdio(object):
    '''
    Class containing simulators for common stdio functions.
    '''

    __IDASIM_DEFAULT_HANDLER_CLASS__ = True

    def __init__(self, sim=None):
        '''
        Class constructor.
        '''
        if sim is not None:
            self.mmu = sim.mmu
            self.cpu = sim.cpu
            self.sim = sim

        self.file_descriptors = {
                0 : sys.stdin,
                1 : sys.stdout,
                2 : sys.stderr,
        }

    def _next_fd(self):
        i = 0
        while self.file_descriptors.has_key(i):
            i += 1
        return i

    def _add_fd(self, fp):
        fd = self._next_fd()
        self.file_descriptors[fd] = fp
        return fd

    def _close(self, fd):
        if self.file_descriptors.has_key(fd):
            self.file_descriptors[fd].close()
            del self.file_descriptors[fd]

    def _open(self, fname, mode="rwb"):
        try:
            fp = open(fname, mode)
            fd = self._add_fd(fp)
        except:
            fd = -1

        return fd

    def _read(self, fd, size):
        data = ""
        if self.file_descriptors.has_key(fd):
            data = self.file_descriptors[fd].read(size)
        return data

    def _write(self, fd, data):
        if self.file_descriptors.has_key(fd):
            self.file_descriptors[fd].write(data)
        return len(data)

    def puts(self, string=''):
        print string
        return 0

    def printf(self, fmt=''):
        print self.sim.vsprintf(fmt, 1),
        return 0

    def syslog(self, i, fmt=''):
        print self.sim.vsprintf(fmt, 2)
        return 0

    def fprintf(self, fd, fmt=''):
        formatted_string = self.sim.vsprintf(fmt, 2)

        if self.file_descriptors.has_key(fd) and fd != 0:
            self._write(fd, formatted_string)
        else:
            print formatted_string,
        return 0

    def sprintf(self, dst, fmt=''):
        '''
        Monitors, reports and simulates sprintf.
        '''
        data = self.sim.vsprintf(ftm, 2)
        print 'sprintf(0x%X, "%s")' % (dst, data)
        idc.DbgWrite(dst, data + "\x00")
        return len(data)

    def snprintf(self, dst, n, fmt=''):
        idc.DbgWrite(dst, self.sim.vsprintf(fmt, 3)[:n] + "\x00")
        return dst

    def popen(self, command='', mode=''):
        '''
        Displays the popen() command, does not execute.
        '''
        print '0x%X : popen("%s", "%s");' % (self.cpu.ReturnAddress(), command, mode)
        #fp = os.popen(command, mode)
        #return self._add_fd(fp)
        return 0

    def pclose(self, fd):
        self._close(fd)
        return 0

    def fopen(self, fname='', modes=''):
        fd = self._open(fname, modes)
        if fd > -1:
            return fd
        else:
            return 0
    
    def fclose(self, fd):
        self._close(fd)
        return 0

    def fread(self, ptr, size, nmemb, fd):
        data = self._read(fd, (size * nmemb))
        idc.DbgWrite(ptr, data)
        return len(data)

    def fwrite(self, ptr, size, nmemb, fd):
        data = idc.DbgRead(ptr, (size * nmemb))
        self._write(fd, data)
        return len(data)

    def fflush(self, fd):
        if self.file_descriptors.has_key(fd):
            self.file_descriptors[fd].flush()
        return 0

    def fgets(self, dst, size, fd):
        if self.file_descriptors.has_key(fd):
            while not data.endswith('\n') and len(data) < (size-1):
                data += self._read(fd, 1)

            data += "\x00"
            idc.DbgWrite(dst, data, len(data))

        return dst

    def fseek(self, fd, offset, whence):
        if self.file_descriptors.has_key(fd):
            self.file_descriptors[fd].seek(offset, whence)
            return self.file_descriptors[fd].tell()
        return -1

    def rewind(self, fd):
        if self.file_descriptors.has_key(fd):
            self.file_descriptors[fd].seek(0, 0)
        return 0

    def ftell(self, fd):
        if self.file_descriptors.has_key(fd):
            return self.file_descriptors[fd].tell()
        return -1


