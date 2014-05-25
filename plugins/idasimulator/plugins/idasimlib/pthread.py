
class PThread(object):

    __IDASIM_DEFAULT_HANDLER_CLASS__ = True

    def __init__(self, idasim):
        self.idasim = idasim

    def pthread_create(self, thread, attr, start_routine, arg):
        '''
        Calls the start_routine, does not create a thread.
        '''
        self.idasim.app.Call(start_routine, arguments=[arg], block_until_return=False)
        return None
