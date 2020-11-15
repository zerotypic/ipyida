import os
import sys
import ctypes

import idaapi

#-----------------------------------------------------------------------------
# Shim Definitions
#-----------------------------------------------------------------------------

USING_PY3 = sys.version_info[0] == 3
USING_IDA7API = bool(idaapi.IDA_SDK_VERSION >= 700)

# PyQt5 is in IDA 6.9 and above
try:
    import PyQt5
    from PyQt5 import QtGui, QtWidgets
    USING_PYQT5 = True

# PySide for older versions of IDA
except ImportError:
    import PySide
    from PySide import QtGui
    QtWidgets = QtGui
    USING_PYQT5 = False

#-----------------------------------------------------------------------------
# IDA Misc
#-----------------------------------------------------------------------------

def monkey_patch_IDAPython_ExecScript():
    """
    This funtion wraps IDAPython_ExecScript to avoid having an empty string has
    a __file__ attribute of a module.

    See https://github.com/idapython/src/pull/23
    """

    # Test the behavior IDAPython_ExecScript see if it needs patching
    fake_globals = {}
    if USING_IDA7API:
        idaapi.IDAPython_ExecScript(os.devnull, fake_globals, False)
    else:
        idaapi.IDAPython_ExecScript(os.devnull, fake_globals)

    if "__file__" in fake_globals:
        # Monkey patch IDAPython_ExecScript
        original_IDAPython_ExecScript = idaapi.IDAPython_ExecScript
        def IDAPython_ExecScript_wrap(script, g, print_error=True):
            has_file = "__file__" in g
            try:
                if USING_IDA7API:
                    original_IDAPython_ExecScript(script, g, print_error)
                else:
                    original_IDAPython_ExecScript(script, g)
            finally:
                if not has_file and "__file__" in g:
                    del g["__file__"]
        idaapi.IDAPython_ExecScript = IDAPython_ExecScript_wrap
        try:
            # Remove the empty strings on existing modules
            for mod_name in sys.modules:
                if hasattr(sys.modules[mod_name], "__file__") and \
                   bool(sys.modules[mod_name].__file__) is False:
                    del sys.modules[mod_name].__file__
        except RuntimeError:
            # Best effort here, let's not crash if something goes wrong
            pass

#-----------------------------------------------------------------------------
# IDA Hook Compatability
#-----------------------------------------------------------------------------

# ui hooks
if USING_IDA7API:

    class UIHooks(idaapi.UI_Hooks):
        def ready_to_run():
            pass

# compatability for older versions of IDA
else:

    class UIHooks(object):
        """
        A minimal ctypes-based UI Hook for older versions of idapython.

        Adapted from: https://gist.github.com/williballenthin/b5e7a80691ed5e44e7fea1964bae18dc 
        """
 
        HT_UI = 1 

        def __init__(self):
            self._dll = get_ida_ctypes()
            self._handler = None
            self.ready_to_run = lambda: None

        def hook(self):
            """
            Hook IDA's HT_UI event stream.
            """
            hook_to_notification_point = self._dll.hook_to_notification_point
            hook_to_notification_point.argtypes = [
                ctypes.c_int,      # hook_type_t hook_type
                HookCb,            # hook_cb_t  *cb
                ctypes.c_void_p,   # void       *user_data
            ]

            def handler(_, event_id, args):
                if event_id == 95: # ui_ready_to_run in kernwin.hpp
                    self.ready_to_run()
                return 0

            self._handler = HookCb(handler)
            hook_to_notification_point(self.HT_UI, self._handler, None)

        def unhook(self):
            """
            Unhook from IDA's HT_UI event stream.
            """
            if not self._handler:
                return

            unhook_from_notification_point = self._dll.unhook_from_notification_point
            unhook_from_notification_point.argtypes = [
                ctypes.c_int,      # hook_type_t hook_type
                HookCb,            # hook_cb_t  *cb
                ctypes.c_void_p,   # void       *user_data
            ]

            unhook_from_notification_point(self.HT_UI, self._handler, None)
            self._handler = None

    def get_ida_ctypes():
        '''
        get the ida sdk dll.

        Args: None
        Returns:
          ctypes.CDLL: the IDA SDK DLL

        via: http://www.hexblog.com/?p=695
        '''
        running_ida64 = idaapi.BADADDR == 0xFFFFFFFFFFFFFFFF
        idaname = 'ida64' if running_ida64 else 'ida'

        if sys.platform == 'win32':
            return ctypes.windll[idaname + '.wll']
        elif sys.platform == 'linux2':
            return ctypes.cdll['lib' + idaname + '.so']
        elif sys.platform == 'darwin':
            return ctypes.cdll['lib' + idaname + '.dylib']
        else:
            raise RuntimeError('unknown platform: ' + sys.platform)

    # typedef int idaapi hook_cb_t(void *user_data, int notification_code, va_list va);
    HookCb = ctypes.WINFUNCTYPE(
        # return type
        ctypes.c_int,      # int idaapi

        # argument types
        ctypes.c_void_p,   # void       *user_data
        ctypes.c_int,      # int         notification_code
        ctypes.c_void_p,   # va_list     va 
    )