# -*- encoding: utf8 -*-
#
# This module integreate a qtconsole to the IDA GUI.
# See README.adoc for more details.
#
# Copyright (c) 2015-2018 ESET
# Author: Marc-Etienne M.Léveillé <leveille@eset.com>
# See LICENSE file for redistribution.

import os
import sys
import types

import idaapi

USING_PY3 = sys.version_info[0] == 3
USING_IDA7API = bool(idaapi.IDA_SDK_VERSION >= 700)

# IDA 6.95+
try:
    import PyQt5
    from PyQt5 import QtGui, QtWidgets
    USING_PYQT5 = True

# < IDA 6.90
except ImportError:
    import PySide
    from PySide import QtGui
    QtWidgets = QtGui
    USING_PYQT5 = False

# QtSvg binairies are not bundled with IDA. So we monkey patch PySide to avoid
# IPython to load a module with missing binary files. This *must* happend before
# importing RichJupyterWidget
if USING_PYQT5:
    try:
        # In the case of pyqt5, we have to avoid patch the binding detection
        # used in qtconsole <= 4.6.
        import qtconsole.qt_loaders
        original_has_binding = qtconsole.qt_loaders.has_binding
        def hooked_has_bindings(arg):
            if arg == 'pyqt5':
                return True
            else:
                return original_has_binding(arg)
        qtconsole.qt_loaders.has_binding = hooked_has_bindings
    except ImportError:
        # qtconsole.qt_loaders doesn't exist in qtconsole >= 4.7. It uses QtPy.
        os.environ["QT_API"] = "pyqt5"
    sys.modules["PyQt5.QtSvg"] = types.ModuleType("EmptyQtSvg")
    sys.modules["PyQt5.QtPrintSupport"] = types.ModuleType("EmptyQtPrintSupport")

# PySide
else:
    sys.modules["PySide.QtSvg"] = types.ModuleType("EmptyQtSvg")
    sys.modules["PySide.QtPrintSupport"] = types.ModuleType("EmptyQtPrintSupport")
    os.environ["QT_API"] = "pyside"

from qtconsole.rich_jupyter_widget import RichJupyterWidget
from qtconsole.manager import QtKernelManager
from qtconsole.client import QtKernelClient
from jupyter_client import find_connection_file

import ipyida.kernel

class IdaRichJupyterWidget(RichJupyterWidget):

    def __init__(self, ida_console, *args, **kwargs):
        super(IdaRichJupyterWidget, self).__init__(*args, **kwargs)
        # Store a reference to the containing IPythonConsole
        self._ida_console = ida_console
    #enddef

    def _keyboard_quit(self):
        # If the input buffer is empty, and the escape key was pressed,
        # return focus to the widget that was originally holding focus
        # before the IPython console took over.
        prev_widget = self._ida_console.prev_focus_widget
        if self.input_buffer == "" and prev_widget != None:
            if USING_IDA7API:
                idaapi.activate_widget(prev_widget, True)
            else:
                idaapi.switchto_tform(prev_widget, True)
            self._ida_console.prev_focus_widget = None
        else:
            super(IdaRichJupyterWidget, self)._keyboard_quit()

class IdaRichJupyterWidget4(IdaRichJupyterWidget):
    def _is_complete(self, source, interactive):
        # The original implementation in qtconsole is synchronous. IDA Python is
        # single threaded and the IPython kernel runs on the same thread as the
        # UI so the is_complete request can never be processed by the kernel,
        # which results in always returning (False, '') and having to to
        # <Shift-Enter> to execute a command.
        #
        # Our solution here was to copy the original _is_complete and call the
        # kernel's do_one_iteration before expecting a reply. Original implemetation is in:
        # https://github.com/jupyter/qtconsole/blob/4.3.1/qtconsole/frontend_widget.py#L260
        try:
            from queue import Empty
        except ImportError:
            from Queue import Empty
        kc = self.blocking_client
        if kc is None:
            self.log.warn("No blocking client to make is_complete requests")
            return False, u''
        msg_id = kc.is_complete(source)
        MAX_RETRY_COUNT = 5
        retry_count = 0
        is_complete_timeout = self.is_complete_timeout / float(MAX_RETRY_COUNT)
        while True:
            try:
                ipyida.kernel.do_one_iteration()
                reply = kc.shell_channel.get_msg(block=True, timeout=is_complete_timeout)
            except Empty:
                ipyida.kernel.do_one_iteration()
                if retry_count < MAX_RETRY_COUNT:
                    retry_count += 1
                    continue
                else:
                    # assume incomplete output if we get no reply in time
                    return False, u''
            if reply['parent_header'].get('msg_id', None) == msg_id:
                status = reply['content'].get('status', u'complete')
                indent = reply['content'].get('indent', u'')
                return status != 'incomplete', indent

_user_widget_options = {}

def set_widget_options(options):
    """"
    This function is intended to be called in ipyidarc.py to set additionnal
    options during the creation of if the RichJupyterWidget.

    Args: options is expected to be a dict

    See https://qtconsole.readthedocs.io/en/stable/config_options.html for a
    list of available options.
    """
    global _user_widget_options
    _user_widget_options = options.copy()

class IPythonConsole(idaapi.PluginForm):
    
    def __init__(self, connection_file, *args):
        super(IPythonConsole, self).__init__(*args)
        self.connection_file = connection_file
        self.prev_focus_widget = None
    
    def OnCreate(self, form):
        try:
            if USING_PYQT5:
                self.parent = self.FormToPyQtWidget(form, ctx=sys.modules[__name__])
            else:
                self.parent = self.FormToPySideWidget(form, ctx=sys.modules[__name__])
            layout = self._createConsoleWidget()
            self.parent.setLayout(layout)
        except:
            import traceback
            print(traceback.format_exc())

    def _createConsoleWidget(self):
        if USING_PYQT5:
            layout = QtWidgets.QVBoxLayout()
        else:
            layout = QtGui.QVBoxLayout()
        connection_file = find_connection_file(self.connection_file)
        self.kernel_manager = QtKernelManager(connection_file=connection_file)
        self.kernel_manager.load_connection_file()
        self.kernel_manager.client_factory = QtKernelClient
        self.kernel_client = self.kernel_manager.client()
        self.kernel_client.start_channels()

        widget_options = {}
        if sys.platform.startswith('linux'):
            # Some upstream bug crashes IDA when the ncurses completion is
            # used. I'm not sure where the bug is exactly (IDA's Qt5 bindings?)
            # but using the "droplist" instead works around the crash. The
            # problem is present only on Linux.
            # See: https://github.com/eset/ipyida/issues/8
            widget_options["gui_completion"] = 'droplist'
        widget_options.update(_user_widget_options)
        if ipyida.kernel.is_using_ipykernel_5():
            self.ipython_widget = IdaRichJupyterWidget(self, self.parent, **widget_options)
        else:
            self.ipython_widget = IdaRichJupyterWidget4(self, self.parent, **widget_options)
        self.ipython_widget.kernel_manager = self.kernel_manager
        self.ipython_widget.kernel_client = self.kernel_client
        layout.addWidget(self.ipython_widget)

        return layout

    def Show(self, name="IPython Console"):
        # Save widget that is currently focused
        if USING_IDA7API:
            self.prev_focus_widget = idaapi.get_current_widget()
        else:
            self.prev_focus_widget = idaapi.get_current_tform()
        r = idaapi.PluginForm.Show(self, name)
        self.setFocusToPrompt()
        return r

    def setFocusToPrompt(self):
        # This relies on the internal _control widget but it's the most reliable
        # way I found so far.
        if hasattr(self.ipython_widget, "_control"):
            self.ipython_widget._control.setFocus()
        else:
            print("[IPyIDA] setFocusToPrompt: Widget has no _control attribute.")

    def OnClose(self, form):
        try:
            self.kernel_client.stop_channels()
        except:
            import traceback
            print(traceback.format_exc())

