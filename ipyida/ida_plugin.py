# -*- encoding: utf8 -*-
#
# IDA plugin definition.
#
# Copyright (c) 2015-2018 ESET
# Author: Marc-Etienne M.Léveillé <leveille@eset.com>
# See LICENSE file for redistribution.

import os
import sys

import idaapi

from ipyida.utils import *
from ipyida import ida_qtconsole, kernel

#-----------------------------------------------------------------------------
# IDA Plugin
#-----------------------------------------------------------------------------

def PLUGIN_ENTRY():
    return IPyIDAPlugIn()

class IPyIDAPlugIn(idaapi.plugin_t):

    # plugin info
    wanted_name = "IPyIDA"
    wanted_hotkey = "Shift-."
    comment = ""
    help = "Starts an IPython console in IDA Pro"

    # load/unload the plugin with IDB's
    flags = idaapi.PLUGIN_PROC
    
    def init(self):
        """
        An IDB is opening, load the plugin.
        """
        self.kernel = kernel.IPythonKernel()
        self.kernel.start()
        
        self.widget = ida_qtconsole.IPythonConsole(self, self.kernel.connection_file)

        self._startup_hooks = UIHooks()
        self._startup_hooks.ready_to_run = self._ready_to_run
        self._startup_hooks.hook()

        # Save a reference to this plugin in the module, so it can be accessed
        # TODO: remove?
        import ipyida
        ipyida._PLUGIN = self

        return idaapi.PLUGIN_KEEP

    def run(self, _):
        """
        Handle plugin hotkey activation.
        """
        if not self.widget:
            self.widget = ida_qtconsole.IPythonConsole(self, self.kernel.connection_file)
            self.widget.Show()
        else:
            self.widget.setFocusToPrompt()

    def term(self):
        """
        The IDB is closing, unload the plugin.
        """

        # Cleanup the console widget
        if self.widget:
            self.widget.Close(0)
            self.widget = None

        # Spin down the IPython kernel
        if self.kernel:
            self.kernel.stop()
            self.kernel = None

    def _ready_to_run(self):
        """
        Callback executed when the IDA UI has setteled upon IDB load.
        """
        self._startup_hooks.unhook()
        self.widget.Show()

#-----------------------------------------------------------------------------
# IDA Startup
#-----------------------------------------------------------------------------

def _setup_asyncio_event_loop():
    """
    Links Qt's event loop with asyncio's event loop. This allows asyncio to
    work properly, which is required for ipykernel >= 5 (more specifically,
    because ipykernel uses tornado, which is backed by asyncio).
    """
    if not (USING_PY3 and kernel.is_using_ipykernel_5()):
        return

    from PyQt5.QtWidgets import QApplication
    import qasync
    import asyncio

    if isinstance(asyncio.get_event_loop(), qasync.QEventLoop):
        print("Note: qasync event loop already set up.")
    else:
        qapp = QApplication.instance()
        loop = qasync.QEventLoop(qapp, already_running=True)
        asyncio.set_event_loop(loop)

# run immediately when IDA loads
_setup_asyncio_event_loop()
monkey_patch_IDAPython_ExecScript()
