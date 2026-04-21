import sys
import time
import threading
import platform

if platform.system() == "Darwin":
    import objc
    from Foundation import NSRunLoop
    from Cocoa import NSWorkspace

class DeviceMonitor:
    def __init__(self, callback):
        self.callback = callback
        self.running = False
        self.thread = None

    def start(self):
        if platform.system() == "Darwin":
            self.running = True
            self.thread = threading.Thread(target=self._run_mac)
            self.thread.daemon = True
            self.thread.start()
        # Add elif for Windows/Linux if needed

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()

    def _run_mac(self):
        workspace = NSWorkspace.sharedWorkspace()
        nc = workspace.notificationCenter()
        nc.addObserver_selector_name_object_(
            self, self.deviceDidMount_, "NSWorkspaceDidMountNotification", None
        )
        while self.running:
            NSRunLoop.currentRunLoop().runUntilDate_(time.time() + 0.5)

    def deviceDidMount_(self, notification):
        device_info = notification.userInfo()
        self.callback(device_info)

# Usage example:
# def on_device_attached(info):
#     print("Device attached:", info)
# monitor = DeviceMonitor(on_device_attached)
# monitor.start()
