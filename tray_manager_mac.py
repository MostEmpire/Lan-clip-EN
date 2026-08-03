# alias lc="nohup python3 /Users/shrimppipi/Documents/Github/Lan-clip-master/app.py --tray  > /dev/null 2>&1 &"

import os
import sys
import webbrowser
import threading
import json
from PIL import Image, ImageDraw

# GUI deps (pyobjc's AppKit, pystray) may be missing when running from source.
# An import failure must not kill the process: app.py imports this module on
# macOS even for web-only (--no-tray) runs, so tray mode just becomes unavailable.
try:
    import AppKit # Import the native macOS library

    # Tell macOS: I am a background app, do not show an icon in the Dock!
    AppKit.NSApplication.sharedApplication().setActivationPolicy_(1)

    import pystray
    from pystray import MenuItem as item, Menu
except ImportError as e:
    print(f"Tray unavailable ({e}). Install with: pip3 install pystray pyobjc-framework-Cocoa")
    AppKit = None
    pystray = None
    item = None
    Menu = None

from clipboard_service import ClipboardMonitor

CONFIG_FILE = 'tray_config.json'

class TrayManager:
    def __init__(self, port, icon_path):
        self.port = port
        self.icon_path = icon_path
        self.monitor = ClipboardMonitor(port)
        
        # Load config
        self.config = self._load_config()
        self._listener_enabled = self.config.get('listener_enabled', False)
        self._threshold_mb = self.config.get('threshold_mb', 10)
        self._compress_enabled = self.config.get('compress_enabled', False)

        # Initialize the monitor
        self.monitor.set_max_size(self._threshold_mb)
        self.monitor.set_compression(self._compress_enabled, 80)
        if self._listener_enabled:
            self.monitor.start()

        # Icon handling
        self.base_image = self._load_base_image()
        self.active_image = self._create_active_image(self.base_image)

    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def _save_config(self):
        config = {
            'listener_enabled': self._listener_enabled,
            'threshold_mb': self._threshold_mb,
            'compress_enabled': self._compress_enabled
        }
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config, f)
        except Exception as e:
            print(f"Failed to save config: {e}")

    def _load_base_image(self):
        try:
            # A macOS menu bar icon is best as monochrome (black) with an alpha channel; the system inverts colors automatically
            img = Image.open(self.icon_path).convert('RGBA')
            # Resize to fit the menu bar
            return img.resize((64, 64))
        except Exception as e:
            print(f"Failed to load icon: {e}")
            # Return a default blue square
            return Image.new('RGBA', (64, 64), (100, 100, 255, 200))

    def _create_active_image(self, base_img):
        # Draw a green dot in the top-right corner of the icon to indicate listening is active
        active_img = base_img.copy()
        draw = ImageDraw.Draw(active_img)
        margin = 4
        dot_size = 18
        # Draw the green dot
        draw.ellipse([64 - dot_size - margin, margin, 64 - margin, margin + dot_size], 
                     fill=(0, 255, 0, 255), outline=(255, 255, 255, 255), width=2)
        return active_img

    def _get_current_icon(self):
        return self.active_image if self._listener_enabled else self.base_image

    # --- Core macOS change: use subprocess to open folders ---
    def _open_folder(self, folder_name):
        def action(icon, item):
            path = os.path.join(os.path.abspath("."), folder_name)
            if not os.path.exists(path):
                try:
                    os.makedirs(path)
                except:
                    pass
            
            if os.path.exists(path):
                # macOS uses the 'open' command
                os.system(f'open "{path}"')
        return action

    def _open_browser(self, icon, item):
        import net_utils
        webbrowser.open(net_utils.format_url('127.0.0.1', self.port))

    def _show_mdns_settings(self, icon, item):
        """Open the mDNS settings dialog.

        Cocoa rather than Tk: on macOS every UI call must happen on the main
        thread, and pystray already owns it with the AppKit run loop, so the
        Windows approach (a Tk window in a side thread) would crash here. The
        work is queued onto the main queue so it runs on the right thread no
        matter which thread pystray dispatched the menu action on.
        """
        if AppKit is None:
            print("mDNS settings need AppKit (pip3 install pyobjc-framework-Cocoa)")
            return
        AppKit.NSOperationQueue.mainQueue().addOperationWithBlock_(self._mdns_dialog)

    def _mdns_status_text(self, mdns_service, notice=None):
        """The dialog body: address, what it resolves to, and the verdict."""
        state, detail = mdns_service.status()
        lines = []
        if notice:
            lines += [notice, ""]
        lines.append(mdns_service.url(self.port))
        ip = mdns_service.advertised_ip()
        lines.append(f"resolves to {ip}" if ip else "not advertising")
        lines.append("")
        lines.append({'ok': "All OK", 'checking': "Checking..."}.get(state, "Problem"))
        if state == 'problem' and detail:
            lines.append(detail)
        return "\n".join(lines)

    def _mdns_dialog(self):
        import mdns_service

        notice = None
        try:
            while True:
                adapters = mdns_service.available_adapters()  # [(label, value), ...]
                alert = AppKit.NSAlert.alloc().init()
                alert.setMessageText_("Lan-clip - mDNS")
                alert.setInformativeText_(self._mdns_status_text(mdns_service, notice))
                alert.addButtonWithTitle_("Save")
                alert.addButtonWithTitle_("Re-check")
                alert.addButtonWithTitle_("Close")

                # Frames as ((x, y), (w, h)) tuples: pyobjc converts those to NSRect,
                # so this doesn't depend on NSMakeRect being re-exported by AppKit.
                view = AppKit.NSView.alloc().initWithFrame_(((0, 0), (380, 76)))
                name_field = AppKit.NSTextField.alloc().initWithFrame_(((0, 46), (180, 24)))
                name_field.setStringValue_(mdns_service.hostname())
                suffix = AppKit.NSTextField.alloc().initWithFrame_(((186, 50), (80, 18)))
                suffix.setStringValue_(".local")
                suffix.setBezeled_(False)
                suffix.setDrawsBackground_(False)
                suffix.setEditable_(False)
                suffix.setSelectable_(False)
                popup = AppKit.NSPopUpButton.alloc().initWithFrame_pullsDown_(
                    ((0, 8), (380, 26)), False)
                current = mdns_service.adapter()
                for index, (label, value) in enumerate(adapters):
                    popup.addItemWithTitle_(label)
                    if value == current:
                        popup.selectItemAtIndex_(index)
                view.addSubview_(name_field)
                view.addSubview_(suffix)
                view.addSubview_(popup)
                alert.setAccessoryView_(view)
                alert.window().setInitialFirstResponder_(name_field)

                # Accessory apps (setActivationPolicy_(1)) are not frontmost, so the
                # dialog would otherwise open behind whatever the user is looking at.
                AppKit.NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
                response = alert.runModal()

                if response == AppKit.NSAlertFirstButtonReturn:      # Save
                    chosen = popup.indexOfSelectedItem()
                    value = adapters[chosen][1] if 0 <= chosen < len(adapters) else None
                    # Blocks ~1-2s on the mDNS re-registration probe; the dialog is
                    # already dismissed at this point, so nothing looks frozen.
                    _ok, notice = mdns_service.set_settings(str(name_field.stringValue()), value)
                elif response == AppKit.NSAlertSecondButtonReturn:   # Re-check
                    mdns_service.recheck()
                    notice = "Re-checking..."
                else:
                    return
        except Exception as e:
            print(f"mDNS settings dialog failed: {e}")

    def _toggle_listener(self, icon, item):
        self._listener_enabled = not self._listener_enabled
        if self._listener_enabled:
            self.monitor.start()
        else:
            self.monitor.stop()
        # Update the icon state
        icon.icon = self._get_current_icon()
        self._save_config()

    def _toggle_compression(self, icon, item):
        self._compress_enabled = not self._compress_enabled
        self.monitor.set_compression(self._compress_enabled, 80)
        self._save_config()

    def _set_threshold(self, mb):
        def action(icon, item):
            self._threshold_mb = mb
            self.monitor.set_max_size(mb)
            self._save_config()
        return action

    def _exit(self, icon, item):
        self.monitor.stop()
        # Send mDNS goodbye packets before the hard exit (os._exit skips atexit)
        import mdns_service
        mdns_service.stop()
        icon.stop()
        os._exit(0)

    def run(self):
        # 1. Folder submenu
        folder_menu = Menu(
            item('Images folder', self._open_folder('images')),
            item('Uploads folder', self._open_folder('uploads')),
            item('Project root folder', self._open_folder('.'))
        )

        # 2. Threshold submenu
        threshold_menu = Menu(
            item('5 MB', self._set_threshold(5), checked=lambda _: self._threshold_mb == 5),
            item('10 MB', self._set_threshold(10), checked=lambda _: self._threshold_mb == 10),
            item('20 MB', self._set_threshold(20), checked=lambda _: self._threshold_mb == 20),
            item('50 MB', self._set_threshold(50), checked=lambda _: self._threshold_mb == 50),
        )

        # 3. Main menu
        menu = Menu(
            item('Open browser', self._open_browser),
            item('mDNS', self._show_mdns_settings),
            item('Browse local files', folder_menu),
            pystray.Menu.SEPARATOR,
            item('Listening mode (on/off)', self._toggle_listener, checked=lambda _: self._listener_enabled),
            item('Enable image compression', self._toggle_compression, checked=lambda _: self._compress_enabled),
            item('Sync threshold', threshold_menu),
            pystray.Menu.SEPARATOR,
            item('Exit', self._exit)
        )

        # 4. Create and run the icon
        # On macOS the title parameter is shown as menu bar text (optional)
        self.icon = pystray.Icon(
            "Lan-clip",
            self._get_current_icon(),
            "Lan-clip clipboard sync",
            menu
        )

        print("✅ Tray icon started...")
        self.icon.run()

def start_tray(port, icon_path):
    if pystray is None:
        # Tray deps are missing but the web server (background thread) still works;
        # block forever so the daemon server thread isn't killed by process exit.
        print("Running without tray icon; the web server stays available.")
        threading.Event().wait()
    tray = TrayManager(port, icon_path)
    tray.run()