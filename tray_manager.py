import os
import io
import webbrowser
import threading
import sys
import json
from PIL import Image, ImageDraw

try:
    if sys.platform == 'win32':
        import pystray
        from pystray import MenuItem as item, Menu
    else:
        # Provide empty mocks for non-Windows environments (e.g. Docker)
        pystray = None
        item = None
        Menu = None
except ImportError:
    pystray = None
    item = None
    Menu = None

from clipboard_service import ClipboardMonitor

# Config file path
CONFIG_FILE = 'tray_config.json'

class TrayManager:
    def __init__(self, port, icon_path):
        self.port = port
        self.icon_path = icon_path
        self.monitor = ClipboardMonitor(port)
        self.icon = None
        
        # Load config
        self.config = self._load_config()
        self._listener_enabled = self.config.get('listener_enabled', False)
        self._threshold_mb = self.config.get('threshold_mb', 10)
        self._compress_enabled = self.config.get('compress_enabled', False) # No compression by default

        # Initialize monitor settings
        self.monitor.set_max_size(self._threshold_mb)
        self.monitor.set_compression(self._compress_enabled, 80)
        
        if self._listener_enabled:
            self.monitor.start()

        # Icon cache
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
            img = Image.open(self.icon_path).convert('RGBA')
            return img.resize((64, 64))
        except Exception as e:
            print(f"Failed to load icon: {e}")
            return Image.new('RGBA', (64, 64), (100, 100, 255, 255))

    def _create_active_image(self, base_img):
        active_img = base_img.copy()
        draw = ImageDraw.Draw(active_img)
        margin = 4
        dot_size = 18
        draw.ellipse([64 - dot_size - margin, margin, 64 - margin, margin + dot_size], 
                     fill=(0, 255, 0, 255), outline=(255, 255, 255, 255), width=2)
        return active_img

    def _get_current_icon(self):
        return self.active_image if self._listener_enabled else self.base_image

    def _update_icon(self):
        if self.icon:
            self.icon.icon = self._get_current_icon()

    def _open_browser(self, icon, item):
        webbrowser.open(f'http://127.0.0.1:{self.port}')

    def _show_qr_codes(self, icon, item):
        """Open a popup listing a QR code per active network adapter so phones can
        scan the right address. Runs the Tk window in its own thread because pystray
        owns the main thread; a single window is kept at a time."""
        if getattr(self, '_qr_thread', None) and self._qr_thread.is_alive():
            return  # already open
        self._qr_thread = threading.Thread(target=self._qr_window_worker, daemon=True)
        self._qr_thread.start()

    def _build_server_urls(self):
        """Return [(url, label, ip), ...] for every active adapter. `label` is the
        real adapter name when the OS can provide it (e.g. 'Intel(R) Wireless-AC
        9560'), otherwise a generic '<IPv4/IPv6> adapter' fallback."""
        import net_utils
        try:
            names = net_utils.get_adapter_names()
        except Exception:
            names = {}
        entries = []
        for ip, version in net_utils.get_host_ips():
            if version == 'IPv6':
                url = f"http://[{ip}]:{self.port}"
            else:
                url = f"http://{ip}:{self.port}"
            label = names.get(ip) or f"{version} adapter"
            entries.append((url, label, ip))
        return entries

    @staticmethod
    def _qr_pil_image(url, size=200):
        """Render `url` to a square RGB PIL image. Go through a PNG buffer so we
        don't depend on the qrcode image-factory's internal representation."""
        import qrcode
        buf = io.BytesIO()
        qrcode.make(url).save(buf, format='PNG')
        buf.seek(0)
        return Image.open(buf).convert('RGB').resize((size, size))

    def _qr_window_worker(self):
        try:
            import tkinter as tk
            from PIL import ImageTk
        except Exception as e:
            print(f"QR window unavailable (tkinter/PIL missing): {e}")
            return

        try:
            entries = self._build_server_urls()
        except Exception as e:
            print(f"Could not enumerate network adapters: {e}")
            entries = []

        BG, CARD, FG, ACCENT, MUTED = "#1e1e1e", "#2a2a2a", "#ffffff", "#9fd0ff", "#aaaaaa"

        root = tk.Tk()
        root.title("Lan-clip - Scan to connect")
        root.configure(bg=BG)
        root.withdraw()  # stay hidden until sized + centered, so it never flashes at the default position
        root._imgs = []  # keep PhotoImage refs alive (Tk doesn't hold them)

        # Scrollable column so a machine with many adapters can't overflow the screen.
        container = tk.Frame(root, bg=BG)
        container.pack(fill="both", expand=True)
        canvas = tk.Canvas(container, bg=BG, highlightthickness=0, width=320)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw", width=320)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-e.delta / 120), "units"))

        tk.Label(inner, text="Scan a code to open Lan-clip", fg=FG, bg=BG,
                 font=("Segoe UI", 12, "bold")).pack(pady=(14, 6), padx=20)

        if not entries:
            tk.Label(inner, text="No active network adapters found.", fg="#ff6b6b", bg=BG,
                     wraplength=280, justify="center").pack(pady=20, padx=20)
        for url, label, ip in entries:
            try:
                photo = ImageTk.PhotoImage(self._qr_pil_image(url))
            except Exception as e:
                print(f"Failed to render QR for {url}: {e}")
                continue
            root._imgs.append(photo)
            cell = tk.Frame(inner, bg=CARD)
            cell.pack(pady=8, padx=20, fill="x")
            tk.Label(cell, image=photo, bg=CARD).pack(pady=(10, 4))
            tk.Label(cell, text=label, fg=FG, bg=CARD, font=("Segoe UI", 9, "bold"),
                     wraplength=260, justify="center").pack()
            tk.Label(cell, text=url, fg=ACCENT, bg=CARD, font=("Consolas", 10)).pack(pady=(0, 10))

        tk.Button(inner, text="Close", command=root.destroy, bg="#3a3a3a", fg=FG,
                  relief="flat", padx=18, pady=6, cursor="hand2").pack(pady=(6, 16))

        # Easy to dismiss: Close button, Esc, or the window's X.
        root.bind("<Escape>", lambda e: root.destroy())

        # Size to content (capped to screen height), reveal, then center using the
        # *outer* window rect. Centering by the client size alone leaves it a
        # title-bar-height too low and a border too far right.
        root.update_idletasks()
        w = 360
        sh = root.winfo_screenheight()
        h = max(200, min(inner.winfo_reqheight() + 4, int(sh * 0.85)))
        root.geometry(f"{w}x{h}")
        root.deiconify()
        root.update_idletasks()
        try:
            import ctypes
            user32 = ctypes.windll.user32
            frame = user32.GetAncestor(root.winfo_id(), 2)  # GA_ROOT = the decorated window

            class _RECT(ctypes.Structure):
                _fields_ = [("l", ctypes.c_long), ("t", ctypes.c_long),
                            ("r", ctypes.c_long), ("b", ctypes.c_long)]

            rc = _RECT()
            user32.GetWindowRect(frame, ctypes.byref(rc))
            ow, oh = rc.r - rc.l, rc.b - rc.t
            sw, sh2 = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
            user32.MoveWindow(frame, max(0, (sw - ow) // 2), max(0, (sh2 - oh) // 2), ow, oh, True)
        except Exception:
            # Non-Windows / failure: center by client size (good enough).
            x = max(0, (root.winfo_screenwidth() - root.winfo_width()) // 2)
            y = max(0, (sh - root.winfo_height()) // 2)
            root.geometry(f"+{x}+{y}")
        root.lift()
        root.attributes("-topmost", True)
        root.after(400, lambda: root.attributes("-topmost", False))
        try:
            root.mainloop()
        finally:
            try:
                canvas.unbind_all("<MouseWheel>")
            except Exception:
                pass

    def _open_folder(self, folder_name):
        def inner(icon, item):
            path = os.path.join(os.path.abspath("."), folder_name)
            if not os.path.exists(path):
                try:
                    os.makedirs(path)
                except:
                    pass
            if os.path.exists(path):
                os.startfile(path)
        return inner

    def _toggle_listener(self, icon, item):
        self._listener_enabled = not self._listener_enabled
        if self._listener_enabled:
            self.monitor.start()
        else:
            self.monitor.stop()
        self._update_icon()
        self._save_config()

    def _toggle_compression(self, icon, item):
        self._compress_enabled = not self._compress_enabled
        self.monitor.set_compression(self._compress_enabled, 80)
        self._save_config()

    def _set_threshold(self, mb):
        def inner(icon, item):
            self._threshold_mb = mb
            self.monitor.set_max_size(mb)
            self._save_config()
        return inner

    def _exit(self, icon, item):
        self.monitor.stop()
        icon.stop()
        os._exit(0)

    def run(self):
        # Folder submenu
        folder_menu = Menu(
            item('Images folder (pasted images)', self._open_folder('images')),
            item('Uploads folder (file/web uploads)', self._open_folder('uploads')),
            item('Project root folder', self._open_folder('.'))
        )

        # Threshold submenu
        threshold_menu = Menu(
            item('5 MB', self._set_threshold(5), checked=lambda _: self._threshold_mb == 5),
            item('10 MB', self._set_threshold(10), checked=lambda _: self._threshold_mb == 10),
            item('20 MB', self._set_threshold(20), checked=lambda _: self._threshold_mb == 20),
            item('50 MB', self._set_threshold(50), checked=lambda _: self._threshold_mb == 50),
            item('100 MB', self._set_threshold(100), checked=lambda _: self._threshold_mb == 100),
        )

        # Create menu
        menu = (
            item('Open browser', self._open_browser),
            item('Show QR codes', self._show_qr_codes),
            item('Browse local files', folder_menu),
            Menu.SEPARATOR,
            item('Listening mode (on if icon has green dot)', self._toggle_listener, checked=lambda item: self._listener_enabled),
            item('Enable clipboard image compression (80% quality)', self._toggle_compression, checked=lambda item: self._compress_enabled),
            item('Sync threshold limit', threshold_menu),
            Menu.SEPARATOR,
            item('Exit', self._exit)
        )

        # Create tray icon
        self.icon = pystray.Icon(
            "Lan-clip",
            self._get_current_icon(),
            "Lan-clip clipboard sync",
            menu
        )

        # Show the QR-codes popup once at startup. The old console builds printed the
        # scan codes at launch; windowed/tray builds surface them here instead so users
        # still get the addresses up front. (Opens in its own thread; non-blocking.)
        self._show_qr_codes(None, None)

        self.icon.run()

def start_tray(port, icon_path):
    tray = TrayManager(port, icon_path)
    tray.run()
