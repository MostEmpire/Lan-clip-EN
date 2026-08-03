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
        import net_utils
        webbrowser.open(net_utils.format_url('127.0.0.1', self.port))

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
        9560'), otherwise a generic '<IPv4/IPv6> adapter' fallback.

        HTTPS addresses are listed first: browsers only allow one-click copy and
        paste in a secure context, so that's what a phone wants. The plain HTTP
        entries stay below for devices that would rather skip the certificate
        warning (the app's CA can be installed from /ca.crt to remove it)."""
        import net_utils
        import mdns_service
        import tls_service
        try:
            names = net_utils.get_adapter_names()
        except Exception:
            names = {}
        mdns_host = f"{mdns_service.hostname()}.local" if mdns_service.is_active() else None
        ips = net_utils.get_host_ips()
        entries = []
        if tls_service.is_active():
            if mdns_host:
                entries.append((tls_service.url(mdns_host),
                                "HTTPS - mDNS name (may not work on Android)", mdns_host))
            for ip, version in ips:
                url = tls_service.url(ip, ipv6=(version == 'IPv6'))
                entries.append((url, f"HTTPS - {names.get(ip) or version + ' adapter'}", ip))
        if mdns_host:
            entries.append((mdns_service.url(self.port),
                            "mDNS name (may not work on Android)", mdns_host))
        for ip, version in ips:
            url = net_utils.format_url(ip, self.port, ipv6=(version == 'IPv6'))
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

    def _show_mdns_settings(self, icon, item):
        """Open the mDNS settings popup (centered). Same single-window threading
        pattern as the QR popup: pystray owns the main thread, Tk gets its own."""
        import mdns_service

        if getattr(self, '_mdns_thread', None) and self._mdns_thread.is_alive():
            return  # already open
        mdns_service.recheck()  # verify now, so the verdict on screen is current
        self._mdns_thread = threading.Thread(target=self._mdns_window_worker, daemon=True)
        self._mdns_thread.start()

    def _mdns_window_worker(self):
        try:
            import tkinter as tk
            from tkinter import ttk
        except Exception as e:
            print(f"mDNS window unavailable (tkinter missing): {e}")
            return
        import mdns_service

        BG, CARD, FG, ACCENT, MUTED = "#1e1e1e", "#2a2a2a", "#ffffff", "#9fd0ff", "#aaaaaa"
        OK_GREEN, ERR_RED = "#7ee787", "#ff6b6b"

        root = tk.Tk()
        root.title("Lan-clip - mDNS")
        root.configure(bg=BG)
        root.withdraw()  # stay hidden until centered, so it never flashes at the default position

        def add_copy_menu(widget, get_all):
            """Right-click > Copy: the selection if there is one, else the full text."""
            menu = tk.Menu(widget, tearoff=0, bg=CARD, fg=FG,
                           activebackground="#3a3a3a", activeforeground=FG)

            def do_copy():
                try:
                    text = widget.selection_get()
                except Exception:
                    text = get_all()
                root.clipboard_clear()
                root.clipboard_append(text)

            menu.add_command(label="Copy", command=do_copy)
            widget.bind("<Button-3>", lambda e: menu.tk_popup(e.x_root, e.y_root))

        tk.Label(root, text="mDNS network name", fg=FG, bg=BG,
                 font=("Segoe UI", 12, "bold")).pack(pady=(16, 4), padx=24)
        # Read-only Entry instead of Label so the URL can be selected and copied.
        # All variables get an explicit master: with two Tk instances in this
        # process (QR window + this one), an unbound StringVar can attach to the
        # other window's interpreter and the widget then shows nothing.
        url_var = tk.StringVar(master=root, value=mdns_service.url(self.port))
        url_entry = tk.Entry(root, textvariable=url_var, state="readonly", justify="center",
                             readonlybackground=BG, fg=ACCENT, relief="flat", bd=0,
                             highlightthickness=0, font=("Consolas", 13))
        url_entry.pack(pady=(0, 2), padx=24, fill="x")
        add_copy_menu(url_entry, url_var.get)
        ip_var = tk.StringVar(master=root, value="")
        ip_entry = tk.Entry(root, textvariable=ip_var, state="readonly", justify="center",
                            readonlybackground=BG, fg=MUTED, relief="flat", bd=0,
                            highlightthickness=0, font=("Segoe UI", 9))
        ip_entry.pack(pady=(0, 12), padx=24, fill="x")
        add_copy_menu(ip_entry, ip_var.get)

        # Prefix editor: [entry].local  [Save]
        row = tk.Frame(root, bg=BG)
        row.pack(padx=24)
        entry = tk.Entry(row, width=16, bg=CARD, fg=FG, insertbackground=FG,
                         relief="flat", font=("Consolas", 12), justify="right")
        entry.insert(0, mdns_service.hostname())
        entry.pack(side="left", ipady=4)
        tk.Label(row, text=".local", fg=MUTED, bg=BG,
                 font=("Consolas", 12)).pack(side="left", padx=(2, 12))

        # Source adapter: the name resolves to exactly one adapter's IP
        tk.Label(root, text="Advertised adapter", fg=MUTED, bg=BG,
                 font=("Segoe UI", 9)).pack(pady=(12, 2))
        adapter_options = mdns_service.available_adapters()  # [(label, value), ...]
        adapter_lookup = dict(adapter_options)
        current_label = adapter_options[0][0]
        for label, value in adapter_options:
            if value == mdns_service.adapter():
                current_label = label
                break
        adapter_var = tk.StringVar(master=root, value=current_label)
        # ttk.Combobox instead of tk.OptionMenu: on Windows the OptionMenu
        # menubutton renders as a themed gray box that swallows the styling (and
        # sometimes the text). The clam theme is the one that honors dark colors.
        style = ttk.Style(root)
        style.theme_use('clam')
        style.configure('Dark.TCombobox', fieldbackground=CARD, background=CARD,
                        foreground=FG, arrowcolor=FG, bordercolor=CARD,
                        lightcolor=CARD, darkcolor=CARD, insertcolor=FG)
        style.map('Dark.TCombobox',
                  fieldbackground=[('readonly', CARD)],
                  foreground=[('readonly', FG)],
                  selectbackground=[('readonly', CARD)],
                  selectforeground=[('readonly', FG)])
        root.option_add('*TCombobox*Listbox.background', CARD)
        root.option_add('*TCombobox*Listbox.foreground', FG)
        root.option_add('*TCombobox*Listbox.selectBackground', '#3a3a3a')
        root.option_add('*TCombobox*Listbox.selectForeground', FG)
        dropdown = ttk.Combobox(root, textvariable=adapter_var, state='readonly',
                                values=[label for label, _ in adapter_options],
                                style='Dark.TCombobox', font=("Segoe UI", 9))
        dropdown.pack(padx=24, fill="x", ipady=2)

        feedback = tk.Label(root, text="", fg=MUTED, bg=BG, wraplength=380,
                            justify="center", font=("Segoe UI", 9))
        feedback.pack(pady=(6, 10), padx=24)

        status_lbl = tk.Label(root, text="", bg=BG, font=("Segoe UI", 12, "bold"))
        status_lbl.pack(pady=(2, 2))
        # Problem details; packed/unpacked dynamically by refresh_status. A disabled
        # Text (not a Label) so the message - e.g. the netsh fix command - can be
        # selected and copied.
        detail = tk.Text(root, bg=CARD, fg=FG, wrap="word", relief="flat", bd=0,
                         highlightthickness=0, font=("Segoe UI", 9), width=54, height=3,
                         padx=10, pady=8, state="disabled", cursor="arrow")
        add_copy_menu(detail, lambda: detail.get("1.0", "end-1c"))

        def set_detail(msg):
            """Replace the detail text and grow the widget to fit it."""
            detail.config(state="normal")
            detail.delete("1.0", "end")
            detail.insert("1.0", msg)
            detail.config(state="disabled")
            # Estimate wrapped lines from text length; Text.count('displaylines')
            # is unreliable before the widget is mapped (counts ~1 char per line).
            lines = sum(max(1, len(line) // 52 + 1) for line in (msg.splitlines() or ['']))
            detail.config(height=max(2, min(lines + 1, 14)))

        close_btn = tk.Button(root, text="Close", command=root.destroy, bg="#3a3a3a", fg=FG,
                              relief="flat", padx=18, pady=6, cursor="hand2")

        last = {'detail': None}

        def refresh_status():
            state, msg = mdns_service.status()
            if state == 'ok':
                status_lbl.config(text="All OK", fg=OK_GREEN)
            elif state == 'checking':
                status_lbl.config(text="Checking...", fg=MUTED)
            else:
                status_lbl.config(text="Problem", fg=ERR_RED)
            if state == 'problem' and msg:
                if msg != last['detail']:  # don't wipe the user's selection every tick
                    last['detail'] = msg
                    set_detail(msg)
                detail.pack(pady=(4, 4), padx=24, fill="x", before=close_btn)
            else:
                last['detail'] = None
                detail.pack_forget()
            # Setting a textvariable clears any selection; only update on change
            new_url = mdns_service.url(self.port)
            if url_var.get() != new_url:
                url_var.set(new_url)
            ip = mdns_service.advertised_ip()
            new_ip = f"resolves to {ip}" if ip else "not advertising"
            if ip_var.get() != new_ip:
                ip_var.set(new_ip)
            root.after(1000, refresh_status)

        save_result = []  # set_hostname blocks ~1-2s (re-registration); run off the UI thread

        def poll_save():
            if not save_result:
                root.after(200, poll_save)
                return
            ok, msg = save_result.pop()
            feedback.config(text=msg, fg=(OK_GREEN if ok else ERR_RED))
            save_btn.config(state="normal")

        def do_save():
            prefix = entry.get()
            adapter_choice = adapter_lookup.get(adapter_var.get())
            save_btn.config(state="disabled")
            feedback.config(text="Saving...", fg=MUTED)
            threading.Thread(
                target=lambda: save_result.append(mdns_service.set_settings(prefix, adapter_choice)),
                daemon=True).start()
            poll_save()

        save_btn = tk.Button(row, text="Save", command=do_save, bg="#3a3a3a", fg=FG,
                             relief="flat", padx=14, pady=4, cursor="hand2")
        save_btn.pack(side="left")
        close_btn.pack(pady=(10, 16))

        root.bind("<Escape>", lambda e: root.destroy())
        entry.bind("<Return>", lambda e: do_save())
        refresh_status()

        # Center on screen (position only - the window grows if details appear)
        root.update_idletasks()
        x = max(0, (root.winfo_screenwidth() - root.winfo_reqwidth()) // 2)
        y = max(0, (root.winfo_screenheight() - root.winfo_reqheight()) // 2)
        root.geometry(f"+{x}+{y}")
        root.deiconify()
        root.lift()
        root.attributes("-topmost", True)
        root.after(400, lambda: root.attributes("-topmost", False))
        root.mainloop()

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
        # Send mDNS goodbye packets before the hard exit (os._exit skips atexit)
        import mdns_service
        mdns_service.stop()
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
            item('mDNS', self._show_mdns_settings),
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
