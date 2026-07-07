"""Advertise the web server over mDNS so LAN devices can reach it by name.

Registers `<prefix>.local` (default clip.local) as the host of a `_http._tcp`
DNS-SD service via python-zeroconf, which then answers A queries for the name
from any device on the LAN. Combined with the server preferring port 80, this
makes the app reachable at plain http://clip.local/.

The prefix is user-configurable (tray menu > mDNS) and persisted in
mdns_config.json next to the other runtime config files.

Degrades to a no-op when the zeroconf package is missing or registration
fails, so the app never hard-depends on it.

Client support: Windows 10+, macOS/iOS, and Linux with avahi/nss-mdns resolve
.local names natively; Android browsers generally do not — keep the IP/QR
access paths around for those.
"""
import atexit
import json
import os
import re
import socket
import subprocess
import sys
import threading

import net_utils

CONFIG_FILE = 'mdns_config.json'
DEFAULT_HOSTNAME = "clip"   # advertised as clip.local
SERVICE_NAME = "Lan-clip"   # shown in DNS-SD service browsers

_lock = threading.Lock()
_zeroconf = None
_info = None
_port = None
_start_error = None
_atexit_registered = False
_reach_warnings = None  # None = self-check still running; [] = no issues found


def _valid_hostname(name):
    """Single DNS label: 1-63 chars of a-z, 0-9 and hyphens, no edge hyphens."""
    return bool(re.fullmatch(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?', name or ''))


def _load_hostname():
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            name = (json.load(f).get('hostname') or '').strip().lower()
        if _valid_hostname(name):
            return name
    except Exception:
        pass
    return DEFAULT_HOSTNAME


_hostname = _load_hostname()


def hostname():
    """The current mDNS prefix, e.g. 'clip' for clip.local."""
    return _hostname


def url(port):
    """The URL the mDNS name resolves to, e.g. http://clip.local/ on port 80."""
    return net_utils.format_url(f"{_hostname}.local", port)


def is_active():
    return _zeroconf is not None


def status():
    """Snapshot for UI display: ('ok'|'checking'|'problem', detail_message)."""
    if _zeroconf is None:
        return 'problem', _start_error or "mDNS advertising is not active."
    w = _reach_warnings
    if w is None:
        return 'checking', "Checking firewall / network configuration..."
    if w:
        return 'problem', w[0]
    return 'ok', ""


def set_hostname(prefix):
    """Validate and persist a new mDNS prefix; re-advertise live if active.

    Returns (ok, message). Blocks for the mDNS re-registration probe (~1-2 s)
    when the responder is running, so call it off the UI thread.
    """
    global _hostname
    prefix = (prefix or '').strip().lower()
    if not _valid_hostname(prefix):
        return False, ("Invalid name: use 1-63 letters, digits or hyphens "
                       "(no spaces, no leading/trailing hyphen).")
    if prefix == _hostname:
        return True, "Name unchanged."

    was_active = is_active()
    if was_active:
        stop()
    _hostname = prefix
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump({'hostname': prefix}, f)
    except Exception as e:
        print(f"[mDNS] Could not save {CONFIG_FILE}: {e}")

    if was_active and _port is not None:
        if not start(_port):
            return False, f"Saved, but re-advertising {prefix}.local failed."
        return True, f"Saved. Advertising {url(_port)}"
    return True, "Saved."


def _windows_firewall_warnings():
    """Inspect Windows Firewall via the HNetCfg.FwPolicy2 COM API.

    The failure mode this catches: the responder binds fine locally, but the
    firewall drops inbound UDP 5353 from the LAN, so only this machine can
    resolve the name. Clicking 'Cancel' on the first-run prompt even creates
    explicit BLOCK rules for the program, which beat any allow rule.
    """
    import pythoncom
    import win32com.client

    UDP, ANY_PROTOCOL = 17, 256
    DIR_IN, ACTION_ALLOW = 1, 1

    # No matching CoUninitialize: the COM objects live until this short-lived
    # thread's interpreter references drop, and uninitializing the apartment
    # first makes their release spew "Win32 exception occurred" noise.
    pythoncom.CoInitialize()
    fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
    active = fw.CurrentProfileTypes
    if not any(fw.FirewallEnabled(p) for p in (1, 2, 4) if active & p):
        return []  # firewall is off for the active network profile(s)

    exe = sys.executable or ''
    exe_cmp = os.path.normcase(exe)
    allow = block = False
    for rule in fw.Rules:
        try:
            if not rule.Enabled or rule.Direction != DIR_IN:
                continue
            if os.path.normcase(rule.ApplicationName or '') != exe_cmp:
                continue
            if rule.Protocol not in (UDP, ANY_PROTOCOL):
                continue
            ports = rule.LocalPorts if rule.Protocol == UDP else '*'
            if ports in ('*', '', None) or '5353' in str(ports).split(','):
                if rule.Action == ACTION_ALLOW:
                    allow = True
                else:
                    block = True
        except Exception:
            continue  # some rules expose partial COM properties

    if block:
        return [f"Windows Firewall has an inbound BLOCK rule for this program ({exe}) - "
                "probably from clicking 'Cancel' on the connection prompt. Other devices cannot "
                f"resolve {_hostname}.local or reach the app. Fix: Windows Security > Firewall & "
                "network protection > Allow an app through firewall > tick this program (all "
                "profiles), or delete its block rules."]
    if not allow:
        return [f"No inbound Windows Firewall rule found for this program ({exe}). Windows should "
                "show a permission prompt on first run - click 'Allow'. To pre-authorize from an "
                'admin console: netsh advfirewall firewall add rule name="Lan-clip mDNS" dir=in '
                f'action=allow protocol=UDP localport=5353 program="{exe}"']
    return []


def _macos_firewall_warnings():
    sf = '/usr/libexec/ApplicationFirewall/socketfilterfw'
    if not os.path.exists(sf):
        return []

    def _out(*args):
        return subprocess.run([sf, *args], capture_output=True, text=True).stdout.lower()

    if 'enabled' not in _out('--getglobalstate'):
        return []  # application firewall is off (macOS default)
    exe = sys.executable or ''
    if 'enabled' in _out('--getblockall'):
        return [f"The macOS firewall is set to 'Block all incoming connections' - other devices cannot "
                f"resolve {_hostname}.local or reach the app. Disable block-all in System Settings > "
                "Network > Firewall > Options."]
    if 'blocked' in _out('--getappblocked', exe):
        return [f"The macOS firewall blocks incoming connections for {exe}. Allow it with: sudo {sf} "
                f"--add \"{exe}\" && sudo {sf} --unblockapp \"{exe}\" (or System Settings > Network > "
                "Firewall > Options)."]
    return []


def _linux_firewall_warnings():
    if os.path.exists('/.dockerenv'):
        return [f"Running inside Docker: multicast does not cross the default bridge network, so "
                f"{_hostname}.local is invisible to the LAN. Run the container with --network host."]

    import shutil
    warnings = []
    if shutil.which('ufw'):
        r = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
        if r.returncode == 0 and 'status: active' in r.stdout.lower() and '5353' not in r.stdout:
            warnings.append(f"ufw is active with no rule for mDNS - other devices cannot resolve "
                            f"{_hostname}.local. Allow it with: sudo ufw allow 5353/udp")
    if shutil.which('firewall-cmd'):
        r = subprocess.run(['firewall-cmd', '--query-service=mdns'], capture_output=True, text=True)
        blob = (r.stdout + r.stderr).lower()
        if r.returncode != 0 and 'not running' not in blob and 'no' in blob:
            warnings.append(f"firewalld is active without the mdns service - other devices cannot "
                            f"resolve {_hostname}.local. Allow it with: sudo firewall-cmd "
                            "--permanent --add-service=mdns && sudo firewall-cmd --reload")
    return warnings


def _check_reachability():
    """Populate _reach_warnings; never raises (a failed self-check is not an error)."""
    global _reach_warnings
    try:
        if sys.platform == 'win32':
            warnings = _windows_firewall_warnings()
        elif sys.platform == 'darwin':
            warnings = _macos_firewall_warnings()
        else:
            warnings = _linux_firewall_warnings()
    except Exception as e:
        print(f"[mDNS] Reachability self-check failed: {e}")
        warnings = []
    _reach_warnings = warnings
    for w in warnings:
        print(f"[mDNS] WARNING: {w}")


def start(port):
    """Register <prefix>.local pointing at this machine's LAN IPv4 addresses.

    Blocks for the mDNS probe (~1s); returns True when the name is being
    advertised. Requires inbound UDP 5353 through the firewall to answer
    queries (the standard first-run firewall prompt covers this).
    """
    global _zeroconf, _info, _port, _start_error, _atexit_registered
    _port = port
    try:
        from zeroconf import ServiceInfo, Zeroconf
    except ImportError:
        _start_error = f"The 'zeroconf' package is not installed - {_hostname}.local is disabled."
        print(f"[mDNS] {_start_error}")
        return False

    addresses = []
    for ip, version in net_utils.get_host_ips():
        if version == "IPv4" and ip != "127.0.0.1":
            try:
                addresses.append(socket.inet_pton(socket.AF_INET, ip))
            except OSError:
                pass
    if not addresses:
        _start_error = f"No LAN IPv4 address found - {_hostname}.local is disabled."
        print(f"[mDNS] {_start_error}")
        return False

    with _lock:
        if _zeroconf is not None:
            return True
        try:
            info = ServiceInfo(
                "_http._tcp.local.",
                f"{SERVICE_NAME}._http._tcp.local.",
                addresses=addresses,
                port=port,
                server=f"{_hostname}.local.",
                properties={"path": "/"},
            )
            zc = Zeroconf()
            zc.register_service(info)
        except Exception as e:
            _start_error = f"Could not advertise {_hostname}.local: {e}"
            print(f"[mDNS] {_start_error}")
            return False
        _zeroconf, _info = zc, info
        _start_error = None

    if not _atexit_registered:
        atexit.register(stop)
        _atexit_registered = True
    print(f"[mDNS] Advertising {url(port)}")
    # Registration only proves we bound the socket; whether OTHER devices can
    # query us depends on the OS firewall. Check in the background (the COM /
    # subprocess probes can take a few seconds) and report what to fix.
    threading.Thread(target=_check_reachability, daemon=True).start()
    return True


def stop():
    """Unregister the name and shut the responder down; safe to call twice.

    Called explicitly from the tray Exit handlers because they terminate via
    os._exit(), which skips atexit hooks — without the goodbye packets the
    stale name would linger in peers' mDNS caches.
    """
    global _zeroconf, _info
    with _lock:
        zc, info = _zeroconf, _info
        _zeroconf = _info = None
    if zc is None:
        return
    try:
        if info is not None:
            zc.unregister_service(info)
        zc.close()
    except Exception:
        pass
