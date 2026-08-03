"""Advertise the web server over mDNS so LAN devices can reach it by name.

Registers `<prefix>.local` (default clip.local) as the host of a `_http._tcp`
DNS-SD service via python-zeroconf, which then answers A queries for the name
from any device on the LAN. Combined with the server preferring port 80, this
makes the app reachable at plain http://clip.local/.

The prefix and the source adapter are user-configurable (tray menu > mDNS)
and persisted in mdns_config.json next to the other runtime config files.
Only ONE adapter's IPv4 is advertised: machines routinely carry virtual
adapters (VirtualBox/VMware host-only, hotspot/ICS, VPN) whose addresses are
unreachable from the LAN, and a client that picks such an A record fails to
connect. Default is the primary adapter (the one holding the default route).

zeroconf enumerates the interfaces once, when the responder is constructed, and
binds one socket per address; it never rebinds. So a DHCP change, a different
Wi-Fi network or a sleep/resume leaves the responder listening on addresses that
no longer exist - silently deaf on the current network, still handing out the old
IP. A watchdog thread therefore re-registers whenever the machine's addresses
change or the name stops answering on the interface we advertise.

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
import struct
import subprocess
import sys
import threading
import time

import net_utils

CONFIG_FILE = 'mdns_config.json'
DEFAULT_HOSTNAME = "clip"   # advertised as clip.local
SERVICE_NAME = "Lan-clip"   # shown in DNS-SD service browsers

MCAST_GROUP = '224.0.0.251'
MDNS_PORT = 5353
_HEALTH_TICK = 5            # seconds between watchdog polls
_PROBE_TICKS = 6            # polls between end-to-end self-probes (30 s)
_PROBE_BACKOFF_TICKS = 120  # ... once re-registering has stopped helping (10 min)

_lock = threading.Lock()
_zeroconf = None
_info = None
_port = None
_start_error = None
_atexit_registered = False
_reach_warnings = None  # None = self-check still running; [] = no issues found
_advertised_ip = None   # the single IPv4 the name currently resolves to
_advert_note = None     # set when the configured adapter was unavailable (fallback)
_watch_thread = None    # health watchdog (see _health_loop)
_watch_stop = threading.Event()
_restart_lock = threading.Lock()  # serializes a re-registration against shutdown
_bound_ips = frozenset()    # the machine's IPv4s as of the last (re-)registration
_probe_countdown = _PROBE_TICKS
_deaf_restarts = 0
_restarting = False     # True during the brief teardown/re-register window


def _valid_hostname(name):
    """Single DNS label: 1-63 chars of a-z, 0-9 and hyphens, no edge hyphens."""
    return bool(re.fullmatch(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?', name or ''))


def _load_config():
    """Returns (hostname, adapter). adapter is an adapter description (or the
    bare IP for adapters the OS can't name); None means auto (primary)."""
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        data = {}
    name = (data.get('hostname') or '').strip().lower()
    if not _valid_hostname(name):
        name = DEFAULT_HOSTNAME
    return name, (data.get('adapter') or None)


_hostname, _adapter = _load_config()


def _save_config():
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump({'hostname': _hostname, 'adapter': _adapter}, f)
    except Exception as e:
        print(f"[mDNS] Could not save {CONFIG_FILE}: {e}")


def hostname():
    """The current mDNS prefix, e.g. 'clip' for clip.local."""
    return _hostname


def adapter():
    """The configured source adapter (description or IP), None = auto."""
    return _adapter


def advertised_ip():
    """The single IPv4 the name currently resolves to (None when inactive)."""
    return _advertised_ip


def available_adapters():
    """[(display_label, value), ...] for the settings UI; first entry is Auto.

    `value` is the adapter description when the OS provides one (stable across
    DHCP renewals), else the bare IP; None stands for auto (primary adapter).
    """
    try:
        names = net_utils.get_adapter_names()
    except Exception:
        names = {}
    options = [("Auto (primary adapter)", None)]
    # include_virtual: a VM/VPN adapter is rarely the right answer, but the point
    # of this list is to let the user override when it is.
    for ip, version in net_utils.get_host_ips(include_virtual=True):
        if version != 'IPv4' or ip == '127.0.0.1':
            continue
        desc = names.get(ip)
        options.append((f"{desc} ({ip})" if desc else ip, desc or ip))
    return options


def _pick_address():
    """(ip, note): the single IPv4 to advertise. Honors the configured adapter,
    falling back to the primary (default-route) adapter when it has no IP."""
    # get_host_ips orders best-first (default route, then real adapters, then
    # virtual ones), so ipv4s[0] is the right automatic choice and the right
    # fallback when a configured adapter has gone away.
    ipv4s = [ip for ip, v in net_utils.get_host_ips(include_virtual=True)
             if v == "IPv4" and ip != "127.0.0.1"]
    if not ipv4s:
        return None, None
    if _adapter:
        try:
            names = net_utils.get_adapter_names()
        except Exception:
            names = {}
        for ip in ipv4s:
            if _adapter in (names.get(ip), ip):
                return ip, None
        return ipv4s[0], (f"The configured adapter '{_adapter}' has no active IP right now - "
                          f"advertising the primary adapter ({ipv4s[0]}) instead.")
    return ipv4s[0], None  # get_host_ips puts the default-route IP first


def url(port):
    """The URL the mDNS name resolves to, e.g. http://clip.local/ on port 80."""
    return net_utils.format_url(f"{_hostname}.local", port)


def is_active():
    return _zeroconf is not None


def status():
    """Snapshot for UI display: ('ok'|'checking'|'problem', detail_message)."""
    if _zeroconf is None:
        if _restarting:  # a second-long gap, not a failure worth alarming about
            return 'checking', "Re-registering the name after a network change..."
        return 'problem', _start_error or "mDNS advertising is not active."
    w = _reach_warnings
    if w is None:
        return 'checking', "Checking firewall / network configuration..."
    if w:
        return 'problem', "\n\n".join(w)
    return 'ok', ""


def recheck():
    """Re-run the reachability self-check in the background (the settings popup
    calls this when it opens, so the verdict on screen is current, not from
    whenever the responder last started)."""
    global _reach_warnings
    if _zeroconf is None:
        return
    _reach_warnings = None
    threading.Thread(target=_check_reachability, daemon=True).start()


def set_settings(prefix, adapter_choice):
    """Validate and persist prefix + source adapter; re-advertise live if active.

    adapter_choice: a value from available_adapters() (None = auto).
    Returns (ok, message). Blocks for the mDNS re-registration probe (~1-2 s)
    when the responder is running, so call it off the UI thread.
    """
    global _hostname, _adapter, _deaf_restarts, _restarting
    prefix = (prefix or '').strip().lower()
    if not _valid_hostname(prefix):
        return False, ("Invalid name: use 1-63 letters, digits or hyphens "
                       "(no spaces, no leading/trailing hyphen).")
    if prefix == _hostname and adapter_choice == _adapter:
        return True, "Settings unchanged."

    was_active = is_active()
    _restarting = was_active  # keep the status line calm during the swap
    try:
        if was_active:
            _stop_responder()  # not stop(): the watchdog stays up across a settings change
        _hostname, _adapter = prefix, adapter_choice
        _deaf_restarts = 0  # an explicit settings change deserves a fresh set of retries
        _save_config()

        if was_active and _port is not None:
            if not start(_port):
                return False, f"Saved, but re-advertising {prefix}.local failed."
            return True, f"Saved. Advertising {url(_port)} -> {_advertised_ip}"
        return True, "Saved."
    finally:
        _restarting = False


def _local_ipv4s():
    """The machine's current LAN IPv4 addresses; empty when it has none."""
    try:
        # include_virtual: the advertised adapter may be one of those, and its
        # address changing has to trigger a re-registration like any other.
        return frozenset(ip for ip, v in net_utils.get_host_ips(include_virtual=True)
                         if v == 'IPv4' and ip != '127.0.0.1')
    except Exception:
        return frozenset()


def _encode_name(name):
    return b''.join(bytes([len(l)]) + l.encode() for l in name.split('.') if l) + b'\x00'


def _skip_name(data, off):
    """Advance past a DNS name, which is either labels ending in a 0 byte or a
    two-byte pointer into an earlier name."""
    while True:
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length


def _a_records(data):
    """The IPv4 addresses carried by an mDNS response packet."""
    qd, an, ns, ar = struct.unpack('!4H', data[4:12])
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4  # question: name + qtype + qclass
    found = set()
    for _ in range(an + ns + ar):
        off = _skip_name(data, off)
        rtype, _cls, _ttl, rdlen = struct.unpack('!2HIH', data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            found.add(socket.inet_ntoa(data[off:off + 4]))
        off += rdlen
    return found


def _self_query(ip, timeout=1.5):
    """Ask the network for <prefix>.local through `ip`'s interface and return the
    set of IPv4 answers, or None when the probe itself could not run.

    This is the only check that proves the responder is actually working:
    registration success merely means a socket was bound, and the firewall
    inspection only reads rules. Multicast loops back on the local host, so our
    own responder receives this question and answers it; silence means we are no
    longer listening on that interface. The question carries the QU (unicast
    response) bit, so the answer comes back to an ephemeral port - no second
    socket on 5353 and no interference with the responder.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.settimeout(0.3)
        query = (struct.pack('!6H', 0, 0, 1, 0, 0, 0)          # 1 question, no flags
                 + _encode_name(f"{_hostname}.local")
                 + struct.pack('!2H', 1, 0x8001))              # type A, class IN | unicast bit
        sock.sendto(query, (MCAST_GROUP, MDNS_PORT))
    except OSError as e:
        print(f"[mDNS] Self-probe could not run on {ip}: {e}")
        if sock is not None:
            sock.close()
        return None

    answers = set()
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline and ip not in answers:
            try:
                data, _src = sock.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                if struct.unpack('!H', data[2:4])[0] & 0x8000:  # response, not a question
                    answers |= _a_records(data)
            except Exception:
                continue  # some other device's packet, shaped in a way we don't parse
    finally:
        sock.close()
    return answers


def _responding_warnings():
    """Verify end-to-end that <prefix>.local answers on the address we advertise.

    Retries a few times: the announcement can still be in flight right after
    registration, and a single dropped multicast packet is not a failure.
    """
    ip = _advertised_ip
    if not ip:
        return []
    answers = None
    for attempt in range(3):
        answers = _self_query(ip)
        if answers is None or ip in answers:
            return []  # probe unavailable, or the name resolved to us correctly
        if attempt < 2:
            time.sleep(1.0)
    if answers:
        return [f"Another device on this network answers {_hostname}.local with "
                f"{', '.join(sorted(answers))} instead of {ip}. Choose a different prefix above so "
                "the two names stop colliding."]
    return [f"{_hostname}.local is not answering queries on {ip}, so other devices cannot resolve "
            f"the name (the app itself is still reachable at its IP address). Most often the "
            "firewall blocks inbound UDP 5353 for this program - allow it in Windows Security > "
            "Firewall & network protection > Allow an app through firewall."]


def _restart(reason):
    """Register the name again from scratch.

    zeroconf binds its sockets when the Zeroconf object is built and never
    revisits them, so recovering from a network change means throwing the whole
    responder away and constructing a new one.
    """
    global _restarting
    port = _port
    print(f"[mDNS] {reason} - re-registering {_hostname}.local")
    _restarting = True
    try:
        # Under the lock, and skipped once shutdown has been asked for: otherwise a
        # stop() landing mid-restart is undone by the start() below, and the tray's
        # os._exit() then leaves the name advertised in every peer's cache.
        with _restart_lock:
            _stop_responder()
            if port is not None and not _watch_stop.is_set():
                start(port)
    finally:
        _restarting = False


def _health_probe():
    """Re-register when the responder has gone deaf on the advertised address."""
    global _probe_countdown, _deaf_restarts
    ip = _advertised_ip
    answers = _self_query(ip) if ip else None
    if answers is None or not ip or ip in answers:
        _deaf_restarts = 0
        _probe_countdown = _PROBE_TICKS
        return
    if answers:
        # Someone else is answering for the name; re-registering ours won't win
        # that argument, and _check_reachability already reports the collision.
        _probe_countdown = _PROBE_BACKOFF_TICKS
        return
    _deaf_restarts += 1
    # Two futile re-registrations mean the cause is not the interface list
    # (a firewall block, most likely) - keep retrying, but stop churning.
    _probe_countdown = _PROBE_TICKS if _deaf_restarts <= 2 else _PROBE_BACKOFF_TICKS
    _restart(f"no answer to {_hostname}.local on {ip}")


def _health_loop():
    """Watch for the two ways the responder silently stops working: the machine's
    addresses change underneath it, or it stops answering on the advertised one."""
    global _probe_countdown
    while not _watch_stop.wait(_HEALTH_TICK):
        try:
            if _zeroconf is None:
                continue
            current = _local_ipv4s()
            if current and current != _bound_ips:
                _restart(f"network addresses changed ({', '.join(sorted(current))})")
                continue
            _probe_countdown -= 1
            if _probe_countdown <= 0:
                _health_probe()
        except Exception as e:
            print(f"[mDNS] Health check error: {e}")


def _ensure_watchdog():
    global _watch_thread
    if _watch_thread is not None and _watch_thread.is_alive():
        return  # already running (this is also the no-op when called from the loop itself)
    _watch_stop.clear()
    _watch_thread = threading.Thread(target=_health_loop, daemon=True, name='mdns-health')
    _watch_thread.start()


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
    try:
        warnings = _responding_warnings() + warnings
    except Exception as e:
        print(f"[mDNS] Self-probe failed: {e}")
    if _advert_note:
        # Surface the adapter fallback in the settings popup as well
        warnings = [_advert_note] + warnings
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
    global _advertised_ip, _advert_note, _reach_warnings, _bound_ips, _probe_countdown
    _port = port
    _reach_warnings = None  # a fresh registration deserves a fresh verdict
    try:
        from zeroconf import ServiceInfo, Zeroconf
    except ImportError:
        _start_error = f"The 'zeroconf' package is not installed - {_hostname}.local is disabled."
        print(f"[mDNS] {_start_error}")
        return False

    ip, note = _pick_address()
    try:
        addresses = [socket.inet_pton(socket.AF_INET, ip)] if ip else []
    except OSError:
        addresses = []
    if not addresses:
        _start_error = f"No LAN IPv4 address found - {_hostname}.local is disabled."
        print(f"[mDNS] {_start_error}")
        return False
    if note:
        print(f"[mDNS] {note}")

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
        _advertised_ip, _advert_note = ip, note
        _bound_ips = _local_ipv4s()  # what zeroconf just bound its sockets to
        _probe_countdown = _PROBE_TICKS

    if not _atexit_registered:
        atexit.register(stop)
        _atexit_registered = True
    print(f"[mDNS] Advertising {url(port)} -> {ip}")
    # Registration only proves we bound a socket; whether OTHER devices can query
    # us depends on the OS firewall and on those sockets still matching the live
    # network. Check in the background (the COM / subprocess probes can take a few
    # seconds), report what to fix, and keep watching for changes afterwards.
    threading.Thread(target=_check_reachability, daemon=True).start()
    _ensure_watchdog()
    return True


def stop():
    """Unregister the name, stop the watchdog and shut the responder down; safe
    to call twice.

    Called explicitly from the tray Exit handlers because they terminate via
    os._exit(), which skips atexit hooks — without the goodbye packets the
    stale name would linger in peers' mDNS caches.
    """
    _watch_stop.set()
    # The lock waits out a re-registration already in flight, so the teardown is
    # the last thing that happens rather than being overtaken by it.
    with _restart_lock:
        _stop_responder()


def _stop_responder():
    """Tear down the zeroconf instance only, leaving the watchdog running (used
    by _restart, which builds a new responder immediately afterwards)."""
    global _zeroconf, _info, _advertised_ip
    with _lock:
        zc, info = _zeroconf, _info
        _zeroconf = _info = None
        _advertised_ip = None
    if zc is None:
        return
    try:
        if info is not None:
            zc.unregister_service(info)
        zc.close()
    except Exception:
        pass
