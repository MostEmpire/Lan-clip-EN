import sys
import socket
import qrcode

# Adapters created by virtualization, containers and VPN clients. Matched as
# lowercase substrings of the adapter name/description. Used only for ranking -
# see get_host_ips() - because on some hosts one of these is the real network path.
VIRTUAL_ADAPTER_HINTS = (
    'virtualbox', 'vmware', 'hyper-v', 'vethernet', 'virtual', 'docker', 'veth',
    'br-', 'lxc', 'wsl', 'loopback', 'tailscale', 'zerotier', 'wireguard', 'wg0',
    'openvpn', 'wintun', 'tap-windows', 'tun', 'utun', 'ppp', 'bluetooth',
)

# Default ranges of the same products, as a second opinion for when the name is
# uninformative - psutil on Windows reports the connection name ('Ethernet 2'),
# not the device description, so the hints above can't see what it really is.
# Also ranking only: a home network really can live on 172.18.x, and the
# default-route rule in get_host_ips() overrides both signals regardless.
VIRTUAL_SUBNET_HINTS = (
    '192.168.56.',                                  # VirtualBox host-only
    '192.168.137.',                                 # Windows ICS / Mobile hotspot
    '172.17.', '172.18.',                           # Docker default bridges
    '192.168.44.', '192.168.163.', '192.168.206.',  # VMware
    '10.211.55.', '10.37.129.',                     # Parallels
)

def format_url(host, port, ipv6=False):
    """Build an http:// URL, omitting the port when it's the HTTP default (80)."""
    hostpart = f"[{host}]" if ipv6 else host
    return f"http://{hostpart}" if port == 80 else f"http://{hostpart}:{port}"

def pick_server_port(fallback, preferred=80):
    """Return `preferred` if this machine can bind it on all interfaces, else `fallback`.

    Port 80 lets the mDNS name work without a port suffix (http://clip.local/).
    The probe bind fails when another server (e.g. IIS/http.sys) holds the port or
    when the OS treats it as privileged (Linux without CAP_NET_BIND_SERVICE)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("0.0.0.0", preferred))
        finally:
            s.close()
        return preferred
    except OSError:
        return fallback

def _windows_interfaces():
    """Windows: [(ip, version, adapter_description, is_up)] via GetAdaptersAddresses.

    Pure stdlib ctypes (no pywin32) so it bundles cleanly into a frozen build.
    This is the authoritative list - it reports every adapter the OS has, with
    its real name and link state, instead of guessing from a name lookup."""
    import ctypes
    from ctypes import wintypes

    AF_UNSPEC, AF_INET, AF_INET6 = 0, 2, 23
    GAA_FLAGS = 0x0002 | 0x0004 | 0x0008  # skip anycast, multicast, DNS servers
    ERROR_SUCCESS, ERROR_BUFFER_OVERFLOW = 0, 111
    IF_OPER_STATUS_UP = 1
    IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL = 24, 131

    class SOCKADDR(ctypes.Structure):
        _fields_ = [("sa_family", wintypes.USHORT), ("sa_data", ctypes.c_ubyte * 26)]

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [("lpSockaddr", ctypes.POINTER(SOCKADDR)), ("iSockaddrLength", ctypes.c_int)]

    class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
        pass
    IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
        ("Length", wintypes.ULONG), ("Flags", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("Address", SOCKET_ADDRESS),
        ("PrefixOrigin", ctypes.c_int), ("SuffixOrigin", ctypes.c_int), ("DadState", ctypes.c_int),
        ("ValidLifetime", wintypes.ULONG), ("PreferredLifetime", wintypes.ULONG),
        ("LeaseLifetime", wintypes.ULONG), ("OnLinkPrefixLength", ctypes.c_ubyte),
    ]

    class IP_ADAPTER_ADDRESSES(ctypes.Structure):
        pass
    IP_ADAPTER_ADDRESSES._fields_ = [
        ("Length", wintypes.ULONG), ("IfIndex", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", wintypes.ULONG),
        ("Flags", wintypes.ULONG),
        ("Mtu", wintypes.ULONG),
        ("IfType", wintypes.DWORD),
        ("OperStatus", ctypes.c_int),
    ]  # later fields omitted; we read no further than OperStatus and walk via Next

    GetAdaptersAddresses = ctypes.windll.iphlpapi.GetAdaptersAddresses
    GetAdaptersAddresses.restype = wintypes.ULONG

    found = []
    size = ctypes.c_ulong(15 * 1024)
    for _ in range(3):  # grow the buffer if the first guess was too small
        buf = ctypes.create_string_buffer(size.value)
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAGS, None,
                                   ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
                                   ctypes.byref(size))
        if ret == ERROR_BUFFER_OVERFLOW:
            continue
        if ret != ERROR_SUCCESS:
            return found
        adapter = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
        while adapter:
            a = adapter.contents
            desc = a.Description or a.FriendlyName
            is_up = (a.OperStatus == IF_OPER_STATUS_UP)
            # Loopback and tunnel adapters are virtual whatever they call themselves
            kind_virtual = a.IfType in (IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL)
            ua = a.FirstUnicastAddress
            while ua:
                sa = ua.contents.Address.lpSockaddr
                if sa:
                    fam = sa.contents.sa_family
                    raw = bytes(sa.contents.sa_data)  # bytes after the 2-byte sa_family
                    ip, version = None, None
                    if fam == AF_INET:
                        ip, version = ".".join(str(b) for b in raw[2:6]), 'IPv4'
                    elif fam == AF_INET6:
                        ip, version = socket.inet_ntop(socket.AF_INET6, raw[6:22]), 'IPv6'
                    if ip:
                        name = f"{desc} (virtual)" if (kind_virtual and desc) else desc
                        found.append((ip, version, name, is_up))
                ua = ua.contents.Next
            adapter = a.Next
        return found
    return found

def _psutil_interfaces():
    """[(ip, version, interface_name, is_up)] via psutil - the cross-platform path."""
    import psutil
    stats = psutil.net_if_stats()
    found = []
    for name, addrs in psutil.net_if_addrs().items():
        st = stats.get(name)
        is_up = getattr(st, 'isup', True)
        for a in addrs:
            version = ('IPv4' if a.family == socket.AF_INET
                       else 'IPv6' if a.family == getattr(socket, 'AF_INET6', None) else None)
            if version and getattr(a, 'address', None):
                found.append((a.address.split('%')[0], version, name, is_up))
    return found

def _command_interfaces():
    """[(ip, version, interface_name, is_up)] by asking the OS tools, for POSIX
    systems without psutil: `ip addr` on Linux, `ifconfig` on macOS/BSD."""
    import subprocess

    def _run(cmd):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout

    found = []
    try:  # Linux: "2: eth0    inet 192.168.1.10/24 brd ... scope global eth0"
        for line in _run(['ip', '-o', 'addr', 'show']).splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] in ('inet', 'inet6'):
                ip = parts[3].split('/')[0].split('%')[0]
                found.append((ip, 'IPv4' if parts[2] == 'inet' else 'IPv6',
                              parts[1].rstrip(':'), True))
        if found:
            return found
    except (OSError, subprocess.SubprocessError):
        pass

    # macOS/BSD: a flags line per interface, then indented "inet <addr> ..." lines
    name, is_up = None, True
    for line in _run(['ifconfig', '-a']).splitlines():
        if line and not line[0].isspace():
            head = line.split(':', 1)
            name = head[0].strip()
            is_up = 'UP' in (head[1] if len(head) > 1 else '')
        else:
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('inet', 'inet6') and name:
                found.append((parts[1].split('%')[0],
                              'IPv4' if parts[0] == 'inet' else 'IPv6', name, is_up))
    return found

def _hostname_interfaces():
    """Last resort: whatever the machine's own name resolves to. Gives no adapter
    names, and on Linux hosts that map their hostname to 127.0.1.1 it finds
    nothing useful - which is exactly why it is the last thing tried."""
    found = []
    for item in socket.getaddrinfo(socket.gethostname(), None):
        family, addr = item[0], item[4][0]
        if family == socket.AF_INET:
            found.append((addr, 'IPv4', None, True))
        elif family == getattr(socket, 'AF_INET6', None):
            found.append((addr.split('%')[0], 'IPv6', None, True))
    return found

def _enumerate_interfaces():
    """[(ip, version, adapter_name, is_up)] from the most authoritative source
    that works on this machine, falling back until something returns data."""
    sources = []
    if sys.platform == 'win32':
        sources.append(_windows_interfaces)
    sources += [_psutil_interfaces, _command_interfaces, _hostname_interfaces]
    for source in sources:
        try:
            found = source()
        except Exception:
            continue  # tool missing, import failed, unparsable output - try the next
        if found:
            return found
    return []

def _is_virtual_adapter(name):
    """True for adapters that exist for virtualization, containers or VPNs. Their
    addresses are usually unreachable from the LAN, so they are ranked last -
    never dropped, because on some hosts one of them IS the real path out."""
    n = (name or '').lower()
    return any(hint in n for hint in VIRTUAL_ADAPTER_HINTS)

def _primary_ipv4():
    """The address the OS would use to reach the internet, i.e. the default-route
    adapter's. No packet is sent; connecting a UDP socket only sets the route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
        return None if not ip or ip.startswith('127.') or ip == '0.0.0.0' else ip
    except OSError:
        return None
    finally:
        s.close()

def get_adapter_names():
    """Best-effort map of {ip_string: human-readable adapter name}, cross-platform.

    Windows gives device descriptions ('Intel(R) Wireless-AC 9560'), POSIX gives
    interface names ('en0', 'eth0'). Returns {} when no source could name them;
    callers fall back to a generic label.
    """
    names = {}
    for ip, _version, name, _is_up in _enumerate_interfaces():
        if name and ip not in names:
            names[ip] = name
    return names

def get_host_ips(include_virtual=False):
    """Addresses a LAN client could use to reach this machine, best one first.

    Order: the default-route address, then other real adapters, then virtual ones
    (VM/container bridges, VPN tunnels) when `include_virtual` is set - the mDNS
    adapter picker asks for those so a deliberate choice stays possible.

    The default-route address is never filtered out, whatever range or adapter it
    belongs to. That single rule is what keeps the app working on networks which
    happen to use a range some virtualization product also likes (172.18.x,
    192.168.56.x): the machine's actual route to the network always wins over any
    guess made from the address itself.
    """
    primary = _primary_ipv4()
    primary_entry, real, virtual, seen = None, [], [], set()
    for ip, version, name, is_up in _enumerate_interfaces():
        if not ip or ip in seen:
            continue
        if ip == primary:
            seen.add(ip)
            primary_entry = (ip, version)
            continue
        if not is_up:
            continue
        if version == 'IPv4':
            if ip.startswith('127.'):
                continue
            link_local = ip.startswith('169.254.')
        else:
            # Only globally routable IPv6 (2000::/3); link-local needs a zone index
            # that a browser URL can't carry anyway.
            if not (ip.startswith('2') or ip.startswith('3')):
                continue
            link_local = False
        seen.add(ip)
        entry = (ip, version)
        looks_virtual = _is_virtual_adapter(name) or ip.startswith(VIRTUAL_SUBNET_HINTS)
        # Link-local addresses are real (two laptops on one cable), just a last resort.
        (virtual if link_local or looks_virtual else real).append(entry)

    ips = ([primary_entry] if primary_entry else []) + real
    if include_virtual or not ips:
        ips += virtual  # better an unusual address than none at all
    if not ips:
        ips = [("127.0.0.1", "IPv4")]
    return ips

def display_server_info(port, mdns_url=None):
    """Display the access URL and QR code in the terminal"""
    ips = get_host_ips()

    print("\n" + "╔" + "═"*60 + "╗")
    print(f"║  Lan-clip service started, listening on port: {port:<31} ║")
    print("╚" + "═"*60 + "╝")

    if mdns_url:
        print(f"\n▶ [mDNS] Access URL: {mdns_url}")
        print("  (Works on Windows / macOS / iOS / most Linux; Android usually cannot resolve .local names)")

    if not ips:
        print(f"Local access: {format_url('127.0.0.1', port)}")

    for ip, version in ips:
        url = format_url(ip, port, ipv6=(version != "IPv4"))

        print(f"\n▶ [{version}] Access URL: {url}")
        print("  Scan the QR code with your phone for quick access:")

        try:
            # Use the QR code library to print to the console
            qr = qrcode.QRCode(version=1, box_size=1, border=1)
            qr.add_data(url)
            qr.make(fit=True)
            # Some terminals may require invert=True for the QR code to be scannable
            qr.print_ascii(invert=True)
        except Exception as e:
            print(f"  [!] Unable to generate QR code: {e}")
    
    print("\n" + "═"*62 + "\n")
