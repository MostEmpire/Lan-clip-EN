import sys
import socket
import qrcode

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

def _windows_adapter_map():
    """Windows: {ip_string: adapter Description} via iphlpapi.GetAdaptersAddresses.
    Pure stdlib ctypes (no pywin32) so it bundles cleanly into a frozen build."""
    import ctypes
    from ctypes import wintypes

    AF_UNSPEC, AF_INET, AF_INET6 = 0, 2, 23
    GAA_FLAGS = 0x0002 | 0x0004 | 0x0008  # skip anycast, multicast, DNS servers
    ERROR_SUCCESS, ERROR_BUFFER_OVERFLOW = 0, 111

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
    ]  # remaining fields omitted; we only read up to FriendlyName and walk via Next

    GetAdaptersAddresses = ctypes.windll.iphlpapi.GetAdaptersAddresses
    GetAdaptersAddresses.restype = wintypes.ULONG

    mapping = {}
    size = ctypes.c_ulong(15 * 1024)
    for _ in range(3):  # grow the buffer if the first guess was too small
        buf = ctypes.create_string_buffer(size.value)
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAGS, None,
                                   ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
                                   ctypes.byref(size))
        if ret == ERROR_BUFFER_OVERFLOW:
            continue
        if ret != ERROR_SUCCESS:
            return mapping
        adapter = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
        while adapter:
            a = adapter.contents
            desc = a.Description or a.FriendlyName
            ua = a.FirstUnicastAddress
            while ua:
                sa = ua.contents.Address.lpSockaddr
                if sa and desc:
                    fam = sa.contents.sa_family
                    raw = bytes(sa.contents.sa_data)  # bytes after the 2-byte sa_family
                    ip = None
                    if fam == AF_INET:
                        ip = ".".join(str(b) for b in raw[2:6])
                    elif fam == AF_INET6:
                        ip = socket.inet_ntop(socket.AF_INET6, raw[6:22])
                    if ip:
                        mapping[ip] = desc
                ua = ua.contents.Next
            adapter = a.Next
        return mapping
    return mapping

def get_adapter_names():
    """Best-effort map of {ip_string: human-readable adapter name}, cross-platform.

    - Windows: device descriptions via GetAdaptersAddresses (stdlib ctypes), e.g.
      'Intel(R) Wireless-AC 9560' or 'VirtualBox Host-Only Ethernet Adapter'.
    - Other platforms: interface names via psutil if it happens to be installed.
    Returns {} on failure; callers fall back to a generic label when an IP is missing.
    """
    mapping = {}
    if sys.platform == 'win32':
        try:
            mapping = _windows_adapter_map()
        except Exception:
            mapping = {}

    if not mapping:
        # Cross-platform fallback (Linux/macOS, or Windows if the API call failed).
        try:
            import psutil
            for name, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if getattr(a, 'address', None):
                        mapping.setdefault(a.address.split('%')[0], name)
        except Exception:
            pass

    return mapping

def get_host_ips():
    """Get all internal IPv4 and IPv6 addresses of the machine's physical network adapters"""
    ips = []
    try:
        # Try to detect the primary IP via UDP
        primary_ip = "127.0.0.1"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            primary_ip = s.getsockname()[0]
        except Exception:
            pass
        finally:
            s.close()

        hostname = socket.gethostname()
        addr_info = socket.getaddrinfo(hostname, None)
        
        seen = set()
        
        # Exclusion list: common virtual adapters, proxies, loopback ranges, invalid prefixes
        exclude_prefixes = (
            '127.', '169.254.', '198.18.', '172.17.', '172.18.', '172.19.', '172.20.',
            '44.', '100.64.', 'fe80:', '::1'
        )
        
        # Specific virtual subnets mentioned by users
        exclude_specific = ('192.168.206.', '192.168.56.', '192.168.163.', '192.168.44.')

        for item in addr_info:
            family = item[0]
            addr = item[4][0]
            
            # Basic filtering
            if any(addr.startswith(p) for p in exclude_prefixes):
                continue

            # Virtual subnet filtering
            if any(addr.startswith(p) for p in exclude_specific):
                # If this IP happens to be primary_ip (e.g. this adapter is actually in use), keep it; otherwise filter it out
                if addr != primary_ip:
                    continue

            if addr not in seen:
                if family == socket.AF_INET:
                    # Put primary_ip at the front of the list
                    if addr == primary_ip:
                        ips.insert(0, (addr, "IPv4"))
                    else:
                        ips.append((addr, "IPv4"))
                    seen.add(addr)
                elif hasattr(socket, 'AF_INET6') and family == socket.AF_INET6:
                    # Only keep IPv6 addresses that are likely public/global (usually starting with 2 or 3)
                    # If IPv6 cannot connect and users report connection failures, stricter filtering can be applied here
                    if addr.startswith('2') or addr.startswith('3'):
                        ips.append((addr, "IPv6"))
                        seen.add(addr)
                    
    except Exception as e:
        print(f"Error while getting IP addresses: {e}")

    # If no external IP was found, fall back to 127.0.0.1
    if not ips:
        ips.append(("127.0.0.1", "IPv4"))
    
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
