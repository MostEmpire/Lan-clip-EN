"""Serve the app over HTTPS on a LAN, with a certificate the app issues itself.

Why: browsers only hand out the clipboard API (and other powerful features) in a
"secure context" - HTTPS, or localhost. Over plain http://<lan-ip> a phone cannot
use one-click copy/paste at all, which is most of the point of a clipboard app.

No public certificate authority will ever sign a name like clip.local or
192.168.88.238, so the app runs a tiny CA of its own: certs/ca.crt is created
once and kept, and a short-lived server certificate is issued from it covering
every name and address this machine currently answers to. Browsers show the
usual "not trusted" warning until the CA is installed (it is downloadable from
the running app at /ca.crt); the traffic is properly encrypted either way, and
installing the CA once keeps working across certificate reissues.

The certificate is reissued automatically when the machine's addresses change,
so carrying the app to a different network keeps it usable - the same failure
mode the mDNS responder has to survive.

waitress has no TLS support, so the request path is:

    client --TLS--> this module's listener --plain--> waitress on 127.0.0.1 --> Flask

The loopback waitress instance is told url_scheme='https' so Flask sees a secure
request. Degrades to a no-op (HTTP keeps working) when the 'cryptography'
package is missing or the listener cannot bind.
"""
import datetime
import os
import socket
import ssl
import threading

import net_utils

CERT_DIR = 'certs'
CA_CERT = os.path.join(CERT_DIR, 'ca.crt')
CA_KEY = os.path.join(CERT_DIR, 'ca.key')
SERVER_CERT = os.path.join(CERT_DIR, 'server.crt')
SERVER_KEY = os.path.join(CERT_DIR, 'server.key')

CA_YEARS = 10
LEAF_DAYS = 397     # the longest lifetime Apple/Chrome accept for a server certificate
RENEW_BEFORE = 30   # reissue this many days before expiry
REFRESH_TICK = 60   # seconds between "did the network change?" checks

_lock = threading.Lock()
_context = None         # cached SSLContext, dropped whenever the certificate is reissued
_listener = None
_port = None
_target_port = None
_stop = threading.Event()
_start_error = None
_refresh_thread = None


def is_active():
    return _listener is not None


def port():
    return _port


def ca_path():
    """Absolute path of the CA certificate to hand out, or None when there isn't
    one. Absolute on purpose: Flask's send_file resolves a relative path against
    app.root_path, which in a frozen build is the bundle directory rather than
    the working directory the certificates live in."""
    return os.path.abspath(CA_CERT) if os.path.exists(CA_CERT) else None


def url(host, ipv6=False):
    return net_utils.format_url(host, _port, ipv6=ipv6, scheme='https')


def status():
    """('ok'|'problem', detail) for display."""
    if _listener is not None:
        return 'ok', ""
    return 'problem', _start_error or "HTTPS is not active."


# --- certificate store -------------------------------------------------------

def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _not_after(cert):
    """Expiry as an aware datetime (the naive properties are deprecated)."""
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def _desired_sans():
    """(dns_names, ips) the certificate has to cover for this machine right now."""
    dns = {'localhost'}
    try:
        import mdns_service
        dns.add(f"{mdns_service.hostname()}.local")
    except Exception:
        pass
    try:
        host = socket.gethostname().split('.')[0].strip().lower()
        if host:
            dns.update({host, f"{host}.local"})
    except Exception:
        pass
    ips = {'127.0.0.1'}
    try:
        # include_virtual: covering an extra address costs nothing, and a client
        # reaching us over a VM bridge or VPN should not meet a name mismatch.
        ips.update(ip for ip, version in net_utils.get_host_ips(include_virtual=True)
                   if version == 'IPv4')
    except Exception:
        pass
    return sorted(dns), sorted(ips)


def _write_private(path, data):
    """Write a key file, readable by this user only where the OS supports it."""
    with open(path, 'wb') as f:
        f.write(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows ACLs don't map onto POSIX modes; the file stays user-owned


def _load_ca(x509, serialization):
    """Return (cert, key) for the local CA, creating it on first run.

    The CA is the part worth keeping: a user who installs it once stays free of
    browser warnings across every later reissue of the server certificate.
    """
    if os.path.exists(CA_CERT) and os.path.exists(CA_KEY):
        try:
            with open(CA_CERT, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
            with open(CA_KEY, 'rb') as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            if _not_after(cert) > _now() + datetime.timedelta(days=RENEW_BEFORE):
                return cert, key
            print("[HTTPS] The local CA is about to expire - creating a new one.")
        except Exception as e:
            print(f"[HTTPS] Could not read the existing CA ({e}) - creating a new one.")

    from cryptography import x509 as x509_mod
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509_mod.Name([
        x509_mod.NameAttribute(NameOID.COMMON_NAME, 'Lan-clip local CA'),
        x509_mod.NameAttribute(NameOID.ORGANIZATION_NAME, 'Lan-clip'),
    ])
    now = _now()
    cert = (
        x509_mod.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509_mod.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))  # tolerate client clock skew
        .not_valid_after(now + datetime.timedelta(days=365 * CA_YEARS))
        .add_extension(x509_mod.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509_mod.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509_mod.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .sign(key, hashes.SHA256())
    )
    os.makedirs(CERT_DIR, exist_ok=True)
    with open(CA_CERT, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    _write_private(CA_KEY, key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
    print(f"[HTTPS] Created the local certificate authority ({CA_CERT}).")
    return cert, key


def _cert_is_current(cert, dns, ips, x509):
    """True when the certificate still covers exactly today's names and is not
    about to expire. Any adapter appearing or disappearing forces a reissue."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except Exception:
        return False
    have_dns = sorted(set(san.get_values_for_type(x509.DNSName)))
    have_ips = sorted({str(i) for i in san.get_values_for_type(x509.IPAddress)})
    if have_dns != sorted(set(dns)) or have_ips != sorted(set(ips)):
        return False
    return _not_after(cert) > _now() + datetime.timedelta(days=RENEW_BEFORE)


def ensure_certificate():
    """Make sure certs/server.crt matches this machine; returns True if reissued.

    Raises when 'cryptography' is missing - the caller decides whether that is
    fatal (it isn't: the app simply stays HTTP-only).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    import ipaddress

    dns, ips = _desired_sans()
    if os.path.exists(SERVER_CERT) and os.path.exists(SERVER_KEY):
        try:
            with open(SERVER_CERT, 'rb') as f:
                existing = x509.load_pem_x509_certificate(f.read())
            if _cert_is_current(existing, dns, ips, x509):
                return False
        except Exception as e:
            print(f"[HTTPS] Could not read the existing certificate ({e}) - reissuing.")

    os.makedirs(CERT_DIR, exist_ok=True)
    ca_cert, ca_key = _load_ca(x509, serialization)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alt_names = [x509.DNSName(n) for n in dns]
    alt_names += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns[0][:64])]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=LEAF_DAYS))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    with open(SERVER_CERT, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    _write_private(SERVER_KEY, key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
    print(f"[HTTPS] Issued a certificate for {', '.join(dns)} / {', '.join(ips)}")
    return True


def _ssl_context():
    """The SSLContext for new connections, rebuilt after a certificate reissue."""
    global _context
    with _lock:
        if _context is None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(SERVER_CERT, SERVER_KEY)
            _context = ctx
        return _context


# --- TLS listener ------------------------------------------------------------

def _pump(src, dst):
    """Copy one direction until it ends. Blocking reads rather than select():
    an SSLSocket can hold decrypted bytes that select() never reports."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass  # the other end went away mid-transfer; both sockets close below


def _handle(conn, target_port):
    """Terminate TLS for one client and shuttle its bytes to the loopback server."""
    upstream = None
    tls = None
    try:
        conn.settimeout(20)  # a stalled handshake must not hold a thread forever
        tls = _ssl_context().wrap_socket(conn, server_side=True)
        tls.settimeout(None)
        upstream = socket.create_connection(('127.0.0.1', target_port), timeout=10)
        upstream.settimeout(None)
        back = threading.Thread(target=_pump, args=(upstream, tls), daemon=True)
        back.start()
        _pump(tls, upstream)          # client -> server, in this thread
        back.join(timeout=10)
    except (ssl.SSLError, socket.timeout, OSError):
        # Plain HTTP sent to the TLS port, a client rejecting our certificate, a
        # port scan: all normal, and none of them are worth a log line.
        pass
    finally:
        for sock in (tls, conn, upstream):
            try:
                if sock is not None:
                    sock.close()
            except OSError:
                pass


def _accept_loop(listener, target_port):
    while not _stop.is_set():
        try:
            conn, _addr = listener.accept()
        except OSError:
            break  # listener closed by stop()
        threading.Thread(target=_handle, args=(conn, target_port), daemon=True).start()


def _refresh_loop():
    """Reissue the certificate when the machine's addresses change, so the app
    keeps presenting a valid certificate after moving to another network."""
    while not _stop.wait(REFRESH_TICK):
        global _context
        try:
            if ensure_certificate():
                with _lock:
                    _context = None  # next connection picks up the new certificate
        except Exception as e:
            print(f"[HTTPS] Certificate refresh failed: {e}")


def start(target_port, port_choice=None, fallback_port=5443):
    """Start the TLS front-end for the loopback server on `target_port`.

    Returns the HTTPS port, or None when HTTPS could not be enabled (the caller
    just keeps serving HTTP).
    """
    global _listener, _port, _target_port, _start_error, _refresh_thread
    if _listener is not None:
        return _port

    try:
        ensure_certificate()
    except ImportError:
        _start_error = ("The 'cryptography' package is not installed - HTTPS is disabled. "
                        "Install it with: pip install cryptography")
        print(f"[HTTPS] {_start_error}")
        return None
    except Exception as e:
        _start_error = f"Could not create the certificate: {e}"
        print(f"[HTTPS] {_start_error}")
        return None

    # 443 keeps the URL clean (https://clip.local/); fall back when it is taken
    # or privileged (Linux without CAP_NET_BIND_SERVICE).
    chosen = port_choice or net_utils.pick_server_port(fallback=fallback_port, preferred=443)
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('0.0.0.0', chosen))
        listener.listen(64)
    except OSError as e:
        _start_error = f"Could not listen on port {chosen}: {e}"
        print(f"[HTTPS] {_start_error}")
        return None

    _stop.clear()
    _listener, _port, _target_port, _start_error = listener, chosen, target_port, None
    threading.Thread(target=_accept_loop, args=(listener, target_port),
                     daemon=True, name='https-accept').start()
    if _refresh_thread is None or not _refresh_thread.is_alive():
        _refresh_thread = threading.Thread(target=_refresh_loop, daemon=True, name='https-certs')
        _refresh_thread.start()
    print(f"[HTTPS] Serving TLS on port {chosen} (certificate: {SERVER_CERT})")
    return chosen


def stop():
    """Close the listener; in-flight connections finish on their own threads."""
    global _listener, _port
    _stop.set()
    listener, _listener, _port = _listener, None, None
    if listener is not None:
        try:
            listener.close()
        except OSError:
            pass
