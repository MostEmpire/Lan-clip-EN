"""One-click firewall authorization for the ports Lan-clip needs.

The mDNS window can only ever *report* that the firewall is in the way; this
module is the other half - it asks the OS, with an elevation prompt, to allow
inbound UDP 5353 (mDNS) and the web ports for this program.

Every platform needs administrator rights for this, and every platform has its
own way of asking for them without a terminal:

  Windows  a second, short-lived copy of this same program, elevated through
           ShellExecuteEx("runas") -> UAC, which then edits the rules through
           the Windows Firewall COM API
  macOS    socketfilterfw, elevated through osascript "with administrator
           privileges" -> the standard authentication sheet
  Linux    ufw or firewalld, elevated through pkexec -> the polkit dialog

On Windows the elevated worker is deliberately *this executable* rather than a
shell: the UAC prompt then names and verifies Lan-clip instead of showing
"Windows Command Processor", nothing is written to a temporary script, and no
interpreter is spawned. Writing a batch file into %TEMP% and running it
elevated is a shape that behavioural antivirus is right to distrust, and it
would hide the app's identity at the exact moment the user is asked to trust
it. The running app itself is never elevated - only the helper, which edits
the rules and exits within a second.

`plan()` describes the changes so the UI can show them before anything runs.
`apply()` is idempotent: running it twice leaves the same rules behind.
"""

import os
import shutil
import subprocess
import sys

MDNS_PORT = 5353
RULE_PREFIX = "Lan-clip"

# The argument that turns a normal start into the elevated firewall helper.
HELPER_FLAG = '--apply-firewall-rules'
ALLOW_ARG = '--allow='

# Helper exit codes. These are the only channel back to the parent - deliberately
# so, because a result file would put a temporary artifact back into the flow.
EXIT_OK = 0
EXIT_PARTIAL = 2      # some rules could not be changed
EXIT_ERROR = 3        # nothing could be changed
EXIT_BAD_ARGS = 4

# Windows Firewall COM constants (NET_FW_* enumerations)
_DIR_IN, _DIR_OUT = 1, 2
_ACTION_BLOCK, _ACTION_ALLOW = 0, 1
_PROTO = {'TCP': 6, 'UDP': 17}
_PROTO_ANY = 256
_PROFILE_ALL = 0x7FFFFFFF


def _program():
    """The executable the firewall rules must name.

    Frozen: lan-clip.exe. From source: the Python interpreter, because that is
    the process that owns the sockets - and therefore the one the firewall
    matches on. Same value mdns_service inspects, so a fix here clears the
    warning there.
    """
    return sys.executable or ''


def ports_to_open(http_port, https_port=None):
    """The full port list for a given running configuration."""
    entries = [('UDP', MDNS_PORT)]
    for p in (http_port, https_port):
        if p:
            entries.append(('TCP', int(p)))
    return entries


def supported():
    """True when apply() has a real implementation for this platform."""
    if sys.platform == 'win32':
        return True
    if sys.platform == 'darwin':
        return os.path.exists('/usr/libexec/ApplicationFirewall/socketfilterfw')
    return bool(shutil.which('ufw') or shutil.which('firewall-cmd'))


def _purpose(proto, port):
    if (proto, port) == ('UDP', MDNS_PORT):
        return "mDNS, so other devices can resolve the .local name"
    return "the web interface"


def _rule_name(proto, port):
    return f'{RULE_PREFIX} {proto} {port} (in)'


_OUT_RULE_NAME = f'{RULE_PREFIX} (out)'


def _windows_plan(entries):
    lines = ["Remove any inbound BLOCK rule Windows holds for this program "
             "(a block always overrides an allow, so it has to go first)"]
    lines += [f"Allow incoming {proto} port {port} - {_purpose(proto, port)}"
              for proto, port in entries]
    lines.append("Allow this program to make outgoing connections")
    lines.append("Apply the rules to all network profiles (Domain, Private, Public)")
    return lines


def _mac_commands(_entries):
    sf = '/usr/libexec/ApplicationFirewall/socketfilterfw'
    exe = _program()
    # The macOS application firewall is per-program, not per-port: registering the
    # binary and unblocking it is the whole job.
    return [f'"{sf}" --add "{exe}"', f'"{sf}" --unblockapp "{exe}"']


def _linux_commands(entries):
    if shutil.which('firewall-cmd'):
        cmds = ['firewall-cmd --permanent --add-service=mdns']
        cmds += [f'firewall-cmd --permanent --add-port={port}/{proto.lower()}'
                 for proto, port in entries if proto == 'TCP']
        cmds.append('firewall-cmd --reload')
        return cmds
    if shutil.which('ufw'):
        return [f'ufw allow {port}/{proto.lower()} comment "{RULE_PREFIX}"'
                for proto, port in entries]
    return []


def plan(entries):
    """What apply() will change, as human-readable lines for the confirmation
    dialog. On macOS and Linux the changes *are* shell commands, so those are
    shown verbatim; on Windows they are COM API calls, so they are described.
    """
    if sys.platform == 'win32':
        return _windows_plan(entries)
    if sys.platform == 'darwin':
        return _mac_commands(entries)
    return _linux_commands(entries)


# --------------------------------------------------------------------------
# Windows: the elevated helper (runs as administrator, in its own process)
# --------------------------------------------------------------------------

def _new_rule(win32com_client, name, description, direction, protocol, port=None):
    rule = win32com_client.Dispatch("HNetCfg.FWRule")
    rule.Name = name
    rule.Description = description
    rule.ApplicationName = _program()
    rule.Protocol = protocol          # must precede LocalPorts
    if port is not None:
        rule.LocalPorts = str(port)
    rule.Direction = direction
    rule.Enabled = True
    rule.Grouping = RULE_PREFIX
    rule.Profiles = _PROFILE_ALL
    rule.Action = _ACTION_ALLOW
    rule.InterfaceTypes = 'All'
    return rule


def apply_rules_windows(entries):
    """Edit the firewall rules. MUST already be running elevated.

    Returns one of the EXIT_* codes.
    """
    import pythoncom
    import win32com.client

    try:
        pythoncom.CoInitialize()
        fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
    except Exception:
        return EXIT_ERROR

    exe_cmp = os.path.normcase(_program())

    def matches_us(rule):
        try:
            return os.path.normcase(rule.ApplicationName or '') == exe_cmp
        except Exception:
            return False

    # 1. Collect the inbound BLOCK rules that name this program. Clicking
    #    'Cancel' on the Windows connection prompt creates exactly these, and no
    #    allow rule can override one.
    blocked = set()
    for rule in fw.Rules:
        try:
            if rule.Direction == _DIR_IN and rule.Action == _ACTION_BLOCK and matches_us(rule):
                blocked.add(rule.Name)
        except Exception:
            continue  # some rules expose partial COM properties

    # INetFwRules::Remove can only delete by name, and a name may be shared with
    # a rule belonging to a different program. Removing such a name would take
    # someone else's rule with it, so those are left alone and reported instead.
    shared = set()
    if blocked:
        for rule in fw.Rules:
            try:
                if rule.Name in blocked and not matches_us(rule):
                    shared.add(rule.Name)
            except Exception:
                continue

    partial = bool(shared)
    for name in sorted(blocked - shared):
        try:
            fw.Rules.Remove(name)
        except Exception:
            partial = True

    # 2. Drop our own previous rules so a second run replaces rather than
    #    duplicates them, then add the current set.
    wanted = [(_rule_name(proto, port), _PROTO.get(proto, _PROTO_ANY), port, _DIR_IN,
               f"Lan-clip: allow incoming {proto} {port} ({_purpose(proto, port)})")
              for proto, port in entries]
    wanted.append((_OUT_RULE_NAME, _PROTO_ANY, None, _DIR_OUT,
                   "Lan-clip: allow outgoing connections"))

    for name, _proto, _port, _direction, _desc in wanted:
        try:
            fw.Rules.Remove(name)
        except Exception:
            pass  # not present is the normal case

    added = 0
    for name, protocol, port, direction, description in wanted:
        try:
            # Outbound is left unrestricted rather than pinned to these ports: on
            # an outgoing packet the local port is the ephemeral one, so pinning
            # 5353 would match almost nothing.
            fw.Rules.Add(_new_rule(win32com.client, name, description,
                                   direction, protocol, port))
            added += 1
        except Exception:
            partial = True

    if not added:
        return EXIT_ERROR
    return EXIT_PARTIAL if partial else EXIT_OK


def run_elevated_helper(argv):
    """Entry point for the elevated copy: parse --allow=PROTO:PORT and apply.

    Called before the app starts anything else, so this process never binds a
    port, never shows a tray icon and never serves a request - it edits rules
    and exits. Returns a process exit code.
    """
    if sys.platform != 'win32':
        return EXIT_ERROR
    entries = []
    for arg in argv:
        if not arg.startswith(ALLOW_ARG):
            continue
        proto, _, port = arg[len(ALLOW_ARG):].partition(':')
        try:
            entries.append((proto.upper(), int(port)))
        except ValueError:
            return EXIT_BAD_ARGS
    if not entries:
        return EXIT_BAD_ARGS
    try:
        return apply_rules_windows(entries)
    except Exception:
        return EXIT_ERROR


# --------------------------------------------------------------------------
# Windows: the non-elevated side that requests elevation
# --------------------------------------------------------------------------

def _helper_invocation(entries):
    """(file, parameters) for ShellExecuteEx.

    Frozen, this is the signed executable itself, so the UAC prompt names and
    verifies Lan-clip. From source there is no signed binary to elevate, so it
    is the interpreter plus this app's script.
    """
    args = [HELPER_FLAG] + [f'{ALLOW_ARG}{proto}:{port}' for proto, port in entries]
    if getattr(sys, 'frozen', False):
        return sys.executable, ' '.join(args)
    # __main__.__file__ rather than sys.argv[0]: argv[0] is whatever the caller
    # put there, and a launcher that rewrites it would send the elevated copy to
    # the wrong script - with administrator rights.
    main = sys.modules.get('__main__')
    script = os.path.abspath(getattr(main, '__file__', None) or sys.argv[0] or 'app.py')
    return sys.executable, ' '.join([f'"{script}"'] + args)


def _run_windows(entries):
    """Launch the elevated helper and wait for it. Returns (ok, message)."""
    import ctypes
    from ctypes import wintypes

    file, parameters = _helper_invocation(entries)

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [('cbSize', wintypes.DWORD), ('fMask', ctypes.c_ulong),
                    ('hwnd', wintypes.HWND), ('lpVerb', wintypes.LPCWSTR),
                    ('lpFile', wintypes.LPCWSTR), ('lpParameters', wintypes.LPCWSTR),
                    ('lpDirectory', wintypes.LPCWSTR), ('nShow', ctypes.c_int),
                    ('hInstApp', wintypes.HINSTANCE), ('lpIDList', ctypes.c_void_p),
                    ('lpClass', wintypes.LPCWSTR), ('hkeyClass', wintypes.HKEY),
                    ('dwHotKey', wintypes.DWORD), ('hIcon', wintypes.HANDLE),
                    ('hProcess', wintypes.HANDLE)]

    SEE_MASK_NOCLOSEPROCESS, SEE_MASK_NOASYNC, SW_HIDE = 0x40, 0x100, 0
    ERROR_CANCELLED = 1223

    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
    info.lpVerb = 'runas'          # this is what raises the UAC prompt
    info.lpFile = file
    info.lpParameters = parameters
    info.lpDirectory = os.getcwd()  # so the helper never writes stray files elsewhere
    info.nShow = SW_HIDE

    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
        err = ctypes.get_last_error() or ctypes.GetLastError()
        if err == ERROR_CANCELLED:
            return False, "Administrator approval was declined - no rules were changed."
        return False, f"Could not request administrator rights (error {err})."

    ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, 120000)
    code = wintypes.DWORD()
    ctypes.windll.kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    ctypes.windll.kernel32.CloseHandle(info.hProcess)

    return {
        EXIT_OK: (True, "Firewall rules added."),
        EXIT_PARTIAL: (True, "Firewall rules added, but some existing rules could not be "
                             "changed - open Windows Firewall to check."),
        EXIT_ERROR: (False, "The firewall rules could not be changed."),
        EXIT_BAD_ARGS: (False, "The firewall helper was started incorrectly."),
    }.get(code.value, (False, f"The firewall helper failed (exit code {code.value})."))


# --------------------------------------------------------------------------
# macOS / Linux
# --------------------------------------------------------------------------

def _run_macos(cmds):
    script = '; '.join(cmds).replace('\\', '\\\\').replace('"', '\\"')
    try:
        r = subprocess.run(
            ['osascript', '-e',
             f'do shell script "{script}" with administrator privileges'],
            capture_output=True, text=True, timeout=120)
    except Exception as e:
        return False, f"Could not run the firewall command: {e}"
    if r.returncode == 0:
        return True, "Firewall rules added."
    if 'User canceled' in (r.stderr or ''):
        return False, "Administrator approval was declined - no rules were changed."
    return False, (r.stderr or 'The firewall command failed.').strip()


def _run_linux(cmds):
    runner = shutil.which('pkexec')
    if not runner:
        return False, ("pkexec is not installed, so the rules cannot be applied from here. "
                       "Run these as root:\n" + "\n".join(cmds))
    joined = ' && '.join(cmds)
    try:
        r = subprocess.run([runner, 'sh', '-c', joined],
                           capture_output=True, text=True, timeout=120)
    except Exception as e:
        return False, f"Could not run the firewall command: {e}"
    if r.returncode == 0:
        return True, "Firewall rules added."
    if r.returncode == 126:  # polkit: dismissed or not authorized
        return False, "Administrator approval was declined - no rules were changed."
    return False, (r.stderr or 'The firewall command failed.').strip()


def apply(entries):
    """Ask the OS to allow `entries` for this program. Returns (ok, message).

    Blocks until the user answers the elevation prompt, so call it off the UI
    thread. Never raises.
    """
    try:
        if sys.platform == 'win32':
            return _run_windows(entries)
        cmds = plan(entries)
        if not cmds:
            return False, "No supported firewall tool was found on this system."
        if sys.platform == 'darwin':
            return _run_macos(cmds)
        return _run_linux(cmds)
    except Exception as e:
        return False, f"Could not change the firewall: {type(e).__name__}: {e}"
