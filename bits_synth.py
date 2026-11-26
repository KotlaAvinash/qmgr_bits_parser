"""bits_synth.py - build synthetic BITS records ($I30, job and file blobs, security
descriptors) for tests and demos. Produces no real system data."""
import datetime as dt
import struct
import uuid

import bits_qmgr_parser as P


def sd_blob(owner="S-1-5-21-1000-2000-3000-1001", group=None, aces=(("allow", 0xF003F, "S-1-5-32-544"),)):
    """Minimal self-relative SECURITY_DESCRIPTOR (owner, group, DACL of allow/deny ACEs)."""
    def sid(s):
        parts = [int(x) for x in s.split("-")[2:]]
        auth, subs = parts[0], parts[1:]
        return bytes([1, len(subs)]) + auth.to_bytes(6, "big") + struct.pack("<%dI" % len(subs), *subs)
    ace_bytes = b""
    for kind, mask, s in aces:
        body = struct.pack("<I", mask) + sid(s)
        ace_bytes += struct.pack("<BBH", 0 if kind == "allow" else 1, 0, 4 + len(body)) + body
    dacl = struct.pack("<BBHHH", 2, 0, 8 + len(ace_bytes), len(aces), 0) + ace_bytes
    o, g = sid(owner), sid(group or owner)
    off_o = 20
    off_g = off_o + len(o)
    off_d = off_g + len(g)
    hdr = struct.pack("<BBHIIII", 1, 0, 0x8004, off_o, off_g, 0, off_d)
    return hdr + o + g + dacl


def ustr(s):
    s += "\x00"
    return struct.pack("<I", len(s)) + s.encode("utf-16-le")


def ftb(days, base=dt.datetime(2026, 1, 1)):
    t = base + dt.timedelta(days=days)
    return struct.pack("<Q", int((t - dt.datetime(1601, 1, 1)).total_seconds() * 10_000_000))


def job_blob(name="System update", cmd="C:\\Users\\Public\\mail.exe", args="", state=4,
             jtype=0, errors=1, file_ids=(), sid="S-1-5-21-1-2-3-1001", jid=None,
             creator="C:\\Windows\\System32\\bitsadmin.exe", delim=None, sd=None):
    """Win10 job record. `sd`: security descriptor bytes, or None for an opaque filler."""
    b = (delim or P.JOB_DELIMS[0]) + struct.pack("<IIII", jtype, 2, state, 0) + \
        (jid or uuid.uuid4()).bytes_le
    b += ustr(name) + ustr("desc") + ustr(cmd) + ustr(args) + ustr(sid)
    if sd is None:
        b += struct.pack("<I", 3) + b"\x01" * 40
    else:                                   # [measured] flags, 5 x u32, sd_len, SD
        b += struct.pack("<I", 3) + bytes(20) + struct.pack("<I", len(sd)) + sd
    b += P.XFER_HDR + struct.pack("<I", len(file_ids)) + b"".join(
        uuid.UUID(f).bytes_le for f in file_ids) + P.XFER_HDR
    b += struct.pack("<I", errors)
    for _ in range(errors):
        b += struct.pack("<II", 0, 0x80072EE7) + struct.pack("<IIII", 1, 5, 3, 256) + b"\x00"
    if not errors:
        b += struct.pack("<I", 0)
    b += struct.pack("<II", 60, 86400) + ftb(0) + ftb(1) + ftb(1) + ftb(1) + b"\x00" * 6 + ftb(1) + ftb(91)
    b += ustr(creator) + ustr("GET") + (delim or P.JOB_DELIMS[0])
    return b


def file_blob(src="http://127.0.0.1/a.exe", dest="C:\\Users\\Public\\mail.exe", got=0, total=None):
    b = P.FILE_DELIM + ustr(dest) + ustr(src) + ustr("C:\\Users\\Public\\BIT1.tmp")
    b += struct.pack("<QQ", got, 0xFFFFFFFFFFFFFFFF if total is None else total) + b"\x00"
    b += ustr("C:\\") + ustr("\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\") + b"\x00" * 60
    return b + P.FILE_DELIM


def fn_entry(name, days=0, size=123):
    """INDX entry: 0x10 entry header + $FILE_NAME."""
    nm = name.encode("utf-16-le")
    body = struct.pack("<Q", 5 | (1 << 48)) + ftb(days) * 4 + struct.pack("<QQ", 4096, size) + \
        struct.pack("<II", 0x20, 0) + bytes([len(name), 1]) + nm
    ln = (0x10 + len(body) + 7) & ~7
    hdr = struct.pack("<QHHI", 42, ln, len(body), 0)
    return (hdr + body).ljust(ln, b"\x00")


def indx_block(live, slack):
    entries = b"".join(fn_entry(n, i) for i, n in enumerate(live))
    end = struct.pack("<QHHI", 0, 0x10, 0, 2)                 # last-entry marker
    first = 0x28
    used = first + len(entries) + len(end)
    b = bytearray(4096)
    b[0:4] = b"INDX"
    struct.pack_into("<HH", b, 4, 0x28 + 0x18 + 0x10, 1)       # usa_off past header, usa_cnt=1
    struct.pack_into("<III", b, 0x18, first, used, 4096 - 0x18)
    pos = 0x18 + first
    b[pos:pos + len(entries) + len(end)] = entries + end
    s = pos + len(entries) + len(end) + 64
    for i, n in enumerate(slack):
        e = fn_entry(n, 10 + i); b[s:s + len(e)] = e; s += len(e) + 8
    return bytes(b)
