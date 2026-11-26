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


# ---------------------------------------------------------------- synthetic $MFT
def _ft(days):
    return int(((dt.datetime(2026, 1, 1) + dt.timedelta(days=days)) - dt.datetime(1601, 1, 1)).total_seconds()
               * 10_000_000)


def _attr_res(typ, content, attr_id=0):
    hdr_len = 0x18
    ln = (hdr_len + len(content) + 7) & ~7
    return (struct.pack("<IIBBHHH", typ, ln, 0, 0, 0, 0, attr_id) +
            struct.pack("<IHBB", len(content), hdr_len, 0, 0) + content).ljust(ln, b"\x00")


def _attr_nonres_data(real_size):
    ln = 0x48
    return (struct.pack("<IIBBHHH", 0x80, ln, 1, 0, 0, 0, 3) +
            struct.pack("<QQHH4xQQQ", 0, 0, 0x40, 0, real_size, real_size, real_size) + bytes(8))


def mft_record(entry, names=(), days=0, size=None, in_use=True, is_dir=False, seq=1, base=0,
               attr_list=(), rec_size=1024, nonres_data=False, pad_before_fn=0):
    """One NTFS FILE record with update-sequence fix-ups applied (as on disk).
    names: (namespace, name, parent_entry, parent_seq). attr_list: (type, ext_entry) tuples."""
    attrs = b""
    if not base:
        attrs += _attr_res(0x10, struct.pack("<4Q", _ft(days), _ft(days + 1), _ft(days + 2), _ft(days + 3))
                           + bytes(16))
    if attr_list:
        al = b""
        for typ, ext in attr_list:
            al += struct.pack("<IHBBQQH6x", typ, 0x20, 0, 0x1A, 0, (1 << 48) | ext, 0)
        attrs += _attr_res(0x20, al)
    if pad_before_fn and names:                               # valid filler: a DOS-name $FN
        names = [(2, "~" * pad_before_fn, names[0][2], names[0][3])] + list(names)
    for ns, nm, par, par_seq in names:
        enc = nm.encode("utf-16-le")
        fn = struct.pack("<Q", (par_seq << 48) | par) + struct.pack("<4Q", *[_ft(days)] * 4) + \
            struct.pack("<QQII", 0, size or 0, 0x20, 0) + bytes([len(nm), ns]) + enc
        attrs += _attr_res(0x30, fn)
    if size is not None:
        attrs += _attr_nonres_data(size) if nonres_data else _attr_res(0x80, bytes(size))
    attrs += struct.pack("<I", 0xFFFFFFFF) + bytes(4)
    usa_cnt = rec_size // 512 + 1
    attr_off = (0x30 + 2 * usa_cnt + 7) & ~7
    flags = (1 if in_use else 0) | (2 if is_dir else 0)
    b = bytearray(rec_size)
    b[0:4] = b"FILE"
    struct.pack_into("<HHQHHHHII", b, 4, 0x30, usa_cnt, 0, seq, 1, attr_off, flags,
                     attr_off + len(attrs), rec_size)
    struct.pack_into("<QHHI", b, 0x20, (1 << 48) | base if base else 0, 0, 0, entry)
    b[attr_off:attr_off + len(attrs)] = attrs
    usn = b"\x07\x00"
    b[0x30:0x32] = usn
    for i in range(1, usa_cnt):                                   # fix-ups: save + overwrite
        pos = i * 512 - 2
        b[0x30 + 2 * i:0x30 + 2 * i + 2] = b[pos:pos + 2]
        b[pos:pos + 2] = usn
    return bytes(b)


def mft_image(records, count=None, rec_size=1024):
    """dict entry -> record bytes  ->  $MFT image (empty slots are zero-filled)."""
    n = count or (max(records) + 1)
    img = bytearray(n * rec_size)
    for e, r in records.items():
        img[e * rec_size:(e + 1) * rec_size] = r
    return bytes(img)
