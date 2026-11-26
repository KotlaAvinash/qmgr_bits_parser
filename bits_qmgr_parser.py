#!/usr/bin/env python3
"""
bits_qmgr_parser.py - Windows 10/11 BITS queue (qmgr.db) parser + carver.

Reads an exported %ALLUSERSPROFILE%\\Microsoft\\Network\\Downloader folder:
  * qmgr.db           -> live ESE tables Jobs / Files (dissect.esedb)
  * qmgr.db (raw), edb*.log, *.jrs, *.FileSlack, anything else
                      -> raw carving for job / file records (deleted + historic)
  * $I30              -> NTFS INDX entries for the folder (incl. slack)

Evidence is opened read-only and SHA-256 hashed. Output: JSON, CSV, triage.

Layout reference: ANSSI-FR bits_parser structs.py + FireEye BitsParser
constants; verified byte-by-byte against a real Windows 11 queue.
"""
import argparse, csv, datetime as dt, hashlib, json, ntpath, os, re, struct, sys, uuid

__version__ = "1.2.1"

JOB_DELIMS = [bytes.fromhex(h) for h in (
    "a15609e143afc94292e66f9856eba7f6", "9f95d44c6470f24b84d7476a7e62699f",
    "f11926a93203bf4c9427898818958831", "c133bcddfb5aaf4db8a12268b39d01ad",
    "d057568f2c013e4ead2cf4a5d7656faf", "5067419457031d46a4cc5dd9990706e4")]
FILE_DELIM = bytes.fromhex("e4cf9e5146d99743b73e268513051ab2")
XFER_HDR = bytes.fromhex("36da56776f515a43acac44a248fff34d")

JOB_TYPE = {0: "download", 1: "upload", 2: "upload_reply"}
JOB_PRIO = {0: "foreground", 1: "high", 2: "normal", 3: "low"}
JOB_STATE = {0: "queued", 1: "connecting", 2: "transferring", 3: "suspended", 4: "error",
             5: "transient_error", 6: "transferred", 7: "acknowledged", 8: "cancelled"}
NOTIFY_FLAGS = {1: "JOB_TRANSFERRED", 2: "JOB_ERROR", 4: "DISABLE", 8: "JOB_MODIFICATION",
                16: "FILE_TRANSFERRED"}

HRESULT_HINT = {"0x80072EE7": "WinINet: server name not resolved (DNS)",
                "0x80072EFD": "WinINet: cannot connect", "0x80072EE2": "WinINet: timeout",
                "0x80070057": "E_INVALIDARG", "0x80070005": "E_ACCESSDENIED",
                "0x80200010": "BITS facility 0x8020 error"}
for _c in range(400, 600):                  # 0x8019xxxx = BG_E_HTTP_ERROR_<status>
    HRESULT_HINT["0x8019%04X" % _c] = "HTTP %d" % _c

# Known updater hosts. Matched on the parsed hostname as an exact domain or a dot-suffix,
# never as a substring, so "microsoft.com.evil.ru" or "/knowledge/" cannot pass.
BENIGN_HOSTS = ("microsoft.com", "windowsupdate.com", "office.net", "live.com", "sfx.ms",
                "gvt1.com", "google.com", "googleapis.com", "bravesoftware.com", "mozilla.net",
                "mozilla.org", "msedge.net", "office.com", "microsoftonline.com", "windows.com",
                "digicert.com", "akamaized.net")
BENIGN_CREATORS = re.compile(
    r"^[a-z]:\\(program files( \(x86\))?|windows\\system32)\\.*\\?(msedge|msedgewebview2|"
    r"onedrive[\w.]*|officeclicktorun|chrome|firefox|braveupdate|googleupdate|microsoftedgeupdate|"
    r"directxdatabaseupdater|microsoft\.sharepoint)\.exe$", re.I)
ATTACKER_CREATORS = re.compile(r"\\(bitsadmin|powershell|pwsh|cmd|wscript|cscript|mshta|"
                               r"rundll32|regsvr32)\.exe$", re.I)
USER_WRITABLE = re.compile(r"\\users\\|\\appdata\\|\\temp\\|\\programdata\\|\\public\\|"
                           r"\\windows\\tasks\\|\\perflogs\\", re.I)


def url_host(url):
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/?#@\[\]]*@)?(\[[^\]]+\]|[^/:?#\[\]]+)", url or "", re.I)
    if not m:
        return ""
    return m.group(2).lower().strip("[]").rstrip(".")


def benign_host(url):
    h = url_host(url)
    return bool(h) and any(h == d or h.endswith("." + d) for d in BENIGN_HOSTS)


def is_url(s):
    return bool(re.match(r"^[a-z][a-z0-9+.-]*://", s or "", re.I))


def csv_safe(v):
    """Neutralise spreadsheet formula injection in attacker-controlled strings."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


class ParseError(Exception):
    pass


# ---------------------------------------------------------------- primitives
def filetime(v):
    if not v or v < 0x0100000000000000 or v > 0x0200000000000000:
        return None
    return (dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=v // 10)).isoformat() + "Z"


def sid_str(b, off=0):
    """Binary SID -> 'S-1-...'; returns (string, length) or (None, 0)."""
    if len(b) < off + 8 or b[off] != 1:
        return None, 0
    n = b[off + 1]
    if n > 15 or len(b) < off + 8 + 4 * n:
        return None, 0
    auth = int.from_bytes(b[off + 2:off + 8], "big")
    subs = struct.unpack_from("<%dI" % n, b, off + 8)
    return "S-1-%d%s" % (auth, "".join("-%d" % s for s in subs)), 8 + 4 * n


def _sddl_windows(sd):
    try:
        import ctypes
        from ctypes import wintypes
        adv = ctypes.WinDLL("advapi32")
        fn = adv.ConvertSecurityDescriptorToStringSecurityDescriptorW
        fn.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                       ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.ULONG)]
        buf = ctypes.create_string_buffer(sd)
        if not adv.IsValidSecurityDescriptor(buf):
            return None
        out, n = wintypes.LPWSTR(), wintypes.ULONG()
        if not fn(buf, 1, 0x1 | 0x2 | 0x4, ctypes.byref(out), ctypes.byref(n)):
            return None
        s = out.value
        ctypes.windll.kernel32.LocalFree(out)
        return s
    except (OSError, AttributeError, ImportError):
        return None


def decode_sd(sd):
    """Self-relative SECURITY_DESCRIPTOR -> owner/group SIDs, DACL ACEs, SDDL (Windows)."""
    out = {}
    try:
        _, _, _ctl, o_own, o_grp, _o_sacl, o_dacl = struct.unpack_from("<BBHIIII", sd, 0)
    except struct.error:
        return out
    if o_own:
        out["sd_owner_sid"] = sid_str(sd, o_own)[0]
    if o_grp:
        out["sd_group_sid"] = sid_str(sd, o_grp)[0]
    aces = []
    if o_dacl and o_dacl + 8 <= len(sd):
        _rev, _z, _size, count, _z2 = struct.unpack_from("<BBHHH", sd, o_dacl)
        p = o_dacl + 8
        for _ in range(min(count, 64)):
            if p + 8 > len(sd):
                break
            typ, _flags, size = struct.unpack_from("<BBH", sd, p)
            mask = struct.unpack_from("<I", sd, p + 4)[0]
            if typ in (0, 1):
                aces.append("%s 0x%08X %s" % ("allow" if typ == 0 else "deny", mask, sid_str(sd, p + 8)[0]))
            if size < 8:
                break
            p += size
    out["sd_dacl"] = aces
    sddl = _sddl_windows(sd) if os.name == "nt" else None
    if sddl:
        out["sd_sddl"] = sddl
    return out


class Reader:
    def __init__(self, buf, off=0, end=None):
        self.b, self.o = buf, off
        self.end = len(buf) if end is None else end

    def need(self, n):
        if self.o + n > self.end:
            raise ParseError("truncated at 0x%x" % self.o)

    def u8(self):
        self.need(1); v = self.b[self.o]; self.o += 1; return v

    def u32(self):
        self.need(4); v = struct.unpack_from("<I", self.b, self.o)[0]; self.o += 4; return v

    def u64(self):
        self.need(8); v = struct.unpack_from("<Q", self.b, self.o)[0]; self.o += 8; return v

    def guid(self):
        self.need(16); v = uuid.UUID(bytes_le=bytes(self.b[self.o:self.o + 16])); self.o += 16
        return str(v)

    def raw(self, n):
        self.need(n); v = bytes(self.b[self.o:self.o + n]); self.o += n; return v

    def ustr(self, maxchars=4096):
        """PascalUtf16(Int32ul): char count incl. terminating NUL."""
        n = self.u32()
        if n > maxchars:
            raise ParseError("string length %d too large at 0x%x" % (n, self.o - 4))
        if n == 0:
            return ""
        data = self.raw(n * 2)
        try:
            s = data.decode("utf-16-le")
        except UnicodeDecodeError:
            raise ParseError("bad utf16 at 0x%x" % self.o)
        if not s.endswith("\x00"):
            raise ParseError("unterminated string at 0x%x" % self.o)
        s = s[:-1]
        if any(ord(c) < 0x20 and c not in "\t\r\n" for c in s):
            raise ParseError("control chars in string")
        return s


# ---------------------------------------------------------------- records
def parse_job(buf, off=0, end=None):
    """Parse a Win10 job blob starting at its 16-byte delimiter."""
    r = Reader(buf, off, end)
    delim = r.raw(16)
    if delim not in JOB_DELIMS:
        raise ParseError("no job delimiter")
    j = {}
    t, p, s = r.u32(), r.u32(), r.u32()
    if t not in JOB_TYPE or p not in JOB_PRIO or s not in JOB_STATE:
        raise ParseError("enum out of range")
    j["job_type"], j["priority"], j["state"] = JOB_TYPE[t], JOB_PRIO[p], JOB_STATE[s]
    r.u32()
    j["job_id"] = r.guid()
    j["name"] = r.ustr()
    j["description"] = r.ustr()
    j["notify_cmd"] = r.ustr()
    j["notify_args"] = r.ustr()
    j["owner_sid"] = r.ustr(256)
    if not re.fullmatch(r"S-1-\d+(-\d+)+", j["owner_sid"]):
        raise ParseError("bad SID")
    flags = r.u32()
    j["notify_flags"] = "|".join(v for k, v in NOTIFY_FLAGS.items() if flags & k) or str(flags)
    # access token / security descriptor up to the transfer header
    lim = min(r.end, r.o + 8192)
    x = bytes(buf[r.o:lim]).find(XFER_HDR)
    if x >= 24:
        # [measured] 5 x u32 (unknown), u32 sd_len, self-relative SECURITY_DESCRIPTOR
        region = bytes(buf[r.o:r.o + x])
        sd_len = struct.unpack_from("<I", region, 20)[0]
        sd = region[24:24 + sd_len]
        if sd_len >= 20 and len(sd) == sd_len and sd[0] == 1:
            j.update(decode_sd(sd))
    if x < 0:
        j["_partial"] = "no transfer header after SID"
        return j, r.o
    r.o += x + 16
    count = r.u32()
    if count > 1000:
        raise ParseError("file count absurd")
    j["file_ids"] = [r.guid() for _ in range(count)]
    if r.raw(16) != XFER_HDR:
        j["_partial"] = "file list not closed"
        return j, r.o
    # METADATA
    ec = r.u32()
    if ec > 1000:
        raise ParseError("error count absurd")
    errs = []
    for _ in range(ec):
        # [measured on sample] u32 0, u32 HRESULT, u32 x4, u8  (ANSSI: u64 code + 4 stats + byte)
        lo, hr = r.u32(), r.u32(); stats = [r.u32() for _ in range(4)]; r.u8()
        errs.append({"hresult": "0x%08X" % (hr or lo), "stats": stats})
    j["errors"] = errs
    # [measured] with 0 errors a u32 transient-error count follows; with >=1 error the
    # retry delay follows directly. Pick the alignment where ctime is a valid FILETIME.
    def _ft_ok(o):
        try:
            return filetime(struct.unpack_from("<Q", buf, o)[0]) is not None
        except struct.error:
            return False
    if not ec or not _ft_ok(r.o + 8) and _ft_ok(r.o + 12):
        j["transient_error_count"] = r.u32()
    j["retry_delay_s"] = r.u32()
    j["no_progress_timeout_s"] = r.u32()
    j["created"] = filetime(r.u64())
    j["modified"] = filetime(r.u64())
    j["transfer_completed"] = filetime(r.u64())   # ANSSI: other_time0
    j["time_in_padding"] = filetime(r.u64())      # ANSSI treats these 14 bytes as padding
    r.raw(6)
    j["other_time1"] = filetime(r.u64())
    j["expiration"] = filetime(r.u64())           # ANSSI: other_time2 (= completed + 90 d here)
    # trailing strings (Win10+): creating process image and HTTP verb seen in sample
    tail_end = min(r.end, r.o + 1024)   # tail is ~300 B; never run into the next record
    closed = False
    for d in JOB_DELIMS:
        p2 = bytes(buf[r.o:tail_end]).find(d)
        if p2 >= 0:
            tail_end, closed = min(tail_end, r.o + p2), True
    j.update(scan_tail_strings(buf, r.o, tail_end))
    # ESE blobs end exactly at the closing delimiter; carved records without one may be cut off
    j["tail_complete"] = closed or (tail_end == r.end and "http_method" in j)
    return j, tail_end + 16 if closed else r.o


def scan_tail_strings(buf, start, end):
    out, o = {}, start
    found = []
    while o + 6 <= end:
        n = struct.unpack_from("<I", buf, o)[0]
        if 2 <= n <= 1024 and o + 4 + n * 2 <= end:
            try:
                s = bytes(buf[o + 4:o + 4 + n * 2]).decode("utf-16-le")
                if s.endswith("\x00") and s[:-1].isprintable() and len(s) > 2:
                    found.append(s[:-1]); o += 4 + n * 2; continue
            except UnicodeDecodeError:
                pass
        o += 1
    for s in found:
        if s.upper() in ("GET", "POST", "PUT", "HEAD", "BITS_POST"):
            out["http_method"] = s
        elif re.match(r"^[A-Za-z]:\\|^\\\\", s) and "creator_process_inferred" not in out:
            out["creator_process_inferred"] = s
        elif s.startswith("!") and out.get("tail_strings"):
            out["creator_aumid_inferred"] = out["tail_strings"].pop() + s   # PackageFamily!AppId
        else:
            out.setdefault("tail_strings", []).append(s)
    return out


def parse_file(buf, off=0, end=None):
    """Parse a Win10 file blob; off points at FILE_DELIM."""
    r = Reader(buf, off, end)
    if r.raw(16) != FILE_DELIM:
        raise ParseError("no file delimiter")
    f = {"dest_file": r.ustr(), "source_url": r.ustr(), "tmp_file": r.ustr()}
    if not (f["dest_file"] or f["source_url"]):
        raise ParseError("empty file record")
    if f["source_url"] and not re.match(r"^(https?|ftp|file|smb)://|^\\\\|^[A-Za-z]:\\",
                                         f["source_url"], re.I):
        raise ParseError("source does not look like URL/path")
    # ANSSI names these download_size / transfer_size. [measured] on this host the first is
    # bytes received so far and the second is total size (-1 = not yet known).
    f["download_size"] = r.u64()   # bytes transferred
    f["transfer_size"] = r.u64()   # total bytes
    r.u8()
    f["drive"] = r.ustr(64)
    f["volume_guid"] = r.ustr(128)
    base = r.o
    try:
        v = struct.unpack_from("<Q", buf, base + 29)[0]
        f["remote_last_modified_inferred"] = filetime(v)   # BitsParser labels this CreationTime
    except struct.error:
        pass
    for k in ("download_size", "transfer_size"):
        if f[k] == 0xFFFFFFFFFFFFFFFF:
            f[k] = None
    ds, ts = f["download_size"], f["transfer_size"]
    f["complete"] = bool(ts) and ds == ts
    return f, base


# ---------------------------------------------------------------- sources
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_ese(path):
    try:
        from dissect.esedb import EseDB
    except ImportError:
        print("[!] dissect.esedb not installed - skipping ESE table parse (carving still runs)")
        return [], {}, []
    notes, jobs, files = [], [], {}
    try:
        with open(path, "rb") as fh:
            db = EseDB(fh)
            for rec in db.table("Files").records():
                fid, blob = str(rec.get("Id")), rec.get("Blob")
                try:
                    f, _ = parse_file(blob)
                    f["file_id"] = fid
                    files[fid] = f
                except ParseError as e:
                    notes.append("Files %s: %s" % (fid, e))
            for rec in db.table("Jobs").records():
                jid, blob = str(rec.get("Id")), rec.get("Blob")
                try:
                    j, _ = parse_job(blob)
                    j["ese_key"] = jid
                    j["source"] = ["qmgr.db:Jobs (active)"]
                    jobs.append(j)
                except ParseError as e:
                    notes.append("Jobs %s: %s" % (jid, e))
    except Exception as e:   # dirty/corrupt/truncated DB: keep going, carving still runs
        notes.append("ESE read of %s failed (%s: %s) - results come from carving only"
                     % (os.path.basename(path), type(e).__name__, e))
    return jobs, files, notes


def carve(path, label=None):
    import mmap
    name = label or os.path.basename(path)
    if os.path.getsize(path) == 0:
        return [], []
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data:
        return _carve_buf(data, name)


def _carve_buf(data, name):
    jobs, files = [], []
    for d in JOB_DELIMS:
        for m in re.finditer(re.escape(d), data):
            try:
                j, _ = parse_job(data, m.start())
            except ParseError:
                continue
            j["source"] = ["%s@0x%x" % (name, m.start())]
            jobs.append(j)
    for m in re.finditer(re.escape(FILE_DELIM), data):
        try:
            f, _ = parse_file(data, m.start())
        except ParseError:
            continue
        # FireEye BitsParser carve heuristic: file GUID sits 22..6 bytes before
        if m.start() >= 22:
            f["file_id_guess"] = str(uuid.UUID(bytes_le=bytes(data[m.start() - 22:m.start() - 6])))
        f["source"] = ["%s@0x%x" % (name, m.start())]
        files.append(f)
    return jobs, files


def parse_i30(path):
    """Minimal INDX parser: walk records + slack for $FILE_NAME keys."""
    with open(path, "rb") as fh:
        data = fh.read()
    out = []
    for blk in range(0, len(data), 4096):
        b = bytearray(data[blk:blk + 4096])
        if b[:4] != b"INDX":
            continue
        usa_off, usa_cnt = struct.unpack_from("<HH", b, 4)
        usn = b[usa_off:usa_off + 2]
        for i in range(1, usa_cnt):                       # undo fix-ups
            pos = i * 512 - 2
            if pos + 2 <= len(b) and b[pos:pos + 2] == usn:
                b[pos:pos + 2] = b[usa_off + 2 * i:usa_off + 2 * i + 2]
        hdr = 0x18
        first, used = struct.unpack_from("<II", b, hdr)[:2]
        live_end = hdr + used
        # scan every offset for a plausible $FILE_NAME (live + slack)
        for o in range(hdr + first, len(b) - 0x52, 2):
            try:
                nlen, ns = b[o + 0x50], b[o + 0x51]
                if not (1 <= nlen <= 255 and ns in (0, 1, 2, 3)):
                    continue
                par = struct.unpack_from("<Q", b, o + 0x10)[0]
                times = struct.unpack_from("<4Q", b, o + 0x18)
                if not all(filetime(t) for t in times):
                    continue
                fname = bytes(b[o + 0x52:o + 0x52 + nlen * 2]).decode("utf-16-le")
                if not fname.isprintable():
                    continue
                size = struct.unpack_from("<Q", b, o + 0x40)[0]
                out.append({"name": fname, "namespace": ns, "logical_size": size,
                            "parent_ref": par & 0xFFFFFFFFFFFF, "created": filetime(times[0]),
                            "modified": filetime(times[1]), "mft_modified": filetime(times[2]),
                            "accessed": filetime(times[3]),
                            "in_slack": o >= live_end,
                            "source": "$I30@0x%x" % (blk + o)})
            except (struct.error, UnicodeDecodeError):
                continue
    seen, res = set(), []
    for e in out:
        k = (e["name"], e["created"], e["modified"], e["logical_size"])
        if k in seen or e["namespace"] == 2:
            continue
        seen.add(k); res.append(e)
    return res


def slack_strings(path):
    """FileSlack is not BITS data - only list ASCII/UTF-16 URLs for leads."""
    with open(path, "rb") as fh:
        data = fh.read()
    urls = set(m.group().decode("ascii", "replace") for m in
               re.finditer(rb"https?://[\x21-\x7e]{4,300}", data))
    for m in re.finditer(rb"h\x00t\x00t\x00p\x00s?\x00:\x00/\x00/\x00(?:[\x21-\x7e]\x00){4,300}", data):
        urls.add(m.group().decode("utf-16-le", "replace"))
    return sorted(urls)


# ---------------------------------------------------------------- merge / triage
def job_key(j):
    return (j.get("job_id"), j.get("name"), j.get("state"), j.get("modified"),
            j.get("notify_cmd"), tuple(j.get("file_ids", [])))


def file_key(f):
    return (f.get("dest_file"), f.get("source_url"), f.get("tmp_file"), f.get("transfer_size"))


def merge(records, keyf):
    out = {}
    for r in records:
        k = keyf(r)
        if k in out:
            for s in r["source"]:
                if s not in out[k]["source"]:
                    out[k]["source"].append(s)
        else:
            out[k] = r
    return list(out.values())


def _remote_local(f):
    """Return (remote URL, local path). For upload jobs BITS stores them the other way round."""
    a, b = f.get("source_url") or "", f.get("dest_file") or ""
    return (b, a) if is_url(b) and not is_url(a) else (a, b)


def triage(job, files):
    flags = []
    prog, args = job.get("notify_cmd") or "", job.get("notify_args") or ""
    cmd = (prog + " " + args).strip()
    if cmd:
        sysbin = re.match(r'^\s*"?[a-z]:\\windows\\system32\\[^\\ ]+\.exe"?$', prog, re.I)
        lolbin = re.search(r"\\(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|"
                           r"certutil|bitsadmin|msiexec)\.exe", prog + " " + args, re.I) or \
            re.match(r"^\s*(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript)(\.exe)?\b",
                     args, re.I)
        lvl = "REVIEW" if sysbin and not lolbin else "HIGH"
        flags.append(lvl + ": notify command set (persistence vector) - verify signer/args: " + cmd)
        if USER_WRITABLE.search(cmd):
            flags.append("HIGH: notify command in user-writable path")
        if lolbin:
            flags.append("HIGH: notify command uses LOLBin/interpreter")
        if job.get("errors") or job.get("state") in ("error", "transient_error"):
            flags.append(lvl + ": job erroring AND has notify command (error-loop persistence pattern)")
    if job.get("errors"):
        flags.append("INFO: transfer error " + ", ".join(
            "%s (%s)" % (e.get("hresult"), HRESULT_HINT.get(e.get("hresult"), "see bits.h / winerror.h"))
            for e in job["errors"]))
    if job.get("job_type") in ("upload", "upload_reply"):
        flags.append("MED: upload job (possible exfiltration)")
    if re.search(r"system update|windows update|\bupdate\s*$", job.get("name") or "", re.I):
        flags.append("MED: generic 'update' style job name")
    creator = job.get("creator_process_inferred") or job.get("creator_process_evt") or ""
    if ATTACKER_CREATORS.search(creator):
        flags.append("MED: job created by %s (scripted/manual BITS use)" % ntpath.basename(creator))
    elif creator and USER_WRITABLE.search(creator):
        flags.append("MED: job created by a process in a user-writable path: " + creator)
    for f in files:
        remote, local = _remote_local(f)
        host = url_host(remote)
        if host in ("localhost", "0.0.0.0", "::1") or host.startswith("127."):
            flags.append("HIGH: remote URL is localhost (never-resolving error loop trick): " + remote)
        elif re.fullmatch(r"\d+\.\d+\.\d+\.\d+|[0-9a-f:]+:[0-9a-f:]*", host or "x"):
            flags.append("MED: remote URL is a raw IP: " + remote)
        if remote and not is_url(remote) and remote.startswith("\\\\"):
            flags.append("MED: SMB/UNC transfer: " + remote)
        if re.search(r"\.(exe|dll|ps1|bat|cmd|vbs|js|jse|hta|scr|msi|lnk|sys)$", local, re.I) \
                and not benign_host(remote):
            flags.append("MED: executable/script written by BITS: " + local)
        if remote and not benign_host(remote) and not host.startswith("127.") and \
                host not in ("localhost", ""):
            flags.append("INFO: non-allowlisted host " + host)
    if job.get("sd_owner_sid") and job.get("owner_sid") and job["sd_owner_sid"] != job["owner_sid"]:
        flags.append("MED: job security-descriptor owner %s differs from job owner %s (take-over/tamper?)"
                     % (job["sd_owner_sid"], job["owner_sid"]))
    flags += file_status_flags(files)
    if not any(x.split(":")[0] in ("HIGH", "MED", "REVIEW") for x in flags):
        hosts_ok = files and all(benign_host(_remote_local(f)[0]) for f in files)
        if hosts_ok or (not files and BENIGN_CREATORS.match(creator or "")):
            flags.append("INFO: looks like known-benign updater noise")
    return flags




# ---------------------------------------------------------------- pipeline
LEVELS = ("HIGH", "MED", "REVIEW", "INFO")
ACTIVE_SRC = "qmgr.db:Jobs (active)"


def level_of(flags):
    for lv in LEVELS:
        if any(f.startswith(lv) for f in flags):
            return lv
    return ""


def retriage(j):
    j["triage"] = triage(j, j.get("files") or [])
    j["level"] = level_of(j["triage"])
    return j


# Every job record - DB, carved, event-log-only or live - carries every key, so consumers
# (CSV, GUI, scripts) never hit a KeyError. None = "not known from this source".
JOB_SCHEMA = {
    "job_id": "", "name": "", "description": None, "status": "", "state": "", "job_type": "",
    "priority": None, "owner_sid": None, "owner": None, "created": None, "modified": None,
    "transfer_completed": None, "expiration": None, "notify_cmd": "", "notify_args": "",
    "notify_flags": None, "notify_cmd_evt": None, "notify_args_evt": None, "retry_delay_s": None,
    "no_progress_timeout_s": None, "transient_error_count": None, "errors": [], "file_ids": [],
    "files": [], "events": [], "creator_process_inferred": None, "creator_process_evt": None,
    "creator_aumid_inferred": None, "http_method": None, "sd_owner_sid": None, "sd_group_sid": None,
    "sd_dacl": [], "sd_sddl": None, "tail_complete": None, "source": [], "triage": [], "level": "",
}


def normalize_job(j):
    for k, v in JOB_SCHEMA.items():
        if k not in j:
            j[k] = list(v) if isinstance(v, list) else v
    return j


def _walk(input_dir):
    """All files below input_dir (KAPE exports nest the Downloader path)."""
    for root, dirs, fns in os.walk(input_dir):
        dirs.sort()
        for fn in sorted(fns):
            p = os.path.join(root, fn)
            if os.path.isfile(p):
                yield p, os.path.relpath(p, input_dir)


def analyse(input_dir, no_carve=False, progress=None, events=None, mount_root=None, mft_drive="C:"):
    """Parse + carve a collection folder (recursively).

    Recognised anywhere below input_dir: qmgr.db, edb*/jrs logs (carved), $I30*, *.evtx
    (BITS-Client -> events; PowerShell/other channels -> BITS command hunting),
    ConsoleHost_history.txt (PSReadLine), MFTECmd $MFT CSV, *.FileSlack.
    `events`     extra pre-read BITS events (e.g. the live log) to correlate.
    `mount_root` mounted image root: check whether each job's local file exists + hash."""
    say = progress or (lambda m: None)
    inventory, all_jobs, all_files, notes = [], [], [], []
    ese_files = {}
    i30, slack, evtx_events, commands, mft_csvs, raw_mfts = [], {}, [], [], [], []
    for p, rel in _walk(input_dir):
        fn = os.path.basename(p)
        low = fn.lower()
        say("hashing " + rel)
        inventory.append({"file": rel, "size": os.path.getsize(p), "sha256": sha256(p)})
        if low == "qmgr.db":
            say("reading ESE tables in " + rel)
            j, f, n = read_ese(p)
            all_jobs += j; ese_files.update(f); notes += n
        if re.fullmatch(r"qmgr[01]\.dat", low):
            notes.append("%s is the Win7/8 legacy queue format: only signature carving is applied "
                         "(field layout differs, results may be partial)" % rel)
        if low == "$i30" or low.startswith("$i30"):
            say("parsing " + rel); i30 += parse_i30(p); continue
        if low.endswith(".fileslack"):
            slack[rel] = slack_strings(p); continue
        if low.endswith(".evtx"):
            say("reading event log " + rel)
            try:
                evs = read_events(path=p, match=BITS_CMD_RE.pattern)
                evtx_events += [e for e in evs if "bits-client" in (e.get("channel") or "").lower()]
                commands += commands_from_events(
                    [e for e in evs if "bits-client" not in (e.get("channel") or "").lower()])
            except Exception as e:
                notes.append("event log %s: %s" % (rel, e))
            continue
        if low == "consolehost_history.txt":
            commands += scan_ps_history(p); continue
        if low.endswith(".csv"):
            if is_mftecmd_csv(p):
                mft_csvs.append(p)
            continue
        if low == "$mft" or low.startswith("$mft."):
            raw_mfts.append(p); continue                  # NTFS metadata: parse, never carve
        if low.startswith(("$logfile", "$usnjrnl", "$j", "$secure", "$boot", "$bitmap")):
            continue
        if low.endswith((".txt", ".json", ".md")):
            continue
        if not no_carve and not low.endswith((".chk", ".jfm")):
            say("carving " + rel)
            cj, cf = carve(p, rel)
            all_jobs += cj; all_files += cf

    say("merging + triage")
    for fid, f in ese_files.items():
        f["source"] = ["qmgr.db:Files (active)"]
    files = merge(list(ese_files.values()) + all_files, file_key)
    jobs = merge(all_jobs, job_key)

    active_ids = {j["job_id"] for j in jobs if ACTIVE_SRC in j["source"]}
    by_fid = {}
    for f in files:
        for k in ("file_id", "file_id_guess"):
            if f.get(k):
                by_fid.setdefault(f[k], []).append(f)
    for j in jobs:
        j["status"] = "active" if ACTIVE_SRC in j["source"] else \
            ("historic_version_of_active" if j["job_id"] in active_ids else "deleted/recovered")
        linked = []
        for fid in j.get("file_ids", []):
            for f in by_fid.get(fid, []):
                if f not in linked:
                    linked.append(f)
        j["files"] = [{k: v for k, v in f.items() if k != "source"} for f in linked]

    all_events = evtx_events + list(events or [])
    jobs = [normalize_job(j) for j in correlate(jobs, all_events, "event log only")]
    if mount_root:
        say("checking local files under " + mount_root)
        check_files(jobs, mount_root)
    for c in mft_csvs:
        say("correlating $MFT CSV " + os.path.basename(c))
        try:
            notes.append("$MFT CSV %s: %d matches" % (os.path.basename(c), correlate_mft(jobs, c, mft_drive)))
        except Exception as e:
            notes.append("$MFT CSV %s: %s" % (os.path.basename(c), e))
    for m in raw_mfts:
        say("scanning raw $MFT %s (one pass)" % os.path.basename(m))
        try:
            n, stats = correlate_raw_mft(jobs, m, mft_drive)
            notes.append("raw $MFT %s: %d records scanned, %d matches"
                         % (os.path.basename(m), stats["records"], n))
        except Exception as e:
            notes.append("raw $MFT %s: %s: %s" % (os.path.basename(m), type(e).__name__, e))
    for j in jobs:
        retriage(j)
    jobs.sort(key=lambda j: (j.get("created") or "", j.get("modified") or ""))
    latest = latest_per_job(jobs)

    return {"tool": "bits_qmgr_parser", "version": __version__,
            "run_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "input": os.path.abspath(input_dir), "inventory": inventory,
            "summary": {"job_records": len(jobs), "unique_jobs": len(latest),
                        "active_jobs": len(active_ids),
                        "recovered_only_jobs": len([j for j in latest
                                                    if j["job_id"] not in active_ids
                                                    and j["status"] != "event log only"]),
                        "event_only_jobs": len([j for j in latest if j["status"] == "event log only"]),
                        "events": len(all_events),
                        "file_records": len(files), "i30_entries": len(i30),
                        "flagged_jobs": len({j["job_id"] for j in latest
                                             if j["level"] in ("HIGH", "MED", "REVIEW")}),
                        "commands": len(commands)},
            "jobs": jobs, "latest": latest, "files": files, "i30": i30, "events": all_events,
            "commands": commands, "do_downloads": [],
            "fileslack_urls": slack, "parse_notes": notes}


def latest_per_job(jobs):
    latest = {}
    for j in jobs:
        cur = latest.get(j["job_id"])
        if cur is None or (j.get("modified") or "") > (cur.get("modified") or ""):
            latest[j["job_id"]] = j
    return list(latest.values())


def write_outputs(result, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    jobs, files, i30 = result["jobs"], result["files"], result["i30"]
    with open(os.path.join(out_dir, "bits_report.json"), "w", encoding="utf-8") as fh:
        json.dump({k: v for k, v in result.items() if k != "latest"}, fh, indent=2, default=str)

    def row_safe(d):
        return {k: csv_safe(v) for k, v in d.items()}
    cols = ["level", "status", "job_id", "name", "job_type", "state", "priority", "owner_sid", "owner",
            "created", "modified", "transfer_completed", "expiration", "notify_cmd", "notify_args",
            "notify_flags", "creator_process_inferred", "creator_process_evt", "creator_aumid_inferred",
            "http_method", "error_count", "event_count", "source_url", "dest_file", "tmp_file",
            "download_size", "transfer_size", "triage", "source"]
    with open(os.path.join(out_dir, "bits_jobs.csv"), "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, cols, extrasaction="ignore")
        w.writeheader()
        for j in jobs:
            for f in (j.get("files") or [{}]):
                row = dict(j); row.update({k: f.get(k) for k in
                                           ("source_url", "dest_file", "tmp_file",
                                            "download_size", "transfer_size")})
                row["error_count"] = len(j.get("errors", []))
                row["event_count"] = len(j.get("events", []))
                row["triage"] = " | ".join(j["triage"]); row["source"] = " ; ".join(j["source"])
                w.writerow(row_safe(row))
    with open(os.path.join(out_dir, "bits_files.csv"), "w", newline="", encoding="utf-8-sig") as fh:
        fc = ["file_id", "file_id_guess", "source_url", "dest_file", "tmp_file", "download_size",
              "transfer_size", "complete", "drive", "volume_guid",
              "remote_last_modified_inferred", "source"]
        w = csv.DictWriter(fh, fc, extrasaction="ignore"); w.writeheader()
        for f in files:
            row = dict(f); row["source"] = " ; ".join(f["source"]); w.writerow(row_safe(row))
    if i30:
        with open(os.path.join(out_dir, "i30_entries.csv"), "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, list(i30[0].keys())); w.writeheader()
            w.writerows(row_safe(r) for r in i30)
    if result.get("events"):
        with open(os.path.join(out_dir, "bits_events.csv"), "w", newline="", encoding="utf-8-sig") as fh:
            ec = ["time", "event_id", "what", "job_name", "job_id", "url", "local", "process",
                  "program", "parameters", "owner", "hr", "bytes_total", "bytes_transferred",
                  "record", "source", "message"]
            w = csv.DictWriter(fh, ec, extrasaction="ignore"); w.writeheader()
            w.writerows(row_safe(e) for e in result["events"])
    if result.get("commands"):
        with open(os.path.join(out_dir, "bits_commands.csv"), "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, ["level", "time", "kind", "text", "note", "source", "record", "line_no"],
                               extrasaction="ignore"); w.writeheader()
            w.writerows(row_safe(c) for c in result["commands"])
    if result.get("do_downloads"):
        with open(os.path.join(out_dir, "delivery_optimization.csv"), "w", newline="", encoding="utf-8-sig") as fh:
            dc = ["level", "status", "caller", "host", "source_url", "size", "downloaded", "from_http",
                  "from_peers", "mode", "priority", "cache_host", "expires", "duration", "file_id"]
            w = csv.DictWriter(fh, dc, extrasaction="ignore"); w.writeheader()
            w.writerows(row_safe(d) for d in result["do_downloads"])


# ---------------------------------------------------------------- event log
EVENT_WHAT = {3: "job created", 4: "job completed", 5: "job cancelled", 6: "notify command set",
              59: "transfer started", 60: "transfer stopped", 61: "transfer error",
              16403: "file added to job", 209: "high-performance property", 306: "job list loaded",
              310: "peer helper init failed", 7: "job modified (owner/props)"}

EVENTS_PS = r"""
$ErrorActionPreference='Stop'
$p = @{}
if ($env:BITS_EVTX_PATH) { $p['Path'] = $env:BITS_EVTX_PATH }
else { $p['LogName'] = $(if ($env:BITS_EVT_LOG) { $env:BITS_EVT_LOG } else { 'Microsoft-Windows-Bits-Client/Operational' }) }
try { $ev = @(Get-WinEvent @p -Oldest) } catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $ev=@() } else { throw } }
$rx = $env:BITS_EVT_MATCH
@($ev | ForEach-Object {
  $xml = $_.ToXml(); $x = [xml]$xml; $ch = [string]$x.Event.System.Channel
  if ($rx -and $ch -notlike '*Bits-Client*' -and $xml -notmatch $rx) { return }
  $d = @{}
  foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }
  $m = ''; try { $m = ($_.Message -split "`r?`n")[0] } catch {}
  [pscustomobject]@{ id=$_.Id; time=$_.TimeCreated.ToUniversalTime().ToString('o'); record=$_.RecordId;
                     channel=$ch; data=$d; message=$m }
}) | ConvertTo-Json -Depth 4 -Compress
"""


def _ps(script, env_extra=None, timeout=180):
    import subprocess
    env = dict(os.environ)
    for k in ("BITS_EVTX_PATH", "BITS_EVT_LOG", "BITS_EVT_MATCH"):
        env.pop(k, None)
    env.update(env_extra or {})
    exe = "powershell" if os.name == "nt" else "pwsh"
    out = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", script],
                         capture_output=True, text=True, encoding="utf-8", errors="replace",
                         timeout=timeout, env=env,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if out.returncode != 0 and not out.stdout.strip():
        raise RuntimeError("PowerShell failed: " + (out.stderr.strip().splitlines() or ["?"])[0][:300])
    return out.stdout.strip()


def _guid(s):
    return (s or "").strip("{}").lower()


def normalize_event(e, source):
    d = e.get("data") or {}
    eid = int(e.get("id"))
    hr = d.get("hr")
    try:
        hr = "0x%08X" % (int(hr) & 0xFFFFFFFF) if hr not in (None, "") else ""
    except ValueError:
        pass
    return {"time": e.get("time") or "",
            "event_id": eid, "what": EVENT_WHAT.get(eid, "event %d" % eid),
            "job_id": _guid(d.get("jobId") or d.get("Id")),
            "job_name": d.get("jobTitle") or d.get("name") or d.get("jobName") or "",
            "url": d.get("url") or d.get("RemoteName") or "", "local": d.get("LocalName") or "",
            "process": d.get("processPath") or "", "program": d.get("program") or "",
            "parameters": d.get("parameters") or "", "owner": d.get("jobOwner") or d.get("User") or "",
            "hr": hr if hr not in ("0x00000000",) else "", "bytes_total": d.get("bytesTotal"),
            "bytes_transferred": d.get("bytesTransferred"), "record": e.get("record"),
            "channel": e.get("channel") or "Microsoft-Windows-Bits-Client/Operational",
            # 4104 -> ScriptBlockText; 4103 -> Payload (pipeline detail) AND ContextInfo (the
            # host command line). Keep all of them: the BITS call is often only in ContextInfo.
            "script": "\n".join(v for v in (d.get("ScriptBlockText"), d.get("Payload"),
                                            d.get("ContextInfo")) if v),
            "source": source, "message": e.get("message") or ""}


def read_events(path=None, raw_json=None, log=None, match=None):
    """Event records from the live BITS-Client log (default), another live `log`, or an .evtx.
    `match`: regex; events from non-BITS channels are only returned if their XML matches."""
    env = {}
    if path:
        env["BITS_EVTX_PATH"] = os.path.abspath(path)
    if log:
        env["BITS_EVT_LOG"] = log
    if match:
        env["BITS_EVT_MATCH"] = match
    txt = raw_json if raw_json is not None else _ps(EVENTS_PS, env or None)
    if not txt:
        return []
    data = json.loads(txt)
    if isinstance(data, dict):
        data = [data]
    src = ("evtx:" + os.path.basename(path)) if path else ("eventlog:live" if not log else "live:" + log)
    return [normalize_event(e, src) for e in data]


def correlate(jobs, events, standalone_status):
    """Attach events to jobs by job GUID, fill gaps, add jobs only seen in the log."""
    by_job = {}
    for e in sorted(events, key=lambda e: e.get("time") or ""):
        if e.get("job_id"):
            by_job.setdefault(e["job_id"], []).append(e)
    known = {_guid(j.get("job_id")) for j in jobs}
    for j in jobs:
        evs = by_job.get(_guid(j.get("job_id")), [])
        if evs:
            j["events"] = evs
            _enrich(j, evs)
    for jid, evs in by_job.items():
        if jid in known:
            continue
        j = {"job_id": jid, "name": next((e["job_name"] for e in evs if e["job_name"]), ""),
             "status": standalone_status, "state": evs[-1]["what"], "job_type": "",
             "created": None, "modified": evs[-1]["time"], "notify_cmd": "", "notify_args": "",
             "errors": [], "files": [], "events": evs, "source": sorted({e["source"] for e in evs})}
        _enrich(j, evs)
        jobs.append(j)
    return jobs


def _enrich(j, evs):
    files = j.setdefault("files", [])
    seen = {(f.get("source_url"), f.get("dest_file")) for f in files}
    for e in evs:
        if e["event_id"] == 3:
            if not j.get("created"):
                j["created"] = e["time"]
            j["creator_process_evt"] = e["process"]
            if not j.get("owner"):
                j["owner"] = e["owner"]
        elif e["event_id"] == 6 and (e["program"] or e["parameters"]):
            j["notify_cmd_evt"] = e["program"]; j["notify_args_evt"] = e["parameters"]
            if not j.get("notify_cmd") and not j.get("notify_args"):
                j["notify_cmd"], j["notify_args"] = e["program"], e["parameters"]
        elif e["event_id"] == 61 and e["hr"]:
            if j.get("status") == "event log only" or j.get("status", "").startswith("live"):
                if not any(x.get("hresult") == e["hr"] for x in j.setdefault("errors", [])):
                    j["errors"].append({"hresult": e["hr"], "stats": [], "from": "event 61"})
        if e["url"] and not any(e["url"] in k for k in seen):
            f = {"source_url": e["url"], "dest_file": e["local"], "from": "event %d" % e["event_id"]}
            files.append(f); seen.add((e["url"], e["local"]))
        elif e["url"] and e["local"]:
            for f in files:
                if f.get("source_url") == e["url"] and not f.get("dest_file"):
                    f["dest_file"] = e["local"]


# ---------------------------------------------------------------- live (current user only)
LIVE_PS = r"""
$ErrorActionPreference='Stop'
@(Get-BitsTransfer | ForEach-Object {
  [pscustomobject]@{
    job_id=$_.JobId.ToString(); name=$_.DisplayName; description=$_.Description
    job_type=[int]$_.TransferType; state=[int]$_.JobState; priority=[int]$_.Priority
    owner=$_.OwnerAccount.Value; created=$_.CreationTime.ToUniversalTime().ToString('o')
    modified=$_.ModificationTime.ToUniversalTime().ToString('o')
    completed=$(if($_.TransferCompletionTime.Year -gt 1){$_.TransferCompletionTime.ToUniversalTime().ToString('o')})
    error_context=[int]$_.ErrorContext
    error_code=$(if($_.InternalErrorCode){'0x{0:X8}' -f $_.InternalErrorCode}); retry_delay_s=$_.RetryInterval
    notify_cmd=$_.NotifyCmdLine[0]; notify_args=$_.NotifyCmdLine[1]; notify_flags=[int]$_.NotifyFlags
    files=@($_.FileList | ForEach-Object { @{source_url=$_.RemoteName; dest_file=$_.LocalName;
           download_size=$_.BytesTransferred; transfer_size=$_.BytesTotal} })
  } }) | ConvertTo-Json -Depth 4
"""


def live_snapshot():
    """Live jobs (current user) + live BITS-Client event log, correlated.
    Returns (jobs, events). Events-only jobs include other users' and deleted jobs."""
    jobs = live_jobs()
    try:
        events = read_events()
    except Exception as e:
        events = []
        for j in jobs:
            j.setdefault("notes", []).append("event log unavailable: %s" % e)
    jobs = [normalize_job(j) for j in correlate(jobs, events, "event log only (live)")]
    check_files(jobs)                       # live disk: does the payload still exist? hash it
    return jobs, events


def live_extras():
    """Other no-admin sources on this PC: PSReadLine history, PowerShell/Operational
    script blocks that mention BITS, Delivery Optimization cache. Never raises."""
    out = {"commands": [], "do_downloads": [], "notes": []}
    hist = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "PowerShell",
                        "PSReadLine", "ConsoleHost_history.txt")
    if os.path.isfile(hist):
        out["commands"] += scan_ps_history(hist)
    for log in ("Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"):
        try:
            out["commands"] += commands_from_events(read_events(log=log, match=BITS_CMD_RE.pattern))
        except Exception as e:
            out["notes"].append("%s: %s" % (log, e))
    try:
        out["do_downloads"] = delivery_optimization()
    except Exception as e:
        out["notes"].append("Delivery Optimization: %s" % e)
    return out


def live_jobs(raw_json=None):
    """Jobs visible to the current user via Get-BitsTransfer (no admin needed)."""
    txt = raw_json if raw_json is not None else _ps(LIVE_PS, timeout=60)
    if not txt:
        return []
    data = json.loads(txt)
    if isinstance(data, dict):
        data = [data]
    jobs = []
    for d in data:
        j = dict(d)
        j["job_type"] = JOB_TYPE.get(d.get("job_type"), str(d.get("job_type")))
        j["state"] = JOB_STATE.get(d.get("state"), str(d.get("state")))
        j["priority"] = JOB_PRIO.get(d.get("priority"), str(d.get("priority")))
        j["errors"] = ([{"hresult": d["error_code"], "stats": [d.get("error_context")]}]
                       if d.get("error_code") else [])
        j["notify_cmd"] = d.get("notify_cmd") or ""
        j["notify_args"] = d.get("notify_args") or ""
        files = d.get("files") or []
        if isinstance(files, dict):
            files = [files]
        for f in files:
            if f.get("transfer_size") == 0xFFFFFFFFFFFFFFFF:
                f["transfer_size"] = None
        j["files"] = files
        j["status"] = "live"
        j["source"] = ["Get-BitsTransfer"]
        j["triage"] = triage(j, files)
        j["level"] = level_of(j["triage"])
        jobs.append(normalize_job(j))
    return jobs


# ---------------------------------------------------------------- extra artifacts
BITS_CMD_RE = re.compile(r"\bbitsadmin(\.exe)?\b|\b(Start|Get|Set|Add|Complete|Remove|Suspend|Resume)"
                         r"-BitsTransfer\b|BackgroundCopyManager|IBackgroundCopy|"
                         r"Import-Module\s+BitsTransfer|SetNotifyCmdLine", re.I)


def command_level(text):
    t = text or ""
    if re.search(r"SetNotifyCmdLine", t, re.I):          # setting it, not merely reading .NotifyCmdLine
        return "HIGH"
    urls = re.findall(r"[a-z][a-z0-9+.-]*://[^\s'\"<>]+", t, re.I)
    if any(url_host(u).startswith("127.") or url_host(u) == "localhost" for u in urls):
        return "HIGH"
    if re.search(r"/upload\b|TransferType\s+Upload|/transfer\b|/create\b|/addfile\b|Start-BitsTransfer", t, re.I) \
            and not (urls and all(benign_host(u) for u in urls)):
        return "MED"
    return "INFO"


def _cmd(source, text, time=None, kind="", extra=None):
    m = BITS_CMD_RE.search(text or "")
    s = max(0, (m.start() if m else 0) - 150)
    snippet = (text or "")[s:s + 500].replace("\r", " ").replace("\n", " ⏎ ")
    d = {"time": time, "kind": kind, "source": source, "text": snippet, "level": command_level(text)}
    if "[pscustomobject]@{" in (text or "") and "job_id=$_.JobId.ToString()" in (text or ""):
        d["note"] = "read-only query made by bits-qmgr's own live mode"
        d["level"] = "INFO"
    d.update(extra or {})
    return d


def scan_ps_history(path):
    """PSReadLine ConsoleHost_history.txt -> BITS-related command lines (no timestamps exist)."""
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                if BITS_CMD_RE.search(line):
                    out.append(_cmd("%s:%d" % (path, n), line.strip(), None, "PSReadLine history",
                                    {"line_no": n}))
    except OSError:
        pass
    return out


def commands_from_events(events):
    """PowerShell 4103/4104 (or any non-BITS channel) events that mention BITS."""
    out = []
    for e in events:
        txt = "\n".join(x for x in (e.get("script"), e.get("message")) if x)
        if BITS_CMD_RE.search(txt):
            out.append(_cmd(e.get("source"), txt, e.get("time"), "%s %s" % (
                (e.get("channel") or "").split("/")[0].replace("Microsoft-Windows-", ""), e["event_id"]),
                {"record": e.get("record")}))
    return out


DO_PS = r"""
$ErrorActionPreference='Stop'
@(Get-DeliveryOptimizationStatus | ForEach-Object { [pscustomobject]@{
  file_id=$_.FileId; source_url=$_.SourceURL; size=$_.FileSize; downloaded=$_.TotalBytesDownloaded
  status=[string]$_.Status; priority=[string]$_.Priority; mode=[string]$_.DownloadMode
  from_http=$_.BytesFromHttp; from_peers=$_.BytesFromPeers; cache_host=$_.CacheHost
  caller=$_.PredefinedCallerApplication; expires=$(if($_.ExpireOn){$_.ExpireOn.ToUniversalTime().ToString('o')})
  duration=[string]$_.DownloadDuration } }) | ConvertTo-Json -Depth 3 -Compress
"""


def delivery_optimization(raw_json=None):
    """Live Delivery Optimization cache (non-BITS Windows Update/Store/Office/Edge downloads)."""
    txt = raw_json if raw_json is not None else _ps(DO_PS, timeout=90)
    if not txt:
        return []
    data = json.loads(txt)
    if isinstance(data, dict):
        data = [data]
    for d in data:
        h = url_host(d.get("source_url") or "")
        d["host"] = h
        d["level"] = "INFO" if (benign_host(d.get("source_url")) or not h) else "MED"
        d["triage"] = [] if d["level"] == "INFO" else ["MED: Delivery Optimization source not allowlisted: " + h]
    return data


def _map_path(p, root):
    if not p or is_url(p) or "%" in p:
        return None
    if root is None:
        return p
    m = re.match(r"^[A-Za-z]:\\(.*)$", p)
    if not m:
        return None
    base = os.path.realpath(root)
    q = os.path.realpath(os.path.join(base, *[x for x in m.group(1).split("\\") if x]))
    # attacker-controlled paths must not escape the mounted image (e.g. C:\..\..\x)
    return q if os.path.commonpath([base, q]) == base else None


def check_files(jobs, root=None, hash_limit=256 << 20):
    """Does each job's local file exist (live disk, or a mounted image at `root`)? Size, times, SHA-256."""
    for j in jobs:
        for f in j.get("files") or []:
            remote, local = _remote_local(f)
            for key, p in (("local_check", local), ("tmp_check", f.get("tmp_file"))):
                q = _map_path(p, root)
                if not q:
                    continue
                res = {"path": q, "exists": os.path.isfile(q)}
                if res["exists"]:
                    st = os.stat(q)
                    res.update(size=st.st_size, modified=dt.datetime.fromtimestamp(
                        st.st_mtime, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
                    if st.st_size <= hash_limit:
                        try:
                            res["sha256"] = sha256(q)
                        except OSError as e:
                            res["error"] = str(e)
                f[key] = res
        retriage(j)
    return jobs


MFT_COLS = {"ParentPath", "FileName", "InUse"}


def is_mftecmd_csv(path):
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            return MFT_COLS <= set(next(csv.reader(fh), []))
    except OSError:
        return False


def correlate_mft(jobs, csv_path, drive="C:"):
    """MFTECmd $MFT CSV -> did each job's local/tmp file land, get deleted, or never exist?"""
    want = {}
    for j in jobs:
        for f in j.get("files") or []:
            for p in (_remote_local(f)[1], f.get("tmp_file")):
                if p and re.match(r"^[A-Za-z]:\\", p) and p[:2].upper() == drive.upper():
                    want.setdefault(p.lower(), []).append(f)
    if not want:
        return 0
    hits = 0
    with open(csv_path, encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            par = (row.get("ParentPath") or "").lstrip(".")
            full = (drive + par.rstrip("\\") + "\\" + (row.get("FileName") or "")).lower()
            for f in want.get(full, []):
                ent = {"in_use": (row.get("InUse") or "").lower() == "true",
                       "entry": row.get("EntryNumber"), "size": row.get("FileSize"),
                       "created": row.get("Created0x10"), "modified": row.get("LastModified0x10"),
                       "fn_created": row.get("Created0x30"), "source": os.path.basename(csv_path)}
                f.setdefault("mft", []).append(ent)
                hits += 1
    for j in jobs:
        retriage(j)
    return hits


class RawMft:
    """Minimal read-only $MFT parser (file records, fix-ups, $SI/$FN/$DATA, path resolution).
    Only what is needed to answer: did this path exist, is it deleted, size, timestamps."""

    def __init__(self, path):
        import mmap
        self._fh = open(path, "rb")
        self.size = os.path.getsize(path)
        self.mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        rs = 1024                       # record size from the first valid FILE record (record 0
        for o in range(0, min(self.size, 1 << 20), 1024):   # may be missing in partial copies)
            if self.mm[o:o + 4] == b"FILE":
                v = struct.unpack_from("<I", self.mm, o + 0x1C)[0]
                rs = v if v in (1024, 4096) else 1024
                break
        self.rec_size = rs
        self.count = self.size // self.rec_size
        self._names = {}

    def close(self):
        self.mm.close(); self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def record(self, n):
        """Parsed record n or None. Applies update-sequence fix-ups on a private copy."""
        o = n * self.rec_size
        if o + self.rec_size > self.size or self.mm[o:o + 4] != b"FILE":
            return None
        b = bytearray(self.mm[o:o + self.rec_size])
        usa_off, usa_cnt = struct.unpack_from("<HH", b, 4)
        if usa_off + 2 * usa_cnt > len(b):
            return None
        for i in range(1, usa_cnt):
            pos = i * 512 - 2
            if pos + 2 <= len(b):
                b[pos:pos + 2] = b[usa_off + 2 * i:usa_off + 2 * i + 2]
        seq, _links, attr_off, flags = struct.unpack_from("<HHHH", b, 0x10)
        base = struct.unpack_from("<Q", b, 0x20)[0] & 0xFFFFFFFFFFFF
        rec = {"entry": n, "seq": seq, "in_use": bool(flags & 1), "is_dir": bool(flags & 2),
               "names": [], "si": None, "size": None, "base": base, "attr_list": []}
        p = attr_off
        while p + 16 <= len(b):
            typ, ln = struct.unpack_from("<II", b, p)
            if typ == 0xFFFFFFFF or ln < 16 or p + ln > len(b):
                break
            nonres, name_len = b[p + 8], b[p + 9]
            if not nonres:
                csz, coff = struct.unpack_from("<IH", b, p + 0x10)
                c = p + coff
                if typ == 0x10 and csz >= 32:
                    rec["si"] = struct.unpack_from("<4Q", b, c)
                elif typ == 0x30 and csz >= 0x42:
                    par = struct.unpack_from("<Q", b, c)[0]
                    times = struct.unpack_from("<4Q", b, c + 8)
                    nlen, ns = b[c + 0x40], b[c + 0x41]
                    try:
                        nm = bytes(b[c + 0x42:c + 0x42 + 2 * nlen]).decode("utf-16-le")
                    except UnicodeDecodeError:
                        nm = None
                    if nm is not None:
                        rec["names"].append((ns, nm, par & 0xFFFFFFFFFFFF, par >> 48, times))
                elif typ == 0x80 and name_len == 0:
                    rec["size"] = csz
                elif typ == 0x20:                      # resident $ATTRIBUTE_LIST
                    q = c
                    while q + 26 <= c + csz:
                        a_typ, a_len = struct.unpack_from("<IH", b, q)
                        a_nlen = b[q + 6]
                        a_ref = struct.unpack_from("<Q", b, q + 16)[0] & 0xFFFFFFFFFFFF
                        if a_len < 26:
                            break
                        rec["attr_list"].append((a_typ, a_nlen, a_ref))
                        q += a_len
            elif typ == 0x80 and name_len == 0 and rec["size"] is None:
                rec["size"] = struct.unpack_from("<Q", b, p + 0x30)[0]     # real size
            p += ln
        return rec

    def full_record(self, n):
        """Record n merged with its extension records: base $SI/flags + every $FN and $DATA size,
        whether the hit was found in the base or in an extension record."""
        rec = self.record(n)
        if rec is None:
            return None
        if rec["base"] and rec["base"] != n:
            base = self.record(rec["base"])
            if base is None:
                return rec
            rec = base
        for a_typ, a_nlen, a_ref in rec["attr_list"]:
            if a_ref == rec["entry"] or a_typ not in (0x30, 0x80):
                continue
            ext = self.record(a_ref)
            if not ext:
                continue
            for nm in ext["names"]:
                if nm not in rec["names"]:
                    rec["names"].append(nm)
            if a_typ == 0x80 and a_nlen == 0 and rec["size"] is None:
                rec["size"] = ext["size"]
        return rec

    @staticmethod
    def best_name(rec):
        names = sorted(rec["names"], key=lambda x: {1: 0, 3: 1, 0: 2, 2: 3}.get(x[0], 4))
        return names[0] if names else None

    def paths_of(self, rec, drive="C:"):
        """Every path of a record: one per hard link (distinct non-DOS $FILE_NAME parent/name).
        System32 binaries, for example, are hard links shared with WinSxS."""
        out, seen = [], set()
        for ns, nm, par, par_seq, t in rec["names"]:
            if ns == 2 or (nm.lower(), par) in seen:
                continue
            seen.add((nm.lower(), par))
            out.append(self.path_of(dict(rec, names=[(ns, nm, par, par_seq, t)]), drive))
        return out or [self.path_of(rec, drive)]

    def path_of(self, rec, drive="C:"):
        """Full path via parent chain. Returns (path, complete). complete=False if a parent was
        reused (sequence mismatch) - typical for deleted files in deleted folders."""
        parts, cur, complete, seen = [], rec, True, set()
        for _ in range(255):
            bn = self.best_name(cur)
            if not bn:
                complete = False; break
            _ns, nm, par, par_seq, _t = bn
            if cur["entry"] == 5:
                break
            parts.append(nm)
            if par in seen:
                complete = False; break
            seen.add(par)
            if par not in self._names:
                self._names[par] = self.record(par)
            parent = self._names[par]
            if parent is None:
                complete = False; break
            if parent["seq"] != par_seq and par != 5:
                complete = False
            cur = parent
        return drive + "\\" + "\\".join(reversed(parts)), complete

    def scan_names(self, wanted_lower):
        """One pass over all records: those whose $FN name (any namespace) is in wanted_lower.
        Fast path reads only $FILE_NAME names (set lookup); full parse only for hits."""
        hits, seen, mm, rs, unpack = [], set(), self.mm, self.rec_size, struct.unpack_from
        for n in range(self.count):
            o = n * rs
            if mm[o:o + 4] != b"FILE":
                continue
            p = o + unpack("<H", mm, o + 0x14)[0]
            end = o + rs
            hit = False
            while p + 16 <= end:
                typ, ln = unpack("<II", mm, p)
                if typ == 0xFFFFFFFF or ln < 16 or typ > 0x30:
                    break
                if typ == 0x30 and not mm[p + 8]:
                    c = p + unpack("<H", mm, p + 0x14)[0]
                    nlen = mm[c + 0x40]
                    a, z = c + 0x42 - o, c + 0x42 + 2 * nlen - o
                    if any(a <= k * 512 - 2 < z for k in range(1, rs // 512 + 1)):
                        hit = True; break       # name crosses a fix-up slot: verify with full parse
                    raw = mm[c + 0x42:c + 0x42 + 2 * nlen]
                    try:
                        if raw.decode("utf-16-le").lower() in wanted_lower:
                            hit = True; break
                    except UnicodeDecodeError:
                        hit = True; break       # possibly a fix-up inside the name: verify below
                p += ln
            if hit:
                rec = self.full_record(n)
                if rec and rec["entry"] not in seen and \
                        any(nm.lower() in wanted_lower for _ns, nm, *_ in rec["names"]):
                    seen.add(rec["entry"])
                    hits.append(rec)
        return hits


def _ft_iso(v):
    return filetime(v) if v else None


def correlate_raw_mft(jobs, mft_path, drive="C:"):
    """Raw $MFT -> for each job's local/tmp path: entry, in use / DELETED, size, $SI/$FN times."""
    want = {}
    for j in jobs:
        for f in j.get("files") or []:
            for p in (_remote_local(f)[1], f.get("tmp_file")):
                if p and re.match(r"^[A-Za-z]:\\", p) and p[:2].upper() == drive.upper():
                    want.setdefault(p.lower(), []).append(f)
    stats = {"records": 0}
    if not want:
        return 0, stats
    hits = 0
    with RawMft(mft_path) as mft:
        stats["records"] = mft.count
        for rec in mft.scan_names({ntpath.basename(p) for p in want}):
            matched = [(p, c) for p, c in mft.paths_of(rec, drive) if p.lower() in want]
            if not matched:
                continue
            path, complete = matched[0]
            si = rec["si"] or (None,) * 4
            fn = (RawMft.best_name(rec) or (None,) * 5)[4] or (None,) * 4
            for f in want[path.lower()]:
                f.setdefault("mft", []).append({
                    "in_use": rec["in_use"], "entry": rec["entry"], "seq": rec["seq"], "size": rec["size"],
                    "created": _ft_iso(si[0]), "modified": _ft_iso(si[1]), "mft_changed": _ft_iso(si[2]),
                    "accessed": _ft_iso(si[3]), "fn_created": _ft_iso(fn[0]), "path_complete": complete,
                    "source": "raw " + os.path.basename(mft_path)})
                hits += 1
    for j in jobs:
        retriage(j)
    return hits, stats


def file_status_flags(files):
    flags = []
    for f in files:
        local = _remote_local(f)[1]
        lc = f.get("local_check") or {}
        if lc.get("exists") and re.search(r"\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi|sys)$", local, re.I) \
                and not benign_host(_remote_local(f)[0]):
            flags.append("HIGH: BITS-written executable still on disk: %s sha256=%s"
                         % (lc["path"], lc.get("sha256", "?")))
        for m in f.get("mft") or []:
            flags.append("INFO: $MFT entry %s for %s (%s, created %s)" % (
                m["entry"], local, "in use" if m["in_use"] else "DELETED", m["created"]))
    return flags


# ---------------------------------------------------------------- main
def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
    ap = argparse.ArgumentParser(description="BITS qmgr.db parser + carver (v%s)" % __version__)
    ap.add_argument("-i", "--input", required=True,
                    help="collection folder: qmgr.db, edb*.log, $I30, *.evtx, ConsoleHost_history.txt, "
                         "MFTECmd CSV (searched recursively)")
    ap.add_argument("-o", "--output", required=True, help="output folder")
    ap.add_argument("--no-carve", action="store_true", help="ESE tables only")
    ap.add_argument("--live-events", action="store_true",
                    help="also correlate THIS machine's BITS-Client/Operational log "
                         "(only if the evidence came from this machine)")
    ap.add_argument("--live-extras", action="store_true",
                    help="also collect THIS machine's PowerShell history/script blocks mentioning BITS "
                         "and the Delivery Optimization cache")
    ap.add_argument("--mount-root", help="mounted image root (e.g. E:\\) to check/hash each job's local file")
    ap.add_argument("--mft-drive", default="C:", help="drive letter the MFTECmd CSV belongs to (default C:)")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    if not os.path.isdir(a.input):
        ap.error("input folder not found: %s" % a.input)
    extra = read_events() if a.live_events else None
    result = analyse(a.input, a.no_carve, events=extra, mount_root=a.mount_root, mft_drive=a.mft_drive)
    if a.live_extras:
        x = live_extras()
        result["commands"] += x["commands"]; result["do_downloads"] = x["do_downloads"]
        result["parse_notes"] += x["notes"]; result["summary"]["commands"] = len(result["commands"])
    write_outputs(result, a.output)
    s = result["summary"]
    print("[+] v%s: %d job records -> %d unique jobs (%d active, %d recovered-only, %d event-log-only); "
          "%d file records; %d events; %d BITS commands; %d $I30 entries"
          % (__version__, s["job_records"], s["unique_jobs"], s["active_jobs"], s["recovered_only_jobs"],
             s["event_only_jobs"], s["file_records"], s["events"], s["commands"], s["i30_entries"]))
    for c in result["commands"]:
        if c["level"] != "INFO":
            print("  [cmd %s] %s  %s" % (c["level"], c["kind"], c["text"][:140]))
    shown = 0
    for j in result["latest"]:
        top = [t for t in j["triage"] if not t.startswith("INFO")]
        if j["status"] != "active" and not top:
            continue
        shown += 1
        print("  %-17s %-11s %-30s %s %s" % (j["status"], j["state"], (j["name"] or "")[:30],
                                             j.get("created"), "!! " + "; ".join(top) if top else ""))
    print("  (%d active/flagged jobs shown; all %d in bits_jobs.csv)" % (shown, len(result["jobs"])))
    for n in result["parse_notes"]:
        print("  [note]", n)
    print("[+] wrote", os.path.abspath(a.output))


if __name__ == "__main__":
    main()
