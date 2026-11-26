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
import argparse, csv, datetime as dt, hashlib, json, os, re, struct, sys, uuid

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
        flags.append("MED: job created by %s (scripted/manual BITS use)" % os.path.basename(creator))
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


def _walk(input_dir):
    """All files below input_dir (KAPE exports nest the Downloader path)."""
    for root, dirs, fns in os.walk(input_dir):
        dirs.sort()
        for fn in sorted(fns):
            p = os.path.join(root, fn)
            if os.path.isfile(p):
                yield p, os.path.relpath(p, input_dir)


def analyse(input_dir, no_carve=False, progress=None, events=None):
    """Parse + carve a Downloader folder (recursively). Any *.evtx in it is read as a
    BITS-Client log. `events` = extra pre-read events (e.g. live log) to correlate."""
    say = progress or (lambda m: None)
    inventory, all_jobs, all_files, notes = [], [], [], []
    ese_files = {}
    i30, slack, evtx_events = [], {}, []
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
                evtx_events += read_events(path=p)
            except Exception as e:
                notes.append("event log %s: %s" % (rel, e))
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
    jobs = correlate(jobs, all_events, "event log only")
    for j in jobs:
        retriage(j)
    jobs.sort(key=lambda j: (j.get("created") or "", j.get("modified") or ""))
    latest = latest_per_job(jobs)

    return {"tool": "bits_qmgr_parser",
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
                                             if j["level"] in ("HIGH", "MED", "REVIEW")})},
            "jobs": jobs, "latest": latest, "files": files, "i30": i30, "events": all_events,
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


# ---------------------------------------------------------------- event log
EVENT_WHAT = {3: "job created", 4: "job completed", 5: "job cancelled", 6: "notify command set",
              59: "transfer started", 60: "transfer stopped", 61: "transfer error",
              16403: "file added to job", 209: "high-performance property", 306: "job list loaded",
              310: "peer helper init failed", 7: "job modified (owner/props)"}

EVENTS_PS = r"""
$ErrorActionPreference='Stop'
$p = @{}
if ($env:BITS_EVTX_PATH) { $p['Path'] = $env:BITS_EVTX_PATH } else { $p['LogName'] = 'Microsoft-Windows-Bits-Client/Operational' }
try { $ev = @(Get-WinEvent @p -Oldest) } catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $ev=@() } else { throw } }
@($ev | ForEach-Object {
  $x = [xml]$_.ToXml(); $d = @{}
  foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }
  $m = ''; try { $m = ($_.Message -split "`r?`n")[0] } catch {}
  [pscustomobject]@{ id=$_.Id; time=$_.TimeCreated.ToUniversalTime().ToString('o'); record=$_.RecordId; data=$d; message=$m }
}) | ConvertTo-Json -Depth 4 -Compress
"""


def _ps(script, env_extra=None, timeout=180):
    import subprocess
    env = dict(os.environ)
    env.pop("BITS_EVTX_PATH", None)
    env.update(env_extra or {})
    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
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
            "source": source, "message": e.get("message") or ""}


def read_events(path=None, raw_json=None):
    """BITS-Client/Operational events: live log (path=None) or an exported .evtx."""
    txt = raw_json if raw_json is not None else \
        _ps(EVENTS_PS, {"BITS_EVTX_PATH": os.path.abspath(path)} if path else None)
    if not txt:
        return []
    data = json.loads(txt)
    if isinstance(data, dict):
        data = [data]
    src = ("evtx:" + os.path.basename(path)) if path else "eventlog:live"
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
    jobs = correlate(jobs, events, "event log only (live)")
    for j in jobs:
        retriage(j)
    return jobs, events


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
        jobs.append(j)
    return jobs


# ---------------------------------------------------------------- main
def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
    ap = argparse.ArgumentParser(description="BITS qmgr.db parser + carver")
    ap.add_argument("-i", "--input", required=True, help="folder with qmgr.db, edb*.log, ...")
    ap.add_argument("-o", "--output", required=True, help="output folder")
    ap.add_argument("--no-carve", action="store_true")
    ap.add_argument("--live-events", action="store_true",
                    help="also correlate THIS machine's BITS-Client/Operational log "
                         "(only if the evidence came from this machine)")
    a = ap.parse_args()
    extra = read_events() if a.live_events else None
    result = analyse(a.input, a.no_carve, events=extra)
    write_outputs(result, a.output)
    s = result["summary"]
    print("[+] %d job records -> %d unique jobs (%d active, %d recovered-only, %d event-log-only); "
          "%d file records; %d events; %d $I30 entries"
          % (s["job_records"], s["unique_jobs"], s["active_jobs"], s["recovered_only_jobs"],
             s["event_only_jobs"], s["file_records"], s["events"], s["i30_entries"]))
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
