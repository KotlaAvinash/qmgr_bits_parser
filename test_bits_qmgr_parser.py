"""Test suite for bits_qmgr_parser + bits_gui.

  Unit     - synthetic blobs, every parser primitive, triage rules, CSV safety
  Robust   - fuzzed / truncated / corrupt inputs never crash the pipeline
  Pipeline - analyse() on synthetic folders (nested, corrupt DB, evtx), CLI
  Real     - regression against F:\\bits_qmgr + ground truth from this PC (skipped if absent)
  GUI      - Tk smoke test: load data, filters, both themes, detail panes

Run:  .venv\\Scripts\\python -m unittest -v test_bits_qmgr_parser
"""
import csv, datetime as dt, json, os, random, struct, subprocess, sys
import tempfile, unittest, uuid
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bits_qmgr_parser as P  # noqa: E402

# Real-evidence tests are opt-in and keep your system's identifiers out of the repo:
#   set BITS_EVIDENCE=<exported Downloader folder>   -> generic invariants
#   optional local_expectations.json (git-ignored)   -> exact values (see README)
LOCAL = os.path.join(HERE, "local_expectations.json")
try:
    with open(LOCAL, encoding="utf-8") as _fh:
        EXPECT = json.load(_fh)
except (OSError, ValueError):
    EXPECT = {}
EVIDENCE = os.environ.get("BITS_EVIDENCE") or EXPECT.get("evidence") or ""
HAVE_EVIDENCE = bool(EVIDENCE) and os.path.exists(os.path.join(EVIDENCE, "qmgr.db"))


# ------------------------------------------------------------------ builders
def ustr(s):
    s += "\x00"
    return struct.pack("<I", len(s)) + s.encode("utf-16-le")


def ftb(days, base=dt.datetime(2026, 1, 1)):
    t = base + dt.timedelta(days=days)
    return struct.pack("<Q", int((t - dt.datetime(1601, 1, 1)).total_seconds() * 10_000_000))


def job_blob(name="System update", cmd="C:\\Users\\Public\\mail.exe", args="", state=4,
             jtype=0, errors=1, file_ids=(), sid="S-1-5-21-1-2-3-1001", jid=None,
             creator="C:\\Windows\\System32\\bitsadmin.exe", delim=None):
    b = (delim or P.JOB_DELIMS[0]) + struct.pack("<IIII", jtype, 2, state, 0) + \
        (jid or uuid.uuid4()).bytes_le
    b += ustr(name) + ustr("desc") + ustr(cmd) + ustr(args) + ustr(sid)
    b += struct.pack("<I", 3) + b"\x01" * 40
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


def make_folder(root, nested=True, corrupt_db=False, extra=None):
    d = os.path.join(root, "C", "ProgramData", "Microsoft", "Network", "Downloader") if nested else root
    os.makedirs(d, exist_ok=True)
    fid = str(uuid.uuid4())
    log = b"\x00" * 100 + job_blob(file_ids=[fid]) + b"\xcc" * 33 + \
        job_blob(name="Edge Component Updater", cmd="", errors=0, state=6,
                 creator="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe") + \
        b"\x00" * 7 + file_blob() + \
        file_blob(src="http://msedge.b.tlu.dl.delivery.mp.microsoft.com/x", dest="C:\\t\\x", got=5, total=5)
    with open(os.path.join(d, "edb.log"), "wb") as fh:
        fh.write(log)
    if corrupt_db:
        with open(os.path.join(d, "qmgr.db"), "wb") as fh:
            fh.write(b"\x00" * 4 + b"\xef\xcd\xab\x89" + os.urandom(9000))
    with open(os.path.join(d, "$I30"), "wb") as fh:
        fh.write(indx_block(["qmgr.db", "edb.log"], ["evil_deleted.tmp"]))
    with open(os.path.join(d, "edb.chk"), "wb") as fh:
        fh.write(b"\x00" * 64)
    for k, v in (extra or {}).items():
        with open(os.path.join(d, k), "wb") as fh:
            fh.write(v)
    return d


# ------------------------------------------------------------------ unit
class TestPrimitives(unittest.TestCase):
    def test_filetime_bounds(self):
        self.assertIsNone(P.filetime(0))
        self.assertIsNone(P.filetime(1))
        self.assertIsNone(P.filetime(0xFFFFFFFFFFFFFFFF))
        v = struct.unpack("<Q", ftb(0))[0]
        self.assertEqual(P.filetime(v), "2026-01-01T00:00:00Z")

    def test_reader_truncation_and_limits(self):
        with self.assertRaises(P.ParseError):
            P.Reader(b"\x01\x02").u32()
        with self.assertRaises(P.ParseError):
            P.Reader(struct.pack("<I", 5000) + b"\x00" * 20).ustr()       # too long
        with self.assertRaises(P.ParseError):
            P.Reader(struct.pack("<I", 3) + "ab".encode("utf-16-le")).ustr()   # truncated
        with self.assertRaises(P.ParseError):
            P.Reader(struct.pack("<I", 2) + "ab".encode("utf-16-le")).ustr()   # no NUL
        with self.assertRaises(P.ParseError):
            P.Reader(ustr("a\x01b")).ustr()                                 # control char
        self.assertEqual(P.Reader(struct.pack("<I", 0)).ustr(), "")

    def test_url_host(self):
        self.assertEqual(P.url_host("http://user@Example.COM:8080/x"), "example.com")
        self.assertEqual(P.url_host("http://[::1]:9/x"), "::1")
        self.assertEqual(P.url_host("C:\\x"), "")
        self.assertTrue(P.benign_host("http://msedge.b.tlu.dl.delivery.mp.microsoft.com/a"))
        self.assertFalse(P.benign_host("http://microsoft.com.evil.ru/a"))
        self.assertFalse(P.benign_host("http://evilmicrosoft.com/a"))
        self.assertFalse(P.benign_host("http://microsoft.com@evil.ru/a"))

    def test_csv_safe(self):
        for s in ("=cmd|' /c calc'!A0", "+1", "-2", "@SUM(1)"):
            self.assertTrue(P.csv_safe(s).startswith("'"))
        self.assertEqual(P.csv_safe("Edge"), "Edge")
        self.assertEqual(P.csv_safe(5), 5)


class TestRecords(unittest.TestCase):
    def test_job_fields_with_error(self):
        j, _ = P.parse_job(job_blob())
        self.assertEqual(j["name"], "System update")
        self.assertEqual(j["notify_cmd"], "C:\\Users\\Public\\mail.exe")
        self.assertEqual(j["state"], "error")
        self.assertEqual(j["errors"][0]["hresult"], "0x80072EE7")
        self.assertNotIn("transient_error_count", j)
        self.assertEqual(j["retry_delay_s"], 60)
        self.assertEqual(j["no_progress_timeout_s"], 86400)
        self.assertTrue(j["created"].startswith("2026-01-01"))
        self.assertTrue(j["expiration"].startswith("2026-04-02"))
        self.assertEqual(j["http_method"], "GET")
        self.assertEqual(j["creator_process_inferred"], "C:\\Windows\\System32\\bitsadmin.exe")
        self.assertEqual(j["notify_flags"], "JOB_TRANSFERRED|JOB_ERROR")

    def test_job_without_error_alignment(self):
        j, _ = P.parse_job(job_blob(errors=0, state=6, cmd=""))
        self.assertEqual(j["transient_error_count"], 0)
        self.assertTrue(j["modified"].startswith("2026-01-02"))

    def test_multiple_errors(self):
        j, _ = P.parse_job(job_blob(errors=3))
        self.assertEqual(len(j["errors"]), 3)
        self.assertTrue(j["created"].startswith("2026-01-01"))

    def test_all_job_delimiters(self):
        for d in P.JOB_DELIMS:
            j, _ = P.parse_job(job_blob(delim=d))
            self.assertEqual(j["name"], "System update")

    def test_file_ids_and_enums(self):
        f1, f2 = str(uuid.uuid4()), str(uuid.uuid4())
        j, _ = P.parse_job(job_blob(file_ids=[f1, f2], jtype=1, state=8))
        self.assertEqual(j["file_ids"], [f1, f2])
        self.assertEqual((j["job_type"], j["state"]), ("upload", "cancelled"))

    def test_bad_sid_and_enum_rejected(self):
        with self.assertRaises(P.ParseError):
            P.parse_job(job_blob(sid="garbage"))
        bad = bytearray(job_blob()); struct.pack_into("<I", bad, 24, 99)   # state 99
        with self.assertRaises(P.ParseError):
            P.parse_job(bytes(bad))

    def test_file_sizes(self):
        f, _ = P.parse_file(file_blob(got=10, total=10))
        self.assertTrue(f["complete"])
        f, _ = P.parse_file(file_blob(got=3, total=10))
        self.assertFalse(f["complete"])
        f, _ = P.parse_file(file_blob())
        self.assertIsNone(f["transfer_size"]); self.assertFalse(f["complete"])

    def test_file_bad_source_rejected(self):
        with self.assertRaises(P.ParseError):
            P.parse_file(file_blob(src="not a url"))

    def test_garbage_rejected(self):
        with self.assertRaises(P.ParseError):
            P.parse_job(P.JOB_DELIMS[0] + b"\xff" * 200)
        with self.assertRaises(P.ParseError):
            P.parse_file(P.FILE_DELIM + b"\xff" * 200)


class TestTriage(unittest.TestCase):
    def tri(self, **kw):
        files = kw.pop("files", [])
        j, _ = P.parse_job(job_blob(**kw))
        return " ".join(P.triage(j, files)), P.level_of(P.triage(j, files))

    def test_ryuk_style(self):
        f, _ = P.parse_file(file_blob())
        t, lv = self.tri(files=[f])
        self.assertEqual(lv, "HIGH")
        for needle in ("HIGH: notify command set", "user-writable", "error-loop", "localhost",
                       "generic 'update'", "created by bitsadmin.exe", "executable/script written"):
            self.assertIn(needle, t)

    def test_system32_notify_is_review(self):
        t, lv = self.tri(cmd="C:\\WINDOWS\\system32\\directxdatabaseupdater.exe",
                         name="DirectX_Database_Download", errors=0, state=0,
                         creator="C:\\Windows\\System32\\directxdatabaseupdater.exe")
        self.assertEqual(lv, "REVIEW")

    def test_system32_lolbin_notify_is_high(self):
        _, lv = self.tri(cmd="C:\\Windows\\System32\\cmd.exe", args="cmd.exe /c evil",
                         name="x", errors=0, state=0, creator="C:\\Program Files\\x\\x.exe")
        self.assertEqual(lv, "HIGH")

    def test_upload_flag_and_swapped_fields(self):
        f = {"source_url": "C:\\secret.zip", "dest_file": "http://10.1.2.3/u"}
        t, lv = self.tri(jtype=1, cmd="", errors=0, state=6, name="sync", files=[f])
        self.assertIn("MED: upload job", t)
        self.assertIn("raw IP: http://10.1.2.3/u", t)

    def test_allowlist_bypass_closed(self):
        f = {"source_url": "http://microsoft.com.evil.ru/msedge/update.exe",
             "dest_file": "C:\\Program Files (x86)\\Microsoft\\Edge\\knowledge.exe"}
        t, lv = self.tri(cmd="", errors=0, state=6, name="Edge Component Updater",
                         creator="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                         files=[f])
        self.assertIn("MED: executable/script written", t)
        self.assertNotIn("benign updater noise", t)

    def test_benign_updater_is_info(self):
        f = {"source_url": "http://msedge.b.tlu.dl.delivery.mp.microsoft.com/files/x",
             "dest_file": "C:\\Users\\u\\AppData\\Local\\Temp\\x"}
        t, lv = self.tri(cmd="", errors=0, state=6, name="Edge Component Updater",
                         creator="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                         files=[f])
        self.assertEqual(lv, "INFO"); self.assertIn("benign updater noise", t)

    def test_creator_in_user_path(self):
        t, _ = self.tri(cmd="", errors=0, state=6, name="x",
                        creator="C:\\Users\\bob\\AppData\\Roaming\\x.exe")
        self.assertIn("user-writable path", t)

    def test_unc_and_hresult_hint(self):
        f = {"source_url": "\\\\host\\share\\a.dll", "dest_file": "C:\\x\\a.dll"}
        t, _ = self.tri(cmd="", name="x", creator="", files=[f])
        self.assertIn("SMB/UNC", t)
        self.assertIn("WinINet: server name not resolved", t)


# ------------------------------------------------------------------ robustness
class TestRobustness(unittest.TestCase):
    def test_fuzz_carve_never_raises(self):
        rnd = random.Random(1234)
        good = job_blob() + file_blob()
        for i in range(300):
            buf = bytearray(rnd.randbytes(rnd.randint(0, 3000)))
            for _ in range(rnd.randint(0, 6)):                     # sprinkle delimiters
                pos = rnd.randint(0, max(0, len(buf)))
                buf[pos:pos] = rnd.choice(P.JOB_DELIMS + [P.FILE_DELIM, P.XFER_HDR])
            if i % 10 == 0:                                         # truncated real records
                cut = rnd.randint(1, len(good) - 1); buf += good[:cut]
            P._carve_buf(bytes(buf), "fuzz")

    def test_truncated_records_rejected_not_half_parsed(self):
        good = job_blob()
        for cut in range(20, len(good) - 40, 7):
            try:
                j, _ = P.parse_job(good[:cut])
            except P.ParseError:
                continue
            self.assertTrue("_partial" in j or not j["tail_complete"], cut)

    def test_empty_file_carve(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "empty.log"); open(p, "wb").close()
            self.assertEqual(P.carve(p), ([], []))

    def test_corrupt_db_does_not_abort(self):
        with tempfile.TemporaryDirectory() as d:
            make_folder(d, nested=False, corrupt_db=True)
            r = P.analyse(d)
            self.assertTrue(any("ESE read" in n for n in r["parse_notes"]), r["parse_notes"])
            self.assertGreaterEqual(r["summary"]["unique_jobs"], 2)   # carving still ran


# ------------------------------------------------------------------ i30
class TestI30(unittest.TestCase):
    def test_live_and_slack(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "$I30")
            with open(p, "wb") as fh:
                fh.write(indx_block(["qmgr.db", "edb.log"], ["evil_deleted.tmp"]))
            es = {e["name"]: e for e in P.parse_i30(p)}
        self.assertEqual(set(es), {"qmgr.db", "edb.log", "evil_deleted.tmp"})
        self.assertFalse(es["qmgr.db"]["in_slack"])
        self.assertTrue(es["evil_deleted.tmp"]["in_slack"])
        self.assertTrue(es["edb.log"]["created"].startswith("2026-01-02"))


# ------------------------------------------------------------------ events / live (mocked)
EVT_JSON = json.dumps([
    {"id": 3, "time": "2026-11-26T19:39:43.8658967Z", "record": 1, "message": "created",
     "data": {"jobTitle": "Evil", "jobId": "{AAAAAAAA-0000-0000-0000-000000000001}",
              "jobOwner": "PC\\u", "processPath": "C:\\Windows\\System32\\bitsadmin.exe"}},
    {"id": 6, "time": "2026-11-26T19:39:44Z", "record": 2, "message": "cmd",
     "data": {"jobId": "aaaaaaaa-0000-0000-0000-000000000001", "jobOwner": "PC\\u",
              "program": "C:\\Users\\u\\AppData\\x.exe", "parameters": "x.exe -p"}},
    {"id": 61, "time": "2026-11-26T19:39:45Z", "record": 3, "message": "err",
     "data": {"name": "Evil", "Id": "aaaaaaaa-0000-0000-0000-000000000001",
              "url": "http://127.0.0.1:9/p.exe", "hr": "2147954429"}},
    {"id": 59, "time": "2026-11-26T19:40:00Z", "record": 4, "message": "start",
     "data": {"name": "Known", "Id": "bbbbbbbb-0000-0000-0000-000000000002",
              "url": "http://msedge.b.tlu.dl.delivery.mp.microsoft.com/f"}},
    {"id": 306, "time": "2026-11-26T19:00:00Z", "record": 5, "message": "loaded", "data": {}}])

LIVE_JSON = json.dumps({"job_id": "bbbbbbbb-0000-0000-0000-000000000002", "name": "Known",
                        "job_type": 0, "state": 6, "priority": 2, "owner": "PC\\u",
                        "created": "2026-11-26T19:39:00Z", "modified": "2026-11-26T19:40:01Z",
                        "error_code": None, "notify_cmd": "", "notify_args": "",
                        "files": {"source_url": "http://msedge.b.tlu.dl.delivery.mp.microsoft.com/f",
                                  "dest_file": "C:\\t\\f", "download_size": 5,
                                  "transfer_size": 18446744073709551615}})


class TestEvents(unittest.TestCase):
    def test_normalize(self):
        ev = P.read_events(raw_json=EVT_JSON)
        self.assertEqual(len(ev), 5)
        e61 = [e for e in ev if e["event_id"] == 61][0]
        self.assertEqual(e61["hr"], "0x80072EFD")
        self.assertEqual(e61["job_id"], "aaaaaaaa-0000-0000-0000-000000000001")
        self.assertEqual([e for e in ev if e["event_id"] == 3][0]["job_id"],
                         "aaaaaaaa-0000-0000-0000-000000000001")          # braces stripped
        self.assertEqual(P.read_events(raw_json=""), [])
        self.assertEqual(len(P.read_events(raw_json=json.dumps(json.loads(EVT_JSON)[0]))), 1)

    def test_correlate_event_only_job(self):
        ev = P.read_events(raw_json=EVT_JSON)
        jobs = P.correlate([], ev, "event log only")
        evil = [j for j in jobs if j["name"] == "Evil"][0]
        P.retriage(evil)
        self.assertEqual(evil["status"], "event log only")
        self.assertEqual(evil["creator_process_evt"], "C:\\Windows\\System32\\bitsadmin.exe")
        self.assertEqual(evil["notify_cmd"], "C:\\Users\\u\\AppData\\x.exe")
        self.assertEqual(evil["errors"][0]["hresult"], "0x80072EFD")
        self.assertEqual(evil["level"], "HIGH")
        t = " ".join(evil["triage"])
        for needle in ("notify command set", "user-writable", "localhost", "bitsadmin.exe", "error-loop"):
            self.assertIn(needle, t)

    def test_correlate_enriches_existing_without_overwrite(self):
        j, _ = P.parse_job(job_blob(jid=uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001"),
                                    cmd="C:\\a.exe", errors=0, state=6))
        j["files"], j["source"] = [], ["x"]
        out = P.correlate([j], P.read_events(raw_json=EVT_JSON), "event log only")
        self.assertEqual(out[0]["notify_cmd"], "C:\\a.exe")                 # DB value kept
        self.assertEqual(out[0]["notify_cmd_evt"], "C:\\Users\\u\\AppData\\x.exe")
        self.assertEqual(len(out[0]["events"]), 3)
        self.assertTrue(any(f["source_url"] == "http://127.0.0.1:9/p.exe" for f in out[0]["files"]))

    def test_live_jobs_parsing(self):
        jobs = P.live_jobs(raw_json=LIVE_JSON)                              # single dict form
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["state"], "transferred")
        self.assertIsNone(jobs[0]["files"][0]["transfer_size"])
        self.assertEqual(jobs[0]["level"], "INFO")
        self.assertEqual(P.live_jobs(raw_json=""), [])

    def test_live_snapshot_mocked(self):
        with mock.patch.object(P, "_ps", side_effect=[LIVE_JSON, EVT_JSON]):
            jobs, ev = P.live_snapshot()
        names = {j["name"]: j for j in jobs}
        self.assertEqual(names["Known"]["status"], "live")
        self.assertEqual(len(names["Known"]["events"]), 1)
        self.assertEqual(names["Evil"]["status"], "event log only (live)")

    def test_live_snapshot_event_log_failure(self):
        with mock.patch.object(P, "_ps", side_effect=[LIVE_JSON, RuntimeError("denied")]):
            jobs, ev = P.live_snapshot()
        self.assertEqual(ev, []); self.assertEqual(len(jobs), 1)

    def test_ps_error_surfaces(self):
        with self.assertRaises(RuntimeError):
            P._ps("throw 'boom'", timeout=60)

    def test_evtx_path_passed_via_env_not_string(self):
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"], captured["env"] = cmd, kw["env"]
            return subprocess.CompletedProcess(cmd, 0, "", "")
        with mock.patch("subprocess.run", fake_run):
            P.read_events(path="C:\\x\\a'; calc; '.evtx")
        self.assertNotIn("calc", " ".join(captured["cmd"]))
        self.assertIn("calc", captured["env"]["BITS_EVTX_PATH"])


# ------------------------------------------------------------------ pipeline
class TestPipeline(unittest.TestCase):
    def test_nested_folder_analyse_and_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            make_folder(d, extra={"evil=1.log": job_blob(name="=HYPERLINK(\"x\")")})
            r = P.analyse(d)
            self.assertEqual(r["summary"]["i30_entries"], 3)
            names = {j["name"] for j in r["latest"]}
            self.assertIn("System update", names)
            self.assertIn("Edge Component Updater", names)
            self.assertTrue(all(i["sha256"] and len(i["sha256"]) == 64 for i in r["inventory"]))
            self.assertTrue(any(i["file"].startswith("C" + os.sep) for i in r["inventory"]))
            sysu = [j for j in r["latest"] if j["name"] == "System update"][0]
            self.assertEqual(sysu["status"], "deleted/recovered")
            self.assertEqual(sysu["level"], "HIGH")
            out = os.path.join(d, "out"); P.write_outputs(r, out)
            for fn in ("bits_report.json", "bits_jobs.csv", "bits_files.csv", "i30_entries.csv"):
                self.assertTrue(os.path.getsize(os.path.join(out, fn)) > 0, fn)
            with open(os.path.join(out, "bits_jobs.csv"), encoding="utf-8-sig") as fh:
                rows = list(csv.DictReader(fh))
            for row in rows:
                for v in row.values():
                    self.assertFalse((v or " ")[:1] in "=+@", "formula not neutralised: %r" % v)
            self.assertTrue(any(row["name"].startswith("'=HYPERLINK") for row in rows))
            with open(os.path.join(out, "bits_report.json"), encoding="utf-8") as fh:
                json.load(fh)

    def test_source_name_containing_active_is_not_active(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "inactive_backup.log"), "wb") as fh:
                fh.write(job_blob())
            r = P.analyse(d)
            self.assertEqual(r["summary"]["active_jobs"], 0)
            self.assertEqual(r["latest"][0]["status"], "deleted/recovered")

    def test_dedupe_merges_sources(self):
        jid = uuid.uuid4()
        blob = job_blob(jid=jid)
        with tempfile.TemporaryDirectory() as d:
            for n in ("a.log", "b.log"):
                with open(os.path.join(d, n), "wb") as fh:
                    fh.write(b"\x00" * 10 + blob + b"\x00" * 10 + blob)
            r = P.analyse(d)
        self.assertEqual(len(r["jobs"]), 1)
        self.assertEqual(len(r["jobs"][0]["source"]), 4)

    def test_legacy_queue_noted(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "qmgr0.dat"), "wb") as fh:
                fh.write(b"\x00" * 100)
            r = P.analyse(d)
        self.assertTrue(any("legacy" in n for n in r["parse_notes"]))

    def test_no_carve(self):
        with tempfile.TemporaryDirectory() as d:
            make_folder(d, nested=False)
            self.assertEqual(P.analyse(d, no_carve=True)["summary"]["job_records"], 0)

    def test_evidence_not_modified(self):
        with tempfile.TemporaryDirectory() as d:
            make_folder(d, nested=False)
            before = {f: P.sha256(os.path.join(d, f)) for f in os.listdir(d)}
            P.analyse(d)
            after = {f: P.sha256(os.path.join(d, f)) for f in os.listdir(d)}
        self.assertEqual(before, after)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            make_folder(d)
            out = os.path.join(d, "o")
            p = subprocess.run([sys.executable, os.path.join(HERE, "bits_qmgr_parser.py"),
                                "-i", d, "-o", out], capture_output=True, text=True, timeout=120)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("unique jobs", p.stdout)
            self.assertTrue(os.path.exists(os.path.join(out, "bits_jobs.csv")))


class TestDemoData(unittest.TestCase):
    def test_demo_folder_levels_and_links(self):
        import make_demo_data
        with tempfile.TemporaryDirectory() as d:
            r = P.analyse(make_demo_data.build(d))
        lv = {j["name"]: j["level"] for j in r["latest"]}
        self.assertEqual(lv, {"Edge Component Updater": "INFO", "System update": "HIGH",
                              "sync": "MED", "DirectX_Database_Download_AsUser_1.9.3": "REVIEW"})
        self.assertTrue(all(j["files"] for j in r["latest"]))          # file GUID linking works
        self.assertIn("edb00042.log", {e["name"] for e in r["i30"] if e["in_slack"]})


# ------------------------------------------------------------------ real data / this PC
@unittest.skipUnless(HAVE_EVIDENCE, "set BITS_EVIDENCE to an exported Downloader folder")
class TestRealEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before = {n: P.sha256(os.path.join(EVIDENCE, n)) for n in os.listdir(EVIDENCE)
                      if os.path.isfile(os.path.join(EVIDENCE, n))}
        cls.r = P.analyse(EVIDENCE)

    # generic invariants - hold for any real export
    def test_evidence_unchanged(self):
        after = {n: P.sha256(os.path.join(EVIDENCE, n)) for n in self.before}
        self.assertEqual(self.before, after)

    def test_ese_read_cleanly_and_active_jobs_complete(self):
        self.assertFalse([n for n in self.r["parse_notes"] if "ESE read" in n], self.r["parse_notes"])
        for j in self.r["jobs"]:
            if j["status"] == "active":
                self.assertTrue(j["files"], j["job_id"])
                self.assertTrue(j.get("tail_complete"), j["job_id"])

    def test_all_records_have_valid_times_and_sids(self):
        for j in self.r["jobs"]:
            self.assertTrue(j.get("created"), j["source"])
            self.assertRegex(j["owner_sid"], r"^S-1-\d+(-\d+)+$")
            self.assertIn(j["state"], P.JOB_STATE.values())

    def test_review_items_are_system32_notify(self):
        for j in self.r["latest"]:
            if j["level"] == "REVIEW":
                self.assertRegex(j["notify_cmd"], r"(?i)^[a-z]:\\windows\\system32\\")

    def test_fileslack_not_treated_as_bits(self):
        self.assertTrue(all("FileSlack" not in s for j in self.r["jobs"] for s in j["source"]))

    def test_i30_lists_queue_files(self):
        if self.r["i30"]:
            self.assertIn("qmgr.db", {e["name"] for e in self.r["i30"]})

    # exact values - only when local_expectations.json describes this export
    def test_exact_expectations(self):
        if not EXPECT:
            self.skipTest("no local_expectations.json")
        if "qmgr_sha256" in EXPECT:
            self.assertEqual(self.before.get("qmgr.db"), EXPECT["qmgr_sha256"])
        if "active_job_ids" in EXPECT:
            self.assertEqual({j["job_id"] for j in self.r["jobs"] if j["status"] == "active"},
                             set(EXPECT["active_job_ids"]))
        for k in EXPECT.get("known_files", []):
            j = [j for j in self.r["latest"] if j["job_id"] == k["job_id"]][0]
            f = j["files"][0]
            self.assertEqual((f["download_size"], f["transfer_size"]),
                             (k["download_size"], k["transfer_size"]))
            self.assertEqual(j["created"], k["created"])
        if "allowed_levels" in EXPECT:
            self.assertTrue({j["level"] for j in self.r["latest"]} <= set(EXPECT["allowed_levels"]))
        if "i30_names" in EXPECT:
            self.assertEqual({e["name"] for e in self.r["i30"]}, set(EXPECT["i30_names"]))


def _live_events_available():
    try:
        return bool(P.read_events())
    except Exception:
        return False


@unittest.skipUnless(HAVE_EVIDENCE and EXPECT.get("from_this_pc") and os.name == "nt"
                     and _live_events_available(), "needs evidence exported from this PC + its event log")
class TestGroundTruthThisPC(unittest.TestCase):
    """The evidence was exported from this PC, so its live log/API are ground truth."""
    @classmethod
    def setUpClass(cls):
        cls.ev = P.read_events()
        cls.r = P.analyse(EVIDENCE, events=cls.ev)

    def test_creator_process_inferred_matches_event_3(self):
        both = [j for j in self.r["jobs"] if j.get("creator_process_inferred") and j.get("creator_process_evt")]
        self.assertGreater(len(both), 50)
        bad = [j for j in both if j["creator_process_inferred"].lower() != j["creator_process_evt"].lower()]
        self.assertEqual(bad, [])

    def test_sizes_and_urls_match_get_bitstransfer(self):
        live = {j["job_id"].lower(): j for j in P.live_jobs()}
        checked = 0
        for j in self.r["jobs"]:
            if j["status"] == "active" and j["job_id"] in live:
                f, lf = j["files"][0], live[j["job_id"]]["files"][0]
                self.assertEqual((f["download_size"], f["transfer_size"], f["source_url"]),
                                 (lf["download_size"], lf["transfer_size"], lf["source_url"]))
                checked += 1
        if not checked:
            self.skipTest("active jobs no longer live")

    def test_evtx_file_equals_live_log(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bits.evtx")
            subprocess.run(["wevtutil", "epl", "Microsoft-Windows-Bits-Client/Operational", p],
                           check=True, capture_output=True)
            ev = P.read_events(path=p)
            self.assertGreater(len(ev), 0)
            live_rec = {e["record"] for e in P.read_events()}
            self.assertTrue({e["record"] for e in ev} <= live_rec | {max(live_rec) + i for i in range(1, 50)})
            r = P.analyse(d)                                  # evtx found inside a folder
            self.assertEqual(r["summary"]["events"], len(ev))
            self.assertTrue(all(e["source"] == "evtx:bits.evtx" for e in r["events"]))


# ------------------------------------------------------------------ GUI
class TestGUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tkinter
            tkinter.Tk().destroy()
        except Exception as e:
            raise unittest.SkipTest("no display: %s" % e)
        import bits_gui
        cls.G = bits_gui

    def test_gui_end_to_end(self):
        G = self.G
        with tempfile.TemporaryDirectory() as d, mock.patch.object(G, "save_prefs") as sp:
            make_folder(d)
            app = G.App(d, "light")
            app.withdraw()
            try:
                app.result = P.analyse(d, events=P.read_events(raw_json=EVT_JSON))
                app._fill_static()
                with mock.patch.object(P, "_ps", side_effect=[LIVE_JSON, EVT_JSON]):
                    app.live, app.live_events = P.live_snapshot()
                app._fill_events(); app.refresh(); app.update()
                n_all = len(app.jobs_tv.get_children())
                self.assertGreaterEqual(n_all, 4)
                first = app.rows[app.jobs_tv.get_children()[0]]
                self.assertEqual(first["level"], "HIGH")                # severity sorted first
                app._show_detail()
                self.assertIn("HIGH", app.detail.get("1.0", "end"))
                for lvl in ("Flagged (H/M/R)", "HIGH", "MED", "REVIEW", "INFO", "All"):
                    app.level.set(lvl); app.refresh()
                    for iid in app.jobs_tv.get_children():
                        lv = app.rows[iid]["level"]
                        if lvl in ("HIGH", "MED", "REVIEW", "INFO"):
                            self.assertEqual(lv, lvl)
                for stf in G.STATUSES:
                    app.status_f.set(stf); app.refresh()
                app.status_f.set("All")
                app.search.set("evil"); app.refresh()
                self.assertTrue(all("evil" in json.dumps(app.rows[i], default=str).lower()
                                    for i in app.jobs_tv.get_children()))
                app.search.set(""); app.hide_noise.set(True); app.refresh()
                self.assertTrue(all(app.rows[i]["level"] != "INFO" for i in app.jobs_tv.get_children()))
                self.assertGreater(len(app.ev_tv.get_children()), 0)
                app.ev_tv.selection_set(app.ev_tv.get_children()[0]); app._show_event()
                self.assertTrue(app.detail.get("1.0", "end").strip())
                for th in ("dark", "light", "dark"):
                    app.apply_theme(th); app.update()
                    self.assertEqual(str(app.detail.cget("bg")), G.THEMES[th]["panel"])
                app.toggle_theme()
                self.assertEqual(app.theme, "light"); sp.assert_called()
                app._sort(app.jobs_tv, "created", False); app._sort(app.jobs_tv, "events", True)
                out = os.path.join(d, "exp")
                with mock.patch.object(G.filedialog, "askdirectory", return_value=out):
                    os.makedirs(out); app.export()
                self.assertTrue(os.path.exists(os.path.join(out, "bits_live_snapshot.json")))
                self.assertTrue(os.path.exists(os.path.join(out, "bits_events.csv")))
            finally:
                app.destroy()


if __name__ == "__main__":
    unittest.main()
