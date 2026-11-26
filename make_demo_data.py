#!/usr/bin/env python3
"""
make_demo_data.py - build a SYNTHETIC Downloader folder for demos and screenshots.

Contains no real system data: a benign Edge-style job, a Ryuk-style "System update"
persistence job (localhost URL + notify command), an upload/exfil job and a deleted
DirectX-style job, embedded in an edb.log as carvable records, plus a $I30 with one
deleted entry in slack.

    python make_demo_data.py demo_evidence
    python bits_gui.py demo_evidence
"""
import os, sys, uuid

from test_bits_qmgr_parser import job_blob, file_blob, indx_block

EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
SYS32 = "C:\\Windows\\System32\\"


def linked(fid, blob):
    """ESE leaf layout seen in logs: the file GUID sits 22..6 bytes before the record."""
    return uuid.UUID(fid).bytes_le + bytes(6) + blob


def build(out):
    os.makedirs(out, exist_ok=True)
    f1, f2, f3, f4 = (str(uuid.uuid4()) for _ in range(4))
    recs = [
        job_blob(name="Edge Component Updater", cmd="", errors=0, state=6,
                 sid="S-1-5-21-1000-2000-3000-1001", creator=EDGE, file_ids=[f1]),
        linked(f1, file_blob(
            src="http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/demo",
            dest="C:\\Users\\demo\\AppData\\Local\\Temp\\msedge_BITS\\demo", got=24471, total=24471)),

        job_blob(name="System update", cmd="C:\\Users\\Public\\mail.exe", args="mail.exe -k",
                 sid="S-1-5-18", creator=SYS32 + "bitsadmin.exe", file_ids=[f2]),
        linked(f2, file_blob(src="http://127.0.0.1/nonexistent.exe", dest="C:\\Users\\Public\\mail.exe")),

        job_blob(name="sync", cmd="", errors=0, state=6, jtype=1, file_ids=[f3],
                 creator=SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"),
        linked(f3, file_blob(src="C:\\Users\\demo\\Documents\\finance.zip",
                             dest="http://203.0.113.7/upload", got=1048576, total=1048576)),

        job_blob(name="DirectX_Database_Download_AsUser_1.9.3", errors=0, state=0, sid="S-1-5-18",
                 cmd="C:\\WINDOWS\\system32\\directxdatabaseupdater.exe",
                 args="C:\\WINDOWS\\system32\\directxdatabaseupdater.exe -DatabaseComplete "
                      "{00000000-0000-0000-0000-000000000000}",
                 creator=SYS32 + "directxdatabaseupdater.exe", file_ids=[f4]),
        linked(f4, file_blob(src="https://fs.microsoft.com/fs/directxdatabase/1.9.3/DirectXApps.lzma",
                             dest="C:\\WINDOWS\\apppatch\\DirectXApps.lzma", got=588351, total=588351)),
    ]
    with open(os.path.join(out, "edb.log"), "wb") as fh:
        fh.write(bytes(512) + bytes(64).join(recs) + bytes(512))
    with open(os.path.join(out, "$I30"), "wb") as fh:
        fh.write(indx_block(["edb.log", "qmgr.db", "qmgr.jfm"], ["edb00042.log"]))
    return out


if __name__ == "__main__":
    print(build(sys.argv[1] if len(sys.argv) > 1 else "demo_evidence"))
