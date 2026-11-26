# qmgr_bits_parser

Offline forensic parser, carver and GUI for the **Windows BITS queue** (`qmgr.db`). It recovers active **and deleted** BITS jobs, correlates them with the BITS event log, and flags the patterns attackers use: notify-command persistence, error-loop jobs, localhost or raw-IP sources, and upload exfiltration.

![Dark theme, synthetic demo data](docs/gui_dark.png)

## Why BITS matters
BITS (Background Intelligent Transfer Service) is the Windows service that downloads files in the background. Attackers like it for three reasons:
- **Hidden downloads.** Transfers run inside `svchost.exe`, so firewalls and EDR see a trusted Windows service instead of the malware.
- **Registry-free persistence.** `SetNotifyCmdLine` runs a program when a job completes or fails. Point a job at a URL that never resolves (for example `127.0.0.1`), and it fails and re-runs the command forever. Ryuk operators did exactly this with a job named "System update" (Mandiant, 2020).
- **Exfiltration.** Upload jobs send files out.

Completed and cancelled jobs are deleted from the queue, but their records often survive in free database pages and transaction logs. This tool carves them back.

## Features
| | |
|---|---|
| **ESE parse** | Reads the `Jobs`/`Files` tables in `qmgr.db` (Windows 10/11) using `dissect.esedb` |
| **Carving** | Signature-carves job and file records from `qmgr.db`, `edb*.log`, `edbtmp.log` and `*.jrs`, which recovers deleted and older job versions |
| **`$I30`** | Parses the Downloader folder's NTFS index, including deleted entries in slack |
| **Event log** | Reads Microsoft-Windows-Bits-Client/Operational (an exported `.evtx` or the live log). See the event table below |
| **Live snapshot** | `Get-BitsTransfer` plus the live event log, no admin needed |
| **Triage** | HIGH / MED / REVIEW / INFO, with an exact-domain allowlist for known updaters |
| **GUI** | Tkinter: filters, search, detail pane with an event timeline, light/dark theme, export |
| **Outputs** | CSV (formula-injection safe) and JSON, with SHA-256 of every input file |

Events read from the BITS-Client log:

| Event | Meaning | What it adds |
|---|---|---|
| 3 | Job created | The **creating process** |
| 6 | Notify command set | The **notify command**, even after the job is deleted |
| 59 / 60 | Transfer started / stopped | The URL |
| 61 | Transfer error | URL + HRESULT |
| 16403 | File added to job | URL + local path |

Evidence is opened read-only (mmap). Input folders are walked recursively, so KAPE-style nested exports work.

## Install
```powershell
git clone https://github.com/KotlaAvinash/qmgr_bits_parser
cd qmgr_bits_parser
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```
Python 3.10+. The parser and carver are pure Python. The live snapshot and `.evtx` reading use PowerShell, so they are Windows-only.

## Collect the evidence
`qmgr.db` is locked while BITS is running, so take a raw copy as admin (KAPE, FTK Imager or a disk image) of:
```
C:\ProgramData\Microsoft\Network\Downloader\   (qmgr.db, qmgr.jfm, edb*.log, edbtmp.log, *.jrs)
```
Optionally also export the event log (this works without admin):
```powershell
wevtutil epl Microsoft-Windows-Bits-Client/Operational bits.evtx
```
Put the `.evtx` in the same folder and it will be picked up.

## Use
```powershell
# command line
.\.venv\Scripts\python bits_qmgr_parser.py -i <export folder> -o out
#   --live-events   also correlate THIS machine's BITS log (only if the export came from it)
#   --no-carve      ESE tables only

# GUI
.\.venv\Scripts\python bits_gui.py <export folder> [--live] [--dark|--light]

# try it on synthetic demo data
.\.venv\Scripts\python make_demo_data.py demo_evidence
.\.venv\Scripts\python bits_gui.py demo_evidence
```
Outputs: `bits_jobs.csv`, `bits_files.csv`, `bits_events.csv`, `i30_entries.csv`, `bits_report.json`.

`status` values:
- `active`: in the ESE table now
- `historic_version_of_active`: an older state of a live job
- `deleted/recovered`: carved only
- `event log only`: seen only in the event log
- `live`: returned by `Get-BitsTransfer`

## Triage rules
| Level | Trigger |
|---|---|
| HIGH | Notify command set (non-System32 program, or a LOLBin anywhere); notify command in a user-writable path; error loop + notify command; localhost remote URL |
| MED | Upload job; raw-IP or UNC remote; executable written from a host that isn't allowlisted; generic "update" job name; job created by bitsadmin, PowerShell or a script host, or by a process in a user-writable path |
| REVIEW | Notify command is a System32 binary (for example `directxdatabaseupdater.exe`). Verify the signer |
| INFO | Known updater traffic (Edge, Office, OneDrive, Chrome, Brave, Firefox …), transfer errors with HRESULT hints |

Hosts are allowlisted by exact domain or dot-suffix, so `microsoft.com.evil.ru` does **not** pass.

## Record layout notes
These were verified on a real Windows 11 host: a known test job's notify command was observed firing, and parsed fields were compared against `Get-BitsTransfer` and event ID 3.
- Job strings in order: name, description, notify program, notify arguments, owner SID.
- An error entry is `u32 0, u32 HRESULT, 4×u32, u8`. With one or more errors there is **no** transient-error counter before the retry delay. The ANSSI struct misaligns here.
- File sizes: the first u64 is bytes transferred and the second is the total (–1 means unknown). This matched `Get-BitsTransfer` for 10/10 live jobs.
- Windows 10+ job tail: the creating process path, an optional package family + `!AppId`, and the HTTP verb. The creator path matched event 3 `processPath` for 479/479 jobs.
- The FILETIME at file-record offset +29 is the server's Last-Modified time, not a creation time. `expiration` is completion + 90 days.

## Limits: what it does not see
- **Non-BITS downloads.** Browser downloads, Delivery Optimization (most modern Windows Update and Store traffic), winget, curl/`Invoke-WebRequest`, and custom updaters.
- **Other users' live jobs**, without admin. The event log still records their activity.
- **Overwritten history.** Deleted records survive only until ESE pages and logs are reused, and the event log is capped at 1 MB by default.
- **Legacy Win7/8 `qmgr0.dat`/`qmgr1.dat`.** These get signature carving only.
- Carved file records can't always be linked to their job. They are still listed in `bits_files.csv`, and the event log often fills the gap.

## Tests
```powershell
.\.venv\Scripts\python -m unittest -v test_bits_qmgr_parser
```
53 tests:
- unit, triage and allowlist-bypass checks
- fuzzing and truncation
- full pipeline and command line
- mocked event-log and live paths
- a GUI smoke test
- synthetic demo data

Real-evidence tests are opt-in, so your system identifiers stay out of the repo:
```powershell
$env:BITS_EVIDENCE = "D:\case\Downloader"      # generic invariants on any real export
```
For exact-value regression tests, create a git-ignored `local_expectations.json` with any of these keys: `evidence`, `from_this_pc`, `qmgr_sha256`, `active_job_ids`, `known_files`, `allowed_levels`, `i30_names`.

## Credits and license
- The record layout builds on [ANSSI-FR/bits_parser](https://github.com/ANSSI-FR/bits_parser) (MIT) and the delimiter constants published in [fireeye/BitsParser](https://github.com/fireeye/BitsParser). No code was copied. Corrections to the published layout are listed above.
- ESE reading uses [`dissect.esedb`](https://github.com/fox-it/dissect.esedb) (Apache-2.0).
- Background: Mandiant, *Attacker Use of Windows Background Intelligent Transfer Service* (2021).

Released under the [MIT License](LICENSE).
