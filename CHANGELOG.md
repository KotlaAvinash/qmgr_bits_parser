# Changelog

## 1.2.0 - 2026-11-27
### Added
- **Raw `$MFT` support** with no new dependency. A `$MFT` anywhere in the collection folder is scanned in one pass (about 2.7 M records in about 5 s on a real Windows 11 volume). For each job's local and temp file it reports the entry, whether it is in use or **deleted**, size and `$SI`/`$FN` times. It handles:
  - update-sequence fix-ups, including names that cross a sector boundary
  - hard links (every path is resolved)
  - extension records via resident `$ATTRIBUTE_LIST`
  - reused parent folders (`path_complete=false`)
  - 1024- and 4096-byte records

  Verified against `os.stat` on 60 live files: 59 matched exactly (size, creation time, in-use flag), and 1 had been replaced by Windows servicing after the snapshot.
- Uniform job schema (`JOB_SCHEMA`): every job, whether from the database, carving, the event log only or live, carries every key.
- Commands output gains a `note` column. Read-only queries made by bits-qmgr's own live mode are labelled and kept at INFO.

### Fixed
- **Linux CI failure:** Windows paths in evidence were split with `os.path.basename`, which doesn't split on `\` on Linux, so a creator showed as the full path. Now `ntpath`.
- **Event-log-only and live jobs were missing 26 keys** (`KeyError: 'owner_sid'`), and the real-evidence tests crashed whenever an `.evtx` was in the evidence folder.
- **PowerShell 4103 events were silently dropped.** The command line lives in `ContextInfo`, but only the first non-empty field (`Payload`) was searched. On real data this went from 0 to 25 hits.
- **False HIGH:** merely *reading* `.NotifyCmdLine` was treated like setting it. Only `SetNotifyCmdLine` is HIGH now.
- `$MFT`, `$LogFile` and `$UsnJrnl` are no longer hashed and carved as if they were BITS logs.
- Record size is detected from the first valid FILE record (partial/carved `$MFT`).
- `local_expectations.json` is only applied to the folder it describes.
- CI actions moved to Node 24 (`checkout@v5`, `setup-python@v6`).

## 1.1.0 - 2026-11-27
### Added
- **Job security descriptor** decoded from each job record: owner SID, group SID, DACL ACEs, and SDDL on Windows. A new rule flags a descriptor owner that differs from the job owner. On a real Windows 11 queue the descriptor owner matched the job owner for 797/797 records.
- **BITS command hunting.** Finds bitsadmin / `*-BitsTransfer` / `SetNotifyCmdLine` / BITS COM usage in:
  - PSReadLine `ConsoleHost_history.txt` (in the evidence folder, or the live user's history)
  - PowerShell/Operational 4103/4104 and Windows PowerShell events, from any `.evtx` in the folder or the live logs

  Each hit is levelled HIGH/MED/INFO.
- **Delivery Optimization cache** (live, no admin): Windows Update, Store and Office downloads that do **not** go through BITS, with the calling application and a host allowlist check.
- **Destination-file check.** In live mode, or with `--mount-root` against a mounted image, it checks whether each job's local file still exists, with size, mtime and SHA-256. A BITS-written executable still on disk is flagged HIGH.
- **MFTECmd `$MFT` CSV correlation.** Shows whether each job's local and temp file has an MFT entry, and whether it is in use or deleted.
- `.evtx` files are routed by channel (BITS-Client goes to job events; everything else goes to command hunting).
- New outputs: `bits_commands.csv`, `delivery_optimization.csv`.
- GUI: **Commands** and **Delivery Opt.** tabs, new summary cards, and security-descriptor, file-check and MFT details for each job.
- CLI: `--live-extras`, `--mount-root`, `--mft-drive`, `--version`. `main()` accepts an argv list.
- Packaging: `pyproject.toml` with the `bits-qmgr` / `bits-qmgr-gui` entry points, pinned `requirements.txt`, and GitHub Actions CI covering Windows 3.10–3.13, pinned dependencies, a Linux core run and a wheel build.
- `bits_synth.py`: synthetic record builders shared by the tests and the demo.

### Fixed
- `--mount-root` path mapping can no longer be escaped with `..\` in attacker-controlled job paths.
- PowerShell helper clears all `BITS_*` environment variables between calls and uses `pwsh` off Windows.

## 1.0.0 - 2026-11-27
- First release: ESE parse, carving, `$I30`, BITS-Client event correlation, live snapshot, triage, Tkinter GUI (light/dark), CSV/JSON output, 53 tests.
