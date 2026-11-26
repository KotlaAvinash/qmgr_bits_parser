# Changelog

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
