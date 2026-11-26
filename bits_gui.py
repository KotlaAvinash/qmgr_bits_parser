#!/usr/bin/env python3
"""
bits_gui.py - Tkinter front-end for bits_qmgr_parser.

  * Parse an exported Downloader folder (qmgr.db + edb*.log + $I30 + *.evtx, recursive)
  * Or take a live snapshot: Get-BitsTransfer (current user) + BITS-Client event log
  * Filter by triage level / status / free text, hide updater noise
  * Jobs / Files / Events / $I30 / Evidence tabs, per-job detail with event timeline
  * Light and dark theme (remembered), export CSV/JSON

Run:  .venv\\Scripts\\python bits_gui.py [folder] [--live] [--dark|--light]
                                         [--screenshot out.png [--flagged] [--tab N]]
"""
import json, os, queue, sys, threading, tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:                                   # crisp text + correct coordinates on scaled displays
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bits_qmgr_parser as P  # noqa: E402

PREFS = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "bits_gui.json")

THEMES = {
    "light": {"bg": "#eef1f4", "panel": "#ffffff", "card": "#f7f9fb", "fg": "#1d232a",
              "muted": "#5b6672", "border": "#c9d1d9", "accent": "#2563eb", "sel": "#9cc3ff",
              "sel_fg": "#0b1220", "head": "#e3e8ee", "entry": "#ffffff", "key": "#1f4e8c",
              "lv": {"HIGH": ("#f8d0d0", "#8f1414"), "MED": ("#fde3bf", "#7a4300"),
                     "REVIEW": ("#fff3b8", "#5e4f00"), "INFO": ("#ffffff", "#1d232a"),
                     "": ("#ffffff", "#1d232a")}},
    "dark": {"bg": "#16191d", "panel": "#1e2228", "card": "#242a31", "fg": "#e3e7ec",
             "muted": "#9aa5b1", "border": "#363d46", "accent": "#5b9cff", "sel": "#2f5fa8",
             "sel_fg": "#ffffff", "head": "#2a3038", "entry": "#262b32", "key": "#86b6ff",
             "lv": {"HIGH": ("#4a1d22", "#ffb4b4"), "MED": ("#4a3415", "#ffd59a"),
                    "REVIEW": ("#423c14", "#f6e58d"), "INFO": ("#1e2228", "#e3e7ec"),
                    "": ("#1e2228", "#e3e7ec")}},
}
EVENT_LV = {6: "HIGH", 61: "MED", 3: "REVIEW"}      # colouring only: notify set / error / created

JOB_COLS = [("level", 70), ("status", 150), ("state", 110), ("name", 230), ("created", 150),
            ("modified", 150), ("notify", 260), ("remote_url", 330), ("local_file", 300),
            ("creator", 260), ("owner", 150), ("events", 60), ("record_source", 170)]
FILE_COLS = [("source_url", 420), ("dest_file", 360), ("download_size", 95), ("transfer_size", 95),
             ("complete", 70), ("remote_last_modified", 160), ("record_source", 220)]
EVT_COLS = [("time", 165), ("event_id", 70), ("what", 150), ("job_name", 220), ("job_id", 270),
            ("url", 330), ("local", 280), ("process", 260), ("program_args", 300), ("hr", 95),
            ("owner", 170), ("source", 120)]
CMD_COLS = [("level", 70), ("time", 160), ("kind", 170), ("text", 640), ("note", 260), ("source", 330)]
DO_COLS = [("level", 70), ("status", 90), ("caller", 210), ("host", 260), ("size", 110),
           ("downloaded", 110), ("from_http", 100), ("from_peers", 95), ("mode", 80), ("expires", 160),
           ("source_url", 500)]
I30_COLS = [("name", 180), ("logical_size", 100), ("created", 170), ("modified", 170),
            ("mft_modified", 170), ("accessed", 170), ("in_slack", 70), ("dir_path", 330), ("source", 160)]
UTC_COLS = {"created", "modified", "mft_modified", "accessed", "remote_last_modified", "time"}
STATUSES = ["All", "live", "active", "historic_version_of_active", "deleted/recovered",
            "event log only", "event log only (live)"]


def short(ts):
    return (ts or "")[:19].replace("T", " ")


def load_prefs():
    try:
        with open(PREFS, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_prefs(p):
    try:
        with open(PREFS, "w", encoding="utf-8") as fh:
            json.dump(p, fh)
    except Exception:
        pass


class App(tk.Tk):
    def __init__(self, folder=None, theme=None):
        super().__init__()
        self.title("BITS QMGR Analyzer v%s" % P.__version__)
        self.geometry("1500x900")
        self.minsize(1000, 600)
        self.prefs = load_prefs()
        self.theme = theme or self.prefs.get("theme", "light")
        self.result, self.live, self.live_events = None, [], []
        self.extras = {"commands": [], "do_downloads": [], "notes": []}
        self.cmdrows, self.dorows = {}, {}
        self.rows, self.evrows = {}, {}
        self.q = queue.Queue()
        self._search_job = None
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self._build()
        self.apply_theme(self.theme)
        if folder:
            self.folder.set(folder)
        self.after(100, self._poll)

    # ------------------------------------------------------------------ theme
    def apply_theme(self, name):
        self.theme = name
        t = THEMES[name]
        st = self.style
        self.configure(bg=t["bg"])
        st.configure(".", background=t["bg"], foreground=t["fg"], fieldbackground=t["entry"],
                     bordercolor=t["border"], lightcolor=t["bg"], darkcolor=t["bg"],
                     troughcolor=t["panel"], focuscolor=t["accent"], font=("Segoe UI", 9),
                     selectbackground=t["sel"], selectforeground=t["sel_fg"], insertcolor=t["fg"])
        st.configure("TFrame", background=t["bg"])
        st.configure("TLabel", background=t["bg"], foreground=t["fg"])
        st.configure("Hdr.TLabel", font=("Segoe UI", 13, "bold"), background=t["bg"], foreground=t["fg"])
        st.configure("Muted.TLabel", background=t["bg"], foreground=t["muted"])
        st.configure("TButton", background=t["head"], foreground=t["fg"], bordercolor=t["border"],
                     padding=(10, 4))
        st.map("TButton", background=[("active", t["card"]), ("pressed", t["sel"])])
        st.configure("Accent.TButton", background=t["accent"], foreground="#ffffff",
                     font=("Segoe UI", 9, "bold"))
        st.map("Accent.TButton", background=[("active", t["sel"])])
        st.configure("TCheckbutton", background=t["bg"], foreground=t["fg"],
                     indicatorbackground=t["entry"], indicatorforeground=t["fg"])
        st.map("TCheckbutton", background=[("active", t["bg"])],
               indicatorbackground=[("selected", t["accent"])])
        st.configure("TEntry", fieldbackground=t["entry"], foreground=t["fg"])
        st.configure("TCombobox", fieldbackground=t["entry"], foreground=t["fg"],
                     background=t["head"], arrowcolor=t["fg"])
        st.map("TCombobox", fieldbackground=[("readonly", t["entry"])],
               foreground=[("readonly", t["fg"])], selectbackground=[("readonly", t["entry"])],
               selectforeground=[("readonly", t["fg"])])
        self.option_add("*TCombobox*Listbox.background", t["entry"])
        self.option_add("*TCombobox*Listbox.foreground", t["fg"])
        self.option_add("*TCombobox*Listbox.selectBackground", t["sel"])
        self.option_add("*TCombobox*Listbox.selectForeground", t["sel_fg"])
        st.configure("TNotebook", background=t["bg"], bordercolor=t["border"])
        st.configure("TNotebook.Tab", background=t["head"], foreground=t["muted"], padding=(12, 4))
        st.map("TNotebook.Tab", background=[("selected", t["panel"])],
               foreground=[("selected", t["fg"])])
        st.configure("Treeview", background=t["panel"], fieldbackground=t["panel"],
                     foreground=t["fg"], rowheight=22, font=("Segoe UI", 9), bordercolor=t["border"])
        st.map("Treeview", background=[("selected", t["sel"])], foreground=[("selected", t["sel_fg"])])
        st.configure("Treeview.Heading", background=t["head"], foreground=t["fg"],
                     font=("Segoe UI", 9, "bold"), bordercolor=t["border"])
        st.map("Treeview.Heading", background=[("active", t["card"])])
        st.configure("Card.TFrame", background=t["card"], relief="solid", borderwidth=1)
        st.configure("CardV.TLabel", background=t["card"], foreground=t["fg"], font=("Segoe UI", 15, "bold"))
        st.configure("CardK.TLabel", background=t["card"], foreground=t["muted"], font=("Segoe UI", 8))
        for lv in ("HIGH", "MED", "REVIEW"):
            st.configure("Card%s.TLabel" % lv, background=t["card"], foreground=t["lv"][lv][1],
                         font=("Segoe UI", 15, "bold"))
        st.configure("TLabelframe", background=t["bg"], bordercolor=t["border"])
        st.configure("TLabelframe.Label", background=t["bg"], foreground=t["muted"])
        st.configure("TPanedwindow", background=t["bg"])
        st.configure("TScrollbar", background=t["head"], troughcolor=t["bg"], arrowcolor=t["fg"],
                     bordercolor=t["border"])
        st.configure("Horizontal.TProgressbar", background=t["accent"], troughcolor=t["panel"])
        for tv in (self.jobs_tv, self.ev_tv, self.cmd_tv, self.do_tv):
            for lv, (bg, fg) in t["lv"].items():
                tv.tag_configure(lv or "none", background=bg, foreground=fg)
        for w in (self.detail, self.ev_txt):
            w.configure(bg=t["panel"], fg=t["fg"], insertbackground=t["fg"],
                        selectbackground=t["sel"], selectforeground=t["sel_fg"],
                        highlightthickness=0, borderwidth=0)
        for lv in ("HIGH", "MED", "REVIEW"):
            self.detail.tag_configure(lv, foreground=t["lv"][lv][1], font=("Consolas", 9, "bold"))
        self.detail.tag_configure("key", foreground=t["key"])
        self.detail.tag_configure("muted", foreground=t["muted"])
        self.theme_btn.configure(text="☀  Light" if name == "dark" else "☾  Dark")

    def toggle_theme(self):
        self.apply_theme("light" if self.theme == "dark" else "dark")
        self.prefs["theme"] = self.theme
        save_prefs(self.prefs)

    # ------------------------------------------------------------------ ui
    def _build(self):
        self.status = tk.StringVar(value="Pick an exported Downloader folder and press Parse, "
                                         "or take a live snapshot of this PC.")
        bar = ttk.Frame(self, padding=(10, 2)); bar.pack(fill="x", side="bottom")   # before the pane
        self.prog = ttk.Progressbar(bar, mode="indeterminate", length=160); self.prog.pack(side="right")
        ttk.Label(bar, textvariable=self.status, style="Muted.TLabel").pack(side="left")

        top = ttk.Frame(self, padding=(10, 8)); top.pack(fill="x")
        self.theme_btn = ttk.Button(top, text="☾  Dark", command=self.toggle_theme, width=9)
        self.theme_btn.pack(side="right")                      # packed first so it never clips
        ttk.Label(top, text="BITS QMGR Analyzer", style="Hdr.TLabel").pack(side="left")
        ttk.Label(top, text="   Evidence folder:").pack(side="left")
        self.folder = tk.StringVar()
        ttk.Entry(top, textvariable=self.folder, width=36).pack(side="left", padx=4, fill="x", expand=True)
        ttk.Button(top, text="Browse…", command=self._browse).pack(side="left")
        self.carve = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Carve deleted", variable=self.carve).pack(side="left", padx=6)
        ttk.Button(top, text="Parse folder", style="Accent.TButton", command=self.parse).pack(side="left")
        ttk.Button(top, text="Live snapshot (this PC)", command=self.load_live).pack(side="left", padx=4)
        ttk.Button(top, text="Export…", command=self.export).pack(side="left")

        self.cards = ttk.Frame(self, padding=(10, 0)); self.cards.pack(fill="x")
        self.card_vars = {}
        for key, label in (("unique_jobs", "Unique jobs (folder)"), ("active_jobs", "Active in qmgr.db"),
                           ("recovered_only_jobs", "Recovered (deleted)"),
                           ("event_only_jobs", "Event-log only"), ("events", "Events"),
                           ("file_records", "File records"), ("HIGH", "HIGH"), ("MED", "MED"),
                           ("REVIEW", "REVIEW"), ("live", "Live jobs"),
                           ("commands", "BITS commands"), ("do", "Deliv. Opt.")):
            f = ttk.Frame(self.cards, style="Card.TFrame", padding=(10, 4))
            f.pack(side="left", padx=(0, 6), pady=6)
            v = tk.StringVar(value="–"); self.card_vars[key] = v
            sty = "Card%s.TLabel" % key if key in ("HIGH", "MED", "REVIEW") else "CardV.TLabel"
            ttk.Label(f, textvariable=v, style=sty).pack(anchor="w")
            ttk.Label(f, text=label, style="CardK.TLabel").pack(anchor="w")

        flt = ttk.Frame(self, padding=(10, 2)); flt.pack(fill="x")
        ttk.Label(flt, text="Search:").pack(side="left")
        self.search = tk.StringVar(); self.search.trace_add("write", lambda *_: self._debounce())
        ttk.Entry(flt, textvariable=self.search, width=30).pack(side="left", padx=4)
        ttk.Label(flt, text="Level:").pack(side="left", padx=(10, 0))
        self.level = tk.StringVar(value="All")
        cb = ttk.Combobox(flt, textvariable=self.level, width=15, state="readonly",
                          values=["All", "Flagged (H/M/R)", "HIGH", "MED", "REVIEW", "INFO"])
        cb.pack(side="left", padx=4); cb.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        ttk.Label(flt, text="Status:").pack(side="left", padx=(10, 0))
        self.status_f = tk.StringVar(value="All")
        cb2 = ttk.Combobox(flt, textvariable=self.status_f, width=24, state="readonly", values=STATUSES)
        cb2.pack(side="left", padx=4); cb2.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        self.latest_only = tk.BooleanVar(value=True)
        ttk.Checkbutton(flt, text="Latest record per job", variable=self.latest_only,
                        command=self.refresh).pack(side="left", padx=8)
        self.hide_noise = tk.BooleanVar(value=False)
        ttk.Checkbutton(flt, text="Hide INFO-only", variable=self.hide_noise,
                        command=self.refresh).pack(side="left")
        self.count = tk.StringVar(); ttk.Label(flt, textvariable=self.count, style="Muted.TLabel").pack(side="right")

        pw = ttk.PanedWindow(self, orient="vertical"); pw.pack(fill="both", expand=True, padx=10, pady=4)
        self.nb = ttk.Notebook(pw); pw.add(self.nb, weight=4)
        self.jobs_tv = self._tree(self.nb, JOB_COLS, "Jobs")
        self.files_tv = self._tree(self.nb, FILE_COLS, "Files")
        self.ev_tv = self._tree(self.nb, EVT_COLS, "Events")
        self.cmd_tv = self._tree(self.nb, CMD_COLS, "Commands")
        self.do_tv = self._tree(self.nb, DO_COLS, "Delivery Opt.")
        self.i30_tv = self._tree(self.nb, I30_COLS, "$I30")
        ev = ttk.Frame(self.nb); self.nb.add(ev, text="Evidence & notes")
        self.ev_txt = tk.Text(ev, font=("Consolas", 9), wrap="none", relief="flat")
        self.ev_txt.pack(fill="both", expand=True)
        self.jobs_tv.bind("<<TreeviewSelect>>", self._show_detail)
        self.ev_tv.bind("<<TreeviewSelect>>", self._show_event)
        self.cmd_tv.bind("<<TreeviewSelect>>", lambda e: self._show_row(self.cmd_tv, self.cmdrows))
        self.do_tv.bind("<<TreeviewSelect>>", lambda e: self._show_row(self.do_tv, self.dorows))

        det = ttk.LabelFrame(pw, text="Details", padding=4); pw.add(det, weight=2)
        self.detail = tk.Text(det, font=("Consolas", 9), wrap="word", relief="flat", height=12)
        sb = ttk.Scrollbar(det, command=self.detail.yview); self.detail.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); self.detail.pack(fill="both", expand=True)

    def _tree(self, parent, cols, title):
        fr = ttk.Frame(parent); parent.add(fr, text=title)
        tv = ttk.Treeview(fr, columns=[c for c, _ in cols], show="headings", selectmode="browse")
        for c, w in cols:
            label = c.replace("_", " ") + (" (UTC)" if c in UTC_COLS else "")
            tv.heading(c, text=label, command=lambda c=c, tv=tv: self._sort(tv, c, False))
            tv.column(c, width=w, minwidth=40, stretch=False)
        ys = ttk.Scrollbar(fr, orient="vertical", command=tv.yview)
        xs = ttk.Scrollbar(fr, orient="horizontal", command=tv.xview)
        tv.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        tv.grid(row=0, column=0, sticky="nsew"); ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        fr.rowconfigure(0, weight=1); fr.columnconfigure(0, weight=1)
        return tv

    def _sort(self, tv, col, rev):
        def key(v):
            try:
                return (0, float(v), "")
            except (TypeError, ValueError):
                return (1, 0.0, str(v).lower())
        items = sorted(((tv.set(k, col), k) for k in tv.get_children("")),
                       key=lambda x: key(x[0]), reverse=rev)
        for i, (_, k) in enumerate(items):
            tv.move(k, "", i)
        tv.heading(col, command=lambda: self._sort(tv, col, not rev))

    def _debounce(self):
        if self._search_job:
            self.after_cancel(self._search_job)
        self._search_job = self.after(250, self.refresh)

    # ------------------------------------------------------------------ actions
    def _browse(self):
        d = filedialog.askdirectory(title="Exported Downloader folder")
        if d:
            self.folder.set(d)

    def parse(self):
        d = self.folder.get().strip()
        if not os.path.isdir(d):
            messagebox.showerror("BITS", "Folder not found:\n" + d); return
        self._busy("Parsing " + d + " …")
        carve = self.carve.get()

        def work():
            try:
                res = P.analyse(d, no_carve=not carve, progress=lambda m: self.q.put(("msg", m)))
                self.q.put(("result", res))
            except Exception as e:      # surface any parser failure in the GUI
                self.q.put(("error", "%s: %s" % (type(e).__name__, e)))
        threading.Thread(target=work, daemon=True).start()

    def load_live(self):
        self._busy("Querying Get-BitsTransfer, event logs, PowerShell history, Delivery Optimization …")

        def work():
            try:
                jobs, events = P.live_snapshot()
                self.q.put(("live", (jobs, events, P.live_extras())))
            except Exception as e:
                self.q.put(("error", "%s: %s" % (type(e).__name__, e)))
        threading.Thread(target=work, daemon=True).start()

    def export(self):
        if not self.result and not self.live:
            messagebox.showinfo("BITS", "Nothing to export yet."); return
        d = filedialog.askdirectory(title="Export to folder")
        if not d:
            return
        if self.result:
            P.write_outputs(self.result, d)
        if self.live:
            with open(os.path.join(d, "bits_live_snapshot.json"), "w", encoding="utf-8") as fh:
                json.dump({"version": P.__version__, "jobs": self.live, "events": self.live_events,
                           "extras": self.extras}, fh, indent=2, default=str)
        self.status.set("Exported to " + d)

    def _busy(self, msg):
        self.status.set(msg); self.prog.start(12)

    def _poll(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "msg":
                    self.status.set(val)
                elif kind == "result":
                    self.result = val; self.prog.stop(); self._fill_static(); self.refresh()
                    s = val["summary"]
                    self.status.set("Parsed %s — %d job records, %d unique jobs, %d events, %d file records"
                                    % (val["input"], s["job_records"], s["unique_jobs"], s["events"],
                                       s["file_records"]))
                elif kind == "live":
                    self.live, self.live_events, self.extras = val; self.prog.stop()
                    self._fill_events(); self._fill_extras(); self.refresh()
                    notes = "; ".join(self.extras.get("notes") or [])
                    self.status.set("Live snapshot: %d jobs (%d from Get-BitsTransfer), %d events, "
                                    "%d BITS commands, %d Delivery Optimization downloads%s"
                                    % (len(self.live), len([j for j in self.live if j["status"] == "live"]),
                                       len(self.live_events), len(self.extras["commands"]),
                                       len(self.extras["do_downloads"]),
                                       ("  [" + notes + "]") if notes else ""))
                elif kind == "error":
                    self.prog.stop(); self.status.set("Error: " + val)
                    messagebox.showerror("BITS", val)
        except queue.Empty:
            pass
        self.after(100, self._poll)

    # ------------------------------------------------------------------ data → views
    def _all_jobs(self):
        out = list(self.live)
        if self.result:
            out += self.result["latest"] if self.latest_only.get() else self.result["jobs"]
        return out

    def refresh(self):
        tv = self.jobs_tv
        tv.delete(*tv.get_children()); self.rows.clear()
        q = self.search.get().lower().strip()
        lvl, stf = self.level.get(), self.status_f.get()
        counts = {"HIGH": 0, "MED": 0, "REVIEW": 0}
        jobs = self._all_jobs()
        jobs.sort(key=lambda j: j.get("created") or j.get("modified") or "", reverse=True)
        jobs.sort(key=lambda j: P.LEVELS.index(j["level"]) if j.get("level") in P.LEVELS else 9)
        shown = 0
        for i, j in enumerate(jobs):
            lv = j.get("level", "")
            if lv in counts:
                counts[lv] += 1
            if lvl == "Flagged (H/M/R)" and lv not in ("HIGH", "MED", "REVIEW"):
                continue
            if lvl not in ("All", "Flagged (H/M/R)") and lv != lvl:
                continue
            if stf != "All" and j.get("status") != stf:
                continue
            if self.hide_noise.get() and lv in ("INFO", ""):
                continue
            remote, local = P._remote_local((j.get("files") or [{}])[0])
            notify = ((j.get("notify_cmd") or "") + " " + (j.get("notify_args") or "")).strip()
            vals = (lv, j.get("status"), j.get("state"), j.get("name"), short(j.get("created")),
                    short(j.get("modified")), notify, remote, local,
                    j.get("creator_process_inferred") or j.get("creator_process_evt")
                    or j.get("creator_aumid_inferred") or "",
                    j.get("owner_sid") or j.get("owner") or "", len(j.get("events") or []),
                    "; ".join(j.get("source", []))[:120])
            if q and q not in " ".join(str(v) for v in vals).lower() and \
                    q not in json.dumps(j, default=str).lower():
                continue
            iid = "j%d" % i
            tv.insert("", "end", iid=iid, values=vals, tags=(lv or "none",))
            self.rows[iid] = j; shown += 1
        self.count.set("%d jobs shown" % shown)
        s = self.result["summary"] if self.result else {}
        for k in ("unique_jobs", "active_jobs", "recovered_only_jobs", "event_only_jobs", "file_records"):
            self.card_vars[k].set(str(s.get(k, "–")))
        n_ev = (s.get("events") or 0) + len(self.live_events)
        self.card_vars["events"].set(str(n_ev) if (self.result or self.live_events) else "–")
        for k, v in counts.items():
            self.card_vars[k].set(str(v))
        self.card_vars["live"].set(str(len([j for j in self.live if j["status"] == "live"]))
                                   if self.live else "–")
        n_cmd = len(self.extras["commands"]) + len((self.result or {}).get("commands") or [])
        self.card_vars["commands"].set(str(n_cmd) if (self.result or self.live) else "–")
        self.card_vars["do"].set(str(len(self.extras["do_downloads"])) if self.live else "–")
        kids = tv.get_children()
        if kids:
            tv.selection_set(kids[0])

    def _fill_events(self):
        tv = self.ev_tv
        tv.delete(*tv.get_children()); self.evrows.clear()
        evs = list(self.live_events) + list((self.result or {}).get("events") or [])
        seen = set()
        for i, e in enumerate(sorted(evs, key=lambda e: e.get("time") or "", reverse=True)):
            k = (e.get("record"), e.get("time"), e.get("event_id"))
            if k in seen:
                continue
            seen.add(k)
            pa = ((e.get("program") or "") + " " + (e.get("parameters") or "")).strip()
            iid = "e%d" % i
            tv.insert("", "end", iid=iid, tags=(EVENT_LV.get(e["event_id"], "none"),), values=(
                short(e.get("time")), e["event_id"], e["what"], e.get("job_name"), e.get("job_id"),
                e.get("url"), e.get("local"), e.get("process"), pa, e.get("hr"), e.get("owner"),
                e.get("source")))
            self.evrows[iid] = e

    def _fill_static(self):
        r = self.result
        self.files_tv.delete(*self.files_tv.get_children())
        for f in r["files"]:
            self.files_tv.insert("", "end", values=(
                f.get("source_url"), f.get("dest_file"), f.get("download_size"), f.get("transfer_size"),
                f.get("complete"), short(f.get("remote_last_modified_inferred")),
                "; ".join(f.get("source", []))[:120]))
        self.i30_tv.delete(*self.i30_tv.get_children())
        for e in r["i30"]:
            self.i30_tv.insert("", "end", values=(e["name"], e["logical_size"], short(e["created"]),
                                                  short(e["modified"]), short(e["mft_modified"]),
                                                  short(e["accessed"]), e["in_slack"], e.get("dir_path") or e["parent_ref"],
                                                  e["source"]))
        self._fill_events(); self._fill_extras()
        t = self.ev_txt; t.delete("1.0", "end")
        t.insert("end", "Input: %s\nRun (UTC): %s\n\n" % (r["input"], r["run_utc"]))
        c = r.get("collection") or {}
        if c:
            t.insert("end", "COLLECTION CHECK: %s\n" % c["verdict"])
            for w in c["windows"]:
                t.insert("end", "  %-58s %s -> %s\n" % (w["artifact"][:58], w["from"], w["to"]))
            for f in c["findings"]:
                t.insert("end", "  [%s] %s\n" % (f["level"], f["text"]))
            t.insert("end", "\n")
        for d, info in (r.get("mft_dirs") or {}).items():
            t.insert("end", "$MFT entries in %s (entry %s)\n" % (info["path"], d))
            for k in info["entries"]:
                t.insert("end", "  %-34s %-8s %-8s %12s  created %s  modified %s\n" % (
                    k["name"][:34], k["entry"], "in use" if k["in_use"] else "DELETED", k["size"],
                    (k["created"] or "")[:19], (k["modified"] or "")[:19]))
            t.insert("end", "\n")
        t.insert("end", "Inventory (SHA-256, copied-file mtime)\n")
        for i in r["inventory"]:
            t.insert("end", "  %-40s %12d  %s  %s\n" % (i["file"], i["size"], i.get("mtime", ""), i["sha256"]))
        t.insert("end", "\nFileSlack URLs (earlier disk content — NOT BITS records)\n")
        for k, v in r["fileslack_urls"].items():
            t.insert("end", "  [%s]\n" % k)
            for u in v:
                t.insert("end", "    %s\n" % u)
        t.insert("end", "\nParse notes\n" + ("".join("  %s\n" % n for n in r["parse_notes"]) or "  (none)\n"))

    def _show_detail(self, _e=None):
        sel = self.jobs_tv.selection()
        j = self.rows.get(sel[0]) if sel else None
        if not j:
            return
        t = self.detail
        t.delete("1.0", "end")
        order = {lv: n for n, lv in enumerate(P.LEVELS)}
        for fl in sorted(j.get("triage", []), key=lambda s: order.get(s.split(":")[0], 9)):
            t.insert("end", "• " + fl + "\n", (fl.split(":")[0],))
        t.insert("end", "\n")
        keys = ["job_id", "name", "description", "status", "job_type", "state", "priority",
                "owner_sid", "owner", "created", "modified", "transfer_completed", "completed",
                "expiration", "notify_cmd", "notify_args", "notify_cmd_evt", "notify_args_evt",
                "notify_flags", "retry_delay_s", "no_progress_timeout_s", "creator_process_inferred",
                "creator_process_evt", "creator_aumid_inferred", "http_method", "errors",
                "sd_owner_sid", "sd_group_sid", "sd_sddl", "sd_dacl", "source"]
        for k in keys:
            if k in j and j[k] not in (None, "", []):
                t.insert("end", "%-26s" % k, ("key",)); t.insert("end", "%s\n" % (j[k],))
        for n, f in enumerate(j.get("files") or []):
            t.insert("end", "\nfile[%d]\n" % n, ("key",))
            for k in ("source_url", "dest_file", "tmp_file", "download_size", "transfer_size",
                      "complete", "remote_last_modified_inferred", "from", "local_check", "tmp_check"):
                if f.get(k) not in (None, ""):
                    t.insert("end", "  %-24s%s\n" % (k, f[k]))
            for m in f.get("mft") or []:
                t.insert("end", "  %-24s%s\n" % ("$MFT", m))
        if j.get("events"):
            t.insert("end", "\nevent timeline (%d)\n" % len(j["events"]), ("key",))
            for e in j["events"]:
                extra = e.get("url") or e.get("process") or \
                    ((e.get("program") or "") + " " + (e.get("parameters") or "")).strip()
                t.insert("end", "  %s  %-5s %-20s %s %s\n" % (short(e["time"]), e["event_id"], e["what"],
                                                             extra, e.get("hr") or ""),
                         (EVENT_LV.get(e["event_id"], "muted"),))

    def _fill_extras(self):
        cmds = list(self.extras["commands"]) + list((self.result or {}).get("commands") or [])
        order = {lv: n for n, lv in enumerate(P.LEVELS)}
        for tv, rows, data, cols in ((self.cmd_tv, self.cmdrows, cmds, CMD_COLS),
                                     (self.do_tv, self.dorows, self.extras["do_downloads"], DO_COLS)):
            tv.delete(*tv.get_children()); rows.clear()
            for i, d in enumerate(sorted(data, key=lambda d: order.get(d.get("level"), 9))):
                iid = "x%d" % i
                vals = [short(d.get(c)) if c in ("time", "expires") else d.get(c) for c, _ in cols]
                tv.insert("", "end", iid=iid, values=vals, tags=(d.get("level") or "none",))
                rows[iid] = d

    def _show_row(self, tv, rows):
        sel = tv.selection()
        d = rows.get(sel[0]) if sel else None
        if not d:
            return
        t = self.detail
        t.delete("1.0", "end")
        for fl in d.get("triage") or []:
            t.insert("end", "• " + fl + "\n", (fl.split(":")[0],))
        for k, v in d.items():
            if v not in (None, "", []) and k != "triage":
                t.insert("end", "%-20s" % k, ("key",)); t.insert("end", "%s\n" % (v,))

    def _show_event(self, _e=None):
        sel = self.ev_tv.selection()
        e = self.evrows.get(sel[0]) if sel else None
        if not e:
            return
        t = self.detail
        t.delete("1.0", "end")
        t.insert("end", e.get("message") or "", ("key",)); t.insert("end", "\n\n")
        for k, v in e.items():
            if v not in (None, "") and k != "message":
                t.insert("end", "%-20s" % k, ("key",)); t.insert("end", "%s\n" % (v,))


def main():
    args = sys.argv[1:]
    shot, tab = None, 0
    if "--screenshot" in args:
        i = args.index("--screenshot"); shot = args[i + 1]; del args[i:i + 2]
    if "--tab" in args:
        i = args.index("--tab"); tab = int(args[i + 1]); del args[i:i + 2]
    live = "--live" in args
    flagged = "--flagged" in args
    theme = "dark" if "--dark" in args else ("light" if "--light" in args else None)
    args = [a for a in args if not a.startswith("--")]
    app = App(args[0] if args else None, theme)
    if args:
        app.after(300, app.parse)
    if live:
        app.after(400, app.load_live)
    if shot:
        def snap(tries=[0]):
            done = (not args or app.result) and (not live or app.live)
            tries[0] += 1
            if not done and tries[0] < 600:
                app.after(500, snap); return
            if flagged:
                app.level.set("Flagged (H/M/R)")
            app.refresh(); app.nb.select(tab); app.update(); app.after(800, grab)

        def grab():
            from PIL import ImageGrab
            app.lift(); app.attributes("-topmost", True); app.update()
            x, y = app.winfo_rootx(), app.winfo_rooty()
            w, h = app.winfo_width(), app.winfo_height()
            ImageGrab.grab(bbox=(x, y, x + w, y + h), all_screens=True).save(shot)
            app.destroy()
        app.after(1000, snap)
    app.mainloop()


if __name__ == "__main__":
    main()
