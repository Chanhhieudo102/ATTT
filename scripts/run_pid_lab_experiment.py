"""Run one bounded PID lab session: harmless simulations + benign workloads, labeled collection.

The script
1. deploys the prebuilt harmless simulations from ``lab/simulations/out`` to user-writable
   lab folders (``%TEMP%``, ``%APPDATA%``, ``%LOCALAPPDATA%`` under ``pg_lab``),
2. launches them together with benign workloads (Notepad, a Python compression job and a
   PowerShell directory walk) and picks already-running benign applications,
3. records label 1 (simulated) and label 0 (benign) PIDs in parallel with
   ``scripts/collect_pid_samples.py`` and
4. stops every process it started and deletes the deployed lab folders.

Build the simulations first:
    dotnet publish lab/simulations/beacon -c Release -o lab/simulations/out/beacon -p:AssemblyName=svch0st
(see ``lab/simulations/README.md`` for all five). Nothing here contacts external hosts.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import psutil

SIM_OUT = ROOT / "lab/simulations/out"
LAB_DIRS = [Path(os.environ.get(name, "")) / "pg_lab" for name in ("TEMP", "APPDATA", "LOCALAPPDATA")]
SIMULATIONS = [
    # (build folder, executable, deploy root, ATT&CK reference, description)
    ("beacon", "svch0st.exe", "TEMP", "T1036.005, T1071",
     "Tên giả svchost chạy từ Temp, 16 kết nối beacon loopback"),
    ("miner", "winupdater.exe", "APPDATA", "T1496",
     "Băm SHA-256 liên tục trên một nửa số lõi CPU"),
    ("locker", "invoice_viewer.exe", "TEMP", "T1486",
     "Mã hóa XOR lặp lại 120 file giả trong thư mục tạm riêng"),
    ("dropper", "expl0rer.exe", "LOCALAPPDATA", "T1036.005, T1106",
     "Tên giả explorer, sinh 6 tiến trình con cmd/ping loopback"),
    ("officeshell", "WINWORD.EXE", "TEMP", "T1204.002, T1059.001",
     "Word giả sinh PowerShell -EncodedCommand beacon loopback"),
]
BENIGN_RUNNING = {"chrome.exe": 3, "code.exe": 3, "explorer.exe": 1, "msedgewebview2.exe": 2,
                  "runtimebroker.exe": 2, "taskhostw.exe": 1, "searchhost.exe": 1,
                  "textinputhost.exe": 1, "warp-svc.exe": 1, "smartappearancesvc.exe": 1,
                  "lenovovantageservice.exe": 1, "msmpeng.exe": 1}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _readable(proc: psutil.Process) -> bool:
    try:
        return bool(proc.exe()) and proc.create_time() > 0
    except (psutil.Error, OSError):
        return False


def _exe_map(pids: list[int]) -> dict[int, str]:
    result = {}
    for pid in pids:
        try:
            result[pid] = psutil.Process(pid).exe()
        except psutil.Error:
            pass  # exited between selection and manifest; the collector skips it too
    return result


def deploy() -> list[dict]:
    deployed = []
    for folder, exe, env_root, technique, description in SIMULATIONS:
        source = SIM_OUT / folder
        if not (source / exe).exists():
            raise SystemExit(f"Thiếu {source / exe}; hãy build lab/simulations trước (xem README).")
        target = Path(os.environ[env_root]) / "pg_lab" / Path(exe).stem.lower()
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target)
        deployed.append({"exe": str(target / exe), "technique": technique, "description": description,
                         "sha256": _sha256(target / exe), "dll_sha256": _sha256(target / (Path(exe).stem + ".dll"))})
    return deployed


def cleanup() -> None:
    for lab_dir in LAB_DIRS:
        if lab_dir.name == "pg_lab" and lab_dir.exists():
            shutil.rmtree(lab_dir, ignore_errors=True)
    # The locker simulation deletes its dummy folder itself, but not when it is killed early.
    for dummy_dir in [*Path(os.environ.get("TEMP", "")).glob("processguard_lab_locker_*"),
                      *Path(os.environ.get("TEMP", "")).glob("processguard_lab_benign_*")]:
        if dummy_dir.is_dir():
            shutil.rmtree(dummy_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--phase", choices=["train", "eval"], required=True,
                        help="train: dữ liệu huấn luyện; eval: phiên mới để đánh giá tích hợp")
    parser.add_argument("--duration", type=int, default=180, help="giây thu thập (30..540)")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--hard-negatives", action="store_true",
                        help="thêm workload hợp lệ bận rộn và ứng dụng chạy từ đường dẫn người dùng (nhãn 0)")
    parser.add_argument("--all-benign", action="store_true",
                        help="gán nhãn 0 cho mọi tiến trình đọc được trên máy (giả định máy sạch), trừ mô phỏng")
    parser.add_argument("--keep-running", type=int, default=0,
                        help="giữ các tiến trình thêm N giây sau thu thập (để chụp ảnh giao diện)")
    args = parser.parse_args()
    duration = max(30, min(540, args.duration))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    session_dir = ROOT / "data/observations" / f"lab_{args.phase}_{stamp}"
    session_dir.mkdir(parents=True, exist_ok=False)
    run_seconds = duration + 20 + max(0, args.keep_running)
    started: list[subprocess.Popen] = []
    extra_pids: list[int] = []  # processes this run caused (e.g. packaged Notepad) but did not Popen
    launch_time = time.time()
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        deployed = deploy()
        for item in deployed:
            started.append(subprocess.Popen([item["exe"], str(min(600, run_seconds))], creationflags=flags,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        # Benign workloads started by the experiment.
        started.append(subprocess.Popen(["notepad.exe"]))
        started.append(subprocess.Popen([sys.executable, "-c", (
            "import zlib,os,time\nend=time.time()+%d\ndata=os.urandom(1<<20)\n"
            "while time.time()<end:\n    zlib.compress(data,6)\n    time.sleep(0.05)\n") % run_seconds],
            creationflags=flags))
        started.append(subprocess.Popen(["powershell.exe", "-NoProfile", "-Command",
            f"$end=(Get-Date).AddSeconds({run_seconds}); while((Get-Date) -lt $end)"
            "{Get-ChildItem $env:WINDIR\\System32 -ErrorAction SilentlyContinue | Out-Null; Start-Sleep 2}"],
            creationflags=flags))
        if args.hard_negatives:
            # Legitimate busy workloads that resemble the simulations (see lab/benign_workloads.py).
            base_python = getattr(sys, "_base_executable", sys.executable)
            for mode in ("backup", "compute", "webserver"):
                started.append(subprocess.Popen([base_python, str(ROOT / "lab/benign_workloads.py"), mode,
                                                 str(run_seconds)], creationflags=flags))
        time.sleep(5)

        simulated_pids = [p.pid for p in started[:len(deployed)] if p.poll() is None]
        try:
            word_children = psutil.Process(started[len(deployed) - 1].pid).children()
        except psutil.Error:
            word_children = []
        simulated_pids += [pid for pid, exe in _exe_map([child.pid for child in word_children]).items()
                           if exe.lower().endswith("\\powershell.exe")]
        own_benign = [p.pid for p in started[len(deployed):] if p.poll() is None]
        # notepad on Windows 11 may hand off to a packaged process; include the visible one by name.
        seen = {exe.lower() for exe in _exe_map(simulated_pids).values()}
        benign_pids = list(_exe_map(own_benign))
        counts: dict[str, int] = {}
        windir = os.environ.get("WINDIR", r"C:\Windows").lower()
        trusted_prefixes = tuple(p.lower() + "\\" for p in (windir, os.environ.get("ProgramFiles", ""),
                                                             os.environ.get("ProgramFiles(x86)", "")) if p)
        me = psutil.Process()
        own_tools = {me.pid, *(p.pid for p in me.parents())}  # this script and the shell that ran it
        for proc in psutil.process_iter(["name"]):
            name = (proc.info["name"] or "").lower()
            if name == "notepad.exe":
                if proc.pid not in benign_pids and _readable(proc) and proc.create_time() >= launch_time - 1:
                    benign_pids.append(proc.pid)
                    extra_pids.append(proc.pid)
                continue
            exe = _exe_map([proc.pid]).get(proc.pid, "").lower() if _readable(proc) else ""
            if not exe or exe in seen or proc.pid in benign_pids or proc.pid in own_tools:
                continue
            # Hard negatives: legitimate apps installed outside Windows/Program Files.
            user_path_app = args.hard_negatives and not exe.startswith(trusted_prefixes)
            limit = max(BENIGN_RUNNING.get(name, 0), 2 if user_path_app else 0)
            if args.all_benign:
                limit = 10 ** 6  # whole-host baseline: every readable process except the simulations
            if counts.get(name, 0) < limit:
                benign_pids.append(proc.pid)
                counts[name] = counts.get(name, 0) + 1
        # Drop short-lived PIDs that exited while the scenario was being prepared.
        simulated_exes, benign_exes = _exe_map(simulated_pids), _exe_map(benign_pids)
        simulated_pids, benign_pids = list(simulated_exes), list(benign_exes)

        manifest = {"phase": args.phase, "started_at_utc": datetime.now(timezone.utc).isoformat(),
                    "duration_seconds": duration, "interval_seconds": args.interval,
                    "host": {"os": f"{os.name} {sys.platform}", "cpu_count": psutil.cpu_count(),
                             "memory_gb": round(psutil.virtual_memory().total / 2**30, 1)},
                    "environment_note": "Máy phát triển của nhóm (không phải VM cô lập); chỉ chạy mô phỏng vô hại.",
                    "simulations": deployed,
                    "simulated_pids": simulated_exes, "benign_pids": benign_exes}
        (session_dir / "scenario_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Simulated PIDs: {simulated_pids}\nBenign PIDs: {benign_pids}")

        collector = ROOT / "scripts/collect_pid_samples.py"
        source_tag = f"devhost/{args.phase}/{stamp}"
        jobs = [subprocess.Popen([sys.executable, str(collector), "--pid", *map(str, pids), "--label", str(label),
                                  "--label-source", f"{source_tag}/{name}/scenario_manifest.json",
                                  "--duration", str(duration), "--interval", str(args.interval),
                                  "--output", str(session_dir / f"{name}.csv")],
                                 stdout=subprocess.DEVNULL)
                for name, label, pids in (("simulated", 1, simulated_pids), ("benign", 0, benign_pids))]
        codes = [job.wait() for job in jobs]
        print(f"Collectors finished with exit codes {codes}; output: {session_dir}")
        if args.keep_running:
            print(f"Keeping processes alive for {args.keep_running}s...")
            time.sleep(args.keep_running)
        return 0 if all(code == 0 for code in codes) else 1
    finally:
        for proc in started:
            try:
                parent = psutil.Process(proc.pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
            except psutil.Error:
                pass
        for pid in extra_pids:
            try:
                psutil.Process(pid).kill()
            except psutil.Error:
                pass
        time.sleep(1)
        cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
