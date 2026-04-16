#!/usr/bin/env python3
"""
AFL++ Fuzzing Helper for flux-security

Unified tool for managing AFL fuzzing campaigns.
Replaces multiple bash scripts with a single Python CLI.

Usage:
    ./fuzz.py start [--afl-path PATH] [--corpus-dir DIR]
    ./fuzz.py stop
    ./fuzz.py watch [--findings-dir DIR] [--refresh-secs N]
    ./fuzz.py triage [--findings-dir DIR]
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional


class FuzzConfig:
    """Configuration for fuzzing operations"""

    def __init__(self, args):
        self.PROJECT_ROOT = self._find_project_root()
        self.AFL_PATH = self._resolve_afl_path(getattr(args, 'afl_path', None))
        self.CORPUS_DIR = self.PROJECT_ROOT / getattr(args, 'corpus_dir', 'corpus')
        self.FINDINGS_DIR = self.PROJECT_ROOT / getattr(args, 'findings_dir', 'findings')

    def _find_project_root(self) -> Path:
        """Find project root by looking for configure.ac"""
        current = Path(__file__).resolve().parent.parent
        while current != current.parent:
            if (current / "configure.ac").exists():
                return current
            current = current.parent
        raise FileNotFoundError(
            "Could not find project root (no configure.ac found)"
        )

    def _resolve_afl_path(self, provided_path: Optional[str]) -> Path:
        """Auto-detect or use provided AFL++ path"""
        if provided_path:
            path = Path(provided_path)
            if not (path / "afl-fuzz").exists():
                raise FileNotFoundError(f"afl-fuzz not found at {path}")
            return path

        # Try common locations
        candidates = [
            Path.home() / "git" / "AFLplusplus",
            Path("/usr/local/bin"),
            Path("/usr/bin"),
        ]

        for path in candidates:
            if (path / "afl-fuzz").exists():
                return path

        raise FileNotFoundError(
            "AFL++ not found. Install it or use --afl-path\n"
            "See: https://github.com/AFLplusplus/AFLplusplus"
        )


class FuzzerManager:
    """Manages start/stop of fuzzing sessions"""

    def __init__(self, config: FuzzConfig):
        self.config = config

    def start(self):
        """Start all fuzzing harnesses in tmux"""
        print("Starting all fuzzing harnesses...")
        print()

        # Check prerequisites
        self._check_prerequisites()

        # Kill existing session if present
        if self._tmux_session_exists("fuzzing"):
            print("⚠️  Existing 'fuzzing' session found. Stopping it first...")
            subprocess.run(["tmux", "kill-session", "-t", "fuzzing"],
                         stderr=subprocess.DEVNULL)
            time.sleep(1)

        # Create tmux session with 4 fuzzer windows
        self._create_tmux_session()

        print()
        print("✅ All fuzzers started successfully!")
        print()
        print("Note: AFL_AUTORESUME=1 is set - will resume existing runs if found")
        print("      To start fresh: rm -rf findings/")
        print()
        print("Single tmux session 'fuzzing' with 4 windows:")
        print("  - fuzzer01: Primary fuzzer (sign_unwrap_noverify) [MASTER]")
        print("  - fuzzer02: Full verification fuzzer (sign_unwrap) [SLAVE]")
        print("  - fuzzer03: KV format fuzzer [SLAVE]")
        print("  - fuzzer04: Config (cf) interface fuzzer [SLAVE]")
        print()
        print("Commands:")
        print("  Attach session:     tmux attach -t fuzzing")
        print("  Switch windows:     Ctrl+b then 0/1/2/3 (or n for next)")
        print("  Detach:             Ctrl+b then d")
        print("  Monitor stats:      ./fuzz.py watch")
        print("  Triage crashes:     ./fuzz.py triage")
        print("  Stop all:           ./fuzz.py stop")
        print()
        print("Let fuzzers run for at least 24-48 hours for meaningful results.")

    def stop(self):
        """Stop the fuzzing session"""
        print("Stopping fuzzing session...")

        if not self._tmux_session_exists("fuzzing"):
            print("  No 'fuzzing' session found")
            print()
            print("⚠️  No active fuzzing session")
        else:
            subprocess.run(["tmux", "kill-session", "-t", "fuzzing"])
            print("  Killed tmux session: fuzzing (all 4 fuzzers)")
            print()
            print("✅ Fuzzing session stopped")

        print()
        print("To view results:")
        print("  Dashboard:          ./fuzz.py watch")
        print("  Triage crashes:     ./fuzz.py triage")
        print()

        # Report crash count
        crash_count = len(list(self.config.FINDINGS_DIR.glob("*/crashes/id:*")))
        if crash_count > 0:
            print(f"Crash files found: ⚠️  {crash_count} crashes")
            print("  Run ./fuzz.py triage to investigate")
        else:
            print("Crash files found: ✅ No crashes")

    def _generate_corpus(self):
        """Generate seed corpus using generate-fuzz-corpus.sh"""
        script = self.config.PROJECT_ROOT / "scripts" / "generate-fuzz-corpus.sh"
        if not script.exists():
            raise FileNotFoundError(f"Corpus generation script not found: {script}")

        print("Generating seed corpus...")
        result = subprocess.run(
            [str(script), str(self.config.CORPUS_DIR)],
            cwd=self.config.PROJECT_ROOT,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Corpus generation failed:\n{result.stderr}"
            )

        print(f"✓ Corpus generated at {self.config.CORPUS_DIR}")
        print()

    def _check_prerequisites(self):
        """Verify all required components exist"""
        # Check AFL
        afl_fuzz = self.config.AFL_PATH / "afl-fuzz"
        if not afl_fuzz.exists():
            raise FileNotFoundError(f"AFL++ not found at {afl_fuzz}")

        # Check tmux
        if subprocess.run(["which", "tmux"], capture_output=True).returncode != 0:
            raise FileNotFoundError(
                "tmux not found. Install it:\n"
                "  Ubuntu/Debian: apt-get install tmux\n"
                "  macOS: brew install tmux"
            )

        # Check fuzz harnesses
        harness = self.config.PROJECT_ROOT / "src/fuzz/fuzz_sign_unwrap_noverify"
        if not harness.exists():
            raise FileNotFoundError(
                f"Fuzz harnesses not built. Build them:\n"
                f"  CC=afl-clang-fast ./configure --enable-fuzzing --enable-sanitizers\n"
                f"  make"
            )

        # Check corpus - auto-generate if missing
        corpus_missing = (
            not (self.config.CORPUS_DIR / "sign-none").exists()
            or not (self.config.CORPUS_DIR / "kv").exists()
            or not (self.config.CORPUS_DIR / "toml").exists()
        )

        if corpus_missing:
            self._generate_corpus()

    def _tmux_session_exists(self, name: str) -> bool:
        """Check if tmux session exists"""
        result = subprocess.run(
            ["tmux", "has-session", "-t", name],
            capture_output=True
        )
        return result.returncode == 0

    def _create_tmux_session(self):
        """Create tmux session with 4 fuzzer windows"""
        root = self.config.PROJECT_ROOT
        afl = self.config.AFL_PATH / "afl-fuzz"

        # AFL++ requires specific ASAN_OPTIONS when using ASan:
        # - abort_on_error=1: crashes must abort for AFL to detect them
        # - symbolize=0: AFL handles symbolization itself
        # - detect_leaks=0: don't care about leaks at exit
        asan_opts = "abort_on_error=1:symbolize=0:detect_leaks=0"

        fuzzers = [
            {
                "name": "fuzzer01",
                "desc": "sign_unwrap_noverify - MASTER",
                "mode": "-M fuzzer01",
                "input": "corpus/sign-none",
                "timeout": "1000",
                "harness": "./src/fuzz/fuzz_sign_unwrap_noverify",
            },
            {
                "name": "fuzzer02",
                "desc": "sign_unwrap - SLAVE",
                "mode": "-S fuzzer02",
                "input": "corpus/sign-none",
                "timeout": "5000",
                "harness": "./src/fuzz/fuzz_sign_unwrap",
            },
            {
                "name": "fuzzer03",
                "desc": "kv - SLAVE",
                "mode": "-S fuzzer03",
                "input": "corpus/kv",
                "timeout": "1000",
                "harness": "./src/fuzz/fuzz_kv",
            },
            {
                "name": "fuzzer04",
                "desc": "cf - SLAVE",
                "mode": "-S fuzzer04",
                "input": "corpus/toml",
                "timeout": "5000",
                "harness": "./src/fuzz/fuzz_cf",
            },
        ]

        # Create session with first fuzzer
        print(f"[1/4] Starting {fuzzers[0]['name']} ({fuzzers[0]['desc']})...")
        cmd = [
            "tmux", "new-session", "-d", "-s", "fuzzing", "-n", fuzzers[0]['name'],
            f"cd {root} && "
            f"ASAN_OPTIONS={asan_opts} AFL_AUTORESUME=1 {afl} "
            f"-i {fuzzers[0]['input']} -o findings "
            f"{fuzzers[0]['mode']} -t {fuzzers[0]['timeout']} "
            f"{fuzzers[0].get('extra_flags', '')} "
            f"-- {fuzzers[0]['harness']} || read -p 'Press enter'"
        ]
        subprocess.run(cmd)
        time.sleep(2)

        # Verify session started
        if not self._tmux_session_exists("fuzzing"):
            raise RuntimeError(
                "ERROR: Failed to start fuzzing session\n"
                f"Check if AFL can run: {afl} -i corpus/sign-none -o findings "
                f"-M fuzzer01 -- ./src/fuzz/fuzz_sign_unwrap_noverify"
            )

        # Add remaining fuzzers as windows
        for i, fuzzer in enumerate(fuzzers[1:], start=2):
            print(f"[{i}/4] Starting {fuzzer['name']} ({fuzzer['desc']})...")
            cmd = [
                "tmux", "new-window", "-t", "fuzzing:", "-n", fuzzer['name'],
                f"cd {root} && "
                f"ASAN_OPTIONS={asan_opts} AFL_AUTORESUME=1 {afl} "
                f"-i {fuzzer['input']} -o findings "
                f"{fuzzer['mode']} -t {fuzzer['timeout']} "
                f"{fuzzer.get('extra_flags', '')} "
                f"-- {fuzzer['harness']} || read -p 'Press enter'"
            ]
            subprocess.run(cmd)
            time.sleep(1)

        # Verify all fuzzers started successfully
        self._verify_fuzzer_startup(fuzzers)

    def _verify_fuzzer_startup(self, fuzzers: List[Dict]):
        """Verify all fuzzers started successfully"""
        print()
        print("Verifying fuzzer startup...")

        # Wait a bit for fuzzers to initialize
        time.sleep(3)

        failed = []
        for fuzzer in fuzzers:
            fuzzer_name = fuzzer['name']
            stats_file = self.config.FINDINGS_DIR / fuzzer_name / "fuzzer_stats"

            if not stats_file.exists():
                failed.append(fuzzer_name)

        if failed:
            print()
            print(f"⚠️  Warning: {len(failed)} fuzzer(s) failed to start:")
            for name in failed:
                print(f"  - {name}")
            print()
            print("Attach to tmux to see error messages:")
            print("  tmux attach -t fuzzing")
            print()
            print("Common issues:")
            print("  - ASAN_OPTIONS incompatibility with AFL++")
            print("  - Harness not built or not executable")
            print("  - Corpus directory missing")
            print()
            raise RuntimeError(f"Fuzzer startup failed for: {', '.join(failed)}")

        print(f"✓ All {len(fuzzers)} fuzzers started successfully")


class DashboardMonitor:
    """Live monitoring dashboard for fuzzing status"""

    def __init__(self, config: FuzzConfig):
        self.config = config

    def _tmux_session_exists(self, name: str) -> bool:
        """Check if tmux session exists"""
        result = subprocess.run(
            ["tmux", "has-session", "-t", name],
            capture_output=True
        )
        return result.returncode == 0

    def watch(self, refresh_secs: int = 5):
        """Display live fuzzing statistics"""
        try:
            while True:
                self._display_dashboard()
                time.sleep(refresh_secs)
        except KeyboardInterrupt:
            print("\n\nExiting dashboard...")

    def _check_fuzzers_running(self) -> bool:
        """Check if fuzzing session is actually running"""
        # Check if tmux session exists
        if not self._tmux_session_exists("fuzzing"):
            return False

        # Check if any afl-fuzz processes are running
        result = subprocess.run(
            ["pgrep", "-f", "afl-fuzz"],
            capture_output=True
        )
        return result.returncode == 0

    def _display_dashboard(self):
        """Display current fuzzing status"""
        # Clear screen without flicker using ANSI escape codes
        # Move cursor to home position and clear from cursor to end of screen
        print("\033[H\033[J", end="", flush=True)

        # Check if fuzzers are running
        running = self._check_fuzzers_running()
        status_indicator = "🟢 RUNNING" if running else "🔴 STOPPED"

        print(f"================ FUZZING STATUS ({time.strftime('%H:%M:%S')}) {status_indicator} ================")
        print()

        if not self.config.FINDINGS_DIR.exists():
            print("Error: Findings directory not found")
            print(f"Expected: {self.config.FINDINGS_DIR}")
            return

        # Find all fuzzer stats
        stats_files = list(self.config.FINDINGS_DIR.glob("*/fuzzer_stats"))

        if not stats_files:
            print("No active fuzzers found")
            print()
            if running:
                print("Fuzzers are starting up... (stats files not yet created)")
            else:
                print("Start fuzzing with: ./fuzz.py start")
            return

        all_stats = []
        for stats_file in stats_files:
            stats = self._parse_fuzzer_stats(stats_file)
            if stats:
                all_stats.append(stats)

        # Display per-fuzzer stats
        for stats in all_stats:
            self._print_fuzzer_stats(stats)
            print()

        # Overall summary
        self._print_summary(all_stats)

        print()
        print("Press Ctrl+C to exit | Commands: ./fuzz.py stop, ./fuzz.py triage")

    def _parse_fuzzer_stats(self, stats_file: Path) -> Optional[Dict]:
        """Parse AFL fuzzer_stats file"""
        try:
            stats = {}
            with open(stats_file) as f:
                for line in f:
                    if ':' in line:
                        key, value = line.strip().split(':', 1)
                        stats[key.strip()] = value.strip()

            # Add derived fields
            stats['_name'] = stats_file.parent.name
            stats['_now'] = int(time.time())

            return stats
        except Exception:
            return None

    def _is_fuzzer_running(self, fuzzer_name: str) -> bool:
        """Check if a specific fuzzer is currently running"""
        # Check if tmux window exists
        result = subprocess.run(
            ["tmux", "list-windows", "-t", "fuzzing", "-F", "#{window_name}"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return False

        windows = result.stdout.strip().split('\n')
        if fuzzer_name not in windows:
            return False

        # Check if there's an afl-fuzz process for this fuzzer
        result = subprocess.run(
            ["pgrep", "-f", f"afl-fuzz.*{fuzzer_name}"],
            capture_output=True
        )
        return result.returncode == 0

    def _print_fuzzer_stats(self, stats: Dict):
        """Print formatted stats for one fuzzer"""
        name = stats['_name']

        # Calculate runtime
        start_time = int(stats.get('start_time', 0))
        now = stats['_now']
        runtime_secs = now - start_time
        hours = runtime_secs // 3600
        mins = (runtime_secs % 3600) // 60

        # Get stats
        execs = int(stats.get('execs_done', 0))
        speed = int(float(stats.get('execs_per_sec', 0)))
        paths = stats.get('corpus_count', '0')
        crashes = stats.get('saved_crashes', '0')
        hangs = stats.get('saved_hangs', '0')
        coverage = stats.get('bitmap_cvg', '0.00')

        # Last path discovery
        last_find = int(stats.get('last_find', now))
        time_since = now - last_find
        hours_since = time_since // 3600

        # Format exec count
        if execs > 1000000:
            execs_display = f"{execs // 1000000}M"
        elif execs > 1000:
            execs_display = f"{execs // 1000}k"
        else:
            execs_display = str(execs)

        # Check if this fuzzer is currently running
        is_running = self._is_fuzzer_running(name)
        run_indicator = "●" if is_running else "○"

        # Status
        if not is_running:
            status = "STOPPED"
        elif time_since > 86400:
            status = "PLATEAU"
        elif time_since > 43200:
            status = "SLOWING"
        else:
            status = "ACTIVE"

        # Print compact format
        print(f"{run_indicator} {name:10s} {hours:2d}h{mins:02d}m | {speed:6d} ex/s | "
              f"{paths:4s} paths | {coverage:4s} cov | C:{crashes} H:{hangs}")
        print(f"  Execs: {execs_display:8s} | Last find: {hours_since}h ago | "
              f"Status: {status}")

    def _print_summary(self, all_stats: List[Dict]):
        """Print overall summary"""
        print("=" * 67)

        # Count total crashes/hangs
        total_crashes = len(list(self.config.FINDINGS_DIR.glob("*/crashes/id:*")))
        total_hangs = len(list(self.config.FINDINGS_DIR.glob("*/hangs/id:*")))
        fuzzer_count = len(all_stats)

        if total_crashes == 0 and total_hangs == 0:
            print(f"Status: OK | Fuzzers: {fuzzer_count} | Crashes: 0 | Hangs: 0")
        elif total_crashes > 0:
            print(f"Status: **CRASHES** | Fuzzers: {fuzzer_count} | "
                  f"Crashes: {total_crashes} | Hangs: {total_hangs}")
            # Show first few crashes
            for crash in list(self.config.FINDINGS_DIR.glob("*/crashes/id:*"))[:3]:
                fuzzer = crash.parts[-3]
                filename = crash.name[:50]
                print(f"  {fuzzer:10s} {filename}...")
        else:
            print(f"Status: HANGS | Fuzzers: {fuzzer_count} | "
                  f"Crashes: {total_crashes} | Hangs: {total_hangs}")

        print("=" * 67)


class CrashTriager:
    """Interactive crash triage tool"""

    def __init__(self, config: FuzzConfig):
        self.config = config

    def triage(self):
        """Run interactive crash triage"""
        print("=" * 67)
        print("AFL Fuzzing Crash Triage")
        print("=" * 67)
        print()

        # Find all crashes
        crashes = self._find_crashes()

        if not crashes:
            print("✅ No crashes found!")
            print()
            hangs = len(list(self.config.FINDINGS_DIR.glob("*/hangs/id:*")))
            print(f"Hangs found: {hangs}")
            return

        print(f"⚠️  Found {len(crashes)} crash files")
        print()

        # Group by fuzzer and signal
        self._print_crash_summary(crashes)

        # Interactive menu
        print()
        print("Options:")
        print("  1) Quick test all crashes (just run them)")
        print("  2) Full triage first crash (ASAN report + minimization)")
        print("  3) Show crash inputs")
        print("  4) Exit")
        print()

        try:
            choice = input("Select option [1-4]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            return

        if choice == "1":
            self._quick_test(crashes)
        elif choice == "2":
            self._full_triage(crashes[0])
        elif choice == "3":
            self._show_inputs(crashes)
        else:
            print("Exiting.")

    def _find_crashes(self) -> List[Path]:
        """Find all crash files"""
        return sorted(self.config.FINDINGS_DIR.glob("*/crashes/id:*"))

    def _print_crash_summary(self, crashes: List[Path]):
        """Print crash summary grouped by fuzzer and signal"""
        print("--- Crashes by Fuzzer and Signal ---")

        # Group crashes
        groups = {}
        for crash in crashes:
            fuzzer = crash.parts[-3]
            signal = crash.name.split(',')[1]  # Extract sig:XX
            key = f"{fuzzer} {signal}"
            groups[key] = groups.get(key, 0) + 1

        for key in sorted(groups.keys(), key=lambda k: groups[k], reverse=True):
            print(f"  {groups[key]:3d} {key}")

        print()
        print("Signal types:")
        print("  sig:05 = SIGTRAP (ASAN/UBSAN caught something)")
        print("  sig:06 = SIGABRT (assertion/abort)")
        print("  sig:11 = SIGSEGV (segfault/null pointer)")
        print("  sig:04 = SIGILL (illegal instruction)")
        print("  sig:08 = SIGFPE (div by zero)")

    def _get_harness(self, fuzzer_name: str) -> str:
        """Determine harness from fuzzer name"""
        if "fuzzer02" in fuzzer_name:
            return "fuzz_sign_unwrap"
        elif "fuzzer03" in fuzzer_name:
            return "fuzz_kv"
        elif "fuzzer04" in fuzzer_name:
            return "fuzz_cf"
        else:
            return "fuzz_sign_unwrap_noverify"

    def _quick_test(self, crashes: List[Path]):
        """Quick test all crashes"""
        print()
        print("=== Quick Testing All Crashes ===")

        for crash in crashes:
            fuzzer = crash.parts[-3]
            harness = self._get_harness(fuzzer)
            signal = crash.name.split(',')[1]

            print()
            print(f"--- {crash.name} ---")
            print(f"Fuzzer: {fuzzer} | Harness: {harness} | Signal: {signal}")

            harness_path = self.config.PROJECT_ROOT / "src/fuzz" / harness

            # Run with timeout
            try:
                result = subprocess.run(
                    [str(harness_path)],
                    stdin=open(crash, 'rb'),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2,
                    env={**os.environ, 'FUZZ_DEBUG': '1'}
                )
                if result.returncode == 0:
                    print("Result: ✅ NO CRASH (maybe fixed?)")
                else:
                    print(f"Result: ❌ CRASHED (exit {result.returncode})")
            except subprocess.TimeoutExpired:
                print("Result: ⏱️  TIMEOUT (infinite loop?)")

    def _full_triage(self, crash: Path):
        """Full triage of first crash"""
        fuzzer = crash.parts[-3]
        harness = self._get_harness(fuzzer)

        print()
        print(f"=== Full Triage: {crash.name} ===")
        print(f"Fuzzer: {fuzzer}")
        print(f"Harness: {harness}")
        print()

        # Show input
        print("--- Crash Input (first 200 bytes) ---")
        subprocess.run(["hexdump", "-C", str(crash)], stdout=sys.stdout)
        print()
        print("As string:")
        with open(crash, 'rb') as f:
            data = f.read(200)
            print(data.decode('utf-8', errors='replace'))
        print()
        print()

        # Run with ASAN
        print("--- ASAN/UBSAN Report ---")
        harness_path = self.config.PROJECT_ROOT / "src/fuzz" / harness
        env = {
            **os.environ,
            'FUZZ_DEBUG': '1',
            'ASAN_OPTIONS': 'symbolize=1:abort_on_error=0:detect_leaks=0',
            'UBSAN_OPTIONS': 'print_stacktrace=1:symbolize=1',
        }
        subprocess.run(
            [str(harness_path)],
            stdin=open(crash, 'rb'),
            env=env
        )

        print()
        print("--- GDB Backtrace ---")
        with open(crash, 'rb') as crash_input:
            subprocess.run(
                ["gdb", "-batch",
                 "-ex", "set pagination off",
                 "-ex", "run",
                 "-ex", "bt",
                 "-ex", "info registers",
                 "-ex", "quit",
                 str(harness_path)],
                stdin=crash_input,
                env={'FUZZ_DEBUG': '1'},
                stderr=subprocess.STDOUT
            )

    def _show_inputs(self, crashes: List[Path]):
        """Show crash inputs"""
        print()
        print("=== Crash Inputs ===")

        for crash in crashes:
            print()
            print(f"--- {crash.name} ---")
            fuzzer = crash.parts[-3]
            size = crash.stat().st_size
            print(f"Fuzzer: {fuzzer} | Size: {size} bytes")
            print()
            subprocess.run(["hexdump", "-C", str(crash)], stdout=sys.stdout)
            print()
            print("As string:")
            with open(crash, 'rb') as f:
                data = f.read(100)
                print(data.decode('utf-8', errors='replace'))
            print("...")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="AFL++ fuzzing helper for flux-security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./fuzz.py start                      # Start all fuzzers
  ./fuzz.py watch                      # Monitor fuzzing status
  ./fuzz.py triage                     # Triage crashes
  ./fuzz.py stop                       # Stop all fuzzers

  ./fuzz.py start --afl-path ~/AFLplusplus
  ./fuzz.py watch --refresh-secs 10
"""
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Start command
    start_parser = subparsers.add_parser('start', help='Start fuzzing session')
    start_parser.add_argument('--afl-path', help='Path to AFL++ installation')
    start_parser.add_argument('--corpus-dir', default='corpus',
                            help='Corpus directory (default: corpus)')
    start_parser.add_argument('--findings-dir', default='findings',
                            help='Findings directory (default: findings)')

    # Stop command
    stop_parser = subparsers.add_parser('stop', help='Stop fuzzing session')
    stop_parser.add_argument('--findings-dir', default='findings',
                           help='Findings directory (default: findings)')

    # Watch command
    watch_parser = subparsers.add_parser('watch', help='Monitor fuzzing status')
    watch_parser.add_argument('--findings-dir', default='findings',
                            help='Findings directory (default: findings)')
    watch_parser.add_argument('--refresh-secs', type=int, default=5,
                            help='Refresh interval in seconds (default: 5)')

    # Triage command
    triage_parser = subparsers.add_parser('triage', help='Triage crashes')
    triage_parser.add_argument('--findings-dir', default='findings',
                             help='Findings directory (default: findings)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        config = FuzzConfig(args)

        if args.command == 'start':
            manager = FuzzerManager(config)
            manager.start()
        elif args.command == 'stop':
            manager = FuzzerManager(config)
            manager.stop()
        elif args.command == 'watch':
            monitor = DashboardMonitor(config)
            monitor.watch(args.refresh_secs)
        elif args.command == 'triage':
            triager = CrashTriager(config)
            triager.triage()

        return 0

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
