#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import random
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

from tqdm import tqdm


STOP_REQUESTED = False


def handle_stop_signal(signum, frame):
    global STOP_REQUESTED
    STOP_REQUESTED = True


@dataclass
class Job:
    ip: str
    ports: List[int]

    @property
    def ip_ports_arg(self) -> str:
        return ",".join([self.ip] + [str(p) for p in self.ports])

    @property
    def key(self) -> str:
        return self.ip


@dataclass
class JobResult:
    ip: str
    ports: List[int]
    strategy: str
    round_no: int
    attempt_no: int
    command: List[str]
    skipped: bool
    returncode: int | None
    started_at: float | None
    ended_at: float | None
    duration_seconds: float | None
    stdout_log: str | None
    stderr_log: str | None
    reason: str | None
    status: str
    result_json: str | None
    result_json_exists: bool

    @property
    def success(self) -> bool:
        return self.status in {
            "ok",
            "result-json-written",
            "interrupted-but-result-written",
        } or self.result_json_exists


class CrawlInterrupted(Exception):
    def __init__(self, partial_result: JobResult):
        super().__init__("crawl interrupted")
        self.partial_result = partial_result


def atomic_write_json(path: Path, payload: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def append_jsonl(path: Path, payload: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        f.flush()


def read_ip_file(path: Path) -> Set[str]:
    ips: Set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        ip = line.split()[0]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"[WARN] skip invalid ip in {path}: {line}")
            continue
        ips.add(ip)
    return ips


def build_jobs(file_389: Path, file_636: Path, shuffle: bool, seed: int | None) -> List[Job]:
    ips_389 = read_ip_file(file_389)
    ips_636 = read_ip_file(file_636)

    all_ips = sorted(ips_389 | ips_636, key=lambda s: tuple(int(x) for x in s.split(".")))
    jobs: List[Job] = []
    for ip in all_ips:
        ports: List[int] = []
        if ip in ips_636:
            ports.append(636)
        if ip in ips_389:
            ports.append(389)
        jobs.append(Job(ip=ip, ports=ports))

    if shuffle:
        rnd = random.Random(seed)
        rnd.shuffle(jobs)

    return jobs


def ensure_dirs(out_dir: Path) -> None:
    (out_dir / "results").mkdir(parents=True, exist_ok=True)
    (out_dir / "crawler_logs").mkdir(parents=True, exist_ok=True)
    (out_dir / "batch_logs").mkdir(parents=True, exist_ok=True)
    (out_dir / "batch_state").mkdir(parents=True, exist_ok=True)


def expected_result_paths(job: Job, out_dir: Path) -> List[Path]:
    results_dir = out_dir / "results"
    return [results_dir / f"{job.ip}_{port}.json" for port in job.ports]


def find_result_json(job: Job, out_dir: Path) -> Optional[Path]:
    candidates = [p for p in expected_result_paths(job, out_dir) if p.exists()]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def is_done(job: Job, out_dir: Path) -> bool:
    return find_result_json(job, out_dir) is not None


def classify_status(
    skipped: bool,
    reason: str | None,
    returncode: int | None,
    result_json: Optional[Path],
) -> str:
    if skipped:
        if reason == "dry-run":
            return "dry-run"
        if reason == "existing-result":
            return "skipped-existing"
        if reason == "already-succeeded-in-state":
            return "skipped-state-success"
        return "skipped"

    if reason == "interrupted-by-user":
        return "interrupted-but-result-written" if result_json is not None else "interrupted"

    if reason == "timeout":
        return "timeout-but-result-written" if result_json is not None else "timeout"

    if returncode == 0:
        return "ok" if result_json is not None else "ok-no-result-json"

    if result_json is not None:
        return "result-json-written"

    return "failed"


def strategy_name(ports: List[int]) -> str:
    if ports == [636, 389]:
        return "both_pref636"
    if ports == [636]:
        return "636_only"
    if ports == [389]:
        return "389_only"
    return "_".join(map(str, ports))


def strategy_port_sets(job: Job, enable_port_fallback: bool) -> List[List[int]]:
    base: List[List[int]] = [job.ports[:]]
    if not enable_port_fallback:
        return base

    has_636 = 636 in job.ports
    has_389 = 389 in job.ports

    fallbacks: List[List[int]] = []
    if has_636:
        fallbacks.append([636])
    if has_389:
        fallbacks.append([389])

    seen = set()
    ordered: List[List[int]] = []
    for pset in base + fallbacks:
        key = tuple(pset)
        if key not in seen:
            seen.add(key)
            ordered.append(pset)
    return ordered


def sleep_with_stop(seconds: float) -> None:
    end = time.time() + seconds
    while time.time() < end:
        if STOP_REQUESTED:
            return
        time.sleep(min(1.0, end - time.time()))


def load_state(state_path: Path) -> dict:
    if not state_path.exists():
        return {
            "jobs": {},
            "results_count": 0,
            "updated_at": None,
        }
    return json.loads(state_path.read_text(encoding="utf-8"))


def update_state_with_result(state: dict, result: JobResult) -> None:
    jobs = state.setdefault("jobs", {})
    entry = jobs.setdefault(
        result.ip,
        {
            "success": False,
            "best_result_json": None,
            "attempts": [],
            "last_status": None,
            "last_reason": None,
            "last_round_no": None,
            "last_attempt_no": None,
        },
    )
    entry["attempts"].append(asdict(result))
    entry["last_status"] = result.status
    entry["last_reason"] = result.reason
    entry["last_round_no"] = result.round_no
    entry["last_attempt_no"] = result.attempt_no
    if result.result_json_exists and result.result_json:
        entry["best_result_json"] = result.result_json
    if result.success:
        entry["success"] = True

    state["results_count"] = int(state.get("results_count", 0)) + 1
    state["updated_at"] = time.time()


def job_succeeded_in_state(state: dict, job: Job) -> bool:
    jobs = state.get("jobs", {})
    return bool(jobs.get(job.ip, {}).get("success"))


def run_once(
    job: Job,
    ports: List[int],
    repo_root: Path,
    out_dir: Path,
    python_exe: str,
    dry_run: bool,
    round_no: int,
    attempt_no: int,
    host_timeout: int,
) -> JobResult:
    crawler = repo_root / "ldap_crawler" / "crawler.py"
    effective_job = Job(ip=job.ip, ports=ports)
    cmd = [python_exe, str(crawler), effective_job.ip_ports_arg, str(out_dir)]
    strat = strategy_name(ports)

    batch_logs_dir = out_dir / "batch_logs"
    stdout_log = batch_logs_dir / f"{job.ip}.{strat}.r{round_no}.a{attempt_no}.stdout.log"
    stderr_log = batch_logs_dir / f"{job.ip}.{strat}.r{round_no}.a{attempt_no}.stderr.log"

    if dry_run:
        return JobResult(
            ip=job.ip,
            ports=ports,
            strategy=strat,
            round_no=round_no,
            attempt_no=attempt_no,
            command=cmd,
            skipped=True,
            returncode=None,
            started_at=None,
            ended_at=None,
            duration_seconds=None,
            stdout_log=str(stdout_log),
            stderr_log=str(stderr_log),
            reason="dry-run",
            status="dry-run",
            result_json=None,
            result_json_exists=False,
        )

    started_at = time.time()
    proc: subprocess.Popen[str] | None = None

    try:
        with open(stdout_log, "w", encoding="utf-8") as out_f, open(stderr_log, "w", encoding="utf-8") as err_f:
            proc = subprocess.Popen(
                cmd,
                cwd=str(repo_root),
                stdout=out_f,
                stderr=err_f,
                text=True,
            )
            returncode = proc.wait(timeout=host_timeout)
            ended_at = time.time()
            result_json = find_result_json(effective_job, out_dir)
            return JobResult(
                ip=job.ip,
                ports=ports,
                strategy=strat,
                round_no=round_no,
                attempt_no=attempt_no,
                command=cmd,
                skipped=False,
                returncode=returncode,
                started_at=started_at,
                ended_at=ended_at,
                duration_seconds=ended_at - started_at,
                stdout_log=str(stdout_log),
                stderr_log=str(stderr_log),
                reason=None,
                status=classify_status(False, None, returncode, result_json),
                result_json=None if result_json is None else str(result_json),
                result_json_exists=result_json is not None,
            )
    except subprocess.TimeoutExpired:
        ended_at = time.time()
        if proc is not None and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        result_json = find_result_json(effective_job, out_dir)
        return JobResult(
            ip=job.ip,
            ports=ports,
            strategy=strat,
            round_no=round_no,
            attempt_no=attempt_no,
            command=cmd,
            skipped=False,
            returncode=None if proc is None else proc.returncode,
            started_at=started_at,
            ended_at=ended_at,
            duration_seconds=ended_at - started_at,
            stdout_log=str(stdout_log),
            stderr_log=str(stderr_log),
            reason="timeout",
            status=classify_status(False, "timeout", None if proc is None else proc.returncode, result_json),
            result_json=None if result_json is None else str(result_json),
            result_json_exists=result_json is not None,
        )
    except KeyboardInterrupt:
        ended_at = time.time()
        if proc is not None and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        result_json = find_result_json(effective_job, out_dir)
        partial = JobResult(
            ip=job.ip,
            ports=ports,
            strategy=strat,
            round_no=round_no,
            attempt_no=attempt_no,
            command=cmd,
            skipped=False,
            returncode=None if proc is None else proc.returncode,
            started_at=started_at,
            ended_at=ended_at,
            duration_seconds=ended_at - started_at,
            stdout_log=str(stdout_log),
            stderr_log=str(stderr_log),
            reason="interrupted-by-user",
            status=classify_status(False, "interrupted-by-user", None if proc is None else proc.returncode, result_json),
            result_json=None if result_json is None else str(result_json),
            result_json_exists=result_json is not None,
        )
        raise CrawlInterrupted(partial)


def summarize(results: List[JobResult], total_jobs: int, interrupted: bool) -> dict:
    counts = {
        "ok": 0,
        "result_json_written": 0,
        "failed": 0,
        "skipped": 0,
        "interrupted": 0,
        "timeout": 0,
    }
    for r in results:
        if r.status == "ok":
            counts["ok"] += 1
        elif r.status in {
            "result-json-written",
            "interrupted-but-result-written",
            "ok-no-result-json",
            "timeout-but-result-written",
        }:
            counts["result_json_written"] += 1
        elif r.status in {"dry-run", "skipped-existing", "skipped", "skipped-state-success"}:
            counts["skipped"] += 1
        elif r.status in {"interrupted", "interrupted-but-result-written"}:
            counts["interrupted"] += 1
        elif r.status == "timeout":
            counts["timeout"] += 1
        elif r.status == "failed":
            counts["failed"] += 1

    unique_success_ips = len({r.ip for r in results if r.success})
    return {
        "total_jobs": total_jobs,
        "completed_attempts": len(results),
        "unique_success_ips": unique_success_ips,
        "interrupted": interrupted,
        **counts,
        "results": [asdict(r) for r in results],
    }


def write_summary(out_dir: Path, results: List[JobResult], total_jobs: int, interrupted: bool) -> Path:
    summary = summarize(results, total_jobs=total_jobs, interrupted=interrupted)
    path = out_dir / "batch_summary.json"
    atomic_write_json(path, summary)
    return path


def compute_backoff(base_delay: float, backoff: float, attempt_index_zero_based: int, jitter: float) -> float:
    delay = base_delay * (backoff ** attempt_index_zero_based)
    if jitter > 0:
        delay += random.uniform(0, jitter)
    return delay


def main() -> int:
    signal.signal(signal.SIGINT, handle_stop_signal)
    signal.signal(signal.SIGTERM, handle_stop_signal)

    parser = argparse.ArgumentParser(
        description=(
            "Robust batch runner for FHMS-ITS/SMINE ldap_crawler/crawler.py over CN/HK IP lists. "
            "Supports retries, rounds, per-host timeout, port fallback, tqdm and resumable state."
        )
    )
    parser.add_argument("--file389", default="./geoip_filter_output/cert_server_ips_389_cn_hk_geoip.txt", help="389 IP list")
    parser.add_argument("--file636", default="./geoip_filter_output/cert_server_ips_636_cn_hk_geoip.txt", help="636 IP list")
    parser.add_argument("--repo-root", default=".", help="SMINE repo root")
    parser.add_argument("--out-dir", default="./cn_hk_crawl_output", help="output directory")
    parser.add_argument("--python-exe", default=sys.executable, help="python executable for calling crawler.py")

    parser.add_argument("--shuffle", action="store_true", help="shuffle host order")
    parser.add_argument("--seed", type=int, default=None, help="random seed for shuffle")
    parser.add_argument("--limit", type=int, default=0, help="crawl at most N hosts (0 = no limit)")
    parser.add_argument("--dry-run", action="store_true", help="print/record jobs without executing them")

    parser.add_argument("--skip-existing", action="store_true", help="skip hosts that already have a result json")
    parser.add_argument("--resume-state", action="store_true", help="resume from batch_state/state.json success records")
    parser.add_argument("--force-retry-failed", action="store_true", help="ignore prior failed attempts in state and try again")

    parser.add_argument("--max-rounds", type=int, default=3, help="max retry rounds over remaining unfinished hosts")
    parser.add_argument("--max-attempts-per-strategy", type=int, default=2, help="attempts per strategy within one round")
    parser.add_argument("--host-timeout", type=int, default=3600, help="per-host subprocess timeout in seconds")
    parser.add_argument("--sleep", type=float, default=2.0, help="base sleep between hosts")
    parser.add_argument("--retry-delay", type=float, default=20.0, help="base delay before retry")
    parser.add_argument("--retry-backoff", type=float, default=2.0, help="exponential retry backoff")
    parser.add_argument("--jitter", type=float, default=5.0, help="random jitter seconds added to delays")
    parser.add_argument("--port-fallback", action="store_true", help="after combined 636,389 try 636-only and 389-only")
    parser.add_argument("--write-jsonl", action="store_true", help="append each attempt to batch_results.jsonl")
    args = parser.parse_args()

    file_389 = Path(args.file389).expanduser().resolve()
    file_636 = Path(args.file636).expanduser().resolve()
    repo_root = Path(args.repo_root).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()

    if not file_389.exists():
        raise FileNotFoundError(f"389 list not found: {file_389}")
    if not file_636.exists():
        raise FileNotFoundError(f"636 list not found: {file_636}")
    if not (repo_root / "ldap_crawler" / "crawler.py").exists():
        raise FileNotFoundError(f"crawler.py not found under repo root: {repo_root / 'ldap_crawler' / 'crawler.py'}")

    ensure_dirs(out_dir)

    jobs = build_jobs(file_389, file_636, shuffle=args.shuffle, seed=args.seed)
    if args.limit > 0:
        jobs = jobs[: args.limit]

    state_path = out_dir / "batch_state" / "state.json"
    jsonl_path = out_dir / "batch_state" / "batch_results.jsonl"
    manifest_path = out_dir / "batch_state" / "manifest.json"

    manifest = {
        "file389": str(file_389),
        "file636": str(file_636),
        "repo_root": str(repo_root),
        "out_dir": str(out_dir),
        "python_exe": args.python_exe,
        "shuffle": args.shuffle,
        "seed": args.seed,
        "limit": args.limit,
        "dry_run": args.dry_run,
        "skip_existing": args.skip_existing,
        "resume_state": args.resume_state,
        "force_retry_failed": args.force_retry_failed,
        "max_rounds": args.max_rounds,
        "max_attempts_per_strategy": args.max_attempts_per_strategy,
        "host_timeout": args.host_timeout,
        "sleep": args.sleep,
        "retry_delay": args.retry_delay,
        "retry_backoff": args.retry_backoff,
        "jitter": args.jitter,
        "port_fallback": args.port_fallback,
        "job_count": len(jobs),
        "jobs": [asdict(j) for j in jobs],
        "created_at": time.time(),
    }
    atomic_write_json(manifest_path, manifest)

    state = load_state(state_path) if args.resume_state else {"jobs": {}, "results_count": 0, "updated_at": None}
    results: List[JobResult] = []
    interrupted = False

    for round_no in range(1, args.max_rounds + 1):
        if STOP_REQUESTED:
            interrupted = True
            break

        remaining: List[Job] = []
        for job in jobs:
            if args.skip_existing and is_done(job, out_dir):
                if not job_succeeded_in_state(state, job):
                    existing = find_result_json(job, out_dir)
                    result = JobResult(
                        ip=job.ip,
                        ports=job.ports,
                        strategy="existing",
                        round_no=round_no,
                        attempt_no=0,
                        command=[],
                        skipped=True,
                        returncode=None,
                        started_at=None,
                        ended_at=None,
                        duration_seconds=None,
                        stdout_log=None,
                        stderr_log=None,
                        reason="existing-result",
                        status="skipped-existing",
                        result_json=None if existing is None else str(existing),
                        result_json_exists=existing is not None,
                    )
                    results.append(result)
                    update_state_with_result(state, result)
                continue

            if args.resume_state and not args.force_retry_failed and job_succeeded_in_state(state, job):
                result = JobResult(
                    ip=job.ip,
                    ports=job.ports,
                    strategy="state-success",
                    round_no=round_no,
                    attempt_no=0,
                    command=[],
                    skipped=True,
                    returncode=None,
                    started_at=None,
                    ended_at=None,
                    duration_seconds=None,
                    stdout_log=None,
                    stderr_log=None,
                    reason="already-succeeded-in-state",
                    status="skipped-state-success",
                    result_json=state["jobs"].get(job.ip, {}).get("best_result_json"),
                    result_json_exists=bool(state["jobs"].get(job.ip, {}).get("best_result_json")),
                )
                results.append(result)
                continue

            remaining.append(job)

        if not remaining:
            break

        if args.shuffle:
            rnd = random.Random((args.seed or 0) + round_no)
            rnd.shuffle(remaining)

        pbar = tqdm(remaining, desc=f"round {round_no}/{args.max_rounds}", unit="host", dynamic_ncols=True)

        round_success = 0

        for job in pbar:
            if STOP_REQUESTED:
                interrupted = True
                break

            if args.skip_existing and is_done(job, out_dir):
                existing = find_result_json(job, out_dir)
                result = JobResult(
                    ip=job.ip,
                    ports=job.ports,
                    strategy="existing",
                    round_no=round_no,
                    attempt_no=0,
                    command=[],
                    skipped=True,
                    returncode=None,
                    started_at=None,
                    ended_at=None,
                    duration_seconds=None,
                    stdout_log=None,
                    stderr_log=None,
                    reason="existing-result",
                    status="skipped-existing",
                    result_json=None if existing is None else str(existing),
                    result_json_exists=existing is not None,
                )
                results.append(result)
                update_state_with_result(state, result)
                atomic_write_json(state_path, state)
                continue

            success_for_job = False
            strategies = strategy_port_sets(job, enable_port_fallback=args.port_fallback)

            for ports in strategies:
                if success_for_job or STOP_REQUESTED:
                    break

                for attempt_no in range(1, args.max_attempts_per_strategy + 1):
                    if STOP_REQUESTED:
                        interrupted = True
                        break

                    try:
                        result = run_once(
                            job=job,
                            ports=ports,
                            repo_root=repo_root,
                            out_dir=out_dir,
                            python_exe=args.python_exe,
                            dry_run=args.dry_run,
                            round_no=round_no,
                            attempt_no=attempt_no,
                            host_timeout=args.host_timeout,
                        )
                        results.append(result)
                        update_state_with_result(state, result)
                        atomic_write_json(state_path, state)
                        if args.write_jsonl:
                            append_jsonl(jsonl_path, asdict(result))

                        pbar.set_postfix_str(
                            f"ip={job.ip} strat={result.strategy} status={result.status}",
                            refresh=False,
                        )

                        if result.success or is_done(job, out_dir):
                            success_for_job = True
                            round_success += 1
                            break

                        if attempt_no < args.max_attempts_per_strategy:
                            delay = compute_backoff(
                                args.retry_delay,
                                args.retry_backoff,
                                attempt_no - 1,
                                args.jitter,
                            )
                            sleep_with_stop(delay)
                    except CrawlInterrupted as exc:
                        results.append(exc.partial_result)
                        update_state_with_result(state, exc.partial_result)
                        atomic_write_json(state_path, state)
                        if args.write_jsonl:
                            append_jsonl(jsonl_path, asdict(exc.partial_result))
                        interrupted = True
                        success_for_job = exc.partial_result.success
                        break

                if success_for_job:
                    break

            if args.sleep > 0 and not STOP_REQUESTED:
                sleep_with_stop(args.sleep)

        pbar.close()

        if interrupted:
            break

        unfinished = [
            j for j in jobs
            if not is_done(j, out_dir)
            and not job_succeeded_in_state(state, j)
        ]

        if not unfinished:
            break

        if round_success == 0 and round_no < args.max_rounds:
            # 没有新增成功，下一轮还是可以继续，但给一点提示
            print(f"[INFO] round {round_no} finished with no new successes; retrying remaining hosts")

    summary_path = write_summary(out_dir, results, total_jobs=len(jobs), interrupted=interrupted)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    print("\nDone.")
    print(
        "  ok={ok} result_json_written={result_json_written} failed={failed} "
        "timeout={timeout} skipped={skipped} interrupted={interrupted_count} unique_success_ips={unique_success_ips}".format(
            ok=summary["ok"],
            result_json_written=summary["result_json_written"],
            failed=summary["failed"],
            timeout=summary["timeout"],
            skipped=summary["skipped"],
            interrupted_count=summary["interrupted"],
            unique_success_ips=summary["unique_success_ips"],
        )
    )
    print(f"  summary={summary_path}")
    print(f"  state={state_path}")

    if interrupted:
        return 130
    if summary["failed"] > 0 or summary["timeout"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())