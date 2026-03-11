"""
Distributed Clock Synchronization System — Performance Test
Phase 4: Performance Evaluation

Tests the system under realistic load conditions:
  - Scenario A : Single client baseline (accuracy reference)
  - Scenario B : 10 concurrent clients
  - Scenario C : 50 concurrent clients
  - Scenario D : 100 concurrent clients

Metrics collected per scenario:
  - Sync accuracy   : mean absolute offset (ms)
  - Latency         : mean and 95th-percentile round-trip delay (ms)
  - Jitter          : standard deviation of delays (ms)
  - Throughput      : successful sync responses per second
  - Packet loss     : percentage of requests with no response
  - Convergence time: rounds until offset < 1 ms

Outputs:
  - Console summary table
  - results/raw_results.json    — full per-client data
  - results/performance_report.txt — human-readable summary
  - results/graphs/             — 4 matplotlib charts
      latency_vs_clients.png
      accuracy_vs_clients.png
      jitter_vs_clients.png
      throughput_vs_clients.png

Usage:
  # Make sure time_server.py is already running, then:
  python performance_test.py
  python performance_test.py --host 192.168.1.5   # remote server
  python performance_test.py --quick              # 10+20+50 clients only
"""

import socket
import struct
import time
import threading
import statistics
import argparse
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime

# ── Try importing matplotlib — warn gracefully if not installed ───────────────
try:
    import matplotlib
    matplotlib.use("Agg")   # non-interactive backend (works without display)
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("[WARN] matplotlib not installed — skipping graphs.")
    print("       Install with:  pip install matplotlib")

# ── Configuration ──────────────────────────────────────────────────────────────
SERVER_HOST   = "127.0.0.1"
UDP_PORT      = 5005
BUFFER_SIZE   = 1024
UDP_TIMEOUT   = 2.0
NUM_SAMPLES   = 4       # samples per sync round (matches Phase 3 client)
SAMPLE_GAP    = 0.05    # tighter gap for perf test (was 0.1s)
ROUNDS_PER_CLIENT = 10  # sync rounds per client during test
CONVERGE_THR  = 1.0     # ms

MSG_SYNC_REQUEST = 0x01

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR  = os.path.join(BASE_DIR, "results")
GRAPHS_DIR   = os.path.join(RESULTS_DIR, "graphs")


# ── Data structures ────────────────────────────────────────────────────────────
@dataclass
class SampleResult:
    offset_ms:  float
    delay_ms:   float
    success:    bool

@dataclass
class ClientResult:
    client_id:      str
    samples:        list = field(default_factory=list)   # list[SampleResult]
    rounds:         int  = 0
    packet_loss:    int  = 0   # count of failed requests
    start_time:     float = 0.0
    end_time:       float = 0.0

    @property
    def successful_samples(self):
        return [s for s in self.samples if s.success]

    @property
    def mean_offset_ms(self):
        s = self.successful_samples
        return statistics.mean(abs(x.offset_ms) for x in s) if s else None

    @property
    def mean_delay_ms(self):
        s = self.successful_samples
        return statistics.mean(x.delay_ms for x in s) if s else None

    @property
    def p95_delay_ms(self):
        s = self.successful_samples
        if not s:
            return None
        delays = sorted(x.delay_ms for x in s)
        idx = int(len(delays) * 0.95)
        return delays[min(idx, len(delays)-1)]

    @property
    def jitter_ms(self):
        s = self.successful_samples
        delays = [x.delay_ms for x in s]
        return statistics.stdev(delays) if len(delays) > 1 else 0.0

    @property
    def loss_pct(self):
        total = len(self.samples) + self.packet_loss
        return (self.packet_loss / total * 100) if total > 0 else 0.0

    @property
    def duration_s(self):
        return self.end_time - self.start_time if self.end_time > self.start_time else 0

    @property
    def throughput_rps(self):
        n = len(self.successful_samples)
        return n / self.duration_s if self.duration_s > 0 else 0.0

@dataclass
class ScenarioResult:
    label:          str
    client_count:   int
    clients:        list = field(default_factory=list)  # list[ClientResult]
    wall_time_s:    float = 0.0

    # Aggregated metrics (computed after all clients finish)
    mean_accuracy_ms: float = 0.0
    mean_latency_ms:  float = 0.0
    p95_latency_ms:   float = 0.0
    mean_jitter_ms:   float = 0.0
    mean_throughput:  float = 0.0
    mean_loss_pct:    float = 0.0
    total_requests:   int   = 0
    total_success:    int   = 0

    def compute(self):
        valid = [c for c in self.clients if c.successful_samples]
        if not valid:
            return
        self.mean_accuracy_ms = statistics.mean(c.mean_offset_ms  for c in valid)
        self.mean_latency_ms  = statistics.mean(c.mean_delay_ms   for c in valid)
        self.p95_latency_ms   = statistics.mean(c.p95_delay_ms    for c in valid)
        self.mean_jitter_ms   = statistics.mean(c.jitter_ms       for c in valid)
        self.mean_throughput  = sum(c.throughput_rps              for c in valid)
        self.mean_loss_pct    = statistics.mean(c.loss_pct        for c in self.clients)
        self.total_requests   = sum(len(c.samples) + c.packet_loss for c in self.clients)
        self.total_success    = sum(len(c.successful_samples)      for c in self.clients)


# ══════════════════════════════════════════════════════════════════════════════
# Single-client worker
# ══════════════════════════════════════════════════════════════════════════════

def run_client(client_id: str, server_host: str,
               rounds: int, result_out: list, idx: int):
    """
    Run ROUNDS sync rounds for one client.
    Stores a ClientResult into result_out[idx].
    """
    cr = ClientResult(client_id=client_id)
    cr.start_time = time.time()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(UDP_TIMEOUT)

    cid_bytes = client_id.encode("ascii")[:16].ljust(16, b"\x00")

    try:
        for _ in range(rounds):
            for s in range(NUM_SAMPLES):
                T1      = time.time()
                request = bytes([MSG_SYNC_REQUEST]) + struct.pack("!d", T1) + cid_bytes

                try:
                    sock.sendto(request, (server_host, UDP_PORT))
                    data, _ = sock.recvfrom(BUFFER_SIZE)
                    T4      = time.time()

                    if len(data) < 24:
                        cr.packet_loss += 1
                        continue

                    T1e, T2, T3 = struct.unpack("!ddd", data[:24])
                    offset = ((T2 - T1e) + (T3 - T4)) / 2.0
                    delay  = (T4 - T1e) - (T3 - T2)
                    cr.samples.append(SampleResult(
                        offset_ms = offset * 1000,
                        delay_ms  = delay  * 1000,
                        success   = True
                    ))

                except socket.timeout:
                    cr.packet_loss += 1
                except struct.error:
                    cr.packet_loss += 1

                if s < NUM_SAMPLES - 1:
                    time.sleep(SAMPLE_GAP)

            cr.rounds += 1

    finally:
        sock.close()
        cr.end_time = time.time()
        result_out[idx] = cr


# ══════════════════════════════════════════════════════════════════════════════
# Scenario runner
# ══════════════════════════════════════════════════════════════════════════════

def run_scenario(label: str, n_clients: int,
                 server_host: str, rounds: int) -> ScenarioResult:
    print(f"\n{'─'*60}")
    print(f"  {label}  ({n_clients} concurrent client{'s' if n_clients>1 else ''})")
    print(f"{'─'*60}")

    results   = [None] * n_clients
    threads   = []
    wall_start = time.time()

    for i in range(n_clients):
        cid = f"perf-{i+1:03d}"
        t   = threading.Thread(
            target=run_client,
            args=(cid, server_host, rounds, results, i),
            daemon=True
        )
        threads.append(t)

    # Stagger launches slightly to avoid thundering-herd on startup
    for t in threads:
        t.start()
        time.sleep(0.01)

    # Wait for all to finish
    for t in threads:
        t.join(timeout=120)

    wall_time = time.time() - wall_start

    sr = ScenarioResult(
        label        = label,
        client_count = n_clients,
        clients      = [r for r in results if r is not None],
        wall_time_s  = wall_time
    )
    sr.compute()

    # Live summary
    print(f"  Wall time       : {wall_time:.1f}s")
    print(f"  Total requests  : {sr.total_requests}  (success={sr.total_success})")
    print(f"  Mean accuracy   : {sr.mean_accuracy_ms:.3f} ms")
    print(f"  Mean latency    : {sr.mean_latency_ms:.3f} ms")
    print(f"  P95  latency    : {sr.p95_latency_ms:.3f} ms")
    print(f"  Mean jitter     : {sr.mean_jitter_ms:.3f} ms")
    print(f"  Throughput      : {sr.mean_throughput:.1f} req/s")
    print(f"  Packet loss     : {sr.mean_loss_pct:.2f}%")

    return sr


# ══════════════════════════════════════════════════════════════════════════════
# Graph generation
# ══════════════════════════════════════════════════════════════════════════════

def save_graphs(scenarios: list[ScenarioResult]):
    if not HAS_MATPLOTLIB:
        return
    os.makedirs(GRAPHS_DIR, exist_ok=True)

    counts    = [s.client_count      for s in scenarios]
    accuracy  = [s.mean_accuracy_ms  for s in scenarios]
    latency   = [s.mean_latency_ms   for s in scenarios]
    p95       = [s.p95_latency_ms    for s in scenarios]
    jitter    = [s.mean_jitter_ms    for s in scenarios]
    throughput= [s.mean_throughput   for s in scenarios]
    loss      = [s.mean_loss_pct     for s in scenarios]

    STYLE  = {"marker": "o", "linewidth": 2, "markersize": 7}
    COLORS = ["#1E40AF", "#DC2626", "#065F46", "#7C3AED"]

    # ── 1. Latency vs Clients ────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(counts, latency, label="Mean latency",  color=COLORS[0], **STYLE)
    ax.plot(counts, p95,     label="P95 latency",   color=COLORS[1], linestyle="--", **STYLE)
    ax.set_xlabel("Concurrent Clients", fontsize=12)
    ax.set_ylabel("Latency (ms)",        fontsize=12)
    ax.set_title("Round-Trip Latency vs Concurrent Clients", fontsize=14, fontweight="bold")
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    ax.set_xticks(counts)
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPHS_DIR, "latency_vs_clients.png"), dpi=150)
    plt.close()

    # ── 2. Accuracy vs Clients ───────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(counts, accuracy, color=COLORS[2], **STYLE)
    ax.axhline(y=1.0, color="red", linestyle="--", alpha=0.6, label="1 ms threshold")
    ax.set_xlabel("Concurrent Clients", fontsize=12)
    ax.set_ylabel("Mean Absolute Offset (ms)", fontsize=12)
    ax.set_title("Sync Accuracy vs Concurrent Clients", fontsize=14, fontweight="bold")
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    ax.set_xticks(counts)
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPHS_DIR, "accuracy_vs_clients.png"), dpi=150)
    plt.close()

    # ── 3. Jitter vs Clients ─────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(counts, jitter, color=COLORS[3], **STYLE)
    ax.set_xlabel("Concurrent Clients", fontsize=12)
    ax.set_ylabel("Jitter — Stdev of Delays (ms)", fontsize=12)
    ax.set_title("Network Jitter vs Concurrent Clients", fontsize=14, fontweight="bold")
    ax.grid(True, alpha=0.3)
    ax.set_xticks(counts)
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPHS_DIR, "jitter_vs_clients.png"), dpi=150)
    plt.close()

    # ── 4. Throughput vs Clients ─────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(counts, throughput, color=COLORS[0], alpha=0.8, width=[c*0.4 for c in counts])
    ax.set_xlabel("Concurrent Clients", fontsize=12)
    ax.set_ylabel("Total Throughput (req/s)", fontsize=12)
    ax.set_title("Server Throughput vs Concurrent Clients", fontsize=14, fontweight="bold")
    ax.set_xticks(counts)
    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPHS_DIR, "throughput_vs_clients.png"), dpi=150)
    plt.close()

    # ── 5. Combined dashboard ─────────────────────────────────────────────────
    fig, axes = plt.subplots(2, 2, figsize=(14, 9))
    fig.suptitle("Clock Sync System — Performance Dashboard", fontsize=16, fontweight="bold")

    axes[0,0].plot(counts, latency, label="Mean", color=COLORS[0], **STYLE)
    axes[0,0].plot(counts, p95, label="P95", color=COLORS[1], linestyle="--", **STYLE)
    axes[0,0].set_title("Latency (ms)"); axes[0,0].legend(); axes[0,0].grid(True, alpha=0.3)
    axes[0,0].set_xticks(counts)

    axes[0,1].plot(counts, accuracy, color=COLORS[2], **STYLE)
    axes[0,1].axhline(y=1.0, color="red", linestyle="--", alpha=0.6)
    axes[0,1].set_title("Sync Accuracy — Mean |Offset| (ms)"); axes[0,1].grid(True, alpha=0.3)
    axes[0,1].set_xticks(counts)

    axes[1,0].plot(counts, jitter, color=COLORS[3], **STYLE)
    axes[1,0].set_title("Jitter — Stdev of Delays (ms)"); axes[1,0].grid(True, alpha=0.3)
    axes[1,0].set_xticks(counts)

    axes[1,1].bar(counts, throughput, color=COLORS[0], alpha=0.8, width=[c*0.4 for c in counts])
    axes[1,1].set_title("Total Throughput (req/s)"); axes[1,1].grid(True, alpha=0.3, axis="y")
    axes[1,1].set_xticks(counts)

    for ax in axes.flat:
        ax.set_xlabel("Concurrent Clients")

    plt.tight_layout()
    plt.savefig(os.path.join(GRAPHS_DIR, "dashboard.png"), dpi=150)
    plt.close()
    print(f"\n  Graphs saved → {GRAPHS_DIR}/")


# ══════════════════════════════════════════════════════════════════════════════
# Report & JSON export
# ══════════════════════════════════════════════════════════════════════════════

def save_report(scenarios: list[ScenarioResult]):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Text report ───────────────────────────────────────────────────────────
    lines = [
        "=" * 70,
        "  DISTRIBUTED CLOCK SYNCHRONIZATION — PERFORMANCE REPORT",
        f"  Generated: {ts}",
        "=" * 70,
        "",
        f"{'Scenario':<30} {'Clients':>7} {'Accuracy':>10} {'Latency':>10} "
        f"{'P95':>10} {'Jitter':>8} {'Tput':>10} {'Loss':>7}",
        f"{'':30} {'':>7} {'(ms)':>10} {'(ms)':>10} "
        f"{'(ms)':>10} {'(ms)':>8} {'(req/s)':>10} {'(%)':>7}",
        "-" * 70,
    ]
    for s in scenarios:
        lines.append(
            f"{s.label:<30} {s.client_count:>7} "
            f"{s.mean_accuracy_ms:>10.3f} {s.mean_latency_ms:>10.3f} "
            f"{s.p95_latency_ms:>10.3f} {s.mean_jitter_ms:>8.3f} "
            f"{s.mean_throughput:>10.1f} {s.mean_loss_pct:>7.2f}"
        )
    lines += [
        "-" * 70,
        "",
        "OBSERVATIONS",
        "─" * 40,
    ]

    # Auto-generate observations
    base = scenarios[0]
    for s in scenarios[1:]:
        lat_delta = s.mean_latency_ms - base.mean_latency_ms
        acc_delta = s.mean_accuracy_ms - base.mean_accuracy_ms
        lines.append(
            f"  {s.label}: latency +{lat_delta:.3f}ms vs baseline, "
            f"accuracy +{acc_delta:.3f}ms vs baseline"
        )
    lines += [
        "",
        "CONCLUSION",
        "─" * 40,
        f"  Baseline accuracy (1 client) : {base.mean_accuracy_ms:.3f} ms",
        f"  Peak throughput              : {max(s.mean_throughput for s in scenarios):.1f} req/s",
        f"  Max packet loss              : {max(s.mean_loss_pct for s in scenarios):.2f}%",
        f"  Max P95 latency              : {max(s.p95_latency_ms for s in scenarios):.3f} ms",
        "",
        "=" * 70,
    ]

    report_path = os.path.join(RESULTS_DIR, "performance_report.txt")
    with open(report_path, "w") as f:
        f.write("\n".join(lines))
    print(f"\n  Report saved → {report_path}")
    print("\n".join(lines))

    # ── JSON export ───────────────────────────────────────────────────────────
    json_data = []
    for s in scenarios:
        json_data.append({
            "label":            s.label,
            "client_count":     s.client_count,
            "wall_time_s":      round(s.wall_time_s, 2),
            "mean_accuracy_ms": round(s.mean_accuracy_ms, 4),
            "mean_latency_ms":  round(s.mean_latency_ms,  4),
            "p95_latency_ms":   round(s.p95_latency_ms,   4),
            "mean_jitter_ms":   round(s.mean_jitter_ms,   4),
            "mean_throughput":  round(s.mean_throughput,  2),
            "mean_loss_pct":    round(s.mean_loss_pct,    4),
            "total_requests":   s.total_requests,
            "total_success":    s.total_success,
        })

    json_path = os.path.join(RESULTS_DIR, "raw_results.json")
    with open(json_path, "w") as f:
        json.dump({"generated": ts, "scenarios": json_data}, f, indent=2)
    print(f"  JSON   saved → {json_path}")


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def check_server(host: str) -> bool:
    """Quick connectivity check — send one UDP packet and see if we get a reply."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    try:
        T1  = time.time()
        cid = b"perf-check\x00\x00\x00\x00\x00\x00"
        req = bytes([MSG_SYNC_REQUEST]) + struct.pack("!d", T1) + cid
        sock.sendto(req, (host, UDP_PORT))
        sock.recvfrom(BUFFER_SIZE)
        return True
    except socket.timeout:
        return False
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="Clock Sync Performance Test")
    parser.add_argument("--host",   default=SERVER_HOST, help="Server IP (default: 127.0.0.1)")
    parser.add_argument("--rounds", type=int, default=ROUNDS_PER_CLIENT,
                        help=f"Sync rounds per client (default: {ROUNDS_PER_CLIENT})")
    parser.add_argument("--quick",  action="store_true",
                        help="Quick mode: 1, 10, 50 clients only")
    args = parser.parse_args()

    print("=" * 60)
    print("  Distributed Clock Sync — Performance Evaluation")
    print(f"  Server : {args.host}:{UDP_PORT}")
    print(f"  Rounds : {args.rounds} per client")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Server reachability check
    print(f"\n  Checking server at {args.host}:{UDP_PORT}...", end=" ", flush=True)
    if not check_server(args.host):
        print("UNREACHABLE")
        print("  Make sure time_server.py is running before running this test.")
        sys.exit(1)
    print("OK ✓")

    # Define test scenarios
    if args.quick:
        scenarios_cfg = [
            ("Baseline — 1 client",    1),
            ("Load — 10 clients",      10),
            ("Load — 50 clients",      50),
        ]
    else:
        scenarios_cfg = [
            ("Baseline — 1 client",    1),
            ("Load — 10 clients",      10),
            ("Load — 50 clients",      50),
            ("Stress — 100 clients",   100),
        ]

    results = []
    for label, n in scenarios_cfg:
        sr = run_scenario(label, n, args.host, args.rounds)
        results.append(sr)
        time.sleep(2)   # brief cooldown between scenarios

    # Save outputs
    save_report(results)
    save_graphs(results)

    print("\n  Performance evaluation complete.")


if __name__ == "__main__":
    main()
