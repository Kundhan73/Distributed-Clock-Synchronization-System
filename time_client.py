"""
Distributed Clock Synchronization System — Time Client
Phase 5: Optimization & Fixes

Fixes and improvements over Phase 3:

  FIX 1  — SSL reconnect with exponential backoff
             Phase 3 retried immediately on reconnect, hammering the server.
             Phase 5 waits 1s, 2s, 4s, 8s, 16s between attempts (max 3 retries).

  FIX 2  — T4 / T1 sanity check before computing offset
             If T4 < T1 (clock jumped backward) or delay < 0 (impossible),
             the sample is discarded rather than producing a garbage offset.

  FIX 3  — UDP socket reuse across samples in a round
             Phase 3 created a new socket every round. Phase 5 reuses the
             same socket for all samples within a round, reducing overhead.
             Socket is still closed cleanly after each round.

  FIX 4  — Offset history capped to prevent unbounded memory growth
             Phase 3 appended to self._history forever. Phase 5 keeps only
             the last MAX_HISTORY entries (100 by default).

  FIX 5  — Graceful SSL close on KeyboardInterrupt
             Phase 3 sometimes skipped BYE if the interrupt fired during
             a sync round. Phase 5 ensures BYE is always sent via try/finally.

  FIX 6  — Stale SSL socket detected before REPORT
             Phase 3 only detected a broken socket when send/recv failed.
             Phase 5 proactively checks if the socket is still valid before
             attempting a REPORT, reducing noisy error logs.

  FIX 7  — Zero-delay guard in drift calculation
             If elapsed time between rounds is 0 (shouldn't happen but can
             on very fast machines), drift computation is now skipped safely.

  FIX 8  — Server host configurable via environment variable
             SERVER_HOST can be overridden with CLOCK_SERVER env var,
             making the client easier to deploy without editing source.
"""

import socket
import ssl
import struct
import time
import logging
import os
import json
import sys
import statistics
import threading
from collections import deque

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s  %(message)s"
)

# ── Configuration ─────────────────────────────────────────────────────────────
# FIX 8: allow override via environment variable
SERVER_HOST    = os.environ.get("CLOCK_SERVER", "127.0.0.1")
UDP_PORT       = 5005
SSL_PORT       = 5006
BUFFER_SIZE    = 1024
NUM_SAMPLES    = 4
SAMPLE_GAP     = 0.1
UDP_TIMEOUT    = 2.0
SYNC_INTERVAL  = 5
FAST_INTERVAL  = 2
DRIFT_FAST_THR = 10.0
REPORT_EVERY   = 3
CONVERGE_THR   = 1.0      # ms
MAX_HISTORY    = 100       # FIX 4: cap offset history
SSL_MAX_RETRY  = 3         # FIX 1: max reconnect attempts
SSL_RETRY_BASE = 1.0       # FIX 1: base backoff in seconds

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE_DIR, "ssl", "server.crt")

MSG_SYNC_REQUEST = 0x01


# ══════════════════════════════════════════════════════════════════════════════
class TimeClient:

    def __init__(self,
                 client_id:   str = "client-1",
                 token:       str = "dev-token",
                 server_host: str = SERVER_HOST):
        self.client_id   = client_id
        self.token       = token
        self.server_host = server_host
        self.log         = logging.getLogger(client_id)

        self.offset    = 0.0
        self.drift     = 0.0
        self.stratum   = None
        self.converged = False

        # FIX 4: bounded deque instead of unbounded list
        self._history: deque[tuple[float, float]] = deque(maxlen=MAX_HISTORY)

        self.rounds  = 0
        self.samples = 0

        self._ssl_sock: ssl.SSLSocket | None = None
        self._ssl_lock = threading.Lock()

    def now(self) -> float:
        return time.time() + self.offset

    # ══════════════════════════════════════════════════════════════════════════
    # ❶  SSL CONTROL CHANNEL
    # ══════════════════════════════════════════════════════════════════════════

    def _build_ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if os.path.exists(CERT_FILE):
            ctx.load_verify_locations(CERT_FILE)
        else:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            self.log.warning("Cert not found locally — skipping verification (dev mode)")
        return ctx

    def _connect_ssl(self) -> bool:
        """
        FIX 1: connect with exponential backoff on failure.
        Retries up to SSL_MAX_RETRY times before giving up.
        """
        for attempt in range(1, SSL_MAX_RETRY + 1):
            try:
                ctx      = self._build_ssl_ctx()
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.settimeout(5.0)
                ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=self.server_host)
                ssl_sock.connect((self.server_host, SSL_PORT))

                cipher = ssl_sock.cipher()
                self.log.info(
                    f"SSL connected → {self.server_host}:{SSL_PORT} | "
                    f"cipher={cipher[0]}  protocol={cipher[1]}"
                )

                # AUTH
                ssl_sock.sendall(f"AUTH {self.token}".encode())
                resp = ssl_sock.recv(BUFFER_SIZE).decode().strip()
                if not resp.startswith("ACK:AUTHORIZED"):
                    self.log.error(f"Authentication failed: {resp}")
                    ssl_sock.close()
                    return False
                self.log.info(f"Authenticated ✓  ({resp})")

                # REGISTER
                ssl_sock.sendall(f"REGISTER {self.client_id}".encode())
                resp = ssl_sock.recv(BUFFER_SIZE).decode().strip()
                if resp not in ("ACK:REGISTERED",):
                    self.log.error(f"Registration failed: {resp}")
                    ssl_sock.close()
                    return False
                self.log.info("Registered with server ✓")

                ssl_sock.settimeout(10.0)
                with self._ssl_lock:
                    self._ssl_sock = ssl_sock
                return True

            except (ssl.SSLError, ConnectionRefusedError, socket.timeout, OSError) as e:
                self.log.warning(f"SSL connect attempt {attempt}/{SSL_MAX_RETRY} failed: {e}")
                if attempt < SSL_MAX_RETRY:
                    # FIX 1: exponential backoff
                    wait = SSL_RETRY_BASE * (2 ** (attempt - 1))
                    self.log.info(f"Retrying in {wait:.0f}s...")
                    time.sleep(wait)

        self.log.error("All SSL connection attempts failed.")
        return False

    def _ssl_is_alive(self) -> bool:
        """FIX 6: non-destructive check that the SSL socket is still usable."""
        with self._ssl_lock:
            if self._ssl_sock is None:
                return False
            try:
                # getpeername() raises OSError if socket is dead
                self._ssl_sock.getpeername()
                return True
            except OSError:
                self._ssl_sock = None
                return False

    def _send_report(self):
        """Push current offset and drift to server over SSL."""
        # FIX 6: check before attempting send
        if not self._ssl_is_alive():
            self.log.info("SSL socket dead — reconnecting before report...")
            if not self._connect_ssl():
                return

        payload = json.dumps({
            "offset_ms": round(self.offset * 1000, 4),
            "drift_ppm": round(self.drift, 2)
        })
        try:
            with self._ssl_lock:
                if self._ssl_sock is None:
                    return
                self._ssl_sock.sendall(f"REPORT {payload}".encode())
                resp = self._ssl_sock.recv(BUFFER_SIZE).decode().strip()

            if resp == "ACK:REPORT":
                self.log.info(
                    f"Report ✓  offset={self.offset*1000:+.3f}ms  "
                    f"drift={self.drift:+.2f}ppm"
                )
            else:
                self.log.warning(f"Unexpected report response: {resp}")

        except (ssl.SSLError, OSError, BrokenPipeError) as e:
            self.log.warning(f"SSL report failed: {e} — will reconnect next round")
            with self._ssl_lock:
                if self._ssl_sock:
                    try: self._ssl_sock.close()
                    except: pass
                self._ssl_sock = None

    def _close_ssl(self):
        with self._ssl_lock:
            if self._ssl_sock:
                try:
                    self._ssl_sock.sendall(b"BYE")
                    self._ssl_sock.recv(BUFFER_SIZE)
                    self._ssl_sock.close()
                    self.log.info("SSL connection closed gracefully.")
                except Exception:
                    pass
                self._ssl_sock = None

    # ══════════════════════════════════════════════════════════════════════════
    # ❷  UDP SYNC ENGINE
    # ══════════════════════════════════════════════════════════════════════════

    def _build_request(self, T1: float) -> bytes:
        cid_bytes = self.client_id.encode("ascii")[:16].ljust(16, b"\x00")
        return bytes([MSG_SYNC_REQUEST]) + struct.pack("!d", T1) + cid_bytes

    def _sync_once(self, sock: socket.socket):
        """
        Single NTP exchange.
        FIX 2: validates T4 > T1 and delay > 0 before accepting the sample.
        Returns (offset, delay, stratum) or None.
        """
        try:
            T1      = time.time()
            request = self._build_request(T1)
            sock.sendto(request, (self.server_host, UDP_PORT))

            data, _ = sock.recvfrom(BUFFER_SIZE)
            T4      = time.time()

            if len(data) < 24:
                self.log.warning(f"Short response {len(data)}B — dropped")
                return None

            T1e, T2, T3 = struct.unpack("!ddd", data[:24])
            stratum     = data[24] if len(data) >= 25 else 1

            # FIX 2: sanity checks
            if T4 < T1:
                self.log.warning("T4 < T1 — local clock jumped backward, discarding sample")
                return None

            delay = (T4 - T1e) - (T3 - T2)
            if delay < 0:
                self.log.warning(f"Negative delay {delay*1000:.3f}ms — discarding sample")
                return None

            offset = ((T2 - T1e) + (T3 - T4)) / 2.0
            self.samples += 1
            return offset, delay, stratum

        except socket.timeout:
            self.log.warning("UDP timeout — sample skipped")
            return None
        except struct.error as e:
            self.log.error(f"Unpack error: {e}")
            return None

    def _sync_round(self):
        """
        FIX 3: reuse socket across all samples in the round.
        FIX 4: bounded history.
        FIX 7: guard against zero elapsed time in drift calculation.
        """
        # FIX 3: one socket per round (not one per sample)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)
        results = []

        try:
            for i in range(NUM_SAMPLES):
                r = self._sync_once(sock)
                if r:
                    results.append(r)
                if i < NUM_SAMPLES - 1:
                    time.sleep(SAMPLE_GAP)
        finally:
            sock.close()   # FIX 3: always closed at end of round

        if not results:
            self.log.error("No valid samples this round — skipping update")
            return

        best_offset, best_delay, best_stratum = min(results, key=lambda r: r[1])
        self.stratum = best_stratum

        # FIX 7: safe drift calculation — guard zero elapsed
        now_ts = time.time()
        if self._history:
            prev_offset, prev_ts = self._history[-1]
            elapsed = now_ts - prev_ts
            if elapsed > 0:  # FIX 7: explicit guard
                self.drift = (best_offset - prev_offset) / elapsed * 1e6
        else:
            self.drift = 0.0

        self.offset = best_offset
        # FIX 4: deque with maxlen auto-discards oldest entry
        self._history.append((best_offset, now_ts))
        self.rounds += 1

        self.converged = abs(best_offset * 1000) < CONVERGE_THR

        delays_ms = [r[1] * 1000 for r in results]
        jitter_ms = statistics.stdev(delays_ms) if len(delays_ms) > 1 else 0.0
        status    = "CONVERGED ✓" if self.converged else "syncing..."

        self.log.info(
            f"Round {self.rounds:3d} | "
            f"offset={best_offset*1000:+7.3f}ms | "
            f"delay={best_delay*1000:6.3f}ms | "
            f"drift={self.drift:+6.2f}ppm | "
            f"jitter={jitter_ms:.3f}ms | "
            f"stratum={best_stratum} | "
            f"samples={len(results)}/{NUM_SAMPLES} | "
            f"{status}"
        )

        if self.rounds % REPORT_EVERY == 0:
            self._send_report()

    # ══════════════════════════════════════════════════════════════════════════
    # ❸  MAIN LOOP
    # ══════════════════════════════════════════════════════════════════════════

    def run(self):
        self.log.info(f"Starting  server={self.server_host}  id={self.client_id}")

        if not self._connect_ssl():
            self.log.error("Cannot authenticate — aborting")
            return

        self.log.info(
            f"Config: {NUM_SAMPLES} samples/round | "
            f"interval={SYNC_INTERVAL}s (fast={FAST_INTERVAL}s when drift>{DRIFT_FAST_THR}ppm)"
        )

        # FIX 5: use try/finally to guarantee BYE is always sent
        try:
            while True:
                self._sync_round()
                interval = FAST_INTERVAL if abs(self.drift) > DRIFT_FAST_THR \
                           else SYNC_INTERVAL
                time.sleep(interval)

        except KeyboardInterrupt:
            self.log.info(
                f"Stopped. rounds={self.rounds}  samples={self.samples}  "
                f"final_offset={self.offset*1000:+.3f}ms  "
                f"drift={self.drift:+.2f}ppm  "
                f"converged={self.converged}"
            )
        finally:
            # FIX 5: BYE always sent regardless of how loop exits
            self._close_ssl()


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    client_id   = sys.argv[1] if len(sys.argv) > 1 else "client-1"
    token       = sys.argv[2] if len(sys.argv) > 2 else "dev-token"
    server_host = sys.argv[3] if len(sys.argv) > 3 else SERVER_HOST
    TimeClient(client_id=client_id, token=token, server_host=server_host).run()
