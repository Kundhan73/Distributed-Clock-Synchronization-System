"""
Distributed Clock Synchronization System — Time Server
Phase 5: Optimization & Fixes

Fixes and improvements over Phase 3:

  FIX 1  — Thread pool replaces thread-per-packet
             ThreadPoolExecutor caps UDP handler concurrency at 32 workers.
             Phase 3 spawned one new thread per UDP packet — unbounded.

  FIX 2  — T1 timestamp sanity validation
             Rejects packets where T1 is more than 1s in the future
             or more than 60s in the past (prevents replayed/corrupt packets).

  FIX 3  — client_id input sanitisation
             Non-ASCII or non-printable bytes no longer crash the server.
             Invalid client_ids are silently replaced with 'unknown'.

  FIX 4  — Address-already-in-use gives a clear, actionable error
             OSError errno 98/48 (EADDRINUSE) is caught at bind() and prints
             a human-readable message with the kill command to use.

  FIX 5  — SSL accept loop no longer references addr before assignment
             Phase 3 logged addr inside the ssl.SSLError handler but addr
             was not yet bound if the error occurred before accept() returned.

  FIX 6  — BrokenPipeError handled in SSL client handler
             Phase 3 only caught ConnectionResetError. A client crash can
             also raise BrokenPipeError on the server side — now handled.

  FIX 7  — Registry cap prevents memory exhaustion
             Registry is capped at MAX_REGISTRY_SIZE entries. A flood of
             REGISTER commands can no longer exhaust server memory.

  FIX 8  — AUTH brute-force rate limiting
             Tracks failed auth attempts per IP. After 5 failures the IP
             is blocked for 60 seconds; successful auth clears the counter.

  FIX 9  — Graceful stop explicitly closes both sockets
             Phase 3 only set self.running=False and slept 1.5s.
             Phase 5 closes UDP and SSL sockets and shuts down the thread pool.

  FIX 10 — Implausible REPORT values rejected
             offset_ms > 1000ms or non-numeric values in REPORT payload
             now return ERR:INVALID_REPORT instead of silently storing garbage.
"""

import socket
import ssl
import threading
import struct
import time
import logging
import os
import json
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(levelname)s  %(message)s"
)
log = logging.getLogger("server")

# ── Configuration ─────────────────────────────────────────────────────────────
HOST              = "0.0.0.0"
UDP_PORT          = 5005
SSL_PORT          = 5006
BUFFER_SIZE       = 1024
MAX_CLIENTS       = 100
DRIFT_ALERT       = 50.0
MAX_REGISTRY_SIZE = 500           # FIX 7
AUTH_MAX_FAILS    = 5             # FIX 8
AUTH_BLOCK_SECS   = 60            # FIX 8
UDP_POOL_WORKERS  = 32            # FIX 1
T1_MAX_FUTURE_S   = 1.0           # FIX 2
T1_MAX_PAST_S     = 60.0          # FIX 2

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE_DIR, "ssl", "server.crt")
KEY_FILE  = os.path.join(BASE_DIR, "ssl", "server.key")

MSG_SYNC_REQUEST = 0x01
STRATUM_SERVER   = 1
REQUEST_SIZE     = 25

VALID_TOKENS = {"token-client-1", "token-client-2", "token-client-3",
                "token-client-4", "token-client-5", "dev-token"}


# ── Client Registry Entry ─────────────────────────────────────────────────────
class ClientRecord:
    def __init__(self, client_id: str, addr: tuple):
        self.client_id     = client_id
        self.ip            = addr[0]
        self.port          = addr[1]
        self.first_seen    = datetime.now().isoformat()
        self.last_sync     = None
        self.sync_count    = 0
        self.last_offset   = None
        self.last_drift    = None
        self.authenticated = False

    def to_dict(self) -> dict:
        return {
            "client_id":      self.client_id,
            "ip":             self.ip,
            "first_seen":     self.first_seen,
            "last_sync":      self.last_sync,
            "sync_count":     self.sync_count,
            "last_offset_ms": round(self.last_offset, 4) if self.last_offset is not None else None,
            "last_drift_ppm": round(self.last_drift,  2) if self.last_drift  is not None else None,
        }


# ══════════════════════════════════════════════════════════════════════════════
class TimeServer:

    def __init__(self, host: str = HOST):
        self.host       = host
        self.running    = False
        self.lock       = threading.Lock()
        self.registry: dict[str, ClientRecord] = {}
        self.start_time = None

        # FIX 1: bounded thread pool for UDP handlers
        self._udp_pool = ThreadPoolExecutor(
            max_workers=UDP_POOL_WORKERS,
            thread_name_prefix="udp-worker"
        )

        # FIX 8: {ip: (fail_count, block_until_timestamp)}
        self._auth_fails: dict[str, tuple[int, float]] = {}

        # FIX 9: socket handles for clean shutdown
        self._udp_sock = None
        self._ssl_sock = None

        self.total_requests   = 0
        self.rejected_packets = 0

    # ══════════════════════════════════════════════════════════════════════════
    # ❶  UDP SYNC CHANNEL
    # ══════════════════════════════════════════════════════════════════════════

    def start_udp(self):
        # FIX 4: EADDRINUSE gives actionable message
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, UDP_PORT))
        except OSError as e:
            if e.errno in (98, 48):
                log.error(
                    f"UDP port {UDP_PORT} already in use. "
                    f"Run:  lsof -i :{UDP_PORT}  then  kill <PID>"
                )
            else:
                log.error(f"UDP bind failed: {e}")
            return

        sock.settimeout(1.0)
        self._udp_sock = sock
        log.info(f"UDP sync server listening on {self.host}:{UDP_PORT}")

        while self.running:
            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)
                T2 = time.time()
                # FIX 1: pool.submit instead of Thread().start()
                self._udp_pool.submit(self._handle_udp, sock, data, addr, T2)
            except socket.timeout:
                continue
            except OSError as e:
                if self.running:
                    log.error(f"UDP recv error: {e}")

        sock.close()
        log.info("UDP socket closed.")

    def _validate_T1(self, T1: float) -> bool:
        """FIX 2: reject timestamps outside the plausible window."""
        now = time.time()
        if T1 > now + T1_MAX_FUTURE_S:
            log.warning(f"T1 rejected — too far in future ({T1 - now:.2f}s ahead)")
            return False
        if T1 < now - T1_MAX_PAST_S:
            log.warning(f"T1 rejected — too old ({now - T1:.2f}s ago)")
            return False
        return True

    def _parse_client_id(self, data: bytes) -> str:
        """FIX 3: safe client_id decode — non-ASCII returns 'unknown'."""
        try:
            raw = data[9:25].decode("ascii").rstrip("\x00").strip()
            return raw if (raw and raw.isprintable()) else "unknown"
        except (UnicodeDecodeError, ValueError):
            return "unknown"

    def _handle_udp(self, sock, data: bytes, addr: tuple, T2: float):
        try:
            if len(data) < 9 or data[0] != MSG_SYNC_REQUEST:
                with self.lock:
                    self.rejected_packets += 1
                log.warning(f"Malformed UDP packet ({len(data)}B) from {addr}")
                return

            T1 = struct.unpack("!d", data[1:9])[0]

            # FIX 2: validate timestamp
            if not self._validate_T1(T1):
                with self.lock:
                    self.rejected_packets += 1
                return

            # FIX 3: safe client_id
            client_id = self._parse_client_id(data) if len(data) >= REQUEST_SIZE else "unknown"

            T3 = time.time()
            response = struct.pack("!dddB", T1, T2, T3, STRATUM_SERVER)
            sock.sendto(response, addr)

            with self.lock:
                self.total_requests += 1
                if client_id in self.registry:
                    rec = self.registry[client_id]
                    rec.last_sync   = datetime.now().isoformat()
                    rec.sync_count += 1

            log.info(
                f"Sync → {addr[0]}  client='{client_id}'  "
                f"proc={(T3-T2)*1000:.3f}ms  total={self.total_requests}"
            )

        except struct.error as e:
            log.error(f"Unpack error from {addr}: {e}")
        except OSError as e:
            log.error(f"Send error to {addr}: {e}")

    # ══════════════════════════════════════════════════════════════════════════
    # ❷  SSL CONTROL CHANNEL
    # ══════════════════════════════════════════════════════════════════════════

    def _build_ssl_context(self) -> ssl.SSLContext:
        for path, label in [(CERT_FILE, "Certificate"), (KEY_FILE, "Key")]:
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"{label} not found: {path}\n"
                    "Run:  bash ssl/generate_certs.sh"
                )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        log.info("SSL context ready (TLS 1.2+)")
        return ctx

    def start_ssl(self):
        try:
            ctx = self._build_ssl_context()
        except FileNotFoundError as e:
            log.error(str(e))
            return

        # FIX 4: EADDRINUSE on SSL port
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw.bind((self.host, SSL_PORT))
            raw.listen(MAX_CLIENTS)
            raw.settimeout(1.0)
        except OSError as e:
            if e.errno in (98, 48):
                log.error(
                    f"SSL port {SSL_PORT} already in use. "
                    f"Run:  lsof -i :{SSL_PORT}  then  kill <PID>"
                )
            else:
                log.error(f"SSL bind failed: {e}")
            return

        with ctx.wrap_socket(raw, server_side=True) as srv:
            self._ssl_sock = srv
            log.info(f"SSL control server listening on {self.host}:{SSL_PORT}")

            while self.running:
                # FIX 5: addr is only used AFTER accept() returns successfully
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except ssl.SSLError as e:
                    # FIX 5: do NOT reference addr here — it may not be assigned
                    if self.running:
                        log.warning(f"SSL handshake failed (client addr unknown): {e}")
                    continue
                except OSError as e:
                    if self.running:
                        log.error(f"SSL accept error: {e}")
                    continue

                threading.Thread(
                    target=self._handle_ssl_client,
                    args=(conn, addr),
                    daemon=True
                ).start()

        log.info("SSL socket closed.")

    def _is_blocked(self, ip: str) -> bool:
        """FIX 8: check if this IP is rate-limited."""
        with self.lock:
            if ip not in self._auth_fails:
                return False
            fails, block_until = self._auth_fails[ip]
            if fails >= AUTH_MAX_FAILS and time.time() < block_until:
                return True
            if time.time() >= block_until:
                del self._auth_fails[ip]
            return False

    def _record_auth_fail(self, ip: str):
        """FIX 8: increment fail counter; block IP if threshold reached."""
        with self.lock:
            fails, _ = self._auth_fails.get(ip, (0, 0))
            fails += 1
            block_until = time.time() + AUTH_BLOCK_SECS if fails >= AUTH_MAX_FAILS else 0
            self._auth_fails[ip] = (fails, block_until)
            if fails >= AUTH_MAX_FAILS:
                log.warning(
                    f"Rate limiting {ip} for {AUTH_BLOCK_SECS}s "
                    f"after {fails} failed auth attempts"
                )

    def _handle_ssl_client(self, conn: ssl.SSLSocket, addr: tuple):
        client_id     = None
        authenticated = False
        ip            = addr[0]

        # FIX 8: reject blocked IPs immediately
        if self._is_blocked(ip):
            log.warning(f"Blocked IP {ip} attempted connection — rejected")
            try: conn.close()
            except: pass
            return

        try:
            conn.settimeout(30.0)
            log.info(f"SSL client connected: {ip}:{addr[1]}")

            while True:
                try:
                    raw_data = conn.recv(BUFFER_SIZE)
                except ssl.SSLError as e:
                    log.warning(f"SSL recv error from {ip}: {e}")
                    break

                if not raw_data:
                    break

                msg = raw_data.decode("utf-8").strip()

                # ── AUTH ─────────────────────────────────────────────────
                if msg.startswith("AUTH "):
                    token = msg[5:].strip()
                    if token in VALID_TOKENS:
                        authenticated = True
                        client_id = token.replace("token-", "")
                        conn.sendall(f"ACK:AUTHORIZED:{client_id}".encode())
                        log.info(f"Authenticated: '{client_id}' from {ip}")
                        with self.lock:
                            self._auth_fails.pop(ip, None)  # clear on success
                    else:
                        conn.sendall(b"ERR:AUTH_FAILED")
                        self._record_auth_fail(ip)           # FIX 8

                # ── REGISTER ─────────────────────────────────────────────
                elif msg.startswith("REGISTER "):
                    if not authenticated:
                        conn.sendall(b"ERR:NOT_AUTHENTICATED")
                        continue
                    reg_id = msg[9:].strip()
                    with self.lock:
                        # FIX 7: cap registry
                        if len(self.registry) >= MAX_REGISTRY_SIZE and reg_id not in self.registry:
                            conn.sendall(b"ERR:REGISTRY_FULL")
                            log.warning(f"Registry full — rejected '{reg_id}'")
                            continue
                        if reg_id not in self.registry:
                            self.registry[reg_id] = ClientRecord(reg_id, addr)
                            self.registry[reg_id].authenticated = True
                        client_id = reg_id
                    conn.sendall(b"ACK:REGISTERED")
                    log.info(f"Registered client: '{reg_id}'")

                # ── STATS ────────────────────────────────────────────────
                elif msg == "STATS":
                    if not authenticated:
                        conn.sendall(b"ERR:NOT_AUTHENTICATED")
                        continue
                    with self.lock:
                        uptime = time.time() - self.start_time if self.start_time else 0
                        stats = {
                            "uptime_s":           round(uptime, 1),
                            "total_requests":     self.total_requests,
                            "rejected_packets":   self.rejected_packets,
                            "clients_registered": len(self.registry),
                            "clients": [r.to_dict() for r in self.registry.values()]
                        }
                    conn.sendall(json.dumps(stats).encode())

                # ── REPORT ───────────────────────────────────────────────
                elif msg.startswith("REPORT "):
                    if not authenticated or not client_id:
                        conn.sendall(b"ERR:NOT_AUTHENTICATED")
                        continue
                    try:
                        payload   = json.loads(msg[7:])
                        offset_ms = float(payload.get("offset_ms", 0.0))
                        drift_ppm = float(payload.get("drift_ppm", 0.0))

                        # FIX 10: reject implausible offset values
                        if abs(offset_ms) > 1000:
                            conn.sendall(b"ERR:INVALID_REPORT")
                            log.warning(
                                f"Implausible offset {offset_ms:.1f}ms "
                                f"from '{client_id}' — rejected"
                            )
                            continue

                        with self.lock:
                            if client_id in self.registry:
                                self.registry[client_id].last_offset = offset_ms
                                self.registry[client_id].last_drift  = drift_ppm
                        conn.sendall(b"ACK:REPORT")

                        if abs(drift_ppm) > DRIFT_ALERT:
                            log.warning(
                                f"DRIFT ALERT: '{client_id}' drift={drift_ppm:+.1f}ppm"
                            )

                    except (json.JSONDecodeError, ValueError, TypeError):
                        conn.sendall(b"ERR:INVALID_REPORT")

                # ── BYE ──────────────────────────────────────────────────
                elif msg == "BYE":
                    conn.sendall(b"ACK:BYE")
                    break

                else:
                    conn.sendall(b"ERR:UNKNOWN_COMMAND")

        except socket.timeout:
            log.warning(f"SSL client {addr} timed out")
        except ssl.SSLError as e:
            log.warning(f"SSL error with {addr}: {e}")
        except ConnectionResetError:
            log.warning(f"SSL client {addr} disconnected abruptly")
        except BrokenPipeError:
            # FIX 6: client process crashed
            log.warning(f"SSL client {addr} pipe broken (client crashed)")
        except Exception as e:
            log.error(f"Unexpected error with {addr}: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass
            log.info(f"SSL client disconnected: {ip} (id='{client_id}')")

    # ══════════════════════════════════════════════════════════════════════════
    # ❸  LIFECYCLE
    # ══════════════════════════════════════════════════════════════════════════

    def start(self):
        self.running    = True
        self.start_time = time.time()

        threading.Thread(target=self.start_udp, daemon=True, name="UDP").start()
        threading.Thread(target=self.start_ssl, daemon=True, name="SSL").start()

        log.info("=" * 62)
        log.info("  Distributed Clock Sync Server — Phase 5 (Optimized)")
        log.info(f"  UDP  sync    → port {UDP_PORT}  (pool={UDP_POOL_WORKERS} workers)")
        log.info(f"  SSL  control → port {SSL_PORT}  (TLS 1.2+)")
        log.info(f"  Registry cap={MAX_REGISTRY_SIZE}  Auth block after {AUTH_MAX_FAILS} fails")
        log.info("  Press Ctrl+C to stop.")
        log.info("=" * 62)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """FIX 9: explicit resource cleanup on shutdown."""
        log.info("Shutting down...")
        self.running = False

        # Shutdown thread pool
        self._udp_pool.shutdown(wait=False)

        # FIX 9: explicitly close both sockets
        for sock_ref, name in [(self._udp_sock, "UDP"), (self._ssl_sock, "SSL")]:
            if sock_ref:
                try:
                    sock_ref.close()
                    log.info(f"{name} socket closed.")
                except Exception as e:
                    log.warning(f"Error closing {name} socket: {e}")

        time.sleep(0.3)
        with self.lock:
            log.info(
                f"Final stats: requests={self.total_requests}  "
                f"rejected={self.rejected_packets}  "
                f"clients={len(self.registry)}"
            )
        log.info("Server stopped.")


if __name__ == "__main__":
    TimeServer().start()
