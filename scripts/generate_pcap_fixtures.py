"""Generate reproducible, real TLS 1.3 PCAP fixtures with OpenSSL and tcpdump.

All traffic is confined to loopback and contains only a fixture HTTP request.
The exported key logs are test-only secrets that decrypt these fixture captures.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "pcap"
REQUEST = b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"


def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, check=False, timeout=30, **kwargs)


def require_tool(name: str) -> str:
    from shutil import which

    binary = which(name)
    if binary is None:
        raise RuntimeError(f"Required fixture tool not found: {name}")
    return binary


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def capture_connection(
    *,
    group: str,
    port: int,
    capture_path: Path,
    endpoint_log: Path,
    keylog_path: Path,
    session_out: Path | None = None,
    session_in: Path | None = None,
) -> str:
    tcpdump_log = capture_path.with_suffix(".tcpdump.log")
    capture_command = [
        require_tool("tcpdump"),
        "-i",
        "any",
        "-nn",
        "-s",
        "0",
        "-U",
        "-w",
        str(capture_path),
        f"tcp port {port}",
    ]
    with tcpdump_log.open("wb") as log_handle:
        sniffer = subprocess.Popen(
            capture_command,
            stdout=subprocess.DEVNULL,
            stderr=log_handle,
        )
        ready_deadline = time.monotonic() + 10
        while time.monotonic() < ready_deadline:
            log_handle.flush()
            if "listening on" in tcpdump_log.read_text(encoding="utf-8", errors="replace"):
                break
            time.sleep(0.1)
        else:
            stop_process(sniffer)
            raise RuntimeError("tcpdump did not report a ready capture interface")
        client_command = [
            require_tool("openssl"),
            "s_client",
            "-connect",
            f"127.0.0.1:{port}",
            "-tls1_3",
            "-groups",
            group,
            "-keylogfile",
            str(keylog_path),
            "-brief",
            "-state",
            "-prexit",
            "-ign_eof",
        ]
        if session_out is not None:
            client_command.extend(["-sess_out", str(session_out)])
        if session_in is not None:
            client_command.extend(["-sess_in", str(session_in)])
        try:
            result = run(
                client_command,
                input=REQUEST,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        finally:
            time.sleep(1.0)
            stop_process(sniffer)
    output = result.stdout.decode("utf-8", errors="replace")
    endpoint_log.write_text(output, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"OpenSSL client failed for {group}: {output[-2000:]}")
    if not capture_path.is_file() or capture_path.stat().st_size <= 24:
        raise RuntimeError(f"tcpdump produced an empty capture: {capture_path}")
    return output


def merge_keylogs(paths: list[Path], destination: Path) -> None:
    lines: set[str] = set()
    for path in paths:
        if path.exists():
            lines.update(
                line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            )
    if not lines:
        raise RuntimeError("OpenSSL did not emit TLS key-log secrets")
    destination.write_text("\n".join(sorted(lines)) + "\n", encoding="ascii")
    os.chmod(destination, 0o600)


def start_server(
    group: str,
    port: int,
    certificate: Path,
    private_key: Path,
    server_keylog: Path,
    server_log: Path,
) -> subprocess.Popen[bytes]:
    handle = server_log.open("wb")
    command = [
        require_tool("openssl"),
        "s_server",
        "-accept",
        str(port),
        "-cert",
        str(certificate),
        "-key",
        str(private_key),
        "-tls1_3",
        "-groups",
        group,
        "-www",
        "-quiet",
        "-num_tickets",
        "2",
        "-keylogfile",
        str(server_keylog),
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=handle,
    )
    time.sleep(0.5)
    if process.poll() is not None:
        handle.close()
        raise RuntimeError(f"OpenSSL server exited early for group {group}")
    return process


def make_certificate(directory: Path) -> tuple[Path, Path]:
    certificate = directory / "fixture-cert.pem"
    private_key = directory / "fixture-key.pem"
    result = run(
        [
            require_tool("openssl"),
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-subj",
            "/CN=localhost",
            "-days",
            "1",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    os.chmod(private_key, 0o600)
    return certificate, private_key


def fixture_entry(
    *,
    name: str,
    group: str,
    expected_kind: str,
    endpoint_reused: bool,
    capture: Path,
    keylog: Path,
    endpoint_log: Path,
    openssl_version: str,
    tcpdump_version: str,
    tshark_version: str,
    port: int,
) -> dict[str, Any]:
    return {
        "name": name,
        "pcap_file": capture.name,
        "keylog_file": keylog.name,
        "endpoint_log_file": endpoint_log.name,
        "expected_group": group,
        "expected_session_kind": expected_kind,
        "endpoint_session_reused": endpoint_reused,
        "capture_sha256": sha256(capture),
        "keylog_sha256": sha256(keylog),
        "endpoint_log_sha256": sha256(endpoint_log),
        "openssl_version": openssl_version,
        "tcpdump_version": tcpdump_version,
        "tshark_version": tshark_version,
        "capture_interface": "any",
        "capture_filter": f"tcp port {port}",
        "capture_time_utc": datetime.now(UTC).isoformat(),
    }


def main() -> None:
    openssl = require_tool("openssl")
    tcpdump = require_tool("tcpdump")
    tshark = require_tool("tshark")
    group_result = run([openssl, "list", "-tls-groups"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    supported_groups = group_result.stdout.decode(errors="replace").casefold()
    for group in ("x25519mlkem768", "x25519"):
        if group not in supported_groups:
            raise RuntimeError(f"OpenSSL build does not support required group: {group}")

    FIXTURES.mkdir(parents=True, exist_ok=True)
    for existing in FIXTURES.iterdir():
        if existing.is_file():
            existing.unlink()

    openssl_version = run([openssl, "version"], stdout=subprocess.PIPE).stdout.decode().strip()
    tcpdump_version = run([tcpdump, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode().splitlines()[0]
    tshark_version = run([tshark, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode().splitlines()[0]
    entries: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="pqtls-capture-") as temporary:
        temp = Path(temporary)
        hybrid_cert, hybrid_key = make_certificate(temp)
        hybrid_server_keys = temp / "hybrid-server.keys"
        hybrid_server_log = temp / "hybrid-server.log"
        hybrid_session = temp / "hybrid-session.pem"
        hybrid_server = start_server(
            "X25519MLKEM768",
            18443,
            hybrid_cert,
            hybrid_key,
            hybrid_server_keys,
            hybrid_server_log,
        )
        try:
            hybrid_full_client_keys = temp / "hybrid-full-client.keys"
            hybrid_full_pcap = FIXTURES / "tls13-x25519mlkem768-full.pcap"
            hybrid_full_log = FIXTURES / "tls13-x25519mlkem768-full.endpoint.txt"
            hybrid_full_output = capture_connection(
                group="X25519MLKEM768",
                port=18443,
                capture_path=hybrid_full_pcap,
                endpoint_log=hybrid_full_log,
                keylog_path=hybrid_full_client_keys,
                session_out=hybrid_session,
            )
            if "Negotiated TLS1.3 group: X25519MLKEM768" not in hybrid_full_output:
                raise RuntimeError("OpenSSL did not confirm the hybrid group in full handshake")
            if not hybrid_session.is_file():
                raise RuntimeError("OpenSSL did not export a TLS 1.3 session ticket")
            hybrid_full_keylog = FIXTURES / "tls13-x25519mlkem768-full.keys"
            merge_keylogs([hybrid_server_keys, hybrid_full_client_keys], hybrid_full_keylog)
            entries.append(
                fixture_entry(
                    name="hybrid-full",
                    group="X25519MLKEM768",
                    expected_kind="full",
                    endpoint_reused=False,
                    capture=hybrid_full_pcap,
                    keylog=hybrid_full_keylog,
                    endpoint_log=hybrid_full_log,
                    openssl_version=openssl_version,
                    tcpdump_version=tcpdump_version,
                    tshark_version=tshark_version,
                    port=18443,
                )
            )

            hybrid_resumed_client_keys = temp / "hybrid-resumed-client.keys"
            hybrid_resumed_pcap = FIXTURES / "tls13-x25519mlkem768-resumed.pcap"
            hybrid_resumed_log = FIXTURES / "tls13-x25519mlkem768-resumed.endpoint.txt"
            hybrid_resumed_output = capture_connection(
                group="X25519MLKEM768",
                port=18443,
                capture_path=hybrid_resumed_pcap,
                endpoint_log=hybrid_resumed_log,
                keylog_path=hybrid_resumed_client_keys,
                session_in=hybrid_session,
            )
            if not re.search(r"Reused, TLSv1\.3", hybrid_resumed_output):
                raise RuntimeError("OpenSSL endpoint did not confirm TLS 1.3 session reuse")
            hybrid_resumed_keylog = FIXTURES / "tls13-x25519mlkem768-resumed.keys"
            merge_keylogs([hybrid_server_keys, hybrid_resumed_client_keys], hybrid_resumed_keylog)
            entries.append(
                fixture_entry(
                    name="hybrid-resumed",
                    group="X25519MLKEM768",
                    expected_kind="resumed",
                    endpoint_reused=True,
                    capture=hybrid_resumed_pcap,
                    keylog=hybrid_resumed_keylog,
                    endpoint_log=hybrid_resumed_log,
                    openssl_version=openssl_version,
                    tcpdump_version=tcpdump_version,
                    tshark_version=tshark_version,
                    port=18444,
                )
            )
        finally:
            stop_process(hybrid_server)

        classical_cert, classical_key = make_certificate(temp)
        classical_server_keys = temp / "classical-server.keys"
        classical_server = start_server(
            "X25519",
            18444,
            classical_cert,
            classical_key,
            classical_server_keys,
            temp / "classical-server.log",
        )
        try:
            classical_client_keys = temp / "classical-client.keys"
            classical_pcap = FIXTURES / "tls13-x25519-full.pcap"
            classical_log = FIXTURES / "tls13-x25519-full.endpoint.txt"
            classical_output = capture_connection(
                group="X25519",
                port=18444,
                capture_path=classical_pcap,
                endpoint_log=classical_log,
                keylog_path=classical_client_keys,
            )
            if not re.search(r"Negotiated TLS1\.3 group: X25519(?:\s|$)", classical_output):
                raise RuntimeError("OpenSSL did not confirm the classical X25519 group")
            classical_keylog = FIXTURES / "tls13-x25519-full.keys"
            merge_keylogs([classical_server_keys, classical_client_keys], classical_keylog)
            entries.append(
                fixture_entry(
                    name="classical-full",
                    group="X25519",
                    expected_kind="full",
                    endpoint_reused=False,
                    capture=classical_pcap,
                    keylog=classical_keylog,
                    endpoint_log=classical_log,
                    openssl_version=openssl_version,
                    tcpdump_version=tcpdump_version,
                    tshark_version=tshark_version,
                )
            )
        finally:
            stop_process(classical_server)

    manifest = {
        "schema_version": 1,
        "provenance": {
            "generator": "scripts/generate_pcap_fixtures.py",
            "endpoint": "OpenSSL s_server and s_client on loopback",
            "capture_tool": "tcpdump",
            "dissector": tshark_version,
            "traffic": "TLS 1.3 over 127.0.0.1; fixture-only HTTP GET; ephemeral self-signed RSA certificate",
            "secrets": "The included .keys files are intentionally public test-only TLS secrets for these captures; never reuse for real traffic.",
            "private_key": "The ephemeral server private key is not included.",
        },
        "fixtures": entries,
    }
    manifest_path = FIXTURES / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {len(entries)} TLS 1.3 packet captures in {FIXTURES}")
    for entry in entries:
        print(f"{entry['name']}: {entry['capture_sha256']} ({entry['expected_group']}, {entry['expected_session_kind']})")


if __name__ == "__main__":
    main()
