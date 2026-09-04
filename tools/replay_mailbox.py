#!/usr/bin/env python3
"""Replay every .eml file in a directory through a test Milter connection."""

import argparse
import email.parser
import email.policy
import json
import re
import socket
import struct
import sys
import time
from pathlib import Path


def send_frame(sock, payload):
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def receive_exact(sock, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("milter closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_frame(sock):
    header = receive_exact(sock, 4)
    length = struct.unpack("!I", header)[0]
    if length < 1 or length > 16 * 1024 * 1024:
        raise RuntimeError(f"invalid milter frame length: {length}")
    return receive_exact(sock, length)


def command(sock, code, payload=b""):
    send_frame(sock, code + payload)
    return receive_frame(sock)


def continue_command(sock, code, payload=b""):
    response = command(sock, code, payload)
    if response != b"c":
        raise RuntimeError(f"unexpected response to {code!r}: {response!r}")


def no_response_command(sock, code, payload=b""):
    send_frame(sock, code + payload)
    previous_timeout = sock.gettimeout()
    try:
        sock.settimeout(0.1)
        unexpected = sock.recv(1)
        if unexpected:
            raise RuntimeError(f"unexpected response to {code!r}: {unexpected!r}")
        raise ConnectionError("milter closed the connection")
    except socket.timeout:
        pass
    finally:
        sock.settimeout(previous_timeout)


def negotiate(sock):
    response = command(sock, b"O", struct.pack("!III", 6, 0, 0))
    if not response.startswith(b"O"):
        raise RuntimeError(f"unexpected negotiation response: {response!r}")


def begin_smtp_session(sock, remote_ip):
    connect_payload = (
        b"replay.local\x00"
        + b"4"
        + struct.pack("!H", 2525)
        + remote_ip.encode("ascii")
        + b"\x00"
    )
    continue_command(sock, b"C", connect_payload)
    continue_command(sock, b"H", b"replay.local\x00")

    # Exercise the transaction reset used when an SMTP session starts again
    # after STARTTLS. SMFIC_ABORT has no response.
    no_response_command(sock, b"A")
    continue_command(sock, b"H", b"replay.local\x00")


def split_message(raw):
    marker = b"\r\n\r\n"
    position = raw.find(marker)
    if position < 0:
        marker = b"\n\n"
        position = raw.find(marker)
    if position < 0:
        return raw, b""
    return raw[:position], raw[position + len(marker) :]


def replay(sock, path, mail_from, rcpt_to):
    raw = path.read_bytes()
    header_bytes, body = split_message(raw)
    parsed = email.parser.BytesHeaderParser(policy=email.policy.compat32).parsebytes(
        header_bytes + b"\n\n"
    )

    started = time.monotonic()
    response = command(sock, b"M", f"<{mail_from}>\x00".encode("ascii"))
    if response != b"c":
        elapsed_ms = round((time.monotonic() - started) * 1000)
        return interpret(response), elapsed_ms
    continue_command(sock, b"R", f"<{rcpt_to}>\x00".encode("ascii"))

    for name, value in parsed.raw_items():
        clean_name = name.replace("\x00", "").encode("utf-8", "replace")
        clean_value = value.replace("\x00", "").encode("utf-8", "replace")
        response = command(sock, b"L", clean_name + b"\x00" + clean_value + b"\x00")
        if response != b"c":
            raise RuntimeError(f"header rejected unexpectedly: {response!r}")

    continue_command(sock, b"N")

    for offset in range(0, len(body), 64 * 1024):
        response = command(sock, b"B", body[offset : offset + 64 * 1024])
        if response != b"c":
            raise RuntimeError(f"body rejected unexpectedly: {response!r}")

    started = time.monotonic()
    response = command(sock, b"E")
    elapsed_ms = round((time.monotonic() - started) * 1000)
    return interpret(response), elapsed_ms


def interpret(response):
    if response == b"a":
        return "accept", ""
    if response == b"r":
        return "reject", ""
    if response == b"t":
        return "tempfail", ""
    if response.startswith(b"y"):
        payload = response[1:]
        if not payload.endswith(b"\x00") or b"\x00" in payload[:-1]:
            return "unknown", f"malformed SMFIR_REPLYCODE: {response!r}"
        detail = payload[:-1].decode("utf-8", "replace")
        if not re.fullmatch(
            r"[45][0-9]{2} (?:[245]\.[0-9]{1,3}\.[0-9]{1,3} )?[^\r\n]+", detail
        ):
            return "unknown", f"malformed SMFIR_REPLYCODE: {response!r}"
        return ("reject" if detail.startswith("5") else "tempfail"), detail
    return "unknown", repr(response)


def message_files(directory):
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix.lower() == ".eml":
            yield path


def main():
    parser = argparse.ArgumentParser(
        description="Replay a directory of .eml files through a test MilterGuard instance."
    )
    parser.add_argument("directory", type=Path, help="directory containing .eml files")
    parser.add_argument("--host", default="127.0.0.1", help="Milter host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8894, help="Milter port (default: 8894)")
    parser.add_argument("--remote-ip", default="127.0.0.1", help="simulated SMTP peer IP")
    parser.add_argument("--mail-from", default="replay-sender@example.invalid")
    parser.add_argument("--rcpt-to", default="replay-recipient@example.invalid")
    parser.add_argument("--expected", choices=("accept", "reject"))
    parser.add_argument("--timeout", type=float, default=90, help="socket timeout in seconds")
    args = parser.parse_args()

    if not args.directory.is_dir():
        parser.error(f"not a directory: {args.directory}")

    totals = {"accept": 0, "reject": 0, "tempfail": 0, "unknown": 0, "error": 0}
    mismatches = 0
    files = list(message_files(args.directory))
    if not files:
        parser.error("no .eml files found")

    with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
        sock.settimeout(args.timeout)
        negotiate(sock)
        begin_smtp_session(sock, args.remote_ip)
        for path in files:
            try:
                (result, detail), latency = replay(
                    sock, path, args.mail_from, args.rcpt_to
                )
                totals[result] += 1
                matched = args.expected is None or result == args.expected
                mismatches += int(not matched)
                print(
                    json.dumps(
                        {
                            "file": str(path),
                            "result": result,
                            "expected": args.expected,
                            "matched": matched,
                            "latency_ms": latency,
                            "detail": detail,
                        }
                    ),
                    flush=True,
                )
            except Exception as exc:
                totals["error"] += 1
                mismatches += int(args.expected is not None)
                print(
                    json.dumps({"file": str(path), "result": "error", "error": str(exc)}),
                    flush=True,
                )
                break
        send_frame(sock, b"Q")

    print(
        json.dumps(
            {"summary": totals, "expected": args.expected, "mismatches": mismatches}
        ),
        flush=True,
    )
    return 1 if mismatches or totals["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
