#!/usr/bin/env python3
"""SEER Linux client enrollment, connection, and device-presence service."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen
import uuid


VERSION = "1.0.0"
INTERFACE = "seer0"
SERVICE = "seer-client.service"
RELEASE_CONFIG = Path("/etc/seer-client/release.conf")
STATE_DIRECTORY = Path("/var/lib/seer-client")
INSTALLATION_ID_FILE = STATE_DIRECTORY / "installation-id"
NETWORK_CONFIG = Path(f"/etc/wireguard/{INTERFACE}.conf")
MAX_RESPONSE_BYTES = 256 * 1024
INVITATION_PATTERN = re.compile(
    r"^(?:[A-Za-z0-9]{15}|[A-Za-z0-9._:-]{32,200})$"
)
FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PRESENCE_MARKER = "# SEER-PRESENCE-URL:"
stop_requested = False


class SeerClientError(RuntimeError):
    pass


def clean_text(value: str, limit: int) -> str:
    return " ".join((value or "").strip().split())[:limit]


def read_release_config(path: Path = RELEASE_CONFIG) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SeerClientError(f"Could not read {path}. Re-run the installer.") from exc
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()

    endpoint = values.get("SEER_ENROLLMENT_URL", "")
    fingerprint = values.get("SEER_CERTIFICATE_SHA256", "").lower()
    parsed = urlsplit(endpoint)
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise SeerClientError("The trusted SEER gateway configuration is invalid.") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/api/vpn/enroll"
        or parsed_port is not None and not 1 <= parsed_port <= 65535
    ):
        raise SeerClientError("The trusted SEER gateway configuration is invalid.")
    if not FINGERPRINT_PATTERN.fullmatch(fingerprint):
        raise SeerClientError("The trusted SEER certificate identity is invalid.")
    return {"endpoint": endpoint, "fingerprint": fingerprint}


def atomic_private_write(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def installation_id(path: Path = INSTALLATION_ID_FILE) -> str:
    try:
        current = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        current = ""
    except OSError as exc:
        raise SeerClientError("Could not read the SEER device identity.") from exc
    if re.fullmatch(r"[A-Za-z0-9._:-]{16,128}", current):
        return current
    generated = str(uuid.uuid4())
    atomic_private_write(path, f"{generated}\n")
    return generated


def read_machine_value(path: str) -> str:
    try:
        return clean_text(Path(path).read_text(encoding="utf-8"), 120)
    except OSError:
        return ""


def device_details() -> dict[str, str]:
    manufacturer = read_machine_value("/sys/class/dmi/id/sys_vendor")
    model = read_machine_value("/sys/class/dmi/id/product_name") or clean_text(
        socket.gethostname(), 120
    )
    return {
        "manufacturer": manufacturer,
        "model": model,
        "os": "Linux",
        "appVersion": VERSION,
    }


def enrollment_payload(invitation: str) -> bytes:
    invitation = invitation.strip()
    if not INVITATION_PATTERN.fullmatch(invitation):
        raise SeerClientError("The invitation is not valid.")
    body = {
        "token": invitation,
        "installationId": installation_id(),
        "device": device_details(),
    }
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def pinned_enrollment_request(
    endpoint: str,
    fingerprint: str,
    payload: bytes,
) -> bytes:
    parsed = urlsplit(endpoint)
    port = parsed.port or 443
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        port,
        timeout=20,
        context=context,
    )
    try:
        connection.connect()
        certificate = connection.sock.getpeercert(binary_form=True) if connection.sock else b""
        actual = hashlib.sha256(certificate).hexdigest()
        if not hmac.compare_digest(actual, fingerprint):
            raise SeerClientError(
                "The SEER gateway identity did not match. Enrollment was stopped."
            )
        connection.request(
            "POST",
            parsed.path,
            body=payload,
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Content-Type": "application/json; charset=utf-8",
                "Content-Length": str(len(payload)),
            },
        )
        response = connection.getresponse()
        content = response.read(MAX_RESPONSE_BYTES + 1)
        if len(content) > MAX_RESPONSE_BYTES:
            raise SeerClientError("The SEER gateway returned too much data.")
        if response.status == 403:
            raise SeerClientError("This invitation or device is not approved.")
        if response.status == 429:
            raise SeerClientError("Too many attempts. Wait a moment and try again.")
        if response.status < 200 or response.status >= 300:
            raise SeerClientError(
                f"The SEER gateway could not enroll this device (status {response.status})."
            )
        return content
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise SeerClientError("The SEER gateway could not be reached.") from exc
    finally:
        connection.close()


def validate_network_config(configuration: str) -> str:
    normalized = configuration.replace("\ufeff", "").strip() + "\n"
    required = (
        "[Interface]",
        "PrivateKey",
        "Address",
        "[Peer]",
        "PublicKey",
        "AllowedIPs",
        "Endpoint",
    )
    if len(normalized.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise SeerClientError("The received network configuration is too large.")
    if any(item not in normalized for item in required):
        raise SeerClientError("The SEER gateway returned an invalid network configuration.")
    return normalized


def enroll(invitation: str) -> None:
    release = read_release_config()
    response = pinned_enrollment_request(
        release["endpoint"],
        release["fingerprint"],
        enrollment_payload(invitation),
    )
    try:
        data: Any = json.loads(response.decode("utf-8"))
        configuration = data["config"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise SeerClientError("The SEER gateway returned an invalid response.") from exc
    if not isinstance(configuration, str):
        raise SeerClientError("The SEER gateway returned an invalid response.")
    atomic_private_write(NETWORK_CONFIG, validate_network_config(configuration))


def run_command(arguments: list[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def interface_is_up() -> bool:
    return run_command(["wg", "show", INTERFACE]).returncode == 0


def bring_up() -> None:
    if not NETWORK_CONFIG.is_file():
        raise SeerClientError("This server has not been enrolled. Re-run the installer.")
    if interface_is_up():
        return
    result = run_command(["wg-quick", "up", INTERFACE])
    if result.returncode != 0:
        detail = clean_text(result.stderr or result.stdout, 240)
        raise SeerClientError(f"The secure connection could not start. {detail}".strip())


def bring_down() -> None:
    if not interface_is_up():
        return
    run_command(["wg-quick", "down", INTERFACE])


def read_network_config() -> str:
    try:
        return NETWORK_CONFIG.read_text(encoding="utf-8")
    except OSError:
        return ""


def presence_url(configuration: str) -> str:
    for line in configuration.splitlines():
        stripped = line.strip()
        if not stripped.startswith(PRESENCE_MARKER):
            continue
        decoded = unquote(stripped[len(PRESENCE_MARKER) :].strip())
        parsed = urlsplit(decoded)
        if (
            parsed.scheme == "http"
            and parsed.hostname == "10.8.0.1"
            and parsed.path == "/api/vpn/client-presence"
            and parsed.port in (3000, 3001)
        ):
            return decoded
        if (
            parsed.scheme == "https"
            and parsed.hostname
            and parsed.path == "/api/vpn/client-presence"
        ):
            return decoded
    return "http://10.8.0.1:3000/api/vpn/client-presence"


def report_presence(connected: bool) -> None:
    endpoint = presence_url(read_network_config())
    details = device_details()
    body = json.dumps(
        {
            "connected": connected,
            "manufacturer": details["manufacturer"],
            "model": details["model"],
            "device_os": details["os"],
            "app_version": details["appVersion"],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Cache-Control": "no-store",
            "Content-Type": "application/json; charset=utf-8",
        },
    )
    try:
        with urlopen(request, timeout=3) as response:
            response.read(1024)
    except OSError:
        pass


def request_stop(_signum: int, _frame: object) -> None:
    global stop_requested
    stop_requested = True


def run_service() -> None:
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    bring_up()
    try:
        while not stop_requested:
            report_presence(True)
            for _ in range(5):
                if stop_requested:
                    break
                time.sleep(1)
            if not interface_is_up() and not stop_requested:
                raise SeerClientError("The secure connection stopped unexpectedly.")
    finally:
        report_presence(False)
        bring_down()


def network_address() -> str:
    configuration = read_network_config()
    for line in configuration.splitlines():
        if line.strip().lower().startswith("address") and "=" in line:
            return line.split("=", 1)[1].strip().split("/", 1)[0]
    return ""


def service_action(action: str) -> None:
    arguments = ["systemctl"]
    if action == "connect":
        arguments += ["enable", "--now", SERVICE]
    elif action == "disconnect":
        arguments += ["disable", "--now", SERVICE]
    else:
        arguments += ["restart", SERVICE]
    result = run_command(arguments)
    if result.returncode != 0:
        raise SeerClientError(clean_text(result.stderr or result.stdout, 240))


def print_status() -> None:
    active = run_command(["systemctl", "is-active", "--quiet", SERVICE]).returncode == 0
    enabled = run_command(["systemctl", "is-enabled", "--quiet", SERVICE]).returncode == 0
    print(f"Connection: {'active' if active and interface_is_up() else 'inactive'}")
    print(f"Start after boot: {'on' if enabled else 'off'}")
    address = network_address()
    if address:
        print(f"Private address: {address}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage the SEER Linux connection.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    enroll_parser = subparsers.add_parser("enroll")
    enroll_parser.add_argument("--invitation-stdin", action="store_true", required=True)
    subparsers.add_parser("run")
    subparsers.add_parser("connect")
    subparsers.add_parser("disconnect")
    subparsers.add_parser("restart")
    subparsers.add_parser("status")
    subparsers.add_parser("address")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "enroll":
            invitation = sys.stdin.readline(4096).strip()
            enroll(invitation)
        elif args.command == "run":
            run_service()
        elif args.command in ("connect", "disconnect", "restart"):
            service_action(args.command)
        elif args.command == "status":
            print_status()
        elif args.command == "address":
            address = network_address()
            if not address:
                raise SeerClientError("No private address is available.")
            print(address)
        return 0
    except SeerClientError as exc:
        print(f"SEER: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
