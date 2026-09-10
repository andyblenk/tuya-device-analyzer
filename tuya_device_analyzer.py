#!/usr/bin/env python3
"""Read-only protocol and DPS analyzer for Tuya LAN devices."""

from __future__ import annotations

import argparse
import getpass
import importlib.metadata
import json
import logging
import os
import re
import socket
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import tinytuya


TUYA_PORTS = (6668, 6669, 8681)
CORE_DPS = (1, 2, 3, 4, 5, 6, 21, 23)
EXTENDED_DPS = (1, 101, 102, 103, 104, 105, 106, 107, 108, 109)
DEFAULT_QUERY_DPS = tuple(
    sorted(set(CORE_DPS + EXTENDED_DPS + tuple(range(7, 15))))
)


@dataclass(frozen=True)
class ProtocolVariant:
    """One wire-protocol and query-mode combination."""

    selector: str
    wire_version: float
    dev_type: str
    query_mode: str = "standard"


PROTOCOL_VARIANTS = (
    ProtocolVariant("3.1", 3.1, "default"),
    ProtocolVariant("3.2", 3.2, "device22"),
    ProtocolVariant("3.3", 3.3, "default"),
    ProtocolVariant("3.22", 3.3, "device22"),
    ProtocolVariant("3.4", 3.4, "default"),
    ProtocolVariant("3.42", 3.4, "device22"),
    ProtocolVariant("3.5", 3.5, "default"),
    ProtocolVariant("3.5-data-dps", 3.5, "default", "data_dps"),
    ProtocolVariant("3.5-explicit-dps", 3.5, "default", "explicit_dps"),
    ProtocolVariant("3.5-explicit-chunks", 3.5, "default", "explicit_chunks"),
    ProtocolVariant("3.5-protocol-dps", 3.5, "default", "protocol_dps"),
    ProtocolVariant("3.5-dpid-list", 3.5, "default", "dpid_list"),
    ProtocolVariant("3.5-updatedps", 3.5, "default", "updatedps"),
    ProtocolVariant("3.5-updatedps-chunks", 3.5, "default", "updatedps_chunks"),
    ProtocolVariant("3.5-passive", 3.5, "default", "passive"),
    ProtocolVariant("3.52", 3.5, "device22"),
)


class Redactor:
    """Remove credentials and device identifiers from diagnostic output."""

    def __init__(self, local_key: str, device_id: str, ip: str) -> None:
        self.local_key = local_key
        self.device_id = device_id
        self.ip = ip

    def clean(self, value: Any) -> Any:
        if isinstance(value, str):
            value = value.replace(self.local_key, "<LOCAL_KEY_REDACTED>")
            value = value.replace(
                self.local_key.encode("utf-8").hex(), "<LOCAL_KEY_HEX_REDACTED>"
            )
            value = value.replace(self.device_id, "<DEVICE_ID_REDACTED>")
            value = value.replace(
                self.device_id.encode("utf-8").hex(), "<DEVICE_ID_HEX_REDACTED>"
            )
            value = value.replace(self.ip, "<DEVICE_IP_REDACTED>")
            value = re.sub(
                r"(?i)(session key[^:]*:\s*).*$",
                r"\1<SESSION_KEY_REDACTED>",
                value,
            )
            value = re.sub(
                r"(?i)(local[_ ]key\s*[=:]\s*).*$",
                r"\1<LOCAL_KEY_REDACTED>",
                value,
            )
            return value
        if isinstance(value, dict):
            cleaned = {}
            for key, item in value.items():
                key_text = str(key)
                if key_text.lower() in {
                    "key",
                    "local_key",
                    "secret",
                    "token",
                    "access_token",
                }:
                    cleaned[key_text] = "<REDACTED>"
                else:
                    cleaned[key_text] = self.clean(item)
            return cleaned
        if isinstance(value, (list, tuple)):
            return [self.clean(item) for item in value]
        return value


class Reporter:
    """Write progress to the terminal and to a text log."""

    def __init__(self, path: Path, redactor: Redactor) -> None:
        self.path = path
        self.redactor = redactor
        self.file = path.open("w", encoding="utf-8")

    def write(self, message: str, data: Any | None = None) -> None:
        stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        line = f"{stamp} | {message}"
        if data is not None:
            line += " | " + json.dumps(
                self.redactor.clean(data),
                ensure_ascii=False,
                sort_keys=True,
                default=repr,
            )
        print(line, flush=True)
        self.file.write(line + "\n")
        self.file.flush()

    def close(self) -> None:
        self.file.close()


class TinyTuyaLogHandler(logging.Handler):
    """Route verbose TinyTuya protocol logging through the redactor."""

    def __init__(self, reporter: Reporter) -> None:
        super().__init__(logging.DEBUG)
        self.reporter = reporter
        self.setFormatter(logging.Formatter("%(name)s | %(levelname)s | %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.reporter.write("TINYTUYA", self.format(record))
        except BaseException:
            self.handleError(record)


def enable_tinytuya_debug(reporter: Reporter) -> logging.Logger:
    """Enable protocol-level logging without TinyTuya's unsafe console handler."""
    logger = logging.getLogger("tinytuya")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addHandler(TinyTuyaLogHandler(reporter))
    return logger


def parse_dps(value: str) -> tuple[int, ...]:
    """Parse a comma-separated, ordered set of Tuya DP IDs."""
    try:
        dps = tuple(dict.fromkeys(int(item.strip()) for item in value.split(",")))
    except ValueError as exc:
        message = "DPs must be comma-separated integers"
        raise argparse.ArgumentTypeError(message) from exc
    if not dps or any(dp < 1 or dp > 255 for dp in dps):
        raise argparse.ArgumentTypeError("DP IDs must be between 1 and 255")
    return dps


def positive_float(value: str) -> float:
    """Parse a positive floating-point command-line value."""
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def positive_int(value: str) -> int:
    """Parse a positive integer command-line value."""
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only protocol and DPS analyzer for Tuya LAN devices."
    )
    parser.add_argument("--ip", required=True, help="IP address of the device")
    parser.add_argument("--device-id", required=True, help="Tuya device ID")
    parser.add_argument(
        "--local-key",
        help=(
            "Tuya LocalKey. If omitted, TUYA_LOCAL_KEY or a hidden prompt is used"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=7.0,
        help="Timeout per network operation in seconds (default: 7)",
    )
    parser.add_argument(
        "--pause",
        type=float,
        default=3.0,
        help="Pause between protocol variants in seconds (default: 3)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("logs"),
        help="Report directory (default: ./logs)",
    )
    parser.add_argument(
        "--dps",
        type=parse_dps,
        default=DEFAULT_QUERY_DPS,
        metavar="ID,ID,...",
        help="Comma-separated DP IDs for targeted probes",
    )
    parser.add_argument(
        "--dp-chunk-size",
        type=positive_int,
        default=5,
        help="Number of DPs per targeted chunk request (default: 5)",
    )
    parser.add_argument(
        "--listen-seconds",
        type=positive_float,
        default=30.0,
        help="Passive observation time for Tuya 3.5 reports (default: 30)",
    )
    return parser.parse_args()


def masked_device_id(device_id: str) -> str:
    if len(device_id) < 8:
        return "<DEVICE_ID>"
    return f"{device_id[:3]}...{device_id[-3:]}"


def exception_result(exc: BaseException, redactor: Redactor) -> dict[str, Any]:
    return {
        "ok": False,
        "exception_type": type(exc).__name__,
        "exception": redactor.clean(repr(exc)),
    }


def timed_call(
    label: str,
    call: Callable[[], Any],
    reporter: Reporter,
    redactor: Redactor,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        response = redactor.clean(call())
        result = {
            "ok": True,
            "duration_seconds": round(time.monotonic() - started, 3),
            "response": response,
        }
        reporter.write(f"{label}: response", result)
        return result
    except Exception as exc:  # Continue so every protocol variant is tested.
        result = exception_result(exc, redactor)
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        reporter.write(f"{label}: failed", result)
        return result


def tcp_probe(ip: str, port: int, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return {
                "reachable": True,
                "duration_seconds": round(time.monotonic() - started, 3),
            }
    except OSError as exc:
        return {
            "reachable": False,
            "duration_seconds": round(time.monotonic() - started, 3),
            "exception_type": type(exc).__name__,
            "exception": repr(exc),
        }


def response_dps(response: Any) -> dict[str, Any]:
    if not isinstance(response, dict):
        return {}
    dps = response.get("dps")
    if isinstance(dps, dict):
        return dps
    for key in ("data", "received", "response"):
        nested_dps = response_dps(response.get(key))
        if nested_dps:
            return nested_dps
    return {}


def create_device(
    device_id: str,
    ip: str,
    local_key: str,
    port: int,
    variant: ProtocolVariant,
    timeout: float,
) -> Any:
    device = tinytuya.Device(
        dev_id=device_id,
        address=ip,
        local_key=local_key,
        dev_type=variant.dev_type,
        connection_timeout=timeout,
        version=variant.wire_version,
        persist=True,
        connection_retry_limit=1,
        connection_retry_delay=0,
        port=port,
    )
    device.set_socketPersistent(True)
    device.set_socketTimeout(timeout)
    device.set_socketRetryLimit(1)
    device.set_socketRetryDelay(0)
    device.set_sendWait(0.1)
    return device


def status_with_query_mode(
    device: Any,
    variant: ProtocolVariant,
    dps: tuple[int, ...],
) -> Any:
    """Read device status using the query payload selected by the variant."""
    if variant.query_mode == "standard":
        return device.status()

    from tinytuya.core import command_types

    if variant.query_mode == "data_dps":
        query_command = {"data": {"dps": {}}}
    elif variant.query_mode in {"explicit_dps", "explicit_chunks"}:
        query_command = {
            "devId": "",
            "uid": "",
            "t": "",
            "dps": {str(dp): None for dp in dps},
        }
    elif variant.query_mode == "protocol_dps":
        query_command = {
            "protocol": 5,
            "t": "int",
            "data": {"dps": {str(dp): None for dp in dps}},
        }
    elif variant.query_mode == "dpid_list":
        query_command = {"dpId": list(dps)}
    else:
        raise ValueError(f"Unsupported query mode: {variant.query_mode}")

    # Adjust only this device instance's payload definition for the single,
    # read-only status call.
    device.generate_payload(command_types.DP_QUERY)
    query_config = device.payload_dict[command_types.DP_QUERY]
    original_command = query_config.get("command")
    query_config["command"] = query_command
    try:
        return device.status()
    finally:
        if original_command is None:
            query_config.pop("command", None)
        else:
            query_config["command"] = original_command


def request_updated_dps(
    device: Any,
    dps: tuple[int, ...],
    wait_seconds: float,
) -> dict[str, Any]:
    """Ask the device to report selected DPs and collect its next message."""
    original_timeout = device.connection_timeout
    device.set_socketTimeout(wait_seconds)
    try:
        send_result = device.updatedps(index=list(dps), nowait=True)
        response = device.receive()
    finally:
        device.set_socketTimeout(original_timeout)
    result: dict[str, Any] = {
        "requested_dps": list(dps),
        "send_result": send_result,
        "received": response,
    }
    received_dps = response_dps(response)
    if received_dps:
        result["dps"] = received_dps
    return result


def listen_for_report(device: Any, seconds: float) -> dict[str, Any]:
    """Listen for one unsolicited device report for a bounded time."""
    original_timeout = device.connection_timeout
    device.set_socketTimeout(seconds)
    try:
        response = device.receive()
    finally:
        device.set_socketTimeout(original_timeout)
    result: dict[str, Any] = {"listen_seconds": seconds, "received": response}
    received_dps = response_dps(response)
    if received_dps:
        result["dps"] = received_dps
    return result


def dp_chunks(dps: tuple[int, ...], size: int) -> list[tuple[int, ...]]:
    """Split DP IDs into deterministic query groups."""
    return [dps[index : index + size] for index in range(0, len(dps), size)]


def probe_variant(
    args: argparse.Namespace,
    local_key: str,
    port: int,
    variant: ProtocolVariant,
    reporter: Reporter,
    redactor: Redactor,
) -> dict[str, Any]:
    reporter.write(
        "Starting protocol variant",
        {**asdict(variant), "port": port},
    )
    result: dict[str, Any] = {
        "variant": asdict(variant),
        "port": port,
        "operations": {},
    }
    device = None
    try:
        device = create_device(
            args.device_id,
            args.ip,
            local_key,
            port,
            variant,
            args.timeout,
        )

        result["operations"]["heartbeat"] = timed_call(
            "heartbeat",
            lambda: device.heartbeat(nowait=False),
            reporter,
            redactor,
        )
        time.sleep(1.5)

        if variant.query_mode in {
            "data_dps",
            "explicit_dps",
            "protocol_dps",
            "dpid_list",
        }:
            operation_name = f"status_{variant.query_mode}"
            result["operations"][operation_name] = timed_call(
                f"status query mode {variant.query_mode}",
                lambda: status_with_query_mode(device, variant, args.dps),
                reporter,
                redactor,
            )
        elif variant.query_mode == "explicit_chunks":
            for group_index, dps_group in enumerate(
                dp_chunks(args.dps, args.dp_chunk_size), start=1
            ):
                result["operations"][f"explicit_chunk_{group_index}"] = timed_call(
                    f"Explicit status DP chunk {','.join(map(str, dps_group))}",
                    lambda dps_group=dps_group: status_with_query_mode(
                        device, variant, dps_group
                    ),
                    reporter,
                    redactor,
                )
                time.sleep(0.5)
        elif variant.query_mode == "updatedps":
            result["operations"]["updatedps"] = timed_call(
                f"UPDATEDPS request {','.join(map(str, args.dps))}",
                lambda: request_updated_dps(device, args.dps, args.timeout),
                reporter,
                redactor,
            )
        elif variant.query_mode == "updatedps_chunks":
            for group_index, dps_group in enumerate(
                dp_chunks(args.dps, args.dp_chunk_size), start=1
            ):
                result["operations"][f"updatedps_chunk_{group_index}"] = timed_call(
                    f"UPDATEDPS chunk {','.join(map(str, dps_group))}",
                    lambda dps_group=dps_group: request_updated_dps(
                        device, dps_group, args.timeout
                    ),
                    reporter,
                    redactor,
                )
                time.sleep(0.5)
        elif variant.query_mode == "passive":
            reporter.write(
                "Passive observation started; operate the device physically now",
                {"seconds": args.listen_seconds},
            )
            result["operations"]["passive_receive"] = timed_call(
                "Passive DP report observation",
                lambda: listen_for_report(device, args.listen_seconds),
                reporter,
                redactor,
            )
        else:
            for group_name, dps_group in (
                ("status_core", CORE_DPS),
                ("status_extended", EXTENDED_DPS),
            ):
                device.set_dpsUsed({str(dp): None for dp in dps_group})
                result["operations"][group_name] = timed_call(
                    f"{group_name} DPS {','.join(map(str, dps_group))}",
                    lambda: status_with_query_mode(device, variant, dps_group),
                    reporter,
                    redactor,
                )
                time.sleep(0.5)

            result["operations"]["product"] = timed_call(
                "product query",
                device.product,
                reporter,
                redactor,
            )
            time.sleep(0.5)

            result["operations"]["detect_available_dps"] = timed_call(
                "DPS detection",
                device.detect_available_dps,
                reporter,
                redactor,
            )

        all_dps: dict[str, Any] = {}
        for operation in result["operations"].values():
            all_dps.update(response_dps(operation.get("response")))
        detected_operation = result["operations"].get("detect_available_dps")
        if detected_operation:
            detected_response = detected_operation.get("response")
            if isinstance(detected_response, dict):
                if "dps" in detected_response:
                    all_dps.update(response_dps(detected_response))
                elif "Error" not in detected_response:
                    all_dps.update(detected_response)
        result["combined_dps"] = all_dps
        result["dp_count"] = len(all_dps)
    except Exception as exc:
        result["setup_error"] = exception_result(exc, redactor)
        reporter.write("Variant setup failed", result["setup_error"])
    finally:
        if device is not None:
            close = getattr(device, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as exc:
                    result["close_error"] = exception_result(exc, redactor)

    reporter.write(
        "Finished protocol variant",
        {
            "selector": variant.selector,
            "port": port,
            "dp_count": result.get("dp_count", 0),
        },
    )
    return result


def sanitized_discovery(
    device_id: str,
    ip: str,
    reporter: Reporter,
    redactor: Redactor,
) -> dict[str, Any]:
    def discover() -> Any:
        try:
            return tinytuya.find_device(dev_id=device_id)
        except TypeError:
            return tinytuya.find_device(address=ip)

    return timed_call("LAN discovery", discover, reporter, redactor)


def write_json_report(path: Path, report: dict[str, Any], redactor: Redactor) -> None:
    path.write_text(
        json.dumps(redactor.clean(report), ensure_ascii=False, indent=2, default=repr)
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    # Make progress visible immediately in terminals, containers and HA add-ons,
    # even when Python would otherwise buffer stdout.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(line_buffering=True, write_through=True)

    print("Tuya Device Analyzer starting...", flush=True)
    args = parse_args()
    local_key = (
        args.local_key
        or os.environ.get("TUYA_LOCAL_KEY")
        or getpass.getpass("Tuya LocalKey (input hidden): ")
    )
    if not local_key:
        print("A LocalKey is required.", file=sys.stderr)
        return 2

    args.output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    log_path = args.output_dir / f"tuya-device-{timestamp}.log"
    json_path = args.output_dir / f"tuya-device-{timestamp}.json"
    redactor = Redactor(local_key, args.device_id, args.ip)
    reporter = Reporter(log_path, redactor)
    tinytuya_logger = enable_tinytuya_debug(reporter)

    report: dict[str, Any] = {
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "tool": "tuya-device-analyzer",
        "safety": "read-only; no state-changing DP commands",
        "target": {
            "ip": args.ip,
            "device_id_masked": masked_device_id(args.device_id),
            "device_id_length": len(args.device_id),
            "local_key_length": len(local_key),
        },
        "environment": {
            "python": sys.version,
            "platform": sys.platform,
            "tinytuya": importlib.metadata.version("tinytuya"),
        },
        "probe_settings": {
            "dps": list(args.dps),
            "dp_chunk_size": args.dp_chunk_size,
            "listen_seconds": args.listen_seconds,
        },
        "tcp_ports": {},
        "discovery": {},
        "probes": [],
    }

    try:
        reporter.write("Analyzer started", report["target"])
        reporter.write("Environment", report["environment"])
        reporter.write("Probe settings", report["probe_settings"])

        reachable_ports = []
        for port in TUYA_PORTS:
            port_result = tcp_probe(args.ip, port, args.timeout)
            report["tcp_ports"][str(port)] = port_result
            reporter.write(f"TCP port {port}", port_result)
            if port_result["reachable"]:
                reachable_ports.append(port)

        report["discovery"] = sanitized_discovery(
            args.device_id, args.ip, reporter, redactor
        )

        if not reachable_ports:
            reporter.write(
                "No known Tuya TCP port is reachable; protocol probes skipped"
            )
            write_json_report(json_path, report, redactor)
            return 1

        time.sleep(args.pause)
        for port in reachable_ports:
            for index, variant in enumerate(PROTOCOL_VARIANTS):
                report["probes"].append(
                    probe_variant(
                        args,
                        local_key,
                        port,
                        variant,
                        reporter,
                        redactor,
                    )
                )
                write_json_report(json_path, report, redactor)
                if index < len(PROTOCOL_VARIANTS) - 1:
                    reporter.write(
                        "Cooling down before next variant",
                        {"seconds": args.pause},
                    )
                    time.sleep(args.pause)

        successful = [
            {
                "selector": probe["variant"]["selector"],
                "port": probe["port"],
                "dp_count": probe.get("dp_count", 0),
                "dps": probe.get("combined_dps", {}),
            }
            for probe in report["probes"]
            if probe.get("dp_count", 0) > 0
        ]
        report["successful_variants"] = successful
        reporter.write("Successful variants", successful)
        write_json_report(json_path, report, redactor)
    finally:
        reporter.write(
            "Analyzer finished",
            {"log": str(log_path), "json": str(json_path)},
        )
        tinytuya_logger.handlers.clear()
        reporter.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
