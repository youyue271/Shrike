from __future__ import annotations

from typing import Any

TRACE_REQUEST_ARTIFACT = "trace_request.json"
TRACE_MANIFEST_ARTIFACT = "trace_manifest.json"

TRACE_ARTIFACTS_BY_MODE: dict[str, list[str]] = {
    "none": [
        TRACE_REQUEST_ARTIFACT,
        TRACE_MANIFEST_ARTIFACT,
    ],
    "dynamic_cfg": [
        TRACE_REQUEST_ARTIFACT,
        TRACE_MANIFEST_ARTIFACT,
        "dynamic_cfg_trace_summary.json",
        "dynamic_cfg_trace.ndjson",
        "trace_backend_diagnostic.json",
    ],
}

SUPPORTED_TRACE_BACKENDS: dict[str, set[str]] = {
    "none": {"none"},
    "dynamic_cfg": {"placeholder"},
}

ALLOWED_CAPTURE_FLAGS = {
    "cfg",
    "dfg",
    "memory_writes",
    "register_snapshots",
}


def expected_trace_artifacts(trace_mode: str) -> list[str]:
    return list(TRACE_ARTIFACTS_BY_MODE.get(trace_mode, TRACE_ARTIFACTS_BY_MODE["none"]))


def validate_task_profile_dict(data: dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise ValueError("task profile JSON must contain an object at the top level")

    trace_mode = data.get("trace_mode", "none")
    if not isinstance(trace_mode, str):
        raise ValueError("task profile field 'trace_mode' must be a string")
    if trace_mode not in SUPPORTED_TRACE_BACKENDS:
        supported = ", ".join(sorted(SUPPORTED_TRACE_BACKENDS))
        raise ValueError(f"unsupported trace_mode '{trace_mode}'; supported values: {supported}")

    trace_backend = data.get("trace_backend", "none")
    if not isinstance(trace_backend, str):
        raise ValueError("task profile field 'trace_backend' must be a string")
    allowed_backends = SUPPORTED_TRACE_BACKENDS[trace_mode]
    if trace_backend not in allowed_backends:
        allowed = ", ".join(sorted(allowed_backends))
        raise ValueError(
            f"unsupported trace_backend '{trace_backend}' for trace_mode '{trace_mode}'; "
            f"supported values: {allowed}"
        )

    capture = data.get("capture", {})
    if capture is None:
        capture = {}
    if not isinstance(capture, dict):
        raise ValueError("task profile field 'capture' must be an object when present")

    unknown_capture_flags = sorted(set(capture) - ALLOWED_CAPTURE_FLAGS)
    if unknown_capture_flags:
        unknown = ", ".join(unknown_capture_flags)
        allowed = ", ".join(sorted(ALLOWED_CAPTURE_FLAGS))
        raise ValueError(f"unsupported capture flags: {unknown}; supported values: {allowed}")

    for key, value in capture.items():
        if not isinstance(value, bool):
            raise ValueError(f"task profile capture flag '{key}' must be a boolean")

    if trace_mode == "dynamic_cfg" and capture.get("cfg") is False:
        raise ValueError("trace_mode 'dynamic_cfg' requires capture.cfg=true when capture is present")

    backend_options = data.get("backend_options")
    if backend_options is not None and not isinstance(backend_options, dict):
        raise ValueError("task profile field 'backend_options' must be an object when present")
