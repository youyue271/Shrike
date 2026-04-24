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
    "dynamic_cfg": {"drio", "placeholder"},
}

ALLOWED_CAPTURE_FLAGS = {
    "cfg",
    "dfg",
    "memory_writes",
    "register_snapshots",
}

DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_VM_BOOT_GRACE_SECONDS = 60
DEFAULT_ARTIFACT_EXPORT_SLACK_SECONDS = 120
TRACE_MODE_EXPORT_SLACK_SECONDS: dict[str, int] = {
    "dynamic_cfg": 60,
}
TRACE_BACKEND_EXPORT_SLACK_SECONDS: dict[str, int] = {
    "drio": 60,
}


def expected_trace_artifacts(trace_mode: str) -> list[str]:
    return list(TRACE_ARTIFACTS_BY_MODE.get(trace_mode, TRACE_ARTIFACTS_BY_MODE["none"]))


def _coerce_nonnegative_int(value: Any, default: int) -> int:
    try:
        result = int(str(value))
    except Exception:
        return default
    return result if result >= 0 else default


def recommended_timeout_seconds(
    task_profile: dict[str, Any] | None,
    default_timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    vm_boot_grace_seconds: int = DEFAULT_VM_BOOT_GRACE_SECONDS,
    artifact_export_slack_seconds: int = DEFAULT_ARTIFACT_EXPORT_SLACK_SECONDS,
) -> int:
    if not isinstance(task_profile, dict) or not task_profile:
        return default_timeout_seconds

    trace_mode = str(task_profile.get("trace_mode", "none") or "none")
    trace_backend = str(task_profile.get("trace_backend", "none") or "none")
    execution_window_seconds = _coerce_nonnegative_int(task_profile.get("execution_window_seconds"), 0)
    boot_stabilization_seconds = _coerce_nonnegative_int(task_profile.get("boot_stabilization_seconds"), 0)
    export_slack_seconds = (
        artifact_export_slack_seconds
        + TRACE_MODE_EXPORT_SLACK_SECONDS.get(trace_mode, 0)
        + TRACE_BACKEND_EXPORT_SLACK_SECONDS.get(trace_backend, 0)
    )
    recommended = vm_boot_grace_seconds + boot_stabilization_seconds + execution_window_seconds + export_slack_seconds
    return max(default_timeout_seconds, recommended)


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
