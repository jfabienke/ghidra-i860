"""Strict schema validation for LLM agent responses.

Zero-dependency validators that reject malformed responses before DB insert.
Each validate_* function returns (parsed_dict, errors).
If errors is non-empty, the response MUST NOT be inserted into the store.
"""


def _check_required(data, fields, errors, prefix=""):
    """Check that all required fields exist in data."""
    for field in fields:
        if field not in data:
            errors.append(f"{prefix}missing required field: {field}")


def _check_type(data, field, expected_type, errors, prefix=""):
    """Check field type if present."""
    if field in data and data[field] is not None:
        if not isinstance(data[field], expected_type):
            errors.append(
                f"{prefix}{field}: expected {expected_type.__name__}, "
                f"got {type(data[field]).__name__}"
            )


def _check_enum(data, field, allowed, errors, prefix=""):
    """Check field value is in allowed set."""
    if field in data and data[field] not in allowed:
        errors.append(
            f"{prefix}{field}: '{data[field]}' not in {allowed}"
        )


def _check_range(data, field, lo, hi, errors, prefix=""):
    """Check numeric field is within [lo, hi]."""
    if field in data and isinstance(data[field], (int, float)):
        v = data[field]
        if v < lo or v > hi:
            errors.append(f"{prefix}{field}: {v} not in [{lo}, {hi}]")


def _check_list_of_dicts(data, field, required_subfields, errors, prefix=""):
    """Check field is a list of dicts with required subfields."""
    if field not in data:
        return
    val = data[field]
    if not isinstance(val, list):
        errors.append(f"{prefix}{field}: expected list, got {type(val).__name__}")
        return
    for i, item in enumerate(val):
        if not isinstance(item, dict):
            errors.append(f"{prefix}{field}[{i}]: expected dict")
            continue
        for sf in required_subfields:
            if sf not in item:
                errors.append(f"{prefix}{field}[{i}]: missing '{sf}'")


def _check_hex_addr(data, field, errors, prefix=""):
    """Check field looks like a hex address string."""
    if field in data and data[field] is not None:
        v = data[field]
        if not isinstance(v, str) or not v.startswith("0x"):
            errors.append(f"{prefix}{field}: '{v}' is not a hex address")


# ---------- Intent claim schema ----------

INTENT_CATEGORIES = {
    "initialization", "dispatch", "parser", "raster", "mmio_driver",
    "math_kernel", "utility", "synchronization", "error_handler", "unknown",
}

SUBSYSTEM_HINTS = {
    "postscript_dispatch", "pixel_pipeline", "memory_management",
    "board_init", "interrupt_handling", "unknown",
}


def validate_intent(data):
    """Validate an intent agent response.

    Returns (data, errors). If errors is non-empty, reject the claim.
    """
    errors = []

    if not isinstance(data, dict):
        return data, ["response is not a dict"]

    if "_parse_error" in data:
        return data, [f"JSON parse failed: {data['_parse_error']}"]

    _check_required(data, [
        "function_id", "primary_intent", "intent_category",
        "evidence", "confidence",
    ], errors)

    _check_hex_addr(data, "function_id", errors)
    _check_type(data, "primary_intent", str, errors)
    _check_enum(data, "intent_category", INTENT_CATEGORIES, errors)
    _check_type(data, "confidence", (int, float), errors)
    _check_range(data, "confidence", 0, 100, errors)

    # Evidence: must be a list with >= 2 entries, each with addr + fact
    _check_list_of_dicts(data, "evidence", ["addr", "fact"], errors)
    evidence = data.get("evidence", [])
    if isinstance(evidence, list) and len(evidence) < 2:
        errors.append(
            f"evidence: {len(evidence)} entries (minimum 2 required)"
        )
    # Verify each evidence addr is hex
    if isinstance(evidence, list):
        for i, e in enumerate(evidence):
            if isinstance(e, dict):
                _check_hex_addr(e, "addr", errors, prefix=f"evidence[{i}].")

    _check_type(data, "register_protocol", dict, errors)
    _check_type(data, "control_flow_summary", str, errors)
    _check_type(data, "alternatives", list, errors)
    _check_type(data, "open_questions", list, errors)

    _check_enum(data, "subsystem_hint",
                SUBSYSTEM_HINTS | {None}, errors)

    return data, errors


# ---------- Verification schema ----------

VERIFICATION_STATUSES = {"accept", "revise", "reject"}


def validate_verification(data):
    """Validate a verifier agent response.

    Returns (data, errors).
    """
    errors = []

    if not isinstance(data, dict):
        return data, ["response is not a dict"]

    if "_parse_error" in data:
        return data, [f"JSON parse failed: {data['_parse_error']}"]

    _check_required(data, [
        "function_id", "status", "overall_assessment",
    ], errors)

    _check_hex_addr(data, "function_id", errors)
    _check_enum(data, "status", VERIFICATION_STATUSES, errors)
    _check_type(data, "overall_assessment", str, errors)

    # Evidence checks
    _check_list_of_dicts(data, "evidence_checks",
                         ["cited_addr", "valid"], errors)
    if "evidence_checks" in data and isinstance(data["evidence_checks"], list):
        for i, ec in enumerate(data["evidence_checks"]):
            if isinstance(ec, dict):
                if "valid" in ec and not isinstance(ec["valid"], bool):
                    errors.append(
                        f"evidence_checks[{i}].valid: expected bool"
                    )

    # Confidence assessment
    ca = data.get("confidence_assessment")
    if ca is not None:
        if not isinstance(ca, dict):
            errors.append("confidence_assessment: expected dict")
        else:
            _check_type(ca, "claimed", (int, float), errors,
                        prefix="confidence_assessment.")
            _check_type(ca, "recommended", (int, float), errors,
                        prefix="confidence_assessment.")
            _check_range(ca, "recommended", 0, 100, errors,
                         prefix="confidence_assessment.")

    return data, errors


# ---------- Contrarian schema ----------

CONTRARIAN_VERDICTS = {
    "primary_stands", "alternative_competitive", "genuinely_ambiguous",
}


def validate_contrarian(data):
    """Validate a contrarian agent response.

    Returns (data, errors).
    """
    errors = []

    if not isinstance(data, dict):
        return data, ["response is not a dict"]

    if "_parse_error" in data:
        return data, [f"JSON parse failed: {data['_parse_error']}"]

    _check_required(data, [
        "function_id", "primary_intent", "strongest_alternative", "verdict",
    ], errors)

    _check_hex_addr(data, "function_id", errors)
    _check_enum(data, "verdict", CONTRARIAN_VERDICTS, errors)

    sa = data.get("strongest_alternative")
    if sa is not None:
        if not isinstance(sa, dict):
            errors.append("strongest_alternative: expected dict")
        else:
            _check_required(sa, ["intent", "argument", "damage_to_primary"],
                            errors, prefix="strongest_alternative.")
            _check_range(sa, "damage_to_primary", 0, 100, errors,
                         prefix="strongest_alternative.")

    _check_range(data, "dead_code_probability", 0, 100, errors)
    _check_range(data, "misidentified_data_probability", 0, 100, errors)

    return data, errors


# ---------- Synthesis schema ----------

def validate_synthesis(data):
    """Validate a synthesizer agent response.

    Returns (data, errors).
    """
    errors = []

    if not isinstance(data, dict):
        return data, ["response is not a dict"]

    if "_parse_error" in data:
        return data, [f"JSON parse failed: {data['_parse_error']}"]

    _check_required(data, ["subsystems"], errors)

    _check_list_of_dicts(data, "subsystems",
                         ["name", "members", "confidence"], errors)

    if "subsystems" in data and isinstance(data["subsystems"], list):
        for i, ss in enumerate(data["subsystems"]):
            if isinstance(ss, dict):
                _check_range(ss, "confidence", 0, 100, errors,
                             prefix=f"subsystems[{i}].")

    _check_type(data, "control_flow_summary", str, errors)
    _check_type(data, "unresolved_runtime_dependencies", list, errors)

    return data, errors
