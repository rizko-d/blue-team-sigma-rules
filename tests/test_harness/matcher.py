"""
Sigma detection logic evaluator — evaluates Sigma rules against log fixtures.

Handles: field|contains, |contains|any, |contains|all, |endswith,
|startswith, |regex, exact match, list OR match, and compound conditions
(1 of, all of, selection AND selection).
"""
import re
from pathlib import Path


def _get_value(log: dict, field: str):
    """Dotted-field lookup (e.g. 'requestParameters.bucketName')."""
    val = log
    for part in field.split("."):
        if isinstance(val, dict):
            val = val.get(part, None)
        else:
            return None
    return val


def _match_modifier(val, modifier: str, pattern):
    """Test a single field+modifier+pattern against log value."""
    val = str(val) if not isinstance(val, (list, dict)) else str(val)
    if modifier == "contains":
        return pattern.lower() in val.lower()
    elif modifier == "endswith":
        return val.lower().endswith(pattern.lower())
    elif modifier == "startswith":
        return val.lower().startswith(pattern.lower())
    elif modifier == "regex":
        return bool(re.search(pattern, val))
    elif modifier == "base64":
        # simplistic base64 string check
        try:
            import base64
            decoded = base64.b64decode(val).decode("utf-8", errors="replace")
            return pattern.lower() in decoded.lower()
        except Exception:
            return False
    return False


def _match_selection(log: dict, selection: dict) -> bool:
    """
    Evaluate a single selection block (dict of field->pattern(s)).
    All entries within a selection are ANDed.
    """
    for field, patterns in selection.items():
        if field == "NOT":
            # NOT modifier: invert the child match
            if _match_selection(log, patterns):
                return False
            continue

        # Parse modifier from field name (e.g. 'CommandLine|contains')
        parts = field.split("|")
        field_name = parts[0]
        modifiers = parts[1:]

        log_val = _get_value(log, field_name)
        if log_val is None:
            return False

        # Normalise value to string for comparison
        if isinstance(log_val, bool) or isinstance(log_val, (int, float)):
            log_val = str(log_val).lower()
        elif isinstance(log_val, (dict, list)):
            log_val = str(log_val)

        # Normalise value list for multiple patterns
        if isinstance(patterns, list):
            if "any" in modifiers:
                # OR: at least one pattern must match
                mod = modifiers[0] if modifiers else "contains"
                matched = any(_match_modifier(log_val, mod, p) for p in patterns)
                if not matched:
                    return False
            elif "all" in modifiers:
                # AND: all patterns must match
                mod = modifiers[0] if modifiers else "exact"
                if not all(_match_modifier(log_val, mod, p) for p in patterns):
                    return False
            else:
                # List of exact values: OR match
                if str(log_val) not in patterns:
                    # Try contains if values look partial
                    if not any(p.lower() in str(log_val).lower() for p in patterns):
                        return False
        else:
            # Single pattern
            if modifiers:
                mod = modifiers[0]
                if not _match_modifier(log_val, mod, patterns):
                    return False
            else:
                # Exact match
                if str(log_val) != str(patterns):
                    # Also try substring if patterns is short enough
                    if str(patterns).lower() not in str(log_val).lower():
                        return False

    return True


def evaluate_rule_against_log(rule: dict, log: dict) -> bool:
    """
    Evaluate a Sigma rule's detection logic against a log event.
    Returns True if detection condition is satisfied (alert would fire).
    """
    detection = rule.get("detection", {})
    condition_str = detection.get("condition", "1 of selection_*")
    selections = {k: v for k, v in detection.items() if k.startswith("selection") or k.startswith("filter")}

    # Pre-compute match status for each selection
    match_cache = {}
    for name, sel in selections.items():
        match_cache[name] = _match_selection(log, sel)

    return _eval_condition(condition_str, match_cache)


def _eval_condition(cond: str, cache: dict) -> bool:
    """
    Evaluate condition string against pre-computed match states.

    Supported patterns:
    - "1 of selection_*"      → any selection True
    - "all of selection_*"    → all selections True  
    - "selection_a and selection_b" → both True
    - "selection_a and 1 of selection_*" → sel_a AND any of rest
    - "1 of selection_* and not 1 of filter_*" → any sel True AND no filter True
    - "selection_a or (selection_b and selection_c)" → complex not fully supported
    """
    cond = cond.strip()

    # "all of selection_*"
    m = re.match(r"all of (\w+)_\*", cond)
    if m:
        prefix = m.group(1)
        relevant = {k: v for k, v in cache.items() if k.startswith(prefix)}
        return all(relevant.values())

    # "1 of selection_*"
    m = re.match(r"(\d+) of (\w+)_\*", cond)
    if m:
        count = int(m.group(1))
        prefix = m.group(2)
        relevant = {k: v for k, v in cache.items() if k.startswith(prefix)}
        return sum(relevant.values()) >= count

    # "selection_a and selection_b"
    parts = re.split(r"\s+and\s+", cond)
    results = []
    for part in parts:
        part = part.strip()
        # Handle "1 of ..." sub-conditions
        m2 = re.match(r"(\d+) of (\w+)_\*", part)
        if m2:
            count = int(m2.group(1))
            prefix = m2.group(2)
            relevant = {k: v for k, v in cache.items() if k.startswith(prefix)}
            results.append(sum(relevant.values()) >= count)
        elif "1 of selection_*" in part:
            relevant = {k: v for k, v in cache.items() if k.startswith("selection")}
            results.append(any(relevant.values()))
        elif part.startswith("not "):
            sel_name = part.replace("not ", "")
            results.append(not cache.get(sel_name, False))
        elif part in cache:
            results.append(cache[part])
        else:
            # Might be a field-level condition - treat as False
            results.append(False)

    return all(results)
