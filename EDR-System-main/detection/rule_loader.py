"""
detection/rule_loader.py

Loads detection rules from JSON files at runtime and compiles them into
callable match functions compatible with the existing DetectionEngine pipeline.

Rule fields supported:
  event_type          - required: PROCESS_CREATE, FILE_CREATE, etc.
  process_name        - exact substring match (case-insensitive)
  process_name_in     - match any of a list
  parent_name_in      - parent process must be in list
  commandline_contains - ALL tokens must appear in cmdline (AND logic)
  path_contains       - substring match on path (string or list: OR logic)
  file_extension_in   - match file extension from details['file_extension']
  min_occurrences     - used by correlation rules (not handled by matcher)
"""

import json
import os
from typing import List, Callable, Dict, Any
from models.event_schema import EventType
from core.logger import logger
from core.mitre import mitre

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


def _build_matcher(rule: Dict[str, Any]) -> Callable:
    """
    Compiles a JSON rule dict into a lambda-compatible callable
    that accepts a single EventSchema and returns bool.
    """
    # Resolve event_type enum once at load time
    raw_event_type = rule.get("event_type", "PROCESS_CREATE").upper()
    try:
        required_event_type = EventType[raw_event_type]
    except KeyError:
        logger.warning(f"RuleLoader: Unknown event_type '{raw_event_type}' in rule '{rule.get('rule_name')}'. Skipping.")
        return None

    # Pre-lower all string lists for fast comparison
    process_name       = rule.get("process_name", "").lower()
    process_name_in    = [p.lower() for p in rule.get("process_name_in", [])]
    parent_name_in     = [p.lower() for p in rule.get("parent_name_in", [])]
    cmdline_tokens     = [t.lower() for t in rule.get("commandline_contains", [])]
    path_contains_raw  = rule.get("path_contains", None)
    path_fragments     = (
        [path_contains_raw.lower()] if isinstance(path_contains_raw, str)
        else [p.lower() for p in path_contains_raw]
    ) if path_contains_raw else []
    file_ext_in        = [e.lower() for e in rule.get("file_extension_in", [])]

    def matcher(event) -> bool:
        # Event type gate
        if event.event_type != required_event_type:
            return False

        proc  = event.process_name.lower()
        par   = event.parent_name.lower()
        cmd   = event.cmdline.lower()
        path  = event.path.lower()

        # process_name: substring match
        if process_name and process_name not in proc:
            return False

        # process_name_in: any match
        if process_name_in and proc not in process_name_in:
            return False

        # parent_name_in: any match
        if parent_name_in and par not in parent_name_in:
            return False

        # commandline_contains: ALL tokens must be present (AND)
        if cmdline_tokens and not all(tok in cmd for tok in cmdline_tokens):
            return False

        # path_contains: ANY fragment must match (OR)
        if path_fragments and not any(frag in path for frag in path_fragments):
            return False

        # file_extension_in: match from event details
        if file_ext_in:
            ext = event.details.get("file_extension", "").lower()
            if ext not in file_ext_in:
                return False

        return True

    return matcher


def _normalize_rule(raw: Dict[str, Any], source_file: str) -> Dict[str, Any]:
    """
    Normalises a raw JSON rule dict into the standard internal format
    used by DetectionEngine._trigger_alert().
    MITRE technique_name is resolved from the catalogue at load time.
    """
    name = raw.get("rule_name") or raw.get("name", "Unnamed_Rule")
    matcher = _build_matcher(raw)
    if matcher is None:
        return None

    # Resolve MITRE info at load time — zero runtime cost per event
    technique_id = raw.get("mitre_id") or raw.get("technique", "")
    mitre_info   = mitre.enrich(technique_id) if technique_id else {}

    return {
        "name":           name,
        "tactic":         mitre_info.get("tactic", raw.get("tactic", "Unknown")),
        "technique":      technique_id,
        "technique_name": mitre_info.get("technique_name", raw.get("technique", "")),
        "mitre_id":       mitre_info.get("mitre_id", technique_id),
        "severity":       raw.get("severity", "MEDIUM"),
        "confidence":     raw.get("confidence", "MEDIUM"),
        "score":          int(raw.get("score", raw.get("risk", 0))),
        "min_occurrences": int(raw.get("min_occurrences", 1)),
        "match":          matcher,
        "_source":        source_file,
    }


def load_rules(filename: str) -> List[Dict[str, Any]]:
    """
    Loads and compiles rules from a single JSON file in detection/rules/.
    Returns a list of normalised rule dicts ready for DetectionEngine.
    """
    path = os.path.join(RULES_DIR, filename)
    if not os.path.exists(path):
        logger.warning(f"RuleLoader: Rule file not found: {path}")
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_rules = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"RuleLoader: JSON parse error in {filename}: {e}")
        return []

    compiled = []
    for raw in raw_rules:
        normalised = _normalize_rule(raw, filename)
        if normalised:
            compiled.append(normalised)

    logger.info(f"RuleLoader: Loaded {len(compiled)} rules from '{filename}'.")
    return compiled


def load_all_rules() -> Dict[str, List[Dict[str, Any]]]:
    """
    Loads every .json rule file in detection/rules/.
    Returns a dict keyed by file stem, e.g.:
      {
        "process_rules": [...],
        "file_rules": [...],
        "correlation_rules": [...]
      }
    """
    result = {}
    if not os.path.isdir(RULES_DIR):
        logger.warning(f"RuleLoader: Rules directory not found: {RULES_DIR}")
        return result

    for fname in sorted(os.listdir(RULES_DIR)):
        if fname.endswith(".json"):
            stem = fname[:-5]
            result[stem] = load_rules(fname)

    total = sum(len(v) for v in result.values())
    logger.info(f"RuleLoader: Total {total} rules loaded from {len(result)} file(s).")
    return result
