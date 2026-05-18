"""
detection/rules.py

RULES is now loaded dynamically from JSON files under detection/rules/.
The hardcoded lambda list has been replaced by the rule_loader compiler.

To add or modify rules, edit the JSON files — no Python changes required.
"""
from detection.rule_loader import load_rules

# Process-based stateless rules (loaded from JSON)
RULES = load_rules("process_rules.json") + load_rules("file_rules.json")