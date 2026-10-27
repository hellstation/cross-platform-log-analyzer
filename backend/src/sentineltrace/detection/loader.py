"""Load YAML detection rules."""

from pathlib import Path

import yaml

from sentineltrace.detection.rule_schema import DetectionRule


def load_rules(rules_dir: Path) -> list[DetectionRule]:
    rules: list[DetectionRule] = []
    if not rules_dir.is_dir():
        return rules
    for path in sorted(rules_dir.glob("*.yaml")):
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not data:
            continue
        if isinstance(data, list):
            for item in data:
                rules.append(DetectionRule(**item))
        else:
            rules.append(DetectionRule(**data))
    return rules


def validate_rules(rules_dir: Path) -> list[dict]:
    results = []
    for path in sorted(rules_dir.glob("*.yaml")):
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, list):
                for item in data:
                    DetectionRule(**item)
            else:
                DetectionRule(**data)
            results.append({"file": path.name, "valid": True, "error": None})
        except Exception as exc:
            results.append({"file": path.name, "valid": False, "error": str(exc)})
    return results
