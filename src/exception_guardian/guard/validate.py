"""Sigma rule validation with pySigma. Empty list = valid."""
from __future__ import annotations

import yaml
from sigma.collection import SigmaCollection

REQUIRED = ("title", "id", "logsource", "detection")


def validate_rule(yaml_text: str, drafted: bool) -> list[str]:
    try:
        docs = [d for d in yaml.safe_load_all(yaml_text) if d is not None]
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {str(exc).splitlines()[0]}"]
    if not docs or not all(isinstance(d, dict) for d in docs):
        return ["not a Sigma rule document"]
    errors: list[str] = []
    for d in docs:
        errors += [f"missing required field: {k}" for k in REQUIRED if k not in d]
    if drafted:
        if len(docs) != 1:
            errors.append(f"drafted file must hold exactly one rule document (found {len(docs)})")
        for d in docs:
            if d.get("status") != "experimental":
                errors.append("drafted rule status must be 'experimental'")
            if not d.get("references"):
                errors.append("drafted rule needs at least one references URL")
    if errors:
        return errors
    try:
        coll = SigmaCollection.from_yaml(yaml_text, collect_errors=True)
    except Exception as exc:
        return [f"pySigma parse error: {exc}"]
    errors += [f"pySigma: {e}" for e in coll.errors]
    for rule in coll.rules:
        errors += [f"pySigma: {e}" for e in rule.errors]
    return errors
