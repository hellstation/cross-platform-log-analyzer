from pathlib import Path

from sentineltrace.detection.engine import DetectionEngine
from sentineltrace.detection.loader import load_rules
from sentineltrace.services.analyze import AnalyzeService

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "linux"
RULES = Path(__file__).resolve().parents[1] / "rules"


def _events_from(name: str):
    svc = AnalyzeService()
    return svc.analyze_file(FIXTURES / name).events


def test_ssh_brute_force_triggers():
    engine = DetectionEngine.from_path(RULES)
    alerts = engine.run(_events_from("auth_bruteforce.log"))
    assert any(a.rule_id == "DET-LNX-001" for a in alerts)


def test_password_spray_triggers():
    engine = DetectionEngine.from_path(RULES)
    alerts = engine.run(_events_from("password_spray.log"))
    assert any(a.rule_id == "DET-LNX-002" for a in alerts)


def test_baseline_no_high_alerts():
    engine = DetectionEngine.from_path(RULES)
    alerts = engine.run(_events_from("baseline.log"))
    high = [a for a in alerts if a.severity.value in ("high", "critical")]
    assert high == []


def test_sudo_activity():
    engine = DetectionEngine.from_path(RULES)
    alerts = engine.run(_events_from("sudo_activity.log"))
    assert any(a.rule_id == "DET-LNX-004" for a in alerts)


def test_all_rules_load():
    rules = load_rules(RULES)
    assert len(rules) >= 13
