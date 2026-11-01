from __future__ import annotations

from pathlib import Path
from ids_parser.models import NormalizedEvent
from ids_rule_engine.evaluator import RuleEvaluationEngine
from ids_rule_engine.indexer import RuleIndexer
from ids_rule_engine.loader import RuleLoader
from ids_rule_engine.parser import RuleParser


def test_t06_protocol_indexing_tcp_udp_ip():
    loader = RuleLoader()
    parser = RuleParser()
    rules = parser.parse_rules(loader.load_file(Path("TEST/EXERCISE-3/rules/case06_indexer.rules")))

    indexer = RuleIndexer(rules=rules)

    tcp_candidates = indexer.get_candidates_by_protocol("TCP")
    udp_candidates = indexer.get_candidates_by_protocol("UDP")
    ip_candidates = indexer.get_candidates_by_protocol("IP")

    tcp_sids = sorted(r.sid for r in tcp_candidates)
    udp_sids = sorted(r.sid for r in udp_candidates)
    ip_sids = sorted(r.sid for r in ip_candidates)

    assert tcp_sids == [601, 602, 604, 605]
    assert udp_sids == [603, 604]
    assert ip_sids == [604]


def test_t06_port_filtering_indexer():
    loader = RuleLoader()
    parser = RuleParser()
    rules = parser.parse_rules(loader.load_file(Path("TEST/EXERCISE-3/rules/case06_indexer.rules")))

    indexer = RuleIndexer(rules=rules)

    ev_tcp_80 = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="TCP",
        src_port=54321,
        dst_port=80,
    )
    c_tcp_80 = sorted(r.sid for r in indexer.get_candidate_rules(ev_tcp_80))
    assert c_tcp_80 == [601, 604, 605]

    ev_tcp_443 = NormalizedEvent(
        packet_id=2,
        timestamp=100.1,
        transport_protocol="TCP",
        src_port=54321,
        dst_port=443,
    )
    c_tcp_443 = sorted(r.sid for r in indexer.get_candidate_rules(ev_tcp_443))
    assert c_tcp_443 == [602, 604, 605]

    ev_udp_53 = NormalizedEvent(
        packet_id=3,
        timestamp=100.2,
        transport_protocol="UDP",
        src_port=53000,
        dst_port=53,
    )
    c_udp_53 = sorted(r.sid for r in indexer.get_candidate_rules(ev_udp_53))
    assert c_udp_53 == [603, 604]


def test_t06_get_rule_by_sid():
    loader = RuleLoader()
    parser = RuleParser()
    rules = parser.parse_rules(loader.load_file(Path("TEST/EXERCISE-3/rules/case06_indexer.rules")))

    indexer = RuleIndexer(rules=rules)

    r601 = indexer.get_rule_by_sid(601)
    assert r601 is not None
    assert r601.msg == "TCP Port 80"

    r999 = indexer.get_rule_by_sid(999)
    assert r999 is None


def test_t06_invalid_rules_ignored_by_indexer():
    parser = RuleParser()
    invalid_rule = parser.parse_rule('alert tcp any -> 80 (msg:"Bad"; sid:901;)')
    assert invalid_rule.status == "invalid"

    indexer = RuleIndexer()
    indexer.add_rule(invalid_rule)

    assert len(indexer.rules) == 0
    assert indexer.get_rule_by_sid(901) is None


def test_t06_evaluator_uses_indexer_properly():
    loader = RuleLoader()
    parser = RuleParser()
    rules = parser.parse_rules(loader.load_file(Path("TEST/EXERCISE-3/rules/case06_indexer.rules")))

    indexer = RuleIndexer(rules=rules)
    evaluator = RuleEvaluationEngine(indexer=indexer)

    ev_udp = NormalizedEvent(
        packet_id=1,
        timestamp=100.0,
        transport_protocol="UDP",
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        src_port=53000,
        dst_port=53,
    )
    candidates = evaluator.get_candidate_rules(ev_udp)
    candidate_sids = sorted(r.sid for r in candidates)
    assert candidate_sids == [603, 604]

    alerts = evaluator.evaluate_event(ev_udp)
    alert_sids = sorted(a.sid for a in alerts)
    assert alert_sids == [603, 604]
    assert evaluator.candidate_rules_evaluated == 2

