"""The Judge. These pin the detection behaviour the README and lab report rely on."""

import pytest

import config
import detectors


def touches(ports, start=1000.0, step=1.0):
    return [(start + i * step, p) for i, p in enumerate(ports)]


def test_cardinality_threshold_is_strictly_greater():
    t15 = touches(range(1, 16))
    t16 = touches(range(1, 17))
    assert detectors.cardinality(t15, now=1020.0) == (15, False)
    assert detectors.cardinality(t16, now=1020.0) == (16, True)


def test_cardinality_ignores_touches_outside_window():
    old = [(0.0, p) for p in range(100)]           # long ago
    assert detectors.cardinality(old, now=1000.0) == (0, False)


def test_entropy_of_one_repeated_port_is_zero():
    h, n = detectors.shannon_entropy([443] * 50)
    assert (h, n) == (0.0, 1)
    assert str(h) == "0.0"                          # no "-0.0" leaking into the dashboard


def test_entropy_of_uniform_ports_is_one():
    h, n = detectors.shannon_entropy([20, 25, 80, 110, 143, 443, 3389, 8080])
    assert n == 8
    assert h == pytest.approx(1.0)


def test_entropy_requires_minimum_samples():
    verdict = detectors.evaluate(touches([1, 2, 3, 4]), now=1004.0)   # one short of 5
    assert verdict.entropy_computed is False
    assert verdict.entropy_alarm is False

    verdict = detectors.evaluate(touches([1, 2, 3, 4, 5]), now=1005.0)
    assert verdict.entropy_computed is True
    assert verdict.entropy_alarm is True


def test_normal_browsing_does_not_alarm():
    verdict = detectors.evaluate(touches([443] * 40 + [80] * 10), now=1050.0)
    assert not verdict.card_alarm
    assert not verdict.entropy_alarm


def test_slow_scan_evades_cardinality_but_trips_entropy():
    """The README's headline claim: 8 ports, 2 s apart."""
    ports = [20, 25, 80, 110, 143, 443, 3389, 8080]
    history, fired_at = [], None
    for i, port in enumerate(ports):
        now = 1000.0 + 2 * i
        history.append((now, port))
        verdict = detectors.evaluate(history, now)
        assert not verdict.card_alarm, "cardinality must never trip on 8 ports"
        if verdict.entropy_alarm and fired_at is None:
            fired_at = i + 1
    assert fired_at == config.ENTROPY_MIN_SAMPLES   # fires as soon as enough samples exist


def test_loud_scan_trips_cardinality():
    verdict = detectors.evaluate(touches(range(1, 40), step=0.1), now=1004.0)
    assert verdict.card_alarm
    assert verdict.card_unique > config.CARDINALITY_THRESHOLD
