"""
THE JUDGE: two complementary detectors feeding one decision.

  (a) Port-cardinality tripwire (Lab 6)    fast, catches loud scans
  (b) Shannon-entropy stealth model (Lab 8) catches slow/low-rate scans that stay under
      the cardinality threshold

Everything here is a pure function of (touches, now), where `touches` is an iterable of
(timestamp, dest_port) pairs for ONE source IP. No I/O, no global state, no Scapy, which is
what makes the detection logic unit-testable.
"""

import math
from collections import Counter
from dataclasses import dataclass

import config


@dataclass(frozen=True)
class Verdict:
    card_unique: int
    card_alarm: bool
    entropy: float
    ent_unique: int
    entropy_alarm: bool
    entropy_computed: bool   # False while there are too few samples for entropy to mean anything


def recent_ports(touches, now, window):
    return [port for (ts, port) in touches if now - ts <= window]


def cardinality(touches, now,
                window=config.CARDINALITY_WINDOW_SECONDS,
                threshold=config.CARDINALITY_THRESHOLD):
    unique = len(set(recent_ports(touches, now, window)))
    return unique, unique > threshold


def shannon_entropy(ports):
    """
    H = -sum( p_i * log2(p_i) )  over the frequency distribution of ports touched.

    Normal traffic hits a small, repeated set of ports (e.g. 443 fifty times) -> LOW entropy.
    A scan, even a slow one, spreads hits close to uniformly across ports it has never
    touched before -> HIGH entropy, and this shows up with far fewer packets than it takes
    to trip a raw unique-port COUNT threshold.

    Result is normalized by the maximum possible entropy for the observed number of unique
    ports (log2(n_unique), the entropy of a perfectly uniform distribution over n_unique
    outcomes), so the score is always 0..1 and comparable across windows of different size.
    Returns (normalized_entropy, n_unique).
    """
    if not ports:
        return 0.0, 0
    counts = Counter(ports)
    total = len(ports)
    n_unique = len(counts)
    entropy = 0.0
    for c in counts.values():
        p_i = c / total
        entropy -= p_i * math.log2(p_i)
    max_entropy = math.log2(n_unique) if n_unique > 1 else 1.0
    return entropy / max_entropy, n_unique


def entropy_check(touches, now,
                  window=config.ENTROPY_WINDOW_SECONDS,
                  min_samples=config.ENTROPY_MIN_SAMPLES,
                  threshold=config.ENTROPY_THRESHOLD):
    """Returns (normalized_entropy, n_unique, is_stealth_scan, computed)."""
    ports = recent_ports(touches, now, window)
    if len(ports) < min_samples:
        return 0.0, len(set(ports)), False, False
    normalized, n_unique = shannon_entropy(ports)
    is_stealth_scan = normalized >= threshold and n_unique >= min_samples
    return normalized, n_unique, is_stealth_scan, True


def evaluate(touches, now):
    """Run both detectors over one IP's recent touches."""
    card_unique, card_alarm = cardinality(touches, now)
    entropy, ent_unique, entropy_alarm, computed = entropy_check(touches, now)
    return Verdict(card_unique, card_alarm, entropy, ent_unique, entropy_alarm, computed)
