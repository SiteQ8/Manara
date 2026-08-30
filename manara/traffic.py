"""The logic behind the reading traffic lesson.

This is the idea at the heart of NetHawk, shrunk to something you can do by hand.
A port scan shows up in a connection log as one source reaching for many ports,
or many hosts, in a short span. The detector groups a small log by source and
counts that spread. No live capture, just a list of connections to read.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

# A small connection log: (source, destination, port). Most of it is normal
# traffic to a couple of services; one host sweeps a wide range of ports.
SAMPLE_LOG: List[Tuple[str, str, int]] = [
    ("10.0.0.5", "10.0.0.20", 443), ("10.0.0.5", "10.0.0.20", 443),
    ("10.0.0.7", "10.0.0.20", 80), ("10.0.0.7", "10.0.0.21", 443),
    ("10.0.0.9", "10.0.0.20", 443),
    ("10.0.0.66", "10.0.0.20", 21), ("10.0.0.66", "10.0.0.20", 22),
    ("10.0.0.66", "10.0.0.20", 23), ("10.0.0.66", "10.0.0.20", 25),
    ("10.0.0.66", "10.0.0.20", 53), ("10.0.0.66", "10.0.0.20", 80),
    ("10.0.0.66", "10.0.0.20", 110), ("10.0.0.66", "10.0.0.20", 143),
    ("10.0.0.66", "10.0.0.20", 443), ("10.0.0.66", "10.0.0.20", 445),
    ("10.0.0.66", "10.0.0.20", 3306), ("10.0.0.66", "10.0.0.20", 3389),
    ("10.0.0.66", "10.0.0.20", 5432), ("10.0.0.66", "10.0.0.20", 8080),
    ("10.0.0.66", "10.0.0.20", 8443),
    ("10.0.0.8", "10.0.0.21", 443),
]


def summarize(log: List[Tuple[str, str, int]]) -> List[Dict]:
    """Per source, count distinct ports and distinct destination hosts."""
    by_src: Dict[str, Dict] = {}
    for src, dst, port in log:
        e = by_src.setdefault(src, {"source": src, "ports": set(), "hosts": set(), "connections": 0})
        e["ports"].add(port)
        e["hosts"].add(dst)
        e["connections"] += 1
    rows = []
    for e in by_src.values():
        rows.append({
            "source": e["source"],
            "distinct_ports": len(e["ports"]),
            "distinct_hosts": len(e["hosts"]),
            "connections": e["connections"],
            "ports": sorted(e["ports"]),
        })
    rows.sort(key=lambda r: r["distinct_ports"], reverse=True)
    return rows


def detect_port_scan(log: List[Tuple[str, str, int]], port_threshold: int = 15) -> Dict:
    """Flag any source that reached more distinct ports than the threshold.

    That wide spread is the signature of a vertical port scan: one host asking
    every door on a target whether it is open.
    """
    rows = summarize(log)
    scanners = []
    for r in rows:
        if r["distinct_ports"] >= port_threshold:
            scanners.append({
                "source": r["source"],
                "distinct_ports": r["distinct_ports"],
                "target": None if r["distinct_hosts"] != 1 else "a single host",
                "sample_ports": r["ports"][:12],
            })
    return {"rows": rows, "scanners": scanners, "threshold": port_threshold}


def explain() -> str:
    return (
        "Most defensive work starts with reading traffic, and the most basic "
        "pattern to recognize is a port scan. Normal clients talk to a service or "
        "two on their usual ports. A scanner does the opposite: a single source "
        "reaches for a long list of ports on a target, or the same port across "
        "many hosts, probing to learn what is open. You do not need fancy tools to "
        "see it, only to group the log by source and count how many distinct ports "
        "or hosts each one touched. One address with a count far above the rest is "
        "the scanner, and that spread is its fingerprint. This is exactly what a "
        "tool like NetHawk automates over a real capture."
    )


TAKEAWAY = (
    "Watch for one source fanning out across many ports or many hosts. That spread, "
    "not any single connection, is the signature of a scan. Group by source, count "
    "the spread, and the outlier stands out."
)
