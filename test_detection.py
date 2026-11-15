import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from app.detection import DetectionEngine, entropy

def ev(src="1.1.1.1", dst="10.0.0.5", dport=80, flags="S", ts=1000.0, **kw):
    return dict(ts=ts, src=src, dst=dst, sport=5000, dport=dport, proto="TCP", flags=flags, size=60, **kw)

def test_port_scan_detected():
    e = DetectionEngine()
    for p in range(1, 31): e.add(ev(dport=p))
    assert [a["category"] for a in e.flush(1010.0)] == ["Port Scanning"]

def test_brute_force_detected():
    e = DetectionEngine()
    for _ in range(20): e.add(ev(dport=22))
    assert any(a["category"] == "Brute Force" for a in e.flush(1010.0))

def test_benign_traffic_no_alert():
    e = DetectionEngine()
    for i in range(10): e.add(ev(dport=443, flags="PA"))
    assert e.flush(1010.0) == []

def test_cooldown_prevents_duplicates():
    e = DetectionEngine()
    for w in range(2):
        for p in range(1, 31): e.add(ev(dport=p))
        out = e.flush(1010.0 + w)
    assert out == []

def test_dns_long_name_flagged():
    e = DetectionEngine()
    assert e.add(ev(flags="", dns="a" * 60 + ".example.com"))[0]["category"] == "Suspicious DNS Activity"

def test_entropy_ordering(): assert entropy("aaaa") < entropy("a1b2c3d4")
