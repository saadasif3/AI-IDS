"""Detection engines: threshold signatures + Isolation Forest anomaly detection.
Events are dicts: ts, src, dst, sport, dport, proto, size, flags, dns (optional)."""
import math, time
from collections import Counter, defaultdict

AUTH_PORTS = {21, 22, 23, 3389}
T = dict(scan_ports=20, brute_syns=15, dos_pkts=300, dns_len=50, dns_entropy=3.8, cooldown=60)

def entropy(s: str) -> float:
    c = Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0

def make(e, cat, sev, conf, method, desc, action, dst=None, dport=None):
    return dict(src_ip=e["src"], dst_ip=dst or e["dst"], src_port=e.get("sport"), dst_port=dport if dport is not None else e.get("dport"),
                protocol=e["proto"], category=cat, severity=sev, confidence=conf, method=method, description=desc, action=action)

class DetectionEngine:
    def __init__(self, baseline_windows: int = 40):
        self.buckets = defaultdict(list); self.cool = {}; self.baseline = []; self.model = None
        self.baseline_windows = baseline_windows

    def _ok(self, src, cat, now):  # one alert per source+category per cooldown
        if now - self.cool.get((src, cat), 0) < T["cooldown"]: return False
        self.cool[(src, cat)] = now; return True

    def add(self, e):
        self.buckets[e["src"]].append(e)
        q = e.get("dns")
        if q and (len(q) > T["dns_len"] or (len(q) > 20 and entropy(q.split(".")[0]) > T["dns_entropy"])) and self._ok(e["src"], "Suspicious DNS Activity", e["ts"]):
            return [make(e, "Suspicious DNS Activity", "medium", 0.6, "signature", f"Unusually long or high-entropy DNS name ({len(q)} chars). Possible tunnelling or DGA; may also be benign.", "Review the queried domain and the host's DNS history.")]
        return []

    def flush(self, now=None):
        now = now or time.time(); out = []
        for src, evs in self.buckets.items():
            hits = self._signatures(src, evs, now)
            out += hits
            out += self._anomaly(src, evs, now, bool(hits))
        self.buckets.clear(); return out

    def _signatures(self, src, evs, now):
        out = []; syn = [e for e in evs if e["proto"] == "TCP" and e.get("flags") == "S"]
        by_dst = defaultdict(set); by_dport = Counter(); by_dst_n = Counter()
        for e in syn: by_dst[e["dst"]].add(e["dport"]); by_dport[(e["dst"], e["dport"])] += 1
        for e in evs: by_dst_n[e["dst"]] += 1
        for dst, ports in by_dst.items():
            if len(ports) >= T["scan_ports"] and self._ok(src, "Port Scanning", now):
                e = next(x for x in syn if x["dst"] == dst)
                out.append(make(e, "Port Scanning", "high", 0.85, "signature", f"{src} sent SYN packets to {len(ports)} distinct ports on {dst} within one window.", "Verify the source is authorized; consider blocking after review.", dport=None))
        for (dst, port), n in by_dport.items():
            if port in AUTH_PORTS and n >= T["brute_syns"] and self._ok(src, "Brute Force", now):
                e = next(x for x in syn if x["dst"] == dst and x["dport"] == port)
                out.append(make(e, "Brute Force", "high", 0.75, "signature", f"{n} connection attempts from {src} to {dst}:{port} in one window. Indicates repeated login attempts; password failures were not observed.", "Check authentication logs on the target; enforce lockout or MFA."))
        for dst, n in by_dst_n.items():
            if n >= T["dos_pkts"] and self._ok(src, "DoS/DDoS Indicators", now):
                e = next(x for x in evs if x["dst"] == dst)
                out.append(make(e, "DoS/DDoS Indicators", "critical", 0.7, "signature", f"{n} packets from {src} to {dst} in one window, far above the configured threshold.", "Confirm service impact; apply rate limiting upstream."))
        return out

    def _anomaly(self, src, evs, now, already):
        f = [len(evs), sum(e["size"] for e in evs), len({e["dport"] for e in evs}), len({e["dst"] for e in evs})]
        if self.model is None:
            self.baseline.append(f)
            if len(self.baseline) >= self.baseline_windows:
                from sklearn.ensemble import IsolationForest
                self.model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42).fit(self.baseline)
            return []
        if already or self.model.predict([f])[0] != -1 or not self._ok(src, "Other Anomalous Activity", now): return []
        score = float(-self.model.score_samples([f])[0]); e = evs[0]
        return [make(e, "Other Anomalous Activity", "medium", round(min(score, 0.99), 2), "isolation_forest",
                     f"Traffic profile differs from the learned baseline (packets={f[0]}, bytes={f[1]}, ports={f[2]}, destinations={f[3]}). Unsupervised score; not a confirmed attack.", "Investigate the host's recent activity.")]
