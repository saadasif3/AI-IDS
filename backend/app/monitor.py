"""Packet capture (live via Scapy) and a clearly labelled simulation mode."""
import asyncio, random, time
from .detection import DetectionEngine

WINDOW = 10

def list_interfaces():
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except Exception:
        return []

class Monitor:
    def __init__(self, on_alerts):
        self.on_alerts = on_alerts; self.running = False; self.mode = None; self.packets = 0; self.error = None
        self.engine = DetectionEngine(); self.q: asyncio.Queue = asyncio.Queue(maxsize=50_000)
        self._task = None; self._sniffer = None; self._tick = 0

    async def start(self, mode: str, iface: str | None):
        if self.running: raise RuntimeError("Already running")
        self.engine = DetectionEngine(); self.packets = 0; self.error = None; self._tick = 0
        if mode == "live":
            from scapy.all import AsyncSniffer  # needs libpcap and capture privileges
            loop = asyncio.get_running_loop()
            def cb(p):
                ev = self._parse(p)
                if ev: loop.call_soon_threadsafe(lambda: self.q.full() or self.q.put_nowait(ev))
            self._sniffer = AsyncSniffer(iface=iface, prn=cb, store=False); self._sniffer.start()
        self.mode, self.running = mode, True
        self._task = asyncio.create_task(self._run())

    async def stop(self):
        self.running = False
        if self._sniffer:
            try: self._sniffer.stop()
            except Exception: pass
            self._sniffer = None
        if self._task: self._task.cancel()

    @staticmethod
    def _parse(p):
        from scapy.all import IP, TCP, UDP, ICMP, DNSQR
        if IP not in p: return None
        ip = p[IP]; ev = dict(ts=time.time(), src=ip.src, dst=ip.dst, size=len(p), sport=None, dport=0, proto="OTHER", flags="")
        if TCP in p: ev.update(proto="TCP", sport=p[TCP].sport, dport=p[TCP].dport, flags=str(p[TCP].flags))
        elif UDP in p: ev.update(proto="UDP", sport=p[UDP].sport, dport=p[UDP].dport)
        elif ICMP in p: ev.update(proto="ICMP")
        if DNSQR in p:
            try: ev["dns"] = p[DNSQR].qname.decode().rstrip(".")
            except Exception: pass
        return ev

    def _simulate(self):
        """Synthetic traffic for demos. Labelled 'simulation' everywhere; it is NOT real network data.
        Benign hosts plus an occasional scan burst from a documentation-range address (203.0.113.0/24)."""
        now = time.time(); self._tick += 1
        for _ in range(25):
            h = f"10.0.0.{random.randint(2, 9)}"
            self.q.put_nowait(dict(ts=now, src=h, dst=random.choice(["10.0.1.10", "10.0.1.11"]), sport=random.randint(40000, 60000),
                                   dport=random.choice([80, 443, 53]), proto="TCP", flags="PA", size=random.randint(60, 1400)))
        if self._tick % 45 == 0:
            for port in range(1, 61):
                self.q.put_nowait(dict(ts=now, src="203.0.113.7", dst="10.0.1.10", sport=51000, dport=port, proto="TCP", flags="S", size=60))

    async def _run(self):
        last = time.time()
        try:
            while self.running:
                await asyncio.sleep(1)
                if self.mode == "simulation": self._simulate()
                alerts = []
                while not self.q.empty():
                    alerts += self.engine.add(self.q.get_nowait()); self.packets += 1
                if time.time() - last >= WINDOW:
                    alerts += self.engine.flush(); last = time.time()
                if alerts: await self.on_alerts(alerts, self.mode)
        except asyncio.CancelledError:
            pass
        except Exception as e:  # surface capture/engine failures instead of dying silently
            self.error, self.running = str(e), False
