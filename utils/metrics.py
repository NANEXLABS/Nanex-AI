"""
NANEX AGENT Metrics Engine: Secure Observability Pipeline with Prometheus/OpenTelemetry Integration
"""

import time
import asyncio
from typing import Dict, List, Optional, Tuple
from enum import Enum, auto
import hashlib
import zlib
from collections import deque
import platform

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
import prometheus_client as prom
from prometheus_client import Gauge, Counter, Histogram
from prometheus_client.openmetrics.exposition import generate_latest
import aiohttp
from aiohttp import web

class MetricType(Enum):
    COUNTER = auto()
    GAUGE = auto()
    HISTOGRAM = auto()
    SUMMARY = auto()

class SecureMetric:
    def __init__(self, 
                 name: str,
                 metric_type: MetricType,
                 labels: List[str],
                 public_key: x25519.X25519PublicKey,
                 private_key: x25519.X25519PrivateKey):
        
        self.name = f"yoo_{name}"
        self.type = metric_type
        self.labels = labels
        self.public_key = public_key
        self.private_key = private_key
        self._derive_signing_key()
        
        # Initialize Prometheus metrics
        self._prom_metric = self._create_prom_metric()
        self._sample_buffer = deque(maxlen=1000)
        self._last_export = time.monotonic()

    def _derive_signing_key(self):
        """X25519 key exchange for per-metric HMAC key derivation"""
        shared_key = self.private_key.exchange(self.public_key)
        self.hmac_key = HKDF(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=None,
            info=b"yoo_metrics_hmac",
        ).derive(shared_key)

    def _create_prom_metric(self):
        """Initialize type-specific Prometheus collector"""
        label_names = ["node_id"] + self.labels
        if self.type == MetricType.COUNTER:
            return Counter(self.name, f"{self.name} description", label_names)
        elif self.type == MetricType.GAUGE:
            return Gauge(self.name, f"{self.name} description", label_names)
        elif self.type == MetricType.HISTOGRAM:
            return Histogram(self.name, f"{self.name} description", label_names)
        else:
            raise ValueError("Unsupported metric type")

    def _sign_metric(self, value: float, labels: Dict[str, str]) -> bytes:
        """Compute HMAC-SHA3-256 of metric data"""
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        payload = f"{self.name}{{ {label_str} }}:{value}"
        h = hmac.HMAC(self.hmac_key, hashes.SHA3_256())
        h.update(payload.encode())
        return h.finalize()

    def record(self, value: float, labels: Dict[str, str]):
        """Securely buffer metric sample with cryptographic verification"""
        required_labels = {label: "" for label in self.labels}
        if not required_labels.keys() <= labels.keys():
            raise ValueError("Missing required labels")
        
        signature = self._sign_metric(value, labels)
        self._sample_buffer.append((time.monotonic(), value, labels, signature))
        
        # Update Prometheus collector
        self._prom_metric.labels(**labels).observe(value)

    async def export(self):
        """Asynchronously push metrics to trusted aggregator"""
        if time.monotonic() - self._last_export < 30:
            return
        
        payload = {
            "metadata": {
                "public_key": self.public_key.public_bytes_raw().hex(),
                "metric_name": self.name,
                "node_id": platform.node()
            },
            "samples": [
                {
                    "timestamp": ts,
                    "value": val,
                    "labels": lbls,
                    "signature": sig.hex()
                } for ts, val, lbls, sig in self._sample_buffer
            ]
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://metrics.yooagent.io/ingest",
                json=payload,
                ssl=False  # TLS handled at load balancer
            ) as resp:
                if resp.status == 200:
                    self._sample_buffer.clear()
                    self._last_export = time.monotonic()

class MetricsServer:
    _instance = None
    
    def __init__(self, port: int = 9100):
        self.port = port
        self.metrics: Dict[str, SecureMetric] = {}
        self.app = web.Application()
        self.app.add_routes([
            web.get('/metrics', self.handle_metrics),
            web.post('/internal/register', self.handle_register)
        ])
        self.runner = web.AppRunner(self.app)
        self._setup_telemetry()

    def _setup_telemetry(self):
        """Configure OpenTelemetry/Prometheus bridge"""
        prom.REGISTRY.unregister(prom.PROCESS_COLLECTOR)
        prom.REGISTRY.unregister(prom.PLATFORM_COLLECTOR)
        
        self.registry = prom.CollectorRegistry()
        self.push_gateway = prom.PushGateway(
            "https://pushgateway.yooagent.io",
            self.registry
        )

    async def handle_metrics(self, request: web.Request) -> web.Response:
        """Secure Prometheus exposition endpoint"""
        auth_header = request.headers.get('Authorization', '')
        if not self._verify_hmac(auth_header):
            return web.Response(status=403)
        
        output = generate_latest(self.registry)
        return web.Response(body=output, content_type="text/plain")

    def _verify_hmac(self, header: str) -> bool:
        """HMAC-based authentication for scrapers"""
        try:
            _, _, signature = header.partition(':')
            received_hmac = bytes.fromhex(signature)
            
            h = hmac.HMAC(os.getenv('METRICS_HMAC_KEY'), hashes.SHA3_256())
            h.update(b"yoo_metrics_access")
            expected_hmac = h.finalize()
            
            return hmac.compare_digest(received_hmac, expected_hmac)
        except:
            return False

    async def handle_register(self, request: web.Request) -> web.Response:
        """Dynamic metric registration endpoint"""
        try:
            data = await request.json()
            public_key = x25519.X25519PublicKey.from_public_bytes(
                bytes.fromhex(data['public_key'])
            )
            private_key = x25519.X25519PrivateKey.generate()
            
            metric = SecureMetric(
                data['name'],
                MetricType[data['type']],
                data['labels'],
                public_key,
                private_key
            )
            
            self.metrics[data['name']] = metric
            return web.json_response({
                "private_key": private_key.private_bytes_raw().hex()
            })
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def start(self):
        """Start metrics server with cleanup handling"""
        await self.runner.setup()
        site = web.TCPSite(self.runner, '0.0.0.0', self.port)
        await site.start()
        
        # Start background export tasks
        asyncio.create_task(self._periodic_export())

    async def _periodic_export(self):
        """Regular secured metric transmission"""
        while True:
            await asyncio.gather(
                *[metric.export() for metric in self.metrics.values()]
            )
            await asyncio.sleep(30)

    @classmethod
    def get_instance(cls):
        if not cls._instance:
            cls._instance = MetricsServer()
        return cls._instance

# Example usage
if __name__ == "__main__":
    server = MetricsServer.get_instance()
    
    # Pre-register core metrics
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    cpu_metric = SecureMetric(
        "cpu_usage",
        MetricType.GAUGE,
        ["service", "zone"],
        public_key,
        private_key
    )
    
    server.metrics["cpu_usage"] = cpu_metric
    
    # Start server
    loop = asyncio.get_event_loop()
    loop.run_until_complete(server.start())
    loop.run_forever()
