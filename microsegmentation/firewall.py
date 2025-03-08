"""
YOO AGENT Next-Gen Firewall: Zero-Trust Network Enforcement with ML-Driven Threat Prevention
"""

import asyncio
import json
import logging
import time
from collections import defaultdict
from datetime import datetime
from ipaddress import ip_address
from typing import Dict, List, Tuple, Optional
import aiohttp
import dpkt
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from prometheus_client import Counter, Gauge

logger = logging.getLogger(__name__)

# Metrics
FIREWALL_PACKETS = Counter("firewall_packets", "Processed packets", ["direction", "verdict"])
FIREWALL_THREATS = Counter("firewall_threats", "Detected threats", ["type"])
CONNECTIONS_GAUGE = Gauge("firewall_active_conns", "Active connections")

# Configuration
MAX_CONN_RATE = 1000  # Connections/second per IP
SYN_FLOOD_THRESHOLD = 500  # SYN packets/second
RULE_RELOAD_INTERVAL = 300  # 5 minutes

class FirewallRule(BaseModel):
    id: str
    priority: int
    action: str  # allow, deny, log
    direction: str  # in, out
    protocol: Optional[str] = None
    src_ips: List[str] = []
    dst_ips: List[str] = []
    ports: List[int] = []
    app_protocol: Optional[str] = None  # HTTP, gRPC, etc.
    expiry: Optional[datetime] = None
    conditions: Dict[str, Any] = {}

class ConnectionState:
    def __init__(self):
        self.syn_count = 0
        self.last_seen = 0.0
        self.rate_limited = False

class ZeroTrustFirewall:
    def __init__(self):
        self.rules: List[FirewallRule] = []
        self.conn_tracker: Dict[Tuple[str, int], ConnectionState] = defaultdict(ConnectionState)
        self.ip_reputation = self._load_ip_reputation()
        self.ml_model = self._load_ml_model()
        self.lock = asyncio.Lock()
        self.ssl_ctx = self._create_ssl_context()

        # Start background tasks
        asyncio.create_task(self._dynamic_rule_updater())
        asyncio.create_task(self._connection_cleaner())

    def _create_ssl_context(self):
        """TLS context for DPI"""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_alpn_protos(["http/1.1", "h2", "grpc"])
        return ctx

    async def process_packet(self, packet: bytes, direction: str) -> bool:
        """Core packet processing pipeline"""
        verdict = True  # Default allow
        
        try:
            eth = dpkt.ethernet.Ethernet(packet)
            ip = eth.data
            transport = ip.data

            src_ip = ip_address(ip.src).exploded
            dst_ip = ip_address(ip.dst).exploded
            src_port = transport.sport if hasattr(transport, 'sport') else 0
            dst_port = transport.dport if hasattr(transport, 'dport') else 0

            # Connection rate limiting
            if not await self._check_conn_rate(src_ip):
                FIREWALL_THREATS.labels(type="rate_limit").inc()
                return False

            # SYN flood detection
            if isinstance(transport, dpkt.tcp.TCP) and (transport.flags & dpkt.tcp.TH_SYN):
                await self._detect_syn_flood(src_ip)

            # Protocol-aware DPI
            app_proto = None
            if isinstance(transport, dpkt.tcp.TCP) and dst_port == 443:
                app_proto = await self._detect_app_protocol(packet)

            # Rule evaluation
            async with self.lock:
                for rule in sorted(self.rules, key=lambda r: -r.priority):
                    if self._match_rule(rule, src_ip, dst_ip, src_port, dst_port, app_proto, direction):
                        verdict = rule.action == "allow"
                        if rule.action == "log":
                            self._log_packet(packet, rule.id)
                        break

            # ML anomaly detection
            if verdict and self.ml_model:
                features = self._extract_features(packet, direction)
                if self.ml_model.predict(features) == "malicious":
                    FIREWALL_THREATS.labels(type="ml_anomaly").inc()
                    verdict = False

        except Exception as e:
            logger.error(f"Packet processing failed: {e}")
            verdict = False

        FIREWALL_PACKETS.labels(direction=direction, verdict=verdict).inc()
        return verdict

    async def _check_conn_rate(self, src_ip: str) -> bool:
        """Connection rate limiting with token bucket"""
        now = time.time()
        key = (src_ip, now // 1)  # Per-second window

        async with self.lock:
            state = self.conn_tracker[key]
            if state.rate_limited:
                return False
            state.syn_count += 1
            if state.syn_count > MAX_CONN_RATE:
                state.rate_limited = True
                return False
        return True

    async def _detect_syn_flood(self, src_ip: str):
        """SYN flood attack detection"""
        syn_counts = defaultdict(int)
        async with self.lock:
            for (ip, _), state in self.conn_tracker.items():
                if ip == src_ip:
                    syn_counts[ip] += state.syn_count

        if sum(syn_counts.values()) > SYN_FLOOD_THRESHOLD:
            logger.warning(f"SYN flood detected from {src_ip}")
            FIREWALL_THREATS.labels(type="syn_flood").inc()
            await self._block_ip(src_ip, "syn_flood", 3600)

    async def _block_ip(self, ip: str, reason: str, duration: int):
        """Dynamic IP blocking"""
        self.rules.append(
            FirewallRule(
                id=f"block_{ip}_{int(time.time())}",
                priority=1000,
                action="deny",
                direction="in",
                src_ips=[ip],
                conditions={"type": "auto_block", "reason": reason},
                expiry=datetime.fromtimestamp(time.time() + duration)
            )
        )

    async def _detect_app_protocol(self, packet: bytes) -> Optional[str]:
        """ALPN-based application protocol detection"""
        try:
            ssl_rec = dpkt.ssl.SSLRecord(packet)
            if isinstance(ssl_rec, dpkt.ssl.SSLHandshake):
                alpn = ssl_rec.data.extensions.get(16)  # ALPN extension ID
                return alpn.decode() if alpn else None
        except Exception:
            pass
        return None

    def _match_rule(self, rule: FirewallRule, src_ip: str, dst_ip: str, 
                   src_port: int, dst_port: int, app_proto: Optional[str], 
                   direction: str) -> bool:
        """Match packet against firewall rules"""
        if rule.direction != direction:
            return False
        if rule.protocol and not self._check_protocol(rule.protocol, packet):
            return False
        if rule.src_ips and not any(ip_address(src_ip) in ip_network(n) for n in rule.src_ips):
            return False
        if rule.dst_ips and not any(ip_address(dst_ip) in ip_network(n) for n in rule.dst_ips):
            return False
        if rule.ports and dst_port not in rule.ports:
            return False
        if rule.app_protocol and app_proto != rule.app_protocol:
            return False
        return True

    def _extract_features(self, packet: bytes, direction: str) -> Dict:
        """Feature extraction for ML model"""
        # Implement actual feature engineering
        return {
            "packet_size": len(packet),
            "protocol": "TCP" if isinstance(packet, dpkt.tcp.TCP) else "UDP",
            "direction": direction
        }

    async def _dynamic_rule_updater(self):
        """Periodically update rules from external sources"""
        while True:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get("https://rules.yoo-agent.com/api/v1/firewall") as resp:
                        new_rules = await resp.json()
                        async with self.lock:
                            self.rules = [FirewallRule(**r) for r in new_rules]
            except Exception as e:
                logger.error(f"Rule update failed: {e}")
            await asyncio.sleep(RULE_RELOAD_INTERVAL)

    async def _connection_cleaner(self):
        """Cleanup old connection states"""
        while True:
            now = time.time()
            async with self.lock:
                to_delete = [k for k, v in self.conn_tracker.items() 
                            if (now - v.last_seen) > 60]
                for k in to_delete:
                    del self.conn_tracker[k]
            await asyncio.sleep(60)

    def _load_ip_reputation(self) -> set:
        """Load malicious IP database"""
        # Implement actual IP reputation service integration
        return set()

    def _load_ml_model(self):
        """Load pre-trained anomaly detection model"""
        # Implement model loading (e.g., ONNX, TensorFlow Lite)
        return None

# Example Usage
async def main():
    firewall = ZeroTrustFirewall()
    with open("sample_traffic.pcap", "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            allowed = await firewall.process_packet(buf, direction="in")
            print(f"Packet allowed: {allowed}")

if __name__ == "__main__":
    asyncio.run(main())
