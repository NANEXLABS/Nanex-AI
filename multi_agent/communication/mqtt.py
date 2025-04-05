"""
NANEX AGENT MQTT Core: Zero-Trust IoT Protocol Engine with Hardware Security Module (HSM) Integration
"""

import asyncio
import logging
import json
import os
import hashlib
import struct
from typing import Dict, Optional, Callable, Awaitable

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_private_key

# Custom modules
from .jwt_rotation import JWTValidator
from .policy_engine import ABACPolicyChecker
from .memory import SecureMemoryAllocator

logger = logging.getLogger(__name__)

class MQTTSecurityError(Exception):
    """Base exception for protocol violations"""

class ZeroTrustMQTTClient:
    def __init__(self, 
                 client_id: str,
                 broker: str = "mqtts://edge.yoo-agent.io:8883",
                 hsm_slot: int = 0,
                 qos: int = 1):
        
        self.client_id = client_id
        self.broker = broker
        self.hsm_slot = hsm_slot
        self.qos = qos
        
        # Security components
        self.jwt_validator = JWTValidator()
        self.abac_checker = ABACPolicyChecker()
        self.secure_mem = SecureMemoryAllocator()
        
        # ECDH key exchange state
        self.eph_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.shared_secret = None
        
        # MQTT client configuration
        self.client = mqtt.Client(
            client_id=client_id,
            protocol=mqtt.MQTTv5,
            transport="tcp"
        )
        
        self._configure_callbacks()
        self._enable_hardware_acceleration()

    def _configure_callbacks(self):
        """Attach security-enhanced callback handlers"""
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect

    def _enable_hardware_acceleration(self):
        """Optimize cryptographic operations using hardware modules"""
        if os.path.exists(f"/dev/cryptohsm{self.hsm_slot}"):
            os.environ["CRYPTOGRAPHY_OPENSSL_DYNAMIC_LOADING"] = "1"
            self.eph_key = load_der_private_key(
                open(f"/dev/cryptohsm{self.hsm_slot}/ec_priv.der", "rb").read(),
                password=None,
                backend=default_backend()
            )

    def _derive_session_key(self, peer_pubkey: ec.EllipticCurvePublicKey) -> bytes:
        """ECDH-P384 key derivation with HKDF-SHA384"""
        self.shared_secret = self.eph_key.exchange(ec.ECDH(), peer_pubkey)
        return HKDF(
            algorithm=hashes.SHA384(),
            length=64,
            salt=None,
            info=b"yoo-agent-mqtt-session",
            backend=default_backend()
        ).derive(self.shared_secret)

    def _encrypt_payload(self, plaintext: bytes) -> bytes:
        """AES-256-GCM encryption with session keys"""
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self.session_key[:32]),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext + encryptor.tag

    def _decrypt_payload(self, ciphertext: bytes) -> bytes:
        """AES-256-GCM decryption with session keys"""
        iv = ciphertext[:12]
        tag = ciphertext[-16:]
        ciphertext = ciphertext[12:-16]
        
        cipher = Cipher(
            algorithms.AES(self.session_key[:32]),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _sign_handshake(self) -> bytes:
        """ECDSA-SHA384 signature for MQTT CONNECT message"""
        return self.eph_key.sign(
            self.client_id.encode(),
            ec.ECDSA(hashes.SHA384())
        )

    async def _authenticate_broker(self, 
                                 username: Optional[str], 
                                 password: Optional[str]) -> None:
        """Mutual TLS + JWT authentication workflow"""
        # Phase 1: ECDH Key Exchange
        broker_pubkey = await self._fetch_broker_certificate()
        self.session_key = self._derive_session_key(broker_pubkey)
        
        # Phase 2: Client Authentication
        jwt_token = self.jwt_validator.issue_device_token(self.client_id)
        self.client.username_pw_set(
            username=jwt_token,
            password=self._sign_handshake().hex()
        )

    async def _authorize_operation(self, 
                                 topic: str, 
                                 operation: str) -> None:
        """ABAC policy check for publish/subscribe"""
        await self.abac_checker.check(
            subject={"client_id": self.client_id},
            resource=topic,
            action=operation
        )

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        """Secure connection handler with zero-trust validation"""
        if rc != mqtt.MQTT_ERR_SUCCESS:
            raise MQTTSecurityError(f"Broker authentication failed: {mqtt.error_string(rc)}")
        
        logger.info(f"Secure MQTT connection established to {self.broker}")

    def _on_message(self, client, userdata, msg):
        """Zero-trust message processing pipeline"""
        try:
            # Step 1: Decrypt payload
            decrypted = self._decrypt_payload(msg.payload)
            
            # Step 2: Verify message integrity
            h = hmac.HMAC(self.session_key[32:], hashes.SHA384(), backend=default_backend())
            h.update(decrypted)
            h.verify(msg.properties.get('hmac', b''))
            
            # Step 3: Process application payload
            self.message_handler(msg.topic, decrypted)
            
        except MQTTSecurityError as e:
            logger.warning(f"Blocked insecure message on {msg.topic}: {str(e)}")

    def _on_disconnect(self, client, userdata, rc, properties=None):
        """Graceful disconnection handler"""
        self.secure_mem.wipe(self.session_key)
        logger.info("Session terminated securely")

    def set_message_handler(self, 
                          handler: Callable[[str, bytes], Awaitable[None]]) -> None:
        """Register application message processor"""
        self.message_handler = handler

    async def connect(self) -> None:
        """Establish zero-trust MQTT connection"""
        self.client.tls_set(
            ca_certs="/etc/yoo-agent/certs/ca-chain.pem",
            certfile=f"/etc/yoo-agent/certs/{self.client_id}.crt",
            keyfile=f"/etc/yoo-agent/certs/{self.client_id}.key",
            tls_version=2  # TLS 1.2+
        )
        await self._authenticate_broker(None, None)
        self.client.connect_async(self.broker.split("//")[1].split(":")[0], 
                                int(self.broker.split(":")[-1]))
        self.client.loop_start()

    async def publish(self, 
                    topic: str, 
                    payload: bytes, 
                    retain: bool = False) -> None:
        """Secure publication workflow"""
        await self._authorize_operation(topic, "publish")
        
        # Step 1: HMAC-SHA384 integrity protection
        h = hmac.HMAC(self.session_key[32:], hashes.SHA384(), backend=default_backend())
        h.update(payload)
        mac = h.finalize()
        
        # Step 2: AES-256-GCM encryption
        encrypted = self._encrypt_payload(payload)
        
        # Step 3: Secure publication
        info = self.client.publish(
            topic=topic,
            payload=encrypted,
            qos=self.qos,
            retain=retain,
            properties={'hmac': mac}
        )
        info.wait_for_publish()

    async def subscribe(self, topic: str) -> None:
        """Authorization-enforced subscription"""
        await self._authorize_operation(topic, "subscribe")
        self.client.subscribe(topic, qos=self.qos)

    async def disconnect(self) -> None:
        """Terminate connection with key material wipe"""
        self.client.disconnect()
        self.client.loop_stop()

# Example usage
if __name__ == "__main__":
    async def sample_handler(topic: str, payload: bytes):
        print(f"Received secure message on {topic}: {payload.decode()}")
    
    client = ZeroTrustMQTTClient(
        client_id="edge-sensor-01",
        broker="mqtts://iot.yoo-agent.io:8883",
        qos=2
    )
    client.set_message_handler(sample_handler)
    
    async def run():
        await client.connect()
        await client.subscribe("sensors/+/telemetry")
        await client.publish("sensors/01/telemetry", b"22.5C, 60%")
        await asyncio.sleep(10)
        await client.disconnect()
    
    asyncio.run(run())
