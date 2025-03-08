"""
YOO AGENT Mutual TLS Engine: Certificate Mutual Authentication with Dynamic Rotation
"""

import os
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional, Union
import hashlib
import watchfiles

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus
from cryptography.x509 import ocsp
import aiofiles
import aiohttp

# Constants
CERT_ROTATION_THRESHOLD = timedelta(hours=4)
OCSP_CACHE_TTL = 3600  # 1 hour
CRL_REFRESH_INTERVAL = 1800  # 30 minutes
PINNED_CERT_STORE = "/etc/yoo-agent/certs"
TLS_SESSION_TICKET_LIFETIME = 28800  # 8 hours

class CertManager:
    def __init__(self):
        self._cert_chain: Optional[bytes] = None
        self._private_key: Optional[rsa.RSAPrivateKey] = None
        self._issuer_cert: Optional[x509.Certificate] = None
        self._crl: Optional[x509.CertificateRevocationList] = None
        self._ocsp_cache: Dict[bytes, Tuple[datetime, bool]] = {}
        self._cert_fingerprints: Dict[str, str] = {}
        self._session_tickets: Dict[bytes, datetime] = {}
        
        self._load_initial_certs()
        self._start_background_tasks()

    def _load_initial_certs(self):
        """Load certificates from secure storage"""
        try:
            with open(f"{PINNED_CERT_STORE}/server.pem", "rb") as f:
                self._cert_chain = f.read()
            with open(f"{PINNED_CERT_STORE}/server_key.pem", "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            with open(f"{PINNED_CERT_STORE}/issuer.pem", "rb") as f:
                self._issuer_cert = x509.load_pem_x509_certificate(f.read())
        except FileNotFoundError as e:
            logging.critical(f"Certificate initialization failed: {str(e)}")
            raise

    def _start_background_tasks(self):
        """Initiate periodic security tasks"""
        loop = asyncio.get_event_loop()
        loop.create_task(self._watch_cert_changes())
        loop.create_task(self._refresh_crl())
        loop.create_task(self._cleanup_session_tickets())

    async def _watch_cert_changes(self):
        """Monitor certificate directory for updates"""
        async for changes in watchfiles.awatch(PINNED_CERT_STORE):
            for change in changes:
                if change[1].endswith(".pem"):
                    logging.info("Reloading updated certificates")
                    self._load_initial_certs()

    async def _refresh_crl(self):
        """Download and validate Certificate Revocation List"""
        async with aiohttp.ClientSession() as session:
            while True:
                try:
                    crl_url = self._issuer_cert.extensions.get_extension_for_class(
                        x509.CRLDistributionPoints
                    ).value[0].full_name[0].value
                    
                    async with session.get(crl_url) as resp:
                        crl_data = await resp.read()
                        self._crl = x509.load_der_x509_crl(crl_data)
                        
                except Exception as e:
                    logging.error(f"CRL refresh failed: {str(e)}")
                
                await asyncio.sleep(CRL_REFRESH_INTERVAL)

    async def _cleanup_session_tickets(self):
        """Remove expired TLS session tickets"""
        while True:
            now = datetime.utcnow()
            expired = [
                ticket for ticket, expiry in self._session_tickets.items()
                if expiry < now
            ]
            for ticket in expired:
                del self._session_tickets[ticket]
            await asyncio.sleep(3600)  # Clean hourly

    def get_server_context(self) -> Tuple[bytes, rsa.RSAPrivateKey]:
        """Retrieve current server certificate and key"""
        return self._cert_chain, self._private_key

    def generate_session_ticket(self) -> bytes:
        """Create TLS session ticket for resumption"""
        ticket = os.urandom(48)
        expiry = datetime.utcnow() + timedelta(seconds=TLS_SESSION_TICKET_LIFETIME)
        self._session_tickets[ticket] = expiry
        return ticket

    def validate_session_ticket(self, ticket: bytes) -> bool:
        """Verify TLS session ticket validity"""
        expiry = self._session_tickets.get(ticket)
        return expiry and expiry > datetime.utcnow()

    async def validate_client_cert(self, cert: x509.Certificate) -> bool:
        """Perform comprehensive client certificate validation"""
        # Check certificate chain
        if not self._verify_chain(cert):
            return False
        
        # Check revocation status
        if await self._is_revoked(cert):
            return False
            
        # Check OCSP status
        if not await self._check_ocsp(cert):
            return False
            
        return True

    def _verify_chain(self, cert: x509.Certificate) -> bool:
        """Validate certificate chain against trusted issuer"""
        try:
            cert.verify_directly_issued_by(self._issuer_cert)
            return True
        except x509.InvalidCertificateError:
            logging.warning("Certificate chain validation failed")
            return False

    async def _is_revoked(self, cert: x509.Certificate) -> bool:
        """Check CRL and OCSP for revocation status"""
        # Check CRL first
        if self._crl:
            for revoked in self._crl:
                if revoked.serial_number == cert.serial_number:
                    return True
        
        # Fallback to OCSP
        return not await self._check_ocsp(cert)

    async def _check_ocsp(self, cert: x509.Certificate) -> bool:
        """Verify certificate via OCSP with caching"""
        cert_fp = hashlib.sha256(cert.tbs_certificate_bytes).digest()
        
        # Check cache
        cached = self._ocsp_cache.get(cert_fp)
        if cached and cached[0] > datetime.utcnow():
            return cached[1]
            
        # Build OCSP request
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(cert, self._issuer_cert)
        req = builder.build()
        
        # Query OCSP responder
        try:
            ocsp_url = cert.extensions.get_extension_for_class(
                x509.AuthorityInformationAccess
            ).value[0].access_location.value
                
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    ocsp_url,
                    data=req.public_bytes(serialization.Encoding.DER),
                    headers={"Content-Type": "application/ocsp-request"}
                ) as resp:
                    ocsp_resp = await resp.read()
                    response = ocsp.load_der_ocsp_response(ocsp_resp)
                    
                    if response.response_status == OCSPResponseStatus.SUCCESSFUL:
                        valid = (
                            response.certificate_status == ocsp.OCSPCertStatus.GOOD
                        )
                        expiry = datetime.utcnow() + timedelta(seconds=OCSP_CACHE_TTL)
                        self._ocsp_cache[cert_fp] = (expiry, valid)
                        return valid
        except Exception as e:
            logging.error(f"OCSP check failed: {str(e)}")
            return False

class MutualTLSMiddleware:
    def __init__(self, cert_manager: CertManager):
        self.cert_manager = cert_manager
        
    async def __call__(self, request, handler):
        """ASGI middleware implementation for mutual TLS"""
        # Extract client certificate from connection
        client_cert = request.scope.get("client_cert")
        if not client_cert:
            logging.warning("Missing client certificate")
            return self._deny_request()
            
        # Validate certificate
        if not await self.cert_manager.validate_client_cert(client_cert):
            return self._deny_request()
            
        # Enforce certificate pinning
        cert_fp = hashlib.sha256(client_cert.tbs_certificate_bytes).hexdigest()
        if cert_fp not in self.cert_manager._cert_fingerprints:
            logging.warning(f"Untrusted certificate fingerprint: {cert_fp}")
            return self._deny_request()
            
        # Process request
        return await handler(request)
        
    def _deny_request(self):
        """Reject unauthorized requests"""
        return aiohttp.web.Response(status=403, text="Invalid client certificate")

# Example Usage
if __name__ == "__main__":
    manager = CertManager()
    middleware = MutualTLSMiddleware(manager)
    
    # Example ASGI app setup
    app = aiohttp.web.Application(middlewares=[middleware])
    
    # Configure TLS parameters
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(*manager.get_server_context())
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ssl_context.load_verify_locations(cafile=f"{PINNED_CERT_STORE}/issuer.pem")
    
    aiohttp.web.run_app(app, ssl_context=ssl_context)
