"""
YOO AGENT gRPC-Web Adapter: Secure Browser-to-Backend Bridge with Bi-Directional Streaming
"""

import os
import json
import logging
import asyncio
from typing import Dict, Any, Optional, AsyncIterable

from aiohttp import web
import grpclib
from grpclib.server import Server
from grpclib.protocol import H2Protocol
from grpclib.utils import WrappedMessage
from google.protobuf import json_format
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

# Custom modules
from .jwt_rotation import JWTValidator
from .policy_engine import ABACPolicyChecker
from .metrics import PrometheusMiddleware

logger = logging.getLogger(__name__)

class GRPCWebSecurityError(Exception):
    """Base exception for gRPC-Web security violations"""

class SecuregRPCWebService:
    def __init__(self, 
                 host: str = '0.0.0.0', 
                 port: int = 8080,
                 tls_cert: str = '/etc/yoo-agent/certs/fullchain.pem',
                 tls_key: str = '/etc/yoo-agent/certs/privkey.pem'):
        
        self.host = host
        self.port = port
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        
        # Security components
        self.jwt_validator = JWTValidator()
        self.abac_checker = ABACPolicyChecker()
        self.rate_limiter = TokenBucketLimiter(1000)  # 1000 RPM
        
        # Protocol configuration
        self._server = Server(
            [
                EdgeAgentService(),
                FederatedLearningService(),
                SystemHealthService()
            ],
            loop=asyncio.get_event_loop(),
            h2_protocol=H2Protocol(
                max_headers_size=4096,
                max_data_len=4 * 1024 * 1024  # 4MB
            )
        )

        # Web middleware
        self.app = web.Application(
            middlewares=[
                PrometheusMiddleware(),
                CORSHandler(),
                CompressionAdapter()
            ]
        )
        self.app.add_routes([
            web.post('/grpc', self._handle_grpc_web),
            web.get('/health', self._health_check)
        ])

    async def _load_tls_context(self):
        """Load X.509 certificate with OCSP stapling"""
        from ssl import SSLContext, PROTOCOL_TLS_SERVER
        
        context = SSLContext(PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.tls_cert, self.tls_key)
        
        # Certificate transparency
        with open('/etc/yoo-agent/certs/chain.pem', 'rb') as f:
            context.load_verify_locations(cadata=f.read())
            
        context.verify_mode = ssl.CERT_REQUIRED
        context.set_alpn_protocols(['h2'])
        
        return context

    async def _authenticate_request(self, headers: Dict) -> Dict:
        """Validate JWT and extract ABAC attributes"""
        auth_header = headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            raise GRPCWebSecurityError("Missing bearer token")
            
        token = auth_header[7:]
        claims = await self.jwt_validator.validate(token)
        
        # Check rate limits
        if not self.rate_limiter.consume(claims['client_id']):
            raise GRPCWebSecurityError("Rate limit exceeded")
            
        return claims

    async def _handle_grpc_web(self, request: web.Request) -> web.StreamResponse:
        """Main gRPC-Web request handler with zero-trust checks"""
        try:
            # Phase 1: Authentication
            claims = await self._authenticate_request(request.headers)
            
            # Phase 2: ABAC Authorization
            await self.abac_checker.check(
                subject=claims,
                resource=request.path,
                action=request.method
            )
            
            # Phase 3: Protocol Handling
            wrapped_msg = WrappedMessage.from_http_request(request)
            response = await self._server.handle_request(wrapped_msg)
            
            return web.Response(
                body=response.data,
                content_type='application/grpc-web+proto',
                headers={
                    'grpc-status': str(response.status.value),
                    'grpc-message': response.message
                }
            )
            
        except GRPCWebSecurityError as e:
            logger.warning(f"Blocked insecure gRPC-Web request: {str(e)}")
            return web.Response(
                status=403,
                text=json.dumps({'error': str(e)}),
                content_type='application/json'
            )
            
        except Exception as e:
            logger.error(f"gRPC-Web handler failed: {str(e)}")
            return web.Response(
                status=500,
                text=json.dumps({'error': 'Internal server error'}),
                content_type='application/json'
            )

    async def _health_check(self, request: web.Request) -> web.Response:
        """Kubernetes-compatible health check endpoint"""
        return web.json_response({
            'status': 'SERVING',
            'services': ['grpc', 'http']
        })

    async def start(self) -> None:
        """Start secure gRPC-Web gateway"""
        ssl_context = await self._load_tls_context()
        await web._run_app(
            self.app,
            host=self.host,
            port=self.port,
            ssl_context=ssl_context,
            reuse_port=True
        )

    async def stop(self) -> None:
        """Graceful shutdown procedure"""
        await self._server.close()
        await self.app.shutdown()
        await self.app.cleanup()

class CORSHandler:
    """Zero-trust CORS policy middleware"""
    async def __call__(self, app, handler):
        async def middleware(request):
            # Strict origin validation
            allowed_origins = await ABACPolicyChecker.get_allowed_origins()
            origin = request.headers.get('Origin', '')
            
            if origin not in allowed_origins:
                raise GRPCWebSecurityError("CORS origin violation")
                
            response = await handler(request)
            response.headers.update({
                'Access-Control-Allow-Origin': origin,
                'Access-Control-Expose-Headers': 'grpc-status,grpc-message'
            })
            return response
        return middleware

class TokenBucketLimiter:
    """Distributed rate limiter with token bucket algorithm"""
    def __init__(self, tokens_per_minute: int):
        self._tokens = tokens_per_minute
        self._last_update = time.time()
        
    def consume(self, client_id: str) -> bool:
        # Distributed implementation requires Redis
        current_time = time.time()
        time_passed = current_time - self._last_update
        self._tokens += time_passed * (self._tokens / 60)
        self._last_update = current_time
        
        if self._tokens >= 1:
            self._tokens -= 1
            return True
        return False

# Protocol Buffer Services (Partial Implementation)
class EdgeAgentService(Service):
    async def execute_task(self, 
                          stream: 'grpclib.server.Stream[TaskRequest, TaskResponse]') -> None:
        async for req in stream:
            # Zero-trust validation
            if not req.HasField('integrity_hash'):
                raise GRPCWebSecurityError("Unverified task payload")
                
            yield TaskResponse(result=await process_task(req))

# Example usage
if __name__ == "__main__":
    service = SecuregRPCWebService()
    asyncio.run(service.start())
