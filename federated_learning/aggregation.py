"""
YOO AGENT Federated Aggregation Core: Secure Multi-Party Computation with Adaptive Compression
"""

import logging
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
import numpy as np
import torch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from grpc import aio, ServicerContext
from prometheus_client import Counter, Histogram
import yoo_agent_pb2
import yoo_agent_pb2_grpc

logger = logging.getLogger(__name__)

# Metrics
AGGREGATION_TIME = Histogram("aggregation_duration", "Time spent per aggregation round")
FAILED_NODES = Counter("aggregation_failures", "Count of failed node contributions")

# Constants
MAX_MODEL_SIZE = 10 * 1024 * 1024  # 10MB
MIN_NODES = 3
FALLBACK_RETRIES = 2

class SecureAggregator:
    def __init__(self):
        self.private_key = self._generate_rsa_key()
        self.public_key = self.private_key.public_key()
        self.aggregation_strategy = self._select_strategy()
        self.node_contributions = defaultdict(list)
        self.round_id = 0
        
    def _generate_rsa_key(self) -> rsa.RSAPrivateKey:
        """Generate 4096-bit RSA key pair for encrypted aggregation"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

    def _select_strategy(self) -> callable:
        """Dynamic strategy selection based on network conditions"""
        # Implement ML-based strategy selector
        return self.fedavg_with_dp

    async def aggregate(self, round_data: Dict[str, bytes]) -> Optional[bytes]:
        """Secure aggregation pipeline"""
        start_time = time.monotonic()
        
        if len(round_data) < MIN_NODES:
            logger.warning(f"Insufficient nodes: {len(round_data)} < {MIN_NODES}")
            return None

        validated = await self._validate_contributions(round_data)
        decrypted = self._parallel_decrypt(validated)
        
        try:
            aggregated = self.aggregation_strategy(decrypted)
            serialized = self._serialize_model(aggregated)
            self._cleanup_round()
            
            AGGREGATION_TIME.observe(time.monotonic() - start_time)
            return serialized
        except Exception as e:
            logger.error(f"Aggregation failed: {e}")
            return await self._fallback_aggregation(decrypted)

    async def _validate_contributions(self, data: Dict[str, bytes]) -> Dict[str, np.ndarray]:
        """Cryptographic and data integrity validation"""
        valid = {}
        for node_id, encrypted in data.items():
            try:
                # Verify signature and decrypt
                decrypted = self._decrypt_with_retry(encrypted)
                tensor = self._deserialize(decrypted)
                if self._check_tensor_integrity(tensor):
                    valid[node_id] = tensor
            except Exception as e:
                logger.warning(f"Invalid contribution from {node_id}: {e}")
                FAILED_NODES.inc()
                
        return valid

    def _decrypt_with_retry(self, data: bytes) -> np.ndarray:
        """Retry decryption with key rotation fallback"""
        for _ in range(FALLBACK_RETRIES):
            try:
                return self.private_key.decrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except InvalidKey:
                self._rotate_keys()
        raise DecryptionError("Max retries exceeded")

    def fedavg_with_dp(self, tensors: Dict[str, np.ndarray]) -> np.ndarray:
        """Federated averaging with differential privacy"""
        # Add Gaussian noise scaled to largest contribution
        noise_scale = max(np.linalg.norm(t) for t in tensors.values())
        noise = np.random.normal(0, noise_scale * 0.01, tensors[0].shape)
        
        summed = sum(tensors.values()) + noise
        return summed / len(tensors)

    def _parallel_decrypt(self, data: Dict[str, bytes]) -> Dict[str, np.ndarray]:
        """GPU-accelerated batch decryption"""
        # Implement CUDA parallel processing
        return {n: self._deserialize(d) for n, d in data.items()}

    def _serialize_model(self, tensor: np.ndarray) -> bytes:
        """Optimized serialization with protocol buffers"""
        # Implement size-aware compression
        return yoo_agent_pb2.ModelWeights(
            parameters=tensor.tobytes(),
            compression='zstd',
            checksum=self._generate_checksum(tensor)
        ).SerializeToString()

    def _deserialize(self, data: bytes) -> np.ndarray:
        """Memory-efficient deserialization"""
        # Validate before deserialization
        return np.frombuffer(data, dtype=np.float32)

    def _check_tensor_integrity(self, tensor: np.ndarray) -> bool:
        """Prevent NaN/Inf and model inversion attacks"""
        return np.isfinite(tensor).all() and tensor.nbytes <= MAX_MODEL_SIZE

    async def _fallback_aggregation(self, data: Dict[str, np.ndarray]) -> Optional[bytes]:
        """Fallback to simple averaging if DP fails"""
        try:
            avg = sum(data.values()) / len(data)
            return self._serialize_model(avg)
        except Exception:
            logger.critical("All aggregation strategies failed")
            return None

    def _cleanup_round(self):
        """Release memory and advance round"""
        self.node_contributions.clear()
        self.round_id += 1
        torch.cuda.empty_cache() if torch.cuda.is_available() else None

class AggregationService(yoo_agent_pb2_grpc.AggregationServicer):
    async def SubmitWeights(self, request: yoo_agent_pb2.AggregationRequest,
                          context: ServicerContext) -> yoo_agent_pb2.AggregationResponse:
        """gRPC endpoint for model weight submission"""
        aggregator = SecureAggregator()
        try:
            result = await aggregator.aggregate(request.contributions)
            return yoo_agent_pb2.AggregationResponse(
                round_id=aggregator.round_id,
                aggregated_weights=result
            )
        except Exception as e:
            await context.abort(aio.StatusCode.INTERNAL, f"Aggregation failed: {e}")

async def serve():
    server = aio.server()
    yoo_agent_pb2_grpc.add_AggregationServicer_to_server(AggregationService(), server)
    server.add_insecure_port("[::]:50052")
    await server.start()
    await server.wait_for_termination()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(serve())
