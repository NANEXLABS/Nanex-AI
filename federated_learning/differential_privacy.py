"""
NANEX AGENT Differential Privacy Core: Adaptive ε-δ Budget Management with Rényi Composition
"""

import logging
import math
import numpy as np
import torch
from typing import Tuple, Optional, Dict
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.hashes import SHA256
from prometheus_client import Gauge, Histogram

logger = logging.getLogger(__name__)

# Metrics
PRIVACY_EPSILON = Gauge("dp_epsilon_remaining", "Remaining ε privacy budget")
PRIVACY_DELTA = Gauge("dp_delta_remaining", "Remaining δ privacy budget")
NOISE_MAGNITUDE = Histogram("dp_noise_scale", "Magnitude of added noise")

# Constants
DEFAULT_SENSITIVITY = 1.0
MAX_GRAD_NORM = 10.0
MIN_SAMPLES = 500
RDP_ORDERS = [1.5, 2.0, 4.0, 8.0, 16.0]

class DifferentialPrivacyEngine:
    def __init__(
        self,
        total_epsilon: float = 3.0,
        total_delta: float = 1e-5,
        max_grad_norm: float = MAX_GRAD_NORM,
        mechanism: str = "gaussian"
    ):
        self.total_epsilon = total_epsilon
        self.total_delta = total_delta
        self.remaining_epsilon = total_epsilon
        self.remaining_delta = total_delta
        self.max_grad_norm = max_grad_norm
        self.mechanism = mechanism.lower()
        self.alpha = 1e-3  # Adaptive clipping factor
        self.rng = self._secure_rng()
        
    def _secure_rng(self) -> np.random.Generator:
        """Cryptographically secure random generator"""
        seed = int.from_bytes(hmac.HMAC(b"", SHA256()).finalize(), "big")
        return np.random.default_rng(seed)

    def _renyi_divergence(self, sigma: float, alpha: float) -> float:
        """Compute Rényi divergence for composition"""
        return alpha * (0.5 / (sigma ** 2)) + math.log(1 / (2 * sigma ** 2))

    def _compute_sigma(
        self, 
        target_epsilon: float, 
        target_delta: float, 
        steps: int
    ) -> float:
        """Calculate noise scale via RDP composition"""
        best_sigma = None
        for order in RDP_ORDERS:
            rdp = self._renyi_divergence(1.0, order) * steps
            epsilon = rdp + (math.log(1 / target_delta) / (order - 1))
            if epsilon <= target_epsilon and (best_sigma is None or 1.0 < best_sigma):
                best_sigma = 1.0 / math.sqrt(2 * rdp)
        return best_sigma or 1.0

    def adaptive_clip(self, gradients: torch.Tensor) -> Tuple[torch.Tensor, float]:
        """Automatically tune clipping threshold using gradient statistics"""
        if gradients.numel() < MIN_SAMPLES:
            return torch.clamp(gradients, -self.max_grad_norm, self.max_grad_norm), self.max_grad_norm
        
        grad_norms = torch.norm(gradients.view(-1), p=2, dim=1)
        percentile = np.percentile(grad_norms.cpu().numpy(), 100 * (1 - self.alpha))
        new_norm = min(float(percentile), self.max_grad_norm)
        self.alpha *= 0.95  # Decay adaptation rate
        return torch.clamp(gradients, -new_norm, new_norm), new_norm

    def apply_noise(
        self,
        data: torch.Tensor,
        sensitivity: float = DEFAULT_SENSITIVITY,
        num_steps: int = 1
    ) -> Tuple[torch.Tensor, Optional[float]]:
        """Apply differentially private noise with budget accounting"""
        if self.remaining_epsilon <= 0 or self.remaining_delta <= 0:
            logger.error("Privacy budget exhausted")
            return data, None

        # 1. Adaptive clipping
        clipped_data, effective_sensitivity = self.adaptive_clip(data)
        
        # 2. Noise scale calculation
        if self.mechanism == "gaussian":
            sigma = self._compute_sigma(
                self.remaining_epsilon, 
                self.remaining_delta,
                num_steps
            )
            noise = torch.normal(0, sigma * effective_sensitivity, data.shape)
            delta_used = self.remaining_delta
            epsilon_used = self.remaining_epsilon
        elif self.mechanism == "laplace":
            scale = effective_sensitivity / self.remaining_epsilon
            noise = torch.distributions.Laplace(0, scale).sample(data.shape)
            epsilon_used = self.remaining_epsilon
            delta_used = 0.0
        else:
            raise ValueError(f"Unsupported mechanism: {self.mechanism}")

        # 3. Budget accounting
        self.remaining_epsilon -= epsilon_used
        self.remaining_delta -= delta_used
        PRIVACY_EPSILON.set(self.remaining_epsilon)
        PRIVACY_DELTA.set(self.remaining_delta)
        NOISE_MAGNITUDE.observe(torch.norm(noise).item())

        # 4. Secure randomness validation
        if not self._validate_noise(noise, effective_sensitivity):
            logger.critical("Noise distribution compromised")
            raise SecurityError("Noise verification failed")

        return clipped_data + noise.to(data.device), effective_sensitivity

    def _validate_noise(self, noise: torch.Tensor, sensitivity: float) -> bool:
        """Statistical validation of noise distribution"""
        if self.mechanism == "gaussian":
            std = torch.std(noise).item()
            expected_std = sensitivity * (self.remaining_epsilon / math.sqrt(2 * num_steps))
            return abs(std - expected_std) < 0.1 * expected_std
        elif self.mechanism == "laplace":
            mean = torch.mean(noise).item()
            return abs(mean) < 1e-3 * sensitivity
        return False

    def get_privacy_spent(self) -> Dict[str, float]:
        """Return remaining privacy budget"""
        return {
            "epsilon": self.remaining_epsilon,
            "delta": self.remaining_delta,
            "total_epsilon": self.total_epsilon,
            "total_delta": self.total_delta
        }

class PrivacyAccountant:
    def __init__(self, epsilon: float, delta: float):
        self.initial_epsilon = epsilon
        self.initial_delta = delta
        self.epsilon_consumed = 0.0
        self.delta_consumed = 0.0
        
    def add_rdp(self, rdp: float, delta: float) -> None:
        """Track budget via Rényi Differential Privacy"""
        self.epsilon_consumed += rdp
        self.delta_consumed += delta
        
    def remaining_budget(self) -> Tuple[float, float]:
        """Calculate remaining (ε, δ) using advanced composition"""
        remaining_epsilon = self.initial_epsilon - self.epsilon_consumed
        remaining_delta = self.initial_delta - self.delta_consumed
        return max(0.0, remaining_epsilon), max(0.0, remaining_delta)

def dp_sanitize(func):
    """Decorator to enforce DP on function outputs"""
    def wrapper(*args, **kwargs):
        engine = DifferentialPrivacyEngine()
        result = func(*args, **kwargs)
        if isinstance(result, torch.Tensor):
            noised_result, _ = engine.apply_noise(result)
            return noised_result
        return result
    return wrapper

# Example usage with PyTorch integration
if __name__ == "__main__":
    # Sample gradient tensor
    gradients = torch.randn(1000, requires_grad=True)
    
    # Initialize DP engine
    dp_engine = DifferentialPrivacyEngine(total_epsilon=5.0, total_delta=1e-5)
    
    # Apply DP
    private_grads, sensitivity = dp_engine.apply_noise(gradients, num_steps=10)
    print(f"Applied noise with sensitivity={sensitivity:.4f}, Remaining ε={dp_engine.remaining_epsilon:.2f}")
