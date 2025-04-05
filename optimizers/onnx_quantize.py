"""
NANEX AGENT ONNX Quantization Engine: Production-Grade Model Optimization with QAT Support
"""

import os
import logging
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import onnx
from onnxruntime.quantization import (
    QuantFormat,
    QuantType,
    quantize_dynamic,
    quantize_static,
    CalibrationDataReader,
)
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

# Security constants
MODEL_SIGNATURE_KEY = os.getenv("YOO_ONNX_SIGNING_KEY", "").encode()
QUANT_MIN_VERSION = "1.15.0"

class SecureONNXQuantizer:
    def __init__(
        self,
        model_path: str,
        calibration_data: Optional[np.ndarray] = None,
        quant_format: QuantFormat = QuantFormat.QDQ,
        opset_version: int = 15,
    ):
        self.model_path = Path(model_path)
        self.calibration_data = calibration_data
        self.quant_format = quant_format
        self.opset_version = opset_version
        self._metadata = {}
        self._validate_environment()

    def _validate_environment(self) -> None:
        """Verify runtime dependencies and security baseline"""
        import onnxruntime as ort
        if ort.__version__ < QUANT_MIN_VERSION:
            raise EnvironmentError(
                f"ONNX Runtime version {ort.__version__} < required {QUANT_MIN_VERSION}"
            )
        
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found: {self.model_path}")
            
        if not self._verify_model_signature():
            raise SecurityError("Model signature verification failed")

    def _verify_model_signature(self) -> bool:
        """HMAC-based model integrity check"""
        try:
            with open(self.model_path, "rb") as f:
                model_bytes = f.read()
                
            h = hmac.HMAC(MODEL_SIGNATURE_KEY, hashes.SHA256())
            h.update(model_bytes)
            h.verify(self.model_path.with_suffix(".sig").read_bytes())
            return True
        except Exception as e:
            logger.error(f"Signature validation failed: {str(e)}")
            return False

    def add_metadata(self, metadata: Dict[str, str]) -> None:
        """Add audit trail metadata for compliance"""
        self._metadata.update(metadata)

    def set_calibration_data(
        self, 
        data: np.ndarray,
        batch_size: int = 32,
        num_samples: int = 100
    ) -> None:
        """Generate representative calibration dataset"""
        if data.shape[0] < num_samples:
            raise ValueError("Insufficient data for calibration")
            
        indices = np.random.choice(data.shape[0], num_samples, replace=False)
        self.calibration_data = data[indices][:batch_size]

    def quantize(
        self,
        output_path: str,
        quant_type: QuantType = QuantType.QInt8,
        per_channel: bool = False,
        enable_encryption: bool = False,
    ) -> Dict[str, str]:
        """Perform secure quantization with post-processing"""
        # Load original model
        model = onnx.load(self.model_path)
        
        # Quantization workflow
        if self.calibration_data and self.quant_format == QuantFormat.QDQ:
            quantized_model = self._static_quantization(model)
        else:
            quantized_model = self._dynamic_quantization(model)
            
        # Post-quantization validation
        self._validate_quantized_model(quantized_model)
        
        # Security hardening
        if enable_encryption:
            quantized_model = self._encrypt_model(quantized_model)
            
        # Save artifacts
        model_bytes = quantized_model.SerializeToString()
        model_hash = self._save_quantized_model(model_bytes, output_path)
        
        return {
            "output_path": output_path,
            "original_size": self._get_file_size(self.model_path),
            "quantized_size": f"{len(model_bytes)/1024:.1f} KB",
            "sha256": model_hash,
            "metadata": self._metadata
        }

    def _static_quantization(self, model: onnx.ModelProto) -> onnx.ModelProto:
        """Static quantization with QDQ format"""
        class CalibrationReader(CalibrationDataReader):
            def __init__(self, data: np.ndarray):
                self.data = iter(data)
                
            def get_next(self) -> dict:
                try:
                    return {"input": next(self.data)}
                except StopIteration:
                    return None

        return quantize_static(
            model,
            calibration_data_reader=CalibrationReader(self.calibration_data),
            quant_format=self.quant_format,
            activation_type=QuantType.QInt8,
            weight_type=QuantType.QInt8,
            per_channel=per_channel,
            opset_version=self.opset_version,
        )

    def _dynamic_quantization(self, model: onnx.ModelProto) -> onnx.ModelProto:
        """Dynamic quantization with tensor type selection"""
        return quantize_dynamic(
            model,
            weight_type=QuantType.QInt8,
            per_channel=per_channel,
            optimize_model=True,
            use_external_data_format=False,
        )

    def _validate_quantized_model(self, model: onnx.ModelProto) -> None:
        """Validate quantized model structure and Opset"""
        from onnxruntime import InferenceSession, SessionOptions
        
        # Model structure checks
        assert len(model.graph.output) == len(onnx.load(self.model_path).graph.output), "Output mismatch"
        
        # Runtime validation
        options = SessionOptions()
        session = InferenceSession(model.SerializeToString(), options)
        
        # Test inference with dummy input
        sample_input = {session.get_inputs()[0].name: np.random.randn(*session.get_inputs()[0].shape).astype(np.float32)}
        try:
            session.run(None, sample_input)
        except Exception as e:
            raise RuntimeError(f"Quantized model validation failed: {str(e)}")

    def _encrypt_model(self, model: onnx.ModelProto) -> onnx.ModelProto:
        """AES-256-GCM model encryption with key derivation"""
        salt = os.urandom(16)
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"onnx_model_encryption",
        )
        key = kdf.derive(MODEL_SIGNATURE_KEY)
        nonce = os.urandom(12)
        
        # Serialize before encryption
        model_bytes = model.SerializeToString()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ct = encryptor.update(model_bytes) + encryptor.finalize()
        
        # Rebuild encrypted ONNX model
        encrypted_model = onnx.ModelProto()
        encrypted_model.graph.initializer.add().name = "encrypted_data"
        encrypted_model.graph.initializer[-1].raw_data = salt + nonce + encryptor.tag + ct
        return encrypted_model

    def _save_quantized_model(self, model_bytes: bytes, path: str) -> str:
        """Save model with metadata and integrity checks"""
        model_hash = hashlib.sha256(model_bytes).hexdigest()
        self._metadata.update({
            "quantization_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "quant_format": str(self.quant_format),
            "opset_version": self.opset_version
        })
        
        # Save main model
        with open(path, "wb") as f:
            f.write(model_bytes)
            
        # Save metadata sidecar
        meta_path = Path(path).with_suffix(".meta")
        with open(meta_path, "w") as f:
            json.dump(self._metadata, f, indent=2)
            
        return model_hash

    @staticmethod
    def _get_file_size(path: Path) -> str:
        """Get human-readable file size"""
        size = path.stat().st_size
        return f"{size/1024:.1f} KB"

    @staticmethod
    def generate_signature(model_path: str) -> None:
        """Generate HMAC signature for model file"""
        with open(model_path, "rb") as f:
            data = f.read()
            
        h = hmac.HMAC(MODEL_SIGNATURE_KEY, hashes.SHA256())
        h.update(data)
        sig_path = Path(model_path).with_suffix(".sig")
        sig_path.write_bytes(h.finalize())

class SecurityError(Exception):
    """Custom security violation exception"""

# Example usage
if __name__ == "__main__":
    # Initialize quantizer
    quantizer = SecureONNXQuantizer(
        model_path="model.onnx",
        calibration_data=np.random.randn(100, 3, 224, 224).astype(np.float32),
        quant_format=QuantFormat.QDQ
    )
    
    # Add compliance metadata
    quantizer.add_metadata({
        "framework": "PyTorch 2.0",
        "training_epochs": "100",
        "privacy_level": "DP-Enabled"
    })
    
    # Perform quantization
    result = quantizer.quantize(
        output_path="quantized_model.onnx",
        enable_encryption=True
    )
    
    print(f"Quantization successful: {result}")
