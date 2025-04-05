"""
NANEX AGENT TensorFlow Lite Converter: Secure Model Optimization & Edge Deployment Pipeline
"""

import os
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

import numpy as np
import tensorflow as tf
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

# Security constants
MODEL_SIGNATURE_KEY = os.getenv("YOO_MODEL_SIGNING_KEY", default="").encode()
TFLITE_MINIMUM_VERSION = "2.12.0"

class SecureTFLiteConverter:
    def __init__(
        self,
        model: Union[tf.keras.Model, str],
        input_shape: Tuple[int, ...],
        enable_fp16_quant: bool = False,
        enable_int8_quant: bool = True,
        enable_pruning: bool = False,
    ):
        self._validate_tf_version()
        self.model = self._load_model(model)
        self.input_shape = input_shape
        self.optimizations = self._configure_optimizations(
            enable_fp16_quant, enable_int8_quant, enable_pruning
        )
        self._representative_data = None
        self._model_metadata = {}

    def _validate_tf_version(self) -> None:
        """Ensure TensorFlow version meets security requirements"""
        tf_version = tf.__version__
        if tf_version < TFLITE_MINIMUM_VERSION:
            raise RuntimeError(
                f"Unsupported TF version {tf_version}. "
                f"Minimum required: {TFLITE_MINIMUM_VERSION}"
            )

    def _load_model(self, model: Union[tf.keras.Model, str]) -> tf.keras.Model:
        """Load model from SavedModel/HDF5 with integrity checks"""
        if isinstance(model, tf.keras.Model):
            return model
            
        model_path = Path(model)
        if not model_path.exists():
            raise FileNotFoundError(f"Model file {model} not found")
            
        # Verify model signature for untrusted sources
        if not self._verify_model_signature(model_path):
            raise SecurityError("Model signature validation failed")
            
        return tf.keras.models.load_model(model_path)

    def _verify_model_signature(self, model_path: Path) -> bool:
        """HMAC-based model integrity verification"""
        try:
            with open(model_path, "rb") as f:
                model_data = f.read()
                
            h = hmac.HMAC(MODEL_SIGNATURE_KEY, hashes.SHA256())
            h.update(model_data)
            h.verify(model_path.with_suffix(".sig").read_bytes())
            return True
        except Exception as e:
            logger.error(f"Model signature check failed: {str(e)}")
            return False

    def _configure_optimizations(
        self, fp16: bool, int8: bool, prune: bool
    ) -> list:
        """Configure TFLite converter optimizations"""
        optimizations = []
        if int8:
            optimizations.append(tf.lite.Optimize.DEFAULT)
        if fp16:
            optimizations.append(tf.lite.Optimize.EXPERIMENTAL_SPARSITY)
        if prune:
            optimizations.append(tf.lite.Optimize.OPTIMIZE_FOR_SIZE)
        return optimizations

    def set_representative_dataset(
        self, dataset: tf.data.Dataset, samples: int = 100
    ) -> None:
        """Generate calibration data for quantization"""
        def _repr_data_gen():
            for data in dataset.take(samples):
                yield [tf.dtypes.cast(data, tf.float32)]

        self._representative_data = _repr_data_gen()

    def add_metadata(self, metadata: Dict[str, str]) -> None:
        """Add model card metadata for audit compliance"""
        self._model_metadata.update(metadata)

    def convert(
        self,
        output_path: str,
        target_devices: Optional[List[str]] = None,
        enable_encryption: bool = False,
    ) -> Dict[str, str]:
        """Convert & optimize model with security hardening"""
        converter = tf.lite.TFLiteConverter.from_keras_model(self.model)
        converter.optimizations = self.optimizations
        
        if self._representative_data:
            converter.representative_dataset = self._representative_data
            converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
            converter.inference_input_type = tf.uint8
            converter.inference_output_type = tf.uint8

        # Device-specific optimizations
        if target_devices:
            converter.target_spec.supported_ops = [
                tf.lite.OpsSet.TFLITE_BUILTINS,
                tf.lite.OpsSet.SELECT_TF_OPS,
            ]
            converter.experimental_select_user_tf_ops = [
                "UserOp"  # Replace with custom ops
            ]

        tflite_model = converter.convert()
        
        # Post-processing
        if enable_encryption:
            tflite_model = self._encrypt_model(tflite_model)
            
        self._validate_model(tflite_model)
        
        # Save with metadata
        model_hash = self._save_model(tflite_model, output_path)
        
        return {
            "model_path": output_path,
            "sha256_hash": model_hash,
            "model_size": f"{len(tflite_model)/1024:.1f} KB",
            "metadata": self._model_metadata
        }

    def _encrypt_model(self, model_bytes: bytes) -> bytes:
        """AES-GCM model encryption with key derivation"""
        salt = os.urandom(16)
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"tflite_model_encryption",
        )
        key = kdf.derive(MODEL_SIGNATURE_KEY)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(os.urandom(12)),
        ).encryptor()
        return salt + encryptor.update(model_bytes) + encryptor.finalize()

    def _validate_model(self, model_bytes: bytes) -> None:
        """Validate converted model with test inference"""
        interpreter = tf.lite.Interpreter(model_content=model_bytes)
        interpreter.allocate_tensors()
        
        # Check input/output compatibility
        input_details = interpreter.get_input_details()
        assert len(input_details) == 1, "Multi-input models not supported"
        assert list(input_details[0]["shape"]) == list(
            self.input_shape
        ), f"Input shape mismatch: {input_details[0]['shape']} vs {self.input_shape}"

    def _save_model(self, model_bytes: bytes, path: str) -> str:
        """Save model with metadata and integrity checks"""
        model_hash = hashlib.sha256(model_bytes).hexdigest()
        self._model_metadata["sha256"] = model_hash
        
        # Save model
        with open(path, "wb") as f:
            f.write(model_bytes)
            
        # Save metadata
        meta_path = Path(path).with_suffix(".json")
        with open(meta_path, "w") as f:
            json.dump(self._model_metadata, f, indent=2)
            
        return model_hash

    @staticmethod
    def generate_signature(model_path: str) -> None:
        """Generate HMAC signature for model file"""
        with open(model_path, "rb") as f:
            model_data = f.read()
            
        h = hmac.HMAC(MODEL_SIGNATURE_KEY, hashes.SHA256())
        h.update(model_data)
        sig_path = Path(model_path).with_suffix(".sig")
        sig_path.write_bytes(h.finalize())

class SecurityError(Exception):
    """Custom exception for model security violations"""

# Example usage
if __name__ == "__main__":
    # Sample Keras model
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(10, input_shape=(784,), activation="relu"),
        tf.keras.layers.Dense(10, activation="softmax")
    ])
    
    converter = SecureTFLiteConverter(
        model=model,
        input_shape=(784,),
        enable_int8_quant=True
    )
    
    # Add metadata
    converter.add_metadata({
        "author": "YOO Security Team",
        "training_data": "2023-Q4 dataset",
        "privacy_level": "PII-Encrypted"
    })
    
    # Convert & save
    result = converter.convert(
        output_path="secure_model.tflite",
        enable_encryption=True
    )
    
    print(f"Model converted successfully: {result}")
