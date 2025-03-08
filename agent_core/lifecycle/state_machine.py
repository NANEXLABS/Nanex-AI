"""
YOO AGENT State Machine: Distributed Finite State Machine with Conflict-free Replicated Data Types (CRDT)
"""

from __future__ import annotations
import logging
import time
from enum import Enum
from typing import Dict, List, Optional, Tuple, TypeVar
from dataclasses import dataclass
import hashlib
import json

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, ValidationError
import msgpack
from sortedcontainers import SortedDict

# Type Aliases
StateHash = bytes
AgentID = str
TransitionProof = bytes

# Constants
MAX_HISTORY_DEPTH = 1000
STATE_HASH_ALGO = hashlib.blake2b
EPOCH_TOLERANCE = 300  # 5 minutes for clock drift

class StateStatus(Enum):
    PENDING_VERIFICATION = 1
    COMMITTED = 2
    ROLLBACK_PENDING = 3

@dataclass(frozen=True)
class StateTransition:
    prev_hash: StateHash
    next_state: bytes
    timestamp: int  # Unix millis
    author: AgentID
    signature: bytes
    proof_of_work: Optional[TransitionProof] = None  # For edge constraints

class StateMachineConfig(BaseModel):
    quorum_size: int = 3
    require_temporal_proofs: bool = True
    max_state_size: int = 1024  # 1KB for edge devices
    allowed_transition_paths: Dict[str, List[str]]  # State transition graph

class CRDTStateMetadata(BaseModel):
    vector_clock: Dict[AgentID, int]
    tombstone_epochs: SortedDict[int, List[StateHash]]  # For GC

class DistributedStateMachine:
    def __init__(self, 
                 agent_id: AgentID,
                 private_key: ed25519.Ed25519PrivateKey,
                 config: StateMachineConfig):
        self.agent_id = agent_id
        self._private_key = private_key
        self.config = config
        
        # CRDT-optimized storage
        self.state_history = SortedDict()
        self.current_state_hash: Optional[StateHash] = None
        self.metadata = CRDTStateMetadata(
            vector_clock={agent_id: 0},
            tombstone_epochs=SortedDict()
        )
        
        # Consensus tracking
        self.pending_transitions: Dict[StateHash, StateTransition] = {}
        self.observed_transitions: Dict[StateHash, List[AgentID]] = {}

    def initialize_state(self, initial_state: bytes):
        """Bootstrap state with cryptographic genesis block"""
        if self.current_state_hash is not None:
            raise RuntimeError("State already initialized")
            
        genesis_hash = self._compute_state_hash(b'', initial_state)
        self._store_state(genesis_hash, initial_state)
        self.current_state_hash = genesis_hash

    def propose_transition(self, 
                          new_state: bytes,
                          require_quorum: bool = True) -> StateTransition:
        """Create signed state transition proposal"""
        if len(new_state) > self.config.max_state_size:
            raise ValueError("State exceeds edge device limits")

        prev_hash = self.current_state_hash
        if prev_hash is None:
            raise RuntimeError("State machine not initialized")

        # Validate state transition path
        current_state_type = self._get_state_type(self.current_state_hash)
        new_state_type = self._parse_state_type(new_state)
        if new_state_type not in self.config.allowed_transition_paths.get(current_state_type, []):
            raise ValueError(f"Illegal transition: {current_state_type} → {new_state_type}")

        transition = StateTransition(
            prev_hash=prev_hash,
            next_state=new_state,
            timestamp=int(time.time() * 1000),
            author=self.agent_id,
            signature=self._sign_transition(prev_hash, new_state),
            proof_of_work=self._generate_edge_proof() if not require_quorum else None
        )
        
        transition_hash = self._hash_transition(transition)
        self.pending_transitions[transition_hash] = transition
        return transition

    def validate_transition(self, transition: StateTransition) -> bool:
        """Verify transition cryptographic integrity and business rules"""
        try:
            # Zero-trust verification
            if transition.timestamp < (time.time() * 1000 - EPOCH_TOLERANCE):
                logging.warning("Stale transition timestamp")
                return False

            # Verify cryptographic signatures
            if not self._verify_signature(transition):
                return False

            # Validate state machine continuity
            if transition.prev_hash not in self.state_history:
                logging.warning("Unknown previous state hash")
                return False

            # Check transition graph compliance
            prev_state_type = self._get_state_type(transition.prev_hash)
            new_state_type = self._parse_state_type(transition.next_state)
            if new_state_type not in self.config.allowed_transition_paths.get(prev_state_type, []):
                logging.error(f"Invalid state transition {prev_state_type}→{new_state_type}")
                return False

            # Edge device proof-of-work check
            if transition.proof_of_work and not self._validate_edge_proof(transition.proof_of_work):
                logging.warning("Invalid edge resource proof")
                return False

            return True

        except (ValidationError, KeyError) as e:
            logging.error(f"Transition validation failed: {str(e)}")
            return False

    def commit_transition(self, transition: StateTransition) -> bool:
        """Apply state transition after quorum verification"""
        transition_hash = self._hash_transition(transition)
        
        # Check if quorum achieved
        witnesses = self.observed_transitions.get(transition_hash, [])
        if len(witnesses) < self.config.quorum_size - 1:  # -1 for self
            logging.info(f"Awaiting quorum: {len(witnesses)+1}/{self.config.quorum_size}")
            return False

        # CRDT conflict resolution
        if not self._resolve_vector_clock_conflicts(transition):
            logging.warning("Vector clock conflict detected, initiating rollback")
            self._mark_for_rollback(transition_hash)
            return False

        # Apply state transition
        new_state_hash = self._compute_state_hash(transition.prev_hash, transition.next_state)
        self._store_state(new_state_hash, transition.next_state)
        self.current_state_hash = new_state_hash
        
        # Update vector clock
        self.metadata.vector_clock[self.agent_id] += 1
        
        # Tombstone old states
        self._apply_garbage_collection()
        return True

    def _store_state(self, state_hash: StateHash, state_data: bytes):
        """Immutable state storage with size-constrained history"""
        if len(self.state_history) >= MAX_HISTORY_DEPTH:
            oldest_key = self.state_history.iloc[0]
            del self.state_history[oldest_key]
            
        self.state_history[state_hash] = {
            'data': msgpack.packb(state_data),
            'timestamp': time.time_ns()
        }

    def _resolve_vector_clock_conflicts(self, transition: StateTransition) -> bool:
        """CRDT-based conflict resolution using vector clock ordering"""
        incoming_clock = self._parse_vector_clock(transition.next_state)
        current_clock = self.metadata.vector_clock.copy()
        
        # Check for concurrent updates
        concurrent_updates = False
        for agent, seq in incoming_clock.items():
            if current_clock.get(agent, 0) > seq:
                concurrent_updates = True
                break
                
        if concurrent_updates:
            return self._merge_conflicting_states(transition)
            
        return True

    def _merge_conflicting_states(self, transition: StateTransition) -> bool:
        """Last-write-wins with cryptographic timestamp validation"""
        current_state = self.state_history[self.current_state_hash]
        current_time = current_state['timestamp']
        incoming_time = transition.timestamp * 1_000_000  # Convert to ns
        
        if incoming_time > current_time:
            return True  # Prefer newer state
        elif incoming_time == current_time:
            # Cryptographic tiebreaker
            return self._cryptographic_tiebreaker(current_state, transition)
        else:
            return False

    def _cryptographic_tiebreaker(self, current_state, transition) -> bool:
        """Ed25519 signature comparison for deterministic conflict resolution"""
        current_sig = current_state['signature']
        incoming_sig = transition.signature
        
        # Compare signatures lex order
        return incoming_sig < current_sig

    def _sign_transition(self, prev_hash: StateHash, state: bytes) -> bytes:
        """EdDSA over state transition components"""
        signing_data = prev_hash + state + str(time.time_ns()).encode()
        return self._private_key.sign(signing_data)

    def _verify_signature(self, transition: StateTransition) -> bool:
        """Ed25519 signature verification"""
        public_key = self._private_key.public_key()
        signing_data = transition.prev_hash + transition.next_state + str(transition.timestamp).encode()
        try:
            public_key.verify(transition.signature, signing_data)
            return True
        except Exception as e:
            logging.warning(f"Signature verification failed: {str(e)}")
            return False

    def _hash_transition(self, transition: StateTransition) -> StateHash:
        """Compute unique identifier for state transition"""
        data = transition.prev_hash + transition.next_state + transition.signature
        return STATE_HASH_ALGO(data).digest()

    def _compute_state_hash(self, prev_hash: StateHash, state: bytes) -> StateHash:
        """Immutable state chain hashing"""
        return STATE_HASH_ALGO(prev_hash + state).digest()

    def _generate_edge_proof(self) -> TransitionProof:
        """Memory-bound proof-of-work for edge device protection"""
        # Simplified example: Find nonce with hash prefix
        nonce = 0
        target_prefix = '0000'
        while True:
            data = f"{nonce}".encode() + self.current_state_hash
            digest = hashlib.sha256(data).hexdigest()
            if digest.startswith(target_prefix):
                return f"{nonce}:{digest}".encode()
            nonce += 1

    def _validate_edge_proof(self, proof: TransitionProof) -> bool:
        """Verify edge device resource proof"""
        try:
            nonce, digest = proof.split(b':', 1)
            data = nonce + self.current_state_hash
            return hashlib.sha256(data).hexdigest().encode() == digest
        except:
            return False

    def _parse_state_type(self, state_data: bytes) -> str:
        """Extract state type identifier from serialized data"""
        try:
            parsed = msgpack.unpackb(state_data)
            return parsed.get('type', 'unknown')
        except:
            return 'invalid'

    def _get_state_type(self, state_hash: StateHash) -> str:
        """Retrieve state type from stored history"""
        state = self.state_history.get(state_hash)
        if not state:
            raise KeyError("State hash not found")
        return self._parse_state_type(msgpack.unpackb(state['data']))
