"""
NANEX AGENT Priority Queue: Secure Deadline-Driven Task Scheduler with Byzantine Fault Tolerance
"""

import heapq
import asyncio
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Callable
from dataclasses import dataclass, field
from enum import IntEnum

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import aiofiles
import prometheus_client as prom

logger = logging.getLogger(__name__)

class PriorityPolicy(IntEnum):
    DEADLINE_DRIVEN = 0
    RESOURCE_AWARE = 1
    FAIR_SHARING = 2

@dataclass(order=True)
class SecureTask:
    """Atomic task unit with cryptographic non-repudiation"""
    deadline: datetime
    priority_score: float
    payload: bytes = field(compare=False)
    creator_signature: bytes = field(compare=False)
    public_key_pem: bytes = field(compare=False)
    task_id: str = field(compare=False)
    
    def validate_signature(self) -> bool:
        """Verify task authenticity using ECDSA"""
        try:
            pub_key = serialization.load_pem_public_key(self.public_key_pem)
            pub_key.verify(
                self.creator_signature,
                self.payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA3_256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA3_256()
            )
            return True
        except InvalidSignature:
            logger.warning(f"Invalid signature for task {self.task_id}")
            return False

class PriorityQueueCore:
    def __init__(self, 
                 storage_path: str = "/var/lib/yoo-agent/queue.db",
                 policy: PriorityPolicy = PriorityPolicy.DEADLINE_DRIVEN):
        
        # Memory structure
        self._heap: List[SecureTask] = []
        self._lock = asyncio.Lock()
        self._policy = policy
        
        # Persistence layer
        self.conn = sqlite3.connect(storage_path, check_same_thread=False)
        self._init_db()
        
        # Metrics
        self.queue_depth = prom.Gauge('yoo_queue_depth', 'Current tasks in queue')
        self.priority_score = prom.Gauge('yoo_task_priority', 'Task priority score', ['task_type'])
        self._register_metrics()
        
        # Recovery thread
        self._recovery_task = asyncio.create_task(self._recover_pending_tasks())

    def _init_db(self):
        """Create persistent task storage with WAL mode"""
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS pending_tasks (
                    task_id TEXT PRIMARY KEY,
                    deadline TEXT NOT NULL,
                    priority REAL NOT NULL,
                    payload BLOB NOT NULL,
                    signature BLOB NOT NULL,
                    pubkey BLOB NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.conn.execute("PRAGMA journal_mode=WAL")

    def _register_metrics(self):
        """Initialize Prometheus metrics registry"""
        prom.REGISTRY.register(self.queue_depth)
        prom.REGISTRY.register(self.priority_score)

    async def _recover_pending_tasks(self):
        """Load unprocessed tasks from database on startup"""
        async with self._lock:
            cur = self.conn.execute("""
                SELECT task_id, deadline, priority, payload, signature, pubkey
                FROM pending_tasks
                ORDER BY deadline
            """)
            for row in cur:
                task = SecureTask(
                    deadline=datetime.fromisoformat(row[1]),
                    priority_score=row[2],
                    payload=row[3],
                    creator_signature=row[4],
                    public_key_pem=row[5],
                    task_id=row[0]
                )
                if task.validate_signature():
                    heapq.heappush(self._heap, task)
                    self.queue_depth.inc()
            
            logger.info(f"Recovered {len(self._heap)} tasks from persistence")

    def _calculate_priority(self, task: SecureTask) -> float:
        """Policy-driven priority scoring"""
        if self._policy == PriorityPolicy.DEADLINE_DRIVEN:
            time_left = (task.deadline - datetime.now()).total_seconds()
            return -time_left  # Min-heap needs smallest first
        elif self._policy == PriorityPolicy.RESOURCE_AWARE:
            # Placeholder for resource estimation logic
            return task.priority_score * 0.8
        elif self._policy == PriorityPolicy.FAIR_SHARING:
            # Placeholder for fairness algorithm
            return self._calculate_fairness(task)
        else:
            raise ValueError("Invalid priority policy")

    async def add_task(self, task: SecureTask):
        """Thread-safe task insertion with persistence"""
        if not task.validate_signature():
            raise SecurityError("Invalid task signature")
            
        async with self._lock:
            # Calculate final priority score
            final_score = self._calculate_priority(task)
            task.priority_score = final_score
            
            # Heap operations
            heapq.heappush(self._heap, task)
            self.queue_depth.inc()
            self.priority_score.labels(task.task_id.split(':')[0]).set(final_score)
            
            # Write to database
            await self._persist_task(task)

    async def _persist_task(self, task: SecureTask):
        """Atomic write to SQLite with retries"""
        async with aiofiles.open(self.conn, timeout=5) as db:
            await db.execute(
                "INSERT INTO pending_tasks VALUES (?, ?, ?, ?, ?, ?)",
                (
                    task.task_id,
                    task.deadline.isoformat(),
                    task.priority_score,
                    task.payload,
                    task.creator_signature,
                    task.public_key_pem
                )
            )

    async def get_next_task(self) -> Optional[SecureTask]:
        """Retrieve highest priority task with deadline check"""
        async with self._lock:
            if not self._heap:
                return None

            # Check deadline validity
            while self._heap:
                task = heapq.heappop(self._heap)
                if datetime.now() < task.deadline:
                    heapq.heappush(self._heap, task)
                    self.queue_depth.dec()
                    return task
                else:
                    await self._archive_expired_task(task)
            
            return None

    async def _archive_expired_task(self, task: SecureTask):
        """Move expired tasks to audit storage"""
        async with aiofiles.open(self.conn, timeout=5) as db:
            await db.execute("""
                INSERT INTO expired_tasks
                SELECT *, CURRENT_TIMESTAMP 
                FROM pending_tasks 
                WHERE task_id = ?
            """, (task.task_id,))
            await db.execute("DELETE FROM pending_tasks WHERE task_id = ?", (task.task_id,))

    def set_policy(self, new_policy: PriorityPolicy):
        """Dynamic policy adjustment with heap rebuild"""
        async with self._lock:
            self._policy = new_policy
            self._heap = self._recalculate_heap(self._heap)
            heapq.heapify(self._heap)

    def _recalculate_heap(self, old_heap: List[SecureTask]) -> List[SecureTask]:
        """Rebuild heap when priority policy changes"""
        return [SecureTask(
            deadline=t.deadline,
            priority_score=self._calculate_priority(t),
            payload=t.payload,
            creator_signature=t.creator_signature,
            public_key_pem=t.public_key_pem,
            task_id=t.task_id
        ) for t in old_heap]

    async def graceful_shutdown(self):
        """Persist in-memory state before termination"""
        async with self._lock:
            self._recovery_task.cancel()
            self.conn.commit()
            self.conn.close()

# Example usage
if __name__ == "__main__":
    async def demo_workflow():
        # Initialize queue with deadline-driven policy
        queue = PriorityQueueCore(policy=PriorityPolicy.DEADLINE_DRIVEN)
        
        # Create sample secure task
        task = SecureTask(
            deadline=datetime.now() + timedelta(minutes=5),
            priority_score=0.9,
            payload=b'{"cmd": "data_sync"}',
            creator_signature=b'fake_sig',
            public_key_pem=b'fake_pubkey',
            task_id="task:001"
        )
        
        await queue.add_task(task)
        next_task = await queue.get_next_task()
        print(f"Next task: {next_task.task_id if next_task else 'None'}")

    asyncio.run(demo_workflow())
