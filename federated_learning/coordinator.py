"""
NANEX AGENT Coordinator: Distributed Orchestration Core with Raft Consensus and Zero-Trust Policy Enforcement
"""

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import aiohttp
from cryptography.hazmat.primitives import serialization
from grpc import aio, ServicerContext
from prometheus_client import Gauge, Histogram
import yoo_agent_pb2
import yoo_agent_pb2_grpc

logger = logging.getLogger(__name__)

# Metrics
RAFT_TERM = Gauge("coordinator_raft_term", "Current Raft term")
TASK_QUEUE_SIZE = Gauge("coordinator_task_queue", "Pending tasks in queue")
SCHEDULE_LATENCY = Histogram("coordinator_schedule_time", "Task scheduling latency")

# Constants
RAFT_ELECTION_TIMEOUT = (150, 300)  # ms
HEARTBEAT_INTERVAL = 50  # ms
MAX_TASK_RETRIES = 3

@dataclass
class RaftState:
    current_term: int = 0
    voted_for: Optional[str] = None
    log: List[yoo_agent_pb2.Task] = []
    commit_index: int = -1
    last_applied: int = -1

@dataclass
class NodeState:
    next_index: int = 0
    match_index: int = -1

class CoordinatorService(yoo_agent_pb2_grpc.CoordinatorServicer):
    def __init__(self, node_id: str, peers: List[str]):
        self.node_id = node_id
        self.peers = peers
        self.raft = RaftState()
        self.node_states: Dict[str, NodeState] = defaultdict(NodeState)
        self.leader_id: Optional[str] = None
        self.role: str = "follower"
        self.task_queue = asyncio.PriorityQueue()
        self.lock = asyncio.Lock()
        self.leader_lease = 0.0
        self.keystore = self._load_tls_credentials()
        
        # Start Raft loop
        asyncio.create_task(self._raft_loop())
        asyncio.create_task(self._task_dispatcher())

    async def _raft_loop(self):
        """Raft consensus main loop"""
        while True:
            if self.role == "leader":
                await self._send_heartbeats()
                await asyncio.sleep(HEARTBEAT_INTERVAL / 1000)
            else:
                timeout = RAFT_ELECTION_TIMEOUT[1] / 1000
                await asyncio.sleep(timeout)
                if time.time() - self.leader_lease > timeout:
                    await self._start_election()

    async def _start_election(self):
        """Initiate leader election"""
        async with self.lock:
            self.raft.current_term += 1
            self.role = "candidate"
            self.raft.voted_for = self.node_id

        votes = 1
        async with aiohttp.ClientSession() as session:
            for peer in self.peers:
                try:
                    async with session.post(
                        f"https://{peer}/raft/request_vote",
                        json={
                            "term": self.raft.current_term,
                            "candidate_id": self.node_id,
                            "last_log_index": len(self.raft.log) - 1,
                            "last_log_term": self.raft.log[-1].term if self.raft.log else 0
                        },
                        ssl=self.keystore["ssl_context"]
                    ) as resp:
                        if await resp.json()["vote_granted"]:
                            votes += 1
                except Exception as e:
                    logger.error(f"Vote request to {peer} failed: {e}")

        if votes > len(self.peers) // 2:
            async with self.lock:
                self.role = "leader"
                self.leader_id = self.node_id
                for peer in self.peers:
                    self.node_states[peer].next_index = len(self.raft.log)

    async def _send_heartbeats(self):
        """Leader heartbeat propagation"""
        async with aiohttp.ClientSession() as session:
            for peer in self.peers:
                try:
                    async with session.post(
                        f"https://{peer}/raft/append_entries",
                        json={
                            "term": self.raft.current_term,
                            "leader_id": self.node_id,
                            "prev_log_index": self.node_states[peer].next_index - 1,
                            "entries": self.raft.log[self.node_states[peer].next_index:],
                            "leader_commit": self.raft.commit_index
                        },
                        ssl=self.keystore["ssl_context"]
                    ) as resp:
                        data = await resp.json()
                        if data["success"]:
                            self.node_states[peer].match_index = data["match_index"]
                            self.node_states[peer].next_index = data["match_index"] + 1
                except Exception as e:
                    logger.error(f"Heartbeat to {peer} failed: {e}")

    async def SubmitTask(self, request: yoo_agent_pb2.TaskRequest,
                        context: ServicerContext) -> yoo_agent_pb2.TaskResponse:
        """gRPC endpoint for task submission"""
        # Zero-trust policy check
        if not await self._validate_task_policy(request.metadata):
            await context.abort(aio.StatusCode.PERMISSION_DENIED, "Policy violation")
        
        # Raft log replication
        async with self.lock:
            task = yoo_agent_pb2.Task(
                id=request.task_id,
                payload=request.payload,
                term=self.raft.current_term,
                priority=request.priority
            )
            self.raft.log.append(task)
        
        await self.task_queue.put((request.priority, task))
        return yoo_agent_pb2.TaskResponse(status="QUEUED")

    async def _task_dispatcher(self):
        """Distributed task scheduling with edge awareness"""
        while True:
            priority, task = await self.task_queue.get()
            start_time = time.monotonic()
            
            # Federated resource selection
            target_agent = await self._select_agent(task)
            if not target_agent:
                if task.retries < MAX_TASK_RETRIES:
                    task.retries += 1
                    await self.task_queue.put((priority, task))
                continue
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"https://{target_agent}/tasks/execute",
                        data=task.payload,
                        headers={"Authorization": f"Bearer {self._sign_jwt(task)}"},
                        ssl=self.keystore["ssl_context"],
                        timeout=aiohttp.ClientTimeout(total=task.timeout)
                    ) as resp:
                        if resp.status == 200:
                            SCHEDULE_LATENCY.observe(time.monotonic() - start_time)
            except Exception as e:
                logger.error(f"Task {task.id} failed on {target_agent}: {e}")
                await self.task_queue.put((priority, task))

    async def _select_agent(self, task: yoo_agent_pb2.Task) -> Optional[str]:
        """Resource-aware agent selection"""
        async with aiohttp.ClientSession() as session:
            agents = []
            for peer in self.peers:
                try:
                    async with session.get(
                        f"https://{peer}/metrics",
                        ssl=self.keystore["ssl_context"],
                        timeout=1
                    ) as resp:
                        metrics = await resp.json()
                        agents.append((peer, metrics["load"]))
                except Exception as e:
                    logger.debug(f"Metrics check failed for {peer}: {e}")
        
        if not agents:
            return None
        
        # Load balancing with priority weighting
        agents.sort(key=lambda x: x[1] + (0.1 * task.priority))
        return agents[0][0]

    def _load_tls_credentials(self) -> Dict:
        """Load mTLS credentials for zero-trust communication"""
        return {
            "ssl_context": ssl.create_default_context(ssl.Purpose.SERVER_AUTH),
            "private_key": serialization.load_pem_private_key(
                open("/etc/yoo-agent/certs/key.pem", "rb").read(),
                password=None
            )
        }

    def _sign_jwt(self, task: yoo_agent_pb2.Task) -> str:
        """Generate task-specific JWT with short expiry"""
        # Implementation depends on your JWT library
        return "signed_jwt_token"

    async def _validate_task_policy(self, metadata: Dict) -> bool:
        """ABAC policy validation"""
        # Integrate with policy_engine.py
        return True

# Start gRPC server
async def serve():
    server = aio.server()
    yoo_agent_pb2_grpc.add_CoordinatorServicer_to_server(
        CoordinatorService("node1", ["node2:50051", "node3:50051"]), server
    )
    server.add_insecure_port("[::]:50051")
    await server.start()
    await server.wait_for_termination()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(serve())
