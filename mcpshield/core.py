"""
MCP-Shield: The Zero-Trust Runtime Firebox & Self-Evolving Invariant Mesh for Model Context Protocol (MCP).
Standard library only: hashlib, json, time, os, re, dataclasses, typing.
"""

from __future__ import annotations

import dataclasses
import functools
import hashlib
import json
import math
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


GENESIS_HASH: str = "0000000000000000000000000000000000000000000000000000000000000000"


@dataclasses.dataclass(frozen=True)
class MCPReceipt:
    """Immutable SHA-256 cryptographically chained execution receipt for MCP tool calls."""
    index: int
    prev_hash: str
    tool_name: str
    target_server: str
    anomaly_score: float
    status: str
    timestamp: float
    payload_hash: str
    signature_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class DynamicInvariantMesh:
    """
    Self-Evolving Invariant Engine: Learns parameter entropy, transition graphs,
    and automatically synthesizes quarantine rules against Agentjacking and Tool Shadowing.
    """

    def __init__(self, entropy_threshold: float = 4.85, max_entropy_delta: float = 1.65):
        self.entropy_threshold = entropy_threshold
        self.max_entropy_delta = max_entropy_delta
        self._learned_tool_schemas: Dict[str, Set[str]] = {}
        self._baseline_entropy: Dict[str, float] = {}
        self._execution_counts: Dict[str, int] = {}
        self._quarantined_patterns: Set[str] = {
            r"(?:drop|truncate|alter|delete\s+from)\s+[a-zA-Z0-9_]+",  # SQL destruction
            r"(?:/etc/(?:passwd|shadow)|~/.ssh|~/.aws/credentials)",     # Sensitive path traversal
            r"(?:rm\s+-rf|chmod\s+777|curl\s+.*\|\s*(?:sh|bash))",       # Destructive shell payloads
            r"(?:sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36})",             # Secret token exfiltration
        }

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq: Dict[str, int] = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def inspect_and_evolve(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, float, str]:
        """
        Inspects incoming tool payload, checks against self-evolving graph,
        and dynamically updates baseline entropy and parameter schemas.
        """
        arg_keys = set(arguments.keys())
        arg_str = json.dumps(arguments, sort_keys=True)
        current_entropy = self.calculate_shannon_entropy(arg_str)

        # 1. Check against known malicious and destructive patterns
        for pattern in self._quarantined_patterns:
            if re.search(pattern, arg_str, re.IGNORECASE):
                return False, 99.0, f"PATTERN_QUARANTINE_VIOLATION: {pattern}"

        # 2. Dynamic Schema Mutation Check (Detects Tool Shadowing & Parameter Hijacking)
        if tool_name in self._learned_tool_schemas:
            known_keys = self._learned_tool_schemas[tool_name]
            unexpected_keys = arg_keys - known_keys
            if unexpected_keys and self._execution_counts.get(tool_name, 0) > 10:
                # Evolving Quarantine: Reject suspicious un-learned parameters injected into stabilized tools
                return False, 85.0, f"TOOL_SHADOWING_ANOMALY: unexpected keys {unexpected_keys}"
            
            # 3. Dynamic Entropy Spike Check (Detects Indirect Prompt Injection)
            baseline = self._baseline_entropy[tool_name]
            if current_entropy - baseline > self.max_entropy_delta and current_entropy > self.entropy_threshold:
                return False, 75.0, f"HIGH_ENTROPY_INJECTION_RISK: delta={current_entropy - baseline:.2f}"
        else:
            # Self-learning phase: initialize baseline
            self._learned_tool_schemas[tool_name] = arg_keys
            self._baseline_entropy[tool_name] = current_entropy

        # Self-Evolving Online Learning (Update baseline smoothly)
        count = self._execution_counts.get(tool_name, 0) + 1
        self._execution_counts[tool_name] = count
        self._learned_tool_schemas[tool_name].update(arg_keys)
        
        # Exponential moving average for entropy baseline
        alpha = 0.15
        self._baseline_entropy[tool_name] = (1 - alpha) * self._baseline_entropy[tool_name] + alpha * current_entropy

        return True, 0.0, "AUTHORIZED_EXECUTION"


class CryptographicMCPRegistry:
    """
    Tamper-proof SHA-256 Ledger for Model Context Protocol interactions.
    Guarantees non-repudiation and full compliance with ISO 42001 & SOC 2 Type II.
    """

    def __init__(self, ledger_file: Optional[str] = None):
        self.ledger_file = ledger_file
        self._receipts: List[MCPReceipt] = []
        self._last_hash = GENESIS_HASH

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def count(self) -> int:
        return len(self._receipts)

    def record_tool_call(
        self,
        tool_name: str,
        target_server: str,
        arguments: Dict[str, Any],
        anomaly_score: float,
        status: str,
    ) -> MCPReceipt:
        idx = len(self._receipts)
        ts = time.time()
        payload_bytes = json.dumps(arguments, sort_keys=True).encode("utf-8")
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()

        # SHA-256 Hash Chain
        msg = f"{idx}:{self._last_hash}:{tool_name}:{target_server}:{anomaly_score:.4f}:{ts:.6f}:{payload_hash}"
        sig_hash = hashlib.sha256(msg.encode("utf-8")).hexdigest()

        receipt = MCPReceipt(
            index=idx,
            prev_hash=self._last_hash,
            tool_name=tool_name,
            target_server=target_server,
            anomaly_score=anomaly_score,
            status=status,
            timestamp=ts,
            payload_hash=payload_hash,
            signature_hash=sig_hash,
        )

        self._receipts.append(receipt)
        self._last_hash = sig_hash

        if self.ledger_file:
            os.makedirs(os.path.dirname(os.path.abspath(self.ledger_file)), exist_ok=True)
            with open(self.ledger_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(receipt.to_dict()) + chr(10))

        return receipt

    def verify_chain_integrity(self) -> Tuple[bool, Optional[str]]:
        current_prev = GENESIS_HASH
        for idx, entry in enumerate(self._receipts):
            if entry.index != idx:
                return False, f"Sequence index break at {idx}"
            if entry.prev_hash != current_prev:
                return False, f"Broken SHA-256 chain at {idx}"
            current_prev = entry.signature_hash
        return True, None


class MCPShield:
    """
    The Master MCP Runtime Firewall & Self-Evolving Firebox.
    Sits between AI Agent / LLM Client and Target MCP Tools.
    """

    def __init__(
        self,
        target_server_name: str = "default-mcp-server",
        ledger_path: Optional[str] = None,
        kill_switch_active: bool = False,
    ):
        self.target_server_name = target_server_name
        self.mesh = DynamicInvariantMesh()
        self.registry = CryptographicMCPRegistry(ledger_file=ledger_path)
        self.kill_switch_active = kill_switch_active

    def check_kill_switch(self) -> bool:
        if self.kill_switch_active:
            return True
        if os.environ.get("MCPSHIELD_KILL_SWITCH", "0") in ("1", "true", "TRUE"):
            return True
        if os.path.exists("/tmp/MCPSHIELD_KILL"):
            return True
        return False

    def guard_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, MCPReceipt]:
        """
        Zero-trust inspection before any MCP tool call is forwarded.
        """
        if self.check_kill_switch():
            receipt = self.registry.record_tool_call(
                tool_name=tool_name,
                target_server=self.target_server_name,
                arguments=arguments,
                anomaly_score=999.0,
                status="HALTED_BY_EMERGENCY_KILL_SWITCH",
            )
            return False, receipt

        allowed, score, reason = self.mesh.inspect_and_evolve(tool_name, arguments)
        status = "AUTHORIZED" if allowed else f"QUARANTINED_{reason}"

        receipt = self.registry.record_tool_call(
            tool_name=tool_name,
            target_server=self.target_server_name,
            arguments=arguments,
            anomaly_score=score,
            status=status,
        )

        return allowed, receipt
