"""Scheduler module for CyberSentinel.

Implements the DSA scheduling architecture:
- FIFO pipeline queue for ordered stages (recon -> scan -> web assessment)
- Min-heap priority queue for port/task prioritization
- Hash map for scan result storage and fast lookup
- Configurable risk scoring based on vulnerability indicators
"""

from __future__ import annotations

import heapq
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional

try:
    from cybersentinel.config import DEFAULT_AI_PROVIDER, PORT_PRIORITIES, RISK_SCORE_WEIGHTS
    from cybersentinel.reconnaissance import recon
    from cybersentinel.scanners import port_scanner as scanner
    from cybersentinel.scanners import web_scanner as web_assess
    from cybersentinel.ai import analyzer
except ImportError:
    from config import DEFAULT_AI_PROVIDER, PORT_PRIORITIES, RISK_SCORE_WEIGHTS
    import modules.recon as recon
    import modules.scanner as scanner
    import modules.web_assess as web_assess
    from ai import analyzer

logger = logging.getLogger(__name__)


@dataclass(order=True)
class ScanTask:
    priority: int
    task_id: str = field(compare=False)
    task_type: str = field(compare=False)
    target: str = field(compare=False)
    payload: Dict[str, Any] = field(default_factory=dict, compare=False)


class TaskScheduler:
    """Manages scan task queuing, prioritization, execution, and risk scoring."""

    def __init__(self) -> None:
        self.pipeline_queue: Deque[ScanTask] = deque()
        self.priority_heap: List[ScanTask] = []
        self.results_map: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Task creation helpers
    # ------------------------------------------------------------------

    def _make_task_id(self, prefix: str, target: str) -> str:
        return f"{prefix}:{target}:{int(time.time() * 1000)}"

    def _resolve_priority(self, port: Optional[int] = None, explicit: Optional[int] = None) -> int:
        if explicit is not None:
            return explicit
        if port is None:
            return max(PORT_PRIORITIES.values(), default=5)
        return PORT_PRIORITIES.get(port, 5)

    def create_task(
        self,
        task_type: str,
        target: str,
        payload: Optional[Dict[str, Any]] = None,
        port: Optional[int] = None,
        explicit_priority: Optional[int] = None,
    ) -> ScanTask:
        payload = payload or {}
        priority = self._resolve_priority(port=port, explicit=explicit_priority)
        task_id = self._make_task_id(task_type, target)
        return ScanTask(
            priority=priority,
            task_id=task_id,
            task_type=task_type,
            target=target,
            payload=payload,
        )

    # ------------------------------------------------------------------
    # Pipeline queue operations
    # ------------------------------------------------------------------

    def enqueue_pipeline_task(self, task: ScanTask) -> None:
        self.pipeline_queue.append(task)

    def dequeue_pipeline_task(self) -> Optional[ScanTask]:
        if not self.pipeline_queue:
            return None
        return self.pipeline_queue.popleft()

    def peek_pipeline_task(self) -> Optional[ScanTask]:
        return self.pipeline_queue[0] if self.pipeline_queue else None

    # ------------------------------------------------------------------
    # Priority queue operations
    # ------------------------------------------------------------------

    def push_priority_task(self, task: ScanTask) -> None:
        heapq.heappush(self.priority_heap, task)

    def pop_priority_task(self) -> Optional[ScanTask]:
        if not self.priority_heap:
            return None
        return heapq.heappop(self.priority_heap)

    def peek_priority_task(self) -> Optional[ScanTask]:
        return self.priority_heap[0] if self.priority_heap else None

    # ------------------------------------------------------------------
    # Task scheduling helpers
    # ------------------------------------------------------------------

    def schedule_recon_task(self, target: str, payload: Optional[Dict[str, Any]] = None) -> ScanTask:
        task = self.create_task("recon", target, payload)
        self.enqueue_pipeline_task(task)
        return task

    def schedule_port_scan_task(self, target: str, port: int, payload: Optional[Dict[str, Any]] = None) -> ScanTask:
        payload = payload or {}
        payload["port"] = port
        task = self.create_task("port_scan", target, payload, port=port)
        self.push_priority_task(task)
        self.enqueue_pipeline_task(task)
        return task

    def schedule_web_assessment_task(self, target: str, payload: Optional[Dict[str, Any]] = None) -> ScanTask:
        task = self.create_task("web_assessment", target, payload)
        self.enqueue_pipeline_task(task)
        return task

    def schedule_default_pipeline(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> List[ScanTask]:
        """Schedule a standard recon -> port scan -> web assessment pipeline."""
        tasks: List[ScanTask] = []
        tasks.append(self.schedule_recon_task(target, payload))

        if ports:
            for port in ports:
                tasks.append(self.schedule_port_scan_task(target, port, payload))
        else:
            tasks.append(self.schedule_port_scan_task(target, 80, payload))
            tasks.append(self.schedule_port_scan_task(target, 443, payload))

        tasks.append(self.schedule_web_assessment_task(target, payload))
        return tasks

    def _execute_recon_task(self, task: ScanTask) -> Dict[str, Any]:
        result = recon.collect_recon_data(task.target)
        self.store_result(task.target, result, subkey="recon")
        return result

    def _execute_port_scan_task(self, task: ScanTask, stop_callback: Optional[Callable[[], bool]] = None) -> Dict[str, Any]:
        port = task.payload.get("port")
        if port is not None:
            result = scanner.scan_single_port(task.target, port=port, stop_callback=stop_callback)
        else:
            ports = task.payload.get("ports")
            result = scanner.scan_ports(task.target, ports=ports, stop_callback=stop_callback)

        findings = [f"Port {entry['port']} is {entry['state']}" for entry in result["ports"] if entry["state"] == "open"]
        self.store_result(
            task.target,
            {
                "scan_data": result,
                "open_ports": result.get("open_ports", []),
                "ports": result.get("ports", []),
                "findings": findings,
            },
            subkey=f"port_{port}" if port is not None else "port_scan",
        )
        return result

    def _execute_web_assessment_task(self, task: ScanTask, stop_callback: Optional[Callable[[], bool]] = None) -> Dict[str, Any]:
        result = web_assess.assess_web_target(task.target, stop_callback=stop_callback)
        self.store_result(
            task.target,
            {
                "web_assessment": result,
                "missing_security_headers": result.get("missing_security_headers", []),
                "exposed_paths": result.get("exposed_paths", []),
                "findings": result.get("findings", []),
            },
            subkey="web_assessment",
        )
        return result

    def _gather_target_results(self, target: str) -> Dict[str, Any]:
        aggregated: Dict[str, Any] = {"target": target, "results": {}}
        for key, data in self.results_map.items():
            if key == target:
                aggregated["results"]["summary"] = data
            elif key.startswith(f"{target}:"):
                subkey = key.split(":", 1)[1]
                aggregated["results"][subkey] = data
        return aggregated

    def get_aggregated_results(self, target: str) -> Dict[str, Any]:
        """Return a target-centric aggregation of stored scan results."""
        return self._gather_target_results(target)

    def _run_ai_analysis_for_target(
        self,
        target: str,
        provider: str = DEFAULT_AI_PROVIDER,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        settings_manager: Optional[object] = None,
    ) -> Dict[str, Any]:
        scan_results = self._gather_target_results(target)
        try:
            ai_result = analyzer.analyze_scan_results(
                scan_results,
                target=target,
                provider=provider,
                model=model,
                api_key=api_key,
                settings_manager=settings_manager,
            )
        except Exception as exc:
            logger.exception("AI analysis failed for target %s", target)
            ai_result = {
                "error": str(exc),
                "analysis": "AI analysis could not be generated.",
            }
        self.store_result(target, ai_result, subkey="ai_analysis")
        return ai_result

    def execute_task(self, task: ScanTask, stop_callback: Optional[Callable[[], bool]] = None) -> Dict[str, Any]:
        if task.task_type == "recon":
            return self._execute_recon_task(task)
        if task.task_type == "port_scan":
            return self._execute_port_scan_task(task, stop_callback=stop_callback)
        if task.task_type == "web_assessment":
            return self._execute_web_assessment_task(task, stop_callback=stop_callback)

        raise ValueError(f"Unknown task type: {task.task_type}")

    def execute_pipeline(
        self,
        run_ai_analysis: bool = True,
        ai_model: Optional[str] = None,
        ai_api_key: Optional[str] = None,
        stop_callback: Optional[Callable[[], bool]] = None,
    ) -> List[Dict[str, Any]]:
        executed_results: List[Dict[str, Any]] = []
        executed_targets: set[str] = set()

        while self.pipeline_queue:
            task = self.dequeue_pipeline_task()
            if task is None:
                break

            if task.task_type == "port_scan" and self.priority_heap:
                while self.priority_heap:
                    priority_task = self.pop_priority_task()
                    if priority_task is not None:
                        executed_results.append(self.execute_task(priority_task, stop_callback=stop_callback))
                        executed_targets.add(priority_task.target)

                # Skip duplicate queued port scan tasks after draining the heap.
                while self.pipeline_queue and self.pipeline_queue[0].task_type == "port_scan":
                    self.dequeue_pipeline_task()
                continue

            if task.task_type == "web_assessment" and self.priority_heap:
                while self.priority_heap:
                    priority_task = self.pop_priority_task()
                    if priority_task is not None:
                        executed_results.append(self.execute_task(priority_task, stop_callback=stop_callback))
                        executed_targets.add(priority_task.target)

            executed_results.append(self.execute_task(task, stop_callback=stop_callback))
            executed_targets.add(task.target)

        if run_ai_analysis:
            for target in executed_targets:
                self._run_ai_analysis_for_target(target, model=ai_model, api_key=ai_api_key)

        return executed_results

    # ------------------------------------------------------------------
    # Result storage and retrieval
    # ------------------------------------------------------------------

    def _build_result_key(self, target: str, subkey: Optional[str] = None) -> str:
        return f"{target}:{subkey}" if subkey else target

    def store_result(self, target: str, data: Dict[str, Any], subkey: Optional[str] = None) -> None:
        key = self._build_result_key(target, subkey)
        existing = self.results_map.get(key, {})
        existing.update(data)
        self.results_map[key] = existing

    def get_result(self, target: str, subkey: Optional[str] = None) -> Optional[Dict[str, Any]]:
        key = self._build_result_key(target, subkey)
        return self.results_map.get(key)

    def get_all_results(self) -> Dict[str, Dict[str, Any]]:
        return dict(self.results_map)

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def calculate_risk_score(self, result_data: Dict[str, Any]) -> int:
        score = 0

        if result_data.get("open_ports"):
            for port in result_data["open_ports"]:
                score += PORT_PRIORITIES.get(port, 3) * 5

        if result_data.get("findings"):
            for finding in result_data["findings"]:
                score += RISK_SCORE_WEIGHTS.get(finding, 0)

        if result_data.get("missing_security_headers"):
            score += len(result_data["missing_security_headers"]) * RISK_SCORE_WEIGHTS.get("missing_security_header", 10)

        if result_data.get("exposed_paths"):
            score += len(result_data["exposed_paths"]) * RISK_SCORE_WEIGHTS.get("exposed_admin_directory", 25)

        if result_data.get("outdated_services"):
            score += len(result_data["outdated_services"]) * RISK_SCORE_WEIGHTS.get("outdated_service_version", 10)

        return min(score, 100)

    def build_overall_risk_summary(self) -> Dict[str, Any]:
        summary = {
            "total_findings": 0,
            "highest_score": 0,
            "scores": {},
            "severity": "Low",
        }

        for key, data in self.results_map.items():
            score = self.calculate_risk_score(data)
            summary["scores"][key] = score
            summary["total_findings"] += 1
            if score > summary["highest_score"]:
                summary["highest_score"] = score

        if summary["highest_score"] >= 75:
            summary["severity"] = "Critical"
        elif summary["highest_score"] >= 50:
            summary["severity"] = "High"
        elif summary["highest_score"] >= 25:
            summary["severity"] = "Medium"

        return summary


DEFAULT_SCHEDULER = TaskScheduler()

__all__ = ["ScanTask", "TaskScheduler", "DEFAULT_SCHEDULER"]
