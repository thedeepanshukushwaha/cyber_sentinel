"""Tests for scheduler module and DSA pipeline queue / heap."""

import pytest

from cybersentinel.core.scheduler import ScanTask, TaskScheduler


def test_scan_task_priority_ordering():
    # Smaller priority numbers come first in min-heap
    task_crit = ScanTask(priority=1, task_id="t1", task_type="port_scan", target="localhost")
    task_high = ScanTask(priority=2, task_id="t2", task_type="port_scan", target="localhost")
    task_med = ScanTask(priority=3, task_id="t3", task_type="port_scan", target="localhost")

    assert task_crit < task_high < task_med


def test_scheduler_queue_fifo():
    scheduler = TaskScheduler()
    t1 = scheduler.create_task("recon", "127.0.0.1")
    t2 = scheduler.create_task("web_assessment", "127.0.0.1")

    scheduler.enqueue_pipeline_task(t1)
    scheduler.enqueue_pipeline_task(t2)

    assert scheduler.peek_pipeline_task().task_id == t1.task_id
    assert scheduler.dequeue_pipeline_task().task_id == t1.task_id
    assert scheduler.dequeue_pipeline_task().task_id == t2.task_id
    assert scheduler.dequeue_pipeline_task() is None


def test_scheduler_priority_heap():
    scheduler = TaskScheduler()
    t_low = scheduler.create_task("port_scan", "127.0.0.1", explicit_priority=5)
    t_crit = scheduler.create_task("port_scan", "127.0.0.1", explicit_priority=1)
    t_med = scheduler.create_task("port_scan", "127.0.0.1", explicit_priority=3)

    scheduler.push_priority_task(t_low)
    scheduler.push_priority_task(t_crit)
    scheduler.push_priority_task(t_med)

    assert scheduler.peek_priority_task().priority == 1
    assert scheduler.pop_priority_task().priority == 1
    assert scheduler.pop_priority_task().priority == 3
    assert scheduler.pop_priority_task().priority == 5
    assert scheduler.pop_priority_task() is None


def test_schedule_default_pipeline():
    scheduler = TaskScheduler()
    tasks = scheduler.schedule_default_pipeline("127.0.0.1", ports=[80, 443])
    # Should schedule recon + port 80 + port 443 + web_assessment
    assert len(tasks) == 4
    assert tasks[0].task_type == "recon"
    assert tasks[1].task_type == "port_scan"
    assert tasks[2].task_type == "port_scan"
    assert tasks[3].task_type == "web_assessment"


def test_risk_scoring_calculation():
    scheduler = TaskScheduler()
    clean_data = {
        "open_ports": [],
        "findings": [],
        "missing_security_headers": [],
    }
    assert scheduler.calculate_risk_score(clean_data) == 0

    risky_data = {
        "open_ports": [21, 23],  # FTP (priority 1) + Telnet (priority 1)
        "missing_security_headers": ["content-security-policy", "strict-transport-security"],
        "exposed_paths": [{"path": "admin"}],
    }
    score = scheduler.calculate_risk_score(risky_data)
    assert score > 0
    assert score <= 100


def test_overall_risk_summary_severity():
    scheduler = TaskScheduler()
    scheduler.store_result("target.test", {
        "open_ports": [21, 23, 445, 3389],
        "missing_security_headers": ["csp", "hsts", "xfo", "xcto", "rp"],
        "exposed_paths": ["admin", "login"],
    })
    summary = scheduler.build_overall_risk_summary()
    assert summary["severity"] in ("Medium", "High", "Critical")
    assert summary["highest_score"] >= 25
