"""Single-process background job queue for investigations.

The LLM investigation can take minutes, so HTTP requests must never run it
inline. One worker thread is deliberate: the existing agent state file and
report id sequence assume a single writer. A production deployment should
replace this with a durable queue (Redis, SQS, etc.) before adding workers.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from services.triage_api.schemas import JobView

logger = logging.getLogger(__name__)

JobExecutor = Callable[[str], Dict[str, Any]]

_STOP = object()
_STATUSES = ("queued", "running", "succeeded", "failed")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


class JobManager:
    def __init__(self, executor: JobExecutor, workers: int = 1) -> None:
        self._executor = executor
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._queue: "queue.Queue[Any]" = queue.Queue()
        self._stop = threading.Event()
        self._workers = [
            threading.Thread(target=self._worker, name="triage-job-%d" % index, daemon=True)
            for index in range(max(1, workers))
        ]
        self._started = False

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        for worker in self._workers:
            worker.start()

    def stop(self, timeout: float = 5.0) -> None:
        if not self._started:
            return
        self._stop.set()
        for _ in self._workers:
            self._queue.put(_STOP)
        for worker in self._workers:
            worker.join(timeout=timeout)
        self._started = False

    @property
    def alive(self) -> bool:
        return self._started and all(worker.is_alive() for worker in self._workers)

    def submit(self, alert_id: str, force: bool = False) -> JobView:
        with self._lock:
            if not force:
                for existing in self._jobs.values():
                    if existing["alert_id"] == alert_id and existing["status"] in ("queued", "running"):
                        return JobView(**existing)
            job_id = uuid.uuid4().hex
            job: Dict[str, Any] = {
                "job_id": job_id,
                "alert_id": alert_id,
                "status": "queued",
                "created_at": _now(),
                "started_at": None,
                "finished_at": None,
                "result": None,
                "error": None,
            }
            self._jobs[job_id] = job
            view = JobView(**job)
        self._queue.put(job_id)
        return view

    def get(self, job_id: str) -> Optional[JobView]:
        with self._lock:
            job = self._jobs.get(job_id)
            return JobView(**job) if job else None

    def list_recent(self, limit: int = 50) -> List[JobView]:
        with self._lock:
            jobs = sorted(
                self._jobs.values(),
                key=lambda item: item.get("created_at") or "",
                reverse=True,
            )[:limit]
            return [JobView(**job) for job in jobs]

    def counts(self) -> Dict[str, int]:
        with self._lock:
            counts = {status: 0 for status in _STATUSES}
            for job in self._jobs.values():
                status = job.get("status")
                if status in counts:
                    counts[status] += 1
            return counts

    def _update(self, job_id: str, **values: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.update(values)

    def _worker(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _STOP:
                    return
                job_id = str(item)
                with self._lock:
                    job = self._jobs.get(job_id)
                    alert_id = job["alert_id"] if job else ""
                if not job:
                    continue
                self._update(job_id, status="running", started_at=_now())
                try:
                    result = self._executor(alert_id)
                except Exception as exc:
                    logger.exception("investigation job %s failed", job_id)
                    self._update(
                        job_id,
                        status="failed",
                        finished_at=_now(),
                        error="%s: %s" % (type(exc).__name__, exc),
                    )
                else:
                    safe_result = _jsonable(result)
                    if not isinstance(safe_result, dict):
                        safe_result = {"value": safe_result}
                    self._update(
                        job_id,
                        status="succeeded",
                        finished_at=_now(),
                        result=safe_result,
                    )
            finally:
                self._queue.task_done()
