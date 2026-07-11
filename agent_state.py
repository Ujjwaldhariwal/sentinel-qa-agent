#!/usr/bin/env python3
"""Local scan history for Sentinel QA Agent."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

import sentinel_qa
import settings


DEFAULT_DB = Path(
    os.getenv(
        "SENTINEL_QA_DB",
        str(settings.state_path("history.sqlite3")),
    )
)


def connect(db_path: Path = DEFAULT_DB) -> sqlite3.Connection:
    db_path = db_path.expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    initialize(connection)
    return connection


def initialize(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at REAL NOT NULL,
            finished_at REAL NOT NULL,
            root TEXT NOT NULL,
            output_dir TEXT NOT NULL,
            report_md TEXT NOT NULL,
            report_json TEXT NOT NULL,
            ai_review_md TEXT,
            status TEXT NOT NULL,
            project_count INTEGER NOT NULL,
            finding_count INTEGER NOT NULL,
            severity_counts TEXT NOT NULL,
            error TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at REAL NOT NULL,
            started_at REAL,
            finished_at REAL,
            payload TEXT NOT NULL,
            result TEXT,
            error TEXT
        )
        """
    )
    connection.commit()


def severity_counts(findings: list[sentinel_qa.Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in sentinel_qa.SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def record_scan(
    result: dict[str, Any],
    output_dir: Path,
    ai_review_md: Path | None = None,
    status: str = "completed",
    error: str | None = None,
    db_path: Path = DEFAULT_DB,
) -> int:
    now = time.time()
    with connect(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO scan_runs (
                started_at, finished_at, root, output_dir, report_md, report_json,
                ai_review_md, status, project_count, finding_count, severity_counts, error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now - float(result.get("elapsed", 0)),
                now,
                str(result["root"]),
                str(output_dir.resolve()),
                str(result["markdown_path"]),
                str(result["json_path"]),
                str(ai_review_md) if ai_review_md else None,
                status,
                len(result["projects"]),
                len(result["findings"]),
                json.dumps(severity_counts(result["findings"])),
                error,
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)


def list_runs(limit: int = 20, db_path: Path = DEFAULT_DB) -> list[dict[str, Any]]:
    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, started_at, finished_at, root, output_dir, report_md, report_json,
                   ai_review_md, status, project_count, finding_count, severity_counts, error
            FROM scan_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [row_to_dict(row) for row in rows]


def get_run(run_id: int, db_path: Path = DEFAULT_DB) -> dict[str, Any] | None:
    with connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT id, started_at, finished_at, root, output_dir, report_md, report_json,
                   ai_review_md, status, project_count, finding_count, severity_counts, error
            FROM scan_runs
            WHERE id = ?
            """,
            (run_id,),
        ).fetchone()
    return row_to_dict(row) if row else None


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["severity_counts"] = json.loads(data["severity_counts"])
    output_dir = Path(data["output_dir"])
    test_cases_md = output_dir / "test_cases.md"
    test_cases_json = output_dir / "test_cases.json"
    if test_cases_md.exists():
        data["test_cases_md"] = str(test_cases_md)
    if test_cases_json.exists():
        data["test_cases_json"] = str(test_cases_json)
    return data


def create_job(job_id: str, kind: str, payload: dict[str, Any], db_path: Path = DEFAULT_DB) -> None:
    now = time.time()
    with connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO jobs (id, kind, status, created_at, started_at, finished_at, payload, result, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (job_id, kind, "queued", now, None, None, json.dumps(payload), None, None),
        )
        connection.commit()


def update_job(
    job_id: str,
    status: str,
    result: dict[str, Any] | None = None,
    error: str | None = None,
    started: bool = False,
    finished: bool = False,
    db_path: Path = DEFAULT_DB,
) -> None:
    now = time.time()
    with connect(db_path) as connection:
        connection.execute(
            """
            UPDATE jobs
            SET status = ?,
                started_at = COALESCE(?, started_at),
                finished_at = COALESCE(?, finished_at),
                result = COALESCE(?, result),
                error = COALESCE(?, error)
            WHERE id = ?
            """,
            (
                status,
                now if started else None,
                now if finished else None,
                json.dumps(result) if result is not None else None,
                error,
                job_id,
            ),
        )
        connection.commit()


def get_job(job_id: str, db_path: Path = DEFAULT_DB) -> dict[str, Any] | None:
    with connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT id, kind, status, created_at, started_at, finished_at, payload, result, error
            FROM jobs
            WHERE id = ?
            """,
            (job_id,),
        ).fetchone()
    return job_row_to_dict(row) if row else None


def list_jobs(limit: int = 50, db_path: Path = DEFAULT_DB) -> list[dict[str, Any]]:
    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, kind, status, created_at, started_at, finished_at, payload, result, error
            FROM jobs
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [job_row_to_dict(row) for row in rows]


def job_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    try:
        data["payload"] = json.loads(data["payload"]) if data.get("payload") else None
    except json.JSONDecodeError:
        data["payload"] = None
        data["error"] = data.get("error") or "Stored job payload is corrupt JSON."
    try:
        data["result"] = json.loads(data["result"]) if data.get("result") else None
    except json.JSONDecodeError:
        data["result"] = None
        data["error"] = data.get("error") or "Stored job result is corrupt JSON."
    return data
