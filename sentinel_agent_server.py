#!/usr/bin/env python3
"""
Tiny local service for Sentinel QA Agent.

Run it when you want the agent to operate like a background tool that a modal,
browser extension, editor command, or automation can call.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import mimetypes
import socketserver
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import agent_state
import agent_log
import qa_ai_agent
import sentinel_qa
import sentinel_policy
import settings
import web_qa


APP_DIR = Path(__file__).resolve().parent
EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=2)
SERVICE_CONFIG = settings.load_config()
SAFE_ARTIFACT_SUFFIXES = {".json", ".md", ".txt", ".log", ".png", ".jpg", ".jpeg", ".webp"}


class FastLocalHTTPServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


class AgentHandler(BaseHTTPRequestHandler):
    server_version = "SentinelQA/1.0"

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Sentinel-Token")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path not in {"/", "/health"} and not self.is_authorized():
            self.send_json({"ok": False, "error": "unauthorized"}, status=401)
            return
        if parsed.path == "/":
            self.send_file(APP_DIR / "ui" / "index.html", "text/html; charset=utf-8")
        elif parsed.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        elif parsed.path == "/health":
            self.send_json({"ok": True, "service": "sentinel-qa-agent"})
        elif parsed.path == "/browse":
            try:
                query = parse_qs(parsed.query)
                current = (query.get("path") or [""])[0]
                self.send_json({"ok": True, **browse_directory(current)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, status=400)
        elif parsed.path == "/artifact":
            query = parse_qs(parsed.query)
            artifact = (query.get("path") or [""])[0]
            self.send_artifact(artifact)
        elif parsed.path == "/jobs":
            self.send_json({"ok": True, "jobs": agent_state.list_jobs()})
        elif parsed.path == "/job":
            query = parse_qs(parsed.query)
            job_id = (query.get("id") or [""])[0]
            job = agent_state.get_job(job_id)
            self.send_json({"ok": bool(job), "job": job})
        elif parsed.path == "/logs":
            query = parse_qs(parsed.query)
            limit = int((query.get("limit") or ["100"])[0])
            self.send_json({"ok": True, "events": agent_log.tail_events(limit)})
        elif parsed.path == "/policy":
            query = parse_qs(parsed.query)
            root = Path((query.get("root") or ["."])[0]).expanduser().resolve()
            self.send_json({"ok": True, "policy": sentinel_policy.load_policy(root=root)})
        elif parsed.path == "/runs":
            query = parse_qs(parsed.query)
            limit = int((query.get("limit") or ["20"])[0])
            self.send_json({"ok": True, "runs": agent_state.list_runs(limit=limit)})
        elif parsed.path == "/run":
            query = parse_qs(parsed.query)
            run_id = int((query.get("id") or ["0"])[0])
            run = agent_state.get_run(run_id)
            self.send_json({"ok": bool(run), "run": run})
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if not self.is_authorized():
            self.send_json({"ok": False, "error": "unauthorized"}, status=401)
            return
        if parsed.path == "/web-qa":
            self.handle_web_qa()
            return
        if parsed.path == "/scan-async":
            self.handle_scan_async()
            return
        if parsed.path != "/scan":
            self.send_error(404)
            return
        try:
            body = self.read_json()
            self.send_json(run_scan_request(body))
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=500)

    def handle_web_qa(self) -> None:
        try:
            body = self.read_json()
            output_dir = Path(body.get("output_dir") or APP_DIR / SERVICE_CONFIG.get("default_web_output_dir", "latest-web-qa")).expanduser().resolve()
            routes = body.get("routes") or []
            if body.get("discover_routes"):
                root = Path(body.get("root") or ".").expanduser().resolve()
                routes = routes + web_qa.discover_routes(root)
            if routes:
                result = web_qa.run_web_crawl(
                    body["url"],
                    routes,
                    output_dir,
                    clicks=body.get("clicks") or [],
                    viewport=body.get("viewport") or "desktop",
                )
                report_md = output_dir / "web_crawl.md"
                report_json = output_dir / "web_crawl.json"
                screenshot = None
            else:
                result = web_qa.run_web_qa(
                    body["url"],
                    output_dir,
                    clicks=body.get("clicks") or [],
                    viewport=body.get("viewport") or "desktop",
                )
                report_md = output_dir / "web_qa.md"
                report_json = output_dir / "web_qa.json"
                screenshot = result.get("screenshot")
            self.send_json(
                {
                    "ok": bool(result.get("ok")),
                    "status": result.get("status"),
                    "web_qa_md": str(report_md),
                    "web_qa_json": str(report_json),
                    "screenshot": screenshot,
                    "routes": result.get("route_count"),
                    "passed": result.get("passed"),
                    "failed": result.get("failed"),
                    "errors": result.get("errors") or [],
                    "warnings": result.get("warnings") or [],
                },
                status=200 if result.get("ok") else 500,
            )
            agent_log.log_event("web_qa_finished", url=body.get("url"), status=result.get("status"), routes=result.get("route_count"))
        except Exception as exc:
            agent_log.log_event("web_qa_failed", error=str(exc))
            self.send_json({"ok": False, "error": str(exc)}, status=500)

    def handle_scan_async(self) -> None:
        try:
            body = self.read_json()
            job_id = create_job("scan", body)
            EXECUTOR.submit(run_scan_job, job_id, body)
            self.send_json({"ok": True, "job_id": job_id, "status": "queued"}, status=202)
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=500)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        return json.loads(raw)

    def is_authorized(self) -> bool:
        if not SERVICE_CONFIG.get("require_token"):
            return True
        token = SERVICE_CONFIG.get("auth_token") or ""
        if not token:
            return True
        header = self.headers.get("Authorization", "")
        if header == f"Bearer {token}":
            return True
        if self.headers.get("X-Sentinel-Token") == token:
            return True
        return False

    def send_file(self, path: Path, content_type: str) -> None:
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_artifact(self, raw_path: str) -> None:
        try:
            path = safe_local_path(raw_path)
            if not path.is_file():
                raise FileNotFoundError(f"Artifact does not exist: {path}")
            if path.suffix.lower() not in SAFE_ARTIFACT_SUFFIXES:
                raise ValueError("Only report and image artifacts can be opened.")
            content_type = mimetypes.guess_type(path.name)[0] or "text/plain"
            self.send_file(path, content_type)
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=404)

    def send_json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Sentinel-Token")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def create_job(kind: str, payload: dict) -> str:
    job_id = uuid.uuid4().hex
    agent_state.create_job(job_id, kind, safe_payload(payload))
    agent_log.log_event("job_queued", job_id=job_id, kind=kind)
    return job_id


def list_jobs(limit: int = 50) -> list[dict]:
    return agent_state.list_jobs(limit)


def safe_payload(payload: dict) -> dict:
    clean = dict(payload)
    if "token" in clean:
        clean["token"] = "[redacted]"
    return clean


def safe_local_path(raw_path: str) -> Path:
    if not raw_path:
        raise ValueError("Path is required.")
    path = Path(raw_path).expanduser().resolve()
    home = Path.home().resolve()
    if path != home and home not in path.parents:
        raise ValueError("Path must be inside your home folder.")
    return path


def browse_roots() -> list[Path]:
    candidates = [
        Path.home(),
        Path.home() / "Desktop",
        Path.home() / "Documents",
        Path.home() / "Downloads",
        APP_DIR,
    ]
    seen: set[Path] = set()
    roots: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if resolved.exists() and resolved.is_dir() and resolved not in seen:
            seen.add(resolved)
            roots.append(resolved)
    return roots


def browse_directory(raw_path: str = "") -> dict:
    if raw_path:
        path = safe_local_path(raw_path)
    else:
        path = Path.home().resolve()
    if not path.exists() or not path.is_dir():
        raise NotADirectoryError(f"Folder does not exist: {path}")
    entries = []
    for child in path.iterdir():
        if child.name.startswith(".") or not child.is_dir():
            continue
        try:
            resolved = child.resolve()
        except OSError:
            continue
        entries.append({"name": child.name, "path": str(resolved)})
    entries.sort(key=lambda item: item["name"].lower())
    parent = path.parent if path != Path.home().resolve() else None
    return {
        "path": str(path),
        "parent": str(parent) if parent and parent.exists() else None,
        "roots": [{"name": root.name or str(root), "path": str(root)} for root in browse_roots()],
        "entries": entries[:300],
    }


def default_scan_output_dir(root: Path) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return root / "reports" / f"sentinel-{stamp}"


def run_scan_job(job_id: str, body: dict) -> None:
    agent_state.update_job(job_id, "running", started=True)
    agent_log.log_event("job_started", job_id=job_id)
    try:
        response = run_scan_request(body)
        status = "completed" if response.get("ok") else "failed"
        agent_state.update_job(job_id, status, result=response, finished=True)
        agent_log.log_event("job_finished", job_id=job_id, status=status)
    except Exception as exc:
        agent_state.update_job(job_id, "failed", error=str(exc), finished=True)
        agent_log.log_event("job_failed", job_id=job_id, error=str(exc))


def run_scan_request(body: dict) -> dict:
    root = Path(body["root"]).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Project folder does not exist: {root}")
    policy_path = Path(body["policy_path"]).expanduser().resolve() if body.get("policy_path") else None
    policy = sentinel_policy.load_policy(root=root, path=policy_path)
    output_dir = Path(body["output_dir"]).expanduser().resolve() if body.get("output_dir") else default_scan_output_dir(root).resolve()
    model = body.get("model") or policy["ai"].get("model") or SERVICE_CONFIG.get("model") or qa_ai_agent.DEFAULT_MODEL
    include_ai = bool(body.get("ai_review", policy["ai"].get("enabled") if policy["ai"].get("enabled") is not None else SERVICE_CONFIG.get("ai_review", False)))
    web_url = body.get("web_url") or policy["web"].get("base_url")
    agent_log.log_event("scan_started", root=str(root), output_dir=str(output_dir))
    result = sentinel_qa.run_scan(
        root=root,
        output_dir=output_dir,
        config_path=policy_path,
        workers=body.get("workers") or policy["scan"].get("workers") or SERVICE_CONFIG.get("max_workers"),
        timeout=int(body.get("timeout") or policy["scan"].get("timeout_seconds") or SERVICE_CONFIG.get("scan_timeout_seconds", 90)),
    )
    ai_path = None
    status = "completed"
    error = None
    response = {
        "ok": True,
        "report_md": str(result["markdown_path"]),
        "report_json": str(result["json_path"]),
        "finding_count": len(result["findings"]),
        "project_count": len(result["projects"]),
        "severity_counts": agent_state.severity_counts(result["findings"]),
    }
    if include_ai:
        try:
            qa_ai_agent.write_ai_review(
                output_dir,
                root,
                result["projects"],
                result["findings"],
                model=model,
            )
            ai_path = output_dir / "ai_review.md"
            response["ai_review_md"] = str(ai_path)
            response["ai_review_json"] = str(output_dir / "ai_review.json")
        except Exception as exc:
            status = "completed_with_ai_error"
            error = str(exc)
            error_path = output_dir / "ai_review_error.txt"
            error_path.write_text(error, encoding="utf-8")
            response["ai_error"] = error
            response["ai_error_path"] = str(error_path)
    if web_url:
        routes = body.get("web_routes") or policy["web"].get("routes") or []
        if not routes and (body.get("web_discover_routes") or policy["web"].get("discover_routes")):
            routes = web_qa.discover_routes(root)
        if routes:
            web_result = web_qa.run_web_crawl(
                web_url,
                routes,
                output_dir,
                clicks=body.get("web_clicks") or policy["web"].get("clicks") or [],
                viewport=body.get("web_viewport") or policy["web"].get("viewport") or "desktop",
            )
            response["web_qa_md"] = str(output_dir / "web_crawl.md")
            response["web_qa_json"] = str(output_dir / "web_crawl.json")
        else:
            web_result = web_qa.run_web_qa(
                web_url,
                output_dir,
                clicks=body.get("web_clicks") or policy["web"].get("clicks") or [],
                viewport=body.get("web_viewport") or policy["web"].get("viewport") or "desktop",
            )
            response["web_qa_md"] = str(output_dir / "web_qa.md")
            response["web_qa_json"] = str(output_dir / "web_qa.json")
        response["web_qa_status"] = web_result.get("status")
        response["web_qa_screenshot"] = web_result.get("screenshot")
    run_id = agent_state.record_scan(
        result,
        output_dir=output_dir,
        ai_review_md=ai_path,
        status=status,
        error=error,
    )
    response["run_id"] = run_id
    response["status"] = status
    response["policy"] = policy.get("_path")
    agent_log.log_event("scan_finished", root=str(root), run_id=run_id, finding_count=len(result["findings"]), status=status)
    return response


def main() -> int:
    global SERVICE_CONFIG
    parser = argparse.ArgumentParser(description="Run Sentinel QA Agent as a local service.")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--init-config", action="store_true")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--no-auth", action="store_true")
    args = parser.parse_args()
    if args.init_config:
        config_path = settings.ensure_config(args.config)
        print(f"Config written to {config_path}")
        return 0
    SERVICE_CONFIG = settings.load_config(args.config)
    if args.host:
        SERVICE_CONFIG["host"] = args.host
    if args.port:
        SERVICE_CONFIG["port"] = args.port
    if args.no_auth:
        SERVICE_CONFIG["require_token"] = False
    host = SERVICE_CONFIG.get("host", "127.0.0.1")
    port = int(SERVICE_CONFIG.get("port", 8765))
    server = FastLocalHTTPServer((host, port), AgentHandler)
    print(f"Sentinel QA Agent listening on http://{host}:{port}", flush=True)
    if SERVICE_CONFIG.get("require_token") and SERVICE_CONFIG.get("auth_token"):
        print("Token auth enabled. Send Authorization: Bearer <token>.", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
