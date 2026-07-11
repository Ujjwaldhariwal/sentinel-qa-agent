import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "sentinel_qa.py"
SPEC = importlib.util.spec_from_file_location("sentinel_qa", MODULE_PATH)
sentinel_qa = importlib.util.module_from_spec(SPEC)
sys.modules["sentinel_qa"] = sentinel_qa
SPEC.loader.exec_module(sentinel_qa)

STATE_PATH = Path(__file__).resolve().parents[1] / "agent_state.py"
STATE_SPEC = importlib.util.spec_from_file_location("agent_state", STATE_PATH)
agent_state = importlib.util.module_from_spec(STATE_SPEC)
sys.modules["agent_state"] = agent_state
STATE_SPEC.loader.exec_module(agent_state)

WEB_QA_PATH = Path(__file__).resolve().parents[1] / "web_qa.py"
WEB_QA_SPEC = importlib.util.spec_from_file_location("web_qa", WEB_QA_PATH)
web_qa = importlib.util.module_from_spec(WEB_QA_SPEC)
sys.modules["web_qa"] = web_qa
WEB_QA_SPEC.loader.exec_module(web_qa)

SETTINGS_PATH = Path(__file__).resolve().parents[1] / "settings.py"
SETTINGS_SPEC = importlib.util.spec_from_file_location("settings", SETTINGS_PATH)
settings = importlib.util.module_from_spec(SETTINGS_SPEC)
sys.modules["settings"] = settings
SETTINGS_SPEC.loader.exec_module(settings)

POLICY_PATH = Path(__file__).resolve().parents[1] / "sentinel_policy.py"
POLICY_SPEC = importlib.util.spec_from_file_location("sentinel_policy", POLICY_PATH)
sentinel_policy = importlib.util.module_from_spec(POLICY_SPEC)
sys.modules["sentinel_policy"] = sentinel_policy
POLICY_SPEC.loader.exec_module(sentinel_policy)

SERVER_PATH = Path(__file__).resolve().parents[1] / "sentinel_agent_server.py"
SERVER_SPEC = importlib.util.spec_from_file_location("sentinel_agent_server", SERVER_PATH)
sentinel_agent_server = importlib.util.module_from_spec(SERVER_SPEC)
sys.modules["sentinel_agent_server"] = sentinel_agent_server
SERVER_SPEC.loader.exec_module(sentinel_agent_server)


class SentinelQaTests(unittest.TestCase):
    def test_secret_pattern_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            source = project / "app.py"
            key_name = "API" + "_KEY"
            source.write_text(f"{key_name} = 'secret-value-12345'\n", encoding="utf-8")

            findings = sentinel_qa.scan_file(project, source, project)

        self.assertTrue(any(finding.category == "secrets" for finding in findings))

    def test_scanner_rule_definitions_are_not_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            source = project / "rules.py"
            source.write_text(
                '("high", "Potential XSS sink", re.compile(r"innerHTML"))\n',
                encoding="utf-8",
            )

            findings = sentinel_qa.scan_file(project, source, project)

        self.assertEqual(findings, [])

    def test_safe_subprocess_run_is_not_shell_interpolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            source = project / "tool.py"
            source.write_text(
                'completed = subprocess.run(["git", "status"], check=False)\n',
                encoding="utf-8",
            )

            findings = sentinel_qa.scan_file(project, source, project)

        self.assertFalse(any(finding.title == "Shell execution with interpolation" for finding in findings))

    def test_report_folders_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "package.json").write_text("{}", encoding="utf-8")
            reports = project / "reports"
            reports.mkdir()
            (reports / "report.md").write_text("innerHTML\n", encoding="utf-8")  # sentinel-qa: ignore

            result = sentinel_qa.run_scan(project, output_dir=project / "out", workers=1, run_optional_tools=False)

        self.assertFalse(any(finding.path.startswith("reports/") for finding in result["findings"]))

    def test_inline_ignore_marker_suppresses_known_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            source = project / "fixture.py"
            source.write_text('sample = "innerHTML"  # sentinel-qa: ignore\n', encoding="utf-8")

            findings = sentinel_qa.scan_file(project, source, project)

        self.assertEqual(findings, [])

    def test_markdown_report_contains_summary(self):
        report = sentinel_qa.render_markdown(
            Path("/tmp/example"),
            [Path("/tmp/example/app")],
            [],
            0.25,
        )

        self.assertIn("Sentinel QA Agent Report", report)
        self.assertIn("Projects scanned", report)

    def test_run_scan_writes_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "app"
            output = Path(tmp) / "report"
            project.mkdir()
            (project / "package.json").write_text('{"scripts":{}}\n', encoding="utf-8")

            result = sentinel_qa.run_scan(project, output_dir=output, workers=1, run_optional_tools=False)
            markdown_exists = result["markdown_path"].exists()
            json_exists = result["json_path"].exists()

        self.assertTrue(markdown_exists)
        self.assertTrue(json_exists)

    def test_project_profile_detects_common_stack_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "package.json").write_text(
                '{"dependencies":{"next":"latest","react":"latest"},"scripts":{"test":"vitest"}}',
                encoding="utf-8",
            )
            (project / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
            (project / "tests").mkdir()
            (project / ".github" / "workflows").mkdir(parents=True)

            profile = sentinel_qa.detect_project_profile(project)

        self.assertIn("node", profile["languages"])
        self.assertIn("Next.js", profile["frameworks"])
        self.assertIn("React", profile["frameworks"])
        self.assertIn("pnpm", profile["package_managers"])
        self.assertIn("npm script: test", profile["test_signals"])
        self.assertIn(".github/workflows", profile["ci"])

    def test_run_scan_json_includes_summary_and_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            output = project / "report"
            (project / "pyproject.toml").write_text("[project]\nname='api'\ndependencies=['fastapi']\n", encoding="utf-8")
            (project / "app.py").write_text("debug = true\n", encoding="utf-8")

            result = sentinel_qa.run_scan(project, output_dir=output, workers=1, run_optional_tools=False)
            payload = json.loads(result["json_path"].read_text(encoding="utf-8"))

        self.assertIn("summary", payload)
        self.assertIn("profiles", payload)
        self.assertIn("FastAPI", payload["profiles"][str(project.resolve())]["frameworks"])
        self.assertGreaterEqual(payload["summary"]["severity_counts"]["medium"], 1)

    def test_scan_history_records_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "history.sqlite3"
            output = Path(tmp) / "report"
            output.mkdir()
            result = {
                "root": Path(tmp),
                "projects": [Path(tmp)],
                "findings": [
                    sentinel_qa.Finding(
                        "high",
                        "secrets",
                        "app",
                        "app.py",
                        1,
                        "Example",
                        "detail",
                        "fix",
                    )
                ],
                "elapsed": 0.1,
                "markdown_path": output / "report.md",
                "json_path": output / "report.json",
            }

            run_id = agent_state.record_scan(result, output, db_path=db_path)
            runs = agent_state.list_runs(db_path=db_path)

        self.assertEqual(run_id, 1)
        self.assertEqual(runs[0]["severity_counts"]["high"], 1)

    def test_web_qa_markdown_reports_errors(self):
        report = web_qa.render_markdown(
            {
                "url": "http://localhost:3000",
                "status": "failed",
                "blank": True,
                "errors": ["page appears blank or nearly blank"],
                "warnings": [],
            }
        )

        self.assertIn("Sentinel Web QA Report", report)
        self.assertIn("page appears blank", report)

    def test_web_routes_are_normalized(self):
        urls = web_qa.normalize_routes("http://localhost:3000/app", ["/", "login", "https://example.com/x"])

        self.assertEqual(urls[0], "http://localhost:3000/app/")
        self.assertEqual(urls[1], "http://localhost:3000/app/login")
        self.assertEqual(urls[2], "https://example.com/x")

    def test_web_crawl_markdown_summarizes_routes(self):
        report = web_qa.render_crawl_markdown(
            {
                "base_url": "http://localhost:3000",
                "status": "failed",
                "route_count": 2,
                "passed": 1,
                "failed": 1,
                "routes": [
                    {"url": "http://localhost:3000", "status": "passed", "errors": [], "warnings": []},
                    {"url": "http://localhost:3000/login", "status": "failed", "errors": ["boom"], "warnings": []},
                ],
            }
        )

        self.assertIn("Sentinel Web Crawl Report", report)
        self.assertIn("boom", report)

    def test_settings_generates_config_with_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "sentinel.config.json"

            written = settings.ensure_config(config_path)
            config = settings.load_config(written)

        self.assertTrue(written.name == "sentinel.config.json")
        self.assertTrue(config["auth_token"])
        self.assertTrue(config["require_token"])

    def test_persistent_jobs_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "history.sqlite3"
            agent_state.create_job("job-1", "scan", {"root": "/tmp/project"}, db_path=db_path)
            agent_state.update_job("job-1", "completed", result={"ok": True}, started=True, finished=True, db_path=db_path)
            job = agent_state.get_job("job-1", db_path=db_path)

        self.assertEqual(job["status"], "completed")
        self.assertTrue(job["result"]["ok"])

    def test_policy_loads_nested_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sentinel.policy.json").write_text(
                '{"web":{"routes":["/","/login"],"discover_routes":true},"ai":{"enabled":true}}',
                encoding="utf-8",
            )

            policy = sentinel_policy.load_policy(root=root)

        self.assertEqual(policy["web"]["routes"], ["/", "/login"])
        self.assertTrue(policy["web"]["discover_routes"])
        self.assertTrue(policy["ai"]["enabled"])

    def test_route_discovery_finds_next_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app" / "dashboard").mkdir(parents=True)
            (root / "app" / "dashboard" / "page.tsx").write_text("export default function Page() {}", encoding="utf-8")
            (root / "pages").mkdir()
            (root / "pages" / "login.tsx").write_text("export default function Login() {}", encoding="utf-8")

            routes = web_qa.discover_routes(root)

        self.assertIn("/dashboard", routes)
        self.assertIn("/login", routes)

    def test_browse_directory_lists_home_child_folders(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp)
            child = root / "sample-project"
            child.mkdir()

            listing = sentinel_agent_server.browse_directory(str(root))

        self.assertEqual(listing["path"], str(root.resolve()))
        self.assertTrue(any(item["name"] == "sample-project" for item in listing["entries"]))

    def test_safe_local_path_rejects_paths_outside_home(self):
        outside_home = Path("/private/tmp").resolve()

        with self.assertRaises(ValueError):
            sentinel_agent_server.safe_local_path(str(outside_home))

    def test_scan_request_includes_severity_counts(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            project = Path(tmp)
            (project / "package.json").write_text("{}", encoding="utf-8")
            original_record_scan = sentinel_agent_server.agent_state.record_scan
            sentinel_agent_server.agent_state.record_scan = lambda *args, **kwargs: 999
            try:
                response = sentinel_agent_server.run_scan_request(
                    {
                        "root": str(project),
                        "output_dir": str(project / "reports" / "smoke"),
                        "ai_review": False,
                        "skip_optional_tools": True,
                    }
                )
            finally:
                sentinel_agent_server.agent_state.record_scan = original_record_scan

        self.assertTrue(response["ok"])
        self.assertIn("severity_counts", response)
        self.assertEqual(response["project_count"], 1)
        self.assertEqual(response["run_id"], 999)

    def test_doctor_fails_closed_when_docker_is_unavailable(self):
        original = sentinel_agent_server.doctor.sandbox_runner.docker_available
        sentinel_agent_server.doctor.sandbox_runner.docker_available = lambda: False
        try:
            payload = sentinel_agent_server.doctor.run_doctor()
        finally:
            sentinel_agent_server.doctor.sandbox_runner.docker_available = original

        statuses = {check["name"]: check["status"] for check in payload["checks"]}
        self.assertEqual(statuses["Docker"], "fail")
        self.assertEqual(statuses["Scanner image"], "fail")
        self.assertFalse(payload["ok"])

    def test_dashboard_contains_findings_investigation_controls(self):
        html = (Path(__file__).resolve().parents[1] / "ui" / "index.html").read_text(encoding="utf-8")

        self.assertIn('id="findingsPanel"', html)
        self.assertIn('id="severityFilter"', html)
        self.assertIn('id="categoryFilter"', html)
        self.assertIn('id="readiness"', html)
        self.assertIn("loadDoctor", html)
        self.assertIn("loadFindings", html)
        self.assertIn("inspectRun", html)
        self.assertIn("Inspect", html)


if __name__ == "__main__":
    unittest.main()
