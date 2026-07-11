#!/usr/bin/env python3
"""Static QA test-case planning for Sentinel reports.

This module designs test cases from repository shape and scanner findings. It
does not execute generated tests against the target repository; existing project
test commands are still executed by sentinel_qa through the Docker sandbox.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import re
from pathlib import Path
from typing import Any


@dataclasses.dataclass(frozen=True)
class TestCaseSpec:
    id: str
    project: str
    priority: str
    kind: str
    title: str
    target: str
    rationale: str
    steps: list[str]
    expected_result: str
    execution_status: str = "planned"


def generate_test_cases(
    project: Path,
    profile: dict[str, Any],
    findings: list[Any],
    *,
    max_cases: int = 16,
) -> list[TestCaseSpec]:
    cases: list[TestCaseSpec] = []
    project_name = profile.get("name") or project.name or str(project)

    cases.extend(stack_cases(project_name, profile))
    cases.extend(finding_cases(project_name, findings))
    cases.extend(code_shape_cases(project, project_name))

    deduped: list[TestCaseSpec] = []
    seen: set[tuple[str, str]] = set()
    for case in cases:
        key = (case.kind, case.target)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(case)
        if len(deduped) >= max_cases:
            break
    return [renumber(case, index + 1) for index, case in enumerate(deduped)]


def stack_cases(project_name: str, profile: dict[str, Any]) -> list[TestCaseSpec]:
    cases: list[TestCaseSpec] = []
    languages = set(profile.get("languages") or [])
    frameworks = set(profile.get("frameworks") or [])
    tests = profile.get("test_signals") or []

    if tests:
        cases.append(
            make_case(
                project_name,
                "high",
                "existing-suite",
                "Existing test suite must pass in a clean checkout",
                ", ".join(tests),
                "Existing test signals were detected, so they should become the baseline QA gate.",
                [
                    "Install dependencies using the repository's documented command.",
                    "Run the detected test command or framework test runner.",
                    "Fail the scan if any test fails or hangs.",
                ],
                "All existing automated tests pass without network-only side effects.",
            )
        )
    else:
        cases.append(
            make_case(
                project_name,
                "high",
                "bootstrap",
                "Add a first smoke test suite",
                ".",
                "No obvious test suite was detected.",
                [
                    "Identify the main entry point or most important workflow.",
                    "Create one smoke test that exercises it without external services.",
                    "Add the test command to project scripts or CI.",
                ],
                "The project has at least one deterministic smoke test that can run locally.",
            )
        )

    if "Next.js" in frameworks or "React" in frameworks:
        cases.append(
            make_case(
                project_name,
                "high",
                "frontend-smoke",
                "Primary page renders without console errors",
                "app/pages/components",
                "React or Next.js projects commonly fail through blank screens, hydration issues, or browser console errors.",
                [
                    "Start the app locally.",
                    "Open the primary route and one secondary route.",
                    "Capture console errors, failed requests, and visible blank states.",
                ],
                "Pages render visible content and no uncaught browser errors are produced.",
            )
        )
    if {"FastAPI", "Flask", "Django"} & frameworks:
        cases.append(
            make_case(
                project_name,
                "high",
                "api-smoke",
                "API health and invalid-input behavior",
                "api routes",
                "Python web APIs need coverage for success paths and malformed requests.",
                [
                    "Start the app with test settings.",
                    "Call a healthy route or documented endpoint.",
                    "Send malformed JSON or missing required fields.",
                ],
                "Healthy routes return success and malformed inputs return controlled 4xx errors.",
            )
        )
    if "python" in languages:
        cases.append(
            make_case(
                project_name,
                "medium",
                "python-import",
                "Python modules import cleanly",
                "*.py",
                "Import-time crashes break CLIs, services, and tests before business logic can run.",
                [
                    "Import top-level application modules in a test process.",
                    "Block network and production side effects during import.",
                    "Assert no exception is raised.",
                ],
                "Application modules import without executing unsafe production side effects.",
            )
        )
    return cases


def finding_cases(project_name: str, findings: list[Any]) -> list[TestCaseSpec]:
    cases: list[TestCaseSpec] = []
    for finding in sorted(findings, key=lambda item: (severity_rank(getattr(item, "severity", "")), getattr(item, "path", ""))):
        title = getattr(finding, "title", "")
        category = getattr(finding, "category", "")
        path = getattr(finding, "path", ".")
        if category == "secrets":
            cases.append(
                make_case(
                    project_name,
                    "critical",
                    "secret-regression",
                    "Secret leakage regression check",
                    path,
                    "A secret-like value was detected and should never reappear in source or generated reports.",
                    [
                        "Remove and rotate any real credential.",
                        "Add a fixture or scanner test that catches the same token pattern.",
                        "Run the scanner before commit.",
                    ],
                    "The same credential pattern is blocked before code is shared.",
                )
            )
        elif "XSS" in title or "innerHTML" in getattr(finding, "detail", ""):  # sentinel-qa: ignore
            cases.append(
                make_case(
                    project_name,
                    "high",
                    "xss-abuse",
                    "Untrusted HTML input cannot execute script",
                    path,
                    "The scanner found a browser HTML sink.",
                    [
                        "Render the component or page with a payload such as <img src=x onerror=alert(1)>.",
                        "Assert the payload is escaped or sanitized.",
                        "Assert no script execution or unexpected DOM mutation occurs.",
                    ],
                    "Untrusted input is displayed safely and cannot execute JavaScript.",
                )
            )
        elif "eval" in title.lower() or "shell" in title.lower():
            cases.append(
                make_case(
                    project_name,
                    "high",
                    "input-abuse",
                    f"Unsafe execution path is unreachable from user input: {title}",
                    path,
                    "The scanner found a dangerous execution primitive.",
                    [
                        "Identify the public function, CLI argument, or route that reaches this code.",
                        "Send metacharacters, command separators, and invalid expressions.",
                        "Assert the input is rejected or treated as inert data.",
                    ],
                    "User-controlled input cannot trigger code or shell execution.",
                )
            )
        elif "SQL" in title:
            cases.append(
                make_case(
                    project_name,
                    "high",
                    "sql-injection",
                    "SQL injection payload is rejected",
                    path,
                    "The scanner found SQL construction that may be unsafe.",
                    [
                        "Call the query path with payloads like ' OR '1'='1.",
                        "Assert parameter binding is used or the request is rejected.",
                        "Assert no extra records are returned.",
                    ],
                    "SQL metacharacters do not change query semantics.",
                )
            )
        elif category in {"qa-coverage", "test-failure"}:
            cases.append(
                make_case(
                    project_name,
                    "high",
                    "qa-gate",
                    title,
                    path,
                    getattr(finding, "detail", "") or "QA gate needs attention.",
                    [
                        "Create or repair the smallest deterministic test for this gap.",
                        "Run it locally.",
                        "Add it to the project's default test command.",
                    ],
                    "The QA gap is covered by an automated test that runs in the default suite.",
                )
            )
    return cases


def code_shape_cases(project: Path, project_name: str) -> list[TestCaseSpec]:
    cases: list[TestCaseSpec] = []
    for path, functions in discover_python_functions(project)[:5]:
        for function in functions[:2]:
            cases.append(
                make_case(
                    project_name,
                    "medium",
                    "unit",
                    f"Unit behavior for {function}()",
                    path.as_posix(),
                    "Public Python functions should have deterministic input/output coverage.",
                    [
                        f"Call {function}() with a normal input.",
                        f"Call {function}() with an empty, missing, or invalid input.",
                        "Assert the return value or raised exception is explicit.",
                    ],
                    "Normal and invalid inputs have documented, repeatable behavior.",
                )
            )
    for path, symbols in discover_js_symbols(project)[:5]:
        for symbol in symbols[:2]:
            cases.append(
                make_case(
                    project_name,
                    "medium",
                    "unit",
                    f"Unit or render behavior for {symbol}",
                    path.as_posix(),
                    "Exported JavaScript or TypeScript symbols should have regression coverage.",
                    [
                        f"Import or render {symbol} in the project test runner.",
                        "Exercise the primary success path.",
                        "Exercise one invalid or empty state.",
                    ],
                    "The exported behavior is stable for success and empty/error states.",
                )
            )
    return cases


def discover_python_functions(project: Path) -> list[tuple[Path, list[str]]]:
    discovered: list[tuple[Path, list[str]]] = []
    for path in sorted(project.rglob("*.py")):
        if skip_path(path):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError):
            continue
        functions = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not node.name.startswith("_")
            and node.name not in {"main"}
        ]
        if functions:
            discovered.append((path.relative_to(project), sorted(set(functions))))
    return discovered


def discover_js_symbols(project: Path) -> list[tuple[Path, list[str]]]:
    discovered: list[tuple[Path, list[str]]] = []
    pattern = re.compile(r"\bexport\s+(?:default\s+)?(?:function|const|class)\s+([A-Za-z_$][\w$]*)")
    for suffix in ("*.js", "*.jsx", "*.ts", "*.tsx"):
        for path in sorted(project.rglob(suffix)):
            if skip_path(path):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            symbols = sorted(set(pattern.findall(text)))
            if symbols:
                discovered.append((path.relative_to(project), symbols))
    return discovered


def skip_path(path: Path) -> bool:
    blocked = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", "reports", "state"}
    return bool(set(path.parts) & blocked) or path.name.startswith("test_") or ".test." in path.name or ".spec." in path.name


def make_case(
    project: str,
    priority: str,
    kind: str,
    title: str,
    target: str,
    rationale: str,
    steps: list[str],
    expected_result: str,
) -> TestCaseSpec:
    return TestCaseSpec(
        id="pending",
        project=project,
        priority=priority,
        kind=kind,
        title=title,
        target=target,
        rationale=rationale,
        steps=steps,
        expected_result=expected_result,
    )


def renumber(case: TestCaseSpec, index: int) -> TestCaseSpec:
    return dataclasses.replace(case, id=f"TC-{index:03d}")


def severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity, 99)


def render_markdown(cases: list[TestCaseSpec]) -> str:
    lines = ["# Sentinel Generated QA Test Cases", ""]
    if not cases:
        lines.append("No test cases were generated.")
        return "\n".join(lines) + "\n"
    lines.extend(
        [
            "These are generated test-case specs based on static project signals and scanner findings.",
            "Existing project test commands are executed separately by Sentinel through the Docker sandbox when enabled.",
            "",
        ]
    )
    for case in cases:
        lines.extend(
            [
                f"## {case.id}: {case.title}",
                "",
                f"- Project: `{case.project}`",
                f"- Priority: `{case.priority}`",
                f"- Type: `{case.kind}`",
                f"- Target: `{case.target}`",
                f"- Execution status: `{case.execution_status}`",
                f"- Rationale: {case.rationale}",
                "- Steps:",
            ]
        )
        for step in case.steps:
            lines.append(f"  - {step}")
        lines.extend([f"- Expected result: {case.expected_result}", ""])
    return "\n".join(lines)


def write_artifacts(output_dir: Path, cases: list[TestCaseSpec]) -> tuple[Path, Path]:
    markdown_path = output_dir / "test_cases.md"
    json_path = output_dir / "test_cases.json"
    markdown_path.write_text(render_markdown(cases), encoding="utf-8")
    payload = {"test_cases": [dataclasses.asdict(case) for case in cases]}
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return markdown_path.resolve(), json_path.resolve()
