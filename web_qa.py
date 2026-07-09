#!/usr/bin/env python3
"""Playwright-powered web QA checks for Sentinel QA Agent."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse


def playwright_available() -> bool:
    return shutil.which("node") is not None and shutil.which("npx") is not None


def run_web_qa(
    url: str,
    output_dir: Path,
    clicks: list[str] | None = None,
    timeout_ms: int = 30_000,
    viewport: str = "desktop",
) -> dict[str, Any]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    screenshot_path = output_dir / "web_qa_screenshot.png"
    json_path = output_dir / "web_qa.json"
    markdown_path = output_dir / "web_qa.md"

    if not playwright_available():
        result = {
            "ok": False,
            "status": "playwright_unavailable",
            "url": url,
            "errors": ["node and npx are required for web QA mode."],
            "warnings": [],
            "screenshot": None,
        }
        write_outputs(result, json_path, markdown_path)
        return result

    script = build_playwright_script()
    with tempfile.NamedTemporaryFile("w", suffix=".cjs", delete=False, encoding="utf-8") as handle:
        handle.write(script)
        script_path = Path(handle.name)

    payload = json.dumps(
        {
            "url": url,
            "clicks": clicks or [],
            "timeoutMs": timeout_ms,
            "viewport": viewport,
            "screenshotPath": str(screenshot_path),
        }
    )
    command = [
        "npx",
        "--yes",
        "-p",
        "playwright",
        "-c",
        "NODE_PATH=$(dirname $(dirname $(command -v playwright))) "
        f"node {shlex.quote(str(script_path))} {shlex.quote(payload)}",
    ]
    started = time.time()
    try:
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(20, timeout_ms // 1000 + 45),
            check=False,
        )
        result = parse_node_result(completed.stdout, completed.stderr, completed.returncode)
    except subprocess.TimeoutExpired as exc:
        result = {
            "ok": False,
            "status": "timeout",
            "url": url,
            "errors": [f"Web QA timed out: {exc}"],
            "warnings": [],
            "screenshot": None,
        }
    finally:
        try:
            script_path.unlink()
        except OSError:
            pass

    result["runtime_seconds"] = round(time.time() - started, 2)
    result["screenshot"] = str(screenshot_path) if screenshot_path.exists() else None
    write_outputs(result, json_path, markdown_path)
    return result


def run_web_crawl(
    base_url: str,
    routes: list[str],
    output_dir: Path,
    clicks: list[str] | None = None,
    timeout_ms: int = 30_000,
    viewport: str = "desktop",
) -> dict[str, Any]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    urls = normalize_routes(base_url, routes)
    results = []
    for index, url in enumerate(urls, start=1):
        route_dir = output_dir / f"route-{index:02d}"
        result = run_web_qa(
            url,
            route_dir,
            clicks=clicks,
            timeout_ms=timeout_ms,
            viewport=viewport,
        )
        results.append(result)

    passed = sum(1 for result in results if result.get("ok"))
    failed = len(results) - passed
    crawl = {
        "ok": failed == 0,
        "status": "passed" if failed == 0 else "failed",
        "base_url": base_url,
        "route_count": len(results),
        "passed": passed,
        "failed": failed,
        "routes": results,
    }
    (output_dir / "web_crawl.json").write_text(json.dumps(crawl, indent=2), encoding="utf-8")
    (output_dir / "web_crawl.md").write_text(render_crawl_markdown(crawl), encoding="utf-8")
    return crawl


def normalize_routes(base_url: str, routes: list[str]) -> list[str]:
    if not routes:
        return [base_url]
    urls = []
    for route in routes:
        route = route.strip()
        if not route:
            continue
        if urlparse(route).scheme:
            urls.append(route)
        else:
            urls.append(urljoin(base_url.rstrip("/") + "/", route.lstrip("/")))
    return urls or [base_url]


def discover_routes(root: Path) -> list[str]:
    root = root.expanduser().resolve()
    discovered: set[str] = set()
    for pattern in [
        "app/**/page.tsx",
        "app/**/page.jsx",
        "app/**/page.ts",
        "app/**/page.js",
        "pages/**/*.tsx",
        "pages/**/*.jsx",
        "pages/**/*.ts",
        "pages/**/*.js",
        "src/pages/**/*.tsx",
        "src/pages/**/*.jsx",
        "src/pages/**/*.ts",
        "src/pages/**/*.js",
        "public/**/*.html",
    ]:
        for path in root.glob(pattern):
            if any(part in {"node_modules", ".next", "dist", "build"} for part in path.parts):
                continue
            route = route_from_path(root, path)
            if route:
                discovered.add(route)
    return sorted(discovered, key=lambda item: (item.count("/"), item))


def route_from_path(root: Path, path: Path) -> str | None:
    rel = path.relative_to(root)
    parts = list(rel.parts)
    if not parts:
        return None
    if parts[0] == "app" and parts[-1].startswith("page."):
        route_parts = parts[1:-1]
    elif parts[0] in {"pages", "public"}:
        route_parts = parts[1:]
        route_parts[-1] = strip_extension(route_parts[-1])
    elif len(parts) >= 2 and parts[0] == "src" and parts[1] == "pages":
        route_parts = parts[2:]
        route_parts[-1] = strip_extension(route_parts[-1])
    else:
        return None
    route_parts = [part for part in route_parts if part not in {"index", "page"}]
    route_parts = [dynamic_segment(part) for part in route_parts]
    route = "/" + "/".join(route_parts)
    return route.rstrip("/") or "/"


def strip_extension(name: str) -> str:
    return name.split(".", 1)[0]


def dynamic_segment(part: str) -> str:
    if part.startswith("[") and part.endswith("]"):
        return "sample"
    return part


def build_playwright_script() -> str:
    return textwrap.dedent(
        """
        const { chromium } = require('playwright');

        (async () => {
        const input = JSON.parse(process.argv[2]);
        const errors = [];
        const warnings = [];
        const networkFailures = [];
        const badResponses = [];
        const consoleMessages = [];
        const viewport = input.viewport === 'mobile'
          ? { width: 390, height: 844 }
          : { width: 1440, height: 900 };

        let browser;
        try {
          browser = await chromium.launch({ headless: true });
          const page = await browser.newPage({ viewport });
          page.on('console', message => {
            const item = { type: message.type(), text: message.text() };
            consoleMessages.push(item);
            if (message.type() === 'error') errors.push(`console error: ${message.text()}`);
            if (message.type() === 'warning') warnings.push(`console warning: ${message.text()}`);
          });
          page.on('pageerror', error => errors.push(`page error: ${error.message}`));
          page.on('requestfailed', request => {
            networkFailures.push({
              url: request.url(),
              method: request.method(),
              failure: request.failure()?.errorText || 'unknown',
            });
          });
          page.on('response', response => {
            if (response.status() >= 400) {
              badResponses.push({ url: response.url(), status: response.status() });
            }
          });

          const response = await page.goto(input.url, {
            waitUntil: 'domcontentloaded',
            timeout: input.timeoutMs,
          });
          await page.waitForTimeout(1000);

          const clickResults = [];
          for (const selector of input.clicks) {
            try {
              await page.locator(selector).first().click({ timeout: 5000 });
              await page.waitForTimeout(500);
              clickResults.push({ selector, ok: true });
            } catch (error) {
              errors.push(`click failed for ${selector}: ${error.message}`);
              clickResults.push({ selector, ok: false, error: error.message });
            }
          }

          const bodyText = await page.locator('body').innerText({ timeout: 5000 }).catch(() => '');
          const title = await page.title();
          const finalUrl = page.url();
          const htmlLength = await page.content().then(html => html.length);
          await page.screenshot({ path: input.screenshotPath, fullPage: false });

          const blank = bodyText.trim().length < 20 && htmlLength < 1000;
          if (blank) errors.push('page appears blank or nearly blank');
          if (badResponses.length) warnings.push(`${badResponses.length} HTTP response(s) returned 4xx/5xx`);
          if (networkFailures.length) warnings.push(`${networkFailures.length} network request(s) failed`);

          const result = {
            ok: errors.length === 0,
            status: errors.length === 0 ? 'passed' : 'failed',
            url: input.url,
            final_url: finalUrl,
            title,
            http_status: response ? response.status() : null,
            viewport,
            body_text_length: bodyText.trim().length,
            html_length: htmlLength,
            blank,
            errors,
            warnings,
            network_failures: networkFailures.slice(0, 25),
            bad_responses: badResponses.slice(0, 25),
            console_messages: consoleMessages.slice(0, 50),
            click_results: clickResults,
          };
          console.log(JSON.stringify(result)); // sentinel-qa: ignore
        } catch (error) {
          console.log(JSON.stringify({ // sentinel-qa: ignore
            ok: false,
            status: 'failed',
            url: input.url,
            errors: [error.message],
            warnings,
            network_failures: networkFailures,
            bad_responses: badResponses,
            console_messages: consoleMessages,
          }));
        } finally {
          if (browser) await browser.close();
        }
        })();
        """
    )


def parse_node_result(stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
    lines = [line for line in stdout.splitlines() if line.strip()]
    for line in reversed(lines):
        try:
            result = json.loads(line)
            if returncode != 0:
                result["ok"] = False
                result["status"] = result.get("status") or "failed"
                result.setdefault("errors", []).append(f"Playwright exited with code {returncode}")
            if stderr.strip():
                result.setdefault("warnings", []).append(stderr.strip()[-1000:])
            return result
        except json.JSONDecodeError:
            continue
    return {
        "ok": False,
        "status": "failed",
        "errors": [stderr.strip() or stdout.strip() or "Playwright did not return JSON."],
        "warnings": [],
    }


def write_outputs(result: dict[str, Any], json_path: Path, markdown_path: Path) -> None:
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown(result), encoding="utf-8")


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Sentinel Web QA Report",
        "",
        f"- URL: `{result.get('url', '')}`",
        f"- Final URL: `{result.get('final_url', 'n/a')}`",
        f"- Status: `{result.get('status', 'unknown')}`",
        f"- Title: `{result.get('title', 'n/a')}`",
        f"- Screenshot: `{result.get('screenshot') or 'none'}`",
        "",
        "## Checks",
        "",
        f"- Page loaded: {'pass' if result.get('http_status') is None or result.get('http_status', 0) < 400 else 'fail'}",
        f"- Not blank: {'pass' if not result.get('blank') else 'fail'}",
        f"- Console/page errors: {'pass' if not result.get('errors') else 'fail'}",
        f"- Network warnings: {'pass' if not result.get('network_failures') and not result.get('bad_responses') else 'warn'}",
        "",
        "## Errors",
        "",
    ]
    errors = result.get("errors") or []
    lines.extend([f"- {item}" for item in errors] or ["- None"])
    lines.extend(["", "## Warnings", ""])
    warnings = result.get("warnings") or []
    lines.extend([f"- {item}" for item in warnings] or ["- None"])
    lines.extend(["", "## Click Results", ""])
    clicks = result.get("click_results") or []
    lines.extend([f"- `{item.get('selector')}`: {'pass' if item.get('ok') else 'fail'}" for item in clicks] or ["- No click actions configured."])
    return "\n".join(lines) + "\n"


def render_crawl_markdown(crawl: dict[str, Any]) -> str:
    lines = [
        "# Sentinel Web Crawl Report",
        "",
        f"- Base URL: `{crawl.get('base_url', '')}`",
        f"- Status: `{crawl.get('status', 'unknown')}`",
        f"- Routes: `{crawl.get('route_count', 0)}`",
        f"- Passed: `{crawl.get('passed', 0)}`",
        f"- Failed: `{crawl.get('failed', 0)}`",
        "",
        "## Route Results",
        "",
    ]
    for index, result in enumerate(crawl.get("routes") or [], start=1):
        lines.extend(
            [
                f"### {index}. {result.get('url', '')}",
                "",
                f"- Status: `{result.get('status', 'unknown')}`",
                f"- Title: `{result.get('title', 'n/a')}`",
                f"- Final URL: `{result.get('final_url', 'n/a')}`",
                f"- Screenshot: `{result.get('screenshot') or 'none'}`",
                f"- Errors: `{len(result.get('errors') or [])}`",
                f"- Warnings: `{len(result.get('warnings') or [])}`",
                "",
            ]
        )
        for error in result.get("errors") or []:
            lines.append(f"  - Error: {error}")
        for warning in result.get("warnings") or []:
            lines.append(f"  - Warning: {warning}")
        if result.get("errors") or result.get("warnings"):
            lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run Sentinel web QA checks against a URL.")
    parser.add_argument("url")
    parser.add_argument("--route", action="append", default=[])
    parser.add_argument("--output-dir", type=Path, default=Path("sentinel-web-qa-report"))
    parser.add_argument("--click", action="append", default=[])
    parser.add_argument("--timeout-ms", type=int, default=30_000)
    parser.add_argument("--viewport", choices=["desktop", "mobile"], default="desktop")
    args = parser.parse_args()
    if args.route:
        result = run_web_crawl(args.url, args.route, args.output_dir, args.click, args.timeout_ms, args.viewport)
        print(f"Web crawl report: {(args.output_dir / 'web_crawl.md').resolve()}")
        print(f"Routes: {result.get('passed')} passed, {result.get('failed')} failed")
    else:
        result = run_web_qa(args.url, args.output_dir, args.click, args.timeout_ms, args.viewport)
        print(f"Web QA report: {(args.output_dir / 'web_qa.md').resolve()}")
        print(f"Screenshot: {result.get('screenshot') or 'none'}")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
