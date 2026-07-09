# Sentinel QA Agent Design

## Goal

Create a proper autonomous QA agent that can run across many projects, find likely bugs and vulnerability flaws, triage them with AI, and produce practical next actions with minimal UI.

## Architecture

```text
CLI / modal / browser extension / editor command
  -> local Sentinel service
    -> project discovery
    -> scanner tools
      -> secrets checks
      -> dependency audits
      -> tests
      -> SAST tools
      -> QA process checks
      -> Playwright web QA
    -> redacted evidence pack
    -> AI reviewer
    -> markdown + JSON reports
```

## Why This Is An AI Agent

The deterministic scanner is the toolbelt. The AI reviewer is the reasoning layer.

The agent can:

- choose the highest-risk findings for review
- inspect nearby code evidence
- classify likely real issues vs false positives
- suggest fixes and tests
- create a ranked QA queue
- run headlessly or behind a tiny UI

## Modes

- `sentinel_qa.py`: CLI and CI mode.
- `sentinel_qa.py --ai-review`: CLI with AI triage.
- `sentinel_agent_server.py`: local background service.
- `ui/index.html`: minimal modal-style UI served by the local service.
- `sentinel_daemon.py`: watch-mode runner for autonomous background scans.
- `agent_state.py`: local SQLite scan history.
- `web_qa.py`: Playwright page-load, console, network, screenshot, and click checks.
- Future extension: Chrome, VS Code, or macOS menu bar can call `POST /scan`.

## Privacy And Safety

- Full projects are not uploaded to the model.
- The AI layer receives only findings and small surrounding snippets.
- Secret-looking values are redacted before model calls.
- Reports are written locally.

## Future Upgrades

- Patch generation with approval.
- Pull request review mode.
- Scheduled scans.
- Per-project policy files.
- Multi-route Playwright crawling for web apps.
- GitHub issue creation for confirmed findings.
- A real extension that calls the local service.

## Production Notes

The current production-oriented build includes installable commands, JSON config,
token auth, async scan jobs, persistent job polling, structured JSONL logs,
project policy files, route discovery, local scan history, web QA reports, and
minimal local UI support. It is suitable as a local developer tool or internal
prototype.

For team/server deployment, add a process manager, HTTPS reverse proxy, log
rotation, team identity, and role-based authorization before exposing it outside
localhost.
