# Deployment Log Analyzer

Upload the logs from a failed Intune or Windows app deployment and get back the most likely root cause, the log lines that prove it, and the steps to fix it. It reads like a note from a senior Intune support engineer, not a list of regex hits.

It was built and tested against real Patch My PC logs (ScriptRunner, detection script, MSI verbose logs and Dell Update Package logs). On that set it picked out one real failure in 10,500 lines of mostly harmless noise: Dell Command Update 5.7.2 refusing to install because the .NET Desktop Runtime 10 was missing.

## How you use it

1. Drop in your logs. The first pass uses the built-in pattern library only. Nothing goes to any AI service, and you get findings, evidence and a confidence score straight away.
2. If that is enough, export the report.
3. If you want a fuller write-up, click **Add AI analysis** on the results page. The findings and surrounding log lines (not your whole files) go to the AI provider you pick, and a second analysis appears. A switch at the top flips between the two. The evidence is shared, so only the written analysis changes.

The server still keeps nothing between steps: your browser holds the first result and sends it back for step 2.

## What it does

1. Takes a ZIP (or tar.gz, gz, or loose log files) by drag and drop. Nested archives are opened automatically.
2. Works out what each log is (Intune Management Extension, Patch My PC ScriptRunner, MSI verbose, Dell DUP, PSADT, CMTrace, or generic text). UTF-16 logs are handled, with or without a BOM.
3. Runs a library of regex patterns (plain JSON, easy to extend) and filters out known harmless noise first.
4. Pulls 100 lines either side of each finding.
5. Ranks causes above symptoms, and links logs that point at each other (ScriptRunner names the installer log it launched).
6. Asks an LLM to write the analysis (Claude, OpenAI or Azure OpenAI), or falls back to the pattern library alone.
7. Scores confidence from five visible factors. The model can nudge the number but cannot push it more than 10 points above what the evidence supports.
8. Exports a Markdown report.

## Run it

You need Python 3.11+ and Node 20+.

```bash
# 1. Backend
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # add a key for the provider you want, or leave empty
uvicorn app.main:app --port 8000

# 2. Frontend (new terminal)
cd frontend
npm install
npm run dev                 # http://localhost:3000
```

Or with Docker: `docker compose up --build`, then open http://localhost:3000.

To host it on Azure instead, see [deploy/azure/README.md](deploy/azure/README.md).

With no API key set the app still works. It runs in "pattern library only" mode, which needs no outside network access at all.

## Choosing an LLM

Set the keys on the server in `backend/.env`. Keys never reach the browser. The results page lets the user pick from whatever is configured when they ask for the AI analysis. Set `LLM_PROVIDER=none` to switch AI off entirely.

| Provider | Settings |
|---|---|
| Anthropic Claude | `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` (default `claude-opus-5-5`) |
| OpenAI | `OPENAI_API_KEY`, `OPENAI_MODEL` (default `gpt-5`), optional `OPENAI_BASE_URL` |
| Azure OpenAI | `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT`, `AZURE_OPENAI_API_VERSION`, and either `AZURE_OPENAI_API_KEY` or nothing (then it uses the host's managed identity / Entra ID) |

`LLM_PROVIDER=auto` picks the first one configured. To add another provider, subclass `LLMProvider` in `backend/app/llm/providers.py` (one method: `complete`) and register it in `factory.py`.

If a provider call fails (rate limit, refusal, bad JSON), the user still gets the pattern-library result, with a note saying why.

## Privacy and data handling

- Nothing is stored. There is no database, no job queue, no session store. A request is read into memory and analysed, and progress is streamed back. The finished result waits in memory for the browser to collect in small pieces (some hosts cut large replies), and is dropped as soon as it has, or after ten minutes. Nothing is written to disk. Because of this the API runs as a single copy.
- Archives are expanded in memory. Size, file count, nesting depth and compression ratio are all limited.
- Only excerpts go to the LLM, not whole files. Before they go, passwords, tokens, SAS signatures, emails and `C:\Users\<name>` are masked (switch off per request if you need to).
- The log text is treated as untrusted. The prompt tells the model to ignore instructions found inside logs, and the model's output is validated before use. A finding ID it makes up is ignored.
- The server never logs file names or contents. Responses are sent with `Cache-Control: no-store`.
- The Docker setup runs read-only with `/tmp` on tmpfs. Large uploads can spill to `/tmp` while being received, and that space disappears with the container.

If your policy says log data must not leave your tenant, use Azure OpenAI in your own subscription, or leave the provider on "pattern library only".

## Large diagnostics packages

An Intune "Collect diagnostics" package can be several hundred MB of mostly noise. The app does not load it all at once:

- Files are listed first and read **one at a time**, so memory stays close to the size of the upload itself.
- `backend/app/patterns/library/triage.json` decides what is worth reading. **High** priority files (Intune Management Extension logs, `dsregcmd` output, Windows Update and servicing logs, installer logs) are read first. **Low** priority files (agent logs, update orchestrator logs, registry exports) are capped to the newest few files and the last N lines. Binary files are skipped with a reason shown in the results.
- Every file is limited to the last `MAX_LINES_PER_FILE` lines, and the whole run stops reading after `MAX_TOTAL_LINES` lines or `TIME_BUDGET_SECONDS` seconds, always high priority first. Line numbers in the evidence are those of the original file.
- Scanning uses a plain-text pre-check so that most lines never reach a regex (about 25,000 lines per second in testing on a 490 MB package, with the peak memory about 30 MB above the size of the upload).

Not read yet: Windows event logs (`.evtx`), `.cab` archives (the MDM diagnostics report is inside one) and `.etl` traces. The results page lists everything that was skipped and why.

## Adding patterns

Patterns live in `backend/app/patterns/library/*.json`. A pattern looks like this:

```json
{
  "id": "dep-dotnet-missing",
  "title": ".NET runtime prerequisite is not installed",
  "category": "prerequisite",
  "severity": "high",
  "role": "cause",
  "weight": 0.95,
  "regex": ["(?P<detail>.{0,120}\\.NET (?:Desktop )?Runtime.{0,120}needs to be installed.{0,60})"],
  "summary": "The installer checked for a required .NET runtime and did not find it: {detail}",
  "remediation": [{ "action": "Deploy the runtime first", "detail": "...", "command": "dotnet --list-runtimes" }],
  "applies_to": ["msi_verbose", "dell_dup"]
}
```

- `role`: `cause` says why it broke, `symptom` only says that it did (exit codes, "installation failed"). Causes always rank above symptoms.
- `weight`: how specific the signature is. A named missing prerequisite is 0.9+, a generic exit code is about 0.35.
- `(?P<detail>...)` captures text to show in the finding.
- `ignore_details` lists regexes for captured values that should not count (for example exit code `0`).
- Known-harmless lines go in `suppressions.json`. They are filtered out before matching and listed in the report as "checked and ruled out".

Set `PATTERN_DIR` to a folder of extra JSON files to add your own without editing the built-in set. The tests check that every regex compiles, every pattern has remediation, and known benign lines do not match.

## Adding a log format

Create a class in `backend/app/parsers/`, subclass `LogParser`, implement `detect` (a 0 to 1 score from the filename and first lines) and `parse` (physical lines to entries), and add it to `PARSERS` in `parsers/__init__.py`.

## Limits

Configured in `backend/.env`: `MAX_UPLOAD_MB` (200), `MAX_EXTRACTED_MB` (600), `MAX_FILE_MB` (100), `MAX_FILES` (1000). Not supported yet: 7z, RAR and CAB archives, and binary `.evtx` / `.etl` files. They are skipped and listed.

## API

| Endpoint | Purpose |
|---|---|
| `POST /api/analyze` | multipart: `files`, optional `provider`, `context`, `redact`. Streams newline-delimited JSON: `progress` events, then the result as `result_begin` (everything except the findings), one `result_finding` per finding and `result_end` (or an `error`). The result is split up because some proxies handle one large streamed message badly. |
| `POST /api/enhance` | JSON: a result from `/api/analyze`, plus `provider` and optional `redact`. Streams progress, then a new result (same message format) with an AI-written analysis. Used by the "Add AI analysis" button. |
| `GET /api/config` | Which providers exist and are configured, and whether AI is available. No secrets. |
| `GET /api/health` | Liveness. |
| `GET /api/docs` | OpenAPI docs. |

## Tests

```bash
cd backend && pip install -r requirements-dev.txt && python -m pytest
cd frontend && npm run typecheck && npm run build
```

The backend tests cover decoding, archive safety, parsers, the pattern library, the 100-line evidence window, scoring, the pipeline end to end, and each provider's request format against a mocked HTTP layer.

## Known limits

- The LLM step cannot be tested here without a live key. The request shape for each provider is tested against mocks, but the quality of the written analysis depends on the model you connect.
- Confidence is a judgement from the evidence, not a probability. It is capped at 95 on purpose.
- The pattern library is a starting point built from common Intune, MSI and PowerShell failures. Add your own as you meet new ones.
