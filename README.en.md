<div align="center">

<img src="assets/camty-mark.png" width="180" alt="Camty"/>

# Camty

**Red-Team Engagement Workbench** — Recon → Verify → Exploit → Lateral → Report, fully automated

English | [简体中文](README.md)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/tests-330%20passed-brightgreen)
![Adapters](https://img.shields.io/badge/adapters-42-orange)
![License](https://img.shields.io/badge/license-Apache%202.0-black)

</div>

---

## What It Is

Camty is an **auditable red-team engagement workbench**: it puts every action of a penetration test — recon & mapping, vulnerability verification, privilege escalation, lateral movement, evidence archiving, report generation — onto one pipeline, with scope guardrails, an audit hash chain (with optional HMAC and anchoring for tamper evidence), and an evidence ledger, so **every step is compliant, replayable, and deliverable**.

It is at once a toolbox (41 structured adapters), a command console (multi-agent engine + web panel), and an archive (dual-graph cognition + lineage ledger + three-format reports).

## Strengths

**1. Evidence-chain-first governance.** Deny-by-default scope whitelist (DNS-resolution checked), per-action JSONL audit with hash chaining (local edits always break the chain; with `CAMTY_AUDIT_KEY` or saved anchors it also detects full-rewrite-with-recompute and tail truncation; replayable), exploitation actions hard-gated on verified findings by ID, findings carry lineage (`F-003 ← F-001` shows exactly where an exploit chain came from).

**2. 41 structured adapters.** External tools (subfinder/httpx/nuclei/fscan) + purpose-built weapons (js-recon frontend mapping, inj-probe multi-carrier injection with 7 evasion variants, authz-probe authorization matrix, code-audit white-box, mail-code OTP retrieval, osint-recon target profiling, cve-intel CVE matching, hashcrack GPU cracking) + full AD suite (13 impacket tools + 5 lateral engines) + C2 trio. Tool output flows into the ledger and asset graph automatically.

**3. Multi-agent engine with dual-graph cognition.** An LLM planner reads the ledger and asset coverage to build an attack-chain todolist; N workers claim intents in parallel and write back. Asset graph (source of truth + coverage) and exploration graph (intent lineage) resume across restarts; rate-limit backoff, automatic degradation to deterministic mode on repeated LLM failure, and human-in-the-loop steering at any moment.

**4. Adversarial layer.** Chrome TLS fingerprint impersonation for all HTTP traffic (curl_cffi), tri-state browser stealth (Turnstile interplay battle-tested), 7-variant injection obfuscation + chunked transfer, MITM traffic-capture proxy (decrypt-and-record, record-before-response, out-of-scope 403 defense-in-depth).

**5. In-house C2, end to end.** Server + zero-dependency C implant (AES/SHA/HMAC, KAT cross-checked), WinHTTP/schannel encrypted channel, disguise profile (URI/UA/Content-Type switchable), beacon jitter, and a fileless loading chain (XOR-decrypt → in-memory section mapping → IAT resolution → relocation) verified by real E2E.

**6. Engagement output is the deliverable.** HTML / docx / SRC-submission-format reports plus retest diff; IM push (Feishu/DingTalk/WeCom/Telegram); seven-tab panel with force-directed asset coverage graph, per-request traffic replay, attack chain, exploration graph, approval queue, and a human-in-the-loop steering box.

## Quick Start

```bash
git clone https://github.com/MiyanoShihoo/camty.git && cd camty
pip install -r requirements.txt                    # or: pip install --target vendor <pkg>
pip install -r requirements-dev.txt                # test/CI deps (pytest + httpx2), installed separately from runtime deps
python -m camty keys set main --kind openai --base-url https://api.deepseek.com/v1 \
    --api-key sk-xxx --model-decide deepseek-reasoner   # LLM for engine/approvals
python -m pytest tests/ -q                         # 330-test self check
```

Camty supports Python 3.10–3.13 (verified by the CI matrix on Ubuntu and Windows).

## Usage

**Three steps per engagement**: write the authorization config → run → produce the report.

```yaml
# engagements/my-target.yaml — one file per engagement
name: my-target
pack: single-web            # scenario pack under packs/: phases & attack graph
scope:
  domains: [target.com]     # authorization scope: anything else is refused
  min_interval_seconds: 0.3 # rate guardrail
auto_confirm: true          # operator grants full delegation
```

```bash
# (1) Deterministic chain: phases from the scenario pack (resumable)
python -m camty run engagements/my-target.yaml --phase probe
python -m camty auto engagements/my-target.yaml            # full-auto: chain + report

# (2) Multi-agent engine: LLM planner explores autonomously (step budget)
python -m camty engine engagements/my-target.yaml --agent --budget 30 --traffic

# (3) Deliverables
python -m camty report engagements/my-target.yaml --format html   # / docx / src
python -m camty audit engagements/my-target.yaml                 # audit hash-chain check (prints a (count, head_hash) anchor for external archival)
```

**Audit tamper-evidence boundary**: the hash chain itself detects local edits (any change/deletion/insertion breaks it); `save_state` and report generation automatically anchor `(count, head_hash)` into `state.db` to detect tail truncation; setting the `CAMTY_AUDIT_KEY` environment variable appends an HMAC-SHA256 to each entry, detecting "rewrite every record and recompute the whole chain". Without a key or anchors, only local edits are detectable.

**Panel**: `uvicorn camty.api.app:app --port 8090` — dashboard, ledger, force-directed asset coverage, attack chain, traffic replay, exploration graph, approval queue; the header input box injects steering messages at any time (human-in-the-loop). Panel `/api/*` endpoints require a Bearer token: it uses `CAMTY_PANEL_TOKEN` when set, and a random token is generated and printed to stderr otherwise.

**Multiple targets in parallel**: `python -m camty multi a.yaml b.yaml c.yaml`.

**Interactive Repeater**: `python -m camty repeater engagements/my-target.yaml --port 8895` — a speed multiplier for manual vector verification: persistent session (cookies carried across requests), automatic csrf extraction before POSTs, batch vector testing (send N payloads in one call, responses clustered by fingerprint so only outlier clusters need human eyes), and `mode=browser` backed by a persistent stealth browser (`render:true` performs full page rendering, defeating anti-automation client detection). Every request still passes the three gates: scope whitelist, rate limiting, and the tamper-evident audit chain.

```bash
# Single request: auto-extracts title/forms/CSRF/error markers, auto-diffs against the path baseline
curl -X POST localhost:8895/req -H "Content-Type: application/json" \
  -d '{"method":"GET","url":"https://target.example/"}'
# Batch vectors: N payloads in one call, returns baseline + outlier clusters
curl -X POST localhost:8895/vector -H "Content-Type: application/json" \
  -d '{"url":"https://target.example/","param":"q","payloads":["a","b","c"]}'
# POST with automatic CSRF follow: point auto_csrf at the form page
curl -X POST localhost:8895/req -H "Content-Type: application/json" \
  -d '{"method":"POST","url":"https://target.example/login","body":{"user":"x","pass":"y"},"auto_csrf":"https://target.example/login"}'
```

## Engagement Discipline (enforced by the engine)

- Anything outside the scope whitelist is refused (DNS-resolution checked against look-alike domains)
- Exploit-grade actions must reference a verified ledger finding or the engine refuses
- Destructive-action rule gates deny (delete-style endpoints / SQL destruction / dangerous shells)
- Every action is audit-logged with a hash chain + seq + optional HMAC/anchors for tamper evidence (without a key or anchors only local edits are detectable; with them, full-rewrite-with-recompute and tail truncation are detectable); test credentials/sessions never enter the repo (.gitignore enforced)

## Compliance & Disclaimer

**This project is provided solely for authorized security testing and research with explicit written authorization. Unauthorized or illegal use is strictly prohibited. Users are solely responsible for all legal consequences and damages arising from any violation of laws or regulations or from unauthorized testing. The developers of this project are not responsible for any misuse.**

## Layout

```
camty/
├── camty/                    # main package
│   ├── cli.py                #   CLI (run/auto/engine/multi/keys/report/audit)
│   ├── report.py             #   report engine (HTML/docx/SRC submission/retest diff)
│   ├── storage.py            #   SQLite resumable state (progress/context/ledger/graphs)
│   ├── tools.py              #   external tool resolution (tools dir → user Scripts → PATH)
│   ├── traffic.py            #   MITM traffic-capture proxy (CA + per-host certs + scope)
│   ├── mcpbridge.py          #   MCP bridge (external MCP servers → adapters)
│   ├── notify.py             #   IM push (Feishu/DingTalk/WeCom/TG/webhook)
│   ├── adapters/             #   41 structured adapters
│   │   ├── mapping:   osint-recon / subfinder / httpx / js-recon / secret-scan / dir-scan / cve-intel / scopesentry-sync
│   │   ├── browser:   browser-visit / browser-action (tri-state stealth, A/B sessions)
│   │   ├── injection: inj-probe / sqli-probe / sqli-exploit (7-variant evasion + chunked)
│   │   ├── authz:     authz-probe (A/B matrix + forced browsing)
│   │   ├── cracking: hashcrack (hashcat GPU; JWT/NTLM/Kerberoast/bcrypt auto-detect)
│   │   ├── AD:       fscan / smb-enum / samr-enum / ad-users / ad-computers / delegation-find /
│   │   │             kerberoast-check / asreproast-check / secretsdump / laps-read / gpp-password /
│   │   │             keylist / cred-test / lateral-move (5 engines) / machine-account / rbcd-set /
│   │   │             ticket-forgery / ntlmrelay
│   │   ├── C2:       c2-sessions / c2-task / c2-collect
│   │   └── helpers:  code-audit (white-box) / mail-code (IMAP OTP) / evidence-search / report
│   ├── agent/                #   cognition layer
│   │   ├── assets.py         #     asset graph (truth store: auto parent chain + coverage)
│   │   ├── explore.py        #     exploration graph (goal/intent/fact lineage + trace search)
│   │   ├── engine.py         #     multi-agent engine (planner → frontier → N parallel workers)
│   │   ├── planner.py        #     attack-tree planner v2 (parallel batches/priority/budget)
│   │   ├── orchestrator.py   #     engagement orchestration (gates + resume + auto reports)
│   │   ├── runner.py         #     dual runners (deterministic chain / LLM agent loop)
│   │   └── state.py          #     Engagement + lineage ledger
│   ├── guardrail/            #   governance layer
│   │   ├── scope.py          #     scope whitelist (deny-by-default + DNS check + rate)
│   │   ├── audit.py          #     audit hash chain + seq + optional HMAC/anchoring (tamper-evident, replayable)
│   │   ├── rules.py          #     destructive-action rule gates
│   │   ├── approval.py       #     three-mode approvals (interactive/model-fallback/auto)
│   │   ├── preauth.py        #     pre-authorization queue (bulk release + audit)
│   │   └── steer.py          #     human-in-the-loop steering
│   ├── modules/              #   pure-logic weapons (no external deps)
│   │   ├── js_recon.py       #     frontend mapping (endpoints/routes/sourcemap/secrets)
│   │   ├── inj_probe.py      #     multi-carrier injection (GET/POST/JSON × 5 kinds × 7 variants)
│   │   ├── authz_probe.py    #     authz verdicts (similarity/ID echo/session extraction)
│   │   ├── code_audit.py     #     white-box pattern scan (5 languages, noise-tuned)
│   │   ├── cve_intel.py      #     CVE intel (CIRCL matching + CVSS + version filter)
│   │   ├── waf.py            #     WAF fingerprinting (14 passive header signatures)
│   │   ├── http_fp.py        #     Chrome TLS/HTTP impersonation (curl_cffi + urllib fallback)
│   │   └── secret_scan / dir_scan / sqli_probe / sqli_exploit
│   ├── llm/                  #   multi-provider router (openai/responses/anthropic protocols
│   │                         #   + encrypted vault + pool backoff)
│   ├── api/                  #   FastAPI panel (7 tabs + approval queue + engine control)
│   └── knowledge/            #   tactic playbooks ("see X → try Y" injection)
├── c2/                       # in-house C2
│   ├── server/               #   server (beacon endpoint + operator API + disguise profile)
│   ├── implant/              #   C implant sources (beacon.c/loader.c/crypto.c + build scripts +
│   │                         #   fileless-load E2E; binaries built locally, not committed)
│   └── deploy/               #   deploy kit (systemd/Caddyfile/env/deploy.sh/selfcheck.sh)
├── packs/                    # scenario packs: single-web / ext-web / int-ad
├── playbooks/                # tactic playbooks: web/ (10+ service fingerprints) + ad/
├── tests/                    # 330 tests (26 suites: engine/authz/adversarial/MITM E2E/cracking)
├── scripts/                  # helpers (build_beacon/pack_xor/smoke_browser/fetch_tools/build_dist)
├── docs/                     # design.md + c2-design.md (protocol & roadmap)
├── engagements/              # engagement configs (demo templates; real data gitignored)
└── assets/                   # Logo (SVG source + 512/128 PNG)
```

## License

[Apache License 2.0](LICENSE)
