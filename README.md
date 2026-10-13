# Juice Shop Security Lab

A hands-on lab that uses [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) v20.2.0 as a target for AI-assisted security work with Claude Code. It covers project instructions (`CLAUDE.md`), skills, MCP servers and subagents, and produces a set of security reports on the application.

> **Juice Shop is deliberately vulnerable.** Most findings in this repo are intentional challenge content. Run it only on an isolated machine or network, never with real data, and never expose it to the internet. The original upstream README is kept as [UPSTREAM-README.md](UPSTREAM-README.md), and the upstream source and licence (MIT) are unchanged.

## What is in this repo

| Path | What it is |
|---|---|
| Everything under the upstream layout (`routes/`, `lib/`, `frontend/`, `terraform/`, ...) | The unmodified Juice Shop source |
| [`.claude/CLAUDE.md`](.claude/CLAUDE.md) | Project instructions for Claude Code (points to `AGENTS.md`) |
| [`.claude/skills/stride-threat-model/`](.claude/skills/stride-threat-model/SKILL.md) | Skill: STRIDE threat model with ASCII diagrams |
| [`.claude/skills/compliance-check/`](.claude/skills/compliance-check/SKILL.md) | Skill: PCI-DSS and ISO 27001 gap analysis |
| [`threat.md`](threat.md) | STRIDE threat model produced by the skill (`threat.old.md` and `threat-model-earlier-run.md` are earlier threat models) |
| [`compliance-report.md`](compliance-report.md) | Compliance gap analysis produced by the skill. It cites an `output.md` review that is not in this repo (see the note at the top of the file) |
| [`report_scan.md`](report_scan.md) | First Snyk scan report |
| [`report_scan_2.md`](report_scan_2.md) | Second Snyk scan report, with Terraform fix steps |
| [`security-assessment.md`](security-assessment.md) | Combined assessment produced by four parallel subagents |
| [`UPSTREAM-README.md`](UPSTREAM-README.md) | The original Juice Shop README |

## What we did, in order

The first three steps are described from the files they left behind. I have not re-run them.

### 1. Project memory: `CLAUDE.md`

- `.claude/CLAUDE.md` tells Claude Code to treat the root `AGENTS.md` as the authoritative guide and to check its `Skills` section before starting a task. Juice Shop's own shared skills live under `.ai/skills/`.
- A global rules file, `~/.claude/rules/context7.md` (outside this repo), tells Claude to use the Context7 MCP server for library documentation questions.
- A machine-local `.claude/settings.local.json` holds permissions. It is git-ignored and not published.

### 2. Skills

- `stride-threat-model` builds a STRIDE threat model with separate ASCII diagrams (component, data flow, trust boundary, threat mapping) and writes `threat.md`.
- `compliance-check` maps the code to PCI-DSS and ISO 27001 controls with `file:line` evidence and writes `compliance-report.md`.
- `context7-mcp` (global, in `~/.claude/skills/`) makes Claude fetch current library docs through Context7 instead of answering from memory.
- A skill is a folder with a `SKILL.md` whose front matter `description` tells Claude when to load it.

### 3. MCP servers

| Server | How it was set up | Used for |
|---|---|---|
| Snyk | `claude mcp add snyk -s user -- snyk mcp -t stdio` | Dependency, code, secret, IaC, container and SBOM scans |
| Miro | Authenticated through `/mcp` | Diagrams and tables on a Miro board |
| Context7 | Added to the Claude Code config | Current docs for libraries and cloud providers |

Things worth remembering from this stage:

- Snyk CLI. The standalone binaries downloaded with `curl` were removed, and the CLI was reinstalled from Snyk's tap: `brew tap snyk/tap`, `brew trust snyk/tap`, `brew install snyk`. The older `snyk-cli` formula was uninstalled to avoid a link conflict. Check with `snyk whoami --experimental`.
- Re-authentication. The Snyk MCP session expired between sessions and every tool returned "User not authenticated". The `snyk_auth` tool (or `snyk auth` in a terminal) restores it.
- Connection fix. The Snyk MCP server first failed with `ECONNREFUSED` because a stale project-level entry pointed at `http://127.0.0.1:7695/sse` and overrode the user-level stdio entry. The fix was `claude mcp remove snyk -s local`. A loopback URL like that only works if you start the server yourself with an SSE transport. The stdio setup avoids this.
- Scope. `-s user` makes a server available in every project. `-s local` limits it to one project and takes priority.
- Context7 test. It returned correct, current syntax for the Terraform AWS `aws_lb_listener` redirect action and for `google_compute_firewall`. It adds a couple of thousand tokens per lookup, so it pays off for version-sensitive syntax and not for patterns already well known.
- Other connectors (Gmail, Calendar, Notion, Slack, Docs) were available in the session. None was used.

### 4. Snyk scans and reports

Run with the Snyk MCP server on 2026-10-11 (`report_scan_2.md`):

| Scan | Result |
|---|---|
| Dependencies (SCA) | 115 issues: 5 critical, 59 high, 49 medium, 2 low |
| Code (SAST) | 293 results: 26 high, 11 medium, 256 low (235 in test fixtures) |
| Secrets | Not run. Snyk Secrets is disabled for the org (403) |
| DAST | Not run. No DAST tool in the Snyk MCP server |
| SBOM (CycloneDX) | 714 components, 102 issues |
| Terraform (IaC) | 10 issues in each folder: 3 medium, 7 low |
| Container image `bkimminich/juice-shop:v20.2.0` | 173 issues: 50 OS layer, 123 application |

- Comparison. A second run matched the first report on every count. The only differences were scope and formatting, listed in section 10 of `report_scan_2.md`.
- Terraform fix steps. `report_scan_2.md` has step-by-step fixes for the three medium findings (HTTP-to-HTTPS redirect and open ingress). They are written up but not applied to the Terraform files.
- Org settings. Snyk Code had to be enabled on the org before the SAST scan would run. Snyk Secrets is still off and needs an org admin to enable it in the web UI.

### 5. Miro board

Three sections were added to a Miro board, each appended below the previous one:

1. A STRIDE threat model diagram: actors, components, back ends, trust boundaries TB1 to TB5 and the 18 threat IDs from `threat.md`.
2. The Snyk results as bars by severity, plus the scans that did not run and the "fix first" upgrades.
3. A table of the five critical dependency issues, and a table of the ten Terraform findings with fixes.

### 6. Subagents: parallel security assessment

`security-assessment.md` came from four read-only specialist subagents running in parallel, then merged by the main session:

| Agent | Scope | Tools it used |
|---|---|---|
| Code analysis | Architecture, entry points, data flows, trust boundaries | File reads and searches |
| Secrets scanner | Hardcoded secrets, git history, env defaults, ignore files | `git grep`, `git log`, file reads |
| Dependency auditor | Manifests, deprecated packages, upgrade paths | `npm view` calls and reads of `report_scan_2.md`. It made no MCP calls |
| Configuration reviewer | Terraform, Docker, headers, CORS, cookies, rate limiting | File reads and searches |

- Merge steps. The main session deduplicated findings and spot-checked key line numbers against the source.
- Reorganisation. The final report splits 34 findings into Part A (intentional challenge code, 25 rows) and Part B (hygiene gaps, 12 rows). Three mixed findings are split into an `a` and a `b` part, which makes 37 rows.
- Quality review. The report was then tightened: bold limited to table labels, long cells shortened, the process-narration section removed, Dockerfile and Terraform line references verified, and the critical dependency count re-checked with a fresh Snyk MCP scan on 2026-10-13 (the same five issues).
- Top 5 actions. Isolate the deployment, remove and rotate embedded secrets, close the injection and `eval` paths, patch critical dependencies, and restore access control.

## Things that are easy to miss

- Nothing here was fixed. The reports describe problems and fixes, but no source or Terraform file was changed.
- Unverified items (listed in section 5 of `security-assessment.md`): whether the `pull_request_target` workflow runs PR code, the contents of the KeePass file in `ftp/`, and the deleted `mongodb/secrets.js` in git history.
- No lockfile is committed upstream, so dependency versions depend on install time. The scan resolved `zod` 4.6.5 while the image has 4.4.3.
- Stale local install. `node_modules` was installed with `npm install --ignore-scripts` and still contains `libxmljs2`, which `package.json` has replaced with `libxml2-wasm`.
- Subagents can use any tool. By default they inherit the full tool list, MCP tools included, so say in the prompt which tools they should and should not use.

## Suggested next steps

1. Ask an org admin to enable Snyk Secrets, then run the secret scan and add the results to the reports.
2. Run OWASP ZAP against a local instance for DAST coverage (`.github/workflows/zap_scan.yml` already has a ZAP setup).
3. Apply the Terraform fixes on a copy and re-run `snyk iac test` on both folders.
4. Upgrade the non-challenge dependencies first (`multer`, `handlebars`, `sqlite3`, `socket.io`), following Appendix D of `security-assessment.md`.
5. Verify the open items above.

## Licence

Juice Shop is released under the MIT licence (see [LICENSE](LICENSE)). The reports and notes in this repo are the lab's own work.
