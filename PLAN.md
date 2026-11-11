# Site Security Auditor: Codex Implementation Plan

**File:** `PLAN.md`  
**Version:** 1.0  
**Implementation authority:** `SPEC.md` defines product and security contracts; `DESIGN.md` defines UI. This plan controls order and milestones.  
**Execution mode:** Small verified vertical slices. Never trade access control or evidence quality for visual polish.

## 0. Agent workflow rules

- Read `SPEC.md`, `DESIGN.md`, this file and `PROMPT.txt` before coding.
- Start by inspecting the repository. Do not overwrite existing work without understanding it. If it is empty, create the documented structure.
- Maintain an actual checklist in this file (or `PROGRESS.md` with references here), checking items **only** after implementation and test evidence.
- After every milestone: run relevant tests and lint, report commands and actual results, note constraints and commit logical changes if repository conventions permit.
- Never claim a test passed unless it was executed. If Docker, Composer, npm or WordPress is unavailable, explain what is unverified and continue with safe static work.
- Security-sensitive decisions are explicit, documented and tested. Do not leave a placeholder route that exposes private scan data.
- If a phase uncovers a necessary deviation, amend the specification/design/plan with a short rationale before implementing it.
- Do not add unrelated features, unnecessary SaaS, telemetry or automated remediation.

## 1. Target repository structure

```text
project-root/
├── SPEC.md
├── DESIGN.md
├── PLAN.md
├── PROMPT.txt
├── README.md
├── SECURITY.md
├── LICENSE
├── composer.json
├── composer.lock
├── package.json
├── package-lock.json
├── phpunit.xml.dist
├── phpcs.xml.dist
├── .wp-env.json
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml
├── site-security-auditor/
│   ├── site-security-auditor.php
│   ├── readme.txt
│   ├── uninstall.php
│   ├── includes/
│   │   ├── Plugin.php
│   │   ├── Admin/AdminPage.php
│   │   ├── Api/Routes.php
│   │   ├── Audit/{AuditEngine,AuditRegistry,AuditCheckInterface}.php
│   │   ├── Audit/Checks/*.php
│   │   ├── Providers/{VulnerabilityProvider,WPVulnerabilityProvider,ChecksumProvider}.php
│   │   ├── Persistence/{ScanRepository,FindingRepository,Schema}.php
│   │   ├── Services/{ScoreCalculator,ScanDiff,ExportService,RetentionService}.php
│   │   └── Support/{Capabilities,Clock,Logger}.php
│   ├── src/
│   │   ├── index.tsx
│   │   ├── App.tsx
│   │   ├── pages/*.tsx
│   │   ├── components/*.tsx
│   │   ├── hooks/*.ts
│   │   ├── api/client.ts
│   │   └── styles/app.css
│   ├── build/                 # built artefacts committed or included in release ZIP
│   └── languages/
├── tests/
│   ├── php/
│   │   ├── Unit/
│   │   └── Integration/
│   ├── e2e/
│   └── fixtures/
│       └── provider-responses/
└── scripts/
    └── package-plugin.sh
```

**Scaffold deviation:** the React package manifest and source live inside `site-security-auditor/` alongside the deployable plugin, so its npm commands use `npm --prefix site-security-auditor`. The release packager has an explicit runtime-file allowlist to keep its development dependencies out of the ZIP.

**Implementation structure deviations:** `Services/ScanRunner` owns bounded orchestration instead of adding a separate `AuditEngine`; `LocalChecks` and `ProviderChecks` expose individually dispatched stable-ID checks instead of one wrapper class per check; and provider adapters are concrete fixed-endpoint classes without unused provider interfaces. These keep the one-provider v1 path small while preserving per-check status, fixture coverage, fixed destinations and the same REST/data contracts.

The root is for source/build tools and project documentation. `site-security-auditor/` is the distributable plugin directory. The ZIP root must contain that plugin directory. Adjust namespace/autoload paths if warranted but keep a clear separation between runtime files and development tooling.

## 2. Phase 1: Scaffold a secure WordPress plugin

**Outcome:** Plugin activates with an authorised menu, a React shell and no outbound traffic.

- [ ] Add GPL-compatible metadata, correct plugin headers, text domain, licence, `readme.txt`, `README.md`, `SECURITY.md` and `.gitignore`.
- [ ] Register activation/deactivation/uninstall lifecycle. Activation is idempotent; deactivation clears schedules; uninstall removes plugin-owned tables/options/hooks after user initiates deletion.
- [ ] Add Composer autoloading or a small secure local autoloader that works in a standalone release ZIP. Never require Composer on the target WordPress site.
- [ ] Create admin page limited to `manage_options` and make a single scoped enqueue target.
- [ ] Set up React + TypeScript using `@wordpress/scripts` and native WordPress dependencies. Render a clean no-scan state.
- [ ] Wire GitHub Actions, PHPCS, ESLint/TypeScript, PHPUnit harness and `@wordpress/env` or Docker.
- [ ] Add REST route registration skeleton with real permission callbacks, no placeholder `__return_true` private endpoints.
- [ ] Include tests proving anonymous/subscriber users cannot load sensitive data or admin views.

**Gate:** Test activate/deactivate/uninstall, build assets, verify capability restriction, ensure no external requests and no JS/PHP errors. Record test output.

## 3. Phase 2: Persistence and local audit engine

**Outcome:** A full manual audit with reliable local checks and durable history, even offline.

- [ ] Implement versioned `dbDelta()` schema, migrations and repositories with query parameterisation, pagination and retention.
- [ ] Implement scan states, individual check results, finding identities, audit registry, clock abstraction and read-only check interface.
- [ ] Implement `POST /scans`, `GET /scans/{id}`, `/overview` and paginated routes with capability checks and verified REST nonces on browser writes.
- [ ] Build bounded batch runner, state cursor, lock handling, idempotent retries and WP-Cron continuation.
- [ ] Implement authorised `advance` fallback and `cancel`; prevent overlapping scans and stale lock failures.
- [ ] Implement purely local checks: `SSA-001`, `002`, `003`, `007`, `008`, `009`, `010`, `011`, `013`, `014`, `015`, `016`.
- [ ] Handle missing update transients, unusual file-permission environments and ambiguous transport configurations with unknown/qualified results.
- [ ] Add unit tests for each local check in positive, negative and unknown conditions, including role-capability defaults and WP child themes.
- [ ] Add REST integration tests for anonymous, subscriber and admin access; duplicate scans; invalid IDs, input and pagination; nonce failures.

**Gate:** A manually created test issue appears as a safe, evidence-backed finding. Offline scans finish/partially finish correctly, are stored and survive page reload. No requests to third-party providers.

## 4. Phase 3: Consent-based vulnerability intelligence and integrity

**Outcome:** External checks are strictly opt-in, cached and never reported as successful after lookup failure.

- [ ] Build Settings API and an explicit `Vulnerability intelligence` toggle, default false. Include provider data notice and documentation link.
- [ ] Implement strict WPVulnerability adapter using `wp_safe_remote_get` for **fixed trusted endpoints only**, redirects disabled or securely restricted, short timeouts, size limits and response schema validation. Do not accept externally supplied target URLs.
- [ ] Validate version-range matching, advisory IDs and source severity; preserve unknown when upstream data is incomplete or unavailable.
- [ ] Add provider caching, backoff, per-scan request cap and fixtures reflecting current documented response schema.
- [ ] Implement `SSA-004`, `005`, `006` for confirmed matching installed versions. Cover unknown slug, missing version, malformed response and timeout.
- [ ] Add independent `Core integrity verification` toggle, default false. Retrieve official WordPress.org checksums via a strictly HTTPS-only adapter after consent (the WordPress helper may fall back to HTTP), and hash only allowlisted core files safely in batches.
- [ ] Implement `SSA-012`, guarding symlinks, traversal, unexpected files, missing WordPress.org checksum response and file read errors.
- [ ] Add tests: **no outbound requests on activation, page view or scan with opt-ins off**; immediate opt-out; rate-limited/malformed provider; malicious advisory text; changed core file; non-matching versions.

**Gate:** Vulnerable test fixtures are detected correctly; turning off the feed prevents new calls; provider outage yields `unknown` and partial results. Checksums identify a modified test core file without claiming malware.

## 5. Phase 4: Scoring and reports

**Outcome:** Scan results are interpretable, reproducible and exportable without leaking information.

- [ ] Implement versioned score formula and 70% coverage threshold exactly as defined in `SPEC.md`.
- [ ] Implement stable issue identity, `New`/`Still present`/`Resolved`/`Not evaluated` comparison, handling unknown properly.
- [ ] Add history retention (last 20 scans / 90 days, whichever more restrictive) with safe clean-up.
- [ ] Add authorised JSON and CSV exports for stored scans, with `Content-Disposition` and no-cache headers.
- [ ] Add CSV formula-injection mitigation and content encoding tests.
- [ ] Add report page and `@media print` stylesheet, using a real user-triggered print action for PDF saving.
- [ ] Add tests for historical score immutability, unknown coverage and missing scans.

**Gate:** Two successive scans produce a sensible, reproducible diff; report fields match stored results; exports are inaccessible to unauthorised users and contain no secrets.

## 6. Phase 5: Complete the administrator experience

**Outcome:** Usable, responsive, accessible product, not a functional API behind a static mock dashboard.

- [ ] Implement Overview from real REST data, including no-scan, queued, running, partial, failed and low-coverage states.
- [ ] Implement Findings filtering, detail view with evidence/remediation, validation and safe advisory URLs.
- [ ] Implement History, comparison and Report deep links.
- [ ] Implement Settings consent and weekly scheduling, both default off; explain WP-Cron limitations.
- [ ] Apply `DESIGN.md` token system with CSS isolation and progressive glass surface effects.
- [ ] Test accessible controls, keyboard/focus management, errors, polling live regions, mobile view and 200% text zoom.
- [ ] Add browser E2E tests with seeded local fixtures; no release-only fake scores or findings.

**Gate:** A site administrator can install, configure, audit, investigate, export and compare results end-to-end on desktop and mobile, without confusion between unknown and safe.

## 7. Phase 6: Hardening and public-release preparation

**Outcome:** Reproducible GitHub project and installable candidate ZIP, with documented limits.

- [ ] Conduct threat-model review for XSS, CSRF, SQLi, SSRF, IDOR, path traversal, PHP execution, sensitive output and resource exhaustion.
- [ ] Run PHPCS, PHP/unit/integration tests, npm lint/typecheck/build, Playwright and Plugin Check. Fix material warnings, not merely suppress them.
- [ ] Test WordPress minimum and latest stable versions using supported PHP versions, including PHP 8.3 and 8.4 where available. Record actual tested matrix, not guessed support.
- [ ] Manually test slow WordPress hosts, WP-Cron disabled, offline environment, API outage, malformed response, multiple admin tabs and plugin uninstall.
- [ ] Validate GPL compatibility, third-party licences, text domains, translation strings, README privacy disclosures and plugin directory standards.
- [ ] Ensure bundled assets are local; check built artefacts, plugin size, no `.env`, `.git`, credentials, tests, `node_modules` or dev Composer folders in release ZIP.
- [ ] Publish architecture diagram, threat model, screenshots, local setup steps, limitations and test evidence to GitHub documentation.
- [ ] Package and test installation of the **actual ZIP** in a clean WordPress environment.
- [ ] Run final git status/diff review and record remaining known issues. If directory submission is desired, verify slug/trademark suitability and current WordPress.org guidance separately.

**Gate:** A usable candidate release ZIP exists, but call it a candidate until installation, security and compatibility checks actually pass.

## 8. Test matrix

| Test group | Minimum scenarios | Tool |
|---|---|---|
| PHP unit | check states, provider mapping, scoring, diff, privacy scrub | PHPUnit |
| WP integration | auth, nonce, DB migrations, cron, REST, export | WP test suite |
| E2E | installation, admin flows, settings, scan, report | Playwright + local WP |
| Static | coding standards, TS checks, dependency audit where feasible | PHPCS, ESLint, tsc |
| Plugin Directory | headers, external-service consent, i18n, assets, security guidance | Plugin Check |
| Security adversarial | HTML/CSV injection, IDOR, SSRF prevention, symlinks, races, huge feed | Automated fixtures + manual review |
| Compatibility | WP 6.6 and latest stable, supported PHP branches | Docker/wp-env matrix |

Keep test fixtures deterministic and never require a production AWS or Cloudflare account. Do not scan third-party sites.

## 9. Task tracker and completion report template

Each milestone report should include:

```text
Phase: <number and name>
Implemented: <file-level summary>
Tests executed: <exact commands, pass/fail and result>
Security review: <what was validated>
Spec deviations: <none or documented change>
Remaining: <unverified work or known failures>
Next step: <smallest safe next milestone>
```

Stop and fix failing security checks before expanding to new features. A static UI with invented results is not acceptable as a finished milestone. For partial environments, produce as much tested work as tools allow and explicitly distinguish implemented code from verified behaviour.
