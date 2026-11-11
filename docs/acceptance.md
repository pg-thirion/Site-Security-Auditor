# Acceptance audit

**Reviewed:** 10 November 2026  
**Scope:** `SPEC.md` acceptance criteria, `DESIGN.md` explicit UI/accessibility gates and `PLAN.md` named release artefacts and phase gates. This records evidence and remaining scope; it does not change the product contract.

## Status key

- **Verified** — direct test or artefact evidence covers the stated requirement.
- **Partial** — implementation and some evidence exist, with a specific acceptance case still open.
- **Unverified** — evidence has not established the requirement.
- **Environment unavailable** — the check needs an environment not available in this workspace.

Evidence references below point to files in this repository. `PROGRESS.md` is the verification index; named logs and tests are primary evidence where available.

## SPEC.md acceptance criteria

| Requirement | Status | Evidence and remaining scope |
|---|---|---|
| Install, activate, deactivate and uninstall safely | **Verified** | The current candidate installed/activated on both WordPress versions. Exact-archive uninstall removed both custom tables, plugin options/transient and cron including argument-bearing hooks, preserved an unrelated option, then reinstalled successfully. Fresh real UI/API confirms empty history and consent/scheduling off (`.tools/fresh-ui-detection.log`). PHP lifecycle integration also passes. |
| No PHP warnings or browser errors in ordinary use | **Partial** | The six WordPress/PHP integration runs and nine-browser-test runs pass; runtime smoke passes on both WordPress versions. This is representative coverage, not proof over every ordinary-use state or hosting configuration. |
| Administrator-only menu and REST data, including negative tests | **Verified** | `RouteAccessTest.php` and the detection integration matrix exercise anonymous/subscriber denial, administrator access and nonce enforcement. The admin page also checks `manage_options` in `includes/Admin/AdminPage.php`. `http-atomic-66.log` and `http-atomic-714.log` are real-HTTP smoke evidence for the preceding archive, not the current candidate. |
| All 16 checks follow their specified methods and limitations | **Verified** | `AuditRegistry.php` registers all 16 stable IDs; current runtime scans store all 16 results. Local/provider fixtures cover expected pass/fail/unknown cases, including privileged-role capabilities and parent-directory `wp-config.php` (`tests/unit/checks.php`, `ScanLifecycleTest.php`, detection integration logs). The Linux/POSIX run adds 17 filesystem assertions with no skips, including unsafe/safe permissions, direct and ancestor symlinks, parent-config root precedence and exclusion of another installation (`.tools/posix-driver.log`, `.tools/posix-serial.log`). A deliberate guest-only mutation removed the parent-config fallback and produced the expected `RuntimeException` for a world-writable supported parent config; restored source passed all 17 assertions. The expected mutation failure is evidence the guard is exercised, not a product failure. |
| No provider request before informed opt-in | **Verified** | Detection runtime smokes report zero provider HTTP calls with integrations off. Integration fixtures cover pre-consent requests and opt-out; Settings presents separate provider controls and data disclosures (`src/index.tsx`). |
| Provider failure yields `unknown` and an honest partial result | **Verified** | Provider outage/malformed-response fixtures and `slow-provider-integration.log` cover bounded timeout, unknown status and unfinished work without invented findings. |
| Scan survives refresh, supports manual continuation and prevents concurrent starts | **Partial** | Real-browser scan tests cover queued/running state, polling without automatic write advances, manual continuation, cancellation and completion with all 16 checks. Integration tests cover lock acquisition, owner safety, retry and large/slow work. Browser runs (`browser-atomic-*.log`) predate the final `LocalChecks.php` change; multiple real administrator tabs contending on the current candidate remain unverified. |
| Score, coverage and historical score immutability match the formula | **Verified** | `ScoreCalculatorTest.php`, `StoredScanTest.php`, scan-history integration coverage and the UI-state browser fixture cover penalties, coverage suppression, stored score validation and settings changes without retroactive recalculation. |
| Findings include safe evidence, context, remediation, source and timestamps | **Partial** | Output sanitisation/privacy integration tests and the browser finding-detail flow cover safe stored evidence, references, detail navigation and filtering. A full content-by-content audit of every finding produced by every check is not recorded. |
| History never marks an unassessed issue resolved | **Verified** | `ScanDiffTest.php` covers unknown/not-evaluated comparisons; integration fixtures verify stored scan history and the UI fixture checks unknown confidence is not presented as a pass. |
| Print/PDF, CSV and JSON are authorised and exclude secrets | **Verified** | Current-archive browser suites pass nine tests each, including selected-scan JSON and multi-page print/PDF (`.tools/browser-detection-66.log`, `.tools/browser-detection-714.log`). Real HTTP authentication, JSON/CSV bodies, attachment headers and stored identity pass on both (`.tools/http-detection-66.log`, `.tools/http-detection-714.log`). Integration fixtures verify private output scrubbing and CSV formula protection. |
| 360px wp-admin view remains usable with keyboard navigation | **Partial** | The nine browser tests set a 360px viewport, check no app-level horizontal overflow, exercise finding-detail Escape/focus return and capture mobile screenshots (`artifacts/screenshots/`). Full keyboard-only navigation across every control is not established. |
| No fixes, exploitation, malware claims or arbitrary outbound targets | **Verified** | Product/source contract and provider architecture use fixed endpoints, optional consent, bounded read-only checks and safe advisory references. Plugin Check reports no errors on the candidate. Automated architecture/fixture checks cover outbound-call gating and untrusted provider content. |
| Installable ZIP, readme, GPL licence, release instructions and test evidence | **Verified** | Candidate ZIP exists and was installed; `site-security-auditor/readme.txt`, its bundled `LICENSE`, root `LICENSE`, `README.md`, `PROGRESS.md` and this audit cover the named materials. `plugin-check-detection.json` reports no errors. This remains an engineering candidate, not a public release claim. |

## DESIGN.md UI and accessibility gates

| Design gate | Status | Evidence and remaining scope |
|---|---|---|
| Five-view navigation, real stored data, no fabricated production metrics | **Partial** | Real dashboard, stored findings, selected report/export and actual scan flows pass browser tests. The synthetic state suite verifies empty history, failed/insufficient-coverage states and missing-report gating; live tests cover queued/running/partial scans. DESIGN's completed-clean and completed-with-findings overview states lack explicit browser assertions. |
| Unknown, partial and failed states stay distinct from success | **Verified** | `ui-states-browser-66.log` checks failed/unknown/insufficient-coverage and missing-report behaviour; real scan tests cover queued, running, cancelled and completed/partial states. |
| Findings, history comparison, missing/expired history and report selection | **Partial** | Finding details, filtering, selected-scan exports, zero history, cancelled history and missing-report deep links are covered. A browser comparison flow and expired-history empty-state flow are not recorded; retention itself has runtime/integration evidence. |
| Settings default off, save error, opt-out and separate consent explanations | **Partial** | Browser tests verify defaults and recoverable save failure; PHP integration tests cover immediate opt-out and disabled network calls. Provider enable/save success and disabled-scheduler messaging are not both demonstrated end-to-end. |
| Responsive 360px layout, doubled text and no horizontal overflow | **Verified** for the tested viewport/text-size simulation | `admin-access.spec.ts` sets width to 360px, doubles computed font sizes, asserts content does not overflow and saves screenshots. This is a CSS text-size simulation, not browser zoom. |
| Scoped CSS, reduced motion and local assets | **Partial** | CSS is rooted under `.ssa-app`; built asset metadata uses WordPress-provided React/API/components/i18n dependencies, and the archive contains local compiled assets. Reduced-motion behaviour has not been explicitly tested. |
| Automated WCAG checks and keyboard interactions | **Partial** | `a11y-browser-66.log` and `a11y-browser.log` report zero axe violations across all five views. Browser tests cover Escape and focus return for finding details. A broader keyboard-only walkthrough and screen-reader landmark/manual review are not recorded; no hardware-specific test is treated as a release requirement. |
| Print layout, multi-page output and report controls | **Verified** | Both current-archive browser suites pass report selection, export controls, print-media layout and multi-page PDF checks (`.tools/browser-detection-66.log`, `.tools/browser-detection-714.log`). |

## PLAN.md release artefacts and phase gates

| Named deliverable or gate | Status | Evidence and remaining scope |
|---|---|---|
| Root README, plugin `readme.txt`, security policy, licence and ignore rules | **Verified** | Root and plugin documentation files and both licence copies are present. Plugin metadata declares GPL-2.0-or-later; bundled license text is GPLv2. |
| Architecture diagram and threat model | **Verified** | `docs/architecture.md` contains the system flow; `docs/threat-model.md` lists assets, trust boundaries, controls and verification cases. |
| Screenshots and local setup, limitations and test evidence | **Verified** | Screenshots are in `artifacts/screenshots/`; `README.md` documents setup, scope, limits and commands; `PROGRESS.md` records executed environments and results. |
| Reproducible package allowlist, runtime assets and clean candidate ZIP | **Verified** | Required-file checks and runtime allowlist in `scripts/package-plugin.php`; independent archive inspection excludes development dependencies and tests. Two builds matched SHA256 `6a5a437a4d13368ce2628a38afb46a9a51dcbd2959a91249f2321cf34ec41539` (50,653 bytes). Current-archive browser, runtime, HTTP, Plugin Check and uninstall/reinstall checks pass. |
| PHPCS, PHP unit/integration, frontend lint/typecheck/build and Plugin Check | **Verified** | `PROGRESS.md` records PHPCS with no findings, PHPUnit 11 tests/37 assertions, standalone self-checks on PHP 8.2/8.3/8.4, frontend lint/typecheck/build, and Plugin Check. Detection integration matrix logs each report 13 tests/95 assertions. |
| WordPress/PHP compatibility matrix | **Partial** | Detection integration tests pass on WordPress 6.6 and 7.1.4 across PHP 8.2, 8.3 and 8.4. Runtime/archive smoke passes on both WordPress versions with PHP 8.4. GitHub Actions was not executed; this workspace has no Git metadata/remote. |
| POSIX permissions and symlink checks | **Verified** | QEMU 11.1 TCG booted Alpine 3.24.4 / Linux 6.18.60 with PHP 8.4.27. The read-only source/fixture tar was extracted under guest `/tmp`; seven standalone commands passed, including all 17 filesystem assertions with no skips (`.tools/posix-driver.log`, `.tools/posix-serial.log`). The mutation proof described above passed after source restoration. `.tools/posix-shutdown.log` records clean power-down; QEMU exited 0 with no process/listener left. Source and ZIP hashes were unchanged by this proof. |
| Actual ZIP install, runtime/auth/export checks and Plugin Check | **Verified** | Current ZIP installed/activated on WordPress 6.6 and 7.1.4. Runtime/auth/retention/export checks passed; `.tools/plugin-check-detection.json` reports no errors against the explicit installed directory. Current browser/HTTP logs are `browser-detection-*` and `http-detection-*`; fresh reinstall evidence is `fresh-ui-detection.log`. |
| GitHub publication, directory submission or CI execution | **Not a v1 product acceptance gate here** | No remote or repository metadata exists. The source artefacts are present locally; no publication, WordPress.org approval or CI run is claimed. |

## Remaining acceptance work

1. Current-archive browser and real HTTP revalidation are complete.
2. Close remaining named UI cases: browser history comparison/expiry and broader keyboard navigation; do not expand this into exhaustive permutations or hardware-specific requirements.
3. Keep candidate/release wording: WordPress.org submission, public publication and GitHub Actions execution have not occurred.

This audit does not require new product features, a public submission, GitHub CI execution, a screen-reader hardware lab or a manual re-audit of development-only dependency trees.
