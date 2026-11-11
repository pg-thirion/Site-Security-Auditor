# Implementation tracker
## Current archive acceptance — 10 November 2026
- Current candidate remains 50,653 bytes, SHA256 `6a5a437a4d13368ce2628a38afb46a9a51dcbd2959a91249f2321cf34ec41539`. Its full browser suite passes **9 tests on each WordPress 6.6/7.1.4 site** (`.tools/browser-detection-66.log`, `.tools/browser-detection-714.log`). Real authenticated HTTP JSON/CSV/export header checks pass on both (`.tools/http-detection-66.log`, `.tools/http-detection-714.log`).
- Exact-archive uninstall/reinstall exercised on both disposable sites after verifying targets were owned non-symlink plugin copies. Both custom tables, options, a transient and argument-bearing cron hooks were removed; an unrelated option survived. The same archive reinstalled/activated successfully. Fresh real database/UI/API checks then proved no audits, empty history and all three consent/scheduling settings false (`.tools/fresh-ui-detection.log`, fresh-overview screenshots).
- Native POSIX verification below closes the former Windows filesystem skips. Remaining named UI coverage and final requirement audit stay open; no public publication, WordPress.org approval or GitHub Actions execution is claimed.
## Native POSIX verification — 10 November 2026
- Booted checksum-verified Alpine 3.24.4 x86_64 under portable QEMU 11.1.0 TCG, entirely under `.tools`, without host installation, WSL/Docker or Windows feature changes. Linux 6.18.60 and PHP 8.4.27 executed the same standalone source/fixtures from a read-only tar disk, extracted to native guest `/tmp`.
- **Filesystem: 17 assertions passed, no skips.** This covers native POSIX permission bits, direct/ancestor symlinks and the new parent-config root-precedence, unsafe/safe-permission and unrelated-installation cases. Default/debug/secure/mods checks, output/privacy and dense-advisory cursor fixtures also passed: all seven commands exited 0 without missing-file warnings. `SPEC.md`, needed by an existing checksum fixture, was supplied with host/guest SHA256 verification.
- Regression strength checked: removing only the parent-config lookup in the guest reproduced the expected failing parent-permission assertion; restoring the actual source returned all 17 assertions to passing. The expected RuntimeException in the log belongs to this deliberate regression proof. Host production source was not mutated.
- Evidence: `.tools/posix-driver.log`, `.tools/posix-serial.log`. Guest powered down cleanly (`.tools/posix-shutdown.log`, QEMU exit 0); process and loopback serial listener are gone. This closes the previously Windows-skipped filesystem gate; it does not claim a complete Linux WordPress/database compatibility matrix.
## Detection corrections — 10 November 2026
- Current matrix: all six WordPress 6.6/7.1.4 × PHP 8.2/8.3/8.4 combinations pass **13 tests, 95 assertions** (`.tools/integration-detection-*.log`). PHP unit tests pass 11/37; PHPCS reports no findings. Both real WordPress runtime/auth/retention/export smokes pass from the new archive with zero pre-consent provider requests. Explicit installed-directory Plugin Check reports no errors.
- Updated candidate: `artifacts/site-security-auditor.zip`, 50,653 bytes, reproducible SHA256 `6a5a437a4d13368ce2628a38afb46a9a51dcbd2959a91249f2321cf34ec41539`. Two packaging runs matched; installed successfully on both disposable sites. Earlier atomic-lock-only ZIP/hash is superseded.
- Independent scoped release review found no missing requested document or incompatible shipped dependency: GPL-2.0-or-later header/readme grant and full GPLv2 text agree; service disclosures, threat model, architecture, security policy, screenshots and setup/test guidance exist. Archive allowlist excludes development dependencies; framework asset dependencies resolve through WordPress handles. This does not claim a full manual audit of every npm development licence.
- SSA-011 now recognises additional user-administration and plugin/theme/core modification capabilities. A new table-driven regression failed on `create_users` before the fix; all nine added capabilities now fail critically when granted and remain passing when explicitly denied. All standalone fixture modes pass on PHP 8.2/8.3/8.4. A genuine WordPress role integration test also checks these operations and confirms that disabled public registration remains passing.
- SSA-013 now follows `wp-load.php` lookup order: root config first; otherwise parent config only when the parent has no `wp-settings.php`. It reads metadata only and keeps unknown for Windows/ACL ambiguity. Filesystem fixtures now use an isolated nested WordPress root, with POSIX cases for root precedence, unsafe/safe parent permissions and exclusion of another parent installation. These new POSIX cases are not yet executed on Windows; do not count them as verified until a genuine POSIX run succeeds.
- The previous atomic-lock ZIP/hash predates these source changes and is superseded by the candidate above. Remaining release review continues.
## Atomic-lock correction — 10 November 2026
- Final browser revalidation against the updated archive: **9 tests passed on WordPress 6.6 and 9 on 7.1.4**, including all five-view automated accessibility checks, explicit edge states, real scan start/cancel/manual completion and selected report exports. Logs: `.tools/browser-atomic-66.log`, `.tools/browser-atomic-714.log`. The first 7.1.4 attempt had only connection-refused failures because its helper server had exited; absence of process/listener was verified before restarting, and the full run was then repeated successfully. WordPress versions were rechecked as 6.6 and 7.1.4. Real HTTP cookie/nonce/export smoke passed on 6.6; 7.1.4 result is recorded in `.tools/http-atomic-714.log`.
- Next detection review: SSA-011 currently checks seven privileged capabilities; assess omitted user-management and plugin/theme modification capabilities with table-driven fixtures, preserving the rule that unavailable effective privileges are not confirmed risks. SSA-013 currently checks only `ABSPATH/wp-config.php`; WordPress `wp-load.php` also supports the parent directory when it contains no `wp-settings.php`. Add metadata-only coverage for that supported layout, preserving unknown on Windows/ACL ambiguity. These independent review findings are not yet fixed or accepted as complete.
- Updated reproducible candidate: `artifacts/site-security-auditor.zip`, 50,463 bytes, SHA256 `a7d8ecc84d11640dfe00409b00784e9575cf8d3117069a1f65918ca16c4ab7d7`. Two packaging runs matched. Installed from this archive on both disposable sites; real runtime/auth/retention/export smokes passed and Plugin Check reported no errors against the explicit installed directory. Browser revalidation is recorded separately below when complete.
- Genuine overlapping PHP processes reproduced two simultaneous successful scan starts on the WordPress 7.1.4 disposable site. Root cause confirmed in WordPress `add_option()`: after competing missing-value observations, its `INSERT ... ON DUPLICATE KEY UPDATE` can replace a live lock. `Support/Lock.php` now uses `INSERT IGNORE` and accepts ownership only when exactly one row was inserted; stale compare-and-swap and owner-specific release remain intact.
- Added a deterministic stale-option-observation regression and a 1,000-plugin slow-provider integration test. The expanded genuine WordPress/MariaDB suite passes all six WordPress 6.6/7.1.4 × PHP 8.2/8.3/8.4 combinations: **12 tests, 74 assertions** each (`.tools/integration-atomic-*.log`). The slow fixture consumes actual configured timeout durations, stops within 11 seconds, preserves an unfinished cursor and returns unknown without fabricated findings.
- `scripts/concurrency-smoke.py` and its local-only PHP worker verify competing starts produce one scan/conflict, overlapping workers execute one check and later continuation executes the next. Repeated post-fix runs passed on both disposable WordPress versions with SQLite. Harness kills/waits its own live child processes and cancels recognised owned scans on exit. This tests real process overlap, not parallel HTTP serving or production database throughput.
- PHP unit tests (11/37), all standalone fixtures and PHPCS passed after the correction. Windows-only POSIX skips remain. Candidate ZIP must use the new hash below; earlier archive hashes describe the superseded lock implementation.
- Read-only dependency review confirmed npm audit remains 27 transitive development dependency nodes (9 low, 18 moderate, no high/critical). Compatible dry-run fixes left the count unchanged and raised peer override warnings; no blanket dependency changes applied. Inspected build/source paths did not establish exploitation of the reported Babel, deepmerge, YAML, KaTeX, minimatch, TOML or UUID paths. This is a scoped assessment, not a full manual dependency-tree audit; development tools should process trusted repository inputs only.
## Additional acceptance evidence — 10 November 2026
- Added two Playwright acceptance tests in `site-security-auditor/e2e/admin-access.spec.ts`. Both pass separately on real WordPress 6.6 and 7.1.4: axe-core 4.14.0 reports zero WCAG 2 A/AA, 2.1 A/AA and 2.2 AA violations across all five populated plugin views; intercepted test-only responses verify empty history, failed report gating, insufficient-coverage score suppression, unknown advisory results and missing-report export/print gating. Scope is `.ssa-app`, excluding WordPress chrome. Automated checks do not prove screen-reader usability or actual browser zoom. Existing installed axe-core reused; no dependency or runtime asset changed. Frontend typecheck passed. Logs: `.tools/a11y-browser{,-66}.log` and `.tools/ui-states-browser{,-66}.log`.
- These results satisfy the automated accessibility and explicit state-rendering checks below. Manual accessibility review, real browser zoom, concurrent administrators, slow-provider/large-inventory timing, POSIX checks and final security/licence/requirements review remain open. Full goal remains active.

## Current verified state — 10 November 2026

This section supersedes the older work log below. The full project goal remains active.

- PHPUnit: 11 tests, 37 assertions passed on PHP 8.2.35, 8.3.36 and 8.4.24. Standalone checks passed in default/debug/secure/mods modes, plus filesystem/privacy/advisory-cursor suites, on all three versions. POSIX permission/symlink branches remain skipped on Windows. Custom plugin/theme `UpdateURI` fixtures explicitly verify unknown results without provider HTTP calls.
- Genuine WordPress PHPUnit/MariaDB integration now passes all six combinations of WordPress core 6.6/7.1.4 and PHP 8.2.35/8.3.36/8.4.24: **10 tests, 61 assertions** each. The tests cover activation/deactivation, capability/nonce permissions, retention, output safety, bounded scans, scheduled hook execution/rescheduling, lock exclusion and stale-owner release, zero pre-consent HTTP, historical immutability, idempotent findings and selected private JSON/CSV exports. MariaDB 11.8.3 runs only on loopback port 3307 with a dedicated `ssa_phpunit` database. Test-library maintenance branches are separate from the exact released core directories configured as `ABSPATH`. Logs: `.tools/integration-*-php-*.log`. WordPress 6.6's upstream test installer references deprecated `E_STRICT` on PHP 8.4; all assertions pass and no plugin warning was reported.
- PHPCS, frontend lint, typecheck and build all exited 0 with no material findings.
- Build tooling is now `@wordpress/scripts` 37.1.0 with explicit Node 22 types and CI Node 22.22.2. A scoped `copy-webpack-plugin` serialiser override selects patched `serialize-javascript` 7.1.3; its transform-cache path passed `.tools/copy-plugin-smoke.cjs`. Deprecated redundant print CSS was removed. Final npm audit: **27 development-only findings (9 low, 18 moderate), zero high/critical**; `npm audit --omit=dev` reports zero findings. The full npm dependency tree was not manually audited. Both seven-test browser suites passed again against this toolchain's rebuilt ZIP. Fresh `npm ci` exited 0; existing deprecation notices and three unneeded postinstall-script approval notices remain. No npm scripts were separately approved, and no GitHub Actions execution is claimed.
- Actual final ZIP installed and activated on WordPress 6.6 and 7.1.4, using PHP 8.4.24 and SQLite Database Integration 3.1.3. Both versions passed runtime and authenticated HTTP smoke checks. Both produced all 16 stored check records, honest partial coverage and zero provider HTTP calls with integrations disabled.
- Version correction: background updates had changed the original disposable sites. Earlier 6.6/7.0 labels were therefore unreliable. Automatic updates were disabled on `.tools/wordpress66`, core restored to 6.6, and all runtime/HTTP/browser checks repeated. WP-CLI confirmed 6.6 again after those tests. The other site is verified 7.1.4, currently stable per https://wordpress.org/download/releases/ .
- Seven Playwright tests passed on each verified version: previous private API/dashboard/detail/filter/export/layout/print/settings coverage plus actual browser scan start, delayed-read refresh race, polling without automatic POST advances, manual progress, confirmation/cancel and unavailable cancelled-report actions. All 16 real checks completed via manual continuation with automatic cron disabled on 6.6; 7.1.4 also permits cron to complete concurrently. Screenshots were inspected visually. Artifacts: `artifacts/screenshots/`.
- A real start/load race was reproduced and fixed by awaiting an active read before refreshing mutated scan state. Cancelled scans no longer offer an enabled report action. Consent wording now distinguishes transmitted slugs/core version from plugin/theme versions compared locally.
- Finding filters now constrain intrinsic input widths at double text size. Inactive inventories remain informational rather than failed checks. Confidence uses stored check results independently of current consent settings.
- Runtime retention smoke now accounts for existing newer scans instead of assuming an empty database. It verifies expected fixture survivors and the global 20-terminal-scan limit.
- Plugin Check 2.2.0 against the explicit absolute directory extracted from the ZIP reported `Success: Checks complete. No errors found.` Evidence: `.tools/plugin-check-package.json`. Earlier bare-slug commands selected the source directory and included development files; they do not describe the ZIP. Readme compatibility metadata and the global uninstall variable were corrected.
- Final candidate: `artifacts/site-security-auditor.zip`, 26 runtime files. Independent inspection found no development dependencies, tests, source maps, logs or paths outside the plugin root. Repeated final builds have SHA256 `9867af0e2c3a0d4dd8b52a88cf3d91b05234a530673c4c13c930e908347b0c4a`. This supersedes earlier candidate hashes. Final-archive uninstall, reinstall and runtime/HTTP smoke were repeated on 6.6 after the toolchain upgrade.
- Final ZIP uninstall on pinned 6.6 removed both tables, plugin options, worker lock, test transient and every plugin cron hook, including argument-bearing batches. An unrelated option survived. The ZIP then reinstalled and activated successfully.
- The latest-version site's old development copy could not be replaced by WP-CLI because of its development dependencies. It was moved without deletion to `.tools/retired-plugin-copy`; the actual ZIP then installed successfully.
- Both Impeccable side-tab reports describe intentional native WordPress alert/status notices. The narrow file-scoped value exception is persisted in `.impeccable/config.json`.

Remaining gates: POSIX checks; remaining accessibility/race/error acceptance cases; assessment of residual low/moderate development audit findings and final security/licence review; full requirement-by-requirement completion audit. Docker and WSL are unavailable locally, but portable MariaDB, both WordPress test libraries and PHP 8.2/8.3 are now installed under `.tools/` and the database matrix above has executed. Configured GitHub Actions has not executed, and no remote/commit/CI artifact is claimed. The ZIP remains an engineering candidate.

Concrete next acceptance checks from the independent read-only review:

1. Run automated accessibility checks on the plugin surface and record keyboard/landmark/contrast review. Existing synthetic double-text sizing does not prove actual browser zoom or a screen-reader review.
2. Prove fresh zero-history, failed/insufficient-coverage/provider-outage rendering and missing report deep links. Existing browser fixtures do not cover these states directly.
3. Exercise multiple administrator tabs contending for start/advance and a deliberately slow provider or large inventory. Existing bounded feed/checksum fixtures and sequential lock ownership tests are relevant but do not prove every concurrent/slow-host condition.
4. Assess the residual 27 development audit findings and finish the security/licence and requirement-by-requirement review. The archive allowlist excludes development dependencies; that is not a complete manual audit of the build dependency tree.

## Earlier work log (superseded where inconsistent)

This tracker records executed evidence. A phase stays open until its release gate has been exercised.

## Phase 1 - plugin scaffold

- [x] Plugin header, activation and deactivation hooks load in local WordPress.
- [x] Activation creates the scans and findings tables and default settings; reactivation is idempotent.
- [x] Deactivation clears scan events carrying arguments and schedule hooks.
- [ ] Verify uninstall cleanup and install/activate from a clean candidate ZIP.
- [ ] Run the WordPress 6.6 minimum-version CI job.

## Phase 2 - persistence and local audit engine

- [x] Local WordPress smoke started and advanced a scan, then reloaded stored state: 16 check records, `partial`, 64.29% coverage.
- [x] Anonymous and subscriber REST reads were denied; administrator reads succeeded.
- [x] Missing write nonce, invalid scan ID and invalid pagination were rejected; duplicate active scan returned conflict.
- [x] Retention smoke seeded 25 recent scans plus a highest-ID 91-day scan; verified the latest 20 recent scans remain and expired findings are removed.
- [ ] Run the WP_UnitTestCase integration suite for database migration, cron and real HTTP lifecycle under wp-env.

## Phase 3 - consent-based providers and integrity

- [x] Local scan observed zero WordPress HTTP API calls with both provider opt-ins disabled.
- [x] PHP self-checks cover local checks, provider mapping/outage cases, output scrubbing and core-file safeguards.
- [ ] Verify provider contract and opt-in HTTP behavior against the final fixtures; CI must exercise POSIX permission/symlink branches.

## Phase 4 - scoring, comparison and reports

- [x] PHPUnit unit tests cover score penalties/deduplication/coverage threshold/floor, finding comparison and stored-score validation.
- [x] Loopback HTTP smoke verified cookie authentication, nonce, overview/history, JSON and CSV bodies, attachment and no-store/nosniff headers, and anonymous denial.
- [x] Output fixtures cover HTML/path/reference scrubbing and CSV formula prefixes.
- [ ] Run export privacy and historical immutability cases in the WordPress integration suite.

## Phase 5 - administrator experience

- [ ] Run Playwright admin flow against the built app, including finding details and report selection.
- [ ] Verify filtering/history/settings, progress/partial/error states, keyboard use, 360px layout and 200% zoom.

## Phase 6 - release preparation

- [ ] Finish PHPCS and frontend lint/typecheck/build without material findings.
- [ ] Run Plugin Check and the WordPress/PHP CI matrix.
- [ ] Install the final ZIP in a clean WordPress environment, verify its file list and repeat-build hash, then retain the CI artifact.

## Verification record

- Local environment: PHP 8.4.24, WordPress 7.0, SQLite Database Integration 3.1.3, WP-CLI 2.12.0. Docker/MySQL are unavailable locally.
- `composer test`: 11 PHPUnit tests / 37 assertions passed; `checks.php` passed default, `debug`, `secure`, and `mods` modes; filesystem checks passed 8 assertions with POSIX-only permission/symlink cases skipped on Windows; output checks passed.
- `php .tools/wp-cli.phar eval-file scripts/runtime-smoke.php --path=.tools/wordpress`: passed after resetting only the disposable `.tools` test database. Scan was `partial`, with 16 checks and 64.29% coverage; zero provider HTTP calls. Lifecycle arguments, injected output, 20-scan/90-day retention and finding cleanup also passed.
- `python scripts/http-smoke.py`: passed against the local loopback WordPress site, including cookie login, nonce and export headers.
- `composer test:wp` cannot run locally because `WP_TESTS_DIR` / `WP_UnitTestCase` is supplied by wp-env and Docker is unavailable. CI is configured to run it but has not run here.
- PHPCS currently reports warnings in the provider file under active changes; rerun after that work lands. Frontend checks, Playwright, Plugin Check, matrix and clean ZIP installation remain open.

## Latest direct verification (2026-11-10)

- Sub-agents stopped at their usage limit; root continued from saved files. Goal remains active.
- PHPUnit: 11 tests, 37 assertions passed. Standalone check modes default/debug/secure/mods pass; filesystem suite passes 8 Windows assertions with POSIX/symlink cases explicitly skipped; output privacy suite passes.
- New `php tests/unit/advisory-cursor.php` passes: 150 advisories in 100/50 batches, deterministic retry, no duplicated identities, changed-feed detection, immediate opt-out and rejection of malformed empty JSON objects.
- `phpcs --report=summary` exits 0 with no findings after scoped, documented standards exceptions.
- Frontend `npm run lint`, `npm run typecheck` and `npm run build` pass. Playwright Chromium installed; `WP_BASE_URL=http://127.0.0.1:8888 npm run e2e` passes both initial tests (authenticated/private API nonce handling and real dashboard loading). These two tests do not prove the full UX acceptance matrix.
- Current runtime PHP/build copied into the disposable WordPress 7.0 test site; real HTTP smoke passes. The final empty-object provider validation was added afterwards and has standalone regression coverage.
- Live primary API verification confirmed core version-scoped advisory membership, nested impact.cvss3 severity, and that nonexistent plugin slugs are echoed by the provider. Plugin/theme identity now requires fresh native update metadata; claimed PluginURI alone is insufficient.

### Next required work

1. Audit final frontend against review findings: historical report readiness/identity, reachable detail and keyboard return, polling race guards, failed consent saves, mixed `has_unknown` confidence, metric gating and CSS isolation. Confidence must describe stored checks independently of current consent settings.
2. Expand real browser tests beyond the two smoke cases; verify finding details, selected historical report/export, settings errors, scan progression/cancel, filters, keyboard, 360px, 200% text zoom and multi-page printing; capture actual screenshots.
3. Finish/prove local WordPress 6.6 setup (`.tools/wordpress66` exists but was not verified complete before sub-agent stopped), run Plugin Check, clean archive installation/uninstall and repeat-build hashes. Inspect current process handles before restarting any local server.
4. Run the WordPress PHPUnit/MySQL/PHP compatibility and POSIX matrix in a suitable environment. Docker is unavailable locally; configured CI has not run.
5. Rebuild the ZIP only after final source verification. Existing `artifacts/site-security-auditor.zip` is stale and must not be described as the verified final release.
