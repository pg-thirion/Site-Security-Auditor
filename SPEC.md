# Site Security Auditor for WordPress

**File:** `SPEC.md`  
**Status:** Implementation specification, version 1.0  
**Date:** 2 November 2026  
**Companion files:** `DESIGN.md`, `PLAN.md`, `PROMPT.txt`  
**Working product name:** Site Security Auditor  
**Plugin slug:** `site-security-auditor`  
**Text domain:** `site-security-auditor`

> Naming is provisional. Check the WordPress Plugin Directory, trademarks and the intended repository name before public release. Do not claim the plugin has passed directory review.

## 1. Purpose

Build an installable, open-source, administrator-only WordPress plugin that performs **non-destructive security posture audits**. The tool must show exactly what was checked, explain each finding in plain language, prioritise corrective actions and preserve a limited history of scans. The goal is a technically credible security engineering portfolio project and a useful free plugin, not a guaranteed malware detector or penetration-testing product.

**User promise:** In a few minutes, a site administrator can identify common WordPress configuration risks, outdated components and known published vulnerabilities, then obtain an evidence-based report and practical remediation guidance.

**Definition of done for v1:** A working plugin ZIP can be installed on a clean WordPress test site, an administrator can run a scan end-to-end, findings accurately reflect planted test conditions, reports work without external SaaS, and automated security tests pass.

## 2. Target users and principles

- Primary: WordPress website owners, freelancers, maintainers and administrators.
- Secondary: agencies performing repeatable baseline reviews.
- Administrator-only: no front-end widgets, no public REST findings, no guest scanning.
- Read-only by design: **never** patch files, update WordPress, alter firewall rules, change user accounts or rewrite server configuration.
- Local-first: a meaningful audit must run with all optional network integrations disabled.
- Explain limitations: a passing result means *this check passed*, not that the entire website is secure.
- Honest uncertainty: show `unknown` or `not_applicable` instead of fabricating a pass.
- Be a good WordPress citizen: WordPress APIs, native authentication, accessibility, translations and scoped assets.

## 3. Technical compatibility and packaging

- Backend: PHP 8.2+ with WordPress Coding Standards, compatible with supported PHP branches at release time.
- WordPress baseline: WordPress 6.6+ as an initial engineering target. Test this minimum and the latest stable release before shipping. Adjust headers and claims only to match verified test coverage.
- Frontend: React/TypeScript built with `@wordpress/scripts`; prefer bundled `@wordpress/components`, `@wordpress/element`, `@wordpress/api-fetch` and native WordPress script handles over shipping duplicate framework runtimes.
- Data: WordPress options for configuration, two small custom tables for scans and findings via `dbDelta()`.
- Scan processing: bounded PHP batches scheduled using WP-Cron, with a secure administrator-controlled fallback when WP-Cron is delayed.
- Vulnerability source: optional WPVulnerability public core/plugin/theme API behind a provider adapter. Do not assume an API response shape without fixtures and contract tests.
- File integrity: optional WordPress.org official core checksums through an HTTPS-only adapter informed by the `get_core_checksums( $version, $locale )` API, with bounded local file hashing. Do not permit HTTP fallback.
- Local development: `@wordpress/env` or equivalent Docker-backed WordPress environment, PHPUnit/WordPress test suite, Playwright, ESLint, PHPCS and Plugin Check.
- Licence: GPL-2.0-or-later for original source and distribution, subject to licence review of all dependencies.
- Output: valid installable `site-security-auditor.zip`, including compiled assets and excluding developer-only dependencies, secrets, test fixtures and generated scan data.

## 4. MVP user journeys

### UJ-01 First installation
1. Administrator activates plugin; database tables are created and settings are initialised.
2. Menu item **Security Audit** appears in wp-admin, visible only to users with `manage_options`.
3. Dashboard shows `No audits yet`, scan scope and a prominent **Run audit** button.
4. Clearly labelled opt-in toggles separately enable vulnerability intelligence and WordPress.org checksum retrieval. Both default off. Explain provider, transmitted data and privacy implications before consent.
5. No unsolicited outbound requests are made by this plugin on activation or page load.

### UJ-02 Manual audit
1. Administrator starts a scan using authenticated, nonce-protected REST API access.
2. Scan is queued; UI displays `Queued`, `Running`, `Completed`, `Partial`, `Failed` or `Cancelled` accurately.
3. Local checks run regardless of provider availability. Opted-in network checks run with strict request budgets and caching.
4. UI polls authenticated scan status and shows stage progress; if WP-Cron is delayed, authorised **Continue scan** advances one bounded batch.
5. Completed scan appears in history with its findings, assessment coverage, score when eligible and completion timestamp.

### UJ-03 Examine a finding
1. Administrator filters findings by status, severity or category.
2. A finding shows title, affected component, observed state, reason, potential consequence, remediation steps, source and last verified time.
3. Where possible, link to official WordPress documentation or advisory; do not link directly to untrusted exploit code.
4. Findings with insufficient evidence show `Unknown` with a useful reason.

### UJ-04 Export report
1. From a completed or partial scan, administrator selects **Print / Save as PDF**, **Download CSV** or **Download JSON**.
2. Print layout contains a heading, date, site display hostname, check coverage, findings and a limitations note. Browser print-to-PDF is the v1 PDF path. **Do not claim server-generated PDF support.**
3. CSV/JSON are served through authorised endpoints and exclude sensitive paths, raw secrets, hashes of secret content and credentials.

### UJ-05 Review previous scans
1. History shows the latest 20 scans or the last 90 days, whichever is more restrictive.
2. Compare current and previous findings by stable check ID and component identity: `New`, `Still present`, `Resolved`, and `Not evaluated`.
3. A check that became unknown must not be presented as resolved.

## 5. Audit check catalogue

All checks must be individually testable modules with consistent output, and each must return `pass`, `fail`, `unknown` or `not_applicable`. For `fail`, the module emits one or more findings. Informational checks can emit `info` findings but do not affect the score. Use stable IDs, not display names, for history comparisons.

| ID | Check | Method | Default severity when failing | Notes |
|---|---|---|---|---|
| SSA-001 | WordPress core updates | Read WordPress update transient/state | Medium | Unknown when update data missing or stale; do not force a network update without consent |
| SSA-002 | Plugin updates | Read core-managed plugin update data | Medium | List affected active/inactive plugins without leaking installation paths |
| SSA-003 | Theme updates | Read theme update data | Medium | Parent and child themes handled accurately |
| SSA-004 | Known vulnerable WordPress core | Opt-in vulnerability feed, installed version | Critical/High from advisory mapping | Unknown if feed disabled/unavailable; only flag confirmed affected version ranges |
| SSA-005 | Known vulnerable plugins | Opt-in vulnerability feed, verified slug/version | Critical/High/Medium as supported | Cache per slug; unverified slug gives unknown, not safe |
| SSA-006 | Known vulnerable themes | Opt-in vulnerability feed, verified slug/version | Critical/High/Medium as supported | Distinguish themes with no advisory from unsupported matching |
| SSA-007 | HTTPS site configuration | Inspect `home_url()` and `site_url()` scheme | High | Check configured schemes, not real transport/certificate validity |
| SSA-008 | SSL for admin sessions | Inspect `force_ssl_admin()` and site context | Medium | A false setting alone may be advice, not proof admin requests use HTTP; explain limitations |
| SSA-009 | Debug output exposure | Inspect `WP_DEBUG` and `WP_DEBUG_DISPLAY` safely | High | Only fail when debug output is configured to display; debug logging alone is not a failure |
| SSA-010 | Built-in file editor enabled | Inspect `DISALLOW_FILE_EDIT` | Medium | Mark as hardening guidance, not a confirmed exploit |
| SSA-011 | Privileged public registration | Inspect `users_can_register`, `default_role` and role capabilities | Critical | Only fail where self-registration may grant privileged capabilities |
| SSA-012 | Core file checksum integrity | Opt-in WordPress.org checksums, local bounded hashes | High | Ignore known environment-specific exclusions; report changed/missing files, not malware claims |
| SSA-013 | World-writable configuration file | Inspect `wp-config.php` metadata without reading content | High | Fail only for verifiable unsafe permissions; unknown on Windows/ACL ambiguity or unavailable path |
| SSA-014 | End-of-life PHP version | Compare PHP branch against verified PHP support schedule | High | Support schedule must be maintainable and covered by date-boundary tests |
| SSA-015 | Inactive plugin inventory | WordPress installed plugin data | Informational | Suggest reviewing unnecessary plugins, no automatic failure |
| SSA-016 | Unused theme inventory | WordPress installed theme data | Informational | Do not mislabel active child theme's parent as unused |

### Audit-specific safety rules

- **No arbitrary HTTP target scanning.** Only documented provider endpoints may be called. No crawling visitors, brute forcing accounts, port scanning or exploitation.
- Never fetch the site's configured URL from the server just to test headers. This avoids SSRF, loopback, redirect and authentication complications in v1. HTTP headers and Cloudflare are future optional features.
- Never read password hashes, authentication cookies, private keys, database credentials or `wp-config.php` contents.
- Do not claim to detect malware, weak passwords, an absent MFA policy or real internet exposure if not directly verified.
- For update checks, rely on existing WordPress update state, recording its freshness. If unavailable, mark unknown.
- For external advisories, record advisory ID, URL, source, affected range, fetch time and matching rationale. Never treat absent feed data as proof of safety if the lookup failed.
- Advisory severity must be derived from credible provider data when available. When insufficient, display `Unrated` and use conservative documented prioritisation rather than inventing CVSS.
- Hardening recommendations are distinguished from confirmed, version-matched vulnerabilities.

## 6. Finding model

Store a normalised record per finding, with enough information for report and diff views:

```json
{
  "id": "opaque-generated-id",
  "scan_id": 123,
  "check_id": "SSA-005",
  "component_type": "plugin",
  "component_key": "example-plugin/example-plugin.php",
  "component_name": "Example Plugin",
  "component_version": "1.2.3",
  "status": "fail",
  "severity": "high",
  "kind": "confirmed_vulnerability",
  "title": "Known vulnerability affects installed version",
  "summary": "Version 1.2.3 matches the advisory's affected range.",
  "evidence": "Advisory ID and affected-version comparison, without secrets",
  "remediation": ["Review the vendor advisory", "Update to a fixed version after taking a backup"],
  "references": ["https://example.org/advisory"],
  "checked_at": "ISO-8601 UTC timestamp",
  "source": "wpvulnerability",
  "source_updated_at": "ISO-8601 UTC timestamp or null"
}
```

This is an **illustrative structure, not a real advisory**. Reject or sanitise external URLs, HTML and strings. Store structured payloads as bounded, safely serialised JSON. Never render raw provider HTML.

**Statuses:** `pass`, `fail`, `unknown`, `not_applicable`; `info` is a finding kind and not a check status.  
**Kinds:** `confirmed_vulnerability`, `configuration_risk`, `hardening`, `integrity_difference`, `informational`, `unverified`.  
**Severity:** `critical`, `high`, `medium`, `low`, `info`, `unrated`.  
**Scans:** `queued`, `running`, `completed`, `partial`, `failed`, `cancelled`.

For each check, persist a check result even if no finding was emitted. Result contains check ID, status, reason, checked time, duration and count of affected items. Keep per-component findings in a separate table. In JSON exports, preserve unknown states explicitly.

## 7. Scoring, coverage and comparison

The score is a **bounded configuration posture indicator**, not an independent assessment of compromise likelihood.

- Start at 100.
- For each *distinct assessed failing check ID*, subtract the penalty associated with that check's highest-severity finding: critical 25, high 12, medium 6, low 2, info/unrated 0. Multiple components under the same check do not multiply the penalty. Floor at zero.
- Exclude `unknown`, `not_applicable` and informational-only checks from penalties.
- Coverage = count of `pass`/`fail` eligible check IDs divided by count of eligible check IDs excluding `not_applicable` and informational-only checks (`SSA-015` and `SSA-016`). Unknowns remain in the denominator. The two optional remote vulnerability feeds and checksum integrity count toward coverage even when disabled, making the limitation visible.
- If coverage is under **70%**, suppress the number and display `Insufficient coverage` instead. Display coverage next to every score.
- Score calculation must use explicit versioned rules (`score_version: 1`) so future weighting changes do not silently change historical scores.
- On two scans, stable `(check_id, component_type, component_key, advisory_id-if-present)` is the issue identity. `Resolved` means the check was reassessed and it no longer failed. `Unknown` means *not evaluated*, never resolved.

Store scoring formula and coverage calculation in deterministic, unit-tested code. Clearly state that severity is contextual, not a CVSS calculation.

## 8. External providers and privacy

### WPVulnerability (optional)

- User explicitly enables **Vulnerability intelligence** in Settings. The default is off.
- Send only the component type, public plugin/theme slug and version as required by the API query and matching. Do not transmit email, WordPress user lists, secrets, raw site configuration or the site's full URL.
- Be transparent that the provider may observe the requesting server IP and request metadata.
- Public core/plugin/theme endpoints are currently documented without authentication, but implementation must verify terms, endpoint shapes and availability before shipping.
- Cache successful responses approximately 12 hours. Use shorter bounded negative caching when appropriate. Backoff on 429/503/timeouts; do not overwhelm the feed or issue hundreds of simultaneous requests.
- On error, mark corresponding checks `unknown` with source error category. Never score as pass.

### WordPress.org core checksum service (optional)

- A separate **Core integrity verification** opt-in must explain that the WordPress version and locale are requested from WordPress.org.
- WordPress provides `get_core_checksums()`, which can return `false`. Its implementation may fall back to HTTP if HTTPS fails. To preserve checksum authenticity, use an HTTPS-only trusted WordPress.org fetch adapter (or verify that the WordPress helper can be used without insecure fallback). Fail closed to `unknown` on TLS or checksum-service errors. Never trust checksums retrieved over plain HTTP.
- Hash only files listed in the response; do not recurse through uploads or arbitrary plugin paths. Check paths remain within the WordPress core root, guard against symlinks/path traversal and stop on budget exhaustion. Avoid logging raw filesystem paths in persistent findings.
- A checksum mismatch is a file integrity difference, **not proof of infection**.

### Other requests

- The plugin must not embed remote fonts, analytics or telemetry. Bundle UI assets locally.
- The plugin must not contact a server under developer control.
- Existing WordPress background update checks are outside this plugin's control and should not be misrepresented as plugin-originated requests.
- Document each external service, requested data and opt-in mechanism in `readme.txt` and Settings.

## 9. Storage and service contracts

### Tables

1. `{$wpdb->prefix}ssa_scans`: `id BIGINT`, `started_by BIGINT nullable`, `status VARCHAR(20)`, `stage VARCHAR(32)`, `cursor LONGTEXT nullable`, `checks_json LONGTEXT`, `score SMALLINT nullable`, `score_version SMALLINT`, `coverage DECIMAL(5,2)`, `error_code VARCHAR(64) nullable`, `started_at DATETIME`, `finished_at DATETIME nullable`, `created_at DATETIME`. Add indexes on `status`, `created_at`.
2. `{$wpdb->prefix}ssa_findings`: `id BIGINT`, `scan_id BIGINT`, `identity_hash CHAR(64)`, `check_id VARCHAR(16)`, `status VARCHAR(20)`, `severity VARCHAR(20)`, `kind VARCHAR(40)`, `component_key VARCHAR(255)`, `payload_json LONGTEXT`, `created_at DATETIME`. Add indexes on `scan_id`, `identity_hash`, `severity`.

Use correct `$wpdb->prefix`, `$wpdb->prepare()` for dynamic values, indexed pagination, safe `dbDelta()` migrations and an explicit schema version option. No raw SQL interpolated from request values. The checks JSON must be bounded and schema validated. Consider multisite support only after v1 (v1 should show a clear unsupported-network-admin message rather than silently mixing data).

### REST routes (all under `/site-security-auditor/v1`)

| Method | Path | Behaviour |
|---|---|---|
| GET | `/overview` | Latest scan, counts, status and coverage |
| POST | `/scans` | Start scan; return scan ID and initial state; return 409 if another scan active |
| GET | `/scans` | Paginated history, capped page size |
| GET | `/scans/{id}` | Scan metadata and check statuses |
| GET | `/scans/{id}/findings` | Paginated filtered findings |
| POST | `/scans/{id}/advance` | Administrator-triggered bounded progress if cron is delayed |
| POST | `/scans/{id}/cancel` | Cancel pending/running scan safely |
| GET | `/scans/{id}/export` | `format=json|csv`; permission checked, safe attachment headers |
| GET | `/settings` | Opt-ins and scan schedule |
| POST | `/settings` | Validate settings and consent changes |

All endpoints must have explicit `permission_callback` checking `current_user_can( 'manage_options' )` and WordPress REST authentication with `X-WP-Nonce` for browser writes. REST nonces **do not replace** capabilities. Validate route IDs, allowed statuses, pagination, format and input lengths. Disable caching of sensitive authenticated responses. Unknown paths return 404; disallowed access returns 403 with no data leakage.

### Scan orchestration

- Server-side stages: `inventory -> local_checks -> vulnerability_lookup -> checksum_lookup -> aggregate -> complete`.
- Persist progress between batches. Each worker invocation is bounded to about 10 seconds of compute, 5 external requests and 250 file hashes at most; tune in tests to stay within common shared hosting limits.
- Lock scans to prevent overlapping workers. Handle stale locks with an expiry; make each stage idempotent so retry does not duplicate findings.
- Start with `wp_schedule_single_event()` and reschedule work while pending. Add secure `/advance` fallback and a clear UX note if loopback or WP-Cron is unreliable.
- A scan with completed local checks but failed optional checks is `partial`; include unknown reasons. A total failure is `failed` and keeps safe diagnostic codes.
- Manual scans work when WP-Cron disabled by advancing one bounded batch per authorised interaction; no hidden browser loop that can exhaust a site.
- Schedule: weekly **off by default**. When enabled, use WP-Cron and clear hooks on deactivation. Disabling any opt-in immediately prevents new provider requests.
- Never automatically run fixes, delete files, change site settings or fetch arbitrary URLs.

## 10. Administrator UI requirements

Implement five views inside a single admin application, scoped to its own menu page:

1. **Overview:** posture indicator or coverage warning, open severity counts, latest scan, scan CTA, top actionable findings.
2. **Findings:** searchable/filterable table with status, severity, category, affected component, verified timestamp and detail drawer.
3. **History:** scan list with timestamps, states, coverage, scores and comparison to previous assessed scan.
4. **Report:** printable report view, CSV and JSON download controls, visible disclaimers.
5. **Settings:** explicit per-provider consent, weekly scheduling toggle, provider/privacy description and data retention statement.

Follow `DESIGN.md` exactly for interaction, accessibility and visual constraints. Show useful empty/loading/partial/error states. Do not expose path, environment variables, tokens or database credentials in UI or reports.

## 11. Security requirements for the plugin itself

- Apply least privilege: only `manage_options` users can view, start, retrieve or export scans, including all direct REST endpoints.
- Use nonce protection for state-changing browser operations and capability checks for every route. Do not create unauthenticated AJAX routes.
- Escape all HTML and attributes, validate and sanitise request data, treat feed output as untrusted and use allowlisted URLs.
- Protect against stored/reflected XSS, SQL injection, CSRF, SSRF, insecure deserialisation, path traversal and unbounded resource consumption.
- Never execute downloaded code, remote templates, advisory HTML or user-supplied PHP.
- Never upload arbitrary files, modify filesystem permissions, alter roles/users or install plugins/themes.
- Keep report access authenticated and non-indexable; do not publish static reports under `uploads`.
- Explicitly limit API response sizes, request timeouts, database retention and scan concurrency.
- Safe error codes must replace detailed stack traces and absolute paths in user-facing responses. Detailed debugging is opt-in local development only and must not expose secrets.
- Include a threat model and checks explaining how the plugin avoids becoming a security liability itself.

## 12. Automated quality gates and testing

**Unit tests:** each check in pass/fail/unknown states; affected-range matching; advisory severity handling; score calculation; diff logic; response parsing and provider downtime; read-only file integrity safeguards; PHP EOL date boundaries.

**Integration tests:** installation/upgrades; DB migrations; cron lifecycle; scan batching/retries/locking; retention; export; REST permissions with unauthenticated, subscriber and administrator identities; nonce failures; large plugin inventories.

**End-to-end:** fresh install, zero-state, opt-in and opt-out, manual scan, cancel/resume error path, filtering, history, CSV/JSON, browser print view, narrow/mobile wp-admin layout and keyboard interaction.

**Security regression:** XSS via malicious advisory text, malformed provider JSON, SSRF attempt (must be impossible by architecture), traversal/symlink tests, malicious IDs/filters, oversized results, concurrent scan start, missing nonce, wrong privilege, no outbound request before opt-in.

**Tooling:** Composer + PHPCS (WordPress rules), PHPStan if feasible, PHPUnit, npm build/test/lint, Plugin Check and a GitHub Actions matrix for minimum/latest WordPress with supported PHP versions. Do not skip failing checks or claim tests passed without running them.

## 13. Acceptance criteria

- [ ] Plugin installs, activates, deactivates and uninstalls safely on specified supported environments.
- [ ] No PHP warnings or browser errors during ordinary use.
- [ ] Administrator-only menu and REST data, verified with negative security tests.
- [ ] All 16 checks implemented to the exact method and limitations above.
- [ ] No external provider request before specific informed opt-in.
- [ ] Provider failure results in `unknown` and an honest `partial` scan, not a pass.
- [ ] Scan survives refresh, can be advanced on low-traffic sites and cannot run concurrently with another scan.
- [ ] Scores and coverage match documented formula and historical data is not retroactively rewritten.
- [ ] Findings include safe evidence, context, remediation, source and timestamps.
- [ ] History comparison never classifies an unassessed issue as resolved.
- [ ] Print-to-PDF, CSV and JSON reports have correct access control and no secrets.
- [ ] Mobile wp-admin view remains usable at 360px width, with full keyboard navigation.
- [ ] No automatic fixes, exploitation attempts, malware claims or arbitrary outbound targets.
- [ ] Build output includes installable ZIP, `readme.txt`, GPL licence, release instructions and test evidence.

## 14. Explicitly out of scope for v1

Automated remediation, malware detection, content scanning, brute-force testing, password inspection, MFA proof, login protection, public-site badges, user-facing SaaS dashboards, paid plans, telemetry, multi-tenant or multisite network scanning, WP-CLI command suite, WPVulnerability bulk feed, Cloudflare API/WAF integration, external TLS validation, HTTP header scanning, intrusion detection and guaranteed WordPress.org acceptance.

**Future v2 ideas:** optional Cloudflare read-only posture adapter; audited HTTP response-header checker with explicit same-origin constraints; signed report exports; more precise evidence mapping; WP-CLI commands; multisite; agency aggregate dashboard.

## 15. Documentation and upstream references

Verify up-to-date guidance before final release:

- Plugin Handbook: https://developer.wordpress.org/plugins/
- WordPress.org Plugin Directory guidelines: https://developer.wordpress.org/plugins/wordpress-org/detailed-plugin-guidelines/
- Custom REST routes and permission callbacks: https://developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/
- Nonce security: https://developer.wordpress.org/apis/security/nonces/
- `get_core_checksums()`: https://developer.wordpress.org/reference/functions/get_core_checksums/
- WPVulnerability API: https://docs.wpvulnerability.com/
- Plugin Check: https://wordpress.org/plugins/plugin-check/
- Supported PHP releases: https://www.php.net/supported-versions.php

If documentation and a planned implementation conflict, prioritise correctness and security, document the decision and update this specification before silently changing scope.
