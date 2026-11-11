# Site Security Auditor

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary users are WordPress website owners, freelancers, maintainers and administrators reviewing the security posture of sites they manage. Agencies performing repeatable baseline reviews are a secondary audience. Access is restricted to administrators with `manage_options`.

## Product Purpose

An installable, open-source WordPress plugin for non-destructive security posture audits. It identifies common configuration risks, outdated components and known published vulnerabilities, explains the evidence and prioritises practical remediation.

The product is intended to be a useful free plugin and a credible security engineering portfolio project. V1 succeeds when an administrator can install the plugin ZIP, run an audit end-to-end, inspect accurate findings and export a report, with relevant security tests passing.

## Positioning

Read-only, local-first audits inside wp-admin, with meaningful results when optional external integrations are disabled. Findings explain what was checked, why it matters and what the administrator can do. Passing a check never means the entire site is secure.

## Operating Context

- The administrator opens **Security Audit**, reviews the audit scope and selects **Run audit**.
- Scans run in bounded batches using WP-Cron, with a secure administrator-controlled fallback when cron is delayed. Processing states are `Queued`, `Running`, `Completed`, `Partial`, `Failed` and `Cancelled`.
- The administrator filters findings, examines evidence and remediation, and reviews scan history and comparisons.
- Reports support browser **Print / Save PDF**, CSV and JSON. V1 does not generate PDFs on the server.
- Settings cover separate provider opt-ins, optional weekly scheduling and retention. History retains at most the latest 20 scans within the last 90 days.

## Capabilities and Constraints

These are approved requirements, not claims of shipped functionality. At init, the project contains specifications and a design document, with no application implementation.

- Audit scope is the check catalogue in `SPEC.md`: configuration, component versions, environment support, optional published vulnerability intelligence and optional core file checksums.
- Checks return `pass`, `fail`, `unknown` or `not_applicable`. Unavailable evidence is never treated as a pass; checks that become unknown are not reported as resolved.
- A score is a bounded configuration posture indicator, with coverage alongside it. Below 70% coverage, show `Insufficient coverage` instead of a numeric score.
- WPVulnerability intelligence and WordPress.org checksum retrieval require separate explicit opt-ins and default off. Explain the provider and transmitted data before consent. Make no unsolicited plugin requests on activation or page load.
- Keep findings and reports administrator-only. Enforce capabilities and authenticated access, protect state-changing browser requests with nonces, validate input and escape output. Exclude credentials, secrets and sensitive paths from UI and exports.
- Never patch files, update components, change accounts or server configuration, exploit vulnerabilities, scan arbitrary targets or claim malware detection. V1 excludes multisite network scanning and external SaaS dashboards.
- Bundle assets locally. No remote fonts, analytics or telemetry. Reports must work without an external SaaS.
- Initial engineering targets are PHP 8.2+ and WordPress 6.6+; compatibility claims require testing. Original source and distribution are intended to use GPL-2.0-or-later, subject to dependency licence review.

## Brand Commitments

Working name: **Site Security Auditor**. Plugin slug and text domain: `site-security-auditor`. Explain findings in plain language and make limitations explicit. Naming remains provisional pending directory, trademark and repository checks before public release.

## Evidence on Hand

- `SPEC.md`: approved intended users, scope, workflows, security constraints and acceptance criteria.
- `DESIGN.md`: existing interface and interaction guidance; preserved by init.
- `PLAN.md`: implementation sequence.
- `PROMPT.txt`: implementation hand-off instructions.

There is no implemented plugin, rendered interface or verified test evidence in the project at init. Do not invent performance benchmarks, customer proof, compatibility results or WordPress.org review status.

## Product Principles

1. Observe and explain; leave corrective changes to the administrator.
2. Deliver useful local results without requiring external services.
3. Show evidence, uncertainty and coverage honestly.
4. Protect administrative access and minimise retained or transmitted data.
5. Follow WordPress conventions for authentication, translations, controls and scoped assets.

## Accessibility & Inclusion

Target WCAG 2.2 AA where feasible, as required by `DESIGN.md`. Provide keyboard access, visible focus, semantic labels and headings, accessible errors and scan announcements, sufficient contrast and status cues beyond colour. Support 200% zoom, reduced motion and WordPress locale/time settings. These are requirements awaiting implementation and verification.
