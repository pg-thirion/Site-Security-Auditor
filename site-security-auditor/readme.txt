=== Site Security Auditor ===
Contributors: site-security-auditor
Tags: security, audit, hardening
Requires at least: 6.6
Tested up to: 7.1
Requires PHP: 8.2
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Read-only WordPress security posture checks with evidence, coverage and private reports.

== Description ==

An administrator-only, local-first posture audit. Findings describe selected configuration, update and vulnerability indicators. Passing checks do not establish that a site is secure or free from compromise. This plugin does not detect malware, inspect passwords, exploit vulnerabilities or apply fixes.

Includes a bounded background worker with a manual Continue scan fallback, limited history, browser printing, and authenticated CSV and JSON exports. Multisite auditing is not supported.

This is a development release candidate. See the repository verification record for the actual tested environment; compatibility headers describe the intended minimum, not a completed compatibility matrix.

== External services ==

Both integrations default off and require separate administrator consent in Settings. No telemetry, remote assets or developer-operated service is used.

* Vulnerability intelligence: https://www.wpvulnerability.net/ receives component slugs and WordPress version identifiers for advisory queries. Installed versions are compared locally. The service can observe the requesting server IP and ordinary request metadata. No full site URL, user list or credentials are sent. Documentation: https://docs.wpvulnerability.com/ . Review the provider's current terms and privacy information before enabling it.
* Core integrity: https://api.wordpress.org/core/checksums/1.0/ receives the WordPress version and locale to retrieve official checksums over HTTPS. File hashes and file contents remain local. WordPress.org privacy information: https://wordpress.org/about/privacy/ .

Failed, disabled or unverifiable lookups return Unknown. WordPress itself may perform background update requests independently of this plugin.

== Installation ==

The WordPress options table and this plugin's audit tables must use InnoDB for safe scan writes. The plugin reports incompatible storage engines and does not convert tables automatically.

1. Build the candidate ZIP using the repository instructions, or obtain a trusted built release.
2. Upload site-security-auditor.zip through Plugins > Add New > Upload Plugin.
3. Activate on a single-site WordPress installation.
4. Open Security Audit. Review optional service consent before running an audit.

== Frequently Asked Questions ==

= Does it fix findings? =
No. Review the evidence and remediation, then make changes using your normal backup and change process.

= How is the score calculated? =
Version 1 deducts the highest severity penalty once per failing eligible check: critical 25, high 12, medium 6, low 2. Informational and unrated findings have no penalty. Unknown checks reduce coverage. Below 70% coverage the numeric score is suppressed. This indicator is not a probability of compromise.

= Is PDF generation included? =
Use Print / Save as PDF in the report. Your browser prints the selected stored audit; there is no server PDF service.

= What data is stored and removed? =
The plugin stores check results, safe findings and consent options in the site's database. History is limited to the latest 20 scans and 90 days. Deactivation clears scheduled work but retains history. Deleting the plugin through WordPress removes its tables, options, cached provider responses and scheduled work.

== Changelog ==

= 0.1.0 =
* Initial development candidate. Local audit checks, private administration, consent-based providers, bounded scanning and reports.

== Processing limits ==
Each scan worker is bounded to five provider requests and 250 file hashes. A scan that exceeds the 5,000-finding cap stops with a safe diagnostic instead of silently dropping findings. Results are retained for at most 20 scans and 90 days, whichever is more restrictive.

Provider disclosures: Vulnerability lookups send component identifiers to [WPVulnerability](https://www.wpvulnerability.net/); see its [API documentation](https://www.wpvulnerability.com/api/) and review current provider privacy terms before enabling. Core checksum lookups send only the WordPress version and locale to [WordPress.org's checksum API](https://api.wordpress.org/core/checksums/1.0/); see [WordPress.org privacy information](https://wordpress.org/about/privacy/).
