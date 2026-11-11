# Threat model

## Assets and trust boundaries

Audit findings reveal installed components and configuration posture. They remain in private database tables and authenticated admin responses. Administrator consent controls each external service separately. WordPress, its database and authenticated administrators are trusted; provider responses, component metadata, REST parameters and filesystem paths are not.

This plugin cannot establish that WordPress or another plugin has not already been compromised. A privileged attacker able to change PHP, database records or WordPress authentication can falsify the audit.

## Controls and remaining verification

| Threat | Implemented control | Required release evidence |
| --- | --- | --- |
| Unauthorised reads / IDOR | Every route checks `manage_options`; admin render checks capability; reports have no public files | Anonymous and subscriber requests fail for every route, including exports |
| CSRF | Browser writes require a valid `wp_rest` header nonce as well as capability | Missing, stale and invalid nonce requests fail |
| Stored XSS | React renders text; provider HTML stripped; advisory links restricted to HTTPS hosts; fields and arrays bounded | Malicious provider and component metadata fixtures plus browser inspection |
| SQL injection | Fixed table names from WordPress prefix; dynamic values passed through `$wpdb` prepare/CRUD methods | Invalid IDs, pagination and filters rejected |
| SSRF | Fixed HTTPS service endpoints; no user URL inputs; safe HTTP client, no redirects, response caps | Malicious identifiers rejected and no requests before consent |
| Sensitive output | Config check reads metadata only; no password/account-secret access; safe finding allowlist; internal worker cursors withheld | Review JSON/CSV/browser results for paths and confidential configuration |
| CSV formula execution | Formula prefixes and leading controls receive an apostrophe; CSV writer quotes fields | Injection and encoding tests |
| Filesystem traversal | Only official checksum keys; path validation and root containment; unsafe symlinks rejected | Traversal, symlink, missing-file and read-error fixtures |
| Resource exhaustion | One check per worker; external request/hash/time budgets; paginated endpoints; bounded exports and retention | Large inventories, API delays, huge responses and interrupted batches |
| Concurrent workers | Atomic database option acquisition, expiry and compare-and-swap takeover; token-specific release | Concurrent starts, retries and stale locks |
| Lost/duplicated findings | Stable identity unique per scan; findings stored before cursor advancement; retries replace records | Crash/retry and historical comparison tests |
| Provider outage | Separate consent, cache/backoff and unknown states; score coverage exposes missing assessment | Timeout, 429, malformed response and immediate opt-out tests |
| Destructive behaviour | No repair endpoints; read-only checks; data deletion limited to retention and WordPress uninstall | Review shipped ZIP, lifecycle and uninstall tests |

## Operational limits

WP-Cron depends on traffic or server scheduling. Administrators can advance one bounded batch explicitly. PHP and database failures can interrupt a worker; findings may be partial and must not be interpreted as a clean audit. Checks use observed configuration and provider version ranges, not an exploitation test.

Do not treat this document as proof that the verification column passed. `PROGRESS.md` records executed evidence and outstanding gates. Release review must include the actual packaged ZIP and a clean installation.
