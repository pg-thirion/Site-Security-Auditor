# Changelog

- Reject SQLite drop-ins from transactional scans even when they report InnoDB metadata.
- Return storage errors for failed scan and finding reads instead of empty results.
- Reject failed finding reads instead of calculating scores from an empty report.
- Delete retained scans and their findings together.
- Retry schema setup until both scan tables are confirmed as InnoDB.
- Mark plugin and theme inventory checks unknown when their inventories change mid-scan.
- Rebuild the candidate ZIP with current privacy and scan fixes.
- Keep the site URL out of provider request headers and detect public registration with unfiltered HTML privileges.
- Match update metadata to installed versions before reporting update status.
- Guard scan creation with current lock ownership and transactional writes.
- Refresh findings when polling observes scan completion; clear recovered polling errors and show history loading accurately.
- Remove unused findings from progress responses and declare the browser accessibility test dependency directly.
## 0.1.0 â€” unreleased engineering candidate

- Guard batch persistence with current worker ownership and transactional row locks; reject incompatible storage engines explicitly.
- Check new finding identities against remaining capacity before storing a batch, while allowing retries at the limit.
- Preserve every stored finding when exporting older scans that exceeded the limit.
- Reject impossible advisory intervals and exclude protected checksum paths regardless of letter case.
- Restore enabled weekly scans after reactivation without duplicating scheduled events.
- Load selected reports despite unrelated history/settings failures and correct report coverage formatting.
- Fail packaging when adding files, setting timestamps or closing the archive fails.

- Confirm settings persistence before reporting success or changing scheduled scans.
- Treat empty or malformed checksum maps and contradictory advisory ranges as unknown results.
- Keep Overview findings tied to their scan when refreshing results fails.
- Page findings in the database and retain bounded text search for older database compatibility.
- Report installed component versions in update findings and remove an unused provider URL helper.

- Detect public-registration roles with user-management and plugin/theme/core modification capabilities that were previously omitted.
- Check metadata for WordPress's supported parent-directory configuration layout while excluding another parent installation.

- Acquire scan locks with atomic insert-only SQL so competing administrators cannot replace a live owner after observing a missing option.
- Add overlapping-process scan tests and a 1,000-plugin slow-provider integration test.

- Add administrator-only, read-only WordPress security posture audits.
- Add local checks, persistent scan history, score and coverage, comparison, and JSON/CSV/print reporting.
- Add separately opt-in vulnerability and checksum lookups, disabled by default.
- Add PHP unit and WordPress integration harnesses, Playwright checks, and candidate ZIP packaging.
- Keep inactive component inventories informational and fit finding filters at double text size on narrow screens.
- Complete candidate readme compatibility metadata and avoid global uninstall variables.
- Queue audit refreshes behind active reads so starting or advancing a scan cannot leave stale progress visible.
- Add real MariaDB scan lifecycle/export integration coverage and custom UpdateURI consent safeguards to the test suite.
- Disable unavailable historical report actions and clarify which identifiers optional advisory requests transmit.
- Upgrade the build toolchain, patch its cache serialiser and align the CI Node version; remaining npm audit findings are development-only.

This is an unreleased development build. Compatibility and release acceptance checks remain open in `PROGRESS.md`.
