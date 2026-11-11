# Site Security Auditor

An administrator-only WordPress plugin for read-only security posture audits. It reports the checks it could assess and distinguishes unknown results from passing checks. It is not a malware detector or penetration-testing tool.

## Development

For overlapping-process scan checks, run `python scripts/concurrency-smoke.py --path /path/to/disposable/wordpress --wp-cli /path/to/wp-cli.phar` after activating the plugin. The site must set `WP_ENVIRONMENT_TYPE` to `local`. This creates and cancels its own scan, runs competing PHP processes against the site's shared database, and checks singleton starts, worker exclusion and safe continuation. It requires Python, PHP and WP-CLI; use `--php` when PHP is not on PATH. It does not replace HTTP authorisation tests or prove production database performance.

Requirements: PHP 8.2+, Composer, Node.js 22.22.2+ (22.x) or 24.15.0+ (24.x), npm and Docker for the local WordPress environment.

Safe scan writes require InnoDB for the WordPress options table and the plugin's scan and finding tables. Other storage engines receive an explicit compatibility error; the plugin does not convert existing tables.

From the repository root:

```sh
composer install
npm --prefix site-security-auditor install
npx --yes @wordpress/env start
composer test
composer lint
npx --yes @wordpress/env run tests-cli --env-cwd=project vendor/bin/phpunit -c phpunit-wp.xml.dist
npm --prefix site-security-auditor run typecheck
npm --prefix site-security-auditor run lint
npm --prefix site-security-auditor run e2e
```

The WordPress integration suite needs a configured WordPress test library and database (`WP_TESTS_DIR`); without it, only the unit suite runs. The browser suite needs the local WordPress environment and Playwright browsers. See `PLAN.md` for required release coverage. These commands are setup guidance; no environment-specific result is implied.

The build uses `@wordpress/scripts` 37. Its copy plugin still requests an older `serialize-javascript`; the scoped npm override selects patched 7.1.3 or newer in that major. The serialiser is used for development cache keys, not shipped plugin code. Remove the override when the copy plugin's declared range includes the patched release. Its transform-cache path and the plugin build were checked with this combination.

Docker-free integration testing can use a separate WordPress test library and disposable MariaDB/MySQL database. Set `WP_TESTS_DIR` to the library's `tests/phpunit` directory and run `composer test:wp`. Configure its `wp-tests-config.php` with the core `ABSPATH`, isolated database credentials and `WP_TESTS_PHPUNIT_POLYFILLS_PATH` pointing to this repository's `vendor/yoast/phpunit-polyfills/`. Composer installs that test dependency. The WordPress test bootstrap rebuilds test tables; use a dedicated test database. On Windows, quote `PHP_BINARY` with `escapeshellarg()` when defining `WP_PHP_BINARY` if the path contains spaces.

For a real WordPress REST and scan smoke check, activate the plugin on a disposable site whose `WP_ENVIRONMENT_TYPE` is `local`, then run `php wp-cli.phar eval-file scripts/runtime-smoke.php`. It creates a subscriber and audit records, so do not point it at a production site.

With the repository's wp-env running, the same check is `npx --yes @wordpress/env run cli --env-cwd=project wp --path=/var/www/html eval-file scripts/runtime-smoke.php`. After it has completed a scan, run `python scripts/http-smoke.py` to verify WordPress cookie authentication and actual JSON/CSV response headers on `localhost` (or set `SSA_TEST_URL` to another loopback URL).

Build a candidate archive after compiling the plugin:

```sh
npm --prefix site-security-auditor run build
php scripts/package-plugin.php
```

The resulting `artifacts/site-security-auditor.zip` contains the plugin folder and its runtime assets. Install it on a clean WordPress test site before treating it as a release candidate.

## Scope and privacy

Audits are read-only. Optional external vulnerability and checksum lookups require separate opt-in. The plugin does not scan arbitrary hosts. See `SECURITY.md` for reporting vulnerabilities and `SPEC.md` for the check catalogue and known limitations.

Each worker is bounded to at most five provider requests and 250 file hashes. A scan stops safely with an error if it exceeds the 5,000-finding storage cap; results are not silently truncated.

## Licence

GPL-2.0-or-later. See `LICENSE`.
