# Provider fixtures

`wpvulnerability-plugin.json` is a minimised contract fixture whose envelope, `data.plugin`, `data.vulnerability`, `operator`, `source`, `impact.cvss3`, and `updated` fields were checked against the public WPVulnerability endpoint and its current OpenAPI documentation on 10 November 2026. It represents a synthetic test advisory; it is not a claim about the named fixture slug.

`wpvulnerability-core-6.6.2.json` contains 21 records selected from the live `/core/6.6.2/` endpoint response on 10 November 2026. Advisory source descriptions and unrelated impact fields were removed; the version-scoped response names, source identities/links and full `impact.cvss3.severity` values are retained. The core records have no `operator`; the endpoint's echoed `data.core` and version-specific membership are the evidence tested by the adapter contract.

The other WPVulnerability JSON files are deliberately malformed or hostile test inputs derived from that documented shape. `core-file.txt` is a local checksum test input. These files are development fixtures and must not be included in the distributable plugin ZIP.
