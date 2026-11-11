<?php
/** Standalone dense-feed regression: php tests/unit/advisory-cursor.php */
define( 'HOUR_IN_SECONDS', 3600 );
class WP_Error {
	public function __construct( public string $code = '' ) {}
}
function is_wp_error( $value ) {
	return $value instanceof WP_Error;
}
function get_option( $key, $default = false ) {
	return 'ssa_settings' === $key ? array( 'vulnerability_intelligence' => $GLOBALS['ssa_enabled'] ) : $default;
}
function get_bloginfo( $key ) {
	return '6.6';
}
function get_transient( $key ) {
	return $GLOBALS['ssa_cache'][ $key ] ?? false;
}
function set_transient( $key, $value, $ttl ) {
	$GLOBALS['ssa_cache'][ $key ] = $value;
}
function wp_json_encode( $value ) {
	return json_encode( $value ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Test stub for the WordPress API.
}
function wp_strip_all_tags( $value ) {
	return strip_tags( $value ); // phpcs:ignore WordPress.WP.AlternativeFunctions.strip_tags_strip_tags -- Plain-text fixture stub.
}
function wp_safe_remote_get( $url, $args ) {
	++$GLOBALS['ssa_requests'];
	return array(
		'body' => wp_json_encode(
			array(
				'error'   => 0,
				'updated' => (string) time(),
				'data'    => array(
					'core'          => '6.6',
					'vulnerability' => $GLOBALS['ssa_advisories'],
				),
			)
		),
	);
}
function wp_remote_retrieve_response_code( $response ) {
	return 200;
}
function wp_remote_retrieve_body( $response ) {
	return $response['body'];
}
function wp_parse_url( $url ) {
	return parse_url( $url );
}
require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Providers/WPVulnerabilityProvider.php';
require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Audit/Checks/ProviderChecks.php';

use SiteSecurityAuditor\Audit\Checks\ProviderChecks;

$GLOBALS['ssa_enabled']    = true;
$GLOBALS['ssa_cache']      = array();
$GLOBALS['ssa_requests']   = 0;
$GLOBALS['ssa_advisories'] = array();
foreach ( range( 1, 150 ) as $index ) {
	$GLOBALS['ssa_advisories'][] = array(
		'uuid'   => hash( 'sha256', (string) $index ),
		'name'   => '6.6',
		'source' => array(
			array(
				'id'   => hash( 'sha1', (string) $index ),
				'name' => 'Fixture advisory ' . $index,
				'link' => 'https://www.cve.org/',
			),
		),
		'impact' => array( 'cvss3' => array( 'severity' => 'high' ) ),
	);
}
$first = ProviderChecks::run( 4, array() );
$retry = ProviderChecks::run( 4, array() );
if ( 100 !== count( $first['findings'] ) || ! $first['cursor'] || $first['findings'] !== $retry['findings'] ) {
	throw new RuntimeException( 'First batch must be bounded and retries deterministic.' );
}
$second     = ProviderChecks::run( 4, array( 'cursor' => $first['cursor'] ) );
$identities = array_column( array_merge( $first['findings'], $second['findings'] ), 'advisory_id' );
if ( 50 !== count( $second['findings'] ) || $second['cursor'] || 150 !== $second['affected_count'] || 150 !== count( array_unique( $identities ) ) ) {
	throw new RuntimeException( 'Resuming a dense feed skipped or duplicated advisories.' );
}
$GLOBALS['ssa_cache']                              = array();
$GLOBALS['ssa_advisories'][0]['source'][0]['name'] = 'Changed upstream';
$changed = ProviderChecks::run( 4, array( 'cursor' => $first['cursor'] ) );
if ( 'unknown' !== $changed['status'] || empty( $changed['has_unknown'] ) ) {
	throw new RuntimeException( 'Changed feed must not resume an obsolete cursor.' );
}
$GLOBALS['ssa_cache']      = array();
$GLOBALS['ssa_advisories'] = new stdClass();
$malformed                 = ProviderChecks::run( 4, array() );
if ( 'unknown' !== $malformed['status'] ) {
	throw new RuntimeException( 'An empty JSON object must not be treated as a verified empty advisory list.' );
}
$GLOBALS['ssa_enabled'] = false;
$before                 = $GLOBALS['ssa_requests'];
$off                    = ProviderChecks::run( 4, array( 'cursor' => $first['cursor'] ) );
if ( 'unknown' !== $off['status'] || $before !== $GLOBALS['ssa_requests'] ) {
	throw new RuntimeException( 'Opt-out must prevent further requests during a paused lookup.' );
}
echo "advisory cursor: bounded retries, 150 unique findings, changed-feed and opt-out checks passed\n";
