<?php
/** Standalone provider validation regressions: php tests/unit/provider-validation.php */
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );

class WP_Error {
	public function __construct( public string $code = '' ) {}
}

function is_wp_error( $value ) {
	return $value instanceof WP_Error;
}
function get_option( $key, $default = false ) {
	return 'ssa_settings' === $key ? array( 'core_integrity' => true, 'vulnerability_intelligence' => true ) : $default;
}
function get_transient( $key ) {
	return $GLOBALS['ssa_provider_cache'][ $key ] ?? false;
}
function set_transient( $key, $value, $ttl ) {
	$GLOBALS['ssa_provider_cache'][ $key ] = $value;
}
function get_site_transient( $key ) {
	return $GLOBALS['ssa_provider_updates'] ?? false;
}
function get_plugins() {
	return $GLOBALS['ssa_plugins'] ?? array();
}
function wp_safe_remote_get( $url, $args ) {
	return array( 'body' => $GLOBALS['ssa_provider_body'] );
}
function wp_remote_retrieve_response_code( $response ) {
	return 200;
}
function wp_remote_retrieve_body( $response ) {
	return $response['body'];
}
function wp_json_encode( $value ) {
	return json_encode( $value );
}
function get_bloginfo( $key ) {
	return '6.6';
}
function get_locale() {
	return 'en_US';
}
function wp_parse_url( $url ) {
	return parse_url( $url );
}

require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Providers/ChecksumProvider.php';
require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Providers/WPVulnerabilityProvider.php';
require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Audit/Checks/ProviderChecks.php';

$ssa_test_root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ssa-provider-validation-' . bin2hex( random_bytes( 6 ) );
if ( ! mkdir( $ssa_test_root, 0700 ) || ! mkdir( $ssa_test_root . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins', 0700, true ) ) {
	throw new RuntimeException( 'Could not create provider validation fixture.' );
}
define( 'ABSPATH', $ssa_test_root . DIRECTORY_SEPARATOR );
$ssa_config_path = ABSPATH . 'wp-config.php';
$ssa_plugin_path = ABSPATH . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins' . DIRECTORY_SEPARATOR . 'fixture.php';
file_put_contents( $ssa_config_path, 'test config' );
file_put_contents( $ssa_plugin_path, 'test plugin' );
register_shutdown_function(
	static function () use ( $ssa_config_path, $ssa_plugin_path, $ssa_test_root ): void {
		@unlink( $ssa_config_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Best-effort cleanup of this test's private fixture.
		@unlink( $ssa_plugin_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Best-effort cleanup of this test's private fixture.
		@rmdir( dirname( $ssa_plugin_path ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Best-effort cleanup of this test's private fixture.
		@rmdir( dirname( dirname( $ssa_plugin_path ) ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Best-effort cleanup of this test's private fixture.
		@rmdir( $ssa_test_root ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Best-effort cleanup of this test's private fixture.
	}
);

$affected = new ReflectionMethod( SiteSecurityAuditor\Audit\Checks\ProviderChecks::class, 'affected' );
$affected->setAccessible( true );
if ( null !== $affected->invoke( null, '1.0', array( 'min_version' => '5.0', 'min_operator' => 'ge', 'max_version' => '2.0', 'max_operator' => 'le' ) ) ) {
	throw new RuntimeException( 'An inverted provider range must be unknown even when installed version misses its minimum.' );
}

if ( null !== $affected->invoke( null, '1.0', array( 'min_version' => '2.0', 'min_operator' => 'ge', 'max_version' => '2.0', 'max_operator' => 'lt' ) ) || null !== $affected->invoke( null, '3.0', array( 'min_version' => '2.0', 'min_operator' => 'gt', 'max_version' => '2.0', 'max_operator' => 'le' ) ) ) {
	throw new RuntimeException( 'Contradictory equal-bound provider ranges must be unknown before installed-version comparison.' );
}
if ( true !== $affected->invoke( null, '2.0', array( 'min_version' => '2.0', 'min_operator' => 'ge', 'max_version' => '2.0', 'max_operator' => 'le' ) ) || true !== $affected->invoke( null, '2.5', array( 'min_version' => '2.0', 'min_operator' => 'ge', 'max_version' => '3.0', 'max_operator' => 'lt' ) ) ) {
	throw new RuntimeException( 'Valid closed and bounded provider intervals must remain usable.' );
}

$GLOBALS['ssa_provider_cache']   = array();
$GLOBALS['ssa_plugins']          = array( 'fixture/fixture.php' => array( 'Version' => '1.0', 'Name' => 'Fixture' ) );
$GLOBALS['ssa_provider_updates'] = (object) array(
	'last_checked' => time(),
	'checked'      => array( 'fixture/fixture.php' => '1.0' ),
	'response'     => array(),
	'no_update'    => array( 'fixture/fixture.php' => (object) array( 'slug' => 'fixture' ) ),
);
$GLOBALS['ssa_provider_body'] = wp_json_encode(
	array(
		'error'   => 0,
		'updated' => time(),
		'data'    => array(
			'plugin'        => 'fixture',
			'vulnerability' => array(
				array(
					'uuid'     => str_repeat( 'a', 40 ),
					'name'     => 'Fixture advisory with an empty range',
					'operator' => array( 'min_version' => '2.0', 'min_operator' => 'ge', 'max_version' => '2.0', 'max_operator' => 'lt' ),
					'source'   => array( array( 'id' => 'CVE-2025-12345', 'link' => 'https://www.cve.org/CVERecord?id=CVE-2025-12345' ) ),
					'impact'   => array( 'cvss3' => array( 'severity' => 'high' ) ),
				),
			),
		),
	)
);
$impossible_range = SiteSecurityAuditor\Audit\Checks\ProviderChecks::run( 5, array() );
if ( 'unknown' !== $impossible_range['status'] || empty( $impossible_range['has_unknown'] ) || $impossible_range['findings'] ) {
	throw new RuntimeException( 'An impossible range from a valid provider response must remain unknown.' );
}

$GLOBALS['ssa_provider_cache'] = array();
$GLOBALS['ssa_provider_body']  = wp_json_encode( array( 'checksums' => array() ) );
$empty = SiteSecurityAuditor\Audit\Checks\ProviderChecks::run( 12, array() );
$GLOBALS['ssa_provider_cache'] = array();
$GLOBALS['ssa_provider_body']  = wp_json_encode( array( 'checksums' => array( 'missing-core-file.php' => 'invalid' ) ) );
$invalid = SiteSecurityAuditor\Audit\Checks\ProviderChecks::run( 12, array() );
if ( 'unknown' !== $empty['status'] || 'unknown' !== $invalid['status'] || $invalid['findings'] ) {
	throw new RuntimeException( 'Empty maps and invalid hashes for missing files must not produce a security finding.' );
}

$cache_key = 'ssa_checksums_' . md5( '6.6:en_US' );
foreach ( array( array(), array( 'missing-core-file.php' => 'invalid' ), array( 'missing-core-file.php' => md5( 'fixture' ) . "\n" ) ) as $checksums ) {
	$GLOBALS['ssa_provider_cache'] = array();
	$GLOBALS['ssa_provider_body'] = wp_json_encode( array( 'checksums' => $checksums ) );
	if ( ! is_wp_error( SiteSecurityAuditor\Providers\ChecksumProvider::checksums( '6.6', 'en_US' ) ) ) {
		throw new RuntimeException( 'Unusable network checksum data must be rejected.' );
	}
	$GLOBALS['ssa_provider_cache'] = array( $cache_key => $checksums );
	if ( ! is_wp_error( SiteSecurityAuditor\Providers\ChecksumProvider::checksums( '6.6', 'en_US' ) ) ) {
		throw new RuntimeException( 'Unusable cached checksum data must be rejected.' );
	}
}
$checksums = array( 'wp-includes/version.php' => md5( 'fixture' ) );
$GLOBALS['ssa_provider_cache'] = array();
$GLOBALS['ssa_provider_body'] = wp_json_encode( array( 'checksums' => $checksums ) );
if ( $checksums !== SiteSecurityAuditor\Providers\ChecksumProvider::checksums( '6.6', 'en_US' ) || $checksums !== SiteSecurityAuditor\Providers\ChecksumProvider::checksums( '6.6', 'en_US' ) ) {
	throw new RuntimeException( 'Valid network and cached checksum data must remain usable.' );
}
$protected_paths = array(
	'wp-config.php'                  => str_repeat( '0', 32 ),
	'wp-content/plugins/fixture.php' => str_repeat( '0', 32 ),
);
$GLOBALS['ssa_provider_cache'] = array();
$GLOBALS['ssa_provider_body']  = wp_json_encode( array( 'checksums' => $protected_paths ) );
$lowercase_paths               = SiteSecurityAuditor\Audit\Checks\ProviderChecks::run( 12, array() );
if ( 'unknown' !== $lowercase_paths['status'] || $lowercase_paths['findings'] ) {
	throw new RuntimeException( 'Lowercase wp-config.php and wp-content paths must be excluded on every platform.' );
}
if ( '\\' === DIRECTORY_SEPARATOR ) {
	$GLOBALS['ssa_provider_cache'] = array();
	$GLOBALS['ssa_provider_body']  = wp_json_encode(
		array(
			'checksums' => array(
				'WP-CONFIG.PHP'                 => str_repeat( '0', 32 ),
				'WP-CONTENT/PLUGINS/fixture.php' => str_repeat( '0', 32 ),
			),
		)
	);
	$uppercase_paths = SiteSecurityAuditor\Audit\Checks\ProviderChecks::run( 12, array() );
	if ( 'unknown' !== $uppercase_paths['status'] || $uppercase_paths['findings'] ) {
		throw new RuntimeException( 'Case variants of protected paths must be excluded on Windows.' );
	}
}
echo "provider validation: checksum maps, protected paths and ranges passed\n";
