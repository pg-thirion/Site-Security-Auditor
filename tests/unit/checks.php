<?php
// Run with: php tests/unit/checks.php
declare( strict_types=1 );

define( 'DAY_IN_SECONDS', 86400 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'ABSPATH', dirname( __DIR__, 2 ) . DIRECTORY_SEPARATOR );
$fixture_mode = $argv[1] ?? '';
if ( 'debug' === $fixture_mode ) {
	define( 'WP_DEBUG', true );
	define( 'WP_DEBUG_DISPLAY', true );
	define( 'DISALLOW_FILE_EDIT', false ); }
if ( 'secure' === $fixture_mode ) {
	define( 'WP_DEBUG', false );
	define( 'WP_DEBUG_DISPLAY', false );
	define( 'DISALLOW_FILE_EDIT', true );
define( 'DISALLOW_UNFILTERED_HTML', true ); }
if ( 'mods' === $fixture_mode ) {
	define( 'DISALLOW_FILE_MODS', true );
	define( 'DISALLOW_FILE_EDIT', false ); }
class WP_Error {
	public function __construct( public string $code = '' ) {}
}
class FixtureTheme {
	public function __construct( private string $name, private string $version, private string $stylesheet = '', private string $template = '', private string $update_uri = '' ) {} public function get( $key ) {
		return 'Name' === $key ? $this->name : ( 'Version' === $key ? $this->version : ( 'UpdateURI' === $key ? $this->update_uri : '' ) );
	} public function get_stylesheet() {
		return $this->stylesheet;
	} public function get_template() {
		return $this->template; }
}
function is_wp_error( $v ): bool {
	return $v instanceof WP_Error; }
function get_option( $key, $default = false ) {
	return $GLOBALS['ssa_options'][ $key ] ?? $default; }
function get_transient( $key ) {
	return $GLOBALS['ssa_cache'][ $key ] ?? false; }
function set_transient( $key, $value, $ttl ) {
	$GLOBALS['ssa_cache'][ $key ] = $value;
	return true; }
function wp_safe_remote_get( $url, $args ) {
	if ( 'Site Security Auditor' !== ( $args['user-agent'] ?? '' ) ) {
		throw new RuntimeException( 'Provider requests must use a neutral User-Agent.' );
	}
	++$GLOBALS['ssa_http_calls'];
	if ( ! empty( $GLOBALS['ssa_http_error'] ) ) {
		return new WP_Error( 'mock_timeout' );
	} $body = $GLOBALS['ssa_http_body'] ?? file_get_contents( dirname( __DIR__, 2 ) . '/provider-responses/wpvulnerability-plugin.json' );
	if ( ! isset( $GLOBALS['ssa_http_body'] ) && preg_match( '~/(?:plugin|theme)/([^/]+)/$~', $url, $m ) ) {
		$data                  = json_decode( $body, true );
		$kind                  = str_contains( $url, '/theme/' ) ? 'theme' : 'plugin';
		$data['data'][ $kind ] = $m[1];
		$body                  = json_encode( $data );
	} return array(
		'code' => $GLOBALS['ssa_http_code'] ?? 200,
		'body' => $body,
	); }
function wp_remote_retrieve_response_code( $r ) {
	return $r['code']; }
function wp_remote_retrieve_body( $r ) {
	return $r['body']; }
function wp_json_encode( $data, $flags = 0, $depth = 512 ) {
	return json_encode( $data, $flags, $depth ); }
function wp_strip_all_tags( $text ) {
	return strip_tags( $text ); }
function wp_parse_url( $url, $component = -1 ) {
	return parse_url( $url, $component ); }
function get_plugins() {
	return $GLOBALS['ssa_plugins'] ?? array(
		'fixture-plugin/main.php' => array(
			'Version'   => '1.2.3',
			'Name'      => 'Fixture Plugin',
			'PluginURI' => 'https://wordpress.org/plugins/fixture-plugin/',
		),
	); }
function get_bloginfo( $key ) {
	return $GLOBALS['ssa_wp_version'] ?? '6.8.3'; }
function get_locale() {
	return 'en_US'; }
function get_site_transient( $key ) {
	return $GLOBALS['ssa_transients'][ $key ] ?? false; }
function home_url() {
	return $GLOBALS['ssa_urls'][0] ?? 'https://example.test'; }
function site_url() {
	return $GLOBALS['ssa_urls'][1] ?? 'https://example.test'; }
function force_ssl_admin() {
	return $GLOBALS['ssa_force_ssl'] ?? true; }
function get_role( $role ) {
	if ( 'missing' === $role ) {
		return null;
	} return (object) array( 'capabilities' => $GLOBALS['ssa_role_caps'] ?? array() ); }
function wp_get_themes() {
	return $GLOBALS['ssa_themes'] ?? array(); }
function wp_get_theme() {
	return new FixtureTheme( 'Child', '1.0', 'child-theme', 'parent-theme' ); }

require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Providers/WPVulnerabilityProvider.php';
require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Providers/ChecksumProvider.php';
require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Audit/Checks/LocalChecks.php';
require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Audit/Checks/ProviderChecks.php';
require dirname( __DIR__, 2 ) . '/site-security-auditor/includes/Audit/AuditRegistry.php';

use SiteSecurityAuditor\Audit\AuditRegistry;
use SiteSecurityAuditor\Audit\Checks\ProviderChecks;

function check( bool $condition, string $message ): void {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	} }
$ids = AuditRegistry::ids();
check( count( $ids ) === 16 && $ids[0] === 'SSA-001' && end( $ids ) === 'SSA-016', 'registry IDs must be stable and complete' );
$GLOBALS['ssa_options']    = array(
	'ssa_settings' => array(
		'vulnerability_intelligence' => false,
		'core_integrity'             => false,
	),
);
$GLOBALS['ssa_cache']      = array();
$GLOBALS['ssa_http_calls'] = 0;
$off                       = AuditRegistry::run( 'SSA-005' );
check( $off['status'] === 'unknown' && $GLOBALS['ssa_http_calls'] === 0, 'disabled provider must be unknown without a request' );
check( AuditRegistry::run( 'SSA-012' )['status'] === 'unknown' && $GLOBALS['ssa_http_calls'] === 0, 'disabled checksum provider must be unknown without a request' );
$GLOBALS['ssa_options']['ssa_settings']['vulnerability_intelligence'] = 'yes';
check( AuditRegistry::run( 'SSA-005' )['status'] === 'unknown' && $GLOBALS['ssa_http_calls'] === 0, 'truthy non-boolean setting must not count as consent' );
$GLOBALS['ssa_options']['ssa_settings']['vulnerability_intelligence'] = false;

$affected = new ReflectionMethod( ProviderChecks::class, 'affected' );
$affected->setAccessible( true );
$range = array(
	'min_version'  => null,
	'min_operator' => null,
	'max_version'  => '2.0.0',
	'max_operator' => 'lt',
);
check( $affected->invoke( null, '1.9.9', $range ), 'version below exclusive fixed version must match' );
check( ! $affected->invoke( null, '2.0.0', $range ), 'exclusive fixed version must not match' );
check( ! $affected->invoke( null, 'bad-version', $range ), 'invalid version must not match' );
$eol = SiteSecurityAuditor\Audit\Checks\LocalChecks::run(
	14,
	array(
		'php_version' => '8.2.99',
		'today'       => '2026-12-31',
	)
);
check( $eol['status'] === 'pass', 'PHP security support includes its published end date' );
$eol = SiteSecurityAuditor\Audit\Checks\LocalChecks::run(
	14,
	array(
		'php_version' => '8.2.99',
		'today'       => '2027-01-01',
	)
);
check( $eol['status'] === 'fail', 'PHP branch must be reported EOL after its end date' );

$GLOBALS['ssa_options']['ssa_settings']['vulnerability_intelligence'] = true;
$identity_now                                = time();
$GLOBALS['ssa_transients']['update_plugins'] = (object) array(
	'last_checked' => $identity_now,
	'checked'      => array( 'fixture-plugin/main.php' => '1.2.3' ),
	'response'     => array(),
	'no_update'    => array( 'fixture-plugin/main.php' => (object) array( 'slug' => 'fixture-plugin' ) ),
);
$GLOBALS['ssa_cache']                        = array();
$result                                      = AuditRegistry::run( 'SSA-005' );
check( $result['status'] === 'fail' && $result['affected_count'] === 1 && $result['findings'][0]['check_id'] === 'SSA-005', 'matching provider advisory must produce a check finding' );
check( $result['findings'][0]['references'][0] === 'https://www.cve.org/CVERecord?id=CVE-2025-12345', 'only allowlisted HTTPS advisory reference may be returned' );
check( $result['findings'][0]['advisory_id'] === 'CVE-2025-12345' && $result['findings'][0]['affected_range'] === 'lt 2.0.0', 'advisory identity and affected range must be preserved' );
check( ! array_filter( $result, static fn( $v ) => is_string( $v ) && str_contains( $v, ABSPATH ) ), 'results must not expose absolute paths' );
$GLOBALS['ssa_plugins'] = array(
	'fixture-plugin/main.php' => array(
		'Version'   => '1.2.3',
		'Name'      => 'Custom update plugin',
		'UpdateURI' => 'https://vendor.example/plugin',
	),
);
$GLOBALS['ssa_cache']   = array();
$before_custom_update   = $GLOBALS['ssa_http_calls'];
$custom_update          = AuditRegistry::run( 'SSA-005' );
check( $custom_update['status'] === 'unknown' && $GLOBALS['ssa_http_calls'] === $before_custom_update, 'custom plugin UpdateURI must override matching repository metadata without HTTP' );
$GLOBALS['ssa_plugins'] = array(
	'custom-plugin/main.php' => array(
		'Version'   => '1.2.3',
		'Name'      => 'Custom',
		'PluginURI' => 'https://wordpress.org/plugins/custom-plugin/',
	),
);
$GLOBALS['ssa_cache']   = array();
$before_unverified      = $GLOBALS['ssa_http_calls'];
$unverified             = AuditRegistry::run( 'SSA-005' );
check( $unverified['status'] === 'unknown' && $GLOBALS['ssa_http_calls'] === $before_unverified, 'unverified plugin slug must not trigger provider lookup' );
$GLOBALS['ssa_plugins']                                    = null;
$GLOBALS['ssa_transients']['update_plugins']->last_checked = $identity_now - DAY_IN_SECONDS - 1;
$stale_slug = AuditRegistry::run( 'SSA-005' );
check( $stale_slug['status'] === 'unknown' && $GLOBALS['ssa_http_calls'] === $before_unverified, 'stale native update transient must not verify plugin slug' );
$GLOBALS['ssa_transients']['update_plugins']->last_checked = time();
$GLOBALS['ssa_themes']                                     = array( 'repo-theme' => new FixtureTheme( 'Repo Theme', '1.2.3' ) );
$GLOBALS['ssa_transients']['update_themes']                = (object) array(
	'last_checked' => time(),
	'checked'      => array( 'repo-theme' => '1.2.3' ),
	'response'     => array(),
	'no_update'    => array( 'repo-theme' => (object) array() ),
);
$GLOBALS['ssa_cache']                                      = array();
$theme_identity = AuditRegistry::run( 'SSA-006' );
check( $theme_identity['status'] === 'fail' && $theme_identity['affected_count'] === 1, 'fresh core-managed theme update metadata should verify its stylesheet slug' );
$GLOBALS['ssa_themes'] = array( 'repo-theme' => new FixtureTheme( 'Custom Theme', '1.2.3', '', '', 'https://vendor.example/theme' ) );
$GLOBALS['ssa_cache']  = array();
$before_custom_update  = $GLOBALS['ssa_http_calls'];
$custom_update         = AuditRegistry::run( 'SSA-006' );
check( $custom_update['status'] === 'unknown' && $GLOBALS['ssa_http_calls'] === $before_custom_update, 'custom theme UpdateURI must override matching repository metadata without HTTP' );
$GLOBALS['ssa_themes'] = array();
$before_unverified     = $GLOBALS['ssa_http_calls'];
$GLOBALS['ssa_transients']['update_plugins']->last_checked = $identity_now - DAY_IN_SECONDS - 1;
$stale_identity = AuditRegistry::run( 'SSA-005' );
check( $stale_identity['status'] === 'unknown' && $GLOBALS['ssa_http_calls'] === $before_unverified, 'stale update metadata and fabricated PluginURI must not verify a plugin slug' );
$GLOBALS['ssa_plugins'] = array();
$batch_checked          = array();
$batch_no_update        = array();
for ( $i = 1; $i <= 6; ++$i ) {
	$GLOBALS['ssa_plugins'][ 'batch-' . $i . '/main.php' ] = array(
		'Version'   => '1.2.3',
		'Name'      => 'Batch plugin',
		'PluginURI' => 'https://wordpress.org/plugins/batch-' . $i . '/',
	);
	$batch_checked[ 'batch-' . $i . '/main.php' ]          = '1.2.3';
	$batch_no_update[ 'batch-' . $i . '/main.php' ]        = (object) array( 'slug' => 'batch-' . $i );
}
$GLOBALS['ssa_transients']['update_plugins'] = (object) array(
	'last_checked' => time(),
	'checked'      => $batch_checked,
	'response'     => array(),
	'no_update'    => $batch_no_update,
);
$GLOBALS['ssa_cache']                        = array();
$GLOBALS['ssa_http_body']                    = null;
$GLOBALS['ssa_http_code']                    = 200;
$before_batch                                = $GLOBALS['ssa_http_calls'];
$batch                                       = AuditRegistry::run( 'SSA-005' );
check( $batch['cursor']['offset'] === 5 && $GLOBALS['ssa_http_calls'] === $before_batch + 5, 'vulnerability batch must stop at five requests' );
$batch = AuditRegistry::run( 'SSA-005', array( 'cursor' => $batch['cursor'] ) );
check( ! isset( $batch['cursor'] ) && $batch['affected_count'] === 6 && $GLOBALS['ssa_http_calls'] === $before_batch + 6, 'vulnerability cursor must resume remaining component' );
$GLOBALS['ssa_cache']                           = array();
$first_batch                                    = AuditRegistry::run( 'SSA-005' );
$GLOBALS['ssa_plugins']['late-plugin/main.php'] = array(
	'Version'   => '1.0.0',
	'Name'      => 'Late',
	'PluginURI' => 'https://wordpress.org/plugins/late-plugin/',
);
$changed_inventory                              = AuditRegistry::run( 'SSA-005', array( 'cursor' => $first_batch['cursor'] ) );
check( $changed_inventory['status'] === 'unknown' && $changed_inventory['has_unknown'], 'changed component inventory must not resume against stale cursor' );
$GLOBALS['ssa_plugins']                                   = null;
$GLOBALS['ssa_transients']['update_plugins']              = (object) array(
	'last_checked' => time(),
	'checked'      => array( 'fixture-plugin/main.php' => '1.2.3' ),
	'response'     => array(),
	'no_update'    => array( 'fixture-plugin/main.php' => (object) array( 'slug' => 'fixture-plugin' ) ),
);
$GLOBALS['ssa_options']['ssa_settings']['core_integrity'] = true;
$core_file                = dirname( __DIR__, 2 ) . '/provider-responses/core-file.txt';
$GLOBALS['ssa_http_body'] = json_encode( array( 'checksums' => array( 'provider-responses/core-file.txt' => md5_file( $core_file ) ) ) );
$GLOBALS['ssa_cache']     = array();
$integrity                = AuditRegistry::run( 'SSA-012' );
check( $integrity['status'] === 'pass' && $integrity['findings'] === array(), 'matching official checksum must pass' );
$GLOBALS['ssa_http_body'] = json_encode( array( 'checksums' => array( '../SPEC.md' => md5_file( dirname( __DIR__, 2 ) . '/SPEC.md' ) ) ) );
$GLOBALS['ssa_cache']     = array();
$integrity                = AuditRegistry::run( 'SSA-012' );
check( $integrity['status'] === 'unknown' && $integrity['has_unknown'], 'traversal checksum path must be unknown' );
$checksums = array(); for ( $i = 0; $i < 251; ++$i ) {
	$checksums[ sprintf( 'missing-%03d.php', $i ) ] = str_repeat( 'a', 32 );
}
$GLOBALS['ssa_http_body'] = json_encode( array( 'checksums' => $checksums ) );
$GLOBALS['ssa_cache']     = array();
$hash_batch               = AuditRegistry::run( 'SSA-012' );
check( $hash_batch['cursor']['offset'] === 250 && count( $hash_batch['findings'] ) === 250, 'checksum batch must hash at most 250 files' );
$hash_batch = AuditRegistry::run( 'SSA-012', array( 'cursor' => $hash_batch['cursor'] ) );
check( ! isset( $hash_batch['cursor'] ) && $hash_batch['affected_count'] === 251, 'checksum cursor must finish remaining file' );
$GLOBALS['ssa_cache']     = array();
$hash_batch               = AuditRegistry::run( 'SSA-012' );
$GLOBALS['ssa_http_body'] = json_encode( array( 'checksums' => array( 'provider-responses/core-file.txt' => md5_file( $core_file ) ) ) );
$GLOBALS['ssa_cache']     = array();
$changed_checksums        = AuditRegistry::run( 'SSA-012', array( 'cursor' => $hash_batch['cursor'] ) );
check( $changed_checksums['status'] === 'unknown' && $changed_checksums['has_unknown'], 'changed checksum inventory must not resume against stale cursor' );

$GLOBALS['ssa_http_body']                                 = file_get_contents( dirname( __DIR__, 2 ) . '/provider-responses/wpvulnerability-malformed.json' );
$GLOBALS['ssa_options']['ssa_settings']['core_integrity'] = false;
$GLOBALS['ssa_cache']                                     = array();
$before_bad = $GLOBALS['ssa_http_calls'];
$malformed  = AuditRegistry::run( 'SSA-005' );
check( $malformed['status'] === 'unknown', 'malformed provider envelope must not pass: ' . $malformed['status'] . ' / ' . $malformed['reason'] . ' / calls=' . ( $GLOBALS['ssa_http_calls'] - $before_bad ) );
$GLOBALS['ssa_http_body']  = null;
$GLOBALS['ssa_http_code']  = 429;
$GLOBALS['ssa_http_error'] = false;
$GLOBALS['ssa_cache']      = array();
$before_429                = $GLOBALS['ssa_http_calls'];
check( AuditRegistry::run( 'SSA-005' )['status'] === 'unknown', 'provider rate limit must remain unknown' );
$after_429 = $GLOBALS['ssa_http_calls'];
check( AuditRegistry::run( 'SSA-005' )['status'] === 'unknown' && $GLOBALS['ssa_http_calls'] === $after_429 && $after_429 === $before_429 + 1, 'negative cache must back off repeated provider errors' );
$GLOBALS['ssa_http_code']  = 200;
$GLOBALS['ssa_http_error'] = true;
$GLOBALS['ssa_cache']      = array();
check( AuditRegistry::run( 'SSA-005' )['status'] === 'unknown', 'provider timeout must remain unknown' );
$GLOBALS['ssa_http_error'] = false;
$GLOBALS['ssa_http_code']  = 200;
$GLOBALS['ssa_http_body']  = file_get_contents( dirname( __DIR__, 2 ) . '/provider-responses/wpvulnerability-invalid-range.json' );
$GLOBALS['ssa_cache']      = array();
$invalid_range             = AuditRegistry::run( 'SSA-005' );
check( $invalid_range['status'] === 'unknown' && $invalid_range['has_unknown'], 'unsupported provider version operator must remain unknown' );
$hostile_fixture = json_decode( $GLOBALS['ssa_http_body'], true );
$hostile_fixture['data']['vulnerability'][0]['operator']['max_operator'] = 'lt';
$GLOBALS['ssa_http_body'] = json_encode( $hostile_fixture );
$GLOBALS['ssa_cache']     = array();
$hostile                  = AuditRegistry::run( 'SSA-005' );
check( $hostile['status'] === 'fail' && ! str_contains( $hostile['findings'][0]['title'], '<script>' ), 'hostile advisory HTML must be removed from finding title' );

$now                                      = time();
$GLOBALS['ssa_transients']['update_core'] = false;
check( AuditRegistry::run( 'SSA-001' )['status'] === 'unknown', 'missing core update state must be unknown' );
$GLOBALS['ssa_transients']['update_core'] = (object) array(
	'last_checked' => $now,
	'version_checked' => get_bloginfo( 'version' ),
	'updates'      => array(
		(object) array(
			'response' => 'upgrade',
			'current'  => '6.9.0',
		),
	),
);
$core_update = AuditRegistry::run( 'SSA-001' );
check( $core_update['status'] === 'fail' && $core_update['findings'][0]['component_key'] === 'wordpress-core' && $core_update['findings'][0]['component_type'] === 'core' && $core_update['findings'][0]['component_name'] === 'WordPress' && $core_update['findings'][0]['component_version'] === '6.8.3' && str_contains( $core_update['findings'][0]['evidence'], '6.9.0' ), 'core update finding must identify installed version and offered version in evidence' );
$GLOBALS['ssa_transients']['update_core']->updates[0]->response = 'latest';
$GLOBALS['ssa_transients']['update_core']->version_checked = '6.8.2';
check( AuditRegistry::run( 'SSA-001' )['status'] === 'unknown', 'core version_checked mismatch must be unknown' );
$GLOBALS['ssa_transients']['update_core']->version_checked = get_bloginfo( 'version' );
check( AuditRegistry::run( 'SSA-001' )['status'] === 'pass', 'current core with complete update state must pass' );
$GLOBALS['ssa_transients']['update_core']->last_checked = $now - DAY_IN_SECONDS - 1;
check( AuditRegistry::run( 'SSA-001' )['status'] === 'unknown', 'stale core update state must be unknown' );

$plugin_file                                 = 'fixture-plugin/main.php';
$GLOBALS['ssa_transients']['update_plugins'] = (object) array(
	'last_checked' => $now,
	'checked' => array( 'fixture-plugin/main.php' => '1.2.3' ),
	'response'     => array( $plugin_file => (object) array( 'new_version' => '2.0.0' ) ),
	'no_update'    => array(),
);
$plugin_update                               = AuditRegistry::run( 'SSA-002' );
check( $plugin_update['status'] === 'fail' && $plugin_update['findings'][0]['component_key'] === 'fixture-plugin' && $plugin_update['findings'][0]['component_type'] === 'plugin' && $plugin_update['findings'][0]['component_name'] === 'Fixture Plugin' && $plugin_update['findings'][0]['component_version'] === '1.2.3' && str_contains( $plugin_update['findings'][0]['evidence'], '2.0.0' ), 'plugin update finding must identify installed component version and offered version in evidence' );
$GLOBALS['ssa_transients']['update_plugins']->response  = array();
$GLOBALS['ssa_transients']['update_plugins']->no_update = array( $plugin_file => array() );
check( AuditRegistry::run( 'SSA-002' )['status'] === 'pass', 'plugin in complete no-update map must pass' );
$GLOBALS['ssa_transients']['update_plugins']->checked[ $plugin_file ] = '0.9.0';
check( AuditRegistry::run( 'SSA-002' )['status'] === 'unknown', 'plugin checked version mismatch must be unknown' );
$GLOBALS['ssa_transients']['update_plugins']->checked[ $plugin_file ] = '1.2.3';
$GLOBALS['ssa_transients']['update_plugins']->no_update = array();
check( AuditRegistry::run( 'SSA-002' )['status'] === 'unknown', 'plugin missing from core update maps must be unknown' );

$GLOBALS['ssa_themes']                      = array(
	'child-theme'  => new FixtureTheme( 'Child', '1.0' ),
	'parent-theme' => new FixtureTheme( 'Parent', '1.0' ),
	'unused-theme' => new FixtureTheme( 'Unused', '1.0' ),
);
$GLOBALS['ssa_transients']['update_themes'] = (object) array(
	'last_checked' => $now,
	'checked' => array( 'child-theme' => '1.0', 'parent-theme' => '1.0', 'unused-theme' => '1.0' ),
	'response'     => array( 'unused-theme' => (object) array( 'new_version' => '2.0' ) ),
	'no_update'    => array(
		'child-theme'  => array(),
		'parent-theme' => array(),
	),
);
$theme_update                               = AuditRegistry::run( 'SSA-003' );
check( $theme_update['status'] === 'fail' && $theme_update['findings'][0]['component_key'] === 'unused-theme' && $theme_update['findings'][0]['component_type'] === 'theme' && $theme_update['findings'][0]['component_name'] === 'Unused' && $theme_update['findings'][0]['component_version'] === '1.0' && str_contains( $theme_update['findings'][0]['evidence'], '2.0' ), 'theme update finding must identify installed component version and offered version in evidence' );
$GLOBALS['ssa_transients']['update_themes']->response  = array();
$GLOBALS['ssa_transients']['update_themes']->no_update = array(
	'child-theme'  => array(),
	'parent-theme' => array(),
	'unused-theme' => array(),
);
check( AuditRegistry::run( 'SSA-003' )['status'] === 'pass', 'complete theme update map must pass' );
$GLOBALS['ssa_transients']['update_themes']->checked['unused-theme'] = '0.9.0';
check( AuditRegistry::run( 'SSA-003' )['status'] === 'unknown', 'theme checked version mismatch must be unknown' );
$GLOBALS['ssa_transients']['update_themes']->checked['unused-theme'] = '1.0';
$GLOBALS['ssa_themes']['late-theme'] = new FixtureTheme( 'Late', '1.0' );
check( AuditRegistry::run( 'SSA-003' )['status'] === 'unknown', 'theme installed after update check must be unknown' );

$GLOBALS['ssa_urls'] = array( 'https://example.test', 'https://example.test/wp' );
check( AuditRegistry::run( 'SSA-007' )['status'] === 'pass', 'HTTPS home and site URLs must pass' );
$GLOBALS['ssa_urls'][1] = 'http://example.test/wp';
check( AuditRegistry::run( 'SSA-007' )['status'] === 'fail', 'HTTP configured site URL must fail' );
$GLOBALS['ssa_urls'] = array( 'not a URL', 'https://example.test' );
check( AuditRegistry::run( 'SSA-007' )['status'] === 'unknown', 'unreadable URL scheme must be unknown' );
$GLOBALS['ssa_force_ssl'] = false;
check( AuditRegistry::run( 'SSA-008' )['status'] === 'fail', 'disabled admin SSL hardening must fail' );
$GLOBALS['ssa_force_ssl'] = true;
check( AuditRegistry::run( 'SSA-008' )['status'] === 'pass', 'enabled admin SSL hardening must pass' );
$debug = AuditRegistry::run( 'SSA-009' );
check( 'debug' === $fixture_mode ? $debug['status'] === 'fail' : ( 'secure' === $fixture_mode ? $debug['status'] === 'pass' : $debug['status'] === 'unknown' ), 'debug output state must reflect defined constants' );
$editor = AuditRegistry::run( 'SSA-010' );
check( in_array( $fixture_mode, array( 'secure', 'mods' ), true ) ? $editor['status'] === 'pass' : $editor['status'] === 'fail', 'file editor hardening must respect both file modification constants' );
$GLOBALS['ssa_options']['users_can_register'] = true;
$GLOBALS['ssa_options']['default_role']       = 'subscriber';
$GLOBALS['ssa_role_caps']                     = array( 'read' => true );
check( AuditRegistry::run( 'SSA-011' )['status'] === 'pass', 'public registration with low-privilege default role must pass' );
$GLOBALS['ssa_role_caps'] = array( 'unfiltered_html' => true );
check( AuditRegistry::run( 'SSA-011' )['status'] === ( defined( 'DISALLOW_UNFILTERED_HTML' ) ? 'pass' : 'fail' ), 'registration unfiltered_html must use effective capability' );
$GLOBALS['ssa_role_caps'] = array( 'manage_options' => true );
check( AuditRegistry::run( 'SSA-011' )['status'] === 'fail', 'public registration with privileged default role must fail' );
foreach ( array( 'create_users', 'delete_users', 'remove_users', 'delete_plugins', 'update_plugins', 'edit_themes', 'delete_themes', 'update_themes', 'update_core' ) as $capability ) {
	$GLOBALS['ssa_role_caps'] = array( $capability => true );
	$registration = AuditRegistry::run( 'SSA-011' );
	check( 'fail' === $registration['status'] && 'critical' === $registration['findings'][0]['severity'], 'public registration granting ' . $capability . ' must fail critically' );
	$GLOBALS['ssa_role_caps'] = array( $capability => false );
	check( 'pass' === AuditRegistry::run( 'SSA-011' )['status'], 'denied role capability ' . $capability . ' must not be reported as granted' );
}
$GLOBALS['ssa_options']['default_role'] = 'missing';
check( AuditRegistry::run( 'SSA-011' )['status'] === 'unknown', 'unresolvable default role must be unknown' );
check( AuditRegistry::run( 'SSA-013' )['status'] === 'unknown', 'Windows ACL permissions must remain unknown' );
check( AuditRegistry::run( 'SSA-015' )['findings'][0]['component_key'] === 'fixture-plugin', 'inactive plugin inventory must use safe component identity' );
$inactive_themes = AuditRegistry::run( 'SSA-016' );
check( $inactive_themes['status'] === 'pass' && $inactive_themes['findings'][0]['status'] === 'pass', 'informational theme inventory must not be reported as a failed check or actionable failure' );
$inactive_plugins = AuditRegistry::run( 'SSA-015' );
check( $inactive_plugins['status'] === 'pass' && $inactive_plugins['findings'][0]['status'] === 'pass', 'informational plugin inventory must not be reported as failure' );
$inactive_theme_keys = array_column( $inactive_themes['findings'], 'component_key' );
check( in_array( 'unused-theme', $inactive_theme_keys, true ) && ! in_array( 'parent-theme', $inactive_theme_keys, true ) && ! in_array( 'child-theme', $inactive_theme_keys, true ), 'active child theme and its parent must not be reported as unused' );
$GLOBALS['ssa_wp_version'] = '6.6.2';
$GLOBALS['ssa_options']['ssa_settings']['vulnerability_intelligence'] = true;
$GLOBALS['ssa_cache']     = array();
$GLOBALS['ssa_http_body'] = file_get_contents( dirname( __DIR__, 2 ) . '/provider-responses/wpvulnerability-core-6.6.2.json' );
$core_advisories          = AuditRegistry::run( 'SSA-004' );
check( $core_advisories['status'] === 'fail' && $core_advisories['affected_count'] === 21, 'authentic version-scoped core feed without operator fields must produce confirmed advisories' );
check( $core_advisories['findings'][0]['affected_range'] === 'Exact queried WordPress core version 6.6.2' && str_contains( $core_advisories['findings'][0]['matching_rationale'], 'exact-version' ), 'core advisory must explain exact endpoint membership as its match proof' );
check( in_array( $core_advisories['findings'][0]['severity'], array( 'critical', 'high', 'medium', 'low', 'unrated' ), true ), 'core advisory severity must use full nested CVSS3 label or unrated' );
$core_contract            = json_decode( $GLOBALS['ssa_http_body'], true );
$core_contract['error']   = 'nonsense';
$GLOBALS['ssa_http_body'] = wp_json_encode( $core_contract );
$GLOBALS['ssa_cache']     = array();
check( AuditRegistry::run( 'SSA-004' )['status'] === 'unknown', 'non-integer provider error must remain unknown' );
$core_contract['error']   = 0;
$core_contract['updated'] = 'not-a-timestamp';
$GLOBALS['ssa_http_body'] = wp_json_encode( $core_contract );
$GLOBALS['ssa_cache']     = array();
check( AuditRegistry::run( 'SSA-004' )['status'] === 'unknown', 'malformed provider timestamp must remain unknown' );

$GLOBALS['ssa_plugins'] = array();
for ( $index = 0; $index < 101; ++$index ) {
	$file                           = sprintf( 'fixture-plugin-%03d/main.php', $index );
	$GLOBALS['ssa_plugins'][ $file ] = array( 'Version' => '1.0', 'Name' => $file );
}
$GLOBALS['ssa_options']['active_plugins'] = array();
$plugin_batch                             = AuditRegistry::run( 'SSA-015' );
$plugin_complete                          = AuditRegistry::run( 'SSA-015', array( 'cursor' => $plugin_batch['cursor'] ) );
check( 'pass' === $plugin_complete['status'] && ! isset( $plugin_complete['cursor'] ), 'unchanged plugin inventory must resume and complete' );
unset( $GLOBALS['ssa_plugins']['fixture-plugin-000/main.php'] );
$plugin_resume = AuditRegistry::run( 'SSA-015', array( 'cursor' => $plugin_batch['cursor'] ) );
check( 'unknown' === $plugin_resume['status'] && null === ( $plugin_resume['cursor'] ?? null ), 'plugin inventory changes between batches must stop as unknown' );

$GLOBALS['ssa_themes'] = array();
for ( $index = 0; $index < 101; ++$index ) {
	$slug                          = sprintf( 'fixture-theme-%03d', $index );
	$GLOBALS['ssa_themes'][ $slug ] = new FixtureTheme( $slug, '1.0' );
}
$theme_batch = AuditRegistry::run( 'SSA-016' );
$theme_complete = AuditRegistry::run( 'SSA-016', array( 'cursor' => $theme_batch['cursor'] ) );
check( 'pass' === $theme_complete['status'] && ! isset( $theme_complete['cursor'] ), 'unchanged theme inventory must resume and complete' );
unset( $GLOBALS['ssa_themes']['fixture-theme-000'] );
$theme_resume = AuditRegistry::run( 'SSA-016', array( 'cursor' => $theme_batch['cursor'] ) );
check( 'unknown' === $theme_resume['status'] && null === ( $theme_resume['cursor'] ?? null ), 'theme inventory changes between batches must stop as unknown' );

echo "checks: all assertions passed\n";
