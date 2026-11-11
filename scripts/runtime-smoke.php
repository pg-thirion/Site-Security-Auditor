<?php

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery -- This local-only smoke seeds and checks the plugin's private custom tables.

use SiteSecurityAuditor\Api\Routes;
use SiteSecurityAuditor\Plugin;
use SiteSecurityAuditor\Services\RetentionService;
use SiteSecurityAuditor\Support\SafeOutput;

if ( 'local' !== wp_get_environment_type() ) {
	throw new RuntimeException( 'Run this mutating smoke check only on a WordPress environment configured as local.' );
}

/**
 * Stop the smoke check with an actionable CLI failure.
 *
 * @param bool   $condition Whether the assertion passed.
 * @param string $message   Failure detail shown in the local CLI.
 * @throws RuntimeException When an assertion fails.
 */
function ssa_assert( bool $condition, string $message ): void {
	if ( ! $condition ) {
		throw new RuntimeException( $message ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- This is a local WP-CLI test, not HTML output.
	}
}

$routes  = new Routes();
$request = new WP_REST_Request( 'GET', '/site-security-auditor/v1/overview' );
wp_set_current_user( 0 );
$response = rest_get_server()->dispatch( $request );
ssa_assert( $response->get_status() === 403, 'Anonymous overview access was not denied.' );

$admin_id = get_user_by( 'login', 'admin' )->ID;
wp_set_current_user( $admin_id );
$subscriber_login = 'ssa_subscriber_' . wp_generate_password( 10, false, false );
$subscriber       = wp_insert_user(
	array(
		'user_login' => $subscriber_login,
		'user_pass'  => wp_generate_password(),
		'user_email' => $subscriber_login . '@example.test',
		'role'       => 'subscriber',
	)
);
ssa_assert( ! is_wp_error( $subscriber ), 'Could not provision subscriber test user: ' . ( is_wp_error( $subscriber ) ? $subscriber->get_error_message() : 'unknown' ) );
wp_set_current_user( $subscriber );
$response = rest_get_server()->dispatch( new WP_REST_Request( 'GET', '/site-security-auditor/v1/overview' ) );
ssa_assert( $response->get_status() === 403, 'Subscriber overview access was not denied.' );

wp_set_current_user( $admin_id );
$response = rest_get_server()->dispatch( new WP_REST_Request( 'GET', '/site-security-auditor/v1/overview' ) );
ssa_assert( $response->get_status() === 200, 'Administrator overview did not load.' );

wp_schedule_single_event( time() + 60, 'ssa_batch', array( 123 ) );
Plugin::deactivate();
ssa_assert( wp_next_scheduled( 'ssa_batch', array( 123 ) ) === false, 'Deactivation left a scan event scheduled with arguments.' );
Plugin::activate();

$scrubbed = SafeOutput::finding(
	array(
		'title'      => '<script>alert(1)</script> exposed',
		'summary'    => 'Found /etc/passwd and C:\\Users\\operator\\private.txt',
		'references' => array( 'javascript:alert(1)', 'https://user:secret@wordpress.org/support/article/' ),
	)
);
ssa_assert( false === strpos( $scrubbed['title'], '<script>' ), 'Untrusted HTML was not stripped.' );
ssa_assert( false === strpos( $scrubbed['summary'], '/etc/passwd' ) && false === strpos( $scrubbed['summary'], 'operator' ), 'Absolute server paths were not redacted.' );
ssa_assert( array() === $scrubbed['references'], 'Unsafe advisory references were retained.' );

global $wpdb;
$scan_table    = $wpdb->prefix . 'ssa_scans';
$finding_table = $wpdb->prefix . 'ssa_findings';
$retention_tag = 'ssa_retention_' . wp_generate_password( 8, false, false );
$recent        = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
$expired       = gmdate( 'Y-m-d H:i:s', time() - ( 91 * DAY_IN_SECONDS ) );
for ( $index = 0; $index < 25; ++$index ) {
	$wpdb->insert(
		$scan_table,
		array(
			'status'        => 'completed',
			'diagnostic'    => $retention_tag,
			'checks_json'   => '{}',
			'progress_json' => '{}',
			'started_at'    => $recent,
			'updated_at'    => $recent,
		)
	);
	$scan_id = (int) $wpdb->insert_id;
	$payload = array(
		'check_id'       => 'SSA-007',
		'component_type' => 'site',
		'component_key'  => (string) $scan_id,
		'title'          => 'Retention smoke fixture',
		'status'         => 'fail',
		'severity'       => 'low',
	);
	$wpdb->insert(
		$finding_table,
		array(
			'scan_id'       => $scan_id,
			'identity_hash' => hash( 'sha256', (string) $scan_id ),
			'check_id'      => 'SSA-007',
			'status'        => 'fail',
			'severity'      => 'low',
			'kind'          => 'hardening',
			'component_key' => (string) $scan_id,
			'payload_json'  => wp_json_encode( $payload ),
			'created_at'    => $recent,
		)
	);
}
$wpdb->insert(
	$scan_table,
	array(
		'status'        => 'completed',
		'diagnostic'    => $retention_tag,
		'checks_json'   => '{}',
		'progress_json' => '{}',
		'started_at'    => $expired,
		'updated_at'    => $expired,
	)
);
$expired_id = (int) $wpdb->insert_id;
$wpdb->insert(
	$finding_table,
	array(
		'scan_id'       => $expired_id,
		'identity_hash' => hash( 'sha256', (string) $expired_id ),
		'check_id'      => 'SSA-007',
		'status'        => 'fail',
		'severity'      => 'low',
		'kind'          => 'hardening',
		'component_key' => (string) $expired_id,
		'payload_json'  => wp_json_encode(
			array(
				'check_id'       => 'SSA-007',
				'component_type' => 'site',
				'component_key'  => (string) $expired_id,
				'title'          => 'Expired retention fixture',
				'status'         => 'fail',
				'severity'       => 'low',
			)
		),
		'created_at'    => $expired,
	)
);
$expected_tags = $wpdb->get_col( $wpdb->prepare( "SELECT diagnostic FROM %i WHERE status NOT IN ('queued','running') AND started_at >= %s ORDER BY started_at DESC,id DESC LIMIT 20", $scan_table, gmdate( 'Y-m-d H:i:s', time() - 90 * DAY_IN_SECONDS ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching -- Account for newer scans already present in the disposable test site.
$expected_kept = count( array_keys( $expected_tags, $retention_tag, true ) );
RetentionService::prune();
$kept          = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE diagnostic=%s', $scan_table, $retention_tag ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Check the seeded retention fixture only.
$kept_findings = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE scan_id IN (SELECT id FROM %i WHERE diagnostic=%s)', $finding_table, $scan_table, $retention_tag ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Verify retention removed the expired scan's dependent finding.
ssa_assert( $expected_kept === $kept && $expected_kept === $kept_findings, sprintf( 'Retention expected %d fixture scans/findings, got %d/%d.', $expected_kept, $kept, $kept_findings ) );
$terminal_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$scan_table} WHERE status NOT IN ('queued','running')" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table name; no external values.
ssa_assert( 20 === $terminal_count, 'Retention did not keep exactly 20 terminal scans.' );

$nonce            = wp_create_nonce( 'wp_rest' );
$settings_request = new WP_REST_Request( 'POST', '/site-security-auditor/v1/settings' );
$settings_request->set_body( wp_json_encode( array( 'weekly_schedule' => false ) ) );
$response = rest_get_server()->dispatch( $settings_request );
ssa_assert( $response->get_status() === 403, 'POST without nonce was not denied.' );

$calls = 0;
add_filter(
	'pre_http_request',
	static function () use ( &$calls ) {
		++$calls;
		return new WP_Error( 'unexpected_http', 'No provider request expected.' );
	},
	10,
	1
);

$start = new WP_REST_Request( 'POST', '/site-security-auditor/v1/scans' );
$start->set_header( 'X-WP-Nonce', $nonce );
$started = rest_get_server()->dispatch( $start );
ssa_assert( $started->get_status() === 200 || $started->get_status() === 201, 'Administrator could not start a scan.' );
$start_data = $started->get_data();
$scan_id    = (int) ( $start_data['id'] ?? 0 );
ssa_assert( $scan_id > 0, 'Scan start did not return an ID.' );

$duplicate = new WP_REST_Request( 'POST', '/site-security-auditor/v1/scans' );
$duplicate->set_header( 'X-WP-Nonce', $nonce );
ssa_assert( rest_get_server()->dispatch( $duplicate )->get_status() === 409, 'Concurrent scan start was not rejected.' );

$invalid_id = rest_get_server()->dispatch( new WP_REST_Request( 'GET', '/site-security-auditor/v1/scans/999999' ) );
ssa_assert( $invalid_id->get_status() === 404, 'Unknown scan ID was not rejected.' );

$invalid_page = new WP_REST_Request( 'GET', '/site-security-auditor/v1/scans' );
$invalid_page->set_param( 'page', 0 );
ssa_assert( rest_get_server()->dispatch( $invalid_page )->get_status() === 400, 'Invalid pagination was not rejected.' );

for ( $attempt = 0; $attempt < 40; ++$attempt ) {
	$advance = new WP_REST_Request( 'POST', '/site-security-auditor/v1/scans/' . $scan_id . '/advance' );
	$advance->set_header( 'X-WP-Nonce', $nonce );
	$advanced = rest_get_server()->dispatch( $advance );
	ssa_assert( $advanced->get_status() === 200, 'Scan advance failed.' );
	$detail = rest_get_server()->dispatch( new WP_REST_Request( 'GET', '/site-security-auditor/v1/scans/' . $scan_id ) );
	ssa_assert( $detail->get_status() === 200, 'Stored scan could not be reloaded.' );
	$scan = $detail->get_data();
	if ( in_array( $scan['status'] ?? '', array( 'completed', 'partial', 'failed' ), true ) ) {
		break;
	}
}

ssa_assert( isset( $scan ) && in_array( $scan['status'] ?? '', array( 'completed', 'partial' ), true ), 'Scan did not complete successfully.' );
ssa_assert( count( $scan['checks'] ?? array() ) === 16, 'Expected all 16 catalogue checks in stored scan.' );
ssa_assert( array_key_exists( 'score', $scan ) && array_key_exists( 'coverage', $scan ), 'Stored score or coverage is missing.' );
ssa_assert( 0 === $calls, 'A provider HTTP request occurred with opt-ins off.' );

$export_request = new WP_REST_Request( 'GET', '/site-security-auditor/v1/scans/' . $scan_id . '/export' );
$export_request->set_param( 'format', 'json' );
$export = rest_get_server()->dispatch( $export_request );
ssa_assert( $export->get_status() === 200, 'Administrator could not export the report.' );

wp_set_current_user( 0 );
$private_export = rest_get_server()->dispatch( $export_request );
ssa_assert( $private_export->get_status() === 403, 'Anonymous export access was not denied.' );

WP_CLI::success( sprintf( 'Auth, nonce, scan, retention and export checks passed. Scan %d: %s, coverage %.2f%%; no provider HTTP calls.', $scan_id, $scan['status'], $scan['coverage'] ) );
