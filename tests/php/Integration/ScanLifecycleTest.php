<?php

namespace SiteSecurityAuditor\Tests\Integration;

use SiteSecurityAuditor\Persistence\FindingRepository;
use SiteSecurityAuditor\Persistence\ScanRepository;
use SiteSecurityAuditor\Plugin;
use SiteSecurityAuditor\Services\ScanRunner;
use SiteSecurityAuditor\Support\Lock;
use WP_Error;
use WP_REST_Request;
use WP_UnitTestCase;

final class ScanLifecycleTest extends WP_UnitTestCase {
	public function test_registration_uses_real_role_capabilities_for_privileged_operations(): void {
		$role_name = 'ssa_registration_fixture';
		$role      = add_role( $role_name, 'Security audit fixture', array( 'read' => true ) );
		$this->assertInstanceOf( \WP_Role::class, $role );
		update_option( 'users_can_register', true );
		update_option( 'default_role', $role_name );
		try {
			$this->assertSame( 'pass', \SiteSecurityAuditor\Audit\AuditRegistry::run( 'SSA-011' )['status'] );
			foreach ( array( 'create_users', 'delete_users', 'remove_users', 'delete_plugins', 'update_plugins', 'edit_themes', 'delete_themes', 'update_themes', 'update_core' ) as $capability ) {
				$role->add_cap( $capability );
				$result = \SiteSecurityAuditor\Audit\AuditRegistry::run( 'SSA-011' );
				$this->assertSame( 'fail', $result['status'], $capability );
				$this->assertSame( 'critical', $result['findings'][0]['severity'], $capability );
				$role->remove_cap( $capability );
			}
			update_option( 'users_can_register', false );
			$role->add_cap( 'edit_themes' );
			$this->assertSame( 'pass', \SiteSecurityAuditor\Audit\AuditRegistry::run( 'SSA-011' )['status'] );
		} finally {
			remove_role( $role_name );
		}
	}
	public function test_lock_does_not_replace_owner_when_option_api_observes_no_value(): void {
		$name  = 'ssa_stale_option_observation';
		$owner = Lock::acquire( $name );
		$this->assertIsString( $owner );
		// Reproduce the stale observation made by a second process before the first insert.
		add_filter( 'option_' . $name, '__return_false' );
		try {
			$this->assertNull( Lock::acquire( $name ) );
		} finally {
			remove_filter( 'option_' . $name, '__return_false' );
		}
		$this->assertSame( $owner, get_option( $name ) );
		Lock::release( $name, $owner );
		$this->assertIsString( Lock::acquire( $name ) );
	}
	public function test_large_inventory_and_slow_provider_remain_bounded_and_unknown(): void {
		update_option(
			'ssa_settings',
			array(
				'vulnerability_intelligence' => true,
				'core_integrity'             => false,
			)
		);
		$previous_plugins = wp_cache_get( 'plugins', 'plugins' );
		$plugins          = array();
		$updates          = (object) array(
			'last_checked' => time(),
			'checked'      => array(),
			'response'     => array(),
			'no_update'    => array(),
		);
		foreach ( range( 1, 1000 ) as $number ) {
			$slug                        = 'ssa-bounded-fixture-' . $number;
			$file                        = $slug . '/main.php';
			$plugins[ $file ]            = array(
				'Name'      => $slug,
				'Version'   => '1.0',
				'UpdateURI' => '',
			);
			$updates->checked[ $file ]   = '1.0';
			$updates->no_update[ $file ] = (object) array( 'slug' => $slug );
		}
		wp_cache_set( 'plugins', array( '' => $plugins ), 'plugins' );
		$update_filter = static fn() => $updates;
		$calls         = 0;
		$http_filter   = static function ( $preempt, $request_args, $url ) use ( &$calls ) {
			if ( str_starts_with( $url, 'https://www.wpvulnerability.net/plugin/ssa-bounded-fixture-' ) ) {
				++$calls;
				usleep( (int) ( $request_args['timeout'] * 1000000 ) );
				return new WP_Error( 'http_request_failed', 'Simulated provider timeout.' );
			}
			return $preempt;
		};
		add_filter( 'pre_site_transient_update_plugins', $update_filter );
		add_filter( 'pre_http_request', $http_filter, 10, 3 );
		try {
			$started = microtime( true );
			$result  = \SiteSecurityAuditor\Audit\Checks\ProviderChecks::run( 5, array() );
			$elapsed = microtime( true ) - $started;
			$this->assertGreaterThan( 0, $calls );
			$this->assertLessThanOrEqual( 5, $calls );
			$this->assertLessThan( 11, $elapsed, 'One batch must not process the entire slow inventory.' );
			$this->assertSame( 'unknown', $result['status'] );
			$this->assertTrue( $result['has_unknown'] );
			$this->assertNotEmpty( $result['cursor'] );
			$this->assertSame( $calls, $result['cursor']['offset'] );
			$this->assertSame( array(), $result['findings'] );
		} finally {
			remove_filter( 'pre_site_transient_update_plugins', $update_filter );
			remove_filter( 'pre_http_request', $http_filter, 10 );
			wp_cache_delete( 'plugins', 'plugins' );
			if ( false !== $previous_plugins ) {
				wp_cache_set( 'plugins', $previous_plugins, 'plugins' );
			}
		}
	}

	public static function wpSetUpBeforeClass( $factory ): void {
		Plugin::activate();
	}

	public function test_scheduled_batch_hook_advances_and_reschedules_bounded_work(): void {
		update_option(
			'ssa_settings',
			array(
				'vulnerability_intelligence' => false,
				'core_integrity'             => false,
			)
		);
		$scan = ScanRunner::start( 0 );
		$this->assertIsArray( $scan );
		$scheduled = wp_next_scheduled( 'ssa_batch', array( $scan['id'] ) );
		$this->assertNotFalse( $scheduled );
		// WP-Cron removes a single event before invoking its registered callback.
		wp_unschedule_event( $scheduled, 'ssa_batch', array( $scan['id'] ) );
		do_action( 'ssa_batch', $scan['id'] );
		$advanced = ( new ScanRepository() )->get( $scan['id'] );
		$this->assertSame( 'running', $advanced['status'] );
		$this->assertCount( 1, $advanced['checks'] );
		$this->assertNotFalse( wp_next_scheduled( 'ssa_batch', array( $scan['id'] ) ) );
		wp_clear_scheduled_hook( 'ssa_batch', array( $scan['id'] ) );
	}

	public function test_worker_lock_excludes_other_owners_and_survives_stale_release(): void {
		$name  = 'ssa_worker_integration';
		$owner = Lock::acquire( $name );
		$this->assertIsString( $owner );
		$this->assertNull( Lock::acquire( $name ) );
		Lock::release( $name, 'not-the-owner' );
		$this->assertNull( Lock::acquire( $name ) );
		$expired = ( time() - 1 ) . ':expired-owner';
		update_option( $name, $expired );
		$replacement = Lock::acquire( $name );
		$this->assertIsString( $replacement );
		Lock::release( $name, $expired );
		$this->assertNull( Lock::acquire( $name ) );
		Lock::release( $name, $replacement );
		$next_owner = Lock::acquire( $name );
		$this->assertIsString( $next_owner );
		Lock::release( $name, $next_owner );
	}

	public function test_start_does_not_create_scan_after_start_lock_is_replaced(): void {
		$repo         = new ScanRepository();
		$before       = $repo->listing()['total'];
		$replacement  = null;
		$replace_lock = static function ( $query ) use ( &$replacement ) {
			if ( null === $replacement && str_starts_with( $query, 'SHOW TABLE STATUS LIKE' ) ) {
				$replacement = ( time() + 120 ) . ':replacement';
				update_option( 'ssa_start_lock', $replacement );
			}
			return $query;
		};
		add_filter( 'query', $replace_lock );
		try {
			$result = ScanRunner::start( 0 );
		} finally {
			remove_filter( 'query', $replace_lock );
			if ( $replacement ) {
				Lock::release( 'ssa_start_lock', $replacement );
			}
		}
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'ssa_busy', $result->get_error_code() );
		$this->assertSame( $before, $repo->listing()['total'] );
	}

	public function test_bounded_local_scan_and_historical_results_survive_settings_changes(): void {
		$user = self::factory()->user->create( array( 'role' => 'administrator' ) );
		update_option(
			'ssa_settings',
			array(
				'vulnerability_intelligence' => false,
				'core_integrity'             => false,
			)
		);
		$calls      = 0;
		$block_http = static function () use ( &$calls ) {
			++$calls;
			return new WP_Error( 'unexpected_http', 'Network disabled in integration test.' );
		};
		add_filter( 'pre_http_request', $block_http );
		try {
			$scan = ScanRunner::start( $user );
			$this->assertIsArray( $scan );
			$this->assertSame( 'queued', $scan['status'] );
			$this->assertWPError( ScanRunner::start( $user ) );
			$scan = ScanRunner::advance( $scan['id'] );
			$this->assertSame( 'running', $scan['status'] );
			$this->assertCount( 1, $scan['checks'] );
			for ( $batch = 1; $batch < 16; ++$batch ) {
				$scan = ScanRunner::advance( $scan['id'] );
			}
			$this->assertContains( $scan['status'], array( 'completed', 'partial' ) );
			$this->assertCount( 16, $scan['checks'] );
			foreach ( array( 'SSA-004', 'SSA-005', 'SSA-006', 'SSA-012' ) as $check_id ) {
				$this->assertSame( 'unknown', $scan['checks'][ $check_id ]['status'] );
			}
			$this->assertSame( 0, $calls );
			update_option(
				'ssa_settings',
				array(
					'vulnerability_intelligence' => true,
					'core_integrity'             => true,
				)
			);
			$this->assertSame( $scan, ScanRunner::advance( $scan['id'] ) );
			$this->assertSame( $scan, ( new ScanRepository() )->get( $scan['id'] ) );
			$this->assertSame( 0, $calls );
		} finally {
			remove_filter( 'pre_http_request', $block_http );
		}
	}

	public function test_retried_findings_and_selected_exports_preserve_identity_and_privacy(): void {
		$user = self::factory()->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $user );
		$scans    = new ScanRepository();
		$id       = $scans->create( $user );
		$other_id = $scans->create( $user );
		$findings = new FindingRepository();
		$finding  = array(
			'check_id'       => 'SSA-007',
			'component_type' => 'site',
			'component_key'  => 'https',
			'status'         => 'fail',
			'severity'       => 'low',
			'kind'           => 'configuration_risk',
			'title'          => '=SUM(1,2)',
			'evidence'       => '<script>bad()</script> /etc/passwd C:\\Users\\operator\\private.txt',
			'references'     => array( 'https://github.com/example/exploit/blob/main/poc.php', 'https://wordpress.org/support/article/hardening-wordpress/' ),
		);
		$findings->store( $id, $finding );
		$first = $findings->all( $id )[0];
		$findings->store( $id, $finding );
		$this->assertSame( 1, $findings->count( $id ) );
		$this->assertSame( $first['id'], $findings->all( $id )[0]['id'] );
		$finding['title'] = 'Other scan only';
		$findings->store( $other_id, $finding );
		$scans->save(
			$id,
			array(
				'progress' => array(
					'index'  => 0,
					'cursor' => array( 'private' => 'internal_cursor_marker' ),
				),
			)
		);
		$request  = new WP_REST_Request( 'GET', '/site-security-auditor/v1/scans/' . $id . '/export' );
		$response = rest_get_server()->dispatch( $request );
		$this->assertSame( 200, $response->get_status() );
		$body   = $response->get_data();
		$report = json_decode( $body, true );
		$this->assertSame( $id, $report['scan']['id'] );
		$this->assertCount( 1, $report['findings'] );
		$this->assertArrayNotHasKey( 'progress', $report['scan'] );
		foreach ( array( '<script>', '/etc/passwd', 'private.txt', 'internal_cursor_marker', 'Other scan only', '/exploit/' ) as $private_value ) {
			$this->assertStringNotContainsString( $private_value, $body );
		}
		$this->assertSame( array( 'https://wordpress.org/support/article/hardening-wordpress/' ), $report['findings'][0]['references'] );
		$request->set_param( 'format', 'csv' );
		$csv_response = rest_get_server()->dispatch( $request );
		$this->assertSame( 200, $csv_response->get_status() );
		$this->assertStringContainsString( "'=SUM(1,2)", $csv_response->get_data() );
		$this->assertStringNotContainsString( 'Other scan only', $csv_response->get_data() );
	}
}
