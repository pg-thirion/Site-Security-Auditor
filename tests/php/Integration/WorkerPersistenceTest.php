<?php
namespace SiteSecurityAuditor\Tests\Integration;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- These fixtures verify real database locks, rollback and cross-connection visibility.

use SiteSecurityAuditor\Api\Routes;
use SiteSecurityAuditor\Persistence\FindingRepository;
use SiteSecurityAuditor\Persistence\ScanRepository;
use SiteSecurityAuditor\Services\ScanRunner;
use SiteSecurityAuditor\Support\Lock;
use WP_UnitTestCase;

final class WorkerPersistenceTest extends WP_UnitTestCase {
	public function test_replaced_worker_cannot_append_findings_after_cancellation(): void {
		global $wpdb;
		$scans = new ScanRepository();
		$id    = $scans->create( 0 );
		$scans->running( $id );
		$scans->save( $id, array( 'progress' => array( 'index' => 12 ) ) );
		update_option( 'ssa_settings', array( 'vulnerability_intelligence' => true ) );
		$version = get_bloginfo( 'version' );
		delete_transient( 'ssa_wpv_' . md5( 'core:' . $version ) );
		$name        = 'ssa_worker_' . $id;
		$replacement = null;
		$http        = static function () use ( $scans, $id, $name, $version, &$replacement ) {
			global $wpdb;
			// Simulate the lease expiring while the provider request is in flight.
			$wpdb->update( $wpdb->options, array( 'option_value' => ( time() - 1 ) . ':expired-owner' ), array( 'option_name' => $name ) );
			$replacement = Lock::acquire( $name );
			$scans->cancel( $id );
			$body = json_decode( file_get_contents( dirname( __DIR__, 3 ) . '/provider-responses/wpvulnerability-plugin.json' ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local provider fixture, never a remote URL.
			unset( $body['data']['plugin'] );
			$body['data']['core']                     = $version;
			$body['data']['vulnerability'][0]['name'] = $version;
			return array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode( $body ),
			);
		};
		add_filter( 'pre_http_request', $http );
		try {
			$result = ScanRunner::advance( $id );
			$this->assertIsString( $replacement );
			$this->assertSame( 'cancelled', $result['status'] );
			$this->assertSame( array(), $result['checks'] );
			$this->assertSame( 0, ( new FindingRepository() )->count( $id ) );
			$this->assertSame( 0, $scans->fail_if_owner( $id, 'not-the-owner', 'batch_failed' ) );
			$this->assertSame( $replacement, $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name=%s", $name ) ) );
		} finally {
			remove_filter( 'pre_http_request', $http );
			if ( is_string( $replacement ) ) {
				Lock::release( $name, $replacement );
			}
		}
	}
	public function test_capacity_is_checked_before_writes_and_retries_fit_at_the_cap(): void {
		$scans = new ScanRepository();
		$id    = $scans->create( 0 );
		$scans->running( $id );
		$scans->save( $id, array( 'progress' => array( 'index' => 15 ) ) );
		$findings = new FindingRepository();
		for ( $index = 0; $index < 4900; ++$index ) {
			$findings->store(
				$id,
				array(
					'check_id'      => 'SSA-015',
					'component_key' => 'seed-' . $index,
					'title'         => 'Existing finding',
				)
			);
		}
		update_option( 'ssa_settings', array( 'core_integrity' => true ) );
		$checksums = array();
		for ( $index = 0; $index < 250; ++$index ) {
			$checksums[ 'ssa-missing-fixture-' . $index . '.php' ] = md5( 'fixture' );
		}
		$key    = 'ssa_checksums_' . md5( get_bloginfo( 'version' ) . ':' . get_locale() );
		$cached = static fn() => $checksums;
		add_filter( 'pre_transient_' . $key, $cached );
		try {
			$result = ScanRunner::advance( $id );
			$this->assertSame( 'failed', $result['status'] );
			$this->assertSame( 'finding_limit', $result['diagnostic'] );
			$this->assertSame( 4900, $findings->count( $id ) );
			$request = new \WP_REST_Request( 'GET', '/site-security-auditor/v1/scans/' . $id . '/export' );
			$request->set_param( 'id', $id );
			$export = ( new Routes() )->dispatch( $request );
			$this->assertSame( 200, $export->get_status() );
			$this->assertCount( 4900, json_decode( $export->get_data(), true )['findings'] );
			$retry = array();
			for ( $index = 4900; $index < 5000; ++$index ) {
				$retry[] = array(
					'check_id'      => 'SSA-015',
					'component_key' => 'seed-' . $index,
					'title'         => 'Retry finding',
				);
			}
			$findings->store_batch( $id, $retry );
			$findings->store_batch( $id, array_merge( $retry, $retry ) );
			$this->assertSame( 5000, $findings->count( $id ) );
			// Preserve every row from oversized failed scans created before capacity was checked up front.
			for ( $index = 0; $index < 150; ++$index ) {
				$findings->store(
					$id,
					array(
						'check_id'      => 'SSA-015',
						'component_key' => 'legacy-' . $index,
						'title'         => 'Legacy finding',
					)
				);
			}
			$legacy = ( new Routes() )->dispatch( $request );
			$this->assertCount( 5150, json_decode( $legacy->get_data(), true )['findings'] );
		} finally {
			remove_filter( 'pre_transient_' . $key, $cached );
		}
	}
	public function test_guard_preserves_outer_transaction_and_rolls_back_failed_persistence(): void {
		global $wpdb;
		$name  = 'ssa_worker_guard_test';
		$owner = Lock::acquire( $name );
		$this->assertIsString( $owner );
		$original          = $owner;
		$reconnect_retries = $wpdb->reconnect_retries;
		$other             = new \wpdb( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
		try {
			$this->assertTrue(
				Lock::with_owner(
					$name,
					$owner,
					array(),
					function () use ( $wpdb ) {
						$this->assertSame( 0, $wpdb->reconnect_retries );
						add_option( 'ssa_guard_uncommitted', 'not committed' );
					}
				)
			);
			$this->assertNotSame( $original, $owner );
			$this->assertSame( $reconnect_retries, $wpdb->reconnect_retries );
			$this->assertNull( $other->get_var( "SELECT option_value FROM {$wpdb->options} WHERE option_name='ssa_guard_uncommitted'" ) );
			try {
				Lock::with_owner(
					$name,
					$owner,
					array(),
					static function () use ( $wpdb ) {
						$wpdb->insert(
							$wpdb->options,
							array(
								'option_name'  => 'ssa_guard_rolled_back',
								'option_value' => 'discard',
								'autoload'     => 'no',
							)
						);
						throw new \RuntimeException( 'simulated_failure' );
					}
				);
				$this->fail( 'Expected persistence to fail.' );
			} catch ( \RuntimeException $error ) {
				$this->assertSame( 'simulated_failure', $error->getMessage() );
			}
			$this->assertNull( $wpdb->get_var( "SELECT option_value FROM {$wpdb->options} WHERE option_name='ssa_guard_rolled_back'" ) );
			$this->assertSame( $reconnect_retries, $wpdb->reconnect_retries );
		} finally {
			$other->close();
			Lock::release( $name, $owner );
		}
	}
	public function test_live_persistence_blocks_a_second_database_connection(): void {
		global $wpdb;
		self::commit_transaction();
		$wpdb->query( 'SET autocommit=1' );
		$name  = 'ssa_worker_guard_contention';
		$owner = Lock::acquire( $name );
		$this->assertIsString( $owner );
		$other = new \wpdb( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
		$other->suppress_errors( true );
		$other->query( 'SET SESSION innodb_lock_wait_timeout=1' );
		try {
			$this->assertTrue(
				Lock::with_owner(
					$name,
					$owner,
					array(),
					function () use ( $other, $wpdb, $name ) {
						$changed = $other->query( $other->prepare( "UPDATE {$wpdb->options} SET option_value='replacement' WHERE option_name=%s", $name ) );
						$this->assertFalse( $changed );
						$this->assertStringContainsString( 'Lock wait timeout', $other->last_error );
					}
				)
			);
		} finally {
			$other->close();
			Lock::release( $name, $owner );
			$this->start_transaction();
		}
	}
	public function test_nontransactional_storage_returns_an_explicit_error(): void {
		global $wpdb;
		$id     = ( new ScanRepository() )->create( 0 );
		$engine = static fn( $query ) => str_starts_with( $query, 'SHOW TABLE STATUS' ) ? "SELECT 'MyISAM' AS Engine" : $query;
		add_filter( 'query', $engine );
		try {
			$result = ScanRunner::advance( $id );
			$this->assertWPError( $result );
			$this->assertSame( 'ssa_storage_engine', $result->get_error_code() );
			$this->assertSame( 0, ( new FindingRepository() )->count( $id ) );
			$scans = new ScanRepository();
			$this->assertSame( 'failed', $scans->get( $id )['status'] );
			$this->assertNull( $scans->active() );
			$count = $scans->listing()['total'];
			$this->assertWPError( ScanRunner::start( 0 ) );
			$this->assertSame( $count, $scans->listing()['total'] );
		} finally {
			remove_filter( 'query', $engine );
		}
	}
}
