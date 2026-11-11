<?php
namespace SiteSecurityAuditor\Tests\Integration;

use SiteSecurityAuditor\Api\Routes;
use SiteSecurityAuditor\Persistence\FindingRepository;
use SiteSecurityAuditor\Persistence\ScanRepository;
use WP_REST_Request;
use WP_UnitTestCase;

final class ApiPersistenceTest extends WP_UnitTestCase {
	public function test_overview_does_not_include_findings(): void {
		$id = ( new ScanRepository() )->create( 0 );
		$this->assertGreaterThan( 0, $id );
		$request  = new WP_REST_Request( 'GET', '/site-security-auditor/v1/overview' );
		$response = ( new Routes() )->dispatch( $request )->get_data();
		$this->assertSame( $id, $response['latest']['id'] );
		$this->assertArrayNotHasKey( 'findings', $response );
	}

	public function test_failed_opt_out_does_not_report_success_or_change_schedule(): void {
		$settings = array(
			'vulnerability_intelligence' => true,
			'core_integrity'             => false,
			'weekly_schedule'            => true,
		);
		update_option( 'ssa_settings', $settings, false );
		wp_clear_scheduled_hook( 'ssa_weekly' );
		$scheduled = time() + WEEK_IN_SECONDS;
		wp_schedule_event( $scheduled, 'weekly', 'ssa_weekly' );
		$block_write = static fn( $new_value, $old_value ) => $old_value;
		add_filter( 'pre_update_option_ssa_settings', $block_write, 10, 2 );
		try {
			$request = new WP_REST_Request( 'POST', '/site-security-auditor/v1/settings' );
			$request->set_header( 'Content-Type', 'application/json' );
			$request->set_body(
				wp_json_encode(
					array(
						'vulnerability_intelligence' => false,
						'weekly_schedule'            => false,
					)
				)
			);
			$response = ( new Routes() )->dispatch( $request );
			$this->assertWPError( $response );
			$this->assertSame( 'ssa_settings_save', $response->get_error_code() );
			$this->assertSame( 500, $response->get_error_data()['status'] );
			$this->assertSame( $settings, get_option( 'ssa_settings' ) );
			$this->assertSame( $scheduled, wp_next_scheduled( 'ssa_weekly' ) );
		} finally {
			remove_filter( 'pre_update_option_ssa_settings', $block_write, 10 );
			wp_clear_scheduled_hook( 'ssa_weekly' );
		}
	}
	public function test_unchanged_settings_and_successful_opt_out_are_accepted(): void {
		$settings = array(
			'vulnerability_intelligence' => true,
			'core_integrity'             => false,
			'weekly_schedule'            => false,
		);
		update_option( 'ssa_settings', $settings, false );
		$request = new WP_REST_Request( 'POST', '/site-security-auditor/v1/settings' );
		$request->set_header( 'Content-Type', 'application/json' );
		$request->set_body( wp_json_encode( $settings ) );
		$this->assertSame( $settings, ( new Routes() )->dispatch( $request )->get_data() );
		$request->set_body( wp_json_encode( array( 'vulnerability_intelligence' => false ) ) );
		$settings['vulnerability_intelligence'] = false;
		$this->assertSame( $settings, ( new Routes() )->dispatch( $request )->get_data() );
		$this->assertSame( $settings, get_option( 'ssa_settings' ) );
	}
	public function test_findings_pages_filter_in_sql_and_preserve_literal_search(): void {
		$id         = ( new ScanRepository() )->create( 0 );
		$repository = new FindingRepository();
		for ( $index = 0; $index < 205; ++$index ) {
			$repository->store(
				$id,
				array(
					'check_id'       => 'SSA-007',
					'component_type' => 'plugin',
					'component_key'  => 'fixture-' . $index,
					'component_name' => 'Fixture',
					'status'         => 'fail',
					'severity'       => $index < 5 ? 'high' : 'low',
					'kind'           => 'configuration_risk',
					'title'          => 'Fixture ' . $index . ( 0 === $index ? ' 100%_literal' : '' ),
				)
			);
		}
		$queries = array();
		$record  = static function ( $query ) use ( &$queries ) {
			if ( str_contains( $query, 'SELECT payload_json' ) ) {
				$queries[] = $query;
			}
			return $query;
		};
		add_filter( 'query', $record );
		try {
			$request = new WP_REST_Request( 'GET', '/site-security-auditor/v1/scans/' . $id . '/findings' );
			$request->set_param( 'id', $id );
			$request->set_param( 'page', 2 );
			$request->set_param( 'per_page', 100 );
			$result = ( new Routes() )->dispatch( $request )->get_data();
			$this->assertSame( 205, $result['total'] );
			$this->assertCount( 100, $result['items'] );
			$this->assertCount( 1, $queries );
			$this->assertStringContainsString( 'LIMIT 100 OFFSET 100', $queries[0] );
			$this->assertSame( 'fixture-109', $result['items'][0]['component_key'] );
			$filtered = $repository->listing(
				$id,
				1,
				100,
				array(
					'severity' => 'high',
					'status'   => 'fail',
					'kind'     => 'configuration_risk',
				)
			);
			$this->assertSame( 5, $filtered['total'] );
			$this->assertCount( 5, $filtered['items'] );
			$this->assertSame( 0, $repository->listing( $id, 1, 100, array( 'status' => 'pass' ) )['total'] );
			$search = $repository->listing( $id, 1, 100, array(), '100%_literal' );
			$this->assertSame( 1, $search['total'] );
			$this->assertSame( 'fixture-0', $search['items'][0]['component_key'] );
			$this->assertSame( 0, $repository->listing( $id + 1, 1, 100 )['total'] );
		} finally {
			remove_filter( 'query', $record );
		}
	}
}
