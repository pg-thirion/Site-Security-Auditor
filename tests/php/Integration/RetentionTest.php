<?php
namespace SiteSecurityAuditor\Tests\Integration;

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery -- This integration fixture seeds private custom tables to exercise pruning.

use SiteSecurityAuditor\Persistence\Schema;
use SiteSecurityAuditor\Services\RetentionService;
use WP_UnitTestCase;

final class RetentionTest extends WP_UnitTestCase {
	public function test_prunes_beyond_twenty_or_ninety_days_and_cascades_findings(): void {
		global $wpdb;

		Schema::install();
		$scan_table    = $wpdb->prefix . 'ssa_scans';
		$finding_table = $wpdb->prefix . 'ssa_findings';
		$recent        = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
		$old           = gmdate( 'Y-m-d H:i:s', time() - ( 91 * DAY_IN_SECONDS ) );
		$seeded_ids    = array();

		for ( $index = 0; $index < 25; ++$index ) {
			$wpdb->insert(
				$scan_table,
				array(
					'status'        => 'completed',
					'checks_json'   => '{}',
					'progress_json' => '{}',
					'started_at'    => $recent,
					'updated_at'    => $recent,
				)
			);
			$seeded_ids[] = (int) $wpdb->insert_id;
		}

		$wpdb->insert(
			$scan_table,
			array(
				'status'        => 'completed',
				'checks_json'   => '{}',
				'progress_json' => '{}',
				'started_at'    => $old,
				'updated_at'    => $old,
			)
		);
		$expired_id   = (int) $wpdb->insert_id;
		$seeded_ids[] = $expired_id;

		foreach ( $seeded_ids as $scan_id ) {
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
					'payload_json'  => '{}',
					'created_at'    => $recent,
				)
			);
		}

		RetentionService::prune();

		$remaining_ids      = $wpdb->get_col( $wpdb->prepare( 'SELECT id FROM %i ORDER BY id DESC LIMIT %d', $scan_table, 100 ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching -- Verify the custom retention table directly.
		$remaining_findings = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $finding_table ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching -- Verify dependent custom rows were removed.

		$this->assertCount( 20, $remaining_ids );
		$this->assertNotContains( $expired_id, array_map( 'intval', $remaining_ids ) );
		$this->assertSame( 20, $remaining_findings );
	}
}
