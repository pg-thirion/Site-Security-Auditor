<?php
namespace SiteSecurityAuditor\Tests\Integration;

use SiteSecurityAuditor\Plugin;
use WP_UnitTestCase;

final class PluginLifecycleTest extends WP_UnitTestCase {
	public function test_activation_installs_tables_and_default_settings(): void {
		global $wpdb;

		Plugin::activate();
		$this->assertSame( '1', get_option( 'ssa_schema_version' ) );
		$this->assertIsArray( get_option( 'ssa_settings' ) );
		$this->assertNotFalse( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $wpdb->prefix . 'ssa_scans' ) ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Verify activation created the custom table.
		$this->assertNotFalse( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $wpdb->prefix . 'ssa_findings' ) ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Verify activation created the custom table.
	}

	public function test_deactivation_clears_plugin_schedules(): void {
		wp_schedule_single_event( time() + 60, 'ssa_batch', array( 123 ) );
		wp_schedule_event( time() + 60, 'weekly', 'ssa_weekly' );

		Plugin::deactivate();

		$this->assertFalse( wp_next_scheduled( 'ssa_batch', array( 123 ) ) );
		$this->assertFalse( wp_next_scheduled( 'ssa_weekly' ) );
	}

	public function test_reactivation_restores_saved_weekly_schedule_once(): void {
		wp_clear_scheduled_hook( 'ssa_weekly' );
		update_option(
			'ssa_settings',
			array(
				'vulnerability_intelligence' => false,
				'core_integrity'             => false,
				'weekly_schedule'            => true,
			)
		);

		Plugin::activate();
		$this->assertSame( 1, $this->scheduled_event_count( 'ssa_weekly' ) );

		Plugin::deactivate();
		$this->assertFalse( wp_next_scheduled( 'ssa_weekly' ) );
		$this->assertTrue( get_option( 'ssa_settings' )['weekly_schedule'] );

		Plugin::activate();
		$scheduled = wp_next_scheduled( 'ssa_weekly' );
		$this->assertNotFalse( $scheduled );
		$this->assertSame( 'weekly', wp_get_schedule( 'ssa_weekly' ) );
		Plugin::activate();
		$this->assertSame( $scheduled, wp_next_scheduled( 'ssa_weekly' ) );
		$this->assertSame( 1, $this->scheduled_event_count( 'ssa_weekly' ) );

		Plugin::deactivate();
		update_option( 'ssa_settings', array( 'weekly_schedule' => false ) );
		Plugin::activate();
		$this->assertFalse( wp_next_scheduled( 'ssa_weekly' ) );
	}

	private function scheduled_event_count( string $hook ): int {
		$count = 0;
		foreach ( (array) _get_cron_array() as $events ) {
			$count += count( $events[ $hook ] ?? array() );
		}
		return $count;
	}
}
